"""Parser of the `btool --debug` output, and `[default]` de-expansion
(spec sections 6.3-6.4, format measured in M-3).

The output is NOT "one line = one record": a multi-line value continues on the
next physical line without any path prefix, and the path column width is
variable - aligned on the longest path of the current output. Never assume a
fixed width.
"""

from .model import BtoolConf, BtoolRecord, BtoolWinner


def parse_btool_output(text, etc_prefix):
    """Parse a `btool <conf> list --debug` output into a `BtoolConf`.

    A line is path-prefixed when it starts with the resolved `$SPLUNK_HOME/etc`
    prefix AND its first token (up to the first blank) ends with `.conf`
    (spec section 6.3). Then:

    - a rest of the form `[<name>]` is a stanza header: the carried path is the
      highest-precedence file declaring the stanza (M-1) - a resolution
      metadata, EXCLUDED from the definitions;
    - otherwise it is a definition: separator ` = ` STRICT (space, equals,
      space); the value runs to the end of line, trailing spaces included, and
      may be empty (`hostname = ` ends with the separator's space).

    Any line without the path prefix is a continuation of the previous
    definition's value, concatenated with `\\n` (the source `\\` was consumed
    by btool, the line break belongs to the value - M-3d).

    Residual ambiguity (reserve R-8, accepted by D-14): a multi-line value
    whose continuation line would start with the resolved etc prefix followed
    by a `.conf` token would be misclassified as a record. The probability is
    negligible, and the confrontation of section 6.5 guarantees detection
    through `resolver_mismatch` - never a silent failure.
    """
    stanzas = {}
    headers = {}
    current_stanza = None
    last = None  # (stanza, key) of the previous definition, for continuations

    lines = text.split("\n")
    if lines and lines[-1] == "":
        # Artifact of the final newline: without this, it would be read as an
        # empty continuation line appended to the last value.
        lines.pop()

    for raw in lines:
        line = raw[:-1] if raw.endswith("\r") else raw
        first_token = line.split(" ", 1)[0]
        if line.startswith(etc_prefix) and first_token.endswith(".conf"):
            path = first_token
            # The path column is padded with a variable number of spaces
            # (>= 1), aligned on the longest path of THIS output; the rest is
            # taken verbatim after the blank block.
            rest = line[len(first_token):].lstrip(" ")
            if rest.startswith("[") and rest.endswith("]"):
                current_stanza = rest[1:-1]
                headers[current_stanza] = path
                last = None
                continue
            sep = rest.find(" = ")
            if sep == -1 or current_stanza is None:
                # Not a definition per M-3e (defensive: cannot happen on a
                # conformant output).
                last = None
                continue
            key = rest[:sep]
            value = rest[sep + 3:]
            stanzas.setdefault(current_stanza, {})[key] = BtoolRecord(
                path=path, key=key, value=value
            )
            last = (current_stanza, key)
        else:
            if last is None:
                continue  # defensive: continuation without a previous record
            stanza, key = last
            record = stanzas[stanza][key]
            stanzas[stanza][key] = BtoolRecord(
                path=record.path, key=key, value=record.value + "\n" + line
            )

    return BtoolConf(stanzas=stanzas, headers=headers)


def deexpand(btool, literal_defs):
    """De-expand the `[default]` repetitions; return the btool verdicts.

    btool repeats every `[default]` key in every stanza of the conf, with the
    path of the file CARRYING the `[default]` definition - the path alone does
    not distinguish an inheritance line from a local definition (M-3b).

    The reference set is built from OUR OWN parsed `[default]` definitions, not
    from the `[default]` stanza of the btool output (D-21). Measured on 9.4.6
    over 76 conf types: btool prints a `[default]` stanza header whenever a
    source file declares one - EXCEPT for `inputs`, where the header is
    suppressed although the inheritance is still expanded into every stanza.
    The btool header is therefore not a reliable carrier of the `[default]`
    definitions, while the source files always are. Building `D` from the
    output made every inherited key of every stanza an anomaly on `inputs`
    (803 `resolver_mismatch` on a full sweep).

    Rule, per conf (spec section 6.4, D-21):

    1. `D` = `(path, key, value)` triplets of our literal `[default]`
       definitions - explicit `[default]` header or implicit head-of-file
       stanza, both parsed as `default` (section 4.2).
    2. A btool record in stanza S != default whose triplet belongs to `D` is an
       inheritance repetition, and is FOLDED BACK onto `(default, key)` - the
       literal origin it was expanded from (D-7) - UNLESS the file at that path
       carries an `(S, key)` definition of its own, in which case the btool
       line restitutes a REAL local redefinition and is kept as the verdict of
       `(S, key)` ("source information" rule: we read the files, btool only
       shows its view). D-11 stated that rule as an exception; D-21 makes it
       the foundation.
    3. The folding never overrides an explicit `[default]` record of the btool
       output: when btool does print the header, that record is authoritative.
       The fold only reconstructs the verdict btool withholds when it
       suppresses the header, from btool's own expanded lines.
    4. The remaining records form, per `(stanza, key)` group, the btool
       verdict - at most one per group.

    `literal_defs` is a set of `(stanza, key, path, value)` tuples built from
    our own parsed definitions (section 4).
    """
    default_triplets = {
        (path, key, value)
        for stanza, key, path, value in literal_defs
        if stanza == "default"
    }
    # `(path, stanza, key)` of every definition we read: tells whether the file
    # a btool line points at carries an `(S, key)` of its own (D-21, step 2).
    own_definitions = {
        (path, stanza, key) for stanza, key, path, value in literal_defs
    }

    winners = {}
    folded = {}
    for stanza, records in btool.stanzas.items():
        for key, record in records.items():
            triplet = (record.path, key, record.value)
            if (stanza != "default" and triplet in default_triplets
                    and (record.path, stanza, key) not in own_definitions):
                # Inheritance repetition: its literal origin is the `[default]`
                # definition of that very file.
                folded[key] = BtoolWinner(path=record.path, value=record.value)
                continue
            winners[(stanza, key)] = BtoolWinner(path=record.path, value=record.value)

    for key, winner in folded.items():
        winners.setdefault(("default", key), winner)
    return winners
