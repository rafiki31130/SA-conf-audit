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
    not distinguish an inheritance line from a local definition (M-3b). Rule,
    per conf (spec section 6.4):

    1. `D` = set of `(path, key, value)` triplets of the `default` stanza.
    2. A definition in stanza S != default whose triplet belongs to `D` is an
       inheritance repetition - discarded - UNLESS our literal definitions
       contain a `(S, key)` definition with the same path and value: then the
       btool line restitutes a REAL local redefinition and is kept ("source
       information" rule, D-11: we read the files, btool only shows its view).
    3. The remaining records form, per `(stanza, key)` group, the btool
       verdict - at most one per group.

    `literal_defs` is a set of `(stanza, key, path, value)` tuples built from
    our own parsed definitions (section 4).
    """
    default_records = btool.stanzas.get("default", {})
    default_triplets = {
        (record.path, key, record.value)
        for key, record in default_records.items()
    }

    winners = {}
    for stanza, records in btool.stanzas.items():
        for key, record in records.items():
            if stanza != "default" and (record.path, key, record.value) in default_triplets:
                if (stanza, key, record.path, record.value) not in literal_defs:
                    continue  # inheritance repetition, discarded
            winners[(stanza, key)] = BtoolWinner(path=record.path, value=record.value)
    return winners
