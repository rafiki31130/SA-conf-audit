"""Parser of the `btool --debug` output, and `[default]` de-expansion
(spec sections 6.3-6.4, format measured in M-3).

The output is NOT "one line = one record": a multi-line value continues on the
next physical line without any path prefix, and the path column width is
variable - aligned on the longest path of the current output. Never assume a
fixed width.
"""

from .model import BtoolConf, BtoolRecord, BtoolWinner


def parse_btool_output(text, etc_prefix, unattributed=()):
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

    A line WITHOUT the path prefix is one of two things (D-24):

    - an **unattributed definition**: btool emits `<key> = <value>` at column 0,
      with no path at all, when it cannot attach the value to any file. Measured
      on 9.4.6: it happens for the `[default]` keys inherited by a stanza whose
      input scheme btool does not recognise - `[<scheme>://<name>]` where
      `<scheme>` is not a built-in input type gets `host = $decideOnStartup` and
      `index = default` with no path (causal probe: `[zzother://notdefault]`
      reproduces it, `[monitor:///tmp/x]` does not). No source file, therefore
      no origin to report: such a line is OUT of the scope of a tool that
      reports file origins, and is dropped here;
    - otherwise a **continuation** of the previous definition's value,
      concatenated with `\\n` (the source `\\` was consumed by btool, the line
      break belongs to the value - M-3d).

    `unattributed` is the set of `(key, value)` pairs of the conf's `[default]`
    definitions, read from OUR OWN parse of the source files - the "source
    information" rule of D-11/D-21 applied a third time. A path-less line is an
    unattributed definition when it reads as `<key> = <value>` and that pair is
    one of them. Measured on the whole lab corpus (3093 path-less lines over 11
    confs): the rule isolates the 24 unattributed lines with ZERO false positive
    on the 3069 genuine continuations, where the purely syntactic fallback
    ("contains ` = `, key without blank") misclassifies 3 of them.

    Before D-24 those lines were read as continuations, so their text was
    APPENDED to the previous definition's value: on the measured corpus the
    value of `disabled` carried `\\nhost = ...\\nindex = ...`. That was not only
    a false anomaly, it was a WRONG value in the default output - reserve R-8
    was real, not negligible (spec section 6.3 is amended accordingly).

    Residual ambiguity: a multi-line value whose continuation line would start
    with the resolved etc prefix followed by a `.conf` token is still
    misclassified as a record, and a continuation line that happened to read
    exactly as one of the conf's `[default]` pairs would be dropped. Both are
    detected by the confrontation of section 6.5 through `resolver_mismatch` -
    never a silent failure.
    """
    unattributed = frozenset(unattributed)
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
            separator = line.find(" = ")
            if separator != -1 and \
                    (line[:separator], line[separator + 3:]) in unattributed:
                # Unattributed definition (D-24): btool prints an inherited
                # `[default]` value it cannot attach to any file. No origin to
                # report, and - crucially - it must NOT be appended to the
                # previous value.
                continue
            if last is None:
                continue  # defensive: continuation without a previous record
            stanza, key = last
            record = stanzas[stanza][key]
            stanzas[stanza][key] = BtoolRecord(
                path=record.path, key=key, value=record.value + "\n" + line
            )

    return BtoolConf(stanzas=stanzas, headers=headers)


def inherited_parents(stanza):
    """The stanzas `stanza` can inherit from, nearest first (D-21, D-26).

    Two inheritance relations are measured on 9.4.6, and btool expands BOTH of
    them into the child stanza while printing the parent header inconsistently:

    - `<scheme>` -> `<scheme>://<instance>`: the bare stanza of a modular input
      scheme holds the defaults of every instance of that scheme. btool NEVER
      prints its header and expands its keys into each instance, with the path
      of the file declaring the bare stanza. Causal probe: `[zzscheme]` plus
      `[zzscheme://inst1]` yields the keys of `[zzscheme]` inside `inst1` and no
      `[zzscheme]` header; `[zzscheme://inst2]` redefining one of them shows the
      local value. A bare stanza with NO instance (`[zzlonely]`, and `[journald]`
      on the measured corpus) produces NO output line at all - btool designates
      no winner for it, which is a legitimate residual anomaly, not a false
      positive;
    - `default` -> every other stanza (D-21).

    The scheme parent comes first: it is the nearer one, and it is the one that
    wins in Splunk's own resolution.
    """
    parents = []
    marker = stanza.find("://")
    if marker > 0:
        parents.append(stanza[:marker])
    if stanza != "default":
        parents.append("default")
    return parents


def deexpand(btool, literal_defs):
    """De-expand the inheritance repetitions; return the btool verdicts.

    btool repeats every inherited key in every heir stanza of the conf, with the
    path of the file CARRYING the parent definition - the path alone does
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

    Rule, per conf (spec section 6.4, D-21 generalised by D-26):

    1. `D` = `(parent, path, key, value)` quadruples of our literal definitions
       - the `[default]` stanza (explicit header or implicit head-of-file
       stanza, both parsed as `default`, section 4.2) and every bare stanza of a
       modular input scheme (`inherited_parents`).
    2. A btool record in stanza S whose `(P, path, key, value)` belongs to `D`
       for one of S's parents P is an inheritance repetition, and is FOLDED BACK
       onto `(P, key)` - the literal origin it was expanded from (D-7) - UNLESS
       the file at that path carries an `(S, key)` definition of its own, in
       which case the btool line restitutes a REAL local redefinition and is
       kept as the verdict of `(S, key)` ("source information" rule: we read the
       files, btool only shows its view). D-11 stated that rule as an exception;
       D-21 makes it the foundation; D-26 shows it holds one level down too.
    3. The folding never overrides a record btool did print for the parent
       stanza itself: when btool does print the header, that record is
       authoritative. The fold only reconstructs the verdict btool withholds
       when it suppresses the header, from btool's own expanded lines.
    4. The remaining records form, per `(stanza, key)` group, the btool
       verdict - at most one per group.

    `literal_defs` is a set of `(stanza, key, path, value)` tuples built from
    our own parsed definitions (section 4), with the stanza and key names
    already translated into btool's namespace by `normalize` (D-23, D-25) - the
    comparison happens here, so both sides must be spelled the same way. The
    values are NOT normalised: they are compared byte for byte, which is what
    makes the confrontation meaningful.
    """
    # `(stanza, path, key, value)` of every definition we read: the candidate
    # parent origins of an expanded line (D-21/D-26, step 1).
    literal_quadruples = {
        (stanza, path, key, value)
        for stanza, key, path, value in literal_defs
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
            origin = None
            if (record.path, stanza, key) not in own_definitions:
                for parent in inherited_parents(stanza):
                    if (parent, record.path, key, record.value) in literal_quadruples:
                        origin = parent
                        break
            if origin is not None:
                # Inheritance repetition: its literal origin is the parent
                # definition of that very file.
                folded[(origin, key)] = BtoolWinner(
                    path=record.path, value=record.value
                )
                continue
            winners[(stanza, key)] = BtoolWinner(path=record.path, value=record.value)

    for group_key, winner in folded.items():
        winners.setdefault(group_key, winner)
    return winners
