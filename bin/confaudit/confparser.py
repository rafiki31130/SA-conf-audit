"""`.conf` source file parser (spec section 4).

Pure, sequential. Input: decoded text. Output: the list of *effective*
definitions of the file - intra-file duplicates already merged, last occurrence
winning (section 4.4, reserve R-2 arbitrated by D-14).

The micro-tolerances frozen by reserve R-1 were settled empirically against
the real btool (9.4.6) during the lab acceptance run: a line whose first
NON-BLANK character is `#` or `;` is a comment (not only column 0); the
trailing blanks of a value are stripped at the END of the logical value
(intermediate segments of a multi-line value keep theirs); a `\\` followed by
blanks is not a continuation and the `\\` is kept as a literal character;
text after the last `]` of a header is ignored.
"""

from .model import RawDef

#: Characters treated as blanks by every strip of this module (section 4.5).
_BLANKS = " \t"


def decode_conf_bytes(data):
    """Decode a conf file, `utf-8-sig` strict first (section 4.6).

    Returns `(text, degraded)`. On `UnicodeDecodeError`, the bytes are re-decoded
    with `errors="replace"` and the degradation indicator is raised: the caller
    emits one `parse_error` row for the file AND keeps the replacement
    definitions - the resolution is never amputated (btool parses the file its
    own way; a `resolver_mismatch` on such a file is a legitimate signal, not a
    bug - reserve R-5).
    """
    try:
        return data.decode("utf-8-sig"), False
    except UnicodeDecodeError:
        return data.decode("utf-8-sig", errors="replace"), True


def parse_conf_text(text):
    """Parse decoded conf text into a list of `RawDef` (section 4).

    Line classification, in this exact order (section 4.1): continuation,
    comment (column 0 only), blank, stanza header, definition, residue.
    Definitions found before the first header belong to the `default` stanza
    (section 4.2), strictly equivalent to an explicit `[default]` - both merge
    as duplicated occurrences (M-3a).
    """
    # stanza name -> {key: (value, lineno)}; insertion order preserved on both
    # levels, so the output lists definitions in first-seen order with the
    # last-read value (section 4.4).
    stanzas = {}
    current = "default"
    # Open continuation: (stanza, key, value_so_far, lineno). Set only by a
    # definition line (or a continuation line) whose LAST character is `\`
    # (section 4.3) - a comment or header ending with `\` opens nothing.
    pending = None

    lines = text.split("\n")
    if lines and lines[-1] == "":
        # Artifact of the final newline, not a physical line.
        lines.pop()

    for lineno, raw in enumerate(lines, 1):
        # Physical line terminator: `\n` or `\r\n`, the final `\r` is removed.
        line = raw[:-1] if raw.endswith("\r") else raw

        # 1. Continuation: absorbed verbatim, whatever its content - even if it
        # looks like a comment or a stanza header (section 4.3). The source `\`
        # is dropped, the line break is KEPT: btool restitutes the value that
        # way (M-3d), and matching it byte for byte is the condition of the
        # confrontation of section 6.5.
        if pending is not None:
            stanza, key, value, def_lineno = pending
            if line.endswith("\\"):
                pending = (stanza, key, value + "\n" + line[:-1], def_lineno)
            else:
                _store(stanzas, stanza, key, value + "\n" + line, def_lineno)
                pending = None
            continue

        # 2. Comment: first NON-BLANK character `#` or `;`. Measured against
        # the real btool 9.4.6 (lab acceptance, R-1): an indented
        # `  # k = v` or `  ; k = v` yields no definition.
        if line.lstrip(_BLANKS)[:1] in ("#", ";"):
            continue

        # 3. Blank line.
        if line.strip(_BLANKS) == "":
            continue

        # 4. Stanza header: first non-blank character is `[`. Name = content
        # between the first `[` and the LAST `]` of the line; text after the
        # last `]` is ignored; a `[` without `]` takes the rest of the line.
        if line.lstrip(_BLANKS)[:1] == "[":
            start = line.find("[")
            end = line.rfind("]")
            current = line[start + 1:end] if end > start else line[start + 1:]
            # Reopens an existing stanza as is (section 4.4).
            stanzas.setdefault(current, {})
            continue

        # 5. Definition: the line contains a `=`.
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip(_BLANKS)
            if key == "":
                # A line starting with `=` carries no key: ignored.
                continue
            # Leading blanks are stripped here; the trailing blanks of the
            # LOGICAL value are stripped by `_store` - btool strips them at
            # the end of the value (measured on 9.4.6, lab acceptance, R-1:
            # `include.results_link = 1 ` in system/default is restituted
            # as `1`), and keeping what btool strips would create false
            # `resolver_mismatch`.
            value = value.lstrip(_BLANKS)
            if value.endswith("\\"):
                # Continuation opens: the `\` must be the LAST character - a
                # `\` followed by blanks is not a continuation (section 4.3).
                pending = (current, key, value[:-1], lineno)
            else:
                _store(stanzas, current, key, value, lineno)
            continue

        # 6. Residue: non-empty line without `=`, silently ignored (observed
        # btool behavior: orphan lines without `=` yield no definition).

    if pending is not None:
        # `\` on the last line of the file: the value closes as is - the `\`
        # was removed, nothing is appended (section 4.3).
        stanza, key, value, def_lineno = pending
        _store(stanzas, stanza, key, value, def_lineno)

    out = []
    for stanza, keys in stanzas.items():
        for key, (value, lineno) in keys.items():
            out.append(RawDef(stanza=stanza, key=key, value=value, lineno=lineno))
    return out


def _store(stanzas, stanza, key, value, lineno):
    """Record one definition; the last occurrence read wins (section 4.4, R-2).

    The end of the logical value is stripped of its trailing blanks - btool
    behavior measured on 9.4.6 (lab acceptance, R-1), uniform across mono-line
    values, the last segment of a multi-line value, and a value closed by a
    `\\` at end of file. `rstrip(" \\t")` stops at the first `\\n`, so the
    intermediate segments of a multi-line value keep their spaces (M-3d).
    """
    keys = stanzas.setdefault(stanza, {})
    keys[key] = (value.rstrip(_BLANKS), lineno)
