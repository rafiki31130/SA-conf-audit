"""`.conf` parser contract (spec section 4, test list of section 12.1)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit.confparser import decode_conf_bytes, parse_conf_text


def _defs(text):
    return {
        (d.stanza, d.key): d.value for d in parse_conf_text(text)
    }


class ContinuationTest(unittest.TestCase):
    """Section 4.3 - the `\\` is dropped, the line break is KEPT."""

    def test_simple_continuation(self):
        defs = _defs("[s]\nkey = line_one \\\nline_two\n")
        self.assertEqual(defs[("s", "key")], "line_one \nline_two")

    def test_space_before_backslash_belongs_to_the_value(self):
        # M-3d verbatim: source `line_one \` -> segment `line_one ` with its
        # trailing space, then the newline, then the next line verbatim.
        defs = _defs("[s]\nkey = line_one \\\nline_two_continuation\n")
        self.assertEqual(defs[("s", "key")], "line_one \nline_two_continuation")

    def test_multiple_continuations(self):
        defs = _defs("[s]\nkey = a \\\nb \\\nc\n")
        self.assertEqual(defs[("s", "key")], "a \nb \nc")

    def test_continuation_absorbs_comment_and_header_lookalikes(self):
        # Section 4.1 rule 1: absorbed whatever the content.
        defs = _defs("[s]\nkey = a \\\n# not a comment \\\n[not a stanza]\n")
        self.assertEqual(defs[("s", "key")], "a \n# not a comment \n[not a stanza]")
        self.assertNotIn(("not a stanza", "key"), defs)

    def test_backslash_on_last_line_of_file_closes_the_value(self):
        # Measured (lab acceptance, R-1): `xx \` at EOF -> btool restitutes
        # `xx` - the `\` is consumed and the end of the value is stripped.
        defs = _defs("[s]\nkey = dangling \\")
        self.assertEqual(defs[("s", "key")], "dangling")

    def test_backslash_followed_by_blanks_is_not_a_continuation(self):
        # The LAST character is not `\` (section 4.3). Measured (lab
        # acceptance, R-1): `foo\ ` -> btool restitutes `foo\` - literal
        # backslash kept, trailing blank stripped, next line untouched.
        defs = _defs("[s]\nkey = not_continued\\ \nother = x\n")
        self.assertEqual(defs[("s", "key")], "not_continued\\")
        self.assertEqual(defs[("s", "other")], "x")

    def test_trailing_blanks_of_last_continuation_segment_are_stripped(self):
        # Measured (lab acceptance, R-1): `a \` then `b  ` -> `a \nb`.
        defs = _defs("[s]\nkey = a \\\nb  \nafter = ok\n")
        self.assertEqual(defs[("s", "key")], "a \nb")
        self.assertEqual(defs[("s", "after")], "ok")


class DefaultStanzaTest(unittest.TestCase):
    """Section 4.2 - keys before the first header belong to `default` (M-3a)."""

    def test_orphan_key_equals_explicit_default(self):
        orphan = _defs("orphan = v1\n")
        explicit = _defs("[default]\norphan = v1\n")
        self.assertEqual(orphan, explicit)
        self.assertEqual(orphan[("default", "orphan")], "v1")

    def test_orphan_and_explicit_default_merge(self):
        defs = _defs("k1 = head\n[default]\nk2 = explicit\n")
        self.assertEqual(defs[("default", "k1")], "head")
        self.assertEqual(defs[("default", "k2")], "explicit")


class DuplicatedStanzaTest(unittest.TestCase):
    """Section 4.4 - duplicated occurrences merge (M-3c); same key: the last
    occurrence read wins (R-2, arbitrated by D-14)."""

    def test_distinct_keys_merge(self):
        defs = _defs("[s]\na = 1\n[other]\nx = y\n[s]\nb = 2\n")
        self.assertEqual(defs[("s", "a")], "1")
        self.assertEqual(defs[("s", "b")], "2")

    def test_same_key_last_occurrence_wins(self):
        defs = _defs("[s]\nk = first\n[other]\nx = y\n[s]\nk = second\n")
        self.assertEqual(defs[("s", "k")], "second")

    def test_one_definition_per_stanza_key_pair(self):
        raw = parse_conf_text("[s]\nk = first\n[s]\nk = second\n")
        self.assertEqual(len(raw), 1)


class LineClassificationTest(unittest.TestCase):
    """Section 4.1 - comments, headers, key-less lines, residue."""

    def test_hash_comment_at_column_zero(self):
        self.assertEqual(_defs("# k = v\n"), {})

    def test_semicolon_comment_at_column_zero(self):
        self.assertEqual(_defs("; k = v\n"), {})

    def test_blank_preceded_hash_comment_is_ignored(self):
        # Measured against real btool 9.4.6 (lab acceptance, R-1): an
        # indented `  # k = v` yields no definition.
        self.assertEqual(_defs("[s]\n   # k = v\n"), {})

    def test_blank_preceded_semicolon_comment_is_ignored(self):
        self.assertEqual(_defs("[s]\n\t; k = v\n"), {})

    def test_line_starting_with_equals_is_ignored(self):
        self.assertEqual(_defs("[s]\n=value\n"), {})

    def test_text_after_last_bracket_is_ignored(self):
        defs = _defs("[s] trailing junk\nk = v\n")
        self.assertEqual(defs[("s", "k")], "v")

    def test_header_without_closing_bracket_takes_rest_of_line(self):
        defs = _defs("[unterminated\nk = v\n")
        self.assertEqual(defs[("unterminated", "k")], "v")

    def test_residue_line_without_equals_is_ignored(self):
        defs = _defs("[s]\nloose words\nk = v\n")
        self.assertEqual(defs, {("s", "k"): "v"})


class ValueEdgeTest(unittest.TestCase):
    """Section 4.5 - empty values, trailing spaces, tabulations."""

    def test_empty_value(self):
        defs = _defs("[s]\nk =\n")
        self.assertEqual(defs[("s", "k")], "")

    def test_trailing_spaces_are_stripped(self):
        # Measured (lab acceptance, R-1): btool strips the trailing blanks
        # of a value - `include.results_link = 1 ` restituted as `1`.
        defs = _defs("[s]\nk = value_with_trailing   \n")
        self.assertEqual(defs[("s", "k")], "value_with_trailing")

    def test_trailing_tab_is_stripped(self):
        defs = _defs("[s]\nk = tabval\t\n")
        self.assertEqual(defs[("s", "k")], "tabval")

    def test_blanks_only_value_is_empty(self):
        defs = _defs("[s]\nk =  \n")
        self.assertEqual(defs[("s", "k")], "")

    def test_tabs_are_blanks_in_key_and_leading_value_strips(self):
        defs = _defs("[s]\n\tk\t=\tv\n")
        self.assertEqual(defs[("s", "k")], "v")

    def test_key_split_on_first_equals_only(self):
        defs = _defs("[s]\nk = a=b=c\n")
        self.assertEqual(defs[("s", "k")], "a=b=c")

    def test_crlf_terminators(self):
        defs = _defs("[s]\r\nk = v\r\n")
        self.assertEqual(defs[("s", "k")], "v")


class DecodingTest(unittest.TestCase):
    """Section 4.6 - BOM, degraded decoding, empty file."""

    def test_empty_file(self):
        text, degraded = decode_conf_bytes(b"")
        self.assertFalse(degraded)
        self.assertEqual(parse_conf_text(text), [])

    def test_utf8_bom_is_removed(self):
        text, degraded = decode_conf_bytes(b"\xef\xbb\xbf[s]\nk = v\n")
        self.assertFalse(degraded)
        self.assertEqual(_defs(text)[("s", "k")], "v")

    def test_degraded_decoding_raises_the_indicator_and_keeps_definitions(self):
        # Invalid UTF-8 byte: the indicator is raised AND the replacement
        # definitions are extracted (U+FFFD allowed) - the resolution is never
        # amputated (section 4.6).
        text, degraded = decode_conf_bytes(b"[s]\nk = bad\xff\nother = ok\n")
        self.assertTrue(degraded)
        defs = _defs(text)
        self.assertEqual(defs[("s", "other")], "ok")
        self.assertEqual(defs[("s", "k")], "bad�")


if __name__ == "__main__":
    unittest.main()
