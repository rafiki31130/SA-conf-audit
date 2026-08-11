"""btool output parser and `[default]` de-expansion (spec sections 6.3-6.4,
format measured in M-3)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit.btoolparser import deexpand, parse_btool_output
from tests.helpers import ETC, build_btool_output

SYS_DEFAULT = ETC + "/system/default/probe.conf"
APP_LOCAL = ETC + "/apps/zz_sample_app/local/probe.conf"


class ParserTest(unittest.TestCase):

    def test_variable_column_width_between_two_outputs(self):
        # The path column width follows the longest path of THE output: the
        # same records must parse identically under two different paddings
        # (M-3e - never assume a fixed width).
        narrow = build_btool_output([(SYS_DEFAULT, "[s]"), (SYS_DEFAULT, "k = v")])
        wide = build_btool_output([
            (SYS_DEFAULT, "[s]"),
            (SYS_DEFAULT, "k = v"),
            (ETC + "/apps/an_app_with_a_much_longer_name/local/probe.conf",
             "[zz_other]"),
        ])
        parsed_narrow = parse_btool_output(narrow, ETC)
        parsed_wide = parse_btool_output(wide, ETC)
        self.assertEqual(
            parsed_narrow.stanzas["s"]["k"], parsed_wide.stanzas["s"]["k"]
        )

    def test_strict_space_equals_space_separator(self):
        # `no_sep=x` inside the value column is NOT a separator; the key ends
        # at the first ` = ` occurrence.
        output = build_btool_output([
            (SYS_DEFAULT, "[s]"),
            (SYS_DEFAULT, "k = a=b = c"),
        ])
        record = parse_btool_output(output, ETC).stanzas["s"]["k"]
        self.assertEqual(record.value, "a=b = c")

    def test_empty_value_with_trailing_separator_space(self):
        # M-3e: `hostname = ` ends with the separator's space, value empty.
        output = build_btool_output([
            (SYS_DEFAULT, "[s]"),
            (SYS_DEFAULT, "hostname = "),
        ])
        record = parse_btool_output(output, ETC).stanzas["s"]["hostname"]
        self.assertEqual(record.value, "")

    def test_trailing_spaces_of_the_value_are_kept(self):
        output = build_btool_output([
            (SYS_DEFAULT, "[s]"),
            (SYS_DEFAULT, "k = value_with_trailing   "),
        ])
        record = parse_btool_output(output, ETC).stanzas["s"]["k"]
        self.assertEqual(record.value, "value_with_trailing   ")

    def test_continuation_line_without_prefix_concatenates_with_newline(self):
        # M-3d: the source `\` was consumed by btool, the line break belongs
        # to the value, the continuation carries no path prefix.
        output = build_btool_output([
            (APP_LOCAL, "[s]"),
            (APP_LOCAL, "zz_multiline_key = line_one \nline_two_continuation"),
        ])
        record = parse_btool_output(output, ETC).stanzas["s"]["zz_multiline_key"]
        self.assertEqual(record.value, "line_one \nline_two_continuation")

    def test_stanza_headers_are_metadata_not_definitions(self):
        output = build_btool_output([
            (APP_LOCAL, "[zz_probe]"),
            (SYS_DEFAULT, "k = v"),
        ])
        parsed = parse_btool_output(output, ETC)
        self.assertEqual(parsed.headers["zz_probe"], APP_LOCAL)
        self.assertEqual(list(parsed.stanzas["zz_probe"]), ["k"])

    def test_final_newline_is_not_an_empty_continuation(self):
        output = build_btool_output([
            (SYS_DEFAULT, "[s]"),
            (SYS_DEFAULT, "k = v"),
        ])
        self.assertTrue(output.endswith("\n"))
        record = parse_btool_output(output, ETC).stanzas["s"]["k"]
        self.assertEqual(record.value, "v")


class DeexpansionTest(unittest.TestCase):
    """Section 6.4 - inheritance repetitions carry the path of the `[default]`
    CARRIER file, so the path alone distinguishes nothing (M-3b)."""

    @staticmethod
    def _fifteen_stanza_output():
        # Mirrors the M-3b measurement: one [default] key repeated in every
        # stanza of the conf, 15 stanzas total, always with the carrier path.
        entries = [(APP_LOCAL, "[default]"),
                   (APP_LOCAL, "zz_default_key = default_val")]
        for index in range(14):
            entries.append((SYS_DEFAULT, "[stanza_%02d]" % index))
            entries.append((APP_LOCAL, "zz_default_key = default_val"))
            entries.append((SYS_DEFAULT, "own_key_%02d = own_val" % index))
        return build_btool_output(entries)

    def test_inheritance_repetitions_discarded_15_of_15(self):
        parsed = parse_btool_output(self._fifteen_stanza_output(), ETC)
        literal = {("default", "zz_default_key", APP_LOCAL, "default_val")}
        winners = deexpand(parsed, literal)
        carriers = [key for key in winners if key[1] == "zz_default_key"]
        # The [default] origin survives; the 14 repetitions are gone.
        self.assertEqual(carriers, [("default", "zz_default_key")])
        self.assertEqual(len([k for k in winners if k[1].startswith("own_key")]), 14)

    def test_local_definition_with_distinct_value_is_kept(self):
        output = build_btool_output([
            (APP_LOCAL, "[default]"),
            (APP_LOCAL, "zz_default_key = default_val"),
            (APP_LOCAL, "[zz_probe_s1]"),
            (APP_LOCAL, "zz_default_key = s1_override"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {
            ("default", "zz_default_key", APP_LOCAL, "default_val"),
            ("zz_probe_s1", "zz_default_key", APP_LOCAL, "s1_override"),
        }
        winners = deexpand(parsed, literal)
        self.assertEqual(winners[("zz_probe_s1", "zz_default_key")].value,
                         "s1_override")

    def test_identical_local_redefinition_kept_by_source_information_rule(self):
        # R-4 / D-11: a stanza redefining a [default] key with the SAME value
        # in the SAME file is indistinguishable from inheritance in the btool
        # output alone; the source files decide - we carry a literal (S, key)
        # definition, so the btool line restitutes a real redefinition.
        output = build_btool_output([
            (APP_LOCAL, "[default]"),
            (APP_LOCAL, "case7_key = same_val"),
            (APP_LOCAL, "[ref_s3]"),
            (APP_LOCAL, "case7_key = same_val"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {
            ("default", "case7_key", APP_LOCAL, "same_val"),
            ("ref_s3", "case7_key", APP_LOCAL, "same_val"),
        }
        winners = deexpand(parsed, literal)
        self.assertIn(("ref_s3", "case7_key"), winners)
        self.assertEqual(winners[("ref_s3", "case7_key")].path, APP_LOCAL)

    def test_identical_repetition_without_literal_definition_is_discarded(self):
        # Same output as above, but the source files carry NO (ref_s3,
        # case7_key) definition: pure inheritance repetition, discarded.
        output = build_btool_output([
            (APP_LOCAL, "[default]"),
            (APP_LOCAL, "case7_key = same_val"),
            (APP_LOCAL, "[ref_s3]"),
            (APP_LOCAL, "case7_key = same_val"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {("default", "case7_key", APP_LOCAL, "same_val")}
        winners = deexpand(parsed, literal)
        self.assertNotIn(("ref_s3", "case7_key"), winners)


if __name__ == "__main__":
    unittest.main()
