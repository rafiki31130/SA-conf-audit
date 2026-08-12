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


class UnattributedLineTest(unittest.TestCase):
    """D-24 - reserve R-8 materialised: btool emits `<key> = <value>` at column
    0, with no path at all, for a `[default]` key inherited by a stanza whose
    input scheme it does not recognise. Measured on 9.4.6 over the 12
    modular-input stanzas of `inputs`; causal probe: `[zzother://notdefault]`
    reproduces it, `[monitor:///tmp/x]` does not."""

    #: `(key, value)` of the conf's `[default]` definitions, our own reading.
    DEFAULTS = frozenset((("host", "$decideOnStartup"), ("index", "default")))

    @staticmethod
    def _measured_shape():
        # Byte-identical to the measured output: the two path-less lines follow
        # `disabled = 0` with no prefix and no padding.
        return build_btool_output([
            (APP_LOCAL, "[zz_scheme://default]"),
            (APP_LOCAL, "disabled = 0\nhost = $decideOnStartup\nindex = default"),
            (SYS_DEFAULT, "interval = 30"),
        ])

    def test_before_the_rule_the_previous_value_is_corrupted(self):
        # Without the source information, the two lines are read as
        # continuations and CONCATENATED to the previous value: the emitted
        # `disabled` carried `\nhost = ...\nindex = ...`. This is what the
        # decision calls a wrong value, not merely a false anomaly.
        parsed = parse_btool_output(self._measured_shape(), ETC)
        self.assertEqual(
            parsed.stanzas["zz_scheme://default"]["disabled"].value,
            "0\nhost = $decideOnStartup\nindex = default",
        )

    def test_unattributed_lines_leave_the_previous_value_intact(self):
        parsed = parse_btool_output(self._measured_shape(), ETC, self.DEFAULTS)
        self.assertEqual(
            parsed.stanzas["zz_scheme://default"]["disabled"].value, "0")

    def test_unattributed_lines_are_out_of_the_confrontation_set(self):
        # No source file, therefore no origin to report: they must not become
        # records of the stanza either.
        parsed = parse_btool_output(self._measured_shape(), ETC, self.DEFAULTS)
        self.assertEqual(
            sorted(parsed.stanzas["zz_scheme://default"]), ["disabled", "interval"])

    def test_a_genuine_continuation_reading_as_a_pair_is_still_a_continuation(self):
        # The rule is semantic, not syntactic: a continuation line containing
        # ` = ` whose pair is NOT one of the conf's `[default]` definitions is
        # absorbed into the value, as before. The purely syntactic fallback
        # ("contains ` = `") misclassified 3 of the 3069 genuine continuation
        # lines of the measured corpus; this rule misclassified none.
        output = build_btool_output([
            (APP_LOCAL, "[s]"),
            (APP_LOCAL, "search = index=main \nstats count by host = whatever"),
        ])
        parsed = parse_btool_output(output, ETC, self.DEFAULTS)
        self.assertEqual(
            parsed.stanzas["s"]["search"].value,
            "index=main \nstats count by host = whatever",
        )

    def test_a_continuation_equal_to_a_default_pair_is_dropped_and_shouts(self):
        # Honest statement of the residual ambiguity: a continuation line that
        # reads EXACTLY as one of the conf's `[default]` pairs is dropped. The
        # value is then truncated - which the confrontation of section 6.5
        # surfaces as `resolver_mismatch`, never silently.
        output = build_btool_output([
            (APP_LOCAL, "[s]"),
            (APP_LOCAL, "k = first\nindex = default"),
        ])
        parsed = parse_btool_output(output, ETC, self.DEFAULTS)
        self.assertEqual(parsed.stanzas["s"]["k"].value, "first")


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

    def test_reference_set_comes_from_the_source_files_not_the_btool_stanza(self):
        # D-21, the `inputs` case measured on 9.4.6: btool EXPANDS the
        # [default] keys into every stanza but does NOT print the [default]
        # stanza header. Reading the reference set from the output would leave
        # it empty and turn every inherited key of every stanza into an
        # anomaly (803 `resolver_mismatch` on the real conf). Reading it from
        # our own parsed definitions makes the de-expansion immune to the
        # missing header.
        output = build_btool_output([
            (SYS_DEFAULT, "[stanza_a]"),
            (SYS_DEFAULT, "index = default"),
            (SYS_DEFAULT, "own_a = a_val"),
            (SYS_DEFAULT, "[stanza_b]"),
            (SYS_DEFAULT, "index = default"),
            (SYS_DEFAULT, "own_b = b_val"),
        ])
        parsed = parse_btool_output(output, ETC)
        self.assertNotIn("default", parsed.stanzas)  # the header is absent
        literal = {
            ("default", "index", SYS_DEFAULT, "default"),
            ("stanza_a", "own_a", SYS_DEFAULT, "a_val"),
            ("stanza_b", "own_b", SYS_DEFAULT, "b_val"),
        }
        winners = deexpand(parsed, literal)
        # No repetition survives as a stanza verdict...
        self.assertNotIn(("stanza_a", "index"), winners)
        self.assertNotIn(("stanza_b", "index"), winners)
        # ...and the verdict is folded back onto its literal origin (D-7), so
        # the `[default]` group keeps a btool verdict despite the missing
        # header - otherwise the fix would merely move the anomalies.
        self.assertEqual(winners[("default", "index")].value, "default")
        self.assertEqual(winners[("default", "index")].path, SYS_DEFAULT)
        self.assertEqual(winners[("stanza_a", "own_a")].value, "a_val")
        self.assertEqual(winners[("stanza_b", "own_b")].value, "b_val")

    def test_printed_default_header_stays_authoritative(self):
        # The `authorize` case: btool DOES print the header. That record is the
        # verdict of the `[default]` group; the fold must never override it.
        output = build_btool_output([
            (APP_LOCAL, "[default]"),
            (APP_LOCAL, "srchJobsQuota = 3"),
            (SYS_DEFAULT, "[role_probe]"),
            (APP_LOCAL, "srchJobsQuota = 3"),
        ])
        parsed = parse_btool_output(output, ETC)
        self.assertIn("default", parsed.stanzas)
        literal = {("default", "srchJobsQuota", APP_LOCAL, "3")}
        winners = deexpand(parsed, literal)
        self.assertNotIn(("role_probe", "srchJobsQuota"), winners)
        self.assertEqual(winners[("default", "srchJobsQuota")].path, APP_LOCAL)
        self.assertEqual(winners[("default", "srchJobsQuota")].value, "3")

    def test_a_real_divergence_is_never_swallowed_by_the_fold(self):
        # The fix removes false positives, it must not remove the signal: a
        # btool line whose value differs from the `[default]` triplet is not a
        # repetition, it stays the verdict of its own stanza - which is what
        # lets the confrontation raise `resolver_mismatch`.
        output = build_btool_output([
            (SYS_DEFAULT, "[stanza_a]"),
            (SYS_DEFAULT, "index = default"),
            (SYS_DEFAULT, "[stanza_b]"),
            (APP_LOCAL, "index = overridden"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {("default", "index", SYS_DEFAULT, "default")}
        winners = deexpand(parsed, literal)
        self.assertNotIn(("stanza_a", "index"), winners)
        self.assertEqual(winners[("stanza_b", "index")].path, APP_LOCAL)
        self.assertEqual(winners[("stanza_b", "index")].value, "overridden")

    def test_scheme_stanza_expansion_is_folded_back_onto_the_bare_stanza(self):
        # D-26: `[<scheme>]` holds the defaults of every `[<scheme>://<name>]`.
        # btool NEVER prints its header and expands its keys into each instance
        # with the path of the file declaring the bare stanza - the very shape
        # of the `[default]` case, one level down. Causal probe on 9.4.6:
        # `[zzscheme]` + `[zzscheme://inst1]`.
        output = build_btool_output([
            (APP_LOCAL, "[zz_scheme://inst1]"),
            (APP_LOCAL, "disabled = 0"),
            (APP_LOCAL, "interval = 77"),
        ])
        parsed = parse_btool_output(output, ETC)
        self.assertNotIn("zz_scheme", parsed.stanzas)  # the header is absent
        literal = {
            ("zz_scheme", "interval", APP_LOCAL, "77"),
            ("zz_scheme://inst1", "disabled", APP_LOCAL, "0"),
        }
        winners = deexpand(parsed, literal)
        self.assertNotIn(("zz_scheme://inst1", "interval"), winners)
        self.assertEqual(winners[("zz_scheme", "interval")].value, "77")
        self.assertEqual(winners[("zz_scheme://inst1", "disabled")].value, "0")

    def test_instance_redefining_a_scheme_default_keeps_its_own_verdict(self):
        # `[zzscheme://inst2] zzkey = local_override` measured on the probe: the
        # source information rule of D-11 applies to the scheme parent too.
        output = build_btool_output([
            (APP_LOCAL, "[zz_scheme://inst2]"),
            (APP_LOCAL, "zzkey = local_override"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {
            ("zz_scheme", "zzkey", APP_LOCAL, "zzval"),
            ("zz_scheme://inst2", "zzkey", APP_LOCAL, "local_override"),
        }
        winners = deexpand(parsed, literal)
        self.assertEqual(
            winners[("zz_scheme://inst2", "zzkey")].value, "local_override")

    def test_nearest_parent_wins_when_both_could_explain_the_line(self):
        # `[default]` and `[zz_scheme]` carrying the same key, same value, same
        # file: the scheme parent is the nearer one and is the one Splunk
        # resolves from.
        output = build_btool_output([
            (APP_LOCAL, "[zz_scheme://inst1]"),
            (APP_LOCAL, "k = v"),
        ])
        parsed = parse_btool_output(output, ETC)
        literal = {
            ("default", "k", APP_LOCAL, "v"),
            ("zz_scheme", "k", APP_LOCAL, "v"),
        }
        winners = deexpand(parsed, literal)
        self.assertIn(("zz_scheme", "k"), winners)
        self.assertNotIn(("default", "k"), winners)

    def test_bare_scheme_stanza_without_instance_keeps_no_verdict(self):
        # The measured `journald` case: btool prints NOTHING for a bare scheme
        # stanza that has no instance, so no verdict can be reconstructed. The
        # anomaly that follows is legitimate and documented (D-26) - the tool
        # must not invent a verdict to silence it.
        output = build_btool_output([(SYS_DEFAULT, "[splunktcp]"),
                                     (SYS_DEFAULT, "route = has_key:_utf8")])
        parsed = parse_btool_output(output, ETC)
        literal = {("journald", "interval", APP_LOCAL, "30")}
        winners = deexpand(parsed, literal)
        self.assertNotIn(("journald", "interval"), winners)

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
