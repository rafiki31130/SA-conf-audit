"""Reference conf set (spec section 12.2, CDC v1.2 criterion 1).

Eight cases, synthetic anonymized fixtures under `tests/fixtures/`, exercised
against a SIMULATED btool output conforming byte for byte to the M-3 format
(variable column width, continuations without path prefix, strict ` = `
separator). The lab acceptance run (phase 3) replays the same conf set against
the real btool.

1. `system/local` vs app conflict;
2. inter-app conflict on ASCII order, numeric prefixes included;
3. `local` vs `default` conflict inside one app;
4. implicit `[default]` stanza (key before any header);
5. duplicated stanza in one file (distinct keys AND same key redefined, R-2);
6. multi-line value (continuation, space before `\\`);
7. (R-4/D-11) local redefinition of a `[default]` key, same value and file;
8. (R-1) micro-syntax: `;` comment, blank-preceded comment, text after `]`,
   trailing value spaces, `\\` followed by a blank. The R-1 verdicts were
   settled against the real btool 9.4.6 (lab acceptance, 2026-08-12):
   blank-preceded comments are ignored, trailing value blanks are stripped
   at the end of the logical value, `\\` + blank is not a continuation and
   the `\\` is kept literally.
"""

import os
import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import pipeline
from confaudit.btoolparser import parse_btool_output
from tests import FIXTURES_DIR
from tests.helpers import CollectingLog, FakeBtool, FakeFs, FakeRest

ETC = "/opt/splunk/etc"

SYS_L = ETC + "/system/local/refconf.conf"
SYS_D = ETC + "/system/default/refconf.conf"
A00_L = ETC + "/apps/00_corp_base/local/refconf.conf"
A00_D = ETC + "/apps/00_corp_base/default/refconf.conf"
ZZ_L = ETC + "/apps/zz_sample_app/local/refconf.conf"
ZZ_D = ETC + "/apps/zz_sample_app/default/refconf.conf"

#: Expected criterion-1 projection: (file_path, stanza, key, value) of every
#: `is_btool_winner=true` row - hand-established from the fixture sources.
EXPECTED_WINNERS = {
    (A00_D, "default", "case4_orphan", "orphan_val"),
    (ZZ_L, "default", "case7_key", "same_val"),
    (ZZ_D, "ref_dup", "case5_a", "a1"),
    (ZZ_D, "ref_dup", "case5_b", "b2"),
    (ZZ_D, "ref_dup", "case5_same", "second"),
    (SYS_L, "ref_s1", "case1_key", "sys_local_wins"),
    (A00_L, "ref_s1", "case2_key", "from_00"),
    (ZZ_L, "ref_s2", "case3_key", "zz_local"),
    (A00_L, "ref_s2", "case6_multi", "line_one \nline_two_continuation"),
    (ZZ_L, "ref_s3", "case7_key", "same_val"),
    (SYS_D, "ref_s4", "case8_bs", "val_bs\\"),
    (SYS_D, "ref_s4", "case8_trail", "value_with_trailing"),
}


def _fixture_bytes(*relative):
    with open(os.path.join(FIXTURES_DIR, *relative), "rb") as handle:
        return handle.read()


def _build_ports():
    fs = FakeFs()
    fs.add("system", "", "local", "refconf",
           _fixture_bytes("etc", "system", "local", "refconf.conf"))
    fs.add("system", "", "default", "refconf",
           _fixture_bytes("etc", "system", "default", "refconf.conf"))
    for app in ("00_corp_base", "zz_sample_app"):
        for layer in ("local", "default"):
            fs.add("app", app, layer, "refconf",
                   _fixture_bytes("etc", "apps", app, layer, "refconf.conf"))
    output = _fixture_bytes("btool", "refconf.out").decode("utf-8")
    return fs, FakeBtool({"refconf": output}), output


def _run(audit, debug=False):
    fs, btool, _ = _build_ports()
    return pipeline.run(
        fs=fs, btool=btool, rest=FakeRest(), fieldnames=["refconf"],
        audit=audit, debug=debug, member="member-01", etc_prefix=ETC,
        log=CollectingLog(),
    )


class SimulatedOutputConformanceTest(unittest.TestCase):
    """The simulated output respects the M-3 byte-level format."""

    def test_padding_is_longest_path_plus_one_space(self):
        _, _, output = _build_ports()
        prefixed = [
            line for line in output.splitlines()
            if line.startswith(ETC)
        ]
        longest = max(len(line.split(" ", 1)[0]) for line in prefixed)
        for line in prefixed:
            path = line.split(" ", 1)[0]
            # The rest starts exactly at column longest+1.
            self.assertEqual(line[longest:longest + 1], " ")
            self.assertEqual(line[len(path):longest].strip(), "")

    def test_exactly_one_continuation_line_without_prefix(self):
        _, _, output = _build_ports()
        bare = [
            line for line in output.splitlines()
            if not line.startswith(ETC)
        ]
        self.assertEqual(bare, ["line_two_continuation"])

    def test_separator_is_space_equals_space(self):
        parsed = parse_btool_output(_build_ports()[2], ETC)
        record = parsed.stanzas["ref_s4"]["case8_trail"]
        self.assertEqual(record.value, "value_with_trailing")


class ReferenceSetTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rows = _run(audit=True)
        cls.by_group = {}
        for row in cls.rows:
            cls.by_group.setdefault((row["stanza"], row["key"]), []).append(row)

    def test_no_anomaly_on_the_whole_set(self):
        self.assertEqual(
            [row for row in self.rows if row["anomaly"]], []
        )

    def test_total_row_count(self):
        self.assertEqual(len(self.rows), 16)

    def test_case1_system_local_beats_app(self):
        rows = self.by_group[("ref_s1", "case1_key")]
        self.assertEqual(
            [(r["precedence_rank"], r["file_path"], r["value"],
              r["is_btool_winner"]) for r in rows],
            [(1, SYS_L, "sys_local_wins", "true"),
             (2, A00_L, "app_shadowed", "false"),
             (3, SYS_D, "sys_default_shadowed", "false")],
        )
        self.assertTrue(all(r["definition_count"] == 3 for r in rows))

    def test_case2_inter_app_ascii_ascending_00_beats_zz(self):
        rows = self.by_group[("ref_s1", "case2_key")]
        self.assertEqual(
            [(r["precedence_rank"], r["app"], r["is_btool_winner"])
             for r in rows],
            [(1, "00_corp_base", "true"), (2, "zz_sample_app", "false")],
        )

    def test_case3_local_beats_default_inside_one_app(self):
        rows = self.by_group[("ref_s2", "case3_key")]
        self.assertEqual(
            [(r["layer"], r["value"], r["is_btool_winner"]) for r in rows],
            [("local", "zz_local", "true"), ("default", "zz_default", "false")],
        )

    def test_case4_implicit_default_stanza(self):
        rows = self.by_group[("default", "case4_orphan")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_path"], A00_D)
        self.assertEqual(rows[0]["stanza"], "default")
        self.assertEqual(rows[0]["is_btool_winner"], "true")

    def test_case5_duplicated_stanza_merged_last_occurrence_wins(self):
        self.assertEqual(
            self.by_group[("ref_dup", "case5_a")][0]["value"], "a1")
        self.assertEqual(
            self.by_group[("ref_dup", "case5_b")][0]["value"], "b2")
        same = self.by_group[("ref_dup", "case5_same")]
        self.assertEqual(len(same), 1)          # merged, one definition
        self.assertEqual(same[0]["value"], "second")  # last occurrence

    def test_case6_multiline_value(self):
        rows = self.by_group[("ref_s2", "case6_multi")]
        self.assertEqual(rows[0]["value"], "line_one \nline_two_continuation")
        self.assertEqual(rows[0]["is_btool_winner"], "true")

    def test_case7_identical_local_redefinition_kept_without_mismatch(self):
        # R-4/D-11: same value, same file as the [default] carrier - the
        # source information rule keeps the btool verdict, no false mismatch.
        rows = self.by_group[("ref_s3", "case7_key")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["is_btool_winner"], "true")
        self.assertEqual(rows[0]["file_path"], ZZ_L)
        # And the [default] origin is emitted once, at its literal origin.
        default_rows = self.by_group[("default", "case7_key")]
        self.assertEqual(len(default_rows), 1)

    def test_case8_micro_syntax(self):
        # R-1 verdicts, measured against real btool 9.4.6 (lab acceptance):
        # `;` comment ignored; text after `]` ignored (stanza is ref_s4);
        # trailing value blanks stripped; blank-preceded comment ignored;
        # `\` + blank is not a continuation, the `\` is kept literally.
        trail = self.by_group[("ref_s4", "case8_trail")]
        self.assertEqual(trail[0]["value"], "value_with_trailing")
        bs = self.by_group[("ref_s4", "case8_bs")]
        self.assertEqual(bs[0]["value"], "val_bs\\")
        self.assertNotIn(("ref_s4", "# indented"), self.by_group)
        self.assertNotIn(("; semicolon comment at column zero", ""),
                         self.by_group)

    def test_criterion1_projection_matches_the_normalized_btool_output(self):
        winners = {
            (row["file_path"], row["stanza"], row["key"], row["value"])
            for row in self.rows if row["is_btool_winner"] == "true"
        }
        self.assertEqual(winners, EXPECTED_WINNERS)

    def test_default_run_emits_winners_only(self):
        # `debug=true` because the criterion-1 projection is the quadruplet
        # (file_path, stanza, key, value): in `audit=false` the path is only
        # emitted when it is asked for (D-17). The winner SET is what is under
        # test here, and it does not depend on `debug`.
        rows = _run(audit=False, debug=True)
        self.assertEqual(
            {(r["file_path"], r["stanza"], r["key"], r["value"]) for r in rows},
            EXPECTED_WINNERS,
        )
        self.assertEqual(len(rows), len(EXPECTED_WINNERS))


if __name__ == "__main__":
    unittest.main()
