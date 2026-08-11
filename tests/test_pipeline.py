"""End-to-end pipeline over the in-memory ports (spec sections 1.2, 3.2, 10).

Covers: capability gate (exact message), btool failure (exact message, D-13),
row shape and emission order, `debug=false`, `parse_error` never filtered,
rank/count insensitive to filters, secrets end-to-end (`value` AND
`btool_winner_value` hashed, no raw sensitive value in any row), upstream
pruning, member field.
"""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import pipeline
from confaudit.errors import FatalBtoolError, FatalCapabilityError, FatalUsageError
from confaudit.model import BtoolResult
from confaudit.secrets import hash_value
from tests.helpers import (
    CollectingLog,
    FakeBtool,
    FakeFs,
    FakeRest,
    build_btool_output,
)

ETC = "/opt/splunk/etc"


def _run(fs, btool, rest=None, **kwargs):
    kwargs.setdefault("fieldnames", ["probe"])
    kwargs.setdefault("member", "member-01")
    kwargs.setdefault("etc_prefix", ETC)
    return pipeline.run(fs=fs, btool=btool, rest=rest or FakeRest(), **kwargs)


def _simple_fixture(value="v1"):
    fs = FakeFs()
    path = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = %s\n" % value)
    btool = FakeBtool({"probe": build_btool_output([
        (path, "[s]"), (path, "k = %s" % value),
    ])})
    return fs, btool, path


class CapabilityTest(unittest.TestCase):

    def test_missing_capability_exact_message(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError) as ctx:
            _run(fs, btool, rest=FakeRest(capabilities=frozenset(("search",))))
        self.assertEqual(
            str(ctx.exception),
            "confbtool: the run_confbtool capability is required to run this "
            "command. The app grants it to the admin role by default; any "
            "other role needs an explicit grant (authorize.conf) by a Splunk "
            "administrator.",
        )

    def test_failed_rest_check_never_presumes_the_authorization(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError):
            _run(fs, btool, rest=FakeRest(capabilities=None))

    def test_rejection_happens_before_any_etc_read(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError):
            _run(fs, btool, rest=FakeRest(capabilities=frozenset()))
        self.assertEqual(fs.read_paths, [])
        self.assertEqual(btool.calls, [])


class BtoolFailureTest(unittest.TestCase):
    """D-13: without the oracle, no verdict - fatal, no partial output."""

    def test_nonzero_exit_exact_message(self):
        fs, _, _ = _simple_fixture()
        btool = FakeBtool({"probe": BtoolResult(2, "", "exit code 2")})
        with self.assertRaises(FatalBtoolError) as ctx:
            _run(fs, btool)
        self.assertEqual(
            str(ctx.exception),
            "confbtool: 'splunk btool probe list --debug' failed (exit code "
            "2); aborting: the winner verdict cannot be established without "
            "btool. No partial results were produced.",
        )

    def test_timeout_and_missing_binary_are_fatal_too(self):
        fs, _, _ = _simple_fixture()
        for cause in ("timeout after 60 s", "No such file or directory"):
            btool = FakeBtool({"probe": BtoolResult(-1, "", cause)})
            with self.assertRaises(FatalBtoolError) as ctx:
                _run(fs, btool)
            self.assertIn(cause, str(ctx.exception))

    def test_conf_without_any_file_is_not_an_error_and_skips_btool(self):
        fs, btool, _ = _simple_fixture()
        rows = _run(fs, btool, fieldnames=["probe,absent_conf"])
        self.assertEqual(btool.calls, ["probe"])
        self.assertEqual({row["conf"] for row in rows}, {"probe"})


class RowShapeTest(unittest.TestCase):

    def test_fifteen_fields_in_contract_order(self):
        from confaudit.model import OUTPUT_FIELDS
        fs, btool, _ = _simple_fixture()
        rows = _run(fs, btool)
        self.assertEqual(len(OUTPUT_FIELDS), 15)
        self.assertEqual(tuple(rows[0].keys()), OUTPUT_FIELDS)

    def test_nominal_row_content(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool)[0]
        self.assertEqual(row["file_path"], path)
        self.assertEqual(row["conf"], "probe")
        self.assertEqual(row["stanza"], "s")
        self.assertEqual(row["key"], "k")
        self.assertEqual(row["value"], "v1")
        self.assertEqual(row["scope"], "app")
        self.assertEqual(row["app"], "00_corp_base")
        self.assertEqual(row["layer"], "local")
        self.assertEqual(row["precedence_rank"], 1)
        self.assertEqual(row["is_btool_winner"], "true")
        self.assertEqual(row["btool_winner_path"], path)
        self.assertEqual(row["btool_winner_value"], "v1")
        self.assertEqual(row["definition_count"], 1)
        self.assertEqual(row["member"], "member-01")
        self.assertEqual(row["anomaly"], "")

    def test_debug_false_empties_file_path_only(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool, debug=False)[0]
        self.assertEqual(row["file_path"], "")
        # btool is still invoked and the verdict fields stay filled.
        self.assertEqual(row["btool_winner_path"], path)
        self.assertEqual(row["is_btool_winner"], "true")

    def test_winner_fields_on_every_row_of_the_group(self):
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        p_app = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = app\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["btool_winner_path"], p_sys)
            self.assertEqual(row["btool_winner_value"], "sys")
            self.assertEqual(row["definition_count"], 2)
        self.assertEqual(
            [(row["precedence_rank"], row["is_btool_winner"]) for row in rows],
            [(1, "true"), (2, "false")],
        )
        self.assertEqual(rows[1]["file_path"], p_app)


class RankCountFilterInsensitivityTest(unittest.TestCase):
    """Section 5.3: rank, winner and count are computed on the real layer set,
    never recomputed after filtering."""

    @staticmethod
    def _fixture():
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = a00\n")
        fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = azz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        return fs, btool

    def test_same_rank_and_count_with_and_without_filters(self):
        fs, btool = self._fixture()
        unfiltered = _run(fs, btool, audit=True)
        by_value = {row["value"]: row for row in unfiltered}
        self.assertEqual(by_value["azz"]["precedence_rank"], 3)
        self.assertEqual(by_value["azz"]["definition_count"], 3)

        fs, btool = self._fixture()
        filtered = _run(fs, btool, audit=True, app="zz_*")
        by_value = {row["value"]: row for row in filtered}
        # Extrapolation emits the whole group; the zz row keeps rank 3 of 3.
        self.assertEqual(by_value["azz"]["precedence_rank"], 3)
        self.assertEqual(by_value["azz"]["definition_count"], 3)
        self.assertEqual(by_value["sys"]["precedence_rank"], 1)


class ParseErrorTest(unittest.TestCase):

    @staticmethod
    def _fixture():
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = zz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = zz"),
        ])})
        return fs, btool, bad

    def test_unreadable_file_yields_parse_error_and_the_run_continues(self):
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool)
        anomalies = [row for row in rows if row["anomaly"] == "parse_error"]
        self.assertEqual(len(anomalies), 1)
        row = anomalies[0]
        self.assertEqual(row["file_path"], bad)
        self.assertEqual(row["conf"], "probe")
        self.assertEqual((row["stanza"], row["key"], row["value"]), ("", "", ""))
        self.assertEqual((row["scope"], row["app"], row["layer"]),
                         ("app", "00_corp_base", "local"))
        self.assertEqual(row["precedence_rank"], "")
        self.assertEqual(row["definition_count"], "")
        self.assertEqual(row["member"], "member-01")
        # The other results are unchanged.
        winners = [row for row in rows if row["is_btool_winner"] == "true"]
        self.assertEqual(len(winners), 1)

    def test_parse_error_rows_are_never_filtered(self):
        # stanza=/key=/app= filters that match nothing, audit=false: the
        # parse_error row still comes out (spec section 4.6).
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool, stanza="no_match", key="no_match", app="no_match")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["anomaly"], "parse_error")
        self.assertEqual(rows[0]["file_path"], bad)

    def test_parse_error_rows_sort_at_the_head_of_their_conf(self):
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool)
        self.assertEqual(rows[0]["anomaly"], "parse_error")

    def test_degraded_decoding_emits_parse_error_and_replacement_definitions(self):
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe",
                     b"[s]\nk = bad\xff\n")
        btool = FakeBtool({"probe": build_btool_output([
            (bad, "[s]"), (bad, "k = bad�"),
        ])})
        rows = _run(fs, btool)
        kinds = sorted(row["anomaly"] for row in rows)
        self.assertEqual(kinds, ["", "parse_error"])
        replacement = [row for row in rows if row["anomaly"] == ""][0]
        self.assertEqual(replacement["value"], "bad�")


class MismatchRowTest(unittest.TestCase):

    def test_mismatch_row_sorts_after_the_ranked_rows_of_its_group(self):
        fs = FakeFs()
        p1 = fs.add("system", "", "local", "probe", "[s]\nk = v1\n")
        p2 = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v2\n")
        # btool designates the rank-2 definition: inversion.
        btool = FakeBtool({"probe": build_btool_output([
            (p2, "[s]"), (p2, "k = v2"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual(
            [row["anomaly"] for row in rows], ["", "", "resolver_mismatch"]
        )
        mismatch = rows[2]
        self.assertEqual(mismatch["file_path"], p1)          # internal verdict
        self.assertEqual(mismatch["value"], "v1")
        self.assertEqual(mismatch["btool_winner_path"], p2)  # btool verdict
        self.assertEqual(mismatch["btool_winner_value"], "v2")
        self.assertEqual(mismatch["precedence_rank"], "")
        self.assertEqual(mismatch["is_btool_winner"], "")
        self.assertEqual(mismatch["definition_count"], 2)
        # The oracle primes: the winner flag follows btool.
        self.assertEqual(rows[1]["is_btool_winner"], "true")
        self.assertEqual(rows[0]["is_btool_winner"], "false")

    def test_mismatch_rows_are_never_filtered(self):
        fs = FakeFs()
        p1 = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v1\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p1, "[s]"), (p1, "k = v1"),
            (p1, "[zz_ghost]"), (p1, "ghost_key = ghost_val"),
        ])})
        rows = _run(fs, btool, stanza="no_match")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["anomaly"], "resolver_mismatch")
        self.assertEqual((rows[0]["stanza"], rows[0]["key"]),
                         ("zz_ghost", "ghost_key"))
        self.assertEqual(rows[0]["definition_count"], 0)


class SecretsEndToEndTest(unittest.TestCase):

    @staticmethod
    def _fixture():
        fs = FakeFs()
        fs.add("system", "", "local", "server",
               '[general]\nencrypt_fields = "probe:s:hidden_key"\n')
        p_sys = fs.add("system", "", "local", "probe",
                       "[s]\nhidden_key = $7$sys_cipher\n")
        p_app = fs.add("app", "00_corp_base", "local", "probe",
                       "[s]\nhidden_key = $7$app_cipher\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "hidden_key = $7$sys_cipher"),
        ])})
        return fs, btool

    def test_value_and_btool_winner_value_are_hashed(self):
        fs, btool = self._fixture()
        rows = _run(fs, btool, audit=True)
        probe_rows = [row for row in rows if row["conf"] == "probe"]
        self.assertEqual(len(probe_rows), 2)
        for row in probe_rows:
            self.assertEqual(row["btool_winner_value"],
                             hash_value("$7$sys_cipher"))
        self.assertEqual(probe_rows[0]["value"], hash_value("$7$sys_cipher"))
        self.assertEqual(probe_rows[1]["value"], hash_value("$7$app_cipher"))

    def test_no_raw_sensitive_value_in_any_produced_row(self):
        fs, btool = self._fixture()
        rows = _run(fs, btool, audit=True)
        dump = repr(rows)
        self.assertNotIn("$7$sys_cipher", dump)
        self.assertNotIn("$7$app_cipher", dump)

    def test_configurable_key_patterns_apply_case_insensitively(self):
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nMyPassword = cleartext\n")
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "MyPassword = cleartext"),
        ])})
        rows = _run(fs, btool)
        self.assertEqual(rows[0]["value"], hash_value("cleartext"))


class OrderingAndPruningTest(unittest.TestCase):

    def test_emission_sorted_by_conf_stanza_key_rank(self):
        fs = FakeFs()
        pa = fs.add("app", "00_corp_base", "local", "aconf",
                    "[s2]\nk = x\n[s1]\nb = 1\na = 2\n")
        pb = fs.add("app", "00_corp_base", "local", "bconf", "[s]\nk = y\n")
        btool = FakeBtool({
            "aconf": build_btool_output([
                (pa, "[s1]"), (pa, "a = 2"), (pa, "b = 1"),
                (pa, "[s2]"), (pa, "k = x"),
            ]),
            "bconf": build_btool_output([(pb, "[s]"), (pb, "k = y")]),
        })
        rows = _run(fs, btool, fieldnames=["bconf,aconf"])
        self.assertEqual(
            [(row["conf"], row["stanza"], row["key"]) for row in rows],
            [("aconf", "s1", "a"), ("aconf", "s1", "b"),
             ("aconf", "s2", "k"), ("bconf", "s", "k")],
        )

    def test_explicit_conf_list_prunes_upstream(self):
        fs = FakeFs()
        p1 = fs.add("app", "00_corp_base", "local", "wanted", "[s]\nk = v\n")
        p2 = fs.add("app", "00_corp_base", "local", "unwanted", "[s]\nk = v\n")
        btool = FakeBtool({"wanted": build_btool_output([
            (p1, "[s]"), (p1, "k = v"),
        ])})
        _run(fs, btool, fieldnames=["wanted"])
        self.assertEqual(btool.calls, ["wanted"])
        self.assertNotIn(p2, fs.read_paths)

    def test_star_covers_every_conf_on_disk(self):
        fs = FakeFs()
        p1 = fs.add("app", "00_corp_base", "local", "aconf", "[s]\nk = v\n")
        p2 = fs.add("system", "", "default", "bconf", "[s]\nk = w\n")
        btool = FakeBtool({
            "aconf": build_btool_output([(p1, "[s]"), (p1, "k = v")]),
            "bconf": build_btool_output([(p2, "[s]"), (p2, "k = w")]),
        })
        rows = _run(fs, btool, fieldnames=["*"])
        self.assertEqual(sorted(btool.calls), ["aconf", "bconf"])
        self.assertEqual(len(rows), 2)

    def test_invalid_filter_is_fatal_before_any_btool_call(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalUsageError):
            _run(fs, btool, stanza="")
        self.assertEqual(btool.calls, [])


if __name__ == "__main__":
    unittest.main()
