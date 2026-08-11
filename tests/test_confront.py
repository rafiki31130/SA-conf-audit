"""Confrontation with the btool oracle (spec section 6.5)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit.confront import confront
from confaudit.model import BtoolWinner, Definition, Group
from confaudit.secrets import hash_value


def _definition(path, value, stanza="s", key="k"):
    return Definition(
        path=path, conf="probe", stanza=stanza, key=key, value=value,
        scope="app", app="00_corp_base", layer="local",
    )


def _group(*defs, stanza="s", key="k"):
    return Group(conf="probe", stanza=stanza, key=key, defs=tuple(defs))


P1 = "/opt/splunk/etc/apps/00_corp_base/local/probe.conf"
P2 = "/opt/splunk/etc/apps/zz_sample_app/local/probe.conf"


class ConfrontTest(unittest.TestCase):

    def test_nominal_true_on_rank_one_no_anomaly(self):
        group = _group(_definition(P1, "v1"), _definition(P2, "v2"))
        verdicts, anomalies = confront(
            "probe", {("s", "k"): group}, {("s", "k"): BtoolWinner(P1, "v1")}
        )
        self.assertEqual(verdicts[("s", "k")].index, 0)
        self.assertEqual(anomalies, [])

    def test_rank_inversion_oracle_primes_and_mismatch_emitted(self):
        # btool designates the rank-2 definition: the oracle primes - the
        # winner flag goes to btool's choice, plus one resolver_mismatch line
        # carrying both verdicts.
        group = _group(_definition(P1, "v1"), _definition(P2, "v2"))
        verdicts, anomalies = confront(
            "probe", {("s", "k"): group}, {("s", "k"): BtoolWinner(P2, "v2")}
        )
        self.assertEqual(verdicts[("s", "k")].index, 1)
        self.assertEqual(len(anomalies), 1)
        anomaly = anomalies[0]
        self.assertEqual(anomaly.internal.path, P1)      # internal verdict
        self.assertEqual(anomaly.btool.path, P2)         # btool verdict
        self.assertEqual(anomaly.definition_count, 2)

    def test_unknown_btool_winner_no_true_row(self):
        group = _group(_definition(P1, "v1"))
        verdicts, anomalies = confront(
            "probe", {("s", "k"): group},
            {("s", "k"): BtoolWinner(P2, "elsewhere")},
        )
        self.assertIsNone(verdicts[("s", "k")].index)
        self.assertEqual(verdicts[("s", "k")].winner.value, "elsewhere")
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].internal.path, P1)
        self.assertEqual(anomalies[0].btool.value, "elsewhere")

    def test_group_without_btool_verdict(self):
        group = _group(_definition(P1, "v1"))
        verdicts, anomalies = confront("probe", {("s", "k"): group}, {})
        self.assertIsNone(verdicts[("s", "k")].index)
        self.assertIsNone(verdicts[("s", "k")].winner)
        self.assertEqual(len(anomalies), 1)
        self.assertIsNone(anomalies[0].btool)
        self.assertEqual(anomalies[0].definition_count, 1)

    def test_btool_verdict_without_group(self):
        verdicts, anomalies = confront(
            "probe", {}, {("ghost", "k"): BtoolWinner(P1, "v")}
        )
        self.assertEqual(verdicts, {})
        self.assertEqual(len(anomalies), 1)
        anomaly = anomalies[0]
        self.assertEqual((anomaly.stanza, anomaly.key), ("ghost", "k"))
        self.assertIsNone(anomaly.internal)
        self.assertEqual(anomaly.definition_count, 0)

    def test_comparison_uses_raw_values_before_hashing(self):
        # The btool verdict carries the raw value; a hashed internal value
        # would break the match. The confrontation must run on raw values -
        # hashing only happens at row construction (section 9.2).
        raw = "$7$abcdefgh"
        group = _group(_definition(P1, raw))
        verdicts, anomalies = confront(
            "probe", {("s", "k"): group}, {("s", "k"): BtoolWinner(P1, raw)}
        )
        self.assertEqual(verdicts[("s", "k")].index, 0)
        self.assertEqual(anomalies, [])
        # Control: the hashed form would NOT have matched.
        self.assertNotEqual(hash_value(raw), raw)


if __name__ == "__main__":
    unittest.main()
