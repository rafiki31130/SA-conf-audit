"""Resolution and rank (spec section 5, test list of section 12.1)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import resolver
from confaudit.confparser import parse_conf_text
from confaudit.model import LayerFile


def _lf(scope, app, layer):
    if scope == "system":
        path = "/opt/splunk/etc/system/%s/probe.conf" % layer
    else:
        path = "/opt/splunk/etc/apps/%s/%s/probe.conf" % (app, layer)
    return LayerFile(scope, app, layer, path)


def _resolve(files):
    """files: list of (LayerFile, conf_text)."""
    return resolver.resolve(
        "probe", [(lf, parse_conf_text(text)) for lf, text in files]
    )


class LayerOrderTest(unittest.TestCase):
    """Section 5.2 - system/local > apps/*/local > apps/*/default >
    system/default."""

    def test_four_layer_order(self):
        groups = _resolve([
            (_lf("system", "", "default"), "[s]\nk = sys_default\n"),
            (_lf("app", "mid_app", "default"), "[s]\nk = app_default\n"),
            (_lf("app", "mid_app", "local"), "[s]\nk = app_local\n"),
            (_lf("system", "", "local"), "[s]\nk = sys_local\n"),
        ])
        values = [d.value for d in groups[("s", "k")].defs]
        self.assertEqual(
            values, ["sys_local", "app_local", "app_default", "sys_default"]
        )

    def test_rank_is_one_based_and_count_is_group_cardinal(self):
        groups = _resolve([
            (_lf("system", "", "local"), "[s]\nk = a\n"),
            (_lf("system", "", "default"), "[s]\nk = b\n"),
        ])
        group = groups[("s", "k")]
        self.assertEqual(len(group.defs), 2)
        self.assertEqual(group.defs[0].value, "a")   # rank 1
        self.assertEqual(group.defs[1].value, "b")   # rank 2


class AsciiAscendingAppOrderTest(unittest.TestCase):
    """⚠ The flagged trap (M-1): inside an apps tier, the app FIRST in ASCII
    ASCENDING order wins - `00_corp_base` beats `zz_sample_app`, numeric
    prefixes before letters. The reverse order is the most likely
    implementation error of the project (spec section 5.2)."""

    def test_00_beats_zz_on_the_local_tier(self):
        groups = _resolve([
            (_lf("app", "zz_sample_app", "local"), "[s]\nk = from_zz\n"),
            (_lf("app", "00_corp_base", "local"), "[s]\nk = from_00\n"),
        ])
        defs = groups[("s", "k")].defs
        self.assertEqual(defs[0].value, "from_00")
        self.assertEqual(defs[0].app, "00_corp_base")
        self.assertEqual(defs[1].value, "from_zz")

    def test_00_beats_zz_on_the_default_tier(self):
        groups = _resolve([
            (_lf("app", "zz_sample_app", "default"), "[s]\nk = from_zz\n"),
            (_lf("app", "00_corp_base", "default"), "[s]\nk = from_00\n"),
        ])
        self.assertEqual(groups[("s", "k")].defs[0].value, "from_00")

    def test_any_app_local_beats_any_app_default(self):
        # The tier dominates the app name: zz local beats 00 default.
        groups = _resolve([
            (_lf("app", "00_corp_base", "default"), "[s]\nk = from_00_default\n"),
            (_lf("app", "zz_sample_app", "local"), "[s]\nk = from_zz_local\n"),
        ])
        self.assertEqual(groups[("s", "k")].defs[0].value, "from_zz_local")

    def test_code_point_comparison_no_case_folding(self):
        # 'B' (0x42) < 'a' (0x61) by code points: app 'Beta' wins over 'alpha'.
        groups = _resolve([
            (_lf("app", "alpha", "local"), "[s]\nk = from_alpha\n"),
            (_lf("app", "Beta", "local"), "[s]\nk = from_Beta\n"),
        ])
        self.assertEqual(groups[("s", "k")].defs[0].value, "from_Beta")


class GroupSemanticsTest(unittest.TestCase):
    """Section 5.3 - default groups distinct from stanza groups (D-7)."""

    def test_default_and_stanza_groups_do_not_compete(self):
        groups = _resolve([
            (_lf("app", "00_corp_base", "local"),
             "[default]\nk = inherited\n[s]\nk = local_override\n"),
        ])
        self.assertEqual(len(groups[("default", "k")].defs), 1)
        self.assertEqual(len(groups[("s", "k")].defs), 1)
        self.assertEqual(groups[("default", "k")].defs[0].value, "inherited")
        self.assertEqual(groups[("s", "k")].defs[0].value, "local_override")

    def test_default_key_emitted_once_at_literal_origin(self):
        # No expansion anywhere: one group per literal (stanza, key), never a
        # repetition per inheriting stanza (section 5.4).
        groups = _resolve([
            (_lf("app", "00_corp_base", "local"),
             "[default]\nk = v\n[s1]\nother = x\n[s2]\nmore = y\n"),
        ])
        self.assertEqual(
            sorted(groups), [("default", "k"), ("s1", "other"), ("s2", "more")]
        )


if __name__ == "__main__":
    unittest.main()
