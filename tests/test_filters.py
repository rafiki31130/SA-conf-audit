"""Parameter validation, `app=` x `audit=` matrix, extrapolation
(spec section 7)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import filters
from confaudit.errors import FatalUsageError
from confaudit.model import Definition, Group, STAR, Verdict


def _definition(scope, app, layer, value):
    if scope == "system":
        path = "/opt/splunk/etc/system/%s/probe.conf" % layer
    else:
        path = "/opt/splunk/etc/apps/%s/%s/probe.conf" % (app, layer)
    return Definition(
        path=path, conf="probe", stanza="s", key="k", value=value,
        scope=scope, app=app, layer=layer,
    )


class ConfArgumentTest(unittest.TestCase):
    """Reconstruction of the positional conf list from `fieldnames`
    (spec section 3.1)."""

    def test_comma_joined_single_token(self):
        self.assertEqual(filters.parse_conf_argument(["a,b"]), ("a", "b"))

    def test_comma_and_space(self):
        # `a, b` reaches the SDK as ['a,', 'b'].
        self.assertEqual(filters.parse_conf_argument(["a,", "b"]), ("a", "b"))

    def test_space_separated(self):
        # `a b` reaches the SDK as ['a', 'b'].
        self.assertEqual(filters.parse_conf_argument(["a", "b"]), ("a", "b"))

    def test_star_alone(self):
        self.assertIs(filters.parse_conf_argument(["*"]), STAR)

    def test_duplicates_are_removed(self):
        # One btool invocation per conf at most (CDC section 7.2).
        self.assertEqual(filters.parse_conf_argument(["a,a", "a"]), ("a",))

    def test_missing_argument_exact_message(self):
        with self.assertRaises(FatalUsageError) as ctx:
            filters.parse_conf_argument([])
        self.assertEqual(
            str(ctx.exception),
            "confbtool: missing conf argument. Usage: | confbtool "
            "<conf|conf,conf|*> [stanza=<pattern>] [key=<pattern>] "
            "[app=<pattern>] [audit=<bool>] [debug=<bool>]",
        )

    def test_invalid_conf_name_exact_message(self):
        with self.assertRaises(FatalUsageError) as ctx:
            filters.parse_conf_argument(["bad/name"])
        self.assertEqual(
            str(ctx.exception),
            "confbtool: invalid conf name 'bad/name': letters, digits, '.', "
            "'_', '-' only (or a single '*').",
        )

    def test_star_in_a_list_is_rejected(self):
        with self.assertRaises(FatalUsageError):
            filters.parse_conf_argument(["a,*"])

    def test_valid_names_cover_the_real_repertoire(self):
        self.assertEqual(
            filters.parse_conf_argument(["alert_actions,ui-prefs,server"]),
            ("alert_actions", "ui-prefs", "server"),
        )


class PatternValidationTest(unittest.TestCase):
    """Spec section 7.1 - wildcards accepted, empty pattern refused."""

    def test_wildcards_star_and_question_mark(self):
        rx = filters.compile_filter("stanza", "cred*al_?")
        self.assertTrue(rx.match("credential_a"))   # * substring, ? one char
        self.assertFalse(rx.match("credential_"))   # ? requires one character
        self.assertFalse(rx.match("credential_ab"))  # exactly one

    def test_literal_regex_metacharacters_are_escaped(self):
        rx = filters.compile_filter("key", "a.b+c")
        self.assertTrue(rx.match("a.b+c"))
        self.assertFalse(rx.match("aXb+c"))

    def test_case_sensitive(self):
        rx = filters.compile_filter("app", "Corp*")
        self.assertFalse(rx.match("corp_base"))

    def test_empty_pattern_exact_message(self):
        with self.assertRaises(FatalUsageError) as ctx:
            filters.compile_filter("stanza", "")
        self.assertEqual(
            str(ctx.exception),
            "confbtool: invalid stanza filter '': literal characters plus "
            "the wildcards '*' and '?' only.",
        )

    def test_control_character_refused(self):
        with self.assertRaises(FatalUsageError):
            filters.compile_filter("key", "bad\x01pattern")

    def test_defaults(self):
        params = filters.validate_params(["probe"])
        self.assertEqual(params.stanza_raw, "*")
        self.assertEqual(params.key_raw, "*")
        self.assertIsNone(params.app_rx)
        self.assertFalse(params.audit)
        self.assertTrue(params.debug)


class MatrixTest(unittest.TestCase):
    """The four cells of the `app=` x `audit=` matrix on the SAME group set
    (spec section 7.2)."""

    def setUp(self):
        # One key carried by system/local, 00_corp_base and zz_sample_app;
        # one key carried only by zz_sample_app.
        self.shared = Group(conf="probe", stanza="s", key="k", defs=(
            _definition("system", "", "local", "sys_wins"),
            _definition("app", "00_corp_base", "local", "shadowed_00"),
            _definition("app", "zz_sample_app", "default", "shadowed_zz"),
        ))
        self.zz_only = Group(conf="probe", stanza="s", key="zz_key", defs=(
            _definition("app", "zz_sample_app", "local", "zz_val"),
        ))
        self.groups = {
            ("s", "k"): self.shared,
            ("s", "zz_key"): self.zz_only,
        }
        self.verdicts = {
            ("s", "k"): Verdict(index=0, winner=None),
            ("s", "zz_key"): Verdict(index=0, winner=None),
        }

    def _select(self, stanza=None, key=None, app=None, audit=False):
        params = filters.validate_params(
            ["probe"], stanza=stanza, key=key, app=app, audit=audit,
        )
        return filters.select(self.groups, self.verdicts, params)

    def _values(self, selected):
        return sorted(group.defs[index].value for group, index in selected)

    def test_cell_no_app_no_audit_winners_only(self):
        self.assertEqual(self._values(self._select()), ["sys_wins", "zz_val"])

    def test_cell_no_app_audit_every_definition(self):
        self.assertEqual(
            self._values(self._select(audit=True)),
            ["shadowed_00", "shadowed_zz", "sys_wins", "zz_val"],
        )

    def test_cell_app_no_audit_winners_located_in_the_app(self):
        # k's winner is system: excluded; zz_key's winner is in zz: kept.
        self.assertEqual(
            self._values(self._select(app="zz_*")), ["zz_val"]
        )

    def test_cell_app_audit_extrapolation(self):
        # zz carries a definition of k (shadowed) and of zz_key: BOTH groups
        # are selected, and EVERY line of each group is emitted - competitors
        # outside the app and the system layer included.
        self.assertEqual(
            self._values(self._select(app="zz_*", audit=True)),
            ["shadowed_00", "shadowed_zz", "sys_wins", "zz_val"],
        )

    def test_extrapolation_key_not_carried_by_the_app_never_appears(self):
        # 00_corp_base carries k but not zz_key.
        self.assertEqual(
            self._values(self._select(app="00_*", audit=True)),
            ["shadowed_00", "shadowed_zz", "sys_wins"],
        )

    def test_composition_with_stanza_and_key_filters(self):
        self.assertEqual(
            self._values(self._select(key="zz_*", audit=True)), ["zz_val"]
        )
        self.assertEqual(self._values(self._select(stanza="nope")), [])

    def test_rank_and_count_are_untouched_by_selection(self):
        # The matrix selects (group, index) pairs; the group object - hence
        # rank order and cardinal - is the resolution's, never rebuilt.
        selected = self._select(app="zz_*", audit=True)
        for group, _ in selected:
            if group.key == "k":
                self.assertEqual(len(group.defs), 3)
                self.assertEqual(group.defs[0].value, "sys_wins")


if __name__ == "__main__":
    unittest.main()
