"""Normalisation for the confrontation only (D-23, D-25; spec sections 6.3-6.5).

Every rule here is measured on Splunk 9.4.6 over the whole conf corpus of the
lab instance; the counts quoted in the docstrings are those measurements.
"""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import normalize

ETC = "/opt/splunk/etc"
HOME = "/opt/splunk"
APP_DEFAULT = ETC + "/apps/zz_sample_app/default/inputs.conf"
SYS_DEFAULT = ETC + "/system/default/inputs.conf"


class SplunkHomeTest(unittest.TestCase):

    def test_home_derived_from_the_resolved_etc_prefix(self):
        self.assertEqual(normalize.splunk_home_from_etc(ETC), HOME)
        self.assertEqual(normalize.splunk_home_from_etc(ETC + "/"), HOME)

    def test_unusable_prefix_yields_no_expansion_rather_than_a_guess(self):
        self.assertEqual(normalize.splunk_home_from_etc(""), "")
        self.assertEqual(normalize.splunk_home_from_etc("/opt/splunk"), "")


class StanzaTest(unittest.TestCase):
    """D-23: 60 stanzas of the measured `inputs` carry a variable or a relative
    path, 60 are explained by these two transformations, 0 are left over."""

    def test_splunk_home_variable_is_expanded(self):
        self.assertEqual(
            normalize.stanza_for_match(
                "monitor://$SPLUNK_HOME/var/log/splunk", HOME, SYS_DEFAULT),
            "monitor:///opt/splunk/var/log/splunk",
        )

    def test_variable_expanded_for_every_scheme_of_the_corpus(self):
        for scheme, separator in (("monitor", "://"), ("batch", "://"),
                                  ("script", "://"), ("fschange", ":"),
                                  ("blacklist", ":")):
            spelling = "%s%s$SPLUNK_HOME/etc" % (scheme, separator)
            with self.subTest(scheme=scheme):
                self.assertEqual(
                    normalize.stanza_for_match(spelling, HOME, SYS_DEFAULT),
                    "%s%s/opt/splunk/etc" % (scheme, separator),
                )

    def test_relative_path_resolved_against_the_declaring_app_directory(self):
        self.assertEqual(
            normalize.stanza_for_match(
                "script://./bin/x.py", HOME, APP_DEFAULT),
            "script:///opt/splunk/etc/apps/zz_sample_app/bin/x.py",
        )

    def test_relative_path_left_alone_when_declared_by_a_system_layer(self):
        # No app directory to anchor on: inventing a base would be a guess, and
        # the case does not appear on the measured corpus.
        self.assertEqual(
            normalize.stanza_for_match("script://./bin/x.py", HOME, SYS_DEFAULT),
            "script://./bin/x.py",
        )

    def test_idempotent_on_an_already_resolved_name(self):
        resolved = "monitor:///opt/splunk/var/log/splunk"
        self.assertEqual(
            normalize.stanza_for_match(resolved, HOME, SYS_DEFAULT), resolved)

    def test_a_plain_stanza_name_is_untouched(self):
        self.assertEqual(
            normalize.stanza_for_match("splunktcp", HOME, SYS_DEFAULT),
            "splunktcp",
        )


class KeyTest(unittest.TestCase):
    """D-25: btool collapses a doubled backslash of a KEY NAME; measured on
    `sourcetypes`, 75 keys out of 75 explained, and the 21 values of the corpus
    carrying a doubled backslash are restituted byte for byte."""

    def test_doubled_backslash_collapses(self):
        self.assertEqual(
            normalize.key_for_match('L-x_-_\\\\"\\\\"_L7('),
            'L-x_-_\\"\\"_L7(',
        )

    def test_single_backslash_is_not_unescaped(self):
        # `\"` stays `\"`: the collapse is about the doubling, not a general
        # unescaping.
        self.assertEqual(normalize.key_for_match('k\\"v'), 'k\\"v')

    def test_ordinary_key_untouched(self):
        self.assertEqual(normalize.key_for_match("host"), "host")


class AppRootTest(unittest.TestCase):

    def test_app_layer_file_yields_its_app_directory(self):
        self.assertEqual(
            normalize.app_root(APP_DEFAULT), ETC + "/apps/zz_sample_app")

    def test_system_layer_file_yields_none(self):
        self.assertIsNone(normalize.app_root(SYS_DEFAULT))


if __name__ == "__main__":
    unittest.main()
