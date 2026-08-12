"""Secret rules and hashing (spec section 9)."""

import hashlib
import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit.model import AppSettings
from confaudit.secrets import (
    SecretMatcher,
    SecretRule,
    hash_value,
    parse_encrypt_fields,
    parse_pattern_list,
)

#: Synthetic excerpt of the M-5 format - generic entries only.
ENCRYPT_FIELDS = (
    '"server: :pass4SymmKey", "server: :sslPassword", '
    '"outputs:tcpout:token", "passwords:credential:password"'
)


class ParseEncryptFieldsTest(unittest.TestCase):

    def test_entries_with_empty_stanza_component(self):
        rules = parse_encrypt_fields(ENCRYPT_FIELDS)
        self.assertIn(SecretRule("server", "", "pass4SymmKey"), rules)
        self.assertIn(SecretRule("outputs", "tcpout", "token"), rules)

    def test_malformed_entry_is_ignored_and_reported(self):
        reported = []
        rules = parse_encrypt_fields(
            '"server: :pass4SymmKey", "broken_entry", "a:b:c:d"',
            on_malformed=reported.append,
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(reported, ["broken_entry", "a:b:c:d"])

    def test_empty_value(self):
        self.assertEqual(parse_encrypt_fields(""), [])


class SecretMatcherTest(unittest.TestCase):

    def setUp(self):
        self.matcher = SecretMatcher(
            rules=parse_encrypt_fields(ENCRYPT_FIELDS),
            settings=AppSettings(),
        )

    def test_empty_stanza_component_matches_every_stanza(self):
        for stanza in ("general", "default", "any_stanza"):
            self.assertTrue(
                self.matcher.is_sensitive("server", stanza, "pass4SymmKey")
            )

    def test_non_empty_stanza_component_compares_strictly(self):
        self.assertTrue(self.matcher.is_sensitive("outputs", "tcpout", "token"))
        # Different conf: the outputs:tcpout:token entry does not apply -
        # but the default *token* key pattern still catches the key name, so
        # probe a conf-scoped rule with a matcher without extra patterns.
        bare = SecretMatcher(
            rules=[SecretRule("outputs", "tcpout", "specific_key")],
            settings=AppSettings(extra_key_patterns=(), extra_stanza_patterns=()),
        )
        self.assertTrue(bare.is_sensitive("outputs", "tcpout", "specific_key"))
        self.assertFalse(bare.is_sensitive("outputs", "other", "specific_key"))
        self.assertFalse(bare.is_sensitive("inputs", "tcpout", "specific_key"))

    def test_key_patterns_are_case_insensitive(self):
        self.assertTrue(self.matcher.is_sensitive("probe", "s", "MyPassword"))
        self.assertTrue(self.matcher.is_sensitive("probe", "s", "PASS4SYMMKEY"))
        self.assertTrue(self.matcher.is_sensitive("probe", "s", "api_TOKEN_x"))

    def test_stanza_patterns_mark_every_key_of_the_stanza(self):
        # Default `credential*` covers the [credential:...] stanzas of
        # passwords.conf: every key of a matching stanza is sensitive.
        self.assertTrue(
            self.matcher.is_sensitive("passwords", "credential:x:y:", "anything")
        )
        self.assertFalse(self.matcher.is_sensitive("probe", "plain", "harmless"))

    def test_pattern_list_parsing(self):
        self.assertEqual(
            parse_pattern_list(" a , *b* ,, c "), ("a", "*b*", "c")
        )


class PatternExcludedConfsTest(unittest.TestCase):
    """D-29 / CDC section 6.2 - the complementary patterns, and only they, are
    switched off on the excluded confs."""

    def setUp(self):
        self.matcher = SecretMatcher(
            rules=parse_encrypt_fields(ENCRYPT_FIELDS),
            settings=AppSettings(),
        )

    def test_authorize_is_excluded_by_default(self):
        # The eleven capability names of the A-1 measurement: their value is
        # `enabled`, hashing them protects nothing and hides the conf every
        # administrator audits first.
        for key in (
            "edit_splunktcp_token", "edit_storage_passwords", "edit_token_http",
            "edit_tokens_all", "edit_tokens_own", "edit_tokens_settings",
            "list_storage_passwords", "list_token_http", "list_tokens_all",
            "list_tokens_own", "change_own_password",
        ):
            self.assertFalse(
                self.matcher.is_sensitive("authorize", "role_admin", key), key
            )

    def test_other_default_exclusions(self):
        # One measured key per conf of the shipped default list.
        for conf, stanza, key in (
            ("sourcetypes", "../scripts/logs/apache.error.log", "password"),
            ("multikv", "PerfmonMk", "body.tokens"),
            ("web-features", "feature:page_migration",
             "enable_password_management_page_vnext"),
            ("collections", "delete_tokens", "field.token_id"),
            ("fields", "default", "TOKENIZER"),
        ):
            self.assertFalse(self.matcher.is_sensitive(conf, stanza, key),
                             "%s/%s" % (conf, key))

    def test_a_conf_that_is_not_excluded_is_still_hashed(self):
        # authentication.conf carries LDAP/SAML credentials by design, so it
        # is deliberately NOT excluded: its policy keys stay hashed rather
        # than risk unmasking a neighbouring secret.
        for key in ("minPasswordLength", "expirePasswordDays",
                    "passwordHashAlgorithm"):
            self.assertTrue(
                self.matcher.is_sensitive("authentication", "splunk_auth", key)
            )
        # And so does every conf outside the list.
        self.assertTrue(self.matcher.is_sensitive("web", "settings",
                                                  "loginPasswordHint"))
        self.assertTrue(self.matcher.is_sensitive("limits", "http_input",
                                                  "max_number_of_tokens"))

    def test_encrypt_fields_is_never_excluded(self):
        # Even on an excluded conf, an encrypt_fields entry keeps hashing.
        matcher = SecretMatcher(
            rules=parse_encrypt_fields('"authorize: :bindDNpassword"'),
            settings=AppSettings(),
        )
        self.assertFalse(matcher.is_sensitive("authorize", "role_admin",
                                              "edit_token_http"))
        self.assertTrue(matcher.is_sensitive("authorize", "role_admin",
                                             "bindDNpassword"))

    def test_exclusion_list_is_configurable_and_exact(self):
        settings = AppSettings(pattern_excluded_confs=("probe",))
        matcher = SecretMatcher(rules=(), settings=settings)
        self.assertFalse(matcher.is_sensitive("probe", "s", "api_token"))
        # Not excluded any more: the shipped default is fully overridden.
        self.assertTrue(matcher.is_sensitive("authorize", "s", "edit_token_http"))
        # Exact names only - no glob semantics, so `probe*` never widens.
        self.assertTrue(matcher.is_sensitive("probe_other", "s", "api_token"))

    def test_empty_exclusion_list_restores_the_pre_d29_behaviour(self):
        matcher = SecretMatcher(
            rules=(), settings=AppSettings(pattern_excluded_confs=()),
        )
        self.assertTrue(
            matcher.is_sensitive("authorize", "role_admin", "edit_token_http")
        )


class HashTest(unittest.TestCase):

    def test_format_sha256_hex64(self):
        digest = hash_value("anything")
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}\Z")

    def test_digest_of_utf8_bytes(self):
        self.assertEqual(
            hash_value("v"),
            "sha256:" + hashlib.sha256(b"v").hexdigest(),
        )

    def test_encrypted_form_hashed_as_is(self):
        # M-5: btool restitutes the `$7$...` encrypted form untouched; the
        # hash applies to that form, never to a cleartext.
        encrypted = "$7$synthetic_fixture_not_a_real_secret"
        self.assertEqual(
            hash_value(encrypted),
            "sha256:" + hashlib.sha256(encrypted.encode("utf-8")).hexdigest(),
        )

    def test_equal_values_give_equal_digests_across_layers(self):
        self.assertEqual(hash_value("same"), hash_value("same"))
        self.assertNotEqual(hash_value("same"), hash_value("other"))


if __name__ == "__main__":
    unittest.main()
