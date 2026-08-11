"""Secret rules and hashing (spec section 9)."""

import hashlib
import re
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
