"""Sensitive-key rules and hashing (spec section 9, CDC section 6.2).

Two sources, both read at execution time:

1. `encrypt_fields` (`server.conf`) - the canonical list maintained by Splunk
   itself (M-5), obtained through the library's own layer resolution;
2. complementary configurable glob patterns (`confbtool.conf` `[secrets]`),
   covering sensitive keys the platform does not encrypt.

The hashed value is the value as restituted by the file layer - the `$7$...`
encrypted form when Splunk encrypted it (btool never emits a cleartext, M-5) -
so hashing preserves comparability across layers (equal values give equal
digests) without exposing anything.
"""

import hashlib
import re
from dataclasses import dataclass

from .model import AppSettings


@dataclass(frozen=True)
class SecretRule:
    """One `encrypt_fields` entry: `<conf>:<stanza>:<key>`, stanza possibly
    empty (= every stanza)."""

    conf: str
    stanza: str
    key: str


def parse_encrypt_fields(value, on_malformed=None):
    """Parse the `encrypt_fields` value into a list of `SecretRule` (M-5 format).

    Comma-split outside double quotes; quotes and edge blanks removed; each
    entry colon-split into exactly three components, each stripped
    (`"server: :pass4SymmKey"` -> conf `server`, stanza empty, key
    `pass4SymmKey`). A malformed entry (not exactly 3 components) is reported
    through `on_malformed` and skipped - never blocking (spec section 9.1).
    """
    rules = []
    for entry in _split_outside_quotes(value or ""):
        entry = entry.strip(" \t")
        if entry.startswith('"') and entry.endswith('"') and len(entry) >= 2:
            entry = entry[1:-1]
        entry = entry.strip(" \t")
        if not entry:
            continue
        components = entry.split(":")
        if len(components) != 3:
            if on_malformed is not None:
                on_malformed(entry)
            continue
        conf, stanza, key = (component.strip(" \t") for component in components)
        rules.append(SecretRule(conf=conf, stanza=stanza, key=key))
    return rules


def _split_outside_quotes(value):
    """Split on `,` outside double quotes."""
    parts = []
    current = []
    in_quotes = False
    for character in value:
        if character == '"':
            in_quotes = not in_quotes
            current.append(character)
        elif character == "," and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def parse_pattern_list(raw):
    """Comma-separated glob pattern list of `confbtool.conf` -> tuple."""
    return tuple(
        token.strip() for token in (raw or "").split(",") if token.strip()
    )


def _compile_glob(pattern, ignore_case):
    parts = []
    for character in pattern:
        if character == "*":
            parts.append(".*")
        elif character == "?":
            parts.append(".")
        else:
            parts.append(re.escape(character))
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("^" + "".join(parts) + r"\Z", flags)


class SecretMatcher:
    """Decides whether a `(conf, stanza, key)` is sensitive (spec section 9.1).

    True if an `encrypt_fields` entry matches (conf and key strict equality,
    case-sensitive; an EMPTY stanza component matches every stanza, `default`
    included; a non-empty one compares strictly) OR a complementary pattern
    matches (key globs case-INsensitive; stanza globs mark every key of a
    matching stanza as sensitive).
    """

    def __init__(self, rules=(), settings=None):
        settings = settings or AppSettings()
        self._rules = tuple(rules)
        self._key_rx = tuple(
            _compile_glob(p, ignore_case=True)
            for p in settings.extra_key_patterns
        )
        self._stanza_rx = tuple(
            _compile_glob(p, ignore_case=False)
            for p in settings.extra_stanza_patterns
        )

    def is_sensitive(self, conf, stanza, key):
        for rule in self._rules:
            if rule.conf == conf and rule.key == key:
                if rule.stanza == "" or rule.stanza == stanza:
                    return True
        for pattern in self._key_rx:
            if pattern.match(key):
                return True
        for pattern in self._stanza_rx:
            if pattern.match(stanza):
                return True
        return False


def hash_value(value):
    """`sha256:` + hex digest of the UTF-8 bytes of the value (spec 9.2)."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
