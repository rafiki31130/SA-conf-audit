"""`README/confbtool.conf.spec` holds `default/confbtool.conf` to its contract.

`confbtool.conf` is a conf file PROPER TO THIS APP: no platform spec describes
it, so without a `.spec` of its own the settings are exploitable by nothing -
not Splunk Web, not an operator reading the app, not a tool that walks
`README/`. The file existed only as comments inside `default/confbtool.conf`
until 1.4.0.

The correspondence is checked BOTH WAYS on purpose. One way alone is a
ratchet that only tightens in the direction someone remembered:

- shipped -> specified catches the real failure mode, a new setting added to
  `default/` and never written down (which is exactly how `ca_file` could have
  landed);
- specified -> shipped catches the other one, a setting documented and then
  removed or renamed, leaving a spec that describes an app that no longer
  exists.

The spec is parsed here by an explicit reader of the `.spec` grammar rather
than by `confparser`: a `.spec` is not a `.conf` - its `*` description lines
are content, not residue - and reading it with the wrong parser would make
this test agree with itself instead of with the file.
"""

import os
import re
import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import confparser
from tests import ROOT

SPEC_PATH = os.path.join(ROOT, "README", "confbtool.conf.spec")
CONF_PATH = os.path.join(ROOT, "default", "confbtool.conf")

#: An attribute is declared by its TYPE, never by a value (Splunk convention,
#: charter CH-5.5): `<something>` or an `[a|b|c]` enumeration.
TYPE_FORM = re.compile(r"^(<.+>|\[.+\])$")


def _read_spec(path):
    """`({stanza: {attribute: type}}, {(stanza, attribute): [description]})`.

    Grammar of a `.spec`, line by line: `#` comment, `[stanza]` header,
    `* text` description of whatever was declared last, an INDENTED line
    continuing the description above it (the platform's own spec files wrap
    that way, without repeating the `*`), and `name = <type>` attribute.
    Anything else is a defect of the file and fails the test that walks these
    structures.
    """
    attributes = {}
    descriptions = {}
    stanza = None
    current = None
    open_description = None
    residue = []
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.rstrip("\n").rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                open_description = None
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                stanza = stripped[1:-1]
                attributes.setdefault(stanza, {})
                current = None
                open_description = None
                continue
            if stripped.startswith("*"):
                key = (stanza, current)
                open_description = descriptions.setdefault(key, [])
                open_description.append(stripped[1:].strip())
                continue
            if line[:1] in (" ", "\t") and open_description:
                # Wrapped description line: appended to the sentence above it.
                open_description[-1] += " " + stripped
                continue
            open_description = None
            if "=" in stripped:
                name, _, value = stripped.partition("=")
                current = name.strip()
                attributes.setdefault(stanza, {})[current] = value.strip()
                descriptions.setdefault((stanza, current), [])
                continue
            residue.append((lineno, line))
    return attributes, descriptions, residue


def _read_shipped(path):
    """`{stanza: {key: value}}` of `default/confbtool.conf`, read with the
    app's OWN parser - the one that will read it at run time."""
    with open(path, "rb") as handle:
        text, degraded = confparser.decode_conf_bytes(handle.read())
    shipped = {}
    for definition in confparser.parse_conf_text(text):
        shipped.setdefault(definition.stanza, {})[definition.key] = definition.value
    return shipped, degraded


class ConfSpecTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.spec, cls.descriptions, cls.residue = _read_spec(SPEC_PATH)
        cls.shipped, cls.degraded = _read_shipped(CONF_PATH)

    def test_the_spec_file_is_shipped_with_the_app(self):
        self.assertTrue(
            os.path.isfile(SPEC_PATH),
            "README/confbtool.conf.spec is missing: a conf proper to the app "
            "without a spec is exploitable by nothing",
        )

    def test_the_shipped_conf_decodes_cleanly(self):
        self.assertFalse(self.degraded)

    def test_the_control_is_not_concluding_on_emptiness(self):
        """Calibration: both sides must carry something, or every assertion
        below would pass on two empty files (charter CH-10.3)."""
        self.assertTrue(self.spec, "no stanza parsed out of the spec")
        self.assertTrue(self.shipped, "no stanza parsed out of the shipped conf")
        self.assertGreaterEqual(
            sum(len(keys) for keys in self.spec.values()), 6
        )

    def test_the_spec_carries_no_line_outside_its_grammar(self):
        self.assertEqual(self.residue, [])

    def test_every_shipped_stanza_is_specified(self):
        self.assertEqual(sorted(self.shipped), sorted(self.spec))

    def test_every_shipped_attribute_is_specified(self):
        for stanza, keys in sorted(self.shipped.items()):
            for key in sorted(keys):
                with self.subTest(stanza=stanza, attribute=key):
                    self.assertIn(
                        key, self.spec.get(stanza, {}),
                        "[%s] %s is shipped in default/confbtool.conf but "
                        "absent from README/confbtool.conf.spec" % (stanza, key),
                    )

    def test_every_specified_attribute_is_shipped(self):
        for stanza, keys in sorted(self.spec.items()):
            for key in sorted(keys):
                with self.subTest(stanza=stanza, attribute=key):
                    self.assertIn(
                        key, self.shipped.get(stanza, {}),
                        "[%s] %s is specified but absent from "
                        "default/confbtool.conf" % (stanza, key),
                    )

    def test_no_attribute_of_the_spec_carries_a_value(self):
        """A `.spec` declares a TYPE. A value assigned here is ignored by the
        platform and invites a reader to configure the app in the wrong file
        (charter CH-5.5)."""
        for stanza, keys in sorted(self.spec.items()):
            for key, declared in sorted(keys.items()):
                with self.subTest(stanza=stanza, attribute=key):
                    self.assertRegex(declared, TYPE_FORM)

    def test_every_specified_attribute_is_described(self):
        for stanza, keys in sorted(self.spec.items()):
            for key in sorted(keys):
                with self.subTest(stanza=stanza, attribute=key):
                    self.assertTrue(
                        self.descriptions.get((stanza, key)),
                        "[%s] %s is declared with no description" % (stanza, key),
                    )

    def test_every_specified_attribute_states_its_default(self):
        for stanza, keys in sorted(self.spec.items()):
            for key in sorted(keys):
                with self.subTest(stanza=stanza, attribute=key):
                    text = " ".join(self.descriptions[(stanza, key)])
                    self.assertIn("Default:", text)

    def test_the_setting_this_release_adds_is_specified(self):
        """Pinned by name: `ca_file` is the setting the 1.4.0 fix introduces,
        and the reason this whole correspondence now has a test."""
        self.assertIn("ca_file", self.spec.get("rest", {}))
        self.assertIn("ca_file", self.shipped.get("rest", {}))


if __name__ == "__main__":
    unittest.main()
