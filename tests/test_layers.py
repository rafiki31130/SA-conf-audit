"""`layers.py` adapter - disabled-app exclusion (reserve R-7).

The rule was measured against the real btool 9.4.6 (lab acceptance,
2026-08-12): an app takes part in the resolution if and only if its
`[install] state`, resolved on the app's own `app.conf` layers (`local` over
`default`), is absent or equals exactly `enabled`. Any other value - case
variants and unknown values included - excludes the app.

These tests exercise the adapter on a temporary directory: no Splunk, no
network (contract of spec section 12).
"""

import os
import shutil
import tempfile
import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit.layers import LocalFileSystem


def _write(root, *relative_and_content):
    *relative, content = relative_and_content
    path = os.path.join(root, *relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


class DisabledAppExclusionTest(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        self.apps = os.path.join(self.home, "etc", "apps")

    def _fs(self):
        return LocalFileSystem(splunk_home=self.home)

    def _add_app(self, name, app_conf=None, layer="local"):
        _write(self.apps, name, "local", "probe.conf", "[s]\nk = v\n")
        if app_conf is not None:
            _write(self.apps, name, layer, "app.conf", app_conf)

    def _apps_seen(self):
        return [f.app for f in self._fs().list_layer_files("probe")]

    def test_app_without_app_conf_is_enabled(self):
        self._add_app("plain_app")
        self.assertEqual(self._apps_seen(), ["plain_app"])

    def test_state_enabled_is_enabled(self):
        self._add_app("on_app", "[install]\nstate = enabled\n")
        self.assertEqual(self._apps_seen(), ["on_app"])

    def test_state_disabled_is_excluded(self):
        self._add_app("off_app", "[install]\nstate = disabled\n")
        self.assertEqual(self._apps_seen(), [])

    def test_state_disabled_in_default_layer_is_excluded(self):
        self._add_app("off_app", "[install]\nstate = disabled\n",
                      layer="default")
        self.assertEqual(self._apps_seen(), [])

    def test_local_enabled_overrides_default_disabled(self):
        self._add_app("mixed_app", "[install]\nstate = disabled\n",
                      layer="default")
        _write(self.apps, "mixed_app", "local", "app.conf",
               "[install]\nstate = enabled\n")
        self.assertEqual(self._apps_seen(), ["mixed_app"])

    def test_case_variant_excludes(self):
        # Measured: `state = Enabled` and `state = Disabled` both exclude -
        # the comparison is case-sensitive on the exact value `enabled`.
        self._add_app("cased_app", "[install]\nstate = Enabled\n")
        self.assertEqual(self._apps_seen(), [])

    def test_unknown_value_excludes(self):
        self._add_app("odd_app", "[install]\nstate = foo\n")
        self.assertEqual(self._apps_seen(), [])

    def test_conf_names_of_a_disabled_app_are_not_enumerated(self):
        self._add_app("off_app", "[install]\nstate = disabled\n")
        self.assertEqual(self._fs().list_conf_names(), [])


if __name__ == "__main__":
    unittest.main()
