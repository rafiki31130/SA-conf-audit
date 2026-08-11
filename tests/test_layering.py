"""Layer separation: the import rule of spec section 1.3, checked mechanically.

Without this test the rule is nothing but an intention in a comment: one import
hastily added to a core module is enough to stop the whole contract of
section 12 - testable outside Splunk, without network - from being provable.

The rule (spec section 1.3): no file of `bin/confaudit/` mentions `splunklib`;
`subprocess` only appears in `btoolrun.py`; `urllib.request`/`ssl`/`http` only
in `rest.py`; disk access (`open`, `os.walk`, `glob`, `os.listdir`, `os.stat`)
only in `layers.py` and `applog.py`.
"""

import ast
import os
import unittest

from tests import BIN_DIR

PACKAGE_DIR = os.path.join(BIN_DIR, "confaudit")

#: The only module allowed to spawn a process.
SUBPROCESS_MODULE = "btoolrun.py"

#: The only module allowed to speak HTTP/TLS.
NETWORK_MODULE = "rest.py"

#: The modules allowed to touch the disk.
DISK_MODULES = ("layers.py", "applog.py")

#: Network imports forbidden outside NETWORK_MODULE. `urllib.parse` would be
#: string computation and stays allowed; the network branches are proscribed.
NETWORK_IMPORTS = ("socket", "http", "urllib.request", "urllib.error", "ssl")

#: Disk-access call names forbidden outside DISK_MODULES.
DISK_CALLS = ("open", "os.walk", "glob.glob", "glob.iglob", "os.listdir",
              "os.stat", "os.scandir")

#: Text pattern forbidden in the whole package: the SDK has no place in the
#: library. The name is reassembled so this test file is not a counter-example.
SDK_PATTERN = "splunk" + "lib"

#: Standard-library allowlist for the whole package (third-party forbidden).
ALLOWED_MODULES = {
    "ast", "dataclasses", "hashlib", "json", "logging", "logging.handlers",
    "os", "re", "ssl", "subprocess", "sys", "time", "typing",
    "urllib", "urllib.request", "urllib.error", "urllib.parse",
    "collections", "collections.abc",
}


def _python_files():
    for name in sorted(os.listdir(PACKAGE_DIR)):
        if name.endswith(".py"):
            yield name, os.path.join(PACKAGE_DIR, name)


def _tree(path):
    with open(path, encoding="utf-8") as handle:
        return ast.parse(handle.read(), filename=path)


def _imported_modules(path):
    modules = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module)
    return modules


def _called_names(path):
    names = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            try:
                names.add(ast.unparse(node.func))
            except Exception:  # noqa: BLE001 - unparseable calls are irrelevant
                pass
    return names


class LayeringTest(unittest.TestCase):

    def test_the_package_exists_with_its_fourteen_modules(self):
        names = [name for name, _ in _python_files()]
        expected = [
            "__init__.py", "applog.py", "btoolparser.py", "btoolrun.py",
            "confparser.py", "confront.py", "errors.py", "filters.py",
            "layers.py", "model.py", "pipeline.py", "resolver.py",
            "rest.py", "secrets.py", "volume.py",
        ]
        self.assertEqual(names, expected)

    def test_no_file_of_the_package_mentions_the_sdk(self):
        for name, path in _python_files():
            with self.subTest(module=name):
                with open(path, encoding="utf-8") as handle:
                    self.assertNotIn(
                        SDK_PATTERN, handle.read(),
                        "%s mentions the SDK: the library must stay "
                        "importable without it" % name,
                    )

    def test_subprocess_confined_to_btoolrun(self):
        for name, path in _python_files():
            if name == SUBPROCESS_MODULE:
                continue
            with self.subTest(module=name):
                modules = _imported_modules(path)
                self.assertNotIn("subprocess", {m.split(".")[0] for m in modules})

    def test_network_confined_to_rest(self):
        for name, path in _python_files():
            if name == NETWORK_MODULE:
                continue
            with self.subTest(module=name):
                modules = _imported_modules(path)
                offenders = []
                for module in modules:
                    root = module.split(".")[0]
                    for forbidden in NETWORK_IMPORTS:
                        if module == forbidden or module.startswith(forbidden + "."):
                            offenders.append(module)
                        elif root == forbidden and forbidden != "urllib":
                            offenders.append(module)
                    if module == "urllib":
                        offenders.append(module)
                offenders = [m for m in offenders if not m.startswith("urllib.parse")]
                self.assertEqual(
                    offenders, [],
                    "%s imports %r: the network is confined to "
                    "confaudit/rest.py" % (name, offenders),
                )

    def test_disk_access_confined_to_layers_and_applog(self):
        for name, path in _python_files():
            if name in DISK_MODULES:
                continue
            with self.subTest(module=name):
                offenders = sorted(
                    called for called in _called_names(path)
                    if called in DISK_CALLS
                )
                self.assertEqual(
                    offenders, [],
                    "%s calls %r: disk access is confined to layers.py and "
                    "applog.py" % (name, offenders),
                )

    def test_only_the_standard_library_is_imported(self):
        for name, path in _python_files():
            with self.subTest(module=name):
                for module in _imported_modules(path):
                    root = module.split(".")[0]
                    if root == "confaudit":
                        continue
                    self.assertIn(
                        module if module in ALLOWED_MODULES else root,
                        ALLOWED_MODULES,
                        "%s imports %r, outside the allowed standard library"
                        % (name, module),
                    )

    def test_the_core_imports_without_bin_lib_on_the_path(self):
        """The tests never insert `bin/lib` into `sys.path`: the mere fact
        that the suite runs proves the core does not depend on the vendored
        SDK (spec section 2.3)."""
        import sys

        self.assertNotIn(os.path.join(BIN_DIR, "lib"), sys.path)

        import confaudit.btoolparser  # noqa: F401
        import confaudit.confparser  # noqa: F401
        import confaudit.confront  # noqa: F401
        import confaudit.filters  # noqa: F401
        import confaudit.pipeline  # noqa: F401
        import confaudit.resolver  # noqa: F401
        import confaudit.secrets  # noqa: F401
        import confaudit.volume  # noqa: F401

    def test_the_wrapper_compiles_and_inserts_syspath_before_the_sdk(self):
        """`bin/confbtool.py` is not importable without the SDK - which is the
        point - but it must compile, and its `sys.path` insertion must come
        before the first SDK import (spec section 2.3)."""
        path = os.path.join(BIN_DIR, "confbtool.py")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        compile(source, path, "exec")

        tree = ast.parse(source, filename=path)
        syspath_line = None
        sdk_line = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and syspath_line is None:
                if ast.unparse(node.func) == "sys.path.insert":
                    syspath_line = node.lineno
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith(SDK_PATTERN) and sdk_line is None:
                    sdk_line = node.lineno
        self.assertIsNotNone(syspath_line, "no insertion into sys.path")
        self.assertIsNotNone(sdk_line, "no import of the SDK")
        self.assertLess(
            syspath_line, sdk_line,
            "bin/lib must be at the head of sys.path BEFORE the first SDK import",
        )

    def test_the_wrapper_carries_no_business_rule(self):
        """The wrapper wires, it does not decide: none of the decision
        functions of the core is redefined there (spec section 3.1)."""
        path = os.path.join(BIN_DIR, "confbtool.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        defined = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        forbidden = {
            "parse_conf_text", "decode_conf_bytes", "resolve",
            "parse_btool_output", "deexpand", "confront", "select",
            "validate_params", "parse_conf_argument", "check", "hash_value",
            "parse_encrypt_fields", "load_settings",
        }
        self.assertEqual(defined & forbidden, set())


if __name__ == "__main__":
    unittest.main()
