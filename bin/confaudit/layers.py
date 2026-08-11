"""FsPort implementation: layer enumeration and file reading (spec section 5.1).

The ONLY module of the package, with `applog.py`, allowed to touch the disk
(layer rule of spec section 1.3, enforced by `tests/test_layering.py`).
"""

import os

from .model import LayerFile


class LocalFileSystem:
    """Enumerates the four btool layers under `$SPLUNK_HOME/etc`.

    For a conf `<c>`, the candidate files are exactly (depth 1 of each
    directory):

        etc/system/local/<c>.conf
        etc/apps/<app>/local/<c>.conf      (for each app present on disk)
        etc/apps/<app>/default/<c>.conf    (idem)
        etc/system/default/<c>.conf

    `etc/users` is EXCLUDED (D-1: btool in global context ignores the user
    layer, M-1). Every app present on disk is enumerated, with NO filtering on
    its activation state (reserve R-7, accepted by D-14: the confrontation
    would signal a divergence). Symbolic links are resolved by the OS, with no
    special treatment.
    """

    def __init__(self, splunk_home=None):
        home = splunk_home or os.environ.get("SPLUNK_HOME", "")
        self.etc_root = os.path.join(home, "etc")
        self._apps_root = os.path.join(self.etc_root, "apps")

    # -- FsPort ---------------------------------------------------------- #

    def list_conf_names(self):
        """Distinct conf names (no extension), union of the four layers."""
        names = set()
        for directory in self._layer_directories():
            names.update(self._conf_names_in(directory))
        return sorted(names)

    def list_layer_files(self, conf):
        """The existing candidate files of a conf, one per `(scope, app,
        layer)`. Order is irrelevant: the resolver sorts by precedence."""
        filename = conf + ".conf"
        out = []
        path = os.path.join(self.etc_root, "system", "local", filename)
        if os.path.isfile(path):
            out.append(LayerFile("system", "", "local", path))
        for app in self._app_names():
            for layer in ("local", "default"):
                path = os.path.join(self._apps_root, app, layer, filename)
                if os.path.isfile(path):
                    out.append(LayerFile("app", app, layer, path))
        path = os.path.join(self.etc_root, "system", "default", filename)
        if os.path.isfile(path):
            out.append(LayerFile("system", "", "default", path))
        return out

    def read_bytes(self, path):
        """Raw bytes of a file; `OSError` propagates - the pipeline turns it
        into a `parse_error` row (spec section 4.6)."""
        with open(path, "rb") as handle:
            return handle.read()

    # -- internals ------------------------------------------------------- #

    def _layer_directories(self):
        yield os.path.join(self.etc_root, "system", "local")
        yield os.path.join(self.etc_root, "system", "default")
        for app in self._app_names():
            yield os.path.join(self._apps_root, app, "local")
            yield os.path.join(self._apps_root, app, "default")

    def _app_names(self):
        try:
            entries = sorted(os.listdir(self._apps_root))
        except OSError:
            return []
        return [
            name for name in entries
            if os.path.isdir(os.path.join(self._apps_root, name))
        ]

    @staticmethod
    def _conf_names_in(directory):
        try:
            entries = os.listdir(directory)
        except OSError:
            return []
        return [
            name[:-5] for name in entries
            if name.endswith(".conf")
            and os.path.isfile(os.path.join(directory, name))
        ]


def read_app_conf_bytes(app_root):
    """Bytes of the app's own `confbtool.conf` layers: `(default, local)`,
    `None` for an absent layer. The parsing itself is pure
    (`pipeline.load_settings`)."""
    out = []
    for layer in ("default", "local"):
        path = os.path.join(app_root, layer, "confbtool.conf")
        try:
            with open(path, "rb") as handle:
                out.append(handle.read())
        except OSError:
            out.append(None)
    return tuple(out)
