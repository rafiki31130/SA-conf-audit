"""FsPort implementation: layer enumeration and file reading (spec section 5.1).

The ONLY module of the package, with `applog.py`, allowed to touch the disk
(layer rule of spec section 1.3, enforced by `tests/test_layering.py`).
"""

import os

from .confparser import decode_conf_bytes, parse_conf_text
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
    layer, M-1). Disabled apps are EXCLUDED: reserve R-7 was settled
    empirically against the real btool 9.4.6 (lab acceptance, 2026-08-12,
    adjustment planned by D-14) - btool ignores an app whose `[install] state`
    does not resolve to exactly `enabled` (see `_app_enabled`). Symbolic links
    are resolved by the OS, with no special treatment.
    """

    def __init__(self, splunk_home=None):
        home = splunk_home or os.environ.get("SPLUNK_HOME", "")
        self.etc_root = os.path.join(home, "etc")
        self._apps_root = os.path.join(self.etc_root, "apps")
        self._app_names_cache = None

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
        if self._app_names_cache is None:
            try:
                entries = sorted(os.listdir(self._apps_root))
            except OSError:
                entries = []
            self._app_names_cache = [
                name for name in entries
                if os.path.isdir(os.path.join(self._apps_root, name))
                and self._app_enabled(name)
            ]
        return self._app_names_cache

    def _app_enabled(self, app):
        """btool participation rule, measured on 9.4.6 (lab acceptance, R-7).

        An app takes part in the btool resolution if and only if its
        `[install] state` - resolved on the app's own `app.conf` layers,
        `local` over `default` - is absent (absent file, stanza or key means
        enabled) or equals exactly `enabled`. Any other value excludes the
        app: `disabled`, of course, but also case variants (`Enabled`,
        `Disabled`) and unknown values (`foo`), all measured as excluding.
        """
        state = None
        for layer in ("default", "local"):
            path = os.path.join(self._apps_root, app, layer, "app.conf")
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            text, _ = decode_conf_bytes(data)
            for definition in parse_conf_text(text):
                if definition.stanza == "install" and definition.key == "state":
                    state = definition.value
        return state is None or state == "enabled"

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
