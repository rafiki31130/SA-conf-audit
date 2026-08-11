"""In-memory ports and fixture builders (spec section 1.4).

The fake ports are plain objects, no mock library. Every fixture is synthetic
and anonymized: generic app names (`00_corp_base`, `zz_sample_app`), generic
paths (`/opt/splunk/etc`), never a capture of a real environment.
"""

from confaudit.model import BtoolResult, LayerFile

#: Generic etc prefix used by every in-memory fixture.
ETC = "/opt/splunk/etc"


class FakeFs:
    """FsPort backed by a dict - `(scope, app, layer, conf)` -> bytes."""

    def __init__(self, etc_root=ETC):
        self.etc_root = etc_root
        self._files = {}
        self._layers = {}
        self.unreadable = set()
        self.read_paths = []

    def add(self, scope, app, layer, conf, data):
        """Register one layer file; returns its (virtual) path."""
        if scope == "system":
            path = "%s/system/%s/%s.conf" % (self.etc_root, layer, conf)
        else:
            path = "%s/apps/%s/%s/%s.conf" % (self.etc_root, app, layer, conf)
        self._files[path] = data if isinstance(data, bytes) else data.encode("utf-8")
        self._layers.setdefault(conf, []).append(LayerFile(scope, app, layer, path))
        return path

    def path_of(self, scope, app, layer, conf):
        if scope == "system":
            return "%s/system/%s/%s.conf" % (self.etc_root, layer, conf)
        return "%s/apps/%s/%s/%s.conf" % (self.etc_root, app, layer, conf)

    # -- FsPort ---------------------------------------------------------- #

    def list_conf_names(self):
        return sorted(self._layers)

    def list_layer_files(self, conf):
        return list(self._layers.get(conf, []))

    def read_bytes(self, path):
        self.read_paths.append(path)
        if path in self.unreadable:
            raise OSError("permission denied: %s" % path)
        return self._files[path]


class FakeBtool:
    """BtoolPort backed by a dict - conf -> output text or `BtoolResult`."""

    def __init__(self, outputs=None):
        self.outputs = dict(outputs or {})
        self.calls = []

    def run(self, conf):
        self.calls.append(conf)
        value = self.outputs.get(conf, "")
        if isinstance(value, BtoolResult):
            return value
        return BtoolResult(returncode=0, stdout=value, error=None)


class FakeRest:
    """RestPort with a fixed capability set and server name."""

    def __init__(self, capabilities=frozenset(("run_confbtool",)),
                 server_name="member-01"):
        self.capabilities = capabilities
        self.server_name = server_name

    def get_capabilities(self):
        return self.capabilities

    def get_server_name(self):
        return self.server_name


class CollectingLog:
    """Log port that records every message, for content assertions."""

    def __init__(self):
        self.messages = []

    def _record(self, level, args):
        self.messages.append((level, args[0] if args else ""))

    def debug(self, *args):
        self._record("DEBUG", args)

    def info(self, *args):
        self._record("INFO", args)

    def warning(self, *args):
        self._record("WARNING", args)

    def error(self, *args):
        self._record("ERROR", args)

    def all_text(self):
        return "\n".join(message for _, message in self.messages)


def build_btool_output(entries):
    """Build a `btool --debug` output conforming to the M-3 format.

    `entries` is an ordered list of `(path, text)` where `text` is either
    `[stanza]` (header) or `key = value`; a value containing `\\n` produces
    continuation lines WITHOUT path prefix, exactly as btool restitutes a
    source `\\` continuation (M-3d).

    The path column is left-aligned, padded to the longest path present in
    THIS output, plus one separator space - the width therefore varies from
    one output to the next (M-3e), which is what the parser tests exercise.
    """
    width = max(len(path) for path, _ in entries)
    lines = []
    for path, text in entries:
        head, *continuations = text.split("\n")
        lines.append(path.ljust(width) + " " + head)
        lines.extend(continuations)
    return "\n".join(lines) + "\n"
