#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`| confbtool` search command - Splunk wrapper, **no business rule here**.

This file does three things and nothing else (spec section 3.1, last block):

1. it inserts `bin/lib` then `bin` at the head of `sys.path`, before any other
   import;
2. it declares the generating command and its options, and rebuilds the
   positional conf list from `self.fieldnames`;
3. it wires the adapters (file system, btool, REST, log) into the `confaudit`
   pipeline and converts the fatal errors into `self.error_exit(...)`.

Every rule - parsing, resolution, btool confrontation, filters, volume guard,
secrets - lives in `bin/confaudit/`, which depends neither on the SDK nor on
the network and is tested outside Splunk.
"""

import os
import sys

# --------------------------------------------------------------------------- #
# sys.path - BEFORE any import of the project or of the SDK (spec section 2.3).
# `bin/lib` first: the vendored SDK takes precedence over the platform's.
# `bin` as well, so that `confaudit` is importable independently of the working
# directory of the search process. Paths derived from `__file__`, never
# absolute (public repository).
# --------------------------------------------------------------------------- #
_BIN = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_BIN, "lib"), _BIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import socket  # noqa: E402

from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)

from confaudit import pipeline  # noqa: E402
from confaudit.applog import open_app_log  # noqa: E402
from confaudit.btoolrun import BtoolRunner  # noqa: E402
from confaudit.errors import FatalError  # noqa: E402
from confaudit.layers import LocalFileSystem, read_app_conf_bytes  # noqa: E402
from confaudit.rest import RestClient  # noqa: E402

_APP_ROOT = os.path.dirname(_BIN)


@Configuration(distributed=False)
class ConfBtoolCommand(GeneratingCommand):
    """Audit the file origin of configuration definitions, like btool --debug.

    ##Syntax

    .. code-block::
        | confbtool <conf|conf,conf|*> [stanza=<pattern>] [key=<pattern>]
                    [app=<pattern>] [audit=<bool>] [debug=<bool>]

    ##Description

    Generating command. Emits one row per configuration definition, with the
    file path, the global precedence rank and the btool winner verdict.
    Requires the run_confbtool capability.

    ##Example

    .. code-block::
        | confbtool authorize app=00_corp_base audit=true
    """

    stanza = Option(
        doc="Stanza filter: literal characters plus the wildcards '*' and "
            "'?'. Default: *.",
        require=False,
        default=None,
    )
    key = Option(
        doc="Key filter: literal characters plus the wildcards '*' and '?'. "
            "Default: *.",
        require=False,
        default=None,
    )
    app = Option(
        doc="App filter: restricts to keys carried by the matching app(s); "
            "with audit=true it extrapolates to every concurrent definition "
            "of those keys. Default: absent.",
        require=False,
        default=None,
    )
    audit = Option(
        doc="true: emit every concurrent definition, winners and shadowed. "
            "Default: false (winners only).",
        require=False,
        default=False,
        validate=validators.Boolean(),
    )
    debug = Option(
        doc="true (default): fill file_path on every row.",
        require=False,
        default=True,
        validate=validators.Boolean(),
    )

    def generate(self):
        try:
            rows = self._run()
        except FatalError as exc:
            self.error_exit(exc, str(exc))
            return
        for row in rows:
            yield row

    def _run(self):
        """Wire the adapters and call the pipeline - wiring only."""
        info = self._metadata.searchinfo
        session_key = str(getattr(info, "session_key", "") or "")
        splunkd_uri = str(getattr(info, "splunkd_uri", "") or "")
        # $SPLUNK_HOME is read from the environment of the search process
        # (spec section 5.1).
        splunk_home = os.environ.get("SPLUNK_HOME", "")

        default_data, local_data = read_app_conf_bytes(_APP_ROOT)
        settings = pipeline.load_settings(default_data, local_data)

        log_dir = (
            os.path.join(splunk_home, "var", "log", "splunk")
            if splunk_home else ""
        )
        log = open_app_log(log_dir, settings.log_level)
        if log is None:
            # Single warning, execution carries on: the log is a diagnostic
            # comfort, not a safety net (spec section 11).
            self.write_warning(
                "confbtool: could not open sa_conf_audit.log; the run "
                "continues without a log file."
            )

        ca_file = None
        if settings.verify_ssl and splunk_home:
            candidate = os.path.join(splunk_home, "etc", "auth", "cacert.pem")
            if os.path.exists(candidate):
                ca_file = candidate
        if not settings.verify_ssl:
            self.write_warning(
                "confbtool: verify_ssl=false: verification of the splunkd "
                "certificate is disabled by local/confbtool.conf."
            )

        rest = RestClient(
            splunkd_uri, session_key,
            verify_ssl=settings.verify_ssl, ca_file=ca_file,
        )
        member = rest.get_server_name() or socket.gethostname()
        file_system = LocalFileSystem(splunk_home)

        return pipeline.run(
            fs=file_system,
            btool=BtoolRunner(splunk_home),
            rest=rest,
            fieldnames=list(self.fieldnames or []),
            stanza=self.stanza,
            key=self.key,
            app=self.app,
            audit=bool(self.audit),
            debug=bool(self.debug),
            settings=settings,
            member=member,
            etc_prefix=file_system.etc_root,
            log=log,
        )


dispatch(ConfBtoolCommand, sys.argv, sys.stdin, sys.stdout, __name__)
