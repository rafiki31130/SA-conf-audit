"""RestPort implementation: loopback splunkd REST calls (spec section 10).

The ONLY module of the package allowed to import `urllib.request`, `ssl` and
`http` (layer rule of spec section 1.3, enforced by `tests/test_layering.py`).

The session key never appears in any log, error message or URL: it only lives
in the `Authorization` header, and every failure comes back as `None` - the
caller (pipeline section 10) never presumes the authorization on an impossible
check.
"""

import json
import ssl
import urllib.request

#: Module constants (spec section 3.1). `urllib` applies a single timeout to
#: the whole exchange; the read timeout, the larger of the two, is passed.
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 30


class RestClient:
    """Minimal splunkd client: capability list and serverName."""

    def __init__(self, splunkd_uri, session_key, verify_ssl=True, ca_file=None):
        self._base = (splunkd_uri or "").rstrip("/")
        self._session_key = session_key or ""
        self._context = self._build_context(verify_ssl, ca_file)

    @staticmethod
    def _build_context(verify_ssl, ca_file):
        """TLS context per `[rest] verify_ssl` (spec section 2.2).

        `verify_ssl=true`: chain verified against the provided CA file
        (`$SPLUNK_HOME/etc/auth/cacert.pem`), hostname check disabled - the
        splunkd URI is a loopback address and the default Splunk certificates
        carry no matching SAN. `verify_ssl=false`: no verification (the
        wrapper emits a single startup warning).
        """
        if verify_ssl:
            context = ssl.create_default_context(cafile=ca_file)
            context.check_hostname = False
            return context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _get_json(self, path):
        """GET a splunkd endpoint; `None` on ANY failure - no network
        exception ever propagates out of this module (spec section 3.1)."""
        request = urllib.request.Request(
            self._base + path,
            headers={"Authorization": "Splunk %s" % self._session_key},
        )
        try:
            with urllib.request.urlopen(
                request, timeout=READ_TIMEOUT_SECONDS, context=self._context,
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - converted into an error result
            return None

    # -- RestPort -------------------------------------------------------- #

    def get_capabilities(self):
        """Capabilities of the current context, roles cumulated - `None` when
        the check itself failed (spec section 10)."""
        document = self._get_json(
            "/services/authentication/current-context?output_mode=json"
        )
        try:
            return frozenset(document["entry"][0]["content"]["capabilities"])
        except (TypeError, KeyError, IndexError):
            return None

    def get_server_name(self):
        """`serverName` of the member, `None` when unavailable (the wrapper
        falls back to the local hostname)."""
        document = self._get_json("/services/server/info?output_mode=json")
        try:
            name = document["entry"][0]["content"]["serverName"]
        except (TypeError, KeyError, IndexError):
            return None
        return name or None
