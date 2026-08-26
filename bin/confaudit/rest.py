"""RestPort implementation: loopback splunkd REST calls (spec section 10).

The ONLY module of the package allowed to import `urllib.request`, `ssl` and
`http` (layer rule of spec section 1.3, enforced by `tests/test_layering.py`).
It never touches the DISK either: the `.conf` bytes it needs are handed over by
`layers.py`, and the existence check of a CA file is an injected predicate
(`os.path.isfile`, wired by the wrapper). That is what keeps the whole CA
resolution unit-testable with no file system at all.

Two contracts hold here:

- the session key never appears in any log, error message or URL: it only
  lives in the `Authorization` header;
- no network exception ever escapes the module - but, since 1.4.0, a failed
  exchange no longer collapses into a bare `None`. It comes back as a
  `RestFailure` that NAMES its cause, which is what lets the pipeline tell a
  missing right from an impossible check (spec section 10). Collapsing the
  two was the 1.3.0 defect: a splunkd certificate signed by an enterprise CA
  produced the message about rights, and the rights were never the problem.
"""

import json
import ssl
import urllib.error
import urllib.request

from . import confparser, normalize
from .model import CaResolution, RestFailure

#: Module constants (spec section 3.1). `urllib` applies a single timeout to
#: the whole exchange; the read timeout, the larger of the two, is passed.
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 30

#: The two endpoints of the port.
CURRENT_CONTEXT_PATH = "/services/authentication/current-context?output_mode=json"
SERVER_INFO_PATH = "/services/server/info?output_mode=json"

# --------------------------------------------------------------------------- #
# CA store resolution (spec section 2.2; charter CH-9.13, CH-9.14, CH-9.19).
#
# CH-9.19 asks that the retained resolution path be NAMED and that the
# forbidden ones be named with their failure mode. Retained, strongest first:
# `[rest] ca_file`, then `server.conf [sslConfig] sslRootCAPath`, then Splunk's
# own truststore. Forbidden, and why:
#
# - hardcoding `$SPLUNK_HOME/etc/auth/cacert.pem` as the ONLY store (what
#   1.3.0 did): on any member whose splunkd certificate was replaced by an
#   enterprise one, the chain is not in that file and every verification
#   fails - while the information needed sits in `server.conf`, unread;
# - leaning on the vendored SDK's REST client for the TLS layer: its default
#   is `verify=False`, so it would trade a broken verification for no
#   verification at all. `urllib` + `ssl` is used directly, here and nowhere
#   else.
# --------------------------------------------------------------------------- #

#: Human labels of the resolution paths, quoted verbatim in the diagnostic.
CA_SOURCE_SETTING = "[rest] ca_file of the app's confbtool.conf"
CA_SOURCE_SERVER_CONF = "server.conf [sslConfig] sslRootCAPath"
CA_SOURCE_SPLUNK_DEFAULT = "the Splunk truststore $SPLUNK_HOME/etc/auth/cacert.pem"
CA_SOURCE_SYSTEM_STORE = "the platform's default trust store"

#: Where the instance declares its trust anchor.
SSL_STANZA = "sslConfig"
SSL_KEY = "sslRootCAPath"

#: Splunk's own truststore, relative to `$SPLUNK_HOME` - the fallback, and the
#: only path 1.3.0 knew about.
SPLUNK_CA_RELATIVE = "etc/auth/cacert.pem"

# --------------------------------------------------------------------------- #
# Failure taxonomy. `kind` is the machine handle a test asserts on; the
# messages name the class of cause and the parameter in play, and never a
# value (charter CH-4.12, CH-9.4).
# --------------------------------------------------------------------------- #

#: Machine handles of a CONFIGURED store the resolution refuses outright.
#: Carried by `CaResolution.refusal`, turned into a message by
#: `_refusal_failure`. Distinct from `exists=False`, which describes a path
#: that is well formed and simply not there.
REFUSAL_EMPTY = "empty_after_expansion"
REFUSAL_NO_HOME = "splunk_home_unknown"
REFUSAL_TRAVERSAL = "escapes_its_anchor"

FAILURE_TLS = "tls_verification_failed"
FAILURE_CA_FILE = "ca_store_unusable"
FAILURE_AUTH = "authentication_refused"
FAILURE_TIMEOUT = "timeout"
FAILURE_UNREADABLE = "unreadable_answer"
FAILURE_HTTP = "http_error"
FAILURE_NETWORK = "endpoint_unreachable"

#: Names TLS, names the CA store actually used, and names the file to edit -
#: the three things that turn this failure into an immediate diagnosis
#: (CH-9.13). `%s` = store, resolution path.
TLS_MESSAGE = (
    "TLS verification of the splunkd certificate failed against the CA store "
    "%s, resolved from %s. If splunkd carries an enterprise certificate, "
    "declare its CA in server.conf [sslConfig] sslRootCAPath, or point "
    "[rest] ca_file of SA-conf-audit/local/confbtool.conf at it"
)

#: A store that was configured but cannot be used at all. Distinct from
#: `TLS_MESSAGE`: nothing was even attempted, and the fix is a path, not a
#: chain of trust. `%s` = store, resolution path.
CA_FILE_MESSAGE = (
    "the CA store %s, resolved from %s, is missing or unusable, so the "
    "splunkd certificate could not even be checked against it. Fix that path, "
    "or point [rest] ca_file of SA-conf-audit/local/confbtool.conf at a "
    "readable CA bundle"
)

#: A store that WAS configured and whose path resolves to nothing at all.
#: Handing `cafile=None` to `ssl` there would anchor the verification on the
#: platform's default trust store while every message kept naming the setting:
#: the silent fallback this whole resolution exists to forbid. `%s` =
#: resolution path.
CA_EMPTY_MESSAGE = (
    "the CA store configured through %s resolves to an empty path, so no "
    "store could be anchored. The check is refused rather than falling back "
    "to the platform's default trust store: a verification anchored somewhere "
    "nobody chose is worse than a loud refusal. Give an absolute path"
)

#: The same family, caught one step earlier: the path is WRITTEN against
#: `$SPLUNK_HOME` and `$SPLUNK_HOME` is not in the environment of the search
#: process. Expanding the variable to nothing would silently re-anchor the
#: store on the file system root - `$SPLUNK_HOME/etc/auth/x.pem` becoming
#: `/etc/auth/x.pem` - or leave nothing at all. Neither is the path anybody
#: wrote. `%s` = resolution path.
CA_NO_HOME_MESSAGE = (
    "the CA store configured through %s is written against $SPLUNK_HOME, and "
    "$SPLUNK_HOME is not set in the environment of the search process, so the "
    "path cannot be resolved. The check is refused rather than anchoring the "
    "verification on a path nobody configured. Give an absolute path"
)

#: A RELATIVE declaration whose `..` segments climb above the anchor the
#: contract gives it. `%s` = resolution path.
CA_TRAVERSAL_MESSAGE = (
    "the CA store configured through %s is a relative path that climbs above "
    "$SPLUNK_HOME through its parent segments. A relative path is anchored on "
    "$SPLUNK_HOME and may not leave it; give an absolute path if the store "
    "really lives outside the installation"
)

#: Refusal handle -> sentence. `%s` = resolution path, in every entry.
REFUSAL_MESSAGES = {
    REFUSAL_EMPTY: CA_EMPTY_MESSAGE,
    REFUSAL_NO_HOME: CA_NO_HOME_MESSAGE,
    REFUSAL_TRAVERSAL: CA_TRAVERSAL_MESSAGE,
}

AUTH_MESSAGE = (
    "splunkd refused the authentication of the search's session key "
    "(HTTP %s); the capability could not be read"
)

TIMEOUT_MESSAGE = "splunkd did not answer within %d seconds"

UNREADABLE_MESSAGE = (
    "the splunkd answer on %s could not be read as the expected JSON document"
)

HTTP_MESSAGE = "splunkd answered HTTP %s on %s"

NETWORK_MESSAGE = "the splunkd endpoint could not be reached (%s)"

#: Network cause -> stable label, keyed by the exception CLASS name (CH-4.12).
#: The platform's own text never reaches the operator: `[WinError 3] Le chemin
#: d'acces specifie est introuvable` is localised, it changes between releases
#: of the runtime, and it can quote a host or a path the message was never
#: meant to disclose. A class name is a Python identifier - stable and
#: translated nowhere - and this table is the single place that turns one into
#: a sentence an operator can act on.
NETWORK_REASONS = {
    "ConnectionRefusedError": "the endpoint refused the connection",
    "ConnectionResetError": "the endpoint reset the connection",
    "ConnectionAbortedError": "the connection was aborted",
    "BrokenPipeError": "the connection was closed mid-exchange",
    #: `socket.gaierror` / `socket.herror`, by name: `socket` is kept out of
    #: the package by the layering rule, exactly as `_is_timeout` does.
    "gaierror": "the host of the splunkd address could not be resolved",
    "herror": "the host of the splunkd address could not be resolved",
    "PermissionError": "the operating system refused the outgoing connection",
    "ValueError": "the splunkd address is not a usable URL",
}

#: Every cause the table does not name. It deliberately says nothing about the
#: platform: an unlisted cause is one we have not qualified, and saying so is
#: more honest - and more actionable - than quoting a sentence written by the
#: operating system.
NETWORK_REASON_DEFAULT = "no connection to the endpoint could be established"


def read_ssl_root_ca_path(default_data, local_data):
    """`server.conf [sslConfig] sslRootCAPath`, `local` winning over `default`.

    Pure. The bytes of the two SYSTEM layers are read by the `layers` adapter
    (`read_system_conf_bytes`) and parsed HERE by the library's own parser:
    the project has exactly one `.conf` parser and this is it - a second one
    would drift from the first on the very tolerances that were measured
    against btool (spec section 4).

    Returns `None` when neither layer carries the key.
    """
    value = None
    for data in (default_data, local_data):
        if data is None:
            continue
        text, _ = confparser.decode_conf_bytes(data)
        for raw in confparser.parse_conf_text(text):
            if raw.stanza == SSL_STANZA and raw.key == SSL_KEY:
                value = raw.value
    return value


def _split_root(path):
    """`(root, remainder)` - the leading absolute prefix, and what follows.

    The root is kept VERBATIM rather than rebuilt: a drive letter, a UNC
    double separator and a POSIX leading slash are three different things and
    only the original spelling says which one is meant.
    """
    if len(path) >= 3 and path[1] == ":" and path[2] in ("/", "\\"):
        return path[:3], path[3:]
    if path[:2] in ("//", "\\\\"):
        return path[:2], path[2:]
    if path[:1] in ("/", "\\"):
        return path[:1], path[1:]
    return "", path


def normalize_ca_path(path):
    """`path` normalised the way its consumer reads it (CH-9.18).

    Returns `(normalised, escapes)`. `escapes` counts the `..` segments that
    climbed past the head of the path - past `$SPLUNK_HOME` for the relative
    form the contract anchors there, past the root for an absolute one.

    Segment by segment, never by an anchored regular expression: `.`, an empty
    segment (a doubled separator) and `..` are resolved exactly as the file
    system resolves them, so the path this function returns designates the
    same resource as the string handed to `ssl` - because it IS that string.
    A guard that normalises differently from the component it protects
    validates one spelling and lets another through, which is the whole reason
    the rule exists.

    Two deliberate non-normalisations, both of them "like the consumer":

    - percent sequences are NOT decoded. `ssl` and OpenSSL do not decode them
      either, so `x%2Fy` is one segment named `x%2Fy`, and treating it as a
      separator would invent a traversal the file system will never perform;
    - the case of the segments is left alone. Nothing here compares a path to
      an allow-list, so folding case would only lose information.

    A backslash counts as a separator on every platform. On Linux it is a
    legal file name character, so this is stricter than the local file system
    - but it is the spelling `_is_absolute` and `_join` already use in this
    module, and being stricter can only turn a store into a refusal, never a
    refusal into a store.
    """
    root, remainder = _split_root(path)
    separator = "\\" if ("\\" in path and "/" not in path) else "/"
    kept = []
    escapes = 0
    for segment in remainder.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if kept:
                kept.pop()
            else:
                escapes += 1
            continue
        kept.append(segment)
    return root + separator.join(kept), escapes


def expand_ca_path(raw, splunk_home):
    """A CA path as written in a conf file, turned into a usable path.

    Returns `(path, escapes)`; `escapes` is the count `normalize_ca_path`
    reports, non-zero when the declaration climbs above its anchor.

    `$SPLUNK_HOME` is expanded to its runtime value - `server.conf` ships
    `sslRootCAPath = $SPLUNK_HOME/etc/auth/cacert.pem` in that very spelling -
    then the path is normalised segment by segment, and only then is a
    relative path anchored on `$SPLUNK_HOME`, which is how splunkd reads it.
    The order matters: normalising BEFORE the anchoring is what makes an
    escape visible at all. Anchor first and `../../etc/passwd` becomes
    `/opt/splunk/../../etc/passwd`, which normalises to a perfectly ordinary
    `/etc/passwd` with nothing left to say it was ever relative.

    The variable name is the one `normalize` already measured on the corpus,
    not a second spelling of the same thing.

    Path arithmetic only, deliberately not `os.path`: this module must stay
    off the disk, and `os.path` semantics differ between the platform running
    the tests and the platform running the app.
    """
    path = (raw or "").strip()
    if not path:
        return "", 0
    if normalize.HOME_VARIABLE in path:
        path = path.replace(normalize.HOME_VARIABLE, splunk_home or "")
    path, escapes = normalize_ca_path(path)
    if splunk_home and path and not _is_absolute(path):
        path = _join(splunk_home, path)
    return path, escapes


def resolve_ca_file(configured, ssl_root_ca_path, splunk_home, exists):
    """The CA store to verify the splunkd chain against, and WHERE it comes from.

    Precedence, strongest first:

    a. `[rest] ca_file` of the app's own `confbtool.conf` - the explicit escape
       hatch, for whatever the two paths below do not cover;
    b. `server.conf [sslConfig] sslRootCAPath` - what the INSTANCE itself
       declares as its trust anchor. This is the path 1.3.0 was missing: on a
       member whose splunkd certificate was replaced by an enterprise one, the
       enterprise CA is declared right there, and the app simply did not read
       it;
    c. `$SPLUNK_HOME/etc/auth/cacert.pem` - Splunk's own truststore, the 1.3.0
       behavior, kept as the fallback.

    A path resolved by (a) or (b) is RETAINED even when it does not exist:
    `exists=False` travels into the diagnostic. A typo in `ca_file` must be
    visible as a typo, not silently downgraded to another store that happens
    to work - a silent downgrade is how a verification ends up anchored
    somewhere nobody chose. A declaration under (a) or (b) that cannot yield a
    usable path at all is REFUSED rather than resolved:
    `CaResolution.refusal` carries the handle, the client turns it into a
    fail-closed message. Only (c) falls through, to the platform's default
    trust store, when `cacert.pem` is absent - which is exactly what the 1.3.0
    wrapper already did.

    So the claim holds without an asterisk: once a store is DECLARED, no input
    to this function reaches the platform's default trust store.

    `exists` is an injected predicate (`os.path.isfile` in the wrapper): this
    module never touches the disk.
    """
    setting = (configured or "").strip()
    if setting:
        return _configured_resolution(setting, CA_SOURCE_SETTING, splunk_home,
                                      exists)

    declared = (ssl_root_ca_path or "").strip()
    if declared:
        return _configured_resolution(declared, CA_SOURCE_SERVER_CONF,
                                      splunk_home, exists)

    if splunk_home:
        path = _join(splunk_home, SPLUNK_CA_RELATIVE)
        if exists(path):
            return CaResolution(path, CA_SOURCE_SPLUNK_DEFAULT, True)
    return CaResolution("", CA_SOURCE_SYSTEM_STORE, True)


def _configured_resolution(raw, source, splunk_home, exists):
    """One `CaResolution` for a store the operator or the instance DECLARED.

    Sources (a) and (b) share every rule, refusals included, so they share one
    function: the day a refusal is added it cannot be added to one of the two
    and forgotten on the other - which is how `ca_file` and `sslRootCAPath`
    would start behaving differently on the same input.

    Two refusals, both of the same family: a declaration that cannot yield the
    path its author wrote.

    - `$SPLUNK_HOME` in the value while `$SPLUNK_HOME` is unknown to the search
      process. Expanding it to nothing turns `ca_file = $SPLUNK_HOME` into the
      empty string and `$SPLUNK_HOME/etc/auth/x.pem` into `/etc/auth/x.pem` -
      the file system root, not the installation. Neither is what was written;
    - an expansion that lands on the EMPTY string for any other reason. That
      one is the dangerous shape: `ssl` reads `cafile=None` as "use the
      platform's default trust store", so the run would have carried on,
      verified against a store nobody chose, with every message still naming
      the setting. That is precisely the silent fallback the contract forbids.

    And one refusal of a different nature (CH-9.18): a declaration whose `..`
    segments climb above the anchor it was given. `ca_file =
    ../../../../etc/passwd` is documented as anchored on `$SPLUNK_HOME`, and
    it designates a file that has nothing to do with `$SPLUNK_HOME`. The
    anchoring is a promise the contract makes; this is what keeps it.
    """
    if normalize.HOME_VARIABLE in raw and not splunk_home:
        return CaResolution("", source, False, REFUSAL_NO_HOME)
    path, escapes = expand_ca_path(raw, splunk_home)
    if escapes:
        return CaResolution("", source, False, REFUSAL_TRAVERSAL)
    if not path:
        return CaResolution("", source, False, REFUSAL_EMPTY)
    return CaResolution(path, source, bool(exists(path)))


def _is_absolute(path):
    """POSIX absolute path, Windows drive path or UNC path."""
    if path[:1] in ("/", "\\"):
        return True
    return len(path) >= 3 and path[1] == ":" and path[2] in ("/", "\\")


def _join(base, relative):
    """Join with the separator the base already uses - no `os.path`."""
    separator = "\\" if ("\\" in base and "/" not in base) else "/"
    return base.rstrip("/\\") + separator + relative.lstrip("/\\")


def _is_timeout(exc):
    """Timeout, without importing `socket`.

    On Python 3.10+ `socket.timeout` IS `TimeoutError`; on 3.9 - the
    interpreter Splunk 9.4 embeds - it is a distinct `OSError` subclass named
    `timeout`. The name check covers the older platform without pulling a
    module the layering rule keeps out of the package.
    """
    return isinstance(exc, TimeoutError) or type(exc).__name__ == "timeout"


def _reason_label(exc, reason):
    """The stable label of one network cause (CH-4.12).

    Looked up on the CLASS of the exception, never on its text, and on the
    WRAPPED one first: `urlopen` hands back a `URLError` whose `reason`
    carries the cause that actually happened.

    What this replaces is `str(exception)`, rendered verbatim. That string is
    written by the C library and the operating system - `[WinError 3] Le
    chemin d'acces specifie est introuvable` is a real answer of this code
    path - so it is localised, unstable across runtimes, and free to quote a
    path or a host. The charter forbids passing a raw Python exception through
    to the user for all three reasons at once.
    """
    for item in (reason, exc):
        if item is None:
            continue
        label = NETWORK_REASONS.get(type(item).__name__)
        if label is not None:
            return label
    return NETWORK_REASON_DEFAULT


class RestClient:
    """Minimal splunkd client: capability list and serverName."""

    def __init__(self, splunkd_uri, session_key, verify_ssl=True, ca=None):
        self._base = (splunkd_uri or "").rstrip("/")
        self._session_key = session_key or ""
        self._ca = ca if ca is not None else CaResolution(
            "", CA_SOURCE_SYSTEM_STORE, True
        )
        self._context = None
        #: Set when no usable TLS context could be built at all. Every
        #: exchange then returns it: the run fails closed AND says why.
        self._context_failure = None
        self._build_context(verify_ssl)

    def _build_context(self, verify_ssl):
        """TLS context per `[rest] verify_ssl` (spec section 2.2).

        `verify_ssl=true`: chain verified against the RESOLVED CA store,
        hostname check disabled - the splunkd URI is a loopback address and
        the default Splunk certificates carry no matching SAN. The hostname is
        not the variable in play here; the chain of trust is.

        `verify_ssl=false`: no verification (the wrapper emits a single
        startup warning).

        Never raises: a store that `ssl` refuses becomes a `RestFailure`, so
        the wrapper cannot die on a missing file while wiring its adapters.
        """
        if not verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._context = context
            return

        if self._ca.refusal is not None:
            self._context_failure = self._refusal_failure()
            return
        if self._ca.path and not self._ca.exists:
            self._context_failure = self._ca_file_failure()
            return
        try:
            context = ssl.create_default_context(cafile=self._ca.path or None)
        except (OSError, ValueError):
            # Absent, unreadable, or not a PEM bundle at all.
            self._context_failure = self._ca_file_failure()
            return
        context.check_hostname = False
        self._context = context

    def _refusal_failure(self):
        """The message of a CONFIGURED store the resolution refused.

        One table, one lookup (CH-4.12): every refusal handle maps to a stable
        sentence naming its class of cause. An unknown handle still fails
        closed under the generic wording rather than passing through.
        """
        message = REFUSAL_MESSAGES.get(self._ca.refusal)
        if message is None:
            return self._ca_file_failure()
        return RestFailure(FAILURE_CA_FILE, message % self._ca.source)

    def _ca_file_failure(self):
        return RestFailure(
            FAILURE_CA_FILE,
            CA_FILE_MESSAGE % (self._ca.path or CA_SOURCE_SYSTEM_STORE,
                               self._ca.source),
        )

    def _get_json(self, path):
        """GET a splunkd endpoint; returns `(document, failure)`.

        Exactly one of the two is `None`. No network exception propagates out
        of this module (spec section 3.1) - each one is CLASSIFIED instead of
        being swallowed.
        """
        if self._context_failure is not None:
            return None, self._context_failure
        # The `Request` is BUILT inside a guard, not just sent inside one.
        # `urllib` parses the URL as it constructs the object, so an empty or
        # malformed `splunkd_uri` - what the search process hands over when its
        # metadata is incomplete - raised `ValueError: unknown url type`
        # straight out of the module, past the contract stated at the top of
        # this file. "No network exception escapes" has to cover the whole
        # exchange, addressing included, or it is not a contract.
        try:
            request = urllib.request.Request(
                self._base + path,
                headers={"Authorization": "Splunk %s" % self._session_key},
            )
        except Exception as exc:  # noqa: BLE001 - classified, never propagated
            return None, RestFailure(
                FAILURE_NETWORK, NETWORK_MESSAGE % _reason_label(exc, None)
            )
        try:
            with urllib.request.urlopen(
                request, timeout=READ_TIMEOUT_SECONDS, context=self._context,
            ) as response:
                payload = response.read().decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - classified, never propagated
            return None, self._classify(exc, path)
        try:
            return json.loads(payload), None
        except Exception as exc:  # noqa: BLE001 - classified, never propagated
            return None, self._classify(exc, path)

    def _classify(self, exc, path):
        """Name the class of cause of one failed exchange (CH-4.12, CH-9.13).

        The order matters, and so does the unwrapping: `urlopen` does NOT let
        the `ssl.SSLCertVerificationError` through, it comes back wrapped in a
        `URLError` whose `reason` carries it. A classifier written against the
        theoretical exception alone misses the nominal case - which is the
        measured lesson CH-9.13 is built on, and `tests/test_rest.py` freezes
        both shapes.
        """
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code in (401, 403):
                return RestFailure(FAILURE_AUTH, AUTH_MESSAGE % exc.code)
            return RestFailure(FAILURE_HTTP, HTTP_MESSAGE % (exc.code, path))

        reason = getattr(exc, "reason", None)
        candidates = (exc, reason)
        if any(isinstance(item, ssl.SSLError) for item in candidates):
            return RestFailure(
                FAILURE_TLS,
                TLS_MESSAGE % (self._ca.path or CA_SOURCE_SYSTEM_STORE,
                               self._ca.source),
            )
        if any(_is_timeout(item) for item in candidates):
            return RestFailure(
                FAILURE_TIMEOUT, TIMEOUT_MESSAGE % READ_TIMEOUT_SECONDS
            )
        if isinstance(exc, ValueError):
            # `json.JSONDecodeError` and `UnicodeDecodeError` both land here.
            return RestFailure(FAILURE_UNREADABLE, UNREADABLE_MESSAGE % path)
        # Everything left - a `URLError` and anything the port never predicted
        # alike - is a failed exchange named by its CLASS of cause, through
        # the one table that holds the wording.
        return RestFailure(
            FAILURE_NETWORK, NETWORK_MESSAGE % _reason_label(exc, reason)
        )

    # -- RestPort -------------------------------------------------------- #

    def get_capabilities(self):
        """`(capabilities, failure)` - exactly one of the two is `None`.

        RestPort contract widened in 1.4.0 (spec section 1.4): 1.3.0 returned
        a bare `None` for an impossible check, so the pipeline could only emit
        the message about rights. The nature of the failure now travels with
        the answer; the fail-closed decision of spec section 10 is untouched -
        a check that could not be completed still never presumes the
        authorization.
        """
        document, failure = self._get_json(CURRENT_CONTEXT_PATH)
        if failure is not None:
            return None, failure
        try:
            capabilities = document["entry"][0]["content"]["capabilities"]
        except (TypeError, KeyError, IndexError):
            return None, RestFailure(
                FAILURE_UNREADABLE, UNREADABLE_MESSAGE % CURRENT_CONTEXT_PATH
            )
        return frozenset(capabilities), None

    def get_server_name(self):
        """`serverName` of the member, `None` when unavailable (the wrapper
        falls back to the local hostname).

        No failure is surfaced here on purpose: the fallback is legitimate and
        silent, where an unverifiable capability must be loud.
        """
        document, failure = self._get_json(SERVER_INFO_PATH)
        if failure is not None:
            return None
        try:
            name = document["entry"][0]["content"]["serverName"]
        except (TypeError, KeyError, IndexError):
            return None
        return name or None
