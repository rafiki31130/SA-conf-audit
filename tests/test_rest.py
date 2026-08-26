"""RestPort adapter: CA store resolution and failure taxonomy (spec section 10).

`bin/confaudit/rest.py` was the only module of the package without a dedicated
unit test, and it is the one that carried the production defect: the CA store
was hardcoded to `$SPLUNK_HOME/etc/auth/cacert.pem`, so a member whose splunkd
certificate had been replaced by an enterprise one failed the chain
verification; `_get_json` then collapsed that failure - and a 401, and a
timeout, and a malformed answer - into the same bare `None`, and the pipeline
emitted the message about rights. The rights were never the problem.

Two families of assertions, matching the two halves of the fix:

- **resolution**: the a/b/c precedence, `$SPLUNK_HOME` expansion, relative
  paths, and a configured-but-absent path staying visible;
- **diagnosis**: every failure shape classified under its own `kind`, with a
  message that names the class of cause - and, for TLS, the CA store actually
  used (charter CH-4.12, CH-9.13).

No network and no certificate material: `urlopen` and `ssl.create_default_context`
are replaced by plain recording objects (no mock library, like the in-memory
ports of `tests/helpers.py`), and no PEM is ever written to the test tree -
the charter forbids certificate content in a test just as it forbids it in a
log (CH-9.4).
"""

import json
import ssl
import unittest
import urllib.error

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import rest
from confaudit.model import CaResolution

#: Generic, synthetic environment - never a capture of a real instance.
SPLUNK_HOME = "/opt/splunk"
SPLUNK_CA = "/opt/splunk/etc/auth/cacert.pem"
ENTERPRISE_CA = "/opt/splunk/etc/auth/corp-root-ca.pem"
OPERATOR_CA = "/etc/pki/tls/certs/operator-bundle.pem"
URI = "https://127.0.0.1:8089"

#: If this string ever reaches a message, the session key leaked (R5).
SESSION_SENTINEL = "SESSION_KEY_SENTINEL_4f2a"

CURRENT_CONTEXT = {
    "entry": [{"content": {"capabilities": ["search", "run_confbtool"]}}]
}
SERVER_INFO = {"entry": [{"content": {"serverName": "member-01"}}]}


def _present(*paths):
    """`exists` predicate over a fixed set of paths - no disk involved."""
    known = frozenset(paths)
    return lambda path: path in known


def _server_conf(value, stanza="sslConfig", key="sslRootCAPath"):
    return ("[%s]\n%s = %s\n" % (stanza, key, value)).encode("utf-8")


class _Response:
    """Minimal stand-in for the `urlopen` context manager."""

    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self):
        return self._payload


class _Urlopen:
    """Records every call, then answers with a payload or raises."""

    def __init__(self, payload=None, raises=None):
        self.payload = payload
        self.raises = raises
        self.requests = []
        self.timeouts = []
        self.contexts = []

    def __call__(self, request, timeout=None, context=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        self.contexts.append(context)
        if self.raises is not None:
            raise self.raises
        return _Response(self.payload)


class _ContextFactory:
    """Stand-in for `ssl.create_default_context`, recording its `cafile`.

    The tests carry no certificate material, so no real CA bundle can be
    loaded; everything downstream of the context - classification, messages,
    the header - is exercised for real. What this factory buys, beyond making
    the client constructible, is the ability to assert WHICH store was handed
    to `ssl`, which is the whole point of the fix.
    """

    def __init__(self, raises=None):
        self.cafiles = []
        self.raises = raises

    def __call__(self, cafile=None):
        self.cafiles.append(cafile)
        if self.raises is not None:
            raise self.raises
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


class RestTestCase(unittest.TestCase):
    """Swaps the two module-level seams of `rest.py`, restores them after."""

    def use_urlopen(self, urlopen):
        original = rest.urllib.request.urlopen
        rest.urllib.request.urlopen = urlopen
        self.addCleanup(setattr, rest.urllib.request, "urlopen", original)
        return urlopen

    def use_context_factory(self, factory):
        original = rest.ssl.create_default_context
        rest.ssl.create_default_context = factory
        self.addCleanup(setattr, rest.ssl, "create_default_context", original)
        return factory

    def client(self, ca=None, verify_ssl=True, session_key=SESSION_SENTINEL):
        return rest.RestClient(URI, session_key, verify_ssl=verify_ssl, ca=ca)


# --------------------------------------------------------------------------- #
# a/b/c precedence of the CA store
# --------------------------------------------------------------------------- #

class CaPrecedenceTest(RestTestCase):
    """`[rest] ca_file` > `server.conf sslRootCAPath` > `cacert.pem`."""

    def test_a_the_configured_ca_file_outranks_everything(self):
        resolution = rest.resolve_ca_file(
            OPERATOR_CA,
            ENTERPRISE_CA,
            SPLUNK_HOME,
            _present(OPERATOR_CA, ENTERPRISE_CA, SPLUNK_CA),
        )
        self.assertEqual(resolution.path, OPERATOR_CA)
        self.assertEqual(resolution.source, rest.CA_SOURCE_SETTING)
        self.assertTrue(resolution.exists)

    def test_b_sslrootcapath_outranks_the_splunk_truststore(self):
        """The production case, demonstrated rather than asserted.

        The enterprise CA is declared in `server.conf` and is NOT in
        `cacert.pem`; both files exist. What must come out is the enterprise
        one - 1.3.0 returned `cacert.pem` here, and every verification failed.
        """
        resolution = rest.resolve_ca_file(
            "",
            ENTERPRISE_CA,
            SPLUNK_HOME,
            _present(ENTERPRISE_CA, SPLUNK_CA),
        )
        self.assertEqual(resolution.path, ENTERPRISE_CA)
        self.assertEqual(resolution.source, rest.CA_SOURCE_SERVER_CONF)
        self.assertNotEqual(resolution.path, SPLUNK_CA)

    def test_c_the_splunk_truststore_is_the_fallback(self):
        resolution = rest.resolve_ca_file(
            "", None, SPLUNK_HOME, _present(SPLUNK_CA)
        )
        self.assertEqual(resolution.path, SPLUNK_CA)
        self.assertEqual(resolution.source, rest.CA_SOURCE_SPLUNK_DEFAULT)

    def test_the_platform_store_closes_the_chain(self):
        """No setting, no declaration, no `cacert.pem`: the platform's own
        store - which is what the 1.3.0 wrapper already did."""
        resolution = rest.resolve_ca_file("", None, SPLUNK_HOME, _present())
        self.assertEqual(resolution.path, "")
        self.assertEqual(resolution.source, rest.CA_SOURCE_SYSTEM_STORE)
        self.assertTrue(resolution.exists)

    def test_a_blank_setting_does_not_count_as_configured(self):
        """`ca_file =` is shipped empty in `default/confbtool.conf`: an empty
        or blank value must fall through, not resolve to an empty path."""
        for blank in ("", "   ", "\t"):
            with self.subTest(value=repr(blank)):
                resolution = rest.resolve_ca_file(
                    blank, ENTERPRISE_CA, SPLUNK_HOME, _present(ENTERPRISE_CA)
                )
                self.assertEqual(resolution.path, ENTERPRISE_CA)

    def test_a_blank_sslrootcapath_falls_through_to_the_truststore(self):
        resolution = rest.resolve_ca_file(
            "", "  ", SPLUNK_HOME, _present(SPLUNK_CA)
        )
        self.assertEqual(resolution.path, SPLUNK_CA)


class CaPathExpansionTest(RestTestCase):

    def test_splunk_home_is_expanded_in_sslrootcapath(self):
        """`server.conf` ships the variable spelling, not an absolute path."""
        resolution = rest.resolve_ca_file(
            "", "$SPLUNK_HOME/etc/auth/cacert.pem", SPLUNK_HOME,
            _present(SPLUNK_CA),
        )
        self.assertEqual(resolution.path, SPLUNK_CA)
        self.assertTrue(resolution.exists)

    def test_splunk_home_is_expanded_in_the_configured_ca_file(self):
        resolution = rest.resolve_ca_file(
            "$SPLUNK_HOME/etc/auth/corp-root-ca.pem", None, SPLUNK_HOME,
            _present(ENTERPRISE_CA),
        )
        self.assertEqual(resolution.path, ENTERPRISE_CA)
        self.assertEqual(resolution.source, rest.CA_SOURCE_SETTING)

    def test_a_relative_path_is_anchored_on_splunk_home(self):
        resolution = rest.resolve_ca_file(
            "", "etc/auth/corp-root-ca.pem", SPLUNK_HOME,
            _present(ENTERPRISE_CA),
        )
        self.assertEqual(resolution.path, ENTERPRISE_CA)

    def test_an_absolute_path_is_left_alone(self):
        resolution = rest.resolve_ca_file(
            "", OPERATOR_CA, SPLUNK_HOME, _present(OPERATOR_CA)
        )
        self.assertEqual(resolution.path, OPERATOR_CA)

    def test_a_windows_path_is_not_anchored_a_second_time(self):
        windows_ca = "C:\\Program Files\\Splunk\\etc\\auth\\corp-root-ca.pem"
        resolution = rest.resolve_ca_file(
            "", windows_ca, "C:\\Program Files\\Splunk", _present(windows_ca)
        )
        self.assertEqual(resolution.path, windows_ca)

    def test_expansion_without_a_known_home_changes_nothing(self):
        resolution = rest.resolve_ca_file("", OPERATOR_CA, "", _present())
        self.assertEqual(resolution.path, OPERATOR_CA)
        self.assertFalse(resolution.exists)


class CaMissingPathTest(RestTestCase):
    """A configured path that is not there stays visible - never a silent
    downgrade to another store."""

    def test_a_configured_ca_file_that_does_not_exist_is_kept(self):
        resolution = rest.resolve_ca_file(
            OPERATOR_CA, ENTERPRISE_CA, SPLUNK_HOME,
            _present(ENTERPRISE_CA, SPLUNK_CA),
        )
        self.assertEqual(resolution.path, OPERATOR_CA)
        self.assertFalse(resolution.exists)
        self.assertEqual(resolution.source, rest.CA_SOURCE_SETTING)

    def test_a_declared_sslrootcapath_that_does_not_exist_is_kept(self):
        resolution = rest.resolve_ca_file(
            "", ENTERPRISE_CA, SPLUNK_HOME, _present(SPLUNK_CA)
        )
        self.assertEqual(resolution.path, ENTERPRISE_CA)
        self.assertFalse(resolution.exists)

    def test_an_absent_store_fails_the_check_and_names_the_file(self):
        """It must be diagnosable, not silent: the refusal names the path AND
        the resolution path it came from - and it costs ZERO network call.

        Both seams are installed - `ssl.create_default_context` AND `urlopen` -
        precisely because neither must be reached. Without them this test read
        the real behaviour of `ssl` towards a path that merely happens not to
        exist on the machine running it: it passed whether or not `rest.py`
        still carried its guard (the mutation that deletes the guard survived
        it), and on a host where that fixture path DID exist it would have
        reached a real `urlopen` - which the suite forbids (CH-10.7).
        """
        factory = self.use_context_factory(_ContextFactory())
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        client = self.client(
            ca=CaResolution(OPERATOR_CA, rest.CA_SOURCE_SETTING, False)
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertIn(OPERATOR_CA, failure.message)
        self.assertIn(rest.CA_SOURCE_SETTING, failure.message)

        # The assertion the guard actually exists for: a store that was
        # declared and cannot be used is refused at context build time, so
        # nothing is ever sent to splunkd and `ssl` is never even consulted.
        self.assertEqual(urlopen.requests, [])
        self.assertEqual(factory.cafiles, [])

        # CH-10.3: the two zeros above are worth something only once the same
        # recorders, read in the same block, are shown to record. One usable
        # store, one context, one request.
        self.client(
            ca=CaResolution(SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT, True)
        ).get_capabilities()
        self.assertEqual(factory.cafiles, [SPLUNK_CA])
        self.assertEqual(len(urlopen.requests), 1)

    def test_a_store_ssl_refuses_is_reported_as_unusable(self):
        """Present but not a CA bundle: `ssl` raises at context build time and
        the constructor must not let it out."""
        self.use_context_factory(
            _ContextFactory(raises=ssl.SSLError("no start line"))
        )
        urlopen = self.use_urlopen(_Urlopen(payload=b"{}"))
        client = self.client(
            ca=CaResolution(OPERATOR_CA, rest.CA_SOURCE_SETTING, True)
        )
        _, failure = client.get_capabilities()
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertIn(OPERATOR_CA, failure.message)
        self.assertEqual(urlopen.requests, [])
        self.assertIn(OPERATOR_CA, failure.message)


class NoSilentFallbackTest(RestTestCase):
    """A DECLARED store never ends up as the platform's default trust store.

    `README.md`, `README/confbtool.conf.spec` and `resolve_ca_file` all three
    state that there is no quiet fallback. Until this test existed the claim
    had a hole exactly one ordinary value wide: `ca_file = $SPLUNK_HOME` on a
    search process whose environment carries no `$SPLUNK_HOME` expands to the
    empty string, the missing-store guard reads a falsy path and steps aside,
    and `ssl` receives `cafile=None` - which means "the platform's own store".
    The run then verified against a store nobody chose while every message
    still named `[rest] ca_file`.
    """

    #: Values whose `$SPLUNK_HOME` cannot be expanded. The first is the
    #: reported case; the third is the very spelling `server.conf` ships, and
    #: it is the one that silently re-anchors on the file system ROOT rather
    #: than on nothing at all.
    UNRESOLVABLE = (
        "$SPLUNK_HOME", "  $SPLUNK_HOME  ", "$SPLUNK_HOME/etc/auth/cacert.pem",
        "$SPLUNK_HOME/", "$SPLUNK_HOME\\etc\\auth\\cacert.pem",
    )

    def test_a_setting_whose_home_is_unknown_is_refused(self):
        for raw in self.UNRESOLVABLE:
            with self.subTest(value=raw):
                resolution = rest.resolve_ca_file(raw, None, "", _present())
                self.assertEqual(resolution.refusal, rest.REFUSAL_NO_HOME)
                self.assertEqual(resolution.source, rest.CA_SOURCE_SETTING)
                self.assertEqual(resolution.path, "")

    def test_a_declaration_whose_home_is_unknown_is_refused_too(self):
        """Same rule on both declared sources - the resolution has one code
        path for the two, so they cannot drift apart."""
        for raw in self.UNRESOLVABLE:
            with self.subTest(value=raw):
                resolution = rest.resolve_ca_file("", raw, "", _present())
                self.assertEqual(resolution.refusal, rest.REFUSAL_NO_HOME)
                self.assertEqual(resolution.source, rest.CA_SOURCE_SERVER_CONF)

    def test_a_known_home_still_expands_normally(self):
        """Calibration (CH-10.2): the refusal above must come from the ABSENT
        home, not from the mere presence of the variable."""
        resolution = rest.resolve_ca_file(
            "$SPLUNK_HOME/etc/auth/cacert.pem", None, SPLUNK_HOME,
            _present(SPLUNK_CA),
        )
        self.assertIsNone(resolution.refusal)
        self.assertEqual(resolution.path, SPLUNK_CA)

    def test_the_refusal_never_reaches_the_platform_store(self):
        """The assertion the defect was hiding behind: `ssl` is not handed
        `cafile=None`, it is not called at all, and no request is emitted."""
        factory = self.use_context_factory(_ContextFactory())
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        resolution = rest.resolve_ca_file("$SPLUNK_HOME", None, "", _present())
        capabilities, failure = self.client(ca=resolution).get_capabilities()

        self.assertIsNone(capabilities, "fail-closed, not a default store")
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertEqual(factory.cafiles, [])
        self.assertEqual(urlopen.requests, [])

        # CH-10.3: the two empty recorders above prove something only once the
        # same recorders are shown to record, in this block, on this reading.
        self.client(
            ca=CaResolution(SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT, True)
        ).get_capabilities()
        self.assertEqual(factory.cafiles, [SPLUNK_CA])
        self.assertEqual(len(urlopen.requests), 1)

    def test_every_refusal_handle_has_its_own_sentence(self):
        """CH-4.12: one table, one message per class of cause, and no handle
        silently sharing another's wording."""
        sentences = set()
        for handle in (rest.REFUSAL_EMPTY, rest.REFUSAL_NO_HOME):
            with self.subTest(refusal=handle):
                self.use_context_factory(_ContextFactory())
                self.use_urlopen(_Urlopen(payload=b"{}"))
                client = self.client(
                    ca=CaResolution("", rest.CA_SOURCE_SETTING, False, handle)
                )
                _, failure = client.get_capabilities()
                self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
                self.assertIn(rest.CA_SOURCE_SETTING, failure.message)
                self.assertNotIn(SESSION_SENTINEL, failure.message)
                sentences.add(failure.message)
        self.assertEqual(len(sentences), 2)

    def test_no_declared_source_can_reach_the_platform_store(self):
        """Family sweep rather than the one value that was reported (CH-10.4).

        Every shape a declared store can take, crossed with both declared
        sources: none of them may come out labelled as the platform's own
        store, and none may come out usable-and-empty.
        """
        shapes = (
            "$SPLUNK_HOME", "$SPLUNK_HOME/", ".", "./", "   $SPLUNK_HOME   ",
            OPERATOR_CA, "etc/auth/corp-root-ca.pem",
            "$SPLUNK_HOME/etc/auth/cacert.pem",
        )
        seen = 0
        for raw in shapes:
            for configured, declared, source in (
                (raw, None, rest.CA_SOURCE_SETTING),
                ("", raw, rest.CA_SOURCE_SERVER_CONF),
            ):
                with self.subTest(value=raw, source=source):
                    resolution = rest.resolve_ca_file(
                        configured, declared, "", _present()
                    )
                    seen += 1
                    self.assertEqual(resolution.source, source)
                    self.assertNotEqual(
                        resolution.source, rest.CA_SOURCE_SYSTEM_STORE
                    )
                    if not resolution.path:
                        self.assertIsNotNone(resolution.refusal)
        self.assertEqual(seen, len(shapes) * 2)


class SslRootCaPathReadingTest(RestTestCase):
    """`server.conf [sslConfig] sslRootCAPath`, read through the library's own
    parser over the two SYSTEM layers."""

    def test_local_wins_over_default(self):
        value = rest.read_ssl_root_ca_path(
            _server_conf(SPLUNK_CA), _server_conf(ENTERPRISE_CA)
        )
        self.assertEqual(value, ENTERPRISE_CA)

    def test_default_alone_is_read(self):
        value = rest.read_ssl_root_ca_path(_server_conf(SPLUNK_CA), None)
        self.assertEqual(value, SPLUNK_CA)

    def test_absent_layers_yield_none(self):
        self.assertIsNone(rest.read_ssl_root_ca_path(None, None))

    def test_another_stanza_is_not_read(self):
        value = rest.read_ssl_root_ca_path(
            None, _server_conf(ENTERPRISE_CA, stanza="general")
        )
        self.assertIsNone(value)

    def test_another_key_is_not_read(self):
        value = rest.read_ssl_root_ca_path(
            None, _server_conf(ENTERPRISE_CA, key="sslRootCAPathFoo")
        )
        self.assertIsNone(value)

    def test_the_layer_bytes_are_parsed_with_the_conf_parser(self):
        """Comments, blank lines and the surrounding stanzas of a real
        `server.conf` do not disturb the reading."""
        data = (
            "# managed by the platform\n"
            "[general]\n"
            "serverName = member-01\n"
            "\n"
            "[sslConfig]\n"
            "  ; sslRootCAPath = /wrong/commented.pem\n"
            "  sslRootCAPath = %s  \n"
            "sslVerifyServerCert = true\n"
        ) % ENTERPRISE_CA
        value = rest.read_ssl_root_ca_path(None, data.encode("utf-8"))
        self.assertEqual(value, ENTERPRISE_CA)


class ResolutionReachesSslTest(RestTestCase):
    """End to end: what `server.conf` declares is what `ssl` is handed."""

    def test_the_enterprise_ca_is_the_store_handed_to_ssl(self):
        factory = self.use_context_factory(_ContextFactory())
        resolution = rest.resolve_ca_file(
            "",
            rest.read_ssl_root_ca_path(
                _server_conf("$SPLUNK_HOME/etc/auth/cacert.pem"),
                _server_conf(ENTERPRISE_CA),
            ),
            SPLUNK_HOME,
            _present(ENTERPRISE_CA, SPLUNK_CA),
        )
        self.client(ca=resolution)
        self.assertEqual(factory.cafiles, [ENTERPRISE_CA])
        self.assertNotIn(SPLUNK_CA, factory.cafiles)

    def test_without_a_declaration_the_truststore_is_handed_to_ssl(self):
        factory = self.use_context_factory(_ContextFactory())
        resolution = rest.resolve_ca_file(
            "", rest.read_ssl_root_ca_path(None, None), SPLUNK_HOME,
            _present(SPLUNK_CA),
        )
        self.client(ca=resolution)
        self.assertEqual(factory.cafiles, [SPLUNK_CA])

    def test_hostname_checking_stays_disabled_when_verifying(self):
        """Deliberate and unchanged: the splunkd URI is a loopback address and
        the default Splunk certificates carry no matching SAN. The chain is
        the variable in play, never the name."""
        self.use_context_factory(_ContextFactory())
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        client = self.client(
            ca=CaResolution(SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT, True)
        )
        client.get_capabilities()
        self.assertFalse(urlopen.contexts[0].check_hostname)
        self.assertEqual(urlopen.contexts[0].verify_mode, ssl.CERT_REQUIRED)

    def test_verify_ssl_false_disables_verification_entirely(self):
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        client = self.client(verify_ssl=False)
        client.get_capabilities()
        self.assertEqual(urlopen.contexts[0].verify_mode, ssl.CERT_NONE)
        self.assertFalse(urlopen.contexts[0].check_hostname)


# --------------------------------------------------------------------------- #
# Failure taxonomy
# --------------------------------------------------------------------------- #

class FailureTaxonomyTest(RestTestCase):
    """One `kind` per class of cause, and a message that names it."""

    def _failure(self, raises, ca=None):
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(raises=raises))
        capabilities, failure = self.client(ca=ca).get_capabilities()
        self.assertIsNone(capabilities, "fail-closed: no capability set")
        self.assertIsNotNone(failure, "the failure must be qualified")
        return failure

    def test_a_wrapped_certificate_error_is_a_tls_failure(self):
        """The measured shape (charter CH-9.13): `urlopen` does not let the
        `SSLCertVerificationError` through, it wraps it in a `URLError`. A
        classifier written against the theoretical exception alone misses the
        nominal case, which is exactly what this test freezes."""
        failure = self._failure(
            urllib.error.URLError(
                ssl.SSLCertVerificationError(
                    1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                       "failed: unable to get local issuer certificate"
                )
            ),
            ca=CaResolution(ENTERPRISE_CA, rest.CA_SOURCE_SERVER_CONF, True),
        )
        self.assertEqual(failure.kind, rest.FAILURE_TLS)

    def test_a_bare_ssl_error_is_a_tls_failure_too(self):
        failure = self._failure(ssl.SSLError("handshake failure"))
        self.assertEqual(failure.kind, rest.FAILURE_TLS)

    def test_the_tls_message_names_tls_the_store_and_the_file_to_edit(self):
        """The three things that made this failure diagnosable at last."""
        failure = self._failure(
            urllib.error.URLError(ssl.SSLCertVerificationError(1, "verify failed")),
            ca=CaResolution(ENTERPRISE_CA, rest.CA_SOURCE_SERVER_CONF, True),
        )
        self.assertIn("TLS", failure.message)
        self.assertIn(ENTERPRISE_CA, failure.message)
        self.assertIn(rest.CA_SOURCE_SERVER_CONF, failure.message)
        self.assertIn("local/confbtool.conf", failure.message)

    def test_the_tls_message_names_whichever_store_was_resolved(self):
        for path, source in (
            (OPERATOR_CA, rest.CA_SOURCE_SETTING),
            (SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT),
        ):
            with self.subTest(source=source):
                failure = self._failure(
                    ssl.SSLError("verify failed"),
                    ca=CaResolution(path, source, True),
                )
                self.assertIn(path, failure.message)
                self.assertIn(source, failure.message)

    def test_a_401_is_an_authentication_refusal(self):
        failure = self._failure(
            urllib.error.HTTPError(URI, 401, "Unauthorized", None, None)
        )
        self.assertEqual(failure.kind, rest.FAILURE_AUTH)
        self.assertIn("401", failure.message)

    def test_a_403_is_an_authentication_refusal(self):
        failure = self._failure(
            urllib.error.HTTPError(URI, 403, "Forbidden", None, None)
        )
        self.assertEqual(failure.kind, rest.FAILURE_AUTH)

    def test_another_http_status_is_an_http_error(self):
        failure = self._failure(
            urllib.error.HTTPError(URI, 503, "Service Unavailable", None, None)
        )
        self.assertEqual(failure.kind, rest.FAILURE_HTTP)
        self.assertIn("503", failure.message)

    def test_a_timeout_error_is_a_timeout(self):
        failure = self._failure(TimeoutError("timed out"))
        self.assertEqual(failure.kind, rest.FAILURE_TIMEOUT)
        self.assertIn(str(rest.READ_TIMEOUT_SECONDS), failure.message)

    def test_a_wrapped_timeout_is_a_timeout(self):
        failure = self._failure(urllib.error.URLError(TimeoutError("timed out")))
        self.assertEqual(failure.kind, rest.FAILURE_TIMEOUT)

    def test_the_python39_socket_timeout_shape_is_a_timeout(self):
        """On 3.9 - the interpreter Splunk 9.4 embeds - `socket.timeout` is a
        distinct `OSError` subclass, not `TimeoutError`. `rest.py` recognises
        it by name so the older platform is covered without importing
        `socket`, which the layering rule keeps out of the package."""

        class timeout(OSError):  # noqa: N801 - the 3.9 spelling, on purpose
            pass

        failure = self._failure(timeout("timed out"))
        self.assertEqual(failure.kind, rest.FAILURE_TIMEOUT)

    def test_an_unreachable_endpoint_is_a_network_failure(self):
        failure = self._failure(
            urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        )
        self.assertEqual(failure.kind, rest.FAILURE_NETWORK)
        self.assertIn("Connection refused", failure.message)

    def test_a_malformed_json_answer_is_unreadable(self):
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(payload=b"<html>not json</html>"))
        capabilities, failure = self.client().get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_UNREADABLE)

    def test_a_json_answer_without_the_capability_list_is_unreadable(self):
        """Well-formed JSON, wrong shape: still a check that did not conclude,
        never an empty capability set that would read as a missing right."""
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(payload=json.dumps({"entry": []}).encode("utf-8")))
        capabilities, failure = self.client().get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_UNREADABLE)

    def test_undecodable_bytes_are_unreadable(self):
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(payload=b"\xff\xfe\x00broken"))
        _, failure = self.client().get_capabilities()
        self.assertEqual(failure.kind, rest.FAILURE_UNREADABLE)

    def test_every_kind_is_distinct(self):
        """The taxonomy is only useful if two causes never share a handle."""
        kinds = [
            rest.FAILURE_TLS, rest.FAILURE_CA_FILE, rest.FAILURE_AUTH,
            rest.FAILURE_TIMEOUT, rest.FAILURE_UNREADABLE, rest.FAILURE_HTTP,
            rest.FAILURE_NETWORK,
        ]
        self.assertEqual(len(set(kinds)), len(kinds))


class NoExceptionEscapesTest(RestTestCase):
    """Contract of the module (spec section 3.1): a network exception is
    classified, never propagated - on BOTH endpoints of the port."""

    SHAPES = (
        ssl.SSLError("handshake failure"),
        urllib.error.URLError(ssl.SSLCertVerificationError(1, "verify failed")),
        urllib.error.HTTPError(URI, 401, "Unauthorized", None, None),
        urllib.error.HTTPError(URI, 500, "Internal Server Error", None, None),
        urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")),
        TimeoutError("timed out"),
        OSError(5, "Input/output error"),
        RuntimeError("something entirely unexpected"),
    )

    def test_get_capabilities_never_raises(self):
        for shape in self.SHAPES:
            with self.subTest(shape=type(shape).__name__):
                self.use_context_factory(_ContextFactory())
                self.use_urlopen(_Urlopen(raises=shape))
                capabilities, failure = self.client().get_capabilities()
                self.assertIsNone(capabilities)
                self.assertIsNotNone(failure)
                self.assertTrue(failure.message)

    def test_get_server_name_never_raises_and_falls_back_silently(self):
        for shape in self.SHAPES:
            with self.subTest(shape=type(shape).__name__):
                self.use_context_factory(_ContextFactory())
                self.use_urlopen(_Urlopen(raises=shape))
                self.assertIsNone(self.client().get_server_name())

    def test_the_constructor_never_raises_on_an_unusable_store(self):
        self.use_context_factory(
            _ContextFactory(raises=OSError(2, "No such file or directory"))
        )
        urlopen = self.use_urlopen(_Urlopen(payload=b"{}"))
        client = self.client(
            ca=CaResolution(OPERATOR_CA, rest.CA_SOURCE_SETTING, True)
        )
        _, failure = client.get_capabilities()
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertEqual(urlopen.requests, [])


class SuccessPathTest(RestTestCase):
    """Positive control: without it, every assertion above could be passing on
    a client that never works at all (charter CH-10.2)."""

    def _urlopen(self, document):
        self.use_context_factory(_ContextFactory())
        return self.use_urlopen(
            _Urlopen(payload=json.dumps(document).encode("utf-8"))
        )

    def test_capabilities_come_back_with_no_failure(self):
        self._urlopen(CURRENT_CONTEXT)
        capabilities, failure = self.client().get_capabilities()
        self.assertIsNone(failure)
        self.assertIn("run_confbtool", capabilities)
        self.assertIsInstance(capabilities, frozenset)

    def test_a_capability_set_without_the_right_is_not_a_failure(self):
        """The two outcomes are genuinely separate: a set that lacks the
        capability is an ANSWER, and the pipeline must be able to tell it from
        a check that did not conclude."""
        self._urlopen({"entry": [{"content": {"capabilities": ["search"]}}]})
        capabilities, failure = self.client().get_capabilities()
        self.assertIsNone(failure)
        self.assertEqual(capabilities, frozenset(("search",)))

    def test_the_server_name_comes_back(self):
        self._urlopen(SERVER_INFO)
        self.assertEqual(self.client().get_server_name(), "member-01")

    def test_the_endpoints_and_the_timeout_are_the_contracted_ones(self):
        urlopen = self._urlopen(CURRENT_CONTEXT)
        self.client().get_capabilities()
        self.assertEqual(
            urlopen.requests[0].full_url, URI + rest.CURRENT_CONTEXT_PATH
        )
        self.assertEqual(urlopen.timeouts[0], rest.READ_TIMEOUT_SECONDS)


class SessionKeyConfinementTest(RestTestCase):
    """R5 / charter CH-9.4: the session key lives in the header and nowhere
    else - not in a URL, not in a failure message."""

    def test_the_key_is_carried_by_the_authorization_header(self):
        """Calibration of the probe below: if the sentinel were absent from
        the exchange altogether, its absence from the messages would prove
        nothing (charter CH-10.2)."""
        self.use_context_factory(_ContextFactory())
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        self.client().get_capabilities()
        header = urlopen.requests[0].get_header("Authorization")
        self.assertEqual(header, "Splunk %s" % SESSION_SENTINEL)
        self.assertNotIn(SESSION_SENTINEL, urlopen.requests[0].full_url)

    def test_no_failure_message_carries_the_key(self):
        for shape in NoExceptionEscapesTest.SHAPES:
            with self.subTest(shape=type(shape).__name__):
                self.use_context_factory(_ContextFactory())
                self.use_urlopen(_Urlopen(raises=shape))
                _, failure = self.client().get_capabilities()
                self.assertNotIn(SESSION_SENTINEL, failure.message)
                self.assertNotIn(SESSION_SENTINEL, failure.kind)

    def test_the_unusable_store_message_carries_no_key(self):
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(payload=b"{}"))
        client = self.client(
            ca=CaResolution(OPERATOR_CA, rest.CA_SOURCE_SETTING, False)
        )
        _, failure = client.get_capabilities()
        self.assertNotIn(SESSION_SENTINEL, failure.message)


if __name__ == "__main__":
    unittest.main()
