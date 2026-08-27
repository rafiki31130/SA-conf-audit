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


#: Which authority each synthetic store carries. NAMES, never certificates:
#: the charter forbids certificate material in a test as in a log (CH-9.4),
#: and a name is all the trust decision below needs.
STORE_AUTHORITIES = {
    SPLUNK_CA: "splunk-default-ca",
    ENTERPRISE_CA: "corp-root-ca",
    OPERATOR_CA: "operator-ca",
}


class _RecordingContext(ssl.SSLContext):
    """A real `SSLContext` that records every store loaded into it.

    Real, so `check_hostname` and `verify_mode` stay the genuine attributes
    the other tests assert on. `load_verify_locations` is overridden because
    the real one wants a PEM on disk, and this tree carries none - and because
    the property the cumulation rests on is precisely that this call ADDS
    authorities to a context and removes none.
    """

    def __new__(cls, protocol=ssl.PROTOCOL_TLS_CLIENT):
        context = super().__new__(cls, protocol)
        context.loaded = []
        context.authorities = set()
        return context

    def add_store(self, cafile):
        self.loaded.append(cafile)
        authority = STORE_AUTHORITIES.get(cafile)
        if authority is not None:
            self.authorities.add(authority)

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        if self.load_raises is not None:
            raise self.load_raises
        self.add_store(cafile)


class _ContextFactory:
    """Stand-in for `ssl.create_default_context`, recording its `cafile`.

    The tests carry no certificate material, so no real CA bundle can be
    loaded; everything downstream of the context - classification, messages,
    the header - is exercised for real. What this factory buys, beyond making
    the client constructible, is the ability to assert WHICH stores were
    handed to `ssl` and in which order, which is the whole point of the fix.

    `cafiles` records the store passed to `create_default_context` - the first
    one, and under `[rest] ca_file` the only one. The stores cumulated after
    it go through `load_verify_locations`, so they land in
    `contexts[n].loaded`, never in `cafiles`: asserting on `cafiles` alone
    would say nothing about the cumulation.
    """

    def __init__(self, raises=None, load_raises=None):
        self.cafiles = []
        self.contexts = []
        self.raises = raises
        self.load_raises = load_raises

    def __call__(self, cafile=None):
        self.cafiles.append(cafile)
        if self.raises is not None:
            raise self.raises
        context = _RecordingContext()
        context.load_raises = self.load_raises
        context.add_store(cafile)
        self.contexts.append(context)
        return context


class _TrustingUrlopen(_Urlopen):
    """`urlopen` that answers only when the chain's signer is trusted.

    Models the one property of `load_verify_locations` the whole fix rests on:
    a chain verifies as soon as ONE loaded store carries the authority that
    signed it. A "certificate" here is the NAME of that authority - no PEM, no
    key, nothing the charter keeps out of a test tree (CH-9.4).
    """

    def __init__(self, signed_by, payload):
        _Urlopen.__init__(self, payload=payload)
        self.signed_by = signed_by

    def __call__(self, request, timeout=None, context=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        self.contexts.append(context)
        if self.signed_by not in set(getattr(context, "authorities", ())):
            raise urllib.error.URLError(
                ssl.SSLCertVerificationError(
                    1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                       "failed: unable to get local issuer certificate"
                )
            )
        return _Response(self.payload)


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


class CaCumulationTest(RestTestCase):
    """The stores CUMULATE; only `[rest] ca_file` stays exclusive.

    Exclusive precedence fixed one failure and created its mirror image. A
    member that had kept its ORIGINAL splunkd certificate, on an instance
    whose administrator had filled `sslRootCAPath` with an enterprise CA for
    unrelated purposes, verified fine in 1.3.0 against `cacert.pem` and was
    refused in 1.4.0 - the enterprise CA outranked the truststore and had
    signed nothing at all. `load_verify_locations` adds authorities to a
    context and removes none, so loading both stores serves both
    configurations without ever verifying less than either would alone.

    The trust decision is modelled, not performed: a certificate is the NAME
    of the authority that signed it (CH-9.4 keeps certificate material out of
    a test tree as firmly as out of a log).
    """

    def _wired(self, configured, declared, present, signed_by,
               load_raises=None):
        factory = self.use_context_factory(
            _ContextFactory(load_raises=load_raises)
        )
        urlopen = self.use_urlopen(_TrustingUrlopen(
            signed_by, json.dumps(CURRENT_CONTEXT).encode("utf-8")
        ))
        resolution = rest.resolve_ca_file(
            configured, declared, SPLUNK_HOME, _present(*present)
        )
        return self.client(ca=resolution), factory, urlopen

    # -- the three trust outcomes ---------------------------------------- #

    def test_a_certificate_signed_by_the_declared_ca_is_accepted(self):
        """The 1.4.0 case that had to keep working: an enterprise certificate
        whose CA is declared in `server.conf`."""
        client, factory, _ = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "corp-root-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(failure)
        self.assertIn("run_confbtool", capabilities)
        self.assertEqual(factory.contexts[0].loaded, [ENTERPRISE_CA, SPLUNK_CA])

    def test_the_original_certificate_survives_a_foreign_sslrootcapath(self):
        """The regression this change exists to undo.

        The splunkd certificate is the ORIGINAL one, signed by the authority
        in `cacert.pem`; `sslRootCAPath` is filled with an enterprise CA that
        signed nothing here. 1.3.0 verified. 1.4.0, with `sslRootCAPath`
        outranking the truststore, refused. Cumulated, it verifies again.
        """
        client, factory, _ = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "splunk-default-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(
            failure, "the configuration that worked in 1.3.0 must work again"
        )
        self.assertIn("run_confbtool", capabilities)
        self.assertEqual(factory.contexts[0].loaded, [ENTERPRISE_CA, SPLUNK_CA])

    def test_a_certificate_signed_by_neither_store_is_refused(self):
        """Cumulating widens trust; it does not abolish it."""
        client, _, _ = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "an-unknown-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(capabilities, "fail-closed")
        self.assertEqual(failure.kind, rest.FAILURE_TLS)

    # -- `[rest] ca_file` stays exclusive -------------------------------- #

    def test_ca_file_is_the_only_store_loaded(self):
        client, factory, _ = self._wired(
            OPERATOR_CA, ENTERPRISE_CA,
            (OPERATOR_CA, ENTERPRISE_CA, SPLUNK_CA), "operator-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(failure)
        self.assertIn("run_confbtool", capabilities)
        self.assertEqual(factory.cafiles, [OPERATOR_CA])
        self.assertEqual(factory.contexts[0].loaded, [OPERATOR_CA])

    def test_ca_file_excludes_a_certificate_the_truststore_would_accept(self):
        """What exclusivity MEANS, rather than what it looks like: with
        `ca_file` set, a chain the Splunk truststore would have accepted is
        refused. An administrator who names an exact set of authorities keeps
        it exact."""
        client, factory, _ = self._wired(
            OPERATOR_CA, ENTERPRISE_CA,
            (OPERATOR_CA, ENTERPRISE_CA, SPLUNK_CA), "splunk-default-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_TLS)
        self.assertEqual(factory.contexts[0].loaded, [OPERATOR_CA])

    # -- the cumulation never masks a configuration error ---------------- #

    def test_a_declared_store_that_is_missing_still_fails_closed(self):
        """A1 in another costume, and the trap of this whole change.

        `sslRootCAPath` names a file that is not there, `cacert.pem` is - and
        the chain WOULD have verified against `cacert.pem` alone. Carrying on
        would be a silent fallback onto the remaining store. The run refuses,
        names the broken path, and emits nothing.
        """
        client, factory, urlopen = self._wired(
            "", ENTERPRISE_CA, (SPLUNK_CA,), "splunk-default-ca",
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertIn(ENTERPRISE_CA, failure.message)
        self.assertEqual(factory.cafiles, [])
        self.assertEqual(urlopen.requests, [])

        # CH-10.3: the two zeros above are read on recorders that do record.
        other, factory, urlopen = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "corp-root-ca",
        )
        other.get_capabilities()
        self.assertEqual(factory.cafiles, [ENTERPRISE_CA])
        self.assertEqual(len(urlopen.requests), 1)

    def test_a_complement_ssl_refuses_names_that_complement(self):
        """The second store is checked as strictly as the first, and the
        message points at the file that is actually broken - naming the first
        one would send an operator to fix a file that is perfectly fine."""
        client, _, urlopen = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "corp-root-ca",
            load_raises=ssl.SSLError("no start line"),
        )
        capabilities, failure = client.get_capabilities()
        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertIn(SPLUNK_CA, failure.message)
        self.assertNotIn(ENTERPRISE_CA, failure.message)
        self.assertEqual(urlopen.requests, [])

    def test_the_shipped_sslrootcapath_is_not_loaded_twice(self):
        """`server.conf` ships `sslRootCAPath` spelled at `cacert.pem` itself.
        The complement is then the same file: one store, named once."""
        resolution = rest.resolve_ca_file(
            "", "$SPLUNK_HOME/etc/auth/cacert.pem", SPLUNK_HOME,
            _present(SPLUNK_CA),
        )
        self.assertEqual(len(resolution.stores), 1)
        self.assertEqual(resolution.path, SPLUNK_CA)

    def test_an_absent_truststore_leaves_the_declaration_alone(self):
        """Nobody configured `cacert.pem`, so its absence is not a
        configuration error - only a DECLARED store can refuse."""
        resolution = rest.resolve_ca_file(
            "", ENTERPRISE_CA, SPLUNK_HOME, _present(ENTERPRISE_CA)
        )
        self.assertEqual(len(resolution.stores), 1)
        self.assertIsNone(resolution.refusal)

    # -- the message names every store ----------------------------------- #

    def test_the_tls_message_names_both_stores_and_both_sources(self):
        """Quoted whole rather than probed: an operator must read the sentence
        and know, without guessing, that TWO authority sets were loaded and
        which file each of them came from."""
        client, _, _ = self._wired(
            "", ENTERPRISE_CA, (ENTERPRISE_CA, SPLUNK_CA), "an-unknown-ca",
        )
        _, failure = client.get_capabilities()
        self.assertEqual(
            failure.message,
            "TLS verification of the splunkd certificate failed against every "
            "CA store loaded: %s (from %s), %s (from %s). If splunkd carries "
            "an enterprise certificate, declare its CA in server.conf "
            "[sslConfig] sslRootCAPath, or point [rest] ca_file of "
            "SA-conf-audit/local/confbtool.conf at it" % (
                ENTERPRISE_CA, rest.CA_SOURCE_SERVER_CONF,
                SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT,
            ),
        )


class CaPathAdversarialTest(RestTestCase):
    """CH-9.18: the path guard normalises like its consumer, segment by
    segment, and a relative declaration may not leave the anchor the contract
    gives it.

    `ca_file` and `sslRootCAPath` are both administrator-held settings, and a
    bad path here fails closed rather than opening anything - but CH-9.18 is
    written `exigé` with no dispensation for a trusted source, and the promise
    the contract actually makes is testable: "a relative path is anchored on
    $SPLUNK_HOME". `../../../../etc/passwd` reached `ssl` verbatim and
    designated a file that has nothing to do with $SPLUNK_HOME, so the promise
    was not kept.
    """

    #: Spellings of the same escape, including the graphies CH-9.18 names.
    TRAVERSALS = (
        "../../../../etc/passwd",
        "..\\..\\..\\..\\etc\\passwd",
        "./../../etc/passwd",
        "etc/../../../etc/passwd",
        "etc/auth/../../../../etc/passwd",
        "  ../../etc/passwd  ",
        "\xa0../../etc/passwd",
        "..//..//etc/passwd",
    )

    #: Graphies that look adversarial and are NOT: they designate a file under
    #: `$SPLUNK_HOME` and must resolve, or the guard would be refusing valid
    #: configurations (CH-10.2 - a refusal that refuses everything proves
    #: nothing).
    BENIGN = (
        "./etc/auth/corp-root-ca.pem",
        "etc//auth//corp-root-ca.pem",
        "etc/./auth/corp-root-ca.pem",
        "etc/auth/../auth/corp-root-ca.pem",
        "\xa0etc/auth/corp-root-ca.pem",
        "etc/auth/corp-root-ca.pem/",
    )

    def test_a_relative_path_that_climbs_above_splunk_home_is_refused(self):
        for raw in self.TRAVERSALS:
            for configured, declared, source in (
                (raw, None, rest.CA_SOURCE_SETTING),
                ("", raw, rest.CA_SOURCE_SERVER_CONF),
            ):
                with self.subTest(value=raw, source=source):
                    resolution = rest.resolve_ca_file(
                        configured, declared, SPLUNK_HOME, _present()
                    )
                    self.assertEqual(
                        resolution.refusal, rest.REFUSAL_TRAVERSAL
                    )
                    self.assertEqual(resolution.path, "")
                    self.assertEqual(resolution.source, source)

    def test_a_benign_graphy_still_resolves(self):
        for raw in self.BENIGN:
            with self.subTest(value=raw):
                resolution = rest.resolve_ca_file(
                    raw, None, SPLUNK_HOME, _present(ENTERPRISE_CA)
                )
                self.assertIsNone(resolution.refusal)
                self.assertEqual(resolution.path, ENTERPRISE_CA)
                self.assertTrue(resolution.exists)

    def test_a_percent_sequence_is_not_decoded_into_a_separator(self):
        """`ssl` and OpenSSL do not decode percent sequences, so neither does
        the guard: `..%2F..` is a file name, not a traversal. Decoding it here
        would invent an escape the file system will never perform - and
        normalising differently from the consumer is the defect CH-9.18 is
        about, in either direction."""
        for raw in ("..%2F..%2Fetc%2Fpasswd", "..%252F..%252Fetc"):
            with self.subTest(value=raw):
                resolution = rest.resolve_ca_file(
                    raw, None, SPLUNK_HOME, _present()
                )
                self.assertIsNone(resolution.refusal)
                self.assertIn("%2", resolution.path)
                self.assertTrue(resolution.path.startswith(SPLUNK_HOME))

    def test_an_absolute_path_outside_splunk_home_stays_allowed(self):
        """The anchor binds the RELATIVE form only. An operator bundle under
        `/etc/pki` is the documented case and must keep working."""
        resolution = rest.resolve_ca_file(
            OPERATOR_CA, None, SPLUNK_HOME, _present(OPERATOR_CA)
        )
        self.assertIsNone(resolution.refusal)
        self.assertEqual(resolution.path, OPERATOR_CA)

    def test_the_guard_and_ssl_receive_the_very_same_string(self):
        """CH-9.18 as an equality rather than an intention.

        The string the existence predicate is asked about and the string `ssl`
        is handed are the same object of comparison, so no spelling can be
        validated on one side and read as another resource on the other.
        """
        asked = []

        def exists(path):
            asked.append(path)
            return True

        factory = self.use_context_factory(_ContextFactory())
        for raw in (
            "etc/./auth//corp-root-ca.pem",
            "etc/auth/../auth/corp-root-ca.pem",
            "./etc/auth/corp-root-ca.pem",
            "$SPLUNK_HOME/etc/auth/../auth/corp-root-ca.pem",
            OPERATOR_CA,
        ):
            with self.subTest(value=raw):
                del asked[:]
                del factory.cafiles[:]
                resolution = rest.resolve_ca_file(
                    raw, None, SPLUNK_HOME, exists
                )
                self.client(ca=resolution)
                self.assertEqual(len(asked), 1)
                self.assertEqual(factory.cafiles, [resolution.path])
                self.assertEqual(asked, factory.cafiles)

    def test_a_refused_traversal_costs_no_network_call(self):
        factory = self.use_context_factory(_ContextFactory())
        urlopen = self.use_urlopen(
            _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
        )
        resolution = rest.resolve_ca_file(
            "../../../../etc/passwd", None, SPLUNK_HOME, _present()
        )
        capabilities, failure = self.client(ca=resolution).get_capabilities()

        self.assertIsNone(capabilities)
        self.assertEqual(failure.kind, rest.FAILURE_CA_FILE)
        self.assertIn(rest.CA_SOURCE_SETTING, failure.message)
        self.assertEqual(factory.cafiles, [])
        self.assertEqual(urlopen.requests, [])

        # CH-10.3: the same two recorders, shown to record.
        self.client(
            ca=CaResolution(SPLUNK_CA, rest.CA_SOURCE_SPLUNK_DEFAULT, True)
        ).get_capabilities()
        self.assertEqual(factory.cafiles, [SPLUNK_CA])
        self.assertEqual(len(urlopen.requests), 1)

    def test_the_normalisation_itself_reports_what_it_folded(self):
        """Unit level, so the table above cannot pass by accident of the
        surrounding resolution."""
        cases = (
            ("etc/./auth//x.pem", "etc/auth/x.pem", 0),
            ("etc/auth/../x.pem", "etc/x.pem", 0),
            ("../x.pem", "x.pem", 1),
            ("a/../../../x.pem", "x.pem", 2),
            ("/opt/splunk/etc/../auth/x.pem", "/opt/splunk/auth/x.pem", 0),
            ("C:\\Splunk\\etc\\.\\auth\\x.pem", "C:\\Splunk\\etc\\auth\\x.pem", 0),
            ("\\\\host\\share\\x.pem", "\\\\host\\share\\x.pem", 0),
            (".", "", 0),
        )
        for raw, expected, escapes in cases:
            with self.subTest(value=raw):
                self.assertEqual(rest.normalize_ca_path(raw), (expected, escapes))


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

    def test_the_enterprise_ca_is_the_first_store_handed_to_ssl(self):
        """The enterprise CA leads, and the truststore is CUMULATED after it.

        Asserted on `contexts[0].loaded`, not on `cafiles` alone: a cumulated
        store never goes through `create_default_context`, so `cafiles` would
        stay `[ENTERPRISE_CA]` whether the second store was loaded or silently
        dropped - a test that could not tell the two apart.
        """
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
        self.assertEqual(factory.contexts[0].loaded, [ENTERPRISE_CA, SPLUNK_CA])

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
        # The label of the class of cause, not the platform's own sentence -
        # `NetworkReasonWordingTest` below is where that rule is enforced.
        self.assertIn(
            rest.NETWORK_REASONS["ConnectionRefusedError"], failure.message
        )

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


class NetworkReasonWordingTest(RestTestCase):
    """CH-4.12: a message names the CLASS of cause, never the raw exception.

    `NETWORK_MESSAGE % str(exception)` used to render the platform's own text
    verbatim - `[WinError 3] Le chemin d'acces specifie est introuvable` on a
    French Windows, something else on the next release, something else again
    on Linux. Three defects in one string: it is localised, it is unstable,
    and it is free to quote a host or a path the message never meant to name.
    """

    #: Stands in for anything an operating system might write. If it ever
    #: reaches a message, the raw exception reached the user with it.
    PLATFORM_SENTINEL = "PLATFORM_TEXT_SENTINEL_9c1d /var/secret/path"

    def _message(self, raises):
        self.use_context_factory(_ContextFactory())
        self.use_urlopen(_Urlopen(raises=raises))
        _, failure = self.client().get_capabilities()
        self.assertEqual(failure.kind, rest.FAILURE_NETWORK)
        return failure.message

    def test_no_platform_text_reaches_the_message(self):
        shapes = (
            urllib.error.URLError(OSError(3, self.PLATFORM_SENTINEL)),
            urllib.error.URLError(
                ConnectionRefusedError(111, self.PLATFORM_SENTINEL)
            ),
            urllib.error.URLError(self.PLATFORM_SENTINEL),
            OSError(5, self.PLATFORM_SENTINEL),
            RuntimeError(self.PLATFORM_SENTINEL),
        )
        for shape in shapes:
            with self.subTest(shape=type(shape).__name__):
                # Calibration (CH-10.2, CH-10.3): the probe must have
                # something to find before its absence proves anything.
                self.assertIn(self.PLATFORM_SENTINEL, str(shape))
                message = self._message(shape)
                self.assertNotIn(self.PLATFORM_SENTINEL, message)
                self.assertNotIn("PLATFORM_TEXT_SENTINEL", message)

    def test_each_named_class_gets_its_own_stable_label(self):
        cases = (
            (ConnectionRefusedError(111, "refused"), "ConnectionRefusedError"),
            (ConnectionResetError(104, "reset"), "ConnectionResetError"),
            (ConnectionAbortedError(103, "aborted"), "ConnectionAbortedError"),
            (BrokenPipeError(32, "broken pipe"), "BrokenPipeError"),
            (PermissionError(13, "denied"), "PermissionError"),
        )
        for cause, key in cases:
            for shape in (cause, urllib.error.URLError(cause)):
                with self.subTest(cause=key, wrapped=shape is not cause):
                    self.assertEqual(
                        self._message(shape),
                        rest.NETWORK_MESSAGE % rest.NETWORK_REASONS[key],
                    )

    def test_the_socket_resolution_shape_is_recognised_by_name(self):
        """`socket.gaierror`, without importing `socket` - the layering rule
        keeps it out of the package, and `_is_timeout` already reads a class
        name for the same reason."""

        class gaierror(OSError):  # noqa: N801 - the `socket` spelling
            pass

        message = self._message(urllib.error.URLError(gaierror(-2, "unknown")))
        self.assertEqual(
            message, rest.NETWORK_MESSAGE % rest.NETWORK_REASONS["gaierror"]
        )

    def test_an_unnamed_cause_falls_back_to_a_qualified_default(self):
        """Not to the platform's text, and not to a class name either: an
        unlisted cause is one the port has not qualified, and the message says
        exactly that."""
        for shape in (
            OSError(5, "Input/output error"),
            RuntimeError("something entirely unexpected"),
            urllib.error.URLError(None),
        ):
            with self.subTest(shape=type(shape).__name__):
                self.assertEqual(
                    self._message(shape),
                    rest.NETWORK_MESSAGE % rest.NETWORK_REASON_DEFAULT,
                )

    def test_no_message_of_the_module_carries_a_class_name(self):
        """Family sweep (CH-10.4): every shape of `NoExceptionEscapesTest`,
        checked against every exception class name it can produce. A class
        name is stable, but it is still Python's vocabulary, not the
        operator's."""
        names = set()
        checked = 0
        for shape in NoExceptionEscapesTest.SHAPES:
            names.add(type(shape).__name__)
            reason = getattr(shape, "reason", None)
            if reason is not None:
                names.add(type(reason).__name__)
        self.assertGreaterEqual(len(names), 5)
        for shape in NoExceptionEscapesTest.SHAPES:
            with self.subTest(shape=type(shape).__name__):
                self.use_context_factory(_ContextFactory())
                self.use_urlopen(_Urlopen(raises=shape))
                _, failure = self.client().get_capabilities()
                checked += 1
                for name in names:
                    self.assertNotIn(name, failure.message)
        self.assertEqual(checked, len(NoExceptionEscapesTest.SHAPES))


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

    def test_an_unusable_splunkd_address_never_escapes(self):
        """The contract covers ADDRESSING too, not only the exchange.

        `urllib.request.Request` parses the URL as it builds the object, and
        the construction sat outside the `try`: an empty `splunkd_uri` - what
        the search process hands over when its metadata is incomplete - raised
        `ValueError: unknown url type` straight out of the module, past the
        docstring that promises no network exception ever does.
        """
        for uri in ("", "   ", "not a url", "localhost"):
            with self.subTest(uri=uri):
                self.use_context_factory(_ContextFactory())
                urlopen = self.use_urlopen(
                    _Urlopen(payload=json.dumps(CURRENT_CONTEXT).encode("utf-8"))
                )
                client = rest.RestClient(uri, SESSION_SENTINEL)

                capabilities, failure = client.get_capabilities()
                self.assertIsNone(capabilities, "fail-closed")
                self.assertEqual(failure.kind, rest.FAILURE_NETWORK)
                self.assertNotIn(SESSION_SENTINEL, failure.message)
                self.assertIsNone(client.get_server_name())
                # Nothing was addressable, so nothing was sent.
                self.assertEqual(urlopen.requests, [])

                # CH-10.3: the recorder records, on the same reading.
                rest.RestClient(URI, SESSION_SENTINEL).get_capabilities()
                self.assertEqual(len(urlopen.requests), 1)

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
