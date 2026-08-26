"""End-to-end pipeline over the in-memory ports (spec sections 1.2, 3.2, 10).

Covers: capability gate (exact message), btool failure (exact message, D-13),
row shape and emission order, the CONDITIONAL field set of D-17/D-18 (asserted
on the keys present, never on their content), the absence of ANY event field -
neither `_raw` nor `_time` (D-34, which cancels D-16), `app=system` (D-19), the
filter scoping of anomaly rows (D-35), rank/count insensitive to filters,
secrets end-to-end (`value` AND `btool_winner_value` hashed, no raw sensitive
value in any row), upstream pruning, member field.
"""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import pipeline, rest
from confaudit.errors import FatalBtoolError, FatalCapabilityError, FatalUsageError
from confaudit.model import BtoolResult, CaResolution, RestFailure
from confaudit.secrets import hash_value
from tests.helpers import (
    CollectingLog,
    FakeBtool,
    FakeFs,
    FakeRest,
    build_btool_output,
)

ETC = "/opt/splunk/etc"


def _run(fs, btool, rest=None, **kwargs):
    kwargs.setdefault("fieldnames", ["probe"])
    kwargs.setdefault("member", "member-01")
    kwargs.setdefault("etc_prefix", ETC)
    return pipeline.run(fs=fs, btool=btool, rest=rest or FakeRest(), **kwargs)


def _simple_fixture(value="v1"):
    fs = FakeFs()
    path = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = %s\n" % value)
    btool = FakeBtool({"probe": build_btool_output([
        (path, "[s]"), (path, "k = %s" % value),
    ])})
    return fs, btool, path


class CapabilityTest(unittest.TestCase):

    def test_missing_capability_exact_message(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError) as ctx:
            _run(fs, btool, rest=FakeRest(capabilities=frozenset(("search",))))
        self.assertEqual(
            str(ctx.exception),
            "confbtool: the run_confbtool capability is required to run this "
            "command. The app grants it to the admin role by default; any "
            "other role needs an explicit grant (authorize.conf) by a Splunk "
            "administrator.",
        )

    def test_failed_rest_check_never_presumes_the_authorization(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError):
            _run(fs, btool, rest=FakeRest(capabilities=None))

    def test_rejection_happens_before_any_etc_read(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError):
            _run(fs, btool, rest=FakeRest(capabilities=frozenset()))
        self.assertEqual(fs.read_paths, [])
        self.assertEqual(btool.calls, [])

    def test_an_impossible_check_is_refused_before_any_etc_read_too(self):
        """Fail-closed is unchanged: naming the cause does not soften it."""
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError):
            _run(fs, btool, rest=FakeRest(
                capabilities=None,
                failure=RestFailure(rest.FAILURE_TLS, "TLS verification failed"),
            ))
        self.assertEqual(fs.read_paths, [])
        self.assertEqual(btool.calls, [])


class CapabilityCheckFailureTest(unittest.TestCase):
    """Two outcomes, two messages, two branches.

    Until 1.4.0 a TLS failure, a 401, a timeout and a malformed answer all
    emitted the message about rights. That is what sent a production
    diagnosis hours down the wrong track: the message accused the only thing
    that was not at fault.
    """

    def _refusal(self, failure):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError) as ctx:
            _run(fs, btool, rest=FakeRest(capabilities=None, failure=failure))
        return str(ctx.exception)

    def test_an_impossible_check_does_not_emit_the_rights_message(self):
        message = self._refusal(
            RestFailure(rest.FAILURE_TLS, "TLS verification failed")
        )
        self.assertNotEqual(message, pipeline.CAPABILITY_MESSAGE)
        self.assertNotIn("authorize.conf", message)

    def test_the_two_messages_are_produced_by_two_distinct_paths(self):
        """The point of the whole fix, asserted as such."""
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalCapabilityError) as absent:
            _run(fs, btool, rest=FakeRest(capabilities=frozenset(("search",))))
        with self.assertRaises(FatalCapabilityError) as impossible:
            _run(fs, btool, rest=FakeRest(
                capabilities=None,
                failure=RestFailure(rest.FAILURE_TLS, "TLS verification failed"),
            ))
        self.assertNotEqual(str(absent.exception), str(impossible.exception))
        self.assertEqual(str(absent.exception), pipeline.CAPABILITY_MESSAGE)

    def test_the_exact_message_of_an_impossible_check(self):
        self.assertEqual(
            self._refusal(RestFailure(rest.FAILURE_TIMEOUT, "splunkd did not answer")),
            "confbtool: the run_confbtool capability could not be verified, "
            "so the command refuses to run - an impossible check never "
            "presumes the authorization. Cause: splunkd did not answer.",
        )

    def test_the_reason_reported_by_the_port_reaches_the_message(self):
        """Every nature of failure travels intact - the pipeline relays what
        the adapter measured, it never re-guesses it."""
        for kind, reason in (
            (rest.FAILURE_TLS,
             rest.TLS_MESSAGE % ("/opt/splunk/etc/auth/corp-root-ca.pem",
                                 rest.CA_SOURCE_SERVER_CONF)),
            (rest.FAILURE_AUTH, rest.AUTH_MESSAGE % 401),
            (rest.FAILURE_TIMEOUT, rest.TIMEOUT_MESSAGE % 30),
            (rest.FAILURE_UNREADABLE,
             rest.UNREADABLE_MESSAGE % rest.CURRENT_CONTEXT_PATH),
        ):
            with self.subTest(kind=kind):
                self.assertIn(reason, self._refusal(RestFailure(kind, reason)))

    def test_the_tls_reason_names_the_ca_file_that_was_used(self):
        """The acceptance criterion of the fix: an operator reads the refusal
        and knows which store the chain was checked against."""
        message = self._refusal(RestFailure(
            rest.FAILURE_TLS,
            rest.TLS_MESSAGE % ("/opt/splunk/etc/auth/corp-root-ca.pem",
                                rest.CA_SOURCE_SERVER_CONF),
        ))
        self.assertIn("TLS", message)
        self.assertIn("/opt/splunk/etc/auth/corp-root-ca.pem", message)
        self.assertIn("sslRootCAPath", message)

    def test_a_port_that_reports_nothing_still_refuses_and_says_so(self):
        message = self._refusal(None)
        self.assertIn(pipeline.UNQUALIFIED_FAILURE, message)


class BtoolFailureTest(unittest.TestCase):
    """D-13: without the oracle, no verdict - fatal, no partial output."""

    def test_nonzero_exit_exact_message(self):
        fs, _, _ = _simple_fixture()
        btool = FakeBtool({"probe": BtoolResult(2, "", "exit code 2")})
        with self.assertRaises(FatalBtoolError) as ctx:
            _run(fs, btool)
        self.assertEqual(
            str(ctx.exception),
            "confbtool: 'splunk btool probe list --debug' failed (exit code "
            "2); aborting: the winner verdict cannot be established without "
            "btool. No partial results were produced.",
        )

    def test_timeout_and_missing_binary_are_fatal_too(self):
        fs, _, _ = _simple_fixture()
        for cause in ("timeout after 60 s", "No such file or directory"):
            btool = FakeBtool({"probe": BtoolResult(-1, "", cause)})
            with self.assertRaises(FatalBtoolError) as ctx:
                _run(fs, btool)
            self.assertIn(cause, str(ctx.exception))

    def test_conf_without_any_file_is_not_an_error_and_skips_btool(self):
        fs, btool, _ = _simple_fixture()
        rows = _run(fs, btool, fieldnames=["probe,absent_conf"])
        self.assertEqual(btool.calls, ["probe"])
        self.assertEqual({row["conf"] for row in rows}, {"probe"})


#: The three field SEQUENCES of the contract (CDC v1.7 section 5.1, D-37),
#: written out literally here rather than derived from the code: the order is
#: contractual, so the test must fail when the code changes it, which asserting
#: against `model.output_fields` could never do.
FIELDS_DEFAULT = (
    "conf", "stanza", "key", "value", "anomaly", "member",
)
FIELDS_DEBUG = (
    "app", "layer", "scope", "conf", "stanza", "key", "value",
    "definition_count", "file_path", "anomaly", "member",
)
FIELDS_AUDIT = (
    "app", "layer", "scope", "conf", "stanza", "key", "value",
    "is_btool_winner", "btool_winner_value", "precedence_rank",
    "definition_count", "file_path", "btool_winner_path", "anomaly", "member",
)


class FieldOrderTest(unittest.TestCase):
    """D-37: the field set of each mode, IN ITS CONTRACTUAL ORDER.

    The order is what a user sees as the column order when the command runs
    without `| table`; the chunked writer of the SDK derives the CSV header
    from `list(record.keys())` of the first record of each chunk, so the key
    order of the dict IS the column order. Every assertion here therefore
    compares SEQUENCES (`tuple(row.keys())`), never sets.
    """

    def _mixed_fixture(self):
        """A run yielding the three kinds of row at once: a definition, a
        `parse_error` and a `resolver_mismatch`."""
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = zz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = zz"),
            (p_ok, "[ghost]"), (p_ok, "gk = gv"),
        ])})
        return fs, btool

    def test_default_mode_emits_six_fields_in_order(self):
        fs, btool, _ = _simple_fixture()
        self.assertEqual(tuple(_run(fs, btool)[0].keys()), FIELDS_DEFAULT)
        self.assertEqual(len(FIELDS_DEFAULT), 6)

    def test_debug_mode_emits_eleven_fields_in_order(self):
        fs, btool, _ = _simple_fixture()
        self.assertEqual(
            tuple(_run(fs, btool, debug=True)[0].keys()), FIELDS_DEBUG
        )
        self.assertEqual(len(FIELDS_DEBUG), 11)

    def test_audit_mode_emits_fifteen_fields_in_order(self):
        fs, btool, _ = _simple_fixture()
        self.assertEqual(
            tuple(_run(fs, btool, audit=True)[0].keys()), FIELDS_AUDIT
        )
        self.assertEqual(len(FIELDS_AUDIT), 15)

    def test_audit_true_debug_false_is_the_audit_sequence_too(self):
        # `audit=true` implies `debug=true` (D-18, kept by D-37).
        fs, btool, _ = _simple_fixture()
        row = _run(fs, btool, audit=True, debug=False)[0]
        self.assertEqual(tuple(row.keys()), FIELDS_AUDIT)

    def test_no_unexpected_field_comes_back_in_any_mode_on_any_row_kind(self):
        """The guard: this fails the moment a field reappears in a mode that
        must not emit it - on a definition row, a `parse_error` row or a
        `resolver_mismatch` row alike, since all three are built by different
        code paths and projected onto the same field set."""
        expected = {
            (False, False): FIELDS_DEFAULT,
            (False, True): FIELDS_DEBUG,
            (True, False): FIELDS_AUDIT,
            (True, True): FIELDS_AUDIT,
        }
        for (audit, debug), sequence in expected.items():
            fs, btool = self._mixed_fixture()
            rows = _run(fs, btool, audit=audit, debug=debug)
            self.assertEqual(
                {row["anomaly"] for row in rows},
                {"", "parse_error", "resolver_mismatch"},
                (audit, debug),
            )
            for row in rows:
                self.assertEqual(tuple(row.keys()), sequence, (audit, debug))

    def test_the_three_sequences_are_subsequences_of_the_contract_order(self):
        # Not a restatement of the code: it is what makes the three orders
        # mutually consistent - a field never moves relative to another one
        # from one mode to the next.
        from confaudit.model import CONTRACT_ORDER
        self.assertEqual(CONTRACT_ORDER, FIELDS_AUDIT)
        for sequence in (FIELDS_DEFAULT, FIELDS_DEBUG):
            kept = tuple(n for n in CONTRACT_ORDER if n in set(sequence))
            self.assertEqual(kept, sequence)


class RowShapeTest(unittest.TestCase):

    def test_fifteen_fields_in_contract_order_in_audit_mode(self):
        from confaudit.model import OUTPUT_FIELDS
        fs, btool, _ = _simple_fixture()
        rows = _run(fs, btool, audit=True)
        self.assertEqual(len(OUTPUT_FIELDS), 15)
        # The contract fields, in contract order, and NOTHING else (D-34).
        self.assertEqual(tuple(rows[0].keys()), OUTPUT_FIELDS)

    def test_nominal_row_content(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool, audit=True)[0]
        self.assertEqual(row["file_path"], path)
        self.assertEqual(row["conf"], "probe")
        self.assertEqual(row["stanza"], "s")
        self.assertEqual(row["key"], "k")
        self.assertEqual(row["value"], "v1")
        self.assertEqual(row["scope"], "app")
        self.assertEqual(row["app"], "00_corp_base")
        self.assertEqual(row["layer"], "local")
        self.assertEqual(row["precedence_rank"], 1)
        self.assertEqual(row["is_btool_winner"], "true")
        self.assertEqual(row["btool_winner_path"], path)
        self.assertEqual(row["btool_winner_value"], "v1")
        self.assertEqual(row["definition_count"], 1)
        self.assertEqual(row["member"], "member-01")
        self.assertEqual(row["anomaly"], "")

    def test_winner_fields_on_every_row_of_the_group(self):
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        p_app = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = app\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["btool_winner_path"], p_sys)
            self.assertEqual(row["btool_winner_value"], "sys")
            self.assertEqual(row["definition_count"], 2)
        self.assertEqual(
            [(row["precedence_rank"], row["is_btool_winner"]) for row in rows],
            [(1, "true"), (2, "false")],
        )
        self.assertEqual(rows[1]["file_path"], p_app)


class ConditionalFieldsTest(unittest.TestCase):
    """D-17/D-18, CDC v1.3 criterion 10: the output contract is CONDITIONAL.

    Everything here asserts on the SET OF KEYS actually present in the rows,
    never on their content - a field that is not relevant in a mode must be
    ABSENT, not present and empty.
    """

    VERDICT = {"is_btool_winner", "btool_winner_path", "btool_winner_value"}
    #: D-37 revises D-18: the default mode is reduced to the definition
    #: itself - `app`, `layer`, `scope`, `definition_count` and `file_path`
    #: come back with `debug=true`, the verdicts and `precedence_rank` only in
    #: audit mode.
    ALWAYS = set(FIELDS_DEFAULT)
    DEBUG_ADDED = {"app", "layer", "scope", "definition_count", "file_path"}
    AUDIT_ADDED = DEBUG_ADDED | VERDICT | {"precedence_rank"}

    def test_default_mode_omits_file_path_and_the_verdict_fields(self):
        fs, btool, _ = _simple_fixture()
        keys = set(_run(fs, btool)[0])
        self.assertNotIn("file_path", keys)
        self.assertEqual(keys & self.VERDICT, set())
        self.assertEqual(keys, self.ALWAYS)

    def test_debug_true_adds_the_origin_fields_and_nothing_else(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool, debug=True)[0]
        self.assertEqual(set(row), self.ALWAYS | self.DEBUG_ADDED)
        self.assertEqual(row["file_path"], path)
        self.assertEqual(set(row) & self.VERDICT, set())
        self.assertNotIn("precedence_rank", row)

    def test_audit_true_adds_file_path_and_the_verdict_fields(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool, audit=True)[0]
        self.assertEqual(set(row), self.ALWAYS | self.AUDIT_ADDED)
        self.assertEqual(row["file_path"], path)

    def test_audit_true_ignores_an_explicit_debug_false(self):
        fs, btool, path = _simple_fixture()
        row = _run(fs, btool, audit=True, debug=False)[0]
        self.assertIn("file_path", row)
        self.assertEqual(row["file_path"], path)

    def test_rank_and_count_left_the_default_mode(self):
        # D-37 REVISES the D-18 arbitration: keeping `precedence_rank` and
        # `definition_count` in every mode was a CDP bet on what a reader
        # wants at first glance; use said otherwise. `definition_count` comes
        # back with `debug=true`, `precedence_rank` only in audit mode.
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = app\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        row = _run(fs, btool)[0]
        self.assertNotIn("precedence_rank", row)
        self.assertNotIn("definition_count", row)

        fs, btool = self._contested_fixture()
        row = _run(fs, btool, debug=True)[0]
        self.assertEqual(row["definition_count"], 2)
        self.assertNotIn("precedence_rank", row)

        fs, btool = self._contested_fixture()
        row = _run(fs, btool, audit=True)[0]
        self.assertEqual(row["precedence_rank"], 1)
        self.assertEqual(row["definition_count"], 2)

    @staticmethod
    def _contested_fixture():
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = app\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        return fs, btool

    def test_every_row_of_one_run_carries_the_very_same_keys(self):
        # The SDK's chunked writer freezes the column header on the FIRST
        # record of a chunk: a heterogeneous row set would silently blank the
        # fields the later rows add. Anomaly rows are the risky ones - they
        # are built by other code paths.
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = zz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = zz"),
            (p_ok, "[ghost]"), (p_ok, "gk = gv"),
        ])})
        for kwargs in ({}, {"debug": True}, {"audit": True}):
            fs.read_paths = []
            rows = _run(fs, btool, **kwargs)
            kinds = {row["anomaly"] for row in rows}
            self.assertEqual(kinds, {"", "parse_error", "resolver_mismatch"})
            shapes = {tuple(row.keys()) for row in rows}
            self.assertEqual(len(shapes), 1, kwargs)


class NoEventFieldsTest(unittest.TestCase):
    """D-34 (cancels D-16) - GUARD: the command is generating, NEVER event-
    generating. No record ever carries `_raw` or `_time`, in any mode.

    This class exists to FAIL if either field comes back, by any route: the
    field-set builder, the projection, or a row builder. D-16 had put a
    synthetic `_raw` on every row and typed the command `events`; the decision
    was wrong and its removal must not silently regress.
    """

    #: Every field a Splunk record must not carry here. `_time` was never
    #: fabricated (a configuration definition has no timestamp); `_raw` was,
    #: and no longer is.
    FORBIDDEN = ("_raw", "_time")

    def _all_modes(self):
        return ({}, {"debug": True}, {"debug": False},
                {"audit": True}, {"audit": True, "debug": False})

    def _mixed_fixture(self):
        """A run that yields the three kinds of row at once: a definition, a
        `parse_error` (unreadable file) and a `resolver_mismatch` (a group
        btool knows and we do not)."""
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = zz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = zz"),
            (p_ok, "[ghost]"), (p_ok, "gk = gv"),
        ])})
        return fs, btool

    def test_no_emitted_record_carries_raw_or_time_in_any_mode(self):
        fs, btool = self._mixed_fixture()
        for kwargs in self._all_modes():
            fs.read_paths = []
            rows = _run(fs, btool, **kwargs)
            self.assertEqual(
                {row["anomaly"] for row in rows},
                {"", "parse_error", "resolver_mismatch"},
                kwargs,
            )
            for row in rows:
                for name in self.FORBIDDEN:
                    self.assertNotIn(name, row, (name, kwargs, row))

    def test_no_record_carries_any_underscore_prefixed_field(self):
        # Broader than the two names: every Splunk internal field is
        # underscore-prefixed, and the output contract has none.
        fs, btool = self._mixed_fixture()
        for kwargs in self._all_modes():
            fs.read_paths = []
            for row in _run(fs, btool, **kwargs):
                self.assertEqual(
                    [name for name in row if name.startswith("_")], [], kwargs
                )

    def test_the_field_set_builder_itself_yields_no_event_field(self):
        from confaudit.model import OUTPUT_FIELDS, output_fields
        for audit in (False, True):
            for debug in (False, True):
                fields = output_fields(audit=audit, debug=debug)
                for name in self.FORBIDDEN:
                    self.assertNotIn(name, fields, (name, audit, debug))
        for name in self.FORBIDDEN:
            self.assertNotIn(name, OUTPUT_FIELDS)

    def test_a_hashed_secret_leaves_no_cleartext_anywhere_in_the_record(self):
        # What the synthetic `_raw` used to risk - leaking a value or a path
        # the mode withholds - is now structurally impossible: there is no
        # field left outside the contract. Asserted on the whole record.
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nsslPassword = $7$cipher_text\n")
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "sslPassword = $7$cipher_text"),
        ])})
        row = _run(fs, btool)[0]
        blob = " ".join(str(value) for value in row.values())
        self.assertNotIn("$7$cipher_text", blob)
        self.assertIn(hash_value("$7$cipher_text"), blob)
        self.assertNotIn(path, blob)   # debug=false withholds the path


class EmissionOrderTest(unittest.TestCase):
    """CH-4.15: the capability check precedes every emission of the command.

    The wrapper's startup diagnostics NAME the resolved CA store, which is an
    infrastructure path. Emitted where 1.4.0 put them - ahead of the call to
    `pipeline.run` - an operator without `run_confbtool` learned that path and
    was refused immediately after. The check lives here, so the hook that
    releases them lives here too.
    """

    def _events(self, rest_port):
        events = []
        fs, btool, _ = _simple_fixture()
        try:
            _run(fs, btool, rest=rest_port,
                 on_authorized=lambda: events.append("emitted"))
        except FatalCapabilityError:
            events.append("refused")
        return events

    def test_nothing_is_emitted_when_the_right_is_absent(self):
        self.assertEqual(
            self._events(FakeRest(capabilities=frozenset(("search",)))),
            ["refused"],
        )

    def test_nothing_is_emitted_when_the_check_cannot_conclude(self):
        """Every shape of an impossible check, not just the reported one."""
        failures = (
            RestFailure(rest.FAILURE_TLS, "TLS verification failed"),
            RestFailure(rest.FAILURE_CA_FILE, "the store is unusable"),
            RestFailure(rest.FAILURE_AUTH, "authentication refused"),
            RestFailure(rest.FAILURE_TIMEOUT, "no answer"),
            RestFailure(rest.FAILURE_NETWORK, "unreachable"),
            None,
        )
        for failure in failures:
            with self.subTest(failure=failure.kind if failure else None):
                self.assertEqual(
                    self._events(FakeRest(capabilities=None, failure=failure)),
                    ["refused"],
                )

    def test_the_hook_fires_once_when_the_right_is_there(self):
        """Calibration (CH-10.2): the refusals above prove something only
        because the hook does fire when it should."""
        self.assertEqual(self._events(FakeRest()), ["emitted"])

    def test_the_hook_fires_before_the_run_it_describes(self):
        """A release valve, not a postscript: deferring the diagnostics behind
        the check must not push them behind the work they announce."""
        fs, btool, _ = _simple_fixture()
        seen = {}
        _run(fs, btool, on_authorized=lambda: seen.update(
            reads=list(fs.read_paths), calls=list(btool.calls),
        ))
        self.assertEqual(seen, {"reads": [], "calls": []})
        # CH-10.3: the two empty lists are read on instruments that do fill up.
        self.assertTrue(fs.read_paths)
        self.assertTrue(btool.calls)


class WrapperEmissionOrderTest(unittest.TestCase):
    """The same rule, asserted on the wrapper that actually emits.

    Behavioural rather than structural: a run refused for want of the right
    must not have shown the CA store path to anyone - not in a warning, not in
    the app log.
    """

    CA = CaResolution(
        "/opt/splunk/etc/auth/corp-root-ca.pem",
        "server.conf [sslConfig] sslRootCAPath",
        False,
    )

    def _patch(self, target, name, value):
        original = getattr(target, name)
        setattr(target, name, value)
        self.addCleanup(setattr, target, name, original)

    def _command(self, run_stub):
        import confbtool

        searchinfo = type("_SearchInfo", (), {
            "session_key": "SESSION_KEY_SENTINEL",
            "splunkd_uri": "https://127.0.0.1:8089",
        })()

        command = confbtool.ConfBtoolCommand()
        command._protocol_version = 2
        command.fieldnames = ["probe"]
        command._metadata = type("_Metadata", (), {"searchinfo": searchinfo})()

        warnings = []
        command.write_warning = warnings.append
        log = CollectingLog()

        self._patch(confbtool, "open_app_log", lambda *a, **k: log)
        self._patch(confbtool, "read_system_conf_bytes",
                    lambda *a, **k: (None, None))
        self._patch(confbtool, "resolve_ca_file", lambda *a, **k: self.CA)
        self._patch(confbtool, "RestClient", lambda *a, **k: FakeRest())
        self._patch(confbtool.pipeline, "run", run_stub)
        return command, warnings, log

    def _emitted(self, run_stub):
        command, warnings, log = self._command(run_stub)
        try:
            command._run()
        except FatalCapabilityError:
            pass
        return warnings + [message for _, message in log.messages]

    def test_a_refused_run_never_names_the_ca_store(self):
        """What the defect cost: a path handed to someone about to be told
        they have no right to be here."""
        def refuse(**kwargs):
            raise FatalCapabilityError(pipeline.CAPABILITY_MESSAGE)

        emitted = self._emitted(refuse)
        for message in emitted:
            self.assertNotIn(self.CA.path, message)
            self.assertNotIn(self.CA.source, message)

    def test_an_authorized_run_does_name_it(self):
        """Calibration (CH-10.2): the absence above is only meaningful because
        the diagnostics exist and do come out once the check has passed."""
        def authorize(**kwargs):
            kwargs["on_authorized"]()
            return []

        emitted = self._emitted(authorize)
        self.assertTrue(
            [message for message in emitted if self.CA.path in message],
            "the deferred diagnostics never came out at all",
        )

    def test_the_wrapper_hands_the_pipeline_its_hook(self):
        """The deferral is wiring, and wiring is what the wrapper is for."""
        captured = {}

        def capture(**kwargs):
            captured.update(kwargs)
            return []

        command, _, _ = self._command(capture)
        command._run()
        self.assertIn("on_authorized", captured)
        self.assertTrue(callable(captured["on_authorized"]))


class CommandMetadataTest(unittest.TestCase):
    """D-34: the command declares no `events` type, and declares
    `distributed=False` EXPLICITLY.

    `type='reporting'` is what makes Splunk treat the output as results rather
    than events (measured on the lab: with the SDK default the metadata reads
    `stateful` and the job still reports `eventCount = resultCount`).
    `distributed=False` is declared anyway - the lesson of D-34 is that a
    guarantee implied by the type disappears the day the type changes.
    """

    #: Types the SDK will let Splunk distribute. Anything else pins the
    #: command to the search head.
    DISTRIBUTABLE_TYPES = ("streaming",)

    def _configuration(self):
        import confbtool
        command = confbtool.ConfBtoolCommand()
        command._protocol_version = 2
        return command._configuration

    def test_the_class_declares_distributed_false(self):
        self.assertIs(self._configuration().distributed, False)

    def test_the_class_declares_no_events_type(self):
        self.assertNotEqual(self._configuration().type, "events")

    def test_the_chunked_metadata_reports_a_non_distributable_type(self):
        # These are the bytes Splunk actually receives on getinfo. The SDK
        # drops the `distributed` setting from the protocol-v2 payload, which
        # is why the explicit declaration has to be read on the class, not
        # here; what travels is the type, and it must not be distributable.
        settings = dict(self._configuration().items())
        self.assertEqual(settings["type"], "reporting")
        self.assertNotIn(settings["type"], self.DISTRIBUTABLE_TYPES)
        self.assertNotIn("distributed", settings)
        self.assertIs(settings["generating"], True)


class SystemAppNameTest(unittest.TestCase):
    """D-19: `app` reads `system` for the `etc/system/*` layers, never empty -
    `| stats count by app` must be right with no `eval` fix-up."""

    def test_system_layer_rows_carry_app_system(self):
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("system", "", "default", "probe", "[s]\nk = sysd\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual([row["app"] for row in rows], ["system", "system"])
        self.assertEqual([row["scope"] for row in rows], ["system", "system"])

    def test_app_layer_rows_keep_their_app_name(self):
        fs, btool, _ = _simple_fixture()
        self.assertEqual(_run(fs, btool, debug=True)[0]["app"], "00_corp_base")

    def test_parse_error_row_of_a_system_file_carries_app_system(self):
        fs = FakeFs()
        bad = fs.add("system", "", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = ok\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = ok"),
        ])})
        rows = _run(fs, btool, debug=True)
        error_row = [row for row in rows if row["anomaly"] == "parse_error"][0]
        self.assertEqual(error_row["app"], "system")

    def test_no_emitted_row_carries_an_empty_app(self):
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("app", "00_corp_base", "default", "probe", "[s]\nk = app\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertTrue(rows)
        self.assertNotIn("", {row["app"] for row in rows})


class AppSystemFilterTest(unittest.TestCase):
    """D-38: `app=system` selects the `etc/system/{local,default}` layers.

    General rule the decision adds to the contract, verified beyond this single
    case: **whatever a field displays must be selectable by the filter that
    corresponds to it.** Since D-19 the `app` column shows `system`; until
    v1.2.0 the `app=` filter refused that very value and returned zero rows.
    """

    @staticmethod
    def _fixture():
        """`[s] k` carried by system/local (winner), 00_corp_base and
        zz_sample_app; `[s] app_only` carried by 00_corp_base alone."""
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        p_00 = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nk = a00\napp_only = only\n")
        p_zz = fs.add("app", "zz_sample_app", "default", "probe",
                      "[s]\nk = azz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"), (p_00, "app_only = only"),
        ])})
        return fs, btool, (p_sys, p_00, p_zz)

    # -- filtering (audit=false) ----------------------------------------- #

    def test_app_system_returns_the_system_layer_winners(self):
        fs, btool, (p_sys, _, _) = self._fixture()
        rows = _run(fs, btool, app="system", debug=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_path"], p_sys)
        self.assertEqual((rows[0]["app"], rows[0]["scope"], rows[0]["key"]),
                         ("system", "system", "k"))

    def test_app_system_does_not_return_a_winner_carried_by_an_app(self):
        # `app_only` wins from 00_corp_base: out of scope for `app=system`.
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="system", debug=True)
        self.assertNotIn("app_only", [row["key"] for row in rows])

    def test_what_the_field_displays_is_what_the_filter_selects(self):
        # The rule of D-38, asserted as such: every distinct `app` value of an
        # unfiltered run must be selectable by `app=<that value>`.
        fs, btool, _ = self._fixture()
        displayed = {row["app"] for row in _run(fs, btool, audit=True)}
        self.assertEqual(displayed, {"system", "00_corp_base", "zz_sample_app"})
        for value in sorted(displayed):
            fs, btool, _ = self._fixture()
            rows = _run(fs, btool, app=value, audit=True)
            self.assertTrue(rows, value)
            self.assertIn(value, {row["app"] for row in rows}, value)

    # -- extrapolation (audit=true) -------------------------------------- #

    def test_app_system_extrapolates_from_the_keys_it_carries(self):
        fs, btool, (p_sys, p_00, p_zz) = self._fixture()
        rows = _run(fs, btool, app="system", audit=True)
        # `k` is carried by system: the whole group comes out, competitors
        # in the two apps included. `app_only` is not carried by system.
        self.assertEqual([row["key"] for row in rows], ["k", "k", "k"])
        self.assertEqual([row["file_path"] for row in rows],
                         [p_sys, p_00, p_zz])
        self.assertEqual([row["app"] for row in rows],
                         ["system", "00_corp_base", "zz_sample_app"])
        self.assertEqual([row["precedence_rank"] for row in rows], [1, 2, 3])

    def test_a_key_the_system_layer_does_not_carry_never_appears(self):
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="system", audit=True)
        self.assertNotIn("app_only", [row["key"] for row in rows])

    # -- non-regression of the real app names ---------------------------- #

    def test_filtering_by_a_real_app_name_is_unchanged(self):
        fs, btool, (_, p_00, _) = self._fixture()
        rows = _run(fs, btool, app="00_corp_base", debug=True)
        # `k`'s winner is the system one: still excluded. `app_only` wins in
        # the app: still returned.
        self.assertEqual([row["key"] for row in rows], ["app_only"])
        self.assertEqual(rows[0]["file_path"], p_00)

    def test_extrapolating_from_a_real_app_name_is_unchanged(self):
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="zz_*", audit=True)
        self.assertEqual([row["key"] for row in rows], ["k", "k", "k"])
        self.assertEqual([row["app"] for row in rows],
                         ["system", "00_corp_base", "zz_sample_app"])

    def test_a_pattern_matching_no_app_and_not_system_still_returns_nothing(self):
        fs, btool, _ = self._fixture()
        self.assertEqual(_run(fs, btool, app="no_such_app", audit=True), [])

    # -- assumed consequences of the rule -------------------------------- #

    def test_a_wildcard_now_covers_the_system_layer_too(self):
        # Assumed: `app=*` selects everything the `app` column can display,
        # `system` included - exactly like `| stats count by app` counts it.
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="*", audit=True)
        self.assertIn("system", {row["app"] for row in rows})

    def test_a_glob_prefix_matches_system_like_any_other_value(self):
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="sys*", audit=True)
        self.assertEqual({row["app"] for row in rows},
                         {"system", "00_corp_base", "zz_sample_app"})

    def test_scope_still_separates_the_two_natures(self):
        # `app=system` is now a filter like any other; `scope` remains what
        # distinguishes a system layer from an app that happened to be named
        # after it.
        fs, btool, _ = self._fixture()
        rows = _run(fs, btool, app="system", audit=True)
        scopes = {row["app"]: row["scope"] for row in rows}
        self.assertEqual(scopes["system"], "system")
        self.assertEqual(scopes["00_corp_base"], "app")

    # -- anomaly scoping (D-35 x D-38) ----------------------------------- #

    @staticmethod
    def _system_mismatch_fixture():
        """A `resolver_mismatch` on a group carried by the system layer ALONE,
        alongside a healthy group carried by an app."""
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        p_00 = fs.add("app", "00_corp_base", "local", "probe",
                      "[t]\nother = o\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = SOMETHING_ELSE"),
            (p_00, "[t]"), (p_00, "other = o"),
        ])})
        return fs, btool

    def test_a_mismatch_of_a_system_only_group_is_scoped_under_app_system(self):
        fs, btool = self._system_mismatch_fixture()
        rows = _run(fs, btool)
        self.assertEqual([row["anomaly"] for row in rows].count(
            "resolver_mismatch"), 1)

        fs, btool = self._system_mismatch_fixture()
        rows = _run(fs, btool, app="system")
        self.assertIn("resolver_mismatch", [row["anomaly"] for row in rows])

        fs, btool = self._system_mismatch_fixture()
        rows = _run(fs, btool, app="00_corp_base")
        self.assertNotIn("resolver_mismatch", [row["anomaly"] for row in rows])

    def test_a_groupless_mismatch_on_a_system_path_is_scoped_as_system(self):
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = v\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = v"),
            (p_sys, "[zz_ghost]"), (p_sys, "ghost_key = ghost_val"),
        ])})
        rows = _run(fs, btool, stanza="zz_ghost", app="system")
        self.assertEqual([row["anomaly"] for row in rows],
                         ["resolver_mismatch"])

        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = v\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = v"),
            (p_sys, "[zz_ghost]"), (p_sys, "ghost_key = ghost_val"),
        ])})
        self.assertEqual(_run(fs, btool, stanza="zz_ghost", app="00_*"), [])


class RankCountFilterInsensitivityTest(unittest.TestCase):
    """Section 5.3: rank, winner and count are computed on the real layer set,
    never recomputed after filtering."""

    @staticmethod
    def _fixture():
        fs = FakeFs()
        p_sys = fs.add("system", "", "local", "probe", "[s]\nk = sys\n")
        fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = a00\n")
        fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = azz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "k = sys"),
        ])})
        return fs, btool

    def test_same_rank_and_count_with_and_without_filters(self):
        fs, btool = self._fixture()
        unfiltered = _run(fs, btool, audit=True)
        by_value = {row["value"]: row for row in unfiltered}
        self.assertEqual(by_value["azz"]["precedence_rank"], 3)
        self.assertEqual(by_value["azz"]["definition_count"], 3)

        fs, btool = self._fixture()
        filtered = _run(fs, btool, audit=True, app="zz_*")
        by_value = {row["value"]: row for row in filtered}
        # Extrapolation emits the whole group; the zz row keeps rank 3 of 3.
        self.assertEqual(by_value["azz"]["precedence_rank"], 3)
        self.assertEqual(by_value["azz"]["definition_count"], 3)
        self.assertEqual(by_value["sys"]["precedence_rank"], 1)


class ParseErrorTest(unittest.TestCase):

    @staticmethod
    def _fixture():
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        p_ok = fs.add("app", "zz_sample_app", "local", "probe", "[s]\nk = zz\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_ok, "[s]"), (p_ok, "k = zz"),
        ])})
        return fs, btool, bad

    def test_unreadable_file_yields_parse_error_and_the_run_continues(self):
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool, audit=True)
        anomalies = [row for row in rows if row["anomaly"] == "parse_error"]
        self.assertEqual(len(anomalies), 1)
        row = anomalies[0]
        self.assertEqual(row["file_path"], bad)
        self.assertEqual(row["conf"], "probe")
        self.assertEqual((row["stanza"], row["key"], row["value"]), ("", "", ""))
        self.assertEqual((row["scope"], row["app"], row["layer"]),
                         ("app", "00_corp_base", "local"))
        self.assertEqual(row["precedence_rank"], "")
        self.assertEqual(row["definition_count"], "")
        self.assertEqual(row["member"], "member-01")
        # The other results are unchanged.
        winners = [row for row in rows if row["is_btool_winner"] == "true"]
        self.assertEqual(len(winners), 1)

    def test_parse_error_rows_are_never_filtered(self):
        # stanza=/key=/app= filters that match nothing, audit=false: the
        # parse_error row still comes out (spec section 4.6).
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool, debug=True,
                    stanza="no_match", key="no_match", app="no_match")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["anomaly"], "parse_error")
        self.assertEqual(rows[0]["file_path"], bad)

    def test_parse_error_rows_sort_at_the_head_of_their_conf(self):
        fs, btool, bad = self._fixture()
        rows = _run(fs, btool)
        self.assertEqual(rows[0]["anomaly"], "parse_error")

    def test_degraded_decoding_emits_parse_error_and_replacement_definitions(self):
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe",
                     b"[s]\nk = bad\xff\n")
        btool = FakeBtool({"probe": build_btool_output([
            (bad, "[s]"), (bad, "k = bad�"),
        ])})
        rows = _run(fs, btool)
        kinds = sorted(row["anomaly"] for row in rows)
        self.assertEqual(kinds, ["", "parse_error"])
        replacement = [row for row in rows if row["anomaly"] == ""][0]
        self.assertEqual(replacement["value"], "bad�")


class MismatchRowTest(unittest.TestCase):

    def test_mismatch_row_sorts_after_the_ranked_rows_of_its_group(self):
        fs = FakeFs()
        p1 = fs.add("system", "", "local", "probe", "[s]\nk = v1\n")
        p2 = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v2\n")
        # btool designates the rank-2 definition: inversion.
        btool = FakeBtool({"probe": build_btool_output([
            (p2, "[s]"), (p2, "k = v2"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual(
            [row["anomaly"] for row in rows], ["", "", "resolver_mismatch"]
        )
        mismatch = rows[2]
        self.assertEqual(mismatch["file_path"], p1)          # internal verdict
        self.assertEqual(mismatch["value"], "v1")
        self.assertEqual(mismatch["btool_winner_path"], p2)  # btool verdict
        self.assertEqual(mismatch["btool_winner_value"], "v2")
        self.assertEqual(mismatch["precedence_rank"], "")
        self.assertEqual(mismatch["is_btool_winner"], "")
        self.assertEqual(mismatch["definition_count"], 2)
        # The oracle primes: the winner flag follows btool.
        self.assertEqual(rows[1]["is_btool_winner"], "true")
        self.assertEqual(rows[0]["is_btool_winner"], "false")

    def test_no_anomaly_when_btool_omits_the_default_header(self):
        # D-21 end to end, on the shape measured for `inputs`: the source file
        # carries a `[default]`, btool expands it into every stanza but never
        # prints the `[default]` header. Before the fix this produced one
        # `resolver_mismatch` per inherited key per stanza (803 on the real
        # conf); the sweep must now be silent.
        fs = FakeFs()
        path = fs.add(
            "system", "", "default", "probe",
            "[default]\nindex = default\nhost = probe-host\n"
            "[stanza_a]\nown_a = a_val\n[stanza_b]\nown_b = b_val\n",
        )
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[stanza_a]"),
            (path, "host = probe-host"),
            (path, "index = default"),
            (path, "own_a = a_val"),
            (path, "[stanza_b]"),
            (path, "host = probe-host"),
            (path, "index = default"),
            (path, "own_b = b_val"),
        ])})
        rows = _run(fs, btool, audit=True)
        self.assertEqual([row["anomaly"] for row in rows], ["", "", "", ""])
        # Origin literality (D-7) is untouched: the two `[default]` keys are
        # emitted once each, under `stanza=default`.
        emitted = sorted((row["stanza"], row["key"]) for row in rows)
        self.assertEqual(emitted, [
            ("default", "host"), ("default", "index"),
            ("stanza_a", "own_a"), ("stanza_b", "own_b"),
        ])
        self.assertTrue(all(row["is_btool_winner"] == "true" for row in rows))

    def test_a_real_inversion_still_shouts_when_the_default_header_is_absent(self):
        # Same shape, but btool designates for `[stanza_a]` a value that is
        # NEITHER the inherited one nor any definition we read: the fix must
        # remove the false positives without removing the signal.
        fs = FakeFs()
        path = fs.add(
            "system", "", "default", "probe",
            "[default]\nindex = default\n[stanza_a]\nown_a = a_val\n",
        )
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[stanza_a]"),
            (path, "index = default"),
            (path, "own_a = SOMETHING_ELSE"),
        ])})
        rows = _run(fs, btool, audit=True)
        anomalies = [row for row in rows if row["anomaly"] == "resolver_mismatch"]
        self.assertEqual(len(anomalies), 1)
        self.assertEqual((anomalies[0]["stanza"], anomalies[0]["key"]),
                         ("stanza_a", "own_a"))
        self.assertEqual(anomalies[0]["value"], "a_val")
        self.assertEqual(anomalies[0]["btool_winner_value"], "SOMETHING_ELSE")
        # The inherited key is still de-expanded, not turned into a second
        # anomaly.
        self.assertEqual(
            sorted((row["stanza"], row["key"]) for row in rows
                   if row["anomaly"] == ""),
            [("default", "index"), ("stanza_a", "own_a")],
        )

class AnomalyScopingTest(unittest.TestCase):
    """D-35: anomaly rows are SCOPED BY THE FILTERS, each according to what it
    knows. Replaces the "anomaly rows are never filtered" rule of D-32.

    - `resolver_mismatch` carries a known `(conf, stanza, key)`: scoped like a
      definition, by `<conf>`, `stanza=`, `key=` and `app=`.
    - `parse_error` is scoped by CONF ONLY: the file could not be read, so
      which stanzas and keys it carried is unknown.

    The guarantee kept: INSIDE the requested perimeter an anomaly stays
    unmaskable. Outside it, it no longer pollutes an answer it does not
    concern.
    """

    def _ghost_fixture(self):
        """One definition `[s] k`, plus a `[zz_ghost] ghost_key` that btool
        designates and we never built - a groupless `resolver_mismatch`."""
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nk = v1\n")
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "k = v1"),
            (path, "[zz_ghost]"), (path, "ghost_key = ghost_val"),
        ])})
        return fs, btool

    def _shouting_group_fixture(self):
        """A group carried by `00_corp_base` on which btool designates a value
        we never read - a `resolver_mismatch` WITH a group."""
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nk = v1\n")
        other = fs.add("app", "zz_other_app", "local", "probe",
                       "[t]\nother = o\n")
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "k = SOMETHING_ELSE"),
            (other, "[t]"), (other, "other = o"),
        ])})
        return fs, btool

    # -- resolver_mismatch: scoped like a definition --------------------- #

    def test_an_out_of_scope_mismatch_is_not_emitted(self):
        fs, btool = self._ghost_fixture()
        rows = _run(fs, btool, stanza="no_match")
        self.assertEqual(rows, [])

    def test_an_in_scope_mismatch_is_still_emitted(self):
        fs, btool = self._ghost_fixture()
        rows = _run(fs, btool, stanza="zz_ghost")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["anomaly"], "resolver_mismatch")
        self.assertEqual((rows[0]["stanza"], rows[0]["key"]),
                         ("zz_ghost", "ghost_key"))
        # `definition_count` left the default mode with D-37: read it where
        # the mode emits it.
        fs, btool = self._ghost_fixture()
        row = _run(fs, btool, stanza="zz_ghost", debug=True)[0]
        self.assertEqual(row["definition_count"], 0)

    def test_a_key_filter_scopes_a_mismatch_both_ways(self):
        fs, btool = self._ghost_fixture()
        self.assertEqual(_run(fs, btool, key="no_match"), [])
        rows = _run(fs, btool, key="ghost_*")
        self.assertEqual([row["anomaly"] for row in rows],
                         ["resolver_mismatch"])

    def test_app_filter_scopes_a_mismatch_by_the_apps_of_its_group(self):
        # `app=` is evaluated at GROUP granularity: the anomaly is a statement
        # about the group, and in audit=false the group may have no emitted
        # definition at all - which is exactly when the user must be told.
        fs, btool = self._shouting_group_fixture()
        rows = _run(fs, btool, app="00_corp_base")
        kinds = [row["anomaly"] for row in rows]
        self.assertIn("resolver_mismatch", kinds)
        rows = _run(fs, btool, app="zz_other_app")
        self.assertNotIn("resolver_mismatch",
                         [row["anomaly"] for row in rows])

    def test_a_groupless_mismatch_is_scoped_by_the_app_of_its_btool_path(self):
        fs, btool = self._ghost_fixture()
        rows = _run(fs, btool, stanza="zz_ghost", app="00_corp_base")
        self.assertEqual([row["anomaly"] for row in rows],
                         ["resolver_mismatch"])
        self.assertEqual(_run(fs, btool, stanza="zz_ghost",
                              app="zz_absent_app"), [])

    def test_the_scan_still_shows_every_mismatch(self):
        # Scoping must not make an anomaly vanish from a search that COVERS it.
        fs, btool = self._ghost_fixture()
        rows = _run(fs, btool)
        self.assertEqual(
            sorted(row["anomaly"] for row in rows), ["", "resolver_mismatch"]
        )

    # -- parse_error: scoped by conf only -------------------------------- #

    def _parse_error_fixture(self):
        fs = FakeFs()
        bad = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        fs.unreadable.add(bad)
        ok = fs.add("app", "zz_sample_app", "local", "probe",
                    "[s]\nk = zz\n")
        other = fs.add("app", "00_corp_base", "local", "elsewhere",
                       "[e]\nek = ev\n")
        fs.unreadable.add(other)
        btool = FakeBtool({
            "probe": build_btool_output([(ok, "[s]"), (ok, "k = zz")]),
            "elsewhere": "",
        })
        return fs, btool, bad

    def test_a_parse_error_of_another_conf_is_not_emitted(self):
        fs, btool, bad = self._parse_error_fixture()
        rows = _run(fs, btool, fieldnames=["probe"])
        errors = [row for row in rows if row["anomaly"] == "parse_error"]
        self.assertEqual([row["conf"] for row in errors], ["probe"])

    def test_a_parse_error_survives_a_stanza_filter_that_cannot_match_it(self):
        # The file was unreadable: which stanzas it carried is UNKNOWN, so a
        # `stanza=` can never legitimately exclude it. Silencing it inside its
        # own conf would answer "nothing here" without knowing.
        fs, btool, bad = self._parse_error_fixture()
        for kwargs in ({"stanza": "no_match"}, {"key": "no_match"},
                       {"app": "zz_sample_app"},
                       {"stanza": "no_match", "audit": True}):
            rows = _run(fs, btool, fieldnames=["probe"], **kwargs)
            errors = [row for row in rows if row["anomaly"] == "parse_error"]
            self.assertEqual(len(errors), 1, kwargs)
            self.assertEqual(errors[0]["conf"], "probe", kwargs)


class ConfrontationNormalisationTest(unittest.TestCase):
    """D-23 to D-26 end to end: `btool --debug` is a NORMALISED view, not an
    echo of the source. Both sides are normalised to compare; the emission
    stays literal (D-7). Each shape below is the one measured on Splunk 9.4.6.
    """

    def test_splunk_home_in_a_stanza_name_is_not_an_anomaly(self):
        # Class A, 584 of the 784 residual anomalies. btool emits
        # `[monitor:///opt/splunk/var/log/x]` for the source spelling.
        fs = FakeFs()
        path = fs.add(
            "app", "00_corp_base", "local", "inputs",
            "[monitor://$SPLUNK_HOME/var/log/x]\ndisabled = 0\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[monitor:///opt/splunk/var/log/x]"),
            (path, "disabled = 0"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        self.assertEqual([row["anomaly"] for row in rows], [""])
        # The emitted stanza keeps the SOURCE spelling (D-7): normalising for
        # the comparison must never leak into the output contract.
        self.assertEqual(rows[0]["stanza"], "monitor://$SPLUNK_HOME/var/log/x")
        self.assertEqual(rows[0]["is_btool_winner"], "true")

    def test_relative_script_path_is_resolved_against_the_declaring_app(self):
        # Class A, second form: `[script://./bin/x.py]` declared in an app.
        fs = FakeFs()
        path = fs.add(
            "app", "zz_sample_app", "default", "inputs",
            "[script://./bin/x.py]\ninterval = 60\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[script:///opt/splunk/etc/apps/zz_sample_app/bin/x.py]"),
            (path, "interval = 60"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        self.assertEqual([row["anomaly"] for row in rows], [""])
        self.assertEqual(rows[0]["stanza"], "script://./bin/x.py")

    def test_doubled_backslash_in_a_key_name_is_not_an_anomaly(self):
        # Class D, 150 of the 784: btool collapses `\\` in KEY NAMES only.
        fs = FakeFs()
        path = fs.add(
            "app", "00_corp_base", "local", "sourcetypes",
            '[rule::probe]\nL-x_\\\\"\\\\"_L7( = 0.324888\n',
        )
        btool = FakeBtool({"sourcetypes": build_btool_output([
            (path, "[rule::probe]"),
            (path, 'L-x_\\"\\"_L7( = 0.324888'),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["sourcetypes"])
        self.assertEqual([row["anomaly"] for row in rows], [""])
        self.assertEqual(rows[0]["key"], 'L-x_\\\\"\\\\"_L7(')
        self.assertEqual(rows[0]["is_btool_winner"], "true")

    def test_unattributed_lines_no_longer_corrupt_the_emitted_verdict(self):
        # Class B, the only one that touched EMITTED data. Measured shape of
        # `[secure_gateway_modular_input://default]`: `disabled = 0` with a
        # path, then `host` and `index` with NONE. Read as continuations, they
        # made `btool_winner_value` carry `0\nhost = ...\nindex = ...` AND
        # deprived the group of any winner row in the default output.
        fs = FakeFs()
        path = fs.add(
            "app", "zz_sample_app", "local", "inputs",
            "[default]\nhost = $decideOnStartup\nindex = default\n"
            "[zz_scheme://default]\ndisabled = 0\n"
            "[splunktcp]\nroute = has_key:_utf8\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[splunktcp]"),
            (path, "host = $decideOnStartup"),
            (path, "index = default"),
            (path, "route = has_key:_utf8"),
            (path, "[zz_scheme://default]"),
            (path, "disabled = 0\nhost = $decideOnStartup\nindex = default"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        row = [r for r in rows if r["key"] == "disabled"][0]
        self.assertEqual(row["anomaly"], "")
        self.assertEqual(row["value"], "0")
        self.assertEqual(row["btool_winner_value"], "0")
        self.assertEqual(row["is_btool_winner"], "true")
        self.assertEqual([r["anomaly"] for r in rows], ["", "", "", ""])
        # The two `[default]` keys keep their verdict from the stanza where
        # btool DID attribute them, and are emitted once, at their origin.
        self.assertEqual(
            sorted((r["stanza"], r["key"]) for r in rows),
            [("default", "host"), ("default", "index"),
             ("splunktcp", "route"), ("zz_scheme://default", "disabled")],
        )

    def test_scheme_defaults_are_folded_back_onto_the_bare_stanza(self):
        # Class C / D-26: `[zz_scheme]` holds the defaults of every
        # `[zz_scheme://<name>]`; btool never prints its header and expands its
        # keys into each instance.
        fs = FakeFs()
        path = fs.add(
            "app", "zz_sample_app", "local", "inputs",
            "[zz_scheme]\ninterval = 77\n[zz_scheme://inst1]\ndisabled = 0\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[zz_scheme://inst1]"),
            (path, "disabled = 0"),
            (path, "interval = 77"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        self.assertEqual([row["anomaly"] for row in rows], ["", ""])
        self.assertEqual(
            sorted((row["stanza"], row["key"]) for row in rows),
            [("zz_scheme", "interval"), ("zz_scheme://inst1", "disabled")],
        )

    def test_a_bare_scheme_stanza_without_instance_still_shouts(self):
        # The measured `journald` case, documented residual of D-26: btool
        # prints nothing at all, so no verdict exists. The tool must say so,
        # not invent one.
        fs = FakeFs()
        path = fs.add(
            "app", "zz_sample_app", "default", "inputs",
            "[zz_lonely]\ninterval = 30\n[splunktcp]\nroute = has_key:_utf8\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[splunktcp]"), (path, "route = has_key:_utf8"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        anomalies = [row for row in rows if row["anomaly"] == "resolver_mismatch"]
        self.assertEqual(len(anomalies), 1)
        self.assertEqual((anomalies[0]["stanza"], anomalies[0]["key"]),
                         ("zz_lonely", "interval"))

    def test_the_signal_still_shouts_through_every_normalisation(self):
        # THE guard test of this increment: the four corrections remove false
        # positives, they must not muffle `resolver_mismatch`. Same fixture as
        # the class A and class D cases - normalised stanza, normalised key,
        # unattributed lines present - but btool designates a value we never
        # read. One anomaly, and exactly one.
        fs = FakeFs()
        path = fs.add(
            "app", "zz_sample_app", "local", "inputs",
            "[default]\nhost = $decideOnStartup\n"
            "[monitor://$SPLUNK_HOME/var/log/x]\ndisabled = 0\n"
            'k\\\\"z = ours\n'
            "[splunktcp]\nroute = has_key:_utf8\n",
        )
        btool = FakeBtool({"inputs": build_btool_output([
            (path, "[monitor:///opt/splunk/var/log/x]"),
            (path, "disabled = 0\nhost = $decideOnStartup"),
            (path, 'k\\"z = SOMETHING_ELSE'),
            (path, "[splunktcp]"),
            (path, "host = $decideOnStartup"),
            (path, "route = has_key:_utf8"),
        ])})
        rows = _run(fs, btool, audit=True, fieldnames=["inputs"])
        anomalies = [row for row in rows if row["anomaly"] == "resolver_mismatch"]
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["key"], 'k\\\\"z')
        self.assertEqual(anomalies[0]["value"], "ours")
        self.assertEqual(anomalies[0]["btool_winner_value"], "SOMETHING_ELSE")
        # ...and the two legitimate rows are still clean.
        self.assertEqual(
            sorted((row["stanza"], row["key"]) for row in rows
                   if row["anomaly"] == ""),
            [("default", "host"),
             ("monitor://$SPLUNK_HOME/var/log/x", "disabled"),
             ("monitor://$SPLUNK_HOME/var/log/x", 'k\\\\"z'),
             ("splunktcp", "route")],
        )
        # ...and the definition btool contradicts carries no winner flag: the
        # oracle designates a value we never read (case 3 of section 6.5).
        contested = [row for row in rows
                     if row["key"] == 'k\\\\"z' and row["anomaly"] == ""]
        self.assertEqual([row["is_btool_winner"] for row in contested], ["false"])


class SecretsEndToEndTest(unittest.TestCase):

    @staticmethod
    def _fixture():
        fs = FakeFs()
        fs.add("system", "", "local", "server",
               '[general]\nencrypt_fields = "probe:s:hidden_key"\n')
        p_sys = fs.add("system", "", "local", "probe",
                       "[s]\nhidden_key = $7$sys_cipher\n")
        fs.add("app", "00_corp_base", "local", "probe",
               "[s]\nhidden_key = $7$app_cipher\n")
        btool = FakeBtool({"probe": build_btool_output([
            (p_sys, "[s]"), (p_sys, "hidden_key = $7$sys_cipher"),
        ])})
        return fs, btool

    def test_value_and_btool_winner_value_are_hashed(self):
        fs, btool = self._fixture()
        rows = _run(fs, btool, audit=True)
        probe_rows = [row for row in rows if row["conf"] == "probe"]
        self.assertEqual(len(probe_rows), 2)
        for row in probe_rows:
            self.assertEqual(row["btool_winner_value"],
                             hash_value("$7$sys_cipher"))
        self.assertEqual(probe_rows[0]["value"], hash_value("$7$sys_cipher"))
        self.assertEqual(probe_rows[1]["value"], hash_value("$7$app_cipher"))

    def test_no_raw_sensitive_value_in_any_produced_row(self):
        fs, btool = self._fixture()
        rows = _run(fs, btool, audit=True)
        dump = repr(rows)
        self.assertNotIn("$7$sys_cipher", dump)
        self.assertNotIn("$7$app_cipher", dump)

    def test_configurable_key_patterns_apply_case_insensitively(self):
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\nMyPassword = cleartext\n")
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "MyPassword = cleartext"),
        ])})
        rows = _run(fs, btool)
        self.assertEqual(rows[0]["value"], hash_value("cleartext"))

    @staticmethod
    def _excluded_conf_fixture(conf):
        """One capability-shaped definition, in `conf`, matching *token*."""
        fs = FakeFs()
        fs.add("system", "", "local", "server",
               '[general]\nencrypt_fields = "server: :pass4SymmKey"\n')
        path = fs.add("system", "", "default", conf,
                      "[role_admin]\nedit_token_http = enabled\n")
        btool = FakeBtool({conf: build_btool_output([
            (path, "[role_admin]"), (path, "edit_token_http = enabled"),
        ])})
        return fs, btool

    def test_excluded_conf_emits_the_value_in_clear(self):
        # D-29 / A-1: `| confbtool authorize` must read as the conf itself.
        fs, btool = self._excluded_conf_fixture("authorize")
        rows = _run(fs, btool, fieldnames=["authorize"])
        self.assertEqual(rows[0]["value"], "enabled")
        self.assertNotIn("sha256:", repr(rows))

    def test_same_key_in_a_non_excluded_conf_is_still_hashed(self):
        fs, btool = self._excluded_conf_fixture("notexcluded")
        rows = _run(fs, btool, fieldnames=["notexcluded"])
        self.assertEqual(rows[0]["value"], hash_value("enabled"))


class LoadSettingsTest(unittest.TestCase):
    """`confbtool.conf` -> AppSettings (spec section 2.2)."""

    def test_defaults_when_no_file(self):
        settings = pipeline.load_settings(None, None)
        self.assertIn("authorize", settings.pattern_excluded_confs)
        self.assertIn("*password*", settings.extra_key_patterns)

    def test_local_layer_overrides_the_exclusion_list(self):
        default = b"[secrets]\npattern_excluded_confs = authorize, fields\n"
        local = b"[secrets]\npattern_excluded_confs = authorize\n"
        self.assertEqual(
            pipeline.load_settings(default, local).pattern_excluded_confs,
            ("authorize",),
        )

    def test_empty_value_disables_every_exclusion(self):
        default = b"[secrets]\npattern_excluded_confs =\n"
        self.assertEqual(
            pipeline.load_settings(default, None).pattern_excluded_confs, ()
        )


class OrderingAndPruningTest(unittest.TestCase):

    def test_emission_sorted_by_conf_stanza_key_rank(self):
        fs = FakeFs()
        pa = fs.add("app", "00_corp_base", "local", "aconf",
                    "[s2]\nk = x\n[s1]\nb = 1\na = 2\n")
        pb = fs.add("app", "00_corp_base", "local", "bconf", "[s]\nk = y\n")
        btool = FakeBtool({
            "aconf": build_btool_output([
                (pa, "[s1]"), (pa, "a = 2"), (pa, "b = 1"),
                (pa, "[s2]"), (pa, "k = x"),
            ]),
            "bconf": build_btool_output([(pb, "[s]"), (pb, "k = y")]),
        })
        rows = _run(fs, btool, fieldnames=["bconf,aconf"])
        self.assertEqual(
            [(row["conf"], row["stanza"], row["key"]) for row in rows],
            [("aconf", "s1", "a"), ("aconf", "s1", "b"),
             ("aconf", "s2", "k"), ("bconf", "s", "k")],
        )

    def test_explicit_conf_list_prunes_upstream(self):
        fs = FakeFs()
        p1 = fs.add("app", "00_corp_base", "local", "wanted", "[s]\nk = v\n")
        p2 = fs.add("app", "00_corp_base", "local", "unwanted", "[s]\nk = v\n")
        btool = FakeBtool({"wanted": build_btool_output([
            (p1, "[s]"), (p1, "k = v"),
        ])})
        _run(fs, btool, fieldnames=["wanted"])
        self.assertEqual(btool.calls, ["wanted"])
        self.assertNotIn(p2, fs.read_paths)

    def test_star_covers_every_conf_on_disk(self):
        fs = FakeFs()
        p1 = fs.add("app", "00_corp_base", "local", "aconf", "[s]\nk = v\n")
        p2 = fs.add("system", "", "default", "bconf", "[s]\nk = w\n")
        btool = FakeBtool({
            "aconf": build_btool_output([(p1, "[s]"), (p1, "k = v")]),
            "bconf": build_btool_output([(p2, "[s]"), (p2, "k = w")]),
        })
        rows = _run(fs, btool, fieldnames=["*"])
        self.assertEqual(sorted(btool.calls), ["aconf", "bconf"])
        self.assertEqual(len(rows), 2)

    def test_invalid_filter_is_fatal_before_any_btool_call(self):
        fs, btool, _ = _simple_fixture()
        with self.assertRaises(FatalUsageError):
            _run(fs, btool, stanza="")
        self.assertEqual(btool.calls, [])


if __name__ == "__main__":
    unittest.main()
