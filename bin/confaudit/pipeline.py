"""Pure orchestration of the execution flow (spec sections 1.2 and 3.1).

The pipeline runs entirely on top of the three ports (spec section 1.4):

- `fs`    (FsPort)    - layer enumeration and file reading;
- `btool` (BtoolPort) - btool invocation;
- `rest`  (RestPort)  - capability check, serverName.

In unit tests the ports are plain in-memory objects; nothing here touches the
disk, the network or a subprocess.

Normative ordering points (spec section 1.2): the volume guard runs AFTER the
filters/extrapolation (it counts what would be emitted, anomalies included) and
BEFORE any emission; the secret hashing runs AFTER the confrontation (which
compares raw values) and BEFORE the emission.
"""

import time

from . import btoolparser, confparser, filters, normalize, resolver, volume
from .confront import confront
from .errors import FatalBtoolError, FatalCapabilityError
from .model import STAR, AppSettings, emitted_app, output_fields
from .secrets import (
    SecretMatcher,
    parse_encrypt_fields,
    parse_pattern_list,
    hash_value,
)

#: Exact rejection message when the capability is ABSENT (spec section 10):
#: the check ran, the answer was read, and the right is not there.
CAPABILITY_MESSAGE = (
    "confbtool: the run_confbtool capability is required to run this command. "
    "The app grants it to the admin role by default; any other role needs an "
    "explicit grant (authorize.conf) by a Splunk administrator."
)

#: Exact rejection message when the check itself COULD NOT BE COMPLETED.
#:
#: A distinct message on purpose. Until 1.4.0 both outcomes emitted
#: `CAPABILITY_MESSAGE`, which only ever accused the rights: a TLS failure, a
#: 401, a timeout and an unreadable answer all read as "you lack the
#: capability". That cost hours of production diagnosis on the wrong track,
#: while the actual cause - a splunkd certificate signed by an enterprise CA,
#: against a truststore that did not carry it - was never named.
#:
#: The fail-closed decision is unchanged: an impossible check never presumes
#: the authorization. What changes is that the refusal now SAYS WHY, and the
#: reason is supplied by the port (`RestFailure.message`), not guessed here.
CAPABILITY_CHECK_MESSAGE = (
    "confbtool: the run_confbtool capability could not be verified, so the "
    "command refuses to run - an impossible check never presumes the "
    "authorization. Cause: %s."
)

#: Reason of last resort: a RestPort that reports no capability and no failure
#: either. Not reachable through `rest.py`, which always qualifies; it keeps
#: the pipeline honest against any other implementation of the port.
UNQUALIFIED_FAILURE = "the capability check returned neither an answer nor a reason"

#: Exact message of a btool invocation failure (spec section 6.2, D-13).
BTOOL_FAILED_MESSAGE = (
    "confbtool: 'splunk btool %s list --debug' failed (%s); aborting: the "
    "winner verdict cannot be established without btool. No partial results "
    "were produced."
)

#: The capability whose presence the pipeline requires (D-2).
CAPABILITY = "run_confbtool"


class NullLog:
    """Inert log: the journal is a diagnostic comfort, never a safety net
    (spec section 11)."""

    def debug(self, *args):
        pass

    def info(self, *args):
        pass

    def warning(self, *args):
        pass

    def error(self, *args):
        pass


def load_settings(default_data, local_data):
    """Build `AppSettings` from the app's own `confbtool.conf` layers.

    Parsed with the library's own parser (spec section 2.2): `default/` then
    `local/`, the `local` value winning key by key. Inputs are file bytes or
    `None` when the layer file is absent. Pure - the reading itself is done by
    the `layers` adapter.
    """
    values = {}
    for data in (default_data, local_data):
        if data is None:
            continue
        text, _ = confparser.decode_conf_bytes(data)
        for raw in confparser.parse_conf_text(text):
            values[(raw.stanza, raw.key)] = raw.value

    defaults = AppSettings()
    key_patterns = values.get(("secrets", "extra_key_patterns"))
    stanza_patterns = values.get(("secrets", "extra_stanza_patterns"))
    excluded_confs = values.get(("secrets", "pattern_excluded_confs"))
    level = values.get(("logging", "level"))
    verify = values.get(("rest", "verify_ssl"))
    ca_file = values.get(("rest", "ca_file"))
    return AppSettings(
        extra_key_patterns=(
            parse_pattern_list(key_patterns) if key_patterns is not None
            else defaults.extra_key_patterns
        ),
        extra_stanza_patterns=(
            parse_pattern_list(stanza_patterns) if stanza_patterns is not None
            else defaults.extra_stanza_patterns
        ),
        pattern_excluded_confs=(
            parse_pattern_list(excluded_confs) if excluded_confs is not None
            else defaults.pattern_excluded_confs
        ),
        log_level=(level or defaults.log_level).strip(),
        verify_ssl=(
            _parse_bool(verify, defaults.verify_ssl) if verify is not None
            else defaults.verify_ssl
        ),
        ca_file=(ca_file or defaults.ca_file).strip(),
    )


def _parse_bool(raw, default):
    text = (raw or "").strip().lower()
    if text in ("1", "true", "t", "yes", "y", "on"):
        return True
    if text in ("0", "false", "f", "no", "n", "off"):
        return False
    return default


def run(fs, btool, rest, fieldnames, stanza=None, key=None, app=None,
        audit=False, debug=False, settings=None, member="", etc_prefix="",
        log=None, emit=None):
    """Execute the whole flow of spec section 1.2; return the ordered rows.

    Raises `FatalCapabilityError`, `FatalUsageError`, `FatalBtoolError` or
    `VolumeRefused` - all converted by the wrapper into an explicit search
    error, with no partial output.

    When `emit` is given, each row is passed to it in emission order and the
    return value is the row count; otherwise the list of rows is returned. In
    both cases no row is built before the volume guard has passed.
    """
    log = log if log is not None else NullLog()
    settings = settings if settings is not None else AppSettings()

    # 1. Capability, before any reading of etc/ (spec section 10). An
    # impossible check (REST failure) never presumes the authorization - but
    # it is REFUSED UNDER ITS OWN MESSAGE, which names the cause the port
    # reported. Two outcomes, two messages, two branches: the absence of a
    # right and the impossibility of checking it are not the same event and
    # must not read as one.
    capabilities, failure = rest.get_capabilities()
    if capabilities is None:
        reason = failure.message if failure is not None else UNQUALIFIED_FAILURE
        log.error(
            "capability check failed (%s)"
            % (failure.kind if failure is not None else "unqualified")
        )
        raise FatalCapabilityError(CAPABILITY_CHECK_MESSAGE % reason)
    if CAPABILITY not in capabilities:
        log.error("capability check refused: %s is absent" % CAPABILITY)
        raise FatalCapabilityError(CAPABILITY_MESSAGE)

    # 2. Parameters (spec section 7.1).
    params = filters.validate_params(
        fieldnames, stanza=stanza, key=key, app=app, audit=audit, debug=debug,
    )
    log.info(
        "params: confs=%s stanza=%s key=%s app=%s audit=%s debug=%s" % (
            "*" if params.confs is STAR else ",".join(params.confs),
            params.stanza_raw, params.key_raw,
            "" if params.app_raw is None else params.app_raw,
            str(params.audit).lower(), str(params.debug).lower(),
        )
    )
    log.info("member: %s" % member)

    # 3. Conf list - upstream pruning: when the confs are explicit, only their
    # files are read (CDC section 7.2). `app=` never prunes (section 5.1).
    conf_names = list(fs.list_conf_names()) if params.confs is STAR \
        else list(params.confs)
    log.info("confs resolved: %d (%s)" % (len(conf_names), ",".join(conf_names)))

    # 4. Effective volume limit, by the library's own resolution of
    # `limits.conf` (spec section 8, reserve R-9: disk read, accepted by D-14).
    limit = _read_volume_limit(fs, log)
    log.info("volume limit: %d" % limit)

    # 5. Secret rules: `encrypt_fields` winning value (server.conf) + the
    # configurable complementary patterns (spec section 9.1).
    matcher = _build_secret_matcher(fs, settings, log)

    # 6. Per conf: parse, resolve, btool, de-expand, confront, select.
    selected = []      # (group, index, verdict)
    anomalies = []     # Anomaly (resolver_mismatch)
    parse_errors = []  # (conf, LayerFile)
    for conf in conf_names:
        layer_files = fs.list_layer_files(conf)
        if not layer_files:
            # No file on any layer: not an error - btool would emit an empty
            # output, the command emits nothing for this conf (mimicry, spec
            # section 6.2). The invocation is skipped: there is nothing to
            # confront and "one invocation per conf AT MOST" allows zero. As
            # soon as at least one file exists, btool IS invoked - even if our
            # parser extracted nothing from it - so that a parser/btool
            # disagreement surfaces as `resolver_mismatch`, never silently.
            log.info("conf=%s files=0 defs=0 (no layer file)" % conf)
            continue
        parsed, failed = _parse_layer_files(fs, layer_files)
        parse_errors.extend((conf, layer_file) for layer_file in failed)
        groups = resolver.resolve(conf, parsed)

        started = time.monotonic()
        result = btool.run(conf)
        btool_ms = int((time.monotonic() - started) * 1000)
        if result.returncode != 0 or result.error:
            cause = result.error or ("exit code %d" % result.returncode)
            log.error("btool failed on conf=%s (%s)" % (conf, cause))
            raise FatalBtoolError(BTOOL_FAILED_MESSAGE % (conf, cause))

        # Both sides of the confrontation are spelled in BTOOL's namespace
        # (D-23, D-25): `$SPLUNK_HOME` expanded, relative scheme path resolved,
        # doubled backslash of a key collapsed. The emission stays literal -
        # `groups` itself is never rewritten (D-7).
        splunk_home = normalize.splunk_home_from_etc(etc_prefix)
        literal = {
            (
                normalize.stanza_for_match(
                    definition.stanza, splunk_home, definition.path
                ),
                normalize.key_for_match(definition.key),
                definition.path,
                definition.value,
            )
            for group in groups.values() for definition in group.defs
        }
        # `(key, value)` pairs of our `[default]` definitions: what lets the
        # output parser tell an unattributed definition from a continuation
        # (D-24). Keys in btool's spelling, values byte for byte.
        default_pairs = {
            (key, value) for stanza, key, path, value in literal
            if stanza == "default"
        }
        parsed_output = btoolparser.parse_btool_output(
            result.stdout, etc_prefix, default_pairs
        )
        winners = btoolparser.deexpand(parsed_output, literal)
        verdicts, conf_anomalies = confront(
            conf, groups, winners,
            match_key=lambda group: _match_key(group, splunk_home),
        )
        # D-35: a `resolver_mismatch` carries a known (conf, stanza, key), so
        # it is scoped like a definition. A `parse_error` is not: it is scoped
        # by conf alone, which this per-conf loop already does.
        kept_anomalies = filters.select_anomalies(
            conf_anomalies, groups, params
        )
        anomalies.extend(kept_anomalies)
        selected.extend(
            (group, index, verdicts[(group.stanza, group.key)])
            for group, index in filters.select(groups, verdicts, params)
        )
        log.info(
            "conf=%s files=%d defs=%d groups=%d btool_ms=%d "
            "anomalies=%d/%d (kept/found)" % (
                conf, len(parsed) + len(failed),
                sum(len(group.defs) for group in groups.values()),
                len(groups), btool_ms,
                len(kept_anomalies), len(conf_anomalies),
            )
        )

    # 7. Volume guard (D-8): count what WOULD be emitted - the selected
    # definitions plus the anomaly lines the filters kept (D-35: a
    # `resolver_mismatch` is scoped like a definition, a `parse_error` by conf)
    # - BEFORE building or emitting a single row.
    row_count = len(selected) + len(parse_errors) + len(anomalies)
    try:
        volume.check(row_count, limit)
    except Exception:
        log.info("refused: %d rows over limit %d" % (row_count, limit))
        raise

    # 8. Row construction: secret hashing happens here, after the
    # confrontation (raw values) and before the emission (spec section 9.2).
    #
    # The field set is computed ONCE for the whole run (D-17, D-18) and every
    # row is projected onto it, so all rows of one invocation carry exactly the
    # same keys, in the same order. This is not cosmetic: the chunked writer of
    # the SDK freezes the column header on the FIRST record of a chunk and
    # silently blanks whatever a later record adds - a heterogeneous row set
    # would produce results depending on the emission order.
    fields = output_fields(params.audit, params.debug)
    built = []
    for conf, layer_file in parse_errors:
        built.append(_parse_error_row(conf, layer_file, member))
    for group, index, verdict in selected:
        built.append(_definition_row(group, index, verdict, member, matcher))
    for anomaly in anomalies:
        built.append(_mismatch_row(anomaly, member, matcher))

    # 9. Emission order (spec section 3.2): conf, stanza, key,
    # precedence_rank, code-point string comparisons. `parse_error` rows
    # (empty stanza/key) land at the head of their conf; a `resolver_mismatch`
    # row (empty rank) lands after the ranked rows of its group.
    #
    # The sort runs on the FULL rows, BEFORE the projection: since D-37 the
    # default mode does not emit `precedence_rank`, so sorting projected rows
    # would look for a key that is no longer there. The emission ORDER of the
    # rows and the column order of the record are two different contracts; only
    # the second one is mode-dependent.
    built.sort(key=_sort_key)
    rows = [_project(row, fields) for row in built]
    log.info("emitting %d rows" % len(rows))

    if emit is not None:
        for row in rows:
            emit(row)
        return len(rows)
    return rows


def _match_key(group, splunk_home):
    """The `(stanza, key)` under which a group is looked up among the btool
    verdicts (D-23, D-25).

    The relative form of a scheme stanza is anchored on the file of the RANK-1
    definition. A stanza declared under the same relative spelling by two
    different apps would be two distinct stanzas for btool and a single group
    for us; not observed on the measured corpus, and resolving it would require
    splitting a group by app - a contract change, not a normalisation.
    """
    return (
        normalize.stanza_for_match(group.stanza, splunk_home, group.defs[0].path),
        normalize.key_for_match(group.key),
    )


def _project(row, fields):
    """Keep only `fields`, in the order of `fields` (D-17, D-18).

    A field that is not relevant in the current mode is ABSENT from the record,
    never present with an empty value: an empty column stays visible in a
    result table, which is exactly what made `debug=` look like it did nothing.

    A record carries the contract fields and NOTHING else (D-34): the command
    is generating, never event-generating - no `_raw`, no `_time`.
    """
    return {name: row[name] for name in fields}


def _sort_key(row):
    rank = row["precedence_rank"]
    ranked = isinstance(rank, int)
    return (
        row["conf"], row["stanza"], row["key"],
        0 if ranked else 1, rank if ranked else 0,
    )


def _parse_layer_files(fs, layer_files):
    """Read and parse the given layer files.

    Returns `(parsed, failed)`: `parsed` is a list of `(LayerFile, defs)`,
    `failed` the list of `LayerFile` that must yield a `parse_error` row. A
    degraded decoding contributes to BOTH (one `parse_error` row AND the
    replacement definitions - the resolution is never amputated, spec
    section 4.6). No per-file error is fatal (CDC section 5.4).
    """
    parsed = []
    failed = []
    for layer_file in layer_files:
        try:
            data = fs.read_bytes(layer_file.path)
        except OSError:
            failed.append(layer_file)
            continue
        text, degraded = confparser.decode_conf_bytes(data)
        if degraded:
            failed.append(layer_file)
        defs = confparser.parse_conf_text(text)
        if defs:
            parsed.append((layer_file, defs))
    return parsed, failed


def _resolve_winning_value(fs, conf, stanza, key):
    """Winning value of `(conf, stanza, key)` by the library's own resolution.

    Used for `limits.conf [searchresults] maxresultrows` and for
    `server.conf encrypt_fields`. Returns `None` when the group is absent.
    Per-file errors are silently skipped here: these reads feed internal
    settings, they are not audit output.
    """
    parsed, _ = _parse_layer_files(fs, fs.list_layer_files(conf))
    groups = resolver.resolve(conf, parsed)
    group = groups.get((stanza, key))
    if group is None:
        return None
    return group.defs[0].value


def _read_volume_limit(fs, log):
    raw = _resolve_winning_value(fs, "limits", "searchresults", "maxresultrows")
    if raw is not None:
        try:
            return int(raw.strip())
        except ValueError:
            pass
    log.warning(
        "maxresultrows not readable from limits.conf [searchresults]; "
        "falling back to %d" % volume.DEFAULT_LIMIT
    )
    return volume.DEFAULT_LIMIT


def _build_secret_matcher(fs, settings, log):
    # M-5 locates `encrypt_fields` in the `[general]` stanza of `server.conf`;
    # the empty-stanza spelling would resolve under `default`. Both are read,
    # `[general]` first.
    raw = _resolve_winning_value(fs, "server", "general", "encrypt_fields")
    if raw is None:
        raw = _resolve_winning_value(fs, "server", "default", "encrypt_fields")
    rules = parse_encrypt_fields(
        raw or "",
        on_malformed=lambda entry: log.warning(
            "malformed encrypt_fields entry ignored: %s" % entry
        ),
    )
    if raw is None:
        log.warning(
            "encrypt_fields not readable from server.conf; only the "
            "configurable secret patterns apply"
        )
    return SecretMatcher(rules=rules, settings=settings)


def _definition_row(group, index, verdict, member, matcher):
    """Full row of one definition; `_project` then drops the fields the mode
    does not emit. Every field is computed unconditionally - the mode governs
    what is EMITTED, never what is COMPUTED (the btool confrontation runs in
    both modes, it is what feeds `is_btool_winner` and the audit itself)."""
    definition = group.defs[index]
    sensitive = matcher.is_sensitive(group.conf, group.stanza, group.key)
    winner = verdict.winner
    winner_path = winner.path if winner is not None else ""
    winner_value = winner.value if winner is not None else ""
    return {
        "file_path": definition.path,
        "conf": group.conf,
        "stanza": group.stanza,
        "key": group.key,
        "value": hash_value(definition.value) if sensitive else definition.value,
        "scope": definition.scope,
        "app": emitted_app(definition.app),
        "layer": definition.layer,
        "precedence_rank": index + 1,
        "is_btool_winner": "true" if verdict.index == index else "false",
        "btool_winner_path": winner_path,
        "btool_winner_value": (
            hash_value(winner_value) if sensitive and winner is not None
            else winner_value
        ),
        "definition_count": len(group.defs),
        "member": member,
        "anomaly": "",
    }


def _parse_error_row(conf, layer_file, member):
    """`parse_error` row (spec section 3.2): file identity filled, definition
    fields empty. Never filtered by `stanza=`/`key=`/`app=` nor by `audit` - an
    unparsed file may concern any key, silencing it would skew the audit."""
    return {
        "file_path": layer_file.path,
        "conf": conf,
        "stanza": "",
        "key": "",
        "value": "",
        "scope": layer_file.scope,
        "app": emitted_app(layer_file.app),
        "layer": layer_file.layer,
        "precedence_rank": "",
        "is_btool_winner": "",
        "btool_winner_path": "",
        "btool_winner_value": "",
        "definition_count": "",
        "member": member,
        "anomaly": "parse_error",
    }


def _mismatch_row(anomaly, member, matcher):
    """`resolver_mismatch` row: both verdicts side by side (spec section 3.2).

    Internal side = rank-1 definition when it exists; btool side = btool
    verdict when it exists. Hashing applies to anomaly rows too (spec 9.2)."""
    sensitive = matcher.is_sensitive(anomaly.conf, anomaly.stanza, anomaly.key)
    internal = anomaly.internal
    winner = anomaly.btool
    value = internal.value if internal is not None else ""
    winner_value = winner.value if winner is not None else ""
    return {
        "file_path": internal.path if internal is not None else "",
        "conf": anomaly.conf,
        "stanza": anomaly.stanza,
        "key": anomaly.key,
        "value": hash_value(value) if sensitive and internal is not None else value,
        "scope": internal.scope if internal is not None else "",
        "app": emitted_app(internal.app) if internal is not None else "",
        "layer": internal.layer if internal is not None else "",
        "precedence_rank": "",
        "is_btool_winner": "",
        "btool_winner_path": winner.path if winner is not None else "",
        "btool_winner_value": (
            hash_value(winner_value) if sensitive and winner is not None
            else winner_value
        ),
        "definition_count": anomaly.definition_count,
        "member": member,
        "anomaly": "resolver_mismatch",
    }
