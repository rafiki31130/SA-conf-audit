"""Immutable data structures - no logic here (spec section 3.2)."""

from dataclasses import dataclass, field
from typing import Optional, Pattern, Tuple

#: Sentinel for the `*` conf argument: every conf present on disk.
STAR = "*"

#: Literal value of the `app` field for the `etc/system/{local,default}` layers
#: (D-19). NEVER the empty string: an empty cell forces every SPL consumer to
#: special-case it (`eval app=if(isnull(app),"system",app)`) before the least
#: aggregation, which defeats the flat output contract - `| stats count by app`
#: must be right with no fix-up. Internally the layer still carries an empty app
#: name (`LayerFile.app`), which is what keeps the `app=` filter a filter on
#: APPS: the system layer carries no app and no `app=` pattern selects it.
SYSTEM_APP = "system"

#: Field emitted only when `debug` is effective (D-17).
DEBUG_FIELD = "file_path"

#: Fields emitted only when `audit=true` (D-18): constant (`is_btool_winner` is
#: always `true` when only winners are emitted) or redundant with `file_path`
#: and `value` of the very same row.
VERDICT_FIELDS = ("is_btool_winner", "btool_winner_path", "btool_winner_value")


#: Synthetic raw text of an event (D-16). NOT a contract field: a rendering
#: affordance for the Events tab, which displays the raw text of an event.
#:
#: Measured on the lab (Splunk 9.4.6, 2026-08-12): an `events`-typed generating
#: command needs NEITHER `_raw` NOR `_time` to feed the events pipeline - the
#: job reports `eventCount = resultCount` and `/search/jobs/<sid>/events`
#: returns every row without either field. `_raw` is added because an event
#: with no raw text renders as an empty line in the Events tab; `_time` is NOT
#: fabricated (D-16): a configuration definition has no timestamp, and Splunk
#: does not ask for one.
RAW_FIELD = "_raw"


def output_fields(audit, debug):
    """The output fields of ONE invocation, in contract emission order.

    The output contract is **conditional** (CDC v1.3 section 5.1, D-17/D-18): a
    field that is not relevant in a mode is not emitted with an empty value, it
    is **not emitted at all** - an empty column stays visible in a result table
    and makes the option indistinguishable in use.

    | field                    | `audit=false` (default)      | `audit=true` |
    |--------------------------|------------------------------|--------------|
    | `file_path`              | only if `debug=true`         | always       |
    | the three verdict fields | absent                       | present      |
    | every other field        | present                      | present      |

    `audit=true` implies `debug=true` (D-18); the caller resolves that
    implication once, in `filters.validate_params`.
    """
    fields = [RAW_FIELD]
    if debug:
        fields.append(DEBUG_FIELD)
    fields.extend(
        ("conf", "stanza", "key", "value", "scope", "app", "layer",
         "precedence_rank")
    )
    if audit:
        fields.extend(VERDICT_FIELDS)
    fields.extend(("definition_count", "member", "anomaly"))
    return tuple(fields)


#: The fifteen output fields of the contract, in emission order (CDC section 5.1,
#: spec section 3.2) - the superset, emitted as such in `audit=true`. What one
#: given invocation emits is `output_fields(audit, debug)`, which prepends the
#: non-contractual `_raw`.
OUTPUT_FIELDS = tuple(
    name for name in output_fields(audit=True, debug=True) if name != RAW_FIELD
)


@dataclass(frozen=True)
class LayerFile:
    """One candidate file of one layer (spec section 5.1).

    `scope` is `system` or `app`; `app` is the app name, empty for `system`;
    `layer` is `local` or `default`; `path` is the absolute file path.
    """

    scope: str
    app: str
    layer: str
    path: str


@dataclass(frozen=True)
class RawDef:
    """One effective definition of one parsed file (spec section 4).

    Intra-file duplicates are already merged by the parser (section 4.4): a file
    yields at most one `RawDef` per `(stanza, key)`.
    """

    stanza: str
    key: str
    value: str
    lineno: int


@dataclass(frozen=True)
class Definition:
    """One definition, the unit of the output contract, located in its layer."""

    path: str
    conf: str
    stanza: str
    key: str
    value: str
    scope: str
    app: str
    layer: str


@dataclass(frozen=True)
class Group:
    """Every definition sharing `(conf, stanza, key)`, sorted by precedence.

    `defs[0]` is the internal winner (precedence_rank 1); `len(defs)` is
    `definition_count` (spec section 5.3).
    """

    conf: str
    stanza: str
    key: str
    defs: Tuple[Definition, ...]


@dataclass(frozen=True)
class BtoolRecord:
    """One definition line of the `btool --debug` output (before de-expansion)."""

    path: str
    key: str
    value: str


@dataclass(frozen=True)
class BtoolConf:
    """Parsed `btool <conf> list --debug` output (spec section 6.3).

    `stanzas` maps stanza name to a mapping of key to `BtoolRecord`; `headers`
    maps stanza name to the path carried by its header line - a resolution
    metadata, excluded from the definitions.
    """

    stanzas: dict
    headers: dict


@dataclass(frozen=True)
class BtoolWinner:
    """The btool verdict for one `(stanza, key)` group: at most one per group."""

    path: str
    value: str


@dataclass(frozen=True)
class Verdict:
    """Confrontation outcome for one group (spec section 6.5).

    `index` is the position, in the group's precedence order, of the definition
    designated by btool - `None` when btool designates none (unknown winner, or
    no verdict at all). `winner` is the raw btool verdict, `None` when absent.
    """

    index: Optional[int]
    winner: Optional[BtoolWinner]


@dataclass(frozen=True)
class Anomaly:
    """One `resolver_mismatch` anomaly, carrying both verdicts side by side."""

    conf: str
    stanza: str
    key: str
    internal: Optional[Definition]
    btool: Optional[BtoolWinner]
    definition_count: int


@dataclass(frozen=True)
class Params:
    """Validated invocation parameters (spec section 7.1).

    `confs` is either the STAR sentinel or a tuple of validated conf names.
    The `_raw` fields keep the operator's spelling for the log; the `_rx`
    fields are the compiled, anchored translations of the glob patterns.

    `debug` is the EFFECTIVE value, implication of D-18 already resolved
    (`audit=true` forces it): no module downstream re-derives it.
    """

    confs: object
    stanza_raw: str
    key_raw: str
    app_raw: Optional[str]
    stanza_rx: Pattern
    key_rx: Pattern
    app_rx: Optional[Pattern]
    audit: bool
    debug: bool


@dataclass(frozen=True)
class AppSettings:
    """Settings read from the app's own `confbtool.conf` (spec section 2.2)."""

    extra_key_patterns: Tuple[str, ...] = (
        "pass4SymmKey", "sslPassword", "*password*", "*secret*", "*token*",
    )
    extra_stanza_patterns: Tuple[str, ...] = ("credential*",)
    log_level: str = "INFO"
    verify_ssl: bool = True


@dataclass(frozen=True)
class BtoolResult:
    """Outcome of one btool invocation (BtoolPort, spec section 1.4)."""

    returncode: int
    stdout: str
    error: Optional[str] = None
