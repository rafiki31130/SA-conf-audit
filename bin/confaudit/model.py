"""Immutable data structures - no logic here (spec section 3.2)."""

from dataclasses import dataclass
from typing import Optional, Pattern, Tuple

#: Sentinel for the `*` conf argument: every conf present on disk.
STAR = "*"

#: Literal value of the `app` field for the `etc/system/{local,default}` layers
#: (D-19). NEVER the empty string: an empty cell forces every SPL consumer to
#: special-case it (`eval app=if(isnull(app),"system",app)`) before the least
#: aggregation, which defeats the flat output contract - `| stats count by app`
#: must be right with no fix-up. Internally the layer still carries an empty app
#: name (`LayerFile.app`); `emitted_app` below is the single place that turns
#: that internal spelling into the one the field shows AND the one the `app=`
#: filter matches against (D-38).
SYSTEM_APP = "system"


def emitted_app(app):
    """The `app` value a layer is SEEN under - displayed and filtered alike.

    `LayerFile.app` / `Definition.app` is empty on the system layers; the field
    shows `system` (D-19) and, since D-38, the `app=` filter matches against
    this very same spelling. One function, so the two can never drift apart
    again: **whatever a field displays must be selectable by the filter that
    corresponds to it** (D-38, general rule of the contract). The previous split
    - display `system`, filter on apps only - meant an operator who read
    `system` in a column and typed it into `app=` got zero rows.
    """
    return app or SYSTEM_APP


#: The fifteen output fields in CONTRACT ORDER (D-37, CDC v1.7 section 5.1).
#: The order is CONTRACTUAL: it is the order in which the columns must appear
#: to a user who runs the command without `| table`, and it is deliberately not
#: alphabetical. Every mode emits a SUBSEQUENCE of this tuple - which is what
#: keeps the three orders consistent with one another by construction.
CONTRACT_ORDER = (
    "app", "layer", "scope", "conf", "stanza", "key", "value",
    "is_btool_winner", "btool_winner_value", "precedence_rank",
    "definition_count", "file_path", "btool_winner_path", "anomaly", "member",
)

#: The six fields of the default mode (`audit=false debug=false`): the
#: definition and nothing else - what one reads, without its origin.
DEFAULT_FIELDS = frozenset((
    "conf", "stanza", "key", "value", "anomaly", "member",
))

#: The five fields `debug=true` adds (eleven in total): the physical and
#: logical origin of the definition, plus the count that says the key is
#: contested.
DEBUG_FIELDS = frozenset((
    "app", "layer", "scope", "definition_count", "file_path",
))

#: The four fields `audit=true` adds (fifteen in total): the btool verdict and
#: the rank, meaningless when only winners are emitted.
AUDIT_FIELDS = frozenset((
    "is_btool_winner", "btool_winner_value", "precedence_rank",
    "btool_winner_path",
))


def output_fields(audit, debug):
    """The output fields of ONE invocation, in contract order (D-37).

    The output contract is **conditional AND ordered** (CDC v1.7 section 5.1):
    a field that is not relevant in a mode is not emitted with an empty value,
    it is **not emitted at all** - an empty column stays visible in a result
    table and makes the option indistinguishable in use; and the order below is
    the order the columns must appear in.

    - `audit=false debug=false` (6): `conf stanza key value anomaly member`;
    - `audit=false debug=true` (11): `app layer scope conf stanza key value
      definition_count file_path anomaly member`;
    - `audit=true`, any `debug` (15): the whole of `CONTRACT_ORDER`.

    `audit=true` implies `debug=true` (D-18, kept by D-37); the caller resolves
    that implication once, in `filters.validate_params`, and the `or audit`
    below makes this function right even when called with the raw value.

    D-37 revises D-18 on one point: `precedence_rank` and `definition_count`
    used to be emitted in every mode. They are not any more - `definition_count`
    comes back with `debug=true`, `precedence_rank` only in audit mode.

    The returned set holds CONTRACT FIELDS ONLY (D-34): the command is
    generating, never event-generating, so no `_raw` and no `_time` are ever
    part of a record.
    """
    emitted = set(DEFAULT_FIELDS)
    if debug or audit:
        emitted |= DEBUG_FIELDS
    if audit:
        emitted |= AUDIT_FIELDS
    return tuple(name for name in CONTRACT_ORDER if name in emitted)


#: The fifteen output fields of the contract, in contract order (CDC section
#: 5.1, spec section 3.2) - the superset, emitted as such in `audit=true`. What
#: one given invocation emits is `output_fields(audit, debug)`; a record carries
#: those fields and nothing else (D-34).
OUTPUT_FIELDS = output_fields(audit=True, debug=True)


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
    # Confs where the two complementary pattern lists above do NOT apply
    # (D-29). Exact conf names, case-sensitive - never globs: an exclusion
    # must not be able to grow wider than what was demonstrated. The
    # `encrypt_fields` list is never excluded. Each default name is a conf
    # whose value space cannot hold a credential by construction; the
    # justification is in the README.
    pattern_excluded_confs: Tuple[str, ...] = (
        "authorize", "collections", "fields", "multikv", "sourcetypes",
        "web-features",
    )
    log_level: str = "INFO"
    verify_ssl: bool = True


@dataclass(frozen=True)
class BtoolResult:
    """Outcome of one btool invocation (BtoolPort, spec section 1.4)."""

    returncode: int
    stdout: str
    error: Optional[str] = None
