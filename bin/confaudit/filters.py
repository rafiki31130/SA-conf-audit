"""Parameter validation, `app=` x `audit=` matrix, extrapolation
(spec section 7).

The matrix is an EMISSION filter, never a parsing filter: resolution and
confrontation are always run on the real set of layers (`app=` never prunes,
CDC section 5.2 / C-11), so `precedence_rank`, `is_btool_winner` and
`definition_count` stay right whatever the filters.
"""

import os
import re

from . import normalize
from .errors import FatalUsageError
from .model import Params, STAR

#: Valid conf name (spec section 7.1) - covers `alert_actions`, `ui-prefs`, ...
_CONF_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Exact message of the missing conf argument (spec section 7.1).
USAGE_MESSAGE = (
    "confbtool: missing conf argument. Usage: | confbtool <conf|conf,conf|*> "
    "[stanza=<pattern>] [key=<pattern>] [app=<pattern>] [audit=<bool>] "
    "[debug=<bool>]"
)


def parse_conf_argument(fieldnames):
    """Rebuild the conf list from the SDK's positional `fieldnames`.

    Reconstruction rule (spec section 3.1): `",".join(fieldnames)`, split on
    `,`, `strip()`, empty tokens dropped - accepts `a,b`, `a, b` and `a b`.
    Duplicates are removed (first occurrence kept): one btool invocation per
    conf at most (CDC section 7.2).
    """
    joined = ",".join(fieldnames or [])
    tokens = []
    for token in joined.split(","):
        token = token.strip()
        if token and token not in tokens:
            tokens.append(token)
    if not tokens:
        raise FatalUsageError(USAGE_MESSAGE)
    if tokens == [STAR]:
        return STAR
    for token in tokens:
        if not _CONF_NAME_RE.match(token):
            raise FatalUsageError(
                "confbtool: invalid conf name '%s': letters, digits, '.', "
                "'_', '-' only (or a single '*')." % token
            )
    return tuple(tokens)


def compile_filter(name, pattern):
    """Compile a `stanza=`/`key=`/`app=` glob pattern into an anchored regex.

    Wildcards `*` (any substring) and `?` (one character); everything else is
    literal, case-sensitive. The user pattern is NEVER compiled as a raw regex:
    each character is escaped, only the two wildcards translate (spec
    section 7.1). An empty pattern or one carrying a control character is a
    fatal error - explicit, never a silent partial result (CDC section 5.4).
    """
    if pattern is None:
        return None
    if pattern == "" or any(ord(c) < 32 or ord(c) == 127 for c in pattern):
        raise FatalUsageError(
            "confbtool: invalid %s filter '%s': literal characters plus the "
            "wildcards '*' and '?' only." % (name, pattern)
        )
    parts = []
    for character in pattern:
        if character == "*":
            parts.append(".*")
        elif character == "?":
            parts.append(".")
        else:
            parts.append(re.escape(character))
    return re.compile("^" + "".join(parts) + r"\Z")


def validate_params(fieldnames, stanza=None, key=None, app=None,
                    audit=False, debug=False):
    """Validate every invocation parameter into a `Params` (spec section 7.1).

    Defaults: `stanza=*`, `key=*`, `app=` absent, `audit=false`, `debug=false`
    (D-17: the path is an investigation detail, not front-page information).

    `audit=true` FORCES `debug=true` (D-18): reading a conflict without the
    path makes no sense, so an explicit `debug=false` is ignored in that mode.
    The implication is resolved once, here; `Params.debug` is the EFFECTIVE
    value and every downstream module reads it as such.
    """
    confs = parse_conf_argument(fieldnames)
    stanza_raw = STAR if stanza is None else stanza
    key_raw = STAR if key is None else key
    audit = bool(audit)
    debug = bool(debug) or audit
    return Params(
        confs=confs,
        stanza_raw=stanza_raw,
        key_raw=key_raw,
        app_raw=app,
        stanza_rx=compile_filter("stanza", stanza_raw),
        key_rx=compile_filter("key", key_raw),
        app_rx=compile_filter("app", app) if app is not None else None,
        audit=audit,
        debug=debug,
    )


def match_sk(group, params):
    """`match_sk(G)`: the stanza AND the key of the group satisfy the filters."""
    return bool(params.stanza_rx.match(group.stanza)) and \
        bool(params.key_rx.match(group.key))


def carried(group, app_rx):
    """`carried(G, app_pat)`: at least one definition of the group is carried
    by an app whose name satisfies the pattern - the `system` scope carries no
    app and never satisfies it.

    Note (D-19): the OUTPUT field `app` reads `system` on a system-layer row,
    but `app=` stays a filter on apps, aligned with the `--app` of the btool
    CLI, where no app is named `system`. `app=system` therefore selects
    nothing; `scope="system"` is the SPL predicate for that layer."""
    return any(
        definition.scope == "app" and app_rx.match(definition.app)
        for definition in group.defs
    )


def _app_of_path(path):
    """App name carrying a layer file, or `None` for a system-layer file."""
    root = normalize.app_root(path) if path else None
    return os.path.basename(root.rstrip("/")) if root else None


def select_anomalies(anomalies, groups, params):
    """D-35: scope the `resolver_mismatch` lines of ONE conf to the filters.

    A `resolver_mismatch` carries a KNOWN `(conf, stanza, key)`, so its
    perimeter is determinable and it is scoped like a definition: emitted only
    if the triplet satisfies `<conf>` (already true - anomalies are collected
    per conf), `stanza=`, `key=` and `app=`.

    `app=` is evaluated at GROUP granularity (`carried`), in both modes: the
    anomaly is a statement about the group, not about one of its definitions,
    and in `audit=false` the group may well have no emitted definition at all -
    that is precisely when the user must still be told the resolver disagreed
    about a key the app takes part in. This is the loosest scoping that stays
    inside the requested perimeter, and it is what keeps an in-scope anomaly
    UNMASKABLE (D-35, CDC section 5.4).

    Two degenerate shapes are handled explicitly:

    - no group at all (btool designates a `(stanza, key)` we never built): the
      app is read off the paths the anomaly does carry;
    - no determinable app on any known path: the anomaly is EMITTED. Never drop
      what cannot be scoped - dropping it would be exactly the silent wrong
      answer the rule exists to prevent.

    `parse_error` lines are NOT handled here: they are scoped by conf alone,
    which the per-conf collection already does. The file could not be read, so
    which stanzas and keys it carried is unknown, and silencing it inside its
    own conf would answer "nothing here" without knowing (D-35).
    """
    out = []
    for anomaly in anomalies:
        if not params.stanza_rx.match(anomaly.stanza):
            continue
        if not params.key_rx.match(anomaly.key):
            continue
        if params.app_rx is not None and not _anomaly_in_app(
                anomaly, groups, params.app_rx):
            continue
        out.append(anomaly)
    return out


def _anomaly_in_app(anomaly, groups, app_rx):
    group = groups.get((anomaly.stanza, anomaly.key))
    if group is not None:
        return carried(group, app_rx)
    paths = [
        side.path for side in (anomaly.internal, anomaly.btool)
        if side is not None and getattr(side, "path", None)
    ]
    apps = [_app_of_path(path) for path in paths]
    named = [app for app in apps if app]
    if not named:
        return True     # not scopable: emit rather than silently drop
    return any(app_rx.match(app) for app in named)


def select(groups, verdicts, params):
    """Apply the `app=` x `audit=` emission matrix (spec section 7.2).

    `groups` maps `(stanza, key)` to `Group`, `verdicts` maps the same keys to
    `Verdict`. Returns the list of `(group, index)` pairs to emit, where
    `index` addresses `group.defs`.

    The four cells:

    - no `app=`, `audit=false`: `match_sk` groups, `is_btool_winner=true` rows;
    - no `app=`, `audit=true`: `match_sk` groups, every row;
    - `app=`, `audit=false`: `match_sk` groups, winner rows whose app satisfies
      the pattern (a `system` winner carries no app: excluded);
    - `app=`, `audit=true`: EXTRAPOLATION - `match_sk` and `carried` groups,
      every row of the group, competitors outside the app and the `system`
      layer included. `app=` selects the KEYS (those where the app carries at
      least one definition); restricting the emission to the app as well would
      hide the competitors and defeat the mode (CDC section 5.3). A key the app
      does not carry never appears.
    """
    selected = []
    for group_key in groups:
        group = groups[group_key]
        if not match_sk(group, params):
            continue
        verdict = verdicts.get(group_key)
        winner_index = verdict.index if verdict is not None else None
        if params.app_rx is None:
            if params.audit:
                selected.extend((group, i) for i in range(len(group.defs)))
            elif winner_index is not None:
                selected.append((group, winner_index))
        else:
            if params.audit:
                if carried(group, params.app_rx):
                    selected.extend((group, i) for i in range(len(group.defs)))
            elif winner_index is not None:
                winner = group.defs[winner_index]
                if winner.scope == "app" and params.app_rx.match(winner.app):
                    selected.append((group, winner_index))
    return selected
