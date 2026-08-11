"""Parameter validation, `app=` x `audit=` matrix, extrapolation
(spec section 7).

The matrix is an EMISSION filter, never a parsing filter: resolution and
confrontation are always run on the real set of layers (`app=` never prunes,
CDC section 5.2 / C-11), so `precedence_rank`, `is_btool_winner` and
`definition_count` stay right whatever the filters.
"""

import re

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
                    audit=False, debug=True):
    """Validate every invocation parameter into a `Params` (spec section 7.1).

    Defaults: `stanza=*`, `key=*`, `app=` absent, `audit=false`, `debug=true`.
    """
    confs = parse_conf_argument(fieldnames)
    stanza_raw = STAR if stanza is None else stanza
    key_raw = STAR if key is None else key
    return Params(
        confs=confs,
        stanza_raw=stanza_raw,
        key_raw=key_raw,
        app_raw=app,
        stanza_rx=compile_filter("stanza", stanza_raw),
        key_rx=compile_filter("key", key_raw),
        app_rx=compile_filter("app", app) if app is not None else None,
        audit=bool(audit),
        debug=bool(debug),
    )


def match_sk(group, params):
    """`match_sk(G)`: the stanza AND the key of the group satisfy the filters."""
    return bool(params.stanza_rx.match(group.stanza)) and \
        bool(params.key_rx.match(group.key))


def carried(group, app_rx):
    """`carried(G, app_pat)`: at least one definition of the group is carried
    by an app whose name satisfies the pattern - the `system` scope carries no
    app and never satisfies it."""
    return any(
        definition.scope == "app" and app_rx.match(definition.app)
        for definition in group.defs
    )


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
