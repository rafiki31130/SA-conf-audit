"""Groups, precedence rank, definition count (spec section 5).

The resolution is unique and global - the one btool applies outside of any
app or user context (CDC section 5.2). It ranks the shadowed definitions; the
"winner" verdict itself always comes from the real btool execution
(`confront.py`), never from this ranking.
"""

from .model import Definition, Group

#: Global precedence order of the four layers (spec section 5.2).
LAYER_RANK = {
    ("system", "local"): 1,
    ("app", "local"): 2,
    ("app", "default"): 3,
    ("system", "default"): 4,
}


def sort_key(layer_file):
    """Precedence sort key of one definition: `(layer rank, app name)`.

    ⚠ Flagged trap (M-1, CDC section 5.2): inside an `apps/*` tier, the app
    FIRST in ASCII ASCENDING order wins - `00_corp_base` beats `zz_sample_app`
    (numeric prefixes before letters, verified empirically). The reverse is the
    most likely implementation error of the project; a dedicated unit test
    locks it. App names compare by code points (byte order in ASCII), with NO
    case or locale normalization - which is exactly what the plain string
    comparison below does. The app name is empty for `system` and unique per
    tier for a given conf (one file per `(app, layer, conf)`), so the order is
    total.
    """
    return (LAYER_RANK[(layer_file.scope, layer_file.layer)], layer_file.app)


def resolve(conf, parsed_files):
    """Build the groups of a conf from its parsed layer files.

    `parsed_files` is an iterable of `(LayerFile, list[RawDef])`. Returns a
    mapping `(stanza, key) -> Group` whose `defs` tuple is sorted by the global
    precedence order: `defs[0]` is the internal winner (rank 1), `len(defs)`
    the definition count.

    The `[default]` inheritance is NOT a concurrence (D-7): `(conf, default, k)`
    and `(conf, S, k)` are two distinct groups by construction - the grouping
    key is the literal stanza, never an expanded view. No expansion exists
    anywhere in the pipeline (spec section 5.4).

    Rank and count are computed on the real set of layers, before any filter,
    and are never recomputed after filtering (spec section 5.3): the filters of
    section 7 select rows for emission, they never feed back into this module.
    """
    entries = {}
    for layer_file, defs in parsed_files:
        for raw in defs:
            entries.setdefault((raw.stanza, raw.key), []).append((layer_file, raw))

    groups = {}
    for (stanza, key), items in entries.items():
        items.sort(key=lambda item: sort_key(item[0]))
        defs = tuple(
            Definition(
                path=layer_file.path,
                conf=conf,
                stanza=stanza,
                key=key,
                value=raw.value,
                scope=layer_file.scope,
                app=layer_file.app,
                layer=layer_file.layer,
            )
            for layer_file, raw in items
        )
        groups[(stanza, key)] = Group(conf=conf, stanza=stanza, key=key, defs=defs)
    return groups
