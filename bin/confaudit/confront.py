"""Confrontation of the internal resolution with the btool verdict
(spec section 6.5) - the self-validation of CDC section 4.

The comparison uses RAW values, before any secret hashing (section 9.2 orders
the hashing after this step). The `resolver_mismatch` anomalies are emitted for
every parsed conf, independently of the filters and of the audit mode: they are
the proof channel that the resolver does not lie, and filtering them would hide
that proof.
"""

from .model import Anomaly, Verdict


def confront(conf, groups, winners):
    """Confront each group with the btool verdicts of its conf.

    `groups` maps `(stanza, key)` to `Group`; `winners` maps `(stanza, key)` to
    `BtoolWinner` (output of `btoolparser.deexpand`).

    Returns `(verdicts, anomalies)` where `verdicts` maps every group key to a
    `Verdict` - `index` is the position of the btool-designated definition in
    the group's precedence order (the oracle primes over the internal rank),
    `None` when btool designates none - and `anomalies` lists the
    `resolver_mismatch` lines, each carrying both verdicts side by side.

    The five cases of spec section 6.5:

    - nominal: verdict == rank-1 definition -> no anomaly;
    - rank inversion: verdict == another definition of the group -> that one is
      the winner (oracle primes), one anomaly;
    - unknown btool winner: verdict matches no definition -> no winner row, one
      anomaly (both sides filled);
    - group without btool verdict -> no winner row, one anomaly (btool side
      empty);
    - btool verdict without group -> one anomaly (internal side empty,
      definition_count 0).
    """
    verdicts = {}
    anomalies = []

    for group_key, group in groups.items():
        winner = winners.get(group_key)
        if winner is None:
            verdicts[group_key] = Verdict(index=None, winner=None)
            anomalies.append(Anomaly(
                conf=conf, stanza=group.stanza, key=group.key,
                internal=group.defs[0], btool=None,
                definition_count=len(group.defs),
            ))
            continue
        index = None
        for position, definition in enumerate(group.defs):
            # Match on (path, value): the path is unique inside a group (one
            # definition per (stanza, key) per file), so the match is
            # unambiguous.
            if definition.path == winner.path and definition.value == winner.value:
                index = position
                break
        verdicts[group_key] = Verdict(index=index, winner=winner)
        if index == 0:
            continue  # nominal: no anomaly
        anomalies.append(Anomaly(
            conf=conf, stanza=group.stanza, key=group.key,
            internal=group.defs[0], btool=winner,
            definition_count=len(group.defs),
        ))

    for group_key, winner in winners.items():
        if group_key not in groups:
            stanza, key = group_key
            anomalies.append(Anomaly(
                conf=conf, stanza=stanza, key=key,
                internal=None, btool=winner, definition_count=0,
            ))

    return verdicts, anomalies
