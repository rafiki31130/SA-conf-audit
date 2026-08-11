"""Volume guard (spec section 8, decision D-8).

Never a silent truncation: in an audit tool, a missing row reads as a missing
definition. The case is real - about 43 000 definitions on a bare instance
(M-4), beyond the default `maxresultrows` (50 000) as soon as an extrapolation
is moderate.
"""

from .errors import VolumeRefused

#: Documented fallback when `maxresultrows` is absent or not an integer
#: (spec section 8) - a WARNING is logged by the pipeline.
DEFAULT_LIMIT = 50000

#: Exact refusal message (spec section 8, CDC criterion 8: name the filters to
#: apply).
REFUSAL_MESSAGE = (
    "confbtool: refusing to emit %d rows: this instance's result limit is %d "
    "(limits.conf [searchresults] maxresultrows). Narrow the request with an "
    "explicit conf list, stanza=, key= or app= filters, or audit=false. "
    "No partial results were produced: a truncated audit would read as "
    "missing definitions."
)


def check(row_count, limit):
    """Refuse strictly above the limit; a batch exactly at the limit passes.

    `row_count` is the exact number of rows that WOULD be emitted - retained
    definitions plus `parse_error` and `resolver_mismatch` lines - computed
    after filters/extrapolation and confrontation, BEFORE any row is built or
    emitted (spec section 8).
    """
    if row_count > limit:
        raise VolumeRefused(REFUSAL_MESSAGE % (row_count, limit))
