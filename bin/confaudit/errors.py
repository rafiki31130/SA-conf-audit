"""Error taxonomy (spec section 3.1).

"Fatal" means: the search is interrupted with an explicit message and no partial
output. No per-file error is ever fatal (CDC section 5.4): unreadable or degraded
files are turned into `parse_error` anomaly rows by the pipeline, never into
exceptions of this module.
"""


class FatalError(Exception):
    """Base class of the errors that abort the search with an explicit message."""


class FatalUsageError(FatalError):
    """Invalid parameters: missing conf argument, invalid conf name, invalid
    filter pattern (spec section 7.1)."""


class FatalCapabilityError(FatalError):
    """The `run_confbtool` capability is absent, or the REST check itself failed -
    an impossible verification never presumes the authorization (spec section 10)."""


class FatalBtoolError(FatalError):
    """The btool invocation failed (non-zero exit, timeout, missing binary).

    btool is the oracle of the winner verdict (CDC section 4, D-13): without it no
    verdict can be established, and a substitute verdict would be a silently
    degraded audit output. Fatal by decision D-13."""


class VolumeRefused(FatalError):
    """The run would emit more rows than the effective result limit (D-8):
    explicit refusal, never a silent truncation (spec section 8)."""
