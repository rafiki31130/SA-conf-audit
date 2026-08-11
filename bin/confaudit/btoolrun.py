"""BtoolPort implementation: btool invocation (spec section 6.2).

The ONLY module of the package allowed to import `subprocess` (layer rule of
spec section 1.3, enforced by `tests/test_layering.py`).
"""

import os
import subprocess

from .model import BtoolResult

#: Module constant, not a parameter (spec section 6.2).
TIMEOUT_SECONDS = 60


class BtoolRunner:
    """Runs `splunk btool <conf> list --debug`, one invocation per conf at
    most (CDC section 7.2), sequentially (M-2: ~105 ms per invocation)."""

    def __init__(self, splunk_home=None):
        home = splunk_home or os.environ.get("SPLUNK_HOME", "")
        self._binary = os.path.join(home, "bin", "splunk")

    def run(self, conf):
        """One invocation. argv as a list, NEVER `shell=True`; the conf name
        was validated upstream (spec section 7.1) - no unvalidated user
        content ever reaches the argv. Inherited environment, 60 s timeout,
        stdout decoded as UTF-8 with `errors="replace"`.

        Never raises: failures come back as a `BtoolResult` carrying `error`,
        which the pipeline turns into the fatal error of D-13.
        """
        argv = [self._binary, "btool", conf, "list", "--debug"]
        try:
            completed = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return BtoolResult(
                returncode=-1, stdout="",
                error="timeout after %d s" % TIMEOUT_SECONDS,
            )
        except OSError as exc:
            return BtoolResult(returncode=-1, stdout="", error=str(exc))
        stdout = completed.stdout.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            detail = "exit code %d" % completed.returncode
            if stderr:
                detail += ": " + stderr.splitlines()[0]
            return BtoolResult(
                returncode=completed.returncode, stdout=stdout, error=detail,
            )
        return BtoolResult(returncode=0, stdout=stdout, error=None)
