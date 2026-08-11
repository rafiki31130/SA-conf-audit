"""Application log adapter: `sa_conf_audit.log` (spec section 11, D-2).

Allowed disk access, together with `layers.py` (layer rule of spec
section 1.3). This log is the ONLY write of the app (CDC section 6.3): the
command is otherwise strictly read-only.

Forbidden content: no configuration VALUE, cleartext or hashed, ever reaches
the log (spec section 9.2, stronger rule than hashing); never the session key.
Conf names, stanzas, keys and paths are admitted. The pipeline builds its
messages accordingly; `tests/test_journal.py` checks it on sentinel values.
"""

import logging
import logging.handlers
import os

#: Rotation: 5 MB x 5 files (spec section 11).
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5

#: Line format; ISO 8601 local timestamp.
LINE_FORMAT = "%(asctime)s level=%(levelname)s %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

FILENAME = "sa_conf_audit.log"


def open_app_log(log_dir, level_name="INFO"):
    """Open the rotating application log; `None` on failure.

    A failure to open is NOT fatal: the wrapper emits a single warning in the
    search output and the run carries on - the log is a diagnostic comfort,
    not a safety net (spec section 11; deliberate contrast with SA-acl-tools,
    where the journal conditioned a write operation - this command is
    read-only).
    """
    try:
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, FILENAME),
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(LINE_FORMAT, datefmt=DATE_FORMAT))
        logger = logging.getLogger("confaudit.app")
        # Replace, never accumulate: dispatch may reuse the interpreter.
        logger.handlers = [handler]
        level = getattr(logging, (level_name or "INFO").strip().upper(), None)
        logger.setLevel(level if isinstance(level, int) else logging.INFO)
        logger.propagate = False
        return logger
    except Exception:  # noqa: BLE001 - the log never conditions the run
        return None
