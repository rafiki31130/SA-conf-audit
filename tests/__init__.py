"""Test suite - runs outside Splunk, without network access (spec section 12).

`bin` is inserted into `sys.path` so that `confaudit` imports directly;
`bin/lib` (the vendored SDK) is NEVER inserted - the mere fact that the suite
runs proves that the core does not depend on the SDK (spec section 2.3).

Run from the repository root:

    python -m unittest discover -s tests
"""

import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
BIN_DIR = os.path.join(ROOT, "bin")
FIXTURES_DIR = os.path.join(TESTS_DIR, "fixtures")

if BIN_DIR not in sys.path:
    sys.path.insert(0, BIN_DIR)
