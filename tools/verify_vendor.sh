#!/usr/bin/env sh
# Checks that `bin/lib/` matches its checksum manifest exactly.
# Non-zero exit status on divergence.
#
# Usage, from the repository root:
#     sh tools/verify_vendor.sh [path/to/python]

set -eu

PYTHON="${1:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec "$PYTHON" "$ROOT/tools/hash_manifest.py" check
