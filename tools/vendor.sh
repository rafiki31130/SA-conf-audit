#!/usr/bin/env sh
# Rebuilds `bin/lib/` identically from `tools/requirements-vendor.txt`.
#
# A `bin/lib/` directory that nobody knows how to rebuild identically is an
# unauditable binary in the middle of a public repository. This script, the checksum
# manifest and `tools/verify_vendor.sh` are what makes the vendoring reproducible AND
# verifiable.
#
# Every version bump goes through editing `requirements-vendor.txt`, then re-running
# this script and `verify_vendor.sh`. NEVER through a direct edit inside `bin/lib/`.
#
# Usage, from the repository root:
#     sh tools/vendor.sh [path/to/python]

set -eu

PYTHON="${1:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT/bin/lib"
REQ="$ROOT/tools/requirements-vendor.txt"

echo "== rebuilding $LIB"
rm -rf "$LIB"
mkdir -p "$LIB"

# `--require-hashes`: the installed content is exactly the one whose checksum is
# frozen in the requirements file. `--no-deps`: no transitive dependency gets in
# without an explicit decision. `--no-compile`: .pyc files compiled by an interpreter
# other than the target platform's are at best diff noise, at worst a source of
# divergent behavior.
"$PYTHON" -m pip install \
    --no-deps \
    --no-compile \
    --require-hashes \
    --target "$LIB" \
    -r "$REQ"

echo "== pruning"
find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$LIB" -name '*.pyc' -delete 2>/dev/null || true
find "$LIB" -name '*.pyo' -delete 2>/dev/null || true
find "$LIB" -name 'RECORD' -path '*.dist-info*' -delete 2>/dev/null || true
rm -rf "$LIB"/splunklib/tests "$LIB"/splunklib/examples 2>/dev/null || true
rm -rf "$LIB"/bin "$LIB"/tests "$LIB"/examples 2>/dev/null || true

echo "== checksum manifest"
"$PYTHON" "$ROOT/tools/hash_manifest.py" write

echo "== done. Verify with: sh tools/verify_vendor.sh"
