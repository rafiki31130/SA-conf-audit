#!/usr/bin/env python3
"""SHA-256 checksum manifest of `bin/lib/`.

`write` (re)generates `bin/lib/MANIFEST.sha256`, `check` recomputes and compares.
Non-zero exit status on divergence: this is what makes any modification of `bin/lib/`
outside `tools/vendor.sh` detectable.

Written in Python rather than in shell so that it stays usable on development
machines without `sha256sum` (Windows, older macOS): the reproducibility of the
verification matters as much as that of the installation.
"""

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "bin", "lib")
MANIFEST = os.path.join(LIB, "MANIFEST.sha256")

#: Files that are not vendored, excluded from the manifest: they are hand-written and
#: versioned, not produced by pip.
EXCLUDED = {"MANIFEST.sha256", "VENDOR.md"}

#: Build artifact directories, excluded from the walk.
EXCLUDED_DIRS = {"__pycache__"}

#: Build artifact suffixes, excluded from the walk.
EXCLUDED_SUFFIXES = (".pyc", ".pyo")


def _is_build_artifact(relative):
    """True for an artifact produced by the interpreter, never by `pip`.

    The manifest describes what `tools/vendor.sh` installs; its pruning step already
    removes `__pycache__` and `*.pyc`. The verification walk must apply the same
    exclusion, failing which **merely importing the vendored SDK makes the verifier
    fail**: an import creates the `.pyc` files under `bin/lib/`, which the walk then
    counts as undeclared files. An integrity check that is broken by the very use of
    what it checks is not workable, and it directs the reader toward a full rebuild
    for a false positive.
    """
    segments = relative.split("/")
    if any(segment in EXCLUDED_DIRS for segment in segments[:-1]):
        return True
    return segments[-1].endswith(EXCLUDED_SUFFIXES)


def _digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _entries():
    for dirpath, dirnames, filenames in os.walk(LIB):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, LIB).replace(os.sep, "/")
            if relative in EXCLUDED or _is_build_artifact(relative):
                continue
            yield relative, _digest(full)


def write():
    lines = ["%s  %s" % (digest, relative) for relative, digest in _entries()]
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + ("\n" if lines else ""))
    print("%d files hashed into %s" % (len(lines), MANIFEST))
    return 0


def check():
    if not os.path.exists(MANIFEST):
        print("FAILED: %s is missing" % MANIFEST, file=sys.stderr)
        return 2
    expected = {}
    with open(MANIFEST, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            digest, _, relative = line.partition("  ")
            expected[relative] = digest
    observed = dict(_entries())

    missing = sorted(set(expected) - set(observed))
    added = sorted(set(observed) - set(expected))
    modified = sorted(
        f for f in set(expected) & set(observed) if expected[f] != observed[f]
    )

    for kind, files in (
        ("missing", missing), ("undeclared", added), ("modified", modified)
    ):
        for name in files:
            print("FAILED [%s] %s" % (kind, name), file=sys.stderr)

    if missing or added or modified:
        print(
            "FAILED: bin/lib/ diverges from the manifest. Rebuild with "
            "tools/vendor.sh, never edit bin/lib/ by hand.",
            file=sys.stderr,
        )
        return 1
    print("OK: %d files match the manifest" % len(expected))
    return 0


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "write":
        sys.exit(write())
    if action == "check":
        sys.exit(check())
    print("usage: hash_manifest.py [write|check]", file=sys.stderr)
    sys.exit(2)
