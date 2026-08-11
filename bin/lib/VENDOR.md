# Vendored dependencies

This directory is **generated**, never hand-edited. It is nevertheless **versioned**:
the app archive must be deployable without network access.

| Element | Value |
|---|---|
| Package | `splunk-sdk` |
| Version | `2.1.1` (pinned to the patch) |
| Upstream archive checksum | `sha256:46300d52f09e0aed7e5962ce2ba08ef54421ffb3a538c6af6164dcbf9f075faa` |
| Upstream license | Apache-2.0 |
| Vendoring date | 2026-08-12 |
| Build interpreter | CPython 3.12 |

## Why this version

The `3.x` series of the SDK requires Python >= 3.13 and is therefore not installable
on the interpreter shipped with Splunk Enterprise 9.x. `2.1.1` is the last compatible
release.

## Why a single dependency

The `bin/confaudit/` core has **no** third-party dependency: the REST calls are raw
HTTP on `urllib` + `ssl` from the standard library, and the tests rely on `unittest`.
The SDK only serves the `bin/confbtool.py` wrapper, which implements the search
command protocol.

In a public repository, every vendored package is a license, audit and CVE surface
the app carries with no update mechanism. Any additional dependency is therefore an
explicit trade-off, not a convenience.

## Rebuilding

From the repository root:

```sh
sh tools/vendor.sh /path/to/python3
sh tools/verify_vendor.sh /path/to/python3
```

`vendor.sh` installs with `--require-hashes --no-deps --no-compile`, prunes the
`__pycache__` directories, the `.pyc` files, the `.dist-info` `RECORD` as well as the
SDK's tests and examples, then regenerates `MANIFEST.sha256`.

`--no-compile` and the `__pycache__` purge are not cosmetic: `.pyc` files compiled by
an interpreter other than the target platform's are at best diff noise, at worst a
source of divergent behavior.

## Version bump

1. Edit `tools/requirements-vendor.txt` (version **and** checksum).
2. Re-run `tools/vendor.sh`.
3. Re-run `tools/verify_vendor.sh`.
4. Update this file.

**Never** through a direct edit inside `bin/lib/`: `verify_vendor.sh` would detect
it, and the archive would stop being rebuildable.
