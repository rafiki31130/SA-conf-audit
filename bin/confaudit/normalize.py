"""Normalisation of stanza and key names FOR THE CONFRONTATION ONLY
(D-23, D-25; spec sections 6.3-6.5).

`btool --debug` is not a faithful echo of the source files: it is a NORMALISED
view. Comparing a literal spelling with a normalised one produces a false
positive everywhere Splunk normalises something - the same lesson as D-11 and
D-21, met a third time. The rule of the project is therefore:

    normalise BOTH sides to compare, emit the LITERAL spelling.

Nothing in this module ever touches an emitted field: the `stanza` and `key`
columns keep the exact spelling of the source file (D-7). The functions below
translate OUR spelling into btool's namespace, so that a group and a btool
record designate the same object; btool's own output is already normalised and
is never passed through them (they are not idempotent on every input - see
`key_for_match`).

Two normalisations are measured on Splunk 9.4.6 (lab, 2026-08-12), each on the
whole conf corpus of the instance:

- **stanza names** (D-23): `$SPLUNK_HOME` is expanded to its runtime value, and
  a `<scheme>://./<rest>` relative path is resolved against the app directory
  of the file declaring the stanza. Measured: 60 stanzas of `inputs` carry one
  of the two forms, 60 are explained by this rule, 0 are left over; the only
  variable appearing in a stanza name of the whole corpus is `$SPLUNK_HOME`.
- **key names** (D-25): a doubled backslash collapses to a single one. Measured
  on `sourcetypes`: 75 keys out of 75 explained. The collapse applies to KEY
  NAMES ONLY - the 21 values of the corpus carrying a doubled backslash are
  restituted byte for byte by btool.
"""

import re

#: The only variable measured in a stanza name of the corpus (D-23).
HOME_VARIABLE = "$SPLUNK_HOME"

#: Relative-path marker of a scheme stanza (`script://./bin/x.py`).
RELATIVE_MARKER = "://./"

#: `<...>/apps/<app>/{local,default}/<conf>.conf` -> `<...>/apps/<app>`.
_APP_DIRECTORY = re.compile(r"^(?P<root>.*/apps/[^/]+)/(?:local|default)/[^/]+$")


def splunk_home_from_etc(etc_prefix):
    """`$SPLUNK_HOME` derived from the resolved etc prefix.

    The pipeline already receives `$SPLUNK_HOME/etc` resolved (it is what
    identifies a path-prefixed line of the btool output); the home is that
    prefix without its trailing `/etc`. Returns `""` when the prefix is empty
    or does not end that way - the expansion then does nothing rather than
    guessing.
    """
    prefix = (etc_prefix or "").rstrip("/")
    if prefix.endswith("/etc"):
        return prefix[:-len("/etc")]
    return ""


def app_root(path):
    """App directory of a layer file, or `None` for a `system` layer file."""
    match = _APP_DIRECTORY.match(path.replace("\\", "/"))
    return match.group("root") if match is not None else None


def stanza_for_match(stanza, splunk_home, path=None):
    """Our stanza name, written the way btool writes it (D-23).

    `splunk_home` is the runtime `$SPLUNK_HOME` (derived from the resolved etc
    prefix); `path` is the file of the RANK-1 definition of the group, which is
    what anchors a relative path.

    Two measured transformations, in this order:

    1. `$SPLUNK_HOME` is replaced by its runtime value, textually - btool emits
       `[monitor:///opt/splunk/var/log/splunk]` for a source
       `[monitor://$SPLUNK_HOME/var/log/splunk]` (the third slash is simply the
       leading slash of the absolute path).
    2. `<scheme>://./<rest>` is resolved against the app directory of `path`:
       `[script://./bin/x.py]` declared in `apps/<app>/default/inputs.conf`
       becomes `[script:///opt/splunk/etc/apps/<app>/bin/x.py]`.

    A `system` layer file carries no app directory, so a relative form declared
    there is left untouched - not observed on the corpus, and inventing a base
    would be a guess. `../` is likewise left alone: it does not appear in the
    corpus and no measurement backs a rule for it.

    Idempotent on an already-resolved name: it carries neither the variable nor
    the marker.
    """
    out = stanza.replace(HOME_VARIABLE, splunk_home) if splunk_home else stanza
    index = out.find(RELATIVE_MARKER)
    if index == -1 or path is None:
        return out
    root = app_root(path)
    if root is None:
        return out
    return out[:index + len("://")] + root + "/" + out[index + len(RELATIVE_MARKER):]


def key_for_match(key):
    """Our key name, written the way btool writes it (D-25).

    btool collapses a doubled backslash of a KEY NAME into a single one:
    `L-..._\\\\"\\\\"_L7(` in the source is emitted as `L-..._\\"\\"_L7(`. A
    single backslash is left as is - `\\"` is NOT unescaped into `"`.

    NOT idempotent: a btool key that legitimately carries a doubled backslash
    would be altered by a second pass. Only OUR side is ever passed through it.
    """
    return key.replace("\\\\", "\\")
