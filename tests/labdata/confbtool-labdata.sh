#!/bin/sh
# confbtool-labdata.sh - synthetic exploration data set for `| confbtool`.
#
#   sh confbtool-labdata.sh deploy   # (re)create everything - idempotent
#   sh confbtool-labdata.sh remove   # delete everything it created, nothing else
#   sh confbtool-labdata.sh list     # print the exact paths it owns
#
# Run it on the Splunk host, as root (or as the `splunk` user, minus the
# chown). It writes ONLY the paths printed by `list`; every one of them is
# created by this script, so `remove` never touches a pre-existing file.
#
# Everything here is synthetic and anonymous: made-up conf names that Splunk
# itself ignores (`labdemo`, `labnet`, `labsecret`, `labbroken`), generic app
# names, fake values. No restart is needed - btool and `| confbtool` both read
# the files from disk on every run.
#
# What it builds, and what each case demonstrates, is documented in README.md
# next to this script, with the searches to run.

set -e

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APPS="$SPLUNK_HOME/etc/apps"
SYSLOCAL="$SPLUNK_HOME/etc/system/local"

# The five apps this script owns entirely (created and deleted as a whole).
LAB_APPS="00_corp_base 10_corp_net 50_team_app zz_lab_overrides zz_disabled_app"

# The files this script adds INSIDE a Splunk-managed directory. They carry
# conf names that do not exist in Splunk, so they add no configuration to the
# instance; `remove` deletes exactly these two paths.
LAB_SYSTEM_FILES="$SYSLOCAL/labdemo.conf $SYSLOCAL/labnet.conf"

usage() {
    echo "usage: sh $0 deploy|remove|list" >&2
    exit 2
}

do_list() {
    for app in $LAB_APPS; do echo "$APPS/$app"; done
    for file in $LAB_SYSTEM_FILES; do echo "$file"; done
}

app_conf() {
    # $1 = app dir, $2 = label, $3 = install state line (may be empty)
    mkdir -p "$1/local" "$1/default" "$1/metadata"
    {
        echo "[install]"
        [ -n "$3" ] && echo "$3"
        echo ""
        echo "[ui]"
        echo "is_visible = 0"
        echo "label = $2"
        echo ""
        echo "[package]"
        echo "id = $(basename "$1")"
    } > "$1/default/app.conf"
    printf '[]\naccess = read : [ * ], write : [ admin ]\nexport = none\n' \
        > "$1/metadata/default.meta"
}

do_remove() {
    for app in $LAB_APPS; do
        if [ -d "$APPS/$app" ]; then
            chmod -R u+rwX "$APPS/$app" 2>/dev/null || true
            rm -rf "$APPS/$app"
            echo "removed $APPS/$app"
        fi
    done
    for file in $LAB_SYSTEM_FILES; do
        if [ -f "$file" ]; then
            rm -f "$file"
            echo "removed $file"
        fi
    done
    echo "done - the instance is back to its pre-data-set state."
}

do_deploy() {
    # Idempotence: wipe first, rebuild from scratch. A half-edited previous
    # run can never survive into the new one.
    do_remove > /dev/null

    # ---------------------------------------------------------------- apps --
    app_conf "$APPS/00_corp_base"     "Lab data set - base layer"      ""
    app_conf "$APPS/10_corp_net"      "Lab data set - network layer"   "state = enabled"
    app_conf "$APPS/50_team_app"      "Lab data set - team layer"      "state = enabled"
    app_conf "$APPS/zz_lab_overrides" "Lab data set - late overrides"  "state = enabled"
    app_conf "$APPS/zz_disabled_app"  "Lab data set - DISABLED app"    "state = disabled"

    # ------------------------------------------------------------- labdemo --
    # Case A - one key defined on 9 layers at once (deep cascade).
    # Case B - ASCII order inside one tier (00_ beats 10_ beats 50_ beats zz_).
    # Case C - local beats default inside one and the same app.
    # Case D - [default] inheritance, emitted once at its literal origin.
    # Case E - stanza duplicated inside one file.
    # Case F - multi-line value.
    # Case G - a disabled app takes no part in the resolution.

    cat > "$SYSLOCAL/labdemo.conf" <<'EOF'
# Lab data set for | confbtool - synthetic, added by confbtool-labdata.sh.
# `labdemo` is not a Splunk conf: this file configures nothing.
[web_tier]
max_threads = 400_system_local_wins
banner = set in system/local, the strongest layer of all
EOF

    cat > "$APPS/00_corp_base/local/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 100_app_00_local
timeout = 30_app_00_local_wins_ascii
banner = shadowed by system/local

[cache_tier]
size_mb = 512_app_00_local
EOF

    cat > "$APPS/00_corp_base/default/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 200_app_00_default
timeout = 90_app_00_default

[cache_tier]
size_mb = 256_app_00_default
eviction = lru_only_definition_in_the_whole_instance
EOF

    cat > "$APPS/10_corp_net/local/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 110_app_10_local

[multiline_demo]
allowed_networks = 10.0.0.0/8, \
    172.16.0.0/12, \
    192.168.0.0/16
EOF

    cat > "$APPS/10_corp_net/default/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 210_app_10_default

[multiline_demo]
allowed_networks = 10.0.0.0/8
EOF

    cat > "$APPS/50_team_app/local/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 150_app_50_local

[cache_tier]
size_mb = 1024_app_50_local
EOF

    cat > "$APPS/50_team_app/default/labdemo.conf" <<'EOF'
[default]
shared_flag = defined_once_in_the_default_stanza

[web_tier]
max_threads = 250_app_50_default

[cache_tier]
size_mb = 128_app_50_default
EOF

    cat > "$APPS/zz_lab_overrides/local/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 199_app_zz_local
timeout = 45_app_zz_local_loses_ascii

[dup_demo]
first_key = from_the_first_occurrence
repeated_key = first_value

[cache_tier]
size_mb = 4096_app_zz_local

[dup_demo]
second_key = from_the_second_occurrence
repeated_key = second_value_wins_inside_the_file
EOF

    cat > "$APPS/zz_lab_overrides/default/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 299_app_zz_default
EOF

    cat > "$APPS/zz_disabled_app/local/labdemo.conf" <<'EOF'
[web_tier]
max_threads = 000_disabled_app_must_never_appear
[disabled_only]
ghost_key = this stanza exists nowhere else and must never be emitted
EOF

    # --------------------------------------------------------------- labnet --
    # A second conf, with a DIFFERENT overlap set: the point is that the
    # conflicts are not concentrated on one file.
    cat > "$SYSLOCAL/labnet.conf" <<'EOF'
# Lab data set for | confbtool - synthetic, added by confbtool-labdata.sh.
[edge]
endpoint = https://edge.example.com:8443
EOF

    cat > "$APPS/00_corp_base/local/labnet.conf" <<'EOF'
[edge]
endpoint = https://edge-00.example.com:8443
EOF

    cat > "$APPS/50_team_app/local/labnet.conf" <<'EOF'
[edge]
endpoint = https://edge-50.example.com:8443
EOF

    cat > "$APPS/10_corp_net/default/labnet.conf" <<'EOF'
[edge]
retries = 3_app_10_default

[peering]
mode = active_passive
EOF

    cat > "$APPS/50_team_app/default/labnet.conf" <<'EOF'
[edge]
retries = 5_app_50_default
EOF

    # ------------------------------------------------------------ labsecret --
    # Sensitive keys: the values below are FAKE and are never emitted in
    # clear - the command replaces them with sha256:<hexdigest>. Two layers
    # carry the SAME fake value, so the digests are equal across layers, which
    # is the point of hashing rather than blanking.
    cat > "$APPS/00_corp_base/local/labsecret.conf" <<'EOF'
[transport]
sslPassword = $7$LAB_FAKE_NOT_A_REAL_SECRET
api_token = LAB_FAKE_TOKEN_VALUE
public_setting = this one is not sensitive and stays readable

[credential_store]
endpoint = https://vault.example.com
EOF

    cat > "$APPS/50_team_app/local/labsecret.conf" <<'EOF'
[transport]
sslPassword = $7$LAB_FAKE_NOT_A_REAL_SECRET
api_token = LAB_FAKE_OTHER_TOKEN
EOF

    # ------------------------------------------------------------ labbroken --
    # An undecodable file: the command emits an `anomaly=parse_error` row and
    # carries on. A byte sequence that is not valid UTF-8 is used rather than
    # a chmod 000 file: it produces the same anomaly without asking btool to
    # read a file it has no permission on.
    # \377 is octal for 0xFF - POSIX printf understands octal escapes, not the
    # \xNN form (which dash writes out literally).
    printf '[broken]\nkey_one = readable\nkey_two = bad byte -> \377 <- here\n' \
        > "$APPS/zz_lab_overrides/local/labbroken.conf"

    # ------------------------------------------------------------ ownership --
    for app in $LAB_APPS; do
        chown -R splunk:splunk "$APPS/$app" 2>/dev/null || true
    done
    for file in $LAB_SYSTEM_FILES; do
        chown splunk:splunk "$file" 2>/dev/null || true
        chmod 600 "$file"
    done

    echo "deployed:"
    do_list | sed 's/^/  /'
    echo "no restart needed - btool reads the files on every run."
}

case "${1:-}" in
    deploy) do_deploy ;;
    remove) do_remove ;;
    list)   do_list ;;
    *)      usage ;;
esac
