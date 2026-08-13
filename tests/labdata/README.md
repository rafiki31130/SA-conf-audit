# Exploration data set for `| confbtool`

A synthetic set of configuration files that puts **the same stanzas and the
same keys** in several apps and several layers at once, so the behaviour of
`| confbtool` can be watched on conflicts you built yourself rather than on
whatever a real instance happens to contain.

It is meant to be **deployed on a lab instance and left in place**. Everything
in it is fabricated: the conf names (`labdemo`, `labnet`, `labsecret`,
`labbroken`) do not exist in Splunk, so **the data set configures nothing** -
Splunk ignores those files, only `btool` and `| confbtool` ever read them.

## Install / uninstall

```sh
# on the Splunk host, as root (SPLUNK_HOME defaults to /opt/splunk)
sh confbtool-labdata.sh deploy    # (re)create everything - idempotent
sh confbtool-labdata.sh list      # the exact paths the script owns
sh confbtool-labdata.sh remove    # delete them, and nothing else
```

`deploy` starts by removing, so running it twice is the same as running it
once. **No restart is needed**: `btool` and the command read the files from
disk on every run.

The script writes to exactly seven paths, all of which it creates itself:

| Path | Note |
|---|---|
| `etc/apps/00_corp_base/` | whole app, created and deleted as a whole |
| `etc/apps/10_corp_net/` | idem |
| `etc/apps/50_team_app/` | idem |
| `etc/apps/zz_lab_overrides/` | idem |
| `etc/apps/zz_disabled_app/` | idem, `[install] state = disabled` |
| `etc/system/local/labdemo.conf` | **new file inside a Splunk directory** |
| `etc/system/local/labnet.conf` | **new file inside a Splunk directory** |

The last two are the only writes inside a directory Splunk owns. They are new
files under conf names Splunk does not know: no pre-existing file is modified,
and `remove` deletes those two paths only.

## The apps

| App | Layer(s) | Role in the set |
|---|---|---|
| `00_corp_base` | `local` + `default` | first in ASCII order - wins its tier |
| `10_corp_net` | `local` + `default` | second in ASCII order |
| `50_team_app` | `local` + `default` | third; also carries the `[default]` stanza case |
| `zz_lab_overrides` | `local` + `default` | last in ASCII order - loses its tier despite the name; also carries the duplicated stanza and the broken file |
| `zz_disabled_app` | `local` | **disabled** - takes no part in the resolution |

All five are `is_visible = 0`: they never show up in the Splunk launcher.

## The cases, and what to run to see them

### A - a nine-layer cascade on one key

`labdemo [web_tier] max_threads` is defined **nine times**: `system/local`,
the `local` of the four enabled apps, the `default` of the four enabled apps.

```
| confbtool labdemo stanza=web_tier key=max_threads audit=true
```

Read the `precedence_rank` column: 1 = `system/local`, then the four `local`
layers in ASCII order of app name, then the four `default` layers in the same
order. One row and one only carries `is_btool_winner=true`, and it is the
verdict of a real `btool` run, not of our ranking.

### B - ASCII order inside one tier

`labdemo [web_tier] timeout` is carried by `00_corp_base/local` and
`zz_lab_overrides/local` - same tier, so the app name decides:

```
| confbtool labdemo key=timeout audit=true
```

`00_corp_base` wins (`30_app_00_local_wins_ascii`); the `zz_` value is
shadowed. The value strings say which one is supposed to win, so a regression
is readable without cross-checking anything.

### C - `local` beats `default` inside one app

```
| confbtool labdemo stanza=cache_tier audit=true
```

`size_mb` exists in the `local` **and** the `default` of three apps: six
definitions, ranked local-tier first. `eviction` is defined once in the whole
instance (`definition_count = 1`) - the contrast is the point.

### D - a `[default]` stanza is emitted once, at its literal origin

`50_team_app/default/labdemo.conf` carries `[default] shared_flag`.

```
| confbtool labdemo stanza=default
```

One row, `stanza=default`. Compare with the CLI, which repeats the inherited
key inside **every** stanza of the conf:

```sh
splunk btool labdemo list --debug | grep shared_flag
```

The command answers *where is this defined*, not *what does each stanza see*.

### E - a stanza written twice in the same file

`zz_lab_overrides/local/labdemo.conf` opens `[dup_demo]` twice.

```
| confbtool labdemo stanza=dup_demo audit=true
```

Three keys come out, merged from both occurrences, and `repeated_key` carries
`second_value_wins_inside_the_file`: inside one file, the last write wins, and
the two occurrences are one single definition (`definition_count = 1`), not a
conflict.

### F - a multi-line value

`labdemo [multiline_demo] allowed_networks` is written over three physical
lines with trailing `\`.

```
| confbtool labdemo stanza=multiline_demo audit=true
```

The `local` value comes back as **one** value containing newlines - the
continuations are folded into a single logical value, and the `default` layer
holds a shorter competing value.

### G - a disabled app takes no part

`zz_disabled_app` defines `[web_tier] max_threads` and a `[disabled_only]`
stanza that exists nowhere else.

```
| confbtool labdemo audit=true | search app=zz_disabled_app
| confbtool labdemo stanza=disabled_only audit=true
```

Both return nothing: an app whose `[install] state` is not `enabled` is out of
the resolution - which is what `btool` itself does on 9.4.6. If either ever
returns a row, the enumeration rule has regressed.

### H - conflicts spread over several confs

The overlaps are not concentrated on one file: `labnet` has its own, on
different keys and a different set of apps.

```
| confbtool labdemo,labnet,labsecret audit=true
| stats dc(file_path) as layers values(app) as apps by conf stanza key
| where layers > 1
```

Every key with more than one definition, in one table - the shape of a real
conflict audit.

### I - sensitive keys are never returned in clear

`labsecret` carries a fake `sslPassword`, two fake `api_token` values, and a
`[credential_store]` stanza.

```
| confbtool labsecret audit=true
```

Every value comes back as `sha256:<hexdigest>`:

- `sslPassword` and `api_token` match the configurable key patterns;
- **the whole `[credential_store]` stanza** is sensitive by the `credential*`
  stanza pattern - even its `endpoint` key, which is a URL. That is the rule
  working as designed, and it is worth seeing once;
- `public_setting`, in the same stanza as `sslPassword`, stays readable.

The two apps carry the **same** fake `sslPassword` value, and their digests
are identical: hashing preserves the cross-layer comparison that blanking
would destroy.

### J - an undecodable file does not abort the run

`zz_lab_overrides/local/labbroken.conf` contains a byte that is not valid
UTF-8.

```
| confbtool labbroken debug=true
```

Three rows: one `anomaly=parse_error` naming the file, plus the definitions
the parser could still extract (the resolution is never amputated). The run
carries on, and an audit spanning this conf is not aborted by it.

The same file also yields one `resolver_mismatch`: the command extracts what
it can from the broken bytes while btool parses them its own way, so the two
views legitimately differ. That row is a signal about the file, not a defect.

```
| confbtool * | where anomaly!=""
```

is the self-validation sweep. Read it per conf (`| stats count by conf
anomaly`) rather than as a single number: a `resolver_mismatch` always means
"our ranking and btool disagree here", which is worth looking at whatever its
cause.

### K - the system layer is named, not blank

```
| confbtool * | stats count by app | sort - count
```

The `etc/system/{local,default}` definitions are counted under `app=system` -
no `eval` fix-up needed. Note that `app=` remains a filter on **apps**:
`app=system` selects nothing, `| where scope="system"` is the predicate for
that layer.

### L - what the mode changes in the output itself

Run the three and look at the **columns**, not the values:

```
| confbtool labdemo
| confbtool labdemo debug=true
| confbtool labdemo audit=true
```

- default: no `file_path`, no verdict columns - 11 fields;
- `debug=true`: `file_path` appears - 12;
- `audit=true`: `file_path` **and** `is_btool_winner`, `btool_winner_path`,
  `btool_winner_value` - the full 15. `audit=true debug=false` gives the same
  thing: audit implies debug.

Contract fields and nothing else: no `_raw`, no `_time` in any mode.

`precedence_rank` and `definition_count` are there in every mode - they are
what tells you a key is contested and worth a second look in `audit=true`.
