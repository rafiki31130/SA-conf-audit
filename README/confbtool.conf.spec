#   confbtool.conf.spec
#
#   Specification of confbtool.conf, the configuration file proper to the
#   SA-conf-audit app. This file is the REFERENCE for the settings the app
#   reads: default/confbtool.conf carries the shipped values, this one carries
#   the contract. tests/test_conf_spec.py holds the two in correspondence, in
#   both directions - a setting cannot be shipped without being specified, and
#   a specified setting cannot vanish from what is shipped.
#
#   Splunk convention, as for any *.conf.spec: an attribute is declared with
#   its TYPE, never with a value; the description lines are prefixed with '*';
#   the default is stated in the description. A value assigned here would be
#   ignored by the platform and would only invite a reader to mistake this
#   file for a place to configure the app - which it is not.
#
#   To override a setting, create SA-conf-audit/local/confbtool.conf. Ship
#   nothing: every default below is functional.
#
#   The app version lives in default/app.conf and is not repeated here.

[secrets]
* Complementary rules for masking sensitive values. They COMPLEMENT the
  encrypt_fields list of server.conf, which is read at run time and is the
  canonical source; nothing here can unmask a key that encrypt_fields
  designates.

extra_key_patterns = <comma-separated list of glob patterns>
* Glob patterns matched against KEY names, case-insensitive. Literal
  characters plus the wildcards '*' and '?'. Every matching key has its value
  replaced by sha256:<hexdigest> in the results.
* Set to an empty list to rely on encrypt_fields alone.
* Default: pass4SymmKey, sslPassword, *password*, *secret*, *token*

extra_stanza_patterns = <comma-separated list of glob patterns>
* Glob patterns matched against STANZA names, case-insensitive. Every key of a
  matching stanza is treated as sensitive, whatever its name.
* Default: credential*

pattern_excluded_confs = <comma-separated list of conf names>
* Confs on which the two pattern lists above do NOT apply. EXACT conf names,
  case-sensitive, never globs - an exclusion must not be able to grow wider
  than what was demonstrated for it.
* encrypt_fields is never excluded: a key the platform declares encryptable
  stays masked even in a conf listed here.
* Only list a conf whose value space cannot hold a credential. The
  justification of each shipped name is in README.md.
* Set to an empty list to mask everything the patterns match, which was the
  behaviour before 1.1.0.
* Default: authorize, collections, fields, multikv, sourcetypes, web-features

[logging]
* Application log $SPLUNK_HOME/var/log/splunk/sa_conf_audit.log, the only file
  the command ever writes. No configuration value, cleartext or hashed, is
  ever written to it.

level = [CRITICAL|ERROR|WARNING|INFO|DEBUG]
* Verbosity of the application log. An unrecognised value falls back to INFO.
* INFO: invocation parameters, member, resolved conf list, volume limit,
  per-conf counters, final row count or refusal reason.
* DEBUG: adds the per-file detail.
* Default: INFO

[rest]
* TLS settings of the loopback splunkd REST calls, which carry the
  run_confbtool capability check and the serverName lookup.

verify_ssl = <boolean>
* true: the splunkd certificate chain is verified against the resolved CA
  store (see ca_file). The hostname check stays disabled either way: the
  splunkd URI is a loopback address and the default Splunk certificates carry
  no matching SAN, so the name is not the property being asserted here - the
  chain of trust is.
* false: no verification at all. The command then emits a single warning at
  startup naming the setting. Do not use this to work around a certificate
  the app cannot validate: set ca_file, or fix
  server.conf [sslConfig] sslRootCAPath, so the chain is really verified.
* Default: true

ca_file = <path>
* CA store the splunkd certificate chain is verified against. Explicit escape
  hatch, for the cases the resolution below does not cover.
* When set, this store is EXCLUSIVE: it is the only one loaded, and neither
  sslRootCAPath nor the Splunk truststore is added to it. An administrator who
  names an exact set of authorities keeps it exact. This key is new in 1.4.0,
  so its exclusivity cannot change how any earlier installation behaved.
* $SPLUNK_HOME is expanded, and a relative path is anchored on $SPLUNK_HOME.
* When empty, the stores are CUMULATED, not ranked:
    1. server.conf [sslConfig] sslRootCAPath, read on etc/system/default then
       etc/system/local, local winning - what the instance itself declares as
       its trust anchor, and what makes a member whose splunkd certificate was
       replaced by an enterprise one work with no setting at all;
    2. $SPLUNK_HOME/etc/auth/cacert.pem, the Splunk truststore.
  Both are loaded into the same verification context whenever both are
  present. Loading a second store ADDS certificate authorities and removes
  none, so the verification is never weakened: it is what lets a member that
  kept its original splunkd certificate keep working on an instance whose
  sslRootCAPath was filled for unrelated purposes.
* A path set here, or declared in sslRootCAPath, is used even when it does not
  exist: the capability check then fails with a message naming that file and
  the setting it came from - even when the other store would have verified the
  chain on its own. There is no silent fallback to the remaining store - a
  verification anchored somewhere nobody chose is worse than a loud refusal.
  The Splunk truststore is not subject to this: nobody configures it, so its
  absence is not a configuration error.
* A path set here, or declared in sslRootCAPath, that cannot be resolved at
  all is refused rather than resolved: a value written against $SPLUNK_HOME
  while the search process has no $SPLUNK_HOME in its environment, a value
  that expands to an empty path, and a relative value whose .. segments climb
  above $SPLUNK_HOME. Give an absolute path in those cases.
* Paths are normalised segment by segment - ., .. and doubled separators are
  resolved as the file system resolves them. Percent sequences are NOT
  decoded: %2F is a character of a file name, never a separator.
* On a verification failure the message names every store that was loaded,
  each with the setting it came from.
* Ignored when verify_ssl is false.
* Default: empty
