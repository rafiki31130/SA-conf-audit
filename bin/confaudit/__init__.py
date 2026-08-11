"""`confaudit` - the library behind the `| confbtool` search command.

Three layers, mechanically enforced by `tests/test_layering.py` (spec section 1.3):

- **pure core**: `errors`, `model`, `confparser`, `resolver`, `btoolparser`,
  `confront`, `filters`, `secrets`, `volume`, `pipeline` - standard library only,
  no subprocess, no network, no disk access;
- **adapters**: `layers` (file system), `btoolrun` (btool invocation), `rest`
  (splunkd REST), `applog` (log file) - each side effect confined to its module;
- **Splunk wrapper**: `bin/confbtool.py`, the only file that imports the
  search command SDK.

The core receives the adapters as ports (spec section 1.4) and is fully testable
outside Splunk, without network access.
"""
