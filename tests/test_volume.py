"""Volume guard (spec section 8, D-8)."""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import volume
from confaudit.errors import VolumeRefused
from tests.helpers import CollectingLog, FakeBtool, FakeFs, FakeRest, build_btool_output
from confaudit import pipeline


class CheckTest(unittest.TestCase):

    def test_exactly_at_the_limit_passes(self):
        volume.check(50000, 50000)  # must not raise

    def test_one_above_the_limit_refuses(self):
        with self.assertRaises(VolumeRefused):
            volume.check(50001, 50000)

    def test_exact_refusal_message(self):
        with self.assertRaises(VolumeRefused) as ctx:
            volume.check(7, 5)
        self.assertEqual(
            str(ctx.exception),
            "confbtool: refusing to emit 7 rows: this instance's result "
            "limit is 5 (limits.conf [searchresults] maxresultrows). Narrow "
            "the request with an explicit conf list, stanza=, key= or app= "
            "filters, or audit=false. No partial results were produced: a "
            "truncated audit would read as missing definitions.",
        )


class PipelineVolumeTest(unittest.TestCase):
    """The guard counts what WOULD be emitted - anomalies included - and no
    row is built before it passes."""

    @staticmethod
    def _fixture(maxresultrows, keys=3, with_mismatch=False):
        fs = FakeFs()
        fs.add("system", "", "local", "limits",
               "[searchresults]\nmaxresultrows = %d\n" % maxresultrows)
        body = "[s]\n" + "".join("k%d = v%d\n" % (i, i) for i in range(keys))
        path = fs.add("app", "00_corp_base", "local", "probe", body)
        entries = [(path, "[s]")]
        for i in range(keys):
            entries.append((path, "k%d = v%d" % (i, i)))
        if with_mismatch:
            # A btool verdict on a group we never parsed: one
            # resolver_mismatch row, counted by the guard.
            entries.append((path, "[zz_ghost]"))
            entries.append((path, "ghost_key = ghost_val"))
        btool = FakeBtool({"probe": build_btool_output(entries)})
        return fs, btool

    def _run(self, fs, btool, emit=None):
        return pipeline.run(
            fs=fs, btool=btool, rest=FakeRest(), fieldnames=["probe"],
            audit=True, member="member-01", etc_prefix="/opt/splunk/etc",
            log=CollectingLog(), emit=emit,
        )

    def test_batch_exactly_at_the_limit_is_emitted(self):
        fs, btool = self._fixture(maxresultrows=3, keys=3)
        rows = self._run(fs, btool)
        self.assertEqual(len(rows), 3)

    def test_batch_one_above_the_limit_is_refused(self):
        fs, btool = self._fixture(maxresultrows=2, keys=3)
        with self.assertRaises(VolumeRefused):
            self._run(fs, btool)

    def test_anomaly_rows_count_toward_the_limit(self):
        # 3 definitions + 1 resolver_mismatch = 4 rows: refused at limit 3.
        fs, btool = self._fixture(maxresultrows=3, keys=3, with_mismatch=True)
        with self.assertRaises(VolumeRefused):
            self._run(fs, btool)

    def test_no_row_reaches_the_emit_port_before_the_refusal(self):
        emitted = []
        fs, btool = self._fixture(maxresultrows=1, keys=3)
        with self.assertRaises(VolumeRefused):
            self._run(fs, btool, emit=emitted.append)
        self.assertEqual(emitted, [])

    def test_limit_read_from_limits_conf_layers_not_hardcoded(self):
        # A permissive local limit lets a batch pass that the default 50000
        # would also pass - so probe the other direction: a tight local limit
        # must be honored over the fallback.
        fs, btool = self._fixture(maxresultrows=2, keys=2)
        rows = self._run(fs, btool)
        self.assertEqual(len(rows), 2)

    def test_fallback_to_50000_with_warning_when_absent(self):
        fs = FakeFs()
        path = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        btool = FakeBtool({
            "probe": build_btool_output([(path, "[s]"), (path, "k = v")])
        })
        log = CollectingLog()
        rows = pipeline.run(
            fs=fs, btool=btool, rest=FakeRest(), fieldnames=["probe"],
            member="member-01", etc_prefix="/opt/splunk/etc", log=log,
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("falling back to 50000", log.all_text())

    def test_fallback_when_not_an_integer(self):
        fs = FakeFs()
        fs.add("system", "", "local", "limits",
               "[searchresults]\nmaxresultrows = not_a_number\n")
        path = fs.add("app", "00_corp_base", "local", "probe", "[s]\nk = v\n")
        btool = FakeBtool({
            "probe": build_btool_output([(path, "[s]"), (path, "k = v")])
        })
        log = CollectingLog()
        rows = pipeline.run(
            fs=fs, btool=btool, rest=FakeRest(), fieldnames=["probe"],
            member="member-01", etc_prefix="/opt/splunk/etc", log=log,
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("falling back to 50000", log.all_text())


if __name__ == "__main__":
    unittest.main()
