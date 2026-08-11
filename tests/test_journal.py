"""Log content rule (spec section 11): the messages built by the pipeline
never carry a configuration VALUE - cleartext or hashed, sensitive or not.
Conf names, stanzas, keys and paths are admitted.

Probed with recognizable sentinel values, secret and non-secret alike.
"""

import unittest

import tests  # noqa: F401  - inserts bin/ into sys.path before confaudit imports
from confaudit import pipeline
from confaudit.secrets import hash_value
from tests.helpers import CollectingLog, FakeBtool, FakeFs, FakeRest, build_btool_output

#: Sentinels: if one of these strings reaches a log message, a value leaked.
PLAIN_SENTINEL = "SENTINEL_PLAIN_VALUE_93b1"
SECRET_SENTINEL = "$7$SENTINEL_ENCRYPTED_VALUE_5c7e"


class JournalContentTest(unittest.TestCase):

    def _run_with_log(self):
        fs = FakeFs()
        fs.add("system", "", "local", "server",
               '[general]\nencrypt_fields = "probe:s:hidden_key"\n')
        path = fs.add(
            "app", "00_corp_base", "local", "probe",
            "[s]\nplain_key = %s\nhidden_key = %s\n"
            % (PLAIN_SENTINEL, SECRET_SENTINEL),
        )
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"),
            (path, "hidden_key = %s" % SECRET_SENTINEL),
            (path, "plain_key = %s" % PLAIN_SENTINEL),
        ])})
        log = CollectingLog()
        rows = pipeline.run(
            fs=fs, btool=btool, rest=FakeRest(), fieldnames=["probe"],
            audit=True, member="member-01", etc_prefix="/opt/splunk/etc",
            log=log,
        )
        return rows, log

    def test_no_value_in_the_log_cleartext_or_hashed(self):
        rows, log = self._run_with_log()
        text = log.all_text()
        self.assertNotIn(PLAIN_SENTINEL, text)
        self.assertNotIn(SECRET_SENTINEL, text)
        self.assertNotIn(hash_value(PLAIN_SENTINEL), text)
        self.assertNotIn(hash_value(SECRET_SENTINEL), text)
        # Control that the run actually processed the sentinels.
        self.assertEqual(len(rows), 2)

    def test_names_and_counts_are_admitted(self):
        _, log = self._run_with_log()
        text = log.all_text()
        self.assertIn("probe", text)          # conf name
        self.assertIn("member-01", text)      # member
        self.assertIn("emitting 2 rows", text)

    def test_refusal_message_in_log_carries_counts_only(self):
        fs = FakeFs()
        fs.add("system", "", "local", "limits",
               "[searchresults]\nmaxresultrows = 1\n")
        path = fs.add("app", "00_corp_base", "local", "probe",
                      "[s]\na = %s\nb = x\n" % PLAIN_SENTINEL)
        btool = FakeBtool({"probe": build_btool_output([
            (path, "[s]"), (path, "a = %s" % PLAIN_SENTINEL), (path, "b = x"),
        ])})
        log = CollectingLog()
        with self.assertRaises(Exception):
            pipeline.run(
                fs=fs, btool=btool, rest=FakeRest(), fieldnames=["probe"],
                audit=True, member="member-01",
                etc_prefix="/opt/splunk/etc", log=log,
            )
        text = log.all_text()
        self.assertIn("refused: 2 rows over limit 1", text)
        self.assertNotIn(PLAIN_SENTINEL, text)


if __name__ == "__main__":
    unittest.main()
