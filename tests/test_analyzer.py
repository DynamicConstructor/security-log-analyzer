import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, read_events


class AnalyzerTests(unittest.TestCase):
    def test_sample_flags_three_patterns(self):
        events = read_events(Path(__file__).resolve().parents[1] / "sample_auth.csv")
        result = analyze(events)
        self.assertEqual(result["total_events"], 10)
        self.assertEqual(len(result["failure_bursts"]), 1)
        self.assertEqual(len(result["multi_account_sources"]), 1)
        self.assertEqual(len(result["success_after_failures"]), 1)

    def test_old_failures_do_not_trigger_burst(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [{"timestamp": start + timedelta(minutes=20 * i),
                   "username": "sample", "source_ip": "192.0.2.1", "event": "failure"}
                  for i in range(5)]
        self.assertFalse(analyze(events)["failure_bursts"])

    def test_missing_columns_rejected(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            file = Path(directory) / "bad.csv"
            file.write_text("username,event\na,failure\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_events(file)

    def test_multi_account_activity_must_fit_in_window(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [{"timestamp": start + timedelta(minutes=25 * i),
                   "username": username, "source_ip": "192.0.2.1", "event": "failure"}
                  for i, username in enumerate(("a", "b", "c"))]
        self.assertEqual(analyze(events)["multi_account_sources"], [])

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)

    def test_unsorted_events_are_sorted_on_read(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text("timestamp,username,source_ip,event\n"
                            "2026-01-01T00:02:00Z,a,192.0.2.1,failure\n"
                            "2026-01-01T00:01:00Z,a,192.0.2.1,failure\n", encoding="utf-8")
            rows = read_events(path)
            self.assertLess(rows[0]["timestamp"], rows[1]["timestamp"])


if __name__ == "__main__":
    unittest.main()
