import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workbench import Policy, investigate, load_events, render_html, render_markdown

ROOT = Path(__file__).resolve().parents[1]


class WorkbenchTests(unittest.TestCase):
    def test_csv_jsonl_equivalence(self):
        csv_report = investigate(load_events(ROOT / "sample_auth.csv"))
        json_report = investigate(load_events(ROOT / "sample_auth.jsonl"))
        self.assertEqual(csv_report, json_report)

    def test_heuristic_severity_and_ordering(self):
        findings = investigate(load_events(ROOT / "sample_auth.csv"))["findings"]
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["severity"], "high")

    def test_stable_finding_identifiers(self):
        rows = load_events(ROOT / "sample_auth.jsonl")
        self.assertEqual(investigate(rows)["findings"], investigate(rows)["findings"])

    def test_custom_threshold_filters_findings(self):
        report = investigate(load_events(ROOT / "sample_auth.csv"), Policy(10, 5, 10))
        self.assertEqual(report["findings"], [])

    def test_html_escapes_untrusted_username(self):
        rows = load_events(ROOT / "sample_auth.jsonl")
        for row in rows:
            if row["username"] == "alex":
                row["username"] = "<img src=x onerror=alert(1)>"
        page = render_html(investigate(rows))
        self.assertIn("&lt;img", page)
        self.assertNotIn("<img src=x", page)

    def test_invalid_jsonl_record_gives_line_number(self):
        with TemporaryDirectory() as path:
            file = Path(path) / "bad.jsonl"
            file.write_text('{"timestamp":"invalid"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Line 1"):
                load_events(file)

    def test_invalid_policy(self):
        with self.assertRaises(ValueError):
            investigate([], Policy(0, 3, 10))

    def test_markdown_contains_disclaimer(self):
        report = investigate(load_events(ROOT / "sample_auth.csv"))
        self.assertIn("human validation", render_markdown(report))

    def test_json_report_serializable(self):
        report = investigate(load_events(ROOT / "sample_auth.csv"))
        self.assertEqual(json.loads(json.dumps(report))["source_event_count"], 10)


if __name__ == "__main__":
    unittest.main()
