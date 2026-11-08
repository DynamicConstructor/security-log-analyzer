"""Controlled examples of alerts, benign behavior, and window boundaries."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark import benchmark, generated_events
from scenario_lab import scenario_report
from workbench import investigate


class ScenarioTests(unittest.TestCase):
    def test_guessing_and_success(self):
        categories = {f["category"] for f in scenario_report("credential_guessing")["findings"]}
        self.assertIn("Repeated login failures", categories)
        self.assertIn("Success following repeated failures", categories)

    def test_spray(self):
        categories = {f["category"] for f in scenario_report("password_spray")["findings"]}
        self.assertIn("Multi-account source activity", categories)

    def test_routine_errors_below_threshold(self):
        self.assertEqual(scenario_report("routine_errors")["findings"], [])

    def test_window_boundary_does_not_combine_distant_events(self):
        self.assertEqual(scenario_report("window_boundary")["findings"], [])

    def test_benchmark_is_structured(self):
        result = benchmark([40], 1)
        self.assertEqual(result["results"][0]["events"], 40)
        self.assertGreaterEqual(result["results"][0]["median_ms"], 0)

    def test_generated_events_are_ordered(self):
        events = generated_events(150)
        self.assertEqual(len(events), 150)
        self.assertLess(events[0]["timestamp"], events[-1]["timestamp"])
        self.assertIsInstance(investigate(events)["findings"], list)


if __name__ == "__main__":
    unittest.main()
