from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BaselineAnomalyDedupTests(unittest.TestCase):
    def setUp(self):
        self.engine = (PROJECT_ROOT / "src/assessment/anomaly_detection_engine.cpp").read_text(
            encoding="utf-8"
        )
        self.header = (PROJECT_ROOT / "src/assessment/protocol_baseline.h").read_text(
            encoding="utf-8"
        )
        self.baseline = (PROJECT_ROOT / "src/assessment/protocol_baseline.cpp").read_text(
            encoding="utf-8"
        )

    def test_baseline_is_evaluated_once_per_packet_processing_path(self):
        self.assertEqual(self.engine.count("baseline.detectAnomalies("), 1)

    def test_repeated_endpoint_type_anomalies_have_a_volatile_cooldown(self):
        self.assertIn("kAnomalyRepeatCooldownMs", self.baseline)
        self.assertIn("shouldEmitAnomaly", self.header)
        self.assertIn("last_anomaly_emit_ms_", self.header)
        self.assertIn("last_anomaly_emit_ms_.clear()", self.baseline)


if __name__ == "__main__":
    unittest.main()
