import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILE_REPORTER_H = ROOT / "src/reporters/file_reporter.h"
FILE_REPORTER_CPP = ROOT / "src/reporters/file_reporter.cpp"
QUEUE_CPP = ROOT / "src/core/psram_reliable_queue.cpp"


class FileDeliveryDiagnosticsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reporter_h = FILE_REPORTER_H.read_text(encoding="utf-8")
        cls.reporter_cpp = FILE_REPORTER_CPP.read_text(encoding="utf-8")
        cls.queue_cpp = QUEUE_CPP.read_text(encoding="utf-8")

    def test_file_append_failures_expose_sampled_stage_and_error_details(self):
        """File delivery failures must identify the failing stage without logging payloads."""
        self.assertIn("append_failure_count_", self.reporter_h)
        self.assertIn("should_log_append_failure", self.reporter_cpp)
        self.assertIn("stage=psram_alloc", self.reporter_cpp)
        self.assertIn("stage=appendFileRaw", self.reporter_cpp)
        self.assertIn("esp_err_to_name(err)", self.reporter_cpp)
        self.assertNotIn("payload=%s", self.reporter_cpp)

    def test_queue_retry_diagnostics_include_event_and_queue_pressure(self):
        """A sampled retry must show event size and queue occupancy, not event contents."""
        self.assertIn("event_bytes=%u", self.queue_cpp)
        self.assertIn("queue=%u/%u", self.queue_cpp)
        self.assertNotIn("payload=%s", self.queue_cpp)


if __name__ == "__main__":
    unittest.main()
