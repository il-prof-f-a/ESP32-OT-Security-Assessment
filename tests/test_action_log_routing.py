import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ActionLogRoutingTests(unittest.TestCase):
    def test_canonical_action_files_and_exclusive_categories(self):
        manager = (ROOT / "src/core/log_file_manager.cpp").read_text(encoding="utf-8")
        for name in ("discovery_events.log", "signature_events.log",
                     "network_presence_events.log"):
            self.assertIn(name, manager)
        self.assertIn("vulnerability_scanner", manager)

    def test_dashboard_logging_labels_new_files(self):
        page = (ROOT / "src/web/ui/logging.html").read_text(encoding="utf-8")
        for name in ("discovery_events.log", "signature_events.log",
                     "network_presence_events.log"):
            self.assertIn(name, page)


if __name__ == "__main__":
    unittest.main()
