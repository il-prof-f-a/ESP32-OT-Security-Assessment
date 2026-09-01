"""Regression contract for the application panic boundary (issue #3)."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PanicSafetyContractTests(unittest.TestCase):
    def test_application_has_no_async_custom_panic_callback(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertNotIn("custom_panic_handler", source)
        self.assertNotIn("panic_info_t*", source)
        self.assertNotIn("AsyncStorage::Global::nvsSet", source)
        self.assertIn("Native ESP-IDF panic handler active", source)

    def test_manual_panic_validation_is_documented_without_a_crash_endpoint(self):
        guide = (ROOT / "docs/user-guide/diagnostics.md").read_text(encoding="utf-8")
        self.assertIn("Panic-path safety verification", guide)
        self.assertIn("already-authorized debugger", guide)
        self.assertIn("Do not add or expose a production crash endpoint", guide)


if __name__ == "__main__":
    unittest.main()
