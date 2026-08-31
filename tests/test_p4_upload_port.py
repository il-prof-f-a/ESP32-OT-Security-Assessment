from importlib.util import module_from_spec, spec_from_file_location
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FLASH_SCRIPT = ROOT / "scripts" / "flash_esptool.py"


def load_flash_module():
    spec = spec_from_file_location("flash_esptool_port_test", FLASH_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {FLASH_SCRIPT}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P4UploadPortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flash = load_flash_module()

    def test_custom_uploader_does_not_emit_a_bare_port_argument(self):
        source = (ROOT / "scripts/p4_upload.py").read_text(encoding="utf-8")
        self.assertIn("UPLOAD_PORT", source)
        self.assertRegex(source, r"if\s+upload_port")
        self.assertNotIn("--port $UPLOAD_PORT'", source)

    def test_flash_tool_can_resolve_an_unspecified_port(self):
        source = (ROOT / "scripts/flash_esptool.py").read_text(encoding="utf-8")
        self.assertIn("resolve_upload_port", source)
        self.assertIn("--port", source)
        self.assertIn("required=False", source)

    def test_single_detected_port_is_selected(self):
        with patch(
            "serial.tools.list_ports.comports",
            return_value=[SimpleNamespace(device="COM10")],
        ):
            self.assertEqual(self.flash.resolve_upload_port(None), "COM10")

    def test_multiple_detected_ports_require_explicit_selection(self):
        with patch(
            "serial.tools.list_ports.comports",
            return_value=[SimpleNamespace(device="COM10"), SimpleNamespace(device="COM12")],
        ):
            with self.assertRaisesRegex(ValueError, "Multiple serial ports"):
                self.flash.resolve_upload_port(None)


if __name__ == "__main__":
    unittest.main()
