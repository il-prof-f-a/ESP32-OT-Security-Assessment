from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "flash_esptool.py"


def load_flash_module():
    spec = spec_from_file_location("flash_esptool", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SCRIPT_PATH}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FirmwareToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flash = load_flash_module()

    def test_supported_targets_map_to_expected_esptool_chips(self):
        self.assertEqual(self.flash.TARGETS["t-poe-pro"].chip, "esp32")
        self.assertEqual(self.flash.TARGETS["esp32-s3-eth"].chip, "esp32s3")
        self.assertEqual(self.flash.TARGETS["waveshare-esp32p4-eth"].chip, "esp32p4")

    def test_application_offset_is_read_from_partition_table(self):
        with tempfile.TemporaryDirectory() as directory:
            partitions = Path(directory) / "partitions.csv"
            partitions.write_text(
                "# Name, Type, SubType, Offset, Size, Flags\n"
                "nvs, data, nvs, 0x9000, 0x1F6000,\n"
                "factory, app, factory, 0x200000, 0x480000,\n",
                encoding="utf-8",
            )
            self.assertEqual(self.flash.parse_application_offset(partitions), 0x200000)

    def test_flash_command_contains_bootloader_partitions_and_application(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            for name in ("bootloader.bin", "partitions.bin", "firmware.bin"):
                (build / name).write_bytes(b"artifact")

            command = self.flash.build_flash_command(
                target="t-poe-pro",
                port="COM10",
                build_dir=build,
                esptool_command=["python", "-m", "esptool"],
            )

            self.assertIn("--chip", command)
            self.assertIn("esp32", command)
            self.assertIn("--port", command)
            self.assertIn("COM10", command)
            self.assertIn("0x1000", command)
            self.assertIn("0x8000", command)
            self.assertIn("0x200000", command)
            self.assertIn(str(build / "firmware.bin"), command)

    def test_unknown_target_is_rejected(self):
        with self.assertRaises(ValueError):
            self.flash.target_config("unknown-board")


if __name__ == "__main__":
    unittest.main()
