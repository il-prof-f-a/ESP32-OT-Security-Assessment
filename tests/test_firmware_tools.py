from importlib.util import module_from_spec, spec_from_file_location
import json
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
        self.assertEqual(
            self.flash.TARGETS["guition-jc-esp32p4-m3-dev"].chip, "esp32p4"
        )

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
            (build / "bootloader").mkdir()
            (build / "partition_table").mkdir()
            (build / "bootloader" / "bootloader.bin").write_bytes(b"bootloader")
            (build / "partition_table" / "partition-table.bin").write_bytes(b"partitions")
            (build / "esp32_ot_security_assessment.bin").write_bytes(b"application")
            (build / "storage.bin").write_bytes(b"filesystem")
            (build / "flasher_args.json").write_text(
                json.dumps(
                    {
                        "flash_settings": {
                            "flash_mode": "qio",
                            "flash_size": "32MB",
                            "flash_freq": "80m",
                        },
                        "flash_files": {
                            "0x2000": "bootloader/bootloader.bin",
                            "0x8000": "partition_table/partition-table.bin",
                            "0x200000": "esp32_ot_security_assessment.bin",
                            "0x690000": "storage.bin",
                        },
                        "extra_esptool_args": {"chip": "esp32p4"},
                    }
                ),
                encoding="utf-8",
            )

            command = self.flash.build_flash_command(
                target="waveshare-esp32p4-eth",
                port="COM10",
                build_dir=build,
                esptool_command=["python", "-m", "esptool"],
            )

            self.assertIn("--chip", command)
            self.assertIn("esp32p4", command)
            self.assertIn("--port", command)
            self.assertIn("COM10", command)
            self.assertIn("--no-progress", command)
            self.assertIn("qio", command)
            self.assertIn("32MB", command)
            self.assertIn("80m", command)
            self.assertIn("0x2000", command)
            self.assertIn("0x8000", command)
            self.assertIn("0x200000", command)
            self.assertIn("0x690000", command)
            self.assertIn(str(build / "esp32_ot_security_assessment.bin"), command)

    def test_flash_command_rejects_manifest_for_a_different_chip(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            (build / "flasher_args.json").write_text(
                json.dumps(
                    {
                        "flash_settings": {
                            "flash_mode": "dio",
                            "flash_size": "16MB",
                            "flash_freq": "40m",
                        },
                        "flash_files": {"0x1000": "bootloader.bin"},
                        "extra_esptool_args": {"chip": "esp32"},
                    }
                ),
                encoding="utf-8",
            )
            (build / "bootloader.bin").write_bytes(b"bootloader")

            with self.assertRaisesRegex(ValueError, "does not match"):
                self.flash.build_flash_command(
                    target="waveshare-esp32p4-eth",
                    port="COM10",
                    build_dir=build,
                    esptool_command=["python", "-m", "esptool"],
                )

    def test_unknown_target_is_rejected(self):
        with self.assertRaises(ValueError):
            self.flash.target_config("unknown-board")

    def test_factory_reset_erases_only_nvs_and_littlefs_regions(self):
        commands = self.flash.build_factory_reset_commands(
            target="t-poe-pro",
            port="COM10",
            partitions_path=PROJECT_ROOT / "partitions.csv",
            esptool_command=["python", "-m", "esptool"],
        )
        rendered = [" ".join(command) for command in commands]
        self.assertEqual(len(rendered), 2)
        self.assertIn("erase-region 0x9000 0x1f6000", rendered[0].lower())
        self.assertIn("erase-region 0x690000 0x970000", rendered[1].lower())
        self.assertTrue(all("erase-flash" not in command for command in rendered))


if __name__ == "__main__":
    unittest.main()
