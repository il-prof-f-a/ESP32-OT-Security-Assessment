from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "package_release.py"


def load_module():
    spec = spec_from_file_location("package_release", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SCRIPT}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleasePackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = load_module()

    def make_build(self, root: Path, *, chip: str, boot_offset: str, mode: str, size: str):
        (root / "bootloader.bin").write_bytes(b"boot")
        (root / "partitions.bin").write_bytes(b"partitions")
        (root / "firmware.bin").write_bytes(b"application")
        (root / "littlefs.bin").write_bytes(b"filesystem")
        args = {
            "flash_settings": {"flash_mode": mode, "flash_size": size, "flash_freq": "80m"},
            "flash_files": {
                boot_offset: "bootloader/bootloader.bin",
                "0x8000": "partition_table/partition-table.bin",
                "0x200000": "esp32_ot_security_assessment.bin",
                "0x690000": "storage.bin",
            },
            "extra_esptool_args": {"chip": chip},
        }
        (root / "flasher_args.json").write_text(json.dumps(args), encoding="utf-8")

    def test_packages_esp32_s3_and_p4_without_hardcoded_flash_settings(self):
        cases = (
            ("t-poe-pro", "esp32", "0x1000", "dio", "16MB"),
            ("esp32-s3-eth", "esp32s3", "0x0", "dio", "16MB"),
            ("waveshare-esp32p4-eth", "esp32p4", "0x2000", "dio", "32MB"),
        )
        for environment, chip, offset, mode, size in cases:
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                build = root / "build"
                output = root / "release"
                build.mkdir()
                self.make_build(build, chip=chip, boot_offset=offset, mode=mode, size=size)

                def fake_merge(command, destination):
                    destination.write_bytes(" ".join(command).encode("utf-8"))

                products = self.package.package_release(
                    environment=environment,
                    build_dir=build,
                    version="0.1.0",
                    output_dir=output,
                    merge_runner=fake_merge,
                )
                manifest = json.loads(products.manifest.read_text(encoding="utf-8"))
                self.assertEqual(manifest["chip"], chip)
                self.assertEqual(manifest["flash_mode"], mode)
                self.assertEqual(manifest["flash_size"], size)
                self.assertEqual(manifest["files"][0]["offset"], int(offset, 0))
                self.assertEqual(products.app.read_bytes(), b"application")
                self.assertTrue(products.factory.is_file())
                with zipfile.ZipFile(products.bundle) as bundle:
                    self.assertIn(products.manifest.name, bundle.namelist())

    def test_missing_flash_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_build(root, chip="esp32", boot_offset="0x1000", mode="dio", size="16MB")
            (root / "littlefs.bin").unlink()
            with self.assertRaises(FileNotFoundError):
                self.package.package_release(
                    environment="t-poe-pro",
                    build_dir=root,
                    version="0.1.0",
                    output_dir=root / "out",
                    merge_runner=lambda command, destination: None,
                )


if __name__ == "__main__":
    unittest.main()
