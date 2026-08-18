from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import tempfile
import unittest
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "check_release_secrets.py"


def load_module():
    spec = spec_from_file_location("check_release_secrets", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SCRIPT}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseSecretScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = load_module()

    def test_detects_synthetic_secrets_in_binary_and_zip_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = b"-----BEGIN PRIVATE KEY-----\nDUMMY-TEST-MATERIAL\n"
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"prefix\0" + secret)
            bundle = root / "bundle.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("config.json", b'{"admin_password":"dummy-secret"}')
            findings = self.scanner.scan_paths([firmware, bundle])
            rendered = "\n".join(finding.safe_description() for finding in findings)
            self.assertIn("private-key-pem", rendered)
            self.assertIn("nonempty-admin-password", rendered)
            self.assertNotIn("DUMMY-TEST-MATERIAL", rendered)
            self.assertNotIn("dummy-secret", rendered)

    def test_private_denylist_is_applied_as_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact.bin"
            artifact.write_bytes(b"safe-prefix local-only-marker safe-suffix")
            findings = self.scanner.scan_paths(
                [artifact], denylist=[b"local-only-marker"]
            )
            self.assertEqual([finding.rule for finding in findings], ["private-denylist-1"])

    def test_clean_artifact_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"deterministic public firmware bytes")
            self.assertEqual(self.scanner.scan_paths([artifact]), [])


if __name__ == "__main__":
    unittest.main()
