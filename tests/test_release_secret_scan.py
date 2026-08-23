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
            secret = b"-----BEGIN PRIVATE KEY-----\nDUMMYTESTMATERIAL\n-----END PRIVATE KEY-----\n"
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"prefix\0" + secret)
            bundle = root / "bundle.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("config.json", b'{"admin_password":"dummy-secret"}')
            findings = self.scanner.scan_paths([firmware, bundle])
            rendered = "\n".join(finding.safe_description() for finding in findings)
            self.assertIn("private-key-pem", rendered)
            self.assertIn("nonempty-admin-password", rendered)
            self.assertNotIn("DUMMYTESTMATERIAL", rendered)
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

    def test_repository_allows_the_documented_placeholder_once_in_each_root_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            placeholder = '"admin_password": "your-fixed-password-here"'
            (root / "README.md").write_text(placeholder, encoding="utf-8")
            (root / "CONFIG.md").write_text(placeholder, encoding="utf-8")

            self.assertEqual(
                self.scanner.main(["--repository", str(root)]),
                0,
            )

    def test_repository_rejects_the_placeholder_in_any_other_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "docs"
            nested.mkdir()
            (nested / "README.md").write_text(
                '"admin_password": "your-fixed-password-here"',
                encoding="utf-8",
            )

            self.assertEqual(
                self.scanner.main(["--repository", str(root)]),
                1,
            )

    def test_repository_rejects_an_unapproved_value_in_an_allowed_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                '"admin_password": "different-example-password"',
                encoding="utf-8",
            )

            self.assertEqual(
                self.scanner.main(["--repository", str(root)]),
                1,
            )

    def test_repository_rejects_more_than_one_allowed_placeholder_per_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            placeholder = '"admin_password": "your-fixed-password-here"'
            (root / "CONFIG.md").write_text(
                f"{placeholder}\n{placeholder}\n",
                encoding="utf-8",
            )

            self.assertEqual(
                self.scanner.main(["--repository", str(root)]),
                1,
            )

    def test_artifacts_never_allow_the_documentation_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            placeholder = b'{"admin_password":"your-fixed-password-here"}'
            firmware = root / "firmware.bin"
            firmware.write_bytes(placeholder)
            bundle = root / "bundle.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("README.md", placeholder)

            firmware_findings = self.scanner.scan_paths([firmware])
            bundle_findings = self.scanner.scan_paths([bundle])
            self.assertIn(
                "nonempty-admin-password",
                [finding.rule for finding in firmware_findings],
            )
            self.assertIn(
                "nonempty-admin-password",
                [finding.rule for finding in bundle_findings],
            )


if __name__ == "__main__":
    unittest.main()
