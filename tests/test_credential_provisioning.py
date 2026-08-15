import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from credential_provisioning import provision, resolve_credentials_dir  # noqa: E402


class CredentialDirectoryResolutionTests(unittest.TestCase):
    def test_environment_override_has_highest_priority(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "public"
            project.mkdir()
            override = root / "explicit-secrets"

            resolved = resolve_credentials_dir(
                project, {"ESP32_OT_CREDENTIALS_DIR": str(override)}
            )

            self.assertEqual(resolved, override.resolve())

    def test_private_parent_credentials_are_preferred(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "public"
            project.mkdir()
            expected = root / "credentials"
            expected.mkdir()

            resolved = resolve_credentials_dir(project, {})

            self.assertEqual(resolved, expected.resolve())

    def test_standalone_clone_uses_ignored_local_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "public"
            project.mkdir()

            resolved = resolve_credentials_dir(project, {})

            self.assertEqual(resolved, (project / ".credentials").resolve())


class CredentialProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.project = self.root / "public"
        self.build = self.root / "build"
        self.credentials = self.root / "secrets"
        self.project.mkdir()
        self.environment = {"ESP32_OT_CREDENTIALS_DIR": str(self.credentials)}

    def tearDown(self):
        self.tempdir.cleanup()

    def test_first_build_generates_complete_private_material(self):
        result = provision(self.project, self.build, self.environment)

        self.assertEqual(result.credentials_dir, self.credentials.resolve())
        self.assertTrue(result.manifest_path.is_file())
        self.assertTrue(result.config_path.is_file())
        self.assertTrue(result.certificate_path.is_file())
        self.assertTrue(result.private_key_path.is_file())
        self.assertTrue(result.header_path.is_file())

        manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        admin_password = manifest["admin"]["password"]
        ap_password = manifest["access_point"]["password"]
        self.assertGreaterEqual(len(admin_password), 24)
        self.assertGreaterEqual(len(ap_password), 24)
        self.assertNotEqual(admin_password, ap_password)
        self.assertNotIn("password", admin_password.lower())

        config = json.loads(result.config_path.read_text(encoding="utf-8"))
        self.assertEqual(config["security"]["admin_password"], admin_password)
        self.assertEqual(config["network"]["wifi"]["password"], "")
        self.assertFalse(config["network"]["wifi"]["enabled"])

    def test_generated_certificate_and_key_form_a_valid_pair(self):
        result = provision(self.project, self.build, self.environment)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(result.certificate_path, result.private_key_path)
        decoded = ssl._ssl._test_decode_cert(str(result.certificate_path))

        common_names = [
            value
            for relative_name in decoded["subject"]
            for key, value in relative_name
            if key == "commonName"
        ]
        self.assertIn("esp32-ot-security.local", common_names)

    def test_repeated_build_is_idempotent(self):
        first = provision(self.project, self.build, self.environment)
        snapshots = {
            path.name: path.read_bytes()
            for path in (
                first.manifest_path,
                first.config_path,
                first.certificate_path,
                first.private_key_path,
                first.header_path,
            )
        }

        second = provision(self.project, self.build, self.environment)

        for path in (
            second.manifest_path,
            second.config_path,
            second.certificate_path,
            second.private_key_path,
            second.header_path,
        ):
            self.assertEqual(path.read_bytes(), snapshots[path.name])

    def test_partial_tls_state_is_repaired_without_rotating_passwords(self):
        first = provision(self.project, self.build, self.environment)
        manifest_before = first.manifest_path.read_bytes()
        first.certificate_path.unlink()

        second = provision(self.project, self.build, self.environment)

        self.assertEqual(second.manifest_path.read_bytes(), manifest_before)
        self.assertTrue(second.certificate_path.is_file())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(second.certificate_path, second.private_key_path)

    def test_generated_header_exists_only_under_build_output(self):
        result = provision(self.project, self.build, self.environment)

        self.assertTrue(result.header_path.is_relative_to(self.build.resolve()))
        self.assertFalse((self.project / "src" / "web" / "tls_cert.h").exists())
        self.assertFalse((self.project / "components" / "config_blob" / "config.json").exists())

        header = result.header_path.read_text(encoding="utf-8")
        self.assertIn("kEmbeddedConfigJson", header)
        self.assertIn("kServerCertificatePem", header)
        self.assertIn("kServerPrivateKeyPem", header)
        self.assertIn("kProvisioningApPassword", header)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not enforced on Windows")
    def test_private_files_are_owner_read_write_only(self):
        result = provision(self.project, self.build, self.environment)

        for path in (
            result.manifest_path,
            result.config_path,
            result.certificate_path,
            result.private_key_path,
        ):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
