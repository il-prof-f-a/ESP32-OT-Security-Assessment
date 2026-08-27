import json
from pathlib import Path
import re
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from build_assets import generate_build_assets  # noqa: E402


class BuildAssetsTests(unittest.TestCase):
    def test_build_rejects_credentials_in_littlefs_seed_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "data/certs/server.key"
            key.parent.mkdir(parents=True)
            key.write_text(
                "-----BEGIN PRIVATE KEY-----\n"
                "DUMMYTESTMATERIAL\n"
                "-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "LittleFS seed"):
                generate_build_assets(root, root / "build", "")

    def test_clean_builds_are_byte_for_byte_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = generate_build_assets(PROJECT_ROOT, root / "first", "t-poe-pro")
            second = generate_build_assets(PROJECT_ROOT, root / "second", "t-poe-pro")

            self.assertEqual(first.header_path.read_bytes(), second.header_path.read_bytes())

    def test_header_contains_only_public_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            result = generate_build_assets(
                PROJECT_ROOT, Path(temp) / "build", "esp32-s3-eth"
            )
            header = result.header_path.read_text(encoding="utf-8")

        self.assertIn("namespace esp32_ot_build", header)
        self.assertIn("kEmbeddedPublicConfigJson", header)
        for forbidden in (
            "kProvisioningApPassword",
            "kServerPrivateKeyPem",
            "kServerCertificatePem",
            "admin_password",
            "ESP32_OT_CREDENTIALS_DIR",
        ):
            self.assertNotIn(forbidden, header)

    def test_embedded_json_is_valid_and_has_no_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            result = generate_build_assets(
                PROJECT_ROOT, Path(temp) / "build", "waveshare-esp32p4-eth"
            )
            header = result.header_path.read_text(encoding="utf-8")

        match = re.search(
            r'R"ESP32CFG\((.*)\)ESP32CFG";', header, flags=re.DOTALL
        )
        self.assertIsNotNone(match)
        config = json.loads(match.group(1))
        self.assertNotIn("admin_password", config["security"])
        self.assertNotIn("admin_password_hash", config["security"])
        self.assertFalse(config["network"]["wifi"]["enabled"])
        self.assertTrue(config["network"]["ethernet"]["dhcp"])
        self.assertFalse(config["reporting"]["mqtt"]["enabled"])
        self.assertFalse(config["reporting"]["webhook"]["enabled"])
        self.assertFalse(config["reporting"]["email"]["enabled"])

    def test_board_name_does_not_change_public_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            headers = {
                generate_build_assets(PROJECT_ROOT, root / board, board)
                .header_path.read_bytes()
                for board in (
                    "t-poe-pro",
                    "esp32-s3-eth",
                    "waveshare-esp32p4-eth",
                    "guition-jc-esp32p4-m3-dev",
                )
            }

        self.assertEqual(len(headers), 1)


if __name__ == "__main__":
    unittest.main()
