import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import build_assets  # noqa: E402


class OffensiveConfigAssetTests(unittest.TestCase):
    def test_public_defaults_use_user_selected_board_pins(self):
        expected = {
            "t-poe-pro": 15,
            "esp32-s3-eth": 16,
            "waveshare-esp32p4-eth": 16,
            "guition-jc-esp32p4-m3-dev": 1,
        }
        for board, gpio in expected.items():
            defaults = build_assets._public_defaults(board)
            policy = defaults["security"]["offensive_testing"]
            self.assertFalse(policy["software_enabled"])
            self.assertTrue(policy["gpio_gate"]["enabled"])
            self.assertTrue(policy["gpio_gate"]["required"])
            self.assertEqual(policy["gpio_gate"]["gpio"], gpio)

    def test_unguarded_embedded_offensive_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "device-config.json").write_text(
                json.dumps(
                    {
                        "admin_password": "A" * 20,
                        "security": {
                            "offensive_testing": {
                                "software_enabled": True,
                                "gpio_gate": {"required": False},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"ESP32_OT_EMBEDDED_CONFIG": "1"}, clear=False):
                with self.assertRaises(ValueError):
                    build_assets.generate_build_assets(root, root / "build", "t-poe-pro")


if __name__ == "__main__":
    unittest.main()
