import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
API = PROJECT_ROOT / "src" / "web" / "security_api.h"
WEB_SERVER = PROJECT_ROOT / "src" / "web" / "web_server.cpp"
SECURITY = PROJECT_ROOT / "src" / "security" / "security_manager.cpp"


class OffensiveApiContractTests(unittest.TestCase):
    def test_api_exposes_build_lock_and_rejects_gate_relaxation(self):
        api = API.read_text(encoding="utf-8")
        manager = SECURITY.read_text(encoding="utf-8")
        for token in (
            '"offensive_interlock_bypass_allowed"',
            '"hardware_interlock_locked_by_build"',
            "isOffensiveInterlockBypassAuthorized",
            "getOffensiveTestingBoardProfile",
        ):
            self.assertIn(token, api + manager)

    def test_api_exposes_policy_status_and_password_gate(self):
        source = API.read_text(encoding="utf-8")
        for token in (
            '"offensive_testing"',
            '"effective"',
            '"gpio_asserted"',
            '"admin_password"',
            "verifyAdminPassword",
            "persistOffensiveTestingPolicy",
        ):
            self.assertIn(token, source)

    def test_api_no_long_legacy_gpio_nvs_keys_remain(self):
        source = API.read_text(encoding="utf-8")
        for key in (
            "fuzzing_gpio_gate_enabled",
            "fuzzing_gpio_gate_required",
            "fuzzing_gpio_num",
            "fuzzing_gpio_active_high",
            "fuzzing_gpio_pull_mode",
        ):
            self.assertNotIn(f'nvsSet("security", "{key}"', source)
            self.assertNotIn(f'nvsGet("security", "{key}"', source)

    def test_policy_uses_crc_protected_short_nvs_blob(self):
        source = SECURITY.read_text(encoding="utf-8")
        self.assertIn('"off_policy_v1"', source)
        self.assertIn("esp_crc32_le", source)
        self.assertIn("validOffensivePolicyRecord", source)

    def test_dedicated_offensive_testing_routes_share_authenticated_handler(self):
        source = WEB_SERVER.read_text(encoding="utf-8")
        self.assertIn('/api/security/offensive-testing', source)
        self.assertIn('h_offensive_testing_post', source)


if __name__ == "__main__":
    unittest.main()
