import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILE_HEADER = PROJECT_ROOT / "src" / "security" / "offensive_testing_board_profile.h"
PROFILE_SOURCE = PROJECT_ROOT / "src" / "security" / "offensive_testing_board_profile.cpp"


class OffensiveBoardProfileTests(unittest.TestCase):
    def test_profile_files_exist_and_define_all_supported_boards(self):
        self.assertTrue(PROFILE_HEADER.is_file())
        self.assertTrue(PROFILE_SOURCE.is_file())
        header = PROFILE_HEADER.read_text(encoding="utf-8")
        source = PROFILE_SOURCE.read_text(encoding="utf-8")
        for macro in (
            "BOARD_TPOE_PRO",
            "BOARD_ESP32_S3_ETH",
            "BOARD_WAVESHARE_ESP32P4_ETH",
            "BOARD_GUITION_JC_ESP32P4_M3_DEV",
        ):
            self.assertIn(macro, source)
        self.assertIn("OffensiveTestingBoardProfile", header)

    def test_defaults_match_user_selected_pins(self):
        source = PROFILE_SOURCE.read_text(encoding="utf-8")
        expected = {
            "BOARD_TPOE_PRO": 15,
            "BOARD_ESP32_S3_ETH": 16,
            "BOARD_WAVESHARE_ESP32P4_ETH": 16,
            "BOARD_GUITION_JC_ESP32P4_M3_DEV": 1,
        }
        profile_names = {
            "BOARD_TPOE_PRO": "kTpoeProfile",
            "BOARD_ESP32_S3_ETH": "kS3Profile",
            "BOARD_WAVESHARE_ESP32P4_ETH": "kP4Profile",
            "BOARD_GUITION_JC_ESP32P4_M3_DEV": "kGuitionProfile",
        }
        for macro, gpio in expected.items():
            self.assertTrue(
                f"#if defined({macro})" in source or f"#elif defined({macro})" in source,
                macro,
            )
            profile = profile_names[macro]
            definition = re.search(rf"k{profile[1:]}\{{(.*?)\}};", source, re.DOTALL)
            self.assertIsNotNone(definition, profile)
            self.assertRegex(definition.group(1), rf'"[^"]+",\s*{gpio},')

    def test_profiles_expose_validation_function(self):
        header = PROFILE_HEADER.read_text(encoding="utf-8")
        self.assertIn("getOffensiveTestingBoardProfile", header)
        self.assertIn("isAllowedOffensiveTestingGpio", header)


if __name__ == "__main__":
    unittest.main()
