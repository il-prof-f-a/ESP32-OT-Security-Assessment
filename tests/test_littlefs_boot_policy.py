import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class LittleFsBootPolicyTests(unittest.TestCase):
    def setUp(self):
        self.main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.ini = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        self.file_reporter = (
            PROJECT_ROOT / "src/reporters/file_reporter.cpp"
        ).read_text(encoding="utf-8")

    def test_mount_format_is_fail_closed_by_default(self):
        self.assertIn("#define ESP32_OT_LITTLEFS_AUTO_FORMAT 0", self.main)
        self.assertIn(
            ".format_if_mount_failed = (ESP32_OT_LITTLEFS_AUTO_FORMAT != 0)",
            self.main,
        )
        self.assertNotIn(".format_if_mount_failed = true", self.main)
        self.assertNotIn("ESP32_OT_LITTLEFS_AUTO_FORMAT=1", self.ini)

    def test_boot_never_recursively_purges_log_directory(self):
        self.assertNotIn("fs_purge_littlefs(", self.main)
        self.assertIn("const bool littlefs_mounted", self.main)
        self.assertIn(
            "Skipping LittleFS report and directory creation because storage is not mounted",
            self.main,
        )
        self.assertIn("Preserving existing LittleFS logs", self.main)

    def test_file_reporter_keeps_bounded_rotated_history(self):
        rotation = self.file_reporter.split(
            "bool FileReporter::rotateIfNeeded", 1
        )[1].split("bool FileReporter::init", 1)[0]
        self.assertIn("max_files", rotation)
        self.assertIn("file_path + \".\"", rotation)
        self.assertIn("AsyncStorage::Global::deleteFile", rotation)
        self.assertIn("AsyncStorage::Global::fileRename", rotation)


if __name__ == "__main__":
    unittest.main()
