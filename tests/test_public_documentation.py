from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PublicDocumentationTests(unittest.TestCase):
    def test_readme_documents_all_tested_hardware_and_observed_limits(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        for device in (
            "LILYGO T-POE Pro",
            "Waveshare ESP32-S3-ETH",
            "Waveshare ESP32-P4-ETH",
        ):
            self.assertIn(device, readme)

        self.assertIn("HTTP only", readme)
        self.assertIn("no native 24 V input", readme)
        self.assertIn("same Ethernet subnet", readme)
        self.assertIn("yet guaranteed", readme)

    def test_readme_local_links_and_images_exist(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        markdown_targets = re.findall(r"\[[^]]+\]\(([^)]+)\)", readme)
        html_images = re.findall(r'<img\s+src="([^"]+)"', readme)

        for target in markdown_targets + html_images:
            if target.startswith(("http://", "https://", "#")):
                continue
            self.assertTrue((PROJECT_ROOT / target).is_file(), target)

    def test_public_markdown_is_english(self):
        markdown_files = (
            PROJECT_ROOT / "README.md",
            PROJECT_ROOT / "CONTRIBUTING.md",
            PROJECT_ROOT / "SECURITY.md",
            PROJECT_ROOT / "tests/README.md",
            PROJECT_ROOT / "docs/assets/hardware/SOURCES.md",
        )
        italian_markers = re.compile(
            r"\b(?:Descrizione|Utilizzo|Problema|Verifica|Configurazione|Riferimenti)\b",
            re.IGNORECASE,
        )

        for path in markdown_files:
            self.assertIsNone(italian_markers.search(path.read_text(encoding="utf-8")), path)

    def test_license_is_the_requested_polyform_variant(self):
        license_text = (PROJECT_ROOT / "LICENSE.md").read_text(encoding="utf-8")

        self.assertTrue(license_text.startswith("# PolyForm Noncommercial License 1.0.0"))
        self.assertIn("Required Notice: Copyright 2026 Francesco Adriani.", license_text)

    def test_readme_documents_both_p4_build_paths(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("idf.py -B", readme)
        self.assertIn("IDF_TARGET=esp32p4", readme)
        self.assertIn("pio run -e waveshare-esp32p4-eth", readme)
        self.assertIn("pioarduino/platform-espressif32", readme)

    def test_readme_documents_installation_and_flash_workflows(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        for fragment in (
            "setup_platformio.ps1",
            "setup_platformio.sh",
            "build_flash.ps1",
            "build_flash.sh",
            "pio run -e t-poe-pro -t upload --upload-port COM10",
            "pio device monitor --port COM10 --baud 115200",
            "python scripts/flash_esptool.py --target t-poe-pro --port COM10",
            "0x1000",
            "0x8000",
            "0x200000",
            "bootloader mode",
        ):
            self.assertIn(fragment, readme)

    def test_onboarding_scripts_are_present(self):
        for name in (
            "setup_platformio.ps1",
            "setup_platformio.sh",
            "build_flash.ps1",
            "build_flash.sh",
            "flash_esptool.py",
        ):
            self.assertTrue((PROJECT_ROOT / "scripts" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
