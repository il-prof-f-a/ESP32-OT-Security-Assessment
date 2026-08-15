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

    def test_readme_uses_native_esp_idf_for_the_p4_target(self):
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("idf.py -B", readme)
        self.assertIn("IDF_TARGET=esp32p4", readme)
        self.assertNotIn("pio run -e waveshare-esp32p4-eth", readme)


if __name__ == "__main__":
    unittest.main()
