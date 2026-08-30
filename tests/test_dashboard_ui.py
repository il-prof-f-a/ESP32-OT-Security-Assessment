from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DashboardUiTests(unittest.TestCase):
    def test_plugin_status_objects_render_name_and_event_count(self):
        for relative_path in (
            "src/web/ui/dashboard.html",
            "src/web/ui/gen/dashboard_html_gen.hpp",
        ):
            content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")

            self.assertIn(
                "const name = protocolName(p && typeof p === 'object' ? p.name : p);",
                content,
                relative_path,
            )
            self.assertIn(
                "const events = p && typeof p === 'object' ? p.events : null;",
                content,
                relative_path,
            )
            self.assertNotIn("protocolName(p))", content, relative_path)

    def test_discovery_and_offensive_pages_are_balanced_and_separate(self):
        discovery = (PROJECT_ROOT / "src/web/ui/discovery.html").read_text(encoding="utf-8")
        scanner = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        for name, content in (("discovery", discovery), ("scanner", scanner)):
            with self.subTest(page=name):
                self.assertEqual(
                    len(re.findall(r"<div\b", content)),
                    len(re.findall(r"</div>", content)),
                )

        self.assertIn('id="discovery"', discovery)
        self.assertNotIn('id="feat_scanner_fuzzing"', discovery)
        self.assertNotIn('data-tab="discovery"', scanner)
        self.assertIn('data-tab="scanner"', scanner)

    def test_dashboard_points_protocol_discovery_to_dedicated_page(self):
        dashboard = (PROJECT_ROOT / "src/web/ui/dashboard.html").read_text(encoding="utf-8")
        self.assertIn('<a href="/discovery" class="nav-btn">🔍 Protocol Discovery</a>', dashboard)


if __name__ == "__main__":
    unittest.main()
