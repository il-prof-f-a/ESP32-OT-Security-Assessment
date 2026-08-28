from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
