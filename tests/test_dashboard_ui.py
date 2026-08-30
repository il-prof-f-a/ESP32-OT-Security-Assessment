from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DashboardUiTests(unittest.TestCase):
    def test_security_ui_locks_gpio_interlock_without_build_authorization(self):
        security = (PROJECT_ROOT / "src/web/ui/security.html").read_text(encoding="utf-8")
        for token in (
            "offensive_interlock_bypass_allowed",
            "Hardware interlock is mandatory",
            "fuzzing-gpio-gate-enabled",
            "disabled = !bypassAllowed",
        ):
            self.assertIn(token, security)

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

    def test_dashboard_hides_redundant_cards_and_links_configuration(self):
        dashboard = (PROJECT_ROOT / "src/web/ui/dashboard.html").read_text(encoding="utf-8")
        self.assertIn('href="/configuration"', dashboard)
        self.assertNotIn('<h2>🔒 Access Log</h2>', dashboard)
        self.assertNotIn('<h2>🧪 Scanner Jobs</h2>', dashboard)
        self.assertNotIn('<h2>⚙️ Config (JSON)</h2>', dashboard)
        self.assertNotIn('<h2>📝 Event Format</h2>', dashboard)
        self.assertIn("downloadLogFile('discovery_events.log')", dashboard)
        self.assertNotIn("downloadLogFile('scanner_events.log')", dashboard)

    def test_configuration_page_declares_safe_draft_actions(self):
        page = (PROJECT_ROOT / "src/web/ui/configuration.html").read_text(encoding="utf-8")
        for token in ("Load current", "Load saved", "Load defaults", "Import JSON",
                      "Validate", "Save to device", "Save as", "/api/config/editor/schema",
                      "secrets_present", "restart_required_paths"):
            self.assertIn(token, page)

    def test_discovery_start_status_is_inside_configuration_card_before_active_jobs(self):
        discovery = (PROJECT_ROOT / "src/web/ui/discovery.html").read_text(encoding="utf-8")

        active_heading = discovery.index('<h3>🕒 Active Discoveries</h3>')
        status_pos = discovery.index('id="status"')
        self.assertLess(status_pos, active_heading)
        self.assertIn('id="status" class="status" role="status" aria-live="polite" hidden', discovery)
        self.assertIn('Results will appear below shortly.', discovery)


if __name__ == "__main__":
    unittest.main()
