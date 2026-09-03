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

    def test_offensive_scanner_page_does_not_duplicate_discovery_navigation(self):
        scanner = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")
        self.assertNotIn('href="/discovery"', scanner)

    def test_audit_live_monitor_normalizes_events_envelope(self):
        audit = (PROJECT_ROOT / "src/web/ui/audit.html").read_text(encoding="utf-8")
        self.assertIn("normalizeAuditEvents", audit)
        self.assertIn("Array.isArray(payload.events)", audit)
        self.assertIn("const events = normalizeAuditEvents", audit)

    def test_audit_analytics_normalizes_api_envelope_and_has_refresh(self):
        audit = (PROJECT_ROOT / "src/web/ui/audit.html").read_text(encoding="utf-8")
        self.assertIn("normalizeAuditAnalytics", audit)
        self.assertIn("payload.analytics", audit)
        self.assertIn("event_types", audit)
        self.assertIn("id=\"analytics_refresh\"", audit)
        self.assertIn("loadAnalytics()", audit)

    def test_serial_page_delegates_configuration_to_reporting_serial_tab(self):
        serial = (PROJECT_ROOT / "src/web/ui/serial_monitor.html").read_text(encoding="utf-8")
        self.assertNotIn("Serial Reporting Configuration", serial)
        self.assertIn('href="/reporting?channel=serial"', serial)
        self.assertIn("Serial Output", serial)

    def test_reporting_page_can_open_requested_channel_tab(self):
        reporting = (PROJECT_ROOT / "src/web/ui/reporting.html").read_text(encoding="utf-8")
        self.assertIn("params.get('channel')", reporting)
        self.assertIn("selectReportChannel(requestedChannel)", reporting)

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

    def test_configuration_dashboard_link_preserves_session_token(self):
        page = (PROJECT_ROOT / "src/web/ui/configuration.html").read_text(encoding="utf-8")
        self.assertIn("querySelectorAll('.nav-btn')", page)
        self.assertIn("window.__sidToken", page)
        self.assertIn("sid=", page)

    def test_dashboard_orders_configuration_after_network_tools(self):
        dashboard = (PROJECT_ROOT / "src/web/ui/dashboard.html").read_text(encoding="utf-8")
        network_pos = dashboard.index('href="/network"')
        config_pos = dashboard.index('href="/configuration"')
        diagnostics_pos = dashboard.index('href="/diagnostics"')
        self.assertLess(network_pos, config_pos)
        self.assertLess(config_pos, diagnostics_pos)

    def test_configuration_page_uses_shared_page_chrome(self):
        page = (PROJECT_ROOT / "src/web/ui/configuration.html").read_text(encoding="utf-8")
        for token in ("class=\"navbar\"", "class=\"container\"", "class=\"nav-brand\"",
                      "class=\"btn nav-btn\"", "--surface:", "--border:"):
            self.assertIn(token, page)

    def test_configuration_groups_fields_by_subsection(self):
        page = (PROJECT_ROOT / "src/web/ui/configuration.html").read_text(encoding="utf-8")
        for token in ("groupFieldsBySubsection", "subsection-card", "subsection-title",
                      "network.wifi", "network.ethernet", "General"):
            self.assertIn(token, page)

    def test_discovery_start_status_is_inside_configuration_card_before_active_jobs(self):
        discovery = (PROJECT_ROOT / "src/web/ui/discovery.html").read_text(encoding="utf-8")

        active_heading = discovery.index('<h3>🕒 Active Discoveries</h3>')
        status_pos = discovery.index('id="status"')
        self.assertLess(status_pos, active_heading)
        self.assertIn('id="status" class="status" role="status" aria-live="polite" hidden', discovery)
        self.assertIn('Results will appear below shortly.', discovery)

    def test_scanner_job_name_is_prefilled_from_the_selected_protocol_but_remains_editable(self):
        scanner = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        self.assertIn("prefillScannerJobName", scanner)
        self.assertIn("jobName.readOnly = false", scanner)
        self.assertIn("jobName.dataset.autoName", scanner)
        self.assertIn("prefillScannerJobName(true)", scanner)
        self.assertIn("jobName.value = protocolName + ' scan'", scanner)

    def test_scanner_jobs_render_protocol_names_instead_of_numeric_ids(self):
        scanner = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        self.assertIn("getProtocolName(job.protocol)", scanner)
        self.assertIn("1: 'Modbus TCP'", scanner)
        self.assertIn("5: 'PROFINET'", scanner)

    def test_discovery_history_keeps_each_completed_result_selectable(self):
        discovery = (PROJECT_ROOT / "src/web/ui/discovery.html").read_text(encoding="utf-8")

        for token in (
            "completedDiscoveryResults",
            "selectedDiscoveryId",
            "showDiscoveryResults",
            "Show results",
            "selected-discovery-result",
        ):
            self.assertIn(token, discovery)


if __name__ == "__main__":
    unittest.main()
