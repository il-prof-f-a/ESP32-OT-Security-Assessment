import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src/web/ui/reporting.html"
CATALOG_DOC = ROOT / "docs/user-guide/reporting-filters.md"


class ReportingUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAGE.read_text(encoding="utf-8")

    def test_top_panels_are_collapsible_and_default_closed(self):
        self.assertRegex(self.html, r'<details[^>]+id="report-stream-panel"[^>]+')
        self.assertRegex(self.html, r'<details[^>]+id="queue-status-panel"[^>]+')
        self.assertIn('id="report-stream-panel"', self.html)
        self.assertIn('id="queue-status-panel"', self.html)
        self.assertIn('class="collapse-indicator"', self.html)

    def test_channels_use_tabs_and_keep_runtime_channel_names(self):
        self.assertIn('id="report-channel-tabs"', self.html)
        self.assertIn('role="tablist"', self.html)
        self.assertIn("mqtt", self.html)
        self.assertIn("webhook", self.html)
        self.assertIn("email", self.html)
        self.assertIn("serial", self.html)

    def test_channel_specific_configuration_contract(self):
        self.assertIn("renderChannelSpecificConfig", self.html)
        for field in (
            "mqtt_broker", "mqtt_port", "mqtt_client_id", "mqtt_topic_prefix",
            "mqtt_username", "mqtt_password", "mqtt_qos", "mqtt_retain",
            "mqtt_timeout_ms", "mqtt_reconnect_interval_ms",
            "email_smtp_server", "email_smtp_port", "email_username", "email_password",
            "email_from_address", "email_to_addresses", "email_subject_prefix",
            "email_use_ssl", "email_use_tls", "email_timeout_ms", "email_retry_attempts",
            "webhook_url", "webhook_headers", "webhook_timeout_ms",
        ):
            self.assertIn(field, self.html)
        self.assertIn("saveChannelConfiguration", self.html)
        self.assertIn("/api/report/endpoints", self.html)
        self.assertIn("reportingEndpointDraft", self.html)

    def test_file_and_gpio_are_dedicated_light_blue_links(self):
        self.assertIn("report-channel-tab-link", self.html)
        self.assertIn("/logging", self.html)
        self.assertIn("/gpio", self.html)
        self.assertIn("FILE", self.html)
        self.assertIn("GPIO", self.html)

    def test_endpoints_and_file_editor_are_hidden(self):
        self.assertRegex(self.html, r'id="reporting-endpoints-panel"[^>]*hidden')
        self.assertIn("display:none", self.html)
        self.assertIn("File settings are intentionally owned by /logging", self.html)

    def test_explicit_save_feedback_and_filter_precedence_are_present(self):
        self.assertIn('id="report-save-status"', self.html)
        self.assertIn("Save Channel", self.html)
        self.assertIn("Save Filters", self.html)
        self.assertRegex(self.html, r"(?i)include patterns are evaluated first")
        self.assertRegex(self.html, r"(?i)exclude patterns veto")

    def test_autocomplete_catalog_is_wired_for_filter_inputs(self):
        self.assertIn("REPORTING_PATTERN_CATALOG", self.html)
        self.assertIn("datalist", self.html)
        self.assertIn("reporting-pattern-suggestions", self.html)
        self.assertTrue(CATALOG_DOC.exists(), "the user-facing filter catalog must be documented")
        doc = CATALOG_DOC.read_text(encoding="utf-8")
        for token in ("MAIN", "NetworkPresenceTracker", "VULNERABILITY_SCANNER", "intrusion_detected"):
            self.assertIn(token, doc)

    def test_filter_values_are_rendered_as_text(self):
        # Filter patterns must not be interpolated as raw HTML.
        self.assertIn("value.textContent = pattern", self.html)
        self.assertNotRegex(self.html, r'<span>\$\{pattern\}</span>')


if __name__ == "__main__":
    unittest.main()
