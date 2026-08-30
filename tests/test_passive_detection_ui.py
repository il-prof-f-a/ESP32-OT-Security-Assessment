from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src/web/ui/passive_detection.html"


class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.handlers = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        self.handlers.extend(value for key, value in attrs.items() if key.startswith("on"))


class PassiveDetectionUiTests(unittest.TestCase):
    def test_shared_page_has_unique_ids_and_scoped_actions(self):
        html = PAGE.read_text(encoding="utf-8")
        markup = Markup()
        markup.feed(html.split("<script>")[0])
        self.assertEqual([key for key, count in Counter(markup.ids).items() if count > 1], [])
        for panel in ("panel-ids", "panel-network-presence", "panel-signatures"):
            self.assertIn(panel, markup.ids)
        for action in markup.handlers:
            self.assertRegex(action, r"^PassivePanels\.(ids|presence|signatures)\.")
        self.assertNotRegex(html, r"<(?:script|link)[^>]+(?:src|href)=['\"]https?://")
        self.assertNotIn("<iframe", html)

    def test_existing_editors_actions_and_protocol_settings_are_retained(self):
        html = PAGE.read_text(encoding="utf-8")
        for endpoint in (
            "/api/whitelist", "/api/allowlist", "/api/config/update", "/api/ids/stats",
            "/api/network-presence/learned", "/api/network-presence/make-permanent",
            "/api/network-presence/remove", "/api/network-presence/clear",
            "/api/ids/presence/config", "/api/ids/presence/stats", "/api/ids/presence/devices",
            "/api/ids/presence/promote", "/api/ids/presence/demote", "/api/ids/presence/clear",
            "/api/signatures/list", "/api/signatures/stats", "/api/signatures/save",
            "/api/signatures/upload", "/api/signatures/download", "/api/signatures/clear",
            "/api/signatures/reload",
        ):
            self.assertIn(endpoint, html)
        for field in ("editCVE", "editName", "editProtocol", "editBytes", "editFunctionCode", "editDescription", "editReferences", "jsonEditor"):
            self.assertIn(f'id="signatures-{field}"', html)
        for protocol in ("modbus", "s7", "profinet", "ethernetip"):
            self.assertIn(f"ids.protocol_specific.{protocol}.", html)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for behavioral UI tests")
    def test_javascript_behavior(self):
        result = subprocess.run(
            [shutil.which("node"), str(ROOT / "tests/passive_detection_behavior.test.js")],
            cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passive detection behavioral checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
