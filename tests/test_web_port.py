import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class WebPortPropagationTests(unittest.TestCase):
    def setUp(self):
        self.server = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(
            encoding="utf-8"
        )
        self.header = (PROJECT_ROOT / "src/web/web_server.h").read_text(
            encoding="utf-8"
        )
        self.controller = (
            PROJECT_ROOT / "src/network/management_interface_controller.cpp"
        ).read_text(encoding="utf-8")

    def test_management_controller_uses_transport_default(self):
        self.assertIn("defaultManagementPort()", self.header)
        self.assertIn("web_.startWithTask(WebServer::defaultManagementPort()", self.controller)
        self.assertNotIn("web_.startWithTask(443", self.controller)

    def test_start_path_preserves_requested_port_for_both_transports(self):
        start = self.server.split("bool WebServer::startOnInterface", 1)[1].split(
            "bool WebServer::connectToWiFi", 1
        )[0]
        self.assertIn("cfg.server_port = port;", start)
        self.assertIn("https_conf.httpd.server_port = port;", start)
        self.assertNotIn("cfg.server_port = 80;", start)
        self.assertNotIn("https_conf.httpd.server_port = 443", start)

    def test_start_events_and_messages_report_the_effective_port(self):
        start = self.server.split("bool WebServer::startOnInterface", 1)[1].split(
            "bool WebServer::connectToWiFi", 1
        )[0]
        self.assertIn('\\"port\\":%u', start)
        self.assertIn("HTTP server started on port %u", start)
        self.assertIn("HTTPS server started on port %u", start)


if __name__ == "__main__":
    unittest.main()
