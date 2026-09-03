import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / "src/web/web_server.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")


class SingleSessionTokenContractTests(unittest.TestCase):
    def test_single_volatile_session_and_ten_minute_idle_timeout_are_declared(self):
        self.assertRegex(HEADER, r"kSessionIdleTimeoutMs\s*=\s*600000")
        self.assertIn("active_session_token_", HEADER)
        self.assertIn("active_session_last_activity_ms_", HEADER)
        self.assertIn("session_mutex_", HEADER)

    def test_authentication_uses_active_session_not_length_or_prefix(self):
        self.assertIn("isActiveSessionToken", SOURCE)
        self.assertNotIn("if (is_dev_token || strlen(sid) >= 16)", SOURCE)
        self.assertNotIn("if (is_dev_token || strlen(token) >= 16)", SOURCE)

    def test_login_replaces_and_logout_invalidates_the_active_token(self):
        login = SOURCE[SOURCE.index("esp_err_t WebServer::h_login_post") : SOURCE.index("esp_err_t WebServer::h_logout")]
        logout = SOURCE[SOURCE.index("esp_err_t WebServer::h_logout") : SOURCE.index("bool WebServer::check_api_auth")]
        self.assertRegex(login, r"replaceActiveSession|createActiveSession")
        self.assertIn("invalidateActiveSession", logout)

    def test_shutdown_invalidates_the_active_token(self):
        shutdown = SOURCE[SOURCE.index("void WebServer::shutdown()") : SOURCE.index("bool WebServer::startHTTPS")]
        self.assertIn('invalidateActiveSession("server_shutdown")', shutdown)

    def test_idle_expiry_is_checked_before_session_is_touched(self):
        check = SOURCE[SOURCE.index("bool WebServer::check_session") : SOURCE.index("esp_err_t WebServer::h_login_get")]
        validator = SOURCE[SOURCE.index("bool WebServer::isActiveSessionToken") : SOURCE.index("void WebServer::replaceActiveSession")]
        self.assertIn("kSessionIdleTimeoutMs", validator)
        self.assertIn("active_session_last_activity_ms_", validator)
        self.assertIn("isActiveSessionToken(sid)", check)

    def test_login_keeps_sid_transport_and_does_not_persist_session(self):
        self.assertIn("?sid=", SOURCE)
        self.assertNotIn("saveConfigJSON(tok_buf)", SOURCE)


if __name__ == "__main__":
    unittest.main()
