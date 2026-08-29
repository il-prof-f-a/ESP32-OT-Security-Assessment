import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class OffensiveGateCoverageTests(unittest.TestCase):
    def test_fuzzing_engine_rechecks_gate_before_unsafe_send(self):
        source = (PROJECT_ROOT / "src" / "assessment" / "fuzzing_engine.cpp").read_text(encoding="utf-8")
        marker = "immediately before send"
        self.assertIn(marker, source)
        self.assertIn("!j.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())", source)

    def test_modbus_write_probe_requires_central_gate(self):
        source = (PROJECT_ROOT / "src" / "protocols" / "modbus_tcp_plugin.cpp").read_text(encoding="utf-8")
        self.assertIn("write_test_blocked", source)
        self.assertIn("sec_->isFuzzingAllowed()", source)

    def test_plugin_manager_injects_one_security_manager(self):
        source = (PROJECT_ROOT / "src" / "core" / "plugin_manager.cpp").read_text(encoding="utf-8")
        self.assertIn("plugin->setSecurityManager(sec_)", source)

    def test_active_protocol_paths_fail_closed_without_policy(self):
        for relative in (
            "src/protocols/ethernetip_plugin.cpp",
            "src/protocols/opcua_plugin.cpp",
            "src/protocols/profinet_plugin.cpp",
        ):
            source = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("blocked_by_offensive_policy", source, relative)
            self.assertIn("!sec_ || !sec_->isFuzzingAllowed()", source, relative)


if __name__ == "__main__":
    unittest.main()
