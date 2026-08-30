import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"


class BasePluginTemplateMethodTests(unittest.TestCase):
    def test_base_owns_non_overridable_packet_template_and_independent_gates(self):
        header = (SRC / "protocols" / "base_plugin.h").read_text(encoding="utf-8")
        source = (SRC / "protocols" / "base_plugin.cpp").read_text(encoding="utf-8")
        self.assertIn("virtual bool doPacketAnalysis(const NetworkPacket& packet) final", header)
        self.assertIn("virtual void onPacket(const NetworkPacket& pkt, bool bypassAuthorization = false) final", header)
        self.assertIn("doPacketIDSAnalysisOfProtocol", header)
        self.assertIn("processDiscoveryOfProtocol", header)
        self.assertIn("isDiscoveryActive", header)
        self.assertIn("isIdsAnalysisEnabled", source)
        self.assertNotIn("processDiscoveryPacketWhenIdsDisabled", header)
        self.assertNotIn("processDiscoveryPacketWhenIdsDisabled", source)

    def test_protocols_implement_hooks_instead_of_reimplementing_template(self):
        for name in ("modbus_tcp", "s7", "opcua", "ethernetip", "profinet"):
            header = (SRC / "protocols" / f"{name}_plugin.h").read_text(encoding="utf-8")
            source = (SRC / "protocols" / f"{name}_plugin.cpp").read_text(encoding="utf-8")
            self.assertIn("doPacketIDSAnalysisOfProtocol", header, name)
            self.assertIn("doPacketIDSAnalysisOfProtocol", source, name)
            self.assertNotIn("doPacketAnalysis(const NetworkPacket", header, name)

    def test_sandbox_delegates_hooks_without_bypassing_base_template(self):
        header = (SRC / "sandbox" / "plugin_sandbox.h").read_text(encoding="utf-8")
        source = (SRC / "sandbox" / "plugin_sandbox.cpp").read_text(encoding="utf-8")
        self.assertNotIn("doPacketAnalysis(const NetworkPacket", header)
        self.assertNotIn("doPacketAnalysis(const NetworkPacket", source)
        self.assertIn("doPacketIDSAnalysisOfProtocol", header)
        self.assertIn("processDiscoveryOfProtocol", header)

    def test_general_ids_remains_in_central_dispatcher(self):
        source = (SRC / "main.cpp").read_text(encoding="utf-8")
        self.assertEqual(source.count("ids.onPacket(pkt)"), 1)


if __name__ == "__main__":
    unittest.main()
