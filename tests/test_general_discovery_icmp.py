from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GeneralDiscoveryIcmpContractTests(unittest.TestCase):
    def test_general_discovery_ping_mode_uses_esp_ping_and_ethernet_binding(self):
        source = (PROJECT_ROOT / "src/protocols/base_plugin.cpp").read_text(encoding="utf-8")
        icmp_source = (PROJECT_ROOT / "src/network/icmp_ping.cpp").read_text(encoding="utf-8")
        self.assertIn('#include "ping/ping_sock.h"', icmp_source)
        self.assertIn("esp_ping_new_session", icmp_source)
        self.assertIn("ESP_PING_PROF_TIMEGAP", icmp_source)
        self.assertIn("esp_netif_get_netif_impl_index", icmp_source)
        self.assertIn('"icmp_ping"', source)

        ping_section = source.split("// Ping mode uses real ICMP", 1)[1].split(
            "        size_t job_index = 0;", 1
        )[0]
        self.assertNotIn("job.port = ping_tcp_port", ping_section)

    def test_network_ping_endpoint_does_not_probe_tcp_port_80(self):
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        endpoint = source.split("esp_err_t WebServer::h_network_ping", 1)[1].split(
            "esp_err_t WebServer::h_network_status", 1
        )[0]
        self.assertIn("IcmpPing::probe", endpoint)
        self.assertNotIn("sa.sin_port = htons(80)", endpoint)


if __name__ == "__main__":
    unittest.main()
