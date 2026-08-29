from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ModbusJsonContractTests(unittest.TestCase):
    def test_modbus_vulnerability_scan_uses_structured_report_contract(self):
        source = (PROJECT_ROOT / "src/protocols/modbus_tcp_plugin.cpp").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("=== Modbus TCP Vulnerability Scan Report ===", source)
        self.assertNotIn("legacyDoVulnerabilityScan", source)

        scan = source.split("bool ModbusTCPPlugin::doVulnerabilityScanPSRAM", 1)[1]
        for key in (
            '"scan"',
            '"asset"',
            '"scan_types_requested"',
            '"findings"',
            '"risk_assessment"',
            '"summary"',
        ):
            self.assertIn(key, scan)

    def test_modbus_scan_result_endpoint_declares_json_content_type(self):
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        handler = source.split("esp_err_t WebServer::h_scan_result_get", 1)[1]
        self.assertIn('"application/json"', handler)


if __name__ == "__main__":
    unittest.main()
