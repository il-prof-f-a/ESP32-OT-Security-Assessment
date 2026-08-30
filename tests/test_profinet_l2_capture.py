import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ProfinetL2CaptureTests(unittest.TestCase):
    def test_p4_defaults_enable_esp_netif_l2_tap(self):
        for name in (
            "sdkconfig.esp32p4.defaults",
            "sdkconfig.guition-jc-esp32p4-m3-dev.defaults",
        ):
            text = (PROJECT_ROOT / name).read_text(encoding="utf-8")
            self.assertIn("CONFIG_ESP_NETIF_L2_TAP=y", text, name)

    def test_p4_capture_uses_l2_tap_without_replacing_netif_input_path(self):
        source = (PROJECT_ROOT / "src" / "network" / "eth_l2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("esp_vfs_l2tap_intf_register", source)
        self.assertIn("L2TAP_S_DEVICE_DRV_HNDL", source)
        self.assertIn("L2TAP_S_RCV_FILTER", source)
        self.assertIn("L2TAP_VFS_DEFAULT_PATH", source)
        self.assertIn("esp_eth_update_input_path", source)
        self.assertIn("CONFIG_IDF_TARGET_ESP32P4", source)

    def test_capture_task_dispatches_complete_ethernet_frames(self):
        source = (PROJECT_ROOT / "src" / "network" / "eth_l2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("ingestL2(eh->src, eh->dst, et", source)
        self.assertIn("read(tap_fd_", source)


if __name__ == "__main__":
    unittest.main()
