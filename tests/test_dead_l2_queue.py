import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DeadL2QueueTests(unittest.TestCase):
    def setUp(self):
        self.main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.header = (
            PROJECT_ROOT / "src/network/ethernet_manager.h"
        ).read_text(encoding="utf-8")
        self.ethernet = (
            PROJECT_ROOT / "src/network/ethernet_manager.cpp"
        ).read_text(encoding="utf-8")

    def test_dead_l2_queue_symbols_and_allocation_are_removed(self):
        for source in (self.main, self.header, self.ethernet):
            self.assertNotIn("l2_snap_t", source)
            self.assertNotIn("g_l2_queue_global", source)
        self.assertNotIn("xQueueCreate(32", self.main)
        self.assertNotIn("configASSERT(l2_queue", self.main)

    def test_active_receive_path_remains_present(self):
        self.assertIn("EthernetManager::input_trampoline", self.ethernet)
        self.assertIn("esp_netif_receive", self.ethernet)
        self.assertIn("registerPacketCallback", self.main)


if __name__ == "__main__":
    unittest.main()
