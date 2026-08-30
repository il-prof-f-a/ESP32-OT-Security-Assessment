import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class L2IngressContractTests(unittest.TestCase):
    def setUp(self):
        self.source = (PROJECT_ROOT / "src" / "network" / "eth_l2_adapter.cpp").read_text(
            encoding="utf-8"
        )
        self.header = (PROJECT_ROOT / "src" / "network" / "eth_l2_adapter.h").read_text(
            encoding="utf-8"
        )

    def test_shared_frame_helper_is_used_by_all_ingress_paths(self):
        self.assertIn("void dispatchFrameToEngine(const uint8_t* buffer, uint32_t length)", self.header)
        self.assertGreaterEqual(self.source.count("dispatchFrameToEngine("), 4)
        self.assertIn("dispatchFrameToEngine(frame, static_cast<uint32_t>(n))", self.source)

    def test_p4_non_tap_frames_are_observed_before_netif_ownership(self):
        callback = self.source.split("esp_err_t EthL2Adapter::l2tapInputTrampoline", 1)[1]
        self.assertIn("if (filtered_length == 0)", callback)
        self.assertIn("self->dispatchFrameToEngine(buffer, static_cast<uint32_t>(filtered_length))", callback)
        self.assertIn("esp_netif_receive(self->netif_, buffer, filtered_length, nullptr)", callback)

    def test_helper_parses_complete_ethernet_header_and_copies_payload(self):
        helper = self.source.split("void EthL2Adapter::dispatchFrameToEngine", 1)[1]
        self.assertIn("length < sizeof(EthHdr)", helper)
        self.assertIn("eng_->ingestL2(eh->src, eh->dst, et", helper)


if __name__ == "__main__":
    unittest.main()
