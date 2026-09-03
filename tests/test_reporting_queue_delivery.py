import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "src/core/reporting_config_loader.cpp"
ENGINE = ROOT / "src/core/reporting_engine.cpp"
QUEUE = ROOT / "src/core/psram_reliable_queue.cpp"


class ReportingQueueDeliveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = LOADER.read_text(encoding="utf-8")
        cls.engine = ENGINE.read_text(encoding="utf-8")
        cls.queue = QUEUE.read_text(encoding="utf-8")

    def test_enabled_webhook_uses_the_real_http_reporter(self):
        """An enabled webhook must not install a callback that always fails."""
        self.assertIn('#include "../reporters/webhook_reporter.h"', self.loader)
        self.assertIn("WebhookReporter", self.loader)
        self.assertIn("webhook_reporter_ptr->post", self.loader)
        self.assertNotIn("Would POST to", self.loader)
        self.assertNotIn("Disabled for now - return true when implemented", self.loader)
        self.assertNotIn("Webhook channel enabled but URL is empty", self.loader)

    def test_unavailable_channels_are_deferred_not_counted_as_delivery_failures(self):
        """Startup/reconfiguration must not poison durable events before a channel is ready."""
        self.assertIn("QueueDeliveryResult::DEFERRED", self.engine)
        self.assertIn("QueueDeliveryResult::DEFERRED", self.queue)
        self.assertNotIn("Event delivery deferred", self.queue)

    def test_retry_diagnostics_identify_the_destination_channel(self):
        self.assertIn("channel=%s", self.queue)


if __name__ == "__main__":
    unittest.main()
