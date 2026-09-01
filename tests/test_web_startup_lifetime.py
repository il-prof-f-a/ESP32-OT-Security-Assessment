import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class WebStartupLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.header = (PROJECT_ROOT / "src/web/web_server_task.h").read_text(
            encoding="utf-8"
        )
        self.task = (PROJECT_ROOT / "src/web/web_server_task.cpp").read_text(
            encoding="utf-8"
        )
        self.server = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(
            encoding="utf-8"
        )
        self.server_header = (PROJECT_ROOT / "src/web/web_server.h").read_text(
            encoding="utf-8"
        )

    def test_start_context_is_heap_owned_and_has_shared_completion_state(self):
        self.assertIn("std::atomic<bool> success", self.header)
        self.assertIn("std::atomic<unsigned> references", self.header)
        self.assertIn("web_server_task_release_args", self.header)
        self.assertNotIn("volatile bool*  success", self.header)
        self.assertNotIn("volatile bool success_flag", self.server)
        self.assertIn("new (raw_args) WebTaskArgs", self.server)

    def test_worker_releases_context_only_after_server_task_finishes(self):
        self.assertIn("web_server_task_release_args(a);", self.task)
        self.assertIn("web_server_task_release_args(args);", self.server)
        self.assertIn("vSemaphoreDelete(args->started)", self.task)
        startup = self.server[self.server.index("bool WebServer::startWithTask"):]
        self.assertNotIn("vSemaphoreDelete(started);", startup[startup.index("bool success"):])
        self.assertIn("a->success.store(true", self.task)

    def test_startup_gate_prevents_duplicate_inflight_start(self):
        self.assertIn("startup_task_active_", self.server_header)
        self.assertIn("compare_exchange_strong", self.server)
        self.assertIn("startTaskFinished", self.server_header)
        self.assertIn("startTaskFinished()", self.task)

    def test_start_checks_the_handle_for_the_selected_transport(self):
        self.assertIn("active_transport_handle", self.server)
        self.assertIn("https_server_", self.server)
        self.assertIn("http_", self.server)


if __name__ == "__main__":
    unittest.main()
