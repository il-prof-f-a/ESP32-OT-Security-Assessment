from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RuntimeLogWatchdogRemediationTests(unittest.TestCase):
    def test_persistent_reads_use_async_storage_contract(self):
        source = (PROJECT_ROOT / "src/core/filesystem_task_delegate.cpp").read_text(encoding="utf-8")
        read_sync = source.split("bool FilesystemTaskDelegate::readFileSync", 1)[1].split(
            "bool FilesystemTaskDelegate::writeFileSync", 1
        )[0]
        internal_read = source.split("bool FilesystemTaskDelegate::readFileInternal", 1)[1].split(
            "// ======================= STREAMING FILE ACCESS", 1
        )[0]

        self.assertIn("AsyncStorage::Global::readFile", read_sync)
        self.assertNotIn("CRITICAL: Cannot allocate PSRAM", internal_read)
        self.assertNotIn("CRITICAL: Cannot clear psram_string", internal_read)

    def test_log_ring_tracks_drops_without_recursive_enqueue(self):
        source = (PROJECT_ROOT / "src/core/logging_system.cpp").read_text(encoding="utf-8")
        enqueue = source.split("void Logger::enqueue", 1)[1].split(
            "void Logger::writerTaskThunk", 1
        )[0]

        self.assertIn("dropped_messages_", enqueue)
        self.assertEqual(enqueue.count("xRingbufferSend("), 1)
        self.assertIn("startupRingBytes", source)

    def test_streaming_reports_chunk_progress_and_finishes_once(self):
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        tail = source.split("esp_err_t WebServer::h_logs_get", 1)[1].split(
            "esp_err_t WebServer::h_logs_download", 1
        )[0]
        download = source.split("esp_err_t WebServer::h_logs_download", 1)[1].split(
            "// Fuzzing API implementations", 1
        )[0]

        self.assertIn("httpdMonitorNoteProgress", source)
        self.assertIn("send_psram_descriptor_chunk", tail)
        self.assertIn("send_psram_descriptor_chunk", download)
        self.assertEqual(tail.count("httpd_resp_send_chunk(req, nullptr, 0)"), 1)
        self.assertEqual(download.count("httpd_resp_send_chunk(req, nullptr, 0)"), 1)

    def test_watchdog_api_identifies_persisted_effective_boot_configuration(self):
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        handler = source.split("esp_err_t WebServer::h_watchdog_config_get", 1)[1].split(
            "esp_err_t WebServer::h_watchdog_config_post", 1
        )[0]

        self.assertIn("configuration_source", handler)
        self.assertIn("effective_timeout_seconds", handler)
        self.assertIn("restart_required", handler)
        self.assertIn("configuration_pending_restart", handler)
        self.assertIn("MainTaskWatchdog::recordBootConfiguration", main)
        self.assertIn("bootEffectiveTimeoutSeconds", handler)


if __name__ == "__main__":
    unittest.main()
