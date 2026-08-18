from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RuntimeProvisioningContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT_ROOT / relative).read_text(encoding="utf-8")

    def test_password_hasher_has_the_approved_public_api(self):
        header = self.read("src/security/password_hasher.h")
        implementation = self.read("src/security/password_hasher.cpp")

        self.assertIn("class PasswordHasher", header)
        self.assertIn("static bool validatePolicy", header)
        self.assertIn("static bool derive", header)
        self.assertIn("static bool verify", header)
        self.assertIn("static bool isSupportedHash", header)
        self.assertIn("100000", implementation)
        self.assertIn('"pbkdf2:', implementation)
        self.assertIn("esp_fill_random", implementation)

    def test_password_policy_is_explicit(self):
        implementation = self.read("src/security/password_hasher.cpp")

        self.assertIn("kMinimumPasswordBytes = 16", implementation)
        self.assertIn("kMaximumPasswordBytes = 128", implementation)
        for blocked in ("admin1234", "password", "changeme", "esp32-ot-setup"):
            self.assertIn(blocked, implementation.lower())

    def test_security_manager_never_creates_or_logs_a_temporary_admin_password(self):
        header = self.read("src/security/security_manager.h")
        implementation = self.read("src/security/security_manager.cpp")

        for forbidden in (
            "generateTemporaryPassword",
            "publishTemporaryAdminCredential",
            "Generated temporary credential",
        ):
            self.assertNotIn(forbidden, header)
            self.assertNotIn(forbidden, implementation)
        self.assertIn("PasswordHasher::verify", implementation)
        self.assertIn("Missing or unsupported administrator password hash", implementation)

    def test_provisioning_types_define_state_and_submission(self):
        header = self.read("src/provisioning/provisioning_types.h")

        for state in (
            "UNPROVISIONED",
            "LEGACY_MIGRATION_REQUIRED",
            "READY",
            "CORRUPT",
        ):
            self.assertIn(state, header)
        self.assertIn("struct ProvisioningSubmission", header)

    def test_provisioning_store_writes_completion_marker_last(self):
        header = self.read("src/provisioning/provisioning_store.h")
        implementation = self.read("src/provisioning/provisioning_store.cpp")

        self.assertIn("ProvisioningState inspect", header)
        self.assertIn("bool migrateLegacyIfValid", header)
        self.assertIn("bool commit", header)
        self.assertIn("bool clearCompletionMarker", header)
        self.assertIn('nvs_open("provisioning"', implementation)
        self.assertIn('"schema_u16"', implementation)
        self.assertIn('"complete_u8"', implementation)
        self.assertIn('"config_crc_u32"', implementation)
        self.assertIn('"completed_at_u64"', implementation)
        self.assertLess(
            implementation.rindex('nvs_set_u32(handle, "config_crc_u32"'),
            implementation.rindex('nvs_set_u8(handle, "complete_u8", 1)'),
        )

    def test_setup_session_is_ephemeral_rate_limited_and_noncopyable(self):
        header = self.read("src/provisioning/setup_session.h")
        implementation = self.read("src/provisioning/setup_session.cpp")

        self.assertIn("SetupSession(const SetupSession&) = delete", header)
        self.assertIn("bool validateToken", header)
        self.assertIn("void consume", header)
        self.assertIn("void zeroize", header)
        self.assertIn("esp_fill_random", implementation)
        self.assertIn("15ULL * 60ULL", implementation)
        self.assertIn("5", implementation)
        self.assertIn("60ULL", implementation)

    def test_wifi_manager_has_no_build_time_setup_credentials(self):
        implementation = self.read("src/network/wifi_manager.cpp")

        self.assertNotIn("esp32_ot_generated_credentials.h", implementation)
        self.assertNotIn("kProvisioningApPassword", implementation)
        self.assertIn("apcfg.ap.max_connection = 1", implementation)
        self.assertIn("WIFI_AUTH_WPA2_PSK", implementation)

    def test_runtime_tls_identity_is_generated_and_persisted_on_device(self):
        header = self.read("src/provisioning/runtime_tls_credentials.h")
        implementation = self.read("src/provisioning/runtime_tls_credentials.cpp")

        for method in (
            "ensurePresent",
            "certificatePem",
            "privateKeyPem",
            "sha256Fingerprint",
        ):
            self.assertIn(method, header)
        self.assertIn("MBEDTLS_ECP_DP_SECP256R1", implementation)
        self.assertIn("mbedtls_ecp_gen_key", implementation)
        self.assertIn('"/data/certs/server.crt"', implementation)
        self.assertIn('"/data/certs/server.key"', implementation)
        self.assertIn('"/data/certs/server.crt.new"', implementation)
        self.assertIn('"/data/certs/server.key.new"', implementation)
        self.assertIn("fileRename", implementation)
        self.assertIn("esp_read_mac", implementation)

    def test_factory_reset_clears_marker_before_other_state(self):
        header = self.read("src/provisioning/provisioning_store.h")
        implementation = self.read("src/provisioning/provisioning_store.cpp")
        web_server = self.read("src/web/web_server.cpp")

        self.assertIn("bool factoryReset", header)
        reset_start = implementation.index("bool ProvisioningStore::factoryReset")
        reset_body = implementation[reset_start:]
        self.assertLess(
            reset_body.index("clearCompletionMarker"),
            reset_body.index('nvsEraseAll("security")'),
        )
        self.assertIn('deleteFile("/data/config/config.json")', reset_body)
        self.assertNotIn(
            'success = success && AsyncStorage::Global::nvsEraseAll("provisioning")',
            reset_body,
        )
        self.assertIn("tls_credentials_.clear()", web_server)
        self.assertIn("const bool tls_cleared", web_server)
        self.assertIn("esp_restart()", web_server)

    def test_operational_web_server_uses_runtime_tls_buffers(self):
        header = self.read("src/web/web_server.h")
        implementation = self.read("src/web/web_server.cpp")

        self.assertIn("RuntimeTlsCredentials", header)
        self.assertNotIn("esp32_ot_generated_credentials.h", implementation)
        self.assertNotIn("kServerPrivateKeyPem", implementation)
        self.assertIn("tls_credentials_.certificatePem()", implementation)
        self.assertIn("tls_credentials_.privateKeyPem()", implementation)

    def test_provisioning_server_exposes_only_the_setup_surface(self):
        implementation = self.read("src/web/provisioning_server.cpp")

        for route in (
            '"/"',
            '"/api/provisioning/status"',
            '"/api/provisioning/complete"',
        ):
            self.assertIn(route, implementation)
        self.assertEqual(implementation.count("httpd_register_uri_handler"), 3)
        self.assertIn("X-Setup-Token", implementation)
        self.assertIn("4096", implementation)
        self.assertIn("Cache-Control", implementation)
        self.assertIn("Content-Security-Policy", implementation)
        self.assertIn("PasswordHasher::derive", implementation)

    def test_startup_gate_precedes_operational_security_and_network_services(self):
        main = self.read("src/main.cpp")
        coordinator = self.read("src/provisioning/provisioning_coordinator.cpp")

        gate = main.index("ProvisioningCoordinator::continueOperationalBoot")
        self.assertLess(gate, main.index("SecurityManager sec"))
        self.assertLess(gate, main.index("ReportingEngine rep"))
        self.assertLess(gate, main.index("NetworkEngine net"))
        self.assertIn("BOOT_MODE=PROVISIONING", coordinator)
        self.assertIn("BOOT_MODE=OPERATIONAL", coordinator)
        self.assertIn("BOOT_MODE=LEGACY_MIGRATION", coordinator)
        self.assertIn("esp_task_wdt_reset", coordinator)


if __name__ == "__main__":
    unittest.main()
