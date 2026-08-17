from pathlib import Path
import json
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BuildIntegrationTests(unittest.TestCase):
    def test_public_build_output_is_isolated_from_the_private_repository(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")

        self.assertIn("/.platformio/build/ESP32-OT-Security-Assessment", platformio)
        self.assertNotIn("/.platformio/build/tesi.embedded-security-device", platformio)

    def test_project_version_does_not_depend_on_git_history(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        version_index = cmake.index('set(PROJECT_VER "0.1.0-experimental")')
        project_index = cmake.index("\nproject(")
        self.assertLess(version_index, project_index)
        self.assertIn("project(esp32_ot_security_assessment)", cmake)

    def test_every_platformio_environment_runs_provisioning_first(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        sections = re.split(r"(?=^\[env:)", platformio, flags=re.MULTILINE)[1:]
        self.assertEqual(len(sections), 3)
        for section in sections:
            self.assertIn("pre:scripts/platformio_provision.py", section)

        self.assertIn("[env:waveshare-esp32p4-eth]", platformio)

    def test_platformio_p4_environment_uses_a_local_waveshare_board_definition(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        board = json.loads(
            (PROJECT_ROOT / "boards/waveshare-esp32p4-eth.json").read_text(
                encoding="utf-8"
            )
        )

        p4 = platformio.split("[env:waveshare-esp32p4-eth]", 1)[1].split(
            "[env:", 1
        )[0]
        self.assertIn("board = waveshare-esp32p4-eth", p4)
        self.assertIn(
            "https://github.com/pioarduino/platform-espressif32.git#4cf6992078a95fb9ab8352fe7811f4eec0d359af",
            p4,
        )
        self.assertIn("pre:scripts/fix_esp32p4_toolchain_path.py", p4)
        self.assertIn("board_build.sdkconfig_defaults = sdkconfig.esp32p4.defaults", p4)
        self.assertEqual(board["build"]["mcu"], "esp32p4")
        self.assertIn("espidf", board["frameworks"])
        self.assertEqual(board["vendor"], "Waveshare")

    def test_p4_emac_configuration_does_not_use_broken_designated_initializer_macro(self):
        source = (PROJECT_ROOT / "src/network/ethernet_manager.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("#if CONFIG_IDF_TARGET_ESP32P4", source)
        self.assertIn("eth_esp32_emac_config_t emac_cfg = {};", source)
        self.assertIn("emac_cfg.emac_dataif_gpio.rmii.tx_en_num", source)
        self.assertIn("emac_cfg.clock_config_out_in.rmii.clock_mode", source)

    def test_p4_toolchain_fallback_is_installed_before_lookup(self):
        script = (PROJECT_ROOT / "scripts/fix_esp32p4_toolchain_path.py").read_text(
            encoding="utf-8"
        )

        self.assertIn('"toolchain-riscv32-esp"', script)
        self.assertLess(
            script.rindex("_patch_missing_idf_package_dirs()"),
            script.rindex("_fix_riscv_toolchain_layout()"),
        )

    def test_p4_profile_selects_the_pre_v3_silicon_family(self):
        defaults = (PROJECT_ROOT / "sdkconfig.esp32p4.defaults").read_text(
            encoding="utf-8"
        )

        self.assertIn("CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y", defaults)

    def test_network_presence_tracker_keeps_required_arithmetic_operators(self):
        source = (PROJECT_ROOT / "src/assessment/network_presence_tracker.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "double final_score = (continuity_score * config_.continuity_weight) +",
            source,
        )
        self.assertIn(
            "size_t expected_size = sizeof(PersistentStorageHeader) +",
            source,
        )

        opcua_vulnerability = (
            PROJECT_ROOT / "src/protocols/opcua_vulnerability_tests.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'PSRAMUtils::createPSRAMString("Endpoint allows anonymous: ") +',
            opcua_vulnerability,
        )
        self.assertIn(
            'psram_string key = cert.subject_common_name + PSRAMUtils::createPSRAMString(":") +',
            opcua_vulnerability,
        )

        opcua_plugin = (PROJECT_ROOT / "src/protocols/opcua_plugin.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '\\"server_url\\":\\\"" +',
            opcua_plugin,
        )

        security = (PROJECT_ROOT / "src/security/security_manager.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('masked_hash = std::string(entry.hash.c_str(), 8) + "***" +', security)

    def test_target_transport_policy_is_explicit(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        lilygo = platformio.split("[env:t-poe-pro]", 1)[1].split("[env:", 1)[0]
        esp32_s3 = platformio.split("[env:esp32-s3-eth]", 1)[1]

        self.assertIn("-DESP32_OT_WEB_HTTP_ONLY=1", lilygo)
        self.assertIn("-DESP32_OT_WEB_HTTP_ONLY=0", esp32_s3)
        self.assertIn('"-DESP32_OT_WEB_HTTP_ONLY=0"', cmake)

    def test_esp32_s3_board_metadata_matches_the_supported_waveshare_board(self):
        metadata = json.loads(
            (PROJECT_ROOT / "boards/esp32-s3-eth.json").read_text(encoding="utf-8")
        )

        self.assertEqual(metadata["name"], "Waveshare ESP32-S3-ETH")
        self.assertEqual(metadata["vendor"], "Waveshare")
        self.assertEqual(metadata["url"], "https://www.waveshare.com/esp32-s3-eth.htm")

    def test_public_build_does_not_hardcode_a_local_serial_port(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")

        self.assertNotRegex(platformio, r"(?m)^\s*(?:upload|monitor)_port\s*=")

    def test_direct_cmake_p4_pin_mapping_matches_the_supported_board(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('"-DETH_PHY_RST_GPIO=51"', cmake)
        self.assertIn('"-DETH_MDC_GPIO=31"', cmake)
        self.assertIn('"-DETH_MDIO_GPIO=52"', cmake)
        self.assertIn('"-DETH_RMII_CLK_GPIO=50"', cmake)

    def test_build_time_messages_and_root_configuration_are_english(self):
        generator = (PROJECT_ROOT / "scripts/convert_html_in_code.py").read_text(
            encoding="utf-8"
        )
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        partitions = (PROJECT_ROOT / "partitions.csv").read_text(encoding="utf-8")

        self.assertNotIn("Pulizia della directory", generator)
        self.assertNotIn("opzionale", cmake)
        self.assertNotIn("maggiorato", partitions)

    def test_host_tests_are_wired_into_github_actions(self):
        workflow = (
            PROJECT_ROOT / ".github/workflows/host-tests.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("submodules: recursive", workflow)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py" -v', workflow)

    def test_target_specific_idf_lockfile_is_local_build_state(self):
        gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

        self.assertRegex(gitignore, r"(?m)^/dependencies\.lock$")

    def test_windows_paths_with_spaces_do_not_break_prefix_map_flags(self):
        defaults = (
            "sdkconfig.defaults",
            "sdkconfig.esp32s3eth.defaults",
            "sdkconfig.esp32p4.defaults",
        )
        for filename in defaults:
            content = (PROJECT_ROOT / filename).read_text(encoding="utf-8")
            self.assertIn("CONFIG_COMPILER_HIDE_PATHS_MACROS=n", content)
            self.assertNotIn("CONFIG_COMPILER_HIDE_PATHS_MACROS=y", content)

    def test_native_p4_profile_uses_the_board_flash_capacity(self):
        defaults = (PROJECT_ROOT / "sdkconfig.esp32p4.defaults").read_text(encoding="utf-8")
        gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

        self.assertIn("CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y", defaults)
        self.assertRegex(gitignore, r"(?m)^/sdkconfig$")

    def test_native_p4_profile_uses_current_esp_idf_kconfig_names(self):
        defaults = (PROJECT_ROOT / "sdkconfig.esp32p4.defaults").read_text(encoding="utf-8")

        self.assertIn("CONFIG_LWIP_SO_RCVBUF=y", defaults)
        self.assertIn("CONFIG_LWIP_TCP_SND_BUF_DEFAULT=8192", defaults)
        self.assertIn("CONFIG_LWIP_TCP_WND_DEFAULT=8192", defaults)
        self.assertIn("CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y", defaults)
        for obsolete_symbol in (
            "CONFIG_ESPTOOLPY_FLASHSIZE_DETECT",
            "CONFIG_LWIP_THREAD_LOCAL_STORAGE_INDEX",
            "CONFIG_LWIP_PBUF_POOL_BUFSIZE",
            "CONFIG_LWIP_PBUF_POOL_SIZE",
            "CONFIG_ETH_ENABLE_PROMISCUOUS",
            "CONFIG_FREERTOS_CHECK_STACKOVERFLOW=",
        ):
            self.assertNotIn(obsolete_symbol, defaults)

    def test_wifi_implementation_has_a_non_wifi_target_stub(self):
        wifi = (PROJECT_ROOT / "src/network/wifi_manager.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn('#include "soc/soc_caps.h"', wifi)
        self.assertIn("#if SOC_WIFI_SUPPORTED", wifi)
        self.assertIn('LOG_INFO(TAG, "Wi-Fi is unavailable on this target")', wifi)

    def test_no_psram_diagnostic_does_not_shadow_runtime_memory_state(self):
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")

        self.assertIn("size_t initial_internal_free =", main)
        self.assertEqual(main.count("size_t internal_free ="), 2)

    def test_littlefs_seed_directory_exists_for_native_builds(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertTrue((PROJECT_ROOT / "data/.gitkeep").is_file())
        self.assertIn("littlefs_create_partition_image(storage data FLASH_IN_PROJECT)", cmake)

    def test_firmware_uses_only_the_generated_secret_header(self):
        configuration = (PROJECT_ROOT / "src/core/configuration_manager.cpp").read_text(encoding="utf-8")
        wifi = (PROJECT_ROOT / "src/network/wifi_manager.cpp").read_text(encoding="utf-8")
        web = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")

        for source in (configuration, wifi, web):
            self.assertIn('#include "esp32_ot_generated_credentials.h"', source)
        self.assertNotIn('#include "tls_cert.h"', web)
        self.assertNotIn("_binary_config_json_start", configuration)
        self.assertNotRegex(wifi, r'startAP\(\s*"[^"]+"\s*,\s*"[^"]+"\s*\)')

    def test_http_only_target_has_a_real_plain_http_start_path(self):
        web = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        web_header = (PROJECT_ROOT / "src/web/web_server.h").read_text(encoding="utf-8")

        self.assertIn("#if ESP32_OT_WEB_HTTP_ONLY", web)
        self.assertIn("httpd_start(&http_, &cfg)", web)
        self.assertIn("httpd_handle_t active_server", web_header)
        self.assertIn("httpd_register_uri_handler(active_server", web)

    def test_obsolete_embedded_secret_component_is_not_linked(self):
        component = (PROJECT_ROOT / "src/CMakeLists.txt").read_text(encoding="utf-8")
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")

        self.assertNotIn("config_blob", component)
        self.assertNotIn("convert_txt_in.S.py", platformio)
        self.assertFalse((PROJECT_ROOT / "scripts/convert_txt_in.S.py").exists())

    def test_platformio_wrapper_adds_generated_include_directory(self):
        wrapper = (PROJECT_ROOT / "scripts/platformio_provision.py").read_text(encoding="utf-8")

        self.assertIn("provision(", wrapper)
        self.assertIn("CPPPATH", wrapper)
        self.assertNotIn("password", wrapper.lower())

    def test_native_idf_build_provisions_credentials_and_adds_generated_include(self):
        root_cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        component_cmake = (PROJECT_ROOT / "src/CMakeLists.txt").read_text(encoding="utf-8")
        psram_allocator = (PROJECT_ROOT / "src/core/psram_allocator.h").read_text(encoding="utf-8")
        task_audit = (PROJECT_ROOT / "src/core/task_audit.c").read_text(encoding="utf-8")

        self.assertIn('set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/src")', root_cmake)
        self.assertIn('set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")', root_cmake)
        self.assertLess(
            root_cmake.index('set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")'),
            root_cmake.index("include($ENV{IDF_PATH}/tools/cmake/project.cmake)"),
        )
        self.assertIn("scripts/credential_provisioning.py", root_cmake)
        self.assertIn("--build-dir", root_cmake)
        self.assertIn("ESP32_OT_GENERATED_INCLUDE_DIR", root_cmake)
        self.assertIn("${ESP32_OT_GENERATED_INCLUDE_DIR}", component_cmake)
        self.assertRegex(component_cmake, r"(?m)^\s+esp_psram\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+efuse\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+esp_littlefs\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+esp_http_client\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+app_update\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+mqtt\s*$")
        self.assertRegex(component_cmake, r"(?m)^\s+espcoredump\s*$")
        self.assertIn('#include "esp_memory_utils.h"', psram_allocator)
        self.assertIn('#include "esp_memory_utils.h"', task_audit)

        filesystem_delegate = (
            PROJECT_ROOT / "src/core/filesystem_task_delegate.cpp"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            "memset(&fileio_resp, 0, sizeof(fileio_resp))", filesystem_delegate
        )
        self.assertIn("sizeof(FileIOResponse*)", filesystem_delegate)


if __name__ == "__main__":
    unittest.main()
