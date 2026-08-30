from pathlib import Path
import json
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BuildIntegrationTests(unittest.TestCase):
    def test_platformio_has_no_malformed_standalone_flag(self):
        source = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        self.assertNotIn("- =1", source)

    def test_public_build_output_is_isolated_from_the_private_repository(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")

        self.assertIn("/.platformio/build/ESP32-OT-Security-Assessment", platformio)
        self.assertNotIn("/.platformio/build/tesi.embedded-security-device", platformio)

    def test_project_version_does_not_depend_on_git_history(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        version_index = cmake.index('file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" PROJECT_VER')
        project_index = cmake.index("\nproject(")
        self.assertLess(version_index, project_index)
        self.assertIn("project(esp32_ot_security_assessment)", cmake)
        version = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")

    def test_detailed_report_device_id_uses_board_neutral_base_mac(self):
        source = (PROJECT_ROOT / "src/core/detailed_report_builder.cpp").read_text(
            encoding="utf-8"
        )
        function = source.split("psram_string DetailedReportBuilderBase::getDeviceId()", 1)[1].split(
            "void DetailedReportBuilderBase::setDeviceId", 1
        )[0]

        self.assertIn("esp_efuse_mac_get_default", function)
        self.assertNotIn("ESP_MAC_WIFI_STA", function)

    def test_file_reporter_serializes_rotation_with_async_storage(self):
        source = (PROJECT_ROOT / "src/reporters/file_reporter.cpp").read_text(
            encoding="utf-8"
        )
        rotation = source.split("bool FileReporter::rotateIfNeeded", 1)[1].split(
            "bool FileReporter::init", 1
        )[0]

        self.assertIn("AsyncStorage::Global::fileSize", rotation)
        self.assertIn("AsyncStorage::Global::deleteFile", rotation)
        self.assertIn("AsyncStorage::Global::fileRename", rotation)
        self.assertNotIn("FilesystemTaskDelegate", source)
        self.assertNotIn("isCurrentTaskOnPSRAMStack", source)

    def test_every_platformio_environment_generates_public_build_assets_first(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        sections = re.split(r"(?=^\[env:)", platformio, flags=re.MULTILINE)[1:]
        self.assertEqual(len(sections), 4)
        for section in sections:
            self.assertIn("pre:scripts/platformio_build_assets.py", section)
            self.assertNotIn("platformio_provision.py", section)

        self.assertIn("[env:waveshare-esp32p4-eth]", platformio)
        self.assertIn("[env:guition-jc-esp32p4-m3-dev]", platformio)

    def test_every_target_declares_an_explicit_management_policy(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        expected = {
            "t-poe-pro": "ESP32_OT_MGMT_WIFI_ONLY",
            "esp32-s3-eth": "ESP32_OT_MGMT_WIFI_ONLY",
            "waveshare-esp32p4-eth": "ESP32_OT_MGMT_ETHERNET_ONLY",
            "guition-jc-esp32p4-m3-dev": "ESP32_OT_MGMT_WIFI_ONLY",
        }

        for environment, policy in expected.items():
            with self.subTest(environment=environment):
                section = platformio.split(f"[env:{environment}]", 1)[1].split(
                    "[env:", 1
                )[0]
                self.assertIn(f"-DESP32_OT_MGMT_POLICY={policy}", section)

        guition = platformio.split("[env:guition-jc-esp32p4-m3-dev]", 1)[1]
        self.assertIn("-DESP32_OT_WIFI_BACKEND_REMOTE=1", guition)
        self.assertIn("-DESP32_OT_WEB_HTTP_ONLY=0", guition)

    def test_guition_p4_environment_uses_a_dedicated_16mb_board_definition(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        metadata_path = PROJECT_ROOT / "boards/guition-jc-esp32p4-m3-dev.json"
        self.assertTrue(metadata_path.is_file())
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        guition = platformio.split("[env:guition-jc-esp32p4-m3-dev]", 1)[1]

        self.assertIn("board = guition-jc-esp32p4-m3-dev", guition)
        self.assertIn("board_build.flash_size = 16MB", guition)
        self.assertIn("-DBOARD_GUITION_JC_ESP32P4_M3_DEV", guition)
        self.assertEqual(metadata["upload"]["flash_size"], "16MB")
        self.assertEqual(metadata["vendor"], "GUITION")

    def test_discovery_page_has_dedicated_handler_and_legacy_offensive_aliases(self):
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        header = (PROJECT_ROOT / "src/web/web_server.h").read_text(encoding="utf-8")

        self.assertIn('uri="/discovery"', source)
        self.assertIn("h_page_discovery", source)
        self.assertIn("h_page_discovery", header)
        for alias in ("/vulnerability-scanner", "/fuzzing", "/scheduled-scans"):
            self.assertIn(f'uri="{alias}"', source)

    def test_direct_p4_build_requires_an_explicit_board_profile(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('set(ESP32_OT_BOARD "" CACHE STRING', cmake)
        self.assertIn('ESP32_OT_BOARD must be set for IDF_TARGET=esp32p4', cmake)
        self.assertIn('STREQUAL "waveshare-esp32p4-eth"', cmake)
        self.assertIn('STREQUAL "guition-jc-esp32p4-m3-dev"', cmake)

    def test_platformio_passes_each_p4_identity_to_cmake(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")
        for environment in (
            "waveshare-esp32p4-eth",
            "guition-jc-esp32p4-m3-dev",
        ):
            with self.subTest(environment=environment):
                section = platformio.split(f"[env:{environment}]", 1)[1].split(
                    "[env:", 1
                )[0]
                self.assertIn(
                    f"board_build.cmake_extra_args = -DESP32_OT_BOARD={environment}",
                    section,
                )

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

    def test_s7_szl_queries_use_standard_snap7_indexes(self):
        source = (PROJECT_ROOT / "src/protocols/s7_plugin.cpp").read_text(
            encoding="utf-8"
        )

        for szl_id in ("SZL_MODULE_IDENTIFICATION", "SZL_COMPONENT_IDENTIFICATION"):
            self.assertRegex(
                source,
                rf"readSZL\([^;]*{szl_id},\s*0x0000\s*,",
                msg=f"{szl_id} must use index 0 according to Snap7/Moka7",
            )
        self.assertNotRegex(
            source,
            r"readSZL\([^;]*SZL_(?:MODULE|COMPONENT)_IDENTIFICATION,\s*0x0001\s*,",
        )
        self.assertIn("SZL_CPU_CHARACTERISTICS, 0x0001", source)

    def test_s7_cpu_info_uses_fixed_offsets_and_rejects_heuristic_serials(self):
        source = (PROJECT_ROOT / "src/protocols/s7_plugin.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("copySZLField", source)
        self.assertIn("138, 24", source)   # Moka7/Snap7 record-only serial offset
        self.assertIn("172, 32", source)   # Moka7/Snap7 record-only module offset
        self.assertIn("104, 26", source)   # Moka7/Snap7 record-only copyright offset
        self.assertNotIn("extract_ascii_tokens", source)
        self.assertIn("looksLikeOrderCode", source)
        self.assertIn("Snap7/Moka7-compatible first SZL telegram", source)
        self.assertIn("0x00,0x08,0x00,0x08", source)
        self.assertIn("first ? 12U : 8U", source)
        self.assertIn("params[9] == 0x00", source)

    def test_s7_stop_proof_uses_job_and_reports_response_state(self):
        source = (PROJECT_ROOT / "src/protocols/s7_plugin.cpp").read_text(
            encoding="utf-8"
        )

        stop_function = source.split("static bool s7_plc_control", 1)[1].split(
            "bool S7Plugin::clientOpsPSRAM", 1
        )[0]
        self.assertIn("PDU_TYPE_JOB", stop_function)
        self.assertIn("P_PROGRAM", stop_function)
        self.assertNotIn("s7_userdata_exchange(sock, pdu_ref", stop_function)
        self.assertIn("command_sent", source)
        self.assertIn("response_accepted", source)
        self.assertIn("plc_state_verified", source)

    def test_p4_combined_image_uses_the_partition_table_application_offset(self):
        upload_script = (PROJECT_ROOT / "scripts/p4_upload.py").read_text(encoding="utf-8")
        self.assertIn('ESP32_APP_OFFSET="0x200000"', upload_script)

    def test_p4_upload_preserves_littlefs_during_an_ordinary_update(self):
        upload_script = (PROJECT_ROOT / "scripts/p4_upload.py").read_text(encoding="utf-8")

        self.assertNotIn("--no-build", upload_script)
        self.assertNotIn("--include-filesystem", upload_script)

    def test_p4_upload_override_runs_after_the_platform_upload_builder(self):
        platformio = (PROJECT_ROOT / "platformio.ini").read_text(encoding="utf-8")

        for environment in (
            "waveshare-esp32p4-eth",
            "guition-jc-esp32p4-m3-dev",
        ):
            section = platformio.split(f"[env:{environment}]", 1)[1].split(
                "[env:", 1
            )[0]
            self.assertIn("post:scripts/p4_upload.py", section)

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

    def test_network_presence_renders_all_recognized_protocol_tags(self):
        page = (PROJECT_ROOT / "src/web/ui/network_presence.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("function getVisibleProtocolLabels(device)", page)
        self.assertIn("const visibleProtocols = getVisibleProtocolLabels(device);", page)
        self.assertIn(".map(protocol =>", page)
        self.assertNotIn("const protocolLabel = protocols.length > 0 ? protocols[0] : 'N/A';", page)

    def test_vulnerability_scanner_contracts(self):
        opcua_tests = (PROJECT_ROOT / "src/protocols/opcua_vulnerability_tests.cpp").read_text(
            encoding="utf-8"
        )
        opcua_plugin = (PROJECT_ROOT / "src/protocols/opcua_plugin.cpp").read_text(
            encoding="utf-8"
        )
        opcua_codec = (PROJECT_ROOT / "src/protocols/opcua_binary_codec.cpp").read_text(
            encoding="utf-8"
        )
        modbus = (PROJECT_ROOT / "src/protocols/modbus_tcp_plugin.cpp").read_text(
            encoding="utf-8"
        )
        scanner = (PROJECT_ROOT / "src/assessment/vulnerability_scanner.cpp").read_text(
            encoding="utf-8"
        )
        page = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        self.assertIn("recvOpcUaFrame", opcua_tests)
        self.assertIn("recvOpcUaFrame", opcua_plugin)
        self.assertIn("msg_size < 8 || msg_size > len", opcua_codec)
        self.assertIn("parseInPSRAM", modbus)
        self.assertIn('cJSON_GetObjectItem(envelope, "scan_types")', modbus)
        self.assertIn('"plugin_no_result"', scanner)
        self.assertIn("1: { // Modbus", page)
        self.assertIn("scan_types:scanTypes", page)

    def test_modbus_reference_scan_matrix(self):
        modbus = (PROJECT_ROOT / "src/protocols/modbus_tcp_plugin.cpp").read_text(
            encoding="utf-8"
        )
        page = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        for marker in (
            "pduDeviceIdentification(uint8_t level, uint8_t object_id)",
            "object_id <= 5",
            "device_identification_regular",
            "device_identification_extended",
            "device_identification_object",
            "conformity_level",
            "unit_id_enumeration",
            "security_profile",
            "authentication_capability",
            "exception_behavior",
            "cleartext_exposure",
            "client_allow_list",
            "cve_correlation",
            "firmware_age",
            "TCP/802",
            "0xFFFF",
        ):
            self.assertIn(marker, modbus)

        for marker in (
            "service_discovery",
            "device_identification_regular",
            "device_identification_extended",
            "device_identification_object",
            "conformity_level",
            "unit_id_enumeration",
            "security_profile",
            "authentication_capability",
            "exception_behavior",
            "cleartext_exposure",
            "client_allow_list",
            "cve_correlation",
            "firmware_age",
        ):
            self.assertIn(marker, page)
        self.assertNotIn("{ id: 'write_capability'", page)
        self.assertIn('cfg_.enable_test_write && scan_types.empty()', modbus)

    def test_vulnerability_scan_result_polling_waits_for_terminal_result(self):
        page = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")
        scanner = (PROJECT_ROOT / "src/assessment/vulnerability_scanner.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("const SCAN_RESULT_POLL_ATTEMPTS = 60;", page)
        self.assertIn("box.dataset.state = 'pending';", page)
        self.assertIn("const done = await viewJobResult(id, true);", page)
        self.assertIn("if(!done && attempts < SCAN_RESULT_POLL_ATTEMPTS)", page)
        self.assertIn("return true;", page)
        self.assertIn("return false;", page)
        self.assertNotIn("box.textContent.trim().length>0", page)
        self.assertIn("last_results_.erase(id);", scanner)

    def test_vulnerability_scanner_protocol_fallback_matches_firmware_enum(self):
        page = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        self.assertIn("{id:3,key:'opcua',     name:'OPC UA'}", page)
        self.assertIn("{id:5,key:'profinet',  name:'PROFINET'}", page)
        self.assertNotIn("{id:3,key:'profinet'", page)
        self.assertNotIn("{id:5,key:'opcua'", page)

    def test_opcua_manual_assessments_are_reported_as_skipped(self):
        plugin = (PROJECT_ROOT / "src/protocols/opcua_plugin.cpp").read_text(
            encoding="utf-8"
        )
        page = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(encoding="utf-8")

        self.assertIn(
            'append_finding("default_credentials", scanner.testDefaultCredentials(host_ps.c_str(), port), true);',
            plugin,
        )
        self.assertIn(
            'append_finding("idor_vulnerability", scanner.testIDORVulnerability(host_ps.c_str(), port), true);',
            plugin,
        )
        self.assertIn("Manual: default credentials", page)
        self.assertIn("Manual: authorization/IDOR", page)

    def test_protocol_scans_emit_text_execution_traces(self):
        modbus = (PROJECT_ROOT / "src/protocols/modbus_tcp_plugin.cpp").read_text(
            encoding="utf-8"
        )
        opcua = (PROJECT_ROOT / "src/protocols/opcua_plugin.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("Modbus vulnerability check started", modbus)
        self.assertIn("Modbus vulnerability check completed", modbus)
        self.assertIn("OPC UA vulnerability check completed", opcua)

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
        self.assertIn("python scripts/convert_html_in_code.py", workflow)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py" -v', workflow)

    def test_target_specific_idf_lockfile_is_local_build_state(self):
        gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

        self.assertRegex(gitignore, r"(?m)^/dependencies\.lock$")

    def test_release_builds_enable_path_redaction_and_reproducibility(self):
        defaults = (
            "sdkconfig.defaults",
            "sdkconfig.esp32s3eth.defaults",
            "sdkconfig.esp32p4.defaults",
            "sdkconfig.guition-jc-esp32p4-m3-dev.defaults",
            "coprocessor/esp32c6/sdkconfig.defaults",
        )
        for filename in defaults:
            content = (PROJECT_ROOT / filename).read_text(encoding="utf-8")
            self.assertIn("CONFIG_APP_REPRODUCIBLE_BUILD=y", content)
            self.assertIn("CONFIG_COMPILER_HIDE_PATHS_MACROS=y", content)
            self.assertNotIn("CONFIG_COMPILER_HIDE_PATHS_MACROS=n", content)

    def test_windows_spaceful_prefix_maps_are_filtered_before_platformio(self):
        root_cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        c6_cmake = (
            PROJECT_ROOT / "coprocessor/esp32c6/CMakeLists.txt"
        ).read_text(encoding="utf-8")
        workaround = (
            PROJECT_ROOT / "scripts/cmake/filter_spaceful_prefix_maps.cmake"
        ).read_text(encoding="utf-8")

        include_line = (
            'include("${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/'
            'filter_spaceful_prefix_maps.cmake")'
        )
        self.assertIn(include_line, root_cmake)
        self.assertIn(
            'include("${CMAKE_CURRENT_LIST_DIR}/../../scripts/cmake/'
            'filter_spaceful_prefix_maps.cmake")',
            c6_cmake,
        )
        self.assertIn("esp32_ot_filter_spaceful_prefix_maps()", root_cmake)
        self.assertIn("esp32_ot_filter_spaceful_prefix_maps()", c6_cmake)
        self.assertIn("idf_build_set_property(COMPILE_OPTIONS", workaround)
        self.assertIn('string(FIND "${_source_prefix}" " "', workaround)

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
        self.assertIn(
            "#if SOC_WIFI_SUPPORTED || ESP32_OT_WIFI_BACKEND_REMOTE", wifi
        )
        self.assertIn('LOG_INFO(TAG, "Wi-Fi is unavailable on this target")', wifi)

    def test_guition_remote_wifi_dependencies_and_sdio_profile_are_pinned(self):
        manifest = (PROJECT_ROOT / "src/idf_component.yml").read_text(
            encoding="utf-8"
        )
        defaults = (
            PROJECT_ROOT / "sdkconfig.guition-jc-esp32p4-m3-dev.defaults"
        ).read_text(encoding="utf-8")

        self.assertIn("espressif/esp_wifi_remote:", manifest)
        self.assertIn("espressif/esp_hosted:", manifest)
        self.assertIn('version: "==1.6.4"', manifest)
        self.assertIn('version: "==3.0.6"', manifest)
        self.assertEqual(manifest.count("rules:"), 2)
        self.assertEqual(manifest.count('if: "target in [esp32p4]"'), 2)
        for setting in (
            "CONFIG_SLAVE_IDF_TARGET_ESP32C6=y",
            "CONFIG_ESP_HOSTED_CP_TARGET_ESP32C6=y",
            "CONFIG_ESP_HOSTED_P4_DEV_BOARD_FUNC_BOARD=y",
            "CONFIG_WIFI_RMT_STATIC_RX_BUFFER_NUM=16",
            "CONFIG_WIFI_RMT_DYNAMIC_RX_BUFFER_NUM=64",
            "CONFIG_WIFI_RMT_DYNAMIC_TX_BUFFER_NUM=64",
        ):
            self.assertIn(setting, defaults)

    def test_guition_psram_is_explicitly_enabled_with_safe_initial_timing(self):
        defaults = (
            PROJECT_ROOT / "sdkconfig.guition-jc-esp32p4-m3-dev.defaults"
        ).read_text(encoding="utf-8")

        for setting in (
            "CONFIG_SPIRAM=y",
            "CONFIG_SPIRAM_MODE_HEX=y",
            "CONFIG_SPIRAM_SPEED_20M=y",
        ):
            self.assertIn(setting, defaults)

    def test_platformio_preserves_esp_hosted_force_include_as_one_flag(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn("if(TARGET eh_host_config)", cmake)
        self.assertIn(
            'list(REMOVE_ITEM _ESP_HOST_CONFIG_OPTIONS "SHELL:-include eh_host_port_master_config.h")',
            cmake,
        )
        self.assertIn(
            'target_compile_options(eh_host_config INTERFACE "-includeeh_host_port_master_config.h")',
            cmake,
        )

    def test_p4_targets_aggregate_linker_fragments_for_windows_spaceful_paths(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn("if(CMAKE_HOST_WIN32)", cmake)
        self.assertIn(
            'if(CMAKE_HOST_WIN32 AND "${_IDF_TGT}" STREQUAL "esp32p4")',
            cmake,
        )
        self.assertIn("function(__ldgen_add_fragment_files fragment_files)", cmake)
        self.assertIn("foreach(fragment_file IN LISTS fragment_files)", cmake)
        self.assertIn("esp32_ot_all_fragments.lf", cmake)
        self.assertIn("__LDGEN_FRAGMENT_FILES", cmake)
        self.assertIn("CMAKE_CONFIGURE_DEPENDS", cmake)

    def test_guition_c6_coprocessor_project_is_reproducible_and_version_pinned(self):
        cp_root = PROJECT_ROOT / "coprocessor/esp32c6"
        manifest = (cp_root / "main/idf_component.yml").read_text(encoding="utf-8")
        defaults = (cp_root / "sdkconfig.defaults").read_text(encoding="utf-8")
        build_script = (PROJECT_ROOT / "scripts/build_c6_coprocessor.ps1").read_text(
            encoding="utf-8"
        )

        for path in (
            cp_root / "CMakeLists.txt",
            cp_root / "main/CMakeLists.txt",
            cp_root / "main/main.c",
            cp_root / "partitions.csv",
            PROJECT_ROOT / "coprocessor/README.md",
        ):
            self.assertTrue(path.is_file(), path)

        self.assertIn('version: "==3.0.6"', manifest)
        self.assertIn('version: ">=5.5,<5.6"', manifest)
        for setting in (
            "CONFIG_APP_REPRODUCIBLE_BUILD=y",
            "CONFIG_COMPILER_HIDE_PATHS_MACROS=y",
            "CONFIG_ESP_HOSTED_CP=y",
            "CONFIG_ESP_HOSTED_CP_FOR_MCU=y",
            "CONFIG_ESP_HOSTED_CP_RPC_V2=y",
            "CONFIG_ESP_HOSTED_CP_FEAT_WIFI=y",
            "CONFIG_EH_TRANSPORT_CP_SDIO=y",
            "CONFIG_EH_TRANSPORT_CP_SDIO_MODE_SW_AGGR=y",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_CMD=18",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_CLK=19",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_D0=20",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_D1=21",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_D2=22",
            "CONFIG_EH_TRANSPORT_CP_SDIO_PIN_D3=23",
        ):
            self.assertIn(setting, defaults)

        self.assertIn('$env:IDF_TARGET = "esp32c6"', build_script)
        self.assertIn('"-B", $BuildDir', build_script)
        self.assertIn('"--project-dir", $projectDir', build_script)
        self.assertIn("idf.py", build_script)

    def test_release_workflow_stages_the_guition_c6_ota_metadata(self):
        workflow = (PROJECT_ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("guition-jc-esp32p4-m3-dev", workflow)
        self.assertIn("pio run --project-dir coprocessor/esp32c6", workflow)
        self.assertIn("ota_data_initial.bin flasher_args.json", workflow)
        self.assertIn("--c6-build-dir", workflow)

    def test_management_controller_replaces_cross_interface_web_fallback(self):
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        coordinator = (
            PROJECT_ROOT / "src/provisioning/provisioning_coordinator.cpp"
        ).read_text(encoding="utf-8")
        controller = (
            PROJECT_ROOT / "src/network/management_interface_controller.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("ManagementInterfaceController management_controller", main)
        self.assertGreaterEqual(main.count("management_controller.tick()"), 2)
        self.assertNotIn("Try Ethernet last", main)
        self.assertNotIn("Try WiFi STA", main)
        self.assertIn('#include "../network/network_policy.h"', coordinator)
        self.assertIn("ESP32_OT_MGMT_POLICY == ESP32_OT_MGMT_ETHERNET_ONLY", coordinator)
        self.assertIn("BLOCKED_SUBNET_OVERLAP", controller)
        self.assertIn("web_.shutdown()", controller)

    def test_web_server_filters_connections_and_handlers_by_local_address(self):
        header = (PROJECT_ROOT / "src/web/web_server.h").read_text(encoding="utf-8")
        source = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        task = (PROJECT_ROOT / "src/web/web_server_task.cpp").read_text(
            encoding="utf-8"
        )
        controller_header = (
            PROJECT_ROOT / "src/network/management_interface_controller.h"
        ).read_text(encoding="utf-8")

        self.assertIn("setAllowedManagementAddress", header)
        self.assertIn("authorizeOpenSocket", header)
        self.assertIn("authorizeRequestInterface", header)
        self.assertIn("guardedUriHandler", header)
        self.assertGreaterEqual(source.count("open_fn = &WebServer::authorizeOpenSocket"), 2)
        self.assertIn("getsockname", source)
        self.assertIn("shutdown(sockfd, SHUT_RDWR)", source)
        self.assertIn("registerGuardedHandler", source)
        self.assertIn("httpd_ssl_stop(https_server_)", source)
        self.assertIn("srv->isRunning()", task)
        self.assertIn('"management_policy"', source)
        self.assertIn('"management_state"', source)
        self.assertIn('"assessment_interface"', source)
        self.assertIn("currentManagementInterfaceState", controller_header)

    def test_assessment_egress_is_centralized_on_ethernet(self):
        header = (
            PROJECT_ROOT / "src/network/assessment_interface.h"
        ).read_text(encoding="utf-8")
        source = (
            PROJECT_ROOT / "src/network/assessment_interface.cpp"
        ).read_text(encoding="utf-8")
        base = (PROJECT_ROOT / "src/protocols/base_plugin.cpp").read_text(
            encoding="utf-8"
        )
        network_engine = (PROJECT_ROOT / "src/core/network_engine.cpp").read_text(
            encoding="utf-8"
        )
        web = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        s7 = (PROJECT_ROOT / "src/protocols/s7_plugin.cpp").read_text(
            encoding="utf-8"
        )
        scanner = (PROJECT_ROOT / "src/web/ui/scanner.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("openBoundSocket", header)
        self.assertIn('esp_netif_get_handle_from_ifkey("ETH_DEF")', source)
        self.assertIn("SO_BINDTODEVICE", source)
        self.assertIn("::bind", source)
        self.assertNotIn('strcmp(requested_ifkey, "AUTO")', base)
        self.assertNotIn('esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")', base)
        self.assertNotRegex(network_engine, r"(?:udp|tcp)_bind\([^\n]*IP_ANY_TYPE")
        self.assertIn('cfg.bind_ifkey = PSRAMUtils::createPSRAMString("ETH_DEF")', web)
        self.assertNotIn('createPSRAMString("AUTO")', web)
        self.assertNotIn('createPSRAMString("WIFI_STA_DEF")', web)
        self.assertNotIn('createPSRAMString("WIFI_AP_DEF")', web)
        self.assertNotIn('esp_netif_get_handle_from_ifkey("WIFI_STA_DEF")', s7)
        self.assertNotIn('"AUTO"', s7)
        self.assertNotIn('<option value="auto">', scanner)
        self.assertNotIn('<option value="wifi_sta">', scanner)
        self.assertNotIn('<option value="wifi_ap">', scanner)

        assessment_sources = [
            PROJECT_ROOT / "src/protocols/base_plugin.cpp",
            PROJECT_ROOT / "src/protocols/modbus_tcp_plugin.cpp",
            PROJECT_ROOT / "src/protocols/ethernetip_plugin.cpp",
            PROJECT_ROOT / "src/protocols/opcua_plugin.cpp",
            PROJECT_ROOT / "src/protocols/opcua_fuzzing_executor.cpp",
            PROJECT_ROOT / "src/protocols/opcua_vulnerability_tests.cpp",
            PROJECT_ROOT / "src/protocols/s7_plugin.cpp",
            PROJECT_ROOT / "src/sandbox/net_guard.cpp",
        ]
        raw_socket = re.compile(r"(?<!openBound)(?<!lwip_)\bsocket\s*\(")
        for path in assessment_sources:
            content = path.read_text(encoding="utf-8")
            self.assertIsNone(raw_socket.search(content), path)
            self.assertNotIn("::bind(", content, path)

    def test_no_psram_diagnostic_does_not_shadow_runtime_memory_state(self):
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")

        self.assertIn("size_t initial_internal_free =", main)
        self.assertEqual(main.count("size_t internal_free ="), 2)

    def test_littlefs_seed_directory_exists_for_native_builds(self):
        cmake = (PROJECT_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertTrue((PROJECT_ROOT / "data/.gitkeep").is_file())
        self.assertIn("littlefs_create_partition_image(storage data FLASH_IN_PROJECT)", cmake)

    def test_firmware_uses_only_the_generated_public_header(self):
        configuration = (PROJECT_ROOT / "src/core/configuration_manager.cpp").read_text(encoding="utf-8")
        wifi = (PROJECT_ROOT / "src/network/wifi_manager.cpp").read_text(encoding="utf-8")
        web = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")

        self.assertIn('#include "esp32_ot_build_assets.h"', configuration)
        for source in (configuration, wifi, web):
            self.assertNotIn('#include "esp32_ot_generated_credentials.h"', source)
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
        wrapper = (PROJECT_ROOT / "scripts/platformio_build_assets.py").read_text(encoding="utf-8")

        self.assertIn("generate_build_assets(", wrapper)
        self.assertIn("CPPPATH", wrapper)
        self.assertNotIn("password", wrapper.lower())

    def test_native_idf_build_generates_public_assets_and_adds_generated_include(self):
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
        self.assertIn("scripts/build_assets.py", root_cmake)
        self.assertNotIn("credential_provisioning.py", root_cmake)
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
