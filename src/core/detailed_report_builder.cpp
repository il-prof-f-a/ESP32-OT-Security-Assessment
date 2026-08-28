#include "detailed_report_builder.h"
#include "reporting_engine.h"
#include "logging_system.h"
#include <iomanip>
#include <sstream>

extern "C" {
    #include "esp_system.h"
    #include "esp_mac.h"
}

static const char* TAG = "DetailedReportBuilder";

// Helper function to format bytes as hex string
psram_string formatPacketHex(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return PSRAMUtils::createPSRAMString("");
    }

    // Use PSRAM for large hex strings
    char* hex_buffer = static_cast<char*>(heap_caps_malloc(size * 2 + 1, MALLOC_CAP_SPIRAM));
    if (!hex_buffer) {
        LOG_ERROR(TAG, "Failed to allocate PSRAM for hex string");
        return PSRAMUtils::createPSRAMString("");
    }

    for (size_t i = 0; i < size; i++) {
        sprintf(&hex_buffer[i * 2], "%02x", data[i]);
    }
    hex_buffer[size * 2] = '\0';

    psram_string result = PSRAMUtils::createPSRAMString(hex_buffer);
    heap_caps_free(hex_buffer);
    return result;
}

// Simple Modbus packet parser
cJSON* parseModbusPacket(const uint8_t* data, size_t size) {
    if (!data || size < 6) return nullptr;

    cJSON* structure = cJSON_CreateObject();
    if (!structure) return nullptr;

    // Modbus TCP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function Code (1)
    if (size >= 8) {
        uint16_t transaction_id = (data[0] << 8) | data[1];
        uint16_t protocol_id = (data[2] << 8) | data[3];
        uint16_t length = (data[4] << 8) | data[5];
        uint8_t unit_id = data[6];
        uint8_t function_code = data[7];

        cJSON_AddNumberToObject(structure, "transaction_id", transaction_id);
        cJSON_AddNumberToObject(structure, "protocol_id", protocol_id);
        cJSON_AddNumberToObject(structure, "length", length);
        cJSON_AddNumberToObject(structure, "unit_id", unit_id);
        cJSON_AddNumberToObject(structure, "function_code", function_code);

        // Parse function-specific data
        if (size > 8) {
            const uint8_t* payload = &data[8];
            size_t payload_size = size - 8;

            switch (function_code) {
                case 3: // Read Holding Registers
                case 4: // Read Input Registers
                    if (payload_size >= 4) {
                        uint16_t start_address = (payload[0] << 8) | payload[1];
                        uint16_t quantity = (payload[2] << 8) | payload[3];
                        cJSON_AddNumberToObject(structure, "start_address", start_address);
                        cJSON_AddNumberToObject(structure, "quantity", quantity);
                    }
                    break;
                case 131: // Exception response (0x80 + 0x03)
                case 132: // Exception response (0x80 + 0x04)
                    if (payload_size >= 1) {
                        uint8_t exception_code = payload[0];
                        cJSON_AddNumberToObject(structure, "exception_code", exception_code);
                        const char* error_type = "unknown";
                        switch (exception_code) {
                            case 1: error_type = "illegal_function"; break;
                            case 2: error_type = "illegal_data_address"; break;
                            case 3: error_type = "illegal_data_value"; break;
                            case 4: error_type = "slave_device_failure"; break;
                        }
                        cJSON_AddStringToObject(structure, "error_type", error_type);
                    }
                    break;
            }
        }
    }

    return structure;
}

// Stub implementations for other protocols
cJSON* parseS7Packet(const uint8_t* data, size_t size) {
    // TODO: Implement S7 parsing
    cJSON* structure = cJSON_CreateObject();
    if (structure) {
        cJSON_AddStringToObject(structure, "protocol", "s7");
        cJSON_AddStringToObject(structure, "status", "parsing_not_implemented");
    }
    return structure;
}

cJSON* parseOPCUAPacket(const uint8_t* data, size_t size) {
    // TODO: Implement OPC-UA parsing
    cJSON* structure = cJSON_CreateObject();
    if (structure) {
        cJSON_AddStringToObject(structure, "protocol", "opcua");
        cJSON_AddStringToObject(structure, "status", "parsing_not_implemented");
    }
    return structure;
}

// EtherNet/IP packet parser
cJSON* parseEtherNetIPPacket(const uint8_t* data, size_t size) {
    if (!data || size < 24) return nullptr;

    cJSON* structure = cJSON_CreateObject();
    if (!structure) return nullptr;

    // Parse Encapsulation Header (24 bytes)
    uint16_t command = (data[1] << 8) | data[0];
    uint16_t length = (data[3] << 8) | data[2];
    uint32_t session_handle = (data[7] << 24) | (data[6] << 16) | (data[5] << 8) | data[4];
    uint32_t status = (data[11] << 24) | (data[10] << 16) | (data[9] << 8) | data[8];
    uint64_t sender_context = 0;
    for (int i = 0; i < 8; i++) {
        sender_context |= ((uint64_t)data[12 + i] << (i * 8));
    }
    uint32_t options = (data[23] << 24) | (data[22] << 16) | (data[21] << 8) | data[20];

    // Add encapsulation header fields
    cJSON_AddNumberToObject(structure, "command", command);
    cJSON_AddNumberToObject(structure, "length", length);
    cJSON_AddNumberToObject(structure, "session_handle", session_handle);
    cJSON_AddNumberToObject(structure, "status", status);

    // Add sender context as hex string
    char sender_context_hex[20];
    snprintf(sender_context_hex, sizeof(sender_context_hex), "0x%016llx", sender_context);
    cJSON_AddStringToObject(structure, "sender_context", sender_context_hex);
    cJSON_AddNumberToObject(structure, "options", options);

    // Decode command type
    const char* command_name = "unknown";
    switch (command) {
        case 0x0001: command_name = "NOP"; break;
        case 0x0004: command_name = "ListServices"; break;
        case 0x0063: command_name = "ListIdentity"; break;
        case 0x0064: command_name = "ListInterfaces"; break;
        case 0x0065: command_name = "RegisterSession"; break;
        case 0x0066: command_name = "UnregisterSession"; break;
        case 0x006F: command_name = "SendRRData"; break;
        case 0x0070: command_name = "SendUnitData"; break;
    }
    cJSON_AddStringToObject(structure, "command_name", command_name);

    // Decode status code
    const char* status_description = "success";
    if (status != 0) {
        switch (status) {
            case 0x0001: status_description = "invalid_command"; break;
            case 0x0002: status_description = "insufficient_memory"; break;
            case 0x0003: status_description = "invalid_or_unsupported_command"; break;
            case 0x0064: status_description = "invalid_session"; break;
            case 0x0065: status_description = "invalid_length"; break;
            case 0x0069: status_description = "unsupported_protocol"; break;
            default: status_description = "error"; break;
        }
    }
    cJSON_AddStringToObject(structure, "status_description", status_description);

    // Parse CIP payload if present and command is SendRRData
    if (command == 0x006F && size > 24) {
        const uint8_t* payload = &data[24];
        size_t payload_size = size - 24;

        // SendRRData has interface handle (4), timeout (2), then CPF items
        if (payload_size >= 6) {
            uint32_t interface_handle = (payload[3] << 24) | (payload[2] << 16) | (payload[1] << 8) | payload[0];
            uint16_t timeout = (payload[5] << 8) | payload[4];

            cJSON_AddNumberToObject(structure, "interface_handle", interface_handle);
            cJSON_AddNumberToObject(structure, "timeout", timeout);

            // Parse CPF (Common Packet Format) items
            if (payload_size >= 8) {
                uint16_t item_count = (payload[7] << 8) | payload[6];
                cJSON_AddNumberToObject(structure, "cpf_item_count", item_count);

                // Parse first CPF item if available
                size_t offset = 8;
                if (item_count > 0 && payload_size >= offset + 4) {
                    uint16_t type_code = (payload[offset + 1] << 8) | payload[offset];
                    uint16_t item_length = (payload[offset + 3] << 8) | payload[offset + 2];

                    cJSON_AddNumberToObject(structure, "cpf_item1_type", type_code);
                    cJSON_AddNumberToObject(structure, "cpf_item1_length", item_length);

                    offset += 4;

                    // Parse second CPF item (typically contains CIP message)
                    if (item_count > 1 && payload_size >= offset + 4) {
                        offset += item_length; // Skip first item data
                        if (payload_size >= offset + 4) {
                            type_code = (payload[offset + 1] << 8) | payload[offset];
                            item_length = (payload[offset + 3] << 8) | payload[offset + 2];

                            cJSON_AddNumberToObject(structure, "cpf_item2_type", type_code);
                            cJSON_AddNumberToObject(structure, "cpf_item2_length", item_length);

                            offset += 4;

                            // Parse CIP message if present
                            if (type_code == 0x00B2 && payload_size >= offset + 2) { // Unconnected Data Item
                                uint8_t service = payload[offset];
                                uint8_t path_size = payload[offset + 1];

                                cJSON_AddNumberToObject(structure, "cip_service", service);
                                cJSON_AddNumberToObject(structure, "cip_path_size", path_size);

                                // Decode CIP service
                                const char* service_name = "unknown";
                                uint8_t service_code = service & 0x7F;
                                bool is_response = (service & 0x80) != 0;

                                switch (service_code) {
                                    case 0x01: service_name = "Get_Attributes_All"; break;
                                    case 0x0E: service_name = "Get_Attribute_Single"; break;
                                    case 0x10: service_name = "Set_Attribute_Single"; break;
                                    case 0x4C: service_name = "CIP_Read"; break;
                                    case 0x4D: service_name = "CIP_Write"; break;
                                }

                                cJSON_AddStringToObject(structure, "cip_service_name", service_name);
                                cJSON_AddBoolToObject(structure, "cip_is_response", is_response);
                            }
                        }
                    }
                }
            }
        }
    }

    return structure;
}

// DetailedReportBuilderBase implementation
DetailedReportBuilderBase::DetailedReportBuilderBase()
    : schema_version_(PSRAMUtils::createPSRAMString("1.0"))
    , timestamp_(esp_timer_get_time() / 1000ULL)
    , device_id_(getDeviceId())
    , module_version_(PSRAMUtils::createPSRAMString("1.0.0")) {
}

DetailedReportBuilderBase::~DetailedReportBuilderBase() = default;

psram_string DetailedReportBuilderBase::getDeviceId() {
    uint8_t mac[6] = {};
    // The base MAC comes from eFuse and is available on every supported target,
    // including ESP32-P4 boards without a native Wi-Fi MAC.
    if (esp_efuse_mac_get_default(mac) == ESP_OK) {
        char device_id[32];
        snprintf(device_id, sizeof(device_id), "ESP32-OT-%02X%02X%02X",
                 mac[3], mac[4], mac[5]);
        return PSRAMUtils::createPSRAMString(device_id);
    }
    return PSRAMUtils::createPSRAMString("ESP32-OT-UNKNOWN");
}

void DetailedReportBuilderBase::setDeviceId(const psram_string& device_id) {
    device_id_ = device_id;
}

void DetailedReportBuilderBase::setSessionId(const psram_string& session_id) {
    session_id_ = session_id;
}

void DetailedReportBuilderBase::setModuleInfo(const psram_string& module, const psram_string& version) {
    module_name_ = module;
    module_version_ = version;
}

void DetailedReportBuilderBase::setTimestamp(uint64_t timestamp_ms) {
    if (timestamp_ms == 0) {
        timestamp_ = esp_timer_get_time() / 1000ULL;
    } else {
        timestamp_ = timestamp_ms;
    }
}

cJSON* DetailedReportBuilderBase::createBaseStructure() {
    cJSON* root = cJSON_CreateObject();
    if (!root) return nullptr;

    // Convert PSRAM strings to C strings for cJSON
    char schema_buffer[16], event_buffer[32], device_buffer[64], session_buffer[64], module_buffer[32], version_buffer[16];

    size_t schema_size = std::min(schema_version_.size(), sizeof(schema_buffer) - 1);
    size_t event_size = std::min(event_type_.size(), sizeof(event_buffer) - 1);
    size_t device_size = std::min(device_id_.size(), sizeof(device_buffer) - 1);
    size_t session_size = std::min(session_id_.size(), sizeof(session_buffer) - 1);
    size_t module_size = std::min(module_name_.size(), sizeof(module_buffer) - 1);
    size_t version_size = std::min(module_version_.size(), sizeof(version_buffer) - 1);

    std::memcpy(schema_buffer, schema_version_.data(), schema_size);
    schema_buffer[schema_size] = '\0';
    std::memcpy(event_buffer, event_type_.data(), event_size);
    event_buffer[event_size] = '\0';
    std::memcpy(device_buffer, device_id_.data(), device_size);
    device_buffer[device_size] = '\0';
    std::memcpy(session_buffer, session_id_.data(), session_size);
    session_buffer[session_size] = '\0';
    std::memcpy(module_buffer, module_name_.data(), module_size);
    module_buffer[module_size] = '\0';
    std::memcpy(version_buffer, module_version_.data(), version_size);
    version_buffer[version_size] = '\0';

    cJSON_AddStringToObject(root, "schema_version", schema_buffer);
    cJSON_AddStringToObject(root, "event_type", event_buffer);
    cJSON_AddNumberToObject(root, "timestamp", (double)timestamp_);
    cJSON_AddStringToObject(root, "device_id", device_buffer);
    if (session_id_.size() > 0) {
        cJSON_AddStringToObject(root, "session_id", session_buffer);
    }

    cJSON* source = cJSON_CreateObject();
    if (source) {
        cJSON_AddStringToObject(source, "module", module_buffer);
        cJSON_AddStringToObject(source, "version", version_buffer);
        cJSON_AddItemToObject(root, "source", source);
    }

    return root;
}

void DetailedReportBuilderBase::addPacketToJSON(cJSON* parent, const char* key, const PacketData& packet) {
    if (!parent || !key) return;

    cJSON* packet_obj = cJSON_CreateObject();
    if (!packet_obj) return;

    // Convert PSRAM string to C string for hex data
    char hex_buffer[1024]; // Limit hex display for memory safety
    size_t hex_size = std::min(packet.hex.size(), sizeof(hex_buffer) - 1);
    std::memcpy(hex_buffer, packet.hex.data(), hex_size);
    hex_buffer[hex_size] = '\0';

    cJSON_AddStringToObject(packet_obj, "hex", hex_buffer);
    cJSON_AddNumberToObject(packet_obj, "size", (double)packet.size);
    cJSON_AddNumberToObject(packet_obj, "timestamp", (double)packet.timestamp);

    if (packet.structure) {
        cJSON* structure_copy = cJSON_Duplicate(packet.structure, 1);
        if (structure_copy) {
            cJSON_AddItemToObject(packet_obj, "structure", structure_copy);
        }
    }

    cJSON_AddItemToObject(parent, key, packet_obj);
}

void DetailedReportBuilderBase::addTestResultToJSON(cJSON* parent, const TestResult& result) {
    if (!parent) return;

    cJSON* result_obj = cJSON_CreateObject();
    if (!result_obj) return;

    // Convert PSRAM strings to C strings
    char status_buffer[32], vuln_type_buffer[64], severity_buffer[16], desc_buffer[256], rec_buffer[256];

    size_t status_size = std::min(result.status.size(), sizeof(status_buffer) - 1);
    size_t vuln_size = std::min(result.vulnerability_type.size(), sizeof(vuln_type_buffer) - 1);
    size_t sev_size = std::min(result.severity.size(), sizeof(severity_buffer) - 1);
    size_t desc_size = std::min(result.description.size(), sizeof(desc_buffer) - 1);
    size_t rec_size = std::min(result.recommendation.size(), sizeof(rec_buffer) - 1);

    std::memcpy(status_buffer, result.status.data(), status_size);
    status_buffer[status_size] = '\0';
    std::memcpy(vuln_type_buffer, result.vulnerability_type.data(), vuln_size);
    vuln_type_buffer[vuln_size] = '\0';
    std::memcpy(severity_buffer, result.severity.data(), sev_size);
    severity_buffer[sev_size] = '\0';
    std::memcpy(desc_buffer, result.description.data(), desc_size);
    desc_buffer[desc_size] = '\0';
    std::memcpy(rec_buffer, result.recommendation.data(), rec_size);
    rec_buffer[rec_size] = '\0';

    cJSON_AddStringToObject(result_obj, "status", status_buffer);
    cJSON_AddBoolToObject(result_obj, "vulnerability_found", result.vulnerability_found);
    if (result.vulnerability_type.size() > 0) {
        cJSON_AddStringToObject(result_obj, "vulnerability_type", vuln_type_buffer);
    }
    if (result.severity.size() > 0) {
        cJSON_AddStringToObject(result_obj, "severity", severity_buffer);
    }
    cJSON_AddNumberToObject(result_obj, "result_code", result.result_code);
    if (result.description.size() > 0) {
        cJSON_AddStringToObject(result_obj, "description", desc_buffer);
    }
    if (result.cvss_score > 0.0f) {
        cJSON_AddNumberToObject(result_obj, "cvss_score", result.cvss_score);
    }
    if (result.recommendation.size() > 0) {
        cJSON_AddStringToObject(result_obj, "recommendation", rec_buffer);
    }

    cJSON_AddItemToObject(parent, "result", result_obj);
}

psram_string DetailedReportBuilderBase::jsonToString(cJSON* root) {
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    // Use cJSON_PrintUnformatted for smaller output
    char* json_string = cJSON_PrintUnformatted(root);
    if (!json_string) {
        // If heap allocation fails, try PSRAM buffer approach
        static const size_t MAX_JSON_SIZE = 32768; // 32KB for complex fuzzing JSON
        char* psram_buffer = (char*)heap_caps_malloc(MAX_JSON_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (psram_buffer) {
            // Try printing to our PSRAM buffer using cJSON_PrintPreallocated
            if (cJSON_PrintPreallocated(root, psram_buffer, MAX_JSON_SIZE, false)) {
                psram_string result = PSRAMUtils::createPSRAMString(psram_buffer);
                heap_caps_free(psram_buffer);
                return result;
            }
            heap_caps_free(psram_buffer);

            // Log that we had a buffer overflow for debugging
            size_t estimated_size = strlen(psram_buffer) + 1000; // rough estimate
            LOG_ERRORF("REPORT_BUILDER", "JSON too large for 32KB buffer (est. %zu bytes)", estimated_size);
        }
        return PSRAMUtils::createPSRAMString("{\"error\":\"json_too_large\",\"max_size\":32768}");
    }

    psram_string result = PSRAMUtils::createPSRAMString(json_string);
    free(json_string);
    return result;
}

// FuzzTestReportBuilder implementation
FuzzTestReportBuilder::FuzzTestReportBuilder() {
    event_type_ = PSRAMUtils::createPSRAMString("fuzz_test");
    module_name_ = PSRAMUtils::createPSRAMString("fuzzing_engine");
}

void FuzzTestReportBuilder::setTestInfo(uint32_t job_id, uint32_t test_case_id, uint32_t mutation_id, uint32_t seed_id) {
    job_id_ = job_id;
    test_case_id_ = test_case_id;
    mutation_id_ = mutation_id;
    seed_id_ = seed_id;
}

void FuzzTestReportBuilder::setTestType(const psram_string& test_type) {
    test_type_ = test_type;
}

void FuzzTestReportBuilder::setProtocol(const psram_string& protocol) {
    protocol_ = protocol;
}

void FuzzTestReportBuilder::setTarget(const psram_string& host, uint16_t port, uint32_t unit_id, const psram_string& endpoint) {
    target_host_ = host;
    target_port_ = port;
    target_unit_id_ = unit_id;
    target_endpoint_ = endpoint;
}

void FuzzTestReportBuilder::setSentPacket(const psram_string& hex, size_t size, cJSON* structure) {
    sent_packet_.hex = hex;
    sent_packet_.size = size;
    sent_packet_.timestamp = esp_timer_get_time() / 1000ULL;
    if (sent_packet_.structure) {
        cJSON_Delete(sent_packet_.structure);
    }
    sent_packet_.structure = structure;
}

void FuzzTestReportBuilder::setReceivedPacket(const psram_string& hex, size_t size, cJSON* structure, uint32_t delay_ms) {
    received_packet_.hex = hex;
    received_packet_.size = size;
    received_packet_.timestamp = esp_timer_get_time() / 1000ULL;
    packet_delay_ms_ = delay_ms;
    if (received_packet_.structure) {
        cJSON_Delete(received_packet_.structure);
    }
    received_packet_.structure = structure;
}

void FuzzTestReportBuilder::setResult(const TestResult& result) {
    result_ = result;
}

void FuzzTestReportBuilder::setMetrics(uint32_t execution_time_ms, uint32_t retries, float success_rate) {
    execution_time_ms_ = execution_time_ms;
    retries_ = retries;
    success_rate_ = success_rate;
}

psram_string FuzzTestReportBuilder::build() {
    cJSON* root = createBaseStructure();
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    // Test information
    cJSON* test = cJSON_CreateObject();
    if (test) {
        cJSON_AddNumberToObject(test, "job_id", job_id_);
        cJSON_AddNumberToObject(test, "test_case_id", test_case_id_);
        cJSON_AddNumberToObject(test, "mutation_id", mutation_id_);
        cJSON_AddNumberToObject(test, "seed_id", seed_id_);

        // Convert PSRAM strings to C strings
        char test_type_buffer[64], protocol_buffer[32];
        size_t test_type_size = std::min(test_type_.size(), sizeof(test_type_buffer) - 1);
        size_t protocol_size = std::min(protocol_.size(), sizeof(protocol_buffer) - 1);
        std::memcpy(test_type_buffer, test_type_.data(), test_type_size);
        test_type_buffer[test_type_size] = '\0';
        std::memcpy(protocol_buffer, protocol_.data(), protocol_size);
        protocol_buffer[protocol_size] = '\0';

        if (test_type_.size() > 0) {
            cJSON_AddStringToObject(test, "test_type", test_type_buffer);
        }
        if (protocol_.size() > 0) {
            cJSON_AddStringToObject(test, "protocol", protocol_buffer);
        }

        // Target information
        cJSON* target = cJSON_CreateObject();
        if (target) {
            char host_buffer[64], endpoint_buffer[128];
            size_t host_size = std::min(target_host_.size(), sizeof(host_buffer) - 1);
            size_t endpoint_size = std::min(target_endpoint_.size(), sizeof(endpoint_buffer) - 1);
            std::memcpy(host_buffer, target_host_.data(), host_size);
            host_buffer[host_size] = '\0';
            std::memcpy(endpoint_buffer, target_endpoint_.data(), endpoint_size);
            endpoint_buffer[endpoint_size] = '\0';

            cJSON_AddStringToObject(target, "host", host_buffer);
            cJSON_AddNumberToObject(target, "port", target_port_);
            if (target_unit_id_ > 0) {
                cJSON_AddNumberToObject(target, "unit_id", target_unit_id_);
            }
            if (target_endpoint_.size() > 0) {
                cJSON_AddStringToObject(target, "endpoint", endpoint_buffer);
            }
            cJSON_AddItemToObject(test, "target", target);
        }

        cJSON_AddItemToObject(root, "test", test);
    }

    // Packets (always include both sent and received for completeness)
    cJSON* packets = cJSON_CreateObject();
    if (packets) {
        if (sent_packet_.size > 0) {
            addPacketToJSON(packets, "sent", sent_packet_);
        }
        // Always include received packet, even if empty/null
        addPacketToJSON(packets, "received", received_packet_);
        if (packet_delay_ms_ > 0) {
            cJSON* received = cJSON_GetObjectItem(packets, "received");
            if (received) {
                cJSON_AddNumberToObject(received, "delay_ms", packet_delay_ms_);
            }
        }
        cJSON_AddItemToObject(root, "packets", packets);
    }

    // Result
    addTestResultToJSON(root, result_);

    // Metrics
    cJSON* metrics = cJSON_CreateObject();
    if (metrics) {
        cJSON_AddNumberToObject(metrics, "execution_time_ms", execution_time_ms_);
        cJSON_AddNumberToObject(metrics, "retries", retries_);
        cJSON_AddNumberToObject(metrics, "success_rate", success_rate_);
        cJSON_AddItemToObject(root, "metrics", metrics);
    }

    psram_string result = jsonToString(root);
    cJSON_Delete(root);
    return result;
}

// VulnScanReportBuilder implementation
VulnScanReportBuilder::VulnScanReportBuilder() {
    event_type_ = PSRAMUtils::createPSRAMString("vuln_scan");
    module_name_ = PSRAMUtils::createPSRAMString("vulnerability_scanner");
}

void VulnScanReportBuilder::setScanInfo(uint32_t job_id, const psram_string& scan_name, const psram_string& scan_type) {
    job_id_ = job_id;
    scan_name_ = scan_name;
    scan_type_ = scan_type;
}

void VulnScanReportBuilder::setProtocol(const psram_string& protocol) {
    protocol_ = protocol;
}

void VulnScanReportBuilder::setTarget(const psram_string& host, uint16_t port, const psram_string& description) {
    target_host_ = host;
    target_port_ = port;
    target_description_ = description;
}

void VulnScanReportBuilder::addTest(VulnTest&& test) {
    tests_.push_back(std::move(test));
}

void VulnScanReportBuilder::setSummary(const ScanSummary& summary) {
    summary_ = summary;
}

psram_string VulnScanReportBuilder::build() {
    cJSON* root = createBaseStructure();
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    // Scan information
    cJSON* scan = cJSON_CreateObject();
    if (scan) {
        cJSON_AddNumberToObject(scan, "job_id", job_id_);

        // Convert PSRAM strings to C strings
        char name_buffer[128], type_buffer[64], protocol_buffer[32];
        size_t name_size = std::min(scan_name_.size(), sizeof(name_buffer) - 1);
        size_t type_size = std::min(scan_type_.size(), sizeof(type_buffer) - 1);
        size_t protocol_size = std::min(protocol_.size(), sizeof(protocol_buffer) - 1);
        std::memcpy(name_buffer, scan_name_.data(), name_size);
        name_buffer[name_size] = '\0';
        std::memcpy(type_buffer, scan_type_.data(), type_size);
        type_buffer[type_size] = '\0';
        std::memcpy(protocol_buffer, protocol_.data(), protocol_size);
        protocol_buffer[protocol_size] = '\0';

        cJSON_AddStringToObject(scan, "scan_name", name_buffer);
        cJSON_AddStringToObject(scan, "scan_type", type_buffer);
        cJSON_AddStringToObject(scan, "protocol", protocol_buffer);

        // Target
        cJSON* target = cJSON_CreateObject();
        if (target) {
            char host_buffer[64], desc_buffer[128];
            size_t host_size = std::min(target_host_.size(), sizeof(host_buffer) - 1);
            size_t desc_size = std::min(target_description_.size(), sizeof(desc_buffer) - 1);
            std::memcpy(host_buffer, target_host_.data(), host_size);
            host_buffer[host_size] = '\0';
            std::memcpy(desc_buffer, target_description_.data(), desc_size);
            desc_buffer[desc_size] = '\0';

            cJSON_AddStringToObject(target, "host", host_buffer);
            cJSON_AddNumberToObject(target, "port", target_port_);
            if (target_description_.size() > 0) {
                cJSON_AddStringToObject(target, "description", desc_buffer);
            }
            cJSON_AddItemToObject(scan, "target", target);
        }

        cJSON_AddItemToObject(root, "scan", scan);
    }

    // Tests array
    cJSON* tests_array = cJSON_CreateArray();
    if (tests_array) {
        for (const auto& test : tests_) {
            cJSON* test_obj = cJSON_CreateObject();
            if (test_obj) {
                // Convert PSRAM strings to C strings
                char id_buffer[64], name_buffer[128], desc_buffer[256];
                size_t id_size = std::min(test.test_id.size(), sizeof(id_buffer) - 1);
                size_t name_size = std::min(test.test_name.size(), sizeof(name_buffer) - 1);
                size_t desc_size = std::min(test.test_description.size(), sizeof(desc_buffer) - 1);
                std::memcpy(id_buffer, test.test_id.data(), id_size);
                id_buffer[id_size] = '\0';
                std::memcpy(name_buffer, test.test_name.data(), name_size);
                name_buffer[name_size] = '\0';
                std::memcpy(desc_buffer, test.test_description.data(), desc_size);
                desc_buffer[desc_size] = '\0';

                cJSON_AddStringToObject(test_obj, "test_id", id_buffer);
                cJSON_AddStringToObject(test_obj, "test_name", name_buffer);
                cJSON_AddStringToObject(test_obj, "test_description", desc_buffer);

                // Packets
                cJSON* packets = cJSON_CreateObject();
                if (packets) {
                    if (test.sent_packet.size > 0) {
                        addPacketToJSON(packets, "sent", test.sent_packet);
                    }
                    if (test.received_packet.size > 0) {
                        addPacketToJSON(packets, "received", test.received_packet);
                    }
                    cJSON_AddItemToObject(test_obj, "packets", packets);
                }

                // Result
                addTestResultToJSON(test_obj, test.result);

                cJSON_AddItemToArray(tests_array, test_obj);
            }
        }
        cJSON_AddItemToObject(root, "tests", tests_array);
    }

    // Summary
    cJSON* summary = cJSON_CreateObject();
    if (summary) {
        cJSON_AddNumberToObject(summary, "tests_run", summary_.tests_run);
        cJSON_AddNumberToObject(summary, "vulnerabilities_found", summary_.vulnerabilities_found);
        cJSON_AddNumberToObject(summary, "critical", summary_.critical);
        cJSON_AddNumberToObject(summary, "high", summary_.high);
        cJSON_AddNumberToObject(summary, "medium", summary_.medium);
        cJSON_AddNumberToObject(summary, "low", summary_.low);
        cJSON_AddNumberToObject(summary, "scan_duration_ms", summary_.scan_duration_ms);

        char risk_buffer[32];
        size_t risk_size = std::min(summary_.overall_risk.size(), sizeof(risk_buffer) - 1);
        std::memcpy(risk_buffer, summary_.overall_risk.data(), risk_size);
        risk_buffer[risk_size] = '\0';
        cJSON_AddStringToObject(summary, "overall_risk", risk_buffer);

        cJSON_AddItemToObject(root, "summary", summary);
    }

    psram_string result = jsonToString(root);
    cJSON_Delete(root);
    return result;
}

// IDSDetectionReportBuilder implementation
IDSDetectionReportBuilder::IDSDetectionReportBuilder() {
    event_type_ = PSRAMUtils::createPSRAMString("ids_detection");
    module_name_ = PSRAMUtils::createPSRAMString("ids_engine");
}

void IDSDetectionReportBuilder::setDetectionInfo(const DetectionInfo& detection) {
    detection_ = detection;
}

void IDSDetectionReportBuilder::setPacketInfo(const PacketInfo& packet) {
    // Move assignment will handle the cJSON* properly
    packet_ = const_cast<PacketInfo&&>(packet);
}

void IDSDetectionReportBuilder::setContext(const DetectionContext& context) {
    context_ = context;
}

void IDSDetectionReportBuilder::setActionTaken(const psram_string& action) {
    action_taken_ = action;
}

psram_string IDSDetectionReportBuilder::build() {
    cJSON* root = createBaseStructure();
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    // Detection information
    cJSON* detection = cJSON_CreateObject();
    if (detection) {
        // Convert PSRAM strings to C strings
        char alert_buffer[64], type_buffer[32], rule_id_buffer[32], rule_name_buffer[128], rule_desc_buffer[256], severity_buffer[16];

        size_t alert_size = std::min(detection_.alert_id.size(), sizeof(alert_buffer) - 1);
        size_t type_size = std::min(detection_.detection_type.size(), sizeof(type_buffer) - 1);
        size_t rule_id_size = std::min(detection_.rule_id.size(), sizeof(rule_id_buffer) - 1);
        size_t rule_name_size = std::min(detection_.rule_name.size(), sizeof(rule_name_buffer) - 1);
        size_t rule_desc_size = std::min(detection_.rule_description.size(), sizeof(rule_desc_buffer) - 1);
        size_t severity_size = std::min(detection_.severity.size(), sizeof(severity_buffer) - 1);

        std::memcpy(alert_buffer, detection_.alert_id.data(), alert_size);
        alert_buffer[alert_size] = '\0';
        std::memcpy(type_buffer, detection_.detection_type.data(), type_size);
        type_buffer[type_size] = '\0';
        std::memcpy(rule_id_buffer, detection_.rule_id.data(), rule_id_size);
        rule_id_buffer[rule_id_size] = '\0';
        std::memcpy(rule_name_buffer, detection_.rule_name.data(), rule_name_size);
        rule_name_buffer[rule_name_size] = '\0';
        std::memcpy(rule_desc_buffer, detection_.rule_description.data(), rule_desc_size);
        rule_desc_buffer[rule_desc_size] = '\0';
        std::memcpy(severity_buffer, detection_.severity.data(), severity_size);
        severity_buffer[severity_size] = '\0';

        cJSON_AddStringToObject(detection, "alert_id", alert_buffer);
        cJSON_AddStringToObject(detection, "detection_type", type_buffer);
        cJSON_AddStringToObject(detection, "rule_id", rule_id_buffer);
        cJSON_AddStringToObject(detection, "rule_name", rule_name_buffer);
        cJSON_AddStringToObject(detection, "rule_description", rule_desc_buffer);
        cJSON_AddStringToObject(detection, "severity", severity_buffer);
        cJSON_AddNumberToObject(detection, "confidence", detection_.confidence);

        cJSON_AddItemToObject(root, "detection", detection);
    }

    // Packet information
    cJSON* packet = cJSON_CreateObject();
    if (packet) {
        // Convert PSRAM strings to C strings for packet info
        char dir_buffer[16], src_ip_buffer[64], src_mac_buffer[32], src_host_buffer[128];
        char dst_ip_buffer[64], dst_mac_buffer[32], dst_host_buffer[128], protocol_buffer[32];

        size_t dir_size = std::min(packet_.direction.size(), sizeof(dir_buffer) - 1);
        size_t src_ip_size = std::min(packet_.src_ip.size(), sizeof(src_ip_buffer) - 1);
        size_t src_mac_size = std::min(packet_.src_mac.size(), sizeof(src_mac_buffer) - 1);
        size_t src_host_size = std::min(packet_.src_hostname.size(), sizeof(src_host_buffer) - 1);
        size_t dst_ip_size = std::min(packet_.dst_ip.size(), sizeof(dst_ip_buffer) - 1);
        size_t dst_mac_size = std::min(packet_.dst_mac.size(), sizeof(dst_mac_buffer) - 1);
        size_t dst_host_size = std::min(packet_.dst_hostname.size(), sizeof(dst_host_buffer) - 1);
        size_t protocol_size = std::min(packet_.protocol.size(), sizeof(protocol_buffer) - 1);

        std::memcpy(dir_buffer, packet_.direction.data(), dir_size);
        dir_buffer[dir_size] = '\0';
        std::memcpy(src_ip_buffer, packet_.src_ip.data(), src_ip_size);
        src_ip_buffer[src_ip_size] = '\0';
        std::memcpy(src_mac_buffer, packet_.src_mac.data(), src_mac_size);
        src_mac_buffer[src_mac_size] = '\0';
        std::memcpy(src_host_buffer, packet_.src_hostname.data(), src_host_size);
        src_host_buffer[src_host_size] = '\0';
        std::memcpy(dst_ip_buffer, packet_.dst_ip.data(), dst_ip_size);
        dst_ip_buffer[dst_ip_size] = '\0';
        std::memcpy(dst_mac_buffer, packet_.dst_mac.data(), dst_mac_size);
        dst_mac_buffer[dst_mac_size] = '\0';
        std::memcpy(dst_host_buffer, packet_.dst_hostname.data(), dst_host_size);
        dst_host_buffer[dst_host_size] = '\0';
        std::memcpy(protocol_buffer, packet_.protocol.data(), protocol_size);
        protocol_buffer[protocol_size] = '\0';

        cJSON_AddStringToObject(packet, "direction", dir_buffer);
        cJSON_AddStringToObject(packet, "protocol", protocol_buffer);

        // Source information
        cJSON* source = cJSON_CreateObject();
        if (source) {
            cJSON_AddStringToObject(source, "ip", src_ip_buffer);
            cJSON_AddNumberToObject(source, "port", packet_.src_port);
            cJSON_AddStringToObject(source, "mac", src_mac_buffer);
            if (packet_.src_hostname.size() > 0) {
                cJSON_AddStringToObject(source, "hostname", src_host_buffer);
            }
            cJSON_AddItemToObject(packet, "source", source);
        }

        // Destination information
        cJSON* destination = cJSON_CreateObject();
        if (destination) {
            cJSON_AddStringToObject(destination, "ip", dst_ip_buffer);
            cJSON_AddNumberToObject(destination, "port", packet_.dst_port);
            cJSON_AddStringToObject(destination, "mac", dst_mac_buffer);
            if (packet_.dst_hostname.size() > 0) {
                cJSON_AddStringToObject(destination, "hostname", dst_host_buffer);
            }
            cJSON_AddItemToObject(packet, "destination", destination);
        }

        // Raw data
        if (packet_.raw_data.size > 0) {
            cJSON* raw_data = cJSON_CreateObject();
            if (raw_data) {
                char hex_buffer[512];
                size_t hex_size = std::min(packet_.raw_data.hex.size(), sizeof(hex_buffer) - 1);
                std::memcpy(hex_buffer, packet_.raw_data.hex.data(), hex_size);
                hex_buffer[hex_size] = '\0';

                cJSON_AddStringToObject(raw_data, "hex", hex_buffer);
                cJSON_AddNumberToObject(raw_data, "size", packet_.raw_data.size);
                cJSON_AddItemToObject(packet, "raw_data", raw_data);
            }
        }

        // Parsed data
        if (packet_.parsed_data) {
            cJSON* parsed_copy = cJSON_Duplicate(packet_.parsed_data, 1);
            if (parsed_copy) {
                cJSON_AddItemToObject(packet, "parsed_data", parsed_copy);
            }
        }

        cJSON_AddItemToObject(root, "packet", packet);
    }

    // Context information
    cJSON* context = cJSON_CreateObject();
    if (context) {
        cJSON_AddNumberToObject(context, "baseline_deviation", context_.baseline_deviation);

        cJSON* frequency = cJSON_CreateObject();
        if (frequency) {
            cJSON_AddNumberToObject(frequency, "requests_per_second", context_.requests_per_second);
            cJSON_AddNumberToObject(frequency, "typical_rate", context_.typical_rate);
            cJSON_AddNumberToObject(frequency, "deviation_factor", context_.deviation_factor);
            cJSON_AddItemToObject(context, "frequency_analysis", frequency);
        }

        // Related events array
        if (!context_.related_events.empty()) {
            cJSON* related = cJSON_CreateArray();
            if (related) {
                for (const auto& event : context_.related_events) {
                    char event_buffer[64];
                    size_t event_size = std::min(event.size(), sizeof(event_buffer) - 1);
                    std::memcpy(event_buffer, event.data(), event_size);
                    event_buffer[event_size] = '\0';
                    cJSON_AddItemToArray(related, cJSON_CreateString(event_buffer));
                }
                cJSON_AddItemToObject(context, "related_events", related);
            }
        }

        if (context_.attack_pattern.size() > 0) {
            char pattern_buffer[64];
            size_t pattern_size = std::min(context_.attack_pattern.size(), sizeof(pattern_buffer) - 1);
            std::memcpy(pattern_buffer, context_.attack_pattern.data(), pattern_size);
            pattern_buffer[pattern_size] = '\0';
            cJSON_AddStringToObject(context, "attack_pattern", pattern_buffer);
        }

        cJSON_AddItemToObject(root, "context", context);
    }

    // Action taken
    if (action_taken_.size() > 0) {
        char action_buffer[64];
        size_t action_size = std::min(action_taken_.size(), sizeof(action_buffer) - 1);
        std::memcpy(action_buffer, action_taken_.data(), action_size);
        action_buffer[action_size] = '\0';
        cJSON_AddStringToObject(root, "action_taken", action_buffer);
    }

    psram_string result = jsonToString(root);
    cJSON_Delete(root);
    return result;
}

// WhitelistViolationReportBuilder implementation
WhitelistViolationReportBuilder::WhitelistViolationReportBuilder() {
    event_type_ = PSRAMUtils::createPSRAMString("whitelist_violation");
    module_name_ = PSRAMUtils::createPSRAMString("whitelist_manager");
}

void WhitelistViolationReportBuilder::setViolationInfo(const ViolationInfo& violation) {
    violation_ = violation;
}

void WhitelistViolationReportBuilder::setPacketInfo(const IDSDetectionReportBuilder::PacketInfo& packet) {
    packet_ = const_cast<IDSDetectionReportBuilder::PacketInfo&&>(packet);
}

void WhitelistViolationReportBuilder::setWhitelistCheck(const WhitelistCheck& check) {
    whitelist_check_ = check;
}

void WhitelistViolationReportBuilder::setActionTaken(const psram_string& action) {
    action_taken_ = action;
}

psram_string WhitelistViolationReportBuilder::build() {
    cJSON* root = createBaseStructure();
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    // Violation information
    cJSON* violation = cJSON_CreateObject();
    if (violation) {
        char id_buffer[64], type_buffer[64], name_buffer[128], severity_buffer[16];

        size_t id_size = std::min(violation_.violation_id.size(), sizeof(id_buffer) - 1);
        size_t type_size = std::min(violation_.violation_type.size(), sizeof(type_buffer) - 1);
        size_t name_size = std::min(violation_.whitelist_name.size(), sizeof(name_buffer) - 1);
        size_t severity_size = std::min(violation_.severity.size(), sizeof(severity_buffer) - 1);

        std::memcpy(id_buffer, violation_.violation_id.data(), id_size);
        id_buffer[id_size] = '\0';
        std::memcpy(type_buffer, violation_.violation_type.data(), type_size);
        type_buffer[type_size] = '\0';
        std::memcpy(name_buffer, violation_.whitelist_name.data(), name_size);
        name_buffer[name_size] = '\0';
        std::memcpy(severity_buffer, violation_.severity.data(), severity_size);
        severity_buffer[severity_size] = '\0';

        cJSON_AddStringToObject(violation, "violation_id", id_buffer);
        cJSON_AddStringToObject(violation, "violation_type", type_buffer);
        cJSON_AddStringToObject(violation, "whitelist_name", name_buffer);
        cJSON_AddStringToObject(violation, "severity", severity_buffer);

        cJSON_AddItemToObject(root, "violation", violation);
    }

    // Packet information (reuse the same structure as IDS)
    cJSON* packet = cJSON_CreateObject();
    if (packet) {
        char dir_buffer[16], src_ip_buffer[64], dst_ip_buffer[64], protocol_buffer[32];

        size_t dir_size = std::min(packet_.direction.size(), sizeof(dir_buffer) - 1);
        size_t src_ip_size = std::min(packet_.src_ip.size(), sizeof(src_ip_buffer) - 1);
        size_t dst_ip_size = std::min(packet_.dst_ip.size(), sizeof(dst_ip_buffer) - 1);
        size_t protocol_size = std::min(packet_.protocol.size(), sizeof(protocol_buffer) - 1);

        std::memcpy(dir_buffer, packet_.direction.data(), dir_size);
        dir_buffer[dir_size] = '\0';
        std::memcpy(src_ip_buffer, packet_.src_ip.data(), src_ip_size);
        src_ip_buffer[src_ip_size] = '\0';
        std::memcpy(dst_ip_buffer, packet_.dst_ip.data(), dst_ip_size);
        dst_ip_buffer[dst_ip_size] = '\0';
        std::memcpy(protocol_buffer, packet_.protocol.data(), protocol_size);
        protocol_buffer[protocol_size] = '\0';

        cJSON_AddStringToObject(packet, "direction", dir_buffer);
        cJSON_AddStringToObject(packet, "protocol", protocol_buffer);

        // Source and destination (simplified for whitelist violation)
        cJSON* source = cJSON_CreateObject();
        if (source) {
            cJSON_AddStringToObject(source, "ip", src_ip_buffer);
            cJSON_AddNumberToObject(source, "port", packet_.src_port);
            cJSON_AddItemToObject(packet, "source", source);
        }

        cJSON* destination = cJSON_CreateObject();
        if (destination) {
            cJSON_AddStringToObject(destination, "ip", dst_ip_buffer);
            cJSON_AddNumberToObject(destination, "port", packet_.dst_port);
            cJSON_AddItemToObject(packet, "destination", destination);
        }

        cJSON_AddItemToObject(root, "packet", packet);
    }

    // Whitelist check results
    cJSON* check = cJSON_CreateObject();
    if (check) {
        cJSON_AddBoolToObject(check, "ip_allowed", whitelist_check_.ip_allowed);
        cJSON_AddBoolToObject(check, "mac_allowed", whitelist_check_.mac_allowed);
        cJSON_AddBoolToObject(check, "protocol_allowed", whitelist_check_.protocol_allowed);
        cJSON_AddBoolToObject(check, "port_allowed", whitelist_check_.port_allowed);
        cJSON_AddBoolToObject(check, "function_allowed", whitelist_check_.function_allowed);

        if (whitelist_check_.failed_check.size() > 0) {
            char failed_buffer[64];
            size_t failed_size = std::min(whitelist_check_.failed_check.size(), sizeof(failed_buffer) - 1);
            std::memcpy(failed_buffer, whitelist_check_.failed_check.data(), failed_size);
            failed_buffer[failed_size] = '\0';
            cJSON_AddStringToObject(check, "failed_check", failed_buffer);
        }

        // Expected IPs array
        if (!whitelist_check_.expected_ips.empty()) {
            cJSON* expected_ips = cJSON_CreateArray();
            if (expected_ips) {
                for (const auto& ip : whitelist_check_.expected_ips) {
                    char ip_buffer[64];
                    size_t ip_size = std::min(ip.size(), sizeof(ip_buffer) - 1);
                    std::memcpy(ip_buffer, ip.data(), ip_size);
                    ip_buffer[ip_size] = '\0';
                    cJSON_AddItemToArray(expected_ips, cJSON_CreateString(ip_buffer));
                }
                cJSON_AddItemToObject(check, "expected_ips", expected_ips);
            }
        }

        cJSON_AddItemToObject(root, "whitelist_check", check);
    }

    // Action taken
    if (action_taken_.size() > 0) {
        char action_buffer[64];
        size_t action_size = std::min(action_taken_.size(), sizeof(action_buffer) - 1);
        std::memcpy(action_buffer, action_taken_.data(), action_size);
        action_buffer[action_size] = '\0';
        cJSON_AddStringToObject(root, "action_taken", action_buffer);
    }

    psram_string result = jsonToString(root);
    cJSON_Delete(root);
    return result;
}
