#include "signature_detector.h"
#include "../core/logging_system.h"
#include "../core/async_storage_engine.h"
#include "../core/psram_json_parser.h"
#include "../core/psram_allocator.h"
#include "../core/plugin_manager.h"
#include "esp_heap_caps.h"
#include <cJSON.h>

namespace SignatureDetection {

static const char* TAG = "SIG_DETECT";

// NVS key for signature database
static const char* NVS_SIGNATURES_KEY = "signatures_db";
static const char* NVS_NAMESPACE = "signatures";

// NVS chunk size (must be < 4000 bytes to fit in NVS)
constexpr size_t NVS_CHUNK_SIZE = 3800;

// Helper: Load chunked string from NVS
static esp_err_t loadChunkedFromNVS(const char* ns, const char* base_key, psram_string& output) {
    // Load chunk count - NVS key limit is 15 chars
    char meta_key[16];
    snprintf(meta_key, sizeof(meta_key), "sig_cnt");

    uint32_t num_chunks = 0;
    esp_err_t err = AsyncStorage::Global::nvsGet(ns, meta_key, num_chunks);
    if (err != ESP_OK) return err;

    if (num_chunks == 0) return ESP_ERR_NOT_FOUND;

    // Pre-allocate approximate size
    output.clear();
    output.reserve(num_chunks * NVS_CHUNK_SIZE);

    // Load and concatenate chunks
    for (uint32_t i = 0; i < num_chunks; ++i) {
        char chunk_key[16];
        snprintf(chunk_key, sizeof(chunk_key), "sig_%lu", (unsigned long)i);

        psram_string chunk;
        err = AsyncStorage::Global::nvsGet(ns, chunk_key, chunk);
        if (err != ESP_OK) {
            output.clear();
            return err;
        }
        output += chunk;
    }

    return ESP_OK;
}

SignatureDetector::SignatureDetector() : total_signatures_(0) {
    // Constructor intentionally minimal - all allocation in initialize()
}

SignatureDetector& SignatureDetector::getInstance() {
    static SignatureDetector instance;
    return instance;
}

void SignatureDetector::setEnabled(bool enabled) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    enabled_.store(enabled, std::memory_order_release);
}

bool SignatureDetector::initialize() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    LOG_INFO(TAG, "Initializing signature detector...");

    // Clear any existing data
    clearSignatures();

    // Load signatures from NVS
    if (!loadSignaturesFromNVS()) {
        LOG_WARNING(TAG, "No signatures loaded from NVS - detection disabled");
        return true; // Not a fatal error, system can work without signatures
    }

    LOG_INFOF(TAG, "✅ Signature detector initialized with %lu signatures", (unsigned long)total_signatures_);
    return true;
}

bool SignatureDetector::reloadSignatures() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    LOG_INFO(TAG, "Hot-reloading signatures from NVS...");

    // Clear current signatures
    clearSignatures();

    // Reload from NVS
    bool success = loadSignaturesFromNVS();

    if (success) {
        LOG_INFOF(TAG, "✅ Signatures reloaded: %lu total", (unsigned long)total_signatures_);
    } else {
        LOG_ERROR(TAG, "❌ Failed to reload signatures");
    }

    return success;
}

DetectionResult SignatureDetector::analyzePacket(const uint8_t* payload, size_t payload_len, ProtocolType protocol) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DetectionResult result;

    if (!isEnabled() || !payload || payload_len == 0) {
        return result;
    }

    // Find signatures for this protocol
    auto it = signatures_.find(protocol);
    if (it == signatures_.end()) {
        return result; // No signatures for this protocol
    }

    const SignatureVector& protocol_signatures = it->second;

    // Check each signature against the payload
    for (const auto& sig : protocol_signatures) {
        uint32_t match_offset = 0;
        if (matchPattern(payload, payload_len, sig, &match_offset)) {
            // Pattern matched!
            result.detected = true;
            strncpy(result.cve_id, sig.cve_id, sizeof(result.cve_id) - 1);
            result.cve_id[sizeof(result.cve_id) - 1] = '\0';
            result.protocol = protocol;
            result.offset = match_offset;
            return result;
        }
    }

    return result; // No match found
}

DetectionResult SignatureDetector::analyzePacketWithReport(const NetworkPacket& packet, psram_string& threat_report_json) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DetectionResult result = analyzePacket(packet.data, packet.length, packet.proto);
    threat_report_json.clear();

    if (result.detected) {
        // Create detailed threat report JSON
        cJSON* report = cJSON_CreateObject();
        if (!report) {
            LOG_ERROR(TAG, "Failed to create threat report JSON");
            return result;
        }

        // Basic threat information
        cJSON_AddStringToObject(report, "event_type", "threat_detected");
        cJSON_AddStringToObject(report, "cve_id", result.cve_id);
        cJSON_AddStringToObject(report, "protocol", PluginManager::protocolTypeToString(result.protocol));
        cJSON_AddNumberToObject(report, "detection_offset", result.offset);
        cJSON_AddNumberToObject(report, "timestamp_ms", packet.ts_ms);

        // Network information
        cJSON* network = cJSON_CreateObject();
        if (network) {
            cJSON_AddStringToObject(network, "src_ip", packet.src_ip.c_str());
            cJSON_AddStringToObject(network, "dst_ip", packet.dst_ip.c_str());
            cJSON_AddNumberToObject(network, "src_port", packet.src_port);
            cJSON_AddNumberToObject(network, "dst_port", packet.dst_port);

            // MAC addresses
            char src_mac_str[18], dst_mac_str[18];
            snprintf(src_mac_str, sizeof(src_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    packet.src_mac[0], packet.src_mac[1], packet.src_mac[2],
                    packet.src_mac[3], packet.src_mac[4], packet.src_mac[5]);
            snprintf(dst_mac_str, sizeof(dst_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    packet.dst_mac[0], packet.dst_mac[1], packet.dst_mac[2],
                    packet.dst_mac[3], packet.dst_mac[4], packet.dst_mac[5]);

            cJSON_AddStringToObject(network, "src_mac", src_mac_str);
            cJSON_AddStringToObject(network, "dst_mac", dst_mac_str);
            cJSON_AddStringToObject(network, "transport_protocol", packet.is_tcp ? "TCP" : (packet.is_udp ? "UDP" : "Other"));

            cJSON_AddItemToObject(report, "network", network);
        }

        // Packet details
        cJSON* packet_info = cJSON_CreateObject();
        if (packet_info) {
            cJSON_AddNumberToObject(packet_info, "length", packet.length);
            cJSON_AddNumberToObject(packet_info, "ether_type", packet.ether_type);

            // Preserve the complete captured buffer for incident review.  The
            // packet object is the ingress snapshot available to the detector;
            // it does not include an Ethernet FCS that the MAC may strip.
            constexpr size_t kMaxReportBytes = 16384;
            const size_t captured_len = (packet.data && packet.length <= kMaxReportBytes)
                ? packet.length : (packet.data ? kMaxReportBytes : 0);
            cJSON_AddNumberToObject(packet_info, "captured_length", captured_len);
            cJSON_AddBoolToObject(packet_info, "capture_complete",
                                  packet.data && packet.length <= kMaxReportBytes);
            cJSON_AddStringToObject(packet_info, "capture_scope", "network_packet_data");
            if (captured_len > 0) {
                char* full_hex = static_cast<char*>(heap_caps_malloc(
                    captured_len * 2 + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
                if (full_hex) {
                    for (size_t i = 0; i < captured_len; ++i) {
                        snprintf(&full_hex[i * 2], 3, "%02X", packet.data[i]);
                    }
                    full_hex[captured_len * 2] = '\0';
                    cJSON_AddStringToObject(packet_info, "payload_hex", full_hex);
                    heap_caps_free(full_hex);
                }
            }

            // Add first 64 bytes of payload as hex for analysis
            size_t hex_len = (captured_len > 64) ? 64 : captured_len;
            char* hex_payload = (char*)heap_caps_malloc(hex_len * 2 + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (hex_payload && packet.data) {
                for (size_t i = 0; i < hex_len; i++) {
                    sprintf(&hex_payload[i * 2], "%02X", packet.data[i]);
                }
                hex_payload[hex_len * 2] = '\0';
                cJSON_AddStringToObject(packet_info, "payload_preview", hex_payload);
                heap_caps_free(hex_payload);
            }

            cJSON_AddItemToObject(report, "packet", packet_info);
        }

        // CVE details placeholder (can be expanded with vulnerability database)
        cJSON* cve_details = cJSON_CreateObject();
        if (cve_details) {
            cJSON_AddStringToObject(cve_details, "description", "Malicious signature pattern detected");
            cJSON_AddStringToObject(cve_details, "severity", "HIGH");
            cJSON_AddStringToObject(cve_details, "impact", "Potential system compromise or data exfiltration");
            cJSON_AddItemToObject(report, "cve_details", cve_details);
        }

        // Security context
        cJSON* security = cJSON_CreateObject();
        if (security) {
            cJSON_AddStringToObject(security, "threat_category", "Signature-based Detection");
            cJSON_AddStringToObject(security, "action_taken", "Alert Generated");
            cJSON_AddStringToObject(security, "recommendation", "Block traffic from source IP and investigate network activity");
            cJSON_AddItemToObject(report, "security", security);
        }

        // Convert to string
        char* json_string = cJSON_PrintUnformatted(report);
        if (json_string) {
            threat_report_json = PSRAMUtils::createPSRAMString(json_string);
            free(json_string);
        }

        cJSON_Delete(report);

        // Enhanced logging with key details
        LOG_WARNINGF(TAG, "🚨 THREAT DETECTED: %s in %s traffic, Source: %s:%d -> Destination: %s:%d, Detection offset: %lu bytes, Packet size: %lu bytes",
                    result.cve_id, PluginManager::protocolTypeToString(result.protocol),packet.src_ip.c_str(), packet.src_port, packet.dst_ip.c_str(), packet.dst_port,(unsigned long)result.offset, (unsigned long)packet.length);
    }

    return result;
}

uint32_t SignatureDetector::getTotalSignatures() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return total_signatures_;
}

uint32_t SignatureDetector::getSignaturesForProtocol(ProtocolType protocol) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = signatures_.find(protocol);
    return (it != signatures_.end()) ? it->second.size() : 0;
}

void SignatureDetector::clearSignatures() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    signatures_.clear();
    total_signatures_ = 0;
}

bool SignatureDetector::loadSignaturesFromNVS() {
    // Try to load signatures JSON from NVS using chunked method
    psram_string signatures_json;
    esp_err_t err = loadChunkedFromNVS(NVS_NAMESPACE, NVS_SIGNATURES_KEY, signatures_json);

    // Fallback to old non-chunked method if chunked fails
    if (err != ESP_OK) {
        err = AsyncStorage::Global::nvsGet(NVS_NAMESPACE, NVS_SIGNATURES_KEY, signatures_json);
    }

    if (err != ESP_OK) {
        LOG_INFOF(TAG, "No signatures found in NVS (first run) - creating default schema");

        // Create default schema with main protocol categories using PSRAM strings
        psram_string default_schema = PSRAMUtils::createPSRAMString(
            "{"
            "\"Modbus TCP\":{\"Vulnerabilities\":[]},"
            "\"S7 Comm\":{\"Vulnerabilities\":[]},"
            "\"PROFINET\":{\"Vulnerabilities\":[]},"
            "\"EtherNet/IP\":{\"Vulnerabilities\":[]},"
            "\"OPC UA\":{\"Vulnerabilities\":[]}"
            "}"
        );

        // Save default schema to NVS
        esp_err_t save_err = AsyncStorage::Global::nvsSet(NVS_NAMESPACE, NVS_SIGNATURES_KEY, default_schema);
        if (save_err != ESP_OK) {
            LOG_ERRORF(TAG, "Failed to save default schema to NVS: %s", esp_err_to_name(save_err));
            return false;
        }

        // Use the default schema for parsing
        signatures_json = default_schema;
        LOG_INFO(TAG, "Default signature schema created and saved to NVS");
    }

    if (signatures_json.empty()) {
        LOG_WARNING(TAG, "Empty signatures data in NVS");
        return false;
    }

    // Parse JSON using PSRAM-safe parser
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(signatures_json.c_str(), signatures_json.length());

    if (!root) {
        LOG_ERROR(TAG, "Failed to parse signatures JSON");
        return false;
    }

    // Parse each protocol section
    uint32_t loaded_count = 0;

    // Modbus TCP
    cJSON* modbus = cJSON_GetObjectItem(root, "Modbus TCP");
    if (modbus) {
        loaded_count += parseProtocolSignatures(modbus, ProtocolType::MODBUS_TCP);
    }

    // PROFINET
    cJSON* profinet = cJSON_GetObjectItem(root, "PROFINET");
    if (profinet) {
        loaded_count += parseProtocolSignatures(profinet, ProtocolType::PROFINET);
    }

    // S7comm
    cJSON* s7comm = cJSON_GetObjectItem(root, "S7comm/S7comm+");
    if (s7comm) {
        loaded_count += parseProtocolSignatures(s7comm, ProtocolType::S7_COMM);
    }

    // OPC UA
    cJSON* opcua = cJSON_GetObjectItem(root, "OPC UA");
    if (opcua) {
        loaded_count += parseProtocolSignatures(opcua, ProtocolType::OPC_UA);
    }

    // EtherNet/IP
    cJSON* enip = cJSON_GetObjectItem(root, "EtherNet/IP");
    if (enip) {
        loaded_count += parseProtocolSignatures(enip, ProtocolType::ETHERNET_IP);
    }

    cJSON_Delete(root);
    total_signatures_ = loaded_count;

    LOG_INFOF(TAG, "Loaded %lu signatures from NVS", (unsigned long)loaded_count);
    return loaded_count > 0;
}

uint32_t SignatureDetector::parseProtocolSignatures(cJSON* protocol_obj, ProtocolType protocol) {
    if (!protocol_obj || !cJSON_IsObject(protocol_obj)) {
        return 0;
    }

    cJSON* vulnerabilities = cJSON_GetObjectItem(protocol_obj, "Vulnerabilities");
    if (!vulnerabilities || !cJSON_IsArray(vulnerabilities)) {
        return 0;
    }

    SignatureVector protocol_signatures;
    uint32_t count = 0;

    cJSON* vuln = nullptr;
    cJSON_ArrayForEach(vuln, vulnerabilities) {
        if (count >= MAX_SIGNATURES_PER_PROTOCOL) {
            LOG_WARNINGF(TAG, "Reached max signatures limit for protocol %s", PluginManager::protocolTypeToString(protocol));
            break;
        }

        // Extract CVE (required)
        cJSON* cve = cJSON_GetObjectItem(vuln, "CVE");
        if (!cve || !cJSON_IsString(cve)) continue;

        // Extract packet info (required)
        cJSON* packet = cJSON_GetObjectItem(vuln, "Packet");
        if (!packet || !cJSON_IsObject(packet)) continue;

        cJSON* bytes = cJSON_GetObjectItem(packet, "Bytes");
        if (!bytes || !cJSON_IsString(bytes)) continue;

        // Create signature entry
        SignatureEntry sig;
        sig.protocol = protocol;

        // Copy CVE ID
        strncpy(sig.cve_id, cve->valuestring, sizeof(sig.cve_id) - 1);
        sig.cve_id[sizeof(sig.cve_id) - 1] = '\0';

        // Extract optional Name field
        cJSON* name = cJSON_GetObjectItem(vuln, "Name");
        if (name && cJSON_IsString(name)) {
            strncpy(sig.name, name->valuestring, sizeof(sig.name) - 1);
            sig.name[sizeof(sig.name) - 1] = '\0';
        }

        // Extract optional Description from Packet or root level
        cJSON* description = cJSON_GetObjectItem(packet, "Description");
        if (!description) {
            description = cJSON_GetObjectItem(vuln, "Description");
        }
        if (description && cJSON_IsString(description)) {
            strncpy(sig.description, description->valuestring, sizeof(sig.description) - 1);
            sig.description[sizeof(sig.description) - 1] = '\0';
        }

        // Extract optional FunctionCode
        cJSON* function_code = cJSON_GetObjectItem(packet, "FunctionCode");
        if (function_code && cJSON_IsString(function_code)) {
            strncpy(sig.function_code, function_code->valuestring, sizeof(sig.function_code) - 1);
            sig.function_code[sizeof(sig.function_code) - 1] = '\0';
        }

        // Extract optional References array
        cJSON* references = cJSON_GetObjectItem(vuln, "References");
        if (references && cJSON_IsArray(references)) {
            cJSON* ref = nullptr;
            sig.num_references = 0;
            cJSON_ArrayForEach(ref, references) {
                if (sig.num_references >= MAX_REFERENCES) break;
                if (cJSON_IsString(ref)) {
                    strncpy(sig.references[sig.num_references], ref->valuestring, MAX_REFERENCE_LEN - 1);
                    sig.references[sig.num_references][MAX_REFERENCE_LEN - 1] = '\0';
                    sig.num_references++;
                }
            }
        }

        // Parse hex bytes
        if (parseSignatureBytes(bytes->valuestring, sig.pattern, &sig.pattern_length)) {
            // Determine pattern type (exact vs prefix)
            const char* byte_str = bytes->valuestring;
            sig.type = (strstr(byte_str, "...") != nullptr) ? PatternType::PREFIX_MATCH : PatternType::EXACT_MATCH;

            // Check PSRAM availability before adding signature
            size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            if (psram_free < 2048) { // Need at least 2KB for larger signature structure
                LOG_WARNINGF(TAG, "⚠️  PSRAM almost full (%u bytes) - skipping signature %s",
                           (unsigned)psram_free, sig.cve_id);
                break;
            }

            protocol_signatures.push_back(sig);
            count++;

            LOG_INFOF(TAG, "Loaded signature %s: %s (%s, %d bytes)",
                     sig.cve_id,
                     sig.name[0] ? sig.name : "No name",
                     (sig.type == PatternType::EXACT_MATCH) ? "exact" : "prefix",
                     sig.pattern_length);
        }
    }

    if (count > 0) {
        signatures_[protocol] = std::move(protocol_signatures);
    }

    return count;
}

bool SignatureDetector::parseSignatureBytes(const char* hex_string, uint8_t* output, uint8_t* length) {
    if (!hex_string || !output || !length) {
        return false;
    }

    *length = 0;
    const char* pos = hex_string;

    // Skip whitespace
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r')) {
        pos++;
    }

    while (*pos && *length < MAX_SIGNATURE_BYTES) {
        // Skip whitespace
        while (*pos && (*pos == ' ' || *pos == '\t')) {
            pos++;
        }

        if (!*pos) break;

        // Check for "..." terminator (prefix match indicator)
        if (strncmp(pos, "...", 3) == 0) {
            break;
        }

        // Parse hex byte (two characters)
        if (!isValidHexChar(pos[0]) || !isValidHexChar(pos[1])) {
            break;
        }

        uint8_t byte_val = (hexCharToValue(pos[0]) << 4) | hexCharToValue(pos[1]);
        output[*length] = byte_val;
        (*length)++;
        pos += 2;
    }

    return (*length > 0);
}

bool SignatureDetector::matchPattern(const uint8_t* payload, size_t payload_len, const SignatureEntry& sig, uint32_t* offset) {
    if (!payload || payload_len == 0 || sig.pattern_length == 0) {
        return false;
    }

    // Search for pattern in payload
    for (size_t i = 0; i <= payload_len - sig.pattern_length; i++) {
        bool match = true;

        // Compare pattern bytes
        for (uint8_t j = 0; j < sig.pattern_length; j++) {
            if (payload[i + j] != sig.pattern[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            if (offset) *offset = i;
            return true;
        }
    }

    return false;
}

bool SignatureDetector::isValidHexChar(char c) {
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f'));
}

uint8_t SignatureDetector::hexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

} // namespace SignatureDetection
