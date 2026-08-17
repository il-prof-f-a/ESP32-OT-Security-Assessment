#include "protocol_baseline.h"
#include "../core/logging_system.h"
#include "../core/psram_json_parser.h"
#include "../core/filesystem_task_delegate.h"
#include <cmath>
#include <cstring>

extern "C" {
    #include "esp_timer.h"
}

static const char* TAG = "BaselineMgr";

// Helper for anomaly type names
static const char* getAnomalyTypeName(AnomalyType type) {
    switch (type) {
        case AnomalyType::NONE: return "NONE";
        case AnomalyType::UNUSUAL_TRAFFIC_RATE: return "UNUSUAL_TRAFFIC_RATE";
        case AnomalyType::EXCESSIVE_ERRORS: return "EXCESSIVE_ERRORS";
        case AnomalyType::FLOODING: return "FLOODING";
        case AnomalyType::UNEXPECTED_WRITER: return "UNEXPECTED_WRITER";
        case AnomalyType::UNUSUAL_PEER: return "UNUSUAL_PEER";
        case AnomalyType::STATE_VIOLATION: return "STATE_VIOLATION";
        case AnomalyType::OPERATION_SEQUENCE_ANOMALY: return "OPERATION_SEQUENCE_ANOMALY";
        case AnomalyType::TRAFFIC_AT_UNUSUAL_TIME: return "TRAFFIC_AT_UNUSUAL_TIME";
        case AnomalyType::SUDDEN_TRAFFIC_SPIKE: return "SUDDEN_TRAFFIC_SPIKE";
        case AnomalyType::MALFORMED_PATTERN: return "MALFORMED_PATTERN";
        case AnomalyType::PROTOCOL_DOWNGRADE: return "PROTOCOL_DOWNGRADE";
        case AnomalyType::RECONNAISSANCE: return "RECONNAISSANCE";
        case AnomalyType::PRIVILEGE_ESCALATION: return "PRIVILEGE_ESCALATION";
        case AnomalyType::DATA_EXFILTRATION: return "DATA_EXFILTRATION";
        default: return "UNKNOWN";
    }
}

ProtocolBaselineManager::ProtocolBaselineManager() {
}

bool ProtocolBaselineManager::initialize(ProtocolType protocol) {
    baseline_.protocol = protocol;
    baseline_.learning_enabled = true;

    LOG_INFOF(TAG, "Baseline manager initialized for protocol %d", (int)protocol);
    return true;
}

bool ProtocolBaselineManager::loadBaseline(const char* filepath) {
    // Use FilesystemTaskDelegate to read from flash (safe from PSRAM task)
    auto& fs = FilesystemTaskDelegate::getInstance();
    if (!fs.isReady()) {
        LOG_WARNING(TAG, "FilesystemTaskDelegate not ready, cannot load baseline");
        return false;
    }

    psram_string file_content;
    if (!fs.readFileSync(std::string(filepath), file_content, 10000)) {
        LOG_WARNINGF(TAG, "Baseline file not found: %s (starting fresh)", filepath);
        return false;  // Not a critical error, we start from scratch
    }

    if (file_content.empty() || file_content.size() > 1024 * 1024) {
        LOG_ERRORF(TAG, "Invalid baseline file size: %zu", file_content.size());
        return false;
    }

    // Parse JSON using cJSON
    cJSON* root = cJSON_Parse(file_content.c_str());

    if (!root) {
        LOG_ERROR(TAG, "Failed to parse baseline JSON");
        return false;
    }

    // Load threshold configuration
    cJSON* item = cJSON_GetObjectItem(root, "pps_threshold_factor");
    if (item && cJSON_IsNumber(item)) baseline_.pps_threshold_factor = (float)item->valuedouble;

    item = cJSON_GetObjectItem(root, "error_rate_threshold");
    if (item && cJSON_IsNumber(item)) baseline_.error_rate_threshold = (float)item->valuedouble;

    item = cJSON_GetObjectItem(root, "peer_change_threshold");
    if (item && cJSON_IsNumber(item)) baseline_.peer_change_threshold = (float)item->valuedouble;

    item = cJSON_GetObjectItem(root, "min_learning_samples");
    if (item && cJSON_IsNumber(item)) baseline_.min_learning_samples = (uint32_t)item->valueint;

    item = cJSON_GetObjectItem(root, "total_flows");
    if (item && cJSON_IsNumber(item)) baseline_.total_flows = (uint64_t)item->valuedouble;

    item = cJSON_GetObjectItem(root, "total_packets");
    if (item && cJSON_IsNumber(item)) baseline_.total_packets = (uint64_t)item->valuedouble;

    // Load endpoints
    cJSON* endpoints_obj = cJSON_GetObjectItem(root, "endpoints");
    if (endpoints_obj) {
        cJSON* endpoints_array = cJSON_GetObjectItem(endpoints_obj, "list");
        if (endpoints_array && cJSON_IsArray(endpoints_array)) {
            cJSON* ep_node = NULL;
            cJSON_ArrayForEach(ep_node, endpoints_array) {
                EndpointBaseline ep;

                cJSON* ip_item = cJSON_GetObjectItem(ep_node, "ip");
                if (ip_item && cJSON_IsString(ip_item)) {
                    ep.ip_address = PSRAMUtils::createPSRAMString(ip_item->valuestring);
                }

                cJSON* mac_item = cJSON_GetObjectItem(ep_node, "mac");
                if (mac_item && cJSON_IsString(mac_item)) {
                    ep.mac_address = PSRAMUtils::createPSRAMString(mac_item->valuestring);
                }

                #define GET_INT_FIELD(field, json_name) do { \
                    cJSON* f = cJSON_GetObjectItem(ep_node, json_name); \
                    if (f && cJSON_IsNumber(f)) ep.field = (uint64_t)f->valuedouble; \
                } while(0)

                #define GET_UINT_FIELD(field, json_name) do { \
                    cJSON* f = cJSON_GetObjectItem(ep_node, json_name); \
                    if (f && cJSON_IsNumber(f)) ep.field = (uint32_t)f->valueint; \
                } while(0)

                #define GET_FLOAT_FIELD(field, json_name) do { \
                    cJSON* f = cJSON_GetObjectItem(ep_node, json_name); \
                    if (f && cJSON_IsNumber(f)) ep.field = (float)f->valuedouble; \
                } while(0)

                #define GET_BOOL_FIELD(field, json_name) do { \
                    cJSON* f = cJSON_GetObjectItem(ep_node, json_name); \
                    if (f && cJSON_IsBool(f)) ep.field = cJSON_IsTrue(f); \
                } while(0)

                GET_INT_FIELD(total_packets, "total_packets");
                GET_INT_FIELD(total_bytes, "total_bytes");
                GET_UINT_FIELD(read_operations, "read_ops");
                GET_UINT_FIELD(write_operations, "write_ops");
                GET_UINT_FIELD(control_operations, "control_ops");
                GET_UINT_FIELD(diagnostic_operations, "diagnostic_ops");
                GET_UINT_FIELD(error_responses, "error_responses");
                GET_FLOAT_FIELD(normal_error_rate, "normal_error_rate");
                GET_UINT_FIELD(normal_states_bitmap, "states_bitmap");
                GET_FLOAT_FIELD(avg_pps, "avg_pps");
                GET_FLOAT_FIELD(max_pps, "max_pps");
                GET_INT_FIELD(first_seen_ms, "first_seen_ms");
                GET_INT_FIELD(last_updated_ms, "last_updated_ms");
                GET_UINT_FIELD(learning_samples, "learning_samples");
                GET_BOOL_FIELD(is_writer, "is_writer");
                GET_BOOL_FIELD(learning_complete, "learning_complete");

                // Load known_peers
                cJSON* peers_array = cJSON_GetObjectItem(ep_node, "known_peers");
                if (peers_array && cJSON_IsArray(peers_array)) {
                    cJSON* peer_item = NULL;
                    cJSON_ArrayForEach(peer_item, peers_array) {
                        if (cJSON_IsString(peer_item)) {
                            ep.known_peers.push_back(PSRAMUtils::createPSRAMString(peer_item->valuestring));
                        }
                    }
                }

                // Add endpoint to the map
                baseline_.endpoints[ep.ip_address] = ep;
            }
        }
    }

    cJSON_Delete(root);

    LOG_INFOF(TAG, "Loaded baseline from %s (%zu endpoints)", filepath, baseline_.endpoints.size());
    return true;
}

bool ProtocolBaselineManager::saveBaseline(const char* filepath) {
    // Build JSON manually (more efficient than cJSON for large structures)
    // Allocate output buffer in PSRAM
    const size_t BUFFER_SIZE = 256 * 1024;  // 256KB buffer
    char* json_buf = (char*)heap_caps_malloc(BUFFER_SIZE, MALLOC_CAP_SPIRAM);
    if (!json_buf) {
        LOG_ERROR(TAG, "Failed to allocate buffer for baseline JSON");
        return false;
    }

    size_t offset = 0;

    // Header JSON
    offset += snprintf(json_buf + offset, BUFFER_SIZE - offset,
        "{\n"
        "  \"protocol\": %d,\n"
        "  \"pps_threshold_factor\": %.2f,\n"
        "  \"error_rate_threshold\": %.2f,\n"
        "  \"peer_change_threshold\": %.2f,\n"
        "  \"min_learning_samples\": %lu,\n"
        "  \"total_flows\": %llu,\n"
        "  \"total_packets\": %llu,\n"
        "  \"endpoints\": {\n"
        "    \"list\": [\n",
        (int)baseline_.protocol,
        baseline_.pps_threshold_factor,
        baseline_.error_rate_threshold,
        baseline_.peer_change_threshold,
        (unsigned long)baseline_.min_learning_samples,
        baseline_.total_flows,
        baseline_.total_packets
    );

    // Serialize each endpoint
    bool first_endpoint = true;
    for (const auto& pair : baseline_.endpoints) {
        const EndpointBaseline& ep = pair.second;

        if (!first_endpoint) {
            offset += snprintf(json_buf + offset, BUFFER_SIZE - offset, ",\n");
        }
        first_endpoint = false;

        // Convert IP and MAC from PSRAM to a normal string
        std::string ip_str = PSRAMUtils::fromPSRAMString(ep.ip_address);
        std::string mac_str = PSRAMUtils::fromPSRAMString(ep.mac_address);

        offset += snprintf(json_buf + offset, BUFFER_SIZE - offset,
            "      {\n"
            "        \"ip\": \"%s\",\n"
            "        \"mac\": \"%s\",\n"
            "        \"total_packets\": %llu,\n"
            "        \"total_bytes\": %llu,\n"
            "        \"read_ops\": %lu,\n"
            "        \"write_ops\": %lu,\n"
            "        \"control_ops\": %lu,\n"
            "        \"diagnostic_ops\": %lu,\n"
            "        \"error_responses\": %lu,\n"
            "        \"normal_error_rate\": %.4f,\n"
            "        \"states_bitmap\": %u,\n"
            "        \"avg_pps\": %.2f,\n"
            "        \"max_pps\": %.2f,\n"
            "        \"first_seen_ms\": %llu,\n"
            "        \"last_updated_ms\": %llu,\n"
            "        \"learning_samples\": %lu,\n"
            "        \"is_writer\": %s,\n"
            "        \"learning_complete\": %s,\n"
            "        \"known_peers\": [",
            ip_str.c_str(),
            mac_str.c_str(),
            ep.total_packets,
            ep.total_bytes,
            (unsigned long)ep.read_operations,
            (unsigned long)ep.write_operations,
            (unsigned long)ep.control_operations,
            (unsigned long)ep.diagnostic_operations,
            (unsigned long)ep.error_responses,
            ep.normal_error_rate,
            ep.normal_states_bitmap,
            ep.avg_pps,
            ep.max_pps,
            ep.first_seen_ms,
            ep.last_updated_ms,
            (unsigned long)ep.learning_samples,
            ep.is_writer ? "true" : "false",
            ep.learning_complete ? "true" : "false"
        );

        // Serialize known_peers
        bool first_peer = true;
        for (const auto& peer : ep.known_peers) {
            if (!first_peer) {
                offset += snprintf(json_buf + offset, BUFFER_SIZE - offset, ", ");
            }
            first_peer = false;

            std::string peer_str = PSRAMUtils::fromPSRAMString(peer);
            offset += snprintf(json_buf + offset, BUFFER_SIZE - offset, "\"%s\"", peer_str.c_str());

            // Check buffer overflow
            if (offset >= BUFFER_SIZE - 1024) {
                LOG_ERROR(TAG, "JSON buffer overflow during baseline save");
                heap_caps_free(json_buf);
                return false;
            }
        }

        offset += snprintf(json_buf + offset, BUFFER_SIZE - offset, "]\n      }");
    }

    // Close JSON
    offset += snprintf(json_buf + offset, BUFFER_SIZE - offset,
        "\n    ]\n"
        "  }\n"
        "}\n"
    );

    // Write to file via FilesystemTaskDelegate (safe from PSRAM task)
    auto& fs = FilesystemTaskDelegate::getInstance();
    if (!fs.isReady()) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not ready, cannot save baseline");
        heap_caps_free(json_buf);
        return false;
    }

    psram_string content(json_buf, offset);
    heap_caps_free(json_buf);

    if (!fs.writeFileSync(std::string(filepath), content, 10000)) {
        LOG_ERRORF(TAG, "Failed to write baseline file: %s", filepath);
        return false;
    }

    baseline_.last_saved_ms = esp_timer_get_time() / 1000;
    LOG_INFOF(TAG, "Saved baseline to %s (%zu bytes, %zu endpoints)",
              filepath, offset, baseline_.endpoints.size());
    return true;
}

bool ProtocolBaselineManager::updateBaseline(const psram_string& endpoint_ip,
                                             const psram_string& mac_address,
                                             uint32_t packet_size,
                                             const psram_string& operation_type,
                                             bool is_error,
                                             FlowState current_state,
                                             const psram_string& peer_ip) {
    if (!baseline_.learning_enabled) {
        return false;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;

    // Get or create baseline endpoint
    auto it = baseline_.endpoints.find(endpoint_ip);
    if (it == baseline_.endpoints.end()) {
        EndpointBaseline new_baseline;
        new_baseline.ip_address = endpoint_ip;
        new_baseline.mac_address = mac_address;
        new_baseline.first_seen_ms = now_ms;
        baseline_.endpoints[endpoint_ip] = new_baseline;
        it = baseline_.endpoints.find(endpoint_ip);
    }

    EndpointBaseline& ep = it->second;
    bool learning_completed_now = false;
    bool was_learning = !ep.learning_complete;

    // Update counters
    ep.total_packets++;
    ep.total_bytes += packet_size;
    ep.last_updated_ms = now_ms;
    ep.learning_samples++;

    // Update operation distribution
    if (operation_type == "READ") {
        ep.read_operations++;
    } else if (operation_type == "WRITE") {
        ep.write_operations++;
        ep.is_writer = true;
    } else if (operation_type == "CONTROL") {
        ep.control_operations++;
    } else if (operation_type == "DIAGNOSTIC") {
        ep.diagnostic_operations++;
    }

    // Update error rate
    if (is_error) {
        ep.error_responses++;
    }
    if (ep.total_packets > 0) {
        ep.normal_error_rate = (float)ep.error_responses / (float)ep.total_packets;
    }

    // Update visited states (bitmap)
    if ((uint8_t)current_state < 16) {
        ep.normal_states_bitmap |= (1 << (uint8_t)current_state);
    }

    // Update known peers
    bool peer_known = false;
    for (const auto& known_peer : ep.known_peers) {
        if (known_peer == peer_ip) {
            peer_known = true;
            break;
        }
    }
    if (!peer_known && !peer_ip.empty()) {
        ep.known_peers.push_back(peer_ip);
    }

    // Calculate average rate (simplified - uses time window)
    if (ep.first_seen_ms > 0 && now_ms > ep.first_seen_ms) {
        uint64_t elapsed_s = (now_ms - ep.first_seen_ms) / 1000;
        if (elapsed_s > 0) {
            ep.avg_pps = (float)ep.total_packets / (float)elapsed_s;
        }
    }

    // Mark learning complete if minimum samples reached
    if (was_learning && ep.learning_samples >= baseline_.min_learning_samples) {
        ep.learning_complete = true;
        learning_completed_now = true;
        LOG_INFOF(TAG, "Baseline learning completed for %s",
                  PSRAMUtils::fromPSRAMString(endpoint_ip).c_str());
    }

    // Update global statistics
    baseline_.total_packets++;
    return learning_completed_now;
}

uint32_t ProtocolBaselineManager::detectAnomalies(const psram_string& endpoint_ip,
                                                  float current_pps,
                                                  float error_rate,
                                                  const psram_string& operation_type,
                                                  FlowState current_state,
                                                  const psram_string& peer_ip,
                                                  psram_vector<AnomalyDetection>& anomalies) {
    uint32_t detected = 0;
    PSRAMAllocator<char> alloc;

    // Find baseline endpoint
    auto it = baseline_.endpoints.find(endpoint_ip);
    if (it == baseline_.endpoints.end()) {
        // New endpoint - we have no baseline
        return 0;
    }

    const EndpointBaseline& ep = it->second;

    // If still learning, do not detect anomalies
    if (!ep.learning_complete) {
        return 0;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;

    // 1. Anomaly: Unusual traffic rate
    if (ep.avg_pps > 0) {
        float threshold_high = ep.avg_pps * baseline_.pps_threshold_factor;
        float threshold_low = ep.avg_pps / baseline_.pps_threshold_factor;

        if (current_pps > threshold_high) {
            AnomalyDetection anomaly;
            anomaly.type = AnomalyType::UNUSUAL_TRAFFIC_RATE;
            anomaly.severity = std::min(1.0f, (current_pps - threshold_high) / threshold_high);
            anomaly.confidence = 0.8f;
            anomaly.endpoint_ip = endpoint_ip;
            anomaly.description = psram_string("Traffic rate significantly higher than baseline", alloc);

            char evidence[128];
            snprintf(evidence, sizeof(evidence), "current_pps=%.2f baseline_avg=%.2f threshold=%.2f",
                    current_pps, ep.avg_pps, threshold_high);
            anomaly.evidence = psram_string(evidence, alloc);
            anomaly.timestamp_ms = now_ms;

            anomalies.push_back(anomaly);
            detected++;
        } else if (current_pps < threshold_low && current_pps > 0.1f) {
            // Rate too low could indicate DoS or device compromise
            AnomalyDetection anomaly;
            anomaly.type = AnomalyType::UNUSUAL_TRAFFIC_RATE;
            anomaly.severity = 0.5f;
            anomaly.confidence = 0.6f;
            anomaly.endpoint_ip = endpoint_ip;
            anomaly.description = psram_string("Traffic rate significantly lower than baseline", alloc);

            char evidence[128];
            snprintf(evidence, sizeof(evidence), "current_pps=%.2f baseline_avg=%.2f threshold_low=%.2f",
                    current_pps, ep.avg_pps, threshold_low);
            anomaly.evidence = psram_string(evidence, alloc);
            anomaly.timestamp_ms = now_ms;

            anomalies.push_back(anomaly);
            detected++;
        }
    }

    // 2. Anomaly: Excessive error rate
    if (error_rate > ep.normal_error_rate + baseline_.error_rate_threshold) {
        AnomalyDetection anomaly;
        anomaly.type = AnomalyType::EXCESSIVE_ERRORS;
        anomaly.severity = std::min(1.0f, (error_rate - ep.normal_error_rate) / baseline_.error_rate_threshold);
        anomaly.confidence = 0.9f;
        anomaly.endpoint_ip = endpoint_ip;
        anomaly.description = psram_string("Error rate exceeds baseline threshold", alloc);

        char evidence[128];
        snprintf(evidence, sizeof(evidence), "error_rate=%.2f%% baseline=%.2f%% threshold=%.2f%%",
                error_rate * 100.0f, ep.normal_error_rate * 100.0f, baseline_.error_rate_threshold * 100.0f);
        anomaly.evidence = psram_string(evidence, alloc);
        anomaly.timestamp_ms = now_ms;

        anomalies.push_back(anomaly);
        detected++;
    }

    // 3. Anomaly: WRITE operation from unauthorized device
    if (operation_type == "WRITE" && !ep.is_writer) {
        AnomalyDetection anomaly;
        anomaly.type = AnomalyType::UNEXPECTED_WRITER;
        anomaly.severity = 0.9f;  // High severity
        anomaly.confidence = 1.0f;
        anomaly.endpoint_ip = endpoint_ip;
        anomaly.description = psram_string("Write operation from unauthorized endpoint", alloc);
        anomaly.evidence = psram_string("endpoint has never performed write operations in baseline", alloc);
        anomaly.timestamp_ms = now_ms;

        anomalies.push_back(anomaly);
        detected++;
    }

    // 4. Anomaly: Unknown peer
    if (!peer_ip.empty()) {
        bool peer_known = false;
        for (const auto& known_peer : ep.known_peers) {
            if (known_peer == peer_ip) {
                peer_known = true;
                break;
            }
        }

        if (!peer_known && ep.known_peers.size() > 0) {
            // Calculate percentage of new peers
            float new_peer_ratio = 1.0f / (float)(ep.known_peers.size() + 1);

            if (new_peer_ratio > baseline_.peer_change_threshold) {
                AnomalyDetection anomaly;
                anomaly.type = AnomalyType::UNUSUAL_PEER;
                anomaly.severity = 0.6f;
                anomaly.confidence = 0.7f;
                anomaly.endpoint_ip = endpoint_ip;
                anomaly.description = psram_string("Communication with unknown peer", alloc);

                char evidence[256];
                snprintf(evidence, sizeof(evidence), "peer_ip=%s known_peers=%zu",
                        PSRAMUtils::fromPSRAMString(peer_ip).c_str(), ep.known_peers.size());
                anomaly.evidence = psram_string(evidence, alloc);
                anomaly.timestamp_ms = now_ms;

                anomalies.push_back(anomaly);
                detected++;
            }
        }
    }

    // 5. Anomaly: State not normally visited
    if ((uint8_t)current_state < 16) {
        uint16_t state_bit = (1 << (uint8_t)current_state);
        if (!(ep.normal_states_bitmap & state_bit)) {
            AnomalyDetection anomaly;
            anomaly.type = AnomalyType::STATE_VIOLATION;
            anomaly.severity = 0.7f;
            anomaly.confidence = 0.8f;
            anomaly.endpoint_ip = endpoint_ip;
            anomaly.description = psram_string("Flow entered unexpected state", alloc);

            char evidence[128];
            snprintf(evidence, sizeof(evidence), "state=%d never_seen_in_baseline=true", (int)current_state);
            anomaly.evidence = psram_string(evidence, alloc);
            anomaly.timestamp_ms = now_ms;

            anomalies.push_back(anomaly);
            detected++;
        }
    }

    if (detected > 0) {
        LOG_WARNINGF(TAG, "Detected %u anomalies for endpoint %s",
                    detected, PSRAMUtils::fromPSRAMString(endpoint_ip).c_str());
    }

    return detected;
}

bool ProtocolBaselineManager::isLearning(const psram_string& endpoint_ip) const {
    auto it = baseline_.endpoints.find(endpoint_ip);
    if (it == baseline_.endpoints.end()) {
        return true;  // New endpoint always in learning
    }
    return !it->second.learning_complete;
}

void ProtocolBaselineManager::completeLearning(const psram_string& endpoint_ip) {
    auto it = baseline_.endpoints.find(endpoint_ip);
    if (it != baseline_.endpoints.end()) {
        it->second.learning_complete = true;
        LOG_INFOF(TAG, "Learning completed for endpoint %s",
                 PSRAMUtils::fromPSRAMString(endpoint_ip).c_str());
    }
}

void ProtocolBaselineManager::resetBaseline() {
    baseline_.endpoints.clear();
    baseline_.normal_state_transitions.clear();
    baseline_.operation_sequences.clear();
    baseline_.total_flows = 0;
    baseline_.total_packets = 0;

    LOG_WARNING(TAG, "Baseline reset - all learning data cleared");
}

uint32_t ProtocolBaselineManager::hashOperationSequence(const psram_vector<psram_string>& ops) const {
    // Simple FNV-1a hash
    uint32_t hash = 2166136261u;
    for (const auto& op : ops) {
        for (size_t i = 0; i < op.size(); ++i) {
            hash ^= (uint8_t)op[i];
            hash *= 16777619u;
        }
        hash ^= ',';  // Separator
        hash *= 16777619u;
    }
    return hash;
}

bool ProtocolBaselineManager::isNormalStateTransition(FlowState from, FlowState to) const {
    uint16_t key = ((uint16_t)from << 8) | (uint16_t)to;
    auto it = baseline_.normal_state_transitions.find(key);
    return it != baseline_.normal_state_transitions.end();
}

float ProtocolBaselineManager::calculateMean(const psram_vector<float>& values) const {
    if (values.empty()) return 0.0f;
    float sum = 0.0f;
    for (float v : values) {
        sum += v;
    }
    return sum / (float)values.size();
}

float ProtocolBaselineManager::calculateStdDev(const psram_vector<float>& values, float mean) const {
    if (values.size() < 2) return 0.0f;
    float sum_sq_diff = 0.0f;
    for (float v : values) {
        float diff = v - mean;
        sum_sq_diff += diff * diff;
    }
    return std::sqrt(sum_sq_diff / (float)(values.size() - 1));
}

bool ProtocolBaselineManager::getLearningStats(const psram_string& endpoint_ip,
                                               float& out_avg_pps,
                                               float& out_stddev_pps,
                                               float& out_error_rate,
                                               uint32_t& out_samples) const {
    auto it = baseline_.endpoints.find(endpoint_ip);
    if (it == baseline_.endpoints.end() || !it->second.learning_complete) {
        return false;
    }

    const EndpointBaseline& ep = it->second;
    out_avg_pps = ep.avg_pps;

    // Calculate std dev from samples (if available)
    // For simplicity we use an estimate: stddev ~= avg * 0.3 (typical coefficient of variation)
    out_stddev_pps = ep.avg_pps * 0.3f;

    out_error_rate = ep.normal_error_rate;
    out_samples = ep.learning_samples;

    return true;
}

bool ProtocolBaselineManager::autoTuneThresholds(const psram_string& endpoint_ip) {
    bool any_tuned = false;

    // If an endpoint is specified, calibrate only that one
    if (!endpoint_ip.empty()) {
        auto it = baseline_.endpoints.find(endpoint_ip);
        if (it == baseline_.endpoints.end() || !it->second.learning_complete) {
            LOG_WARNINGF(TAG, "Cannot auto-tune: endpoint %s not ready", endpoint_ip.c_str());
            return false;
        }

        const EndpointBaseline& ep = it->second;

        // Automatic tuning based on 3-sigma rule
        // PPS threshold: 3 standard deviations above the mean
        float estimated_stddev = ep.avg_pps * 0.3f;  // ~30% typical CV for ICS traffic
        float suggested_pps_factor = 3.0f;  // 3 sigma

        if (estimated_stddev > 0.01f && ep.avg_pps > 0.1f) {
            suggested_pps_factor = 1.0f + (3.0f * estimated_stddev / ep.avg_pps);
        }

        // Error rate threshold: normal + 5% margin
        float suggested_error_threshold = ep.normal_error_rate + 0.05f;
        if (suggested_error_threshold < 0.1f) {
            suggested_error_threshold = 0.1f;  // Minimum 10%
        }

        // Peer change threshold: 30% default (conservative)
        float suggested_peer_threshold = 0.3f;

        // Apply calculated thresholds
        baseline_.pps_threshold_factor = suggested_pps_factor;
        baseline_.error_rate_threshold = suggested_error_threshold;
        baseline_.peer_change_threshold = suggested_peer_threshold;

        LOG_INFOF(TAG, "Auto-tuned thresholds for %s: pps_factor=%.2f, error_rate=%.2f, peer_change=%.2f",
                  endpoint_ip.c_str(), suggested_pps_factor, suggested_error_threshold, suggested_peer_threshold);

        any_tuned = true;

    } else {
        // Calibrate on all endpoints with completed learning
        if (baseline_.endpoints.empty()) {
            LOG_WARNING(TAG, "Cannot auto-tune: no endpoints learned");
            return false;
        }

        // Collect aggregate statistics
        float total_avg_pps = 0.0f;
        float total_error_rate = 0.0f;
        uint32_t complete_count = 0;

        for (const auto& pair : baseline_.endpoints) {
            if (pair.second.learning_complete) {
                total_avg_pps += pair.second.avg_pps;
                total_error_rate += pair.second.normal_error_rate;
                complete_count++;
            }
        }

        if (complete_count == 0) {
            LOG_WARNING(TAG, "Cannot auto-tune: no complete learning data");
            return false;
        }

        float mean_avg_pps = total_avg_pps / (float)complete_count;
        float mean_error_rate = total_error_rate / (float)complete_count;

        // Calculate aggregate standard deviation
        float sum_sq_diff = 0.0f;
        for (const auto& pair : baseline_.endpoints) {
            if (pair.second.learning_complete) {
                float diff = pair.second.avg_pps - mean_avg_pps;
                sum_sq_diff += diff * diff;
            }
        }
        float stddev_pps = std::sqrt(sum_sq_diff / (float)complete_count);

        // Tuning based on aggregate statistics (3-sigma rule)
        float suggested_pps_factor = 3.0f;
        if (stddev_pps > 0.01f && mean_avg_pps > 0.1f) {
            suggested_pps_factor = 1.0f + (3.0f * stddev_pps / mean_avg_pps);
        }

        // Reasonable limits
        if (suggested_pps_factor < 1.5f) suggested_pps_factor = 1.5f;  // Min 50% above average
        if (suggested_pps_factor > 5.0f) suggested_pps_factor = 5.0f;  // Max 5x average

        float suggested_error_threshold = mean_error_rate + 0.05f;
        if (suggested_error_threshold < 0.1f) suggested_error_threshold = 0.1f;
        if (suggested_error_threshold > 0.5f) suggested_error_threshold = 0.5f;

        float suggested_peer_threshold = 0.3f;  // 30% default

        // Apply thresholds
        baseline_.pps_threshold_factor = suggested_pps_factor;
        baseline_.error_rate_threshold = suggested_error_threshold;
        baseline_.peer_change_threshold = suggested_peer_threshold;

        LOG_INFOF(TAG, "Auto-tuned global thresholds from %u endpoints: pps_factor=%.2f, error_rate=%.2f, peer_change=%.2f",
                  complete_count, suggested_pps_factor, suggested_error_threshold, suggested_peer_threshold);

        any_tuned = true;
    }

    return any_tuned;
}
