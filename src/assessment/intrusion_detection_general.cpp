#include "intrusion_detection_general.h"
#include "../core/plugin_manager.h"
#include "../core/logging_system.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include "../core/task_config.h"
#include "../core/detailed_report_builder.h"
#include "../core/async_storage_engine.h"
#include "../core/configuration_manager.h"
#include "anomaly_detection_engine.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <vector>
#include <cJSON.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_heap_caps.h>
class ConfigurationManager;
class ReportingEngine;

extern "C" {
    #include "esp_timer.h"
#include <network/eth_l2_adapter.h>
#include <security/allowlist.h>
}

#define TAG_IDS "IntrusionDetectionGeneral"

namespace {
struct FlowAnalyticsContext {
    bool has_flow;
    float current_pps;
    float error_rate;
    FlowState state;
    bool is_error;
    psram_string operation_type;
    psram_string peer_ip;
    psram_string mac_address;

    FlowAnalyticsContext()
        : has_flow(false),
          current_pps(0.0f),
          error_rate(0.0f),
          state(FlowState::INIT),
          is_error(false),
          operation_type(PSRAMAllocator<char>()),
          peer_ip(PSRAMAllocator<char>()),
          mac_address(PSRAMAllocator<char>()) {}
};

constexpr size_t kPsramLowThresholdBytes = 256U * 1024U;
constexpr size_t kDramLowThresholdBytes = 64U * 1024U;

static const char* anomalyTypeToString(AnomalyType type) {
    switch (type) {
        case AnomalyType::UNUSUAL_TRAFFIC_RATE:      return "unusual_traffic_rate";
        case AnomalyType::EXCESSIVE_ERRORS:          return "excessive_errors";
        case AnomalyType::FLOODING:                  return "flooding";
        case AnomalyType::UNEXPECTED_WRITER:         return "unexpected_writer";
        case AnomalyType::UNUSUAL_PEER:              return "unusual_peer";
        case AnomalyType::STATE_VIOLATION:           return "state_violation";
        case AnomalyType::OPERATION_SEQUENCE_ANOMALY:return "operation_sequence_anomaly";
        case AnomalyType::MALFORMED_PATTERN:         return "malformed_pattern";
        case AnomalyType::PROTOCOL_DOWNGRADE:        return "protocol_downgrade";
        case AnomalyType::RECONNAISSANCE:            return "reconnaissance";
        case AnomalyType::PRIVILEGE_ESCALATION:      return "privilege_escalation";
        case AnomalyType::DATA_EXFILTRATION:         return "data_exfiltration";
        case AnomalyType::TRAFFIC_AT_UNUSUAL_TIME:   return "traffic_at_unusual_time";
        case AnomalyType::SUDDEN_TRAFFIC_SPIKE:      return "sudden_traffic_spike";
        default:                                     return "generic_anomaly";
    }
}

static void buildJsonArray(const psram_vector<psram_string>& values,
                           char* buffer,
                           size_t capacity) {
    if (!buffer || capacity == 0) {
        return;
    }
    size_t pos = 0;
    buffer[pos++] = '[';

    for (size_t idx = 0; idx < values.size() && pos < capacity - 1; ++idx) {
        if (idx > 0) {
            if (pos >= capacity - 1) break;
            buffer[pos++] = ',';
        }
        if (pos >= capacity - 1) break;
        buffer[pos++] = '"';
        const psram_string& item = values[idx];
        for (char ch : item) {
            if (pos >= capacity - 2) {
                break;
            }
            if (ch == '"' || ch == '\\') {
                if (pos >= capacity - 2) {
                    break;
                }
                buffer[pos++] = '\\';
            }
            buffer[pos++] = ch;
        }
        if (pos >= capacity - 1) break;
        buffer[pos++] = '"';
    }

    if (pos >= capacity - 1) {
        pos = capacity - 1;
    }
    buffer[pos++] = ']';
    if (pos >= capacity) {
        pos = capacity - 1;
    }
    buffer[pos] = '\0';
}

static void buildFlowAnalytics(const NetworkPacket& packet,
                               PluginManager* plugins,
                               FlowAnalyticsContext& ctx) {
    ctx.has_flow = false;
    ctx.current_pps = 0.0f;
    ctx.error_rate = 0.0f;
    ctx.state = FlowState::INIT;
    ctx.is_error = false;
    ctx.operation_type.clear();

    if (!packet.dst_ip.empty()) {
        ctx.peer_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
    } else {
        ctx.peer_ip.clear();
    }

    ctx.mac_address = PSRAMUtils::createPSRAMString(EthL2Adapter::macToString(packet.src_mac).c_str());

    if (!plugins) {
        return;
    }

    BasePlugin* plugin = plugins->findByProtocol(packet.proto);
    if (!plugin) {
        return;
    }

    psram_string op_details{PSRAMAllocator<char>()};
    if (!plugin->classifyPacketOperation(packet, ctx.operation_type, op_details, ctx.is_error)) {
        ctx.operation_type.clear();
        ctx.is_error = false;
    }

    FlowKey key;
    const FlowData* flow = nullptr;
    if (plugin->buildFlowKey(packet, key)) {
        FlowTable& table = plugin->getFlowTable();
        flow = table.findFlow(key);
        if (!flow && key.isValid()) {
            FlowKey bidir = key.toBidirectional();
            flow = table.findFlow(bidir);
            if (flow) {
                key = bidir;
            }
        }
    }

    if (flow) {
        ctx.has_flow = true;
        ctx.state = flow->state;

        ctx.current_pps = flow->metrics.packets_per_second;
        if (ctx.current_pps <= 0.0f && flow->metrics.duration_sec() > 0.0f) {
            ctx.current_pps = static_cast<float>(flow->metrics.packet_count) / flow->metrics.duration_sec();
        }

        if (flow->metrics.packet_count > 0) {
            ctx.error_rate = static_cast<float>(flow->metrics.error_responses) /
                             static_cast<float>(flow->metrics.packet_count);
        }

        if (ctx.operation_type.empty() && !flow->recent_operations.empty()) {
            const FlowOperation& op = flow->recent_operations.back();
            ctx.operation_type = op.type;
            ctx.is_error = !op.success || (op.type == "ERROR");
        }

        if (key.isValid()) {
            if (key.src_ip == packet.src_ip.c_str()) {
                ctx.peer_ip = key.dst_ip;
            } else if (key.dst_ip == packet.src_ip.c_str()) {
                ctx.peer_ip = key.src_ip;
            } else if (!key.dst_ip.empty()) {
                ctx.peer_ip = key.dst_ip;
            }
        }
    }
}
} // namespace

// Helper function to convert ProtocolType to string
static const char* getProtocolName(ProtocolType proto) {
    switch (proto) {
        case ProtocolType::MODBUS_TCP: return "Modbus-TCP";
        case ProtocolType::S7_COMM: return "S7-Communication";
        case ProtocolType::OPC_UA: return "OPC-UA";
        case ProtocolType::ETHERNET_IP: return "EtherNet/IP";
        case ProtocolType::PROFINET: return "PROFINET";
        case ProtocolType::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

static const char* getSeverityName(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

IntrusionDetectionGeneral::IntrusionDetectionGeneral() {
}

IntrusionDetectionGeneral::~IntrusionDetectionGeneral() {
    shutdown();
}

bool IntrusionDetectionGeneral::initialize(ConfigurationManager* cfg, ReportingEngine* reporting_engine, PluginManager* plugins) {
    cfg_ = cfg;
    reporting_engine_ = reporting_engine;
    plugins_ = plugins;
    network_presence_.setReportingEngine(reporting_engine);

    if (cfg) network_presence_.setConfig(cfg->getNetworkPresenceConfig());
    network_presence_.initialize();

    if (cfg_) {
        IDSAnomalyConfig anomaly_cfg = cfg_->getIDSAnomalyConfig();
        AnomalyThresholdConfig thresholds;
        thresholds.flooding_pps_threshold = anomaly_cfg.flooding_pps_threshold;
        thresholds.requests_per_second_threshold = anomaly_cfg.requests_per_second_threshold;
        thresholds.request_response_high_ratio = anomaly_cfg.request_response_high_ratio;
        thresholds.request_response_low_ratio = anomaly_cfg.request_response_low_ratio;
        thresholds.malformed_packets_normalizer = anomaly_cfg.malformed_packets_normalizer;
        anomaly_engine_.setThresholds(thresholds);

        CorrelationConfig corr_cfg;
        corr_cfg.enabled = true;
        corr_cfg.time_window_ms = 60000;
        corr_cfg.min_events_for_correlation = 3;
        corr_cfg.max_events_tracked = 512;
        corr_cfg.severity_threshold = 0.4f;
        corr_cfg.event_retention_ms = 300000;
        correlation_engine_.setConfig(corr_cfg);
    } else {
        CorrelationConfig corr_cfg;
        correlation_engine_.setConfig(corr_cfg);
    }
    last_correlation_analysis_ms_ = esp_timer_get_time() / 1000ULL;

    // Initialize protocol baseline managers for all industrial protocols
    PSRAMAllocator<char> alloc;
    protocol_baselines_ = psram_map<ProtocolType, ProtocolBaselineManager>(alloc);

    ProtocolType protocols[] = {
        ProtocolType::MODBUS_TCP,
        ProtocolType::S7_COMM,
        ProtocolType::ETHERNET_IP,
        ProtocolType::PROFINET,
        ProtocolType::OPC_UA
    };

    for (ProtocolType proto : protocols) {
        ProtocolBaselineManager mgr;
        mgr.initialize(proto);
        protocol_baselines_[proto] = mgr;
        LOG_INFOF(TAG_IDS, "Baseline manager initialized for %s", getProtocolName(proto));
    }

    // Load saved baselines (if they exist)
    loadBaselines();

    // Enable baseline learning at startup: the baselines are built
    // during the NetworkPresence learning mode, so that when it switches
    // to protection mode, anomaly detection has data to work with.
    baseline_learning_enabled_ = true;

    LOG_INFO(TAG_IDS, "IntrusionDetectionGeneral initialized (baseline learning ON)");
    return true;
}

void IntrusionDetectionGeneral::applyRuntimeConfig() {
    if (!cfg_) return;
    network_presence_.setConfig(cfg_->getNetworkPresenceConfig());
    if (cfg_->getPassiveDetectionFlags().ids_enabled) startIDS();
    else stopIDS();
}

void IntrusionDetectionGeneral::shutdown() {
    stopIDS();
    worker_stop_ = true;
    while (worker_running_) vTaskDelay(pdMS_TO_TICKS(10));
    ids_task_handle_ = nullptr;
    reporting_engine_ = nullptr;
    cfg_ = nullptr;
    plugins_ = nullptr;
    LOG_INFO(TAG_IDS, "IntrusionDetectionGeneral shutdown");
}

bool IntrusionDetectionGeneral::startIDS() {
    if (ids_active_) return true;
    ids_active_ = true;

    // Create once; disabling IDS pauses the worker without deleting a running task.
    if (!ids_task_handle_) {
    worker_stop_ = false;
    worker_running_ = true;
    ids_task_handle_ = TaskConfig::createTask(
        idsTaskThunk,
        "IDS_Worker",
        TaskConfig::Presets::IDS_WORKER,
        this,
        1
    );

    if (!ids_task_handle_) {
        worker_running_ = false;
        LOG_ERROR(TAG_IDS, "Failed to create IDS worker task");
        ids_active_ = false;
        return false;
    }

    }

    LOG_INFOF("IDS_ENGINE", "IDS started: Baseline learning=%s",
              baseline_learning_enabled_ ? "ON" : "OFF");

    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"ids_started\",\"baseline_learning\":%s}",
                 baseline_learning_enabled_ ? "true" : "false");
        psram_string type = PSRAMUtils::createPSRAMString("lifecycle");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }

    LOG_INFO(TAG_IDS, "IDS started");
    return true;
}

void IntrusionDetectionGeneral::stopIDS() {
    if (!ids_active_) return;
    ids_active_ = false;

    // Keep the worker alive but dormant; no lock or storage transaction is interrupted.

    LOG_INFOF("IDS_ENGINE", "IDS stopped: Total packets analyzed=%llu, Alerts generated=%llu",
              getTotalPacketsAnalyzed(), getAlertsGenerated());

    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"ids_stopped\",\"packets_analyzed\":%llu,\"alerts_generated\":%llu}",
                 getTotalPacketsAnalyzed(), getAlertsGenerated());
        psram_string type = PSRAMUtils::createPSRAMString("lifecycle");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }

    LOG_INFO(TAG_IDS, "IDS stopped");
}


void IntrusionDetectionGeneral::reportWhitelistViolation(const NetworkPacket& p) {
    if (!reporting_engine_) return;
    char json[512];
    snprintf(json, sizeof(json),
      "{\"alert_type\":\"whitelist_violation\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
      "\"src_port\":%u,\"dst_port\":%u,\"protocol\":\"%s\",\"ts_ms\":%llu}",
      p.src_ip.c_str(), p.dst_ip.c_str(), p.src_port, p.dst_port,
      PluginManager::protocolTypeToString(p.proto),
      (unsigned long long)(esp_timer_get_time()/1000ULL));
    psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
    psram_string payload = PSRAMUtils::createPSRAMString(json);
    reporting_engine_->reportEvent(type, payload);

    recordCorrelationEvent(p, "whitelist_violation", 0.6f);
    processCorrelatedAttacks();
}

bool IntrusionDetectionGeneral::onPacket(const NetworkPacket& pkt) {
    if (!ids_active_) return false;
    bool bypassAuthorization = false;
    char mac[18];
    auto mac_str = EthL2Adapter::macToString(pkt.src_mac);
    strncpy(mac, mac_str.c_str(), sizeof(mac) - 1);
    mac[sizeof(mac) - 1] = '\0';
    bool isLearningMode = false;
    if (getNetworkPresenceTracker().isActive())
    {
        isLearningMode = getNetworkPresenceTracker().isInLearningMode();
    }

    if (isLearningMode) {
        // PHASE 1: LEARNING MODE
        // - Allow ALL packets to pass (no whitelist filtering)
        // - NetworkPresence tracker learns from all traffic
        // - Log learning phase decisions for visibility

        bypassAuthorization = true;

        static uint64_t learning_log_counter = 0;
        if (++learning_log_counter % 1000 == 0) { // Log every 1000 packets to avoid spam
            LOG_INFOF(TAG_IDS, "🎓 Learning Mode: Packet %llu - %s (%s) protocol=%s",
                        learning_log_counter, pkt.src_ip.c_str(), mac,
                        PluginManager::protocolTypeToString(pkt.proto));
        }
    } else {
        // PHASE 2: PROTECTION MODE
        // - NetworkPresence tracker controls authorization
        // - Whitelist filtering active for discovery/maintenance traffic
        // - Full security controls active

        static bool protection_mode_announced = false;
        if (!protection_mode_announced) {
            LOG_INFOF(TAG_IDS, "🛡️ Protection Mode ACTIVE - Learning phase completed, full security controls enabled");

            // Log transition to protection mode
            if (reporting_engine_) {
                char event_data[256];
                snprintf(event_data, sizeof(event_data),
                         "{\"alert_type\":\"mode_transition\",\"from\":\"learning\",\"to\":\"protection\",\"reason\":\"learning_phase_completed\",\"timestamp\":%llu}",
                         (unsigned long long)(esp_timer_get_time()/1000ULL));
                psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
                psram_string payload = PSRAMUtils::createPSRAMString(event_data);
                reporting_engine_->reportEvent(type, payload);
            }

            protection_mode_announced = true;
        }

        bool is_writer_packet = false;
        if (plugins_) {
            BasePlugin* plugin = plugins_->findByProtocol(pkt.proto);
            if (plugin) {
                is_writer_packet = plugin->isPacketWriter(pkt);
            }
        }

        bool source_is_trusted = false;
        if (getNetworkPresenceTracker().isActive() && is_writer_packet) {
            source_is_trusted = getNetworkPresenceTracker().isTrustedWriter(pkt.src_ip, mac);
        } else if (getNetworkPresenceTracker().isActive()) {
            source_is_trusted = getNetworkPresenceTracker().isTrustedSender(pkt.src_ip, mac);
        }

        if (source_is_trusted) { //always enabled, unless you want to set the reconnaissance time to zero
            bypassAuthorization = true;  // Known/learned device, bypass whitelist
        }

        // Second check: Global whitelist rules (if not already bypassed)
        if (!bypassAuthorization && getWhitelistManager().isEnabled() && getWhitelistManager().isPacketAllowed(pkt)) {
            bypassAuthorization = true;
        }

        // Third check: Protocol-specific whitelist rules (if not already bypassed)
        if (!bypassAuthorization && getWhitelistManager().isEnabled() && getWhitelistManager().isPacketAllowedPerProtocol(pkt)) {
            bypassAuthorization = true;
        }

        if (!bypassAuthorization) {
            // Block unauthorized traffic in protection mode
            LOG_DEBUGF(TAG_IDS, "🛡️ Whitelist violation: %s (%s) - protocol %s",
                        pkt.src_ip.c_str(), mac,
                        PluginManager::protocolTypeToString(pkt.proto));
        }
    }

    onPacketScan(pkt);
    return bypassAuthorization;
}

void IntrusionDetectionGeneral::disableRule(const psram_string& rule_id) {
    std::lock_guard<std::mutex> lock(rules_mutex_);
    for (auto& rule : rules_) {
        if (rule.rule_id == rule_id) {
            rule.enabled = false;

            LOG_INFOF("IDS_ENGINE", "Rule disabled: ID='%s', Protocol=%s",
                      rule_id.c_str(), getProtocolName(rule.protocol));

            if (reporting_engine_) {
                char event_data[256];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"rule_disabled\",\"rule_id\":\"%s\",\"protocol\":\"%s\"}",
                         rule_id.c_str(), getProtocolName(rule.protocol));
                psram_string type = PSRAMUtils::createPSRAMString("rule_management");
                psram_string payload = PSRAMUtils::createPSRAMString(event_data);
                reporting_engine_->reportEvent(type, payload);
            }
            break;
        }
    }
}



void IntrusionDetectionGeneral::startBaselineLearning() {
    baseline_learning_enabled_ = true;

    LOG_INFOF("IDS_ENGINE", "Baseline learning started: LearningPeriod=%luh, CurrentBaselines=%zu",
              (unsigned long)learning_period_hours_, baselines_.size());

    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"baseline_learning_started\",\"learning_period_hours\":%lu,\"current_baselines\":%zu}",
                 (unsigned long)learning_period_hours_, baselines_.size());
        psram_string type = PSRAMUtils::createPSRAMString("baseline_management");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }

    LOG_INFO(TAG_IDS, "Started baseline learning");
}

void IntrusionDetectionGeneral::stopBaselineLearning() {
    baseline_learning_enabled_ = false;

    LOG_INFOF("IDS_ENGINE", "Baseline learning stopped: TotalBaselines=%zu, TotalPacketsAnalyzed=%llu",
              baselines_.size(), getTotalPacketsAnalyzed());

    // Automatically save the learned baselines
    saveBaselines();

    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"baseline_learning_stopped\",\"total_baselines\":%zu,\"packets_analyzed\":%llu}",
                 baselines_.size(), getTotalPacketsAnalyzed());
        psram_string type = PSRAMUtils::createPSRAMString("baseline_management");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }

    LOG_INFO(TAG_IDS, "Stopped baseline learning");
}

void IntrusionDetectionGeneral::saveBaselines() {
    LOG_INFO(TAG_IDS, "Saving protocol baselines to filesystem...");

    // Save each protocol baseline
    uint32_t saved_count = 0;
    for (auto& pair : protocol_baselines_) {
        ProtocolType proto = pair.first;
        ProtocolBaselineManager& mgr = pair.second;

        // Build the filename: /data/baseline_modbus.json, /data/baseline_s7.json, etc.
        char filepath[64];
        const char* proto_name = nullptr;
        switch (proto) {
            case ProtocolType::MODBUS_TCP:   proto_name = "modbus"; break;
            case ProtocolType::S7_COMM:      proto_name = "s7"; break;
            case ProtocolType::ETHERNET_IP:  proto_name = "ethernetip"; break;
            case ProtocolType::PROFINET:     proto_name = "profinet"; break;
            case ProtocolType::OPC_UA:       proto_name = "opcua"; break;
            default: continue;
        }

        snprintf(filepath, sizeof(filepath), "/data/baseline_%s.json", proto_name);

        if (mgr.saveBaseline(filepath)) {
            saved_count++;
            LOG_INFOF(TAG_IDS, "Saved %s baseline to %s", getProtocolName(proto), filepath);
        } else {
            LOG_ERRORF(TAG_IDS, "Failed to save %s baseline", getProtocolName(proto));
        }
    }

    LOG_INFOF(TAG_IDS, "Saved %u/%zu protocol baselines", saved_count, protocol_baselines_.size());

    // Report event
    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"baselines_saved\",\"count\":%lu,\"learning_enabled\":%s}",
                 (unsigned long)saved_count, baseline_learning_enabled_ ? "true" : "false");
        psram_string type = PSRAMUtils::createPSRAMString("baseline_management");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }
}

void IntrusionDetectionGeneral::loadBaselines() {
    LOG_INFO(TAG_IDS, "Loading protocol baselines from filesystem...");

    // Load each protocol baseline
    uint32_t loaded_count = 0;
    for (auto& pair : protocol_baselines_) {
        ProtocolType proto = pair.first;
        ProtocolBaselineManager& mgr = pair.second;

        // Build the filename
        char filepath[64];
        const char* proto_name = nullptr;
        switch (proto) {
            case ProtocolType::MODBUS_TCP:   proto_name = "modbus"; break;
            case ProtocolType::S7_COMM:      proto_name = "s7"; break;
            case ProtocolType::ETHERNET_IP:  proto_name = "ethernetip"; break;
            case ProtocolType::PROFINET:     proto_name = "profinet"; break;
            case ProtocolType::OPC_UA:       proto_name = "opcua"; break;
            default: continue;
        }

        snprintf(filepath, sizeof(filepath), "/data/baseline_%s.json", proto_name);

        if (mgr.loadBaseline(filepath)) {
            loaded_count++;
            LOG_INFOF(TAG_IDS, "Loaded %s baseline from %s", getProtocolName(proto), filepath);
        } else {
            LOG_WARNINGF(TAG_IDS, "No baseline found for %s (will learn from scratch)", getProtocolName(proto));
        }
    }

    LOG_INFOF(TAG_IDS, "Loaded %u/%zu protocol baselines", loaded_count, protocol_baselines_.size());

    // Report event
    if (reporting_engine_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"baselines_loaded\",\"count\":%lu,\"learning_enabled\":%s}",
                 (unsigned long)loaded_count, baseline_learning_enabled_ ? "true" : "false");
        psram_string type = PSRAMUtils::createPSRAMString("baseline_management");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        reporting_engine_->reportEvent(type, payload);
    }
}

psram_vector<TrafficBaseline> IntrusionDetectionGeneral::getTrafficBaselines() const {
    std::lock_guard<std::mutex> lock(baselines_mutex_);
    return baselines_;
}

uint64_t IntrusionDetectionGeneral::getTotalPacketsAnalyzed() const {
    return total_packets_analyzed_;
}

uint64_t IntrusionDetectionGeneral::getAlertsGenerated() const {
    return alerts_generated_;
}

psram_map<psram_string, uint64_t> IntrusionDetectionGeneral::getProtocolStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return protocol_stats_;
}

void IntrusionDetectionGeneral::idsTaskThunk(void* pvParameters) {
    IntrusionDetectionGeneral* ids = static_cast<IntrusionDetectionGeneral*>(pvParameters);
    ids->idsWorker();
    ids->worker_running_ = false;
    vTaskDelete(nullptr);  // Delete self when done
}

void IntrusionDetectionGeneral::idsWorker() {
    LOG_INFO(TAG_IDS, "IDS worker task started");

    while (!worker_stop_) {
        vTaskDelay(pdMS_TO_TICKS(100));
        if (!ids_active_ || worker_stop_) continue;

        uint64_t now_ms = esp_timer_get_time() / 1000ULL;
        if (now_ms - last_memory_report_ms_ >= 5000ULL) {
            size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            size_t dram_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);

            if (psram_free < kPsramLowThresholdBytes) {
                if (!psram_low_alert_sent_ && reporting_engine_) {
                    char payload[192];
                    snprintf(payload, sizeof(payload),
                             "{\"component\":\"psram\",\"free\":%u,\"threshold\":%u,\"status\":\"low\"}",
                             (unsigned)psram_free,
                             (unsigned)kPsramLowThresholdBytes);
                    reporting_engine_->reportEvent(
                        PSRAMUtils::createPSRAMString("system.memory"),
                        PSRAMUtils::createPSRAMString(payload));
                    psram_low_alert_sent_ = true;
                }
            } else if (psram_low_alert_sent_) {
                if (reporting_engine_) {
                    char payload[192];
                    snprintf(payload, sizeof(payload),
                             "{\"component\":\"psram\",\"free\":%u,\"threshold\":%u,\"status\":\"recovered\"}",
                             (unsigned)psram_free,
                             (unsigned)kPsramLowThresholdBytes);
                    reporting_engine_->reportEvent(
                        PSRAMUtils::createPSRAMString("system.memory"),
                        PSRAMUtils::createPSRAMString(payload));
                }
                psram_low_alert_sent_ = false;
            }

            if (dram_free < kDramLowThresholdBytes) {
                if (!dram_low_alert_sent_ && reporting_engine_) {
                    char payload[192];
                    snprintf(payload, sizeof(payload),
                             "{\"component\":\"dram\",\"free\":%u,\"threshold\":%u,\"status\":\"low\"}",
                             (unsigned)dram_free,
                             (unsigned)kDramLowThresholdBytes);
                    reporting_engine_->reportEvent(
                        PSRAMUtils::createPSRAMString("system.memory"),
                        PSRAMUtils::createPSRAMString(payload));
                    dram_low_alert_sent_ = true;
                }
            } else if (dram_low_alert_sent_) {
                if (reporting_engine_) {
                    char payload[192];
                    snprintf(payload, sizeof(payload),
                             "{\"component\":\"dram\",\"free\":%u,\"threshold\":%u,\"status\":\"recovered\"}",
                             (unsigned)dram_free,
                             (unsigned)kDramLowThresholdBytes);
                    reporting_engine_->reportEvent(
                        PSRAMUtils::createPSRAMString("system.memory"),
                        PSRAMUtils::createPSRAMString(payload));
                }
                dram_low_alert_sent_ = false;
            }

            last_memory_report_ms_ = now_ms;
        }
    }

    LOG_INFO(TAG_IDS, "IDS worker task stopping");
}

bool IntrusionDetectionGeneral::onPacketScan(const NetworkPacket& packet) {
    if (!ids_active_) return true;

    total_packets_analyzed_++;

    bool intrusion = false;
    // Use the same global NetworkPresence tracker used by onPacket()
    // to keep learning/trust decisions coherent across IDS flows.
    NetworkPresenceTracker& presence = getNetworkPresenceTracker();
    const bool presence_active = presence.isActive();

    // Presence is fed once by the common dispatcher, independently of IDS.

    // Don't generate unauthorized_sender alerts during learning.
    bool isLearningMode = presence_active && presence.isInLearningMode();

    char mac[18];
    auto mac_str = EthL2Adapter::macToString(packet.src_mac);
    strncpy(mac, mac_str.c_str(), sizeof(mac) - 1);
    mac[sizeof(mac) - 1] = '\0';
    // If presence tracking is disabled/inactive, skip sender-trust enforcement here.
    bool trusted_sender = true;
    if (presence_active) {
        bool is_writer_packet = false;
        if (plugins_) {
            BasePlugin* plugin = plugins_->findByProtocol(packet.proto);
            if (plugin) {
                is_writer_packet = plugin->isPacketWriter(packet);
            }
        }
        trusted_sender = is_writer_packet
            ? presence.isTrustedWriter(packet.src_ip, mac)
            : presence.isTrustedSender(packet.src_ip, mac);
    }

    if (!trusted_sender) {
        // Only generate unauthorized_sender alerts in Protection Mode (not during Learning Mode)
        if (!isLearningMode && reporting_engine_) {
            // Generate detailed IDS detection report
            IDSDetectionReportBuilder builder;

            // Set common fields
            char session_buf[64];
            snprintf(session_buf, sizeof(session_buf), "ids_session_%llu", esp_timer_get_time() / 1000000ULL);
            builder.setSessionId(PSRAMUtils::createPSRAMString(session_buf));

            // Set detection information
            IDSDetectionReportBuilder::DetectionInfo detection;
            char alert_buf[64];
            snprintf(alert_buf, sizeof(alert_buf), "IDS_%llu", esp_timer_get_time() / 1000ULL);
            detection.alert_id = PSRAMUtils::createPSRAMString(alert_buf);
            detection.detection_type = PSRAMUtils::createPSRAMString("behavioral");
            detection.rule_id = PSRAMUtils::createPSRAMString("NPT_001");
            detection.rule_name = PSRAMUtils::createPSRAMString("Unauthorized Network Sender");
            detection.rule_description = PSRAMUtils::createPSRAMString("Detects packets from unknown or untrusted network senders");
            detection.severity = PSRAMUtils::createPSRAMString("medium");
            detection.confidence = 0.95f;
            builder.setDetectionInfo(detection);

            // Set packet information
            IDSDetectionReportBuilder::PacketInfo packet_info;
            packet_info.direction = PSRAMUtils::createPSRAMString("inbound");
            packet_info.src_ip = PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
            packet_info.src_port = packet.src_port;
            packet_info.src_mac = PSRAMUtils::createPSRAMString(mac);
            packet_info.dst_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
            packet_info.dst_port = packet.dst_port;
            packet_info.protocol = PSRAMUtils::createPSRAMString(PluginManager::protocolTypeToString(packet.proto));

            // Set raw packet data if available
            if (packet.data && packet.length > 0) {
                packet_info.raw_data.hex = formatPacketHex(packet.data, packet.length);
                packet_info.raw_data.size = packet.length;
                packet_info.raw_data.timestamp = esp_timer_get_time() / 1000ULL;

                // Parse protocol-specific data
                if (packet.proto == ProtocolType::MODBUS_TCP && packet.length >= 8) {
                    packet_info.parsed_data = parseModbusPacket(packet.data, packet.length);
                }
            }

            builder.setPacketInfo(std::move(packet_info));

            // Set context information
            IDSDetectionReportBuilder::DetectionContext context;
            context.baseline_deviation = 1.0f;  // Complete deviation from known baseline
            context.attack_pattern = PSRAMUtils::createPSRAMString("reconnaissance");
            builder.setContext(context);

            // Set action taken
            builder.setActionTaken(PSRAMUtils::createPSRAMString("monitored"));

            // Build and report the detailed JSON
            psram_string detailed_report = builder.build();

            // Generate legacy format for backward compatibility
            PSRAMUtils::ScopedBuffer json_buf(512);
            if (json_buf.valid()) {
                snprintf(json_buf.get(), json_buf.size(),
                    "{\"alert_type\":\"unauthorized_sender\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
                    "\"src_port\":%u,\"dst_port\":%u,\"src_mac\":\"%s\",\"protocol\":\"%s\","
                    "\"packet_size\":%lu,\"detection_type\":\"network_presence\",\"action\":\"monitored\",\"timestamp\":%llu}",
                    packet.src_ip.c_str(), packet.dst_ip.c_str(),
                    packet.src_port, packet.dst_port, mac,
                    PluginManager::protocolTypeToString(packet.proto),
                    (unsigned long)packet.length,
                    (unsigned long long)(esp_timer_get_time()/1000ULL));
                // Report old format for backward compatibility
                psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
                psram_string payload = PSRAMUtils::createPSRAMString(json_buf.get());
                reporting_engine_->reportEvent(type, payload);
            }

            // Report new detailed format
            reporting_engine_->reportEvent(PSRAMUtils::createPSRAMString("ids_detection_detailed"), detailed_report);

            intrusion = true;
        } else if (isLearningMode) {
            // During learning mode, just track but don't generate alerts
            static uint64_t learning_scan_counter = 0;
            if (++learning_scan_counter % 5000 == 0) { // Log every 500 scans to avoid spam
                LOG_DEBUGF(TAG_IDS, "🎓 Learning Mode Scan: Packet %llu - tracking %s (%s) without alerts",
                          learning_scan_counter, packet.src_ip.c_str(), mac);
            }
        }
    }

    // Protocol baseline learning is continuous and independent of NetworkPresence.
    // Each EndpointBaseline activates anomaly detection autonomously when
    // it reaches min_learning_samples (100 samples). It works for all
    // protocols: Modbus, S7, OPC UA, EtherNet/IP, PROFINET.
    updateBaseline(packet);

    // Periodic baseline save to filesystem (every 5 minutes)
    {
        constexpr uint64_t kBaselineSaveIntervalMs = 300000ULL;
        uint64_t now_ms = esp_timer_get_time() / 1000ULL;
        if (now_ms - last_baseline_save_ms_ >= kBaselineSaveIntervalMs) {
            last_baseline_save_ms_ = now_ms;
            saveBaselines();
        }
    }

    // During NetworkPresence Learning Mode, skip whitelist, rules, and anomaly checks.
    // Il baseline data collection (sopra) continua indipendentemente.
    if (isLearningMode) {
        return intrusion;
    }

    // First check IP whitelist - if packet is denied, generate alert
    if (!whitelist_manager_.isPacketAllowed(packet)) {
        alerts_generated_++;

        if (reporting_engine_) {
            char mac[18];
    auto mac_str = EthL2Adapter::macToString(packet.src_mac);
    strncpy(mac, mac_str.c_str(), sizeof(mac) - 1);
    mac[sizeof(mac) - 1] = '\0';

            // Generate detailed whitelist violation report
            WhitelistViolationReportBuilder builder;

            // Set common fields
            char session_buf[64];
            snprintf(session_buf, sizeof(session_buf), "ids_session_%llu", esp_timer_get_time() / 1000000ULL);
            builder.setSessionId(PSRAMUtils::createPSRAMString(session_buf));

            // Set violation information
            WhitelistViolationReportBuilder::ViolationInfo violation;
            char violation_buf[64];
            snprintf(violation_buf, sizeof(violation_buf), "WL_VIO_%llu", esp_timer_get_time() / 1000ULL);
            violation.violation_id = PSRAMUtils::createPSRAMString(violation_buf);
            violation.violation_type = PSRAMUtils::createPSRAMString("ip_not_allowed");
            violation.whitelist_name = PSRAMUtils::createPSRAMString("ip_global");
            violation.severity = PSRAMUtils::createPSRAMString("high");
            builder.setViolationInfo(violation);

            // Set packet information
            IDSDetectionReportBuilder::PacketInfo packet_info;
            packet_info.direction = PSRAMUtils::createPSRAMString("inbound");
            packet_info.src_ip = PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
            packet_info.src_port = packet.src_port;
            packet_info.src_mac = PSRAMUtils::createPSRAMString(mac);
            packet_info.dst_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
            packet_info.dst_port = packet.dst_port;
            packet_info.protocol = PSRAMUtils::createPSRAMString(PluginManager::protocolTypeToString(packet.proto));

            // Set raw packet data if available
            if (packet.data && packet.length > 0) {
                packet_info.raw_data.hex = formatPacketHex(packet.data, packet.length);
                packet_info.raw_data.size = packet.length;
                packet_info.raw_data.timestamp = esp_timer_get_time() / 1000ULL;

                // Parse protocol-specific data
                if (packet.proto == ProtocolType::MODBUS_TCP && packet.length >= 8) {
                    packet_info.parsed_data = parseModbusPacket(packet.data, packet.length);
                }
            }

            builder.setPacketInfo(std::move(packet_info));

            // Set whitelist check results
            WhitelistViolationReportBuilder::WhitelistCheck check;
            check.failed_check = PSRAMUtils::createPSRAMString("source_ip");
            check.function_allowed = true;

            constexpr size_t kMaxExpectedIps = 6;
            constexpr size_t kMaxExpectedMacs = 4;
            size_t expected_ip_count = 0;

            auto append_unique_ip = [&](const psram_string& value) {
                if (value.empty() || expected_ip_count >= kMaxExpectedIps) {
                    return;
                }
                for (const auto& existing : check.expected_ips) {
                    if (existing.size() == value.size() &&
                        (existing.empty() ? value.empty() :
                         (existing.size() == value.size() &&
                          memcmp(existing.c_str(), value.c_str(), existing.size()) == 0))) {
                        return;
                    }
                }
                check.expected_ips.push_back(value);
                expected_ip_count++;
            };

            bool ip_allowed = false;
            auto global_ranges = whitelist_manager_.getGlobalIPRanges();
            for (const auto& range : global_ranges) {
                append_unique_ip(range.original_str);
                if (!ip_allowed && range.contains(packet.src_ip)) {
                    ip_allowed = true;
                }
            }

            const ProtocolWhitelist* protocol_whitelist = whitelist_manager_.getProtocolWhitelist(packet.proto);
            if (protocol_whitelist) {
                for (const auto& range : protocol_whitelist->allowed_IP_sources) {
                    append_unique_ip(range.original_str);
                    if (!ip_allowed && range.contains(packet.src_ip)) {
                        ip_allowed = true;
                    }
                }
            }
            check.ip_allowed = ip_allowed;

            bool mac_allowed = false;
            size_t expected_mac_count = 0;
            std::string mac_string_value(mac);
            auto append_unique_mac = [&](const psram_string& value) {
                if (value.empty() || expected_mac_count >= kMaxExpectedMacs) {
                    return;
                }
                for (const auto& existing : check.expected_macs) {
                    if (existing.size() == value.size() &&
                        (existing.empty() ? value.empty() :
                         (existing.size() == value.size() &&
                          memcmp(existing.c_str(), value.c_str(), existing.size()) == 0))) {
                        return;
                    }
                }
                check.expected_macs.push_back(value);
                expected_mac_count++;
            };

            auto global_macs = whitelist_manager_.getGlobalMACPatterns();
            for (const auto& pattern : global_macs) {
                append_unique_mac(pattern.pattern);
                if (!mac_allowed && pattern.matches(mac_string_value)) {
                    mac_allowed = true;
                }
            }

            if (protocol_whitelist) {
                for (const auto& pattern : protocol_whitelist->allowed_MAC_sources) {
                    append_unique_mac(pattern.pattern);
                    if (!mac_allowed && pattern.matches(mac_string_value)) {
                        mac_allowed = true;
                    }
                }
            }
            check.mac_allowed = mac_allowed;

            check.protocol_allowed = (protocol_whitelist == nullptr) ? true : protocol_whitelist->enabled;

            bool port_allowed = true;
            if (protocol_whitelist && !protocol_whitelist->allowed_ports.empty()) {
                port_allowed = false;
                for (const auto port : protocol_whitelist->allowed_ports) {
                    if (port == packet.src_port || port == packet.dst_port) {
                        port_allowed = true;
                        break;
                    }
                }
            }
            check.port_allowed = port_allowed;

            if (check.expected_protocols.empty()) {
                check.expected_protocols.push_back(
                    PSRAMUtils::createPSRAMString(PluginManager::protocolTypeToString(packet.proto)));
            }

            builder.setWhitelistCheck(check);

            // Set action taken
            builder.setActionTaken(PSRAMUtils::createPSRAMString("blocked"));

            // Build and report the detailed JSON
            psram_string detailed_report = builder.build();

            // Generate legacy format for backward compatibility
            PSRAMUtils::ScopedBuffer alert_buf(512);
            if (alert_buf.valid()) {
                snprintf(alert_buf.get(), alert_buf.size(),
                        "{\"alert_type\":\"whitelist_violation\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
                        "\"src_port\":%u,\"dst_port\":%u,\"src_mac\":\"%s\",\"protocol\":\"%s\","
                        "\"packet_size\":%lu,\"whitelist_type\":\"ip_global\",\"action\":\"blocked\",\"timestamp\":%llu}",
                        packet.src_ip.c_str(), packet.dst_ip.c_str(),
                        packet.src_port, packet.dst_port, mac,
                        PluginManager::protocolTypeToString(packet.proto),
                        (unsigned long)packet.length,
                        (unsigned long long)(esp_timer_get_time() / 1000));
                // Report old format for backward compatibility
                psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
                psram_string payload = PSRAMUtils::createPSRAMString(alert_buf.get());
                reporting_engine_->reportEvent(type, payload);
            }

            // Report new detailed format
            reporting_engine_->reportEvent(PSRAMUtils::createPSRAMString("whitelist_violation_detailed"), detailed_report);
        }

        LOG_WARNINGF(TAG_IDS, "⚠️ Whitelist violation: %s:%u → %s:%u [%s]",
                    packet.src_ip.c_str(), packet.src_port,
                    packet.dst_ip.c_str(), packet.dst_port,
                    PluginManager::protocolTypeToString(packet.proto));
        intrusion = true;
    }

    // Check against rules (Protection Mode only)
    std::lock_guard<std::mutex> lock(rules_mutex_);
    for (const auto& rule : rules_) {
        if (rule.enabled && matchesRule(packet, rule)) {
            alerts_generated_++;

            // Enhanced logging for rule triggering
            LOG_INFOF("IDS_ENGINE", "Alert generated: RuleID='%s', Name='%s', Protocol=%s, Severity=%s, SrcIP=%s, DstIP=%s, TotalAlerts=%llu",
                      rule.rule_id.c_str(), rule.name.c_str(), getProtocolName(rule.protocol),
                      getSeverityName(rule.severity), packet.src_ip.c_str(), packet.dst_ip.c_str(),
                      alerts_generated_);

            // Generate alert through reporting engine
            if (reporting_engine_) {
                EventRecord event;
                event.timestamp_ms = packet.ts_ms;
                event.channel = "ids";
                event.type = "rule_triggered";
                event.severity = (rule.severity == LogLevel::ERROR) ? "HIGH" :
                                (rule.severity == LogLevel::WARNING) ? "MEDIUM" : "LOW";
                event.name = "Rule triggered: " + rule.name;
                event.src_ip = packet.src_ip;
                event.dst_ip = packet.dst_ip;
                event.protocol = "IDS_RULE";
                event.signature = rule.rule_id;
                event.ext["rule_name"] = rule.name;
                event.ext["rule_description"] = rule.description;

                event.channel = "ids";
                reporting_engine_->submit(event);

                // Report rule trigger event with detailed information
                char event_data[512];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"rule_triggered\",\"rule_id\":\"%s\",\"name\":\"%s\",\"protocol\":\"%s\",\"severity\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"total_alerts\":%llu}",
                         rule.rule_id.c_str(), rule.name.c_str(), getProtocolName(rule.protocol),
                         getSeverityName(rule.severity), packet.src_ip.c_str(), packet.dst_ip.c_str(),
                         alerts_generated_);
                psram_string type = PSRAMUtils::createPSRAMString("alert_activity");
                psram_string payload = PSRAMUtils::createPSRAMString(event_data);
                reporting_engine_->reportEvent(type, payload);
            }
        }
    }

    checkAnomaliesOnSinglePacket(packet);
    checkAnomalousTrafficOnFlow(packet);

    updateStatistics(packet);

    return intrusion;
}

bool IntrusionDetectionGeneral::matchesRule(const NetworkPacket& packet, const IDSRule& rule) {
    // Simple pattern matching implementation
    if (rule.protocol != ProtocolType::CUSTOM &&
        rule.protocol != packet.proto) {
        return false;
    }

    // Basic pattern matching in packet data
    if (!rule.pattern.empty() && packet.data && packet.length > 0) {
        // Use memmem for binary-safe pattern matching instead of string construction
        const void* found = memmem(packet.data, packet.length,
                                  rule.pattern.c_str(), rule.pattern.length());
        return found != nullptr;
    }

    return false;
}

void IntrusionDetectionGeneral::checkAnomaliesOnSinglePacket(const NetworkPacket& packet) {
    auto baseline_it = protocol_baselines_.find(packet.proto);
    if (baseline_it == protocol_baselines_.end()) {
        return;
    }

    FlowAnalyticsContext ctx;
    buildFlowAnalytics(packet, plugins_, ctx);

    PacketAnomalyFeatures features;
    features.protocol = packet.proto;
    features.endpoint_ip = PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
    if (!ctx.peer_ip.empty()) {
        features.peer_ip = ctx.peer_ip;
    } else if (!packet.dst_ip.empty()) {
        features.peer_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
    }
    if (!ctx.operation_type.empty()) {
        features.operation_type = ctx.operation_type;
    }
    features.packets_per_second = ctx.current_pps;
    features.error_rate = ctx.error_rate;
    features.state = ctx.state;
    features.is_error = ctx.is_error;
    features.packet_size = packet.length;
    features.baseline_learning_enabled = baseline_learning_enabled_;

    psram_vector<AnomalyDetection> anomalies;
    anomaly_engine_.analyzePacket(features, baseline_it->second, anomalies);

    for (const auto& anomaly : anomalies) {
        emitAnomalyEvent(packet, anomaly, "packet");
    }
}

void IntrusionDetectionGeneral::updateBaseline(const NetworkPacket& packet) {
    // Find the baseline manager for this protocol
    auto it = protocol_baselines_.find(packet.proto);
    if (it == protocol_baselines_.end()) {
        return;
    }

    FlowAnalyticsContext ctx;
    buildFlowAnalytics(packet, plugins_, ctx);

    PSRAMAllocator<char> alloc;
    psram_string src_ip(packet.src_ip, alloc);
    psram_string mac_addr = ctx.mac_address;
    if (mac_addr.empty()) {
        mac_addr = PSRAMUtils::createPSRAMString(EthL2Adapter::macToString(packet.src_mac).c_str());
    }

    bool completed_learning = it->second.updateBaseline(
        src_ip,
        mac_addr,
        packet.length,
        ctx.operation_type,
        ctx.is_error,
        ctx.state,
        ctx.peer_ip
    );

    if (completed_learning) {
        it->second.autoTuneThresholds(src_ip);

        // Global calibration if multiple endpoints with completed learning are present
        uint32_t completed = 0;
        const ProtocolBaseline& baseline = it->second.getBaseline();
        for (const auto& entry : baseline.endpoints) {
            if (entry.second.learning_complete) {
                completed++;
            }
        }
        if (completed >= 3) {
            it->second.autoTuneThresholds();
        }
    }
}

bool IntrusionDetectionGeneral::checkAnomalousTrafficOnFlow(const NetworkPacket& packet) {
    auto baseline_it = protocol_baselines_.find(packet.proto);
    if (baseline_it == protocol_baselines_.end()) {
        return false;
    }

    if (!plugins_) {
        return false;
    }

    BasePlugin* plugin = plugins_->findByProtocol(packet.proto);
    if (!plugin) {
        return false;
    }

    FlowAnalyticsContext ctx;
    buildFlowAnalytics(packet, plugins_, ctx);

    FlowKey key;
    if (!plugin->buildFlowKey(packet, key)) {
        return false;
    }

    FlowTable& table = plugin->getFlowTable();
    const FlowData* flow = table.findFlow(key);
    if (!flow && key.isValid()) {
        FlowKey bidirectional = key.toBidirectional();
        flow = table.findFlow(bidirectional);
    }
    if (!flow) {
        return false;
    }

    FlowMetrics metrics = flow->metrics;
    metrics.updateRates();

    float current_pps = ctx.current_pps;
    if (current_pps <= 0.0f) {
        if (metrics.packets_per_second > 0.0f) {
            current_pps = metrics.packets_per_second;
        } else if (metrics.duration_sec() > 0.0f) {
            current_pps = static_cast<float>(metrics.packet_count) / metrics.duration_sec();
        }
    }

    float error_rate = ctx.error_rate;
    if (error_rate <= 0.0f && metrics.packet_count > 0) {
        error_rate = static_cast<float>(metrics.error_responses) / static_cast<float>(metrics.packet_count);
    }

    FlowAnomalyFeatures features;
    features.protocol = packet.proto;
    features.endpoint_ip = PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
    if (!ctx.peer_ip.empty()) {
        features.peer_ip = ctx.peer_ip;
    } else if (!packet.dst_ip.empty()) {
        features.peer_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
    }
    features.state = flow->state;
    features.metrics = metrics;
    features.packets_per_second = current_pps;
    features.error_rate = error_rate;
    features.baseline_learning_enabled = baseline_learning_enabled_;

    if (!flow->recent_operations.empty()) {
        const FlowOperation& op = flow->recent_operations.back();
        features.last_operation = op.type;
        features.last_operation_error = !op.success;
    } else if (!ctx.operation_type.empty()) {
        features.last_operation = ctx.operation_type;
        features.last_operation_error = ctx.is_error;
    }

    psram_vector<AnomalyDetection> anomalies;
    anomaly_engine_.analyzeFlow(features, baseline_it->second, anomalies);

    bool triggered = false;
    for (const auto& anomaly : anomalies) {
        emitAnomalyEvent(packet, anomaly, "flow");
        triggered = true;
    }

    return triggered;
}

void IntrusionDetectionGeneral::emitAnomalyEvent(const NetworkPacket& packet,
                                                 const AnomalyDetection& anomaly,
                                                 const char* scope) {
    if (!reporting_engine_) {
        return;
    }

    const std::string description = PSRAMUtils::fromPSRAMString(anomaly.description);
    const std::string evidence = PSRAMUtils::fromPSRAMString(anomaly.evidence);
    const char* protocol_name = PluginManager::protocolTypeToString(packet.proto);

    const char* severity_label =
        (anomaly.severity >= 0.8f) ? "critical" :
        (anomaly.severity >= 0.6f) ? "high" :
        (anomaly.severity >= 0.4f) ? "medium" : "low";

    const char* confidence_label =
        (anomaly.confidence >= 0.85f) ? "high" :
        (anomaly.confidence >= 0.6f) ? "medium" : "low";

    // PSRAM buffer to avoid stack overflow on net_ana (8KB → 12KB is not enough with the IDS chain)
    PSRAMUtils::ScopedBuffer detailed_buf(768);
    PSRAMUtils::ScopedBuffer legacy_buf(256);
    if (!detailed_buf.valid() || !legacy_buf.valid()) {
        LOG_ERROR(TAG_IDS, "emitAnomalyEvent: PSRAM allocation failed, event lost");
        return;
    }
    snprintf(detailed_buf.get(), detailed_buf.size(),
             "{\"scope\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"%s\","
             "\"anomaly_type\":\"%s\",\"severity\":%.2f,\"severity_label\":\"%s\","
             "\"confidence\":%.2f,\"confidence_label\":\"%s\",\"description\":\"%s\","
             "\"evidence\":\"%s\",\"timestamp_ms\":%llu}",
             scope ? scope : "packet",
             packet.src_ip.c_str(),
             packet.dst_ip.c_str(),
             protocol_name,
             anomalyTypeToString(anomaly.type),
             anomaly.severity,
             severity_label,
             anomaly.confidence,
             confidence_label,
             description.c_str(),
             evidence.c_str(),
             (unsigned long long)anomaly.timestamp_ms);

    reporting_engine_->reportEvent(
        PSRAMUtils::createPSRAMString("ids_detection_detailed"),
        PSRAMUtils::createPSRAMString(detailed_buf.get()));

    // Maintain backward compatibility with legacy alert channel
    snprintf(legacy_buf.get(), legacy_buf.size(),
             "{\"alert_type\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"severity\":%.2f,\"protocol\":\"%s\"}",
             anomalyTypeToString(anomaly.type),
             packet.src_ip.c_str(),
             packet.dst_ip.c_str(),
             anomaly.severity,
             protocol_name);
    reporting_engine_->reportEvent(
        PSRAMUtils::createPSRAMString("intrusion_detected"),
        PSRAMUtils::createPSRAMString(legacy_buf.get()));

    alerts_generated_++;

    recordCorrelationEvent(packet, anomalyTypeToString(anomaly.type), anomaly.severity);
    processCorrelatedAttacks();
}

void IntrusionDetectionGeneral::recordCorrelationEvent(const NetworkPacket& packet,
                                                       const char* attack_type,
                                                       float severity) {
    const CorrelationConfig& cfg = correlation_engine_.getConfig();
    if (!cfg.enabled) {
        return;
    }

    CorrelationEvent evt;
    evt.timestamp_ms = esp_timer_get_time() / 1000ULL;
    evt.source_ip = PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
    if (!packet.dst_ip.empty()) {
        evt.dest_ip = PSRAMUtils::createPSRAMString(packet.dst_ip.c_str());
    }
    if (attack_type && attack_type[0] != '\0') {
        evt.attack_type = PSRAMUtils::createPSRAMString(attack_type);
    } else {
        evt.attack_type = PSRAMUtils::createPSRAMString("generic");
    }
    evt.protocol = packet.proto;
    evt.severity = severity;

    correlation_engine_.recordEvent(evt);
}

void IntrusionDetectionGeneral::reportCorrelatedAttack(const CorrelatedAttack& attack) {
    if (!reporting_engine_) {
        return;
    }

    PSRAMUtils::ScopedBuffer sources_buf(512);
    PSRAMUtils::ScopedBuffer targets_buf(256);
    buildJsonArray(attack.involved_sources, sources_buf.get(), sources_buf.size());
    buildJsonArray(attack.involved_targets, targets_buf.get(), targets_buf.size());

    PSRAMUtils::ScopedBuffer payload_buf(768);
    snprintf(payload_buf.get(),
             payload_buf.size(),
             "{\"type\":\"correlated_attack\",\"pattern\":\"%s\",\"event_count\":%u,"
             "\"sources\":%s,\"targets\":%s,\"first_seen_ms\":%llu,\"last_seen_ms\":%llu,"
             "\"combined_severity\":%.2f}",
             attack.attack_pattern.c_str(),
             (unsigned)attack.event_count,
             sources_buf.get(),
             targets_buf.get(),
             (unsigned long long)attack.first_seen_ms,
             (unsigned long long)attack.last_seen_ms,
             attack.combined_severity);

    reporting_engine_->reportEvent(
        PSRAMUtils::createPSRAMString("ids_correlation"),
        PSRAMUtils::createPSRAMString(payload_buf.get()));
}

void IntrusionDetectionGeneral::processCorrelatedAttacks() {
    const CorrelationConfig& cfg = correlation_engine_.getConfig();
    if (!cfg.enabled) {
        return;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    if (now_ms - last_correlation_analysis_ms_ < 2000ULL) {
        return;
    }
    last_correlation_analysis_ms_ = now_ms;

    PSRAMAllocator<CorrelatedAttack> alloc;
    psram_vector<CorrelatedAttack> attacks(alloc);
    uint32_t detected = correlation_engine_.analyzeCorrelations(attacks);
    if (detected == 0) {
        correlation_engine_.cleanupOldEvents();
        return;
    }

    for (const auto& attack : attacks) {
        reportCorrelatedAttack(attack);
    }

    correlation_engine_.cleanupOldEvents();
    correlation_engine_.reset();
}

void IntrusionDetectionGeneral::updateStatistics(const NetworkPacket& packet) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    char proto_key_buf[32];
    snprintf(proto_key_buf, sizeof(proto_key_buf), "protocol_%d", static_cast<int>(packet.proto));
    psram_string proto_key = PSRAMUtils::createPSRAMString(proto_key_buf);
    protocol_stats_[proto_key]++;
}

void IntrusionDetectionGeneral::reloadWhitelistFromConfig() {
    if (!cfg_) {
        LOG_WARNING("IDS_ENGINE", "No configuration manager, cannot reload ip_whitelist");
        return;
    }

    // Check available memory before loading config
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    LOG_INFOF("IDS_ENGINE", "Memory before whitelist reload: DRAM %u bytes, PSRAM %u bytes",
             (unsigned)free_heap, (unsigned)free_psram);

    /*const size_t kMinDramForReload = 50 * 1024; // 50KB
    if (free_heap < kMinDramForReload) {  // Require at least 50KB free
        LOG_ERRORF("IDS_ENGINE", "Insufficient DRAM for config reload: %u bytes free (< %u)",
                   (unsigned)free_heap, (unsigned)kMinDramForReload);
        return;
    }
        */

    // Use memory-safe PSRAM allocation for JSON buffer
    size_t json_size = 0;
    char* json_buffer = cfg_->getRawConfigInPSRAM(&json_size);

    if (!json_buffer || json_size == 0) {
        LOG_WARNING("IDS_ENGINE", "Failed to allocate config JSON in PSRAM or empty config");
        return;
    }

    // Check JSON size is reasonable
    if (json_size > 32768) {  // 32KB limit
        LOG_ERRORF("IDS_ENGINE", "Configuration JSON too large: %u bytes", (unsigned)json_size);
        heap_caps_free(json_buffer);
        return;
    }

    LOG_INFOF("IDS_ENGINE", "Loading whitelist config (%u bytes in PSRAM, %u DRAM free)",
             (unsigned)json_size, (unsigned)free_heap);

    // Use memory-safe loading with PSRAM JSON parsing
    bool success = whitelist_manager_.loadFromConfigSafe(json_buffer, json_size);

    // Clean up PSRAM buffer
    heap_caps_free(json_buffer);

    // Get final memory state for logging
    size_t final_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t final_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    if (success) {
        LOG_INFO("IDS_ENGINE", "✅ ip_whitelist reloaded from config using PSRAM");

        // Log whitelist initialization to ids_events.log
        if (reporting_engine_) {
            char event_data[512];
            snprintf(event_data, sizeof(event_data),
                     "{\"alert_type\":\"whitelist_initialized\",\"source\":\"config\",\"status\":\"success\",\"memory_used\":%u,\"timestamp\":%llu}",
                     (unsigned)(free_heap - final_heap),
                     (unsigned long long)(esp_timer_get_time()/1000ULL));
            psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
            psram_string payload = PSRAMUtils::createPSRAMString(event_data);
            reporting_engine_->reportEvent(type, payload);
        }
    } else {
        LOG_ERROR("IDS_ENGINE", "❌ Failed to load ip_whitelist from config - using defaults");

        // Log whitelist initialization failure to ids_events.log
        if (reporting_engine_) {
            char event_data[256];
            snprintf(event_data, sizeof(event_data),
                     "{\"alert_type\":\"whitelist_initialization_failed\",\"source\":\"config\",\"reason\":\"parsing_error\",\"timestamp\":%llu}",
                     (unsigned long long)(esp_timer_get_time()/1000ULL));
            psram_string type = PSRAMUtils::createPSRAMString("intrusion_detected");
            psram_string payload = PSRAMUtils::createPSRAMString(event_data);
            reporting_engine_->reportEvent(type, payload);
        }
    }

    // Log final memory state (already declared above)
    LOG_INFOF("IDS_ENGINE", "Memory after whitelist reload: DRAM %u bytes, PSRAM %u bytes",
             (unsigned)final_heap, (unsigned)final_psram);
}
