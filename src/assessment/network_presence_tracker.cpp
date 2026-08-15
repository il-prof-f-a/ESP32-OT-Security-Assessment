#include "network_presence_tracker.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include "../core/filesystem_task_delegate.h"
#include "../core/whitelist_manager.h"
#include <cJSON.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "network/eth_l2_adapter.h"
#include "security/allowlist.h"
#include <cctype>
#include <unordered_set>
#include <cmath>
#include <vector>
#include <cstdint>
#include <cstring>
extern "C" {
    #include "esp_timer.h"
    #include "nvs_flash.h"
    #include "nvs.h"
    #include <cstring>
#include <core/async_storage_engine.h>
}

#define TAG_NET_PRESENCE "NetworkPresenceTracker"
#define NVS_NAMESPACE_PRESENCE "net_presence"

namespace {
    inline PSRAMUtils::PSRAMStringView make_view(const psram_string& s) {
        return PSRAMUtils::PSRAMStringView::fromPSRAMString(s);
    }

    inline psram_string to_upper_copy(PSRAMUtils::PSRAMStringView view) {
        psram_string out;
        out.resize(view.length);
        for (size_t i = 0; i < view.length; ++i) {
            unsigned char c = static_cast<unsigned char>(view.data[i]);
            out[i] = static_cast<char>(std::toupper(c));
        }
        return out;
    }

    inline psram_string canon_mac_ps(PSRAMUtils::PSRAMStringView view) {
        psram_string out = to_upper_copy(view);
        for (char& ch : out) {
            if (ch == '-') {
                ch = ':';
            }
        }
        return out;
    }

    inline bool isBroadcastOrMulticastMacPS(PSRAMUtils::PSRAMStringView mac) {
        if (mac.length == 0 || !mac.data) {
            return false;
        }
        psram_string norm = canon_mac_ps(mac);
        const char* ptr = norm.c_str();
        return (std::strcmp(ptr, "FF:FF:FF:FF:FF:FF") == 0) ||
               (std::strncmp(ptr, "01:00:5E:", 9) == 0) ||
               (std::strncmp(ptr, "33:33:", 5) == 0) ||
               (std::strncmp(ptr, "01:80:C2:", 9) == 0) ||
               (std::strncmp(ptr, "01:0E:CF:", 9) == 0);
    }

    inline bool isBroadcastOrMulticastIpPS(PSRAMUtils::PSRAMStringView ip) {
        if (ip.length == 0 || !ip.data) {
            return false;
        }
        if (ip.length == 15 && std::strncmp(ip.data, "255.255.255.255", 15) == 0) {
            return true;
        }
        return (ip.length >= 4 && std::strncmp(ip.data, "224.", 4) == 0) ||
               (ip.length >= 4 && std::strncmp(ip.data, "239.", 4) == 0);
    }

    inline bool wildcardMatchView(const char* str, size_t str_len,
                                  const char* pat, size_t pat_len) {
        size_t s = 0, p = 0;
        size_t star = static_cast<size_t>(-1);
        size_t ss = 0;
        while (s < str_len) {
            if (p < pat_len && (pat[p] == '?' || pat[p] == str[s])) {
                ++s;
                ++p;
            } else if (p < pat_len && pat[p] == '*') {
                star = p++;
                ss = s;
            } else if (star != static_cast<size_t>(-1)) {
                p = star + 1;
                s = ++ss;
            } else {
                return false;
            }
        }
        while (p < pat_len && pat[p] == '*') {
            ++p;
        }
        return p == pat_len;
    }

    template<typename Container>
    inline bool matchAnyPS(PSRAMUtils::PSRAMStringView value,
                           const Container& patterns,
                           bool mac = false) {
        if (!value.data) {
            return false;
        }
        psram_string value_norm = mac ? canon_mac_ps(value) : to_upper_copy(value);
        for (const auto& raw : patterns) {
            auto raw_view = make_view(raw);
            if (!raw_view.data) {
                continue;
            }
            psram_string pat_norm = mac ? canon_mac_ps(raw_view) : to_upper_copy(raw_view);
            if (value_norm == pat_norm) {
                return true;
            }
            if (wildcardMatchView(value_norm.c_str(), value_norm.size(),
                                  pat_norm.c_str(), pat_norm.size())) {
                return true;
            }
        }
        return false;
    }

    enum class PacketOperationType : uint8_t {
        UNKNOWN = 0,
        READ,
        WRITE,
        CONTROL
    };

    static inline uint16_t le16(const uint8_t* p) {
        return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    }

    inline bool containsToken(const uint8_t* data, size_t len, const char* token) {
        if (!data || !token) {
            return false;
        }
        const size_t token_len = std::strlen(token);
        if (token_len == 0 || len < token_len) {
            return false;
        }
        const uint8_t* end = data + (len - token_len + 1);
        for (const uint8_t* p = data; p < end; ++p) {
            if (p[0] == static_cast<uint8_t>(token[0]) &&
                std::memcmp(p, token, token_len) == 0) {
                return true;
            }
        }
        return false;
    }

    PacketOperationType classifyModbusOperation(const NetworkPacket& packet) {
        if (!packet.data || packet.length < 8) {
            return PacketOperationType::UNKNOWN;
        }
        bool is_request = (packet.dst_port == 502);
        if (!is_request) {
            return PacketOperationType::UNKNOWN;
        }
        uint8_t func = packet.data[7];
        uint8_t base_func = func & 0x7FU;
        switch (base_func) {
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x14:
            case 0x18:
                return PacketOperationType::READ;
            case 0x05:
            case 0x06:
            case 0x0F:
            case 0x10:
            case 0x16:
            case 0x17:
                return PacketOperationType::WRITE;
            case 0x08:
            case 0x11:
            case 0x2B:
                return PacketOperationType::CONTROL;
            default:
                break;
        }
        return PacketOperationType::UNKNOWN;
    }

    PacketOperationType classifyS7Operation(const NetworkPacket& packet) {
        if (!packet.data || packet.length < 17) {
            return PacketOperationType::UNKNOWN;
        }
        if (packet.dst_port != 102) {
            return PacketOperationType::UNKNOWN;
        }
        const uint8_t* data = packet.data;
        size_t len = packet.length;
        if (data[0] != 0x03 || data[1] != 0x00 || len < 5) {
            return PacketOperationType::UNKNOWN;
        }
        uint8_t cotp_len = data[4];
        size_t offset = 4U + static_cast<size_t>(cotp_len);
        if (offset >= len || data[offset] != 0x32 || offset + 11 >= len) {
            return PacketOperationType::UNKNOWN;
        }
        uint8_t func = data[offset + 10];
        switch (func) {
            case 0x04:
            case 0x1A:
            case 0x1C:
            case 0x1E:
                return PacketOperationType::READ;
            case 0x05:
            case 0x1B:
            case 0x1D:
            case 0x2D:
                return PacketOperationType::WRITE;
            case 0x28:
            case 0x29:
            case 0x2F:
                return PacketOperationType::CONTROL;
            default:
                break;
        }
        return PacketOperationType::UNKNOWN;
    }

    PacketOperationType classifyProfinetOperation(const NetworkPacket& packet) {
        if (!packet.data || packet.length < 26) {
            return PacketOperationType::UNKNOWN;
        }
        const uint8_t* frame = packet.data;
        if (frame[12] != 0x88 || frame[13] != 0x92) {
            return PacketOperationType::UNKNOWN;
        }
        const uint8_t* dcp = frame + 14;
        size_t dcp_len = packet.length > 14 ? packet.length - 14 : 0;
        if (dcp_len < 12) {
            return PacketOperationType::UNKNOWN;
        }
        uint16_t frame_id = (static_cast<uint16_t>(dcp[0]) << 8) | static_cast<uint16_t>(dcp[1]);
        if (frame_id < 0xFEFC || frame_id > 0xFEFF) {
            return PacketOperationType::UNKNOWN;
        }
        uint8_t service_id = dcp[2];
        uint8_t service_type = dcp[3];
        if (service_type != 0x00) {
            return PacketOperationType::UNKNOWN;
        }
        switch (service_id) {
            case 0x03:
            case 0x05:
                return PacketOperationType::READ;
            case 0x04:
                return PacketOperationType::WRITE;
            case 0x06:
                return PacketOperationType::CONTROL;
            default:
                break;
        }
        return PacketOperationType::UNKNOWN;
    }

    bool extractEnipService(const uint8_t* data, size_t len, uint8_t& svc, bool& is_response) {
        if (!data || len < 28) {
            return false;
        }
        if (le16(data) != 0x006F) {
            return false;
        }
        const uint8_t* payload = data + 24;
        size_t payload_len = len - 24;
        if (payload_len < 8) {
            return false;
        }
        uint16_t item_count = le16(payload + 6);
        size_t pos = 8;
        for (uint16_t i = 0; i < item_count; ++i) {
            if (pos + 4 > payload_len) {
                return false;
            }
            uint16_t type = le16(payload + pos);
            uint16_t ilen = le16(payload + pos + 2);
            const uint8_t* item_data = payload + pos + 4;
            if (pos + 4 + ilen > payload_len) {
                return false;
            }
            if (type == 0x00B2 && ilen >= 2) {
                svc = item_data[0];
                is_response = (svc & 0x80U) != 0U;
                svc &= 0x7FU;
                return true;
            }
            pos += 4 + ilen;
        }
        return false;
    }

    PacketOperationType classifyEtherNetIPOperation(const NetworkPacket& packet) {
        if (!packet.data || !packet.is_tcp) {
            return PacketOperationType::UNKNOWN;
        }
        if (packet.dst_port != 44818) {
            return PacketOperationType::UNKNOWN;
        }
        uint8_t svc = 0;
        bool is_response = false;
        if (!extractEnipService(packet.data, packet.length, svc, is_response) || is_response) {
            return PacketOperationType::UNKNOWN;
        }
        switch (svc) {
            case 0x01:
            case 0x0E:
                return PacketOperationType::READ;
            case 0x10:
            case 0x16:
                return PacketOperationType::WRITE;
            case 0x05:
                return PacketOperationType::CONTROL;
            default:
                break;
        }
        return PacketOperationType::UNKNOWN;
    }

    PacketOperationType classifyOpcuaOperation(const NetworkPacket& packet) {
        if (!packet.data || packet.length < 8) {
            return PacketOperationType::UNKNOWN;
        }
        if (packet.dst_port != 4840) {
            return PacketOperationType::UNKNOWN;
        }
        const uint8_t* data = packet.data;
        if (std::memcmp(data, "HEL", 3) == 0 ||
            std::memcmp(data, "OPN", 3) == 0 ||
            std::memcmp(data, "CLO", 3) == 0) {
            return PacketOperationType::CONTROL;
        }
        if (std::memcmp(data, "MSG", 3) != 0 || packet.length <= 8) {
            return PacketOperationType::UNKNOWN;
        }
        const uint8_t* payload = data + 8;
        size_t payload_len = packet.length - 8;
        if (containsToken(payload, payload_len, "WriteRequest") ||
            containsToken(payload, payload_len, "CallRequest") ||
            containsToken(payload, payload_len, "DeleteNodes") ||
            containsToken(payload, payload_len, "AddNodes")) {
            return PacketOperationType::WRITE;
        }
        if (containsToken(payload, payload_len, "ReadRequest") ||
            containsToken(payload, payload_len, "BrowseRequest") ||
            containsToken(payload, payload_len, "TranslateBrowsePaths")) {
            return PacketOperationType::READ;
        }
        if (containsToken(payload, payload_len, "CreateSession") ||
            containsToken(payload, payload_len, "ActivateSession") ||
            containsToken(payload, payload_len, "CloseSession")) {
            return PacketOperationType::CONTROL;
        }
        return PacketOperationType::UNKNOWN;
    }

    PacketOperationType detectPacketOperation(const NetworkPacket& packet) {
        PacketOperationType op = PacketOperationType::UNKNOWN;
        switch (packet.proto) {
            case ProtocolType::MODBUS_TCP:
                op = classifyModbusOperation(packet);
                break;
            case ProtocolType::S7_COMM:
                op = classifyS7Operation(packet);
                break;
            case ProtocolType::OPC_UA:
                op = classifyOpcuaOperation(packet);
                break;
            case ProtocolType::ETHERNET_IP:
                op = classifyEtherNetIPOperation(packet);
                break;
            case ProtocolType::PROFINET:
                op = classifyProfinetOperation(packet);
                break;
            default:
                break;
        }
        if (op != PacketOperationType::UNKNOWN) {
            return op;
        }
        if (packet.dst_port == 502) {
            op = classifyModbusOperation(packet);
        } else if (packet.dst_port == 102) {
            op = classifyS7Operation(packet);
        } else if (packet.dst_port == 4840) {
            op = classifyOpcuaOperation(packet);
        } else if (packet.dst_port == 44818) {
            op = classifyEtherNetIPOperation(packet);
        }
        return op;
    }

}


static const char* protocolTypeToLabel(ProtocolType proto) {
    switch (proto) {
        case ProtocolType::MODBUS_TCP:    return "Modbus";
        case ProtocolType::S7_COMM:       return "S7";
        case ProtocolType::OPC_UA:        return "OPC UA";
        case ProtocolType::ETHERNET_IP:   return "EtherNet/IP";
        case ProtocolType::PROFINET:      return "Profinet";
        case ProtocolType::CUSTOM:        return "Custom";
        default:                          return "Unknown";
    }
}

// Constructor and Destructor
NetworkPresenceTracker::NetworkPresenceTracker() {
    last_cleanup_ms_ = getCurrentTimeMs();
    last_retention_cleanup_ms_ = getCurrentTimeMs();
    system_start_time_ms_ = getCurrentTimeMs();

    // Set default configuration
    config_ = NetworkPresenceConfig();
}

NetworkPresenceTracker::~NetworkPresenceTracker() {
    shutdown();
}

bool NetworkPresenceTracker::initialize() {
    //std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO(TAG_NET_PRESENCE, "Initializing NetworkPresenceTracker with learning system");

    // Initialize NVS for persistent storage
    if (config_.enable_persistent_learning) {
        // AsyncStorage engine handles NVS initialization globally
        esp_err_t err = ESP_OK;

        if (err == ESP_OK) {
            persistent_storage_initialized_ = true;
            LOG_INFO(TAG_NET_PRESENCE, "Persistent storage initialized successfully");

            // Load previously learned devices
            /*if (!loadFromPersistentStorage()) {
                LOG_WARNING(TAG_NET_PRESENCE, "Failed to load previous learning data, starting fresh");
            }*/
        } else {
            LOG_ERRORF(TAG_NET_PRESENCE, "Failed to initialize persistent storage: %s", esp_err_to_name(err));
        }
    }

    LOG_INFOF(TAG_NET_PRESENCE, "🎯 NetworkPresenceTracker initialized:");
    LOG_INFOF(TAG_NET_PRESENCE, "  📚 Learning mode: %s (delay: %u min)",
              config_.learning_mode ? "ENABLED" : "DISABLED", config_.activation_delay_minutes);
    LOG_INFOF(TAG_NET_PRESENCE, "  💾 Persistent storage: %s", persistent_storage_initialized_ ? "ENABLED" : "DISABLED");
    LOG_INFOF(TAG_NET_PRESENCE, "  🎯 Trust threshold: %.2f, Min observation: %.3f hours",
              config_.trust_threshold_score, config_.min_observation_period_hours);
    LOG_INFOF(TAG_NET_PRESENCE, "  🧹 Cleanup interval: %u min, Inactive timeout: %u min",
              config_.cleanup_interval_ms / (60*1000), config_.inactive_device_timeout_ms / (60*1000));

    active_ = true;
    return true;
}

bool NetworkPresenceTracker::isActive(){
    return active_;
}

void NetworkPresenceTracker::shutdown() {
    //std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO(TAG_NET_PRESENCE, "Shutting down NetworkPresenceTracker");

    // Save current learning data to persistent storage
    if (persistent_storage_initialized_) {
        saveToPersistentStorage();
    }

    // Clear all data
    devices_.clear();
    whitelisted_devices_.clear();
    learned_trusted_sender_devices_.clear();
    learned_trusted_writer_devices_.clear();

    LOG_INFO(TAG_NET_PRESENCE, "NetworkPresenceTracker shutdown complete");

    active_ = false;
}

// Configuration Management
void NetworkPresenceTracker::setConfig(const NetworkPresenceConfig& config) {
    //std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;

    // Update whitelisted devices from config
    whitelisted_devices_.clear();
    parseWhitelistedDevices(config_.whitelisted_devices);

    LOG_INFOF(TAG_NET_PRESENCE, "NetworkPresence config updated: enabled=%s, learning_mode=%s, whitelisted=%zu",
              config_.enabled ? "true" : "false",
              config_.learning_mode ? "true" : "false",
              whitelisted_devices_.size());
}

NetworkPresenceConfig NetworkPresenceTracker::getConfig() const {
    //std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

// Device Trust Management
void NetworkPresenceTracker::addTrustedDevice(const psram_string& identifier, bool is_persistent) {
    //std::lock_guard<std::mutex> lock(mutex_);
    if (identifier.empty()) {
        return;
    }
    whitelisted_devices_.insert(identifier);
    learned_trusted_sender_devices_.insert(identifier);
    learned_trusted_writer_devices_.insert(identifier);

    // Mark existing device as whitelisted if found
    for (auto& pair : devices_) {
        if (pair.second.ip_address == identifier || pair.second.mac_address == identifier) {
            pair.second.is_whitelisted = true;
            pair.second.is_persistent = is_persistent;
        }
    }

    LOG_INFOF(TAG_NET_PRESENCE, "Added trusted device: %s (persistent: %s)",
              identifier.c_str(), is_persistent ? "yes" : "no");
}

void NetworkPresenceTracker::addTrustedDevice(const std::string& identifier, bool is_persistent) {
    addTrustedDevice(PSRAMUtils::createPSRAMString(identifier.c_str()), is_persistent);
}

void NetworkPresenceTracker::removeTrustedDevice(const psram_string& identifier) {
    //std::lock_guard<std::mutex> lock(mutex_);
    if (identifier.empty()) {
        return;
    }
    whitelisted_devices_.erase(identifier);
    learned_trusted_sender_devices_.erase(identifier);
    learned_trusted_writer_devices_.erase(identifier);

    // Update device flags
    for (auto& pair : devices_) {
        if (pair.second.ip_address == identifier || pair.second.mac_address == identifier) {
            pair.second.is_whitelisted = false;
            pair.second.is_learned_sender = false;
            pair.second.is_learned_writer = false;
            pair.second.is_persistent = false;
        }
    }

    // Remove from persistent storage
    if (persistent_storage_initialized_) {
        removeDeviceFromNVS(PSRAMUtils::fromPSRAMString(identifier));
    }

    LOG_INFOF(TAG_NET_PRESENCE, "Removed trusted device: %s", identifier.c_str());
}

void NetworkPresenceTracker::removeTrustedDevice(const std::string& identifier) {
    removeTrustedDevice(PSRAMUtils::createPSRAMString(identifier.c_str()));
}

bool NetworkPresenceTracker::isTrustedSender(const psram_string& ip, const psram_string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return matchesTrustedDevice(ip, mac);
}

bool NetworkPresenceTracker::isTrustedSender(const psram_string& ip) const {
    return isTrustedSender(ip, psram_string());
}

bool NetworkPresenceTracker::isTrustedSender(const std::string& ip, const std::string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return matchesTrustedDevice(ip, mac);
}

bool NetworkPresenceTracker::isTrustedWriter(const psram_string& ip, const psram_string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return matchesWriterTrustedDevice(ip, mac);
}

bool NetworkPresenceTracker::isTrustedWriter(const psram_string& ip) const {
    return isTrustedWriter(ip, psram_string());
}

bool NetworkPresenceTracker::isTrustedWriter(const std::string& ip, const std::string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return matchesWriterTrustedDevice(ip, mac);
}

// Core Packet Tracking with Advanced Heuristics
void NetworkPresenceTracker::trackPacket(const NetworkPacket& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config_.enabled) return;

    total_tracked_packets_++;

    uint64_t now_ms = getCurrentTimeMs();

    psram_string src_ip_ps = packet.src_ip.empty()
        ? psram_string()
        : PSRAMUtils::createPSRAMString(packet.src_ip.c_str());
    psram_string src_mac_ps = MACPattern::macToString(packet.src_mac);

    if (isBroadcastOrMulticastIpPS(make_view(src_ip_ps)) ||
        isBroadcastOrMulticastMacPS(make_view(src_mac_ps))) {
        return;
    }

    psram_string device_key_psram;
    if (!src_ip_ps.empty()) {
        device_key_psram = src_ip_ps;
    } else {
        device_key_psram = PSRAMUtils::createPSRAMString("MAC:");
        device_key_psram += src_mac_ps;
    }

    bool is_truly_new = devices_.find(device_key_psram) == devices_.end();
    auto& device = devices_[device_key_psram];

    if (is_truly_new) {
        device.ip_address = src_ip_ps;
        device.mac_address = src_mac_ps;
        device.first_seen_ms = now_ms;
        device.is_whitelisted = matchAnyPS(make_view(src_ip_ps), whitelisted_devices_, false) ||
                                matchAnyPS(make_view(src_mac_ps), whitelisted_devices_, true);
        device.is_learned_sender = matchAnyPS(make_view(src_ip_ps), learned_trusted_sender_devices_, false) ||
                                   matchAnyPS(make_view(src_mac_ps), learned_trusted_sender_devices_, true);
        device.is_learned_writer = matchAnyPS(make_view(src_ip_ps), learned_trusted_writer_devices_, false) ||
                                   matchAnyPS(make_view(src_mac_ps), learned_trusted_writer_devices_, true);

        if (!src_ip_ps.empty() || !src_mac_ps.empty()) {
            LOG_INFOF(TAG_NET_PRESENCE,
                      "New device discovered: %s (%s) - whitelisted: %s",
                      !src_ip_ps.empty() ? src_ip_ps.c_str() : "unknown",
                      !src_mac_ps.empty() ? src_mac_ps.c_str() : "unknown",
                      device.is_whitelisted ? "yes" : "no");
        }
    } else {
        device.mac_address = src_mac_ps;
    }

    device.total_packets++;
    device.last_seen_ms = now_ms;
    device.inactive_since_ms = 0; // Mark as active
    device.protocol_counts[packet.proto]++;
    device.port_usage[packet.dst_port]++;

    PacketOperationType op_type = detectPacketOperation(packet);
    if (op_type == PacketOperationType::READ) {
        device.total_read_packets++;
    } else if (op_type == PacketOperationType::WRITE) {
        device.total_write_packets++;
        total_write_packets_++;
    } else if (op_type == PacketOperationType::CONTROL) {
        // Control operations currently tracked only for presence metrics
    } else if (config_.track_all_traffic) {
        device.total_read_packets++;
    }

    // Update presence score and check for auto-promotion
    if (config_.learning_mode && !device.is_whitelisted) {
        updatePresenceScore(device);

        if (!src_ip_ps.empty()) {
            if (shouldPromoteToTrustedSender(device)) {
                promoteTrustedSenderByIp(src_ip_ps);
            }
            if (op_type == PacketOperationType::WRITE && shouldPromoteToTrustedWriter(device)) {
                promoteTrustedWriterByIp(src_ip_ps);
            }
        }
    }

    // Periodic maintenance
    if (now_ms - last_cleanup_ms_ > config_.cleanup_interval_ms) {
        cleanupInactiveDevices();
        last_cleanup_ms_ = now_ms;
    }

    if (now_ms - last_retention_cleanup_ms_ > (config_.retention_days * 24 * 60 * 60 * 1000ULL)) {
        runRetentionCleanup();
        last_retention_cleanup_ms_ = now_ms;
    }

    // Mark devices as dirty for auto-save (new device or updated activity)
    markDevicesDirty();

    // Only enable autosave when NOT in learning mode
    // During learning, we save ONLY when notifyLearningComplete() is called
    if (!isInLearningMode()) {
        uint64_t check_interval = 300000; // Check every 5 minutes in normal mode
        if (now_ms - last_auto_save_check_ms_ >= check_interval) {
            checkAutoSave();
            last_auto_save_check_ms_ = now_ms;
        }
    }
}

// Advanced Presence Scoring Algorithm
double NetworkPresenceTracker::calculatePresenceScore(const NetworkDeviceInfo& device) const {
    uint64_t now_ms = getCurrentTimeMs();
    uint64_t observation_time_ms = now_ms - device.first_seen_ms;

    if (observation_time_ms == 0) return 0.0;

    // 1. Continuity Score: How consistently present the device has been
    double continuity_score = 0.0;
    if (device.total_packets > 0) {
        uint64_t expected_gaps = observation_time_ms / (10 * 1000); // Expected packet every 10s
        uint64_t actual_packets = device.total_packets;
        continuity_score = std::min(1.0, static_cast<double>(actual_packets) / std::max(1ULL, expected_gaps));
    }

    // 2. Diversity Score: Protocol and port variety indicates legitimate network member
    double diversity_score = 0.0;
    size_t protocol_count = device.protocol_counts.size();
    size_t port_count = device.port_usage.size();

    // Normalize: 1+ protocols and 2+ ports = good diversity
    diversity_score = std::min(1.0, (protocol_count * 0.5) + (port_count * 0.1));

    // 3. Frequency Score: Regular communication patterns
    double frequency_score = 0.0;
    if (observation_time_ms > 0) {
        double packets_per_hour = (static_cast<double>(device.total_packets) * 3600000.0) / observation_time_ms;
        frequency_score = std::min(1.0, packets_per_hour / 100.0); // 100+ packets/hour = max score
    }

    // Combined weighted score
    double final_score = (continuity_score * config_.continuity_weight) +
                        (diversity_score * config_.diversity_weight) +
                        (frequency_score * config_.frequency_weight);

    return std::min(1.0, final_score);
}

void NetworkPresenceTracker::updatePresenceScore(NetworkDeviceInfo& device) {
    device.presence_score = calculatePresenceScore(device);

    // Update continuous presence flag
    uint64_t now_ms = getCurrentTimeMs();
    uint64_t observation_time_ms = now_ms - device.first_seen_ms;
    device.is_continuously_present = (observation_time_ms >= (config_.activation_delay_minutes * 60 * 1000ULL)) &&
                                   (device.presence_score >= 0.5);
}

bool NetworkPresenceTracker::shouldPromoteToTrustedSender(const NetworkDeviceInfo& device) const {
    uint64_t now_ms = getCurrentTimeMs();
    uint64_t observation_time_ms = now_ms - device.first_seen_ms;
    uint64_t min_observation_ms = (uint64_t)(config_.min_observation_period_hours * 60.0 * 60.0 * 1000.0);
    double observation_hours = observation_time_ms / (1000.0 * 60.0 * 60.0);

    bool continuous_present = device.is_continuously_present;
    bool score_sufficient = device.presence_score >= config_.trust_threshold_score;
    bool time_sufficient = observation_time_ms >= min_observation_ms;
    bool not_already_promoted = !device.is_learned_sender;

    bool should_promote = continuous_present && score_sufficient && time_sufficient && not_already_promoted;

    // Log detailed evaluation for devices close to promotion (with throttling to avoid spam)
    if (device.presence_score > 0.5 && observation_hours > (config_.min_observation_period_hours * 0.8)) {
        static uint64_t last_log_time = 0;
        uint64_t now = getCurrentTimeMs();

        // Only log every 30 seconds to avoid spam
        if (now - last_log_time >= 30000) {
            unsigned sc100 = (unsigned)(device.presence_score * 100.0f + 0.5f);
            unsigned sc_i = sc100 / 100, sc_f = sc100 % 100;
            unsigned req100 = (unsigned)(config_.trust_threshold_score * 100.0f + 0.5f);
            unsigned req_i = req100 / 100, req_f = req100 % 100;
            unsigned h10 = (unsigned)(observation_hours * 10.0f + 0.5f);
            unsigned h_i = h10 / 10, h_f = h10 % 10;
            unsigned req1000 = (unsigned)(config_.min_observation_period_hours * 1000.0f + 0.5f);
            unsigned reqh_i = req1000 / 1000, reqh_f = req1000 % 1000;
            LOG_DEBUGF(TAG_NET_PRESENCE, "🔍 Trust evaluation for %s: score=%u.%02u(req:%u.%02u), hours=%u.%01u(req:%u.%03u), continuous=%s, already_promoted=%s -> %s",
                      device.ip_address.c_str(), sc_i, sc_f, req_i, req_f,
                      h_i, h_f, reqh_i, reqh_f,
                      continuous_present ? "YES" : "NO", device.is_learned_sender ? "YES" : "NO",
                      should_promote ? "PROMOTE" : "WAIT");
            last_log_time = now;
        }
    }

    return should_promote;
}

bool NetworkPresenceTracker::shouldPromoteToTrustedWriter(const NetworkDeviceInfo& device) const {
    if (device.is_learned_writer || device.total_write_packets == 0) {
        return false;
    }
    uint64_t now_ms = getCurrentTimeMs();
    uint64_t observation_time_ms = now_ms - device.first_seen_ms;
    uint64_t min_observation_ms = (uint64_t)(config_.min_observation_period_hours * 60.0 * 60.0 * 1000.0);
    bool continuous_present = device.is_continuously_present;
    bool score_sufficient = device.presence_score >= config_.trust_threshold_score;
    bool time_sufficient = observation_time_ms >= min_observation_ms;
    return continuous_present && score_sufficient && time_sufficient;
}

void NetworkPresenceTracker::promoteToTrusted(const psram_string& ip) {
    promoteToTrusted(PSRAMUtils::fromPSRAMString(ip));
}

void NetworkPresenceTracker::promoteTrustedSenderByIp(const psram_string& ip) {
    auto it = findDeviceByIp(ip);
    if (it == devices_.end()) return;

    NetworkDeviceInfo& device = it->second;
    if (device.is_learned_sender) {
        return;
    }

    device.is_learned_sender = true;
    device.is_persistent = true;
    if (device.learned_timestamp_ms == 0) {
        device.learned_timestamp_ms = getCurrentTimeMs();
    }

    learned_trusted_sender_devices_.insert(ip);
    learned_trusted_sender_devices_.insert(device.mac_address);

    markDevicesDirty();
}

void NetworkPresenceTracker::promoteTrustedWriterByIp(const psram_string& ip) {
    auto it = findDeviceByIp(ip);
    if (it == devices_.end()) return;

    NetworkDeviceInfo& device = it->second;
    if (device.is_learned_writer) {
        return;
    }

    if (!device.is_learned_sender) {
        promoteTrustedSenderByIp(ip);
        it = findDeviceByIp(ip);
        if (it == devices_.end()) return;
    }

    NetworkDeviceInfo& refreshed = it->second;
    refreshed.is_learned_writer = true;
    refreshed.is_persistent = true;
    if (refreshed.learned_timestamp_ms == 0) {
        refreshed.learned_timestamp_ms = getCurrentTimeMs();
    }

    learned_trusted_writer_devices_.insert(ip);
    learned_trusted_writer_devices_.insert(refreshed.mac_address);

    markDevicesDirty();
}

void NetworkPresenceTracker::promoteToTrusted(const std::string& ip) {
    // Manual promote keeps backward compatibility:
    // trusted as sender and writer.
    psram_string ip_ps = PSRAMUtils::toPSRAMString(ip);
    promoteTrustedSenderByIp(ip_ps);
    promoteTrustedWriterByIp(ip_ps);

    /*
    {
        unsigned sc100 = (unsigned)(device.presence_score * 100.0f + 0.5f);
        unsigned sc_i = sc100 / 100, sc_f = sc100 % 100;
        LOG_INFOF(TAG_NET_PRESENCE, "🎓 Auto-promoted device to trusted: %s (%s) [score=%u.%02u]",
                  ip.c_str(), device.mac_address.c_str(), sc_i, sc_f);
    }*/
}

// Cleanup and Maintenance
void NetworkPresenceTracker::cleanupInactiveDevices() {
    uint64_t now_ms = getCurrentTimeMs();
    auto it = devices_.begin();

    while (it != devices_.end()) {
        NetworkDeviceInfo& device = it->second;
        uint64_t inactive_time_ms = now_ms - device.last_seen_ms;

        if (inactive_time_ms > config_.inactive_device_timeout_ms) {
            if (device.inactive_since_ms == 0) {
                device.inactive_since_ms = now_ms;
                LOG_INFOF(TAG_NET_PRESENCE, "Device marked inactive: %s (idle for %llu minutes)",
                         it->first.c_str(), inactive_time_ms / 60000);
            }

            // Remove non-persistent inactive devices
            if (!device.is_persistent && !device.is_whitelisted) {
                LOG_INFOF(TAG_NET_PRESENCE, "Removing inactive device: %s", it->first.c_str());
                it = devices_.erase(it);
                continue;
            }
        } else if (device.inactive_since_ms != 0) {
            // Device became active again
            device.inactive_since_ms = 0;
            LOG_INFOF(TAG_NET_PRESENCE, "Device reactivated: %s", it->first.c_str());
        }

        ++it;
    }
}

void NetworkPresenceTracker::runRetentionCleanup() {
    uint64_t now_ms = getCurrentTimeMs();
    uint64_t retention_threshold_ms = config_.retention_days * 24 * 60 * 60 * 1000ULL;

    auto it = devices_.begin();
    while (it != devices_.end()) {
        const NetworkDeviceInfo& device = it->second;

        if ((device.is_learned_sender || device.is_learned_writer) && device.inactive_since_ms > 0) {
            uint64_t inactive_time_ms = now_ms - device.inactive_since_ms;

            if (inactive_time_ms > retention_threshold_ms) {
                LOG_INFOF(TAG_NET_PRESENCE, "🗑️ Retention cleanup: removing device %s (inactive for %llu days)",
                         it->first.c_str(), inactive_time_ms / (24 * 60 * 60 * 1000));

                // Remove from learned trust
                learned_trusted_sender_devices_.erase(it->first);
                learned_trusted_sender_devices_.erase(device.mac_address);
                learned_trusted_writer_devices_.erase(it->first);
                learned_trusted_writer_devices_.erase(device.mac_address);

                // Remove from persistent storage
                if (persistent_storage_initialized_) {
                    removeDeviceFromNVS(it->first);
                }

                it = devices_.erase(it);
                continue;
            }
        }
        ++it;
    }
}

// Statistics and Status
psram_vector<NetworkDeviceInfo> NetworkPresenceTracker::getAllDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    psram_vector<NetworkDeviceInfo> result;
    result.reserve(devices_.size());

    for (const auto& pair : devices_) {
        result.push_back(pair.second);
    }

    std::sort(result.begin(), result.end(),
              [](const NetworkDeviceInfo& a, const NetworkDeviceInfo& b) {
                  return a.presence_score > b.presence_score;
              });

    return result;
}

psram_vector<NetworkDeviceInfo> NetworkPresenceTracker::getLearnedDevices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    psram_vector<NetworkDeviceInfo> result;

    for (const auto& pair : devices_) {
        if (pair.second.is_learned_sender || pair.second.is_learned_writer) {
            result.push_back(pair.second);
        }
    }

    std::sort(result.begin(), result.end(),
              [](const NetworkDeviceInfo& a, const NetworkDeviceInfo& b) {
                  return a.learned_timestamp_ms > b.learned_timestamp_ms;
              });

    return result;
}

size_t NetworkPresenceTracker::getTrustedDevicesCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::count_if(devices_.begin(), devices_.end(),
                        [](const auto& pair) {
                            return pair.second.is_whitelisted || pair.second.is_learned_sender || pair.second.is_learned_writer;
                        });
}

size_t NetworkPresenceTracker::getLearnedDevicesCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::count_if(devices_.begin(), devices_.end(),
                        [](const auto& pair) { return pair.second.is_learned_sender || pair.second.is_learned_writer; });
}


bool NetworkPresenceTracker::matchesTrustedDevice(const std::string& ip, const std::string& mac) const {
    return matchesTrustedDevice(PSRAMUtils::createPSRAMString(ip.c_str()),
                                PSRAMUtils::createPSRAMString(mac.c_str()));
}

bool NetworkPresenceTracker::matchesTrustedDevice(const psram_string& ip, const psram_string& mac) const {
    return matchAnyPS(make_view(ip), whitelisted_devices_, false) ||
           matchAnyPS(make_view(mac), whitelisted_devices_, true) ||
           matchAnyPS(make_view(ip), learned_trusted_sender_devices_, false) ||
           matchAnyPS(make_view(mac), learned_trusted_sender_devices_, true);
}

bool NetworkPresenceTracker::matchesWriterTrustedDevice(const std::string& ip, const std::string& mac) const {
    return matchesWriterTrustedDevice(PSRAMUtils::createPSRAMString(ip.c_str()),
                                      PSRAMUtils::createPSRAMString(mac.c_str()));
}

bool NetworkPresenceTracker::matchesWriterTrustedDevice(const psram_string& ip, const psram_string& mac) const {
    return matchAnyPS(make_view(ip), whitelisted_devices_, false) ||
           matchAnyPS(make_view(mac), whitelisted_devices_, true) ||
           matchAnyPS(make_view(ip), learned_trusted_writer_devices_, false) ||
           matchAnyPS(make_view(mac), learned_trusted_writer_devices_, true);
}

uint64_t NetworkPresenceTracker::getCurrentTimeMs() const {
    return esp_timer_get_time() / 1000;
}

void NetworkPresenceTracker::parseWhitelistedDevices(const psram_string_vector& device_list) {
    whitelisted_devices_.clear();
    for (const auto& item : device_list) {
        auto view = make_view(item);
        size_t start = 0;
        while (start < view.length) {
            size_t end = start;
            while (end < view.length && view.data[end] != ';') {
                ++end;
            }
            if (end > start) {
                psram_string token;
                token.assign(view.data + start, view.data + end);
                whitelisted_devices_.insert(token);
            }
            start = end + 1;
        }
    }
}

// Backward compatibility methods
psram_string NetworkPresenceTracker::normalizeIp(const psram_string& ip) {
    auto view = make_view(ip);
    psram_string out;
    out.reserve(view.length);
    for (size_t i = 0; i < view.length; ++i) {
        unsigned char c = static_cast<unsigned char>(view.data[i]);
        if (!std::isspace(c)) {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

psram_string NetworkPresenceTracker::normalizeIp(const std::string& ip) {
    return normalizeIp(PSRAMUtils::createPSRAMString(ip.c_str()));
}

psram_string NetworkPresenceTracker::normalizeMac(const psram_string& mac) {
    auto view = make_view(mac);
    psram_string hexdigits;
    hexdigits.reserve(view.length);
    for (size_t i = 0; i < view.length; ++i) {
        unsigned char c = static_cast<unsigned char>(view.data[i]);
        if (std::isxdigit(c)) {
            hexdigits.push_back(static_cast<char>(std::toupper(c)));
        }
    }
    if (hexdigits.size() != 12) {
        return psram_string();
    }
    psram_string normalized;
    normalized.reserve(17);
    for (size_t i = 0; i < hexdigits.size(); ++i) {
        if (i && (i % 2u == 0)) {
            normalized.push_back(':');
        }
        normalized.push_back(hexdigits[i]);
    }
    return normalized;
}

psram_string NetworkPresenceTracker::normalizeMac(const std::string& mac) {
    return normalizeMac(PSRAMUtils::createPSRAMString(mac.c_str()));
}

bool NetworkPresenceTracker::macMatchesPattern(const psram_string& mac, const psram_string& pattern) {
    psram_string mac_norm = canon_mac_ps(make_view(mac));
    psram_string pat_norm = canon_mac_ps(make_view(pattern));
    return wildcardMatchView(mac_norm.c_str(), mac_norm.size(),
                             pat_norm.c_str(), pat_norm.size());
}

bool NetworkPresenceTracker::macMatchesPattern(const std::string& mac, const std::string& pattern) {
    return macMatchesPattern(PSRAMUtils::createPSRAMString(mac.c_str()),
                             PSRAMUtils::createPSRAMString(pattern.c_str()));
}

bool NetworkPresenceTracker::isWhitelisted(const psram_string& ip, const psram_string& mac) const {
    //std::lock_guard<std::mutex> lock(mutex_);
    return matchesTrustedDevice(ip, mac);
}

bool NetworkPresenceTracker::isWhitelisted(const std::string& ip, const std::string& mac) const {
    //std::lock_guard<std::mutex> lock(mutex_);
    return matchesTrustedDevice(ip, mac);
}

void NetworkPresenceTracker::loadAuthorized(const std::vector<std::string>& ips,
                                           const std::vector<std::string>& macs,
                                           const std::vector<std::string>& wl_ips,
                                           const std::vector<std::string>& wl_macs) {
    psram_vector<psram_string> ips_ps;
    psram_vector<psram_string> macs_ps;
    psram_vector<psram_string> wl_ips_ps;
    psram_vector<psram_string> wl_macs_ps;

    ips_ps.reserve(ips.size());
    for (const auto& s : ips) {
        ips_ps.push_back(PSRAMUtils::createPSRAMString(s.c_str()));
    }

    macs_ps.reserve(macs.size());
    for (const auto& s : macs) {
        macs_ps.push_back(PSRAMUtils::createPSRAMString(s.c_str()));
    }

    wl_ips_ps.reserve(wl_ips.size());
    for (const auto& s : wl_ips) {
        wl_ips_ps.push_back(PSRAMUtils::createPSRAMString(s.c_str()));
    }

    wl_macs_ps.reserve(wl_macs.size());
    for (const auto& s : wl_macs) {
        wl_macs_ps.push_back(PSRAMUtils::createPSRAMString(s.c_str()));
    }

    loadAuthorized(ips_ps, macs_ps, wl_ips_ps, wl_macs_ps);
}

// Persistent Storage Implementation
bool NetworkPresenceTracker::saveToPersistentStorage() {
    if (!persistent_storage_initialized_) {
        LOG_WARNING(TAG_NET_PRESENCE, "Persistent storage not initialized");
        return false;
    }

    //std::lock_guard<std::mutex> lock(mutex_);

    // Ensure directory exists through FilesystemTaskDelegate
    FilesystemTaskDelegate::getInstance().createDirectorySync("/data/network");

    // Count devices to save (persistent or learned)
    psram_vector<PersistentDeviceRecord> records;
    for (const auto& [ip, device] : devices_) {
        if (device.is_persistent || device.is_learned_sender || device.is_learned_writer || device.is_whitelisted) {
            PersistentDeviceRecord record = {};

            // Copy strings with bounds checking
            PSRAMUtils::copyToStackBuffer(record.ip_address, sizeof(record.ip_address), device.ip_address);
            PSRAMUtils::copyToStackBuffer(record.mac_address, sizeof(record.mac_address), device.mac_address);

            // Copy data fields
            record.first_seen_ms = device.first_seen_ms;
            record.last_seen_ms = device.last_seen_ms;
            record.learned_timestamp_ms = device.learned_timestamp_ms;
            record.total_packets = device.total_packets;
            record.total_write_packets = device.total_write_packets;
            record.presence_score = device.presence_score;
            record.is_whitelisted = device.is_whitelisted;
            record.is_learned_writer = device.is_learned_writer;
            record.is_learned_sender = device.is_learned_sender;
            record.is_persistent = device.is_persistent;
            record.is_continuously_present = device.is_continuously_present;

            records.push_back(record);
        }
    }

    if (records.empty()) {
        LOG_INFO(TAG_NET_PRESENCE, "No devices to save to persistent storage");
        devices_dirty_ = false;
        return true;
    }

    // Create header
    PersistentStorageHeader header = {};
    header.magic = STORAGE_MAGIC;
    header.version = STORAGE_VERSION;
    header.device_count = static_cast<uint32_t>(records.size());
    header.last_updated_ms = getCurrentTimeMs();

    // Calculate checksum of device records
    const uint8_t* records_data = reinterpret_cast<const uint8_t*>(records.data());
    size_t records_size = records.size() * sizeof(PersistentDeviceRecord);
    header.checksum = calculateChecksum(records_data, records_size);

    // Build complete file data
    psram_string file_data;
    file_data.reserve(sizeof(header) + records_size);

    // Append header
    file_data.append(reinterpret_cast<const char*>(&header), sizeof(header));

    // Append records
    file_data.append(reinterpret_cast<const char*>(records.data()), records_size);

    // Write to file using FilesystemTaskDelegate for proper task coordination
    bool result = FilesystemTaskDelegate::getInstance().writeFileSync(PERSISTENT_STORAGE_FILE, file_data);
    if (!result) {
        LOG_ERROR(TAG_NET_PRESENCE, "Failed to save devices to persistent storage via FilesystemTaskDelegate");
        return false;
    }

    devices_dirty_ = false;
    last_auto_save_ms_ = getCurrentTimeMs();

    LOG_INFOF(TAG_NET_PRESENCE, "✅ Saved %zu devices to persistent storage (%zu bytes)",
              records.size(), file_data.size());
    return true;
}

bool NetworkPresenceTracker::loadFromPersistentStorage() {
    if (!persistent_storage_initialized_) {
        LOG_WARNING(TAG_NET_PRESENCE, "Persistent storage not initialized");
        return false;
    }

    //std::lock_guard<std::mutex> lock(mutex_);

    // Ensure directory exists through FilesystemTaskDelegate
    FilesystemTaskDelegate::getInstance().createDirectorySync("/data/network");

    // Read the persistent storage file using FilesystemTaskDelegate
    psram_string data;
    if (!FilesystemTaskDelegate::getInstance().readFileSync(PERSISTENT_STORAGE_FILE, data)) {
        LOG_INFO(TAG_NET_PRESENCE, "No persistent learning data found, starting fresh");
        return true; // Not an error, just no saved data
    }

    // Validate file size
    if (data.size() < sizeof(PersistentStorageHeader)) {
        LOG_WARNING(TAG_NET_PRESENCE, "Persistent storage file too small, ignoring");
        return false;
    }

    // Parse header
    PersistentStorageHeader header;
    memcpy(&header, data.data(), sizeof(header));

    // Validate magic and version
    if (header.magic != STORAGE_MAGIC) {
        LOG_WARNING(TAG_NET_PRESENCE, "Invalid persistent storage magic, ignoring");
        return false;
    }

    if (header.version != STORAGE_VERSION) {
        LOG_WARNING(TAG_NET_PRESENCE, "Unsupported persistent storage version, ignoring");
        return false;
    }

    // Validate file size matches expected device count
    size_t expected_size = sizeof(PersistentStorageHeader) +
                          (header.device_count * sizeof(PersistentDeviceRecord));
    if (data.size() != expected_size) {
        LOG_WARNINGF(TAG_NET_PRESENCE, "Persistent storage size mismatch (expected %zu, got %zu)",
                     expected_size, data.size());
        return false;
    }

    // Calculate and verify checksum
    uint32_t calculated_checksum = 0;
    const uint8_t* device_data = reinterpret_cast<const uint8_t*>(data.data() + sizeof(header));
    size_t device_data_size = header.device_count * sizeof(PersistentDeviceRecord);

    for (size_t i = 0; i < device_data_size; i++) {
        calculated_checksum ^= device_data[i];
        calculated_checksum = (calculated_checksum << 1) | (calculated_checksum >> 31);
    }

    if (calculated_checksum != header.checksum) {
        LOG_WARNING(TAG_NET_PRESENCE, "Persistent storage checksum mismatch, data corrupted");
        return false;
    }

    // Load devices
    size_t loaded_count = 0;
    const PersistentDeviceRecord* records =
        reinterpret_cast<const PersistentDeviceRecord*>(device_data);

    for (uint32_t i = 0; i < header.device_count; i++) {
        const PersistentDeviceRecord& record = records[i];

        // Create NetworkDeviceInfo from record
        NetworkDeviceInfo device;
        device.ip_address = PSRAMUtils::toPSRAMString(std::string(record.ip_address));
        device.mac_address = PSRAMUtils::toPSRAMString(std::string(record.mac_address));
        device.first_seen_ms = record.first_seen_ms;
        device.last_seen_ms = record.last_seen_ms;
        device.learned_timestamp_ms = record.learned_timestamp_ms;
        device.total_packets = record.total_packets;
        device.total_write_packets = record.total_write_packets;
        device.presence_score = record.presence_score;
        device.is_whitelisted = record.is_whitelisted;
        device.is_learned_writer = record.is_learned_writer;
        device.is_learned_sender = record.is_learned_sender || record.is_learned_writer;
        device.is_persistent = record.is_persistent;
        device.is_continuously_present = record.is_continuously_present;

        // Add to tracking maps
        devices_[device.ip_address] = device;

        if (device.is_whitelisted || device.is_learned_sender || device.is_learned_writer) {
            if (device.is_whitelisted) {
                whitelisted_devices_.insert(device.ip_address);
                whitelisted_devices_.insert(device.mac_address);
            }
            learned_trusted_sender_devices_.insert(device.ip_address);
            learned_trusted_sender_devices_.insert(device.mac_address);
            if (device.is_whitelisted || device.is_learned_writer) {
                learned_trusted_writer_devices_.insert(device.ip_address);
                learned_trusted_writer_devices_.insert(device.mac_address);
            }
        }

        loaded_count++;
    }

    LOG_INFOF(TAG_NET_PRESENCE, "✅ Loaded %zu devices from persistent storage", loaded_count);

    // Check if we have enough learned devices to skip learning mode
    if (loaded_count >= MIN_DEVICES_FOR_SKIP_LEARNING) {
        size_t trusted_count = learned_trusted_sender_devices_.size();
        LOG_INFOF(TAG_NET_PRESENCE, "🎯 Found %zu learned devices (%zu trusted), skipping learning phase",
                  loaded_count, trusted_count);

        // This will be used by isInLearningMode() to return false immediately
        system_start_time_ms_ = 0; // Force out of learning mode

        return true;
    }

    LOG_INFOF(TAG_NET_PRESENCE, "📚 Only %zu devices loaded, entering learning mode", loaded_count);
    return true;
}

// Complete implementations for web interface support
psram_string NetworkPresenceTracker::getConfigJSON() const {
    std::lock_guard<std::mutex> lock(mutex_);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", config_.enabled);
    cJSON_AddBoolToObject(root, "learning_mode", config_.learning_mode);
    cJSON_AddBoolToObject(root, "alert_unauthorized_writes", config_.alert_unauthorized_writes);
    cJSON_AddBoolToObject(root, "track_all_traffic", config_.track_all_traffic);
    cJSON_AddNumberToObject(root, "cleanup_interval_ms", config_.cleanup_interval_ms);
    cJSON_AddNumberToObject(root, "inactive_device_timeout_ms", config_.inactive_device_timeout_ms);
    cJSON_AddNumberToObject(root, "activation_delay_minutes", config_.activation_delay_minutes);
    cJSON_AddNumberToObject(root, "retention_days", config_.retention_days);
    cJSON_AddNumberToObject(root, "trust_threshold_score", config_.trust_threshold_score);
    cJSON_AddNumberToObject(root, "min_observation_period_hours", config_.min_observation_period_hours);

    char* json_string = cJSON_PrintUnformatted(root);
    psram_string result = PSRAMUtils::createPSRAMString(json_string ? json_string : "{}");
    if (json_string) free(json_string);
    cJSON_Delete(root);

    return result;
}

bool NetworkPresenceTracker::loadConfigFromJSON(const std::string& json) {
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return false;

    //std::lock_guard<std::mutex> lock(mutex_);
    NetworkPresenceConfig new_config = config_;

    cJSON* item = cJSON_GetObjectItem(root, "enabled");
    if (item && cJSON_IsBool(item)) new_config.enabled = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "learning_mode");
    if (item && cJSON_IsBool(item)) new_config.learning_mode = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "alert_unauthorized_writes");
    if (item && cJSON_IsBool(item)) new_config.alert_unauthorized_writes = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "track_all_traffic");
    if (item && cJSON_IsBool(item)) new_config.track_all_traffic = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "cleanup_interval_ms");
    if (item && cJSON_IsNumber(item)) new_config.cleanup_interval_ms = (uint32_t)item->valueint;

    item = cJSON_GetObjectItem(root, "inactive_device_timeout_ms");
    if (item && cJSON_IsNumber(item)) new_config.inactive_device_timeout_ms = (uint32_t)item->valueint;

    item = cJSON_GetObjectItem(root, "activation_delay_minutes");
    if (item && cJSON_IsNumber(item)) new_config.activation_delay_minutes = (uint32_t)item->valueint;

    item = cJSON_GetObjectItem(root, "retention_days");
    if (item && cJSON_IsNumber(item)) new_config.retention_days = (uint32_t)item->valueint;

    item = cJSON_GetObjectItem(root, "trust_threshold_score");
    if (item && cJSON_IsNumber(item)) new_config.trust_threshold_score = item->valuedouble;

    item = cJSON_GetObjectItem(root, "min_observation_period_hours");
    if (item && cJSON_IsNumber(item)) new_config.min_observation_period_hours = item->valuedouble;

    config_ = new_config;
    cJSON_Delete(root);

    LOG_INFO(TAG_NET_PRESENCE, "Configuration updated from JSON");
    return true;
}

psram_vector<psram_string> NetworkPresenceTracker::getTrustedDevices() const {
    //std::lock_guard<std::mutex> lock(mutex_);
    psram_vector<psram_string> trusted;
    psram_string_set seen;

    for (const auto& device : whitelisted_devices_) {
        if (seen.insert(device).second) {
            trusted.push_back(device);
        }
    }
    for (const auto& device : learned_trusted_sender_devices_) {
        if (seen.insert(device).second) {
            trusted.push_back(device);
        }
    }
    for (const auto& device : learned_trusted_writer_devices_) {
        if (seen.insert(device).second) {
            trusted.push_back(device);
        }
    }

    return trusted;
}

// Salva un blob binario versionato, endianness little-endian, con top-N per mappe.
bool NetworkPresenceTracker::saveDeviceToNVS(const NetworkDeviceInfo& d) {
    if (!persistent_storage_initialized_) return false;

    static constexpr uint16_t BLOB_VER      = 3;
    static constexpr uint8_t  TOP_PROTOCOLS = 8;
    static constexpr uint8_t  TOP_PORTS     = 8;

    const char* ns = NVS_NAMESPACE_PRESENCE;
    const psram_string key_psram = getStorageKey(d.ip_address); // es. "learned:192.168.1.23"
    const std::string key = PSRAMUtils::fromPSRAMString(key_psram);

    std::vector<uint8_t> buf;
    buf.reserve(192); // stima iniziale

    auto putU8  = [&](uint8_t v){ buf.push_back(v); };
    auto putU16 = [&](uint16_t v){ buf.push_back((uint8_t)(v)); buf.push_back((uint8_t)(v>>8)); };
    [[maybe_unused]] auto putU32 = [&](uint32_t v){
        for (int i=0;i<4;++i) buf.push_back((uint8_t)(v>>(8*i)));
    };
    auto putU64 = [&](uint64_t v){
        for (int i=0;i<8;++i) buf.push_back((uint8_t)(v>>(8*i)));
    };
    auto putBool = [&](bool b){ putU8(b ? 1u : 0u); };
    auto putDouble = [&](double dv){
        static_assert(sizeof(double)==8, "double deve essere 8 byte su questa piattaforma");
        uint64_t le; std::memcpy(&le, &dv, sizeof(double));
        putU64(le);
    };
    auto putShortStr = [&](const psram_string& s){
        uint8_t n = (uint8_t)std::min<size_t>(255, s.size());
        putU8(n);
        buf.insert(buf.end(), s.data(), s.data()+n);
    };

    // Header
    putU16(BLOB_VER);

    // Identità
    putShortStr(d.ip_address);   // len + bytes
    putShortStr(d.mac_address);  // len + bytes

    // Statistiche di traffico
    putU64(d.total_packets);
    putU64(d.total_read_packets);
    putU64(d.total_write_packets);
    putU64(d.first_seen_ms);
    putU64(d.last_seen_ms);

    // Scoring/presenza/trust
    putDouble(d.presence_score);
    putBool(d.is_continuously_present);
    putBool(d.is_learned_sender);
    putBool(d.is_learned_writer);
    putBool(d.is_whitelisted);
    putU64(d.inactive_since_ms);

    // Persistenza/learned
    putBool(d.is_persistent);
    putU64(d.learned_timestamp_ms);

    // Protocol counts: prendi i TOP_PROTOCOLS per frequenza
    {
        std::vector<std::pair<uint16_t, uint64_t>> v;
        v.reserve(d.protocol_counts.size());
        for (const auto& kv : d.protocol_counts) {
            uint16_t proto = static_cast<uint16_t>(kv.first);
            v.emplace_back(proto, kv.second);
        }
        std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });
        uint8_t n = (uint8_t)std::min<size_t>(TOP_PROTOCOLS, v.size());
        putU8(n);
        for (size_t i=0; i<n; ++i) {
            putU16(v[i].first);   // ProtocolType (cast a u16)
            putU64(v[i].second);  // count
        }
    }

    // Port usage: prendi i TOP_PORTS per frequenza
    {
        std::vector<std::pair<uint16_t, uint64_t>> v;
        v.reserve(d.port_usage.size());
        for (const auto& kv : d.port_usage) v.emplace_back(kv.first, kv.second);
        std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });
        uint8_t n = (uint8_t)std::min<size_t>(TOP_PORTS, v.size());
        putU8(n);
        for (size_t i=0; i<n; ++i) {
            putU16(v[i].first);   // port
            putU64(v[i].second);  // count
        }
    }

    // Scrittura atomica su NVS tramite AsyncStorage engine
    esp_err_t err = AsyncStorage::Global::nvsSetBlob(ns, key, buf.data(), buf.size());
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_NET_PRESENCE, "NVS set_blob failed for key '%s': %s",
                   key.c_str(), esp_err_to_name(err));
        return false;
    }
    return true;
}

void NetworkPresenceTracker::demoteFromTrusted(const psram_string& ip) {
    demoteFromTrusted(PSRAMUtils::fromPSRAMString(ip));
}

void NetworkPresenceTracker::demoteFromTrusted(const std::string& ip) {
    //std::lock_guard<std::mutex> lock(mutex_);
    psram_string mac_to_clear;

    auto it = findDeviceByIp(ip);
    if (it != devices_.end()) {
        mac_to_clear = it->second.mac_address;
        it->second.is_learned_sender = false;
        it->second.is_learned_writer = false;
        it->second.is_persistent = false;
        it->second.learned_timestamp_ms = 0;
    }

    learned_trusted_sender_devices_.erase(PSRAMUtils::toPSRAMString(ip));
    learned_trusted_writer_devices_.erase(PSRAMUtils::toPSRAMString(ip));
    if (!mac_to_clear.empty()) {
        learned_trusted_sender_devices_.erase(mac_to_clear);
        learned_trusted_writer_devices_.erase(mac_to_clear);
    }

    // Remove from persistent storage
    if (persistent_storage_initialized_) {
        removeDeviceFromNVS(ip);
    }

    LOG_INFOF(TAG_NET_PRESENCE, "Device %s demoted from trusted", ip.c_str());
}

void NetworkPresenceTracker::clearLearningData() {
    //std::lock_guard<std::mutex> lock(mutex_);

    // Clear learned devices but keep whitelisted ones (in-RAM)
    for (auto& pair : devices_) {
        if ((pair.second.is_learned_sender || pair.second.is_learned_writer) && !pair.second.is_whitelisted) {
            pair.second.is_learned_sender = false;
            pair.second.is_learned_writer = false;
            pair.second.is_persistent = false;
            pair.second.learned_timestamp_ms = 0;
        }
    }
    learned_trusted_sender_devices_.clear();
    learned_trusted_writer_devices_.clear();

    // Clear persistent storage via AsyncStorage engine
    if (persistent_storage_initialized_) {
        esp_err_t err = AsyncStorage::Global::nvsEraseAll(NVS_NAMESPACE_PRESENCE);
        if (err == ESP_OK) {
            LOG_INFO(TAG_NET_PRESENCE, "Persistent storage cleared for network presence learning data");
        } else {
            LOG_WARNINGF(TAG_NET_PRESENCE,
                        "Failed to clear network presence storage (err=%s)",
                        esp_err_to_name(err));
        }
    }

    LOG_INFO(TAG_NET_PRESENCE, "🗑️ All learning data cleared");
}


NetworkDeviceInfo* NetworkPresenceTracker::getDeviceInfo(const psram_string& ip) {
    //std::lock_guard<std::mutex> lock(mutex_);
    auto it = findDeviceByIp(ip);
    return (it != devices_.end()) ? &it->second : nullptr;
}

NetworkDeviceInfo* NetworkPresenceTracker::getDeviceInfo(const std::string& ip) {
    //std::lock_guard<std::mutex> lock(mutex_);
    auto it = findDeviceByIp(ip);
    return (it != devices_.end()) ? &it->second : nullptr;
}

const NetworkDeviceInfo* NetworkPresenceTracker::getDeviceInfo(const psram_string& ip) const {
    //std::lock_guard<std::mutex> lock(mutex_);
    auto it = findDeviceByIp(ip);
    return (it != devices_.end()) ? &it->second : nullptr;
}

const NetworkDeviceInfo* NetworkPresenceTracker::getDeviceInfo(const std::string& ip) const {
    //std::lock_guard<std::mutex> lock(mutex_);
    auto it = findDeviceByIp(ip);
    return (it != devices_.end()) ? &it->second : nullptr;
}

psram_string NetworkPresenceTracker::getDevicesStatsJSON() const {
    // Step 1: Quickly copy device data while holding the lock
    psram_vector<NetworkDeviceInfo> devices_copy;
    uint64_t total_tracked_packets_copy;
    uint64_t total_write_packets_copy;
    uint64_t now_ms = getCurrentTimeMs();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        devices_copy.reserve(devices_.size());
        for (const auto& pair : devices_) {
            devices_copy.push_back(pair.second);
        }
        total_tracked_packets_copy = total_tracked_packets_;
        total_write_packets_copy = total_write_packets_;
    }
    // Lock released here - now work with the copy

    // Step 2: Build JSON without holding any locks
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        LOG_ERROR(TAG_NET_PRESENCE, "Failed to create JSON root object");
        return "{}";
    }

    cJSON* devices_array = cJSON_CreateArray();
    if (!devices_array) {
        cJSON_Delete(root);
        return "{}";
    }

    size_t trusted_count = 0;
    size_t learned_count = 0;

    for (const auto& device : devices_copy) {
        cJSON* device_obj = cJSON_CreateObject();
        if (!device_obj) {
            LOG_WARNING(TAG_NET_PRESENCE, "Failed to create device JSON object, skipping");
            continue;
        }

        const bool is_trusted_sender = device.is_whitelisted || device.is_learned_sender || device.is_persistent;
        const bool is_trusted_writer = device.is_whitelisted || device.is_learned_writer;
        const bool is_trusted = is_trusted_sender || is_trusted_writer;
        const bool is_reader = device.total_read_packets > 0;
        const bool is_writer = device.total_write_packets > 0;
        const bool is_sender_only = device.total_packets > 0 && !is_reader && !is_writer;
        const char* operation_role = is_writer && is_reader ? "reader_writer" :
                                     is_writer ? "writer_only" :
                                     is_reader ? "reader_only" :
                                     is_sender_only ? "sender_only" : "unknown";
        if (is_trusted) trusted_count++;
        if (device.is_learned_sender || device.is_learned_writer) learned_count++;

        cJSON_AddStringToObject(device_obj, "ip_address", device.ip_address.c_str());
        cJSON_AddStringToObject(device_obj, "mac_address", device.mac_address.c_str());
        cJSON_AddNumberToObject(device_obj, "total_packets", (double)device.total_packets);
        cJSON_AddNumberToObject(device_obj, "total_read_packets", (double)device.total_read_packets);
        cJSON_AddNumberToObject(device_obj, "total_write_packets", (double)device.total_write_packets);
        cJSON_AddNumberToObject(device_obj, "last_seen_ms", (double)device.last_seen_ms);
        cJSON_AddNumberToObject(device_obj, "first_seen_ms", (double)device.first_seen_ms);
        cJSON_AddNumberToObject(device_obj, "presence_score", device.presence_score);
        cJSON_AddBoolToObject(device_obj, "is_continuously_present", device.is_continuously_present);
        cJSON_AddBoolToObject(device_obj, "is_learned_sender", device.is_learned_sender);
        cJSON_AddBoolToObject(device_obj, "is_learned_writer", device.is_learned_writer);
        cJSON_AddBoolToObject(device_obj, "is_whitelisted", device.is_whitelisted);
        cJSON_AddBoolToObject(device_obj, "is_persistent", device.is_persistent);
        cJSON_AddNumberToObject(device_obj, "learned_timestamp_ms", (double)device.learned_timestamp_ms);
        cJSON_AddNumberToObject(device_obj, "inactive_since_ms", (double)device.inactive_since_ms);
        cJSON_AddBoolToObject(device_obj, "is_trusted_sender", is_trusted_sender);
        cJSON_AddBoolToObject(device_obj, "is_trusted_writer", is_trusted_writer);
        cJSON_AddBoolToObject(device_obj, "is_trusted", is_trusted);
        cJSON_AddBoolToObject(device_obj, "is_learned", device.is_learned_sender || device.is_learned_writer);
        cJSON_AddBoolToObject(device_obj, "is_reader", is_reader);
        cJSON_AddBoolToObject(device_obj, "is_writer", is_writer);
        cJSON_AddBoolToObject(device_obj, "is_sender_only", is_sender_only);
        cJSON_AddStringToObject(device_obj, "operation_role", operation_role);

        if (!device.protocol_counts.empty()) {
            cJSON* protocol_counts = cJSON_CreateObject();
            cJSON* protocol_labels = cJSON_CreateArray();
            psram_string_set added_labels;
            uint64_t top_count = 0;
            const char* top_label = nullptr;

            for (const auto& entry : device.protocol_counts) {
                const char* label = protocolTypeToLabel(entry.first);
                if (!label) label = "Unknown";

                cJSON_AddNumberToObject(protocol_counts, label, (double)entry.second);

                psram_string label_ps = PSRAMUtils::createPSRAMString(label);
                if (added_labels.insert(label_ps).second) {
                    cJSON_AddItemToArray(protocol_labels, cJSON_CreateString(label));
                }

                if (entry.second > top_count) {
                    top_count = entry.second;
                    top_label = label;
                }
            }

            if (cJSON_GetArraySize(protocol_counts) > 0) {
                cJSON_AddItemToObject(device_obj, "protocol_counts", protocol_counts);
            } else {
                cJSON_Delete(protocol_counts);
            }

            if (cJSON_GetArraySize(protocol_labels) > 0) {
                cJSON_AddItemToObject(device_obj, "protocols", protocol_labels);
            } else {
                cJSON_Delete(protocol_labels);
            }

            if (top_label) {
                cJSON_AddStringToObject(device_obj, "primary_protocol", top_label);
            }
        }

        cJSON_AddItemToArray(devices_array, device_obj);
    }

    cJSON_AddItemToObject(root, "devices", devices_array);
    cJSON_AddNumberToObject(root, "total_devices", (double)devices_copy.size());
    cJSON_AddNumberToObject(root, "trusted_devices", (double)trusted_count);
    cJSON_AddNumberToObject(root, "learned_devices", (double)learned_count);
    cJSON_AddNumberToObject(root, "total_tracked_packets", (double)total_tracked_packets_copy);
    cJSON_AddNumberToObject(root, "total_write_packets", (double)total_write_packets_copy);
    cJSON_AddNumberToObject(root, "current_time_ms", (double)now_ms);

    char* json_string = cJSON_PrintUnformatted(root);
    psram_string result = PSRAMUtils::createPSRAMString(json_string ? json_string : "{}");
    if (json_string) free(json_string);
    cJSON_Delete(root);

    return result;
}



psram_string NetworkPresenceTracker::getLearnedDevicesJSON() const {
    psram_vector<NetworkDeviceInfo> learned_devices_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        learned_devices_copy.reserve(devices_.size());
        for (const auto& pair : devices_) {
            if (pair.second.is_learned_sender || pair.second.is_learned_writer) {
                learned_devices_copy.push_back(pair.second);
            }
        }
    }

    cJSON* root = cJSON_CreateObject();
    cJSON* learned_array = cJSON_CreateArray();

    for (const auto& device : learned_devices_copy) {
        cJSON* device_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(device_obj, "ip_address", device.ip_address.c_str());
        cJSON_AddStringToObject(device_obj, "mac_address", device.mac_address.c_str());
        cJSON_AddNumberToObject(device_obj, "presence_score", device.presence_score);
        cJSON_AddNumberToObject(device_obj, "learned_timestamp_ms", (double)device.learned_timestamp_ms);
        cJSON_AddNumberToObject(device_obj, "total_packets", (double)device.total_packets);
        cJSON_AddBoolToObject(device_obj, "is_learned_sender", device.is_learned_sender);
        cJSON_AddBoolToObject(device_obj, "is_learned_writer", device.is_learned_writer);
        cJSON_AddBoolToObject(device_obj, "is_persistent", device.is_persistent);
        cJSON_AddItemToArray(learned_array, device_obj);
    }

    cJSON_AddItemToObject(root, "learned_devices", learned_array);
    cJSON_AddNumberToObject(root, "total_learned", (double)learned_devices_copy.size());

    //LOG_INFO("NetworkPresenceTracker", "FOR END1");
    char* json_string = cJSON_PrintUnformatted(root);
    //LOG_INFO("NetworkPresenceTracker", "FOR END2");
    psram_string result = PSRAMUtils::createPSRAMString(json_string ? json_string : "{}");
    //LOG_INFO("NetworkPresenceTracker", "FOR END3");
    if (json_string) free(json_string);
    //LOG_INFO("NetworkPresenceTracker", "FOR END4");
    cJSON_Delete(root);

    //LOG_INFO("NetworkPresenceTracker", "RESULT");
    return result;
}

void NetworkPresenceTracker::clearAllDevices() {
    std::lock_guard<std::mutex> lock(mutex_);
    devices_.clear();
    learned_trusted_sender_devices_.clear();
    learned_trusted_writer_devices_.clear();
    total_tracked_packets_ = 0;
    total_write_packets_ = 0;

    LOG_INFO(TAG_NET_PRESENCE, "🗑️ All device data cleared");
}

size_t NetworkPresenceTracker::getUntrustedDevicesCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::count_if(devices_.begin(), devices_.end(),
                        [](const auto& pair) {
                            return !pair.second.is_whitelisted &&
                                   !pair.second.is_learned_sender &&
                                   !pair.second.is_learned_writer;
                        });
}

void NetworkPresenceTracker::trackWritePacket(const NetworkPacket& packet, bool is_write_operation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_write_operation || !config_.enabled) return;

    total_write_packets_++;

    psram_string src_ip_ps = packet.src_ip.empty()
        ? psram_string()
        : PSRAMUtils::createPSRAMString(packet.src_ip.c_str());

    auto it = src_ip_ps.empty() ? devices_.end() : findDeviceByIp(src_ip_ps);
    if (it != devices_.end()) {
        it->second.total_write_packets++;
    }
}

// NVS Storage helpers
psram_string NetworkPresenceTracker::getStorageKey(const psram_string& ip) const {
    psram_string key = PSRAMUtils::createPSRAMString("dev_");
    key += ip;
    return key;
}

psram_string NetworkPresenceTracker::getStorageKey(const std::string& ip) const {
    return getStorageKey(PSRAMUtils::createPSRAMString(ip.c_str()));
}

bool NetworkPresenceTracker::loadDeviceFromNVS(const std::string& ip, NetworkDeviceInfo& device) {
    if (!persistent_storage_initialized_) return false;

    const char* ns = NVS_NAMESPACE_PRESENCE;
    const psram_string key_psram = getStorageKey(PSRAMUtils::createPSRAMString(ip.c_str()));
    const std::string key = PSRAMUtils::fromPSRAMString(key_psram);

    // Load blob data via AsyncStorage engine
    std::vector<uint8_t> buf;
    esp_err_t r = AsyncStorage::Global::nvsGetBlob(ns, key, buf);
    if (r != ESP_OK || buf.empty()) return false;

    auto rd_ok = [&](size_t off, size_t n){ return off + n <= buf.size(); };

    // Helper LE readers
    auto rdU8  = [&](size_t& o){ uint8_t v=0; if(!rd_ok(o,1)) return (uint8_t)0; v=buf[o]; o+=1; return v; };
    auto rdU16 = [&](size_t& o){ uint16_t v=0; if(!rd_ok(o,2)) return (uint16_t)0; v=(uint16_t)buf[o] | ((uint16_t)buf[o+1]<<8); o+=2; return v; };
    auto rdU64 = [&](size_t& o){ uint64_t v=0; if(!rd_ok(o,8)) return (uint64_t)0; for(int i=0;i<8;++i) v |= ((uint64_t)buf[o+i])<<(8*i); o+=8; return v; };
    auto rdBool= [&](size_t& o){ return rdU8(o)!=0; };
    auto rdDbl = [&](size_t& o){ double d=0; if(!rd_ok(o,8)) return 0.0; std::memcpy(&d, &buf[o], 8); o+=8; return d; };
    auto rdStr8= [&](size_t& o){
        uint8_t n = rdU8(o);
        if(!rd_ok(o,n)) n = (uint8_t)std::min<size_t>(n, buf.size()-o);
        std::string s; s.reserve(n); s.assign((const char*)&buf[o], (size_t)n); o+=n;
        return s;
    };

    // 2) Prova a leggere come BLOB versionato (inizia con u16 versione)
    bool parsed = false;
    size_t off = 0;
    if (buf.size() >= 2) {
        uint16_t ver = rdU16(off);
        if (ver == 3 || ver == 2) {
            // v3/v2: decodifica sequenza
            NetworkDeviceInfo d{};
            d.ip_address  = PSRAMUtils::toPSRAMString(rdStr8(off));
            d.mac_address = PSRAMUtils::toPSRAMString(rdStr8(off));

            d.total_packets        = rdU64(off);
            d.total_read_packets   = rdU64(off);
            d.total_write_packets  = rdU64(off);
            d.first_seen_ms        = rdU64(off);
            d.last_seen_ms         = rdU64(off);

            d.presence_score         = rdDbl(off);
            d.is_continuously_present= rdBool(off);
            if (ver >= 3) {
                d.is_learned_sender  = rdBool(off);
            }
            d.is_learned_writer      = rdBool(off);
            d.is_whitelisted         = rdBool(off);
            d.inactive_since_ms      = rdU64(off);

            d.is_persistent          = rdBool(off);
            d.learned_timestamp_ms   = rdU64(off);
            if (ver < 3) {
                d.is_learned_sender = d.is_learned_writer;
            }

            // protocol_counts (top-N)
            d.protocol_counts.clear();
            if (rd_ok(off,1)) {
                uint8_t n = rdU8(off);
                for (uint8_t i=0; i<n && rd_ok(off,2+8); ++i) {
                    uint16_t proto = rdU16(off);
                    uint64_t cnt   = rdU64(off);
                    d.protocol_counts[(ProtocolType)proto] += cnt;
                }
            }

            // port_usage (top-N)
            d.port_usage.clear();
            if (rd_ok(off,1)) {
                uint8_t n = rdU8(off);
                for (uint8_t i=0; i<n && rd_ok(off,2+8); ++i) {
                    uint16_t port = rdU16(off);
                    uint64_t cnt  = rdU64(off);
                    d.port_usage[port] += cnt;
                }
            }

            device = std::move(d);
            parsed = true;
        }
    }

    if (parsed) return true;

    // 3) Fallback: vecchio blob "struct fissa"
    // Layout atteso (salvato in passato):
    //   ip[16], mac[18], u64 learned_ts, double presence_score, bool learned, bool persistent, padding ~6
    struct OldBlob {
        char     ip[16];
        char     mac[18];
        uint64_t learned_timestamp_ms;
        double   presence_score;
        uint8_t  is_learned_writer;
        uint8_t  is_persistent;
        uint8_t  _reserved[6];
    };

    if (buf.size() == sizeof(OldBlob)) {
        OldBlob ob{};
        std::memcpy(&ob, buf.data(), sizeof(OldBlob));

        NetworkDeviceInfo d{};
        d.ip_address           = PSRAMUtils::toPSRAMString(std::string(ob.ip, strnlen(ob.ip, sizeof(ob.ip))));
        d.mac_address          = PSRAMUtils::toPSRAMString(std::string(ob.mac, strnlen(ob.mac, sizeof(ob.mac))));
        d.learned_timestamp_ms = ob.learned_timestamp_ms;
        d.presence_score       = ob.presence_score;
        d.is_learned_writer    = (ob.is_learned_writer != 0);
        d.is_learned_sender    = d.is_learned_writer;
        d.is_persistent        = (ob.is_persistent != 0);

        // Campi non presenti nel vecchio formato rimangono default (0/false)
        device = std::move(d);
        return true;
    }

    // Formato sconosciuto
    return false;
}

bool NetworkPresenceTracker::loadDeviceFromNVS(const psram_string& ip, NetworkDeviceInfo& device) {
    return loadDeviceFromNVS(PSRAMUtils::fromPSRAMString(ip), device);
}

void NetworkPresenceTracker::removeDeviceFromNVS(const std::string& ip) {
    if (!persistent_storage_initialized_) return;

    const psram_string key_psram = getStorageKey(PSRAMUtils::createPSRAMString(ip.c_str()));
    const std::string key = PSRAMUtils::fromPSRAMString(key_psram);
    const esp_err_t r = AsyncStorage::Global::nvsEraseKey(NVS_NAMESPACE_PRESENCE, key);
    if (r != ESP_OK && r != ESP_ERR_NVS_NOT_FOUND) {
        LOG_ERRORF(TAG_NET_PRESENCE, "NVS erase_key failed for '%s': %s",
                   key.c_str(), esp_err_to_name(r));
    }
}

void NetworkPresenceTracker::removeDeviceFromNVS(const psram_string& ip) {
    if (!persistent_storage_initialized_) return;

    const psram_string key_psram = getStorageKey(ip);
    const std::string key = PSRAMUtils::fromPSRAMString(key_psram);
    const esp_err_t r = AsyncStorage::Global::nvsEraseKey(NVS_NAMESPACE_PRESENCE, key);
    if (r != ESP_OK && r != ESP_ERR_NVS_NOT_FOUND) {
        LOG_ERRORF(TAG_NET_PRESENCE, "NVS erase_key failed for '%s': %s",
                   key.c_str(), esp_err_to_name(r));
    }
}

// Learning mode detection - returns true if we're still in the initial learning phase
bool NetworkPresenceTracker::isInLearningMode() const {
    //std::lock_guard<std::mutex> lock(mutex_);

    // If learning_mode is disabled, we're never in learning mode
    if (!config_.learning_mode) {
        static bool protection_mode_logged = false;
        if (!protection_mode_logged) {
            LOG_INFO(TAG_NET_PRESENCE, "🛡️ PROTECTION MODE: Learning mode disabled in configuration");

            // Note: Logging to ids_events.log happens in IntrusionDetectionGeneral where reporting_engine is available

            protection_mode_logged = true;
        }
        return false;
    }

    // Check if we have enough learned devices to skip learning phase entirely
    size_t trusted_devices_count = 0;
    size_t persistent_devices_count = 0;
    for (const auto& [ip, device] : devices_) {
        if (device.is_whitelisted || device.is_learned_sender || device.is_learned_writer) {
            trusted_devices_count++;
            if (device.is_persistent) {
                persistent_devices_count++;
            }
        }
    }

    // If we have sufficient trusted devices, never enter learning mode
    if (trusted_devices_count >= MIN_DEVICES_FOR_SKIP_LEARNING ||
        persistent_devices_count >= MIN_DEVICES_FOR_SKIP_LEARNING) {
        static bool skip_logged = false;
        if (!skip_logged) {
            LOG_INFOF(TAG_NET_PRESENCE, "🎯 PROTECTION MODE ACTIVE - Learning phase skipped, "
                      "found %zu trusted devices (%zu persistent)",
                      trusted_devices_count, persistent_devices_count);
            skip_logged = true;
        }
        return false; // Skip learning phase entirely
    }

    uint64_t current_time_ms = getCurrentTimeMs();
    uint64_t elapsed_minutes = (current_time_ms - system_start_time_ms_) / (1000 * 60);
    uint64_t remaining_minutes = config_.activation_delay_minutes > elapsed_minutes ?
                                config_.activation_delay_minutes - elapsed_minutes : 0;

    bool is_learning = elapsed_minutes < config_.activation_delay_minutes;

    // Log phase transitions and periodic status
    static bool last_learning_state = true;
    static uint64_t last_log_time = 0;
    static uint64_t log_interval_ms = 60000; // Log every minute

    // Log phase transition
    if (last_learning_state != is_learning) {
        if (is_learning) {
            LOG_INFOF(TAG_NET_PRESENCE, "🎓 LEARNING MODE ACTIVE: %llu/%u minutes elapsed, %zu devices tracked",
                     elapsed_minutes, config_.activation_delay_minutes, devices_.size());
        } else {
            LOG_INFOF(TAG_NET_PRESENCE, "🛡️ PROTECTION MODE ACTIVATED: Learning phase completed after %llu minutes, %zu devices learned",
                     elapsed_minutes, devices_.size());

            // Note: Use notifyLearningComplete() to save devices when learning actually ends
        }
        last_learning_state = is_learning;
    }

    // Periodic status logging during learning phase
    if (is_learning && (current_time_ms - last_log_time) >= log_interval_ms) {
        LOG_INFOF(TAG_NET_PRESENCE, "🎓 Learning progress: %llu/%u min (%llu min remaining), %zu devices, %zu trusted",
                 elapsed_minutes, config_.activation_delay_minutes, remaining_minutes,
                 devices_.size(), trusted_devices_count);
        last_log_time = current_time_ms;
    }

    return is_learning;
}

void NetworkPresenceTracker::notifyLearningComplete() {
    //std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO(TAG_NET_PRESENCE, "🎓➡️🛡️ Learning phase completed - saving discovered devices");

    // Force save immediately when learning completes
    if (devices_dirty_ && persistent_storage_initialized_) {
        if (saveToPersistentStorage()) {
            LOG_INFOF(TAG_NET_PRESENCE, "✅ Successfully saved %zu devices after learning completion", devices_.size());
        } else {
            LOG_ERROR(TAG_NET_PRESENCE, "❌ Failed to save devices after learning completion");
        }
    } else if (!devices_dirty_) {
        LOG_INFO(TAG_NET_PRESENCE, "ℹ️ No new devices to save after learning completion");
    }

    // Learning completion save is done
}

// Device lookup helpers - handle both IP-based and MAC-based keys
psram_map<psram_string, NetworkDeviceInfo>::iterator NetworkPresenceTracker::findDeviceByIp(const psram_string& ip) {
    return findDeviceByIp(PSRAMUtils::fromPSRAMString(ip));
}

psram_map<psram_string, NetworkDeviceInfo>::iterator NetworkPresenceTracker::findDeviceByIp(const std::string& ip) {
    // Convert std::string to psram_string for lookup
    psram_string ip_psram = PSRAMUtils::createPSRAMString(ip.c_str());

    // First try direct IP lookup
    auto it = devices_.find(ip_psram);
    if (it != devices_.end()) {
        return it;
    }

    // Then search by IP address field in case device was stored with MAC key
    for (auto iter = devices_.begin(); iter != devices_.end(); ++iter) {
        if (iter->second.ip_address == ip_psram) {
            return iter;
        }
    }

    return devices_.end();
}

psram_map<psram_string, NetworkDeviceInfo>::const_iterator NetworkPresenceTracker::findDeviceByIp(const psram_string& ip) const {
    return findDeviceByIp(PSRAMUtils::fromPSRAMString(ip));
}

psram_map<psram_string, NetworkDeviceInfo>::const_iterator NetworkPresenceTracker::findDeviceByIp(const std::string& ip) const {
    // Convert std::string to psram_string for lookup
    psram_string ip_psram = PSRAMUtils::createPSRAMString(ip.c_str());

    // First try direct IP lookup
    auto it = devices_.find(ip_psram);
    if (it != devices_.end()) {
        return it;
    }

    // Then search by IP address field in case device was stored with MAC key
    for (auto iter = devices_.begin(); iter != devices_.end(); ++iter) {
        if (iter->second.ip_address == ip_psram) {
            return iter;
        }
    }

    return devices_.end();
}


 // PSRAM-friendly version that accepts char* directly (avoids std::string conversion)
  bool NetworkPresenceTracker::loadConfigFromJSON(const char* json, size_t len) {
      if (!json) return false;

      // Use cJSON_ParseWithLength if len is provided, otherwise cJSON_Parse
      cJSON* root = (len > 0) ? cJSON_ParseWithLength(json, len) : cJSON_Parse(json);
      if (!root) return false;

      //std::lock_guard<std::mutex> lock(mutex_);
      NetworkPresenceConfig new_config = config_;

      cJSON* item = cJSON_GetObjectItem(root, "enabled");
      if (item && cJSON_IsBool(item)) new_config.enabled = cJSON_IsTrue(item);

      item = cJSON_GetObjectItem(root, "learning_mode");
      if (item && cJSON_IsBool(item)) new_config.learning_mode = cJSON_IsTrue(item);

      item = cJSON_GetObjectItem(root, "alert_unauthorized_writes");
      if (item && cJSON_IsBool(item)) new_config.alert_unauthorized_writes = cJSON_IsTrue(item);

      item = cJSON_GetObjectItem(root, "track_all_traffic");
      if (item && cJSON_IsBool(item)) new_config.track_all_traffic = cJSON_IsTrue(item);

      item = cJSON_GetObjectItem(root, "cleanup_interval_ms");
      if (item && cJSON_IsNumber(item)) new_config.cleanup_interval_ms = (uint32_t)item->valueint;

      item = cJSON_GetObjectItem(root, "inactive_device_timeout_ms");
      if (item && cJSON_IsNumber(item)) new_config.inactive_device_timeout_ms =
  (uint32_t)item->valueint;

      item = cJSON_GetObjectItem(root, "activation_delay_minutes");
      if (item && cJSON_IsNumber(item)) new_config.activation_delay_minutes =
  (uint32_t)item->valueint;

      item = cJSON_GetObjectItem(root, "retention_days");
      if (item && cJSON_IsNumber(item)) new_config.retention_days = (uint32_t)item->valueint;

      item = cJSON_GetObjectItem(root, "trust_threshold_score");
      if (item && cJSON_IsNumber(item)) new_config.trust_threshold_score = item->valuedouble;

      item = cJSON_GetObjectItem(root, "min_observation_period_hours");
      if (item && cJSON_IsNumber(item)) new_config.min_observation_period_hours = item->valuedouble;

      config_ = new_config;
      cJSON_Delete(root);

      LOG_INFO(TAG_NET_PRESENCE, "Configuration updated from JSON (PSRAM-optimized)");
      return true;
  }

// Auto-save helper methods
void NetworkPresenceTracker::markDevicesDirty() {
    devices_dirty_ = true;
}

void NetworkPresenceTracker::checkAutoSave() {
    if (!devices_dirty_ || !persistent_storage_initialized_) {
        return;
    }

    // NEVER autosave during learning mode - only save when learning completes
    if (isInLearningMode()) {
        return; // Explicitly skip autosave during discovery
    }

    uint64_t now = getCurrentTimeMs();
    if (now - last_auto_save_ms_ >= AUTO_SAVE_INTERVAL_MS) {
        LOG_INFO(TAG_NET_PRESENCE, "🔄 Auto-saving learned devices (normal mode)...");
        saveToPersistentStorage();
    }
}

uint32_t NetworkPresenceTracker::calculateChecksum(const uint8_t* data, size_t size) const {
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum ^= data[i];
        checksum = (checksum << 1) | (checksum >> 31); // Rotate left
    }
    return checksum;
}
void NetworkPresenceTracker::loadAuthorized(const psram_vector<psram_string>& ips,
                                            const psram_vector<psram_string>& macs,
                                            const psram_vector<psram_string>& wl_ips,
                                            const psram_vector<psram_string>& wl_macs) {
    //std::lock_guard<std::mutex> lock(mutex_);
    whitelisted_devices_.clear();

    auto append_list = [&](const psram_vector<psram_string>& list, bool mac) {
        for (const auto& entry : list) {
            if (entry.empty()) {
                continue;
            }
            psram_string normalized = mac ? canon_mac_ps(make_view(entry))
                                          : normalizeIp(entry);
            if (!normalized.empty()) {
                whitelisted_devices_.insert(normalized);
            }
        }
    };

    append_list(ips, false);
    append_list(macs, true);
    append_list(wl_ips, false);
    append_list(wl_macs, true);

    LOG_INFOF(TAG_NET_PRESENCE, "Loaded whitelists (PSRAM): ips=%u macs=%u wl_ips=%u wl_macs=%u",
              (unsigned)ips.size(), (unsigned)macs.size(),
              (unsigned)wl_ips.size(), (unsigned)wl_macs.size());
}
