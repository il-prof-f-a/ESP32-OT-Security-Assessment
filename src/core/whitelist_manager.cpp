#include "whitelist_manager.h"
#include "logging_system.h"
#include <arpa/inet.h>
#include <sstream>
#include <algorithm>
#include <cstring>
#include "cJSON.h"
#include <esp_heap_caps.h>
#include "psram_json_parser.h"
#include "task_config.h"

static const char* TAG = "Whitelist";

// MACPattern implementation
MACPattern::MACPattern(const psram_string& mac_pattern) : pattern(mac_pattern) {
    std::string std_pattern = PSRAMUtils::fromPSRAMString(mac_pattern);
    if (!parseMACPattern(std_pattern, addr, mask)) {
        LOG_ERRORF(TAG, "Failed to parse MAC pattern: %s", std_pattern.c_str());
        memset(addr, 0, 6);
        memset(mask, 0, 6);
    }
}

MACPattern::MACPattern(const char* mac_pattern) : pattern(PSRAMUtils::createPSRAMString(mac_pattern)) {
    std::string std_pattern(mac_pattern);
    if (!parseMACPattern(std_pattern, addr, mask)) {
        LOG_ERRORF(TAG, "Failed to parse MAC pattern: %s", mac_pattern);
        memset(addr, 0, 6);
        memset(mask, 0, 6);
    }
}

bool MACPattern::matches(const uint8_t* mac) const {
    if (!mac || !isValid()) return false;
    for (int i = 0; i < 6; i++) {
        if ((mac[i] & mask[i]) != (addr[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

bool MACPattern::matches(const std::string& mac_str) const {
    uint8_t mac_bytes[6];
    if (!stringToMAC(mac_str, mac_bytes)) return false;
    return matches(mac_bytes);
}

bool MACPattern::isValid() const {
    // Valid if at least one byte has a non-zero mask
    for (int i = 0; i < 6; i++) {
        if (mask[i] != 0) return true;
    }
    return false;
}

bool MACPattern::parseMACPattern(const std::string& pattern, uint8_t* addr, uint8_t* mask) {
    if (!addr || !mask) return false;

    memset(addr, 0, 6);
    memset(mask, 0, 6);

    // Split by ':'
    std::string current_byte;
    int byte_idx = 0;

    for (size_t i = 0; i <= pattern.length() && byte_idx < 6; i++) {
        if (i == pattern.length() || pattern[i] == ':') {
            if (current_byte.empty()) return false;

            if (current_byte == "*") {
                // Wildcard - keep mask[byte_idx] = 0
                addr[byte_idx] = 0;
            } else {
                // Parse hex byte
                if (current_byte.length() != 2) return false;

                int value = 0;
                for (char c : current_byte) {
                    value <<= 4;
                    if (c >= '0' && c <= '9') value += c - '0';
                    else if (c >= 'A' && c <= 'F') value += c - 'A' + 10;
                    else if (c >= 'a' && c <= 'f') value += c - 'a' + 10;
                    else return false;
                }

                addr[byte_idx] = (uint8_t)value;
                mask[byte_idx] = 0xFF; // Must match exactly
            }

            byte_idx++;
            current_byte.clear();
        } else {
            current_byte += pattern[i];
        }
    }

    return byte_idx == 6;
}

psram_string MACPattern::macToString(const uint8_t* mac) {
    if (!mac) return PSRAMUtils::createPSRAMString("");
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return PSRAMUtils::createPSRAMString(buf);
}

bool MACPattern::stringToMAC(const std::string& mac_str, uint8_t* mac) {
    uint8_t dummy_mask[6];
    return parseMACPattern(mac_str, mac, dummy_mask);
}

// IPRange implementation
IPRange::IPRange(const std::string& cidr_str) : original_str(PSRAMUtils::createPSRAMString(cidr_str.c_str())) {
    if (!WhitelistManager::parseCIDR(cidr_str, network_addr, netmask)) {
        network_addr = 0;
        netmask = 0;
        LOG_ERRORF(TAG, "Failed to parse CIDR: %s", cidr_str.c_str());
    }
}

IPRange::IPRange(const psram_string& cidr_str) : original_str(cidr_str) {
    char buf[24];
    size_t n = 0;
    for (auto ch : cidr_str) { if (n >= sizeof(buf)-1) break; buf[n++] = ch; }
    buf[n] = '\0';
    if (!WhitelistManager::parseCIDR(buf, network_addr, netmask)) {
        network_addr = 0;
        netmask = 0;
        LOG_ERRORF(TAG, "Failed to parse CIDR: %s", buf);
    }
}

IPRange::IPRange(const char* cidr_cstr) : original_str(PSRAMUtils::createPSRAMString(cidr_cstr ? cidr_cstr : "")) {
    const char* s = cidr_cstr ? cidr_cstr : "";
    if (!WhitelistManager::parseCIDR(s, network_addr, netmask)) {
        network_addr = 0;
        netmask = 0;
        LOG_ERRORF(TAG, "Failed to parse CIDR: %s", s);
    }
}

bool IPRange::contains(uint32_t ip) const {
    if (!isValid()) return false;
    return (ip & netmask) == (network_addr & netmask);
}

bool IPRange::contains(const std::string& ip_str) const {
    uint32_t ip;
    if (!WhitelistManager::tryParseIpString(ip_str, ip)) {
        return false;  // Parse failed
    }
    return contains(ip);
}

// WhitelistManager implementation
WhitelistManager::WhitelistManager() {
    // Check memory during construction
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    // Only log if we have sufficient memory for logging
    if (free_heap > 1024) {
        LOG_INFOF(TAG, "🔧 WhitelistManager constructor - %d bytes free, largest: %d", (int)free_heap, (int)largest_block);
    }

    // === CRITICAL MEMORY CHECK ===
    if (free_heap < 1000 || largest_block < 500) {
        // Try emergency cleanup first
        if (TaskConfig::isMemoryInCriticalState()) {
            if (free_heap > 500) {
                LOG_ERRORF(TAG, "⚠️ Attempting emergency memory cleanup before WhitelistManager init");
            }
            TaskConfig::emergencyMemoryCleanup();

            // Re-check after cleanup
            free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        }

        // Still critical after cleanup - emergency mode
        if (free_heap < 1000 || largest_block < 500) {
            if (free_heap > 500) {
                LOG_ERRORF(TAG, "⚠️ EMERGENCY MODE: %d bytes free after cleanup, skipping pre-allocation", (int)free_heap);
            }
            return; // Constructor completes without reserves
        }
    }

    // Safe memory conditions - try to reserve capacity
    // ESP-IDF doesn't support exceptions, so we'll do manual checking

    // Check if we have enough memory for reserves before attempting
    size_t needed_memory = (4 * sizeof(ProtocolWhitelist)) +
                          (8 * sizeof(IPRange)) +
                          (8 * sizeof(MACPattern));

    if (largest_block > needed_memory) {
        // Likely safe to reserve
        protocol_whitelists_.reserve(4);   // Reduced from 8
        global_ip_ranges_.reserve(8);      // Reduced from 16
        global_mac_patterns_.reserve(8);   // Reduced from 16

        size_t free_after = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (free_after > 500) {
            LOG_INFOF(TAG, "✅ WhitelistManager initialized - %d bytes free", (int)free_after);
        }
    } else {
        // Skip reserves - not enough contiguous memory
        if (free_heap > 500) {
            LOG_ERRORF(TAG, "⚠️ Skipping reserves - need %d bytes, largest block: %d", (int)needed_memory, (int)largest_block);
        }
    }
}

bool WhitelistManager::loadFromConfig(const std::string& config_json) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Pre-allocate capacity to avoid reallocation during parsing
    protocol_whitelists_.reserve(16);  // Reserve for typical protocol count
    global_ip_ranges_.reserve(32);     // Reserve for IP ranges
    global_mac_patterns_.reserve(32);  // Reserve for MAC patterns

    cJSON* root = cJSON_Parse(config_json.c_str());
    if (!root) {
        LOG_ERROR(TAG, "Failed to parse whitelist config JSON");
        return false;
    }

    cJSON* whitelist_obj = cJSON_GetObjectItem(root, "ip_whitelist");
    if (!whitelist_obj) {
        cJSON_Delete(root);
        return true; // No whitelist config, keep defaults
    }

    cJSON* enabled = cJSON_GetObjectItem(whitelist_obj, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        enabled_ = enabled->valueint != 0;
    }

    // Support both structures:
    // 1. New structure: "protocols": [...]
    // 2. Current structure: "ip": [...], "mac": [...], "per_protocol": {...}

    cJSON* protocols = cJSON_GetObjectItem(whitelist_obj, "protocols");
    if (protocols && cJSON_IsArray(protocols)) {
        protocol_whitelists_.clear(); // Clear defaults

        int protocol_count = cJSON_GetArraySize(protocols);
        // Reserve capacity to avoid repeated reallocations
        protocol_whitelists_.reserve(protocol_count);

        for (int i = 0; i < protocol_count; i++) {
            cJSON* proto_obj = cJSON_GetArrayItem(protocols, i);
            if (!proto_obj) continue;

            ProtocolWhitelist whitelist;

            cJSON* protocol_name = cJSON_GetObjectItem(proto_obj, "protocol");
            if (protocol_name && cJSON_IsString(protocol_name) && protocol_name->valuestring) {
                const char* proto = protocol_name->valuestring;
                if      (strcmp(proto, "MODBUS_TCP") == 0) whitelist.protocol = ProtocolType::MODBUS_TCP;
                else if (strcmp(proto, "S7") == 0)         whitelist.protocol = ProtocolType::S7_COMM;
                else if (strcmp(proto, "OPCUA") == 0)      whitelist.protocol = ProtocolType::OPC_UA;
                else if (strcmp(proto, "PROFINET") == 0)   whitelist.protocol = ProtocolType::PROFINET;
                else if (strcmp(proto, "ETHERNETIP") == 0) whitelist.protocol = ProtocolType::ETHERNET_IP;
            }

            cJSON* enabled_flag = cJSON_GetObjectItem(proto_obj, "enabled");
            if (enabled_flag && cJSON_IsBool(enabled_flag)) {
                whitelist.enabled = enabled_flag->valueint != 0;
            }

            cJSON* default_deny = cJSON_GetObjectItem(proto_obj, "default_deny");
            if (default_deny && cJSON_IsBool(default_deny)) {
                whitelist.default_deny = default_deny->valueint != 0;
            }

            // Parse allowed sources
            cJSON* allowed_sources = cJSON_GetObjectItem(proto_obj, "allowed_IP_sources");
            if (allowed_sources && cJSON_IsArray(allowed_sources)) {
                int src_count = cJSON_GetArraySize(allowed_sources);
                // Reserve capacity to avoid repeated reallocations
                whitelist.allowed_IP_sources.reserve(src_count);

                for (int j = 0; j < src_count; j++) {
                    cJSON* src = cJSON_GetArrayItem(allowed_sources, j);
                    if (src && cJSON_IsString(src) && src->valuestring) {
                        IPRange range(src->valuestring);
                        if (range.isValid()) {
                            whitelist.allowed_IP_sources.push_back(range);
                        }
                    }
                }
            }


            protocol_whitelists_.emplace_back(std::move(whitelist));
        }
    } else {
        // Handle current structure: "ip": [...], "mac": [...], "per_protocol": {...}
        protocol_whitelists_.clear(); // Clear defaults
        global_ip_ranges_.clear();     // Clear global ranges
        global_mac_patterns_.clear();  // Clear global MACs

        // First, parse and store global rules separately

        // Parse global IP list and store separately
        cJSON* global_ips = cJSON_GetObjectItem(whitelist_obj, "ip");
        if (global_ips && cJSON_IsArray(global_ips)) {
            int ip_count = cJSON_GetArraySize(global_ips);
            // Reserve capacity to avoid repeated reallocations
            global_ip_ranges_.reserve(ip_count);

            for (int j = 0; j < ip_count; j++) {
                cJSON* ip = cJSON_GetArrayItem(global_ips, j);
                if (ip && cJSON_IsString(ip) && ip->valuestring) {
                    IPRange range(ip->valuestring);
                    if (range.isValid()) {
                        global_ip_ranges_.push_back(range);
                    }
                }
            }
        }

        // Parse global MAC list and store separately
        cJSON* global_mac_list = cJSON_GetObjectItem(whitelist_obj, "mac");
        if (global_mac_list && cJSON_IsArray(global_mac_list)) {
            int mac_count = cJSON_GetArraySize(global_mac_list);
            // Reserve capacity to avoid repeated reallocations
            global_mac_patterns_.reserve(mac_count);

            for (int j = 0; j < mac_count; j++) {
                cJSON* mac = cJSON_GetArrayItem(global_mac_list, j);
                if (mac && cJSON_IsString(mac)) {
                    MACPattern pattern(mac->valuestring);
                    if (pattern.isValid()) {
                        global_mac_patterns_.push_back(pattern);
                    }
                }
            }
        }

        // Create default whitelists for all protocols using global IP and MAC ranges
        if (!global_ip_ranges_.empty() || !global_mac_patterns_.empty()) {
            ProtocolType protocols[] = {
                ProtocolType::MODBUS_TCP,
                ProtocolType::S7_COMM,
                ProtocolType::OPC_UA,
                ProtocolType::PROFINET,
                ProtocolType::ETHERNET_IP
            };

            // Reserve capacity for protocol whitelists
            protocol_whitelists_.reserve(5);  // We know we have exactly 5 protocols

            for (ProtocolType proto : protocols) {
                ProtocolWhitelist whitelist;
                whitelist.protocol = proto;
                whitelist.enabled = true;
                whitelist.default_deny = true;
                whitelist.allowed_IP_sources = global_ip_ranges_;
                whitelist.allowed_MAC_sources = global_mac_patterns_;
                protocol_whitelists_.emplace_back(std::move(whitelist));
            }
        }

        // Then, override with per_protocol specific rules if present
        cJSON* per_protocol = cJSON_GetObjectItem(whitelist_obj, "per_protocol");
        if (per_protocol && cJSON_IsObject(per_protocol)) {
            cJSON* proto_item = nullptr;
            cJSON_ArrayForEach(proto_item, per_protocol) {
                if (!proto_item->string) continue;

                // Convert protocol name to ProtocolType
                const char* proto_name = proto_item->string;
                ProtocolType target_proto = ProtocolType::CUSTOM;

                if (!proto_name) { /* leave CUSTOM */ }
                else if (strcmp(proto_name, "MODBUS_TCP") == 0 || strcmp(proto_name, "modbus") == 0) target_proto = ProtocolType::MODBUS_TCP;
                else if (strcmp(proto_name, "S7") == 0         || strcmp(proto_name, "s7") == 0)      target_proto = ProtocolType::S7_COMM;
                else if (strcmp(proto_name, "OPCUA") == 0      || strcmp(proto_name, "opcua") == 0)   target_proto = ProtocolType::OPC_UA;
                else if (strcmp(proto_name, "PROFINET") == 0   || strcmp(proto_name, "profinet") == 0) target_proto = ProtocolType::PROFINET;
                else if (strcmp(proto_name, "ETHERNETIP") == 0 || strcmp(proto_name, "ethernetip") == 0) target_proto = ProtocolType::ETHERNET_IP;
                else continue; // Skip unknown protocols

                // Find existing whitelist for this protocol and update it
                ProtocolWhitelist* existing = findProtocolWhitelist(target_proto);
                if (existing) {
                    existing->allowed_IP_sources.clear();
                    existing->allowed_MAC_sources.clear();

                    // Parse protocol-specific IP addresses
                    cJSON* proto_ips = cJSON_GetObjectItem(proto_item, "ip");
                    if (proto_ips && cJSON_IsArray(proto_ips)) {
                        int ip_count = cJSON_GetArraySize(proto_ips);
                        // Reserve capacity to avoid repeated reallocations
                        existing->allowed_IP_sources.reserve(ip_count);

                        for (int j = 0; j < ip_count; j++) {
                            cJSON* ip = cJSON_GetArrayItem(proto_ips, j);
                            if (ip && cJSON_IsString(ip) && ip->valuestring) {
                                IPRange range(ip->valuestring);
                                if (range.isValid()) {
                                    existing->allowed_IP_sources.push_back(range);
                                }
                            }
                        }
                    }

                    // Parse protocol-specific MAC addresses
                    cJSON* proto_macs = cJSON_GetObjectItem(proto_item, "mac");
                    if (proto_macs && cJSON_IsArray(proto_macs)) {
                        int mac_count = cJSON_GetArraySize(proto_macs);
                        // Reserve capacity to avoid repeated reallocations
                        existing->allowed_MAC_sources.reserve(mac_count);

                        for (int j = 0; j < mac_count; j++) {
                            cJSON* mac = cJSON_GetArrayItem(proto_macs, j);
                            if (mac && cJSON_IsString(mac)) {
                                MACPattern pattern(mac->valuestring);
                                if (pattern.isValid()) {
                                    existing->allowed_MAC_sources.push_back(pattern);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(root);

    // Memory monitoring after whitelist loading
    size_t free_after_load = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t whitelist_count = protocol_whitelists_.size();
    size_t total_ip_ranges = global_ip_ranges_.size();
    size_t total_mac_patterns = global_mac_patterns_.size();

    // Calculate per-protocol totals
    for (const auto& pw : protocol_whitelists_) {
        total_ip_ranges += pw.allowed_IP_sources.size();
        total_mac_patterns += pw.allowed_MAC_sources.size();
    }

    LOG_INFOF(TAG, "Whitelist loaded: %zu protocols, %zu IP ranges, %zu MAC patterns - %d bytes Internal RAM free",
             whitelist_count, total_ip_ranges, total_mac_patterns, (int)free_after_load);

    return true;
}

bool WhitelistManager::loadFromConfigSafe(const char* json_buffer, size_t json_size) {
    if (!json_buffer || json_size == 0) {
        LOG_WARNING(TAG, "Empty JSON buffer provided to loadFromConfigSafe");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Check available memory before parsing
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    LOG_INFOF(TAG, "loadFromConfigSafe: JSON size %u bytes, DRAM free: %u, PSRAM free: %u",
             (unsigned)json_size, (unsigned)free_heap, (unsigned)free_psram);

    // Require minimum DRAM for safety (raise threshold to reduce fragmentation crashes)
    /*const size_t kMinDramForWhitelist = 50 * 1024; // 50 KB
    if (free_heap < kMinDramForWhitelist) {
        LOG_ERRORF(TAG, "Insufficient DRAM for safe whitelist loading: %u bytes (< %u)",
                   (unsigned)free_heap, (unsigned)kMinDramForWhitelist);
        return false;
    }*/

    // Use PSRAM JSON parser with automatic hook management
    PSRAMJsonParser::PSRAMContext context;
    if (!context.isValid()) {
        LOG_ERROR(TAG, "Failed to initialize PSRAM JSON context");
        return false;
    }

    // Pre-allocate capacity to avoid reallocation during parsing
    protocol_whitelists_.reserve(16);
    global_ip_ranges_.reserve(32);
    global_mac_patterns_.reserve(32);

    // Parse JSON in PSRAM
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buffer, json_size);
    if (!root) {
        LOG_ERROR(TAG, "Failed to parse whitelist config JSON in PSRAM");
        return false;
    }

    cJSON* whitelist_obj = cJSON_GetObjectItem(root, "ip_whitelist");
    if (!whitelist_obj) {
        cJSON_Delete(root);
        LOG_INFO(TAG, "No ip_whitelist section found, keeping defaults");
        return true;
    }

    cJSON* enabled = cJSON_GetObjectItem(whitelist_obj, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        enabled_ = enabled->valueint != 0;
    }

    // Load protocols array if present (new format)
    cJSON* protocols = cJSON_GetObjectItem(whitelist_obj, "protocols");
    if (protocols && cJSON_IsArray(protocols)) {
        protocol_whitelists_.clear();

        int protocol_count = cJSON_GetArraySize(protocols);
        protocol_whitelists_.reserve(protocol_count);

        for (int i = 0; i < protocol_count; i++) {
            cJSON* proto_obj = cJSON_GetArrayItem(protocols, i);
            if (!proto_obj) continue;

            ProtocolWhitelist whitelist;

            cJSON* protocol_name = cJSON_GetObjectItem(proto_obj, "protocol");
            if (protocol_name && cJSON_IsString(protocol_name)) {
                std::string proto_str = protocol_name->valuestring;
                if (proto_str == "MODBUS_TCP") whitelist.protocol = ProtocolType::MODBUS_TCP;
                else if (proto_str == "S7") whitelist.protocol = ProtocolType::S7_COMM;
                else if (proto_str == "OPCUA") whitelist.protocol = ProtocolType::OPC_UA;
                else if (proto_str == "PROFINET") whitelist.protocol = ProtocolType::PROFINET;
                else if (proto_str == "ETHERNETIP") whitelist.protocol = ProtocolType::ETHERNET_IP;
            }

            cJSON* enabled_flag = cJSON_GetObjectItem(proto_obj, "enabled");
            if (enabled_flag && cJSON_IsBool(enabled_flag)) {
                whitelist.enabled = enabled_flag->valueint != 0;
            }

            cJSON* default_deny = cJSON_GetObjectItem(proto_obj, "default_deny");
            if (default_deny && cJSON_IsBool(default_deny)) {
                whitelist.default_deny = default_deny->valueint != 0;
            }

            protocol_whitelists_.push_back(whitelist);
        }
    }

    // Load global IP ranges
    cJSON* global_ip_list = cJSON_GetObjectItem(whitelist_obj, "ip");
    if (global_ip_list && cJSON_IsArray(global_ip_list)) {
        global_ip_ranges_.clear();

        int ip_count = cJSON_GetArraySize(global_ip_list);
        global_ip_ranges_.reserve(ip_count);

        for (int j = 0; j < ip_count; j++) {
            cJSON* ip = cJSON_GetArrayItem(global_ip_list, j);
            if (ip && cJSON_IsString(ip)) {
                IPRange range(std::string(ip->valuestring));
                if (range.isValid()) {
                    global_ip_ranges_.push_back(range);
                }
            }
        }
    }

    // Load global MAC patterns
    cJSON* global_mac_list = cJSON_GetObjectItem(whitelist_obj, "mac");
    if (global_mac_list && cJSON_IsArray(global_mac_list)) {
        global_mac_patterns_.clear();

        int mac_count = cJSON_GetArraySize(global_mac_list);
        global_mac_patterns_.reserve(mac_count);

        for (int j = 0; j < mac_count; j++) {
            cJSON* mac = cJSON_GetArrayItem(global_mac_list, j);
            if (mac && cJSON_IsString(mac)) {
                MACPattern pattern(mac->valuestring);
                if (pattern.isValid()) {
                    global_mac_patterns_.push_back(pattern);
                }
            }
        }
    }

    // Create default whitelists for all protocols using global ranges
    if (!global_ip_ranges_.empty() || !global_mac_patterns_.empty()) {
        ProtocolType protocols[] = {
            ProtocolType::MODBUS_TCP, ProtocolType::S7_COMM, ProtocolType::OPC_UA,
            ProtocolType::PROFINET, ProtocolType::ETHERNET_IP
        };

        for (auto proto : protocols) {
            if (!findProtocolWhitelist(proto)) {
                ProtocolWhitelist whitelist;
                whitelist.protocol = proto;
                whitelist.enabled = true;
                whitelist.default_deny = false;
                whitelist.allowed_IP_sources = global_ip_ranges_;
                whitelist.allowed_MAC_sources = global_mac_patterns_;
                protocol_whitelists_.push_back(whitelist);
            }
        }
    }

    cJSON_Delete(root);

    // Memory monitoring after loading
    size_t free_after = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t whitelist_count = protocol_whitelists_.size();
    size_t total_ip_ranges = global_ip_ranges_.size();
    size_t total_mac_patterns = global_mac_patterns_.size();

    for (const auto& pw : protocol_whitelists_) {
        total_ip_ranges += pw.allowed_IP_sources.size();
        total_mac_patterns += pw.allowed_MAC_sources.size();
    }

    LOG_INFOF(TAG, "✅ Whitelist loaded safely: %zu protocols, %zu IP ranges, %zu MAC patterns - %d bytes DRAM free",
             whitelist_count, total_ip_ranges, total_mac_patterns, (int)free_after);

    return true;
}

std::string WhitelistManager::saveToConfigJSON() const {
    std::lock_guard<std::mutex> lock(mutex_);

    cJSON* root = cJSON_CreateObject();
    cJSON* whitelist_obj = cJSON_CreateObject();

    cJSON_AddBoolToObject(whitelist_obj, "enabled", enabled_);

    cJSON* protocols = cJSON_CreateArray();
    for (const auto& whitelist : protocol_whitelists_) {
        cJSON* proto_obj = cJSON_CreateObject();

        // Convert ProtocolType to string
        const char* proto_name = "CUSTOM";
        switch (whitelist.protocol) {
            case ProtocolType::MODBUS_TCP: proto_name = "MODBUS_TCP"; break;
            case ProtocolType::S7_COMM: proto_name = "S7"; break;
            case ProtocolType::OPC_UA: proto_name = "OPCUA"; break;
            case ProtocolType::PROFINET: proto_name = "PROFINET"; break;
            case ProtocolType::ETHERNET_IP: proto_name = "ETHERNETIP"; break;
            default: break;
        }

        cJSON_AddStringToObject(proto_obj, "protocol", proto_name);
        cJSON_AddBoolToObject(proto_obj, "enabled", whitelist.enabled);
        cJSON_AddBoolToObject(proto_obj, "default_deny", whitelist.default_deny);

        // Add allowed sources
        cJSON* allowed_sources = cJSON_CreateArray();
        for (const auto& range : whitelist.allowed_IP_sources) {
            cJSON_AddItemToArray(allowed_sources, cJSON_CreateString(range.original_str.c_str()));
        }
        cJSON_AddItemToObject(proto_obj, "allowed_IP_sources", allowed_sources);

        // Add allowed MAC sources
        cJSON* allowed_mac_sources = cJSON_CreateArray();
        for (const auto& pattern : whitelist.allowed_MAC_sources) {
            cJSON_AddItemToArray(allowed_mac_sources, cJSON_CreateString(pattern.pattern.c_str()));
        }
        cJSON_AddItemToObject(proto_obj, "allowed_MAC_sources", allowed_mac_sources);

        cJSON_AddItemToArray(protocols, proto_obj);
    }

    cJSON_AddItemToObject(whitelist_obj, "protocols", protocols);
    cJSON_AddItemToObject(root, "ip_whitelist", whitelist_obj);

    char* json_str = cJSON_PrintUnformatted(root);
    std::string result(json_str ? json_str : "{}");

    if (json_str) free(json_str);
    cJSON_Delete(root);

    return result;
}

bool WhitelistManager::isPacketAllowed(const NetworkPacket& packet) const {
    if (!enabled_) return true; // Whitelist disabled, allow all

    std::lock_guard<std::mutex> lock(mutex_);

    // Check global IP ranges
    bool ip_allowed = false;
    if (!global_ip_ranges_.empty()) {
        uint32_t ip = ipStringToUint32(packet.src_ip);
        for (const auto& range : global_ip_ranges_) {
            if (range.contains(ip)) {
                ip_allowed = true;
                break;
            }
        }
    } else {
        ip_allowed = true; // No global IP restrictions
    }

    // Check global MAC patterns
    bool mac_allowed = false;
    if (!global_mac_patterns_.empty()) {
        for (const auto& pattern : global_mac_patterns_) {
            if (pattern.matches(packet.src_mac)) {
                mac_allowed = true;
                break;
            }
        }
    } else {
        mac_allowed = true; // No global MAC restrictions
    }

    // New semantics: MAC whitelist overrides IP — allow if either matches
    return ip_allowed || mac_allowed;
}

bool WhitelistManager::isPacketAllowedPerProtocol(const NetworkPacket& packet) const {
    if (!enabled_) return true; // Whitelist disabled, allow all

    std::lock_guard<std::mutex> lock(mutex_);
    const ProtocolWhitelist* whitelist = findProtocolWhitelist(packet.proto);

    if (!whitelist || !whitelist->enabled) {
        return true; // No whitelist for this protocol, allow
    }

    if (!whitelist->default_deny) {
        return true; // Default allow mode
    }

    // Check source IP
    bool ip_allowed = isSourceIPAllowed(packet.proto, packet.src_ip);

    // Check source MAC
    psram_string mac_psram_str = MACPattern::macToString(packet.src_mac);
    std::string mac_str = PSRAMUtils::fromPSRAMString(mac_psram_str);
    bool mac_allowed = isSourceMACAllowed(packet.proto, mac_str);

    return ip_allowed || mac_allowed;
}

bool WhitelistManager::isSourceIPAllowed(ProtocolType protocol, const std::string& src_ip) const {
    if (!enabled_) return true;

    std::lock_guard<std::mutex> lock(mutex_);
    const ProtocolWhitelist* whitelist = findProtocolWhitelist(protocol);

    if (!whitelist || !whitelist->enabled || !whitelist->default_deny) {
        return true;
    }

    if (whitelist->allowed_IP_sources.empty()) {
        return true;
    }

    for (const auto& range : whitelist->allowed_IP_sources) {
        if (range.contains(src_ip)) {
            return true;
        }
    }

    return false;
}

bool WhitelistManager::isSourceMACAllowed(ProtocolType protocol, const std::string& src_mac) const {
    if (!enabled_) return true;

    std::lock_guard<std::mutex> lock(mutex_);
    const ProtocolWhitelist* whitelist = findProtocolWhitelist(protocol);

    if (!whitelist || !whitelist->enabled || !whitelist->default_deny) {
        return true;
    }

    if (whitelist->allowed_MAC_sources.empty()) {
        return true;
    }

    for (const auto& pattern : whitelist->allowed_MAC_sources) {
        if (pattern.matches(src_mac)) {
            return true;
        }
    }

    return false;
}



// Helper methods
uint32_t WhitelistManager::ipStringToUint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr); // Convert to host byte order
    }
    return 0;  // Restore original behavior - will add separate validation
}

bool WhitelistManager::tryParseIpString(const std::string& ip_str, uint32_t& out_ip) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 1) {
        out_ip = ntohl(addr.s_addr);
        return true;
    }
    return false;
}

std::string WhitelistManager::uint32ToIpString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip); // Convert to network byte order
    return std::string(inet_ntoa(addr));
}

bool WhitelistManager::parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& netmask) {
    size_t slash_pos = cidr.find('/');

    if (slash_pos == std::string::npos) {
        // No slash, treat as single IP (/32)
        if (!tryParseIpString(cidr, network)) {
            return false;  // Parse failed
        }
        netmask = 0xFFFFFFFF;
        return true;
    }

    std::string ip_part = cidr.substr(0, slash_pos);
    std::string mask_part = cidr.substr(slash_pos + 1);

    if (!tryParseIpString(ip_part, network)) {
        return false;  // Parse failed
    }

    // Manual parsing instead of std::stoi (no exceptions)
    int prefix_len = 0;
    for (char c : mask_part) {
        if (c >= '0' && c <= '9') {
            prefix_len = prefix_len * 10 + (c - '0');
        } else {
            return false; // Invalid character
        }
    }

    if (prefix_len < 0 || prefix_len > 32) return false;

    // Safe netmask calculation to avoid undefined behavior
    if (prefix_len == 0) {
        netmask = 0;
    } else if (prefix_len == 32) {
        netmask = 0xFFFFFFFF;  // Handle /32 case explicitly
    } else {
        // Safe shift operation: ensure we never shift by 32 or more
        netmask = ~((1U << (32 - prefix_len)) - 1);
    }

    return true;
}

const ProtocolWhitelist* WhitelistManager::findProtocolWhitelist(ProtocolType protocol) const{
    for (auto& whitelist : protocol_whitelists_) {
        if (whitelist.protocol == protocol) {
            return &whitelist;
        }
    }
    return nullptr;
}

ProtocolWhitelist* WhitelistManager::findProtocolWhitelist(ProtocolType protocol) {
    for (auto& whitelist : protocol_whitelists_) {
        if (whitelist.protocol == protocol) {
            return &whitelist;
        }
    }
    return nullptr;
}

const ProtocolWhitelist* WhitelistManager::getProtocolWhitelist(ProtocolType protocol) const {
    return findProtocolWhitelist(protocol);
}

psram_vector<IPRange> WhitelistManager::getGlobalIPRanges() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return global_ip_ranges_;
}

psram_vector<MACPattern> WhitelistManager::getGlobalMACPatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return global_mac_patterns_;
}

psram_vector<ProtocolWhitelist> WhitelistManager::getAllWhitelists() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return protocol_whitelists_;
}

bool WhitelistManager::parseCIDR(const char* cidr, uint32_t& network, uint32_t& netmask) {
    if (!cidr) return false;
    // Find '/'
    const char* slash = strchr(cidr, '/');
    if (!slash) {
        // No slash: single IP (/32)
        if (!tryParseIpString(std::string(cidr), network)) {
            return false;  // Parse failed
        }
        netmask = 0xFFFFFFFF;
        return true;
    }
    std::string ip_part(cidr, slash - cidr);
    const char* mask_part = slash + 1;
    if (!tryParseIpString(ip_part, network)) {
        return false;  // Parse failed
    }
    int prefix_len = 0;
    while (*mask_part) {
        if (*mask_part >= '0' && *mask_part <= '9') {
            prefix_len = prefix_len * 10 + (*mask_part - '0');
            mask_part++;
        } else {
            return false;
        }
    }
    if (prefix_len < 0 || prefix_len > 32) return false;
    if (prefix_len == 0) netmask = 0;
    else if (prefix_len == 32) netmask = 0xFFFFFFFF;
    else netmask = ~((1U << (32 - prefix_len)) - 1);
    return true;
}
