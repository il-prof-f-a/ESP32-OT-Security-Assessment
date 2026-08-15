#pragma once
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <cstdint>
#include <memory>
#include "types.h"
#include "esp_heap_caps.h"

#include "psram_allocator.h"

// IP range for whitelist (supports CIDR notation) - PSRAM optimized
struct IPRange {
    uint32_t network_addr = 0;  // Network address in host byte order
    uint32_t netmask = 0;       // Netmask in host byte order
    psram_string original_str;  // Original string representation in PSRAM (e.g., "192.168.1.0/24")

    IPRange() = default;
    IPRange(const std::string& cidr_str);
    IPRange(const psram_string& cidr_str);
    IPRange(const char* cidr_cstr);

    bool contains(uint32_t ip) const;
    bool contains(const std::string& ip_str) const;
    bool isValid() const { return network_addr != 0 || netmask == 0; }
};

// MAC address pattern for whitelist (supports wildcards) - PSRAM optimized
struct MACPattern {
    psram_string pattern;        // Pattern like "00:1A:2B:*:*:*" or "AC:DE:48:00:11:22" (PSRAM)
    uint8_t mask[6] = {0};       // Mask for matching (0xFF = must match, 0x00 = wildcard)
    uint8_t addr[6] = {0};       // MAC address bytes to match

    MACPattern() = default;
    MACPattern(const psram_string& mac_pattern);
    MACPattern(const char* mac_pattern);

    bool matches(const uint8_t* mac) const;
    bool matches(const std::string& mac_str) const;
    bool isValid() const;

    static bool parseMACPattern(const std::string& pattern, uint8_t* addr, uint8_t* mask);
    static bool parseMACPattern(const psram_string& pattern, uint8_t* addr, uint8_t* mask);
    static bool parseMACPattern(const char* pattern, uint8_t* addr, uint8_t* mask);
    static psram_string macToString(const uint8_t* mac);
    static bool stringToMAC(const std::string& mac_str, uint8_t* mac);
};

// Protocol-specific whitelist configuration (using PSRAM vectors)
struct ProtocolWhitelist {
    ProtocolType protocol = ProtocolType::CUSTOM;
    bool enabled = true;
    psram_vector<IPRange> allowed_IP_sources;     // IP addresses allowed to send packets (PSRAM)
    psram_vector<MACPattern> allowed_MAC_sources; // MAC addresses allowed to send packets (PSRAM)
    psram_vector<uint16_t> allowed_ports;         // Additional port restrictions (PSRAM)
    bool default_deny = true;                     // Deny by default if not in whitelist
};

class WhitelistManager {
public:
    WhitelistManager();
    ~WhitelistManager() = default;

    // Configuration management
    bool loadFromConfig(const std::string& config_json);

    // Memory-safe version using PSRAM for JSON parsing
    bool loadFromConfigSafe(const char* json_buffer, size_t json_size);

    std::string saveToConfigJSON() const;

    // Runtime checking
    bool isPacketAllowed(const NetworkPacket& packet) const;
    bool isPacketAllowedPerProtocol(const NetworkPacket& packet) const;
    const ProtocolWhitelist* getProtocolWhitelist(ProtocolType protocol) const;
    psram_vector<ProtocolWhitelist> getAllWhitelists() const;


    // Global rules access
    psram_vector<IPRange> getGlobalIPRanges() const;
    psram_vector<MACPattern> getGlobalMACPatterns() const;

    // Global enable/disable
    void setEnabled(bool enabled) { enabled_ = enabled; }
    bool isEnabled() const { return enabled_; }

    // Static helper methods (public for IPRange)
    static uint32_t ipStringToUint32(const std::string& ip_str);
    static std::string uint32ToIpString(uint32_t ip);
    static bool parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& netmask);
    static bool parseCIDR(const char* cidr, uint32_t& network, uint32_t& netmask);
    static bool tryParseIpString(const std::string& ip_str, uint32_t& out_ip);

private:
    mutable std::mutex mutex_;
    psram_vector<ProtocolWhitelist> protocol_whitelists_;
    bool enabled_ = true;

    bool isSourceIPAllowed(ProtocolType protocol, const std::string& src_ip) const;
    bool isSourceMACAllowed(ProtocolType protocol, const std::string& src_mac) const;

    // Global rules (separate from protocol-specific rules)
    psram_vector<IPRange> global_ip_ranges_;
    psram_vector<MACPattern> global_mac_patterns_;
    const ProtocolWhitelist* findProtocolWhitelist(ProtocolType protocol) const;
    ProtocolWhitelist* findProtocolWhitelist(ProtocolType protocol);
};
