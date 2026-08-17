/**
 * @file flow_key.h
 * @brief Universal key for network flow identification
 *
 * Unique identification system for multi-protocol network flows.
 * Uses PSRAM for string allocation (NO IRAM).
 *
 * Key format: "src_ip:src_port:dst_ip:dst_port:proto_specific"
 *
 * Examples:
 * - Modbus TCP:  "192.168.1.100:5000:192.168.1.200:502:1" (unit_id=1)
 * - S7:          "192.168.1.100:5000:192.168.1.200:102:0:1" (rack=0, slot=1)
 * - PROFINET:    "AA:BB:CC:DD:EE:FF:12345" (src_mac:xid)
 * - EtherNet/IP: "192.168.1.100:5000:192.168.1.200:44818:0x12345678" (session_handle)
 * - OPC UA:      "192.168.1.100:5000:192.168.1.200:4840:0xABCD" (secure_channel_id)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include "core/psram_allocator.h"
#include <string>
#include <functional>

/**
 * Alias for strings allocated in PSRAM
 * RULE: Only PSRAM, NEVER IRAM
 */
using psram_string = std::basic_string<char, std::char_traits<char>, PSRAMAllocator<char>>;

/**
 * @brief Universal key for flow identification
 *
 * Structure that uniquely identifies a network flow by combining:
 * - Source and destination IP addresses
 * - Source and destination ports
 * - Protocol-specific identifier (optional)
 *
 * ALLOCATION: PSRAM (all strings use PSRAMAllocator)
 */
struct FlowKey {
    psram_string src_ip;              ///< Source IP address (e.g.: "192.168.1.100")
    psram_string dst_ip;              ///< Destination IP address (e.g.: "192.168.1.200")
    uint16_t src_port;                ///< Source port
    uint16_t dst_port;                ///< Destination port
    psram_string protocol_specific;   ///< Protocol-specific identifier

    /**
     * @brief Default constructor with PSRAM allocator
     *
     * Initializes all strings with PSRAMAllocator to ensure
     * PSRAM allocation without fallback to IRAM.
     *
     * @param alloc PSRAM allocator (default: PSRAMAllocator<char>())
     */
    FlowKey(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : src_ip(alloc),
          dst_ip(alloc),
          src_port(0),
          dst_port(0),
          protocol_specific(alloc) {}

    /**
     * @brief Constructor with parameters
     *
     * @param src Source IP address
     * @param s_port Source port
     * @param dst Destination IP address
     * @param d_port Destination port
     * @param proto_spec Protocol-specific identifier (optional)
     */
    FlowKey(const char* src, uint16_t s_port,
            const char* dst, uint16_t d_port,
            const char* proto_spec = "",
            PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : src_ip(src, alloc),
          dst_ip(dst, alloc),
          src_port(s_port),
          dst_port(d_port),
          protocol_specific(proto_spec, alloc) {}

    /**
     * @brief Converts the key to a string for use in a hashtable
     *
     * Format: "src_ip:src_port:dst_ip:dst_port[:protocol_specific]"
     *
     * Examples:
     * - "192.168.1.100:5000:192.168.1.200:502:1"
     * - "192.168.1.100:5000:192.168.1.200:4840:0xABCD"
     *
     * @return PSRAM-allocated string representing the key
     */
    psram_string toString() const {
        PSRAMAllocator<char> alloc;
        psram_string key(alloc);
        key.reserve(128);  // Pre-allocate to avoid reallocations

        // Base format: src_ip:src_port:dst_ip:dst_port
        key = src_ip;
        key += ":";
        key += std::to_string(src_port).c_str();
        key += ":";
        key += dst_ip;
        key += ":";
        key += std::to_string(dst_port).c_str();

        // Add the protocol identifier if present
        if (!protocol_specific.empty()) {
            key += ":";
            key += protocol_specific;
        }

        return key;
    }

    /**
     * @brief Equality operator for key comparison
     *
     * Two keys are equal if all fields match.
     *
     * @param other Other key to compare
     * @return true if the keys are identical, false otherwise
     */
    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol_specific == other.protocol_specific;
    }

    /**
     * @brief Inequality operator
     *
     * @param other Other key to compare
     * @return true if the keys are different, false otherwise
     */
    bool operator!=(const FlowKey& other) const {
        return !(*this == other);
    }

    /**
     * @brief Hash functor for use in std::unordered_map
     *
     * Computes the hash of the string representation of the key.
     * Necessary to use FlowKey as a key in unordered_map.
     */
    struct Hash {
        size_t operator()(const FlowKey& k) const {
            // Hash on the string representation
            return std::hash<psram_string>{}(k.toString());
        }
    };

    /**
     * @brief Create a key for a bidirectional flow
     *
     * Normalizes the key by ordering src/dst so that flows
     * bidirectional flows (A->B and B->A) have the same key.
     *
     * Useful for request/response protocols where we want to track
     * both directions in the same flow.
     *
     * @return Normalized key
     */
    FlowKey toBidirectional() const {
        PSRAMAllocator<char> alloc;

        // Sort by IP (then by port if IPs are equal)
        bool swap = false;
        if (src_ip > dst_ip) {
            swap = true;
        } else if (src_ip == dst_ip && src_port > dst_port) {
            swap = true;
        }

        if (swap) {
            return FlowKey(
                dst_ip.c_str(), dst_port,
                src_ip.c_str(), src_port,
                protocol_specific.c_str(),
                alloc
            );
        } else {
            return *this;
        }
    }

    /**
     * @brief Check whether the key is valid
     *
     * A key is valid if it has at least source and destination IP.
     *
     * @return true if the key is valid, false otherwise
     */
    bool isValid() const {
        return !src_ip.empty() && !dst_ip.empty();
    }

    /**
     * @brief Get the flow direction as a string
     *
     * @return String formatted as "src_ip:src_port -> dst_ip:dst_port"
     */
    psram_string toDirectionString() const {
        PSRAMAllocator<char> alloc;
        psram_string result(alloc);
        result.reserve(64);

        result = src_ip;
        result += ":";
        result += std::to_string(src_port).c_str();
        result += " -> ";
        result += dst_ip;
        result += ":";
        result += std::to_string(dst_port).c_str();

        return result;
    }
};

#endif // FLOW_KEY_H
