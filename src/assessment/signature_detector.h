#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include "../core/psram_allocator.h"
#include "../core/types.h"
#include "../core/logging_system.h"

extern "C" {
    #include "esp_heap_caps.h"
}

// Forward declaration for cJSON
struct cJSON;

// PSRAM-only signature detection system for known attack patterns
// Designed for ESP32 memory constraints with hot-reload capability

namespace SignatureDetection {

// Maximum signature pattern size (reasonable for embedded)
constexpr size_t MAX_SIGNATURE_BYTES = 128;  // Increased for larger patterns
constexpr size_t MAX_CVE_ID_LEN = 20;  // "CVE-2025-12345"
constexpr size_t MAX_NAME_LEN = 128;
constexpr size_t MAX_DESCRIPTION_LEN = 256;
constexpr size_t MAX_FUNCTION_CODE_LEN = 32;
constexpr size_t MAX_REFERENCES = 4;
constexpr size_t MAX_REFERENCE_LEN = 128;
constexpr size_t MAX_SIGNATURES_PER_PROTOCOL = 64;  // Increased limit

// Signature pattern types
enum class PatternType : uint8_t {
    EXACT_MATCH = 0,    // Exact byte sequence match
    PREFIX_MATCH = 1    // Match only prefix bytes (rest can vary)
};

// PSRAM-allocated signature entry with full metadata
struct SignatureEntry {
    char cve_id[MAX_CVE_ID_LEN];                              // CVE identifier
    char name[MAX_NAME_LEN];                                   // Vulnerability name
    char description[MAX_DESCRIPTION_LEN];                     // Packet description
    char function_code[MAX_FUNCTION_CODE_LEN];                 // Function code (if applicable)
    char references[MAX_REFERENCES][MAX_REFERENCE_LEN];        // Reference URLs
    uint8_t num_references;                                    // Number of references
    uint8_t pattern[MAX_SIGNATURE_BYTES];                     // Byte pattern to match
    uint8_t pattern_length;                                    // Actual pattern length
    PatternType type;                                          // Match type
    ProtocolType protocol;                                     // Target protocol

    SignatureEntry() : num_references(0), pattern_length(0), type(PatternType::EXACT_MATCH), protocol(ProtocolType::UNKNOWN) {
        memset(cve_id, 0, sizeof(cve_id));
        memset(name, 0, sizeof(name));
        memset(description, 0, sizeof(description));
        memset(function_code, 0, sizeof(function_code));
        memset(references, 0, sizeof(references));
        memset(pattern, 0, sizeof(pattern));
    }

    // PSRAM-safe copy constructor
    SignatureEntry(const SignatureEntry& other) {
        memcpy(cve_id, other.cve_id, sizeof(cve_id));
        memcpy(name, other.name, sizeof(name));
        memcpy(description, other.description, sizeof(description));
        memcpy(function_code, other.function_code, sizeof(function_code));
        memcpy(references, other.references, sizeof(references));
        num_references = other.num_references;
        memcpy(pattern, other.pattern, sizeof(pattern));
        pattern_length = other.pattern_length;
        type = other.type;
        protocol = other.protocol;
    }
};

// Force PSRAM-only allocator for signatures to preserve internal RAM
template<typename T>
class PSRAMOnlyAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;

    template<typename U>
    struct rebind { using other = PSRAMOnlyAllocator<U>; };

    PSRAMOnlyAllocator() = default;
    template<typename U> PSRAMOnlyAllocator(const PSRAMOnlyAllocator<U>&) noexcept {}

    T* allocate(size_type n) {
        size_type bytes = n * sizeof(T);
        // Force PSRAM allocation only - no fallback to preserve internal RAM
        void* ptr = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!ptr) {
            LOG_ERRORF("SIG_PSRAM", "❌ PSRAM allocation failed for %u bytes - signatures disabled", (unsigned)bytes);
            // ESP32 doesn't support exceptions - return nullptr and let caller handle
            return nullptr;
        }
        LOG_DEBUGF("SIG_PSRAM", "✅ Allocated %u bytes in PSRAM for signatures", (unsigned)bytes);
        return static_cast<T*>(ptr);
    }

    void deallocate(T* ptr, size_type) {
        if (ptr) heap_caps_free(ptr);
    }

    bool operator==(const PSRAMOnlyAllocator&) const { return true; }
    bool operator!=(const PSRAMOnlyAllocator&) const { return false; }
};

// PSRAM-only signature database per protocol
using SignatureVector = std::vector<SignatureEntry, PSRAMOnlyAllocator<SignatureEntry>>;
using ProtocolSignatureMap = std::map<ProtocolType, SignatureVector, std::less<ProtocolType>,
                                     PSRAMOnlyAllocator<std::pair<const ProtocolType, SignatureVector>>>;

// Detection result with minimal memory footprint
struct DetectionResult {
    bool detected;
    char cve_id[MAX_CVE_ID_LEN];
    ProtocolType protocol;
    uint32_t offset;  // Byte offset where pattern was found

    DetectionResult() : detected(false), protocol(ProtocolType::UNKNOWN), offset(0) {
        memset(cve_id, 0, sizeof(cve_id));
    }
};

// Main signature detector class - PSRAM-only allocations
class SignatureDetector {
public:
    SignatureDetector();
    ~SignatureDetector() = default;

    // Initialize from NVS configuration
    bool initialize();

    // Hot-reload signatures from NVS (for real-time updates)
    bool reloadSignatures();

    // Get global instance for hot-reload capability
    static SignatureDetector& getInstance();

    // Analyze packet payload for known attack patterns
    DetectionResult analyzePacket(const uint8_t* payload, size_t payload_len, ProtocolType protocol);

    // Analyze complete network packet and generate detailed threat report
    DetectionResult analyzePacketWithReport(const NetworkPacket& packet, psram_string& threat_report_json);
    DetectionResult analyzePacketWithReport(const NetworkPacket& packet, std::string& threat_report_json) {
        psram_string tmp;
        DetectionResult res = analyzePacketWithReport(packet, tmp);
        if (!tmp.empty()) {
            threat_report_json = PSRAMUtils::fromPSRAMString(tmp);
        } else {
            threat_report_json.clear();
        }
        return res;
    }

    // Statistics
    uint32_t getTotalSignatures() const;
    uint32_t getSignaturesForProtocol(ProtocolType protocol) const;

    // Memory management
    void clearSignatures();

private:
    ProtocolSignatureMap signatures_;
    uint32_t total_signatures_;

    // Helper methods
    bool loadSignaturesFromNVS();
    uint32_t parseProtocolSignatures(cJSON* protocol_obj, ProtocolType protocol);
    bool parseSignatureBytes(const char* hex_string, uint8_t* output, uint8_t* length);
    bool matchPattern(const uint8_t* payload, size_t payload_len, const SignatureEntry& sig, uint32_t* offset);

    // PSRAM-safe string operations
    bool isValidHexChar(char c);
    uint8_t hexCharToValue(char c);
};

} // namespace SignatureDetection
