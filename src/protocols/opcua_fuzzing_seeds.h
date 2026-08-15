#pragma once

#include "../core/psram_allocator.h"
#include <cstdint>
#include <cstddef>

// OPC UA Fuzzing Seed Generator
// Generates 200+ malformed/edge-case seeds across 7 categories for protocol fuzzing

namespace OPCUAFuzzingSeeds {

    // Seed categories
    enum class SeedCategory {
        MALFORMED_HEADERS,      // Invalid message headers and types
        BOUNDARY_VALUES,        // Integer overflow, underflow, edge cases
        STRING_ATTACKS,         // Format strings, injection, encoding issues
        PROTOCOL_VIOLATIONS,    // Invalid sequences, state violations
        RESOURCE_EXHAUSTION,    // Memory/CPU exhaustion attempts
        ENCODING_ERRORS,        // Invalid UTF-8, length mismatches
        CVE_BASED              // Known CVE exploit patterns
    };

    // Fuzzing seed structure
    struct FuzzingSeed {
        SeedCategory category;
        psram_string name;
        psram_string description;
        psram_vector<uint8_t> payload;
        uint32_t expected_behavior;  // Bitmask: crash, hang, memory_leak, protocol_error
        psram_string cve_reference;  // If based on known CVE

        FuzzingSeed() : category(SeedCategory::MALFORMED_HEADERS), expected_behavior(0) {}
    };

    // Expected behavior flags
    constexpr uint32_t EXPECT_CRASH = 0x01;
    constexpr uint32_t EXPECT_HANG = 0x02;
    constexpr uint32_t EXPECT_MEMORY_LEAK = 0x04;
    constexpr uint32_t EXPECT_PROTOCOL_ERROR = 0x08;
    constexpr uint32_t EXPECT_TIMEOUT = 0x10;

    // Seed generator class
    class SeedGenerator {
    public:
        SeedGenerator();
        ~SeedGenerator();

        // Generate all seeds
        psram_vector<FuzzingSeed> generateAllSeeds();

        // Generate seeds by category
        psram_vector<FuzzingSeed> generateMalformedHeaders();
        psram_vector<FuzzingSeed> generateBoundaryValues();
        psram_vector<FuzzingSeed> generateStringAttacks();
        psram_vector<FuzzingSeed> generateProtocolViolations();
        psram_vector<FuzzingSeed> generateResourceExhaustion();
        psram_vector<FuzzingSeed> generateEncodingErrors();
        psram_vector<FuzzingSeed> generateCVEBasedSeeds();

        // Get seed count by category
        size_t getSeedCount(SeedCategory category);
        size_t getTotalSeedCount();

    private:
        // Helper: Create seed
        FuzzingSeed createSeed(SeedCategory category, const char* name,
                              const char* description, const uint8_t* data,
                              size_t len, uint32_t expected_behavior,
                              const char* cve_ref = nullptr);

        // Helper: Build OPC UA message structure
        psram_vector<uint8_t> buildMessage(const char* msg_type, uint32_t size,
                                          const uint8_t* payload, size_t payload_len);

        // Helper: Build malformed integer encodings
        psram_vector<uint8_t> encodeInt32Malformed(int32_t value, uint8_t corruption_type);
        psram_vector<uint8_t> encodeStringMalformed(const char* str, uint8_t corruption_type);

        // Helper: Generate repeating patterns
        psram_vector<uint8_t> generatePattern(uint8_t byte, size_t count);
        psram_vector<uint8_t> generateAlternatingPattern(uint8_t b1, uint8_t b2, size_t count);
    };

    // Seed database - pre-generated common seeds
    class SeedDatabase {
    public:
        static const FuzzingSeed* getKnownCVESeeds(size_t& count);
        static const char* const CVE_REFERENCES[];
        static const size_t CVE_COUNT;
    };
}
