#pragma once

#include "../core/psram_allocator.h"
#include "opcua_fuzzing_seeds.h"
#include <cstdint>

// OPC UA Fuzzing Executor
// Executes fuzzing campaigns with mutation strategies, crash detection, and seed minimization

namespace OPCUAFuzzingExecutor {

    // Import types from fuzzing seeds namespace
    using OPCUAFuzzingSeeds::SeedCategory;
    using OPCUAFuzzingSeeds::FuzzingSeed;

    // Mutation strategies
    enum class MutationStrategy {
        BIT_FLIP,           // Flip random bits
        BYTE_FLIP,          // Flip random bytes
        ARITHMETIC,         // Add/subtract small values
        INTERESTING_VALUES, // Replace with interesting integers
        BLOCK_DELETION,     // Delete random blocks
        BLOCK_DUPLICATION,  // Duplicate random blocks
        BLOCK_SHUFFLE,      // Shuffle blocks
        SPLICE              // Splice two seeds together
    };

    // Fuzzing result
    struct FuzzingResult {
        psram_string seed_name;
        SeedCategory seed_category;
        psram_vector<uint8_t> mutated_payload;

        bool caused_crash;
        bool caused_hang;
        bool caused_memory_leak;
        bool caused_protocol_error;

        uint64_t execution_time_ms;
        psram_string crash_signature;  // Stack trace hash or error pattern
        psram_string server_response;

        FuzzingResult() :
            seed_category(SeedCategory::MALFORMED_HEADERS),
            caused_crash(false), caused_hang(false),
            caused_memory_leak(false), caused_protocol_error(false),
            execution_time_ms(0) {}
    };

    // Fuzzing campaign configuration
    struct FuzzingConfig {
        uint32_t max_mutations_per_seed;
        uint32_t max_total_iterations;
        uint32_t timeout_ms;
        uint32_t hang_detection_timeout_ms;
        bool enable_crash_dedup;
        bool enable_seed_minimization;
        bool aggressive_mode;

        FuzzingConfig() :
            max_mutations_per_seed(10),
            max_total_iterations(1000),
            timeout_ms(5000),
            hang_detection_timeout_ms(10000),
            enable_crash_dedup(true),
            enable_seed_minimization(false),
            aggressive_mode(false) {}
    };

    // Fuzzing statistics
    struct FuzzingStats {
        uint64_t total_executions;
        uint64_t unique_crashes;
        uint64_t unique_hangs;
        uint64_t protocol_errors;
        uint64_t successful_responses;
        uint64_t campaign_duration_ms;

        psram_vector<FuzzingResult> crash_results;
        psram_vector<FuzzingResult> hang_results;

        FuzzingStats() :
            total_executions(0), unique_crashes(0), unique_hangs(0),
            protocol_errors(0), successful_responses(0),
            campaign_duration_ms(0) {}
    };

    // Mutation engine
    class MutationEngine {
    public:
        MutationEngine();

        // Apply mutation to payload
        psram_vector<uint8_t> mutate(const psram_vector<uint8_t>& original,
                                     MutationStrategy strategy);

        // Apply random mutation
        psram_vector<uint8_t> mutateRandom(const psram_vector<uint8_t>& original);

        // Splice two payloads
        psram_vector<uint8_t> splice(const psram_vector<uint8_t>& payload1,
                                     const psram_vector<uint8_t>& payload2);

        // Seed for randomness
        void setSeed(uint32_t seed);

    private:
        uint32_t rng_state_;

        // Internal RNG
        uint32_t random();
        uint32_t randomRange(uint32_t min, uint32_t max);

        // Mutation implementations
        psram_vector<uint8_t> mutateBitFlip(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateByteFlip(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateArithmetic(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateInteresting(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateBlockDelete(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateBlockDuplicate(const psram_vector<uint8_t>& data);
        psram_vector<uint8_t> mutateBlockShuffle(const psram_vector<uint8_t>& data);

        // Interesting values
        static const int32_t INTERESTING_8[];
        static const int32_t INTERESTING_16[];
        static const int32_t INTERESTING_32[];
    };

    // Fuzzing executor
    class FuzzingExecutor {
    public:
        FuzzingExecutor();
        ~FuzzingExecutor();

        // Run fuzzing campaign
        bool runCampaign(const char* server_url, uint16_t port,
                        const FuzzingConfig& config,
                        FuzzingStats& out_stats);

        // Run single fuzzing test
        FuzzingResult executeFuzzingTest(const char* server_url, uint16_t port,
                                        const FuzzingSeed& seed,
                                        const psram_vector<uint8_t>& payload,
                                        uint32_t timeout_ms);

        // Crash detection
        bool detectCrash(const psram_vector<uint8_t>& response);
        psram_string generateCrashSignature(const psram_vector<uint8_t>& response);

        // Seed minimization (delta debugging)
        psram_vector<uint8_t> minimizeSeed(const char* server_url, uint16_t port,
                                           const psram_vector<uint8_t>& crashing_payload,
                                           uint32_t timeout_ms);

        // Report generation
        psram_string generateFuzzingReport(const FuzzingStats& stats);

    private:
        MutationEngine mutation_engine_;
        psram_string_set seen_crash_signatures_;

        // Helper: Connect and send
        bool connectAndSend(const char* server_url, uint16_t port,
                           const uint8_t* data, size_t len,
                           psram_vector<uint8_t>& response,
                           uint32_t timeout_ms, bool& timed_out);

        // Helper: Check if crash is unique
        bool isUniqueCrash(const psram_string& signature);

        // Delta debugging helper
        bool testDeltaVariant(const char* server_url, uint16_t port,
                             const psram_vector<uint8_t>& variant,
                             uint32_t timeout_ms);
    };
}
