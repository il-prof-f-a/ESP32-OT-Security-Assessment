#include "opcua_fuzzing_executor.h"
#include "opcua_fuzzing_seeds.h"
#include "../core/logging_system.h"
#include "../core/psram_json_parser.h"
#include "../network/assessment_interface.h"

extern "C" {
    #include <esp_timer.h>
    #include <lwip/sockets.h>
    #include <lwip/netdb.h>
}

#include <cJSON.h>
#include <cstring>
#include <algorithm>

#define TAG_OPCUA_FUZZ_EXEC "OPCUAFuzzExec"

namespace OPCUAFuzzingExecutor {

using namespace OPCUAFuzzingSeeds;

namespace {
struct JsonHookGuard {
    JsonHookGuard() { PSRAMJson::ensureHooks(); }
};
static JsonHookGuard kJsonHookGuard;
}

// Interesting values for mutation
const int32_t MutationEngine::INTERESTING_8[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127
};

const int32_t MutationEngine::INTERESTING_16[] = {
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767
};

const int32_t MutationEngine::INTERESTING_32[] = {
    -2147483648, -100663046, -32769, 32768, 65535, 65536,
    100663045, 2147483647
};

// MutationEngine implementation
MutationEngine::MutationEngine() : rng_state_(0x12345678) {
}

void MutationEngine::setSeed(uint32_t seed) {
    rng_state_ = seed ? seed : 0x12345678;
}

uint32_t MutationEngine::random() {
    // Simple xorshift RNG
    rng_state_ ^= rng_state_ << 13;
    rng_state_ ^= rng_state_ >> 17;
    rng_state_ ^= rng_state_ << 5;
    return rng_state_;
}

uint32_t MutationEngine::randomRange(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    return min + (random() % (max - min));
}

// Bit flip mutation
psram_vector<uint8_t> MutationEngine::mutateBitFlip(const psram_vector<uint8_t>& data) {
    if (data.empty()) return data;

    psram_vector<uint8_t> mutated = data;
    size_t num_flips = 1 + (random() % 8);  // Flip 1-8 bits

    for (size_t i = 0; i < num_flips; i++) {
        size_t byte_idx = random() % data.size();
        uint8_t bit_idx = random() % 8;
        mutated[byte_idx] ^= (1 << bit_idx);
    }

    return mutated;
}

// Byte flip mutation
psram_vector<uint8_t> MutationEngine::mutateByteFlip(const psram_vector<uint8_t>& data) {
    if (data.empty()) return data;

    psram_vector<uint8_t> mutated = data;
    size_t num_flips = 1 + (random() % 4);  // Flip 1-4 bytes

    for (size_t i = 0; i < num_flips; i++) {
        size_t idx = random() % data.size();
        mutated[idx] = (uint8_t)(random() & 0xFF);
    }

    return mutated;
}

// Arithmetic mutation
psram_vector<uint8_t> MutationEngine::mutateArithmetic(const psram_vector<uint8_t>& data) {
    if (data.size() < 4) return data;

    psram_vector<uint8_t> mutated = data;
    size_t offset = random() % (data.size() - 3);

    // Interpret as int32 and add/subtract
    int32_t value;
    memcpy(&value, &mutated[offset], 4);

    int32_t delta = (int32_t)(random() % 256) - 128;  // -128 to +127
    value += delta;

    memcpy(&mutated[offset], &value, 4);

    return mutated;
}

// Interesting values mutation
psram_vector<uint8_t> MutationEngine::mutateInteresting(const psram_vector<uint8_t>& data) {
    if (data.size() < 4) return data;

    psram_vector<uint8_t> mutated = data;
    size_t offset = random() % (data.size() - 3);

    uint32_t choice = random() % 3;

    if (choice == 0 && offset < data.size()) {
        // 8-bit interesting
        size_t idx = random() % (sizeof(INTERESTING_8) / sizeof(INTERESTING_8[0]));
        mutated[offset] = (uint8_t)INTERESTING_8[idx];
    } else if (choice == 1 && offset < data.size() - 1) {
        // 16-bit interesting
        size_t idx = random() % (sizeof(INTERESTING_16) / sizeof(INTERESTING_16[0]));
        int16_t val = (int16_t)INTERESTING_16[idx];
        memcpy(&mutated[offset], &val, 2);
    } else if (offset < data.size() - 3) {
        // 32-bit interesting
        size_t idx = random() % (sizeof(INTERESTING_32) / sizeof(INTERESTING_32[0]));
        int32_t val = INTERESTING_32[idx];
        memcpy(&mutated[offset], &val, 4);
    }

    return mutated;
}

// Block deletion mutation
psram_vector<uint8_t> MutationEngine::mutateBlockDelete(const psram_vector<uint8_t>& data) {
    if (data.size() < 16) return data;

    size_t block_size = 1 + (random() % (data.size() / 4));
    size_t start = random() % (data.size() - block_size);

    psram_vector<uint8_t> mutated;
    mutated.reserve(data.size() - block_size);

    for (size_t i = 0; i < data.size(); i++) {
        if (i < start || i >= start + block_size) {
            mutated.push_back(data[i]);
        }
    }

    return mutated;
}

// Block duplication mutation
psram_vector<uint8_t> MutationEngine::mutateBlockDuplicate(const psram_vector<uint8_t>& data) {
    if (data.size() < 8) return data;

    size_t block_size = 1 + (random() % (data.size() / 4));
    size_t start = random() % (data.size() - block_size);

    psram_vector<uint8_t> mutated = data;

    // Duplicate the block
    for (size_t i = start; i < start + block_size && i < data.size(); i++) {
        mutated.push_back(data[i]);
    }

    return mutated;
}

// Block shuffle mutation
psram_vector<uint8_t> MutationEngine::mutateBlockShuffle(const psram_vector<uint8_t>& data) {
    if (data.size() < 16) return data;

    psram_vector<uint8_t> mutated = data;

    // Divide into 4 blocks and shuffle
    size_t block_size = data.size() / 4;

    // Simple Fisher-Yates shuffle for 4 blocks
    for (size_t i = 3; i > 0; i--) {
        size_t j = random() % (i + 1);

        // Swap blocks i and j
        size_t offset_i = i * block_size;
        size_t offset_j = j * block_size;

        for (size_t k = 0; k < block_size && offset_i + k < data.size() && offset_j + k < data.size(); k++) {
            uint8_t temp = mutated[offset_i + k];
            mutated[offset_i + k] = mutated[offset_j + k];
            mutated[offset_j + k] = temp;
        }
    }

    return mutated;
}

// Splice two payloads
psram_vector<uint8_t> MutationEngine::splice(const psram_vector<uint8_t>& payload1,
                                             const psram_vector<uint8_t>& payload2) {
    if (payload1.empty()) return payload2;
    if (payload2.empty()) return payload1;

    size_t split1 = random() % payload1.size();
    size_t split2 = random() % payload2.size();

    psram_vector<uint8_t> spliced;
    spliced.reserve(split1 + (payload2.size() - split2));

    // First part of payload1
    for (size_t i = 0; i < split1; i++) {
        spliced.push_back(payload1[i]);
    }

    // Second part of payload2
    for (size_t i = split2; i < payload2.size(); i++) {
        spliced.push_back(payload2[i]);
    }

    return spliced;
}

// Apply specific mutation
psram_vector<uint8_t> MutationEngine::mutate(const psram_vector<uint8_t>& original,
                                             MutationStrategy strategy) {
    switch (strategy) {
        case MutationStrategy::BIT_FLIP:
            return mutateBitFlip(original);
        case MutationStrategy::BYTE_FLIP:
            return mutateByteFlip(original);
        case MutationStrategy::ARITHMETIC:
            return mutateArithmetic(original);
        case MutationStrategy::INTERESTING_VALUES:
            return mutateInteresting(original);
        case MutationStrategy::BLOCK_DELETION:
            return mutateBlockDelete(original);
        case MutationStrategy::BLOCK_DUPLICATION:
            return mutateBlockDuplicate(original);
        case MutationStrategy::BLOCK_SHUFFLE:
            return mutateBlockShuffle(original);
        default:
            return original;
    }
}

// Apply random mutation
psram_vector<uint8_t> MutationEngine::mutateRandom(const psram_vector<uint8_t>& original) {
    MutationStrategy strategies[] = {
        MutationStrategy::BIT_FLIP,
        MutationStrategy::BYTE_FLIP,
        MutationStrategy::ARITHMETIC,
        MutationStrategy::INTERESTING_VALUES,
        MutationStrategy::BLOCK_DELETION,
        MutationStrategy::BLOCK_DUPLICATION,
        MutationStrategy::BLOCK_SHUFFLE
    };

    size_t strategy_idx = random() % 7;
    return mutate(original, strategies[strategy_idx]);
}

// FuzzingExecutor implementation
FuzzingExecutor::FuzzingExecutor() {
    // Seed mutation engine with current time
    uint64_t now = esp_timer_get_time();
    mutation_engine_.setSeed((uint32_t)(now & 0xFFFFFFFF));
}

FuzzingExecutor::~FuzzingExecutor() {
}

// Helper: Connect and send
bool FuzzingExecutor::connectAndSend(const char* server_url, uint16_t port,
                                    const uint8_t* data, size_t len,
                                    psram_vector<uint8_t>& response,
                                    uint32_t timeout_ms, bool& timed_out) {
    timed_out = false;

    int sock_fd = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd < 0) {
        return false;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Resolve hostname
    struct hostent* host = gethostbyname(server_url);
    if (!host) {
        close(sock_fd);
        return false;
    }

    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);

    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock_fd);
        return false;
    }

    // Send data
    ssize_t sent = send(sock_fd, data, len, 0);
    if (sent != (ssize_t)len) {
        close(sock_fd);
        return false;
    }

    // Receive response
    PSRAMUtils::ScopedBuffer buffer(4096);
    if (!buffer.get()) {
        close(sock_fd);
        return false;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock_fd, &read_fds);

    struct timeval recv_tv;
    recv_tv.tv_sec = timeout_ms / 1000;
    recv_tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = select(sock_fd + 1, &read_fds, nullptr, nullptr, &recv_tv);
    if (ready == 0) {
        timed_out = true;
        close(sock_fd);
        return false;
    }

    if (ready < 0) {
        close(sock_fd);
        return false;
    }

    ssize_t received = recv(sock_fd, buffer.get(), 4096, 0);
    close(sock_fd);

    if (received <= 0) {
        return false;
    }

    response.clear();
    response.reserve(received);
    for (ssize_t i = 0; i < received; i++) {
        response.push_back(buffer.get()[i]);
    }

    return true;
}

// Crash detection
bool FuzzingExecutor::detectCrash(const psram_vector<uint8_t>& response) {
    if (response.empty()) return false;

    // Look for error patterns in response
    // OPC UA error responses typically start with "ERR" or have error status codes

    if (response.size() >= 4) {
        if (response[0] == 'E' && response[1] == 'R' && response[2] == 'R') {
            return true;
        }
    }

    // Check for malformed responses (likely server crashed/hung)
    if (response.size() < 8) {
        return true;  // Too short to be valid
    }

    // Check message header validity
    if (response.size() >= 3) {
        bool valid_type = (response[0] == 'H' && response[1] == 'E' && response[2] == 'L') ||
                         (response[0] == 'A' && response[1] == 'C' && response[2] == 'K') ||
                         (response[0] == 'M' && response[1] == 'S' && response[2] == 'G') ||
                         (response[0] == 'O' && response[1] == 'P' && response[2] == 'N') ||
                         (response[0] == 'C' && response[1] == 'L' && response[2] == 'O') ||
                         (response[0] == 'E' && response[1] == 'R' && response[2] == 'R');

        if (!valid_type) {
            return true;  // Invalid message type = corrupted response
        }
    }

    return false;
}

// Generate crash signature
psram_string FuzzingExecutor::generateCrashSignature(const psram_vector<uint8_t>& response) {
    // Simple hash of first 32 bytes
    uint32_t hash = 0x811C9DC5;  // FNV-1a initial value

    size_t len = std::min((size_t)32, response.size());
    for (size_t i = 0; i < len; i++) {
        hash ^= response[i];
        hash *= 0x01000193;  // FNV-1a prime
    }

    char sig[32];
    snprintf(sig, sizeof(sig), "crash_%08lX", (unsigned long)hash);
    return PSRAMUtils::createPSRAMString(sig);
}

// Check if crash is unique
bool FuzzingExecutor::isUniqueCrash(const psram_string& signature) {
    if (seen_crash_signatures_.find(signature) != seen_crash_signatures_.end()) {
        return false;
    }
    seen_crash_signatures_.insert(signature);
    return true;
}

// Execute single fuzzing test
FuzzingResult FuzzingExecutor::executeFuzzingTest(const char* server_url, uint16_t port,
                                                  const FuzzingSeed& seed,
                                                  const psram_vector<uint8_t>& payload,
                                                  uint32_t timeout_ms) {
    FuzzingResult result;
    result.seed_name = seed.name;
    result.seed_category = seed.category;
    result.mutated_payload = payload;

    uint64_t start_time = esp_timer_get_time() / 1000;

    psram_vector<uint8_t> response;
    bool timed_out = false;

    bool success = connectAndSend(server_url, port, payload.data(), payload.size(),
                                  response, timeout_ms, timed_out);

    result.execution_time_ms = (esp_timer_get_time() / 1000) - start_time;

    if (timed_out) {
        result.caused_hang = true;
        result.crash_signature = PSRAMUtils::createPSRAMString("timeout");
    } else if (!success) {
        result.caused_protocol_error = true;
    } else if (detectCrash(response)) {
        result.caused_crash = true;
        result.crash_signature = generateCrashSignature(response);

        // Store first 64 bytes of response
        size_t resp_len = std::min((size_t)64, response.size());
        char hex[129];
        for (size_t i = 0; i < resp_len && i < 64; i++) {
            snprintf(&hex[i*2], 3, "%02X", response[i]);
        }
        hex[resp_len * 2] = '\0';
        result.server_response = PSRAMUtils::createPSRAMString(hex);
    }

    return result;
}

// Run fuzzing campaign
bool FuzzingExecutor::runCampaign(const char* server_url, uint16_t port,
                                 const FuzzingConfig& config,
                                 FuzzingStats& out_stats) {
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "Starting fuzzing campaign: %s:%u", server_url, port);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Max iterations: %u, timeout: %u ms",
             config.max_total_iterations, config.timeout_ms);

    uint64_t campaign_start = esp_timer_get_time() / 1000;

    // Generate seeds
    SeedGenerator seed_gen;
    psram_vector<FuzzingSeed> seeds = seed_gen.generateAllSeeds();

    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "Generated %zu fuzzing seeds", seeds.size());

    uint32_t iterations = 0;
    uint32_t progress_interval = config.max_total_iterations / 10;

    for (const auto& seed : seeds) {
        if (iterations >= config.max_total_iterations) {
            break;
        }

        // Test original seed
        FuzzingResult original_result = executeFuzzingTest(server_url, port, seed,
                                                          seed.payload, config.timeout_ms);
        out_stats.total_executions++;
        iterations++;

        if (original_result.caused_crash && isUniqueCrash(original_result.crash_signature)) {
            out_stats.unique_crashes++;
            out_stats.crash_results.push_back(original_result);

            LOG_WARNINGF(TAG_OPCUA_FUZZ_EXEC, "CRASH FOUND: %s (sig: %s)",
                        PSRAMUtils::fromPSRAMString(seed.name).c_str(),
                        PSRAMUtils::fromPSRAMString(original_result.crash_signature).c_str());

            if (config.enable_seed_minimization) {
                LOG_INFO(TAG_OPCUA_FUZZ_EXEC, "  Minimizing crash seed...");
                psram_vector<uint8_t> minimized = minimizeSeed(server_url, port,
                                                              seed.payload, config.timeout_ms);
                LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Minimized: %zu -> %zu bytes",
                         seed.payload.size(), minimized.size());
            }
        }

        if (original_result.caused_hang) {
            out_stats.unique_hangs++;
            out_stats.hang_results.push_back(original_result);
            LOG_WARNINGF(TAG_OPCUA_FUZZ_EXEC, "HANG FOUND: %s",
                        PSRAMUtils::fromPSRAMString(seed.name).c_str());
        }

        if (original_result.caused_protocol_error) {
            out_stats.protocol_errors++;
        }

        if (!original_result.caused_crash && !original_result.caused_hang &&
            !original_result.caused_protocol_error) {
            out_stats.successful_responses++;
        }

        // Apply mutations
        uint32_t mutations = 0;
        while (mutations < config.max_mutations_per_seed && iterations < config.max_total_iterations) {
            psram_vector<uint8_t> mutated = mutation_engine_.mutateRandom(seed.payload);

            FuzzingResult mutated_result = executeFuzzingTest(server_url, port, seed,
                                                             mutated, config.timeout_ms);
            out_stats.total_executions++;
            iterations++;
            mutations++;

            if (mutated_result.caused_crash && isUniqueCrash(mutated_result.crash_signature)) {
                out_stats.unique_crashes++;
                out_stats.crash_results.push_back(mutated_result);

                LOG_WARNINGF(TAG_OPCUA_FUZZ_EXEC, "CRASH (mutated): %s (sig: %s)",
                            PSRAMUtils::fromPSRAMString(seed.name).c_str(),
                            PSRAMUtils::fromPSRAMString(mutated_result.crash_signature).c_str());
            }

            if (mutated_result.caused_hang) {
                out_stats.unique_hangs++;
                out_stats.hang_results.push_back(mutated_result);
            }

            if (mutated_result.caused_protocol_error) {
                out_stats.protocol_errors++;
            }

            if (!mutated_result.caused_crash && !mutated_result.caused_hang &&
                !mutated_result.caused_protocol_error) {
                out_stats.successful_responses++;
            }
        }

        // Progress reporting
        if (progress_interval > 0 && iterations % progress_interval == 0) {
            LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "Progress: %u/%u iterations, %llu crashes, %llu hangs",
                     iterations, config.max_total_iterations,
                     out_stats.unique_crashes, out_stats.unique_hangs);
        }
    }

    out_stats.campaign_duration_ms = (esp_timer_get_time() / 1000) - campaign_start;

    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "Fuzzing campaign complete:");
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Total executions: %llu", out_stats.total_executions);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Unique crashes: %llu", out_stats.unique_crashes);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Unique hangs: %llu", out_stats.unique_hangs);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Protocol errors: %llu", out_stats.protocol_errors);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Successful: %llu", out_stats.successful_responses);
    LOG_INFOF(TAG_OPCUA_FUZZ_EXEC, "  Duration: %llu ms", out_stats.campaign_duration_ms);

    return true;
}

// Delta debugging seed minimization
psram_vector<uint8_t> FuzzingExecutor::minimizeSeed(const char* server_url, uint16_t port,
                                                    const psram_vector<uint8_t>& crashing_payload,
                                                    uint32_t timeout_ms) {
    psram_vector<uint8_t> minimized = crashing_payload;

    // Binary search for minimal size
    size_t chunk_size = minimized.size() / 2;

    while (chunk_size > 0) {
        bool progress = false;

        for (size_t i = 0; i + chunk_size <= minimized.size(); i += chunk_size) {
            // Try removing this chunk
            psram_vector<uint8_t> candidate;
            candidate.reserve(minimized.size() - chunk_size);

            for (size_t j = 0; j < minimized.size(); j++) {
                if (j < i || j >= i + chunk_size) {
                    candidate.push_back(minimized[j]);
                }
            }

            if (testDeltaVariant(server_url, port, candidate, timeout_ms)) {
                minimized = candidate;
                progress = true;
                break;
            }
        }

        if (!progress) {
            chunk_size /= 2;
        }
    }

    return minimized;
}

bool FuzzingExecutor::testDeltaVariant(const char* server_url, uint16_t port,
                                      const psram_vector<uint8_t>& variant,
                                      uint32_t timeout_ms) {
    psram_vector<uint8_t> response;
    bool timed_out = false;

    bool success = connectAndSend(server_url, port, variant.data(), variant.size(),
                                  response, timeout_ms, timed_out);

    return timed_out || !success || detectCrash(response);
}

// Generate fuzzing report
psram_string FuzzingExecutor::generateFuzzingReport(const FuzzingStats& stats) {
    cJSON* root = cJSON_CreateObject();
    if (!root) return PSRAMUtils::createPSRAMString("{}");

    cJSON_AddNumberToObject(root, "total_executions", (double)stats.total_executions);
    cJSON_AddNumberToObject(root, "unique_crashes", (double)stats.unique_crashes);
    cJSON_AddNumberToObject(root, "unique_hangs", (double)stats.unique_hangs);
    cJSON_AddNumberToObject(root, "protocol_errors", (double)stats.protocol_errors);
    cJSON_AddNumberToObject(root, "successful_responses", (double)stats.successful_responses);
    cJSON_AddNumberToObject(root, "campaign_duration_ms", (double)stats.campaign_duration_ms);

    // Crash details
    cJSON* crashes_array = cJSON_CreateArray();
    for (const auto& crash : stats.crash_results) {
        cJSON* crash_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(crash_obj, "seed_name",
                               PSRAMUtils::fromPSRAMString(crash.seed_name).c_str());
        cJSON_AddStringToObject(crash_obj, "signature",
                               PSRAMUtils::fromPSRAMString(crash.crash_signature).c_str());
        cJSON_AddNumberToObject(crash_obj, "execution_time_ms", (double)crash.execution_time_ms);

        if (!crash.server_response.empty()) {
            cJSON_AddStringToObject(crash_obj, "response",
                                   PSRAMUtils::fromPSRAMString(crash.server_response).c_str());
        }

        cJSON_AddItemToArray(crashes_array, crash_obj);
    }
    cJSON_AddItemToObject(root, "crashes", crashes_array);

    // Hang details
    cJSON* hangs_array = cJSON_CreateArray();
    for (const auto& hang : stats.hang_results) {
        cJSON* hang_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(hang_obj, "seed_name",
                               PSRAMUtils::fromPSRAMString(hang.seed_name).c_str());
        cJSON_AddNumberToObject(hang_obj, "execution_time_ms", (double)hang.execution_time_ms);
        cJSON_AddItemToArray(hangs_array, hang_obj);
    }
    cJSON_AddItemToObject(root, "hangs", hangs_array);

    char* json_str = cJSON_PrintUnformatted(root);
    psram_string result = PSRAMUtils::createPSRAMString(json_str ? json_str : "{}");
    if (json_str) free(json_str);
    cJSON_Delete(root);

    return result;
}

} // namespace OPCUAFuzzingExecutor
