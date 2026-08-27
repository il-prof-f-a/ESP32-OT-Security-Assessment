#include "password_hasher.h"

#include <cctype>
#include <cstdio>
#include <cstring>

extern "C" {
#include "esp_random.h"
#include "mbedtls/base64.h"
#include "mbedtls/pkcs5.h"
}


namespace {
constexpr size_t kMinimumPasswordBytes = 16;
constexpr size_t kMaximumPasswordBytes = 128;
constexpr size_t kSaltBytes = 16;
constexpr size_t kHashBytes = 32;
constexpr uint32_t kIterations = 100000;

void secureZero(void* pointer, size_t length) {
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(pointer);
    while (length-- > 0) *bytes++ = 0;
}

bool constantTimeEqual(const uint8_t* left, const uint8_t* right, size_t length) {
    volatile uint8_t difference = 0;
    for (size_t index = 0; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

bool isLegacySha256(const psram_string& value) {
    if (value.size() != 64) return false;
    for (char character : value) {
        if (!std::isxdigit(static_cast<unsigned char>(character))) return false;
    }
    return true;
}

bool blockedPassword(const char* password, size_t length) {
    char lower[kMaximumPasswordBytes + 1] = {};
    for (size_t index = 0; index < length; ++index) {
        lower[index] = static_cast<char>(
            std::tolower(static_cast<unsigned char>(password[index])));
    }
    const bool blocked = std::strcmp(lower, "admin") == 0 ||
                         std::strcmp(lower, "admin1234") == 0 ||
                         std::strcmp(lower, "password") == 0 ||
                         std::strcmp(lower, "changeme") == 0 ||
                         std::strncmp(lower, "esp32-ot-setup", 14) == 0;
    secureZero(lower, sizeof(lower));
    return blocked;
}

bool parsePbkdf2(const psram_string& encoded,
                 uint8_t salt[kSaltBytes],
                 uint8_t hash[kHashBytes]) {
    const size_t first = encoded.find(':');
    const size_t second = encoded.find(':', first == psram_string::npos ? first : first + 1);
    const size_t third = encoded.find(':', second == psram_string::npos ? second : second + 1);
    if (first == psram_string::npos || second == psram_string::npos ||
        third == psram_string::npos ||
        encoded.substr(0, first) != PSRAMUtils::createPSRAMString("pbkdf2")) {
        return false;
    }

    const psram_string iterations = encoded.substr(second + 1, third - second - 1);
    if (iterations != PSRAMUtils::createPSRAMString("100000")) return false;

    const psram_string salt_b64 = encoded.substr(first + 1, second - first - 1);
    const psram_string hash_b64 = encoded.substr(third + 1);
    size_t salt_length = 0;
    size_t hash_length = 0;
    if (mbedtls_base64_decode(salt, kSaltBytes, &salt_length,
                              reinterpret_cast<const unsigned char*>(salt_b64.data()),
                              salt_b64.size()) != 0 ||
        mbedtls_base64_decode(hash, kHashBytes, &hash_length,
                              reinterpret_cast<const unsigned char*>(hash_b64.data()),
                              hash_b64.size()) != 0) {
        secureZero(salt, kSaltBytes);
        secureZero(hash, kHashBytes);
        return false;
    }
    return salt_length == kSaltBytes && hash_length == kHashBytes;
}

bool compute(const char* password, size_t length, const uint8_t* salt,
             uint8_t output[kHashBytes]) {
    if (!password || length == 0 || length > kMaximumPasswordBytes) return false;

    // The ESP32-P4 SHA accelerator may require input in internal DMA-capable RAM.
    // Password strings are PSRAM-backed, so use a bounded, short-lived stack copy.
    uint8_t password_internal[kMaximumPasswordBytes] = {};
    std::memcpy(password_internal, password, length);
    const bool derived = mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA256,
        password_internal, length,
        salt, kSaltBytes, kIterations, kHashBytes, output) == 0;
    secureZero(password_internal, sizeof(password_internal));
    return derived;
}
}  // namespace


bool PasswordHasher::validatePolicy(const char* password, size_t length) {
    if (!password || length < kMinimumPasswordBytes || length > kMaximumPasswordBytes) {
        return false;
    }
    if (std::isspace(static_cast<unsigned char>(password[0])) ||
        std::isspace(static_cast<unsigned char>(password[length - 1]))) {
        return false;
    }
    return !blockedPassword(password, length);
}

bool PasswordHasher::derive(const char* password, size_t length, psram_string& hash_out) {
    hash_out.clear();
    if (!validatePolicy(password, length)) {
        return false;
    }

    uint8_t salt[kSaltBytes] = {};
    uint8_t hash[kHashBytes] = {};
    esp_fill_random(salt, sizeof(salt));
    if (!compute(password, length, salt, hash)) {
        secureZero(salt, sizeof(salt));
        secureZero(hash, sizeof(hash));
        return false;
    }

    unsigned char salt_b64[25] = {};
    unsigned char hash_b64[45] = {};
    size_t salt_length = 0;
    size_t hash_length = 0;
    const bool encoded =
        // Mbed TLS writes the encoded bytes plus a trailing NUL byte.  The
        // arrays are sized for both, so pass their complete capacity.
        mbedtls_base64_encode(salt_b64, sizeof(salt_b64), &salt_length,
                              salt, sizeof(salt)) == 0 &&
        mbedtls_base64_encode(hash_b64, sizeof(hash_b64), &hash_length,
                              hash, sizeof(hash)) == 0;
    secureZero(salt, sizeof(salt));
    secureZero(hash, sizeof(hash));
    if (!encoded) {
        secureZero(salt_b64, sizeof(salt_b64));
        secureZero(hash_b64, sizeof(hash_b64));
        return false;
    }

    char result[96] = {};
    const int written = std::snprintf(
        result, sizeof(result), "pbkdf2:%.*s:%u:%.*s",
        static_cast<int>(salt_length), salt_b64,
        static_cast<unsigned>(kIterations),
        static_cast<int>(hash_length), hash_b64);
    secureZero(salt_b64, sizeof(salt_b64));
    secureZero(hash_b64, sizeof(hash_b64));
    if (written <= 0 || static_cast<size_t>(written) >= sizeof(result)) {
        secureZero(result, sizeof(result));
        return false;
    }
    hash_out = PSRAMUtils::createPSRAMString(result);
    secureZero(result, sizeof(result));
    return !hash_out.empty();
}

bool PasswordHasher::verify(const char* password, size_t length,
                            const psram_string& encoded_hash) {
    if (!password || length == 0) return false;
    uint8_t salt[kSaltBytes] = {};
    uint8_t expected[kHashBytes] = {};
    uint8_t computed[kHashBytes] = {};
    if (!parsePbkdf2(encoded_hash, salt, expected) ||
        !compute(password, length, salt, computed)) {
        secureZero(salt, sizeof(salt));
        secureZero(expected, sizeof(expected));
        secureZero(computed, sizeof(computed));
        return false;
    }
    const bool matches = constantTimeEqual(expected, computed, sizeof(expected));
    secureZero(salt, sizeof(salt));
    secureZero(expected, sizeof(expected));
    secureZero(computed, sizeof(computed));
    return matches;
}

bool PasswordHasher::isSupportedHash(const psram_string& encoded_hash) {
    if (isLegacySha256(encoded_hash)) return true;
    uint8_t salt[kSaltBytes] = {};
    uint8_t hash[kHashBytes] = {};
    const bool valid = parsePbkdf2(encoded_hash, salt, hash);
    secureZero(salt, sizeof(salt));
    secureZero(hash, sizeof(hash));
    return valid;
}
