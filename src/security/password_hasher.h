#pragma once

#include <cstddef>

#include "../core/psram_allocator.h"


class PasswordHasher {
public:
    static bool validatePolicy(const char* password, size_t length);
    static bool derive(const char* password, size_t length, psram_string& hash_out);
    static bool verify(const char* password, size_t length,
                       const psram_string& encoded_hash);
    static bool isSupportedHash(const psram_string& encoded_hash);
};
