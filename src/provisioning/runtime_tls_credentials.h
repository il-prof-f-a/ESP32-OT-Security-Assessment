#pragma once

#include <cstddef>

#include "../core/psram_allocator.h"


class RuntimeTlsCredentials {
public:
    bool ensurePresent();
    bool load();
    bool clear();
    const char* certificatePem() const { return certificate_pem_.c_str(); }
    size_t certificateLength() const { return certificate_pem_.size(); }
    const char* privateKeyPem() const { return private_key_pem_.c_str(); }
    size_t privateKeyLength() const { return private_key_pem_.size(); }
    bool sha256Fingerprint(char* output, size_t output_size) const;

private:
    bool validatePair(const psram_string& certificate, const psram_string& key) const;
    bool generateAndStore();
    psram_string certificate_pem_ = PSRAMUtils::createPSRAMString("");
    psram_string private_key_pem_ = PSRAMUtils::createPSRAMString("");
};
