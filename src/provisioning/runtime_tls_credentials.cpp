#include "runtime_tls_credentials.h"

#include <cstdio>
#include <cstring>

#include "../core/async_storage_engine.h"

extern "C" {
#include "esp_mac.h"
#include "esp_heap_caps.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
}


#ifndef ESP32_OT_WEB_HTTP_ONLY
#define ESP32_OT_WEB_HTTP_ONLY 0
#endif

namespace {
constexpr const char* kCertificatePath = "/data/certs/server.crt";
constexpr const char* kPrivateKeyPath = "/data/certs/server.key";
constexpr const char* kCertificateNewPath = "/data/certs/server.crt.new";
constexpr const char* kPrivateKeyNewPath = "/data/certs/server.key.new";

bool initializeDrbg(mbedtls_entropy_context& entropy, mbedtls_ctr_drbg_context& drbg) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    static const unsigned char personalization[] = "esp32-ot-runtime-tls";
    return mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                 personalization, sizeof(personalization) - 1) == 0;
}
}  // namespace


bool RuntimeTlsCredentials::validatePair(const psram_string& certificate,
                                         const psram_string& key_pem) const {
    if (certificate.empty() || key_pem.empty()) return false;
    mbedtls_x509_crt parsed_certificate;
    mbedtls_pk_context parsed_key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_x509_crt_init(&parsed_certificate);
    mbedtls_pk_init(&parsed_key);
    const bool rng_ready = initializeDrbg(entropy, drbg);
    const bool valid = rng_ready &&
        mbedtls_x509_crt_parse(
            &parsed_certificate,
            reinterpret_cast<const unsigned char*>(certificate.c_str()),
            certificate.size() + 1) == 0 &&
        mbedtls_pk_parse_key(
            &parsed_key,
            reinterpret_cast<const unsigned char*>(key_pem.c_str()),
            key_pem.size() + 1, nullptr, 0,
            mbedtls_ctr_drbg_random, &drbg) == 0 &&
        mbedtls_pk_check_pair(&parsed_certificate.pk, &parsed_key,
                              mbedtls_ctr_drbg_random, &drbg) == 0;
    mbedtls_pk_free(&parsed_key);
    mbedtls_x509_crt_free(&parsed_certificate);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return valid;
}

bool RuntimeTlsCredentials::load() {
#if ESP32_OT_WEB_HTTP_ONLY
    certificate_pem_.clear();
    private_key_pem_.clear();
    return true;
#else
    psram_string certificate;
    psram_string key;
    if (AsyncStorage::Global::readFile(kCertificatePath, certificate) != ESP_OK ||
        AsyncStorage::Global::readFile(kPrivateKeyPath, key) != ESP_OK ||
        !validatePair(certificate, key)) {
        return false;
    }
    certificate_pem_ = certificate;
    private_key_pem_ = key;
    return true;
#endif
}

bool RuntimeTlsCredentials::generateAndStore() {
#if ESP32_OT_WEB_HTTP_ONLY
    return true;
#else
    bool success = false;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_pk_context key;
    mbedtls_x509write_cert certificate;
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&certificate);
    const bool rng_ready = initializeDrbg(entropy, drbg);

    unsigned char* certificate_buffer = static_cast<unsigned char*>(
        heap_caps_calloc(4096, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    unsigned char* key_buffer = static_cast<unsigned char*>(
        heap_caps_calloc(2048, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    uint8_t serial_bytes[16] = {};
    uint8_t mac[6] = {};
    char distinguished_name[96] = {};

    if (rng_ready && certificate_buffer && key_buffer &&
        esp_read_mac(mac, ESP_MAC_BASE) == ESP_OK &&
        std::snprintf(distinguished_name, sizeof(distinguished_name),
                      "CN=esp32-ot-%02x%02x%02x.local,O=ESP32 OT Security Assessment",
                      mac[3], mac[4], mac[5]) > 0 &&
        mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0 &&
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                            mbedtls_ctr_drbg_random, &drbg) == 0) {
        mbedtls_ctr_drbg_random(&drbg, serial_bytes, sizeof(serial_bytes));
        serial_bytes[0] &= 0x7F;
        serial_bytes[0] |= 0x01;
        mbedtls_x509write_crt_set_version(&certificate, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&certificate, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&certificate, &key);
        mbedtls_x509write_crt_set_issuer_key(&certificate, &key);
        const bool configured =
            mbedtls_x509write_crt_set_subject_name(&certificate, distinguished_name) == 0 &&
            mbedtls_x509write_crt_set_issuer_name(&certificate, distinguished_name) == 0 &&
            mbedtls_x509write_crt_set_serial_raw(
                &certificate, serial_bytes, sizeof(serial_bytes)) == 0 &&
            mbedtls_x509write_crt_set_validity(
                &certificate, "20260101000000", "20360101000000") == 0 &&
            mbedtls_x509write_crt_set_basic_constraints(&certificate, 0, -1) == 0 &&
            mbedtls_x509write_crt_set_key_usage(
                &certificate, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0;
        if (configured &&
            mbedtls_pk_write_key_pem(&key, key_buffer, 2048) == 0 &&
            mbedtls_x509write_crt_pem(&certificate, certificate_buffer, 4096,
                                      mbedtls_ctr_drbg_random, &drbg) == 0) {
            const psram_string generated_certificate = PSRAMUtils::createPSRAMString(
                reinterpret_cast<const char*>(certificate_buffer));
            const psram_string generated_key = PSRAMUtils::createPSRAMString(
                reinterpret_cast<const char*>(key_buffer));
            const esp_err_t directory_result =
                AsyncStorage::Global::createDir("/data/certs");
            if (validatePair(generated_certificate, generated_key) &&
                (directory_result == ESP_OK || directory_result == ESP_ERR_INVALID_ARG) &&
                AsyncStorage::Global::writeFileRaw(
                    kPrivateKeyNewPath, generated_key.data(), generated_key.size()) == ESP_OK &&
                AsyncStorage::Global::writeFileRaw(
                    kCertificateNewPath, generated_certificate.data(),
                    generated_certificate.size()) == ESP_OK &&
                AsyncStorage::Global::fileRename(
                    kPrivateKeyNewPath, kPrivateKeyPath) == ESP_OK &&
                AsyncStorage::Global::fileRename(
                    kCertificateNewPath, kCertificatePath) == ESP_OK) {
                success = true;
            }
        }
    }

    if (certificate_buffer) {
        std::memset(certificate_buffer, 0, 4096);
        heap_caps_free(certificate_buffer);
    }
    if (key_buffer) {
        std::memset(key_buffer, 0, 2048);
        heap_caps_free(key_buffer);
    }
    std::memset(serial_bytes, 0, sizeof(serial_bytes));
    mbedtls_x509write_crt_free(&certificate);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return success;
#endif
}

bool RuntimeTlsCredentials::ensurePresent() {
#if ESP32_OT_WEB_HTTP_ONLY
    return true;
#else
    if (load()) return true;
    AsyncStorage::Global::deleteFile(kCertificateNewPath);
    AsyncStorage::Global::deleteFile(kPrivateKeyNewPath);
    AsyncStorage::Global::deleteFile(kCertificatePath);
    AsyncStorage::Global::deleteFile(kPrivateKeyPath);
    return generateAndStore() && load();
#endif
}

bool RuntimeTlsCredentials::clear() {
    certificate_pem_.clear();
    private_key_pem_.clear();
#if ESP32_OT_WEB_HTTP_ONLY
    return true;
#else
    const esp_err_t certificate = AsyncStorage::Global::deleteFile(kCertificatePath);
    const esp_err_t key = AsyncStorage::Global::deleteFile(kPrivateKeyPath);
    AsyncStorage::Global::deleteFile(kCertificateNewPath);
    AsyncStorage::Global::deleteFile(kPrivateKeyNewPath);
    return (certificate == ESP_OK || certificate == ESP_ERR_NOT_FOUND) &&
           (key == ESP_OK || key == ESP_ERR_NOT_FOUND);
#endif
}

bool RuntimeTlsCredentials::sha256Fingerprint(char* output, size_t output_size) const {
#if ESP32_OT_WEB_HTTP_ONLY
    if (output && output_size) output[0] = '\0';
    return false;
#else
    if (!output || output_size < 96 || certificate_pem_.empty()) return false;
    mbedtls_x509_crt parsed;
    mbedtls_x509_crt_init(&parsed);
    if (mbedtls_x509_crt_parse(
            &parsed,
            reinterpret_cast<const unsigned char*>(certificate_pem_.c_str()),
            certificate_pem_.size() + 1) != 0) {
        mbedtls_x509_crt_free(&parsed);
        return false;
    }
    uint8_t digest[32] = {};
    const int result = mbedtls_sha256(parsed.raw.p, parsed.raw.len, digest, 0);
    mbedtls_x509_crt_free(&parsed);
    if (result != 0) return false;
    size_t position = 0;
    for (size_t index = 0; index < sizeof(digest); ++index) {
        const int written = std::snprintf(
            output + position, output_size - position, index ? ":%02X" : "%02X",
            digest[index]);
        if (written <= 0) return false;
        position += static_cast<size_t>(written);
    }
    std::memset(digest, 0, sizeof(digest));
    return true;
#endif
}
