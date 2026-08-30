#pragma once

#include "../core/psram_allocator.h"
#include "opcua_binary_codec.h"
#include <cstdint>
#include <cstddef>

// X.509 DER Parser - Minimal implementation for OPC UA certificate analysis
// Focuses on extracting security-relevant information without full ASN.1 library

namespace X509DER {
    // ASN.1 Tag types
    constexpr uint8_t TAG_INTEGER = 0x02;
    constexpr uint8_t TAG_BIT_STRING = 0x03;
    constexpr uint8_t TAG_OCTET_STRING = 0x04;
    constexpr uint8_t TAG_NULL = 0x05;
    constexpr uint8_t TAG_OID = 0x06;
    constexpr uint8_t TAG_UTF8_STRING = 0x0C;
    constexpr uint8_t TAG_PRINTABLE_STRING = 0x13;
    constexpr uint8_t TAG_IA5_STRING = 0x16;
    constexpr uint8_t TAG_UTC_TIME = 0x17;
    constexpr uint8_t TAG_GENERALIZED_TIME = 0x18;
    constexpr uint8_t TAG_SEQUENCE = 0x30;
    constexpr uint8_t TAG_SET = 0x31;
    constexpr uint8_t TAG_CONTEXT_0 = 0xA0;
    constexpr uint8_t TAG_CONTEXT_3 = 0xA3;

    // Common OIDs
    struct OID {
        static constexpr const char* CN = "2.5.4.3";           // Common Name
        static constexpr const char* O = "2.5.4.10";           // Organization
        static constexpr const char* OU = "2.5.4.11";          // Organizational Unit
        static constexpr const char* C = "2.5.4.6";            // Country
        static constexpr const char* ST = "2.5.4.8";           // State
        static constexpr const char* L = "2.5.4.7";            // Locality

        static constexpr const char* SHA256_RSA = "1.2.840.113549.1.1.11";
        static constexpr const char* SHA1_RSA = "1.2.840.113549.1.1.5";
        static constexpr const char* MD5_RSA = "1.2.840.113549.1.1.4";
        static constexpr const char* RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

        static constexpr const char* BASIC_CONSTRAINTS = "2.5.29.19";
        static constexpr const char* SUBJECT_ALT_NAME = "2.5.29.17";
        static constexpr const char* KEY_USAGE = "2.5.29.15";
    };

    // TLV structure for ASN.1 parsing
    struct TLV {
        uint8_t tag;
        size_t length;
        size_t value_offset;
        size_t total_size;  // tag + length_bytes + value

        TLV() : tag(0), length(0), value_offset(0), total_size(0) {}
    };

    class Parser {
    public:
        // Parse DER certificate from hex string
        static bool parseCertificate(const psram_string& cert_der_hex,
                                     X509CertificateInfo& out_info,
                                     psram_string& out_error);

        // Parse DER certificate from binary data
        static bool parseCertificateFromBinary(const uint8_t* der_data, size_t der_len,
                                               X509CertificateInfo& out_info,
                                               psram_string& out_error);

        // Re-evaluate cached metadata against wall-clock UTC, never device uptime.
        // A zero/implausible clock means unknown, not valid or expired.
        static void evaluateValidity(X509CertificateInfo& info, int64_t unix_ms);
        static int64_t currentUnixTimeMs();

        // OPC UA Part 6: certificate ByteStrings may concatenate leaf + issuers.
        // Bounded framing only; this never establishes a trusted certificate path.
        static bool certificateChainLengths(const uint8_t* data, size_t len,
                                            psram_vector<size_t>& lengths);

    private:
        // Low-level ASN.1 parsers
        static bool parseTLV(const uint8_t* data, size_t len, size_t& offset, TLV& out_tlv);
        static bool parseLength(const uint8_t* data, size_t len, size_t& offset, size_t& out_length);
        static bool parseOID(const uint8_t* data, size_t len, psram_string& out_oid);
        static bool parseInteger(const uint8_t* data, size_t len, psram_vector<uint8_t>& out_bytes);
        static bool parseString(const uint8_t* data, size_t len, uint8_t tag, psram_string& out_str);
        static bool parseTime(const uint8_t* data, size_t len, uint8_t tag, int64_t& out_timestamp);
        static bool parseCertificateContents(const uint8_t* data, size_t len,
                                             X509CertificateInfo& info, psram_string& error);

        // High-level certificate structure parsers
        static bool parseName(const uint8_t* data, size_t len, size_t& offset,
                             psram_string& out_cn, psram_string& out_org);
        static bool parseSubjectAltName(const uint8_t* data, size_t len,
                                       psram_string_vector& out_dns_names,
                                       psram_string_vector& out_ips);
        static bool parseExtensions(const uint8_t* data, size_t len, size_t& offset,
                                   X509CertificateInfo& info);

        // Security assessment helpers
        static bool isWeakSignatureAlgorithm(const psram_string& sig_alg);
        static bool isWeakKeySize(uint16_t key_size_bits);

        // Utility functions
        static bool hexToBytes(const psram_string& hex, psram_vector<uint8_t>& out_bytes);
        static psram_string bytesToHex(const uint8_t* data, size_t len);
        static bool oidMatches(const psram_string& oid, const char* expected);
    };
}
