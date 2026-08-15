#include "opcua_x509_parser.h"
#include "../core/logging_system.h"
#include <cstring>
#include <ctime>

extern "C" {
    #include "esp_timer.h"
}

#define TAG_X509 "X509Parser"

namespace X509DER {

// ==================== UTILITY FUNCTIONS ====================

bool Parser::hexToBytes(const psram_string& hex, psram_vector<uint8_t>& out_bytes) {
    out_bytes.clear();

    if (hex.empty()) return true;

    size_t len = hex.length();
    if (len % 2 != 0) {
        LOG_ERROR(TAG_X509, "Hex string has odd length");
        return false;
    }

    out_bytes.reserve(len / 2);

    for (size_t i = 0; i < len; i += 2) {
        char c1 = hex[i];
        char c2 = hex[i + 1];

        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };

        int v1 = hexVal(c1);
        int v2 = hexVal(c2);

        if (v1 < 0 || v2 < 0) {
            LOG_ERROR(TAG_X509, "Invalid hex character");
            return false;
        }

        out_bytes.push_back(static_cast<uint8_t>((v1 << 4) | v2));
    }

    return true;
}

psram_string Parser::bytesToHex(const uint8_t* data, size_t len) {
    if (!data || len == 0) return PSRAMUtils::createPSRAMString("");

    PSRAMUtils::ScopedBuffer hex_buf(len * 2 + 1);
    if (!hex_buf.valid()) return PSRAMUtils::createPSRAMString("");

    char* hex_ptr = (char*)hex_buf.get();
    for (size_t i = 0; i < len; ++i) {
        snprintf(hex_ptr + (i * 2), 3, "%02X", data[i]);
    }
    hex_ptr[len * 2] = '\0';

    return PSRAMUtils::createPSRAMString(hex_ptr);
}

bool Parser::oidMatches(const psram_string& oid, const char* expected) {
    return strcmp(oid.c_str(), expected) == 0;
}

// ==================== ASN.1 LOW-LEVEL PARSERS ====================

bool Parser::parseLength(const uint8_t* data, size_t len, size_t& offset, size_t& out_length) {
    if (offset >= len) return false;

    uint8_t first_byte = data[offset++];

    // Short form (0-127)
    if ((first_byte & 0x80) == 0) {
        out_length = first_byte;
        return true;
    }

    // Long form
    uint8_t num_bytes = first_byte & 0x7F;
    if (num_bytes == 0 || num_bytes > 4) {
        LOG_ERRORF(TAG_X509, "Invalid length encoding: %d bytes", num_bytes);
        return false;
    }

    if (offset + num_bytes > len) return false;

    out_length = 0;
    for (uint8_t i = 0; i < num_bytes; ++i) {
        out_length = (out_length << 8) | data[offset++];
    }

    return true;
}

bool Parser::parseTLV(const uint8_t* data, size_t len, size_t& offset, TLV& out_tlv) {
    if (offset >= len) return false;

    size_t start_offset = offset;

    // Parse tag
    out_tlv.tag = data[offset++];

    // Parse length
    if (!parseLength(data, len, offset, out_tlv.length)) {
        return false;
    }

    // Validate length
    if (offset + out_tlv.length > len) {
        LOG_ERROR(TAG_X509, "TLV length exceeds buffer");
        return false;
    }

    out_tlv.value_offset = offset;
    out_tlv.total_size = (offset - start_offset) + out_tlv.length;

    return true;
}

bool Parser::parseOID(const uint8_t* data, size_t len, psram_string& out_oid) {
    if (len == 0) return false;

    // Use stack buffer for OID string (max ~50 chars)
    char oid_buf[64];
    char* oid_ptr = oid_buf;
    size_t oid_remaining = sizeof(oid_buf) - 1;

    // First byte encodes first two components
    uint8_t first = data[0];
    int written = snprintf(oid_ptr, oid_remaining, "%u.%u", first / 40, first % 40);
    if (written < 0) return false;
    oid_ptr += written;
    oid_remaining -= written;

    // Subsequent bytes encode remaining components
    size_t i = 1;
    while (i < len) {
        uint32_t value = 0;

        // Variable-length encoding (base 128)
        do {
            if (i >= len) return false;
            uint8_t byte = data[i++];
            value = (value << 7) | (byte & 0x7F);

            if ((byte & 0x80) == 0) break;
        } while (i < len);

        written = snprintf(oid_ptr, oid_remaining, ".%u", (unsigned)value);
        if (written < 0 || (size_t)written >= oid_remaining) return false;
        oid_ptr += written;
        oid_remaining -= written;
    }

    *oid_ptr = '\0';
    out_oid = PSRAMUtils::createPSRAMString(oid_buf);
    return true;
}

bool Parser::parseInteger(const uint8_t* data, size_t len, psram_vector<uint8_t>& out_bytes) {
    out_bytes.clear();
    if (len == 0) return true;

    // Skip leading zero byte (used for positive integers in ASN.1)
    size_t start = (len > 1 && data[0] == 0) ? 1 : 0;

    out_bytes.reserve(len - start);
    for (size_t i = start; i < len; ++i) {
        out_bytes.push_back(data[i]);
    }

    return true;
}

bool Parser::parseString(const uint8_t* data, size_t len, uint8_t tag, psram_string& out_str) {
    if (len == 0) {
        out_str = PSRAMUtils::createPSRAMString("");
        return true;
    }

    // Use stack buffer for temporary string (max 256 chars)
    char str_buf[256];
    size_t copy_len = (len < sizeof(str_buf) - 1) ? len : (sizeof(str_buf) - 1);

    memcpy(str_buf, data, copy_len);
    str_buf[copy_len] = '\0';

    out_str = PSRAMUtils::createPSRAMString(str_buf);
    return true;
}

bool Parser::parseTime(const uint8_t* data, size_t len, uint8_t tag, uint64_t& out_timestamp) {
    // UTCTime: YYMMDDhhmmssZ (13 bytes)
    // GeneralizedTime: YYYYMMDDhhmmssZ (15 bytes)

    if (len < 13) return false;

    char time_buf[32];
    size_t copy_len = (len < sizeof(time_buf) - 1) ? len : (sizeof(time_buf) - 1);
    memcpy(time_buf, data, copy_len);
    time_buf[copy_len] = '\0';

    struct tm tm_time = {};

    if (tag == TAG_UTC_TIME && len >= 13) {
        // YYMMDDhhmmssZ
        char year_str[3] = {time_buf[0], time_buf[1], 0};
        int year = atoi(year_str);

        // Y2K handling: 00-49 = 2000-2049, 50-99 = 1950-1999
        year += (year < 50) ? 2000 : 1900;

        tm_time.tm_year = year - 1900;
        tm_time.tm_mon = (time_buf[2] - '0') * 10 + (time_buf[3] - '0') - 1;
        tm_time.tm_mday = (time_buf[4] - '0') * 10 + (time_buf[5] - '0');
        tm_time.tm_hour = (time_buf[6] - '0') * 10 + (time_buf[7] - '0');
        tm_time.tm_min = (time_buf[8] - '0') * 10 + (time_buf[9] - '0');
        tm_time.tm_sec = (time_buf[10] - '0') * 10 + (time_buf[11] - '0');
    } else if (tag == TAG_GENERALIZED_TIME && len >= 15) {
        // YYYYMMDDhhmmssZ
        char year_str[5] = {time_buf[0], time_buf[1], time_buf[2], time_buf[3], 0};
        int year = atoi(year_str);

        tm_time.tm_year = year - 1900;
        tm_time.tm_mon = (time_buf[4] - '0') * 10 + (time_buf[5] - '0') - 1;
        tm_time.tm_mday = (time_buf[6] - '0') * 10 + (time_buf[7] - '0');
        tm_time.tm_hour = (time_buf[8] - '0') * 10 + (time_buf[9] - '0');
        tm_time.tm_min = (time_buf[10] - '0') * 10 + (time_buf[11] - '0');
        tm_time.tm_sec = (time_buf[12] - '0') * 10 + (time_buf[13] - '0');
    } else {
        return false;
    }

    // Convert to Unix timestamp (simplified - assumes UTC)
    time_t unix_time = mktime(&tm_time);
    out_timestamp = (uint64_t)unix_time * 1000; // Convert to milliseconds

    return true;
}

// ==================== HIGH-LEVEL PARSERS ====================

bool Parser::parseName(const uint8_t* data, size_t len, size_t& offset,
                      psram_string& out_cn, psram_string& out_org) {
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

    TLV name_seq;
    if (!parseTLV(data, len, offset, name_seq) || name_seq.tag != TAG_SEQUENCE) {
        return false;
    }

    size_t name_offset = name_seq.value_offset;
    size_t name_end = name_offset + name_seq.length;

    out_cn = PSRAMUtils::createPSRAMString("");
    out_org = PSRAMUtils::createPSRAMString("");

    while (name_offset < name_end) {
        TLV rdn_set;
        if (!parseTLV(data, len, name_offset, rdn_set) || rdn_set.tag != TAG_SET) {
            break;
        }

        size_t rdn_offset = rdn_set.value_offset;

        // Parse AttributeTypeAndValue SEQUENCE
        TLV attr_seq;
        if (!parseTLV(data, len, rdn_offset, attr_seq) || attr_seq.tag != TAG_SEQUENCE) {
            name_offset += rdn_set.total_size;
            continue;
        }

        size_t attr_offset = attr_seq.value_offset;

        // Parse OID
        TLV oid_tlv;
        if (!parseTLV(data, len, attr_offset, oid_tlv) || oid_tlv.tag != TAG_OID) {
            name_offset += rdn_set.total_size;
            continue;
        }

        psram_string oid;
        if (!parseOID(data + oid_tlv.value_offset, oid_tlv.length, oid)) {
            name_offset += rdn_set.total_size;
            continue;
        }

        attr_offset += oid_tlv.total_size;

        // Parse Value (string)
        TLV value_tlv;
        if (!parseTLV(data, len, attr_offset, value_tlv)) {
            name_offset += rdn_set.total_size;
            continue;
        }

        psram_string value;
        if (!parseString(data + value_tlv.value_offset, value_tlv.length, value_tlv.tag, value)) {
            name_offset += rdn_set.total_size;
            continue;
        }

        // Store relevant attributes
        if (oidMatches(oid, OID::CN)) {
            out_cn = value;
        } else if (oidMatches(oid, OID::O)) {
            out_org = value;
        }

        name_offset += rdn_set.total_size;
    }

    offset = name_end;
    return true;
}

bool Parser::parseSubjectAltName(const uint8_t* data, size_t len,
                                 psram_string_vector& out_dns_names,
                                 psram_string_vector& out_ips) {
    // SubjectAltName ::= SEQUENCE OF GeneralName
    // GeneralName ::= CHOICE { dNSName [2], iPAddress [7], ... }

    size_t offset = 0;

    while (offset < len) {
        if (offset >= len) break;

        uint8_t tag = data[offset];
        offset++;

        size_t value_len;
        if (!parseLength(data, len, offset, value_len)) break;

        if (offset + value_len > len) break;

        if (tag == 0x82) { // dNSName [2]
            psram_string dns_name;
            if (parseString(data + offset, value_len, TAG_IA5_STRING, dns_name)) {
                out_dns_names.push_back(dns_name);
            }
        } else if (tag == 0x87) { // iPAddress [7]
            if (value_len == 4) { // IPv4
                char ip_buf[16];
                snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u",
                        data[offset], data[offset + 1],
                        data[offset + 2], data[offset + 3]);
                out_ips.push_back(PSRAMUtils::createPSRAMString(ip_buf));
            }
        }

        offset += value_len;
    }

    return true;
}

bool Parser::parseExtensions(const uint8_t* data, size_t len, size_t& offset,
                            X509CertificateInfo& info) {
    // Extensions ::= SEQUENCE OF Extension

    TLV ext_seq;
    if (!parseTLV(data, len, offset, ext_seq) || ext_seq.tag != TAG_SEQUENCE) {
        return false;
    }

    size_t ext_offset = ext_seq.value_offset;
    size_t ext_end = ext_offset + ext_seq.length;

    while (ext_offset < ext_end) {
        TLV extension;
        if (!parseTLV(data, len, ext_offset, extension) || extension.tag != TAG_SEQUENCE) {
            break;
        }

        size_t inner_offset = extension.value_offset;

        // Parse extnID (OID)
        TLV oid_tlv;
        if (!parseTLV(data, len, inner_offset, oid_tlv) || oid_tlv.tag != TAG_OID) {
            ext_offset += extension.total_size;
            continue;
        }

        psram_string oid;
        if (!parseOID(data + oid_tlv.value_offset, oid_tlv.length, oid)) {
            ext_offset += extension.total_size;
            continue;
        }

        inner_offset += oid_tlv.total_size;

        // Check for critical flag (optional BOOLEAN)
        TLV next_tlv;
        if (parseTLV(data, len, inner_offset, next_tlv) && next_tlv.tag == 0x01) {
            inner_offset += next_tlv.total_size;
        }

        // Parse extnValue (OCTET STRING)
        TLV value_tlv;
        if (!parseTLV(data, len, inner_offset, value_tlv) || value_tlv.tag != TAG_OCTET_STRING) {
            ext_offset += extension.total_size;
            continue;
        }

        // Process specific extensions
        if (oidMatches(oid, OID::BASIC_CONSTRAINTS)) {
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN }
            size_t bc_offset = value_tlv.value_offset;
            TLV bc_seq;
            if (parseTLV(data, len, bc_offset, bc_seq) && bc_seq.tag == TAG_SEQUENCE) {
                bc_offset = bc_seq.value_offset;
                TLV ca_tlv;
                if (parseTLV(data, len, bc_offset, ca_tlv) && ca_tlv.tag == 0x01) {
                    info.is_ca = (data[ca_tlv.value_offset] != 0);
                }
            }
        } else if (oidMatches(oid, OID::SUBJECT_ALT_NAME)) {
            parseSubjectAltName(data + value_tlv.value_offset, value_tlv.length,
                              info.san_dns_names, info.san_ip_addresses);
        }

        ext_offset += extension.total_size;
    }

    offset = ext_end;
    return true;
}

// ==================== SECURITY ASSESSMENT ====================

bool Parser::isWeakSignatureAlgorithm(const psram_string& sig_alg) {
    // Check for MD5 or SHA1
    return (sig_alg.find("MD5") != psram_string::npos) ||
           (sig_alg.find("SHA1") != psram_string::npos) ||
           (sig_alg.find("sha1") != psram_string::npos);
}

bool Parser::isWeakKeySize(uint16_t key_size_bits) {
    // RSA keys < 2048 bits are considered weak
    return key_size_bits < 2048;
}

bool Parser::isSelfSigned(const psram_string& subject_cn, const psram_string& issuer_cn) {
    return subject_cn == issuer_cn && !subject_cn.empty();
}

// ==================== MAIN PARSER ====================

bool Parser::parseCertificateFromBinary(const uint8_t* der_data, size_t der_len,
                                       X509CertificateInfo& out_info,
                                       psram_string& out_error) {
    if (!der_data || der_len == 0) {
        out_error = PSRAMUtils::createPSRAMString("Empty certificate data");
        return false;
    }

    LOG_INFOF(TAG_X509, "Parsing X.509 certificate (%zu bytes)", der_len);

    size_t offset = 0;

    // Certificate ::= SEQUENCE {
    //     tbsCertificate       TBSCertificate,
    //     signatureAlgorithm   AlgorithmIdentifier,
    //     signatureValue       BIT STRING
    // }

    TLV cert_seq;
    if (!parseTLV(der_data, der_len, offset, cert_seq) || cert_seq.tag != TAG_SEQUENCE) {
        out_error = PSRAMUtils::createPSRAMString("Invalid certificate structure");
        return false;
    }

    size_t tbs_offset = cert_seq.value_offset;

    // TBSCertificate ::= SEQUENCE
    TLV tbs_seq;
    if (!parseTLV(der_data, der_len, tbs_offset, tbs_seq) || tbs_seq.tag != TAG_SEQUENCE) {
        out_error = PSRAMUtils::createPSRAMString("Invalid TBSCertificate");
        return false;
    }

    size_t tbs_inner = tbs_seq.value_offset;

    // Parse version [0] EXPLICIT (optional, default v1)
    TLV version_tlv;
    if (parseTLV(der_data, der_len, tbs_inner, version_tlv) && version_tlv.tag == TAG_CONTEXT_0) {
        tbs_inner += version_tlv.total_size;
    }

    // Parse serialNumber (INTEGER)
    TLV serial_tlv;
    if (!parseTLV(der_data, der_len, tbs_inner, serial_tlv) || serial_tlv.tag != TAG_INTEGER) {
        out_error = PSRAMUtils::createPSRAMString("Invalid serial number");
        return false;
    }

    psram_vector<uint8_t> serial_bytes;
    parseInteger(der_data + serial_tlv.value_offset, serial_tlv.length, serial_bytes);
    out_info.serial_number = bytesToHex(serial_bytes.data(), serial_bytes.size());

    tbs_inner += serial_tlv.total_size;

    // Parse signature algorithm (SEQUENCE)
    TLV sig_alg_tlv;
    if (!parseTLV(der_data, der_len, tbs_inner, sig_alg_tlv) || sig_alg_tlv.tag != TAG_SEQUENCE) {
        out_error = PSRAMUtils::createPSRAMString("Invalid signature algorithm");
        return false;
    }

    // Extract signature algorithm OID
    size_t sig_alg_offset = sig_alg_tlv.value_offset;
    TLV sig_oid_tlv;
    if (parseTLV(der_data, der_len, sig_alg_offset, sig_oid_tlv) && sig_oid_tlv.tag == TAG_OID) {
        psram_string sig_oid;
        if (parseOID(der_data + sig_oid_tlv.value_offset, sig_oid_tlv.length, sig_oid)) {
            if (oidMatches(sig_oid, OID::SHA256_RSA)) {
                out_info.signature_algorithm = PSRAMUtils::createPSRAMString("sha256WithRSAEncryption");
            } else if (oidMatches(sig_oid, OID::SHA1_RSA)) {
                out_info.signature_algorithm = PSRAMUtils::createPSRAMString("sha1WithRSAEncryption");
            } else if (oidMatches(sig_oid, OID::MD5_RSA)) {
                out_info.signature_algorithm = PSRAMUtils::createPSRAMString("md5WithRSAEncryption");
            } else {
                out_info.signature_algorithm = PSRAMUtils::createPSRAMString("unknown");
            }
        }
    }

    tbs_inner += sig_alg_tlv.total_size;

    // Parse issuer Name
    if (!parseName(der_data, der_len, tbs_inner,
                   out_info.issuer_common_name, out_info.issuer_organization)) {
        out_error = PSRAMUtils::createPSRAMString("Failed to parse issuer");
        return false;
    }

    // Parse validity (SEQUENCE of two times)
    TLV validity_tlv;
    if (!parseTLV(der_data, der_len, tbs_inner, validity_tlv) || validity_tlv.tag != TAG_SEQUENCE) {
        out_error = PSRAMUtils::createPSRAMString("Invalid validity");
        return false;
    }

    size_t validity_offset = validity_tlv.value_offset;

    // Parse notBefore
    TLV not_before_tlv;
    if (parseTLV(der_data, der_len, validity_offset, not_before_tlv)) {
        parseTime(der_data + not_before_tlv.value_offset, not_before_tlv.length,
                 not_before_tlv.tag, out_info.not_before_timestamp);
        validity_offset += not_before_tlv.total_size;
    }

    // Parse notAfter
    TLV not_after_tlv;
    if (parseTLV(der_data, der_len, validity_offset, not_after_tlv)) {
        parseTime(der_data + not_after_tlv.value_offset, not_after_tlv.length,
                 not_after_tlv.tag, out_info.not_after_timestamp);
    }

    tbs_inner += validity_tlv.total_size;

    // Parse subject Name
    if (!parseName(der_data, der_len, tbs_inner,
                   out_info.subject_common_name, out_info.subject_organization)) {
        out_error = PSRAMUtils::createPSRAMString("Failed to parse subject");
        return false;
    }

    // Parse subjectPublicKeyInfo
    TLV spki_tlv;
    if (!parseTLV(der_data, der_len, tbs_inner, spki_tlv) || spki_tlv.tag != TAG_SEQUENCE) {
        out_error = PSRAMUtils::createPSRAMString("Invalid subjectPublicKeyInfo");
        return false;
    }

    // Extract key size (simplified - just estimate from BIT STRING length)
    size_t spki_offset = spki_tlv.value_offset;
    TLV alg_id_tlv;
    if (parseTLV(der_data, der_len, spki_offset, alg_id_tlv) && alg_id_tlv.tag == TAG_SEQUENCE) {
        spki_offset += alg_id_tlv.total_size;

        TLV pub_key_tlv;
        if (parseTLV(der_data, der_len, spki_offset, pub_key_tlv) && pub_key_tlv.tag == TAG_BIT_STRING) {
            // Estimate key size from bit string length (rough approximation)
            size_t bit_len = (pub_key_tlv.length - 1) * 8; // -1 for unused bits byte
            out_info.key_size_bits = (uint16_t)bit_len;

            // More accurate: RSA keys typically have modulus around 75% of total
            if (bit_len > 1024) {
                out_info.key_size_bits = (uint16_t)(bit_len * 0.75);
            }
        }
    }

    tbs_inner += spki_tlv.total_size;

    // Parse extensions [3] EXPLICIT (optional)
    TLV ext_context_tlv;
    if (parseTLV(der_data, der_len, tbs_inner, ext_context_tlv) && ext_context_tlv.tag == TAG_CONTEXT_3) {
        size_t ext_offset = ext_context_tlv.value_offset;
        parseExtensions(der_data, der_len, ext_offset, out_info);
    }

    // Security assessment
    out_info.is_self_signed = isSelfSigned(out_info.subject_common_name, out_info.issuer_common_name);
    out_info.has_weak_signature = isWeakSignatureAlgorithm(out_info.signature_algorithm);
    out_info.has_weak_key = isWeakKeySize(out_info.key_size_bits);

    // Check expiration
    uint64_t now_ms = esp_timer_get_time() / 1000;
    out_info.is_expired = (now_ms > out_info.not_after_timestamp);

    // Populate vulnerabilities
    out_info.vulnerabilities.clear();

    if (out_info.is_expired) {
        out_info.vulnerabilities.push_back(PSRAMUtils::createPSRAMString("CRITICAL: Certificate expired"));
    }

    if (out_info.has_weak_key) {
        char buf[64];
        snprintf(buf, sizeof(buf), "HIGH: Weak key size (%u bits < 2048)", out_info.key_size_bits);
        out_info.vulnerabilities.push_back(PSRAMUtils::createPSRAMString(buf));
    }

    if (out_info.has_weak_signature) {
        out_info.vulnerabilities.push_back(PSRAMUtils::createPSRAMString("HIGH: Weak signature algorithm (MD5/SHA1)"));
    }

    if (out_info.is_self_signed) {
        out_info.vulnerabilities.push_back(PSRAMUtils::createPSRAMString("MEDIUM: Self-signed certificate"));
    }

    LOG_INFOF(TAG_X509, "Certificate parsed: CN=%s, Issuer=%s, KeySize=%u, SigAlg=%s",
              PSRAMUtils::fromPSRAMString(out_info.subject_common_name).c_str(),
              PSRAMUtils::fromPSRAMString(out_info.issuer_common_name).c_str(),
              out_info.key_size_bits,
              PSRAMUtils::fromPSRAMString(out_info.signature_algorithm).c_str());

    return true;
}

bool Parser::parseCertificate(const psram_string& cert_der_hex,
                             X509CertificateInfo& out_info,
                             psram_string& out_error) {
    // Convert hex string to binary
    psram_vector<uint8_t> der_bytes;
    if (!hexToBytes(cert_der_hex, der_bytes)) {
        out_error = PSRAMUtils::createPSRAMString("Failed to decode hex certificate");
        return false;
    }

    if (der_bytes.empty()) {
        out_error = PSRAMUtils::createPSRAMString("Empty certificate after hex decode");
        return false;
    }

    return parseCertificateFromBinary(der_bytes.data(), der_bytes.size(), out_info, out_error);
}

} // namespace X509DER
