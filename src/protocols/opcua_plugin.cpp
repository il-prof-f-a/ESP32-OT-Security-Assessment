
#include "opcua_plugin.h"
#include "../security/security_manager.h"
#include "opcua_binary_codec.h"
#include "opcua_x509_parser.h"
#include "opcua_vulnerability_tests.h"
#include "opcua_fuzzing_seeds.h"
#include "../assessment/fuzzing_engine.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include "../core/logging_system.h"
#include "../core/psram_json_parser.h"
#include "../core/psram_allocator.h"
#include "../core/configuration_manager.h"
#include "../core/async_storage_engine.h"
extern "C" {
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
}
#include "../core/plugin_manager.h"
#include "../core/network_engine.h"
#include "../network/ethernet_tx_if.h"
#include "../network/assessment_interface.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <map>
#include <new>
#include <algorithm>
#include <cctype>
#include <cerrno>

extern ReportingEngine* g_reporting;

#include "../assessment/discovery_manager.h"

struct JsonHookGuard {
    JsonHookGuard() { PSRAMJson::ensureHooks(); }
};
static JsonHookGuard kJsonHookGuard;

namespace {
constexpr size_t kMaxOpcUaFrameSize = 64 * 1024;

// GetEndpoints exposes metadata, not a verified certificate chain or a login.
cJSON* certificateMetadata(X509CertificateInfo info, bool present) {
    X509DER::Parser::evaluateValidity(info, X509DER::Parser::currentUnixTimeMs());
    cJSON* cert = cJSON_CreateObject();
    if (!cert) return nullptr;
    cJSON_AddBoolToObject(cert, "present", present);
    cJSON_AddBoolToObject(cert, "parse_ok", info.parse_ok);
    cJSON_AddNumberToObject(cert, "certificates_in_blob", info.certificates_in_blob);
    cJSON_AddStringToObject(cert, "metadata_subject", "leaf_certificate");
    cJSON_AddNullToObject(cert, "valid");
    cJSON_AddStringToObject(cert, "validation_status", "not_performed");
    cJSON_AddStringToObject(cert, "assessment_scope", "metadata_only");
    cJSON_AddNullToObject(cert, "self_signed");
    cJSON_AddBoolToObject(cert, "time_checked", info.time_checked);
    if (!info.parse_ok) {
        if (!info.parse_error.empty()) cJSON_AddStringToObject(cert, "parse_error", info.parse_error.c_str());
        cJSON_AddNullToObject(cert, "self_issued");
        cJSON_AddNullToObject(cert, "is_ca");
    } else {
        cJSON_AddBoolToObject(cert, "self_issued", info.is_self_issued);
        cJSON_AddBoolToObject(cert, "is_ca", info.is_ca);
        cJSON_AddStringToObject(cert, "subject", info.subject_common_name.c_str());
        cJSON_AddStringToObject(cert, "issuer", info.issuer_common_name.c_str());
        cJSON_AddStringToObject(cert, "serial_number", info.serial_number.c_str());
        cJSON_AddStringToObject(cert, "signature_algorithm", info.signature_algorithm.c_str());
        cJSON_AddNumberToObject(cert, "not_before_ms", static_cast<double>(info.not_before_timestamp));
        cJSON_AddNumberToObject(cert, "not_after_ms", static_cast<double>(info.not_after_timestamp));
        cJSON_AddBoolToObject(cert, "key_size_known", info.key_size_known);
        if (info.key_size_known) cJSON_AddNumberToObject(cert, "key_size_bits", info.key_size_bits);
    }
    if (info.parse_ok && info.time_checked) {
        cJSON_AddBoolToObject(cert, "expired", info.is_expired);
        cJSON_AddBoolToObject(cert, "not_yet_valid", info.is_not_yet_valid);
        cJSON_AddBoolToObject(cert, "time_valid", !info.is_expired && !info.is_not_yet_valid);
    } else {
        cJSON_AddNullToObject(cert, "expired");
        cJSON_AddNullToObject(cert, "not_yet_valid");
        cJSON_AddNullToObject(cert, "time_valid");
    }
    return cert;
}

bool recvExact(int sock_fd, uint8_t* buffer, size_t length) {
    size_t received = 0;
    while (received < length) {
        const ssize_t count = ::recv(sock_fd, buffer + received, length - received, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        received += static_cast<size_t>(count);
    }
    return true;
}

bool recvOpcUaFrame(int sock_fd, psram_vector<uint8_t>& frame) {
    uint8_t header[8] = {};
    if (!recvExact(sock_fd, header, sizeof(header))) {
        return false;
    }

    const uint32_t msg_size = static_cast<uint32_t>(header[4]) |
                              (static_cast<uint32_t>(header[5]) << 8) |
                              (static_cast<uint32_t>(header[6]) << 16) |
                              (static_cast<uint32_t>(header[7]) << 24);
    if (msg_size < sizeof(header) || msg_size > kMaxOpcUaFrameSize) {
        return false;
    }

    frame.clear();
    frame.resize(msg_size);
    std::memcpy(frame.data(), header, sizeof(header));
    return recvExact(sock_fd, frame.data() + sizeof(header), msg_size - sizeof(header));
}

    struct SlidingWindowCounter {
        uint32_t count;
        uint32_t window_start_ms;
        SlidingWindowCounter() : count(0), window_start_ms(0) {}
    };

    inline void resetIfWindowExpired(SlidingWindowCounter& counter,
                                     uint32_t now_ms,
                                     uint32_t window_ms) {
        if (counter.window_start_ms == 0 ||
            (now_ms - counter.window_start_ms) > window_ms) {
            counter.window_start_ms = now_ms;
            counter.count = 0;
        }
    }

    struct EventDedupState {
        uint32_t last_emit_ms;
        EventDedupState() : last_emit_ms(0) {}
    };

    inline uint32_t fnv1a32(const char* text) {
        uint32_t hash = 2166136261u;
        if (!text) {
            return hash;
        }
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
            hash ^= static_cast<uint32_t>(*p);
            hash *= 16777619u;
        }
        return hash;
    }

    inline bool shouldSuppressEvent(const char* json, LogLevel level, uint32_t now_ms) {
        uint32_t window_ms = 0;
        if (level == LogLevel::INFO) {
            window_ms = 10000U;
        } else if (level == LogLevel::WARNING) {
            window_ms = 3000U;
        } else if (level == LogLevel::ERROR) {
            window_ms = 1000U;
        }
        if (window_ms == 0 || !json) {
            return false;
        }

        static psram_map<uint32_t, EventDedupState> event_cache;
        uint32_t key = fnv1a32(json) ^ static_cast<uint32_t>(level);
        auto& state = event_cache[key];
        if (state.last_emit_ms != 0 && (now_ms - state.last_emit_ms) < window_ms) {
            return true;
        }
        state.last_emit_ms = now_ms;
        return false;
    }

    inline bool isMsgType(const uint8_t* data, char a, char b, char c) {
        return data && data[0] == static_cast<uint8_t>(a) &&
               data[1] == static_cast<uint8_t>(b) &&
               data[2] == static_cast<uint8_t>(c);
    }
}

struct UATcpHeader {
    char msgType[3];  // "HEL","ACK","ERR","OPN","CLO","MSG"
    char chunk;       // 'F','C','A'
    uint32_t len;     // little-endian total length
} __attribute__((packed));

static bool parseHeader(const uint8_t* p, size_t n, UATcpHeader& h){
    if (n < 8) return false;
    memcpy(h.msgType, p, 3);
    h.chunk = (char)p[3];
    h.len = (uint32_t)p[4] | ((uint32_t)p[5]<<8) | ((uint32_t)p[6]<<16) | ((uint32_t)p[7]<<24);
    if (h.len < 8 || h.len > 65536) return false;
    return true;
}

static bool locateOpcuaFrame(const NetworkPacket& pkt, const uint8_t*& out, size_t& out_len) {
    out = nullptr;
    out_len = 0;
    if (!pkt.data || pkt.length < 8) return false;

    UATcpHeader h{};
    // Case 1: direct UA-TCP frame
    if (parseHeader(pkt.data, pkt.length, h)) {
        out = pkt.data;
        out_len = pkt.length;
        return true;
    }

    // Case 2: data starts at IPv4 header (L2 ingest path)
    const uint8_t* ip = pkt.data;
    size_t ip_len = pkt.length;
    if ((ip[0] >> 4) != 4 || ip_len < 20) return false;

    size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || ihl > ip_len) return false;
    if (ip[9] != 6) return false; // OPC UA is TCP
    if (ip_len < ihl + 20) return false;

    const uint8_t* tcp = ip + ihl;
    size_t doff = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4U;
    if (doff < 20 || ip_len < ihl + doff) return false;

    const uint8_t* frame = tcp + doff;
    size_t frame_len = ip_len - (ihl + doff);
    if (frame_len < 8) return false;
    if (!parseHeader(frame, frame_len, h)) return false;

    out = frame;
    out_len = frame_len;
    return true;
}

OPCUAPlugin::OPCUAPlugin(): BasePlugin("OPC UA","1.0.0", ProtocolType::OPC_UA){}

static inline bool memfind(const uint8_t* hay, size_t n, const char* needle, size_t m) {
    if (!hay || !needle || m==0 || n<m) return false;
    const uint8_t* end = hay + (n - m + 1);
    const uint8_t* p = hay;
    const uint8_t* pat = (const uint8_t*)needle;
    for (; p < end; ++p) {
        if (p[0] == pat[0] && memcmp(p, pat, m) == 0) return true;
    }
    return false;
}

static inline uint16_t readLe16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t readLe32(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

struct OpcuaServiceDescriptor {
    uint16_t request_id;
    uint16_t response_id;
    const char* name;
    const char* category;      // READ | WRITE | CONTROL | OTHER
    bool write_like;           // true for request services that modify state
    bool auth_related;         // CreateSession/ActivateSession
};

static const OpcuaServiceDescriptor kOpcuaServiceTable[] = {
    {422, 425, "FindServers",                  "READ",    false, false},
    {428, 431, "GetEndpoints",                 "READ",    false, false},
    {461, 464, "CreateSession",                "CONTROL", false, true},
    {467, 470, "ActivateSession",              "CONTROL", false, true},
    {473, 476, "CloseSession",                 "CONTROL", false, false},
    {488, 491, "AddNodes",                     "WRITE",   true,  false},
    {494, 497, "AddReferences",                "WRITE",   true,  false},
    {500, 503, "DeleteNodes",                  "WRITE",   true,  false},
    {506, 509, "DeleteReferences",             "WRITE",   true,  false},
    {527, 530, "Browse",                       "READ",    false, false},
    {533, 536, "BrowseNext",                   "READ",    false, false},
    {554, 557, "TranslateBrowsePathsToNodeIds","READ",    false, false},
    {631, 634, "Read",                         "READ",    false, false},
    {662, 665, "HistoryRead",                  "READ",    false, false},
    {673, 676, "Write",                        "WRITE",   true,  false},
    {700, 703, "HistoryUpdate",                "WRITE",   true,  false},
    {712, 715, "Call",                         "WRITE",   true,  false},
    {751, 754, "CreateMonitoredItems",         "CONTROL", false, false},
    {785, 788, "CreateSubscription",           "CONTROL", false, false},
    {826, 829, "Publish",                      "CONTROL", false, false}
};

static const OpcuaServiceDescriptor* findOpcuaServiceDescriptor(uint16_t service_id, bool* out_is_response) {
    if (out_is_response) {
        *out_is_response = false;
    }
    for (size_t idx = 0; idx < (sizeof(kOpcuaServiceTable) / sizeof(kOpcuaServiceTable[0])); ++idx) {
        const OpcuaServiceDescriptor& d = kOpcuaServiceTable[idx];
        if (d.request_id == service_id) {
            if (out_is_response) {
                *out_is_response = false;
            }
            return &d;
        }
        if (d.response_id == service_id) {
            if (out_is_response) {
                *out_is_response = true;
            }
            return &d;
        }
    }
    return nullptr;
}

static bool parseOpcuaServiceTypeIdFromMsg(const uint8_t* data, size_t len, uint16_t& out_service_id) {
    out_service_id = 0;
    if (!data || len < 25) {
        return false;
    }

    UATcpHeader h{};
    if (!parseHeader(data, len, h)) {
        return false;
    }
    if (!(h.msgType[0] == 'M' && h.msgType[1] == 'S' && h.msgType[2] == 'G')) {
        return false;
    }

    // MSG frame:
    // 0..7   UA-TCP header
    // 8..11  SecureChannelId
    // 12..15 SecurityTokenId
    // 16..19 SequenceNumber
    // 20..23 RequestId
    // 24..   TypeId (NodeId/ExpandedNodeId)
    size_t off = 24;
    if (off >= len) {
        return false;
    }

    const uint8_t enc = data[off++];
    const bool has_namespace_uri = (enc & 0x80U) != 0U;
    const bool has_server_index = (enc & 0x40U) != 0U;
    const uint8_t nodeid_type = static_cast<uint8_t>(enc & 0x3FU);

    uint16_t namespace_index = 0;
    uint32_t identifier = 0;

    if (nodeid_type == OPCUA::TWOBYTE) {
        if (off + 1 > len) {
            return false;
        }
        namespace_index = 0;
        identifier = data[off++];
    } else if (nodeid_type == OPCUA::FOURBYTE) {
        if (off + 3 > len) {
            return false;
        }
        namespace_index = data[off++];
        identifier = readLe16(data + off);
        off += 2;
    } else if (nodeid_type == OPCUA::NUMERIC) {
        if (off + 6 > len) {
            return false;
        }
        namespace_index = readLe16(data + off);
        off += 2;
        identifier = readLe32(data + off);
        off += 4;
    } else {
        return false;
    }

    if (has_namespace_uri) {
        if (off + 4 > len) {
            return false;
        }
        const int32_t uri_len = static_cast<int32_t>(readLe32(data + off));
        off += 4;
        if (uri_len >= 0) {
            if (off + static_cast<size_t>(uri_len) > len) {
                return false;
            }
            off += static_cast<size_t>(uri_len);
        }
    }

    if (has_server_index) {
        if (off + 4 > len) {
            return false;
        }
        off += 4;
    }

    if (namespace_index != 0 || identifier == 0 || identifier > 0xFFFFU) {
        return false;
    }

    out_service_id = static_cast<uint16_t>(identifier);
    return true;
}

static inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<int>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + static_cast<int>(c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + static_cast<int>(c - 'A');
    }
    return -1;
}

static bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.empty()) {
        return false;
    }
    if ((hex.size() % 2U) != 0U) {
        return false;
    }
    out.reserve(hex.size() / 2U);
    for (size_t idx = 0; idx < hex.size(); idx += 2U) {
        int hi = hexNibble(hex[idx]);
        int lo = hexNibble(hex[idx + 1U]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return !out.empty();
}

static std::string bytesToHexWithSpaces(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::string();
    }
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 3U);
    for (size_t i = 0; i < data.size(); ++i) {
        if (i) out.push_back(' ');
        const uint8_t b = data[i];
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

static bool parseJsonIntFieldSimple(const std::string& s, const char* key, int& out) {
    if (!key) return false;
    const std::string k = std::string("\"") + key + "\"";
    size_t p = s.find(k);
    if (p == std::string::npos) return false;
    p = s.find(':', p);
    if (p == std::string::npos) return false;
    ++p;
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) ++p;
    bool neg = false;
    if (p < s.size() && s[p] == '-') { neg = true; ++p; }
    long v = 0;
    bool any = false;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
        any = true;
        v = v * 10 + (s[p] - '0');
        ++p;
    }
    if (!any) return false;
    if (neg) v = -v;
    out = static_cast<int>(v);
    return true;
}

static bool recvExact(int sock, uint8_t* dst, size_t len, bool& out_timed_out) {
    out_timed_out = false;
    if (!dst || len == 0) {
        return false;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = ::recv(sock, dst + off, len - off, 0);
        if (r > 0) {
            off += static_cast<size_t>(r);
            continue;
        }
        if (r == 0) {
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            out_timed_out = true;
        }
        return false;
    }
    return true;
}

static void configureTcpSocket(int sock) {
    if (sock < 0) {
        return;
    }
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
#ifdef SO_LINGER
    struct linger ling;
    memset(&ling, 0, sizeof(ling));
    ling.l_onoff = 1;
    ling.l_linger = 0;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
#endif
}

static bool recvOpcuaFrame(int sock,
                           std::vector<uint8_t>& out_frame,
                           bool& out_timed_out,
                           std::string& out_error) {
    out_frame.clear();
    out_timed_out = false;
    out_error.clear();

    uint8_t header_bytes[8];
    if (!recvExact(sock, header_bytes, sizeof(header_bytes), out_timed_out)) {
        out_error = out_timed_out ? "recv_timeout_header" : "recv_failed_header";
        return false;
    }

    UATcpHeader h{};
    if (!parseHeader(header_bytes, sizeof(header_bytes), h)) {
        out_error = "invalid_ua_tcp_header";
        return false;
    }

    if (h.len < sizeof(header_bytes) || h.len > 65536U) {
        out_error = "invalid_ua_tcp_length";
        return false;
    }

    out_frame.resize(h.len);
    memcpy(out_frame.data(), header_bytes, sizeof(header_bytes));

    const size_t body_len = h.len - sizeof(header_bytes);
    if (body_len == 0) {
        return true;
    }

    bool body_timed_out = false;
    if (!recvExact(sock, out_frame.data() + sizeof(header_bytes), body_len, body_timed_out)) {
        out_timed_out = body_timed_out;
        out_error = body_timed_out ? "recv_timeout_body" : "recv_failed_body";
        return false;
    }
    return true;
}

static void jsonAppendEscaped(psram_string& out, const char* s) {
    if (!s) {
        return;
    }
    while (*s) {
        const char c = *s++;
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else if ((unsigned char)c < 0x20U) {
            // Drop control chars from JSON payloads.
        } else {
            out.push_back(c);
        }
    }
}

static bool parseOpcuaScanTarget(const psram_string& input,
                                 psram_string& out_host,
                                 uint16_t& out_port,
                                 psram_string& out_target_label) {
    out_host.clear();
    out_target_label.clear();
    out_port = OPCUAPlugin::OPCUA_PORT;

    if (input.empty()) {
        return false;
    }

    char raw[192];
    size_t n = input.size();
    if (n >= sizeof(raw)) {
        n = sizeof(raw) - 1;
    }
    memcpy(raw, input.c_str(), n);
    raw[n] = '\0';

    // Trim spaces
    char* start = raw;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
        start++;
    }
    char* end = start + strlen(start);
    while (end > start &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        end--;
    }
    *end = '\0';

    if (*start == '\0') {
        return false;
    }

    const char* p = start;
    static const char kPrefix[] = "opc.tcp://";
    if (strncmp(p, kPrefix, sizeof(kPrefix) - 1U) == 0) {
        p += (sizeof(kPrefix) - 1U);
    }

    char host_port[128];
    size_t hp = 0;
    while (*p && *p != '/' && *p != '?' && hp < sizeof(host_port) - 1U) {
        host_port[hp++] = *p++;
    }
    host_port[hp] = '\0';
    if (hp == 0) {
        return false;
    }

    if (strchr(host_port, '[') || strchr(host_port, ']')) {
        // Keep parser intentionally simple (IPv4/hostname) for embedded target usage.
        return false;
    }

    char* colon = strrchr(host_port, ':');
    if (colon && colon[1] != '\0') {
        char* port_end = nullptr;
        long pnum = strtol(colon + 1, &port_end, 10);
        if (!port_end || *port_end != '\0' || pnum < 1 || pnum > 65535) {
            return false;
        }
        *colon = '\0';
        out_port = static_cast<uint16_t>(pnum);
    } else if (colon && colon[1] == '\0') {
        return false;
    }

    if (host_port[0] == '\0') {
        return false;
    }

    out_host = PSRAMUtils::createPSRAMString(host_port);

    char norm[160];
    snprintf(norm, sizeof(norm), "%s:%u", host_port, (unsigned)out_port);
    out_target_label = PSRAMUtils::createPSRAMString(norm);
    return true;
}

struct OpcuaScanFindingMetadata {
    const char* scan_id;
    const char* category;
    const char* risk_domain;
    const char* cwe_list;       // "|" separated
    const char* cve_list;       // "|" separated
    const char* references;     // "|" separated URLs/refs
    bool active_test;
};

static const OpcuaScanFindingMetadata* getOpcuaScanFindingMetadata(const char* scan_id) {
    if (!scan_id || !*scan_id) {
        return nullptr;
    }
    static const OpcuaScanFindingMetadata kMap[] = {
        {"anonymous_access",      "authentication", "access_control", "CWE-306|CWE-862", "", "OPC UA Part 2 Security Model|OPC UA Part 4 Sessions", false},
        {"weak_security_policies","crypto",         "transport_security", "CWE-326|CWE-327", "", "OPC UA SecurityPolicy documentation", false},
        {"certificate_validation","crypto",         "pkix", "CWE-295", "", "RFC 5280|OPC UA Part 6 Certificates", false},
        {"default_credentials",   "authentication", "identity", "CWE-521|CWE-798", "", "IEC 62443-3-3 SR 1.2", false},
        {"idor_vulnerability",    "authorization",  "object_access", "CWE-639|CWE-862", "", "OPC UA Part 3 Address Space Model", false},
        {"brute_force_resilience","authentication", "rate_limit", "CWE-307", "", "IEC 62443-3-3 SR 1.11", true},
        {"condition_refresh_dos", "availability",   "resource_exhaustion", "CWE-400", "CVE-2022-29864", "OPC UA ConditionRefresh service hardening guidance", true},
        {"chunk_flooding_dos",    "availability",   "resource_exhaustion", "CWE-400", "CVE-2019-6575", "OPC UA TCP chunk processing hardening", true},
        {"browse_loop_dos",       "availability",   "algorithmic_complexity", "CWE-674|CWE-400", "", "OPC UA Browse service limits", true},
        {"certificate_chain_loop","crypto",         "pkix", "CWE-295", "", "RFC 5280 path validation loop checks", false}
    };

    for (size_t i = 0; i < (sizeof(kMap) / sizeof(kMap[0])); ++i) {
        if (strcmp(kMap[i].scan_id, scan_id) == 0) {
            return &kMap[i];
        }
    }
    return nullptr;
}

static void jsonAppendStringArrayField(psram_string& out,
                                       const char* field_name,
                                       const char* delimited_values) {
    if (!field_name || !delimited_values || delimited_values[0] == '\0') {
        return;
    }
    out += PSRAMUtils::createPSRAMString(",\"");
    out += PSRAMUtils::createPSRAMString(field_name);
    out += PSRAMUtils::createPSRAMString("\":[");

    bool first = true;
    const char* cur = delimited_values;
    while (*cur) {
        while (*cur == '|') {
            ++cur;
        }
        if (!*cur) {
            break;
        }
        const char* token_start = cur;
        while (*cur && *cur != '|') {
            ++cur;
        }
        size_t token_len = static_cast<size_t>(cur - token_start);
        if (token_len == 0U) {
            continue;
        }

        if (!first) {
            out += PSRAMUtils::createPSRAMString(",");
        }
        first = false;

        out += PSRAMUtils::createPSRAMString("\"");
        for (size_t i = 0; i < token_len; ++i) {
            char ch = token_start[i];
            if (ch == '\\' || ch == '"') {
                out.push_back('\\');
                out.push_back(ch);
            } else if (static_cast<unsigned char>(ch) >= 0x20U) {
                out.push_back(ch);
            }
        }
        out += PSRAMUtils::createPSRAMString("\"");
    }

    out += PSRAMUtils::createPSRAMString("]");
}

bool OPCUAPlugin::isPacketWriter(const NetworkPacket& pkt) const {
    if (pkt.dst_port != OPCUA_PORT) return false;  // Request to OPC UA server

    const uint8_t* frame = nullptr;
    size_t frame_len = 0;
    if (!locateOpcuaFrame(pkt, frame, frame_len)) return false;

    UATcpHeader h{};
    if (!parseHeader(frame, frame_len, h)) return false;
    if (!(h.msgType[0]=='M' && h.msgType[1]=='S' && h.msgType[2]=='G')) return false;

    uint16_t service_id = 0;
    if (parseOpcuaServiceTypeIdFromMsg(frame, frame_len, service_id)) {
        bool is_response = false;
        const OpcuaServiceDescriptor* d = findOpcuaServiceDescriptor(service_id, &is_response);
        if (d && !is_response && d->write_like) {
            return true;
        }
    }

    // Legacy fallback for textual/non-standard payload
    return memfind(frame, frame_len, "WriteRequest", strlen("WriteRequest")) ||
           memfind(frame, frame_len, "CallRequest", strlen("CallRequest")) ||
           memfind(frame, frame_len, "DeleteNodes", strlen("DeleteNodes")) ||
           memfind(frame, frame_len, "AddNodes", strlen("AddNodes"));
}

void OPCUAPlugin::loadIDSRules(const std::string& rules_json) {
    (void)rules_json;
    LOG_INFO("OPCUA_PLUGIN", "OPC UA IDS rules loaded");
}

bool OPCUAPlugin::activeDiscover(const std::string& ip, uint16_t port, uint32_t timeout_ms){
    // Minimal HEL → expect ACK. No GetEndpoints (requires full encoder).
    // Create TCP socket and connect
    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    // Bind to Ethernet interface (ETH_DEF)
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) { close(sock); return false; }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_aton(ip.c_str(), &addr.sin_addr) == 0 || connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return false;
    }
    if (sock < 0) return false;

    // Build HEL with empty endpoint
    uint8_t buf[64] = {0};
    // Header
    buf[0]='H'; buf[1]='E'; buf[2]='L'; buf[3]='F';
    // len (LE). Fill later. We'll write 8 + 4*5 + 4 + 0 = 32 bytes
    uint32_t len = 32;
    buf[4]= (uint8_t)(len & 0xFF);
    buf[5]= (uint8_t)((len>>8) & 0xFF);
    buf[6]= (uint8_t)((len>>16)& 0xFF);
    buf[7]= (uint8_t)((len>>24)& 0xFF);
    // protocolVersion
    buf[8]=0; buf[9]=0; buf[10]=0; buf[11]=0;
    // receiveBufferSize
    buf[12]=0x00; buf[13]=0x40; buf[14]=0x00; buf[15]=0x00; // 16384
    // sendBufferSize
    buf[16]=0x00; buf[17]=0x40; buf[18]=0x00; buf[19]=0x00;
    // maxMessageSize
    buf[20]=0x00; buf[21]=0x00; buf[22]=0x00; buf[23]=0x00;
    // maxChunkCount
    buf[24]=0x00; buf[25]=0x00; buf[26]=0x00; buf[27]=0x00;
    // endpointUrl length=0
    buf[28]=0x00; buf[29]=0x00; buf[30]=0x00; buf[31]=0x00;

    if (send(sock, buf, len, 0) != (int)len){
        close(sock);
        return false;
    }
    uint8_t rx[64];
    int r = recv(sock, rx, sizeof(rx), 0);
    close(sock);
    if (r >= 8){
        UATcpHeader hdr{};
        if (parseHeader(rx, r, hdr) && std::string(hdr.msgType, hdr.msgType+3)=="ACK"){
            // OPCUA server detected via active discovery
            if (rep_) {
                cJSON* root = cJSON_CreateObject();
                cJSON_AddStringToObject(root, "type", "opcua.server.detected");
                cJSON_AddStringToObject(root, "ip", ip.c_str());
                cJSON_AddNumberToObject(root, "port", port);
                char* json = cJSON_PrintUnformatted(root);
                if (json) {
                    psram_string type = PSRAMUtils::createPSRAMString("opcua_discovery");
                    psram_string payload = PSRAMUtils::createPSRAMString(json);
                    rep_->reportEvent(type, payload);
                    free(json);
                }
                cJSON_Delete(root);
            }
            return true;
        }
    }
    return false;
}

OPCUAPlugin::~OPCUAPlugin() {
    shutdown();
}

bool OPCUAPlugin::initialize(ConfigurationManager* config, ReportingEngine* reporting) {
    if (!BasePlugin::initialize(config, reporting)) {
        return false;
    }

    if (config) {
        SecurityConfig security_cfg = config->getSecurityConfig();
        enforce_secure_endpoints_ = security_cfg.opcua_enforce_security;
        require_certificate_validation_ = security_cfg.certificate_validation;
    }

    // Initialize OPC UA client if needed for active scanning
    client_initialized_ = initializeOPCUAClient();

    // Register OPC UA-specific event extractor with centralized SessionStateMachine
    getSessionStateMachine().registerProtocolCallbacks(
        SessionEventHelpers::extractOPCUAEvent,
        nullptr  // Use default transition validator
    );

    return true;
}

void OPCUAPlugin::shutdown() {
    if (client_initialized_) {
        shutdownOPCUAClient();
        client_initialized_ = false;
    }
    BasePlugin::shutdown();
}

std::string OPCUAPlugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool OPCUAPlugin::doVulnerabilityScanPSRAM(const psram_string& target,
                                           psram_string& out_report) {
    out_report.clear();

    // Accept either plain target "host[:port]" / "opc.tcp://host:port"
    // or scanner wrapper JSON:
    // {"target":"host[:port]","scan_types":[...],"timeout_ms":5000}
    psram_string target_label = target;
    uint32_t timeout_ms = 5000U;

    PSRAMAllocator<psram_string> st_alloc;
    psram_string_vector scan_types(st_alloc);

    if (!target.empty() && target[0] == '{') {
        PSRAMJsonParser::PSRAMContext ctx;
        cJSON* root = PSRAMJsonParser::parseInPSRAM(target.c_str(), target.size());
        if (root) {
            if (auto v = cJSON_GetObjectItem(root, "target"); v && cJSON_IsString(v) && v->valuestring) {
                target_label = PSRAMUtils::createPSRAMString(v->valuestring);
            }
            if (auto v = cJSON_GetObjectItem(root, "timeout_ms"); v && cJSON_IsNumber(v)) {
                double d = v->valuedouble;
                if (d < 200) d = 200;
                if (d > 30000) d = 30000;
                timeout_ms = static_cast<uint32_t>(d);
            }
            if (auto arr = cJSON_GetObjectItem(root, "scan_types"); arr && cJSON_IsArray(arr)) {
                cJSON* it = nullptr;
                cJSON_ArrayForEach(it, arr) {
                    if (it && cJSON_IsString(it) && it->valuestring) {
                        scan_types.push_back(PSRAMUtils::createPSRAMString(it->valuestring));
                    }
                }
            }
            cJSON_Delete(root);
        }
    }

    static const char* kDefaultScanTypes[] = {
        "anonymous_access",
        "weak_security_policies",
        "certificate_validation",
        "default_credentials",
        "idor_vulnerability",
        "certificate_chain_loop"
    };

    auto wants = [&](const char* id) -> bool {
        if (!id) return false;
        if (scan_types.empty()) {
            for (size_t i = 0; i < (sizeof(kDefaultScanTypes) / sizeof(kDefaultScanTypes[0])); ++i) {
                if (strcmp(kDefaultScanTypes[i], id) == 0) return true;
            }
            return false;
        }
        for (const auto& s : scan_types) {
            if (strcmp(s.c_str(), id) == 0) return true;
        }
        return false;
    };

    psram_string host_ps;
    psram_string normalized_target;
    uint16_t port = OPCUA_PORT;
    if (!parseOpcuaScanTarget(target_label, host_ps, port, normalized_target)) {
        out_report = PSRAMUtils::createPSRAMString(
            "{\"scan\":{\"protocol\":\"opcua\",\"status\":\"invalid_target\"},"
            "\"findings\":[],\"summary\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"info\":0}}");
        return false;
    }

    const uint64_t t0_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000ULL);

    OPCUAVulnerabilityTests::VulnerabilityScanner scanner;
    scanner.setTimeout(timeout_ms);
    // Aggressive mode is enabled only when the caller explicitly requested
    // the implemented active chunk-flooding check. It remains off for every
    // default/baseline scan.
    scanner.setAggressiveMode(wants("chunk_flooding_dos"));

    const bool need_endpoints =
        wants("anonymous_access") ||
        wants("weak_security_policies") ||
        wants("certificate_validation") ||
        wants("certificate_chain_loop");

    OPCUA::GetEndpointsResponse endpoints;
    bool endpoints_ok = false;
    if (need_endpoints) {
        endpoints_ok = scanner.discoverEndpointsForScan(host_ps.c_str(), port, endpoints);
    }

    PSRAMAllocator<psram_string> f_alloc;
    psram_string_vector findings(f_alloc);

    uint32_t sev_critical = 0, sev_high = 0, sev_medium = 0, sev_low = 0, sev_info = 0;
    uint32_t vulnerable_count = 0;
    uint32_t tests_executed = 0;
    uint32_t tests_skipped = 0;
    double highest_cvss = 0.0;
    psram_string highest_finding_id;

    auto bump = [&](const char* sev) {
        if (!sev) return;
        if (strcmp(sev, "CRITICAL") == 0) sev_critical++;
        else if (strcmp(sev, "HIGH") == 0) sev_high++;
        else if (strcmp(sev, "MEDIUM") == 0) sev_medium++;
        else if (strcmp(sev, "LOW") == 0) sev_low++;
        else sev_info++;
    };

    auto report_level_from = [&](const psram_string& sev) -> LogLevel {
        const char* s = sev.c_str();
        if (!s) return LogLevel::INFO;
        if (strcmp(s, "CRITICAL") == 0) return LogLevel::ERROR;
        if (strcmp(s, "HIGH") == 0) return LogLevel::ERROR;
        if (strcmp(s, "MEDIUM") == 0) return LogLevel::WARNING;
        if (strcmp(s, "LOW") == 0) return LogLevel::WARNING;
        return LogLevel::INFO;
    };

    auto append_finding = [&](const char* scan_id,
                              const OPCUAVulnerabilityTests::TestResult& tr,
                              bool skipped) {
        const OpcuaScanFindingMetadata* meta = getOpcuaScanFindingMetadata(scan_id);
        psram_string f;
        f.reserve(768);
        f += PSRAMUtils::createPSRAMString("{\"id\":\"opcua_");
        f += PSRAMUtils::createPSRAMString(scan_id ? scan_id : "unknown");
        f += PSRAMUtils::createPSRAMString("\",\"name\":\"");
        jsonAppendEscaped(f, tr.test_name.c_str());
        f += PSRAMUtils::createPSRAMString("\",\"severity\":\"");
        jsonAppendEscaped(f, tr.severity.c_str());
        f += PSRAMUtils::createPSRAMString("\",\"status\":\"");
        if (skipped) {
            f += PSRAMUtils::createPSRAMString("skipped");
        } else {
            f += PSRAMUtils::createPSRAMString(tr.inconclusive ? "inconclusive" : (tr.vulnerable ? "detected" : "not_detected"));
        }
        f += PSRAMUtils::createPSRAMString("\",\"description\":\"");
        jsonAppendEscaped(f, tr.description.c_str());
        f += PSRAMUtils::createPSRAMString("\",\"recommendation\":\"");
        jsonAppendEscaped(f, tr.remediation.c_str());
        f += PSRAMUtils::createPSRAMString("\",\"scan_type\":\"");
        jsonAppendEscaped(f, scan_id ? scan_id : "unknown");
        f += PSRAMUtils::createPSRAMString("\",\"category\":\"");
        jsonAppendEscaped(f, (meta && meta->category) ? meta->category : "general");
        f += PSRAMUtils::createPSRAMString("\",\"risk_domain\":\"");
        jsonAppendEscaped(f, (meta && meta->risk_domain) ? meta->risk_domain : "general");
        f += PSRAMUtils::createPSRAMString("\",\"active_test\":");
        f += PSRAMUtils::createPSRAMString((meta && meta->active_test) ? "true" : "false");
        f += PSRAMUtils::createPSRAMString(",\"vulnerable\":");
        f += PSRAMUtils::createPSRAMString((!skipped && tr.vulnerable) ? "true" : "false");
        f += PSRAMUtils::createPSRAMString(",\"assessment_complete\":");
        f += PSRAMUtils::createPSRAMString((!skipped && !tr.inconclusive && !tr.evidence_incomplete) ? "true" : "false");
        f += PSRAMUtils::createPSRAMString(",\"evidence_source\":\"");
        jsonAppendEscaped(f, tr.evidence_source.c_str());
        f += PSRAMUtils::createPSRAMString("\"");
        char cvss_buf[48];
        snprintf(cvss_buf, sizeof(cvss_buf), ",\"cvss_score\":%.1f", tr.cvss_score);
        f += PSRAMUtils::createPSRAMString(cvss_buf);

        jsonAppendStringArrayField(f, "cwe", meta ? meta->cwe_list : nullptr);
        jsonAppendStringArrayField(f, "cve", meta ? meta->cve_list : nullptr);
        jsonAppendStringArrayField(f, "references", meta ? meta->references : nullptr);

        if (!tr.evidence.empty()) {
            f += PSRAMUtils::createPSRAMString(",\"evidence\":[");
            for (size_t i = 0; i < tr.evidence.size(); ++i) {
                if (i) f += PSRAMUtils::createPSRAMString(",");
                f += PSRAMUtils::createPSRAMString("\"");
                jsonAppendEscaped(f, tr.evidence[i].c_str());
                f += PSRAMUtils::createPSRAMString("\"");
            }
            f += PSRAMUtils::createPSRAMString("]");
        }

        f += PSRAMUtils::createPSRAMString("}");
        findings.push_back(f);

        const char* execution_status = skipped
            ? "skipped"
            : (tr.inconclusive ? "inconclusive" : (tr.vulnerable ? "detected" : "not_detected"));
        LOG_INFOF("OPCUA_PLUGIN",
                  "OPC UA vulnerability check completed: id=%s status=%s vulnerable=%s",
                  scan_id ? scan_id : "unknown",
                  execution_status,
                  (!skipped && tr.vulnerable) ? "yes" : "no");

        if (skipped) {
            tests_skipped++;
        }

        if (!skipped && tr.vulnerable) {
            vulnerable_count++;
            bump(tr.severity.c_str());
            if (tr.cvss_score > highest_cvss) {
                highest_cvss = tr.cvss_score;
                highest_finding_id = PSRAMUtils::createPSRAMString("opcua_");
                highest_finding_id += PSRAMUtils::createPSRAMString(scan_id ? scan_id : "unknown");
            }
            reportVulnerabilityPSRAM(normalized_target, f, psram_string{}, report_level_from(tr.severity));
        }
    };

    auto make_skipped = [&](const char* name, const char* description) -> OPCUAVulnerabilityTests::TestResult {
        OPCUAVulnerabilityTests::TestResult tr;
        tr.test_name = PSRAMUtils::createPSRAMString(name ? name : "OPC UA Test");
        tr.vulnerable = false;
        tr.severity = PSRAMUtils::createPSRAMString("INFO");
        tr.description = PSRAMUtils::createPSRAMString(description ? description : "Test skipped");
        tr.remediation = PSRAMUtils::createPSRAMString("Verify endpoint availability and rerun the scan");
        tr.cvss_score = 0.0;
        return tr;
    };

    if (wants("anonymous_access")) {
        tests_executed++;
        if (endpoints_ok) append_finding("anonymous_access", scanner.assessAnonymousAccess(endpoints), false);
        else append_finding("anonymous_access", make_skipped("Anonymous Access Assessment",
            "Skipped: endpoint discovery failed; login was not attempted"), true);
    }
    if (wants("weak_security_policies")) {
        tests_executed++;
        if (endpoints_ok) append_finding("weak_security_policies", scanner.testWeakSecurityPolicies(endpoints), false);
        else append_finding("weak_security_policies", make_skipped("Weak Security Policies Test",
            "Skipped: endpoint discovery failed, cannot evaluate security policies"), true);
    }
    if (wants("certificate_validation")) {
        tests_executed++;
        if (endpoints_ok) append_finding("certificate_validation", scanner.testCertificateIssues(endpoints), false);
        else append_finding("certificate_validation", make_skipped("Certificate Validation Test",
            "Skipped: endpoint discovery failed, cannot evaluate certificate posture"), true);
    }
    if (wants("default_credentials")) {
        tests_executed++;
        append_finding("default_credentials", scanner.testDefaultCredentials(host_ps.c_str(), port), true);
    }
    if (wants("idor_vulnerability")) {
        tests_executed++;
        append_finding("idor_vulnerability", scanner.testIDORVulnerability(host_ps.c_str(), port), true);
    }
    if (wants("brute_force_resilience")) {
        tests_executed++;
        if (!sec_ || !sec_->isFuzzingAllowed()) {
            append_finding("brute_force_resilience", make_skipped("Brute Force Resilience Test",
                "Skipped: offensive-testing policy is not enabled"), true);
        } else {
            append_finding("brute_force_resilience", scanner.testBruteForceResilience(host_ps.c_str(), port), false);
        }
    }
    if (wants("condition_refresh_dos")) {
        tests_executed++;
        if (!sec_ || !sec_->isFuzzingAllowed()) {
            append_finding("condition_refresh_dos", make_skipped("ConditionRefresh DoS Test",
                "Skipped: offensive-testing policy is not enabled"), true);
        } else {
            append_finding("condition_refresh_dos", scanner.testConditionRefreshDoS(host_ps.c_str(), port), false);
        }
    }
    if (wants("chunk_flooding_dos")) {
        tests_executed++;
        if (!sec_ || !sec_->isFuzzingAllowed()) {
            append_finding("chunk_flooding_dos", make_skipped("Chunk Flooding DoS Test",
                "Skipped: offensive-testing policy is not enabled"), true);
        } else {
            append_finding("chunk_flooding_dos", scanner.testChunkFloodingDoS(host_ps.c_str(), port), false);
        }
    }
    if (wants("browse_loop_dos")) {
        tests_executed++;
        if (!sec_ || !sec_->isFuzzingAllowed()) {
            append_finding("browse_loop_dos", make_skipped("Browse Loop DoS Test",
                "Skipped: offensive-testing policy is not enabled"), true);
        } else {
            append_finding("browse_loop_dos", scanner.testBrowseLoopDoS(host_ps.c_str(), port), false);
        }
    }
    if (wants("certificate_chain_loop")) {
        tests_executed++;
        if (endpoints_ok) append_finding("certificate_chain_loop", scanner.testCertificateChainLoop(endpoints), false);
        else append_finding("certificate_chain_loop", make_skipped("Certificate Chain Loop Test",
            "Skipped: endpoint discovery failed, cannot inspect certificate chain"), true);
    }

    const uint64_t t1_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000ULL);

    psram_string rep;
    rep.reserve(2048 + findings.size() * 512);
    rep += PSRAMUtils::createPSRAMString("{\"scan\":{");
    rep += PSRAMUtils::createPSRAMString("\"protocol\":\"opcua\",");
    rep += PSRAMUtils::createPSRAMString("\"target\":\"");
    jsonAppendEscaped(rep, normalized_target.c_str());
    rep += PSRAMUtils::createPSRAMString("\",\"host\":\"");
    jsonAppendEscaped(rep, host_ps.c_str());
    char sbuf[256];
    snprintf(sbuf,
             sizeof(sbuf),
             "\",\"port\":%u,\"timestamp_ms\":%llu,\"duration_ms\":%llu,\"timeout_ms\":%u,\"endpoint_discovery_ok\":%s,\"tests_executed\":%u},",
             (unsigned)port,
             (unsigned long long)t0_ms,
             (unsigned long long)(t1_ms - t0_ms),
             (unsigned)timeout_ms,
             endpoints_ok ? "true" : "false",
             (unsigned)tests_executed);
    rep += PSRAMUtils::createPSRAMString(sbuf);

    rep += PSRAMUtils::createPSRAMString("\"asset\":{");
    rep += PSRAMUtils::createPSRAMString("\"vendor\":\"Unknown\",");
    rep += PSRAMUtils::createPSRAMString("\"product\":\"OPC UA Server\",");
    rep += PSRAMUtils::createPSRAMString("\"application_uri\":\"");
    if (endpoints_ok) {
        jsonAppendEscaped(rep, endpoints.application_uri.c_str());
    }
    rep += PSRAMUtils::createPSRAMString("\"},");

    rep += PSRAMUtils::createPSRAMString("\"scan_types_requested\":[");
    if (scan_types.empty()) {
        for (size_t i = 0; i < (sizeof(kDefaultScanTypes) / sizeof(kDefaultScanTypes[0])); ++i) {
            if (i) rep += PSRAMUtils::createPSRAMString(",");
            rep += PSRAMUtils::createPSRAMString("\"");
            rep += PSRAMUtils::createPSRAMString(kDefaultScanTypes[i]);
            rep += PSRAMUtils::createPSRAMString("\"");
        }
    } else {
        for (size_t i = 0; i < scan_types.size(); ++i) {
            if (i) rep += PSRAMUtils::createPSRAMString(",");
            rep += PSRAMUtils::createPSRAMString("\"");
            jsonAppendEscaped(rep, scan_types[i].c_str());
            rep += PSRAMUtils::createPSRAMString("\"");
        }
    }
    rep += PSRAMUtils::createPSRAMString("],");

    rep += PSRAMUtils::createPSRAMString("\"findings\":[");
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i) rep += PSRAMUtils::createPSRAMString(",");
        rep += findings[i];
    }
    rep += PSRAMUtils::createPSRAMString("],");

    const char* overall_risk = "none";
    if (sev_critical > 0U) overall_risk = "critical";
    else if (sev_high > 0U) overall_risk = "high";
    else if (sev_medium > 0U) overall_risk = "medium";
    else if (sev_low > 0U) overall_risk = "low";
    else overall_risk = "info";

    rep += PSRAMUtils::createPSRAMString("\"risk_assessment\":{");
    rep += PSRAMUtils::createPSRAMString("\"overall_risk\":\"");
    rep += PSRAMUtils::createPSRAMString(overall_risk);
    rep += PSRAMUtils::createPSRAMString("\",\"highest_cvss\":");
    char risk_buf[96];
    snprintf(risk_buf, sizeof(risk_buf), "%.1f", highest_cvss);
    rep += PSRAMUtils::createPSRAMString(risk_buf);
    rep += PSRAMUtils::createPSRAMString(",\"highest_risk_finding\":\"");
    if (!highest_finding_id.empty()) {
        jsonAppendEscaped(rep, highest_finding_id.c_str());
    } else {
        rep += PSRAMUtils::createPSRAMString("none");
    }
    rep += PSRAMUtils::createPSRAMString("\"},");

    snprintf(sbuf,
             sizeof(sbuf),
             "\"summary\":{\"critical\":%u,\"high\":%u,\"medium\":%u,\"low\":%u,\"info\":%u,\"vulnerabilities_detected\":%u,\"tests_executed\":%u,\"tests_skipped\":%u}}",
             (unsigned)sev_critical,
             (unsigned)sev_high,
             (unsigned)sev_medium,
             (unsigned)sev_low,
             (unsigned)sev_info,
             (unsigned)vulnerable_count,
             (unsigned)tests_executed,
             (unsigned)tests_skipped);
    rep += PSRAMUtils::createPSRAMString(sbuf);

    vulnerabilities_found_ += vulnerable_count;
    out_report = rep;

    if (tests_executed == 0) {
        return false;
    }
    if (need_endpoints && !endpoints_ok && scan_types.empty()) {
        // Default profile depends on endpoint metadata; mark run as failed if unavailable.
        return false;
    }
    return true;
}

std::string OPCUAPlugin::legacyDoVulnerabilityScan(const std::string& target) {
    // Use centralized target parsing from BasePlugin
    std::string ip;
    uint16_t port;
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());

    if (!parseTarget(target, ip, port)) {
        return ""; // Invalid target format
    }

    // Perform active discovery
    bool server_found = activeDiscover(ip, port, 5000);

    if (server_found) {
        // Report vulnerability findings
        std::string vuln_json = "{\"type\":\"opcua.scan.completed\",\"target\":\"" + target + "\",\"server_found\":true}";
        reportVulnerabilityPSRAM(
            target_ps,
            PSRAMUtils::createPSRAMString(vuln_json.c_str()),
            PSRAMUtils::createPSRAMString("OPC UA server discovery completed"),
            LogLevel::INFO);

        // Test for common vulnerabilities
        inspectAnonymousAdvertisement("opc.tcp://" + ip + ":" + std::to_string(port));

        vulnerabilities_found_++;

        psram_string rep;
        rep += PSRAMUtils::createPSRAMString("# OPC UA Vulnerability Scan Report\n");
        rep += PSRAMUtils::createPSRAMString("**Target**: "); rep += PSRAMUtils::createPSRAMString(target.c_str()); rep += PSRAMUtils::createPSRAMString("\n");
        rep += PSRAMUtils::createPSRAMString("**Status**: ✅ SUCCESS\n\n");
        rep += PSRAMUtils::createPSRAMString("**Details**: "); rep += PSRAMUtils::createPSRAMString(vuln_json.c_str()); rep += PSRAMUtils::createPSRAMString("\n");
        return PSRAMUtils::fromPSRAMString(rep);
    }

    // Return empty string if no server found (scan failed)
    return "";
}

std::string OPCUAPlugin::doNetworkDiscovery(const std::string& target_network,
                                            uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool OPCUAPlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                          uint32_t timeout_ms,
                                          psram_string& out_report) {
    auto discovery_scope = beginDiscovery();
    if (!discovery_scope) {
        out_report = PSRAMUtils::createPSRAMString("{\"error\":\"discovery_scope_unavailable\"}");
        return false;
    }
    std::string legacy_target = PSRAMUtils::fromPSRAMString(target_network);
    std::string legacy_report = legacyDoNetworkDiscovery(legacy_target, timeout_ms);
    if (legacy_report.empty()) {
        out_report.clear();
        return false;
    }
    out_report = PSRAMUtils::createPSRAMString(legacy_report.c_str());
    return true;
}

std::string OPCUAPlugin::legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms) {
    cJSON* root = cJSON_CreateObject();
    cJSON* devices = cJSON_CreateArray();
    if (!root || !devices) {
        if (root) cJSON_Delete(root);
        if (devices) cJSON_Delete(devices);
        return "{}";
    }

    cJSON_AddStringToObject(root, "protocol", "opcua");
    cJSON_AddStringToObject(root, "target_network", target_network.c_str());
    cJSON_AddItemToObject(root, "devices", devices);

    // Parse network range (currently optimized for single host or /24)
    psram_vector<psram_string> ips_to_scan;
    if (target_network.find('/') != std::string::npos) {
        const size_t slash_pos = target_network.find('/');
        char base_ip[32];
        size_t base_len = std::min(slash_pos, sizeof(base_ip) - 1);
        memcpy(base_ip, target_network.c_str(), base_len);
        base_ip[base_len] = '\0';

        char* last_dot = strrchr(base_ip, '.');
        if (last_dot) {
            *last_dot = '\0';
            char ip_buf[64];
            for (int i = 1; i < 255; ++i) {
                snprintf(ip_buf, sizeof(ip_buf), "%s.%d", base_ip, i);
                ips_to_scan.push_back(PSRAMUtils::createPSRAMString(ip_buf));
            }
        }
    } else {
        ips_to_scan.push_back(PSRAMUtils::createPSRAMString(target_network.c_str()));
    }

    const uint64_t start_ms = esp_timer_get_time() / 1000ULL;
    int devices_found = 0;
    uint32_t scanned = 0;
    uint32_t endpoint_discovery_ok = 0;
    uint32_t endpoint_discovery_fail = 0;

    DiscoveryManager::getInstance().initTotalsTLS((uint32_t)ips_to_scan.size());

    uint32_t per_target_timeout = 250;
    if (!ips_to_scan.empty()) {
        per_target_timeout = timeout_ms / static_cast<uint32_t>(ips_to_scan.size());
        if (per_target_timeout < 120) per_target_timeout = 120;
        if (per_target_timeout > 3000) per_target_timeout = 3000;
    }

    for (const auto& ip : ips_to_scan) {
        scanned++;
        DiscoveryManager::getInstance().updateProgressTLS(ip.c_str(), scanned, 0, 0, devices_found);
        if (devices_found >= 30) break; // Guardrail output size

        std::string ip_str = PSRAMUtils::fromPSRAMString(ip);
        if (!activeDiscover(ip_str, OPCUA_PORT, per_target_timeout)) {
            if (ips_to_scan.size() > 10) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            continue;
        }

        cJSON* item = cJSON_CreateObject();
        if (!item) {
            continue;
        }

        cJSON_AddStringToObject(item, "ip", ip.c_str());
        cJSON_AddNumberToObject(item, "port", OPCUA_PORT);
        cJSON_AddStringToObject(item, "protocol", "opcua");
        cJSON_AddStringToObject(item, "device_name", "OPC UA Server");
        cJSON_AddStringToObject(item, "vendor", "Unknown");
        cJSON_AddStringToObject(item, "status", "online");
        cJSON_AddStringToObject(item, "discovery_level", "hello_ack");

        char endpoint_url[128];
        snprintf(endpoint_url, sizeof(endpoint_url), "opc.tcp://%s:%u", ip.c_str(), (unsigned)OPCUA_PORT);

        OPCUAServer server_info;
        if (discoverEndpoints(endpoint_url, server_info)) {
            endpoint_discovery_ok++;
            cJSON_ReplaceItemInObject(item, "discovery_level", cJSON_CreateString("get_endpoints"));
            cJSON_AddStringToObject(item, "endpoint_url", server_info.endpoint_url.c_str());

            if (!server_info.server_name.empty()) {
                cJSON_AddStringToObject(item, "server_name", server_info.server_name.c_str());
            }

            cJSON_AddBoolToObject(item, "anonymous_login_allowed", server_info.anonymous_login_allowed);
            cJSON_AddBoolToObject(item, "encryption_available", server_info.encryption_available);

            cJSON* sec_policies = cJSON_CreateArray();
            if (sec_policies) {
                for (const auto& p : server_info.security_policies) {
                    cJSON_AddItemToArray(sec_policies, cJSON_CreateString(p.c_str()));
                }
                cJSON_AddItemToObject(item, "security_policies", sec_policies);
            }

            cJSON* sec_modes = cJSON_CreateArray();
            if (sec_modes) {
                for (const auto& m : server_info.security_modes) {
                    cJSON_AddItemToArray(sec_modes, cJSON_CreateString(m.c_str()));
                }
                cJSON_AddItemToObject(item, "security_modes", sec_modes);
            }

            cJSON_AddStringToObject(item, "evidence_source", "get_endpoints");
            cJSON_AddBoolToObject(item, "anonymous_advertised", server_info.anonymous_login_allowed);
            cJSON_AddBoolToObject(item, "authentication_tested", false);
            cJSON_AddStringToObject(item, "anonymous_login_allowed_semantics", "advertised_not_tested");
            cJSON_AddStringToObject(item, "certificate_summary_scope", "first_advertised_certificate");
            cJSON_AddItemToObject(item, "certificate",
                certificateMetadata(server_info.certificate_info, server_info.certificate_present));
            if (!server_info.endpoints_json.empty()) {
                cJSON* details = cJSON_Parse(server_info.endpoints_json.c_str());
                if (details) cJSON_AddItemToObject(item, "endpoints", details);
            }

            cJSON* vulns = cJSON_CreateArray();
            if (vulns) {
                for (const auto& v : server_info.vulnerabilities) {
                    cJSON_AddItemToArray(vulns, cJSON_CreateString(v.c_str()));
                }
                cJSON_AddItemToObject(item, "vulnerabilities", vulns);
            }
        } else {
            endpoint_discovery_fail++;
            cJSON_AddStringToObject(item, "endpoint_discovery", "failed");
        }

        cJSON_AddItemToArray(devices, item);
        devices_found++;

        if (ips_to_scan.size() > 10) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    const uint64_t elapsed_ms = (esp_timer_get_time() / 1000ULL) - start_ms;
    cJSON_AddNumberToObject(root, "total_found", devices_found);
    cJSON_AddNumberToObject(root, "targets_scanned", scanned);
    cJSON_AddNumberToObject(root, "endpoint_discovery_ok", endpoint_discovery_ok);
    cJSON_AddNumberToObject(root, "endpoint_discovery_fail", endpoint_discovery_fail);
    cJSON_AddNumberToObject(root, "scan_time_ms", static_cast<double>(elapsed_ms));

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        return "{}";
    }

    std::string out(json);
    free(json);
    return out;
}

bool OPCUAPlugin::doPacketIDSAnalysisOfProtocol(const NetworkPacket& packet) {
    packets_analyzed_++;

    const uint8_t* frame = nullptr;
    size_t frame_len = 0;
    if (!locateOpcuaFrame(packet, frame, frame_len)) {
        return false;
    }

    UATcpHeader header{};
    if (!parseHeader(frame, frame_len, header)) {
        return false;
    }

    trackPacketInFlow(packet);
    analyzeOPCUATraffic(packet);

    char message_type[4];
    memcpy(message_type, header.msgType, 3);
    message_type[3] = '\0';

    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);

    uint32_t src_ipv4 = 0;
    if (!packet.src_ip.empty()) {
        struct in_addr addr{};
        if (inet_aton(packet.src_ip.c_str(), &addr) != 0) {
            src_ipv4 = ntohl(addr.s_addr);
        }
    }

    bool alert_generated = false;
    auto emitEvent = [&](const char* json, LogLevel level, bool mark_alert) {
        if (shouldSuppressEvent(json, level, now_ms)) {
            return;
        }
        reportIntrusionPSRAM(packet, PSRAMUtils::createPSRAMString(json), level);
        if (mark_alert) {
            alert_generated = true;
        }
    };

    if (header.len > frame_len || header.len < 8U) {
        char msg[160];
        snprintf(msg,
                 sizeof(msg),
                 "{\"alert_type\":\"opcua.malformed\",\"type\":\"opcua.malformed\",\"declared_len\":%u,\"actual_len\":%u}",
                 (unsigned)header.len,
                 (unsigned)frame_len);
        emitEvent(msg, LogLevel::ERROR, true);
        return true;
    }

    const uint8_t* payload = (frame_len > sizeof(UATcpHeader))
                               ? (frame + sizeof(UATcpHeader))
                               : nullptr;
    size_t payload_len = (payload) ? (frame_len - sizeof(UATcpHeader)) : 0U;

    if (memcmp(message_type, "HEL", 3) == 0) {
        emitEvent("{\"alert_type\":\"opcua.hello\",\"type\":\"opcua.hello\"}", LogLevel::INFO, false);
        if (isBruteForceAttempt(src_ipv4)) {
            char msg[160];
            snprintf(msg,
                     sizeof(msg),
                     "{\"alert_type\":\"opcua.hello.flood\",\"type\":\"opcua.hello.flood\",\"src\":\"%s\"}",
                     packet.src_ip.c_str());
            emitEvent(msg, LogLevel::WARNING, true);
        }
    } else if (memcmp(message_type, "ACK", 3) == 0) {
        emitEvent("{\"alert_type\":\"opcua.ack\",\"type\":\"opcua.ack\"}", LogLevel::INFO, false);
    } else if (memcmp(message_type, "OPN", 3) == 0) {
        emitEvent("{\"alert_type\":\"opcua.open_secure_channel\",\"type\":\"opcua.open_secure_channel\"}",
                  LogLevel::INFO,
                  false);
        if (isBruteForceAttempt(src_ipv4)) {
            char msg[160];
            snprintf(msg,
                     sizeof(msg),
                     "{\"alert_type\":\"opcua.open.flood\",\"type\":\"opcua.open.flood\",\"src\":\"%s\"}",
                     packet.src_ip.c_str());
            emitEvent(msg, LogLevel::WARNING, true);
        }
    } else if (memcmp(message_type, "CLO", 3) == 0) {
        emitEvent("{\"alert_type\":\"opcua.close_secure_channel\",\"type\":\"opcua.close_secure_channel\"}",
                  LogLevel::INFO,
                  false);
    } else if (memcmp(message_type, "MSG", 3) == 0 && payload && payload_len > 0) {
        // Check for insecure and secure policies
        static const char* sp_none = "http://opcfoundation.org/UA/SecurityPolicy#None";
        static const char* sp_b256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
        static const char* sp_b256s = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
        static const char* sp_aes = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

        if (memfind(payload, payload_len, sp_none, strlen(sp_none))) {
            emitEvent("{\"alert_type\":\"opcua.endpoint.insecure\",\"type\":\"opcua.endpoint.insecure\",\"policy\":\"None\"}",
                      LogLevel::WARNING,
                      true);
        }
        if (memfind(payload, payload_len, sp_b256, strlen(sp_b256)) ||
            memfind(payload, payload_len, sp_b256s, strlen(sp_b256s)) ||
            memfind(payload, payload_len, sp_aes, strlen(sp_aes))) {
            emitEvent("{\"alert_type\":\"opcua.endpoint.secure\",\"type\":\"opcua.endpoint.secure\"}",
                      LogLevel::INFO,
                      false);
        }

        uint16_t service_id = 0;
        bool parsed_service = parseOpcuaServiceTypeIdFromMsg(frame, frame_len, service_id);
        bool service_is_response = false;
        const OpcuaServiceDescriptor* service_desc =
            parsed_service ? findOpcuaServiceDescriptor(service_id, &service_is_response) : nullptr;

        // Suspicious state-changing service requests (client -> server only)
        if (service_desc && !service_is_response && packet.dst_port == OPCUA_PORT && service_desc->write_like) {
            const char* event_type = "opcua.write_like_request";
            LogLevel level = LogLevel::WARNING;

            if (service_desc->request_id == 673) {
                event_type = "opcua.write_request";
            } else if (service_desc->request_id == 712) {
                event_type = "opcua.call_request";
            } else if (service_desc->request_id == 488) {
                event_type = "opcua.add_nodes";
            } else if (service_desc->request_id == 500) {
                event_type = "opcua.delete_nodes";
                level = LogLevel::ERROR;
            } else if (service_desc->request_id == 494) {
                event_type = "opcua.add_references";
            } else if (service_desc->request_id == 506) {
                event_type = "opcua.delete_references";
                level = LogLevel::ERROR;
            } else if (service_desc->request_id == 700) {
                event_type = "opcua.history_update";
            }

            char msg[256];
            snprintf(msg,
                     sizeof(msg),
                     "{\"alert_type\":\"%s\",\"type\":\"%s\",\"src\":\"%s\",\"service_id\":%u,\"service\":\"%s\"}",
                     event_type,
                     event_type,
                     packet.src_ip.c_str(),
                     (unsigned)service_id,
                     service_desc->name);
            emitEvent(msg, level, true);
        }

        // Authentication brute force detection (Create/Activate session)
        static psram_map<uint32_t, SlidingWindowCounter> auth_attempts;
        if (src_ipv4 != 0 && service_desc && !service_is_response &&
            packet.dst_port == OPCUA_PORT && service_desc->auth_related) {
            auto& counter = auth_attempts[src_ipv4];
            resetIfWindowExpired(counter, now_ms, 60000U);
            counter.count++;
            if (counter.count > 5U) {
                char msg[192];
                snprintf(msg,
                         sizeof(msg),
                         "{\"alert_type\":\"opcua.auth.bruteforce\",\"type\":\"opcua.auth.bruteforce\",\"src\":\"%s\",\"attempts\":%u,\"window_ms\":60000}",
                         packet.src_ip.c_str(),
                         (unsigned)counter.count);
                emitEvent(msg, LogLevel::ERROR, true);
                counter.count = 0;
                counter.window_start_ms = now_ms;
            }
        }

        // Legacy fallback payload-text detection for non-standard implementations
        if (!service_desc) {
            struct PatternDef {
                const char* pattern;
                const char* event_type;
                LogLevel level;
            };
            static const PatternDef kPatterns[] = {
                {"WriteRequest",  "opcua.write_request",  LogLevel::WARNING},
                {"CallRequest",   "opcua.call_request",   LogLevel::WARNING},
                {"DeleteNodes",   "opcua.delete_nodes",   LogLevel::ERROR},
                {"AddNodes",      "opcua.add_nodes",      LogLevel::WARNING}
            };
            for (const auto& pat : kPatterns) {
                if (memfind(payload, payload_len, pat.pattern, strlen(pat.pattern))) {
                    char msg[224];
                    snprintf(msg,
                             sizeof(msg),
                             "{\"alert_type\":\"%s\",\"type\":\"%s\",\"src\":\"%s\"}",
                             pat.event_type,
                             pat.event_type,
                             packet.src_ip.c_str());
                    emitEvent(msg, pat.level, true);
                }
            }
        }
    } else if (memcmp(message_type, "ERR", 3) == 0) {
        char msg[160];
        snprintf(msg,
                 sizeof(msg),
                 "{\"alert_type\":\"opcua.error\",\"type\":\"opcua.error\",\"src\":\"%s\"}",
                 packet.src_ip.c_str());
        emitEvent(msg, LogLevel::WARNING, false);

        static psram_map<uint32_t, SlidingWindowCounter> error_windows;
        if (src_ipv4 != 0) {
            auto& counter = error_windows[src_ipv4];
            resetIfWindowExpired(counter, now_ms, 30000U);
            counter.count++;
            if (counter.count > 10U) {
                char flood[192];
                snprintf(flood,
                         sizeof(flood),
                         "{\"alert_type\":\"opcua.error.flood\",\"type\":\"opcua.error.flood\",\"src\":\"%s\",\"errors\":%u,\"window_ms\":30000}",
                         packet.src_ip.c_str(),
                         (unsigned)counter.count);
                emitEvent(flood, LogLevel::ERROR, true);
                counter.count = 0;
                counter.window_start_ms = now_ms;
            }
        }
    }

    return alert_generated;
}

bool OPCUAPlugin::isTargetPacket(const NetworkPacket& packet) {
    // Check if it's TCP traffic on OPC UA port (request or response)
    if (!packet.is_tcp || (packet.dst_port != OPCUA_PORT && packet.src_port != OPCUA_PORT)) {
        return false;
    }

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrame(packet, data, data_len) || data_len < 3) return false;
    return (memcmp(data, "HEL", 3) == 0 ||
            memcmp(data, "ACK", 3) == 0 ||
            memcmp(data, "ERR", 3) == 0 ||
            memcmp(data, "MSG", 3) == 0 ||
            memcmp(data, "OPN", 3) == 0 ||
            memcmp(data, "CLO", 3) == 0);
}

// duplicate loadIDSRules removed (defined earlier)

bool OPCUAPlugin::initializeOPCUAClient() {
    if (ua_client_) {
        return true;
    }

    UA_Client* client = new(std::nothrow) UA_Client();
    if (!client) {
        LOG_WARNING("OPCUA_PLUGIN", "Failed to allocate OPC UA client context");
        return false;
    }

    ua_client_ = client;
    LOG_INFO("OPCUA_PLUGIN", "OPC UA client context initialized (lightweight stub)");
    return true;
}

void OPCUAPlugin::shutdownOPCUAClient() {
    if (ua_client_) {
        disconnectFromServer();
        delete ua_client_;
        ua_client_ = nullptr;
        LOG_INFO("OPCUA_PLUGIN", "OPC UA client context released");
    }
}

bool OPCUAPlugin::connectToServer(const std::string& endpoint_url) {
    LOG_INFOF("OPCUA_PLUGIN", "Connecting to OPC UA server: %s", endpoint_url.c_str());

    if (!client_initialized_) {
        if (!initializeOPCUAClient()) {
            return false;
        }
    }

    if (!ua_client_) {
        return false;
    }

    // Parse endpoint URL
    std::string remainder = endpoint_url;
    size_t proto_pos = remainder.find("opc.tcp://");
    if (proto_pos != std::string::npos) {
        remainder = remainder.substr(proto_pos + 10);
    }

    std::string path;
    size_t slash_pos = remainder.find('/');
    if (slash_pos != std::string::npos) {
        path = remainder.substr(slash_pos);
        remainder = remainder.substr(0, slash_pos);
    }

    std::string ip;
    uint16_t port = OPCUA_PORT;
    size_t colon_pos = remainder.find(':');
    if (colon_pos != std::string::npos) {
        ip = remainder.substr(0, colon_pos);
        port = static_cast<uint16_t>(atoi(remainder.substr(colon_pos + 1).c_str()));
    } else {
        ip = remainder;
    }

    if (ip.empty()) {
        LOG_ERROR("OPCUA_PLUGIN", "Invalid endpoint URL: missing host");
        return false;
    }

    std::string canonical_url = "opc.tcp://" + ip + ":" + std::to_string(port) + path;
    bool previously_flagged = false;
    if (enforce_secure_endpoints_) {
        previously_flagged = (suspicious_endpoints_.find(canonical_url) != suspicious_endpoints_.end());
        if (previously_flagged) {
            LOG_WARNINGF("OPCUA_PLUGIN",
                         "Endpoint %s previously marked as insecure; triggering re-evaluation",
                         canonical_url.c_str());
        }
    }

    // If already connected to the requested endpoint
    if (ua_client_->connected && ua_client_->endpoint_url == canonical_url) {
        return true;
    }

    OPCUAServer endpoint_info;
    bool have_snapshot = false;
    {
        std::lock_guard<std::mutex> lock(servers_mutex_);
        auto it = std::find_if(
            discovered_servers_.begin(),
            discovered_servers_.end(),
            [&](const OPCUAServer& entry) { return entry.endpoint_url == canonical_url; });
        if (it != discovered_servers_.end()) {
            endpoint_info = *it;
            have_snapshot = true;
        }
    }

    if (!have_snapshot) {
        if (discoverEndpoints(canonical_url, endpoint_info)) {
            have_snapshot = true;
        } else {
            LOG_WARNINGF("OPCUA_PLUGIN", "Unable to retrieve endpoint metadata for %s",
                         canonical_url.c_str());
        }
    }

    auto emitSecurityEvent = [&](const char* event_type,
                                 LogLevel level,
                                 const OPCUAServer& info) {
        if (!rep_) {
            return;
        }
        cJSON* root = cJSON_CreateObject();
        if (!root) {
            return;
        }
        cJSON_AddStringToObject(root, "type", event_type);
        cJSON_AddStringToObject(root, "endpoint", canonical_url.c_str());
        cJSON_AddBoolToObject(root, "enforced", enforce_secure_endpoints_);
        if (!info.server_name.empty()) {
            cJSON_AddStringToObject(root, "server_name", info.server_name.c_str());
        }
        cJSON_AddBoolToObject(root, "anonymous_allowed", info.anonymous_login_allowed);
        cJSON_AddBoolToObject(root, "encryption_available", info.encryption_available);
        cJSON_AddBoolToObject(root, "certificate_present", info.certificate_present);
        if (info.certificate_validation_checked) cJSON_AddBoolToObject(root, "certificate_valid", info.certificate_valid);
        else cJSON_AddNullToObject(root, "certificate_valid");
        cJSON_AddStringToObject(root, "certificate_validation_scope", "configured_connection_policy");
        cJSON_AddBoolToObject(root, "certificate_validation_checked", info.certificate_validation_checked);
        cJSON_AddItemToObject(root, "certificate", certificateMetadata(info.certificate_info, info.certificate_present));
        if (info.certificate_info.parse_ok && info.certificate_info.time_checked) {
            cJSON_AddBoolToObject(root, "certificate_expired", info.certificate_info.is_expired);
        } else cJSON_AddNullToObject(root, "certificate_expired");
        cJSON_AddNullToObject(root, "certificate_self_signed");
        if (info.certificate_info.parse_ok) cJSON_AddBoolToObject(root, "certificate_is_ca", info.certificate_is_ca);
        else cJSON_AddNullToObject(root, "certificate_is_ca");
        if (!info.certificate_subject.empty()) {
            cJSON_AddStringToObject(root, "certificate_subject", info.certificate_subject.c_str());
        }
        if (!info.certificate_issuer.empty()) {
            cJSON_AddStringToObject(root, "certificate_issuer", info.certificate_issuer.c_str());
        }
        if (info.certificate_not_before != 0) {
            cJSON_AddNumberToObject(root, "certificate_not_before",
                                    static_cast<double>(info.certificate_not_before));
        }
        if (info.certificate_not_after != 0) {
            cJSON_AddNumberToObject(root, "certificate_not_after",
                                    static_cast<double>(info.certificate_not_after));
        }

        if (!info.security_policies.empty()) {
            cJSON* policies = cJSON_CreateArray();
            if (policies) {
                for (const auto& policy : info.security_policies) {
                    cJSON_AddItemToArray(policies, cJSON_CreateString(policy.c_str()));
                }
                cJSON_AddItemToObject(root, "security_policies", policies);
            }
        }

        if (!info.security_modes.empty()) {
            cJSON* modes = cJSON_CreateArray();
            if (modes) {
                for (const auto& mode : info.security_modes) {
                    cJSON_AddItemToArray(modes, cJSON_CreateString(mode.c_str()));
                }
                cJSON_AddItemToObject(root, "security_modes", modes);
            }
        }

        if (!info.vulnerabilities.empty()) {
            cJSON* vulns = cJSON_CreateArray();
            if (vulns) {
                for (const auto& vuln : info.vulnerabilities) {
                    cJSON_AddItemToArray(vulns, cJSON_CreateString(vuln.c_str()));
                }
                cJSON_AddItemToObject(root, "vulnerabilities", vulns);
            }
        }

        if (!info.certificate_issues.empty()) {
            cJSON* cert_issues = cJSON_CreateArray();
            if (cert_issues) {
                for (const auto& issue : info.certificate_issues) {
                    cJSON_AddItemToArray(cert_issues, cJSON_CreateString(issue.c_str()));
                }
                cJSON_AddItemToObject(root, "certificate_issues", cert_issues);
            }
        }

        char* json = cJSON_PrintUnformatted(root);
        if (json) {
            reportVulnerabilityPSRAM(
                PSRAMUtils::createPSRAMString(canonical_url.c_str()),
                PSRAMUtils::createPSRAMString(json),
                PSRAMUtils::createPSRAMString(event_type),
                level);
            free(json);
        }
        cJSON_Delete(root);
    };

    if (have_snapshot) {
        X509DER::Parser::evaluateValidity(endpoint_info.certificate_info, X509DER::Parser::currentUnixTimeMs());
        bool secure_ok = checkSecurityConfiguration(endpoint_info);
        bool certificate_ok = validateServerCertificate(endpoint_info);
        endpoint_info.certificate_valid = certificate_ok;
        endpoint_info.certificate_validation_checked = true;

        {
            std::lock_guard<std::mutex> lock(servers_mutex_);
            auto it = std::find_if(
                discovered_servers_.begin(),
                discovered_servers_.end(),
                [&](const OPCUAServer& entry) { return entry.endpoint_url == canonical_url; });
            if (it != discovered_servers_.end()) {
                *it = endpoint_info;
            } else {
                discovered_servers_.push_back(endpoint_info);
            }
        }

        bool combined_ok = secure_ok && certificate_ok;

        if (!combined_ok) {
            suspicious_endpoints_.insert(canonical_url);
            emitSecurityEvent("opcua.endpoint.blocked",
                              enforce_secure_endpoints_ ? LogLevel::ERROR : LogLevel::WARNING,
                              endpoint_info);
            if (enforce_secure_endpoints_) {
                return false;
            }
        } else {
            suspicious_endpoints_.erase(canonical_url);
            if (!endpoint_info.vulnerabilities.empty()) {
                emitSecurityEvent("opcua.endpoint.audit", LogLevel::WARNING, endpoint_info);
            }
            emitSecurityEvent("opcua.endpoint.accepted", LogLevel::INFO, endpoint_info);
        }
    } else if (enforce_secure_endpoints_) {
        suspicious_endpoints_.insert(canonical_url);
        OPCUAServer empty_snapshot;
        emitSecurityEvent("opcua.endpoint.unknown_security", LogLevel::ERROR, empty_snapshot);
        return false;
    }

    // Reset previous connection if any, then establish TCP session
    disconnectFromServer();

    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("OPCUA_PLUGIN", "Failed to create socket for OPC UA connection");
        return false;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        LOG_ERRORF("OPCUA_PLUGIN", "Invalid IP address: %s", ip.c_str());
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERRORF("OPCUA_PLUGIN", "Failed to connect to %s:%u", ip.c_str(), port);
        close(sock);
        return false;
    }

    LOG_INFOF("OPCUA_PLUGIN", "Successfully connected to %s:%u", ip.c_str(), port);

    uint8_t hel_buf[64] = {0};
    hel_buf[0] = 'H'; hel_buf[1] = 'E'; hel_buf[2] = 'L'; hel_buf[3] = 'F';
    uint32_t hel_len = 32;
    hel_buf[4] = (uint8_t)(hel_len & 0xFF);
    hel_buf[5] = (uint8_t)((hel_len >> 8) & 0xFF);
    hel_buf[6] = (uint8_t)((hel_len >> 16) & 0xFF);
    hel_buf[7] = (uint8_t)((hel_len >> 24) & 0xFF);
    uint32_t buf_value = 0;
    memcpy(&hel_buf[8], &buf_value, sizeof(uint32_t));
    buf_value = 16384;
    memcpy(&hel_buf[12], &buf_value, sizeof(uint32_t));
    memcpy(&hel_buf[16], &buf_value, sizeof(uint32_t));
    buf_value = 0;
    memcpy(&hel_buf[20], &buf_value, sizeof(uint32_t));
    memcpy(&hel_buf[24], &buf_value, sizeof(uint32_t));
    memcpy(&hel_buf[28], &buf_value, sizeof(uint32_t));

    if (send(sock, hel_buf, hel_len, 0) != static_cast<int>(hel_len)) {
        LOG_WARNING("OPCUA_PLUGIN", "Failed to send HEL message during connection verification");
        close(sock);
        return false;
    }

    uint8_t ack_buf[64];
    int received = recv(sock, ack_buf, sizeof(ack_buf), 0);
    if (received < 8) {
        LOG_WARNING("OPCUA_PLUGIN", "No ACK received from OPC UA server");
        close(sock);
        return false;
    }

    UATcpHeader header{};
    if (!parseHeader(ack_buf, static_cast<size_t>(received), header) ||
        std::string(header.msgType, header.msgType + 3) != "ACK") {
        LOG_WARNING("OPCUA_PLUGIN", "Unexpected response to HEL message (expected ACK)");
        close(sock);
        return false;
    }

    ua_client_->socket_fd = sock;
    ua_client_->endpoint_url = canonical_url;
    ua_client_->connected = true;
    return true;
}

void OPCUAPlugin::disconnectFromServer() {
    if (!ua_client_) {
        return;
    }

    if (ua_client_->connected && ua_client_->socket_fd >= 0) {
        ::shutdown(ua_client_->socket_fd, SHUT_RDWR);
        close(ua_client_->socket_fd);
    }

    ua_client_->socket_fd = -1;
    ua_client_->endpoint_url.clear();
    ua_client_->connected = false;
}

bool OPCUAPlugin::discoverEndpoints(const std::string& server_url, OPCUAServer& server) {
    // Enhanced endpoint discovery using OPC UA Binary Protocol
    // This implements OpenSecureChannel + GetEndpoints sequence

    LOG_INFOF("OPCUA_PLUGIN", "Starting advanced endpoint discovery for %s", server_url.c_str());

    // Parse server URL to extract IP and port
    std::string ip;
    uint16_t port = OPCUA_PORT;

    // Simple parsing for opc.tcp://ip:port or just ip:port
    size_t proto_pos = server_url.find("opc.tcp://");
    std::string addr_part = (proto_pos != std::string::npos) ?
                            server_url.substr(proto_pos + 10) : server_url;

    size_t colon_pos = addr_part.find(':');
    if (colon_pos != std::string::npos) {
        ip = addr_part.substr(0, colon_pos);
        port = (uint16_t)atoi(addr_part.substr(colon_pos + 1).c_str());
    } else {
        ip = addr_part;
    }

    // Create TCP socket
    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("OPCUA_PLUGIN", "Failed to create socket");
        return false;
    }

    // Bind to Ethernet interface
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to get Ethernet interface");
        return false;
    }

    // Connect to server
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_aton(ip.c_str(), &server_addr.sin_addr) == 0) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Invalid IP address");
        return false;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Connection failed");
        return false;
    }

    // Set socket timeout (5 seconds)
    struct timeval timeout{};
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Step 1: Send HEL (Hello) message
    uint8_t hel_buf[128];
    memset(hel_buf, 0, sizeof(hel_buf));
    hel_buf[0] = 'H'; hel_buf[1] = 'E'; hel_buf[2] = 'L'; hel_buf[3] = 'F';
    uint32_t hel_len = 32;
    hel_buf[4] = (uint8_t)(hel_len & 0xFF);
    hel_buf[5] = (uint8_t)((hel_len >> 8) & 0xFF);
    hel_buf[6] = (uint8_t)((hel_len >> 16) & 0xFF);
    hel_buf[7] = (uint8_t)((hel_len >> 24) & 0xFF);
    // Protocol version = 0
    // Receive/Send buffer size = 16384
    hel_buf[12] = 0x00; hel_buf[13] = 0x40;
    hel_buf[16] = 0x00; hel_buf[17] = 0x40;

    if (send(sock, hel_buf, hel_len, 0) != (int)hel_len) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to send HEL");
        return false;
    }

    // Receive the complete ACK frame (TCP may fragment even this small message).
    psram_vector<uint8_t> ack_frame;
    if (!recvOpcUaFrame(sock, ack_frame) || ack_frame.size() < 8 ||
        ack_frame[0] != 'A' || ack_frame[1] != 'C' || ack_frame[2] != 'K') {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Invalid ACK response");
        return false;
    }

    LOG_INFO("OPCUA_PLUGIN", "HEL/ACK handshake completed");

    // Step 2: Send OpenSecureChannel request
    psram_vector<uint8_t> opn_msg;
    char endpoint_buf[256];
    snprintf(endpoint_buf, sizeof(endpoint_buf), "opc.tcp://%s:%u", ip.c_str(), port);

    if (!OPCUABinaryCodec::buildOpenSecureChannelRequest(opn_msg, endpoint_buf,
                                                         OPCUA::POLICY_NONE, 60000)) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to build OpenSecureChannel request");
        return false;
    }

    if (send(sock, opn_msg.data(), opn_msg.size(), 0) != (int)opn_msg.size()) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to send OpenSecureChannel");
        return false;
    }

    // Receive the complete OpenSecureChannel frame, including any fragmented tail.
    psram_vector<uint8_t> opn_resp_buf;
    if (!recvOpcUaFrame(sock, opn_resp_buf) || opn_resp_buf.size() < 20) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Invalid OpenSecureChannel response");
        return false;
    }

    uint32_t secure_channel_id = 0;
    uint32_t security_token_id = 0;
    psram_string opn_error;

    if (!OPCUABinaryCodec::parseOpenSecureChannelResponse(opn_resp_buf.data(),
                                                          opn_resp_buf.size(),
                                                          secure_channel_id,
                                                          security_token_id,
                                                          opn_error)) {
        close(sock);
        LOG_ERRORF("OPCUA_PLUGIN", "Failed to parse OpenSecureChannel response: %s",
                   PSRAMUtils::fromPSRAMString(opn_error).c_str());
        return false;
    }

    LOG_INFOF("OPCUA_PLUGIN", "OpenSecureChannel success: ChannelId=%u, TokenId=%u",
              secure_channel_id, security_token_id);

    // Step 3: Send GetEndpoints request
    psram_vector<uint8_t> getep_msg;
    uint32_t sequence_number = 2;
    uint32_t request_id = 2;

    if (!OPCUABinaryCodec::buildGetEndpointsRequest(getep_msg, secure_channel_id,
                                                    security_token_id, sequence_number,
                                                    request_id, endpoint_buf)) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to build GetEndpoints request");
        return false;
    }

    if (send(sock, getep_msg.data(), getep_msg.size(), 0) != (int)getep_msg.size()) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Failed to send GetEndpoints");
        return false;
    }

    // Receive the complete GetEndpoints frame (Siemens servers commonly return
    // several endpoints and therefore exceed a single TCP read).
    psram_vector<uint8_t> getep_resp_buf;
    if (!recvOpcUaFrame(sock, getep_resp_buf) || getep_resp_buf.size() < 20) {
        close(sock);
        LOG_ERROR("OPCUA_PLUGIN", "Invalid GetEndpoints response");
        return false;
    }

    psram_vector<OPCUAEndpoint> endpoints;
    psram_string getep_error;

    if (!OPCUABinaryCodec::parseGetEndpointsResponse(getep_resp_buf.data(),
                                                     getep_resp_buf.size(), endpoints,
                                                     getep_error)) {
        close(sock);
        LOG_ERRORF("OPCUA_PLUGIN", "Failed to parse GetEndpoints response: %s",
                   PSRAMUtils::fromPSRAMString(getep_error).c_str());
        return false;
    }

    // Step 4: Close secure channel (cleanly disconnect)
    psram_vector<uint8_t> close_msg;
    if (OPCUABinaryCodec::buildCloseSecureChannelRequest(close_msg, secure_channel_id,
                                                         security_token_id,
                                                         sequence_number + 1,
                                                         request_id + 1)) {
        send(sock, close_msg.data(), close_msg.size(), 0);
    }

    close(sock);

    LOG_INFOF("OPCUA_PLUGIN", "Successfully discovered %zu endpoints", endpoints.size());

    // Keep per-endpoint relationships: policy, mode, token types and certificate.
    // The legacy summary certificate refers to the first advertised certificate,
    // never to a synthetic validity interval merged from different certificates.
    server = OPCUAServer{};
    server.endpoint_url = server_url;
    auto push_unique = [](std::vector<std::string>& values, const std::string& value) {
        if (std::find(values.begin(), values.end(), value) == values.end()) values.push_back(value);
    };
    cJSON* endpoint_details = cJSON_CreateArray();
    for (const auto& ep : endpoints) {
        if (server.server_name.empty()) server.server_name = ep.server_application_name.c_str();
        push_unique(server.security_policies, ep.security_policy_uri.c_str());
        const char* mode = ep.security_mode == OPCUA::SECURITY_MODE_NONE ? "None" :
            ep.security_mode == OPCUA::SECURITY_MODE_SIGN ? "Sign" :
            ep.security_mode == OPCUA::SECURITY_MODE_SIGNANDENCRYPT ? "SignAndEncrypt" : "Invalid";
        push_unique(server.security_modes, mode);
        server.anonymous_login_allowed |= ep.allows_anonymous; // Advertised, not tested.
        server.encryption_available |= ep.security_mode == OPCUA::SECURITY_MODE_SIGNANDENCRYPT;
        for (const auto& issue : ep.vulnerabilities) push_unique(server.vulnerabilities, issue.c_str());

        X509CertificateInfo info = ep.server_certificate_info;
        X509DER::Parser::evaluateValidity(info, X509DER::Parser::currentUnixTimeMs());
        const bool present = !ep.server_certificate_der_hex.empty();
        if (present) {
            if (!info.parse_ok) push_unique(server.vulnerabilities, "INFO: Certificate metadata could not be parsed; assessment incomplete");
            else {
                if (!info.time_checked) push_unique(server.vulnerabilities, "INFO: Certificate validity period not checked; device UTC clock unavailable");
                if (info.is_expired) push_unique(server.vulnerabilities, "HIGH: Advertised certificate has expired");
                if (info.is_not_yet_valid) push_unique(server.vulnerabilities, "HIGH: Advertised certificate is not yet valid");
            }
            if (!server.certificate_present) {
                server.certificate_present = true;
                server.server_certificate = ep.server_certificate_der_hex.c_str();
                server.certificate_info = info;
                if (info.parse_ok) {
                    server.certificate_subject = info.subject_common_name.c_str();
                    server.certificate_issuer = info.issuer_common_name.c_str();
                    server.certificate_not_before = info.not_before_timestamp;
                    server.certificate_not_after = info.not_after_timestamp;
                    server.certificate_expired = info.is_expired;
                    server.certificate_is_ca = info.is_ca;
                    for (const auto& issue : info.vulnerabilities) push_unique(server.certificate_issues, issue.c_str());
                }
            }
        }
        if (endpoint_details) {
            cJSON* detail = cJSON_CreateObject();
            if (!detail) continue;
            cJSON_AddStringToObject(detail, "endpoint_url", ep.endpoint_url.c_str());
            cJSON_AddStringToObject(detail, "application_uri", ep.server_application_uri.c_str());
            cJSON_AddStringToObject(detail, "product_uri", ep.server_product_uri.c_str());
            cJSON_AddStringToObject(detail, "application_name", ep.server_application_name.c_str());
            cJSON_AddStringToObject(detail, "security_policy", ep.security_policy_uri.c_str());
            cJSON_AddStringToObject(detail, "security_mode", mode);
            cJSON_AddBoolToObject(detail, "anonymous_advertised", ep.allows_anonymous);
            cJSON_AddBoolToObject(detail, "authentication_tested", false);
            cJSON_AddBoolToObject(detail, "encryption_available", ep.security_mode == OPCUA::SECURITY_MODE_SIGNANDENCRYPT);
            cJSON_AddItemToObject(detail, "certificate", certificateMetadata(info, present));
            cJSON_AddItemToArray(endpoint_details, detail);
        }
    }
    if (!server.encryption_available) push_unique(server.vulnerabilities, "HIGH: No encrypted endpoints advertised");
    if (endpoint_details) {
        char* json = cJSON_PrintUnformatted(endpoint_details);
        if (json) { server.endpoints_json = PSRAMUtils::createPSRAMString(json); cJSON_free(json); }
        cJSON_Delete(endpoint_details);
    }
    // Discovery never validates trust/identity. Cache only the finalized metadata.
    {
        std::lock_guard<std::mutex> lock(servers_mutex_);
        auto it = std::find_if(discovered_servers_.begin(), discovered_servers_.end(),
            [&](const OPCUAServer& s) { return s.endpoint_url == server.endpoint_url; });
        if (it != discovered_servers_.end()) *it = server;
        else discovered_servers_.push_back(server);
    }
    LOG_INFOF("OPCUA_PLUGIN", "Endpoint discovery complete: %zu posture observations",
              server.vulnerabilities.size());
    return true;
}

bool OPCUAPlugin::inspectAnonymousAdvertisement(const std::string& server_url) {
    OPCUAServer server_info;
    if (!discoverEndpoints(server_url, server_info)) return false;
    LOG_INFOF("OPCUA_PLUGIN", "Anonymous user token advertised: %s; login/permissions not tested",
              server_info.anonymous_login_allowed ? "yes" : "no");
    return server_info.anonymous_login_allowed;
}

bool OPCUAPlugin::validateServerCertificate(const OPCUAServer& server) {
    if (!server.certificate_present || server.server_certificate.empty()) {
        LOG_WARNING("OPCUA_PLUGIN", "Server certificate is missing or empty");
        return false;
    }

    if (!server.certificate_subject.empty() || !server.certificate_issuer.empty()) {
        LOG_INFOF("OPCUA_PLUGIN",
                  "Validating certificate Subject='%s' Issuer='%s'",
                  server.certificate_subject.c_str(),
                  server.certificate_issuer.c_str());
    }

    X509CertificateInfo metadata;
    psram_string metadata_error;
    if (!X509DER::Parser::parseCertificate(PSRAMUtils::createPSRAMString(server.server_certificate.c_str()),
                                         metadata, metadata_error) || !metadata.time_checked) {
        LOG_WARNING("OPCUA_PLUGIN", "Certificate metadata invalid or UTC clock unavailable; validation refused");
        return false;
    }
    bool valid = true;
    bool has_high_or_critical = false;
    bool chain_validated = false;
    bool parse_success = false;

    std::vector<uint8_t> certificate_der;
    if (!hexToBytes(server.server_certificate, certificate_der)) {
        LOG_WARNING("OPCUA_PLUGIN", "Failed to decode server certificate (hex to DER conversion)");
        valid = false;
    } else {
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);
        psram_vector<size_t> lengths;
        int ret = -1;
        if (X509DER::Parser::certificateChainLengths(certificate_der.data(), certificate_der.size(), lengths)) {
            size_t offset = 0;
            for (size_t length : lengths) {
                ret = mbedtls_x509_crt_parse_der(&cert, certificate_der.data() + offset, length);
                if (ret != 0) break;
                offset += length;
            }
        }
        if (ret != 0) {
            char err_buf[128];
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            LOG_WARNINGF("OPCUA_PLUGIN",
                         "Unable to parse DER certificate: %s (ret=%d)",
                         err_buf,
                         ret);
            valid = false;
        } else {
            parse_success = true;
            if (require_certificate_validation_) {
                mbedtls_x509_crt ca_store;
                mbedtls_x509_crt_init(&ca_store);
                psram_string ca_bundle_ps;
                esp_err_t load_err = AsyncStorage::Global::readFile("/data/certs/ca_bundle.pem",
                                                                    ca_bundle_ps);
                if (load_err == ESP_OK && !ca_bundle_ps.empty()) {
                    int ca_ret = mbedtls_x509_crt_parse(
                        &ca_store,
                        reinterpret_cast<const unsigned char*>(ca_bundle_ps.c_str()),
                        ca_bundle_ps.size() + 1U);
                    if (ca_ret == 0) {
                        uint32_t verify_flags = 0U;
                        ca_ret = mbedtls_x509_crt_verify(&cert,
                                                         &ca_store,
                                                         nullptr,
                                                         nullptr,
                                                         &verify_flags,
                                                         nullptr,
                                                         nullptr);
                        if (ca_ret == 0 && verify_flags == 0U) {
                            chain_validated = true;
                            LOG_INFO("OPCUA_PLUGIN", "OPC UA certificate chain validated against CA bundle");
                        } else {
                            char verify_err[128];
                            mbedtls_strerror(ca_ret, verify_err, sizeof(verify_err));
                            LOG_WARNINGF("OPCUA_PLUGIN",
                                         "Certificate chain verification failed: %s (flags=0x%lx)",
                                         verify_err,
                                         static_cast<unsigned long>(verify_flags));
                            valid = false;
                        }
                    } else {
                        char ca_err[128];
                        mbedtls_strerror(ca_ret, ca_err, sizeof(ca_err));
                        LOG_WARNINGF("OPCUA_PLUGIN",
                                     "Failed to parse CA bundle for validation: %s (ret=%d)",
                                     ca_err,
                                     ca_ret);
                        valid = false;
                    }
                } else {
                    LOG_WARNINGF("OPCUA_PLUGIN",
                                 "CA bundle '/data/certs/ca_bundle.pem' unavailable (err=%s)",
                                 esp_err_to_name(load_err));
                    valid = false;
                }
                mbedtls_x509_crt_free(&ca_store);
            }
        }
        mbedtls_x509_crt_free(&cert);
    }

    if (metadata.is_not_yet_valid || metadata.is_expired) {
        LOG_WARNING("OPCUA_PLUGIN", "Certificate is outside its validity period");
        valid = false;
    }
    has_high_or_critical = metadata.has_weak_key || metadata.has_weak_signature;
    if (has_high_or_critical) {
        LOG_WARNING("OPCUA_PLUGIN", "Certificate advertises a weak key or signature algorithm");
        valid = false;
    }

    if (require_certificate_validation_) {
        if (!parse_success) {
            LOG_WARNING("OPCUA_PLUGIN", "Certificate parsing failed while validation is enforced");
        }
        if (!chain_validated) {
            LOG_WARNING("OPCUA_PLUGIN", "Certificate chain not validated successfully");
            valid = false;
        }
    }

    if (valid &&
        (!require_certificate_validation_ || chain_validated) &&
        !has_high_or_critical) {
        LOG_INFO("OPCUA_PLUGIN", "Certificate validation completed with no blocking findings");
    }

    return valid;
}

bool OPCUAPlugin::checkSecurityConfiguration(const OPCUAServer& server) {
    // Verify OPC UA server security configuration
    bool has_secure_policy = false;
    bool has_secure_mode = false;

    LOG_INFOF("OPCUA_PLUGIN", "Checking security configuration for server: %s",
              server.endpoint_url.c_str());

    // Verify Security Policies
    for (const auto& policy : server.security_policies) {
        LOG_INFOF("OPCUA_PLUGIN", "  Security Policy: %s", policy.c_str());

        // Consider only the policies with encryption as secure
        if (policy == OPCUA::POLICY_BASIC256SHA256 ||
            policy == "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep" ||
            policy == "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss") {
            has_secure_policy = true;
        }

        // Weak or insecure policies
        if (policy.find("#None") != std::string::npos) {
            LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Insecure SecurityPolicy#None detected!");
        }
        if (policy.find("#Basic128Rsa15") != std::string::npos) {
            LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Deprecated SecurityPolicy#Basic128Rsa15 detected!");
        }
    }

    // Verify Security Modes
    for (const auto& mode : server.security_modes) {
        LOG_INFOF("OPCUA_PLUGIN", "  Security Mode: %s", mode.c_str());

        if (mode == "SignAndEncrypt") {
            has_secure_mode = true;
        }

        if (mode.find("None") != std::string::npos) {
            LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Insecure MessageSecurityMode None detected!");
        }
    }

    // Verify encryption
    if (!server.encryption_available) {
        LOG_WARNING("OPCUA_PLUGIN", "  WARNING: No encryption available on this server!");
    }

    // Verify anonymous login
    if (server.anonymous_login_allowed) {
        LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Anonymous user token advertised (login not tested)");
    }

    bool certificate_ok = true;
    if (!server.certificate_present) {
        LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Server did not expose a certificate");
        certificate_ok = false;
    } else if (!server.certificate_issues.empty()) {
        for (const auto& issue : server.certificate_issues) {
            LOG_WARNINGF("OPCUA_PLUGIN", "  Certificate weakness: %s", issue.c_str());
            if (!issue.empty() &&
                (issue.rfind("CRITICAL", 0) == 0 || issue.rfind("HIGH", 0) == 0)) {
                certificate_ok = false;
            }
        }
    }

    if (server.certificate_self_signed) {
        LOG_WARNING("OPCUA_PLUGIN", "  WARNING: Certificate is self-signed");
    }

    // Overall assessment
    bool is_secure = has_secure_policy && has_secure_mode &&
                    server.encryption_available && !server.anonymous_login_allowed &&
                    certificate_ok;

    if (is_secure) {
        LOG_INFO("OPCUA_PLUGIN", "Server security configuration appears SECURE");
    } else {
        LOG_WARNING("OPCUA_PLUGIN", "Server security configuration has WEAKNESSES");
    }

    return is_secure;
}


bool OPCUAPlugin::parseOPCUAPacket(const NetworkPacket& packet, std::string& message_type,
                                  uint32_t& secure_channel_id, uint32_t& sequence_number) {
    const uint8_t* frame = nullptr;
    size_t frame_len = 0;
    if (!locateOpcuaFrame(packet, frame, frame_len)) return false;

    UATcpHeader header;
    if (!parseHeader(frame, frame_len, header)) {
        return false;
    }

    message_type = std::string(header.msgType, header.msgType + 3);

    // For MSG packets, try to extract secure channel ID and sequence number
    if (message_type == "MSG" && frame_len >= 24) {
        // TCP header(8) + SecureChannelId(4) + SecurityTokenId(4) + SequenceNumber(4)
        secure_channel_id = readLe32(frame + 8);
        sequence_number = readLe32(frame + 16);
    }

    return true;
}

// Fuzzing API implementations
bool OPCUAPlugin::generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) {
    out.clear();

    if (!job.profile.empty() && job.profile != "default") {
        if (generateAttackSeeds(job, job.profile, out) && !out.empty()) {
            LOG_INFOF("OPCUA_PLUGIN", "Generated %zu OPC UA seeds for profile '%s'",
                      out.size(), job.profile.c_str());
            return true;
        }
        LOG_WARNINGF("OPCUA_PLUGIN", "Unknown/empty OPC UA fuzz profile '%s', fallback to baseline seeds",
                     job.profile.c_str());
    }

    // Baseline HEL message
    FuzzTestCase hel_case;
    hel_case.seed_id = 4001;
    hel_case.mutation_id = 0;
    hel_case.attack_type = "default";
    hel_case.mutation_description = "UA-TCP HEL baseline";
    hel_case.payload.assign(32U, 0U);
    hel_case.payload[0] = 'H';
    hel_case.payload[1] = 'E';
    hel_case.payload[2] = 'L';
    hel_case.payload[3] = 'F';
    hel_case.payload[4] = 0x20;
    hel_case.payload[12] = 0x00; // receive buffer size = 16384
    hel_case.payload[13] = 0x40;
    hel_case.payload[16] = 0x00; // send buffer size = 16384
    hel_case.payload[17] = 0x40;
    out.push_back(std::move(hel_case));

    // Baseline OpenSecureChannel (policy None), useful for endpoint reaction checks.
    psram_string host_ps = PSRAMUtils::createPSRAMString("127.0.0.1");
    psram_string normalized_target;
    uint16_t port = OPCUA_PORT;
    if (!job.target.empty()) {
        psram_string target_ps = PSRAMUtils::createPSRAMString(job.target.c_str());
        if (!target_ps.empty()) {
            psram_string parsed_host;
            uint16_t parsed_port = OPCUA_PORT;
            psram_string parsed_target;
            if (parseOpcuaScanTarget(target_ps, parsed_host, parsed_port, parsed_target)) {
                host_ps = parsed_host;
                port = parsed_port;
                normalized_target = parsed_target;
            }
        }
    }
    if (normalized_target.empty()) {
        char endpoint_buf[160];
        snprintf(endpoint_buf, sizeof(endpoint_buf), "opc.tcp://%s:%u", host_ps.c_str(), (unsigned)port);
        normalized_target = PSRAMUtils::createPSRAMString(endpoint_buf);
    }

    psram_vector<uint8_t> opn_msg;
    if (OPCUABinaryCodec::buildOpenSecureChannelRequest(opn_msg,
                                                        normalized_target.c_str(),
                                                        OPCUA::POLICY_NONE,
                                                        60000)) {
        FuzzTestCase opn_case;
        opn_case.seed_id = 4002;
        opn_case.mutation_id = 0;
        opn_case.attack_type = "default";
        opn_case.mutation_description = "OpenSecureChannel baseline (SecurityPolicy None)";
        opn_case.payload.assign(opn_msg.begin(), opn_msg.end());
        if (!opn_case.payload.empty()) {
            out.push_back(std::move(opn_case));
        }
    }

    LOG_INFOF("OPCUA_PLUGIN", "Generated %zu OPC UA baseline fuzz seeds", out.size());
    return !out.empty();
}

bool OPCUAPlugin::fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) {
    (void)job;
    out = in;
    if (out.payload.size() >= 8U) {
        const uint32_t length = static_cast<uint32_t>(out.payload.size());
        out.payload[4] = static_cast<uint8_t>(length & 0xFFU);
        out.payload[5] = static_cast<uint8_t>((length >> 8) & 0xFFU);
        out.payload[6] = static_cast<uint8_t>((length >> 16) & 0xFFU);
        out.payload[7] = static_cast<uint8_t>((length >> 24) & 0xFFU);
    }
    return true;
}

FuzzResult OPCUAPlugin::execute(const FuzzJob& job, const FuzzTestCase& tc,
                                std::string& sent_hex, std::string& received_hex,
                                std::string& status_details) {
    if (!job.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())) {
        status_details = "blocked_by_offensive_policy:" +
            std::string(sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
        sent_hex.clear();
        received_hex.clear();
        return FuzzResult::SEND_FAILED;
    }

    sent_hex = bytesToHexWithSpaces(tc.payload);
    received_hex.clear();
    status_details.clear();

    if (tc.payload.empty()) {
        status_details = "empty_payload";
        return FuzzResult::SEND_FAILED;
    }

    psram_string target_ps = PSRAMUtils::createPSRAMString(job.target.c_str());
    psram_string host_ps;
    psram_string normalized_target;
    uint16_t port = OPCUA_PORT;
    if (!parseOpcuaScanTarget(target_ps, host_ps, port, normalized_target)) {
        status_details = "invalid_target";
        return FuzzResult::SOCKET_ERROR;
    }

    uint32_t timeout_ms = 3000U;
    if (!job.extra_config.empty()) {
        int v = 0;
        if (parseJsonIntFieldSimple(job.extra_config, "timeout_ms", v) && v >= 200 && v <= 30000) {
            timeout_ms = static_cast<uint32_t>(v);
        }
    }

    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        status_details = "socket_creation_failed";
        return FuzzResult::SOCKET_ERROR;
    }

    configureTcpSocket(sock);

    struct timeval tv {};
    tv.tv_sec = static_cast<time_t>(timeout_ms / 1000U);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000U) * 1000U);
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    const psram_string bound_if = PSRAMUtils::createPSRAMString("ETH_DEF");

    struct sockaddr_in remote {};
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);

    if (::inet_aton(host_ps.c_str(), &remote.sin_addr) == 0) {
        struct hostent* he = ::gethostbyname(host_ps.c_str());
        if (!he || he->h_length <= 0) {
            ::close(sock);
            status_details = "invalid_ip_or_hostname";
            return FuzzResult::SOCKET_ERROR;
        }
        memcpy(&remote.sin_addr, he->h_addr_list[0], static_cast<size_t>(he->h_length));
    }

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&remote), sizeof(remote)) != 0) {
        ::close(sock);
        status_details = "connect_failed";
        return FuzzResult::CONNECTION_FAILED;
    }

    const ssize_t sent = ::send(sock, tc.payload.data(), tc.payload.size(), 0);
    if (sent != static_cast<ssize_t>(tc.payload.size())) {
        ::close(sock);
        status_details = "send_failed";
        return FuzzResult::SEND_FAILED;
    }

    std::vector<uint8_t> rx_frame;
    bool timed_out = false;
    std::string rx_error;
    const bool rx_ok = recvOpcuaFrame(sock, rx_frame, timed_out, rx_error);
    ::close(sock);

    if (!rx_ok) {
        status_details = rx_error.empty() ? "recv_failed" : rx_error;
        if (timed_out) {
            return FuzzResult::TIMEOUT;
        }
        if (status_details == "recv_failed_header") {
            return FuzzResult::CONNECTION_FAILED;
        }
        if (status_details == "recv_failed_body") {
            return FuzzResult::INVALID_RESPONSE;
        }
        return FuzzResult::SOCKET_ERROR;
    }

    received_hex = bytesToHexWithSpaces(rx_frame);

    UATcpHeader h {};
    if (!parseHeader(rx_frame.data(), rx_frame.size(), h)) {
        status_details = "invalid_ua_tcp_header_after_receive";
        return FuzzResult::INVALID_RESPONSE;
    }

    char msg_type[4] = {h.msgType[0], h.msgType[1], h.msgType[2], '\0'};
    status_details.reserve(160);
    status_details += "if=";
    status_details += bound_if.c_str();
    status_details += " rx_type=";
    status_details += msg_type;
    status_details += " rx_len=";
    status_details += std::to_string((unsigned)h.len);

    const bool known_type =
        (h.msgType[0] == 'H' && h.msgType[1] == 'E' && h.msgType[2] == 'L') ||
        (h.msgType[0] == 'A' && h.msgType[1] == 'C' && h.msgType[2] == 'K') ||
        (h.msgType[0] == 'E' && h.msgType[1] == 'R' && h.msgType[2] == 'R') ||
        (h.msgType[0] == 'O' && h.msgType[1] == 'P' && h.msgType[2] == 'N') ||
        (h.msgType[0] == 'C' && h.msgType[1] == 'L' && h.msgType[2] == 'O') ||
        (h.msgType[0] == 'M' && h.msgType[1] == 'S' && h.msgType[2] == 'G');
    if (!known_type) {
        status_details += " unknown_message_type";
        return FuzzResult::INVALID_RESPONSE;
    }

    if (h.msgType[0] == 'E' && h.msgType[1] == 'R' && h.msgType[2] == 'R') {
        if (rx_frame.size() >= 12U) {
            uint32_t err_code = readLe32(rx_frame.data() + 8U);
            char buf[48];
            snprintf(buf, sizeof(buf), " err_code=0x%08lX", (unsigned long)err_code);
            status_details += buf;
        }
        return FuzzResult::EXCEPTION_RESPONSE;
    }

    if (h.msgType[0] == 'M' && h.msgType[1] == 'S' && h.msgType[2] == 'G') {
        bool is_response = false;
        uint16_t service_id = 0;
        if (parseOpcuaServiceTypeIdFromMsg(rx_frame.data(), rx_frame.size(), service_id)) {
            const OpcuaServiceDescriptor* d = findOpcuaServiceDescriptor(service_id, &is_response);
            char sid_buf[32];
            snprintf(sid_buf, sizeof(sid_buf), " service_id=%u", (unsigned)service_id);
            status_details += sid_buf;
            if (d) {
                status_details += " service=";
                status_details += d->name;
                status_details += is_response ? "(response)" : "(request)";
            }
        } else {
            status_details += " service_id_unparsed";
        }

        uint32_t status_code = 0;
        psram_string diag;
        if (OPCUABinaryCodec::parseServiceFault(rx_frame.data(), rx_frame.size(), status_code, diag)) {
            if (status_code != 0U) {
                char sbuf[64];
                snprintf(sbuf, sizeof(sbuf), " service_fault=0x%08lX", (unsigned long)status_code);
                status_details += sbuf;
                if (!diag.empty()) {
                    status_details += " diag=";
                    status_details += diag.c_str();
                }
                return FuzzResult::EXCEPTION_RESPONSE;
            }
        }
    }

    return FuzzResult::SUCCESS;
}

bool OPCUAPlugin::generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out) {
    out.clear();
    LOG_INFOF("OPCUA_PLUGIN", "Generating OPC UA attack seeds for '%s'", attack_type.c_str());

    auto append_seed = [&](uint32_t& seq,
                           const std::vector<uint8_t>& payload,
                           const char* at,
                           const char* desc) {
        if (payload.empty()) {
            return;
        }
        FuzzTestCase tc;
        tc.seed_id = seq++;
        tc.mutation_id = 0;
        tc.attack_type = at ? at : "opcua";
        tc.mutation_description = desc ? desc : "";
        tc.payload = payload;
        out.push_back(std::move(tc));
    };

    auto append_from_catalog = [&](uint32_t& seq,
                                   const psram_vector<OPCUAFuzzingSeeds::FuzzingSeed>& cat,
                                   const char* at,
                                   size_t limit = 0U) {
        size_t added = 0;
        for (const auto& s : cat) {
            if (limit > 0U && added >= limit) {
                break;
            }
            std::vector<uint8_t> payload;
            payload.assign(s.payload.begin(), s.payload.end());
            if (payload.empty()) {
                continue;
            }
            std::string desc = PSRAMUtils::fromPSRAMString(s.name);
            const std::string extra = PSRAMUtils::fromPSRAMString(s.description);
            if (!extra.empty()) {
                desc += " - ";
                desc += extra;
            }
            append_seed(seq, payload, at, desc.c_str());
            ++added;
        }
    };

    psram_string host_ps = PSRAMUtils::createPSRAMString("127.0.0.1");
    psram_string normalized_target;
    uint16_t port = OPCUA_PORT;
    if (!job.target.empty()) {
        psram_string target_ps = PSRAMUtils::createPSRAMString(job.target.c_str());
        if (!target_ps.empty()) {
            psram_string parsed_host;
            uint16_t parsed_port = OPCUA_PORT;
            psram_string parsed_target;
            if (parseOpcuaScanTarget(target_ps, parsed_host, parsed_port, parsed_target)) {
                host_ps = parsed_host;
                port = parsed_port;
                normalized_target = parsed_target;
            }
        }
    }
    if (normalized_target.empty()) {
        char endpoint_buf[160];
        snprintf(endpoint_buf, sizeof(endpoint_buf), "opc.tcp://%s:%u", host_ps.c_str(), (unsigned)port);
        normalized_target = PSRAMUtils::createPSRAMString(endpoint_buf);
    }

    uint32_t seed_seq = 5001U;
    OPCUAFuzzingSeeds::SeedGenerator generator;

    if (attack_type == "comprehensive") {
        append_from_catalog(seed_seq, generator.generateAllSeeds(), "comprehensive");
    } else if (attack_type == "protocol_violations") {
        append_from_catalog(seed_seq, generator.generateMalformedHeaders(), attack_type.c_str());
        append_from_catalog(seed_seq, generator.generateBoundaryValues(), attack_type.c_str());
        append_from_catalog(seed_seq, generator.generateProtocolViolations(), attack_type.c_str());
        append_from_catalog(seed_seq, generator.generateEncodingErrors(), attack_type.c_str());
    } else if (attack_type == "string_attacks") {
        append_from_catalog(seed_seq, generator.generateStringAttacks(), attack_type.c_str());
    } else if (attack_type == "cve_based") {
        append_from_catalog(seed_seq, generator.generateCVEBasedSeeds(), attack_type.c_str());
    } else if (attack_type == "chunk_exhaustion") {
        append_from_catalog(seed_seq, generator.generateResourceExhaustion(), attack_type.c_str());
        append_from_catalog(seed_seq, generator.generateCVEBasedSeeds(), attack_type.c_str(), 8U);
    } else if (attack_type == "browse_flooding") {
        append_from_catalog(seed_seq, generator.generateResourceExhaustion(), attack_type.c_str(), 40U);
    } else if (attack_type == "session_hijacking") {
        std::vector<uint8_t> hijack_payload = {
            'M','S','G','F', 0x20,0x00,0x00,0x00,
            0x01,0x00,0x00,0x00,
            0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00
        };
        append_seed(seed_seq, hijack_payload, attack_type.c_str(),
                    "Forged MSG with invalid channel/token for session hijacking checks");
        append_from_catalog(seed_seq, generator.generateProtocolViolations(), attack_type.c_str(), 16U);
    } else if (attack_type == "certificate_bypass" ||
               attack_type == "anonymous_access" ||
               attack_type == "weak_security_policies") {
        psram_vector<uint8_t> opn_msg;
        if (OPCUABinaryCodec::buildOpenSecureChannelRequest(opn_msg,
                                                            normalized_target.c_str(),
                                                            OPCUA::POLICY_NONE,
                                                            60000U)) {
            std::vector<uint8_t> payload;
            payload.assign(opn_msg.begin(), opn_msg.end());
            append_seed(seed_seq,
                        payload,
                        attack_type.c_str(),
                        "OpenSecureChannel with SecurityPolicy None");
        }

        std::vector<uint8_t> weak_policy_probe = {
            'O','P','N','F', 0x20,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x4E,0x6F,0x6E,0x65,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00
        };
        append_seed(seed_seq,
                    weak_policy_probe,
                    attack_type.c_str(),
                    "Minimal OPN payload with weak security marker");
    } else {
        append_from_catalog(seed_seq, generator.generateMalformedHeaders(), "default", 8U);
    }

    LOG_INFOF("OPCUA_PLUGIN", "Generated %zu OPC UA seeds for attack/profile '%s'",
              out.size(), attack_type.c_str());
    return !out.empty();
}

// ============================================================================
// FLOW MANAGEMENT IMPLEMENTATION (OPC UA)
// ============================================================================

bool OPCUAPlugin::buildFlowKey(const NetworkPacket& packet, FlowKey& key) {
    // OPC UA uses TCP on port 4840
    // Message structure: MessageType (3 bytes ASCII) + 'F' (1 byte) + MessageSize (4 bytes) + ...
    // For HEL/ACK: No SecureChannel ID
    // For OPN/MSG/CLO: SecureChannelId (4 bytes) at offset 8

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrame(packet, data, data_len)) return false;

    PSRAMAllocator<char> alloc;
    key.src_ip = psram_string(packet.src_ip, alloc);
    key.dst_ip = psram_string(packet.dst_ip, alloc);
    key.src_port = packet.src_port;
    key.dst_port = packet.dst_port;

    // Protocol-specific: SecureChannel ID for OPN/MSG/CLO, or "HEL"/"ACK" for handshake
    if (isMsgType(data, 'H', 'E', 'L') || isMsgType(data, 'A', 'C', 'K') ||
        isMsgType(data, 'E', 'R', 'R') || isMsgType(data, 'R', 'H', 'E')) {
        // No SecureChannel ID for these message types
        char msg_type[4] = {static_cast<char>(data[0]), static_cast<char>(data[1]), static_cast<char>(data[2]), '\0'};
        key.protocol_specific = psram_string(msg_type, alloc);
    } else if (data_len >= 12) {
        // OPN/MSG/CLO have SecureChannelId at offset 8
        uint32_t secure_channel_id = readLe32(data + 8);
        char channel_str[32];
        snprintf(channel_str,
                 sizeof(channel_str),
                 "%c%c%c_0x%08lX",
                 static_cast<char>(data[0]),
                 static_cast<char>(data[1]),
                 static_cast<char>(data[2]),
                 (unsigned long)secure_channel_id);
        key.protocol_specific = psram_string(channel_str, alloc);
    } else {
        char msg_type[4] = {static_cast<char>(data[0]), static_cast<char>(data[1]), static_cast<char>(data[2]), '\0'};
        key.protocol_specific = psram_string(msg_type, alloc);
    }

    return true;
}

bool OPCUAPlugin::classifyPacketOperation(const NetworkPacket& packet,
                                          psram_string& operation_type,
                                          psram_string& operation_details,
                                          bool& is_error) {
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrame(packet, data, data_len)) return false;
    PSRAMAllocator<char> alloc;
    is_error = false;

    UATcpHeader h{};
    if (!parseHeader(data, data_len, h)) {
        return false;
    }

    char details[256];
    memset(details, 0, sizeof(details));

    // Classify based on message type
    if (h.msgType[0] == 'H' && h.msgType[1] == 'E' && h.msgType[2] == 'L') {
        // Hello message - connection initiation
        operation_type = psram_string("CONTROL", alloc);
        if (data_len >= 32) {
            uint32_t protocol_version = readLe32(data + 8);
            uint32_t receive_buffer_size = readLe32(data + 12);
            uint32_t send_buffer_size = readLe32(data + 16);
            snprintf(details, sizeof(details),
                    "Hello Ver=%lu RcvBuf=%lu SndBuf=%lu",
                    (unsigned long)protocol_version, (unsigned long)receive_buffer_size, (unsigned long)send_buffer_size);
        } else {
            snprintf(details, sizeof(details), "Hello (truncated)");
        }

    } else if (h.msgType[0] == 'A' && h.msgType[1] == 'C' && h.msgType[2] == 'K') {
        // Acknowledge message - connection accepted
        operation_type = psram_string("CONTROL", alloc);
        if (data_len >= 28) {
            uint32_t protocol_version = readLe32(data + 8);
            uint32_t receive_buffer_size = readLe32(data + 12);
            uint32_t send_buffer_size = readLe32(data + 16);
            snprintf(details, sizeof(details),
                    "Acknowledge Ver=%lu RcvBuf=%lu SndBuf=%lu",
                    (unsigned long)protocol_version, (unsigned long)receive_buffer_size, (unsigned long)send_buffer_size);
        } else {
            snprintf(details, sizeof(details), "Acknowledge (truncated)");
        }

    } else if (h.msgType[0] == 'E' && h.msgType[1] == 'R' && h.msgType[2] == 'R') {
        // Error message
        is_error = true;
        operation_type = psram_string("ERROR", alloc);
        if (data_len >= 16) {
            uint32_t error_code = readLe32(data + 8);
            snprintf(details, sizeof(details), "Error Code=0x%08lX", (unsigned long)error_code);
        } else {
            snprintf(details, sizeof(details), "Error (unknown code)");
        }

    } else if (h.msgType[0] == 'O' && h.msgType[1] == 'P' && h.msgType[2] == 'N') {
        // OpenSecureChannel message
        operation_type = psram_string("CONTROL", alloc);
        if (data_len >= 12) {
            uint32_t secure_channel_id = readLe32(data + 8);
            snprintf(details, sizeof(details), "OpenSecureChannel ID=0x%08lX", (unsigned long)secure_channel_id);
        } else {
            snprintf(details, sizeof(details), "OpenSecureChannel (truncated)");
        }

    } else if (h.msgType[0] == 'M' && h.msgType[1] == 'S' && h.msgType[2] == 'G') {
        operation_type = psram_string("OTHER", alloc);
        if (data_len >= 24) {
            uint32_t secure_channel_id = readLe32(data + 8);
            bool is_response = false;
            uint16_t service_id = 0;

            if (parseOpcuaServiceTypeIdFromMsg(data, data_len, service_id)) {
                const OpcuaServiceDescriptor* d = findOpcuaServiceDescriptor(service_id, &is_response);
                const bool request_to_server = (packet.dst_port == OPCUA_PORT);
                const bool response_from_server = (packet.src_port == OPCUA_PORT);

                if (d) {
                    operation_type = psram_string(d->category, alloc);
                    snprintf(details,
                             sizeof(details),
                             "MSG %s %s ChannelID=0x%08lX Service=%s(%u)",
                             is_response ? "Resp" : "Req",
                             request_to_server ? "C->S" : (response_from_server ? "S->C" : "UNK"),
                             (unsigned long)secure_channel_id,
                             d->name,
                             (unsigned)d->request_id);
                } else {
                    snprintf(details,
                             sizeof(details),
                             "MSG %s ChannelID=0x%08lX ServiceId=%u",
                             is_response ? "Resp" : "Req",
                             (unsigned long)secure_channel_id,
                             (unsigned)service_id);
                }
            } else {
                // Legacy textual fallback
                if (memfind(data, data_len, "ReadRequest", strlen("ReadRequest")) ||
                    memfind(data, data_len, "BrowseRequest", strlen("BrowseRequest"))) {
                    operation_type = psram_string("READ", alloc);
                } else if (memfind(data, data_len, "WriteRequest", strlen("WriteRequest")) ||
                           memfind(data, data_len, "CallRequest", strlen("CallRequest")) ||
                           memfind(data, data_len, "AddNodes", strlen("AddNodes")) ||
                           memfind(data, data_len, "DeleteNodes", strlen("DeleteNodes"))) {
                    operation_type = psram_string("WRITE", alloc);
                } else if (memfind(data, data_len, "CreateSession", strlen("CreateSession")) ||
                           memfind(data, data_len, "ActivateSession", strlen("ActivateSession"))) {
                    operation_type = psram_string("CONTROL", alloc);
                }
                snprintf(details, sizeof(details), "MSG Generic ChannelID=0x%08lX", (unsigned long)secure_channel_id);
            }
        } else {
            snprintf(details, sizeof(details), "MSG (truncated)");
        }

    } else if (h.msgType[0] == 'C' && h.msgType[1] == 'L' && h.msgType[2] == 'O') {
        // CloseSecureChannel message
        operation_type = psram_string("CONTROL", alloc);
        if (data_len >= 12) {
            uint32_t secure_channel_id = readLe32(data + 8);
            snprintf(details, sizeof(details), "CloseSecureChannel ID=0x%08lX", (unsigned long)secure_channel_id);
        } else {
            snprintf(details, sizeof(details), "CloseSecureChannel (truncated)");
        }

    } else {
        // Unknown message type
        operation_type = psram_string("OTHER", alloc);
        char mt[4] = {(char)h.msgType[0], (char)h.msgType[1], (char)h.msgType[2], '\0'};
        snprintf(details, sizeof(details), "Unknown MsgType='%s'", mt);
    }

    operation_details = psram_string(details, alloc);
    return true;
}

void OPCUAPlugin::updateProtocolState(const NetworkPacket& packet, FlowData& flow) {
    // OPC UA state machine:
    // INIT -> CONNECTING (HEL) -> ESTABLISHED (ACK) ->
    // CONNECTING (OpenSecureChannel) -> AUTHENTICATED (CreateSession + ActivateSession) ->
    // DATA_EXCHANGE -> CLOSING (CloseSecureChannel) -> CLOSED

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrame(packet, data, data_len)) return;
    const bool msg_hel = isMsgType(data, 'H', 'E', 'L');
    const bool msg_msg = isMsgType(data, 'M', 'S', 'G');
    const bool msg_ack = isMsgType(data, 'A', 'C', 'K');
    const bool msg_err = isMsgType(data, 'E', 'R', 'R');
    const bool msg_opn = isMsgType(data, 'O', 'P', 'N');
    const bool msg_clo = isMsgType(data, 'C', 'L', 'O');

    if (flow.state == FlowState::INIT) {
        if (msg_hel) {
            flow.state = FlowState::CONNECTING;
        } else if (msg_msg) {
            // Already in session - skip to data exchange
            flow.state = FlowState::DATA_EXCHANGE;
        }
        return;
    }

    if (flow.state == FlowState::CONNECTING) {
        if (msg_ack) {
            // TCP connection established
            flow.state = FlowState::ESTABLISHED;
        } else if (msg_err) {
            flow.state = FlowState::ERROR;
        }
        return;
    }

    if (flow.state == FlowState::ESTABLISHED) {
        if (msg_opn) {
            // Opening secure channel - stay in CONNECTING for authentication
            flow.state = FlowState::CONNECTING;
        } else if (msg_msg) {
            // Check if this is CreateSession or ActivateSession
            uint16_t service_id = 0;
            bool auth_phase = false;
            if (parseOpcuaServiceTypeIdFromMsg(data, data_len, service_id)) {
                auth_phase = (service_id == 461 || service_id == 464 || service_id == 467 || service_id == 470);
            }
            if (!auth_phase) {
                const size_t scan_len = (data_len < static_cast<size_t>(256)) ? data_len : static_cast<size_t>(256);
                auth_phase = memfind(data, scan_len, "CreateSession", strlen("CreateSession")) ||
                             memfind(data, scan_len, "ActivateSession", strlen("ActivateSession"));
            }
            if (auth_phase) {
                flow.state = FlowState::AUTHENTICATED;
            } else {
                // Generic message - consider it data exchange
                flow.state = FlowState::DATA_EXCHANGE;
            }
        }
        return;
    }

    if (flow.state == FlowState::AUTHENTICATED) {
        if (msg_msg) {
            flow.state = FlowState::DATA_EXCHANGE;
        }
        return;
    }

    if (flow.state == FlowState::DATA_EXCHANGE) {
        if (msg_clo) {
            flow.state = FlowState::CLOSING;
        } else if (msg_err) {
            flow.state = FlowState::ERROR;
        }
        return;
    }

    if (flow.state == FlowState::CLOSING) {
        flow.state = FlowState::CLOSED;
        return;
    }
}

void OPCUAPlugin::assignFlowLabel(FlowData& flow) {
    // 1. Check for flooding attacks
    if (flow.metrics.intensity == FlowIntensity::FLOODING) {
        flow.metrics.primary_label = FlowLabel::FLOODING;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 2. Check for excessive error rate
    if (flow.metrics.hasTooManyErrors(0.3f)) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::PROTOCOL_VIOLATION;
        return;
    }

    // 3. Check for session flooding (excessive CreateSession attempts)
    uint32_t create_session_count = 0, hello_count = 0;
    for (const auto& op : flow.recent_operations) {
        if (op.type == "CONTROL") {
            if (op.details.find("CreateSession") != psram_string::npos) {
                create_session_count++;
            } else if (op.details.find("Hello") != psram_string::npos) {
                hello_count++;
            }
        }
    }

    if (create_session_count > 20 && flow.metrics.intensity >= FlowIntensity::HIGH) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::POTENTIAL_ATTACK;
        return;
    }

    if (hello_count > 30 && flow.metrics.intensity >= FlowIntensity::VERY_HIGH) {
        flow.metrics.primary_label = FlowLabel::FLOODING;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 4. Check for scanning/reconnaissance patterns (excessive Browse requests)
    uint32_t browse_count = 0;
    for (const auto& op : flow.recent_operations) {
        if (op.type == "READ" && op.details.find("Browse") != psram_string::npos) {
            browse_count++;
        }
    }

    if (browse_count > 50 && flow.metrics.intensity >= FlowIntensity::VERY_HIGH) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 5. Check for authentication issues
    if (flow.state == FlowState::ERROR &&
        flow.metrics.error_responses > 10) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::BRUTE_FORCE_ATTEMPT;
        return;
    }

    // 6. Normal classification based on operation types
    if (flow.metrics.isWriter()) {
        flow.metrics.primary_label = (flow.metrics.write_operations > flow.metrics.read_operations * 2)
            ? FlowLabel::WRITER : FlowLabel::MIXED_RW;
    } else if (flow.metrics.isReader()) {
        flow.metrics.primary_label = FlowLabel::READER;
        // Check for polling pattern (regular medium intensity reads)
        if (flow.metrics.intensity >= FlowIntensity::LOW &&
            flow.metrics.intensity <= FlowIntensity::MEDIUM &&
            flow.metrics.read_operations > 10) {
            flow.metrics.secondary_label = FlowLabel::POLLING;
        }
    } else if (flow.metrics.control_operations > flow.metrics.read_operations + flow.metrics.write_operations) {
        // Mostly session management
        flow.metrics.primary_label = FlowLabel::DIAGNOSTIC;
    } else {
        flow.metrics.primary_label = FlowLabel::NORMAL_OPERATION;
    }

    // 7. Mark heavy users
    if (flow.metrics.intensity == FlowIntensity::HIGH &&
        flow.metrics.primary_label != FlowLabel::SCANNER) {
        flow.metrics.secondary_label = FlowLabel::HEAVY_USER;
    }
}

// Enhanced IDS method for real-time packet analysis

void OPCUAPlugin::analyzeOPCUATraffic(const NetworkPacket& packet) {
    network_presence_tracker_.trackPacket(packet);
}

bool OPCUAPlugin::isOPCUAHandshake(const NetworkPacket& packet) {
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrame(packet, data, data_len)) return false;

    UATcpHeader header{};
    if (!parseHeader(data, data_len, header)) {
        return false;
    }
    if ((memcmp(header.msgType, "HEL", 3) == 0) ||
        (memcmp(header.msgType, "ACK", 3) == 0) ||
        (memcmp(header.msgType, "OPN", 3) == 0) ||
        (memcmp(header.msgType, "CLO", 3) == 0)) {
        return true;
    }
    return false;
}

bool OPCUAPlugin::isBruteForceAttempt(uint32_t src_ipv4) {
    if (src_ipv4 == 0) {
        return false;
    }

    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    static psram_map<uint32_t, SlidingWindowCounter> handshake_attempts;

    auto& counter = handshake_attempts[src_ipv4];
    resetIfWindowExpired(counter, now_ms, 60000U);
    counter.count++;
    if (counter.count > 12U) {
        counter.count = 0;
        counter.window_start_ms = now_ms;
        return true;
    }
    return false;
}
