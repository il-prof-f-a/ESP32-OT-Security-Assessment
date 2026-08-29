#include "ethernetip_plugin.h"
#include "../assessment/fuzzing_engine.h"
#include "../security/security_manager.h"
#include "../network/assessment_interface.h"
#include "../core/reporting_engine.h"
#include "../core/logging_system.h"
#include "../core/psram_allocator.h"
#include <cstring>
#include "../core/event_formatter.h"
#include "../core/psram_json_parser.h"
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <unordered_set>
#include <cstdlib>
#include "cJSON.h"
extern "C" {
  #include "lwip/sockets.h"
  #include "lwip/inet.h"
  #include "esp_netif.h"
  #include "lwip/sockets.h"
  #include "lwip/inet.h"
  #include "esp_netif.h"
  #include "esp_heap_caps.h"
  #include "esp_timer.h"
}

#include "../assessment/discovery_manager.h"

static psram_string sanitizePrintablePSRAM(const char* input, size_t len) {
    if (!input || len == 0) {
        return PSRAMUtils::createPSRAMString("");
    }

    psram_string out;
    out.reserve(len);
    for (size_t i = 0; i < len && input[i] != '\0'; ++i) {
        char c = input[i];
        if (c >= 32 && c <= 126) {
            out.push_back(c);
        }
    }
    return out;
}

namespace {
struct JsonHookGuard {
    JsonHookGuard() { PSRAMJson::ensureHooks(); }
};
static JsonHookGuard kJsonHookGuard;

struct EventDedupState {
    uint32_t last_emit_ms;
    EventDedupState() : last_emit_ms(0) {}
};

static inline uint32_t fnv1a32(const char* text) {
    uint32_t hash = 2166136261u;
    if (!text) return hash;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        hash ^= static_cast<uint32_t>(*p);
        hash *= 16777619u;
    }
    return hash;
}

static inline bool shouldSuppressEnipEvent(const char* json, LogLevel level, uint32_t now_ms) {
    if (!json || now_ms == 0) {
        return false;
    }
    uint32_t window_ms = 0;
    if (level == LogLevel::INFO) window_ms = 10000U;
    else if (level == LogLevel::WARNING) window_ms = 3000U;
    else if (level == LogLevel::ERROR) window_ms = 1000U;
    if (window_ms == 0) return false;

    static psram_map<uint32_t, EventDedupState> cache;
    uint32_t key = fnv1a32(json) ^ static_cast<uint32_t>(level);
    auto& st = cache[key];
    if (st.last_emit_ms != 0 && (now_ms - st.last_emit_ms) < window_ms) {
        return true;
    }
    st.last_emit_ms = now_ms;
    return false;
}

static bool parseListInterfacesPayload(const uint8_t* payload,
                                       size_t length,
                                       psram_vector<psram_string>* descriptions) {
    if (!payload || length < 2) {
        return false;
    }
    if (descriptions) {
        descriptions->clear();
    }

    uint16_t count = static_cast<uint16_t>(payload[0] | (payload[1] << 8));
    size_t pos = 2;
    bool parsed_any = false;
    for (uint16_t idx = 0; idx < count; ++idx) {
        if (pos + 4 > length) {
            return false;
        }
        uint16_t type = static_cast<uint16_t>(payload[pos + 0] | (payload[pos + 1] << 8));
        uint16_t ilen = static_cast<uint16_t>(payload[pos + 2] | (payload[pos + 3] << 8));
        pos += 4;
        if (pos + ilen > length) {
            return false;
        }
        parsed_any = true;
        if (descriptions) {
            PSRAMUtils::ScopedBuffer line(192);
            if (line.valid()) {
                snprintf(line.get(), line.size(),
                         "interface_item[%u]: type=0x%04X len=%u",
                         static_cast<unsigned>(idx),
                         static_cast<unsigned>(type),
                         static_cast<unsigned>(ilen));
                descriptions->push_back(PSRAMUtils::createPSRAMString(line.get()));
            }
        }
        pos += ilen;
    }
    return parsed_any;
}

static inline uint16_t rd16le_local(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

static inline bool looksLikeEnipFrame(const uint8_t* p, size_t n) {
    if (!p || n < 24) return false;
    uint16_t payload_len = rd16le_local(p + 2);
    return (24U + static_cast<size_t>(payload_len) <= n);
}

static bool locateUdpAppPayload(const NetworkPacket& pkt, const uint8_t*& out, size_t& out_len) {
    out = nullptr;
    out_len = 0;
    if (!pkt.data || pkt.length < 8) return false;

    // Direct UDP application payload
    if ((pkt.data[0] >> 4) != 4 || pkt.length < 20) {
        out = pkt.data;
        out_len = pkt.length;
        return true;
    }

    // IPv4 + UDP encapsulated payload (L2 ingest path)
    const uint8_t* ip = pkt.data;
    size_t ip_len = pkt.length;
    size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || ihl > ip_len) return false;
    if (ip[9] != 17) return false;
    if (ip_len < ihl + 8) return false;

    const uint8_t* udp = ip + ihl;
    out = udp + 8;
    out_len = ip_len - (ihl + 8);
    return (out_len > 0);
}

static bool locateEnipFrame(const NetworkPacket& pkt, const uint8_t*& out, size_t& out_len) {
    out = nullptr;
    out_len = 0;
    if (!pkt.data || pkt.length < 24) return false;

    // Case 1: direct ENIP frame
    if (looksLikeEnipFrame(pkt.data, pkt.length)) {
        out = pkt.data;
        out_len = pkt.length;
        return true;
    }

    // Case 2: IPv4 encapsulated payload (L2 ingest path)
    const uint8_t* ip = pkt.data;
    size_t ip_len = pkt.length;
    if ((ip[0] >> 4) != 4 || ip_len < 20) return false;

    size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || ihl > ip_len) return false;

    const uint8_t ip_proto = ip[9];
    if (ip_proto == 6) { // TCP
        if (ip_len < ihl + 20) return false;
        const uint8_t* tcp = ip + ihl;
        size_t doff = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4U;
        if (doff < 20 || ip_len < ihl + doff) return false;
        const uint8_t* frame = tcp + doff;
        size_t frame_len = ip_len - (ihl + doff);
        if (!looksLikeEnipFrame(frame, frame_len)) return false;
        out = frame;
        out_len = frame_len;
        return true;
    }

    if (ip_proto == 17) { // UDP
        if (ip_len < ihl + 8) return false;
        const uint8_t* udp = ip + ihl;
        const uint8_t* frame = udp + 8;
        size_t frame_len = ip_len - (ihl + 8);
        if (!looksLikeEnipFrame(frame, frame_len)) return false;
        out = frame;
        out_len = frame_len;
        return true;
    }

    return false;
}
}
#define TAG_EIP "EtherNetIPPlugin"

// --- ENIP constants (confirmed from vendor/user manuals & dissectors) ---
// Encapsulation command codes
static constexpr uint16_t ENIP_CMD_LISTSERVICES = 0x0004;  // may be UDP/TCP
static constexpr uint16_t ENIP_CMD_LISTIDENTITY = 0x0063;  // may be UDP/TCP
static constexpr uint16_t ENIP_CMD_LISTINTERF   = 0x0064;  // may be UDP/TCP
static constexpr uint16_t ENIP_CMD_REGSESSION   = 0x0065;  // TCP only
static constexpr uint16_t ENIP_CMD_UNREGSESS    = 0x0066;  // TCP only
static constexpr uint16_t ENIP_CMD_SENDRRDATA   = 0x006F;  // TCP only (explicit, unconnected)
// CPF item type IDs
static constexpr uint16_t CPF_NULL_ADDR          = 0x0000;
static constexpr uint16_t CPF_IDENTITY_ITEM      = 0x000C;
static constexpr uint16_t CPF_UNCONNECTED_DATA   = 0x00B2;

// CIP services of interest (subset)
static constexpr uint8_t  CIP_SVC_RESET               = 0x05;
static constexpr uint8_t  CIP_SVC_GET_ATTR_ALL        = 0x01;
static constexpr uint8_t  CIP_SVC_GET_ATTR_SINGLE     = 0x0E;
static constexpr uint8_t  CIP_SVC_SET_ATTR_SINGLE     = 0x10;
static constexpr uint8_t  CIP_SVC_SET_ATTR_LIST       = 0x16;
static constexpr uint8_t  CIP_SVC_FORWARD_CLOSE       = 0x4E;
static constexpr uint8_t  CIP_SVC_FORWARD_OPEN        = 0x54;
static constexpr uint8_t  CIP_SVC_LARGE_FORWARD_OPEN  = 0x5B;

// Ports
static constexpr uint16_t ENIP_TCP_PORT = 44818;   // explicit messaging
static constexpr uint16_t ENIP_UDP_PORT = 44818;   // encapsulation over UDP (eg ListIdentity)
static constexpr uint16_t ENIP_IO_UDP   = 2222;


// Helper function to convert IP string to uint32_t
static inline uint32_t ip_to_uint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) != 0) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

// CIP path parsing helpers
static bool parseCipPath(const uint8_t* p, size_t bytes,
                         uint16_t& class_id, uint16_t& inst_id, uint16_t& attr_id) {
    class_id = inst_id = attr_id = 0;
    size_t pos = 0;
    while (pos < bytes) {
        uint8_t seg = p[pos++];
        if ((seg & 0xE0) == 0x20) { // Class segment 0x20
            if (pos >= bytes) break;
            class_id = p[pos++];
        } else if ((seg & 0xE0) == 0x24) { // Instance 0x24
            if (pos >= bytes) break;
            inst_id = p[pos++];
        } else if ((seg & 0xE0) == 0x30) { // Attribute 0x30
            if (pos >= bytes) break;
            attr_id = p[pos++];
        } else if ((seg & 0xE0) == 0x28) { // 16-bit logical segment (word-aligned)
            // Next is 16-bit value
            if (pos + 1 >= bytes) break;
            uint16_t v = (uint16_t)(p[pos] | (p[pos+1]<<8));
            pos+=2;
            (void)v; // suppress unused warning
            // Heuristic: if previous was class marker 0x21/0x20we skip; minimal impl for now
        } else {
            // skip unknown/ANSI/Logical segments best-effort
            if (pos >= bytes) break;
            ++pos;
        }
    }
    return true;
}
    // implicit I/O (not parsed deeply here)

// Configure the TCP socket to close aggressively and free the PCBs immediately
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

EtherNetIPPlugin::EtherNetIPPlugin() : BasePlugin("EtherNetIPPlugin","0.1", ProtocolType::ETHERNET_IP) {}

bool EtherNetIPPlugin::isPacketWriter(const NetworkPacket& pkt) const {
    if (!pkt.is_tcp || !pkt.data || pkt.length < 28) return false;
    const uint8_t* encap = nullptr;
    size_t encap_len = 0;
    if (!locateEnipFrame(pkt, encap, encap_len)) return false;
    if (encap_len < 28) return false;
    uint16_t cmd = le16(encap+0);
    if (cmd != ENIP_CMD_SENDRRDATA) return false;
    const uint8_t* payload = encap + 24;
    size_t pay_len = encap_len - 24;
    uint8_t svc = 0; bool is_resp = false; uint16_t cls=0, inst=0, attr=0;
    if (!parseSendRRDataForCIP(payload, pay_len, svc, is_resp, cls, inst, attr)) return false;
    if (is_resp) return false;
    return (svc == CIP_SVC_SET_ATTR_SINGLE ||
            svc == CIP_SVC_SET_ATTR_LIST ||
            svc == CIP_SVC_RESET ||
            svc == CIP_SVC_FORWARD_OPEN ||
            svc == CIP_SVC_LARGE_FORWARD_OPEN ||
            svc == CIP_SVC_FORWARD_CLOSE);
}

bool EtherNetIPPlugin::initialize(ConfigurationManager* cfg, ReportingEngine* rep) {
    if (!BasePlugin::initialize(cfg, rep)) {
        LOG_ERROR(TAG_EIP, "Failed to initialize base plugin state");
        return false;
    }

    // Register EtherNet/IP-specific event extractor with centralized SessionStateMachine
    getSessionStateMachine().registerProtocolCallbacks(
        SessionEventHelpers::extractEtherNetIPEvent,
        nullptr  // Use default transition validator
    );

    LOG_INFO(TAG_EIP, "EtherNetIPPlugin ready");
    return true;
}

void EtherNetIPPlugin::shutdown() {
    BasePlugin::shutdown();
    LOG_INFO(TAG_EIP, "EtherNetIPPlugin shutdown");
}

void EtherNetIPPlugin::buildEncapHeader(uint8_t* b, uint16_t cmd, uint16_t len, uint32_t session) {
    wr16le(b+0, cmd);
    wr16le(b+2, len);
    wr32le(b+4, session);
    wr32le(b+8, 0); // status
    memset(b+12, 0, 8); // sender context
    wr32le(b+20, 0); // options
}

bool EtherNetIPPlugin::activeListIdentityPSRAM(const psram_string& target, psram_string& out_json) {
    psram_string ip_ps;
    uint16_t port = ENIP_TCP_PORT;
    if (!parseTarget(target, ip_ps, port)) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_target\"}");
        return false;
    }

    char ip_buf[64] = {0};
    PSRAMUtils::copyToStackBuffer(ip_buf, sizeof(ip_buf), ip_ps);

    int s = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"socket\"}");
        return false;
    }
    configureTcpSocket(s);
    struct timeval tv{.tv_sec = 2, .tv_usec = 0};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        ::close(s);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"ethernet_not_ready\"}");
        return false;
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_aton(ip_buf, &sa.sin_addr) == 0) {
        ::close(s);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"bad_ip\"}");
        return false;
    }
    if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        ::close(s);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"connect\"}");
        return false;
    }

    uint8_t req[24];
    buildEncapHeader(req, ENIP_CMD_LISTIDENTITY, 0, 0);
    if (::send(s, req, sizeof(req), 0) != static_cast<ssize_t>(sizeof(req))) {
        ::close(s);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"send\"}");
        return false;
    }

    uint8_t rx[1024];
    ssize_t n = ::recv(s, rx, sizeof(rx), 0);
    ::close(s);
    if (n < 24) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"short\"}");
        return false;
    }

    uint16_t cmd = le16(rx + 0);
    uint16_t elen = le16(rx + 2);
    if (cmd != ENIP_CMD_LISTIDENTITY) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_cmd\"}");
        return false;
    }
    size_t payload_len = elen;
    if (payload_len + 24 > static_cast<size_t>(n)) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"length_mismatch\"}");
        return false;
    }

    psram_string id;
    bool ok = parseListIdentityPayloadPSRAM(rx + 24, payload_len, id);
    if (!ok) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"parse\"}");
        return false;
    }
    // Align identity IP to requested target to avoid sockaddr endianness ambiguity.
    cJSON* obj = cJSON_Parse(id.c_str());
    if (obj && cJSON_IsObject(obj)) {
        cJSON* old_ip = cJSON_GetObjectItem(obj, "ip");
        if (cJSON_IsString(old_ip) && old_ip->valuestring && strcmp(old_ip->valuestring, ip_buf) != 0) {
            cJSON_AddStringToObject(obj, "reported_ip", old_ip->valuestring);
            cJSON_ReplaceItemInObject(obj, "ip", cJSON_CreateString(ip_buf));
        } else if (!cJSON_IsString(old_ip)) {
            cJSON_AddStringToObject(obj, "ip", ip_buf);
        }
        char* patched = cJSON_PrintUnformatted(obj);
        cJSON_Delete(obj);
        if (patched) {
            out_json = PSRAMUtils::createPSRAMString(patched);
            free(patched);
            return !out_json.empty();
        }
    } else if (obj) {
        cJSON_Delete(obj);
    }
    out_json = std::move(id);
    return true;
}

bool EtherNetIPPlugin::activeListIdentity(const std::string& target, std::string& out_json) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string json_ps;
    bool ok = activeListIdentityPSRAM(target_ps, json_ps);
    out_json = PSRAMUtils::fromPSRAMString(json_ps);
    return ok;
}

std::string EtherNetIPPlugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    if (target_ps.empty() && !target.empty()) {
        return std::string{};
    }
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool EtherNetIPPlugin::doVulnerabilityScanPSRAM(const psram_string& target,
                                                psram_string& out_report) {
    // Keep legacy text report for direct calls (no wrapper JSON).
    if (target.empty() || target[0] != '{') {
        psram_string report = legacyDoVulnerabilityScan(target);
        if (report.empty()) {
            out_report.clear();
            return false;
        }
        out_report = std::move(report);
        return true;
    }

    PSRAMJsonParser::PSRAMContext json_ctx;
    const uint64_t t0_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000ULL);
    const size_t mem_internal_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t mem_psram_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    psram_string target_label = target;
    uint32_t timeout_ms = 2000U;
    PSRAMAllocator<psram_string> alloc;
    psram_string_vector scan_types(alloc);

    cJSON* req = PSRAMJsonParser::parseInPSRAM(target.c_str(), target.size());
    if (req) {
        if (auto v = cJSON_GetObjectItem(req, "target"); v && cJSON_IsString(v) && v->valuestring) {
            target_label = PSRAMUtils::createPSRAMString(v->valuestring);
        }
        if (auto v = cJSON_GetObjectItem(req, "timeout_ms"); v && cJSON_IsNumber(v)) {
            double d = v->valuedouble;
            if (d < 300) d = 300;
            if (d > 15000) d = 15000;
            timeout_ms = static_cast<uint32_t>(d);
        }
        if (auto arr = cJSON_GetObjectItem(req, "scan_types"); arr && cJSON_IsArray(arr)) {
            cJSON* it = nullptr;
            cJSON_ArrayForEach(it, arr) {
                if (it && cJSON_IsString(it) && it->valuestring) {
                    scan_types.push_back(PSRAMUtils::createPSRAMString(it->valuestring));
                }
            }
        }
        cJSON_Delete(req);
    }

    if (scan_types.empty()) {
        scan_types.push_back(PSRAMUtils::createPSRAMString("identity_integrity"));
        scan_types.push_back(PSRAMUtils::createPSRAMString("session_security"));
        scan_types.push_back(PSRAMUtils::createPSRAMString("cip_security_advertisement"));
        scan_types.push_back(PSRAMUtils::createPSRAMString("list_services_consistency"));
        scan_types.push_back(PSRAMUtils::createPSRAMString("io_channel_exposure"));
    }

    auto wants = [&](const char* id) -> bool {
        if (!id) return false;
        for (const auto& s : scan_types) {
            if (s == id) return true;
        }
        return false;
    };

    psram_string ip_ps;
    uint16_t port = 0;
    if (!parseTarget(target_label, ip_ps, port)) {
        out_report = PSRAMUtils::createPSRAMString(
            "{\"scan\":{\"protocol\":\"ethernetip\",\"status\":\"invalid_target\"},\"findings\":[],\"summary\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"info\":1},\"risk_assessment\":{\"overall_risk\":\"info\",\"highest_severity\":\"INFO\",\"highest_risk_finding\":\"invalid_target\"}}");
        return true;
    }

    char ip_buf[64] = {0};
    PSRAMUtils::copyToStackBuffer(ip_buf, sizeof(ip_buf), ip_ps);

    // Identity probe (safe)
    psram_string identity_json;
    bool identity_ok = activeListIdentityPSRAM(target_label, identity_json);
    cJSON* identity_obj = nullptr;
    psram_string asset_vendor = PSRAMUtils::createPSRAMString("Unknown");
    psram_string asset_product = PSRAMUtils::createPSRAMString("Unknown");
    psram_string asset_revision = PSRAMUtils::createPSRAMString("");
    int asset_vendor_id = -1;
    int asset_product_code = -1;
    uint32_t asset_serial = 0;
    psram_string asset_reported_ip;

    if (identity_ok) {
        identity_obj = cJSON_Parse(identity_json.c_str());
        if (identity_obj && cJSON_IsObject(identity_obj)) {
            if (auto v = cJSON_GetObjectItem(identity_obj, "product_name"); cJSON_IsString(v) && v->valuestring) {
                asset_product = sanitizePrintablePSRAM(v->valuestring, strlen(v->valuestring));
            }
            if (auto v = cJSON_GetObjectItem(identity_obj, "revision"); cJSON_IsString(v) && v->valuestring) {
                asset_revision = sanitizePrintablePSRAM(v->valuestring, strlen(v->valuestring));
            }
            if (auto v = cJSON_GetObjectItem(identity_obj, "vendor_id"); cJSON_IsNumber(v)) asset_vendor_id = v->valueint;
            if (auto v = cJSON_GetObjectItem(identity_obj, "product_code"); cJSON_IsNumber(v)) asset_product_code = v->valueint;
            if (auto v = cJSON_GetObjectItem(identity_obj, "serial"); cJSON_IsNumber(v)) asset_serial = static_cast<uint32_t>(v->valuedouble);
            if (auto v = cJSON_GetObjectItem(identity_obj, "reported_ip"); cJSON_IsString(v) && v->valuestring) {
                asset_reported_ip = PSRAMUtils::createPSRAMString(v->valuestring);
            }
            if (asset_vendor_id == 42) asset_vendor = PSRAMUtils::createPSRAMString("Rockwell/ODVA");
            else if (asset_vendor_id > 0) {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "Vendor ID %d", asset_vendor_id);
                asset_vendor = PSRAMUtils::createPSRAMString(tmp);
            }
        } else if (identity_obj) {
            cJSON_Delete(identity_obj);
            identity_obj = nullptr;
        }
    }

    bool need_session = wants("session_security") ||
                        wants("cip_security_advertisement") ||
                        wants("list_services_consistency") ||
                        wants("io_channel_exposure") ||
                        wants("explicit_write_capability_assessment") ||
                        wants("reset_capability_assessment") ||
                        wants("forward_open_risk_assessment");

    bool session_ok = false;
    psram_string session_error = PSRAMUtils::createPSRAMString("");
    bool list_services_ok = false;
    bool list_interfaces_ok = false;
    bool cip_security_advertised = false;
    psram_string list_services_error = PSRAMUtils::createPSRAMString("");
    psram_string list_interfaces_error = PSRAMUtils::createPSRAMString("");
    psram_vector<psram_string> services;
    psram_vector<psram_string> interfaces;
    uint32_t session_handle = 0;

    struct Probe {
        bool attempted = false;
        bool response_parsed = false;
        bool success = false;
        uint8_t general_status = 0xFF;
        psram_string error = PSRAMUtils::createPSRAMString("");
    };
    Probe read_probe, write_probe, reset_probe, fwd_probe;

    auto appendLE16 = [](psram_vector<uint8_t>& b, uint16_t v) {
        b.push_back(static_cast<uint8_t>(v & 0xFF));
        b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto appendLE32 = [](psram_vector<uint8_t>& b, uint32_t v) {
        b.push_back(static_cast<uint8_t>(v & 0xFF));
        b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };

    int sock = -1;
    auto send_explicit = [&](uint8_t svc, const psram_vector<uint8_t>& path, const psram_vector<uint8_t>& data, Probe& out) {
        out.attempted = true;
        const bool state_changing = (svc == CIP_SVC_SET_ATTR_SINGLE || svc == CIP_SVC_RESET);
        if (state_changing && (!sec_ || !sec_->isFuzzingAllowed())) {
            out.attempted = false;
            out.error = PSRAMUtils::createPSRAMString(
                sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
            return;
        }
        if (sock < 0 || session_handle == 0) {
            out.error = PSRAMUtils::createPSRAMString("session_not_ready");
            return;
        }
        psram_vector<uint8_t> path_local = path;
        if (path_local.size() % 2 != 0) path_local.push_back(0x00);

        psram_vector<uint8_t> cip_req;
        cip_req.reserve(path_local.size() + data.size() + 2);
        cip_req.push_back(svc);
        cip_req.push_back(static_cast<uint8_t>(path_local.size() / 2));
        cip_req.insert(cip_req.end(), path_local.begin(), path_local.end());
        cip_req.insert(cip_req.end(), data.begin(), data.end());

        psram_vector<uint8_t> cpf;
        cpf.reserve(cip_req.size() + 12);
        appendLE32(cpf, 0);
        appendLE16(cpf, 0);
        appendLE16(cpf, 2);
        appendLE16(cpf, CPF_NULL_ADDR);
        appendLE16(cpf, 0);
        appendLE16(cpf, CPF_UNCONNECTED_DATA);
        appendLE16(cpf, static_cast<uint16_t>(cip_req.size()));
        cpf.insert(cpf.end(), cip_req.begin(), cip_req.end());

        psram_vector<uint8_t> pkt(24 + cpf.size());
        buildEncapHeader(pkt.data(), ENIP_CMD_SENDRRDATA, static_cast<uint16_t>(cpf.size()), session_handle);
        memcpy(pkt.data() + 24, cpf.data(), cpf.size());
        if (::send(sock, pkt.data(), pkt.size(), 0) != static_cast<ssize_t>(pkt.size())) {
            out.error = PSRAMUtils::createPSRAMString("send_failed");
            return;
        }
        uint8_t rx[768];
        ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
        if (n < 24) {
            out.error = PSRAMUtils::createPSRAMString("short_response");
            return;
        }
        if (le16(rx + 0) != ENIP_CMD_SENDRRDATA || le32(rx + 8) != 0) {
            out.error = PSRAMUtils::createPSRAMString("encap_error");
            return;
        }
        uint16_t plen = le16(rx + 2);
        if (24 + plen > static_cast<size_t>(n) || plen < 8) {
            out.error = PSRAMUtils::createPSRAMString("length_mismatch");
            return;
        }
        const uint8_t* p = rx + 24;
        uint16_t items = le16(p + 6);
        size_t pos = 8;
        for (uint16_t i = 0; i < items && pos + 4 <= plen; ++i) {
            uint16_t type = le16(p + pos + 0);
            uint16_t ilen = le16(p + pos + 2);
            pos += 4;
            if (pos + ilen > plen) break;
            if (type == CPF_UNCONNECTED_DATA && ilen >= 4) {
                const uint8_t* cip = p + pos;
                if ((cip[0] & 0x7F) != svc) {
                    out.error = PSRAMUtils::createPSRAMString("service_mismatch");
                    return;
                }
                out.response_parsed = true;
                out.general_status = cip[2];
                out.success = (out.general_status == 0x00);
                if (!out.success) {
                    char gs[48];
                    snprintf(gs, sizeof(gs), "general_status_0x%02X", static_cast<unsigned>(out.general_status));
                    out.error = PSRAMUtils::createPSRAMString(gs);
                }
                return;
            }
            pos += ilen;
        }
        out.error = PSRAMUtils::createPSRAMString("cpf_data_missing");
    };

    if (need_session) {
        do {
            sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock < 0) { session_error = PSRAMUtils::createPSRAMString("socket_failed"); break; }
            configureTcpSocket(sock);
            struct timeval tv{ .tv_sec = static_cast<int>(timeout_ms / 1000U), .tv_usec = static_cast<int>((timeout_ms % 1000U) * 1000U) };
            ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
            esp_netif_ip_info_t eth_ip{};
            if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
                session_error = PSRAMUtils::createPSRAMString("ethernet_not_ready"); break;
            }
            sockaddr_in remote{}; remote.sin_family = AF_INET; remote.sin_port = htons(port);
            if (::inet_aton(ip_buf, &remote.sin_addr) == 0) { session_error = PSRAMUtils::createPSRAMString("invalid_ip"); break; }
            if (::connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) { session_error = PSRAMUtils::createPSRAMString("connect_failed"); break; }

            uint8_t reg_req[28];
            buildEncapHeader(reg_req, ENIP_CMD_REGSESSION, 4, 0);
            reg_req[24] = 0x01; reg_req[25] = 0x00; reg_req[26] = 0x00; reg_req[27] = 0x00;
            if (::send(sock, reg_req, sizeof(reg_req), 0) != static_cast<ssize_t>(sizeof(reg_req))) { session_error = PSRAMUtils::createPSRAMString("register_send_failed"); break; }
            uint8_t reg_resp[64];
            ssize_t rn = ::recv(sock, reg_resp, sizeof(reg_resp), 0);
            if (rn < 24 || le16(reg_resp + 0) != ENIP_CMD_REGSESSION || le32(reg_resp + 8) != 0) {
                session_error = PSRAMUtils::createPSRAMString("register_failed"); break;
            }
            session_handle = le32(reg_resp + 4);
            if (session_handle == 0) { session_error = PSRAMUtils::createPSRAMString("zero_session_handle"); break; }
            session_ok = true;

            if (wants("cip_security_advertisement") || wants("list_services_consistency")) {
                uint8_t ls_req[24];
                buildEncapHeader(ls_req, ENIP_CMD_LISTSERVICES, 0, session_handle);
                if (::send(sock, ls_req, sizeof(ls_req), 0) == static_cast<ssize_t>(sizeof(ls_req))) {
                    uint8_t ls_resp[768];
                    ssize_t ln = ::recv(sock, ls_resp, sizeof(ls_resp), 0);
                    if (ln >= 24 && le16(ls_resp + 0) == ENIP_CMD_LISTSERVICES) {
                        uint16_t len = le16(ls_resp + 2);
                        if (24 + len <= static_cast<size_t>(ln)) {
                            list_services_ok = parseListServicesForSecurity(ls_resp + 24, len, cip_security_advertised, &services);
                            if (!list_services_ok) list_services_error = PSRAMUtils::createPSRAMString("parse_error");
                        } else list_services_error = PSRAMUtils::createPSRAMString("length_mismatch");
                    } else list_services_error = PSRAMUtils::createPSRAMString("unexpected_response");
                } else list_services_error = PSRAMUtils::createPSRAMString("send_failed");
            }

            if (wants("list_services_consistency")) {
                uint8_t li_req[24];
                buildEncapHeader(li_req, ENIP_CMD_LISTINTERF, 0, session_handle);
                if (::send(sock, li_req, sizeof(li_req), 0) == static_cast<ssize_t>(sizeof(li_req))) {
                    uint8_t li_resp[512];
                    ssize_t lin = ::recv(sock, li_resp, sizeof(li_resp), 0);
                    if (lin >= 24 && le16(li_resp + 0) == ENIP_CMD_LISTINTERF) {
                        uint16_t len = le16(li_resp + 2);
                        if (24 + len <= static_cast<size_t>(lin)) {
                            list_interfaces_ok = parseListInterfacesPayload(li_resp + 24, len, &interfaces);
                            if (!list_interfaces_ok) list_interfaces_error = PSRAMUtils::createPSRAMString("parse_error");
                        } else list_interfaces_error = PSRAMUtils::createPSRAMString("length_mismatch");
                    } else list_interfaces_error = PSRAMUtils::createPSRAMString("unexpected_response");
                } else list_interfaces_error = PSRAMUtils::createPSRAMString("send_failed");
            }

            if (wants("io_channel_exposure")) {
                psram_vector<uint8_t> p = {0x20, 0x01, 0x24, 0x01, 0x30, 0x01};
                psram_vector<uint8_t> d;
                send_explicit(CIP_SVC_GET_ATTR_SINGLE, p, d, read_probe);
            }
            if (wants("explicit_write_capability_assessment")) {
                psram_vector<uint8_t> p = {0x20, 0x01, 0x24, 0x01, 0x30, 0x01};
                psram_vector<uint8_t> d = {0x00, 0x00};
                send_explicit(CIP_SVC_SET_ATTR_SINGLE, p, d, write_probe);
            }
            if (wants("reset_capability_assessment")) {
                psram_vector<uint8_t> p = {0x20, 0x01, 0x24, 0x01};
                psram_vector<uint8_t> d;
                send_explicit(CIP_SVC_RESET, p, d, reset_probe);
            }
            if (wants("forward_open_risk_assessment")) {
                psram_vector<uint8_t> p = {0x20, 0x06, 0x24, 0x01};
                psram_vector<uint8_t> d(24, 0x00);
                send_explicit(0x54, p, d, fwd_probe);
            }
        } while (false);
    }

    if (session_handle != 0 && sock >= 0) {
        uint8_t unreg[24];
        buildEncapHeader(unreg, ENIP_CMD_UNREGSESS, 0, session_handle);
        (void)::send(sock, unreg, sizeof(unreg), 0);
    }
    if (sock >= 0) ::close(sock);

    cJSON* findings = cJSON_CreateArray();
    uint32_t tests_executed = 0;
    uint32_t tests_skipped = 0;
    uint32_t sev_critical = 0, sev_high = 0, sev_medium = 0, sev_low = 0, sev_info = 0;
    const char* highest_sev = "INFO";
    psram_string highest_id = PSRAMUtils::createPSRAMString("");
    auto rank = [](const char* s) -> int {
        if (!s) return 0;
        if (strcmp(s, "CRITICAL") == 0) return 5;
        if (strcmp(s, "HIGH") == 0) return 4;
        if (strcmp(s, "MEDIUM") == 0) return 3;
        if (strcmp(s, "LOW") == 0) return 2;
        return 1;
    };
    auto sev_level = [](const char* s) -> LogLevel {
        if (!s) return LogLevel::INFO;
        if (strcmp(s, "CRITICAL") == 0 || strcmp(s, "HIGH") == 0) return LogLevel::ERROR;
        if (strcmp(s, "MEDIUM") == 0 || strcmp(s, "LOW") == 0) return LogLevel::WARNING;
        return LogLevel::INFO;
    };
    auto bump = [&](const char* s) {
        if (!s) return;
        if (strcmp(s, "CRITICAL") == 0) sev_critical++;
        else if (strcmp(s, "HIGH") == 0) sev_high++;
        else if (strcmp(s, "MEDIUM") == 0) sev_medium++;
        else if (strcmp(s, "LOW") == 0) sev_low++;
        else sev_info++;
    };
    auto add_finding = [&](const char* id, const char* name, const char* sev, const char* status, const char* desc, const char* rec) {
        cJSON* f = cJSON_CreateObject();
        cJSON_AddStringToObject(f, "id", id ? id : "unknown");
        cJSON_AddStringToObject(f, "name", name ? name : "Finding");
        cJSON_AddStringToObject(f, "severity", sev ? sev : "INFO");
        cJSON_AddStringToObject(f, "status", status ? status : "detected");
        cJSON_AddStringToObject(f, "description", desc ? desc : "");
        cJSON_AddStringToObject(f, "recommendation", rec ? rec : "");

        const char* category = "protocol_assessment";
        const char* risk_domain = "hardening";
        const char* cwe = "";
        const char* reference = "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/";
        if (id && strstr(id, "cip_security_not_advertised")) {
            category = "transport_security";
            risk_domain = "confidentiality";
            cwe = "CWE-319";
        } else if (id && (strstr(id, "write_capability_exposed") || strstr(id, "reset_capability_exposed"))) {
            category = "unauthorized_control";
            risk_domain = "integrity_availability";
            cwe = "CWE-284";
        } else if (id && strstr(id, "forward_open_capability_exposed")) {
            category = "session_control";
            risk_domain = "availability";
            cwe = "CWE-306";
        } else if (id && strstr(id, "identity_reported_ip_mismatch")) {
            category = "asset_integrity";
            risk_domain = "integrity";
            cwe = "CWE-345";
        }
        cJSON_AddStringToObject(f, "category", category);
        cJSON_AddStringToObject(f, "risk_domain", risk_domain);
        cJSON* cwe_arr = cJSON_CreateArray();
        if (cwe && cwe[0]) cJSON_AddItemToArray(cwe_arr, cJSON_CreateString(cwe));
        cJSON_AddItemToObject(f, "cwe", cwe_arr);
        cJSON* cve_arr = cJSON_CreateArray();
        cJSON_AddItemToObject(f, "cve", cve_arr);
        cJSON* refs_arr = cJSON_CreateArray();
        cJSON_AddItemToArray(refs_arr, cJSON_CreateString(reference));
        cJSON_AddItemToObject(f, "references", refs_arr);

        cJSON_AddItemToArray(findings, f);
        bump(sev);
        if (rank(sev) > rank(highest_sev)) {
            highest_sev = sev ? sev : "INFO";
            highest_id = PSRAMUtils::createPSRAMString(id ? id : "unknown");
        }
        if (rep_) {
            char* js = cJSON_PrintUnformatted(f);
            if (js) {
                reportVulnerabilityPSRAM(target_label, PSRAMUtils::createPSRAMString(js), psram_string{}, sev_level(sev));
                free(js);
            }
        }
    };

    if (wants("identity_integrity")) {
        tests_executed++;
        if (!identity_ok) {
            add_finding("enip_identity_probe_failed", "ListIdentity probe failed", "INFO", "not_executed",
                        identity_json.empty() ? "ListIdentity did not return a valid payload." : identity_json.c_str(),
                        "Verify the target and EtherNet/IP reachability (UDP/TCP 44818).");
        } else if (!asset_reported_ip.empty() && asset_reported_ip != ip_ps) {
            add_finding("enip_identity_reported_ip_mismatch", "Identity reported IP mismatch", "LOW", "detected",
                        "The IP in the Identity payload does not match the observed target/source IP.",
                        "Validate the device network configuration and possible spoofing/NAT phenomena.");
        }
    }

    if (wants("session_security")) {
        tests_executed++;
        if (!session_ok) {
            add_finding("enip_session_setup_failed", "Session setup failed", "MEDIUM", "detected",
                        session_error.empty() ? "Unable to establish an EtherNet/IP session." : session_error.c_str(),
                        "Verify the endpoint, ACLs and TCP/44818 reachability.");
        }
    }
    if (wants("cip_security_advertisement")) {
        if (list_services_ok) {
            tests_executed++;
            if (!cip_security_advertised) {
                add_finding("enip_cip_security_not_advertised", "CIP Security not advertised", "HIGH", "detected",
                            "The endpoint does not advertise CIP Security services; the explicit channel may be unprotected.",
                            "Enable CIP Security where supported and strictly segment the network.");
            }
        } else {
            tests_skipped++;
        }
    }
    if (wants("list_services_consistency")) {
        tests_executed++;
        if (!list_services_ok) {
            add_finding("enip_list_services_failed", "ListServices failed", "INFO", "not_executed",
                        list_services_error.empty() ? "ListServices did not produce parseable output." : list_services_error.c_str(),
                        "Analyze the target's ENIP stack behavior.");
        } else if (services.empty()) {
            add_finding("enip_list_services_empty", "ListServices returned no services", "LOW", "detected",
                        "Endpoint reachable but with no declared services.",
                        "Verify firmware/device profile consistency.");
        }
        if (!list_interfaces_ok) {
            add_finding("enip_list_interfaces_failed", "ListInterfaces failed", "INFO", "not_executed",
                        list_interfaces_error.empty() ? "ListInterfaces not parseable." : list_interfaces_error.c_str(),
                        "Useful baseline data even if not always supported.");
        }
    }
    if (wants("io_channel_exposure")) {
        if (read_probe.attempted) tests_executed++; else tests_skipped++;
        if (read_probe.attempted && read_probe.success) {
            add_finding("enip_explicit_read_exposed", "Explicit read exposure detected", "MEDIUM", "detected",
                        "GetAttributeSingle on Identity accepted (general status 0x00).",
                        "Restrict ENIP access and use channel protection policies.");
        }
    }
    if (wants("explicit_write_capability_assessment")) {
        if (write_probe.attempted) tests_executed++; else tests_skipped++;
        if (write_probe.attempted && write_probe.success) {
            add_finding("enip_write_capability_exposed", "Write capability accepted", "CRITICAL", "detected",
                        "SetAttributeSingle responded successfully (general status 0x00).",
                        "Reduce the attack surface: strict ACLs and industrial access control.");
        }
    }
    if (wants("reset_capability_assessment")) {
        if (reset_probe.attempted) tests_executed++; else tests_skipped++;
        if (reset_probe.attempted && reset_probe.success) {
            add_finding("enip_reset_capability_exposed", "Reset capability accepted", "CRITICAL", "detected",
                        "CIP Reset responded successfully (general status 0x00).",
                        "High operational risk: isolate the control paths immediately.");
        }
    }
    if (wants("forward_open_risk_assessment")) {
        if (fwd_probe.attempted) tests_executed++; else tests_skipped++;
        if (fwd_probe.attempted && fwd_probe.success) {
            add_finding("enip_forward_open_capability_exposed", "ForwardOpen capability accepted", "HIGH", "detected",
                        "ForwardOpen responded successfully (general status 0x00).",
                        "Restrict unauthorized originators and harden the connection manager.");
        }
    }

    // Build final JSON
    cJSON* root = cJSON_CreateObject();
    cJSON* scan = cJSON_CreateObject();
    cJSON_AddStringToObject(scan, "protocol", "ethernetip");
    cJSON_AddStringToObject(scan, "target", ip_ps.c_str());
    cJSON_AddNumberToObject(scan, "port", port);
    cJSON_AddStringToObject(scan, "interface", "ETH_DEF");
    cJSON_AddNumberToObject(scan, "timeout_ms", timeout_ms);
    cJSON_AddNumberToObject(scan, "timestamp_ms", static_cast<double>(t0_ms));
    cJSON_AddBoolToObject(scan, "session_ok", session_ok);
    cJSON_AddItemToObject(root, "scan", scan);

    cJSON* asset = cJSON_CreateObject();
    cJSON_AddStringToObject(asset, "vendor", asset_vendor.c_str());
    cJSON_AddStringToObject(asset, "product", asset_product.c_str());
    cJSON_AddStringToObject(asset, "revision", asset_revision.c_str());
    cJSON_AddNumberToObject(asset, "serial", static_cast<double>(asset_serial));
    cJSON_AddNumberToObject(asset, "vendor_id", asset_vendor_id);
    cJSON_AddNumberToObject(asset, "product_code", asset_product_code);
    cJSON_AddItemToObject(root, "asset", asset);

    cJSON* types = cJSON_CreateArray();
    for (const auto& st : scan_types) cJSON_AddItemToArray(types, cJSON_CreateString(st.c_str()));
    cJSON_AddItemToObject(root, "scan_types_requested", types);

    cJSON* fingerprint = cJSON_CreateObject();
    cJSON_AddBoolToObject(fingerprint, "identity_ok", identity_ok);
    cJSON_AddBoolToObject(fingerprint, "list_services_ok", list_services_ok);
    cJSON_AddBoolToObject(fingerprint, "list_interfaces_ok", list_interfaces_ok);
    cJSON_AddBoolToObject(fingerprint, "cip_security_advertised", cip_security_advertised);
    if (identity_obj && cJSON_IsObject(identity_obj)) {
        cJSON_AddItemToObject(fingerprint, "identity", cJSON_Duplicate(identity_obj, cJSON_True));
    }
    cJSON* services_arr = cJSON_CreateArray();
    for (const auto& s : services) cJSON_AddItemToArray(services_arr, cJSON_CreateString(s.c_str()));
    cJSON_AddItemToObject(fingerprint, "encapsulation_services", services_arr);
    cJSON* if_arr = cJSON_CreateArray();
    for (const auto& s : interfaces) cJSON_AddItemToArray(if_arr, cJSON_CreateString(s.c_str()));
    cJSON_AddItemToObject(fingerprint, "encapsulation_interfaces", if_arr);
    cJSON_AddItemToObject(root, "fingerprint", fingerprint);

    auto probe_to_json = [](const Probe& p) -> cJSON* {
        cJSON* o = cJSON_CreateObject();
        cJSON_AddBoolToObject(o, "attempted", p.attempted);
        cJSON_AddBoolToObject(o, "response_parsed", p.response_parsed);
        cJSON_AddBoolToObject(o, "success", p.success);
        cJSON_AddNumberToObject(o, "general_status", static_cast<int>(p.general_status));
        cJSON_AddStringToObject(o, "error", p.error.c_str());
        return o;
    };
    cJSON* active = cJSON_CreateObject();
    cJSON_AddItemToObject(active, "read_probe", probe_to_json(read_probe));
    cJSON_AddItemToObject(active, "write_probe", probe_to_json(write_probe));
    cJSON_AddItemToObject(active, "reset_probe", probe_to_json(reset_probe));
    cJSON_AddItemToObject(active, "forward_open_probe", probe_to_json(fwd_probe));
    cJSON_AddItemToObject(root, "active_assessments", active);

    cJSON_AddItemToObject(root, "findings", findings);

    cJSON* summary = cJSON_CreateObject();
    cJSON_AddNumberToObject(summary, "critical", sev_critical);
    cJSON_AddNumberToObject(summary, "high", sev_high);
    cJSON_AddNumberToObject(summary, "medium", sev_medium);
    cJSON_AddNumberToObject(summary, "low", sev_low);
    cJSON_AddNumberToObject(summary, "info", sev_info);
    cJSON_AddNumberToObject(summary, "tests_executed", tests_executed);
    cJSON_AddNumberToObject(summary, "tests_skipped", tests_skipped);
    cJSON_AddItemToObject(root, "summary", summary);

    const char* overall = "info";
    if (sev_critical > 0) overall = "critical";
    else if (sev_high > 0) overall = "high";
    else if (sev_medium > 0) overall = "medium";
    else if (sev_low > 0) overall = "low";

    cJSON* risk = cJSON_CreateObject();
    cJSON_AddStringToObject(risk, "overall_risk", overall);
    cJSON_AddStringToObject(risk, "highest_severity", highest_sev);
    cJSON_AddStringToObject(risk, "highest_risk_finding", highest_id.c_str());
    cJSON_AddItemToObject(root, "risk_assessment", risk);

    cJSON_AddNumberToObject(scan, "duration_ms", static_cast<double>((esp_timer_get_time() / 1000ULL) - t0_ms));

    cJSON* mem = cJSON_CreateObject();
    cJSON_AddNumberToObject(mem, "internal_before", static_cast<double>(mem_internal_before));
    cJSON_AddNumberToObject(mem, "internal_after", static_cast<double>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
    cJSON_AddNumberToObject(mem, "internal_largest_after", static_cast<double>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)));
    cJSON_AddNumberToObject(mem, "psram_before", static_cast<double>(mem_psram_before));
    cJSON_AddNumberToObject(mem, "psram_after", static_cast<double>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM)));
    cJSON_AddItemToObject(root, "memory", mem);

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (identity_obj) cJSON_Delete(identity_obj);
    if (!json) {
        out_report.clear();
        return false;
    }
    out_report = PSRAMUtils::createPSRAMString(json);
    free(json);
    return !out_report.empty();
}

psram_string EtherNetIPPlugin::legacyDoVulnerabilityScan(const psram_string& target) {
    psram_string ip_ps;
    uint16_t port = 0;
    if (!parseTarget(target, ip_ps, port)) {
        return psram_string{};
    }

    psram_string target_ps = target;
    char ip_buf[64] = {0};
    PSRAMUtils::copyToStackBuffer(ip_buf, sizeof(ip_buf), ip_ps);

    PSRAMJsonParser::PSRAMContext json_ctx;

    // Use PSRAM for all allocations to avoid IRAM consumption
    struct FindingEntry { psram_string id; psram_string detail; LogLevel level; };
    psram_vector<FindingEntry> findings;

    // JSON escape lambda using PSRAM to avoid IRAM
    auto jsonEscape = [](const char* val) -> psram_string {
        if (!val) return PSRAMUtils::createPSRAMString("");
        psram_string out;
        out.reserve(strlen(val) * 2);  // Reserve for worst case (all chars escaped)
        for (const char* p = val; *p; ++p) {
            char c = *p;
            switch (c) {
                case '"': out += PSRAMUtils::createPSRAMString("\\\""); break;
                case '\\': out += PSRAMUtils::createPSRAMString("\\\\"); break;
                case '\b': out += PSRAMUtils::createPSRAMString("\\b"); break;
                case '\f': out += PSRAMUtils::createPSRAMString("\\f"); break;
                case '\n': out += PSRAMUtils::createPSRAMString("\\n"); break;
                case '\r': out += PSRAMUtils::createPSRAMString("\\r"); break;
                case '\t': out += PSRAMUtils::createPSRAMString("\\t"); break;
                default: {
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned char>(c));
                        out += PSRAMUtils::createPSRAMString(buf);
                    } else {
                        out.push_back(c);
                    }
                }
            }
        }
        return out;
    };

    // Push finding lambda using PSRAM to avoid IRAM
    auto pushFinding = [&](const char* id, const char* detail, LogLevel level) {
        findings.push_back({
            PSRAMUtils::createPSRAMString(id),
            PSRAMUtils::createPSRAMString(detail),
            level
        });

        // Build JSON using PSRAM buffer instead of stringstream
        PSRAMUtils::ScopedBuffer json_buf(512);
        if (json_buf.valid()) {
            psram_string escaped = jsonEscape(detail);
            snprintf(json_buf.get(), json_buf.size(),
                     "{\"issue\":\"%s\",\"detail\":\"%s\"}",
                     id, escaped.c_str());
            psram_string payload = PSRAMUtils::createPSRAMString(json_buf.get());
            reportVulnerabilityPSRAM(target_ps, payload, psram_string{}, level);
        }
    };

    // Convert bytes to hex using PSRAM buffer instead of stringstream
    auto bytesToHex = [](const uint8_t* data, size_t len) -> psram_string {
        if (!data || len == 0) {
            return PSRAMUtils::createPSRAMString("");
        }

        // Allocate PSRAM buffer for hex string (3 bytes per input byte: "XX ")
        size_t hex_size = len * 3;
        char* hex_buf = (char*)heap_caps_malloc(hex_size + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!hex_buf) return PSRAMUtils::createPSRAMString("");

        char* p = hex_buf;
        for (size_t i = 0; i < len; ++i) {
            if (i > 0) *p++ = ' ';
            p += snprintf(p, 3, "%02X", static_cast<unsigned>(data[i]));
        }
        *p = '\0';

        psram_string result = PSRAMUtils::createPSRAMString(hex_buf);
        heap_caps_free(hex_buf);
        return result;
    };

    auto appendLE16 = [](psram_vector<uint8_t>& buf, uint16_t v) {
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto appendLE32 = [](psram_vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };

    psram_string identity_json;
    bool identity_ok = activeListIdentityPSRAM(target_ps, identity_json);
    if (!identity_ok) {
        PSRAMUtils::ScopedBuffer err_buf(256);
        if (err_buf.valid()) {
            snprintf(err_buf.get(), err_buf.size(), "ListIdentity failed (%s)", identity_json.c_str());
            pushFinding("list_identity_failed", err_buf.get(), LogLevel::WARNING);
        }
    } else {
        PSRAMUtils::ScopedBuffer probe_buf(1024);
        if (probe_buf.valid()) {
            snprintf(probe_buf.get(), probe_buf.size(),
                     "{\"probe\":\"list_identity\",\"payload\":%s}",
                     identity_json.c_str());
            psram_string payload = PSRAMUtils::createPSRAMString(probe_buf.get());
            reportVulnerabilityPSRAM(target_ps, payload, psram_string{}, LogLevel::INFO);
        }
    }

    psram_string device_name;
    int vendor_id = -1;
    int product_code = -1;
    psram_string revision;
    uint32_t serial = 0;
    if (identity_ok) {
        cJSON* root = cJSON_Parse(identity_json.c_str());
        if (root) {
            cJSON* item = cJSON_GetObjectItem(root, "product_name");
            if (cJSON_IsString(item) && item->valuestring) {
                device_name = sanitizePrintablePSRAM(item->valuestring, strlen(item->valuestring));
            }
            item = cJSON_GetObjectItem(root, "vendor_id");
            if (cJSON_IsNumber(item)) {
                vendor_id = item->valueint;
            }
            item = cJSON_GetObjectItem(root, "product_code");
            if (cJSON_IsNumber(item)) {
                product_code = item->valueint;
            }
            item = cJSON_GetObjectItem(root, "revision");
            if (cJSON_IsString(item) && item->valuestring) {
                revision = sanitizePrintablePSRAM(item->valuestring, strlen(item->valuestring));
            }
            item = cJSON_GetObjectItem(root, "serial");
            if (cJSON_IsNumber(item)) {
                serial = static_cast<uint32_t>(item->valuedouble);
            }
            cJSON_Delete(root);
        }
    }

    bool session_ok = false;
    bool list_services_ok = false;
    bool cip_security_advertised = false;
    psram_string list_services_error;
    psram_vector<psram_string> services;

    bool explicit_read_sent = false;
    bool explicit_read_ok = false;
    uint8_t explicit_general_status = 0xFF;
    psram_vector<uint8_t> explicit_payload;
    psram_string explicit_error;

    psram_string connect_error;
    int sock = -1;
    uint32_t session_handle = 0;

    do {
        sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            connect_error = PSRAMUtils::createPSRAMString("socket");
            break;
        }

        configureTcpSocket(sock);

        struct timeval tv{ .tv_sec = 2, .tv_usec = 0 };
        ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_netif_ip_info_t eth_ip{};
        if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
            connect_error = PSRAMUtils::createPSRAMString("ethernet_not_ready");
            break;
        }

        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (::inet_aton(ip_buf, &remote.sin_addr) == 0) {
            connect_error = PSRAMUtils::createPSRAMString("bad_ip");
            break;
        }
        if (::connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
            connect_error = PSRAMUtils::createPSRAMString("connect");
            break;
        }

        uint8_t reg_req[28];
        buildEncapHeader(reg_req, ENIP_CMD_REGSESSION, 4, 0);
        reg_req[24] = 0x01; reg_req[25] = 0x00;
        reg_req[26] = 0x00; reg_req[27] = 0x00;
        if (::send(sock, reg_req, sizeof(reg_req), 0) != static_cast<ssize_t>(sizeof(reg_req))) {
            connect_error = PSRAMUtils::createPSRAMString("register_send");
            break;
        }
        uint8_t reg_resp[64];
        ssize_t rlen = ::recv(sock, reg_resp, sizeof(reg_resp), 0);
        if (rlen < 24) {
            connect_error = PSRAMUtils::createPSRAMString("register_recv");
            break;
        }
        if (le16(reg_resp + 0) != ENIP_CMD_REGSESSION) {
            connect_error = PSRAMUtils::createPSRAMString("register_unexpected");
            break;
        }
        if (le32(reg_resp + 8) != 0) {
            connect_error = PSRAMUtils::createPSRAMString("register_status");
            break;
        }
        session_handle = le32(reg_resp + 4);
        if (session_handle == 0) {
            connect_error = PSRAMUtils::createPSRAMString("register_zero_handle");
            break;
        }
        session_ok = true;

        uint8_t ls_req[24];
        buildEncapHeader(ls_req, ENIP_CMD_LISTSERVICES, 0, session_handle);
        if (::send(sock, ls_req, sizeof(ls_req), 0) == static_cast<ssize_t>(sizeof(ls_req))) {
            uint8_t ls_resp[512];
            ssize_t ls_len = ::recv(sock, ls_resp, sizeof(ls_resp), 0);
            if (ls_len >= 24) {
                uint16_t lcmd = le16(ls_resp + 0);
                uint16_t llen = le16(ls_resp + 2);
                if (lcmd == ENIP_CMD_LISTSERVICES && 24 + llen <= static_cast<size_t>(ls_len)) {
                    const uint8_t* payload = ls_resp + 24;
                    bool cip_temp = false;
                    if (parseListServicesForSecurity(payload, llen, cip_temp, &services)) {
                        list_services_ok = true;
                        cip_security_advertised = cip_temp;
                    } else {
                        list_services_error = PSRAMUtils::createPSRAMString("parse_error");
                    }
                } else {
                    list_services_error = PSRAMUtils::createPSRAMString("unexpected_response");
                }
            } else {
                list_services_error = PSRAMUtils::createPSRAMString("no_response");
            }
        } else {
            list_services_error = PSRAMUtils::createPSRAMString("send_failed");
        }

        psram_vector<uint8_t> path = {0x20, 0x01, 0x24, 0x01, 0x30, 0x01};
        if (path.size() % 2 != 0) {
            path.push_back(0x00);
        }
        psram_vector<uint8_t> cip_request;
        cip_request.reserve(path.size() + 2);
        cip_request.push_back(CIP_SVC_GET_ATTR_SINGLE);
        cip_request.push_back(static_cast<uint8_t>(path.size() / 2));
        cip_request.insert(cip_request.end(), path.begin(), path.end());

        psram_vector<uint8_t> cpf_payload;
        cpf_payload.reserve(cip_request.size() + 12);
        appendLE32(cpf_payload, 0);
        appendLE16(cpf_payload, 0);
        appendLE16(cpf_payload, 2);
        appendLE16(cpf_payload, CPF_NULL_ADDR);
        appendLE16(cpf_payload, 0);
        appendLE16(cpf_payload, CPF_UNCONNECTED_DATA);
        appendLE16(cpf_payload, static_cast<uint16_t>(cip_request.size()));
        cpf_payload.insert(cpf_payload.end(), cip_request.begin(), cip_request.end());

        psram_vector<uint8_t> sendrr(24 + cpf_payload.size());
        buildEncapHeader(sendrr.data(), ENIP_CMD_SENDRRDATA, static_cast<uint16_t>(cpf_payload.size()), session_handle);
        std::memcpy(sendrr.data() + 24, cpf_payload.data(), cpf_payload.size());

        explicit_read_sent = true;
        if (::send(sock, sendrr.data(), sendrr.size(), 0) == static_cast<ssize_t>(sendrr.size())) {
            uint8_t rr_resp[768];
            ssize_t rr_len = ::recv(sock, rr_resp, sizeof(rr_resp), 0);
            if (rr_len >= 24) {
                uint16_t rcmd = le16(rr_resp + 0);
                uint16_t rlen = le16(rr_resp + 2);
                uint32_t rstatus = le32(rr_resp + 8);
                if (rcmd == ENIP_CMD_SENDRRDATA && rstatus == 0 && 24 + rlen <= static_cast<size_t>(rr_len)) {
                    const uint8_t* payload = rr_resp + 24;
                    size_t remain = rlen;
                    if (remain >= 8) {
                        uint16_t item_count = le16(payload + 6);
                        size_t pos = 8;
                        for (uint16_t idx = 0; idx < item_count && pos + 4 <= remain; ++idx) {
                            uint16_t type = le16(payload + pos + 0);
                            uint16_t ilen = le16(payload + pos + 2);
                            pos += 4;
                            if (pos + ilen > remain) {
                                break;
                            }
                            if (type == CPF_UNCONNECTED_DATA && ilen >= 4) {
                                const uint8_t* cip_resp = payload + pos;
                                uint8_t svc_resp = cip_resp[0];
                                if ((svc_resp & 0x7F) == CIP_SVC_GET_ATTR_SINGLE) {
                                    explicit_read_ok = true;
                                    explicit_general_status = (ilen >= 3) ? cip_resp[2] : 0xFF;
                                    uint8_t add_words = (ilen >= 4) ? cip_resp[3] : 0;
                                    size_t offset = 4 + static_cast<size_t>(add_words) * 2;
                                    if (offset < ilen) {
                                        explicit_payload.assign(cip_resp + offset, cip_resp + ilen);
                                    }
                                }
                                break;
                            }
                            pos += ilen;
                        }
                    }
                } else {
                    explicit_error = PSRAMUtils::createPSRAMString("encap_status");
                }
            } else {
                explicit_error = PSRAMUtils::createPSRAMString("no_response");
            }
        } else {
            explicit_error = PSRAMUtils::createPSRAMString("send_failed");
        }

    } while (false);

    if (!connect_error.empty() && !session_ok) {
        PSRAMUtils::ScopedBuffer err_msg(256);
        if (err_msg.valid()) {
            snprintf(err_msg.get(), err_msg.size(), "Unable to open EtherNet/IP session (%s)", connect_error.c_str());
            pushFinding("connection_failed", err_msg.get(), LogLevel::WARNING);
        }
    }

    if (session_handle != 0 && sock >= 0) {
        uint8_t unreg[24];
        buildEncapHeader(unreg, ENIP_CMD_UNREGSESS, 0, session_handle);
        (void)::send(sock, unreg, sizeof(unreg), 0);
    }
    if (sock >= 0) {
        ::close(sock);
    }

    if (session_ok && list_services_ok && !cip_security_advertised) {
        pushFinding("cip_security_disabled", "Device does not advertise CIP Security (explicit channel in clear text)", LogLevel::WARNING);
    }
    if (session_ok && explicit_read_ok && explicit_general_status == 0) {
        pushFinding("explicit_messaging_plaintext", "Explicit GetAttributeSingle succeeded over unauthenticated channel", LogLevel::WARNING);
    }

    psram_string report;
    report += PSRAMUtils::createPSRAMString("# EtherNet/IP Vulnerability Scan Report\n");
    report += PSRAMUtils::createPSRAMString("**Target**: ");
    report += target_ps;
    report += PSRAMUtils::createPSRAMString("\n");

    psram_string status_text;
    if (session_ok) {
        status_text = PSRAMUtils::createPSRAMString("OK");
    } else if (identity_ok) {
        status_text = PSRAMUtils::createPSRAMString("PARTIAL");
    } else {
        status_text = PSRAMUtils::createPSRAMString("FAILED");
    }
    report += PSRAMUtils::createPSRAMString("**Status**: ");
    report += status_text;
    report += PSRAMUtils::createPSRAMString("\n\n");

    report += PSRAMUtils::createPSRAMString("## Device Fingerprint\n");
    if (identity_ok) {
        PSRAMUtils::ScopedBuffer summary_buf(512);
        bool has_content = false;
        if (summary_buf.valid()) {
            char* p = summary_buf.get();
            size_t remaining = summary_buf.size();
            int written = 0;

            if (!device_name.empty()) {
                written = snprintf(p, remaining, "- Product: %s", device_name.c_str());
                if (written > 0 && written < (int)remaining) {
                    p += written;
                    remaining -= written;
                    if (!revision.empty()) {
                        written = snprintf(p, remaining, " rev %s", revision.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }
                    written = snprintf(p, remaining, "\n");
                    if (written > 0 && written < (int)remaining) {
                        p += written;
                        remaining -= written;
                        has_content = true;
                    }
                }
            }
            if (vendor_id >= 0) {
                written = snprintf(p, remaining, "- Vendor ID: %d\n", vendor_id);
                if (written > 0 && written < (int)remaining) {
                    p += written;
                    remaining -= written;
                    has_content = true;
                }
            }
            if (product_code >= 0) {
                written = snprintf(p, remaining, "- Product Code: %d\n", product_code);
                if (written > 0 && written < (int)remaining) {
                    p += written;
                    remaining -= written;
                    has_content = true;
                }
            }
            if (serial != 0) {
                written = snprintf(p, remaining, "- Serial: %u\n", (unsigned)serial);
                if (written > 0 && written < (int)remaining) {
                    has_content = true;
                }
            }

            if (has_content) {
                report += PSRAMUtils::createPSRAMString(summary_buf.get());
            } else {
                report += PSRAMUtils::createPSRAMString("- Identity payload: ");
                report += PSRAMUtils::createPSRAMString(identity_json.c_str());
                report += PSRAMUtils::createPSRAMString("\n");
            }
        }
    } else {
        PSRAMUtils::ScopedBuffer line_buf(512);
        if (line_buf.valid()) {
            snprintf(line_buf.get(), line_buf.size(), "- Identity probe failed (%s)\n", identity_json.c_str());
            report += PSRAMUtils::createPSRAMString(line_buf.get());
        }
    }
    report += PSRAMUtils::createPSRAMString("\n");

    report += PSRAMUtils::createPSRAMString("## Encapsulation Services\n");
    if (list_services_ok && !services.empty()) {
        for (const auto& svc : services) {
            report += PSRAMUtils::createPSRAMString("- ");
            report += svc;
            report += PSRAMUtils::createPSRAMString("\n");
        }
    } else if (list_services_ok) {
        report += PSRAMUtils::createPSRAMString("- No services advertised\n");
    } else if (!list_services_error.empty()) {
        PSRAMUtils::ScopedBuffer line_buf(256);
        if (line_buf.valid()) {
            snprintf(line_buf.get(), line_buf.size(), "- ListServices failed (%s)\n", list_services_error.c_str());
            report += PSRAMUtils::createPSRAMString(line_buf.get());
        }
    } else {
        report += PSRAMUtils::createPSRAMString("- ListServices not executed\n");
    }
    if (list_services_ok) {
        const char* line = cip_security_advertised ? "- CIP Security: advertised\n"
                                                   : "- CIP Security: not advertised\n";
        report += PSRAMUtils::createPSRAMString(line);
    }
    report += PSRAMUtils::createPSRAMString("\n");

    report += PSRAMUtils::createPSRAMString("## Explicit Messaging Probe\n");
    if (!explicit_read_sent) {
        report += PSRAMUtils::createPSRAMString("- SendRRData not attempted (session not established)\n");
    } else if (!explicit_read_ok) {
        PSRAMUtils::ScopedBuffer line_buf(256);
        if (line_buf.valid()) {
            if (!explicit_error.empty()) {
                snprintf(line_buf.get(), line_buf.size(),
                        "- GetAttributeSingle rejected (%s)\n", explicit_error.c_str());
            } else if (explicit_general_status != 0xFF) {
                snprintf(line_buf.get(), line_buf.size(),
                        "- GetAttributeSingle rejected (general status 0x%02X)\n",
                        static_cast<unsigned>(explicit_general_status));
            } else {
                snprintf(line_buf.get(), line_buf.size(),
                        "- GetAttributeSingle rejected\n");
            }
            report += PSRAMUtils::createPSRAMString(line_buf.get());
        }
    } else {
        PSRAMUtils::ScopedBuffer line_buf(128);
        if (line_buf.valid()) {
            snprintf(line_buf.get(), line_buf.size(),
                    "- General status: 0x%02X\n",
                    static_cast<unsigned>(explicit_general_status));
            report += PSRAMUtils::createPSRAMString(line_buf.get());
        }
        if (!explicit_payload.empty()) {
            psram_string hex = bytesToHex(explicit_payload.data(), explicit_payload.size());
            report += PSRAMUtils::createPSRAMString("- Payload: ");
            report += hex;
            report += PSRAMUtils::createPSRAMString("\n");
        }
    }
    report += PSRAMUtils::createPSRAMString("\n");

    report += PSRAMUtils::createPSRAMString("## Findings\n");
    if (findings.empty()) {
        report += PSRAMUtils::createPSRAMString("- No critical findings detected.\n");
    } else {
        for (const auto& f : findings) {
            const char* level;
            switch (f.level) {
                case LogLevel::ERROR: level = "ERROR"; break;
                case LogLevel::WARNING: level = "WARNING"; break;
                case LogLevel::INFO: level = "INFO"; break;
                default: level = "DEBUG"; break;
            }
            PSRAMUtils::ScopedBuffer line_buf(512);
            if (line_buf.valid()) {
                snprintf(line_buf.get(), line_buf.size(), "- [%s] %s\n", level, f.detail.c_str());
                report += PSRAMUtils::createPSRAMString(line_buf.get());
            }
        }
    }

    return report;
}

std::string EtherNetIPPlugin::doNetworkDiscovery(const std::string& target_network,
                                                 uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool EtherNetIPPlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                               uint32_t timeout_ms,
                                               psram_string& out_report) {
    std::string legacy_target = PSRAMUtils::fromPSRAMString(target_network);
    std::string legacy_report = legacyDoNetworkDiscovery(legacy_target, timeout_ms);
    if (legacy_report.empty()) {
        out_report.clear();
        return false;
    }
    out_report = PSRAMUtils::createPSRAMString(legacy_report.c_str());
    return true;
}

std::string EtherNetIPPlugin::legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms) {
    const uint64_t start_ms = esp_timer_get_time() / 1000ULL;
    const size_t mem_internal_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t mem_psram_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    // First stage: broadcast ListIdentity
    DiscoveryManager::getInstance().initTotalsTLS(1);
    DiscoveryManager::getInstance().updateProgressTLS(target_network.c_str(), 1, 0, 0, 0);
    std::string discovery_result;
    bool discovery_ok = activeBroadcastDiscovery(timeout_ms, discovery_result);

    if (!discovery_ok) {
        // Discovery failed - use PSRAM buffer instead of std::string concatenation
        PSRAMUtils::ScopedBuffer err_buf(256);
        if (!err_buf.valid()) {
            return "{\"protocol\":\"ethernetip\",\"error\":\"psram_alloc\"}";
        }
        snprintf(err_buf.get(), err_buf.size(),
                "{\"protocol\":\"ethernetip\",\"target_network\":\"%s\",\"devices\":[],\"error\":\"discovery_failed\",\"scan_time_ms\":%u}",
                target_network.c_str(), (unsigned)timeout_ms);
        return err_buf.get();
    }

    cJSON* devices = cJSON_Parse(discovery_result.c_str());
    if (!devices || !cJSON_IsArray(devices)) {
        if (devices) cJSON_Delete(devices);
        PSRAMUtils::ScopedBuffer err_buf(256);
        if (!err_buf.valid()) {
            return "{\"protocol\":\"ethernetip\",\"error\":\"psram_alloc\"}";
        }
        snprintf(err_buf.get(), err_buf.size(),
                 "{\"protocol\":\"ethernetip\",\"target_network\":\"%s\",\"devices\":[],\"error\":\"parse_discovery_payload\",\"scan_time_ms\":%u}",
                 target_network.c_str(), (unsigned)timeout_ms);
        return err_buf.get();
    }

    // Stage 2: per-device non-invasive enrichment (TCP session + service discovery + read-only CIP probe)
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    bool eth_ready = (eth != nullptr) && (esp_netif_get_ip_info(eth, &eth_ip) == ESP_OK) && (eth_ip.ip.addr != 0);
    uint32_t per_sock_timeout_ms = timeout_ms / 3U;
    if (per_sock_timeout_ms < 700U) per_sock_timeout_ms = 700U;
    if (per_sock_timeout_ms > 3000U) per_sock_timeout_ms = 3000U;

    int targets_scanned = 0;
    int enriched_targets = 0;

    auto appendLE16 = [](psram_vector<uint8_t>& buf, uint16_t v) {
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto appendLE32 = [](psram_vector<uint8_t>& buf, uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };

    cJSON* dev = nullptr;
    cJSON_ArrayForEach(dev, devices) {
        if (!cJSON_IsObject(dev)) {
            continue;
        }
        cJSON* ip_item = cJSON_GetObjectItem(dev, "ip");
        if (!cJSON_IsString(ip_item) || !ip_item->valuestring || ip_item->valuestring[0] == '\0') {
            continue;
        }
        targets_scanned++;

        const char* ip = ip_item->valuestring;
        uint16_t port = ENIP_TCP_PORT;
        cJSON* port_item = cJSON_GetObjectItem(dev, "port");
        if (cJSON_IsNumber(port_item) && port_item->valueint > 0 && port_item->valueint <= 65535) {
            port = static_cast<uint16_t>(port_item->valueint);
        }

        bool session_ok = false;
        bool list_services_ok = false;
        bool list_interfaces_ok = false;
        bool explicit_read_ok = false;
        bool cip_security_advertised = false;
        uint8_t explicit_general_status = 0xFF;

        const char* error_phase = "none";
        const char* error_reason = "";
        uint32_t session_handle = 0;

        psram_vector<psram_string> services;
        psram_vector<psram_string> interfaces;

        int sock = -1;
        do {
            if (!eth_ready) {
                error_phase = "ethernet";
                error_reason = "ethernet_not_ready";
                break;
            }

            sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock < 0) {
                error_phase = "socket";
                error_reason = "socket_failed";
                break;
            }
            configureTcpSocket(sock);

            struct timeval tv{
                .tv_sec = static_cast<int>(per_sock_timeout_ms / 1000U),
                .tv_usec = static_cast<int>((per_sock_timeout_ms % 1000U) * 1000U)
            };
            ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            sockaddr_in remote{};
            remote.sin_family = AF_INET;
            remote.sin_port = htons(port);
            if (::inet_aton(ip, &remote.sin_addr) == 0) {
                error_phase = "target";
                error_reason = "invalid_ip";
                break;
            }
            if (::connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
                error_phase = "connect";
                error_reason = "connect_failed";
                break;
            }

            uint8_t reg_req[28];
            buildEncapHeader(reg_req, ENIP_CMD_REGSESSION, 4, 0);
            reg_req[24] = 0x01; reg_req[25] = 0x00;
            reg_req[26] = 0x00; reg_req[27] = 0x00;
            if (::send(sock, reg_req, sizeof(reg_req), 0) != static_cast<ssize_t>(sizeof(reg_req))) {
                error_phase = "register_session";
                error_reason = "send_failed";
                break;
            }

            uint8_t reg_resp[64];
            ssize_t reg_len = ::recv(sock, reg_resp, sizeof(reg_resp), 0);
            if (reg_len < 24) {
                error_phase = "register_session";
                error_reason = "short_response";
                break;
            }
            if (le16(reg_resp + 0) != ENIP_CMD_REGSESSION) {
                error_phase = "register_session";
                error_reason = "unexpected_command";
                break;
            }
            if (le32(reg_resp + 8) != 0) {
                error_phase = "register_session";
                error_reason = "nonzero_status";
                break;
            }
            session_handle = le32(reg_resp + 4);
            if (session_handle == 0) {
                error_phase = "register_session";
                error_reason = "zero_session_handle";
                break;
            }
            session_ok = true;

            uint8_t ls_req[24];
            buildEncapHeader(ls_req, ENIP_CMD_LISTSERVICES, 0, session_handle);
            if (::send(sock, ls_req, sizeof(ls_req), 0) == static_cast<ssize_t>(sizeof(ls_req))) {
                uint8_t ls_resp[768];
                ssize_t ls_len = ::recv(sock, ls_resp, sizeof(ls_resp), 0);
                if (ls_len >= 24 && le16(ls_resp + 0) == ENIP_CMD_LISTSERVICES) {
                    uint16_t ls_payload_len = le16(ls_resp + 2);
                    if (24 + ls_payload_len <= static_cast<size_t>(ls_len)) {
                        list_services_ok = parseListServicesForSecurity(ls_resp + 24,
                                                                        ls_payload_len,
                                                                        cip_security_advertised,
                                                                        &services);
                    }
                }
            }

            uint8_t li_req[24];
            buildEncapHeader(li_req, ENIP_CMD_LISTINTERF, 0, session_handle);
            if (::send(sock, li_req, sizeof(li_req), 0) == static_cast<ssize_t>(sizeof(li_req))) {
                uint8_t li_resp[768];
                ssize_t li_len = ::recv(sock, li_resp, sizeof(li_resp), 0);
                if (li_len >= 24 && le16(li_resp + 0) == ENIP_CMD_LISTINTERF) {
                    uint16_t li_payload_len = le16(li_resp + 2);
                    if (24 + li_payload_len <= static_cast<size_t>(li_len)) {
                        list_interfaces_ok = parseListInterfacesPayload(li_resp + 24,
                                                                        li_payload_len,
                                                                        &interfaces);
                    }
                }
            }

            // Read-only explicit probe: Identity class (0x01), instance 1, attribute 1 (Vendor ID)
            psram_vector<uint8_t> path = {0x20, 0x01, 0x24, 0x01, 0x30, 0x01};
            psram_vector<uint8_t> cip_request;
            cip_request.reserve(path.size() + 2);
            cip_request.push_back(CIP_SVC_GET_ATTR_SINGLE);
            cip_request.push_back(static_cast<uint8_t>(path.size() / 2));
            cip_request.insert(cip_request.end(), path.begin(), path.end());

            psram_vector<uint8_t> cpf_payload;
            cpf_payload.reserve(cip_request.size() + 12);
            appendLE32(cpf_payload, 0);
            appendLE16(cpf_payload, 0);
            appendLE16(cpf_payload, 2);
            appendLE16(cpf_payload, CPF_NULL_ADDR);
            appendLE16(cpf_payload, 0);
            appendLE16(cpf_payload, CPF_UNCONNECTED_DATA);
            appendLE16(cpf_payload, static_cast<uint16_t>(cip_request.size()));
            cpf_payload.insert(cpf_payload.end(), cip_request.begin(), cip_request.end());

            psram_vector<uint8_t> sendrr(24 + cpf_payload.size());
            buildEncapHeader(sendrr.data(),
                             ENIP_CMD_SENDRRDATA,
                             static_cast<uint16_t>(cpf_payload.size()),
                             session_handle);
            std::memcpy(sendrr.data() + 24, cpf_payload.data(), cpf_payload.size());
            if (::send(sock, sendrr.data(), sendrr.size(), 0) == static_cast<ssize_t>(sendrr.size())) {
                uint8_t rr_resp[768];
                ssize_t rr_len = ::recv(sock, rr_resp, sizeof(rr_resp), 0);
                if (rr_len >= 24 &&
                    le16(rr_resp + 0) == ENIP_CMD_SENDRRDATA &&
                    le32(rr_resp + 8) == 0) {
                    uint16_t rr_payload_len = le16(rr_resp + 2);
                    if (24 + rr_payload_len <= static_cast<size_t>(rr_len) && rr_payload_len >= 8) {
                        const uint8_t* payload = rr_resp + 24;
                        uint16_t item_count = le16(payload + 6);
                        size_t pos = 8;
                        for (uint16_t idx = 0; idx < item_count && pos + 4 <= rr_payload_len; ++idx) {
                            uint16_t type = le16(payload + pos + 0);
                            uint16_t ilen = le16(payload + pos + 2);
                            pos += 4;
                            if (pos + ilen > rr_payload_len) break;
                            if (type == CPF_UNCONNECTED_DATA && ilen >= 4) {
                                const uint8_t* cip_resp = payload + pos;
                                uint8_t svc_resp = cip_resp[0];
                                if ((svc_resp & 0x7F) == CIP_SVC_GET_ATTR_SINGLE) {
                                    explicit_general_status = (ilen >= 3) ? cip_resp[2] : 0xFF;
                                    explicit_read_ok = (explicit_general_status == 0x00);
                                }
                                break;
                            }
                            pos += ilen;
                        }
                    }
                }
            }
        } while (false);

        if (session_handle != 0 && sock >= 0) {
            uint8_t unreg[24];
            buildEncapHeader(unreg, ENIP_CMD_UNREGSESS, 0, session_handle);
            (void)::send(sock, unreg, sizeof(unreg), 0);
        }
        if (sock >= 0) {
            ::close(sock);
        }

        cJSON_AddBoolToObject(dev, "cip_security_advertised", cip_security_advertised);

        cJSON* services_arr = cJSON_CreateArray();
        for (const auto& svc : services) {
            cJSON_AddItemToArray(services_arr, cJSON_CreateString(svc.c_str()));
        }
        cJSON_AddItemToObject(dev, "encapsulation_services", services_arr);

        cJSON* interfaces_arr = cJSON_CreateArray();
        for (const auto& iface : interfaces) {
            cJSON_AddItemToArray(interfaces_arr, cJSON_CreateString(iface.c_str()));
        }
        cJSON_AddItemToObject(dev, "encapsulation_interfaces", interfaces_arr);

        cJSON* caps = cJSON_CreateObject();
        cJSON_AddBoolToObject(caps, "identity_discovery", true);
        cJSON_AddBoolToObject(caps, "register_session", session_ok);
        cJSON_AddBoolToObject(caps, "list_services", list_services_ok);
        cJSON_AddBoolToObject(caps, "list_interfaces", list_interfaces_ok);
        cJSON_AddBoolToObject(caps, "explicit_read_identity_attr", explicit_read_ok);
        cJSON_AddBoolToObject(caps, "explicit_write_supported", false);
        cJSON_AddBoolToObject(caps, "explicit_control_supported", false);
        cJSON_AddItemToObject(dev, "capability_matrix", caps);

        cJSON* diag = cJSON_CreateObject();
        cJSON_AddBoolToObject(diag, "session_register_ok", session_ok);
        cJSON_AddBoolToObject(diag, "list_services_ok", list_services_ok);
        cJSON_AddBoolToObject(diag, "list_interfaces_ok", list_interfaces_ok);
        cJSON_AddBoolToObject(diag, "explicit_identity_read_ok", explicit_read_ok);
        cJSON_AddNumberToObject(diag, "explicit_general_status", explicit_general_status);
        cJSON_AddStringToObject(diag, "error_phase", error_phase);
        cJSON_AddStringToObject(diag, "error_reason", error_reason);
        cJSON_AddItemToObject(dev, "diagnostics", diag);

        if (session_ok || list_services_ok || list_interfaces_ok || explicit_read_ok) {
            enriched_targets++;
        }
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "protocol", "ethernetip");
    cJSON_AddStringToObject(root, "target_network", target_network.c_str());
    cJSON_AddItemToObject(root, "devices", devices); // ownership transferred
    cJSON_AddNumberToObject(root, "total_found", cJSON_GetArraySize(devices));
    cJSON_AddNumberToObject(root, "targets_scanned", targets_scanned);
    cJSON_AddNumberToObject(root, "targets_enriched", enriched_targets);
    cJSON_AddNumberToObject(root, "scan_time_ms", static_cast<double>((esp_timer_get_time() / 1000ULL) - start_ms));
    cJSON* mem = cJSON_CreateObject();
    cJSON_AddNumberToObject(mem, "internal_before", static_cast<double>(mem_internal_before));
    cJSON_AddNumberToObject(mem, "internal_after", static_cast<double>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
    cJSON_AddNumberToObject(mem, "internal_largest_after", static_cast<double>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)));
    cJSON_AddNumberToObject(mem, "psram_before", static_cast<double>(mem_psram_before));
    cJSON_AddNumberToObject(mem, "psram_after", static_cast<double>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM)));
    cJSON_AddItemToObject(root, "memory", mem);

    char* out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) {
        return "{}";
    }
    std::string response(out);
    free(out);
    return response;
}

// --- IDS path ---
bool EtherNetIPPlugin::isTargetPacket(const NetworkPacket& pkt) {
    if (pkt.is_udp) {
        return pkt.dst_port==ENIP_UDP_PORT || pkt.src_port==ENIP_UDP_PORT || pkt.dst_port==ENIP_IO_UDP || pkt.src_port==ENIP_IO_UDP;
    } else if (pkt.is_tcp) {
        return pkt.dst_port==ENIP_TCP_PORT || pkt.src_port==ENIP_TCP_PORT;
    }
    return false;
}

void EtherNetIPPlugin::loadIDSRules(const std::string& rules_json) {
    (void)rules_json;
    LOG_INFO("ETHERNETIP_PLUGIN", "EtherNet/IP IDS rules loaded");
}

bool EtherNetIPPlugin::parseSendRRDataForCIP(const uint8_t* p, size_t len, uint8_t& svc, bool& is_resp,
                                                   uint16_t& cls, uint16_t& inst, uint16_t& attr) {
    // ENIP SendRRData payload: InterfaceHandle(4) Timeout(2) ItemCount(2) [Items...]
    // Expect Null Address + Unconnected Data items; inside Unconnected Data the first byte is CIP service.
    if (len < 8) return false;
    cls=inst=attr=0;
    uint32_t iface = le32(p+0); (void)iface;
    uint16_t _timeout = le16(p+4); (void)_timeout;
    uint16_t items = le16(p+6);
    size_t pos = 8;
    for (uint16_t i=0;i<items;i++) {
        if (pos + 4 > len) return false;
        uint16_t type = le16(p+pos+0);
        uint16_t ilen = le16(p+pos+2);
        const uint8_t* idata = p + pos + 4;
        if (pos + 4 + ilen > len) return false;
        if (type == CPF_UNCONNECTED_DATA && ilen >= 2) {
            // CIP: [service 1][path_size 1][path 2*size][req/resp data...]
            svc = idata[0];
            is_resp = (svc & 0x80) != 0;
            svc &= 0x7F;
            if (ilen >= 2) {
                uint8_t path_words = idata[1];
                size_t path_bytes = (size_t)path_words * 2;
                const uint8_t* path = idata + 2;
                if (2 + path_bytes <= ilen) {
                    parseCipPath(path, path_bytes, cls, inst, attr);
                }
            }
            return true;
        }
        pos += 4 + ilen;
    }
    return false;
}

bool EtherNetIPPlugin::parseListServicesForSecurity(const uint8_t* payload,
                                                    size_t length,
                                                    bool& cip_security_found,
                                                    psram_vector<psram_string>* descriptions) {
    cip_security_found = false;
    if (!payload || length < 2) {
        return false;
    }

    if (descriptions) {
        descriptions->clear();
    }

    uint16_t count = le16(payload + 0);
    size_t pos = 2;

    for (uint16_t idx = 0; idx < count; ++idx) {
        if (pos + 4 > length) {
            return false;
        }

        uint16_t type = le16(payload + pos + 0);
        uint16_t ilen = le16(payload + pos + 2);
        pos += 4;
        if (pos + ilen > length) {
            return false;
        }

        uint16_t version = 0;
        uint16_t flags = 0;
        if (ilen >= 2) {
            version = le16(payload + pos + 0);
        }
        if (ilen >= 4) {
            flags = le16(payload + pos + 2);
        }

        psram_string name;
        if (ilen > 4) {
            name = sanitizePrintablePSRAM(reinterpret_cast<const char*>(payload + pos + 4), ilen - 4);
        }

        bool service_is_security = false;
        if (type == 0x0100 || type == 0x0053) {
            service_is_security = true;
        }
        if (!name.empty()) {
            const char* str = name.c_str();
            size_t n = name.size();
            const char target[] = "security";
            for (size_t i = 0; i + sizeof(target) - 1 <= n; ++i) {
                bool match = true;
                for (size_t j = 0; j < sizeof(target) - 1; ++j) {
                    if (std::tolower(static_cast<unsigned char>(str[i + j])) != target[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    service_is_security = true;
                    break;
                }
            }
        }

        if (service_is_security) {
            cip_security_found = true;
        }

        if (descriptions) {
            PSRAMUtils::ScopedBuffer desc_buf(256);
            if (desc_buf.valid()) {
                if (!name.empty()) {
                    snprintf(desc_buf.get(), desc_buf.size(),
                             "type 0x%04X v%u flags 0x%04X name=%s",
                             type, version, flags, name.c_str());
                } else {
                    snprintf(desc_buf.get(), desc_buf.size(),
                             "type 0x%04X v%u flags 0x%04X",
                             type, version, flags);
                }
                descriptions->push_back(PSRAMUtils::createPSRAMString(desc_buf.get()));
            }
        }

        pos += ilen;
    }

    return true;
}

bool EtherNetIPPlugin::analyzeIoDatagram(const NetworkPacket& pkt) {
    uint32_t device_ip = 0;
    const char* device_str = "";
    if (pkt.src_port == ENIP_IO_UDP) {
        device_ip = ip_to_uint32(pkt.src_ip);
        device_str = pkt.src_ip.c_str();
    } else if (pkt.dst_port == ENIP_IO_UDP) {
        device_ip = ip_to_uint32(pkt.dst_ip);
        device_str = pkt.dst_ip.c_str();
    }

    bool alert_generated = false;
    uint32_t now_ms = static_cast<uint32_t>(pkt.ts_ms);
    if (now_ms == 0) {
        now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    }
    auto emitEvent = [&](const char* json, LogLevel level, bool mark_alert) {
        if (shouldSuppressEnipEvent(json, level, now_ms)) {
            return;
        }
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(json), level);
        if (mark_alert) {
            alert_generated = true;
        }
    };

    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (!locateUdpAppPayload(pkt, payload, payload_len) || payload_len < 8) {
        PSRAMUtils::ScopedBuffer msg_buf(192);
        if (msg_buf.valid()) {
            snprintf(msg_buf.get(), msg_buf.size(),
                     "{\"alert_type\":\"enip.io.short_datagram\",\"type\":\"enip.io.short_datagram\",\"device\":\"%s\",\"len\":%u}",
                     device_str, static_cast<unsigned>(pkt.length));
            emitEvent(msg_buf.get(), LogLevel::DEBUG, true);
        }
        return alert_generated;
    }

    uint32_t connection_id = le32(payload + 0);
    uint16_t sequence = le16(payload + 4);
    uint16_t run_idle = le16(payload + 6);

    if (device_ip != 0) {
        auto sec_it = cip_security_status_.find(device_ip);
        bool cip_security_advertised = (sec_it != cip_security_status_.end() && sec_it->second);
        if (!cip_security_advertised) {
            if (io_without_security_reported_.insert(device_ip).second) {
                PSRAMUtils::ScopedBuffer warn_buf(256);
                if (warn_buf.valid()) {
                    snprintf(warn_buf.get(), warn_buf.size(),
                             "{\"alert_type\":\"enip.io.without_cip_security\",\"type\":\"enip.io.without_cip_security\",\"device\":\"%s\",\"connection_id\":%lu}",
                             device_str,
                             static_cast<unsigned long>(connection_id));
                    emitEvent(warn_buf.get(), LogLevel::WARNING, true);
                }
            }
        } else {
            io_without_security_reported_.erase(device_ip);
        }
    }

    if (device_ip != 0) {
        uint64_t state_key = (static_cast<uint64_t>(device_ip) << 32) | connection_id;
        auto prev = io_run_idle_state_.find(state_key);
        if (prev == io_run_idle_state_.end() || prev->second != run_idle) {
            io_run_idle_state_[state_key] = run_idle;
            PSRAMUtils::ScopedBuffer state_buf(256);
            if (state_buf.valid()) {
                const char* state = (run_idle & 0x01) ? "RUN" : "IDLE";
                snprintf(state_buf.get(), state_buf.size(),
                         "{\"alert_type\":\"enip.io.state_change\",\"type\":\"enip.io.state_change\",\"state\":\"%s\",\"device\":\"%s\",\"connection_id\":%lu,\"sequence\":%u}",
                         state,
                         device_str,
                         static_cast<unsigned long>(connection_id),
                         static_cast<unsigned>(sequence));
                emitEvent(state_buf.get(), LogLevel::INFO, true);
            }
        }
    }

    return alert_generated;
}

bool EtherNetIPPlugin::parseListIdentityPayloadPSRAM(const uint8_t* p, size_t len, psram_string& out_json) {
    if (len < 2) return false;
    uint16_t count = le16(p + 0);
    size_t pos = 2;
    for (uint16_t i = 0; i < count; ++i) {
        if (pos + 4 > len) return false;
        uint16_t type = le16(p + pos + 0);
        uint16_t ilen = le16(p + pos + 2);
        const uint8_t* id = p + pos + 4;
        if (pos + 4 + ilen > len) return false;
        if (type == CPF_IDENTITY_ITEM && ilen >= 28) {
            size_t o = 0;
            uint16_t encap_ver = le16(id + o); o += 2;
            if (ilen < o + 16) return false;
            uint16_t sa_port = le16(id + o + 2);
            uint32_t sa_ip = le32(id + o + 4);
            o += 16;
            if (ilen < o + 13) return false;
            uint16_t vendor = le16(id + o + 0);
            uint16_t devtype = le16(id + o + 2);
            uint16_t prodcode = le16(id + o + 4);
            uint8_t rev_maj = id[o + 6];
            uint8_t rev_min = id[o + 7];
            uint16_t status = le16(id + o + 8);
            uint32_t serial = le32(id + o + 10);
            o += 14;
            if (ilen < o + 1) return false;
            uint8_t name_len = id[o++];
            if (ilen < o + name_len) return false;

            const char* name_ptr = reinterpret_cast<const char*>(id + o);
            o += name_len;
            uint8_t state = 0;
            if (ilen > o) state = id[o];

            char ipbuf[16];
            snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                     (unsigned)(sa_ip & 0xFF), (unsigned)((sa_ip >> 8) & 0xFF),
                     (unsigned)((sa_ip >> 16) & 0xFF), (unsigned)((sa_ip >> 24) & 0xFF));

            PSRAMUtils::ScopedBuffer json_buf(512);
            if (!json_buf.valid()) return false;

            char* dst = json_buf.get();
            size_t remaining = json_buf.size();

            int written = snprintf(dst, remaining,
                                   "{\"encap_ver\":%u,\"ip\":\"%s\",\"port\":%u,\"vendor_id\":%u,\"device_type\":%u,\"product_code\":%u,\"revision\":\"%u.%u\",\"status\":%u,\"serial\":%lu,\"product_name\":\"",
                                   encap_ver, ipbuf, sa_port, vendor, devtype, prodcode,
                                   (unsigned)rev_maj, (unsigned)rev_min, status, (unsigned long)serial);
            if (written < 0 || written >= (int)remaining) return false;
            dst += written;
            remaining -= written;

            for (size_t idx = 0; idx < name_len && remaining > 2; ++idx) {
                char c = name_ptr[idx];
                if (c == '\"') {
                    if (remaining < 3) break;
                    *dst++ = '\\';
                    *dst++ = '\"';
                    remaining -= 2;
                } else {
                    *dst++ = c;
                    remaining--;
                }
            }

            written = snprintf(dst, remaining, "\",\"state\":%u}", (unsigned)state);
            if (written < 0 || written >= (int)remaining) return false;

            psram_string json_ps = PSRAMUtils::createPSRAMString(json_buf.get());
            if (json_ps.empty()) return false;
            out_json = std::move(json_ps);
            return true;
        }
        pos += 4 + ilen;
    }
    return false;
}

bool EtherNetIPPlugin::parseListIdentityPayload(const uint8_t* p, size_t len, std::string& out_json) {
    psram_string json_ps;
    if (!parseListIdentityPayloadPSRAM(p, len, json_ps)) {
        return false;
    }
    out_json = PSRAMUtils::fromPSRAMString(json_ps);
    return !out_json.empty();
}

// Fuzzing API implementations
bool EtherNetIPPlugin::generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) {
    out.clear();

    LOG_INFOF("ETHERNETIP_PLUGIN", "Generating seed corpus for job %lu (profile=%s, safe_mode=%s)",
              (unsigned long)job.id,
              job.profile.empty() ? "default" : job.profile.c_str(),
              job.safe_mode ? "true" : "false");

    auto normalizeProfile = [](const std::string& p) -> std::string {
        if (p == "session_flooding") return "session_handle_anomalies";
        if (p == "encapsulation_bypass") return "encap_malformed_headers";
        if (p == "identity_spoofing") return "cpf_item_confusion";
        if (p == "cip_attribute_manipulation") return "unauthorized_writes";
        return p;
    };

    if (!job.profile.empty() && job.profile != "default") {
        const std::string profile_norm = normalizeProfile(job.profile);
        const bool unsafe_profile =
            (profile_norm == "unauthorized_writes") ||
            (profile_norm == "device_reset_attempt");

        if (job.safe_mode && unsafe_profile) {
            LOG_WARNINGF("ETHERNETIP_PLUGIN",
                         "Refusing unsafe EtherNet/IP profile '%s' in safe_mode=true",
                         profile_norm.c_str());
            return false;
        }

        if (generateAttackSeeds(job, profile_norm, out) && !out.empty()) {
            for (auto& tc : out) {
                if (tc.attack_type.empty()) tc.attack_type = profile_norm;
            }
            LOG_INFOF("ETHERNETIP_PLUGIN",
                      "Generated %zu EtherNet/IP profile seeds for '%s'",
                      out.size(),
                      profile_norm.c_str());
            return true;
        }
        LOG_WARNINGF("ETHERNETIP_PLUGIN",
                     "Profile '%s' did not produce seeds, falling back to default",
                     profile_norm.c_str());
    }

    // Default seed: standard explicit read (GetAttributeSingle Identity attr 1).
    std::vector<uint8_t> sendrrdata = {
        0x6F,0x00,            // SendRRData
        0x16,0x00,            // Encap length (fixed by fixup)
        0x00,0x00,0x00,0x00,  // Session handle (injected at runtime)
        0x00,0x00,0x00,0x00,  // Status
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Sender context
        0x00,0x00,0x00,0x00,  // Options
        0x00,0x00,0x00,0x00,  // Interface handle
        0x00,0x00,            // Timeout
        0x02,0x00,            // Item count
        0x00,0x00,0x00,0x00,  // Null Address item
        0xB2,0x00,            // Unconnected Data
        0x08,0x00,            // CIP length
        0x0E,                 // Get_Attribute_Single
        0x03,                 // Path words
        0x20,0x01,            // Class 0x01 Identity
        0x24,0x01,            // Instance 1
        0x30,0x01             // Attribute 1
    };
    FuzzTestCase tc;
    tc.seed_id = 1;
    tc.mutation_id = 0;
    tc.payload = sendrrdata;
    tc.attack_type = "default";
    tc.mutation_description = "Baseline explicit read on Identity Object";
    out.push_back(tc);

    LOG_INFOF("ETHERNETIP_PLUGIN", "Generated %zu EtherNet/IP baseline seeds", out.size());
    return !out.empty();
}

bool EtherNetIPPlugin::fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) {
    out = in;
    const std::string attack = !in.attack_type.empty() ? in.attack_type : job.profile;
    const bool preserve_declared_length = (attack == "encap_malformed_headers");
    if (!preserve_declared_length && out.payload.size() >= 24) {
        uint16_t len = (uint16_t)(out.payload.size() - 24);
        out.payload[2] = (uint8_t)(len & 0xFF);
        out.payload[3] = (uint8_t)((len >> 8) & 0xFF);
    }
    return true;
}

FuzzResult EtherNetIPPlugin::execute(const FuzzJob& job, const FuzzTestCase& tc,
                                    std::string& sent_hex, std::string& received_hex,
                                    std::string& status_details) {
    if (!job.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())) {
        status_details = "blocked_by_offensive_policy:" +
            std::string(sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
        sent_hex.clear();
        received_hex.clear();
        return FuzzResult::SEND_FAILED;
    }

    const std::string attack_profile = !tc.attack_type.empty()
        ? tc.attack_type
        : (job.profile.empty() ? std::string("default") : job.profile);

    // Parse target (IP:PORT)
    std::string ip;
    uint16_t port;
    if (!parseTarget(job.target, ip, port)) {
        status_details = "invalid_target";
        return FuzzResult::SOCKET_ERROR;
    }

    auto set_hex_string = [](const uint8_t* data, size_t len, std::string& out_hex) {
        static constexpr size_t kMaxHexLoggedBytes = 128; // cap string growth in internal RAM
        out_hex.clear();
        if (!data || len == 0) return;
        const size_t used_len = (len > kMaxHexLoggedBytes) ? kMaxHexLoggedBytes : len;
        size_t hex_size = (used_len * 3) + 48;
        char* hex_buf = (char*)heap_caps_malloc(hex_size + 1, MALLOC_CAP_SPIRAM);
        if (!hex_buf) {
            out_hex = "[hex_alloc_failed]";
            return;
        }
        char* p = hex_buf;
        for (size_t i = 0; i < used_len; ++i) {
            if (i > 0) *p++ = ' ';
            p += snprintf(p, 3, "%02X", (unsigned)data[i]);
        }
        if (len > used_len) {
            p += snprintf(p, hex_buf + hex_size - p, " ...(+%u bytes)", (unsigned)(len - used_len));
        }
        *p = '\0';
        out_hex = hex_buf;
        heap_caps_free(hex_buf);
    };

    // UDP I/O profile on port 2222 (no ENIP session handshake required).
    if (attack_profile == "io_udp_2222_anomalies") {
        if (port == ENIP_TCP_PORT) {
            port = ENIP_IO_UDP;
        }
        int us = AssessmentInterface::openBoundSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (us < 0) {
            status_details = "udp_socket_creation_failed";
            return FuzzResult::SOCKET_ERROR;
        }

        configureTcpSocket(us);

        esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_netif_ip_info_t eth_ip{};
        if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
            ::close(us);
            status_details = "ethernet_not_ready";
            return FuzzResult::SOCKET_ERROR;
        }

        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (::inet_aton(ip.c_str(), &remote.sin_addr) == 0) {
            ::close(us);
            status_details = "invalid_ip";
            return FuzzResult::SOCKET_ERROR;
        }

        set_hex_string(tc.payload.data(), tc.payload.size(), sent_hex);
        ssize_t sent = ::sendto(us,
                                tc.payload.data(),
                                tc.payload.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&remote),
                                sizeof(remote));
        if (sent != static_cast<ssize_t>(tc.payload.size())) {
            ::close(us);
            status_details = "udp_send_failed";
            return FuzzResult::SEND_FAILED;
        }

        uint8_t rx_udp[256];
        struct timeval tv_udp { .tv_sec = 0, .tv_usec = 300000 };
        ::setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv_udp, sizeof(tv_udp));
        ssize_t rn = ::recv(us, rx_udp, sizeof(rx_udp), 0);
        if (rn > 0) {
            set_hex_string(rx_udp, (size_t)rn, received_hex);
            char ds[96];
            snprintf(ds, sizeof(ds), "udp_2222_response_len:%u", (unsigned)rn);
            status_details = ds;
        } else {
            received_hex.clear();
            status_details = "udp_2222_sent_no_response_expected";
        }
        ::close(us);
        return FuzzResult::SUCCESS;
    }

    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        status_details = "socket_creation_failed";
        return FuzzResult::SOCKET_ERROR;
    }

    configureTcpSocket(sock);

    struct timeval tv { .tv_sec = 2, .tv_usec = 0 };
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        ::close(sock);
        status_details = "ethernet_not_ready";
        return FuzzResult::SOCKET_ERROR;
    }

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (::inet_aton(ip.c_str(), &remote.sin_addr) == 0) {
        ::close(sock);
        status_details = "invalid_ip";
        return FuzzResult::SOCKET_ERROR;
    }

    if (::connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
        ::close(sock);
        status_details = "connect_failed";
        return FuzzResult::CONNECTION_FAILED;
    }

    uint8_t* rx_buf = (uint8_t*)heap_caps_malloc(2048, MALLOC_CAP_SPIRAM);
    if (!rx_buf) {
        ::close(sock);
        status_details = "psram_alloc_failed";
        return FuzzResult::SOCKET_ERROR;
    }

    if (tc.payload.size() < 24) {
        heap_caps_free(rx_buf);
        ::close(sock);
        status_details = "payload_too_small";
        return FuzzResult::SEND_FAILED;
    }

    uint16_t tx_command = le16(tc.payload.data());
    const bool is_send_rr_data = (tx_command == ENIP_CMD_SENDRRDATA);
    const bool session_handle_anomaly = (attack_profile == "session_handle_anomalies" ||
                                         attack_profile == "session_flooding");
    const bool should_register_session = is_send_rr_data && !session_handle_anomaly;

    uint32_t session_handle = 0;
    if (should_register_session) {
        uint8_t reg_req[28];
        buildEncapHeader(reg_req, ENIP_CMD_REGSESSION, 4, 0);
        reg_req[24] = 0x01; reg_req[25] = 0x00;
        reg_req[26] = 0x00; reg_req[27] = 0x00;

        if (::send(sock, reg_req, sizeof(reg_req), 0) != static_cast<ssize_t>(sizeof(reg_req))) {
            heap_caps_free(rx_buf);
            ::close(sock);
            status_details = "register_send_failed";
            return FuzzResult::SEND_FAILED;
        }

        ssize_t reg_len = ::recv(sock, rx_buf, 64, 0);
        if (reg_len < 24 || le16(rx_buf + 0) != ENIP_CMD_REGSESSION || le32(rx_buf + 8) != 0) {
            heap_caps_free(rx_buf);
            ::close(sock);
            status_details = "register_failed";
            return FuzzResult::CONNECTION_FAILED;
        }

        session_handle = le32(rx_buf + 4);
        if (session_handle == 0) {
            heap_caps_free(rx_buf);
            ::close(sock);
            status_details = "zero_session_handle";
            return FuzzResult::CONNECTION_FAILED;
        }
    }

    uint8_t* fuzz_payload = (uint8_t*)heap_caps_malloc(tc.payload.size(), MALLOC_CAP_SPIRAM);
    if (!fuzz_payload) {
        heap_caps_free(rx_buf);
        ::close(sock);
        status_details = "psram_payload_alloc_failed";
        return FuzzResult::SOCKET_ERROR;
    }

    memcpy(fuzz_payload, tc.payload.data(), tc.payload.size());
    if (should_register_session) {
        wr32le(fuzz_payload + 4, session_handle);
    }
    set_hex_string(fuzz_payload, tc.payload.size(), sent_hex);

    ssize_t sent = ::send(sock, fuzz_payload, tc.payload.size(), 0);
    heap_caps_free(fuzz_payload);

    if (sent != static_cast<ssize_t>(tc.payload.size())) {
        heap_caps_free(rx_buf);
        ::close(sock);
        status_details = "fuzz_send_failed";
        return FuzzResult::SEND_FAILED;
    }

    ssize_t rx_len = ::recv(sock, rx_buf, 2048, 0);

    if (should_register_session && session_handle != 0) {
        uint8_t unreg[24];
        buildEncapHeader(unreg, ENIP_CMD_UNREGSESS, 0, session_handle);
        (void)::send(sock, unreg, sizeof(unreg), 0);
    }

    ::close(sock);

    if (rx_len > 0) {
        set_hex_string(rx_buf, (size_t)rx_len, received_hex);

        if (rx_len < 24) {
            char sb[64];
            snprintf(sb, sizeof(sb), "short_response:%u", (unsigned)rx_len);
            status_details = sb;
            heap_caps_free(rx_buf);
            return FuzzResult::INVALID_RESPONSE;
        }

        uint16_t rx_cmd = le16(rx_buf + 0);
        uint16_t rx_plen = le16(rx_buf + 2);
        uint32_t rx_status = le32(rx_buf + 8);
        if ((size_t)rx_plen + 24U > (size_t)rx_len) {
            status_details = "length_mismatch";
            heap_caps_free(rx_buf);
            return FuzzResult::INVALID_RESPONSE;
        }

        if (rx_status != 0) {
            char sb[96];
            snprintf(sb, sizeof(sb), "encapsulation_error cmd=0x%04X status=0x%08X",
                     (unsigned)rx_cmd, (unsigned)rx_status);
            status_details = sb;
            heap_caps_free(rx_buf);
            return FuzzResult::EXCEPTION_RESPONSE;
        }

        if (is_send_rr_data) {
            if (rx_cmd != ENIP_CMD_SENDRRDATA) {
                status_details = "unexpected_command_for_sendrrdata";
                heap_caps_free(rx_buf);
                return FuzzResult::INVALID_RESPONSE;
            }

            uint8_t tx_svc = 0;
            bool tx_is_resp = false;
            uint16_t cls = 0, inst = 0, attr = 0;
            bool have_tx_svc = parseSendRRDataForCIP(tc.payload.data() + 24,
                                                     tc.payload.size() - 24,
                                                     tx_svc, tx_is_resp, cls, inst, attr);

            const uint8_t* ep = rx_buf + 24;
            size_t ep_len = rx_plen;
            if (ep_len < 8) {
                status_details = "cpf_too_short";
                heap_caps_free(rx_buf);
                return FuzzResult::INVALID_RESPONSE;
            }

            uint16_t item_count = le16(ep + 6);
            size_t pos = 8;
            const uint8_t* cip = nullptr;
            uint16_t cip_len = 0;
            for (uint16_t i = 0; i < item_count; ++i) {
                if (pos + 4 > ep_len) break;
                uint16_t type = le16(ep + pos + 0);
                uint16_t ilen = le16(ep + pos + 2);
                pos += 4;
                if (pos + ilen > ep_len) break;
                if (type == CPF_UNCONNECTED_DATA && ilen >= 4) {
                    cip = ep + pos;
                    cip_len = ilen;
                    break;
                }
                pos += ilen;
            }
            if (!cip || cip_len < 4) {
                status_details = "cip_payload_missing";
                heap_caps_free(rx_buf);
                return FuzzResult::INVALID_RESPONSE;
            }

            uint8_t rx_svc = (uint8_t)(cip[0] & 0x7F);
            bool rx_is_resp = ((cip[0] & 0x80) != 0);
            uint8_t general_status = cip[2];
            uint8_t ext_words = cip[3];
            if (!rx_is_resp) {
                status_details = "cip_not_response";
                heap_caps_free(rx_buf);
                return FuzzResult::INVALID_RESPONSE;
            }
            if (have_tx_svc && tx_svc != rx_svc) {
                char sb[80];
                snprintf(sb, sizeof(sb),
                         "cip_service_mismatch tx=0x%02X rx=0x%02X",
                         (unsigned)tx_svc, (unsigned)rx_svc);
                status_details = sb;
                heap_caps_free(rx_buf);
                return FuzzResult::INVALID_RESPONSE;
            }

            if (general_status == 0x00) {
                char sb[96];
                snprintf(sb, sizeof(sb), "cip_success svc=0x%02X ext_words=%u",
                         (unsigned)rx_svc, (unsigned)ext_words);
                status_details = sb;
                heap_caps_free(rx_buf);
                return FuzzResult::SUCCESS;
            }

            char sb[128];
            snprintf(sb, sizeof(sb),
                     "cip_exception svc=0x%02X general_status=0x%02X ext_words=%u",
                     (unsigned)rx_svc,
                     (unsigned)general_status,
                     (unsigned)ext_words);
            status_details = sb;
            heap_caps_free(rx_buf);
            return FuzzResult::EXCEPTION_RESPONSE;
        }

        if (rx_cmd != tx_command && tx_command != ENIP_CMD_LISTIDENTITY) {
            status_details = "unexpected_command";
            heap_caps_free(rx_buf);
            return FuzzResult::INVALID_RESPONSE;
        }

        status_details = "response_received";
        heap_caps_free(rx_buf);
        return FuzzResult::SUCCESS;
    }

    heap_caps_free(rx_buf);
    if (rx_len == 0) {
        status_details = "connection_closed";
        return FuzzResult::TIMEOUT;
    }
    status_details = "recv_timeout_or_error";
    return FuzzResult::TIMEOUT;
}

bool EtherNetIPPlugin::generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out) {
    (void)job;
    out.clear();

    auto normalizeProfile = [](const std::string& p) -> std::string {
        if (p == "session_flooding") return "session_handle_anomalies";
        if (p == "encapsulation_bypass") return "encap_malformed_headers";
        if (p == "identity_spoofing") return "cpf_item_confusion";
        if (p == "cip_attribute_manipulation") return "unauthorized_writes";
        return p;
    };
    const std::string profile = normalizeProfile(attack_type);

    auto wr16 = [](std::vector<uint8_t>& b, uint16_t v) {
        b.push_back((uint8_t)(v & 0xFF));
        b.push_back((uint8_t)((v >> 8) & 0xFF));
    };
    auto wr32 = [](std::vector<uint8_t>& b, uint32_t v) {
        b.push_back((uint8_t)(v & 0xFF));
        b.push_back((uint8_t)((v >> 8) & 0xFF));
        b.push_back((uint8_t)((v >> 16) & 0xFF));
        b.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto build_sendrr = [&](const std::vector<uint8_t>& cip,
                            uint32_t session,
                            uint16_t force_len) -> std::vector<uint8_t> {
        std::vector<uint8_t> p;
        p.reserve(24 + 16 + cip.size());
        wr16(p, ENIP_CMD_SENDRRDATA);
        wr16(p, force_len ? force_len : (uint16_t)(16 + cip.size()));
        wr32(p, session);
        wr32(p, 0); // status
        for (int i = 0; i < 8; ++i) p.push_back(0x00); // context
        wr32(p, 0); // options
        wr32(p, 0); // interface handle
        wr16(p, 0); // timeout
        wr16(p, 2); // item count
        wr16(p, CPF_NULL_ADDR); wr16(p, 0);
        wr16(p, CPF_UNCONNECTED_DATA); wr16(p, (uint16_t)cip.size());
        p.insert(p.end(), cip.begin(), cip.end());
        return p;
    };
    auto push_case = [&](uint32_t id,
                         const std::vector<uint8_t>& payload,
                         const char* attack,
                         const char* desc) {
        FuzzTestCase tc;
        tc.seed_id = id;
        tc.payload = payload;
        tc.attack_type = attack ? attack : profile;
        tc.mutation_description = desc ? desc : "";
        out.push_back(tc);
    };

    LOG_INFOF("ETHERNETIP_PLUGIN", "Generating %s attack seeds", profile.c_str());

    if (profile == "encap_malformed_headers") {
        std::vector<uint8_t> p1(24, 0x00);
        p1[0] = 0x6F; p1[1] = 0x00;
        p1[2] = 0x80; p1[3] = 0x00; // malformed length mismatch
        push_case(8401, p1, "encap_malformed_headers", "Malformed encapsulation length mismatch");

        std::vector<uint8_t> p2(32, 0x00);
        p2[0] = 0xFF; p2[1] = 0x7F; // unsupported command
        p2[2] = 0x08; p2[3] = 0x00;
        for (size_t i = 24; i < 32; ++i) p2[i] = (uint8_t)i;
        push_case(8402, p2, "encap_malformed_headers", "Unknown command with malformed body");

        std::vector<uint8_t> p3 = {
            0x65,0x00, 0x04,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0xFF,0xFF
        };
        push_case(8403, p3, "encap_malformed_headers", "Malformed RegisterSession payload");
    } else if (profile == "cpf_item_confusion") {
        std::vector<uint8_t> cip = { 0x0E,0x03,0x20,0x01,0x24,0x01,0x30,0x01 };
        std::vector<uint8_t> p = build_sendrr(cip, 0, 0);
        p[30] = 0x03; p[31] = 0x00; // item_count mismatch
        p[36] = 0xB1; p[37] = 0x00; // wrong type
        p[38] = 0xFF; p[39] = 0x00; // wrong length
        push_case(8411, p, "cpf_item_confusion", "CPF item-count/type confusion");
    } else if (profile == "cip_path_boundary") {
        std::vector<uint8_t> cip1 = { 0x0E,0x06,0x20,0x01,0x24,0x01,0x30,0x01 };
        push_case(8421, build_sendrr(cip1, 0, 0), "cip_path_boundary", "CIP path size > provided bytes");
        std::vector<uint8_t> cip2 = { 0x0E,0x03,0x21,0x01,0x25,0x01,0x31,0x01 };
        push_case(8422, build_sendrr(cip2, 0, 0), "cip_path_boundary", "CIP invalid logical segment mix");
    } else if (profile == "cip_service_mutation") {
        std::vector<uint8_t> cip1 = { 0x00,0x03,0x20,0x01,0x24,0x01,0x30,0x01 };
        std::vector<uint8_t> cip2 = { 0x7F,0x03,0x20,0x01,0x24,0x01,0x30,0x01 };
        std::vector<uint8_t> cip3 = { 0x4C,0x03,0x20,0x01,0x24,0x01,0x30,0x01 };
        push_case(8431, build_sendrr(cip1, 0, 0), "cip_service_mutation", "CIP service 0x00 mutation");
        push_case(8432, build_sendrr(cip2, 0, 0), "cip_service_mutation", "CIP reserved service 0x7F");
        push_case(8433, build_sendrr(cip3, 0, 0), "cip_service_mutation", "CIP vendor-specific service mutation");
    } else if (profile == "session_handle_anomalies") {
        std::vector<uint8_t> cip = { 0x0E,0x03,0x20,0x01,0x24,0x01,0x30,0x01 };
        push_case(8441, build_sendrr(cip, 0xFFFFFFFFu, 0), "session_handle_anomalies", "SendRRData with invalid all-ones session handle");
        push_case(8442, build_sendrr(cip, 0xDEADBEEFu, 0), "session_handle_anomalies", "SendRRData with random stale session handle");
        push_case(8443, build_sendrr(cip, 0x00000001u, 0), "session_handle_anomalies", "SendRRData with low non-zero session handle");
    } else if (profile == "io_udp_2222_anomalies") {
        std::vector<uint8_t> p1 = { 0x01,0x00,0x00,0x00, 0x00,0x00,0x01,0x00 };
        std::vector<uint8_t> p2 = { 0xFF,0xFF,0xFF,0x7F, 0xFF,0x7F,0x00,0x00, 0x41,0x41,0x41,0x41 };
        std::vector<uint8_t> p3 = { 0x00,0x00,0x00,0x00, 0x10,0x27,0x01 };
        push_case(8451, p1, "io_udp_2222_anomalies", "UDP/2222 short run/idle datagram");
        push_case(8452, p2, "io_udp_2222_anomalies", "UDP/2222 anomalous conn-id/sequence values");
        push_case(8453, p3, "io_udp_2222_anomalies", "UDP/2222 truncated payload");
    } else if (profile == "connection_manager_forward_open") {
        std::vector<uint8_t> cip1 = {
            0x54,0x02,             // ForwardOpen, path words=2
            0x20,0x06,0x24,0x01,   // Class 6, Instance 1
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        std::vector<uint8_t> cip2 = cip1;
        cip2.insert(cip2.end(), 32, 0xAA);
        push_case(8461, build_sendrr(cip1, 0, 0), "connection_manager_forward_open", "ForwardOpen minimal malformed payload");
        push_case(8462, build_sendrr(cip2, 0, 0), "connection_manager_forward_open", "ForwardOpen oversized malformed payload");
    } else if (profile == "unauthorized_writes") {
        std::vector<uint8_t> cip = {
            0x10,0x03,             // SetAttributeSingle
            0x20,0x04,             // Class Assembly
            0x24,0x01,             // Instance 1
            0x30,0x03,             // Attribute 3
            0x00,0x00
        };
        push_case(8471, build_sendrr(cip, 0, 0), "unauthorized_writes", "SetAttributeSingle write attempt");
    } else if (profile == "device_reset_attempt") {
        std::vector<uint8_t> cip = {
            0x05,0x02,             // Reset
            0x20,0x01,             // Class Identity
            0x24,0x01              // Instance 1
        };
        push_case(8481, build_sendrr(cip, 0, 0), "device_reset_attempt", "CIP Reset service attempt");
    }

    LOG_INFOF("ETHERNETIP_PLUGIN", "Generated %zu advanced EtherNet/IP attack seeds for %s", out.size(), profile.c_str());
    return !out.empty();
}

bool checkENIP(uint32_t now_ms, uint32_t src, uint32_t dst, uint8_t cip_service, uint16_t cls, uint16_t inst, uint16_t attr, uint16_t app_len) {

    return true;
}

// Complete doPacketAnalysis implementation with 5 IDS rules
bool EtherNetIPPlugin::doPacketAnalysis(const NetworkPacket& pkt) {
    // ===== FLOW MANAGEMENT: Track the packet in the flow tracking system =====
    trackPacketInFlow(pkt);

    if (pkt.is_udp && (pkt.src_port == ENIP_IO_UDP || pkt.dst_port == ENIP_IO_UDP)) {
        return analyzeIoDatagram(pkt);
    }

    const uint8_t* b = nullptr;
    size_t l = 0;
    if (!locateEnipFrame(pkt, b, l)) return false;

    // ENIP header present?
    uint16_t cmd = le16(b + 0);
    uint16_t elen = le16(b + 2);
    uint32_t session_handle = le32(b + 4);
    uint32_t status = le32(b + 8);
    if (l < 24 || 24 + elen > l) return false;

    bool alert_generated = false;
    uint32_t now_ms = static_cast<uint32_t>(pkt.ts_ms);
    if (now_ms == 0) {
        now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    }
    auto emitEvent = [&](const char* json, LogLevel level, bool mark_alert) {
        if (shouldSuppressEnipEvent(json, level, now_ms)) {
            return;
        }
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(json), level);
        if (mark_alert) {
            alert_generated = true;
        }
    };
    uint32_t src = ip_to_uint32(pkt.src_ip);
    uint32_t now_sec = (uint32_t)(now_ms / 1000U);
    uint32_t device_ip = 0;
    if (pkt.src_port == ENIP_TCP_PORT) {
        device_ip = ip_to_uint32(pkt.src_ip);
    } else if (pkt.dst_port == ENIP_TCP_PORT) {
        device_ip = ip_to_uint32(pkt.dst_ip);
    }

    // --- IDS Rule 1: Session Flooding Detection (REGSESSION) ---
    if (cmd == ENIP_CMD_REGSESSION) {
        if (pkt.dst_port == ENIP_TCP_PORT && session_handle != 0) {
            uint64_t alert_key = (static_cast<uint64_t>(device_ip) << 32) | session_handle;
            if (session_register_nonzero_alerted_.insert(alert_key).second) {
                PSRAMUtils::ScopedBuffer warn_buf(256);
                if (warn_buf.valid()) {
                    snprintf(warn_buf.get(), warn_buf.size(),
                             "{\"alert_type\":\"enip.session.register_nonzero\",\"type\":\"enip.session.register_nonzero\",\"client\":\"%s\",\"device\":\"%s\",\"handle\":\"0x%08" PRIX32 "\"}",
                             pkt.src_ip.c_str(), pkt.dst_ip.c_str(), session_handle);
                    emitEvent(warn_buf.get(), LogLevel::WARNING, true);
                }
            }
        }

        if (pkt.src_port == ENIP_TCP_PORT) {
            if (session_handle == 0) {
                uint64_t zero_key = (static_cast<uint64_t>(device_ip) << 32);
                if (session_zero_response_alerted_.insert(zero_key).second) {
                    PSRAMUtils::ScopedBuffer err_buf(256);
                    if (err_buf.valid()) {
                        snprintf(err_buf.get(), err_buf.size(),
                                 "{\"alert_type\":\"enip.session.register_zero\",\"type\":\"enip.session.register_zero\",\"device\":\"%s\"}",
                                 pkt.src_ip.c_str());
                        emitEvent(err_buf.get(), LogLevel::ERROR, true);
                    }
                }
            } else {
                auto existing = session_handle_devices_.find(session_handle);
                if (existing != session_handle_devices_.end() && existing->second != device_ip && device_ip != 0) {
                    char prev_ip[16];
                    snprintf(prev_ip, sizeof(prev_ip), "%u.%u.%u.%u",
                             (unsigned)(existing->second & 0xFF),
                             (unsigned)((existing->second >> 8) & 0xFF),
                             (unsigned)((existing->second >> 16) & 0xFF),
                             (unsigned)((existing->second >> 24) & 0xFF));
                    PSRAMUtils::ScopedBuffer reuse_buf(256);
                    if (reuse_buf.valid()) {
                        snprintf(reuse_buf.get(), reuse_buf.size(),
                                 "{\"alert_type\":\"enip.session.handle_reuse\",\"type\":\"enip.session.handle_reuse\",\"device\":\"%s\",\"previous_device\":\"%s\",\"handle\":\"0x%08" PRIX32 "\"}",
                                 pkt.src_ip.c_str(), prev_ip, session_handle);
                        emitEvent(reuse_buf.get(), LogLevel::WARNING, true);
                    }
                }
                session_handle_devices_[session_handle] = device_ip;
                uint64_t map_key = (static_cast<uint64_t>(device_ip) << 32) | session_handle;
                session_unknown_usage_alerted_.erase(map_key);
                session_unknown_usage_alerted_.erase(static_cast<uint64_t>(device_ip) << 32);
                session_register_nonzero_alerted_.erase(map_key);
                session_zero_response_alerted_.erase(map_key);
                session_zero_response_alerted_.erase(static_cast<uint64_t>(device_ip) << 32);
            }
        }

        static psram_map<uint32_t, uint32_t> session_attempts;
        static psram_map<uint32_t, uint32_t> session_time;

        // Check time window expiration (60 seconds)
        if (session_time[src] && (now_sec - session_time[src]) >= 60) {
            session_attempts[src] = 0;
        }

        session_attempts[src]++;
        session_time[src] = now_sec;

        if (session_attempts[src] > 10) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"enip.session.flood\",\"type\":\"enip.session.flood\",\"src\":\"%s\",\"attempts\":%lu,\"window\":60}",
                     pkt.src_ip.c_str(), (unsigned long)session_attempts[src]);
            emitEvent(msg, LogLevel::ERROR, true);
        }
    }

    // --- IDS Rule 2: SendRRData Storm Detection ---
    else if (cmd == ENIP_CMD_SENDRRDATA) {
        if (session_handle == 0) {
            uint64_t zero_use_key = (static_cast<uint64_t>(device_ip) << 32);
            if (session_unknown_usage_alerted_.insert(zero_use_key).second) {
                PSRAMUtils::ScopedBuffer warn_buf(256);
                if (warn_buf.valid()) {
                    snprintf(warn_buf.get(), warn_buf.size(),
                             "{\"alert_type\":\"enip.session.sendrrdata_zero_handle\",\"type\":\"enip.session.sendrrdata_zero_handle\",\"device\":\"%s\"}",
                             (pkt.src_port == ENIP_TCP_PORT) ? pkt.src_ip.c_str() : pkt.dst_ip.c_str());
                    emitEvent(warn_buf.get(), LogLevel::ERROR, true);
                }
            }
        } else {
            uint64_t usage_key = (static_cast<uint64_t>(device_ip) << 32) | session_handle;
            auto handle_it = session_handle_devices_.find(session_handle);
            bool known_handle = (handle_it != session_handle_devices_.end());
            bool handle_mismatch = known_handle && device_ip != 0 && handle_it->second != 0 && handle_it->second != device_ip;
            if (!known_handle || handle_mismatch) {
                if (session_unknown_usage_alerted_.insert(usage_key).second) {
                    PSRAMUtils::ScopedBuffer warn_buf(256);
                    if (warn_buf.valid()) {
                        if (!known_handle) {
                            snprintf(warn_buf.get(), warn_buf.size(),
                                     "{\"alert_type\":\"enip.session.unregistered_handle\",\"type\":\"enip.session.unregistered_handle\",\"device\":\"%s\",\"handle\":\"0x%08" PRIX32 "\"}",
                                     (pkt.src_port == ENIP_TCP_PORT) ? pkt.src_ip.c_str() : pkt.dst_ip.c_str(),
                                     session_handle);
                        } else {
                            char prev_ip[16];
                            snprintf(prev_ip, sizeof(prev_ip), "%u.%u.%u.%u",
                                     (unsigned)(handle_it->second & 0xFF),
                                     (unsigned)((handle_it->second >> 8) & 0xFF),
                                     (unsigned)((handle_it->second >> 16) & 0xFF),
                                     (unsigned)((handle_it->second >> 24) & 0xFF));
                            snprintf(warn_buf.get(), warn_buf.size(),
                                     "{\"alert_type\":\"enip.session.handle_mismatch\",\"type\":\"enip.session.handle_mismatch\",\"device\":\"%s\",\"registered_device\":\"%s\",\"handle\":\"0x%08" PRIX32 "\"}",
                                     (pkt.src_port == ENIP_TCP_PORT) ? pkt.src_ip.c_str() : pkt.dst_ip.c_str(),
                                     prev_ip,
                                     session_handle);
                        }
                        emitEvent(warn_buf.get(), LogLevel::WARNING, true);
                    }
                }
            }
        }

        static psram_map<uint32_t, uint32_t> rrdata_count;
        static psram_map<uint32_t, uint32_t> rrdata_time;

        // Check time window expiration (30 seconds)
        if (rrdata_time[src] && (now_sec - rrdata_time[src]) >= 30) {
            rrdata_count[src] = 0;
        }

        rrdata_count[src]++;
        rrdata_time[src] = now_sec;

        if (rrdata_count[src] > 50) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"enip.sendrrdata.storm\",\"type\":\"enip.sendrrdata.storm\",\"src\":\"%s\",\"requests\":%lu,\"window\":30}",
                     pkt.src_ip.c_str(), (unsigned long)rrdata_count[src]);
            emitEvent(msg, LogLevel::WARNING, true);
        }

        // Parse CIP content for detailed analysis
        uint8_t svc=0; bool is_resp=false; uint16_t cls=0, inst=0, attr=0;
        if (parseSendRRDataForCIP(b+24, elen, svc, is_resp, cls, inst, attr)) {
            if (!is_resp) {
                // --- IDS Rule 3: Write Operations Tracking ---
                if (svc == CIP_SVC_SET_ATTR_SINGLE ||
                    svc == CIP_SVC_SET_ATTR_LIST ||
                    svc == CIP_SVC_RESET ||
                    svc == CIP_SVC_FORWARD_OPEN ||
                    svc == CIP_SVC_LARGE_FORWARD_OPEN ||
                    svc == CIP_SVC_FORWARD_CLOSE) {
                    static psram_map<uint32_t, uint32_t> write_attempts;
                    static psram_map<uint32_t, uint32_t> write_time;

                    // Check time window expiration (120 seconds)
                    if (write_time[src] && (now_sec - write_time[src]) >= 120) {
                        write_attempts[src] = 0;
                    }

                    write_attempts[src]++;
                    write_time[src] = now_sec;

                    if (write_attempts[src] > 5) {
                        char msg[300];
                        snprintf(msg, sizeof(msg),
                                 "{\"alert_type\":\"enip.cip.write.storm\",\"type\":\"enip.cip.write.storm\",\"src\":\"%s\",\"writes\":%lu,\"window\":120,\"service\":\"0x%02x\",\"class\":\"0x%04x\"}",
                                 pkt.src_ip.c_str(), (unsigned long)write_attempts[src], svc, cls);
                        emitEvent(msg, LogLevel::ERROR, true);
                    } else {
                        // Report individual write operations (not a storm yet)
                        if (svc == CIP_SVC_SET_ATTR_SINGLE || svc == CIP_SVC_SET_ATTR_LIST) {
                            // Use stack buffer instead of std::stringstream to avoid IRAM
                            char msg[256];
                            snprintf(msg, sizeof(msg),
                                    "{\"alert_type\":\"enip.cip.write_request\",\"type\":\"enip.cip.write_request\",\"cip_service\":\"write\",\"code\":\"0x%02x\",\"class\":\"0x%04x\",\"instance\":%u,\"attribute\":%u}",
                                    svc, cls, inst, attr);
                            auto level = (cls==0x00F5 ? LogLevel::WARNING : LogLevel::INFO);
                            emitEvent(msg, level, true);
                        } else if (svc == CIP_SVC_RESET) {
                            auto level = (cls==0x0001 ? LogLevel::ERROR : LogLevel::WARNING);
                            // Use stack buffer instead of std::stringstream to avoid IRAM
                            char msg[128];
                            snprintf(msg, sizeof(msg),
                                    "{\"alert_type\":\"enip.cip.reset_request\",\"type\":\"enip.cip.reset_request\",\"cip_service\":\"reset(0x05)\",\"class\":\"0x%04x\"}", cls);
                            emitEvent(msg, level, true);
                        } else {
                            const char* svc_name =
                                (svc == CIP_SVC_FORWARD_OPEN) ? "forward_open(0x54)" :
                                (svc == CIP_SVC_LARGE_FORWARD_OPEN) ? "large_forward_open(0x5B)" :
                                "forward_close(0x4E)";
                            char msg[192];
                            snprintf(msg, sizeof(msg),
                                    "{\"alert_type\":\"enip.cip.connection_control_request\",\"type\":\"enip.cip.connection_control_request\",\"cip_service\":\"%s\",\"class\":\"0x%04x\",\"instance\":%u}",
                                    svc_name, cls, inst);
                            emitEvent(msg, LogLevel::WARNING, true);
                        }
                    }
                }
                // Read operations - track for reconnaissance
                else if (svc == CIP_SVC_GET_ATTR_SINGLE || svc == CIP_SVC_GET_ATTR_ALL) {
                    // Use stack buffer instead of std::stringstream to avoid IRAM
                    char msg[256];
                    snprintf(msg, sizeof(msg),
                            "{\"alert_type\":\"enip.cip.read_request\",\"type\":\"enip.cip.read_request\",\"cip_service\":\"read\",\"class\":\"0x%04x\",\"instance\":%u,\"attribute\":%u}",
                            cls, inst, attr);
                    emitEvent(msg, LogLevel::DEBUG, true);
                }
            }
        }
    }

    else if (cmd == ENIP_CMD_UNREGSESS) {
        if (session_handle == 0) {
            uint64_t zero_key = (static_cast<uint64_t>(device_ip) << 32);
            if (session_unknown_usage_alerted_.insert(zero_key).second) {
                PSRAMUtils::ScopedBuffer warn_buf(256);
                if (warn_buf.valid()) {
                    snprintf(warn_buf.get(), warn_buf.size(),
                             "{\"alert_type\":\"enip.session.unregister_zero_handle\",\"type\":\"enip.session.unregister_zero_handle\",\"participant\":\"%s\"}",
                             (pkt.src_port == ENIP_TCP_PORT) ? pkt.src_ip.c_str() : pkt.dst_ip.c_str());
                    emitEvent(warn_buf.get(), LogLevel::WARNING, true);
                }
            }
        } else {
            session_handle_devices_.erase(session_handle);
            uint64_t key = (static_cast<uint64_t>(device_ip) << 32) | session_handle;
            session_unknown_usage_alerted_.erase(key);
            session_unknown_usage_alerted_.erase(static_cast<uint64_t>(device_ip) << 32);
            session_register_nonzero_alerted_.erase(key);
            session_zero_response_alerted_.erase(key);
            session_zero_response_alerted_.erase(static_cast<uint64_t>(device_ip) << 32);
        }
    }

    // --- IDS Rule 4: Discovery Reconnaissance Detection ---
    else if (cmd == ENIP_CMD_LISTIDENTITY || cmd == ENIP_CMD_LISTSERVICES || cmd == ENIP_CMD_LISTINTERF) {
        static psram_map<uint32_t, uint32_t> discovery_count;
        static psram_map<uint32_t, uint32_t> discovery_time;

        if (cmd == ENIP_CMD_LISTSERVICES && pkt.src_port == ENIP_TCP_PORT && device_ip != 0) {
            bool cip_found = false;
            if (parseListServicesForSecurity(b + 24, elen, cip_found, nullptr)) {
                auto existing = cip_security_status_.find(device_ip);
                bool should_emit = (existing == cip_security_status_.end()) || (existing->second != cip_found);
                if (should_emit) {
                    cip_security_status_[device_ip] = cip_found;
                    PSRAMUtils::ScopedBuffer buf(256);
                    if (buf.valid()) {
                        snprintf(buf.get(), buf.size(),
                                 "{\"alert_type\":\"enip.cip.security_advertisement\",\"type\":\"enip.cip.security_advertisement\",\"device\":\"%s\",\"advertised\":%s}",
                                 pkt.src_ip.c_str(), cip_found ? "true" : "false");
                        emitEvent(buf.get(), cip_found ? LogLevel::INFO : LogLevel::WARNING, true);
                    }
                    if (cip_found) {
                        io_without_security_reported_.erase(device_ip);
                    }
                }
            }
        }

        // Check time window expiration (60 seconds)
        if (discovery_time[src] && (now_sec - discovery_time[src]) >= 60) {
            discovery_count[src] = 0;
        }

        discovery_count[src]++;
        discovery_time[src] = now_sec;

        if (discovery_count[src] > 20) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"enip.discovery.flood\",\"type\":\"enip.discovery.flood\",\"src\":\"%s\",\"discoveries\":%lu,\"window\":60,\"cmd\":\"0x%04x\"}",
                     pkt.src_ip.c_str(), (unsigned long)discovery_count[src], cmd);
            emitEvent(msg, LogLevel::WARNING, true);
        } else if (cmd == ENIP_CMD_LISTIDENTITY) {
            // Report individual ListIdentity responses using PSRAM buffers
            psram_string identity_payload;
            if (parseListIdentityPayloadPSRAM(b + 24, elen, identity_payload)) {
                emitEvent(identity_payload.c_str(), LogLevel::INFO, true);
            }
        }
    }

    // --- IDS Rule 5: Error Pattern Detection ---
    if (status != 0) {
        static psram_map<uint32_t, uint32_t> error_count;
        static psram_map<uint32_t, uint32_t> error_time;

        // Check time window expiration (30 seconds)
        if (error_time[src] && (now_sec - error_time[src]) >= 30) {
            error_count[src] = 0;
        }

        error_count[src]++;
        error_time[src] = now_sec;

        if (error_count[src] > 15) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"enip.error.pattern\",\"type\":\"enip.error.pattern\",\"src\":\"%s\",\"errors\":%lu,\"window\":30,\"status\":\"0x%08x\"}",
                     pkt.src_ip.c_str(), (unsigned long)error_count[src], (unsigned)status);
            emitEvent(msg, LogLevel::INFO, true);
        }
    }

    return alert_generated;
}


bool EtherNetIPPlugin::activeBroadcastDiscovery(uint32_t timeout_ms, std::string& out_json) {
    int s = AssessmentInterface::openBoundSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) { out_json = "{\"error\":\"socket\"}"; return false; }
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
    struct timeval tv{ .tv_sec = (int)(timeout_ms/1000), .tv_usec = (int)((timeout_ms%1000)*1000) };
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in dst{}; dst.sin_family = AF_INET; dst.sin_port = htons(ENIP_UDP_PORT);
    dst.sin_addr.s_addr = htonl(0xFFFFFFFFu); // 255.255.255.255

    uint8_t req[24]; buildEncapHeader(req, ENIP_CMD_LISTIDENTITY, 0, 0);
    ssize_t wr = ::sendto(s, req, sizeof(req), 0, (sockaddr*)&dst, sizeof(dst));
    if (wr != (ssize_t)sizeof(req)) { ::close(s); out_json = "{\"error\":\"send\"}"; return false; }

    // Receive loop - use PSRAM to avoid IRAM consumption
    psram_vector<psram_string> found;
    std::unordered_set<uint32_t,
                       std::hash<uint32_t>,
                       std::equal_to<uint32_t>,
                       PSRAMAllocator<uint32_t>> seen_by_ip;
    uint32_t rx_frames = 0;
    uint32_t rx_identify = 0;
    uint32_t parse_ok = 0;
    uint32_t parse_fail = 0;
    uint8_t rx[1024];
    for(;;) {
        sockaddr_in src{}; socklen_t slen = sizeof(src);
        ssize_t n = ::recvfrom(s, rx, sizeof(rx), 0, (sockaddr*)&src, &slen);
        if (n <= 0) break;
        rx_frames++;
        if (n < 24) continue;
        uint16_t cmd = le16(rx+0); uint16_t elen = le16(rx+2);
        if (cmd != ENIP_CMD_LISTIDENTITY) continue;
        rx_identify++;
        if ((size_t)n < 24 + elen) continue;
        psram_string one;
        if (parseListIdentityPayloadPSRAM(rx + 24, elen, one)) {
            parse_ok++;
            uint32_t ipbe = src.sin_addr.s_addr;
            if (seen_by_ip.find(ipbe) == seen_by_ip.end()) {
                char src_ip[16] = {0};
                if (!inet_ntoa_r(src.sin_addr, src_ip, sizeof(src_ip))) {
                    strncpy(src_ip, "0.0.0.0", sizeof(src_ip) - 1);
                    src_ip[sizeof(src_ip) - 1] = '\0';
                }
                cJSON* item = cJSON_Parse(one.c_str());
                if (item && cJSON_IsObject(item)) {
                    cJSON* ip_item = cJSON_GetObjectItem(item, "ip");
                    if (cJSON_IsString(ip_item) && ip_item->valuestring) {
                        if (strcmp(ip_item->valuestring, src_ip) != 0) {
                            cJSON_AddStringToObject(item, "reported_ip", ip_item->valuestring);
                            cJSON_ReplaceItemInObject(item, "ip", cJSON_CreateString(src_ip));
                        }
                    } else {
                        cJSON_AddStringToObject(item, "ip", src_ip);
                    }
                    cJSON_AddStringToObject(item, "source_ip", src_ip);
                    char* patched = cJSON_PrintUnformatted(item);
                    cJSON_Delete(item);
                    if (patched) {
                        found.push_back(PSRAMUtils::createPSRAMString(patched));
                        free(patched);
                    }
                } else {
                    if (item) cJSON_Delete(item);
                    found.push_back(one);
                }
                seen_by_ip.insert(ipbe);
            }
        } else {
            parse_fail++;
        }
    }
    ::close(s);

    // Build JSON array using PSRAM buffer instead of std::stringstream
    size_t total_size = 2;  // For "[]"
    for (const auto& item : found) {
        total_size += item.size() + 1;  // +1 for comma
    }

    PSRAMUtils::ScopedBuffer json_buf(total_size + 1);
    if (!json_buf.valid()) {
        out_json = "{\"error\":\"psram_alloc\"}";
        return false;
    }

    char* p = json_buf.get();
    *p++ = '[';
    for (size_t i = 0; i < found.size(); ++i) {
        if (i > 0) *p++ = ',';
        size_t len = found[i].size();
        memcpy(p, found[i].c_str(), len);
        p += len;
    }
    *p++ = ']';
    *p = '\0';

    out_json = json_buf.get();
    if (rx_frames > 0 && parse_ok == 0 && parse_fail > 0) {
        LOG_WARNINGF(TAG_EIP,
                     "ListIdentity parse failures: rx_frames=%lu identify=%lu parse_fail=%lu",
                     static_cast<unsigned long>(rx_frames),
                     static_cast<unsigned long>(rx_identify),
                     static_cast<unsigned long>(parse_fail));
    }
    return true;
}

// Enhanced IDS method for real-time packet analysis - COMMENTED OUT (not declared in header)
/*
bool EtherNetIPPlugin::checkPacket(uint32_t now_ms, uint32_t src, uint32_t dst, const uint8_t* pdu, size_t pdu_len) {
    // Basic validation for EtherNet/IP packets
    if (!pdu || pdu_len < 24) return false; // Minimum for Encapsulation header

    bool alert_generated = false;

    // Parse Encapsulation header
    uint16_t command = le16(pdu + 0);
    uint16_t length = le16(pdu + 2);
    // uint32_t session = le32(pdu + 4); // TODO: Use in future analysis
    uint32_t status = le32(pdu + 8);

    // Check for malformed packets
    if (length > pdu_len - 24) { // Length field exceeds packet size
        alert_generated = true;
    }

    // Monitor for suspicious command patterns
    if (command == ENIP_CMD_REGSESSION) {
        // Monitor excessive session registration attempts (potential DoS)
        static psram_map<uint32_t, uint32_t> session_attempts;
        static psram_map<uint32_t, uint32_t> session_time;

        uint32_t current_time = now_ms / 1000;
        session_attempts[src]++;

        if (session_time[src] && (current_time - session_time[src]) < 60) {
            if (session_attempts[src] > 10) { // More than 10 session attempts in 60 seconds
                alert_generated = true;
            }
        } else {
            session_attempts[src] = 1;
        }
        session_time[src] = current_time;

    } else if (command == ENIP_CMD_SENDRRDATA) {
        // Monitor for excessive SendRRData commands (potential scanning/attacks)
        static psram_map<uint32_t, uint32_t> rrdata_count;
        static psram_map<uint32_t, uint32_t> rrdata_time;

        uint32_t current_time = now_ms / 1000;
        rrdata_count[src]++;

        if (rrdata_time[src] && (current_time - rrdata_time[src]) < 30) {
            if (rrdata_count[src] > 50) { // More than 50 RR requests in 30 seconds
                alert_generated = true;
            }
        } else {
            rrdata_count[src] = 1;
        }
        rrdata_time[src] = current_time;

        // Analyze CIP content for write operations
        if (pdu_len > 24 && length > 0) {
            uint8_t service_code = 0;
            bool is_response = false;
            uint16_t cls = 0, inst = 0, attr = 0;

            if (parseSendRRDataForCIP(pdu + 24, length, service_code, is_response, cls, inst, attr)) {
                // Check for suspicious write services
                if (service_code == CIP_SVC_SET_ATTR_SINGLE ||
                    service_code == CIP_SVC_SET_ATTR_LIST ||
                    service_code == CIP_SVC_RESET) {
                    alert_generated = true;

                    // Track write attempts frequency
                    static psram_map<uint32_t, uint32_t> write_attempts;
                    static psram_map<uint32_t, uint32_t> write_time;

                    write_attempts[src]++;

                    if (write_time[src] && (current_time - write_time[src]) < 120) {
                        if (write_attempts[src] > 5) { // More than 5 writes in 2 minutes
                            alert_generated = true;
                        }
                    } else {
                        write_attempts[src] = 1;
                    }
                    write_time[src] = current_time;
                }
            }
        }

    } else if (command == ENIP_CMD_LISTIDENTITY ||
               command == ENIP_CMD_LISTSERVICES ||
               command == ENIP_CMD_LISTINTERF) {
        // Monitor for excessive discovery requests (reconnaissance)
        static psram_map<uint32_t, uint32_t> discovery_count;
        static psram_map<uint32_t, uint32_t> discovery_time;

        uint32_t current_time = now_ms / 1000;
        discovery_count[src]++;

        if (discovery_time[src] && (current_time - discovery_time[src]) < 60) {
            if (discovery_count[src] > 20) { // More than 20 discovery requests in 60 seconds
                alert_generated = true;
            }
        } else {
            discovery_count[src] = 1;
        }
        discovery_time[src] = current_time;
    }

    // Check for error status codes that might indicate attacks
    if (status != 0) {
        static psram_map<uint32_t, uint32_t> error_count;
        static psram_map<uint32_t, uint32_t> error_time;

        uint32_t current_time = now_ms / 1000;
        error_count[src]++;

        if (error_time[src] && (current_time - error_time[src]) < 30) {
            if (error_count[src] > 15) { // More than 15 errors in 30 seconds
                alert_generated = true;
            }
        } else {
            error_count[src] = 1;
        }
        error_time[src] = current_time;
    }

    return alert_generated;
}
*/

// ============================================================================
// FLOW MANAGEMENT IMPLEMENTATION (EtherNet/IP)
// ============================================================================

bool EtherNetIPPlugin::buildFlowKey(const NetworkPacket& packet, FlowKey& key) {
    // EtherNet/IP encapsulation header: 24 bytes minimum for TCP encapsulation
    if (packet.is_udp && (packet.src_port == ENIP_IO_UDP || packet.dst_port == ENIP_IO_UDP)) {
        PSRAMAllocator<char> alloc;
        key.src_ip = psram_string(packet.src_ip, alloc);
        key.dst_ip = psram_string(packet.dst_ip, alloc);
        key.src_port = packet.src_port;
        key.dst_port = packet.dst_port;
        char label[32];
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (locateUdpAppPayload(packet, payload, payload_len) && payload_len >= 4) {
            uint32_t conn_id = le32(payload);
            snprintf(label, sizeof(label), "UDP_IO_0x%08" PRIX32, conn_id);
        } else {
            snprintf(label, sizeof(label), "UDP_IO");
        }
        key.protocol_specific = psram_string(label, alloc);
        return true;
    }

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateEnipFrame(packet, data, data_len)) return false;
    (void)data_len;

    // Extract session handle (bytes 4-7, little-endian)
    uint32_t session_handle = le32(data + 4);

    PSRAMAllocator<char> alloc;
    key.src_ip = psram_string(packet.src_ip, alloc);
    key.dst_ip = psram_string(packet.dst_ip, alloc);
    key.src_port = packet.src_port;
    key.dst_port = packet.dst_port;

    // Protocol-specific: session handle as hex string
    // Session handle 0x00000000 means no session (ListIdentity, ListServices, etc.)
    char session_str[32];
    snprintf(session_str, sizeof(session_str), "0x%08" PRIX32, session_handle);
    key.protocol_specific = psram_string(session_str, alloc);

    return true;
}

bool EtherNetIPPlugin::classifyPacketOperation(const NetworkPacket& packet,
                                               psram_string& operation_type,
                                               psram_string& operation_details,
                                               bool& is_error) {
    PSRAMAllocator<char> alloc;
    is_error = false;

    if (packet.is_udp && (packet.src_port == ENIP_IO_UDP || packet.dst_port == ENIP_IO_UDP)) {
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (!locateUdpAppPayload(packet, payload, payload_len) || payload_len < 8) {
            char details[96];
            snprintf(details, sizeof(details), "UDP IO len=%u", (unsigned)packet.length);
            operation_type = psram_string("IO", alloc);
            operation_details = psram_string(details, alloc);
            return true;
        }
        uint32_t conn_id = le32(payload + 0);
        uint16_t seq = le16(payload + 4);
        uint16_t run_idle = le16(payload + 6);
        const char* state = (run_idle & 0x01) ? "RUN" : "IDLE";
        char details[160];
        snprintf(details, sizeof(details),
                 "UDP IO conn=0x%08" PRIX32 " seq=%u state=%s",
                 conn_id,
                 (unsigned)seq,
                 state);
        operation_type = psram_string("IO", alloc);
        operation_details = psram_string(details, alloc);
        return true;
    }

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateEnipFrame(packet, data, data_len)) return false;

    // Parse encapsulation header
    uint16_t command = le16(data + 0);
    uint16_t length = le16(data + 2);
    uint32_t session_handle = le32(data + 4);
    uint32_t status = le32(data + 8);

    // Check for error status (non-zero status indicates error)
    if (status != 0) {
        is_error = true;
        operation_type = psram_string("ERROR", alloc);
        char details[128];
        snprintf(details, sizeof(details), "CMD=0x%04X Status=0x%08" PRIX32 " Session=0x%08" PRIX32,
                command, status, session_handle);
        operation_details = psram_string(details, alloc);
        return true;
    }

    char details[256];

    // Classify based on command code
    switch (command) {
        case ENIP_CMD_LISTSERVICES:  // 0x0004
            operation_type = psram_string("DIAGNOSTIC", alloc);
            snprintf(details, sizeof(details), "CMD=0x0004 ListServices");
            break;

        case ENIP_CMD_LISTIDENTITY:  // 0x0063
            operation_type = psram_string("DIAGNOSTIC", alloc);
            snprintf(details, sizeof(details), "CMD=0x0063 ListIdentity");
            break;

        case ENIP_CMD_LISTINTERF:    // 0x0064
            operation_type = psram_string("DIAGNOSTIC", alloc);
            snprintf(details, sizeof(details), "CMD=0x0064 ListInterfaces");
            break;

        case ENIP_CMD_REGSESSION:    // 0x0065
            operation_type = psram_string("CONTROL", alloc);
            snprintf(details, sizeof(details), "CMD=0x0065 RegisterSession Session=0x%08" PRIX32, session_handle);
            break;

        case ENIP_CMD_UNREGSESS:     // 0x0066
            operation_type = psram_string("CONTROL", alloc);
            snprintf(details, sizeof(details), "CMD=0x0066 UnRegisterSession Session=0x%08" PRIX32, session_handle);
            break;

        case ENIP_CMD_SENDRRDATA: {  // 0x006F - explicit messaging (contains CIP packet)
            // Try to parse CIP service code from SendRRData payload
            if (data_len >= 24 + length && length >= 6) {
                const uint8_t* encap_data = data + 24;
                uint8_t service_code = 0;
                bool is_response = false;
                uint16_t cls = 0, inst = 0, attr = 0;

                if (parseSendRRDataForCIP(encap_data, length, service_code, is_response, cls, inst, attr)) {
                    // Classify based on CIP service
                    if (service_code == CIP_SVC_RESET) {
                        operation_type = psram_string("CONTROL", alloc);
                        snprintf(details, sizeof(details),
                                "CMD=0x006F SendRRData CIP_Reset Class=%u Inst=%u", cls, inst);
                    } else if (service_code == CIP_SVC_FORWARD_OPEN ||
                               service_code == CIP_SVC_LARGE_FORWARD_OPEN ||
                               service_code == CIP_SVC_FORWARD_CLOSE) {
                        operation_type = psram_string("CONTROL", alloc);
                        const char* svc_name =
                            (service_code == CIP_SVC_FORWARD_OPEN) ? "ForwardOpen" :
                            (service_code == CIP_SVC_LARGE_FORWARD_OPEN) ? "LargeForwardOpen" :
                            "ForwardClose";
                        snprintf(details, sizeof(details),
                                "CMD=0x006F SendRRData CIP_%s(0x%02X) Class=%u Inst=%u",
                                svc_name, service_code, cls, inst);
                    } else if (service_code == CIP_SVC_SET_ATTR_SINGLE || service_code == CIP_SVC_SET_ATTR_LIST) {
                        operation_type = psram_string("WRITE", alloc);
                        snprintf(details, sizeof(details),
                                "CMD=0x006F SendRRData CIP_SetAttr(0x%02X) Class=%u Inst=%u Attr=%u",
                                service_code, cls, inst, attr);
                    } else if (service_code == CIP_SVC_GET_ATTR_ALL || service_code == CIP_SVC_GET_ATTR_SINGLE) {
                        operation_type = psram_string("READ", alloc);
                        snprintf(details, sizeof(details),
                                "CMD=0x006F SendRRData CIP_GetAttr(0x%02X) Class=%u Inst=%u Attr=%u",
                                service_code, cls, inst, attr);
                    } else {
                        operation_type = psram_string("OTHER", alloc);
                        snprintf(details, sizeof(details),
                                "CMD=0x006F SendRRData CIP_Svc=0x%02X Class=%u Inst=%u",
                                service_code, cls, inst);
                    }
                } else {
                    // Could not parse CIP - generic SendRRData
                    operation_type = psram_string("OTHER", alloc);
                    snprintf(details, sizeof(details),
                            "CMD=0x006F SendRRData Session=0x%08" PRIX32 " Len=%u", session_handle, length);
                }
            } else {
                operation_type = psram_string("OTHER", alloc);
                snprintf(details, sizeof(details), "CMD=0x006F SendRRData (no CIP data)");
            }
            break;
        }

        default:
            operation_type = psram_string("OTHER", alloc);
            snprintf(details, sizeof(details), "CMD=0x%04X Unknown Session=0x%08" PRIX32, command, session_handle);
            break;
    }

    operation_details = psram_string(details, alloc);
    return true;
}

void EtherNetIPPlugin::updateProtocolState(const NetworkPacket& packet, FlowData& flow) {
    // EtherNet/IP state machine:
    // INIT -> CONNECTING (RegisterSession request) -> ESTABLISHED (RegisterSession response with session handle) ->
    // DATA_EXCHANGE (SendRRData/SendUnitData) -> CLOSING (UnRegisterSession) -> CLOSED

    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateEnipFrame(packet, data, data_len)) return;
    (void)data_len;
    uint16_t command = le16(data + 0);
    uint32_t session_handle = le32(data + 4);
    uint32_t status = le32(data + 8);

    // Check for error status
    if (status != 0 && flow.state != FlowState::ERROR && flow.state != FlowState::CLOSED) {
        flow.state = FlowState::ERROR;
        return;
    }

    if (flow.state == FlowState::INIT) {
        if (command == ENIP_CMD_REGSESSION) {
            flow.state = FlowState::CONNECTING;
            return;
        }
        if (command == ENIP_CMD_LISTIDENTITY ||
            command == ENIP_CMD_LISTSERVICES ||
            command == ENIP_CMD_LISTINTERF) {
            flow.state = FlowState::DATA_EXCHANGE;
            return;
        }
        if (command == ENIP_CMD_SENDRRDATA || command == 0x0070) {
            // SendRRData without session handle is a protocol anomaly.
            flow.state = (session_handle == 0) ? FlowState::ERROR : FlowState::DATA_EXCHANGE;
            return;
        }
        if (command == ENIP_CMD_UNREGSESS) {
            flow.state = (session_handle == 0) ? FlowState::ERROR : FlowState::CLOSING;
            return;
        }
        flow.state = FlowState::DATA_EXCHANGE;
        return;
    }

    if (flow.state == FlowState::CONNECTING) {
        if (command == ENIP_CMD_REGSESSION) {
            flow.state = (session_handle != 0 && status == 0) ? FlowState::ESTABLISHED : FlowState::ERROR;
            return;
        }
        if (command == ENIP_CMD_UNREGSESS) {
            flow.state = FlowState::CLOSING;
            return;
        }
        if (command == ENIP_CMD_SENDRRDATA || command == 0x0070) {
            flow.state = (session_handle == 0) ? FlowState::ERROR : FlowState::DATA_EXCHANGE;
            return;
        }
        return;
    }

    if (flow.state == FlowState::ESTABLISHED) {
        if (command == ENIP_CMD_SENDRRDATA || command == 0x0070) {
            flow.state = (session_handle == 0) ? FlowState::ERROR : FlowState::DATA_EXCHANGE;
            return;
        }
        if (command == ENIP_CMD_UNREGSESS) {
            flow.state = FlowState::CLOSING;
            return;
        }
        return;
    }

    if (flow.state == FlowState::DATA_EXCHANGE) {
        if (command == ENIP_CMD_UNREGSESS) {
            flow.state = FlowState::CLOSING;
            return;
        }
        if ((command == ENIP_CMD_SENDRRDATA || command == 0x0070) && session_handle == 0) {
            flow.state = FlowState::ERROR;
            return;
        }
        return;
    }

    if (flow.state == FlowState::CLOSING) {
        flow.state = FlowState::CLOSED;
        return;
    }
}

void EtherNetIPPlugin::assignFlowLabel(FlowData& flow) {
    flow.metrics.secondary_label = FlowLabel::NORMAL_OPERATION;

    uint32_t regsession_count = 0;
    uint32_t discovery_count = 0;
    uint32_t reset_count = 0;
    uint32_t connection_ctrl_count = 0;
    uint32_t protocol_error_ops = 0;
    uint32_t zero_session_ops = 0;

    for (const auto& op : flow.recent_operations) {
        if (op.type == "ERROR") {
            protocol_error_ops++;
        }
        if (op.details.find("RegisterSession") != psram_string::npos ||
            op.details.find("UnRegisterSession") != psram_string::npos) {
            regsession_count++;
            connection_ctrl_count++;
        }
        if (op.details.find("ListIdentity") != psram_string::npos ||
            op.details.find("ListServices") != psram_string::npos ||
            op.details.find("ListInterfaces") != psram_string::npos) {
            discovery_count++;
        }
        if (op.details.find("CIP_Reset") != psram_string::npos) {
            reset_count++;
            connection_ctrl_count++;
        }
        if (op.details.find("ForwardOpen") != psram_string::npos ||
            op.details.find("ForwardClose") != psram_string::npos ||
            op.details.find("LargeForwardOpen") != psram_string::npos) {
            connection_ctrl_count++;
        }
        if (op.details.find("Session=0x00000000") != psram_string::npos) {
            zero_session_ops++;
        }
    }

    // 1. Check for flooding attacks
    if (flow.metrics.intensity == FlowIntensity::FLOODING) {
        flow.metrics.primary_label = FlowLabel::FLOODING;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 2. Protocol/state anomalies and malformed/error dominance.
    if (flow.state == FlowState::ERROR || flow.metrics.malformed_packets > 2 || protocol_error_ops > 5) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::PROTOCOL_VIOLATION;
        return;
    }

    // 3. Check for excessive error rate.
    if (flow.metrics.hasTooManyErrors(0.25f) &&
        (flow.metrics.read_operations + flow.metrics.write_operations + flow.metrics.control_operations) > 5) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::PROTOCOL_VIOLATION;
        return;
    }

    // 4. Dangerous operations.
    if (reset_count > 0) {
        flow.metrics.primary_label = FlowLabel::DANGEROUS_OPERATION;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 5. Session abuse / hijack indicators.
    if ((regsession_count > 20 && flow.metrics.intensity >= FlowIntensity::HIGH) || zero_session_ops > 3) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = (zero_session_ops > 0)
            ? FlowLabel::SESSION_HIJACKING
            : FlowLabel::BRUTE_FORCE_ATTEMPT;
        return;
    }

    // 6. Discovery reconnaissance patterns.
    if (discovery_count > 20 && flow.metrics.write_operations == 0 && flow.metrics.control_operations == 0) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 7. Check for scanning/reconnaissance patterns
    if (flow.metrics.intensity >= FlowIntensity::VERY_HIGH &&
        flow.metrics.isReader() &&
        flow.getOperationCount() > 50) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 8. Normal classification based on operation types
    if (flow.metrics.isWriter()) {
        flow.metrics.primary_label = (flow.metrics.write_operations > flow.metrics.read_operations * 2)
            ? FlowLabel::WRITER : FlowLabel::MIXED_RW;
        if (connection_ctrl_count > 0) {
            flow.metrics.secondary_label = FlowLabel::CONFIGURATION_TAMPERING;
        }
        if (flow.metrics.getWriteRatio() > 0.7f && flow.metrics.write_operations >= 5) {
            flow.metrics.primary_label = FlowLabel::CRITICAL_WRITE;
        }
    } else if (flow.metrics.isReader()) {
        flow.metrics.primary_label = FlowLabel::READER;
        // Check for polling pattern (regular medium intensity reads)
        if (flow.metrics.intensity >= FlowIntensity::LOW &&
            flow.metrics.intensity <= FlowIntensity::MEDIUM &&
            flow.metrics.read_operations > 10) {
            flow.metrics.secondary_label = FlowLabel::POLLING;
        }
    } else if (flow.metrics.control_operations > flow.metrics.read_operations + flow.metrics.write_operations) {
        flow.metrics.primary_label = FlowLabel::DIAGNOSTIC;
        if (connection_ctrl_count > 3) {
            flow.metrics.secondary_label = FlowLabel::POTENTIAL_ATTACK;
        }
    } else {
        flow.metrics.primary_label = FlowLabel::NORMAL_OPERATION;
    }

    // 9. Mark heavy users
    if (flow.metrics.intensity == FlowIntensity::HIGH &&
        flow.metrics.primary_label != FlowLabel::SCANNER) {
        flow.metrics.secondary_label = FlowLabel::HEAVY_USER;
    }
}
