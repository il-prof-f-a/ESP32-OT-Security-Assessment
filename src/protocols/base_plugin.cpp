#include "base_plugin.h"
#include "../core/configuration_manager.h"
#include "../core/reporting_engine.h"
#include "../core/logging_system.h"
#include "../core/plugin_manager.h"
#include "../network/eth_l2_adapter.h"
#include "../network/assessment_interface.h"
#include "../network/icmp_ping.h"
#include "../assessment/discovery_manager.h"
#include "../core/psram_json_parser.h"

extern "C" {
    #include "esp_task_wdt.h"
    #include "esp_timer.h"
    #include "esp_netif.h"
    #include "esp_heap_caps.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "lwip/sockets.h"
    #include "lwip/inet.h"
}

#include <errno.h>
#include <cstring>
#include <algorithm>
#include <cstdlib>
#include <vector>
#include <fcntl.h>

#ifdef SO_BINDTODEVICE
#include <net/if.h>
#endif

#include <sstream>


namespace {
    struct JsonHookGuard {
        JsonHookGuard() { PSRAMJson::ensureHooks(); }
    };
    static JsonHookGuard kJsonHookGuard;

    static const char* TAG_GENERAL = "GeneralDiscovery";
    static const char* TAG_WRITER = "WriterGuard";

    class ScopedGeneralDiscoveryWdt {
    public:
        ScopedGeneralDiscoveryWdt(ConfigurationManager* cfg, uint32_t min_timeout_ms)
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
                LOG_INFOF(TAG_GENERAL, "Task WDT extended to %ums for general discovery", (unsigned)desired);
            } else {
                LOG_WARNING(TAG_GENERAL, "Unable to extend the Task WDT for general discovery");
            }
        }

        ~ScopedGeneralDiscoveryWdt() {
            if (!valid_) {
                return;
            }
            if (esp_task_wdt_reconfigure(&saved_config_) == ESP_OK) {
                LOG_INFOF(TAG_GENERAL, "Task WDT restored to %ums", (unsigned)saved_config_.timeout_ms);
            } else {
                LOG_WARNING(TAG_GENERAL, "Task WDT restore failed after general discovery");
            }
        }
    private:
        ConfigurationManager* cfg_ = nullptr;
        esp_task_wdt_config_t saved_config_{};
        bool valid_ = false;
    };

    static inline void feedGeneralDiscoveryWatchdog() {
    #ifdef CONFIG_ESP_TASK_WDT
        esp_task_wdt_reset();
    #endif
        taskYIELD();
    }

    static size_t copyTrimmed(const char* src, size_t src_len, char* dst, size_t dst_sz) {
        if (!src || dst_sz == 0) return 0;
        size_t w = 0;
        for (size_t i = 0; i < src_len && (w + 1) < dst_sz; ++i) {
            char c = src[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            dst[w++] = c;
        }
        if (w < dst_sz) dst[w] = '\0';
        return w;
    }

    static bool expandTargets(const char* target,
                              psram_vector<psram_string>& out,
                              uint32_t max_hosts,
                              bool* truncated) {
        if (!target || !*target) return false;
        const char* slash = strchr(target, '/');
        if (!slash) {
            out.push_back(PSRAMUtils::createPSRAMString(target));
            if (truncated) *truncated = false;
            return true;
        }
        char base_ip[16];
        size_t ip_len = (size_t)(slash - target);
        if (ip_len == 0 || ip_len >= sizeof(base_ip)) return false;
        memcpy(base_ip, target, ip_len);
        base_ip[ip_len] = '\0';
        int prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return false;
        ip4_addr_t base_addr;
        if (!ip4addr_aton(base_ip, &base_addr)) return false;
        uint32_t base_host = lwip_ntohl(base_addr.addr);
        uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
        if (prefix == 32) mask = 0xFFFFFFFFu;
        uint32_t network = base_host & mask;
        uint32_t first = base_host;
        uint32_t last = base_host;
        if (prefix < 31) {
            uint32_t broadcast = network | (~mask);
            first = network + 1;
            last = (broadcast > network) ? (broadcast - 1) : broadcast;
        } else if (prefix == 31) {
            first = network;
            last = network + 1;
        }
        if (prefix == 32) {
            first = base_host;
            last = base_host;
        }
        if (last < first) return false;
        uint32_t total = last - first + 1;
        if (max_hosts == 0) {
            max_hosts = 512;
        }
        bool trunc_local = false;
        uint32_t limit = total;
        if (limit > max_hosts) {
            limit = max_hosts;
            trunc_local = true;
        }
        out.reserve(out.size() + limit);
        for (uint32_t idx = 0; idx < limit; ++idx) {
            uint32_t host = first + idx;
            ip4_addr_t addr;
            addr.addr = lwip_htonl(host);
            char ip_buf[16];
            snprintf(ip_buf, sizeof(ip_buf), IPSTR, IP2STR(&addr));
            out.push_back(PSRAMUtils::createPSRAMString(ip_buf));
        }
        if (truncated) *truncated = trunc_local;
        return true;
    }
}


void BasePlugin::onPacket(const NetworkPacket& pkt, bool bypassAuthorization) {
    if (isTargetPacket(pkt)) {

        // Base-level writers authorization/reporting (PSRAM-only data).
        // Writer events are always evaluated/logged even when IDS requests bypass.
        enforceWritersAuthorization(pkt, bypassAuthorization);

        // Call consolidated IDS analysis only if IDS is enabled
        bool ids_enabled = true;
        if (cfg_) { ids_enabled = cfg_->getIDSConfig().enabled; }
        if (ids_enabled) {
            doPacketAnalysis(pkt);
        }
    }
}

static inline bool is_hex_digit(char c) {
    return (c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');
}

void BasePlugin::loadAllowedWritersFromConfig() {
    allowed_writer_ips_.clear();
    allowed_writer_macs_.clear();
    if (!cfg_) return;
    // Read plugin-specific config map
    auto m = cfg_->getProtocolConfig(getProtocolType());
    auto it = m.find("allowed_writers");
    if (it == m.end()) return;
    const psram_string& csv = it->second; // CSV containing IPs and/or MACs (PSRAM-backed)
    // Parse CSV without allocating extra strings
    size_t i = 0, n = csv.size();
    while (i < n) {
        // Extract token until comma
        size_t j = i;
        while (j < n && csv[j] != ',') ++j;
        // Trim spaces
        size_t a = i; while (a < j && (csv[a]==' '||csv[a]=='\t')) ++a;
        size_t b = j; while (b > a && (csv[b-1]==' '||csv[b-1]=='\t')) --b;
        if (b > a) {
            // Classify token as MAC if it contains ':' and looks like hex pairs
            bool has_colon = false; int hex_pairs = 0; int curr_len = 0; bool mac_like = true;
            for (size_t k=a; k<b; ++k) {
                char c = csv[k];
                if (c == ':') { has_colon = true; if (curr_len == 2) { hex_pairs++; curr_len = 0; } else { mac_like = false; break; } }
                else if (is_hex_digit(c)) { curr_len++; if (curr_len>2) { mac_like=false; break; } }
                else { mac_like = false; break; }
            }
            size_t tok_len = b - a;
            if (mac_like && has_colon && (hex_pairs>=2)) {
                // store in MAC list directly into PSRAM (no std::string temp)
                psram_string tok;
                tok.reserve(tok_len);
                for (size_t k=a; k<b; ++k) tok.push_back(csv[k]);
                if (!tok.empty()) allowed_writer_macs_.push_back(tok);
            } else {
                // treat as IP/FQDN; store into PSRAM vector (no std::string temp)
                psram_string tok;
                tok.reserve(tok_len);
                for (size_t k=a; k<b; ++k) tok.push_back(csv[k]);
                if (!tok.empty()) allowed_writer_ips_.push_back(tok);
            }
        }
        i = (j < n) ? (j + 1) : j;
    }
}

bool BasePlugin::isWriterAuthorized(const std::string& src_ip, const std::string& src_mac) const {
    // If no restrictions configured, allow
    if (allowed_writer_ips_.empty() && allowed_writer_macs_.empty()) return true;
    // Check MAC allow list (exact or case-insensitive colon-separated)
    if (!src_mac.empty()) {
        // Canonicalize src_mac to uppercase with ':' using stack buffer instead of std::string
        char mac[32];  // MAC addresses are typically 17 chars (XX:XX:XX:XX:XX:XX)
        size_t mac_len = src_mac.size();
        if (mac_len >= sizeof(mac)) mac_len = sizeof(mac) - 1;

        for (size_t i = 0; i < mac_len; ++i) {
            char c = src_mac[i];
            if (c == '-') c = ':';
            mac[i] = (char)toupper((unsigned char)c);
        }
        mac[mac_len] = '\0';

        for (const auto& m : allowed_writer_macs_) {
            const char* pat = m.c_str();
            // Compare case-insensitive exact (wildcards could be added later)
            // Convert pat to uppercase on the fly
            size_t L = m.size();
            if (L == mac_len) {
                bool eq = true;
                for (size_t k=0; k<L; ++k) {
                    char pc = pat[k]; if (pc=='-') pc=':'; pc = (char)toupper((unsigned char)pc);
                    if (pc != mac[k]) { eq = false; break; }
                }
                if (eq) return true;
            }
        }
    }
    // Check IP allow list (exact string compare)
    if (!src_ip.empty()) {
        for (const auto& ip : allowed_writer_ips_) {
            if (src_ip.size() == ip.size() && memcmp(src_ip.c_str(), ip.c_str(), ip.size()) == 0) return true;
        }
    }
    return false;
}

void BasePlugin::enforceWritersAuthorization(const NetworkPacket& pkt, bool bypassAuthorization) {
    // Only enforce if plugin reports this packet as a WRITE
    if (!isPacketWriter(pkt)) return;
    std::string src_mac = EthL2Adapter::macToString(pkt.src_mac);
    bool has_policy = !(allowed_writer_ips_.empty() && allowed_writer_macs_.empty());
    bool authorized_by_policy = has_policy ? isWriterAuthorized(pkt.src_ip, src_mac) : false;
    bool allowed_by_trusted_writer = bypassAuthorization;
    bool allowed_by_allowed_writers = authorized_by_policy;
    bool allowed_by_default_no_policy = (!has_policy && !bypassAuthorization);
    bool effective_allowed = allowed_by_trusted_writer || allowed_by_allowed_writers || allowed_by_default_no_policy;
    const char* allow_reason = "denied";
    if (effective_allowed) {
        if (allowed_by_trusted_writer) {
            allow_reason = "trusted_writer";
        } else if (allowed_by_allowed_writers) {
            allow_reason = "allowed_writers";
        } else {
            allow_reason = "no_allowed_writers_policy";
        }
    }

    // Always emit a plain serial log line for writer visibility, independent from reporting filters.
    if (effective_allowed) {
        LOG_INFOF(TAG_WRITER,
                  "Writer packet ALLOWED: reason=%s proto=%s src=%s:%u dst=%s:%u src_mac=%s policy_configured=%s in_allowed_writers=%s trusted_writer=%s",
                  allow_reason,
                  PluginManager::protocolTypeToString(pkt.proto),
                  pkt.src_ip.c_str(), (unsigned)pkt.src_port,
                  pkt.dst_ip.c_str(), (unsigned)pkt.dst_port,
                  src_mac.c_str(),
                  has_policy ? "true" : "false",
                  authorized_by_policy ? "true" : "false",
                  bypassAuthorization ? "true" : "false");
    } else {
        LOG_WARNINGF(TAG_WRITER,
                     "UNAUTHORIZED writer packet: reason=not_trusted_writer_and_not_in_allowed_writers proto=%s src=%s:%u dst=%s:%u src_mac=%s policy_configured=%s blocked=true",
                     PluginManager::protocolTypeToString(pkt.proto),
                     pkt.src_ip.c_str(), (unsigned)pkt.src_port,
                     pkt.dst_ip.c_str(), (unsigned)pkt.dst_port,
                     src_mac.c_str(),
                     has_policy ? "true" : "false");
    }

    events_generated_++;
}

bool BasePlugin::parseTarget(const std::string& target, std::string& ip, uint16_t& port) const {
    // Get default port from configuration for this protocol
    uint16_t default_port = 0;

    if (cfg_) {
        auto config = cfg_->getProtocolConfig(type_);

        // Try different port field names used by different protocols
        auto it_default_port = config.find(PSRAMUtils::createPSRAMString("default_port"));
        auto it_port = config.find(PSRAMUtils::createPSRAMString("port"));
        auto it_tcp_port = config.find(PSRAMUtils::createPSRAMString("tcp_port"));

        if (it_default_port != config.end()) {
            default_port = (uint16_t)atoi(it_default_port->second.c_str());
        } else if (it_port != config.end()) {
            default_port = (uint16_t)atoi(it_port->second.c_str());
        } else if (it_tcp_port != config.end()) {
            default_port = (uint16_t)atoi(it_tcp_port->second.c_str());
        }
    }

    // Fallback to hardcoded defaults if configuration doesn't provide port
    if (default_port == 0) {
        switch (type_) {
            case ProtocolType::MODBUS_TCP: default_port = 502; break;
            case ProtocolType::S7_COMM: default_port = 102; break;
            case ProtocolType::OPC_UA: default_port = 4840; break;
            case ProtocolType::ETHERNET_IP: default_port = 44818; break;
            case ProtocolType::PROFINET: default_port = 0; break; // No port for PROFINET (Layer 2)
            default: default_port = 0; break;
        }
    }

    // Parse target string (format: "ip" or "ip:port")
    ip.clear();
    port = default_port;

    auto colon_pos = target.find(':');
    if (colon_pos == std::string::npos) {
        // No port specified - use default
        ip = target;
    } else {
        // Port specified - parse it
        ip = target.substr(0, colon_pos);
        int parsed_port = atoi(target.substr(colon_pos + 1).c_str());
        if (parsed_port > 0 && parsed_port <= 65535) {
            port = (uint16_t)parsed_port;
        } else {
            port = default_port;
        }
    }

    return !ip.empty();
}

bool BasePlugin::parseTarget(const psram_string& target, psram_string& ip, uint16_t& port) const {
    std::string ip_std;
    bool ok = parseTarget(PSRAMUtils::fromPSRAMString(target), ip_std, port);
    if (!ok) {
        ip.clear();
        return false;
    }
    ip = PSRAMUtils::createPSRAMString(ip_std.c_str());
    return true;
}

void BasePlugin::reportVulnerability(const std::string& target,
                                    const std::string& payload_json,
                                    const std::string& extra,
                                    LogLevel level) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string payload_ps = payload_json.empty()
        ? psram_string{}
        : PSRAMUtils::createPSRAMString(payload_json.c_str());
    psram_string extra_ps = extra.empty()
        ? psram_string{}
        : PSRAMUtils::createPSRAMString(extra.c_str());
    reportVulnerabilityPSRAM(target_ps, payload_ps, extra_ps, level);
}

void BasePlugin::reportVulnerabilityPSRAM(const psram_string& target,
                                          const psram_string& payload_json,
                                          const psram_string& extra,
                                          LogLevel level) {
    PSRAMJsonParser::PSRAMContext json_ctx;
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return;
    }

    cJSON_AddStringToObject(root, "plugin", name_.c_str());
    cJSON_AddStringToObject(root, "version", version_.c_str());
    cJSON_AddStringToObject(root, "target", target.c_str());
    cJSON_AddStringToObject(root, "target_ip", target.c_str());

    if (!extra.empty()) {
        const char* extra_c = extra.c_str();
        size_t extra_len = extra.length();
        if (extra_len > 1 && extra_c[0] == '{' && extra_c[extra_len - 1] == '}') {
            cJSON* extra_obj = cJSON_Parse(extra_c);
            if (extra_obj) {
                cJSON_AddItemToObject(root, "extra", extra_obj);
            } else {
                cJSON_AddStringToObject(root, "extra", extra_c);
            }
        } else {
            cJSON_AddStringToObject(root, "extra", extra_c);
        }
    }

    if (!payload_json.empty()) {
        const char* payload_c = payload_json.c_str();
        size_t payload_len = payload_json.length();
        if (payload_len > 1 && payload_c[0] == '{' && payload_c[payload_len - 1] == '}') {
            cJSON* data_obj = cJSON_Parse(payload_c);
            if (data_obj) {
                cJSON* it = nullptr;
                cJSON_ArrayForEach(it, data_obj) {
                    cJSON_ReplaceItemInObject(root, it->string, cJSON_Duplicate(it, 1));
                }
                cJSON_Delete(data_obj);
            } else {
                cJSON_AddStringToObject(root, "data", payload_c);
            }
        } else {
            cJSON_AddStringToObject(root, "data", payload_c);
        }
    }

    if (rep_) {
        char* json = cJSON_PrintUnformatted(root);
        if (json) {
            psram_string type = PSRAMUtils::createPSRAMString("vulnerability_alert");
            psram_string payload = PSRAMUtils::createPSRAMString(json);
            rep_->reportEvent(type, payload);
            free(json);
        }
    }

    cJSON_Delete(root);
    events_generated_++;
}

void BasePlugin::reportIntrusion(const NetworkPacket& pkt,
                                 const std::string& payload_json,
                                 LogLevel level) {
    psram_string payload_ps = payload_json.empty()
        ? psram_string{}
        : PSRAMUtils::createPSRAMString(payload_json.c_str());
    reportIntrusionPSRAM(pkt, payload_ps, level);
}

void BasePlugin::reportIntrusionPSRAM(const NetworkPacket& pkt,
                                      const psram_string& payload_json,
                                      LogLevel level) {
    PSRAMJsonParser::PSRAMContext json_ctx;
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return;
    }

    cJSON_AddStringToObject(root, "plugin", name_.c_str());
    cJSON_AddStringToObject(root, "version", version_.c_str());
    cJSON_AddStringToObject(root, "src", pkt.src_ip.c_str());
    cJSON_AddStringToObject(root, "dst", pkt.dst_ip.c_str());
    cJSON_AddNumberToObject(root, "sport", pkt.src_port);
    cJSON_AddNumberToObject(root, "dport", pkt.dst_port);
    cJSON_AddBoolToObject(root, "is_tcp", pkt.is_tcp);
    cJSON_AddBoolToObject(root, "is_udp", pkt.is_udp);
    cJSON_AddNumberToObject(root, "timestamp_ms", (double)pkt.ts_ms);

    if (!payload_json.empty()) {
        const char* payload_c = payload_json.c_str();
        size_t payload_len = payload_json.length();
        if (payload_len > 1 && payload_c[0] == '{' && payload_c[payload_len - 1] == '}') {
            cJSON* data_obj = cJSON_Parse(payload_c);
            if (data_obj) {
                cJSON* it = nullptr;
                cJSON_ArrayForEach(it, data_obj) {
                    cJSON_ReplaceItemInObject(root, it->string, cJSON_Duplicate(it, 1));
                }
                cJSON_Delete(data_obj);
            } else {
                cJSON_AddStringToObject(root, "data", payload_c);
            }
        } else {
            cJSON_AddStringToObject(root, "data", payload_c);
        }
    }

    if (rep_) {
        char* json = cJSON_PrintUnformatted(root);
        if (json) {
            psram_string type = PSRAMUtils::createPSRAMString("intrusion_detection");
            psram_string payload = PSRAMUtils::createPSRAMString(json);
            rep_->reportEvent(type, payload);
            free(json);
        }
    }

    cJSON_Delete(root);
    events_generated_++;
}


std::string BasePlugin::runGeneralDiscovery(const GeneralDiscoveryConfig& cfg,
                                           ReportingEngine* rep,
                                           ConfigurationManager* cfg_mgr) {
    const uint32_t kMinWdtMs = 180000U;

    uint32_t wdt_timeout_ms = kMinWdtMs;
    if (cfg.total_timeout_ms > wdt_timeout_ms) {
        wdt_timeout_ms = cfg.total_timeout_ms;
    }
    ScopedGeneralDiscoveryWdt wdt_guard(cfg_mgr, wdt_timeout_ms);

    const char* mode_label = nullptr;
    if (!cfg.mode_label.empty()) {
        mode_label = cfg.mode_label.c_str();
    } else {
        mode_label = cfg.port_scan ? "ports" : "ping";
    }

    PSRAMJsonParser::PSRAMContext json_ctx;

    char target_norm[64] = {0};
    const char* raw_target = cfg.target.empty() ? nullptr : cfg.target.c_str();
    size_t raw_len = cfg.target.size();
    if (raw_target) {
        copyTrimmed(raw_target, raw_len, target_norm, sizeof(target_norm));
    }
    if (!raw_target || target_norm[0] == '\0') {
        LOG_WARNING(TAG_GENERAL, "Invalid target for general discovery");
        cJSON* err = cJSON_CreateObject();
        if (!err) {
            return std::string("{}");
        }
        cJSON_AddStringToObject(err, "status", "invalid_target");
        char* js = cJSON_PrintUnformatted(err);
        std::string out = js ? std::string(js) : std::string("{}");
        if (js) heap_caps_free(js);
        cJSON_Delete(err);
        return out;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return std::string("{}");
    }
    cJSON_AddStringToObject(root, "job", "general_discovery");
    cJSON_AddStringToObject(root, "target", target_norm);
    cJSON_AddStringToObject(root, "mode", mode_label);

    cJSON* hosts = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "hosts", hosts);
    cJSON* reachable_summary = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "reachable_hosts", reachable_summary);

    // Assessment traffic is always Ethernet-only. bind_ifkey is retained in
    // the public structure for configuration compatibility but cannot override
    // the security boundary.
    const char* requested_ifkey = "ETH_DEF";
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t ip_info{};
    if (!netif || esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        cJSON_AddStringToObject(root, "status", "ethernet_not_ready");
        cJSON_AddStringToObject(root, "interface", requested_ifkey);
        char* js = cJSON_PrintUnformatted(root);
        std::string out = js ? std::string(js) : std::string("{}");
        if (js) heap_caps_free(js);
        cJSON_Delete(root);
        return out;
    }
    char bound_ip[16];
    snprintf(bound_ip, sizeof(bound_ip), IPSTR, IP2STR(&ip_info.ip));
    if (requested_ifkey && requested_ifkey[0] != '\0') {
        cJSON_AddStringToObject(root, "interface", requested_ifkey);
    }

    psram_vector<psram_string> ips_to_scan;
    bool truncated = false;
    if (!expandTargets(target_norm, ips_to_scan, cfg.max_hosts, &truncated) || ips_to_scan.empty()) {
        ips_to_scan.push_back(PSRAMUtils::createPSRAMString(target_norm));
        truncated = false;
    }

    uint32_t hosts_enumerated = (uint32_t)ips_to_scan.size();
    DiscoveryManager::getInstance().initTotalsTLS(hosts_enumerated);

    if (truncated) {
        LOG_WARNINGF(TAG_GENERAL, "Target %s troncato a %u host (max=%u)",
                    target_norm,
                    (unsigned)hosts_enumerated,
                    (unsigned)cfg.max_hosts);
    }

    const uint32_t batch_size = (cfg.batch_size == 0) ? (cfg.port_scan ? 2 : 4) : cfg.batch_size;
    const uint32_t batch_delay_ms = cfg.batch_delay_ms;

    uint32_t per_host_timeout_ms = (cfg.per_host_timeout_ms == 0) ? 300U : cfg.per_host_timeout_ms;
    if (per_host_timeout_ms < 200U) {
        per_host_timeout_ms = 200U;
    } else if (per_host_timeout_ms > 60000U) {
        per_host_timeout_ms = 60000U;
    }

    uint32_t connect_timeout_ms = (cfg.connect_timeout_ms == 0) ? 400U : cfg.connect_timeout_ms;
    if (connect_timeout_ms < 100U) {
        connect_timeout_ms = 100U;
    }
    if (connect_timeout_ms > per_host_timeout_ms) {
        connect_timeout_ms = per_host_timeout_ms;
    }

    LOG_INFOF(TAG_GENERAL,
              "Starting general discovery: mode=%s target=%s hosts=%u port_scan=%s per_host_timeout=%u connect_timeout=%u batch=%u delay_ms=%u bound_ip=%s",
              mode_label,
              target_norm,
              (unsigned)hosts_enumerated,
              cfg.port_scan ? "true" : "false",
              (unsigned)per_host_timeout_ms,
              (unsigned)connect_timeout_ms,
              (unsigned)batch_size,
              (unsigned)batch_delay_ms,
              bound_ip);

    psram_vector<uint16_t> port_list = cfg.ports;
    if (cfg.port_scan && port_list.empty()) {
        port_list.push_back(502);
        port_list.push_back(102);
        port_list.push_back(44818);
        port_list.push_back(4840);
    }

    enum class SocketResultCode : uint8_t {
        Pending = 0,
        Open,
        Refused,
        Timeout,
        Error,
        SocketFail,
        InvalidIP
    };

    struct HostBatchInfo {
        const char* ip = nullptr;
        bool valid_ip = false;
        struct in_addr addr{};
    };

    struct SocketResult {
        const HostBatchInfo* host = nullptr;
        uint16_t port = 0;
        uint32_t timeout_ms = 0;
        int sock = -1;
        uint64_t start_us = 0;
        int32_t latency_ms = -1;
        int errno_code = 0;
        SocketResultCode code = SocketResultCode::InvalidIP;
        bool pending = false;
    };

    auto closeSocket = [](SocketResult& ctx) {
        if (ctx.sock >= 0) {
            ::close(ctx.sock);
            ctx.sock = -1;
        }
    };

    auto configureSocketForDiscovery = [](int sock) {
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
    };

    auto beginSocket = [&](SocketResult& ctx) {
        if (!ctx.host || !ctx.host->valid_ip) {
            ctx.code = SocketResultCode::InvalidIP;
            ctx.pending = false;
            ctx.latency_ms = -1;
            return;
        }

        ctx.sock = AssessmentInterface::openBoundSocket(AF_INET, SOCK_STREAM, 0);
        if (ctx.sock < 0) {
            ctx.code = SocketResultCode::SocketFail;
            ctx.errno_code = errno;
            ctx.pending = false;
            ctx.latency_ms = -1;
            return;
        }

        configureSocketForDiscovery(ctx.sock);
        struct timeval tv{};
        tv.tv_sec = ctx.timeout_ms / 1000U;
        tv.tv_usec = (ctx.timeout_ms % 1000U) * 1000;
        setsockopt(ctx.sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(ctx.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int flags = fcntl(ctx.sock, F_GETFL, 0);
        if (flags != -1) {
            (void)fcntl(ctx.sock, F_SETFL, flags | O_NONBLOCK);
        }

        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(ctx.port);
        dest.sin_addr = ctx.host->addr;

        ctx.start_us = esp_timer_get_time();
        int rc = ::connect(ctx.sock, (struct sockaddr*)&dest, sizeof(dest));
        if (rc == 0) {
            ctx.latency_ms = (int32_t)((esp_timer_get_time() - ctx.start_us) / 1000ULL);
            ctx.code = SocketResultCode::Open;
            ctx.pending = false;
            closeSocket(ctx);
            return;
        }

        if (rc < 0) {
            int err = errno;
            if (err == EINPROGRESS) {
                ctx.code = SocketResultCode::Pending;
                ctx.pending = true;
                ctx.errno_code = 0;
                return;
            }
            ctx.errno_code = err;
            ctx.latency_ms = -1;
            ctx.pending = false;
            ctx.code = (err == ECONNREFUSED) ? SocketResultCode::Refused : SocketResultCode::Error;
            closeSocket(ctx);
            return;
        }
    };

    uint32_t hosts_scanned = 0;
    uint32_t hosts_reachable = 0;
    uint32_t open_ports_total = 0;

    uint64_t t0_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

    const size_t MIN_FREE_INTERNAL = 30000;
    const uint64_t MAX_SELECT_SLICE_US = 100000ULL;

    auto waitForInternalMemory = [&](const char* ip) {
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        while (free_internal < MIN_FREE_INTERNAL) {
            LOG_WARNINGF(TAG_GENERAL, "DRAM limitata (%u bytes) prima di %s: attendo cleanup",
                        (unsigned)free_internal, ip);
            vTaskDelay(pdMS_TO_TICKS(120));
            feedGeneralDiscoveryWatchdog();
            free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        }
    };

    for (size_t batch_start = 0; batch_start < ips_to_scan.size(); batch_start += batch_size) {
        feedGeneralDiscoveryWatchdog();
        size_t batch_end = std::min(batch_start + (size_t)batch_size, ips_to_scan.size());

        LOG_INFOF(TAG_GENERAL,
                  "Processo batch %u-%u su %u host",
                  (unsigned)(batch_start + 1),
                  (unsigned)batch_end,
                  (unsigned)ips_to_scan.size());

        psram_vector<HostBatchInfo> host_infos;
        host_infos.reserve(batch_end - batch_start);

        size_t expected_jobs = cfg.port_scan ? ((batch_end - batch_start) * (port_list.empty() ? 1U : port_list.size()))
                                             : (batch_end - batch_start);
        if (expected_jobs == 0) {
            expected_jobs = batch_end - batch_start;
        }

        psram_vector<SocketResult> socket_jobs;
        socket_jobs.reserve(expected_jobs);

        for (size_t idx = batch_start; idx < batch_end; ++idx) {
            const char* ip = ips_to_scan[idx].c_str();
            waitForInternalMemory(ip);

            HostBatchInfo info{};
            info.ip = ip;
            info.valid_ip = inet_aton(ip, &info.addr) != 0;
            host_infos.push_back(info);

            if (cfg.port_scan) {
                for (size_t p = 0; p < port_list.size(); ++p) {
                    SocketResult job{};
                    job.host = &host_infos.back();
                    job.port = port_list[p];
                    job.timeout_ms = connect_timeout_ms;
                    job.sock = -1;
                    job.latency_ms = -1;
                    job.errno_code = 0;
                    job.pending = job.host->valid_ip;
                    job.code = job.pending ? SocketResultCode::Pending : SocketResultCode::InvalidIP;
                    socket_jobs.push_back(job);
                }
            } else {
                SocketResult job{};
                job.host = &host_infos.back();
                job.timeout_ms = per_host_timeout_ms;
                job.sock = -1;
                job.latency_ms = -1;
                job.errno_code = 0;
                job.pending = job.host->valid_ip;
                job.code = job.pending ? SocketResultCode::Pending : SocketResultCode::InvalidIP;
                socket_jobs.push_back(job);
            }
        }

        // lwIP (ESP-IDF): non-blocking connect succeeded → wfds; failed (ECONNREFUSED/RST) → rfds.
        // We monitor both to correctly detect active hosts with a closed port.
        //
        // In port_scan mode we open ONE round per port instead of batch*port_count sockets
        // simultaneously. With batch=4 and 4 ports this reduces concurrent sockets from 16 to 4,
        // avoiding exhausting the ESP32's lwIP pool (CONFIG_LWIP_MAX_SOCKETS ~10-16).

        if (cfg.port_scan) {
            const size_t batch_host_count = batch_end - batch_start;
            const size_t num_ports = port_list.size();

            for (size_t p = 0; p < num_ports; ++p) {
                // Open socket only for port p on all hosts of the current batch
                size_t pending_count = 0;
                for (size_t h = 0; h < batch_host_count; ++h) {
                    SocketResult& job = socket_jobs[h * num_ports + p];
                    if (!job.pending) {
                        continue;
                    }
                    beginSocket(job);
                    if (job.pending) {
                        pending_count++;
                    }
                }

                // Wait for this port to complete for all hosts in the batch
                while (pending_count > 0) {
                    feedGeneralDiscoveryWatchdog();

                    fd_set wfds, rfds;
                    FD_ZERO(&wfds);
                    FD_ZERO(&rfds);
                    int max_fd = -1;
                    uint64_t now_us = esp_timer_get_time();
                    uint64_t min_wait_us = MAX_SELECT_SLICE_US;

                    for (size_t h = 0; h < batch_host_count; ++h) {
                        SocketResult& job = socket_jobs[h * num_ports + p];
                        if (!job.pending) {
                            continue;
                        }
                        uint64_t elapsed = now_us - job.start_us;
                        uint64_t deadline = (uint64_t)job.timeout_ms * 1000ULL;
                        if (elapsed >= deadline) {
                            job.pending = false;
                            job.code = SocketResultCode::Timeout;
                            job.latency_ms = -1;
                            job.errno_code = ETIMEDOUT;
                            closeSocket(job);
                            if (pending_count > 0) {
                                pending_count--;
                            }
                            continue;
                        }
                        uint64_t remaining = deadline - elapsed;
                        if (remaining < min_wait_us) {
                            min_wait_us = remaining;
                        }
                        if (job.sock >= 0) {
                            FD_SET(job.sock, &wfds);
                            FD_SET(job.sock, &rfds);
                            if (job.sock > max_fd) {
                                max_fd = job.sock;
                            }
                        }
                    }

                    if (pending_count == 0) {
                        break;
                    }
                    if (max_fd < 0) {
                        continue;
                    }
                    if (min_wait_us == 0) {
                        min_wait_us = 5000ULL;
                    }

                    struct timeval tv{};
                    tv.tv_sec = (long)(min_wait_us / 1000000ULL);
                    tv.tv_usec = (long)(min_wait_us % 1000000ULL);

                    int sel = select(max_fd + 1, &rfds, &wfds, NULL, &tv);
                    if (sel < 0) {
                        int sel_err = errno;
                        LOG_WARNINGF(TAG_GENERAL, "select failed port %u: errno=%d",
                                     (unsigned)port_list[p], sel_err);
                        for (size_t h = 0; h < batch_host_count; ++h) {
                            SocketResult& job = socket_jobs[h * num_ports + p];
                            if (!job.pending) {
                                continue;
                            }
                            job.pending = false;
                            job.code = SocketResultCode::Error;
                            job.errno_code = sel_err;
                            job.latency_ms = -1;
                            closeSocket(job);
                        }
                        pending_count = 0;
                        break;
                    }
                    if (sel == 0) {
                        continue;
                    }

                    uint64_t after_us = esp_timer_get_time();
                    for (size_t h = 0; h < batch_host_count; ++h) {
                        SocketResult& job = socket_jobs[h * num_ports + p];
                        if (!job.pending || job.sock < 0) {
                            continue;
                        }
                        if (!FD_ISSET(job.sock, &wfds) && !FD_ISSET(job.sock, &rfds)) {
                            continue;
                        }
                        int soerr = 0;
                        socklen_t slen = sizeof(soerr);
                        getsockopt(job.sock, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                        job.pending = false;
                        job.errno_code = soerr;
                        if (soerr == 0) {
                            job.code = SocketResultCode::Open;
                            job.latency_ms = (int32_t)((after_us - job.start_us) / 1000ULL);
                        } else if (soerr == ECONNREFUSED) {
                            job.code = SocketResultCode::Refused;
                            job.latency_ms = (int32_t)((after_us - job.start_us) / 1000ULL);
                        } else {
                            job.code = SocketResultCode::Error;
                            job.latency_ms = -1;
                        }
                        closeSocket(job);
                        if (pending_count > 0) {
                            pending_count--;
                        }
                    }
                }

                // Close any sockets left open (early exit due to select error)
                for (size_t h = 0; h < batch_host_count; ++h) {
                    closeSocket(socket_jobs[h * num_ports + p]);
                }

                // Small pause between ports to release lwIP resources before the next round
                if (p + 1 < num_ports) {
                    vTaskDelay(pdMS_TO_TICKS(20));
                    feedGeneralDiscoveryWatchdog();
                }
            }
        } else {
            // Ping mode uses real ICMP Echo Requests. Keep the same bounded
            // batch loop and result representation used by the TCP path, but
            // execute probes sequentially to keep raw-socket/task usage bounded.
            for (size_t i = 0; i < host_infos.size(); ++i) {
                SocketResult& job = socket_jobs[i];
                const HostBatchInfo& info = host_infos[i];
                job.pending = false;
                job.sock = -1;
                if (!info.valid_ip) {
                    job.code = SocketResultCode::InvalidIP;
                    job.latency_ms = -1;
                } else {
                    IcmpPing::Result ping_result{};
                    const bool replied = IcmpPing::probe(info.addr.s_addr,
                                                         netif,
                                                         per_host_timeout_ms,
                                                         ping_result);
                    job.latency_ms = ping_result.time_ms;
                    if (replied && ping_result.status == IcmpPing::Status::Success) {
                        job.code = SocketResultCode::Open;
                    } else if (ping_result.status == IcmpPing::Status::Timeout) {
                        job.code = SocketResultCode::Timeout;
                        job.errno_code = ETIMEDOUT;
                    } else {
                        job.code = SocketResultCode::Error;
                    }
                }
                feedGeneralDiscoveryWatchdog();
            }
        }

        size_t job_index = 0;
        for (size_t h = 0; h < host_infos.size(); ++h) {
            feedGeneralDiscoveryWatchdog();
            const HostBatchInfo& info = host_infos[h];
            const char* ip = info.ip;

            cJSON* host = cJSON_CreateObject();
            cJSON_AddStringToObject(host, "ip", ip);

            bool reachable = false;
            uint32_t host_open_ports = 0;
            int32_t summary_latency_ms = -1;
            psram_vector<uint16_t> open_ports_summary;
            open_ports_summary.reserve(4);

            if (cfg.port_scan) {
                cJSON* ports_arr = cJSON_CreateArray();
                cJSON_AddItemToObject(host, "ports", ports_arr);
                for (size_t p = 0; p < port_list.size(); ++p, ++job_index) {
                    SocketResult& job = socket_jobs[job_index];
                    cJSON* port_json = cJSON_CreateObject();
                    cJSON_AddNumberToObject(port_json, "port", (int)job.port);
                    cJSON_AddNumberToObject(port_json, "latency_ms", job.latency_ms);

                    switch (job.code) {
                        case SocketResultCode::Open:
                            cJSON_AddStringToObject(port_json, "state", "open");
                            reachable = true;
                            host_open_ports++;
                            open_ports_total++;
                            open_ports_summary.push_back(job.port);
                            break;
                        case SocketResultCode::Refused:
                            cJSON_AddStringToObject(port_json, "state", "closed");
                            reachable = true;
                            break;
                        case SocketResultCode::Timeout:
                            cJSON_AddStringToObject(port_json, "state", "timeout");
                            cJSON_AddNumberToObject(port_json, "errno", ETIMEDOUT);
                            break;
                        case SocketResultCode::SocketFail:
                            cJSON_AddStringToObject(port_json, "state", "socket_error");
                            cJSON_AddNumberToObject(port_json, "errno", job.errno_code);
                            break;
                        case SocketResultCode::InvalidIP:
                            cJSON_AddStringToObject(port_json, "state", "invalid_ip");
                            break;
                        case SocketResultCode::Error:
                        case SocketResultCode::Pending:
                        default:
                            cJSON_AddStringToObject(port_json, "state", "error");
                            if (job.errno_code != 0) {
                                cJSON_AddNumberToObject(port_json, "errno", job.errno_code);
                            }
                            break;
                    }

                    cJSON_AddItemToArray(ports_arr, port_json);
                }

                if (host_open_ports > 0) {
                    cJSON_AddNumberToObject(host, "open_ports", host_open_ports);
                }
            } else {
                SocketResult& job = socket_jobs[job_index++];
                summary_latency_ms = job.latency_ms;
                cJSON_AddNumberToObject(host, "latency_ms", job.latency_ms);

                switch (job.code) {
                    case SocketResultCode::Open:
                        cJSON_AddStringToObject(host, "status", "open");
                        reachable = true;
                        break;
                    case SocketResultCode::Refused:
                        cJSON_AddStringToObject(host, "status", "host_up_port_closed");
                        reachable = true;
                        break;
                    case SocketResultCode::Timeout:
                        cJSON_AddStringToObject(host, "status", "timeout_or_unreachable");
                        break;
                    case SocketResultCode::SocketFail:
                        cJSON_AddStringToObject(host, "status", "socket_error");
                        if (job.errno_code != 0) {
                            cJSON_AddNumberToObject(host, "errno", job.errno_code);
                        }
                        break;
                    case SocketResultCode::InvalidIP:
                        cJSON_AddStringToObject(host, "status", "invalid_ip");
                        break;
                    case SocketResultCode::Error:
                    case SocketResultCode::Pending:
                    default:
                        cJSON_AddStringToObject(host, "status", "timeout_or_unreachable");
                        if (job.errno_code != 0) {
                            cJSON_AddNumberToObject(host, "errno", job.errno_code);
                        }
                        break;
                }
            }

            if (reachable) {
                hosts_reachable++;
            }
            hosts_scanned++;

            if (reachable) {
                cJSON* summary = cJSON_CreateObject();
                cJSON_AddStringToObject(summary, "ip", ip);
                if (cfg.port_scan) {
                    if (!open_ports_summary.empty()) {
                        cJSON* open_arr = cJSON_CreateArray();
                        for (size_t oi = 0; oi < open_ports_summary.size(); ++oi) {
                            cJSON_AddItemToArray(open_arr, cJSON_CreateNumber((int)open_ports_summary[oi]));
                        }
                        cJSON_AddItemToObject(summary, "open_ports", open_arr);
                        cJSON_AddStringToObject(summary, "method", "tcp_ports");
                    } else {
                        cJSON_AddStringToObject(summary, "method", "tcp");
                        cJSON_AddStringToObject(summary, "status", "host_up_port_closed");
                    }
                } else {
                    cJSON_AddStringToObject(summary, "method", "icmp_ping");
                    cJSON_AddNumberToObject(summary, "latency_ms", summary_latency_ms);
                    cJSON_AddStringToObject(summary, "status", summary_latency_ms >= 0 ? "reachable" : "unknown");
                }
                cJSON_AddItemToArray(reachable_summary, summary);

                cJSON_AddBoolToObject(host, "reachable", true);
                cJSON_AddItemToArray(hosts, host);
            } else {
                cJSON_Delete(host);
            }

            if (cfg.port_scan) {
                LOG_INFOF(TAG_GENERAL,
                          "Host %s completed: reachable=%s open_ports=%u",
                          ip,
                          reachable ? "true" : "false",
                          (unsigned)host_open_ports);
            } else {
                LOG_INFOF(TAG_GENERAL,
                          "Host %s completed: reachable=%s latency=%dms",
                          ip,
                          reachable ? "true" : "false",
                          (int)summary_latency_ms);
            }

            DiscoveryManager::getInstance().updateProgressTLS(ip, hosts_scanned, hosts_reachable, 0, open_ports_total);

            if (rep && cfg.emit_progress_events && ((hosts_scanned % 6) == 1 || hosts_scanned == hosts_enumerated)) {
                feedGeneralDiscoveryWatchdog();
                cJSON* ev = cJSON_CreateObject();
                cJSON_AddStringToObject(ev, "event", "general_discovery_progress");
                cJSON_AddStringToObject(ev, "mode", mode_label);
                cJSON_AddStringToObject(ev, "ip_in_scansione", ip);
                cJSON_AddNumberToObject(ev, "index", hosts_scanned);
                cJSON_AddNumberToObject(ev, "total", hosts_enumerated);
                cJSON_AddNumberToObject(ev, "reachable", hosts_reachable);
                cJSON_AddNumberToObject(ev, "open_ports", open_ports_total);
                char* ev_json = cJSON_PrintUnformatted(ev);
                if (ev_json) {
                    psram_string type = PSRAMUtils::createPSRAMString("general_discovery_progress");
                    psram_string payload = PSRAMUtils::createPSRAMString(ev_json);
                    rep->reportEvent(type, payload);
                    LOG_INFOF(TAG_GENERAL,
                              "Discovery progress %u/%u ip=%s reachable=%u open_ports=%u",
                              (unsigned)hosts_scanned,
                              (unsigned)hosts_enumerated,
                              ip,
                              (unsigned)hosts_reachable,
                              (unsigned)open_ports_total);
                    free(ev_json);
                }
                cJSON_Delete(ev);
            }

            vTaskDelay(pdMS_TO_TICKS(5));
        }

        if (batch_end < ips_to_scan.size()) {
            feedGeneralDiscoveryWatchdog();
            uint32_t total_delay = batch_delay_ms > 0 ? (batch_delay_ms + 50) : 50;
            vTaskDelay(pdMS_TO_TICKS(total_delay));
        }
    }

    uint64_t t1_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    cJSON_AddNumberToObject(root, "scan_time_ms", (double)(t1_ms - t0_ms));

    cJSON* params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "hosts_enumerated", hosts_enumerated);
    cJSON_AddNumberToObject(params, "hosts_scanned", hosts_scanned);
    cJSON_AddNumberToObject(params, "hosts_reachable", hosts_reachable);
    cJSON_AddNumberToObject(params, "open_ports", open_ports_total);
    cJSON_AddBoolToObject(params, "truncated", truncated);
    cJSON_AddNumberToObject(params, "per_host_timeout_ms", per_host_timeout_ms);
    cJSON_AddNumberToObject(params, "connect_timeout_ms", connect_timeout_ms);
    cJSON_AddNumberToObject(params, "batch_size", batch_size);
    cJSON_AddNumberToObject(params, "batch_delay_ms", batch_delay_ms);
    cJSON_AddStringToObject(params, "bound_local_ip", bound_ip);
    if (cfg.port_scan) {
        cJSON* ports_cfg = cJSON_CreateArray();
        for (size_t i = 0; i < port_list.size(); ++i) {
            cJSON_AddItemToArray(ports_cfg, cJSON_CreateNumber((int)port_list[i]));
        }
        cJSON_AddItemToObject(params, "ports_requested", ports_cfg);
        cJSON_AddStringToObject(root, "method", "tcp_connect");
    } else {
        cJSON_AddStringToObject(root, "method", "icmp_ping");
    }
    cJSON_AddItemToObject(root, "params", params);

    if (rep) {
        char* report_json = cJSON_PrintUnformatted(root);
        if (report_json) {
            psram_string type = PSRAMUtils::createPSRAMString("general_discovery");
            psram_string payload = PSRAMUtils::createPSRAMString(report_json);
            rep->reportEvent(type, payload);
            free(report_json);
        }
    }

    LOG_INFOF(TAG_GENERAL,
              "General discovery completed: target=%s mode=%s hosts_scanned=%u reachable=%u open_ports=%u",
              target_norm,
              mode_label,
              (unsigned)hosts_scanned,
              (unsigned)hosts_reachable,
              (unsigned)open_ports_total);

    if (rep && cfg.emit_progress_events) {
        feedGeneralDiscoveryWatchdog();
        cJSON* ev = cJSON_CreateObject();
        cJSON_AddStringToObject(ev, "event", "completed");
        cJSON_AddStringToObject(ev, "mode", mode_label);
        cJSON_AddStringToObject(ev, "target", target_norm);
        cJSON_AddNumberToObject(ev, "hosts_scanned", hosts_scanned);
        cJSON_AddNumberToObject(ev, "hosts_reachable", hosts_reachable);
        cJSON_AddNumberToObject(ev, "open_ports", open_ports_total);
        char* ev_json = cJSON_PrintUnformatted(ev);
        if (ev_json) {
            psram_string type = PSRAMUtils::createPSRAMString("general_discovery_progress");
            psram_string payload = PSRAMUtils::createPSRAMString(ev_json);
            rep->reportEvent(type, payload);
            free(ev_json);
        }
        cJSON_Delete(ev);
    }

    char* json = cJSON_PrintUnformatted(root);
    std::string out = json ? std::string(json) : std::string("{}");
    if (json) free(json);
    cJSON_Delete(root);
    return out;
}
bool BasePlugin::doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) {
    std::string legacy_target = PSRAMUtils::fromPSRAMString(target);
    std::string legacy_report = doVulnerabilityScan(legacy_target);
    if (!legacy_report.empty()) {
        out_report = PSRAMUtils::createPSRAMString(legacy_report.c_str());
    } else {
        out_report.clear();
    }
    return !legacy_report.empty();
}

bool BasePlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                         uint32_t timeout_ms,
                                         psram_string& out_report) {
    std::string legacy_target = PSRAMUtils::fromPSRAMString(target_network);
    std::string legacy_report = doNetworkDiscovery(legacy_target, timeout_ms);
    if (!legacy_report.empty()) {
        out_report = PSRAMUtils::createPSRAMString(legacy_report.c_str());
    } else {
        out_report.clear();
    }
    return !legacy_report.empty();
}

void BasePlugin::loadIDSRulesPSRAM(const psram_string& rules_json) {
    if (rules_json.empty()) {
        loadIDSRules(std::string{});
        return;
    }
    loadIDSRules(PSRAMUtils::fromPSRAMString(rules_json));
}

// ==================== FLOW MANAGEMENT IMPLEMENTATION ====================

bool BasePlugin::trackPacketInFlow(const NetworkPacket& packet) {
    // 1. Build the protocol-specific FlowKey
    PSRAMAllocator<char> alloc;
    FlowKey key(alloc);

    if (!buildFlowKey(packet, key)) {
        // Non-trackable packet (e.g., incomplete handshake, malformed)
        return false;
    }

    // 2. Get or create the flow
    FlowData* flow = flow_table_.getOrCreateFlow(key);
    if (!flow) {
        // Table full or PSRAM allocation error
        return false;
    }

    // 3. Update base metrics
    flow->metrics.onPacketReceived(packet.length);

    // Update timestamp
    if (flow->metrics.first_packet_ms == 0) {
        flow->metrics.first_packet_ms = esp_timer_get_time() / 1000;
    }

    // 4. Classify the operation
    psram_string operation_type(alloc);
    psram_string operation_details(alloc);
    bool is_error = false;

    if (classifyPacketOperation(packet, operation_type, operation_details, is_error)) {
        // Update specific counters
        if (!operation_type.empty()) {
            if (operation_type == "READ") {
                flow->metrics.onReadOperation();
            } else if (operation_type == "WRITE") {
                flow->metrics.onWriteOperation();
            } else if (operation_type == "CONTROL") {
                flow->metrics.onControlOperation();
            }
        }

        if (is_error) {
            flow->metrics.onErrorResponse();
        }

        // 5. Add the operation to the history
        uint32_t timestamp = esp_timer_get_time() / 1000;
        flow->addOperation(operation_type.c_str(), operation_details.c_str(),
                          timestamp, !is_error);
    } else {
        // Unclassifiable packet, it might be malformed
        if (packet.length < 8) {  // Arbitrary threshold for suspicious packets
            flow->metrics.onMalformedPacket();
        }
    }

    // 6. Update speed (every 100 packets for efficiency)
    if (flow->metrics.packet_count % 100 == 0) {
        flow->metrics.updateRatesRolling();
    }

    // 7. Update the protocol state via the centralized SessionStateMachine
    // This processes the packet through the generic state machine
    session_state_machine_.processPacket(packet, *flow);

    // 8. Update the plugin-specific protocol state (optional, for extensions)
    // Plugins can use this for additional tracking beyond the state machine
    updateProtocolState(packet, *flow);

    // 9. Assign label
    assignFlowLabel(*flow);

    return true;
}

void BasePlugin::cleanupExpiredFlows() {
    flow_table_.periodicCleanup();
}
