#include "security_manager.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include "../network/ethernet_tx_if.h"
#include "../core/async_storage_engine.h"
#include "../core/reporting_engine.h"
#include "../core/psram_json_parser.h"
#include "../core/types.h"
#include "api_key_rotation_manager.h"
#include "password_hasher.h"
#include "offensive_testing_board_profile.h"
#include <algorithm>
#include <cstring>
#include <cctype>

#include "driver/gpio.h"

extern "C" {
    #include "esp_flash_encrypt.h"
    #include "esp_secure_boot.h"
    #include "lwip/inet.h"
    #include "esp_app_format.h"
    #include "nvs.h"
    #include "nvs_flash.h"
    #include "mbedtls/sha256.h"
    #include "esp_random.h"
    #include "esp_crc.h"
}

static const char* TAG_SEC = "Security";
extern ReportingEngine* g_reporting;

static constexpr uint64_t kApiKeyRotationMs = 90ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
static constexpr uint64_t kApiKeyDisableMs = 120ULL * 24ULL * 60ULL * 60ULL * 1000ULL;

static inline bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static bool is_sha256_hex(const psram_string& value) {
    if (value.size() != 64) {
        return false;
    }
    for (size_t i = 0; i < value.size(); ++i) {
        if (!is_hex_char(value[i])) {
            return false;
        }
    }
    return true;
}

static void zeroize_psram_string(psram_string& value) {
    for (size_t i = 0; i < value.size(); ++i) {
        value[i] = '\0';
    }
    value.clear();
}

static inline void log_api_key_preview(const char* token_preview_source) {
    if (!token_preview_source) {
        return;
    }
    char preview[9];
    size_t idx = 0;
    while (idx < sizeof(preview) - 1 && token_preview_source[idx] != '\0') {
        preview[idx] = token_preview_source[idx];
        ++idx;
    }
    preview[idx] = '\0';
    LOG_WARNINGF(TAG_SEC, "API key rejected: %s***", preview);
}

bool SecurityManager::readFuzzingGpioGateState() const {
    if (!fuzzing_gpio_gate_enabled_ || fuzzing_gpio_num_ < 0) {
        return true; // no physical gating
    }

    // gpio_get_level returns 0/1. We map it to an "ON" meaning based on active_high.
    const int level = gpio_get_level((gpio_num_t)fuzzing_gpio_num_);
    const bool raw_on = (level != 0);
    return fuzzing_gpio_active_high_ ? raw_on : !raw_on;
}

OffensiveTestingDecision SecurityManager::evaluateOffensiveTesting() const {
    OffensiveTestingDecision decision;
    decision.software_enabled = fuzzing_allowed_;
    decision.gpio_required = fuzzing_gpio_gate_enabled_ && fuzzing_gpio_gate_required_;
    decision.gpio_asserted = readFuzzingGpioGateState();
    decision.source = offensive_policy_source_.c_str();
    if (!decision.software_enabled) {
        decision.reason = "disabled_in_security_config";
        return decision;
    }
    if (decision.gpio_required && !decision.gpio_asserted) {
        decision.reason = "disabled_by_physical_switch";
        return decision;
    }
    decision.allowed = true;
    decision.reason = "allowed";
    return decision;
}

bool SecurityManager::isFuzzingAllowed() const {
    return evaluateOffensiveTesting().allowed;
}

const char* SecurityManager::getFuzzingBlockReason() const {
    return evaluateOffensiveTesting().reason;
}

bool SecurityManager::configureFuzzingGpioGate(bool enabled,
                                               int gpio_num,
                                               bool active_high,
                                               int pull_mode,
                                               bool require_gate) {
    fuzzing_gpio_gate_enabled_ = enabled;
    fuzzing_gpio_gate_required_ = require_gate;
    fuzzing_gpio_num_ = gpio_num;
    fuzzing_gpio_active_high_ = active_high;
    fuzzing_gpio_pull_mode_ = pull_mode;

    if (!enabled) {
        LOG_INFO(TAG_SEC, "Fuzzing GPIO gate disabled");
        return true;
    }

    if (!isAllowedOffensiveTestingGpio(gpio_num)) {
        LOG_ERRORF(TAG_SEC, "Fuzzing GPIO gate reserved/invalid gpio_num=%d (fail closed)", gpio_num);
        fuzzing_gpio_gate_enabled_ = false;
        fuzzing_gpio_gate_required_ = true;
        fuzzing_gpio_num_ = -1;
        fuzzing_allowed_ = false;
        return false;
    }

    gpio_config_t io{};
    io.pin_bit_mask = (1ULL << (uint32_t)gpio_num);
    io.mode = GPIO_MODE_INPUT;
    io.intr_type = GPIO_INTR_DISABLE;
    io.pull_up_en = (pull_mode == 1) ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE;
    io.pull_down_en = (pull_mode == 2) ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE;

    esp_err_t err = gpio_config(&io);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_SEC, "Fuzzing GPIO gate gpio_config failed gpio=%d err=%d (disabling gate)", gpio_num, (int)err);
        fuzzing_gpio_gate_enabled_ = false;
        fuzzing_gpio_gate_required_ = true;
        fuzzing_gpio_num_ = -1;
        fuzzing_allowed_ = false;
        return false;
    }

    LOG_INFOF(TAG_SEC,
              "Fuzzing GPIO gate configured: enabled=1 required=%d gpio=%d active_high=%d pull_mode=%d state=%d",
              (int)require_gate,
              gpio_num,
              (int)active_high,
              pull_mode,
              (int)readFuzzingGpioGateState());
    return true;
}

namespace {
struct __attribute__((packed)) OffensivePolicyRecordV1 {
    uint32_t magic;
    uint8_t version;
    uint8_t software_enabled;
    uint8_t gpio_enabled;
    uint8_t gpio_required;
    int16_t gpio;
    uint8_t active_high;
    uint8_t pull_mode;
    uint32_t crc32;
};
constexpr uint32_t kOffensivePolicyMagic = 0x4F54504CUL; // OTP L
constexpr char kOffensivePolicyKey[] = "off_policy_v1";

uint32_t offensivePolicyCrc(const OffensivePolicyRecordV1& record) {
    return esp_crc32_le(0, reinterpret_cast<const uint8_t*>(&record),
                        offsetof(OffensivePolicyRecordV1, crc32));
}

bool validOffensivePolicyRecord(const OffensivePolicyRecordV1& record) {
    return record.magic == kOffensivePolicyMagic && record.version == 1 &&
           record.software_enabled <= 1 && record.gpio_enabled <= 1 &&
           record.gpio_required <= 1 && record.active_high <= 1 &&
           record.pull_mode <= 2 && record.crc32 == offensivePolicyCrc(record);
}
}  // namespace

void SecurityManager::getOffensiveTestingConfigSnapshot(OffensiveTestingConfig& out) const {
    out.software_enabled = fuzzing_allowed_;
    out.gpio_gate.enabled = fuzzing_gpio_gate_enabled_;
    out.gpio_gate.required = fuzzing_gpio_gate_required_;
    out.gpio_gate.gpio = fuzzing_gpio_num_;
    out.gpio_gate.active_high = fuzzing_gpio_active_high_;
    out.gpio_gate.pull_mode = fuzzing_gpio_pull_mode_;
    out.boot_policy = PSRAMUtils::createPSRAMString(offensive_policy_source_ == "config_override"
                                                        ? "force_config" : "seed_if_absent");
}

bool SecurityManager::persistOffensiveTestingPolicy() {
    OffensivePolicyRecordV1 record{};
    record.magic = kOffensivePolicyMagic;
    record.version = 1;
    record.software_enabled = fuzzing_allowed_ ? 1 : 0;
    record.gpio_enabled = fuzzing_gpio_gate_enabled_ ? 1 : 0;
    record.gpio_required = fuzzing_gpio_gate_required_ ? 1 : 0;
    record.gpio = static_cast<int16_t>(fuzzing_gpio_num_);
    record.active_high = fuzzing_gpio_active_high_ ? 1 : 0;
    record.pull_mode = static_cast<uint8_t>(fuzzing_gpio_pull_mode_);
    record.crc32 = offensivePolicyCrc(record);
    return AsyncStorage::Global::nvsSetBlob("security", kOffensivePolicyKey,
                                            &record, sizeof(record)) == ESP_OK;
}

bool SecurityManager::loadOffensiveTestingPolicyFromStorage() {
    const OffensiveTestingConfig configured = cfg_.offensive_testing;
    const auto& profile = getOffensiveTestingBoardProfile();
    const bool force_config = configured.boot_policy == "force_config";

    OffensivePolicyRecordV1 record{};
    std::vector<uint8_t> raw;
    bool loaded = false;
    if (!force_config && AsyncStorage::Global::nvsGetBlob("security", kOffensivePolicyKey, raw) == ESP_OK &&
        raw.size() == sizeof(record)) {
        memcpy(&record, raw.data(), sizeof(record));
        loaded = validOffensivePolicyRecord(record);
    }

    if (loaded) {
        fuzzing_allowed_ = record.software_enabled != 0;
        fuzzing_gpio_gate_enabled_ = record.gpio_enabled != 0;
        fuzzing_gpio_gate_required_ = record.gpio_required != 0;
        fuzzing_gpio_num_ = record.gpio;
        fuzzing_gpio_active_high_ = record.active_high != 0;
        fuzzing_gpio_pull_mode_ = record.pull_mode;
        offensive_policy_source_ = "nvs";
    } else {
        uint8_t legacy = 0;
        const bool has_legacy = !force_config &&
            AsyncStorage::Global::nvsGet("security", "fuzzing_allowed", legacy) == ESP_OK;
        fuzzing_allowed_ = force_config ? configured.software_enabled
                                        : (has_legacy ? legacy != 0 : configured.software_enabled);
        fuzzing_gpio_gate_enabled_ = configured.gpio_gate.enabled;
        fuzzing_gpio_gate_required_ = configured.gpio_gate.required;
        fuzzing_gpio_num_ = configured.gpio_gate.gpio >= 0
                                ? configured.gpio_gate.gpio : profile.default_gpio;
        fuzzing_gpio_active_high_ = configured.gpio_gate.active_high;
        fuzzing_gpio_pull_mode_ = configured.gpio_gate.pull_mode;
        offensive_policy_source_ = force_config ? "config_override"
                                                : (has_legacy ? "legacy_migration" : "config_seed");
        if (!force_config && !persistOffensiveTestingPolicy()) {
            LOG_WARNING(TAG_SEC, "Unable to seed offensive-testing policy; continuing fail-closed");
        }
    }

    if (!configureFuzzingGpioGate(fuzzing_gpio_gate_enabled_, fuzzing_gpio_num_,
                                  fuzzing_gpio_active_high_, fuzzing_gpio_pull_mode_,
                                  fuzzing_gpio_gate_required_)) {
        fuzzing_allowed_ = false;
        offensive_policy_source_ = "invalid_fail_closed";
        return false;
    }
    return true;
}

bool SecurityManager::initialize(const SecurityConfig& cfg) {
    cfg_ = cfg;
    setAlertPolicy(cfg.alert_policy);
    last_email_alert_ms_ = 0;
    last_webhook_alert_ms_ = 0;

    // Log current hardware security state
    LOG_INFOF(TAG_SEC, "Secure Boot (efuse): %d", (int)isSecureBootEnabled());
    LOG_INFOF(TAG_SEC, "Flash Encryption (efuse): %d", (int)isFlashEncryptionEnabled());

    bool secure_boot_active = isSecureBootEnabled();
    bool flash_encryption_active = isFlashEncryptionEnabled();

    if (cfg_.secure_boot && !secure_boot_active) {
        raiseSecurityFault("secure_boot", "Enable eFuse secure boot before deployment");
    }
    if (cfg_.flash_encryption && !flash_encryption_active) {
        raiseSecurityFault("flash_encryption", "Enable flash encryption in eFuse");
    }

    if (cfg_.secure_boot && secure_boot_active) {
        LOG_INFO(TAG_SEC, "Secure Boot enabled and enforced");
    }
    if (cfg_.flash_encryption && flash_encryption_active) {
        LOG_INFO(TAG_SEC, "Flash encryption enabled and enforced");
    }

    // Initialize PSRAM storage for API keys
    PSRAMAllocator<ApiKeyEntry> alloc;
    api_keys_ = psram_vector<ApiKeyEntry>(alloc);
    PSRAMAllocator<SecurityEventLog> event_alloc;
    security_events_ = psram_vector<SecurityEventLog>(event_alloc);

    // Derive master key from chip ID (unique per device)
    uint8_t chip_id[6];
    esp_efuse_mac_get_default(chip_id);

    char* master_key_buf = (char*)heap_caps_malloc(64, MALLOC_CAP_SPIRAM);
    if (master_key_buf) {
        snprintf(master_key_buf, 64, "%02x%02x%02x%02x%02x%02x",
                chip_id[0], chip_id[1], chip_id[2],
                chip_id[3], chip_id[4], chip_id[5]);
        master_key_ = PSRAMUtils::createPSRAMString(master_key_buf);
        heap_caps_free(master_key_buf);
    }

    // Operational mode accepts only a hash persisted by provisioning or legacy migration.
    psram_string persisted_hash;
    if (loadAdminPasswordHash(persisted_hash) &&
        PasswordHasher::isSupportedHash(persisted_hash)) {
        admin_password_hash_ = persisted_hash;
        cfg_.admin_password = admin_password_hash_;
        LOG_INFO(TAG_SEC, "Admin password hash loaded from NVS");
    } else {
        if (PasswordHasher::isSupportedHash(cfg_.admin_password)) {
            admin_password_hash_ = cfg_.admin_password;
            cfg_.admin_password = admin_password_hash_;
            if (!storeAdminPasswordHash(admin_password_hash_)) {
                LOG_ERROR(TAG_SEC, "Failed to persist administrator password hash");
                return false;
            }
        } else {
            LOG_ERROR(TAG_SEC, "Missing or unsupported administrator password hash");
            return false;
        }
    }

    // Load API keys from NVS
    loadApiKeysFromNVS();
    auditApiKeysForRotation();

    loadOffensiveTestingPolicyFromStorage();

    LOG_INFOF(TAG_SEC, "SecurityManager initialized with %zu API keys", api_keys_.size());
    return true;
}

void SecurityManager::shutdown() {}

bool SecurityManager::isSecureBootEnabled() const {
#if ESP_IDF_VERSION_MAJOR >= 4
    return esp_secure_boot_enabled();
#else
    return false;
#endif
}

bool SecurityManager::isFlashEncryptionEnabled() const {
#if ESP_IDF_VERSION_MAJOR >= 4
    return esp_flash_encryption_enabled();
#else
    return false;
#endif
}

std::string SecurityManager::getRunningAppSHA256() const {
    const esp_partition_t* part = esp_ota_get_running_partition();
    if (!part) return "";
    uint8_t sha[32] = {0};
    esp_err_t err = esp_app_get_elf_sha256((char*)sha, sizeof(sha));
    if (err != ESP_OK) return "";

    char hex[65];
    for (int i=0;i<32;++i) sprintf(hex + i*2, "%02x", sha[i]);
    hex[64] = 0;
    return std::string(hex);
}


bool SecurityManager::setExpectedFirmwareHash(const std::string& hex) {
    // Hardening: must be SHA-256 in hexadecimal (64 char 0-9a-fA-F)
    auto is_hex = [](char c){
        return std::isdigit((unsigned char)c) ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };
    if (hex.size() != 64 || !std::all_of(hex.begin(), hex.end(), is_hex)) {
        LOG_ERROR("Security", "Invalid SHA-256 hex (len!=64 or bad chars)");
        return false;
    }

    // Normalize to lowercase for consistency
    std::string hex_norm; hex_norm.reserve(64);
    for (char c : hex) hex_norm.push_back((char)std::tolower((unsigned char)c));

    esp_err_t e = AsyncStorage::Global::nvsSet("cfg", "fw_sha256", hex_norm);
    if (e != ESP_OK) {
        LOG_ERRORF("Security", "Failed to write fw_sha256 to NVS: %s", esp_err_to_name(e));
        return false;
    }
    return true;
}


bool SecurityManager::verifyFirmwareHash() const {
    std::string stored_hash;
    if (AsyncStorage::Global::nvsGet("cfg", "fw_sha256", stored_hash) != ESP_OK) return false;
    std::string now = getRunningAppSHA256();
    return !now.empty() && now == stored_hash;
}

bool SecurityManager::readFile(const std::string& path, std::string& out) const {
    return AsyncStorage::Global::readFile(path, out) == ESP_OK;
}

#pragma pack(push,1)
struct EthHdr { uint8_t dst[6]; uint8_t src[6]; uint16_t type; };
struct IPv4Hdr {
    uint8_t ver_ihl; uint8_t tos; uint16_t totlen; uint16_t id; uint16_t frag;
    uint8_t ttl; uint8_t proto; uint16_t chksum; uint32_t src; uint32_t dst;
};
struct TCPHdr {
    uint16_t sport; uint16_t dport; uint32_t seq; uint32_t ack;
    uint8_t off_res; uint8_t flags; uint16_t win; uint16_t chksum; uint16_t urg;
};
#pragma pack(pop)

static uint16_t ip_checksum(const void* vdata, size_t length) {
    const uint8_t* data = (const uint8_t*)vdata;
    uint32_t acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word = (data[i] << 8) + data[i + 1];
        acc += word;
        if (acc > 0xffff) acc -= 0xffff;
    }
    if (length & 1) {
        acc += data[length - 1] << 8;
        if (acc > 0xffff) acc -= 0xffff;
    }
    return ~acc;
}

static uint16_t tcp_checksum(const IPv4Hdr* ip, const TCPHdr* tcp, const uint8_t* payload, size_t plen) {
    uint32_t acc = 0;
    // pseudo header
    acc += (ip->src >> 16) & 0xFFFF; acc += ip->src & 0xFFFF;
    acc += (ip->dst >> 16) & 0xFFFF; acc += ip->dst & 0xFFFF;
    acc += 0x0006; // TCP
    uint16_t tcp_len = (uint16_t)( ( (tcp->off_res >> 4) * 4 ) + plen );
    acc += tcp_len;
    // TCP header
    const uint16_t* w = (const uint16_t*)tcp;
    size_t tcp_hlen = (tcp->off_res >> 4) * 4;
    for (size_t i=0;i<tcp_hlen/2;i++) { acc += ntohs(w[i]); if (acc>0xFFFF) acc-=0xFFFF; }
    // payload
    for (size_t i=0;i+1<plen;i+=2) { acc += (payload[i]<<8)|payload[i+1]; if (acc>0xFFFF) acc-=0xFFFF; }
    if (plen & 1) { acc += payload[plen-1]<<8; if (acc>0xFFFF) acc-=0xFFFF; }
    return htons(~acc & 0xFFFF);
}

bool SecurityManager::loadPolicyFromConfig(const std::string& json) {
    // very small parse: look for "security": { "policy": { "block_s7_plc_stop": true } }
    const char* key = "\"block_s7_plc_stop\"";
    auto pos = json.find(key);
    if (pos == std::string::npos) return true; // keep default
    auto p2 = json.find_first_of("01truefals", pos + strlen(key));
    if (p2 == std::string::npos) return true;
    policy_.block_s7_plc_stop = (json.find("true", p2) == p2 || json.find('1', p2) == p2);
    return true;
}

bool SecurityManager::mitigateTcpByRst(const uint8_t* frame, size_t len, EthernetTxIf* tx) const {
    if (!tx || !frame || len < sizeof(EthHdr)+sizeof(IPv4Hdr)+sizeof(TCPHdr)) return false;
    const EthHdr* eth = (const EthHdr*)frame;
    if (ntohs(eth->type) != 0x0800) return false; // ipv4 only
    const IPv4Hdr* ip = (const IPv4Hdr*)(frame + sizeof(EthHdr));
    if (ip->proto != 6) return false; // tcp
    size_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (len < sizeof(EthHdr)+ihl+sizeof(TCPHdr)) return false;
    const TCPHdr* tcp = (const TCPHdr*)(frame + sizeof(EthHdr) + ihl);
    size_t thl = ((tcp->off_res >> 4) & 0x0F) * 4;
    if (len < sizeof(EthHdr)+ihl+thl) return false;
    size_t payload_len = ntohs(ip->totlen) - ihl - thl;

    // Build RST in reverse direction (to victim) and forward direction (to sender)
    auto build_send = [&](bool reverse)->bool{
        uint8_t out[14 + 20 + 20] = {0}; // eth+ip+tcp no options
        EthHdr* oeth = (EthHdr*)out;
        IPv4Hdr* oip = (IPv4Hdr*)(out + 14);
        TCPHdr* otcp = (TCPHdr*)(out + 14 + 20);
        const uint8_t* srcmac = reverse ? eth->dst : eth->src;
        const uint8_t* dstmac = reverse ? eth->src : eth->dst;
        memcpy(oeth->dst, dstmac, 6); memcpy(oeth->src, srcmac, 6); oeth->type = htons(0x0800);
        oip->ver_ihl = 0x45; oip->tos = 0; oip->totlen = htons(40); oip->id = 0; oip->frag = htons(0x4000);
        oip->ttl = 64; oip->proto = 6; oip->chksum = 0;
        oip->src = reverse ? ip->dst : ip->src;
        oip->dst = reverse ? ip->src : ip->dst;
        otcp->sport = reverse ? tcp->dport : tcp->sport;
        otcp->dport = reverse ? tcp->sport : tcp->dport;
        otcp->seq = reverse ? tcp->ack : htonl(ntohl(tcp->seq) + (uint32_t)payload_len);
        otcp->ack = reverse ? 0 : tcp->ack;
        otcp->off_res = (5 << 4);
        otcp->flags = 0x04; // RST
        otcp->win = 0; otcp->urg = 0; otcp->chksum = 0;
        oip->chksum = ip_checksum(oip, 20);
        otcp->chksum = tcp_checksum(oip, otcp, nullptr, 0);
        return tx->rawTx(out, sizeof(out));
    };
    bool a = build_send(false);
    bool b = build_send(true);
    return a || b;
}

bool SecurityManager::mitigateTcpByRst(const NetworkPacket& packet, EthernetTxIf* tx) const {
    if (!tx || !packet.is_tcp || packet.src_ip.empty() || packet.dst_ip.empty()) {
        return false;
    }

    auto mac_present = [](const uint8_t mac[6]) -> bool {
        for (int i = 0; i < 6; ++i) {
            if (mac[i] != 0) {
                return true;
            }
        }
        return false;
    };

    uint8_t host_mac[6];
    if (!tx->getMac(host_mac)) {
        return false;
    }

    auto send_rst = [&](bool reverse) -> bool {
        const uint8_t* dest_mac = reverse ? packet.dst_mac : packet.src_mac;
        if (!mac_present(dest_mac)) {
            return false;
        }

        const char* src_ip_str = reverse ? packet.dst_ip.c_str() : packet.src_ip.c_str();
        const char* dst_ip_str = reverse ? packet.src_ip.c_str() : packet.dst_ip.c_str();

        struct in_addr src_addr{}, dst_addr{};
        if (inet_aton(src_ip_str, &src_addr) == 0 || inet_aton(dst_ip_str, &dst_addr) == 0) {
            return false;
        }

        uint8_t frame[14 + 20 + 20] = {0};
        EthHdr* eth = (EthHdr*)frame;
        IPv4Hdr* ip = (IPv4Hdr*)(frame + sizeof(EthHdr));
        TCPHdr* tcp = (TCPHdr*)(frame + sizeof(EthHdr) + sizeof(IPv4Hdr));

        memcpy(eth->src, host_mac, 6);
        memcpy(eth->dst, dest_mac, 6);
        eth->type = htons(0x0800);

        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->totlen = htons(40);
        ip->id = 0;
        ip->frag = htons(0x4000);
        ip->ttl = 64;
        ip->proto = 6;
        ip->chksum = 0;
        ip->src = src_addr.s_addr;
        ip->dst = dst_addr.s_addr;

        tcp->sport = htons(reverse ? packet.dst_port : packet.src_port);
        tcp->dport = htons(reverse ? packet.src_port : packet.dst_port);
        tcp->seq = htonl(esp_random());
        tcp->ack = 0;
        tcp->off_res = (5 << 4);
        tcp->flags = 0x04; // RST
        tcp->win = 0;
        tcp->urg = 0;
        tcp->chksum = 0;

        ip->chksum = ip_checksum(ip, sizeof(IPv4Hdr));
        tcp->chksum = tcp_checksum(ip, tcp, nullptr, 0);

        return tx->rawTx(frame, sizeof(frame));
    };

    bool forward = send_rst(false);
    bool reverse = send_rst(true);
    return forward || reverse;
}


//bool SecurityManager::loadPolicyFromConfig(const std::string& json);
extern bool json_find_bool(const std::string& s, const char* key, bool defval);

// Commented out unused function
/*
static bool find_key(const std::string& s, const char* key) {
    return s.find(key) != std::string::npos;
}
*/

// ========================= API AUTHENTICATION STUB METHODS =========================

bool SecurityManager::verifyApiKey(const psram_string& token) const {
    if (token.empty()) {
        return false;
    }

    psram_string token_hash = computeSHA256(token);
    if (token_hash.empty()) {
        return false;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    bool verified = false;
    bool mutated_state = false;
    uint64_t age_ms = 0;
    std::string label_copy;
    std::string id_copy;

    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);

        for (const auto& entry : api_keys_) {
            if (!entry.enabled) {
                continue;
            }

            if (constantTimeCompare(token_hash, entry.hash)) {
                ApiKeyEntry& mutable_entry = const_cast<ApiKeyEntry&>(entry);
                mutable_entry.last_used_ms = now_ms;

                age_ms = (now_ms >= mutable_entry.created_ms) ?
                             (now_ms - mutable_entry.created_ms) : 0ULL;

                mutated_state = updateApiKeyAgeState(mutable_entry, age_ms);
                label_copy.assign(mutable_entry.label.c_str());
                id_copy.assign(mutable_entry.id.c_str());
                verified = true;
                break;
            }
        }
    }

    if (verified) {
        const_cast<SecurityManager*>(this)->saveApiKeysToNVS();

        if (mutated_state) {
            LOG_WARNINGF(TAG_SEC,
                         "API key %s (%s) requires maintenance (age: %llu days)",
                         id_copy.c_str(),
                         label_copy.c_str(),
                         static_cast<unsigned long long>(age_ms / (24ULL * 60ULL * 60ULL * 1000ULL)));
        }

        LOG_INFOF(TAG_SEC, "API key verified: %s", label_copy.c_str());
        return true;
    }

    log_api_key_preview(token.c_str());
    return false;
}

bool SecurityManager::verifyApiKey(const char* token) const {
    if (!token || *token == '\0') {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(token);
    return verifyApiKey(ps);
}

bool SecurityManager::verifyApiKey(const std::string& token) const {
    if (token.empty()) {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(token.c_str());
    return verifyApiKey(ps);
}

bool SecurityManager::verifyAdminPassword(const psram_string& password) const {
    if (password.empty() || admin_password_hash_.empty()) {
        LOG_WARNING(TAG_SEC, "Admin password verification failed: missing input or hash");
        return false;
    }

    if (admin_password_hash_.size() > 7 &&
        admin_password_hash_.substr(0, 7) == PSRAMUtils::createPSRAMString("pbkdf2:")) {
        const bool valid = PasswordHasher::verify(
            password.c_str(), password.size(), admin_password_hash_);

        if (valid) {
            LOG_INFO(TAG_SEC, "Admin password verified successfully (PBKDF2)");
        } else {
            LOG_WARNING(TAG_SEC, "Invalid admin password attempt (PBKDF2)");
        }

        return valid;

    } else if (is_sha256_hex(admin_password_hash_)) {
        // Legacy SHA-256 verification for backward compatibility
        LOG_INFO(TAG_SEC, "Using legacy SHA-256 verification (consider upgrading to PBKDF2)");

        psram_string material;
        size_t reserve_len = master_key_.size() + password.size() + 1;
        if (reserve_len < password.size()) {
            reserve_len = password.size() + 1;
        }
        material.reserve(reserve_len);

        if (!master_key_.empty()) {
            material.append(master_key_);
        }
        material.push_back(':');
        material.append(password);

        psram_string computed_hash = computeSHA256(material);
        zeroize_psram_string(material);

        if (computed_hash.empty()) {
            LOG_WARNING(TAG_SEC, "Admin password verification failed: cannot compute hash");
            return false;
        }

        bool valid = constantTimeCompare(computed_hash, admin_password_hash_);
        zeroize_psram_string(computed_hash);

        if (valid) {
            LOG_INFO(TAG_SEC, "Admin password verified successfully (legacy SHA-256)");
        } else {
            LOG_WARNING(TAG_SEC, "Invalid admin password attempt (legacy SHA-256)");
        }

        return valid;

    } else {
        LOG_ERROR(TAG_SEC, "Unknown password hash format");
        return false;
    }
}

bool SecurityManager::verifyAdminPassword(const char* password) const {
    if (!password || *password == '\0') {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(password);
    return verifyAdminPassword(ps);
}

bool SecurityManager::verifyAdminPassword(const std::string& password) const {
    if (password.empty()) {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(password.c_str());
    return verifyAdminPassword(ps);
}

std::vector<std::pair<std::string, std::string>> SecurityManager::listApiKeysMasked() const {
    std::vector<std::pair<std::string, std::string>> keys;

    std::lock_guard<std::mutex> lock(api_keys_mutex_);

    for (const auto& entry : api_keys_) {
        // Mask the hash: show first 8 chars and last 4 chars
        std::string masked_hash;
        if (entry.hash.size() > 12) {
            masked_hash = std::string(entry.hash.c_str(), 8) + "***" +
                         std::string(entry.hash.c_str() + entry.hash.size() - 4, 4);
        } else {
            masked_hash = "***";
        }

        keys.push_back({std::string(entry.id.c_str()), std::string(entry.label.c_str()) + " [" + masked_hash + "]"});
    }

    LOG_INFOF(TAG_SEC, "Listed %zu API keys (masked)", keys.size());
    return keys;
}

std::string SecurityManager::createApiKey(const psram_string& label) {
    // Generate cryptographically secure token
    psram_string token = generateSecureToken();
    if (token.empty()) {
        LOG_ERROR(TAG_SEC, "Failed to generate secure token");
        return "";
    }

    // Compute SHA-256 hash of token
    psram_string token_hash = computeSHA256(token);
    if (token_hash.empty()) {
        LOG_ERROR(TAG_SEC, "Failed to compute token hash");
        return "";
    }

    // Create entry
    ApiKeyEntry entry;
    entry.id = generateUUID();
    entry.label = PSRAMUtils::createPSRAMString(label.c_str());
    entry.hash = token_hash;
    entry.created_ms = esp_timer_get_time() / 1000;
    entry.last_used_ms = 0;
    entry.enabled = true;

    // Store in vector
    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);
        api_keys_.push_back(entry);
    }

    // Persist to NVS
    if (!saveApiKeysToNVS()) {
        LOG_WARNING(TAG_SEC, "Failed to save API keys to NVS");
    }

    LOG_INFOF(TAG_SEC, "Created API key '%s' (ID: %s)", label.c_str(), entry.id.c_str());

    scheduleRotationForKey(entry);

    // Return the plain token (only time it's visible)
    return std::string(token.c_str());
}

std::string SecurityManager::createApiKey(const char* label) {
    psram_string ps = label ? PSRAMUtils::createPSRAMString(label) : PSRAMUtils::createPSRAMString("api");
    return createApiKey(ps);
}

std::string SecurityManager::createApiKey(const std::string& label) {
    psram_string ps = PSRAMUtils::createPSRAMString(label.c_str());
    return createApiKey(ps);
}

bool SecurityManager::revokeApiKey(const psram_string& id) {
    if (id.empty()) return false;

    bool found = false;
    std::string label_copy;

    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);

        for (auto& entry : api_keys_) {
            if (constantTimeCompare(entry.id, id)) {
                entry.enabled = false;
                entry.disable_alert_sent = true;
                label_copy.assign(entry.label.c_str());
                found = true;
                break;
            }
        }
    }

    if (!found) {
        LOG_WARNINGF(TAG_SEC, "API key not found: %s", id.c_str());
        return false;
    }

    cancelRotationForKey(id);

    if (!saveApiKeysToNVS()) {
        LOG_WARNING(TAG_SEC, "Failed to save API keys to NVS after revocation");
        return false;
    }

    LOG_INFOF(TAG_SEC, "Revoked API key: %s (%s)", label_copy.c_str(), id.c_str());
    return true;
}

bool SecurityManager::revokeApiKey(const char* id) {
    if (!id || *id == '\0') {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(id);
    return revokeApiKey(ps);
}

bool SecurityManager::revokeApiKey(const std::string& id) {
    if (id.empty()) {
        return false;
    }
    psram_string ps = PSRAMUtils::createPSRAMString(id.c_str());
    return revokeApiKey(ps);
}

bool SecurityManager::saveToConfig(ConfigurationManager* cfg) {
    if (!cfg) {
        return false;
    }

    size_t json_size = 0;
    char* json_buffer = cfg->getRawConfigInPSRAM(&json_size);
    if (!json_buffer || json_size == 0) {
        if (json_buffer) {
            heap_caps_free(json_buffer);
        }
        LOG_WARNING(TAG_SEC, "Cannot persist security configuration: empty JSON buffer");
        return false;
    }

    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buffer, json_size);
    heap_caps_free(json_buffer);
    if (!root) {
        LOG_WARNING(TAG_SEC, "Failed to parse configuration JSON for security persistence");
        return false;
    }

    cJSON* security_obj = cJSON_GetObjectItem(root, "security");
    if (!security_obj) {
        security_obj = cJSON_CreateObject();
        if (!security_obj) {
            cJSON_Delete(root);
            LOG_WARNING(TAG_SEC, "Unable to allocate security object for configuration save");
            return false;
        }
        cJSON_AddItemToObject(root, "security", security_obj);
    }

    // Remove any legacy plaintext field
    cJSON_DeleteItemFromObject(security_obj, "admin_password");

    if (!admin_password_hash_.empty()) {
        cJSON* new_hash = cJSON_CreateString(admin_password_hash_.c_str());
        if (!new_hash) {
            cJSON_Delete(root);
            LOG_WARNING(TAG_SEC, "Unable to allocate admin password hash node");
            return false;
        }
        if (cJSON_HasObjectItem(security_obj, "admin_password_hash")) {
            cJSON_ReplaceItemInObject(security_obj, "admin_password_hash", new_hash);
        } else {
            cJSON_AddItemToObject(security_obj, "admin_password_hash", new_hash);
        }
    }

    cJSON_DeleteItemFromObject(security_obj, "api_keys");
    cJSON* api_keys_array = cJSON_CreateArray();
    if (!api_keys_array) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Unable to allocate api_keys array for configuration save");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);
        cfg_.api_keys.clear();
        for (const auto& entry : api_keys_) {
            cJSON* item = cJSON_CreateObject();
            if (!item) {
                cJSON_Delete(root);
                LOG_WARNING(TAG_SEC, "Unable to allocate api_key object for configuration save");
                return false;
            }

            cJSON_AddStringToObject(item, "id", entry.id.c_str());
            cJSON_AddStringToObject(item, "label", entry.label.c_str());
            cJSON_AddStringToObject(item, "hash", entry.hash.c_str());
            cJSON_AddBoolToObject(item, "enabled", entry.enabled);
            cJSON_AddNumberToObject(item, "created_ms", static_cast<double>(entry.created_ms));
            cJSON_AddNumberToObject(item, "last_used_ms", static_cast<double>(entry.last_used_ms));
            cJSON_AddItemToArray(api_keys_array, item);

            cfg_.api_keys[entry.id] = entry.hash;
        }
    }
    cJSON_AddItemToObject(security_obj, "api_keys", api_keys_array);

    SecurityAlertPolicy policy_snapshot;
    getAlertPolicy(policy_snapshot);

    cJSON_DeleteItemFromObject(security_obj, "alert_policy");
    cJSON* alert_policy = cJSON_CreateObject();
    if (!alert_policy) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Unable to allocate alert_policy object for configuration save");
        return false;
    }

    cJSON* email_policy = cJSON_CreateObject();
    if (!email_policy) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Unable to allocate email policy object for configuration save");
        return false;
    }
    cJSON_AddBoolToObject(email_policy, "enabled", policy_snapshot.email.enabled);
    cJSON_AddNumberToObject(email_policy, "throttle_minutes", static_cast<double>(policy_snapshot.email.throttle_minutes));
    if (!policy_snapshot.email.subject.empty()) {
        cJSON_AddStringToObject(email_policy, "subject", policy_snapshot.email.subject.c_str());
    }
    if (!policy_snapshot.email.recipients.empty()) {
        cJSON* recipients = cJSON_CreateArray();
        if (!recipients) {
            cJSON_Delete(root);
            LOG_WARNING(TAG_SEC, "Unable to allocate recipients array for configuration save");
            return false;
        }
        for (const auto& recipient : policy_snapshot.email.recipients) {
            cJSON_AddItemToArray(recipients, cJSON_CreateString(recipient.c_str()));
        }
        cJSON_AddItemToObject(email_policy, "recipients", recipients);
    }
    cJSON_AddItemToObject(alert_policy, "email", email_policy);

    cJSON* webhook_policy = cJSON_CreateObject();
    if (!webhook_policy) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Unable to allocate webhook policy object for configuration save");
        return false;
    }
    cJSON_AddBoolToObject(webhook_policy, "enabled", policy_snapshot.webhook.enabled);
    if (!policy_snapshot.webhook.url.empty()) {
        cJSON_AddStringToObject(webhook_policy, "url", policy_snapshot.webhook.url.c_str());
    }
    if (!policy_snapshot.webhook.token.empty()) {
        cJSON_AddStringToObject(webhook_policy, "token", policy_snapshot.webhook.token.c_str());
    }
    cJSON_AddItemToObject(alert_policy, "webhook", webhook_policy);

    cJSON* gpio_policy = cJSON_CreateObject();
    if (!gpio_policy) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Unable to allocate gpio policy object for configuration save");
        return false;
    }
    cJSON_AddBoolToObject(gpio_policy, "enabled", policy_snapshot.gpio.enabled);
    cJSON_AddNumberToObject(gpio_policy, "critical_pin", policy_snapshot.gpio.critical_pin);
    cJSON_AddNumberToObject(gpio_policy, "warning_pin", policy_snapshot.gpio.warning_pin);
    cJSON_AddNumberToObject(gpio_policy, "buzzer", policy_snapshot.gpio.buzzer_pin);
    cJSON_AddItemToObject(alert_policy, "gpio", gpio_policy);

    cJSON_AddItemToObject(security_obj, "alert_policy", alert_policy);
    cfg_.alert_policy = policy_snapshot;

    char* updated_json = cJSON_PrintUnformatted(root);
    if (!updated_json) {
        cJSON_Delete(root);
        LOG_WARNING(TAG_SEC, "Failed to serialize updated security configuration");
        return false;
    }

    bool saved = cfg->saveConfigJSON(updated_json);
    free(updated_json);
    cJSON_Delete(root);

    if (!saved) {
        LOG_WARNING(TAG_SEC, "Failed to write security configuration to config.json");
        return false;
    }

    cfg_.admin_password = admin_password_hash_;
    admin_hash_dirty_ = false;
    LOG_INFO(TAG_SEC, "Security configuration persisted to config.json");
    return true;
}

// ========================= SECURE API KEY IMPLEMENTATION =========================

psram_string SecurityManager::generateSecureToken() const {
    // Generate 256-bit (32 bytes) random token
    const size_t TOKEN_BYTES = 32;
    uint8_t* random_bytes = (uint8_t*)heap_caps_malloc(TOKEN_BYTES, MALLOC_CAP_SPIRAM);
    if (!random_bytes) {
        LOG_ERROR(TAG_SEC, "Failed to allocate PSRAM for token generation");
        return PSRAMUtils::createPSRAMString("");
    }

    // Fill with cryptographically secure random data
    for (size_t i = 0; i < TOKEN_BYTES; i++) {
        random_bytes[i] = (uint8_t)(esp_random() & 0xFF);
    }

    // Convert to hex string (64 chars)
    char* hex_token = (char*)heap_caps_malloc(TOKEN_BYTES * 2 + 1, MALLOC_CAP_SPIRAM);
    if (!hex_token) {
        heap_caps_free(random_bytes);
        LOG_ERROR(TAG_SEC, "Failed to allocate PSRAM for hex token");
        return PSRAMUtils::createPSRAMString("");
    }

    for (size_t i = 0; i < TOKEN_BYTES; i++) {
        snprintf(hex_token + i * 2, 3, "%02x", random_bytes[i]);
    }
    hex_token[TOKEN_BYTES * 2] = '\0';

    psram_string result = PSRAMUtils::createPSRAMString(hex_token);

    heap_caps_free(random_bytes);
    heap_caps_free(hex_token);

    return result;
}

psram_string SecurityManager::computeSHA256(const psram_string& data) const {
    if (data.empty()) {
        return PSRAMUtils::createPSRAMString("");
    }

    // Allocate buffer for hash output in PSRAM
    uint8_t* hash = (uint8_t*)heap_caps_malloc(32, MALLOC_CAP_SPIRAM);
    if (!hash) {
        LOG_ERROR(TAG_SEC, "Failed to allocate PSRAM for SHA256 hash");
        return PSRAMUtils::createPSRAMString("");
    }

    // Compute SHA-256
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256 (not SHA-224)
    mbedtls_sha256_update(&ctx, (const unsigned char*)data.c_str(), data.size());
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    // Convert to hex string in PSRAM
    char* hex_hash = (char*)heap_caps_malloc(65, MALLOC_CAP_SPIRAM);
    if (!hex_hash) {
        heap_caps_free(hash);
        LOG_ERROR(TAG_SEC, "Failed to allocate PSRAM for hex hash");
        return PSRAMUtils::createPSRAMString("");
    }

    for (int i = 0; i < 32; i++) {
        snprintf(hex_hash + i * 2, 3, "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    psram_string result = PSRAMUtils::createPSRAMString(hex_hash);

    heap_caps_free(hash);
    heap_caps_free(hex_hash);

    return result;
}

bool SecurityManager::constantTimeCompare(const psram_string& a, const psram_string& b) const {
    // Constant-time comparison to prevent timing attacks
    if (a.size() != b.size()) {
        return false;
    }

    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= (a[i] ^ b[i]);
    }

    return result == 0;
}

psram_string SecurityManager::generateUUID() const {
    // Generate UUID v4 (random) format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // where y is one of [8, 9, a, b]

    char* uuid = (char*)heap_caps_malloc(37, MALLOC_CAP_SPIRAM); // 36 chars + null
    if (!uuid) {
        LOG_ERROR(TAG_SEC, "Failed to allocate PSRAM for UUID");
        return PSRAMUtils::createPSRAMString("");
    }

    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    uint32_t r3 = esp_random();
    uint32_t r4 = esp_random();

    snprintf(uuid, 37, "%08lx-%04x-4%03x-%04x-%08lx%04x",
             (unsigned long)r1,
             (unsigned int)(r2 >> 16),
             (unsigned int)(r2 & 0x0FFF),
             (unsigned int)(0x8000 | (r3 & 0x3FFF)),
             (unsigned long)(r4),
             (unsigned int)(r3 >> 16));

    psram_string result = PSRAMUtils::createPSRAMString(uuid);
    heap_caps_free(uuid);

    return result;
}

bool SecurityManager::loadApiKeysFromNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        LOG_INFOF(TAG_SEC, "No existing API keys in NVS: %s", esp_err_to_name(err));
        return false;
    }

    // Get number of stored keys
    uint32_t key_count = 0;
    err = nvs_get_u32(handle, "api_key_count", &key_count);
    if (err != ESP_OK || key_count == 0) {
        nvs_close(handle);
        LOG_INFO(TAG_SEC, "No API keys found in NVS");
        return false;
    }

    std::lock_guard<std::mutex> lock(api_keys_mutex_);
    api_keys_.clear();

    // Load each key
    for (uint32_t i = 0; i < key_count && i < 100; i++) { // Max 100 keys
        char key_prefix[32];
        snprintf(key_prefix, sizeof(key_prefix), "key_%lu_", (unsigned long)i);

        // Read ID
        size_t id_len = 0;
        char id_key[40];
        snprintf(id_key, sizeof(id_key), "%sid", key_prefix);
        err = nvs_get_str(handle, id_key, NULL, &id_len);
        if (err != ESP_OK || id_len == 0) continue;

        char* id_buf = (char*)heap_caps_malloc(id_len, MALLOC_CAP_SPIRAM);
        if (!id_buf) continue;
        nvs_get_str(handle, id_key, id_buf, &id_len);

        // Read label
        size_t label_len = 0;
        char label_key[40];
        snprintf(label_key, sizeof(label_key), "%slabel", key_prefix);
        err = nvs_get_str(handle, label_key, NULL, &label_len);
        if (err != ESP_OK || label_len == 0) {
            heap_caps_free(id_buf);
            continue;
        }

        char* label_buf = (char*)heap_caps_malloc(label_len, MALLOC_CAP_SPIRAM);
        if (!label_buf) {
            heap_caps_free(id_buf);
            continue;
        }
        nvs_get_str(handle, label_key, label_buf, &label_len);

        // Read hash
        size_t hash_len = 0;
        char hash_key[40];
        snprintf(hash_key, sizeof(hash_key), "%shash", key_prefix);
        err = nvs_get_str(handle, hash_key, NULL, &hash_len);
        if (err != ESP_OK || hash_len == 0) {
            heap_caps_free(id_buf);
            heap_caps_free(label_buf);
            continue;
        }

        char* hash_buf = (char*)heap_caps_malloc(hash_len, MALLOC_CAP_SPIRAM);
        if (!hash_buf) {
            heap_caps_free(id_buf);
            heap_caps_free(label_buf);
            continue;
        }
        nvs_get_str(handle, hash_key, hash_buf, &hash_len);

        // Read timestamps and enabled flag
        uint64_t created_ms = 0, last_used_ms = 0;
        uint8_t enabled = 1;
        uint8_t rotation_alert = 0;
        uint8_t disable_alert = 0;
        char created_key[48], last_used_key[48], enabled_key[48], rot_key[48], dis_key[48];
        snprintf(created_key, sizeof(created_key), "%screated", key_prefix);
        snprintf(last_used_key, sizeof(last_used_key), "%slast_used", key_prefix);
        snprintf(enabled_key, sizeof(enabled_key), "%senabled", key_prefix);
        snprintf(rot_key, sizeof(rot_key), "%srotation_alert", key_prefix);
        snprintf(dis_key, sizeof(dis_key), "%sdisable_alert", key_prefix);

        nvs_get_u64(handle, created_key, &created_ms);
        nvs_get_u64(handle, last_used_key, &last_used_ms);
        nvs_get_u8(handle, enabled_key, &enabled);
        if (nvs_get_u8(handle, rot_key, &rotation_alert) != ESP_OK) {
            rotation_alert = 0;
        }
        if (nvs_get_u8(handle, dis_key, &disable_alert) != ESP_OK) {
            disable_alert = 0;
        }

        // Create entry
        ApiKeyEntry entry;
        entry.id = PSRAMUtils::createPSRAMString(id_buf);
        entry.label = PSRAMUtils::createPSRAMString(label_buf);
        entry.hash = PSRAMUtils::createPSRAMString(hash_buf);
        entry.created_ms = created_ms;
        entry.last_used_ms = last_used_ms;
        entry.enabled = (enabled != 0);
        entry.rotation_alert_sent = (rotation_alert != 0);
        entry.disable_alert_sent = (disable_alert != 0);

        if (entry.rotation_alert_sent) {
            scheduleRotationForKey(entry);
        } else if (!entry.enabled) {
            cancelRotationForKey(entry.id);
        }

        api_keys_.push_back(entry);

        heap_caps_free(id_buf);
        heap_caps_free(label_buf);
        heap_caps_free(hash_buf);
    }

    nvs_close(handle);
    LOG_INFOF(TAG_SEC, "Loaded %zu API keys from NVS", api_keys_.size());
    return true;
}

bool SecurityManager::saveApiKeysToNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_SEC, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return false;
    }

    std::lock_guard<std::mutex> lock(api_keys_mutex_);

    // Clear old keys
    nvs_erase_all(handle);

    // Save key count
    uint32_t key_count = (uint32_t)api_keys_.size();
    err = nvs_set_u32(handle, "api_key_count", key_count);
    if (err != ESP_OK) {
        nvs_close(handle);
        LOG_ERRORF(TAG_SEC, "Failed to write key count: %s", esp_err_to_name(err));
        return false;
    }

    // Save each key
    for (size_t i = 0; i < api_keys_.size(); i++) {
        const ApiKeyEntry& entry = api_keys_[i];
        char key_prefix[32];
        snprintf(key_prefix, sizeof(key_prefix), "key_%zu_", i);

        char key_name[48];

        // Save ID
        snprintf(key_name, sizeof(key_name), "%sid", key_prefix);
        nvs_set_str(handle, key_name, entry.id.c_str());

        // Save label
        snprintf(key_name, sizeof(key_name), "%slabel", key_prefix);
        nvs_set_str(handle, key_name, entry.label.c_str());

        // Save hash
        snprintf(key_name, sizeof(key_name), "%shash", key_prefix);
        nvs_set_str(handle, key_name, entry.hash.c_str());

        // Save timestamps
        snprintf(key_name, sizeof(key_name), "%screated", key_prefix);
        nvs_set_u64(handle, key_name, entry.created_ms);

        snprintf(key_name, sizeof(key_name), "%slast_used", key_prefix);
        nvs_set_u64(handle, key_name, entry.last_used_ms);

        // Save enabled flag
        snprintf(key_name, sizeof(key_name), "%senabled", key_prefix);
        nvs_set_u8(handle, key_name, entry.enabled ? 1 : 0);

        // Save rotation alert state
        snprintf(key_name, sizeof(key_name), "%srotation_alert", key_prefix);
        nvs_set_u8(handle, key_name, entry.rotation_alert_sent ? 1 : 0);

        // Save disable alert state
        snprintf(key_name, sizeof(key_name), "%sdisable_alert", key_prefix);
        nvs_set_u8(handle, key_name, entry.disable_alert_sent ? 1 : 0);
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        LOG_ERRORF(TAG_SEC, "Failed to commit NVS: %s", esp_err_to_name(err));
        return false;
    }

    LOG_INFOF(TAG_SEC, "Saved %zu API keys to NVS", api_keys_.size());
    return true;
}

void SecurityManager::raiseSecurityFault(const char* feature, const char* recommendation) {
    if (!feature) {
        return;
    }

    fuzzing_allowed_ = false;
    security_gap_detected_ = true;

    const char* action = recommendation ? recommendation : "";
    LOG_ERRORF(TAG_SEC, "Security hardening requirement not met: %s -> %s", feature, action);

    if (g_reporting) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),
                 "{\"feature\":\"%s\",\"status\":\"non_compliant\",\"recommendation\":\"%s\",\"mitigation\":\"fuzzing_disabled\"}",
                 feature, action);
        psram_string type = PSRAMUtils::createPSRAMString("security_hardening");
        psram_string payload = PSRAMUtils::createPSRAMString(buffer);
        g_reporting->reportEvent(type, payload);
    }
}

void SecurityManager::emitApiKeySecurityEvent(const ApiKeyEntry& entry,
                                              const char* event_type,
                                              uint64_t age_ms,
                                              bool disabled) const {
    if (!event_type) {
        return;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return;
    }

    cJSON_AddStringToObject(root, "type", event_type);
    cJSON_AddStringToObject(root, "id", entry.id.c_str());
    cJSON_AddStringToObject(root, "label", entry.label.c_str());
    cJSON_AddNumberToObject(root, "age_days",
                            static_cast<double>(age_ms) / (24.0 * 60.0 * 60.0 * 1000.0));
    cJSON_AddBoolToObject(root, "disabled", disabled);
    char* json = cJSON_PrintUnformatted(root);
    if (json) {
        psram_string detail = PSRAMUtils::createPSRAMString(json);
        char summary_buf[160];
        const unsigned long long age_days = static_cast<unsigned long long>(age_ms / (24ULL * 60ULL * 60ULL * 1000ULL));
        snprintf(summary_buf, sizeof(summary_buf),
                 "API key %s (%s) %s%llud",
                 entry.id.c_str(),
                 entry.label.c_str(),
                 disabled ? "disabled pending rotation - age " : "requires rotation - age ",
                 age_days);
        psram_string summary = PSRAMUtils::createPSRAMString(summary_buf);
        const char* severity = disabled ? "critical" : "warning";
        const_cast<SecurityManager*>(this)->recordSecurityEvent(
            event_type,
            severity,
            summary,
            detail);
        free(json);
    }
    cJSON_Delete(root);
}

bool SecurityManager::updateApiKeyAgeState(ApiKeyEntry& entry, uint64_t age_ms) const {
    bool mutated = false;

    if (age_ms > kApiKeyRotationMs) {
        if (!entry.rotation_alert_sent) {
            LOG_WARNINGF(TAG_SEC,
                         "API key %s (%s) exceeded rotation threshold (age: %llu days)",
                         entry.id.c_str(),
                         entry.label.c_str(),
                         static_cast<unsigned long long>(age_ms /
                             (24ULL * 60ULL * 60ULL * 1000ULL)));
            emitApiKeySecurityEvent(entry, "security.api_key.rotation_required", age_ms, false);
            entry.rotation_alert_sent = true;
            mutated = true;
            scheduleRotationForKey(entry);
        }

        if (age_ms > kApiKeyDisableMs) {
            if (entry.enabled) {
                entry.enabled = false;
                LOG_WARNINGF(TAG_SEC,
                             "API key %s disabled pending rotation",
                             entry.id.c_str());
                emitApiKeySecurityEvent(entry, "security.api_key.disabled", age_ms, true);
                mutated = true;
                cancelRotationForKey(entry.id);
            } else if (!entry.disable_alert_sent) {
                emitApiKeySecurityEvent(entry, "security.api_key.disabled", age_ms, true);
                mutated = true;
            }
            entry.disable_alert_sent = true;
        }
    }

    return mutated;
}

void SecurityManager::auditApiKeysForRotation() {
    uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    bool mutated = false;

    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);
        for (auto& entry : api_keys_) {
            uint64_t age_ms = (now_ms >= entry.created_ms)
                                  ? (now_ms - entry.created_ms)
                                  : 0ULL;
            if (age_ms == 0) {
                continue;
            }
            if (updateApiKeyAgeState(entry, age_ms)) {
                mutated = true;
            }
        }
    }

    if (mutated) {
        saveApiKeysToNVS();
    }
}

void SecurityManager::scheduleRotationForKey(const ApiKeyEntry& entry) const {
    if (!g_api_key_rotation_manager) {
        return;
    }
    ApiKeyRotationPolicy policy{};
    g_api_key_rotation_manager->getPolicy(policy);
    if (!policy.enabled) {
        return;
    }
    g_api_key_rotation_manager->scheduleRotation(entry.id.c_str(), entry.label.c_str());
}

void SecurityManager::cancelRotationForKey(const psram_string& key_id) const {
    if (!g_api_key_rotation_manager || key_id.empty()) {
        return;
    }
    g_api_key_rotation_manager->cancelRotation(key_id.c_str());
}

void SecurityManager::setAlertPolicy(const SecurityAlertPolicy& policy) {
    SecurityAlertPolicy new_policy;

    new_policy.email.enabled = policy.email.enabled;
    new_policy.email.throttle_minutes = policy.email.throttle_minutes;
    new_policy.email.subject = policy.email.subject.empty()
        ? PSRAMUtils::createPSRAMString("Security Alert")
        : PSRAMUtils::createPSRAMString(policy.email.subject.c_str());

    {
        PSRAMAllocator<psram_string> alloc;
        new_policy.email.recipients = psram_string_vector(alloc);
        for (const auto& recipient : policy.email.recipients) {
            if (!recipient.empty()) {
                new_policy.email.recipients.push_back(
                    PSRAMUtils::createPSRAMString(recipient.c_str()));
            }
        }
    }

    new_policy.webhook.enabled = policy.webhook.enabled;
    new_policy.webhook.url = PSRAMUtils::createPSRAMString(policy.webhook.url.c_str());
    new_policy.webhook.token = PSRAMUtils::createPSRAMString(policy.webhook.token.c_str());
    new_policy.gpio = policy.gpio;

    {
        std::lock_guard<std::mutex> lock(alert_policy_mutex_);
        alert_policy_ = new_policy;
        cfg_.alert_policy = new_policy;
    }
}

void SecurityManager::getAlertPolicy(SecurityAlertPolicy& out_policy) const {
    std::lock_guard<std::mutex> lock(alert_policy_mutex_);

    out_policy.email.enabled = alert_policy_.email.enabled;
    out_policy.email.throttle_minutes = alert_policy_.email.throttle_minutes;
    out_policy.email.subject = PSRAMUtils::createPSRAMString(alert_policy_.email.subject.c_str());

    {
        PSRAMAllocator<psram_string> alloc;
        out_policy.email.recipients = psram_string_vector(alloc);
        for (const auto& recipient : alert_policy_.email.recipients) {
            out_policy.email.recipients.push_back(
                PSRAMUtils::createPSRAMString(recipient.c_str()));
        }
    }

    out_policy.webhook.enabled = alert_policy_.webhook.enabled;
    out_policy.webhook.url = PSRAMUtils::createPSRAMString(alert_policy_.webhook.url.c_str());
    out_policy.webhook.token = PSRAMUtils::createPSRAMString(alert_policy_.webhook.token.c_str());
    out_policy.gpio = alert_policy_.gpio;
}

void SecurityManager::getSecurityConfigSnapshot(SecurityConfig& out_cfg) const {
    std::lock_guard<std::mutex> lock(alert_policy_mutex_);
    out_cfg = cfg_;
}

bool SecurityManager::loadAdminPasswordHash(psram_string& hash_out) {
    hash_out.clear();

    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return false;
    }

    size_t length = 0;
    err = nvs_get_str(handle, "admin_pwd", nullptr, &length);
    if (err != ESP_OK || length == 0) {
        nvs_close(handle);
        return false;
    }

    char* buffer = (char*)heap_caps_malloc(length, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buffer) {
        nvs_close(handle);
        LOG_WARNING(TAG_SEC, "Failed to allocate PSRAM while loading admin password hash");
        return false;
    }

    err = nvs_get_str(handle, "admin_pwd", buffer, &length);
    if (err == ESP_OK) {
        hash_out = PSRAMUtils::createPSRAMString(buffer);
    }

    heap_caps_free(buffer);
    nvs_close(handle);
    return err == ESP_OK;
}

bool SecurityManager::storeAdminPasswordHash(const psram_string& hash) {
    if (hash.empty()) {
        return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        LOG_WARNINGF(TAG_SEC, "Failed to open NVS for admin password hash: %s", esp_err_to_name(err));
        return false;
    }

    err = nvs_set_str(handle, "admin_pwd", hash.c_str());
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);

    if (err != ESP_OK) {
        LOG_WARNINGF(TAG_SEC, "Failed to persist admin password hash: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}
void SecurityManager::getApiKeyMetrics(ApiKeyMetrics& out_metrics) const {
    out_metrics = {};
    {
        std::lock_guard<std::mutex> lock(api_keys_mutex_);
        out_metrics.total = static_cast<uint32_t>(api_keys_.size());
        for (const auto& entry : api_keys_) {
            if (entry.enabled) {
                ++out_metrics.enabled;
            }
            if (entry.rotation_alert_sent) {
                ++out_metrics.rotation_required;
            }
            if (entry.disable_alert_sent) {
                ++out_metrics.disabled_pending_rotation;
            }
            if (out_metrics.newest_created_ms == 0 || entry.created_ms > out_metrics.newest_created_ms) {
                out_metrics.newest_created_ms = entry.created_ms;
            }
            if (out_metrics.oldest_created_ms == 0 || entry.created_ms < out_metrics.oldest_created_ms) {
                out_metrics.oldest_created_ms = entry.created_ms;
            }
        }
    }
}

void SecurityManager::getSecurityEvents(psram_vector<SecurityEventLog>& out_events) const {
    std::lock_guard<std::mutex> lock(security_events_mutex_);
    PSRAMAllocator<SecurityEventLog> alloc;
    psram_vector<SecurityEventLog> copy(alloc);
    copy = security_events_;
    out_events.swap(copy);
}

bool SecurityManager::acknowledgeSecurityEvent(const psram_string& event_id,
                                               const psram_string& actor,
                                               bool acknowledged) {
    if (event_id.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(security_events_mutex_);
    for (auto& ev : security_events_) {
        if (ev.id == event_id) {
            ev.acknowledged = acknowledged;
            if (acknowledged) {
                ev.ack_timestamp_ms = esp_timer_get_time() / 1000ULL;
                ev.acked_by = actor.empty()
                    ? PSRAMUtils::createPSRAMString("web-ui")
                    : actor;
            } else {
                ev.ack_timestamp_ms = 0;
                ev.acked_by = PSRAMUtils::createPSRAMString("");
            }
            return true;
        }
    }
    return false;
}

void SecurityManager::recordSecurityEvent(const char* type,
                                          const char* severity,
                                          const psram_string& summary,
                                          const psram_string& detail_json) {
    const char* resolved_type = (type && *type) ? type : "security_alert";
    const char* resolved_severity = (severity && *severity) ? severity : "info";

    SecurityEventLog entry;
    entry.type = PSRAMUtils::createPSRAMString(resolved_type);
    entry.severity = PSRAMUtils::createPSRAMString(resolved_severity);
    entry.summary = PSRAMUtils::createPSRAMString(summary.c_str());
    entry.detail_json = PSRAMUtils::createPSRAMString(detail_json.c_str());
    entry.timestamp_ms = esp_timer_get_time() / 1000ULL;
    entry.ack_timestamp_ms = 0;
    entry.acknowledged = false;
    entry.acked_by = PSRAMUtils::createPSRAMString("");

    psram_string event_id = generateSecureToken();
    if (event_id.empty()) {
        char fallback[40];
        snprintf(fallback, sizeof(fallback), "evt_%llu",
                 static_cast<unsigned long long>(entry.timestamp_ms));
        event_id = PSRAMUtils::createPSRAMString(fallback);
    }
    entry.id = event_id;

    {
        std::lock_guard<std::mutex> lock(security_events_mutex_);
        security_events_.push_back(entry);
        if (security_events_.size() > kMaxSecurityEvents) {
            security_events_.erase(security_events_.begin());
        }
    }

    if (!g_reporting) {
        return;
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return;
    }

    cJSON_AddStringToObject(root, "id", entry.id.c_str());
    cJSON_AddStringToObject(root, "type", entry.type.c_str());
    cJSON_AddStringToObject(root, "severity", entry.severity.c_str());
    cJSON_AddStringToObject(root, "summary", entry.summary.c_str());
    if (!entry.detail_json.empty()) {
        cJSON_AddStringToObject(root, "detail", entry.detail_json.c_str());
    }
    cJSON_AddNumberToObject(root, "timestamp_ms", static_cast<double>(entry.timestamp_ms));
    cJSON_AddBoolToObject(root, "acknowledged", entry.acknowledged);
    if (entry.ack_timestamp_ms) {
        cJSON_AddNumberToObject(root, "ack_timestamp_ms", static_cast<double>(entry.ack_timestamp_ms));
    }
    if (!entry.acked_by.empty()) {
        cJSON_AddStringToObject(root, "acked_by", entry.acked_by.c_str());
    }

    cJSON* policy_obj = cJSON_CreateObject();
    SecurityAlertPolicy policy_snapshot;
    getAlertPolicy(policy_snapshot);

    if (policy_obj) {

        cJSON* email_obj = cJSON_CreateObject();
        if (email_obj) {
            cJSON_AddBoolToObject(email_obj, "enabled", policy_snapshot.email.enabled);
            cJSON_AddNumberToObject(email_obj, "throttle_minutes",
                                    static_cast<double>(policy_snapshot.email.throttle_minutes));
            if (!policy_snapshot.email.subject.empty()) {
                cJSON_AddStringToObject(email_obj, "subject", policy_snapshot.email.subject.c_str());
            }
            if (!policy_snapshot.email.recipients.empty()) {
                cJSON* recipients = cJSON_CreateArray();
                if (recipients) {
                    for (const auto& addr : policy_snapshot.email.recipients) {
                        cJSON_AddItemToArray(recipients, cJSON_CreateString(addr.c_str()));
                    }
                    cJSON_AddItemToObject(email_obj, "recipients", recipients);
                }
            }
            cJSON_AddItemToObject(policy_obj, "email", email_obj);
        }

        cJSON* webhook_obj = cJSON_CreateObject();
        if (webhook_obj) {
            cJSON_AddBoolToObject(webhook_obj, "enabled", policy_snapshot.webhook.enabled);
            if (!policy_snapshot.webhook.url.empty()) {
                cJSON_AddStringToObject(webhook_obj, "url", policy_snapshot.webhook.url.c_str());
            }
            cJSON_AddItemToObject(policy_obj, "webhook", webhook_obj);
        }

        cJSON* gpio_obj = cJSON_CreateObject();
        if (gpio_obj) {
            cJSON_AddBoolToObject(gpio_obj, "enabled", policy_snapshot.gpio.enabled);
            cJSON_AddNumberToObject(gpio_obj, "critical_pin", policy_snapshot.gpio.critical_pin);
            cJSON_AddNumberToObject(gpio_obj, "warning_pin", policy_snapshot.gpio.warning_pin);
            cJSON_AddNumberToObject(gpio_obj, "buzzer_pin", policy_snapshot.gpio.buzzer_pin);
            cJSON_AddItemToObject(policy_obj, "gpio", gpio_obj);
        }

        cJSON_AddItemToObject(root, "alert_policy", policy_obj);
    }

    char* json = cJSON_PrintUnformatted(root);
    psram_string payload;
    if (json) {
        payload = PSRAMUtils::createPSRAMString(json);
        free(json);
    }
    cJSON_Delete(root);

    if (payload.empty()) {
        return;
    }

    if (g_reporting) {
        psram_string security_channel = PSRAMUtils::createPSRAMString("security");
        g_reporting->reportEventToChannel(security_channel, entry.type, payload);
    }

    dispatchSecurityEvent(entry.type, payload, entry.severity.c_str(), entry.timestamp_ms, policy_snapshot);
}


void SecurityManager::dispatchSecurityEvent(const psram_string& type,
                                            const psram_string& payload,
                                            const char* severity,
                                            uint64_t timestamp_ms,
                                            const SecurityAlertPolicy& policy) {
    (void)severity;
    if (!g_reporting) {
        return;
    }

    uint64_t now_ms = timestamp_ms;

    if (policy.email.enabled) {
        bool allow = true;
        if (policy.email.throttle_minutes > 0) {
            uint64_t interval_ms = static_cast<uint64_t>(policy.email.throttle_minutes) * 60ULL * 1000ULL;
            if (last_email_alert_ms_ != 0 && (now_ms - last_email_alert_ms_) < interval_ms) {
                allow = false;
            }
        }
        if (allow) {
            g_reporting->reportEventToChannel(PSRAMUtils::createPSRAMString("email"), type, payload);
            last_email_alert_ms_ = now_ms;
        }
    }

    if (policy.webhook.enabled) {
        g_reporting->reportEventToChannel(PSRAMUtils::createPSRAMString("webhook"), type, payload);
        last_webhook_alert_ms_ = now_ms;
    }

    if (policy.gpio.enabled) {
        g_reporting->reportEventToChannel(PSRAMUtils::createPSRAMString("gpio"), type, payload);
    }
}
