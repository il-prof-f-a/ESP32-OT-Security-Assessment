#include "configuration_manager.h"
#include "logging_system.h"
#include "async_storage_engine.h"
#include "psram_json_parser.h"
#include "psram_json_parser.h"
#include "esp32_ot_build_assets.h"
#include <sys/stat.h>
#include <fstream>
#include <stdint.h>
#include <stddef.h>

const char* ConfigurationManager::kNVS_NAMESPACE = "cfg";
const char* ConfigurationManager::kNVS_CRC_KEY   = "config_crc32";
const char* ConfigurationManager::kCONFIG_PATH   = "/data/config/config.json";
const char* ConfigurationManager::kCONFIG_BAK    = "/data/config/config.json.bak";

namespace {
constexpr char kProvisioningNamespace[] = "provisioning";
constexpr uint16_t kProvisioningSchemaVersion = 1;
}

ConfigurationManager::ConfigurationManager() {
}

ConfigurationManager::~ConfigurationManager() {
    if (root_) cJSON_Delete(root_);
}

bool ConfigurationManager::initialize() {
    // NVS initialization is handled by AsyncStorage engine
    // No direct NVS flash operations needed here

    // Ensure config dir exists using AsyncStorage
    bool dir_exists = false;
    esp_err_t err = AsyncStorage::Global::fileExists("/data/config", dir_exists);
    if (err != ESP_OK || !dir_exists) {
        err = AsyncStorage::Global::createDir("/data/config");
        if (err != ESP_OK) {
            LOG_ERROR("Config", "Failed to create config directory");
            return false;
        }
    }

    // Load configuration source tracking
    loadConfigSourceFromNVS();

    // Configuration loading priority:
    // 1. Prefer filesystem configuration to preserve user changes
    // 2. Fallback to embedded defaults when filesystem is unavailable
    // 3. Then attempt backup, finally regenerate defaults

    bool loaded = false;

    // Prefer filesystem configuration whenever available
    if (loadJSONFromFS()) {
        LOG_INFO("Config", "Using filesystem configuration");
        if (config_source_ != ConfigSource::WEB_INTERFACE && config_source_ != ConfigSource::FILESYSTEM) {
            saveConfigSourceToNVS(ConfigSource::FILESYSTEM);
        }
        loaded = true;
    }

    if (!loaded) {
        LOG_INFO("Config", "Filesystem configuration unavailable, checking embedded defaults");
        if (loadDevConfigFromSource()) {
            saveConfigSourceToNVS(ConfigSource::EMBEDDED);
            loaded = true;
        } else {
            LOG_WARNING("Config", "No embedded config available, trying backup");
        }
    }

    // Fall back to backup
    if (!loaded && tryRecoveryFromBackup()) {
        LOG_INFO("Config", "✅ Recovered from backup configuration");
        saveConfigSourceToNVS(ConfigSource::FILESYSTEM);
        loaded = true;
    }

    // Final fallback to default
    if (!loaded && loadOrCreateDefault()) {
        LOG_INFO("Config", "✅ Using default configuration");
        saveConfigSourceToNVS(ConfigSource::DEFAULT);
        loaded = true;
    }

    if (!loaded) {
        LOG_ERROR("Config", "❌ Failed to load any configuration");
        return false;
    }

    // Validate schema
    if (!validateConfig()) {
        LOG_WARNING("Config","Config invalid, attempting backup recovery");
        if (!tryRecoveryFromBackup()) {
            LOG_WARNING("Config","Keeping current configuration despite validation issues");
        }
    }

    // Cache
    parseAndCache(root_);

    // Ensure all protocol fields are present
    mergeDefaultProtocolFields();

    return true;
}

bool ConfigurationManager::loadJSONFromFS() {
    LOG_INFO("Config", "Attempting to load configuration from filesystem");
    LOG_INFOF("Config", "Loading from path: %s", kCONFIG_PATH);

    std::ifstream ifs(kCONFIG_PATH, std::ios::binary);
    if (!ifs) {
        LOG_WARNING("Config", "Configuration file not found on filesystem");
        return false;
    }

    std::string json((std::istreambuf_iterator<char>(ifs)), {});
    //LOG_INFOF("Config", "Read %u bytes from configuration file", (unsigned)json.length());

    if (root_) cJSON_Delete(root_);
    {
        PSRAMJsonParser::PSRAMContext ctx;
        root_ = PSRAMJsonParser::parseInPSRAM(json.c_str(), json.size());
    }
    if (!root_) {
        LOG_ERROR("Config", "Failed to parse JSON configuration - invalid format");
        return false;
    }

    //LOG_INFO("Config", "✅ Configuration JSON parsed successfully");

    // Update raw cache
    raw_ = PSRAMUtils::createPSRAMString(json.c_str());

    // CRC check
    uint32_t crc = 0;
    if (AsyncStorage::Global::nvsGet(kNVS_NAMESPACE, kNVS_CRC_KEY, crc) == ESP_OK) {
        uint32_t now = crc32((const uint8_t*)json.data(), json.size());
        if (now != crc) {
            LOG_WARNING("Config","CRC mismatch for config.json");
        }
    }
    return true;
}

bool ConfigurationManager::tryRecoveryFromBackup() {
    std::ifstream ifs(kCONFIG_BAK, std::ios::binary);
    if (!ifs) return false;
    std::string json((std::istreambuf_iterator<char>(ifs)), {});
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* recovered = PSRAMJsonParser::parseInPSRAM(json.c_str(), json.size());
    if (!recovered) return false;
    cJSON_Delete(recovered);
    return saveConfigJSON(PSRAMUtils::createPSRAMString(json.c_str()));
}

bool ConfigurationManager::loadOrCreateDefault() {
    // Minimal default config
    const char* kDefault = R"json(
    )json";

    if (root_) cJSON_Delete(root_);
    {
        PSRAMJsonParser::PSRAMContext ctx;
        root_ = PSRAMJsonParser::parseInPSRAM(kDefault, strlen(kDefault));
    }
    if (!root_) return false;

    // Update raw cache
    raw_ = PSRAMUtils::createPSRAMString(kDefault);

    // Persist default (atomic + CRC)
    psram_string default_json = PSRAMUtils::createPSRAMString(kDefault);
    return saveConfigJSON(default_json);
}


bool ConfigurationManager::saveConfigJSON(const psram_string& json_ps) {
    auto config_lock = lockConfig();
    // Allocate and validate before touching persistent or runtime state.
    struct Candidate {
        cJSON* value;
        ~Candidate() { cJSON_Delete(value); }
    } candidate{PSRAMJsonParser::parseInPSRAM(json_ps.c_str(), json_ps.size())};
    if (!cJSON_IsObject(candidate.value)) return false;


    //LOG_INFO("Config", "Starting configuration save process");

    //LOG_INFOF("Config", "Configuration size: %u bytes", (unsigned)json_ps.size());



    esp_err_t err = AsyncStorage::Global::createDir("/data/config");

    if (err != ESP_OK && err != ESP_ERR_INVALID_ARG) {

        LOG_ERROR("Config", "Failed to ensure config directory exists");

        return false;

    }

    bool provisioning_transaction = false;
    if (!beginProvisionedConfigUpdate(provisioning_transaction)) {
        LOG_ERROR("Config", "Failed to begin provisioning metadata update");
        return false;
    }

    //LOG_INFO("Config", "Ensured /data/config directory exists");



    bool file_exists = false;

    AsyncStorage::Global::fileExists(kCONFIG_PATH, file_exists);

    if (file_exists) {

        //LOG_INFO("Config", "Creating backup of existing configuration");

        std::string curr;

        if (AsyncStorage::Global::readFile(kCONFIG_PATH, curr) == ESP_OK) {

            AsyncStorage::Global::writeFileRaw(kCONFIG_BAK, curr.data(), curr.size());

            //LOG_INFOF("Config", "Backup saved to %s (%u bytes)", kCONFIG_BAK, (unsigned)curr.length());

        }

    }



    //LOG_INFOF("Config", "Writing configuration to %s", kCONFIG_PATH);

    err = AsyncStorage::Global::writeFileRaw(kCONFIG_PATH, json_ps.data(), json_ps.size());

    if (err != ESP_OK) {

        LOG_ERROR("Config", "Failed to write configuration to filesystem");

        return false;

    }


    //LOG_INFO("Config", " Configuration written to filesystem successfully");



    //LOG_INFO("Config", "Updating NVS with configuration CRC");

    const uint32_t crc = crc32(reinterpret_cast<const uint8_t*>(json_ps.data()), json_ps.size());

    esp_err_t r = AsyncStorage::Global::nvsSet(kNVS_NAMESPACE, kNVS_CRC_KEY, crc);

    if (r == ESP_OK) {

        //LOG_INFOF("Config", " CRC32 saved to NVS: 0x%08lX", (unsigned long)crc);

    } else {

        LOG_ERRORF("Config", "Failed to save CRC to NVS: %s", esp_err_to_name(r));
        return false;

    }



    // NVS has a ~4 KB limit per value; the full config JSON (~6 KB) exceeds it, so the
    // redundant full-JSON NVS copy always fails with ESP_ERR_NVS_VALUE_TOO_LONG. The
    // authoritative copy lives on the filesystem with a CRC in NVS, so only mirror small
    // configs into NVS and skip the copy for large ones.
    if (json_ps.size() <= 3500) {
        AsyncStorage::Global::nvsSet(kNVS_NAMESPACE, "config_json", json_ps);
    }

    saveConfigSourceToNVS(ConfigSource::WEB_INTERFACE);

    //LOG_INFO("Config", "Configuration saved via web interface - future boots will preserve user changes");



    // Do not publish new flags if storage/provisioning metadata failed.
    if (!finishProvisionedConfigUpdate(crc, provisioning_transaction)) {
        LOG_ERROR("Config", "Failed to finalize provisioning metadata update");
        return false;
    }
    cJSON_Delete(root_);
    root_ = candidate.value;
    candidate.value = nullptr;
    raw_ = json_ps;
    parseAndCache(root_);
    if (config_applied_callback_) config_applied_callback_(config_applied_context_);
    return true;
}

bool ConfigurationManager::beginProvisionedConfigUpdate(bool& transaction_active) {
    transaction_active = false;
    nvs_handle_t handle;
    esp_err_t error = nvs_open(kProvisioningNamespace, NVS_READONLY, &handle);
    if (error == ESP_ERR_NVS_NOT_FOUND) return true;
    if (error != ESP_OK) return false;

    uint16_t schema = 0;
    uint8_t complete = 0;
    const bool ready =
        nvs_get_u16(handle, "schema_u16", &schema) == ESP_OK &&
        nvs_get_u8(handle, "complete_u8", &complete) == ESP_OK &&
        schema == kProvisioningSchemaVersion && complete == 1;
    nvs_close(handle);
    if (!ready) return true;

    error = nvs_open(kProvisioningNamespace, NVS_READWRITE, &handle);
    if (error != ESP_OK) return false;
    error = nvs_set_u8(handle, "complete_u8", 0);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    if (error != ESP_OK) return false;
    transaction_active = true;
    return true;
}

bool ConfigurationManager::finishProvisionedConfigUpdate(uint32_t crc,
                                                          bool transaction_active) {
    if (!transaction_active) return true;
    nvs_handle_t handle;
    esp_err_t error = nvs_open(kProvisioningNamespace, NVS_READWRITE, &handle);
    if (error != ESP_OK) return false;
    error = nvs_set_u32(handle, "config_crc_u32", crc);
    if (error == ESP_OK) error = nvs_set_u8(handle, "complete_u8", 1);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error == ESP_OK;
}



bool ConfigurationManager::isFeatureEnabled(const char* name, bool default_value) const {
    if (!name || !*name) return default_value;

    // Hard persistence for scheduled scans toggle:
    // If the device reboots/crashes before filesystem write completes, NVS still preserves this flag.
    // Web UI writes it to NVS namespace "cron" key "enabled".
    if (strcmp(name, "scheduled_scans") == 0 || strcmp(name, "cron_scheduler") == 0) {
        uint8_t nvs_enabled = 0;
        if (AsyncStorage::Global::nvsGet("cron", "enabled", nvs_enabled) == ESP_OK) {
            return (nvs_enabled != 0);
        }
    }

    size_t json_size = 0;
    char* json_psram = getRawConfigInPSRAM(&json_size);
    if (!json_psram || json_size == 0) return default_value;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_psram, json_size);
    heap_caps_free(json_psram);
    if (!root) return default_value;
    bool enabled = default_value;
    if (strcmp(name, "ids") == 0) {
        cJSON* ids = cJSON_GetObjectItem(root, "ids");
        if (ids && cJSON_IsObject(ids)) {
            cJSON* general = cJSON_GetObjectItem(ids, "general");
            if (general && cJSON_IsObject(general)) {
                cJSON* en = cJSON_GetObjectItem(general, "enabled");
                if (en && cJSON_IsBool(en)) enabled = (en->valueint != 0);
            }
        }
    } else if (strcmp(name, "vuln_scanner") == 0 || strcmp(name, "fuzzing") == 0) {
        cJSON* scanner = cJSON_GetObjectItem(root, "scanner");
        if (scanner && cJSON_IsObject(scanner)) {
            cJSON* en = cJSON_GetObjectItem(scanner, "enabled");
            if (en && cJSON_IsBool(en)) enabled = (en->valueint != 0);
        }
    } else if (strcmp(name, "scheduled_scans") == 0 || strcmp(name, "cron_scheduler") == 0) {
        cJSON* scanner = cJSON_GetObjectItem(root, "scanner");
        if (scanner && cJSON_IsObject(scanner)) {
            cJSON* scheduling = cJSON_GetObjectItem(scanner, "scheduling");
            bool value_set = false;
            if (scheduling && cJSON_IsObject(scheduling)) {
                cJSON* en = cJSON_GetObjectItem(scheduling, "enabled");
                if (en && cJSON_IsBool(en)) {
                    enabled = (en->valueint != 0);
                    value_set = true;
                }
            }
            if (!value_set) {
                cJSON* legacy = cJSON_GetObjectItem(scanner, "scheduler_enabled");
                if (legacy && cJSON_IsBool(legacy)) {
                    enabled = (legacy->valueint != 0);
                    value_set = true;
                }
            }
            if (!value_set) {
                cJSON* en = cJSON_GetObjectItem(scanner, "enabled");
                if (en && cJSON_IsBool(en)) enabled = (en->valueint != 0);
            }
        }
    } else if (strcmp(name, "modbus") == 0 || strcmp(name, "opcua") == 0 || strcmp(name, "s7") == 0 || strcmp(name, "profinet") == 0 || strcmp(name, "ethernetip") == 0) {
        cJSON* plugins = cJSON_GetObjectItem(root, "plugins");
        if (plugins && cJSON_IsObject(plugins)) {
            // Read only the requested plugin block by key = name
            cJSON* plugin = cJSON_GetObjectItem(plugins, name);
            if (plugin && cJSON_IsObject(plugin)) {
                cJSON* en = cJSON_GetObjectItem(plugin, "enabled");
                if (en && cJSON_IsBool(en)) enabled = (en->valueint != 0);
            }
        }
    } else {
        enabled = default_value;
    }
    cJSON_Delete(root);
    return enabled;
}

bool ConfigurationManager::validateConfig() const {
    if (!root_) return false;
    // Very lightweight schema validation
    auto mustBool = [](cJSON* obj, const char* key)->bool{
        auto* it = cJSON_GetObjectItemCaseSensitive(obj, key);
        return it && cJSON_IsBool(it);
    };
    auto mustNumber = [](cJSON* obj, const char* key)->bool{
        auto* it = cJSON_GetObjectItemCaseSensitive(obj, key);
        return it && cJSON_IsNumber(it);
    };
    // Removed unused mustString lambda

    cJSON* debug = cJSON_GetObjectItem(root_, "debug");
    if (!debug || !mustNumber(debug,"level") || !mustBool(debug,"color")) return false;

    cJSON* security = cJSON_GetObjectItem(root_, "security");
    if (!security || !mustBool(security,"secure_boot") || !mustBool(security,"flash_encryption")
        || !mustBool(security,"certificate_validation")) return false;
    cJSON* enforce_opcua = cJSON_GetObjectItemCaseSensitive(security, "opcua_enforce_security");
    if (enforce_opcua && !cJSON_IsBool(enforce_opcua)) return false;

    cJSON* network = cJSON_GetObjectItem(root_, "network");
    if (!network) return false;
    cJSON* eth = cJSON_GetObjectItem(network,"ethernet");
    cJSON* wifi = cJSON_GetObjectItem(network,"wifi");
    if (!eth || !wifi) return false;

    auto checkNet = [&](cJSON* obj)->bool{
        if (!mustBool(obj,"enabled") || !mustBool(obj,"dhcp")) return false;
        // optional strings
        const char* keys[] = {"ip","gateway","netmask","ssid","password"};
        for (auto k: keys) {
            cJSON* it = cJSON_GetObjectItemCaseSensitive(obj, k);
            if (it && !cJSON_IsString(it)) return false;
        }
        return true;
    };
    if (!checkNet(eth) || !checkNet(wifi)) return false;

    // plugins object (optional map with enabled flags)
    cJSON* plugins = cJSON_GetObjectItem(root_, "plugins");
    if (plugins && !cJSON_IsObject(plugins)) return false;

    return true;
}

static psram_string jsonStringOrEmpty(cJSON* obj, const char* key) {
    if (!obj || !key) {
        return psram_string{};
    }
    cJSON* it = cJSON_GetObjectItem(obj, key);
    if (it && cJSON_IsString(it) && it->valuestring) {
        return PSRAMUtils::createPSRAMString(it->valuestring);
    }
    return psram_string{};
}

static cJSON* get_path_object(cJSON* root, const char* path);

bool ConfigurationManager::parseAndCache(cJSON* root) {
    auto config_lock = lockConfig();
    if (!root) return false;
    // debug
    cJSON* d = cJSON_GetObjectItem(root,"debug");
    if (d) {
        cJSON* lv = cJSON_GetObjectItem(d,"level");
        cJSON* co = cJSON_GetObjectItem(d,"color");
        if (cJSON_IsNumber(lv)) debug_.level = (int)lv->valuedouble;
        if (cJSON_IsBool(co)) debug_.color = cJSON_IsTrue(co);
    }
    // security
    cJSON* s = cJSON_GetObjectItem(root,"security");
    if (s) {
        sec_.alert_policy = SecurityAlertPolicy();
        {
            PSRAMAllocator<psram_string> alloc;
            sec_.alert_policy.email.recipients = psram_string_vector(alloc);
        }
        cJSON* a = cJSON_GetObjectItem(s,"secure_boot");
        cJSON* b = cJSON_GetObjectItem(s,"flash_encryption");
        cJSON* c = cJSON_GetObjectItem(s,"certificate_validation");
        if (cJSON_IsBool(a)) sec_.secure_boot = cJSON_IsTrue(a);
        if (cJSON_IsBool(b)) sec_.flash_encryption = cJSON_IsTrue(b);
        if (cJSON_IsBool(c)) sec_.certificate_validation = cJSON_IsTrue(c);
        cJSON* opcua_enforce = cJSON_GetObjectItem(s, "opcua_enforce_security");
        if (cJSON_IsBool(opcua_enforce)) {
            sec_.opcua_enforce_security = cJSON_IsTrue(opcua_enforce);
        }

        cJSON* offensive = cJSON_GetObjectItem(s, "offensive_testing");
        if (offensive && cJSON_IsObject(offensive)) {
            cJSON* software = cJSON_GetObjectItem(offensive, "software_enabled");
            if (cJSON_IsBool(software)) {
                sec_.offensive_testing.software_enabled = cJSON_IsTrue(software);
            }
            cJSON* boot_policy = cJSON_GetObjectItem(offensive, "boot_policy");
            if (boot_policy && cJSON_IsString(boot_policy) && boot_policy->valuestring) {
                sec_.offensive_testing.boot_policy =
                    PSRAMUtils::createPSRAMString(boot_policy->valuestring);
            }
            cJSON* gate = cJSON_GetObjectItem(offensive, "gpio_gate");
            if (gate && cJSON_IsObject(gate)) {
                cJSON* enabled = cJSON_GetObjectItem(gate, "enabled");
                cJSON* required = cJSON_GetObjectItem(gate, "required");
                cJSON* gpio = cJSON_GetObjectItem(gate, "gpio");
                cJSON* active_high = cJSON_GetObjectItem(gate, "active_high");
                cJSON* pull_mode = cJSON_GetObjectItem(gate, "pull_mode");
                if (cJSON_IsBool(enabled)) sec_.offensive_testing.gpio_gate.enabled = cJSON_IsTrue(enabled);
                if (cJSON_IsBool(required)) sec_.offensive_testing.gpio_gate.required = cJSON_IsTrue(required);
                if (cJSON_IsNumber(gpio)) sec_.offensive_testing.gpio_gate.gpio = static_cast<int>(gpio->valuedouble);
                if (cJSON_IsBool(active_high)) sec_.offensive_testing.gpio_gate.active_high = cJSON_IsTrue(active_high);
                if (cJSON_IsNumber(pull_mode)) sec_.offensive_testing.gpio_gate.pull_mode = static_cast<int>(pull_mode->valuedouble);
            }
        }
        psram_string admin_hash = jsonStringOrEmpty(s, "admin_password_hash");
        if (!admin_hash.empty()) {
            sec_.admin_password = admin_hash;
        } else {
            psram_string legacy_admin = jsonStringOrEmpty(s, "admin_password");
            if (!legacy_admin.empty()) {
                sec_.admin_password = legacy_admin;
            }
        }

        cJSON* alert_policy = cJSON_GetObjectItem(s, "alert_policy");
        if (alert_policy && cJSON_IsObject(alert_policy)) {
            // Email policy
            cJSON* email_obj = cJSON_GetObjectItem(alert_policy, "email");
            if (email_obj && cJSON_IsObject(email_obj)) {
                cJSON* en = cJSON_GetObjectItem(email_obj, "enabled");
                if (cJSON_IsBool(en)) {
                    sec_.alert_policy.email.enabled = cJSON_IsTrue(en);
                }

                cJSON* subject = cJSON_GetObjectItem(email_obj, "subject");
                if (subject && cJSON_IsString(subject) && subject->valuestring) {
                    sec_.alert_policy.email.subject = PSRAMUtils::createPSRAMString(subject->valuestring);
                }

                cJSON* throttle = cJSON_GetObjectItem(email_obj, "throttle_minutes");
                if (throttle && cJSON_IsNumber(throttle)) {
                    double value = throttle->valuedouble;
                    if (value < 0) value = 0;
                    sec_.alert_policy.email.throttle_minutes = static_cast<uint32_t>(value);
                }

                cJSON* recipients = cJSON_GetObjectItem(email_obj, "recipients");
                {
                    PSRAMAllocator<psram_string> alloc;
                    sec_.alert_policy.email.recipients = psram_string_vector(alloc);
                    if (recipients && cJSON_IsArray(recipients)) {
                        cJSON* item = nullptr;
                        cJSON_ArrayForEach(item, recipients) {
                            if (item && cJSON_IsString(item) && item->valuestring) {
                                sec_.alert_policy.email.recipients.push_back(
                                    PSRAMUtils::createPSRAMString(item->valuestring));
                            }
                        }
                    }
                }
            }

            // Webhook policy
            cJSON* webhook_obj = cJSON_GetObjectItem(alert_policy, "webhook");
            if (webhook_obj && cJSON_IsObject(webhook_obj)) {
                cJSON* en = cJSON_GetObjectItem(webhook_obj, "enabled");
                if (cJSON_IsBool(en)) {
                    sec_.alert_policy.webhook.enabled = cJSON_IsTrue(en);
                }
                cJSON* url = cJSON_GetObjectItem(webhook_obj, "url");
                if (url && cJSON_IsString(url) && url->valuestring) {
                    sec_.alert_policy.webhook.url = PSRAMUtils::createPSRAMString(url->valuestring);
                }
                cJSON* token = cJSON_GetObjectItem(webhook_obj, "token");
                if (token && cJSON_IsString(token) && token->valuestring) {
                    sec_.alert_policy.webhook.token = PSRAMUtils::createPSRAMString(token->valuestring);
                }
            }

            // GPIO policy
            cJSON* gpio_obj = cJSON_GetObjectItem(alert_policy, "gpio");
            if (gpio_obj && cJSON_IsObject(gpio_obj)) {
                cJSON* en = cJSON_GetObjectItem(gpio_obj, "enabled");
                if (cJSON_IsBool(en)) {
                    sec_.alert_policy.gpio.enabled = cJSON_IsTrue(en);
                }
                cJSON* critical = cJSON_GetObjectItem(gpio_obj, "critical_pin");
                if (critical && cJSON_IsNumber(critical)) {
                    sec_.alert_policy.gpio.critical_pin = static_cast<uint8_t>(critical->valuedouble);
                }
                cJSON* warning = cJSON_GetObjectItem(gpio_obj, "warning_pin");
                if (warning && cJSON_IsNumber(warning)) {
                    sec_.alert_policy.gpio.warning_pin = static_cast<uint8_t>(warning->valuedouble);
                }
                cJSON* buzzer = cJSON_GetObjectItem(gpio_obj, "buzzer");
                if (!buzzer) buzzer = cJSON_GetObjectItem(gpio_obj, "buzzer_pin");
                if (buzzer && cJSON_IsNumber(buzzer)) {
                    sec_.alert_policy.gpio.buzzer_pin = static_cast<uint8_t>(buzzer->valuedouble);
                }
            }
        }
    }
    // network
    cJSON* n = cJSON_GetObjectItem(root,"network");
    if (n) {
        cJSON* eth = cJSON_GetObjectItem(n,"ethernet");
        cJSON* wf  = cJSON_GetObjectItem(n,"wifi");
        if (eth) {
            cJSON* en = cJSON_GetObjectItem(eth,"enabled");
            cJSON* dh = cJSON_GetObjectItem(eth,"dhcp");
            cJSON* pr = cJSON_GetObjectItem(eth,"promiscuous");
            if (cJSON_IsBool(en)) net_.eth_enabled = cJSON_IsTrue(en);
            if (cJSON_IsBool(dh)) net_.eth_dhcp   = cJSON_IsTrue(dh);
            if (cJSON_IsBool(pr)) net_.eth_promiscuous   = cJSON_IsTrue(pr);
            net_.eth_ip      = jsonStringOrEmpty(eth, "ip");
            net_.eth_gateway = jsonStringOrEmpty(eth, "gateway");
            net_.eth_netmask = jsonStringOrEmpty(eth, "netmask");
        }
        if (wf) {
            cJSON* en = cJSON_GetObjectItem(wf,"enabled");
            cJSON* dh = cJSON_GetObjectItem(wf,"dhcp");
            if (cJSON_IsBool(en)) net_.wifi_enabled = cJSON_IsTrue(en);
            if (cJSON_IsBool(dh)) net_.wifi_dhcp    = cJSON_IsTrue(dh);
            net_.wifi_ssid    = jsonStringOrEmpty(wf, "ssid");
            net_.wifi_password= jsonStringOrEmpty(wf, "password");
            net_.wifi_ip      = jsonStringOrEmpty(wf, "ip");
            net_.wifi_gateway = jsonStringOrEmpty(wf, "gateway");
            net_.wifi_netmask = jsonStringOrEmpty(wf, "netmask");

            // Read DNS and NTP from wifi section (current config.json format)
            psram_string wifi_dns = jsonStringOrEmpty(wf, "dns");
            psram_string wifi_ntp = jsonStringOrEmpty(wf, "ntp");
            if (!wifi_dns.empty()) {
                net_.dns_primary = wifi_dns;
                // Default secondary DNS
                net_.dns_secondary = PSRAMUtils::createPSRAMString("8.8.4.4");
            }
            if (!wifi_ntp.empty()) {
                net_.ntp_primary = wifi_ntp;
                // Default secondary/tertiary NTP
                net_.ntp_secondary = "";//PSRAMUtils::createPSRAMString("pool.ntp.org");
                net_.ntp_tertiary = "";//PSRAMUtils::createPSRAMString("time.nist.gov");
            }

            // Read new time synchronization configuration
            net_.time_sync = jsonStringOrEmpty(wf, "time_sync");
            if (net_.time_sync.empty()) {
                net_.time_sync = PSRAMUtils::createPSRAMString("ntp"); // Default to NTP
            }
            net_.http_time_sync = jsonStringOrEmpty(wf, "http_time_sync");
        }

        // Alternative: DNS configuration from separate section (fallback)
        cJSON* dns = cJSON_GetObjectItem(n, "dns");
        if (dns && net_.dns_primary.empty()) {
            net_.dns_primary   = jsonStringOrEmpty(dns, "primary");
            net_.dns_secondary = jsonStringOrEmpty(dns, "secondary");
        }

        // Alternative: NTP configuration from separate section (fallback)
        cJSON* ntp = cJSON_GetObjectItem(n, "ntp");
        if (ntp && net_.ntp_primary.empty()) {
            net_.ntp_primary   = jsonStringOrEmpty(ntp, "primary");
            net_.ntp_secondary = jsonStringOrEmpty(ntp, "secondary");
            net_.ntp_tertiary  = jsonStringOrEmpty(ntp, "tertiary");
        }
    }

    // Missing module flags retain the historical enabled defaults, never the
    // state left by a previously loaded configuration.
    ids_ = IDSConfig{};
    signatures_ = SignatureConfig{};
    network_presence_ = NetworkPresenceConfig{};
    // IDS configuration (consolidated under "ids" key)
    cJSON* ids_root = cJSON_GetObjectItem(root,"ids");

    // LEGACY: Support old "advanced_ids" for backward compatibility
    cJSON* ids = cJSON_GetObjectItem(root,"advanced_ids");
    if (!ids_root && ids) {
        ids_root = ids; // Fallback to legacy structure
    }

    if (ids_root) {
        cJSON* signatures = cJSON_GetObjectItemCaseSensitive(ids_root, "signatures");
        cJSON* signature_enabled = cJSON_GetObjectItemCaseSensitive(signatures, "enabled");
        if (cJSON_IsBool(signature_enabled)) signatures_.enabled = cJSON_IsTrue(signature_enabled);
        ids_anomaly_ = IDSAnomalyConfig();
        // Try new structure first
        cJSON* general = cJSON_GetObjectItem(ids_root, "general");
        if (!general && ids_root == ids) {
            // Legacy structure - use root directly
            general = ids_root;
        }

        if (general) {
            cJSON* enabled = cJSON_GetObjectItem(general,"enabled");
            cJSON* modbus = cJSON_GetObjectItem(general,"max_per_sec_modbus");
            cJSON* s7 = cJSON_GetObjectItem(general,"max_per_sec_s7");
            cJSON* enip = cJSON_GetObjectItem(general,"max_per_sec_enip");
            cJSON* pn = cJSON_GetObjectItem(general,"max_per_sec_pn");
            cJSON* opcua = cJSON_GetObjectItem(general,"max_per_sec_opcua");
            cJSON* replay = cJSON_GetObjectItem(general,"replay_window_ms");

            if (cJSON_IsBool(enabled)) ids_.enabled = cJSON_IsTrue(enabled);
            if (cJSON_IsNumber(modbus)) ids_.max_per_sec_modbus = (uint32_t)modbus->valuedouble;
            if (cJSON_IsNumber(s7)) ids_.max_per_sec_s7 = (uint32_t)s7->valuedouble;
            if (cJSON_IsNumber(enip)) ids_.max_per_sec_enip = (uint32_t)enip->valuedouble;
            if (cJSON_IsNumber(pn)) ids_.max_per_sec_pn = (uint32_t)pn->valuedouble;
            if (cJSON_IsNumber(opcua)) ids_.max_per_sec_opcua = (uint32_t)opcua->valuedouble;
            if (cJSON_IsNumber(replay)) ids_.replay_window_ms = (uint32_t)replay->valuedouble;
            // moved: alert_modbus_broadcast_write now under ids.protocol_specific.modbus.alert_broadcast_write
        }

        cJSON* anomaly = cJSON_GetObjectItem(ids_root, "anomaly");
        if (anomaly && cJSON_IsObject(anomaly)) {
            cJSON* flooding = cJSON_GetObjectItem(anomaly, "flooding_pps_threshold");
            if (cJSON_IsNumber(flooding) && flooding->valuedouble > 0.0) {
                ids_anomaly_.flooding_pps_threshold = (float)flooding->valuedouble;
            }

            cJSON* req_sec = cJSON_GetObjectItem(anomaly, "requests_per_second_threshold");
            if (cJSON_IsNumber(req_sec) && req_sec->valuedouble > 0.0) {
                ids_anomaly_.requests_per_second_threshold = (float)req_sec->valuedouble;
            }

            cJSON* rr_high = cJSON_GetObjectItem(anomaly, "request_response_high_ratio");
            if (cJSON_IsNumber(rr_high) && rr_high->valuedouble > 0.0) {
                ids_anomaly_.request_response_high_ratio = (float)rr_high->valuedouble;
            }

            cJSON* rr_low = cJSON_GetObjectItem(anomaly, "request_response_low_ratio");
            if (cJSON_IsNumber(rr_low) && rr_low->valuedouble > 0.0) {
                ids_anomaly_.request_response_low_ratio = (float)rr_low->valuedouble;
            }

            cJSON* malformed_norm = cJSON_GetObjectItem(anomaly, "malformed_packets_normalizer");
            if (cJSON_IsNumber(malformed_norm) && malformed_norm->valuedouble > 0.0) {
                ids_anomaly_.malformed_packets_normalizer = (float)malformed_norm->valuedouble;
            }

            cJSON* cooldown_ms = cJSON_GetObjectItem(anomaly, "reactive_fuzzing_cooldown_ms");
            if (cJSON_IsNumber(cooldown_ms) && cooldown_ms->valuedouble > 0.0) {
                ids_anomaly_.reactive_fuzzing_cooldown_ms = (uint32_t)cooldown_ms->valuedouble;
            }
            cJSON* cooldown_min = cJSON_GetObjectItem(anomaly, "reactive_fuzzing_cooldown_minutes");
            if (cJSON_IsNumber(cooldown_min) && cooldown_min->valuedouble > 0.0) {
                ids_anomaly_.reactive_fuzzing_cooldown_ms = (uint32_t)(cooldown_min->valuedouble * 60000.0);
            }

            cJSON* retention_ms = cJSON_GetObjectItem(anomaly, "reactive_fuzzing_retention_ms");
            if (cJSON_IsNumber(retention_ms) && retention_ms->valuedouble > 0.0) {
                ids_anomaly_.reactive_fuzzing_retention_ms = (uint32_t)retention_ms->valuedouble;
            }
            cJSON* retention_min = cJSON_GetObjectItem(anomaly, "reactive_fuzzing_retention_minutes");
            if (cJSON_IsNumber(retention_min) && retention_min->valuedouble > 0.0) {
                ids_anomaly_.reactive_fuzzing_retention_ms = (uint32_t)(retention_min->valuedouble * 60000.0);
            }
        }

        // Writers configuration (new structure only)
        cJSON* writers = cJSON_GetObjectItem(ids_root, "writers");
        if (writers) {
            cJSON* allowed_ips = cJSON_GetObjectItem(writers, "allowed_ips");
            if (cJSON_IsArray(allowed_ips)) {
                writers_.allowed_ips.clear();
                cJSON* ip = nullptr;
                cJSON_ArrayForEach(ip, allowed_ips) {
                    if (cJSON_IsString(ip)) {
                        writers_.allowed_ips.emplace_back(PSRAMUtils::createPSRAMString(ip->valuestring));
                    }
                }
            }

            cJSON* allowed_macs = cJSON_GetObjectItem(writers, "allowed_macs");
            if (cJSON_IsArray(allowed_macs)) {
                writers_.allowed_macs.clear();
                cJSON* mac = nullptr;
                cJSON_ArrayForEach(mac, allowed_macs) {
                    if (cJSON_IsString(mac)) {
                        writers_.allowed_macs.emplace_back(PSRAMUtils::createPSRAMString(mac->valuestring));
                    }
                }
            }
        }

        // Network presence configuration (moved from top-level)
        cJSON* network_presence_new = cJSON_GetObjectItem(ids_root, "network_presence");
        if (network_presence_new) {
            cJSON* enabled = cJSON_GetObjectItem(network_presence_new,"enabled");
            cJSON* learning_mode = cJSON_GetObjectItem(network_presence_new,"learning_mode");
            cJSON* alert_unauthorized = cJSON_GetObjectItem(network_presence_new,"alert_unauthorized_writes");
            cJSON* track_all = cJSON_GetObjectItem(network_presence_new,"track_all_traffic");
            cJSON* cleanup_interval = cJSON_GetObjectItem(network_presence_new,"cleanup_interval_ms");
            cJSON* inactive_timeout = cJSON_GetObjectItem(network_presence_new,"inactive_device_timeout_ms");
            cJSON* activation_delay = cJSON_GetObjectItem(network_presence_new,"activation_delay_minutes");
            cJSON* retention_days = cJSON_GetObjectItem(network_presence_new,"retention_days");
            cJSON* trust_threshold = cJSON_GetObjectItem(network_presence_new,"trust_threshold_score");
            cJSON* observation_period = cJSON_GetObjectItem(network_presence_new,"min_observation_period_hours");
            cJSON* continuity_weight = cJSON_GetObjectItem(network_presence_new,"continuity_weight");
            cJSON* diversity_weight = cJSON_GetObjectItem(network_presence_new,"diversity_weight");
            cJSON* frequency_weight = cJSON_GetObjectItem(network_presence_new,"frequency_weight");

            if (cJSON_IsBool(enabled)) network_presence_.enabled = cJSON_IsTrue(enabled);
            if (cJSON_IsBool(learning_mode)) network_presence_.learning_mode = cJSON_IsTrue(learning_mode);
            if (cJSON_IsBool(alert_unauthorized)) network_presence_.alert_unauthorized_writes = cJSON_IsTrue(alert_unauthorized);
            if (cJSON_IsBool(track_all)) network_presence_.track_all_traffic = cJSON_IsTrue(track_all);
            if (cJSON_IsNumber(cleanup_interval)) network_presence_.cleanup_interval_ms = (uint32_t)cleanup_interval->valuedouble;
            if (cJSON_IsNumber(inactive_timeout)) network_presence_.inactive_device_timeout_ms = (uint32_t)inactive_timeout->valuedouble;
            if (cJSON_IsNumber(activation_delay)) network_presence_.activation_delay_minutes = (uint32_t)activation_delay->valuedouble;
            if (cJSON_IsNumber(retention_days)) network_presence_.retention_days = (uint32_t)retention_days->valuedouble;
            if (cJSON_IsNumber(trust_threshold)) network_presence_.trust_threshold_score = trust_threshold->valuedouble;
            if (cJSON_IsNumber(observation_period)) network_presence_.min_observation_period_hours = observation_period->valuedouble;
            if (cJSON_IsNumber(continuity_weight)) network_presence_.continuity_weight = continuity_weight->valuedouble;
            if (cJSON_IsNumber(diversity_weight)) network_presence_.diversity_weight = diversity_weight->valuedouble;
            if (cJSON_IsNumber(frequency_weight)) network_presence_.frequency_weight = frequency_weight->valuedouble;
        }
    }

    // writers_config
    cJSON* writers = cJSON_GetObjectItem(root,"writers_config");
    if (writers) {
        cJSON* enabled = cJSON_GetObjectItem(writers,"enabled");
        cJSON* alert = cJSON_GetObjectItem(writers,"alert_unauthorized_writes");
        cJSON* track = cJSON_GetObjectItem(writers,"track_all_senders");
        cJSON* cleanup = cJSON_GetObjectItem(writers,"cleanup_interval_ms");
        cJSON* timeout = cJSON_GetObjectItem(writers,"inactive_sender_timeout_ms");
        cJSON* allowed = cJSON_GetObjectItem(writers,"allowed_writers");

        if (cJSON_IsBool(enabled)) writers_.enabled = cJSON_IsTrue(enabled);
        if (cJSON_IsBool(alert)) writers_.alert_unauthorized_writes = cJSON_IsTrue(alert);
        if (cJSON_IsBool(track)) writers_.track_all_senders = cJSON_IsTrue(track);
        if (cJSON_IsNumber(cleanup)) writers_.cleanup_interval_ms = (uint32_t)cleanup->valuedouble;
        if (cJSON_IsNumber(timeout)) writers_.inactive_sender_timeout_ms = (uint32_t)timeout->valuedouble;

        if (allowed && cJSON_IsArray(allowed)) {
            writers_.allowed_writers.clear();
            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, allowed) {
                if (cJSON_IsString(item)) {
                    writers_.allowed_writers.emplace_back(PSRAMUtils::createPSRAMString(item->valuestring));
                }
            }
        }
    }

    // LEGACY: network_presence configuration (now moved to ids.network_presence)
    cJSON* network_presence = cJSON_GetObjectItem(root,"network_presence");
    if (network_presence && !cJSON_GetObjectItem(ids_root, "network_presence")) {
        // Only use legacy if new structure not found
        cJSON* enabled = cJSON_GetObjectItem(network_presence,"enabled");
        cJSON* learning_mode = cJSON_GetObjectItem(network_presence,"learning_mode");
        cJSON* alert_unauthorized = cJSON_GetObjectItem(network_presence,"alert_unauthorized_writes");
        cJSON* track_all = cJSON_GetObjectItem(network_presence,"track_all_traffic");
        cJSON* cleanup_interval = cJSON_GetObjectItem(network_presence,"cleanup_interval_ms");
        cJSON* inactive_timeout = cJSON_GetObjectItem(network_presence,"inactive_device_timeout_ms");
        cJSON* activation_delay = cJSON_GetObjectItem(network_presence,"activation_delay_minutes");
        cJSON* retention_days = cJSON_GetObjectItem(network_presence,"retention_days");
        cJSON* trust_threshold = cJSON_GetObjectItem(network_presence,"trust_threshold_score");
        cJSON* observation_period = cJSON_GetObjectItem(network_presence,"min_observation_period_hours");
        cJSON* continuity_weight = cJSON_GetObjectItem(network_presence,"continuity_weight");
        cJSON* diversity_weight = cJSON_GetObjectItem(network_presence,"diversity_weight");
        cJSON* frequency_weight = cJSON_GetObjectItem(network_presence,"frequency_weight");

        if (cJSON_IsBool(enabled)) network_presence_.enabled = cJSON_IsTrue(enabled);
        if (cJSON_IsBool(learning_mode)) network_presence_.learning_mode = cJSON_IsTrue(learning_mode);
        if (cJSON_IsBool(alert_unauthorized)) network_presence_.alert_unauthorized_writes = cJSON_IsTrue(alert_unauthorized);
        if (cJSON_IsBool(track_all)) network_presence_.track_all_traffic = cJSON_IsTrue(track_all);
        if (cJSON_IsNumber(cleanup_interval)) network_presence_.cleanup_interval_ms = (uint32_t)cleanup_interval->valuedouble;
        if (cJSON_IsNumber(inactive_timeout)) network_presence_.inactive_device_timeout_ms = (uint32_t)inactive_timeout->valuedouble;
        if (cJSON_IsNumber(activation_delay)) network_presence_.activation_delay_minutes = (uint32_t)activation_delay->valuedouble;
        if (cJSON_IsNumber(retention_days)) network_presence_.retention_days = (uint32_t)retention_days->valuedouble;
        if (cJSON_IsNumber(trust_threshold)) network_presence_.trust_threshold_score = trust_threshold->valuedouble;
        if (cJSON_IsNumber(observation_period)) network_presence_.min_observation_period_hours = observation_period->valuedouble;
        if (cJSON_IsNumber(continuity_weight)) network_presence_.continuity_weight = continuity_weight->valuedouble;
        if (cJSON_IsNumber(diversity_weight)) network_presence_.diversity_weight = diversity_weight->valuedouble;
        if (cJSON_IsNumber(frequency_weight)) network_presence_.frequency_weight = frequency_weight->valuedouble;
    }

    // Read these from the same canonical/legacy object as the other fields.
    cJSON* presence_extra = cJSON_GetObjectItemCaseSensitive(ids_root, "network_presence");
    if (!cJSON_IsObject(presence_extra)) presence_extra = network_presence;
    if (cJSON_IsObject(presence_extra)) {
        cJSON* persistent = cJSON_GetObjectItemCaseSensitive(presence_extra, "enable_persistent_learning");
        cJSON* sync = cJSON_GetObjectItemCaseSensitive(presence_extra, "storage_sync_interval_ms");
        cJSON* whitelist = cJSON_GetObjectItemCaseSensitive(presence_extra, "whitelisted_devices");
        if (cJSON_IsBool(persistent)) network_presence_.enable_persistent_learning = cJSON_IsTrue(persistent);
        if (cJSON_IsNumber(sync)) network_presence_.storage_sync_interval_ms = static_cast<uint32_t>(sync->valuedouble);
        if (cJSON_IsArray(whitelist)) {
            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, whitelist) {
                if (cJSON_IsString(item)) network_presence_.whitelisted_devices.emplace_back(PSRAMUtils::createPSRAMString(item->valuestring));
            }
        }
    }
    const auto flags = PassiveDetection::loadFlags([root](const char* path, bool& out) {
        cJSON* value = get_path_object(root, path);
        if (!cJSON_IsBool(value)) return false;
        out = cJSON_IsTrue(value);
        return true;
    });
    ids_.enabled = flags.ids_enabled;
    signatures_.enabled = flags.signatures_enabled;
    network_presence_.enabled = flags.network_presence_enabled;
    passive_flags_.store(flags.bits(), std::memory_order_release);

    // watchdog
    cJSON* watchdog = cJSON_GetObjectItem(root,"watchdog");
    if (watchdog) {
        cJSON* enabled = cJSON_GetObjectItem(watchdog,"enabled");
        cJSON* timeout_sec = cJSON_GetObjectItem(watchdog,"timeout_seconds");
        cJSON* panic = cJSON_GetObjectItem(watchdog,"panic_on_timeout");
        cJSON* idle = cJSON_GetObjectItem(watchdog,"monitor_idle_cores");

        if (cJSON_IsBool(enabled)) watchdog_.enabled = cJSON_IsTrue(enabled);
        if (cJSON_IsNumber(timeout_sec)) watchdog_.timeout_seconds = (uint32_t)timeout_sec->valuedouble;
        if (cJSON_IsBool(panic)) watchdog_.panic_on_timeout = cJSON_IsTrue(panic);
        if (cJSON_IsBool(idle)) watchdog_.monitor_idle_cores = cJSON_IsTrue(idle);
    }

    // GPIO Reporter configuration (from reporting.gpio section)
    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    if (reporting && cJSON_IsObject(reporting)) {
        cJSON* gpio_rep = cJSON_GetObjectItem(reporting, "gpio");
        if (gpio_rep && cJSON_IsObject(gpio_rep)) {
            // Main GPIO settings
            cJSON* gpio_enabled = cJSON_GetObjectItem(gpio_rep, "enabled");
            cJSON* gpio_format = cJSON_GetObjectItem(gpio_rep, "format");
            cJSON* gpio_verbosity = cJSON_GetObjectItem(gpio_rep, "verbosity");

            if (cJSON_IsBool(gpio_enabled)) gpio_.enabled = cJSON_IsTrue(gpio_enabled);
            if (cJSON_IsString(gpio_format)) gpio_.format = PSRAMUtils::createPSRAMString(gpio_format->valuestring);
            if (cJSON_IsString(gpio_verbosity)) gpio_.verbosity = PSRAMUtils::createPSRAMString(gpio_verbosity->valuestring);

            // GPIO Pin Configuration
            cJSON* config = cJSON_GetObjectItem(gpio_rep, "configuration");
            if (config && cJSON_IsObject(config)) {
                cJSON* pins = cJSON_GetObjectItem(config, "pins");
                if (pins && cJSON_IsObject(pins)) {
                    cJSON* led_critical = cJSON_GetObjectItem(pins, "led_critical");
                    cJSON* led_warning = cJSON_GetObjectItem(pins, "led_warning");
                    cJSON* led_info = cJSON_GetObjectItem(pins, "led_info");
                    cJSON* led_success = cJSON_GetObjectItem(pins, "led_success");
                    cJSON* buzzer = cJSON_GetObjectItem(pins, "buzzer");
                    cJSON* btn_acknowledge = cJSON_GetObjectItem(pins, "btn_acknowledge");
                    cJSON* btn_reset = cJSON_GetObjectItem(pins, "btn_reset");
                    cJSON* btn_learning = cJSON_GetObjectItem(pins, "btn_learning");
                    cJSON* btn_maintenance = cJSON_GetObjectItem(pins, "btn_maintenance");

                    if (cJSON_IsNumber(led_critical)) gpio_.pins.led_critical = (uint8_t)led_critical->valuedouble;
                    if (cJSON_IsNumber(led_warning)) gpio_.pins.led_warning = (uint8_t)led_warning->valuedouble;
                    if (cJSON_IsNumber(led_info)) gpio_.pins.led_info = (uint8_t)led_info->valuedouble;
                    if (cJSON_IsNumber(led_success)) gpio_.pins.led_success = (uint8_t)led_success->valuedouble;
                    if (cJSON_IsNumber(buzzer)) gpio_.pins.buzzer = (uint8_t)buzzer->valuedouble;
                    if (cJSON_IsNumber(btn_acknowledge)) gpio_.pins.btn_acknowledge = (uint8_t)btn_acknowledge->valuedouble;
                    if (cJSON_IsNumber(btn_reset)) gpio_.pins.btn_reset = (uint8_t)btn_reset->valuedouble;
                    if (cJSON_IsNumber(btn_learning)) gpio_.pins.btn_learning = (uint8_t)btn_learning->valuedouble;
                    if (cJSON_IsNumber(btn_maintenance)) gpio_.pins.btn_maintenance = (uint8_t)btn_maintenance->valuedouble;
                }

                // GPIO Behavior Configuration
                cJSON* behavior = cJSON_GetObjectItem(config, "behavior");
                if (behavior && cJSON_IsObject(behavior)) {
                    cJSON* buzzer_enabled = cJSON_GetObjectItem(behavior, "buzzer_enabled");
                    cJSON* alert_duration = cJSON_GetObjectItem(behavior, "alert_duration_ms");
                    cJSON* blink_interval = cJSON_GetObjectItem(behavior, "blink_interval_ms");
                    cJSON* debounce = cJSON_GetObjectItem(behavior, "debounce_ms");

                    if (cJSON_IsBool(buzzer_enabled)) gpio_.behavior.buzzer_enabled = cJSON_IsTrue(buzzer_enabled);
                    if (cJSON_IsNumber(alert_duration)) gpio_.behavior.alert_duration_ms = (uint32_t)alert_duration->valuedouble;
                    if (cJSON_IsNumber(blink_interval)) gpio_.behavior.blink_interval_ms = (uint32_t)blink_interval->valuedouble;
                    if (cJSON_IsNumber(debounce)) gpio_.behavior.debounce_ms = (uint32_t)debounce->valuedouble;
                }
            }

            // GPIO Filters Configuration
            cJSON* filters = cJSON_GetObjectItem(gpio_rep, "filters");
            if (filters && cJSON_IsObject(filters)) {
                cJSON* filters_enabled = cJSON_GetObjectItem(filters, "enabled");
                cJSON* case_sensitive = cJSON_GetObjectItem(filters, "case_sensitive");

                if (cJSON_IsBool(filters_enabled)) gpio_.filters.enabled = cJSON_IsTrue(filters_enabled);
                if (cJSON_IsBool(case_sensitive)) gpio_.filters.case_sensitive = cJSON_IsTrue(case_sensitive);

                // Include filters
                cJSON* include = cJSON_GetObjectItem(filters, "include");
                if (include && cJSON_IsArray(include)) {
                    gpio_.filters.include.clear();
                    int include_size = cJSON_GetArraySize(include);
                    for (int i = 0; i < include_size; i++) {
                        cJSON* item = cJSON_GetArrayItem(include, i);
                        if (cJSON_IsString(item)) {
                            gpio_.filters.include.push_back(PSRAMUtils::createPSRAMString(item->valuestring));
                        }
                    }
                }

                // Exclude filters
                cJSON* exclude = cJSON_GetObjectItem(filters, "exclude");
                if (exclude && cJSON_IsArray(exclude)) {
                    gpio_.filters.exclude.clear();
                    int exclude_size = cJSON_GetArraySize(exclude);
                    for (int i = 0; i < exclude_size; i++) {
                        cJSON* item = cJSON_GetArrayItem(exclude, i);
                        if (cJSON_IsString(item)) {
                            gpio_.filters.exclude.push_back(PSRAMUtils::createPSRAMString(item->valuestring));
                        }
                    }
                }
            }
        }
    }

    return true;
}

static cJSON* get_path_object(cJSON* root, const char* path) {
    if (!root || !path || !*path) return nullptr;
    const char* p = path;
    cJSON* cur = root;
    char key[64];
    while (*p) {
        size_t k = 0;
        while (*p && *p != '.' && k < sizeof(key)-1) key[k++] = *p++;
        key[k] = '\0';
        if (*p == '.') p++;
        cur = cJSON_GetObjectItem(cur, key);
        if (!cur) return nullptr;
    }
    return cur;
}

bool ConfigurationManager::getBoolAtPath(const char* path, bool* out) const {
    if (!path || !out) return false;
    size_t sz = 0; char* buf = getRawConfigInPSRAM(&sz);
    if (!buf || !sz) return false;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(buf, sz);
    heap_caps_free(buf);
    if (!root) return false;
    cJSON* obj = get_path_object(root, path);
    bool ok = obj && cJSON_IsBool(obj);
    if (ok) *out = cJSON_IsTrue(obj);
    cJSON_Delete(root);
    return ok;
}

bool ConfigurationManager::getStringAtPath(const char* path, char* out, size_t out_sz) const {
    if (!path || !out || !out_sz) return false;
    size_t sz = 0; char* buf = getRawConfigInPSRAM(&sz);
    if (!buf || !sz) return false;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(buf, sz);
    heap_caps_free(buf);
    if (!root) return false;
    cJSON* obj = get_path_object(root, path);
    bool ok = obj && cJSON_IsString(obj);
    if (ok) { strncpy(out, obj->valuestring ? obj->valuestring : "", out_sz-1); out[out_sz-1] = '\0'; }
    cJSON_Delete(root);
    return ok;
}

DebugConfig ConfigurationManager::getDebugConfig() const { return debug_; }
SecurityConfig ConfigurationManager::getSecurityConfig() const { return sec_; }
NetworkConfig ConfigurationManager::getNetworkConfig() const { return net_; }
IDSConfig ConfigurationManager::getIDSConfig() const { auto lock = lockConfig(); return ids_; }
SignatureConfig ConfigurationManager::getSignatureConfig() const { return {getPassiveDetectionFlags().signatures_enabled}; }
IDSAnomalyConfig ConfigurationManager::getIDSAnomalyConfig() const { return ids_anomaly_; }
WritersConfig ConfigurationManager::getWritersConfig() const { return writers_; }
NetworkPresenceConfig ConfigurationManager::getNetworkPresenceConfig() const { auto lock = lockConfig(); return network_presence_; }
WatchdogConfig ConfigurationManager::getWatchdogConfig() const { return watchdog_; }
GpioReportingConfig ConfigurationManager::getGpioReportingConfig() const { return gpio_; }

AuditManagerConfig ConfigurationManager::getAuditManagerConfig() const {
    AuditManagerConfig config;
    if (!root_) return config;

    cJSON* audit = cJSON_GetObjectItem(root_, "audit");
    if (!audit) return config;

    // Parse enabled flag
    cJSON* enabled = cJSON_GetObjectItem(audit, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        config.enabled = cJSON_IsTrue(enabled);
    }

    // Parse logging configuration
    cJSON* logging = cJSON_GetObjectItem(audit, "logging");
    if (logging && cJSON_IsObject(logging)) {
        cJSON* item;
        if ((item = cJSON_GetObjectItem(logging, "log_denied")) && cJSON_IsBool(item)) {
            config.logging.log_denied = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "log_timeouts")) && cJSON_IsBool(item)) {
            config.logging.log_timeouts = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "log_ratelimits")) && cJSON_IsBool(item)) {
            config.logging.log_ratelimits = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "log_system_events")) && cJSON_IsBool(item)) {
            config.logging.log_system_events = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "log_security_events")) && cJSON_IsBool(item)) {
            config.logging.log_security_events = cJSON_IsTrue(item);
        }
        if ((item = cJSON_GetObjectItem(logging, "log_config_changes")) && cJSON_IsBool(item)) {
            config.logging.log_config_changes = cJSON_IsTrue(item);
        }
    }

    // Parse rate limiting configuration
    cJSON* rate_limiting = cJSON_GetObjectItem(audit, "rate_limiting");
    if (rate_limiting && cJSON_IsObject(rate_limiting)) {
        cJSON* max_events = cJSON_GetObjectItem(rate_limiting, "max_events_per_second");
        if (max_events && cJSON_IsNumber(max_events)) {
            config.rate_limiting.max_events_per_second = static_cast<uint32_t>(cJSON_GetNumberValue(max_events));
        }
    }

    return config;
}

psram_string_map ConfigurationManager::getProtocolConfig(ProtocolType p) const {
    psram_string_map out;
    if (!root_) return out;
    cJSON* plugins = cJSON_GetObjectItem(root_,"plugins");
    if (!plugins) return out;
    const char* key = nullptr;
    switch(p) {
        case ProtocolType::OPC_UA: key = "opcua"; break;
        case ProtocolType::MODBUS_TCP: key = "modbus"; break;
        case ProtocolType::S7_COMM: key = "s7"; break;
        case ProtocolType::PROFINET: key = "profinet"; break;
        case ProtocolType::ETHERNET_IP: key = "ethernetip"; break;
        default: key = "custom"; break;
    }
    cJSON* obj = cJSON_GetObjectItem(plugins, key);
    if (obj && cJSON_IsObject(obj)) {
        cJSON* it = nullptr;
        cJSON_ArrayForEach(it, obj) {
            if (cJSON_IsString(it) || cJSON_IsNumber(it) || cJSON_IsBool(it)) {
                psram_string key = PSRAMUtils::createPSRAMString(it->string ? it->string : "");
                if (cJSON_IsString(it)) {
                    psram_string value = PSRAMUtils::createPSRAMString(it->valuestring ? it->valuestring : "");
                    out[key] = value;
                } else if (cJSON_IsNumber(it)) {
                    std::string temp = std::to_string(it->valuedouble);
                    psram_string value = PSRAMUtils::toPSRAMString(temp);
                    out[key] = value;
                } else {
                    psram_string value = PSRAMUtils::createPSRAMString(cJSON_IsTrue(it) ? "true" : "false");
                    out[key] = value;
                }
            }
        }
    }

    // Add IDS protocol-specific settings from new consolidated structure
    if (p == ProtocolType::PROFINET || p == ProtocolType::MODBUS_TCP) {
        cJSON* ids_root = cJSON_GetObjectItem(root_, "ids");
        if (ids_root) {
            cJSON* protocol_specific = cJSON_GetObjectItem(ids_root, "protocol_specific");
            if (protocol_specific) {
                const char* key = (p==ProtocolType::PROFINET)?"profinet":"modbus";
                cJSON* ids_obj = cJSON_GetObjectItem(protocol_specific, key);
                if (ids_obj && cJSON_IsObject(ids_obj)) {
                    cJSON* it = nullptr;
                    cJSON_ArrayForEach(it, ids_obj) {
                        if (cJSON_IsString(it) || cJSON_IsNumber(it) || cJSON_IsBool(it)) {
                            psram_string profinet_key = PSRAMUtils::createPSRAMString(it->string ? it->string : "");
                            if (cJSON_IsString(it)) {
                                psram_string profinet_value = PSRAMUtils::createPSRAMString(it->valuestring ? it->valuestring : "");
                                out[profinet_key] = profinet_value;
                            } else if (cJSON_IsNumber(it)) {
                                std::string temp = std::to_string(it->valuedouble);
                                psram_string profinet_value = PSRAMUtils::toPSRAMString(temp);
                                out[profinet_key] = profinet_value;
                            } else {
                                psram_string profinet_value = PSRAMUtils::createPSRAMString(cJSON_IsTrue(it) ? "true" : "false");
                                out[profinet_key] = profinet_value;
                            }
                        }
                    }
                }
            }
        }
    }

    return out;
}


// Simple CRC32 (poly 0xEDB88320)
uint32_t ConfigurationManager::crc32(const uint8_t* data, size_t len) const {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i=0;i<len;++i) {
        crc ^= data[i];
        for (int j=0;j<8;++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

bool ConfigurationManager::saveConfigSourceToNVS(ConfigSource source) {
    esp_err_t err = AsyncStorage::Global::nvsSet(kNVS_NAMESPACE, "config_source",
                                                static_cast<uint32_t>(source));
    if (err == ESP_OK) {
        config_source_ = source;
        //LOG_INFOF("Config", "Configuration source set to: %d", (int)source);
        return true;
    }
    LOG_ERRORF("Config", "Failed to save config_source to NVS: %s", esp_err_to_name(err));
    return false;
}

ConfigurationManager::ConfigSource ConfigurationManager::loadConfigSourceFromNVS() {
    uint8_t source_val = (uint8_t)ConfigSource::DEFAULT;
    if (AsyncStorage::Global::nvsGet(kNVS_NAMESPACE, "config_source", source_val) == ESP_OK) {
        config_source_ = (ConfigSource)source_val;
        LOG_INFOF("Config", "Loaded configuration source from NVS: %d", (int)config_source_);
    } else {
        LOG_INFO("Config", "No configuration source in NVS, using DEFAULT");
        config_source_ = ConfigSource::DEFAULT;
    }
    return config_source_;
}

void ConfigurationManager::mergeDefaultProtocolFields() {
    if (!root_) return;

    // Get or create plugins object
    cJSON* plugins = cJSON_GetObjectItem(root_, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(root_, "plugins", plugins);
    }

    // Default protocol configurations
    struct ProtocolField {
        const char* key;
        const char* value;
        bool is_bool;
    };

    static const ProtocolField modbus_fields[] = {
        {"enabled", "true", true},
        {"default_unit_id", "1", false},
        {"connect_timeout_ms", "1500", false},
        {"io_timeout_ms", "1500", false},
        {"allowed_writers", "", false},
        {"discovery_connect_timeout_ms", "3000", false},
        {"discovery_io_timeout_ms", "3000", false},
        {"discovery_request_retries", "3", false},
        {"discovery_connect_retries", "2", false},
        {"discovery_prescan_enabled", "true", true},
        {"discovery_prescan_timeout_ms", "400", false},
        {"discovery_probe_coils_max", "16", false},
        {"discovery_unit_ids", "1,2,3,4,5,6,7,8,9,10,16,17,32,64,255", false}
    };

    static const ProtocolField s7_fields[] = {
        {"enabled", "true", true},
        {"default_port", "102", false},
        {"connect_timeout", "2000", false},
        {"pdu_size", "240", false},
        {"discovery_lightweight", "true", true},
        {"discovery_host_delay_ms", "150", false},
        {"discovery_pause_every_hosts", "12", false},
        {"discovery_pause_ms", "600", false}
    };

    static const ProtocolField opcua_fields[] = {
        {"enabled", "true", true},
        {"port", "4840", false},
        {"timeout", "5000", false}
    };

    static const ProtocolField profinet_fields[] = {
        {"enabled", "false", true},
        {"dcp_timeout", "1000", false},
        {"vlan_priority", "7", false}
    };

    static const ProtocolField ethernetip_fields[] = {
        {"enabled", "false", true},
        {"tcp_port", "44818", false},
        {"udp_port", "2222", false},
        {"timeout", "3000", false}
    };

    struct ProtocolDefaults {
        const char* name;
        const ProtocolField* fields;
        size_t field_count;
    };

    const ProtocolDefaults defaults[] = {
        {"modbus", modbus_fields, sizeof(modbus_fields) / sizeof(modbus_fields[0])},
        {"s7", s7_fields, sizeof(s7_fields) / sizeof(s7_fields[0])},
        {"opcua", opcua_fields, sizeof(opcua_fields) / sizeof(opcua_fields[0])},
        {"profinet", profinet_fields, sizeof(profinet_fields) / sizeof(profinet_fields[0])},
        {"ethernetip", ethernetip_fields, sizeof(ethernetip_fields) / sizeof(ethernetip_fields[0])}
    };

    bool changed = false;
    for (const auto& def : defaults) {
        cJSON* protocol = cJSON_GetObjectItem(plugins, def.name);
        if (!protocol) {
            protocol = cJSON_CreateObject();
            cJSON_AddItemToObject(plugins, def.name, protocol);
            changed = true;
        }

        for (size_t i = 0; i < def.field_count; ++i) {
            const ProtocolField& field = def.fields[i];
            if (!cJSON_GetObjectItem(protocol, field.key)) {
                if (field.is_bool) {
                    cJSON_AddBoolToObject(protocol, field.key, strcmp(field.value, "true") == 0);
                } else {
                    cJSON_AddStringToObject(protocol, field.key, field.value);
                }
                changed = true;
            }
        }
    }

    // Ensure reporting_endpoints/file exists (default for fuzzing events)
    if (changed) {
        char* updated_json = cJSON_Print(root_);
        if (updated_json) {
            raw_ = PSRAMUtils::createPSRAMString(updated_json);
            saveConfigJSON(raw_);
            free(updated_json);
            //LOG_INFO("Config", "Updated configuration with missing protocol fields and reporting endpoints");
        }
    }
}


static inline size_t config_json_len_bytes(void) {
    return sizeof(esp32_ot_build::kEmbeddedPublicConfigJson) - 1;
}

// as C-string (null-terminated)
static inline const char* config_json_cstr(void) {
    return esp32_ot_build::kEmbeddedPublicConfigJson;
}

bool ConfigurationManager::loadDevConfigFromSource() {
    LOG_INFO("Config", "🔧 Loading embedded development configuration");

    // Check if embedded config is available
    size_t config_len = config_json_len_bytes();
    if (config_len == 0) {
        LOG_WARNING("Config", "No embedded configuration found");
        return false;
    }

    // Get embedded config content
    std::string embedded_json(config_json_cstr(), config_len);
    //LOG_INFOF("Config", "Found embedded config: %u bytes", (unsigned)embedded_json.length());

    // Validate JSON format
    PSRAMJsonParser::PSRAMContext test_ctx;
    cJSON* test_parse = PSRAMJsonParser::parseInPSRAM(embedded_json.c_str(), embedded_json.size());
    if (!test_parse) {
        LOG_ERROR("Config", "❌ Embedded configuration contains invalid JSON");
        return false;
    }
    cJSON_Delete(test_parse);

    // Load directly into memory (don't save to filesystem yet)
    if (root_) cJSON_Delete(root_);
    {
        PSRAMJsonParser::PSRAMContext ctx;
        root_ = PSRAMJsonParser::parseInPSRAM(embedded_json.c_str(), embedded_json.size());
    }
    if (!root_) {
        LOG_ERROR("Config", "❌ Failed to parse embedded configuration");
        return false;
    }

    // Update raw cache
    raw_ = PSRAMUtils::createPSRAMString(embedded_json.c_str());

    // Parse and cache the configuration values
    if (!parseAndCache(root_)) {
        LOG_ERROR("Config", "❌ Failed to parse embedded configuration");
        return false;
    }

    LOG_INFO("Config", "✅ Embedded development configuration loaded and parsed successfully");
    return true;
}

char* ConfigurationManager::getEmbeddedConfigInPSRAM(size_t* size_out) const {
    if (!size_out) return nullptr;
    const size_t config_len = config_json_len_bytes();
    *size_out = config_len;
    if (config_len == 0) return nullptr;

    char* buffer = static_cast<char*>(heap_caps_malloc(
        config_len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!buffer && config_len < 4096) {
        buffer = static_cast<char*>(heap_caps_malloc(
            config_len + 1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (!buffer) {
        *size_out = 0;
        return nullptr;
    }
    memcpy(buffer, config_json_cstr(), config_len);
    buffer[config_len] = '\0';
    return buffer;
}

std::string ConfigurationManager::getConfigSourceName() const {
    switch (config_source_) {
        case ConfigSource::DEFAULT: return "Default";
        case ConfigSource::EMBEDDED: return "Embedded";
        case ConfigSource::FILESYSTEM: return "Filesystem";
        case ConfigSource::WEB_INTERFACE: return "Web Interface";
        default: return "Unknown";
    }
}

bool ConfigurationManager::resetToEmbeddedConfig() {
    LOG_INFO("Config", "🔄 Resetting to embedded configuration");

    // Load embedded config
    if (!loadDevConfigFromSource()) {
        LOG_ERROR("Config", "❌ Failed to load embedded configuration for reset");
        return false;
    }

    // Save to filesystem to persist the reset
    if (!saveConfigJSON(raw_)) {
        LOG_ERROR("Config", "❌ Failed to save embedded configuration to filesystem");
        return false;
    }

    // Update source tracking to reflect the reset
    saveConfigSourceToNVS(ConfigSource::EMBEDDED);

    //LOG_INFO("Config", "✅ Successfully reset to embedded configuration");
    return true;
}
