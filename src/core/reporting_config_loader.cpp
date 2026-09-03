#include "reporting_config_loader.h"
#include "psram_json_parser.h"
#include "psram_allocator.h"
#include "logging_system.h"
#include "../reporters/file_reporter.h"
#include "../reporters/mqtt_reporter.h"
#include "../reporters/email_reporter.h"
#include "../reporters/webhook_reporter.h"

#include <string>
#include <vector>

extern "C" {
    #include "esp_heap_caps.h"
    #include "esp_timer.h"
    #include "esp_log.h"
    #include "cJSON.h"
}

namespace ReportingConfig {
namespace {
    LogFileManager log_file_manager_instance;
    FileReporter file_reporter_instance;
    WebhookReporter webhook_reporter_instance;
    bool log_file_manager_ready = false;
    bool email_reporter_registered = false;
}

LogFileManager* getLogFileManager() { return log_file_manager_ready ? &log_file_manager_instance : nullptr; }
bool isEmailRegistered() { return email_reporter_registered; }

void loadFromConfig(ConfigurationManager* cfg, ReportingEngine* rep) {
    if (!cfg || !rep) {
        LOG_ERROR("REPORTING", "Invalid parameters for ReportingConfig::loadFromConfig");
        return;
    }

    // Get raw JSON configuration using PSRAM-safe approach
    if (PSRAMUtils::isCriticalMemory()) {
        LOG_WARNING("REPORTING", "Reporting config load skipped due to critical memory");
        return;
    }

    size_t json_size = 0;
    char* json_buf = cfg->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) {
        LOG_WARNING("REPORTING", "Empty configuration, using defaults");
        return;
    }

    // Parse JSON configuration
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) {
        LOG_ERROR("REPORTING", "Failed to parse configuration JSON");
        return;
    }

    // Extract reporting section
    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    if (!reporting) {
        LOG_INFO("REPORTING", "No reporting section found in config, using defaults");
        cJSON_Delete(root);
        return;
    }

    LOG_INFO("REPORTING", "Loading reporting configuration from config.json");

    // Validate backward compatibility with existing config.json format
    const char* expected_channels[] = {"serial", "file", "mqtt", "webhook", "email"};
    int channels_found = 0;
    for (const char* channel : expected_channels) {
        if (cJSON_GetObjectItem(reporting, channel)) {
            channels_found++;
        }
    }
    LOG_INFOF("REPORTING", "Found %d/%d reporting channels in configuration", channels_found, 5);

    // Load Serial Reporter (always available)
    cJSON* serial = cJSON_GetObjectItem(reporting, "serial");
    if (serial && cJSON_IsObject(serial)) {
        bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(serial, "enabled"));
        if (enabled) {
            LOG_INFO("REPORTING", "Configuring Serial reporter");

            // Configure serial channel
            ReportingEngine::ChannelConfig serial_cfg;
            serial_cfg.enabled = true;

            // Parse format
            cJSON* format = cJSON_GetObjectItem(serial, "format");
            if (format && cJSON_IsString(format)) {
                std::string fmt_str = format->valuestring;
                if (fmt_str == "JSON") serial_cfg.format = EventFormat::JSON;
                else if (fmt_str == "CEE") serial_cfg.format = EventFormat::CEE;
                else if (fmt_str == "LEEF") serial_cfg.format = EventFormat::LEEF;
                else if (fmt_str == "CEF") serial_cfg.format = EventFormat::CEF;
                else serial_cfg.format = EventFormat::JSON; // default
            }

            // Parse verbosity
            cJSON* verbosity = cJSON_GetObjectItem(serial, "verbosity");
            if (verbosity && cJSON_IsString(verbosity)) {
                std::string verb_str = verbosity->valuestring;
                if (verb_str == "VERBOSE") serial_cfg.verbosity = VerbosityLevel::VERBOSE;
                else serial_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;
            }

            // Parse filters
            ReportingEngine::populateChannelFiltersFromJSON(serial, serial_cfg);

            // Create serial sender function (direct to ESP_LOG)
            auto serial_sender_raw = [](const char* data, size_t len) -> bool {
                if (!data || len==0) return true;
                fwrite(data, 1, len, stdout);
                fputc('\n', stdout);
                fflush(stdout);
                return true;
            };
            rep->setChannelRaw(PSRAMUtils::createPSRAMString("serial"), serial_cfg, serial_sender_raw);
            LOG_INFO("REPORTING", "Serial reporter configured successfully");
        }
    }

    // Load File Reporter with Multi-File Support
    cJSON* file = cJSON_GetObjectItem(reporting, "file");
    if (file && cJSON_IsObject(file)) {
        bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(file, "enabled"));
        if (enabled) {
            LOG_INFO("REPORTING", "Configuring Multi-File reporter with LogFileManager");

            // Initialize LogFileManager and FileReporter (static for global access)
            auto& log_file_manager = log_file_manager_instance;
            auto& file_reporter = file_reporter_instance;

            // Initialize LogFileManager from configuration
            bool log_mgr_init = log_file_manager.loadFromConfiguration(root);
            if (!log_mgr_init) {
                LOG_WARNING("REPORTING", "LogFileManager config failed, using defaults");
                log_file_manager.loadDefaultConfiguration();
            } else {
            }

            // Initialize FileReporter with LogFileManager
            if (!log_file_manager.initialize(&file_reporter)) {
                LOG_ERROR("REPORTING", "Failed to initialize LogFileManager with FileReporter");
            } else {
                // Set global reference for WebServer API access
                log_file_manager_ready = true;
            }

            // Configure file channel
            ReportingEngine::ChannelConfig file_cfg;
            file_cfg.enabled = true;

            // Parse format
            cJSON* format = cJSON_GetObjectItem(file, "format");
            if (format && cJSON_IsString(format)) {
                std::string fmt_str = format->valuestring;
                if (fmt_str == "JSON") file_cfg.format = EventFormat::JSON;
                else if (fmt_str == "CEE") file_cfg.format = EventFormat::CEE;
                else if (fmt_str == "LEEF") file_cfg.format = EventFormat::LEEF;
                else if (fmt_str == "CEF") file_cfg.format = EventFormat::CEF;
                else file_cfg.format = EventFormat::JSON; // default
            } else {
                file_cfg.format = EventFormat::JSON;
            }

            // Parse verbosity
            cJSON* verbosity = cJSON_GetObjectItem(file, "verbosity");
            if (verbosity && cJSON_IsString(verbosity)) {
                std::string verb_str = verbosity->valuestring;
                if (verb_str == "VERBOSE") file_cfg.verbosity = VerbosityLevel::VERBOSE;
                else file_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;
            } else {
                file_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;
            }

            // Parse filters
            ReportingEngine::populateChannelFiltersFromJSON(file, file_cfg);

            // Create multi-file sender function using FileReporter
            // THREAD-SAFE: FileReporter uses AsyncStorage internally for PSRAM safety
            // Use pointer to avoid capturing static variable by reference
            FileReporter* file_reporter_ptr = &file_reporter;
            auto file_sender_raw = [file_reporter_ptr](const char* data, size_t len) -> bool {
                if (!data || len == 0) {
                    return true;
                }
                psram_string payload(data, data + len);
                if (payload.empty() && len > 0) {
                    return false;
                }
                return file_reporter_ptr->append(payload);
            };


            rep->setChannelRaw(PSRAMUtils::createPSRAMString("file"), file_cfg, file_sender_raw);
        }
    }

    // ===== AUDIT CHANNEL CONFIGURATION =====
    // Configure audit channel to output to both file and MQTT reporters (if enabled)
    // This channel receives security events, config changes, and sandbox audit events
    LOG_INFO("REPORTING", "Configuring audit channel for structured audit logging");

    ReportingEngine::ChannelConfig audit_cfg;
    audit_cfg.enabled = true;
    audit_cfg.format = EventFormat::JSON;
    audit_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;

    // Create audit sender - simplified approach for initial implementation
    // The audit events will be processed through the existing ReportingEngine infrastructure
    auto audit_sender = [](const psram_string& payload) -> bool {
        // For now, just log that audit event was received and processed
        // The actual routing to file/MQTT will be handled by ReportingEngine's submit() method
        // when SandboxAuditor calls rep_->submit(ev)
        if (!payload.empty()) {
            //LOG_INFO("AUDIT", "Audit event processed (via ReportingEngine infrastructure)");
            return true;
        }
        return false;
    };

    rep->setChannel(PSRAMUtils::createPSRAMString("audit"), audit_cfg, audit_sender);
    LOG_INFO("REPORTING", " Audit channel configured: routing to file + MQTT");

    cJSON_Delete(root);
    LOG_INFO("REPORTING", "Reporting configuration loaded successfully");
}

void registerNetworkEndpoints(ConfigurationManager* cfg, ReportingEngine* rep) {
    if (!cfg || !rep) {
        LOG_ERROR("REPORTING", "Invalid parameters for ReportingConfig::registerNetworkEndpoints");
        return;
    }

    // Get raw JSON configuration using PSRAM-safe approach
    if (PSRAMUtils::isCriticalMemory()) {
        LOG_WARNING("REPORTING", "Endpoint registration skipped due to critical memory");
        return;
    }

    size_t json_size2 = 0;
    char* json_buf2 = cfg->getRawConfigInPSRAM(&json_size2);
    if (!json_buf2 || json_size2 == 0) {
        LOG_WARNING("REPORTING", "Empty configuration, skipping endpoint registration");
        return;
    }

    // Parse JSON configuration
    PSRAMJsonParser::PSRAMContext ctx2;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf2, json_size2);
    heap_caps_free(json_buf2);
    if (!root) {
        LOG_ERROR("REPORTING", "Failed to parse configuration JSON for endpoints");
        return;
    }

    // Extract reporting section
    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    if (!reporting) {
        LOG_INFO("REPORTING", "No reporting section found for endpoint registration");
        cJSON_Delete(root);
        return;
    }

    LOG_INFO("REPORTING", "Registering network-dependent reporting endpoints");

    // Register MQTT Reporter (network-dependent)
    cJSON* mqtt = cJSON_GetObjectItem(reporting, "mqtt");
    if (mqtt && cJSON_IsObject(mqtt)) {
        bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(mqtt, "enabled"));
        if (enabled) {
            LOG_INFO("REPORTING", "Configuring MQTT reporter");

            // Configure MQTT channel
            ReportingEngine::ChannelConfig mqtt_cfg;
            mqtt_cfg.enabled = true;

            // Parse format
            cJSON* format = cJSON_GetObjectItem(mqtt, "format");
            if (format && cJSON_IsString(format)) {
                std::string fmt_str = format->valuestring;
                if (fmt_str == "JSON") mqtt_cfg.format = EventFormat::JSON;
                else if (fmt_str == "CEE") mqtt_cfg.format = EventFormat::CEE;
                else if (fmt_str == "LEEF") mqtt_cfg.format = EventFormat::LEEF;
                else if (fmt_str == "CEF") mqtt_cfg.format = EventFormat::CEF;
                else mqtt_cfg.format = EventFormat::JSON; // default
            }

            // Parse verbosity
            cJSON* verbosity = cJSON_GetObjectItem(mqtt, "verbosity");
            if (verbosity && cJSON_IsString(verbosity)) {
                std::string verb_str = verbosity->valuestring;
                if (verb_str == "VERBOSE") mqtt_cfg.verbosity = VerbosityLevel::VERBOSE;
                else mqtt_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;
            }

            // Parse filters
            ReportingEngine::populateChannelFiltersFromJSON(mqtt, mqtt_cfg);

            // Parse MQTT configuration - PSRAM-safe using char* instead of std::string
            const char* mqtt_broker = nullptr;
            const char* mqtt_topic_prefix = nullptr;
            const char* mqtt_client_id = nullptr;
            const char* mqtt_username = nullptr;
            const char* mqtt_password = nullptr;
            int mqtt_port = 1883, mqtt_qos = 1;
            bool mqtt_retain = false;

            cJSON* config_obj = cJSON_GetObjectItem(mqtt, "configuration");
            if (config_obj && cJSON_IsObject(config_obj)) {
                cJSON* broker = cJSON_GetObjectItem(config_obj, "broker");
                if (broker && cJSON_IsString(broker)) mqtt_broker = broker->valuestring;

                cJSON* port = cJSON_GetObjectItem(config_obj, "port");
                if (port && cJSON_IsNumber(port)) mqtt_port = port->valueint;

                cJSON* topic_prefix = cJSON_GetObjectItem(config_obj, "topic_prefix");
                if (topic_prefix && cJSON_IsString(topic_prefix)) mqtt_topic_prefix = topic_prefix->valuestring;

                cJSON* client_id = cJSON_GetObjectItem(config_obj, "client_id");
                if (client_id && cJSON_IsString(client_id)) mqtt_client_id = client_id->valuestring;

                cJSON* username = cJSON_GetObjectItem(config_obj, "username");
                if (username && cJSON_IsString(username)) mqtt_username = username->valuestring;

                cJSON* password = cJSON_GetObjectItem(config_obj, "password");
                if (password && cJSON_IsString(password)) mqtt_password = password->valuestring;

                cJSON* qos = cJSON_GetObjectItem(config_obj, "qos");
                if (qos && cJSON_IsNumber(qos)) mqtt_qos = qos->valueint;

                cJSON* retain = cJSON_GetObjectItem(config_obj, "retain");
                if (retain && cJSON_IsBool(retain)) mqtt_retain = cJSON_IsTrue(retain);

                // Note: keep_alive and clean_session removed - not used in current MQTT implementation
            }

            // Create MQTT Reporter with PSRAM-safe implementation
            // Note: Not static to avoid allocation when disabled
            MQTTReporter* mqtt_reporter = new MQTTReporter();
            if (!mqtt_reporter) {
                LOG_ERROR("REPORTING", " Failed to allocate MQTT reporter - insufficient memory");
                return; // Skip MQTT configuration if allocation fails
            }

            // Build MQTT URI from components - PSRAM-safe
            // Calculate needed buffer size for URI
            size_t uri_size = strlen("mqtt://") + (mqtt_broker ? strlen(mqtt_broker) : 0) + 10; // port + null
            if (mqtt_username && mqtt_password) {
                uri_size += strlen(mqtt_username) + strlen(mqtt_password) + 3; // user:pass@
            }

            char* mqtt_uri = (char*)heap_caps_malloc(uri_size + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!mqtt_uri) {
                LOG_ERROR("REPORTING", " Failed to allocate MQTT URI buffer in PSRAM");
                delete mqtt_reporter;
                return;
            }

            strcpy(mqtt_uri, "mqtt://");
            if (mqtt_username && mqtt_password && strlen(mqtt_username) > 0 && strlen(mqtt_password) > 0) {
                strcat(mqtt_uri, mqtt_username);
                strcat(mqtt_uri, ":");
                strcat(mqtt_uri, mqtt_password);
                strcat(mqtt_uri, "@");
            }
            if (mqtt_broker) strcat(mqtt_uri, mqtt_broker);
            if (mqtt_port != 1883) {
                char port_str[8];
                snprintf(port_str, sizeof(port_str), ":%d", mqtt_port);
                strcat(mqtt_uri, port_str);
            }

            // Build topic string - PSRAM-safe
            size_t topic_size = (mqtt_topic_prefix ? strlen(mqtt_topic_prefix) : 0) + strlen("/events") + 1;
            char* mqtt_topic = (char*)heap_caps_malloc(topic_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!mqtt_topic) {
                LOG_ERROR("REPORTING", " Failed to allocate MQTT topic buffer in PSRAM");
                heap_caps_free(mqtt_uri);
                delete mqtt_reporter;
                return;
            }

            if (mqtt_topic_prefix && strlen(mqtt_topic_prefix) > 0) {
                strcpy(mqtt_topic, mqtt_topic_prefix);
                strcat(mqtt_topic, "/events");
            } else {
                strcpy(mqtt_topic, "events");
            }

            // Configure MQTT client
            MqttConfig mqtt_config;
            mqtt_config.uri = mqtt_uri;
            mqtt_config.client_id = mqtt_client_id ? mqtt_client_id : "esp32_device";
            mqtt_config.topic = mqtt_topic;
            mqtt_config.qos = mqtt_qos;
            mqtt_config.retain = mqtt_retain;

            // Start MQTT client
            if (mqtt_reporter->start(mqtt_config)) {
                // PSRAM-safe MQTT sender function
                // Copy the pointer to avoid static variable capture warning
                MQTTReporter* mqtt_reporter_ptr = mqtt_reporter;
                auto mqtt_sender = [mqtt_reporter_ptr](const psram_string& payload) -> bool {
                    // Memory safety check
                    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                    if (free_heap < 2048) {
                        LOG_WARNING("MQTT", "MQTT send skipped - low memory");
                        return false;
                    }

                    // PSRAM-safe payload handling - avoid long-lived std::string allocations
                    // For large payloads, truncate without creating intermediate std::string
                    if (payload.size() > 2048) {
                        LOG_WARNING("MQTT", "MQTT payload too large, truncating");

                        // Create PSRAM buffer for truncated payload
                        char* truncated_buf = (char*)heap_caps_malloc(2049, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                        if (!truncated_buf) {
                            LOG_ERROR("MQTT", " Failed to allocate truncation buffer");
                            return false;
                        }

                        memcpy(truncated_buf, payload.c_str(), 2048);
                        truncated_buf[2048] = '\0';

                        std::string temp_payload(truncated_buf);
                        heap_caps_free(truncated_buf);

                        return mqtt_reporter_ptr->publish(temp_payload);
                    }

                    // Use direct payload for normal size
                    return mqtt_reporter_ptr->publish(PSRAMUtils::fromPSRAMString(payload));
                };

                rep->setChannel(PSRAMUtils::createPSRAMString("mqtt"), mqtt_cfg, mqtt_sender);
                LOG_INFOF("REPORTING", " MQTT reporter started: %s:%d topic=%s",
                         mqtt_broker ? mqtt_broker : "unknown", mqtt_port,
                         mqtt_topic_prefix ? mqtt_topic_prefix : "events");

                // Cleanup PSRAM buffers after configuration
                heap_caps_free(mqtt_uri);
                heap_caps_free(mqtt_topic);
            } else {
                LOG_ERROR("REPORTING", " Failed to start MQTT reporter");
                // Cleanup PSRAM buffers on failure
                heap_caps_free(mqtt_uri);
                heap_caps_free(mqtt_topic);
                delete mqtt_reporter;
            }
        }
    }

    // Register Webhook Reporter (network-dependent)
    cJSON* webhook = cJSON_GetObjectItem(reporting, "webhook");
    if (webhook && cJSON_IsObject(webhook)) {
        bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(webhook, "enabled"));
        if (enabled) {
            LOG_INFO("REPORTING", "Configuring Webhook reporter");

            // Configure webhook channel
            ReportingEngine::ChannelConfig webhook_cfg;
            webhook_cfg.enabled = true;

            // Parse format
            cJSON* format = cJSON_GetObjectItem(webhook, "format");
            if (format && cJSON_IsString(format)) {
                std::string fmt_str = format->valuestring;
                if (fmt_str == "JSON") webhook_cfg.format = EventFormat::JSON;
                else if (fmt_str == "CEE") webhook_cfg.format = EventFormat::CEE;
                else if (fmt_str == "LEEF") webhook_cfg.format = EventFormat::LEEF;
                else if (fmt_str == "CEF") webhook_cfg.format = EventFormat::CEF;
                else webhook_cfg.format = EventFormat::JSON; // default
            }

            // Parse verbosity
            cJSON* verbosity = cJSON_GetObjectItem(webhook, "verbosity");
            if (verbosity && cJSON_IsString(verbosity)) {
                std::string verb_str = verbosity->valuestring;
                if (verb_str == "VERBOSE") webhook_cfg.verbosity = VerbosityLevel::VERBOSE;
                else webhook_cfg.verbosity = VerbosityLevel::REPORTS_ONLY;
            }

            // Parse filters
            ReportingEngine::populateChannelFiltersFromJSON(webhook, webhook_cfg);

            // Parse webhook configuration.  A real WebhookReporter already
            // exists in the project; using it here prevents every enabled
            // webhook event from becoming a permanent PSRAM retry.
            WebhookConfig webhook_config;
            webhook_config.content_type = "application/json";

            cJSON* config_obj = cJSON_GetObjectItem(webhook, "configuration");
            if (config_obj && cJSON_IsObject(config_obj)) {
                cJSON* url = cJSON_GetObjectItem(config_obj, "url");
                if (url && cJSON_IsString(url)) webhook_config.url = url->valuestring;

                cJSON* timeout = cJSON_GetObjectItem(config_obj, "timeout_ms");
                if (timeout && cJSON_IsNumber(timeout)) webhook_config.timeout_ms = timeout->valueint;

                cJSON* headers = cJSON_GetObjectItem(config_obj, "headers");
                if (headers && cJSON_IsObject(headers)) {
                    cJSON* item = nullptr;
                    cJSON_ArrayForEach(item, headers) {
                        if (item->string && cJSON_IsString(item) && item->valuestring) {
                            webhook_config.headers.emplace_back(item->string, item->valuestring);
                        }
                    }
                }
            }

            if (webhook_config.url.empty()) {
                // No endpoint means no channel registration, no delivery and
                // no queue retry.  This intentionally stays silent: an empty
                // optional endpoint is a normal configuration state.
            } else if (!webhook_reporter_instance.init(webhook_config)) {
                LOG_ERROR("REPORTING", "Webhook reporter initialization failed");
            } else {
                WebhookReporter* webhook_reporter_ptr = &webhook_reporter_instance;
                auto webhook_sender = [webhook_reporter_ptr](const char* data, size_t len) -> bool {
                    return webhook_reporter_ptr->post(data, len);
                };
                rep->setChannelRaw(PSRAMUtils::createPSRAMString("webhook"), webhook_cfg, webhook_sender);
                LOG_INFOF("REPORTING", "Webhook reporter configured: timeout=%dms", webhook_config.timeout_ms);
            }
        }
    }

    cJSON_Delete(root);
    LOG_INFO("REPORTING", "Network endpoint registration completed");
}

 // namespace ReportingConfig


bool registerEmailFromConfig(ConfigurationManager* cfg, ReportingEngine* rep) {
    if (!cfg || !rep) return false;
    if (email_reporter_registered) return true;

    size_t json_size = 0;
    char* json_buf = cfg->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return false;

    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return false;

    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    if (!reporting) {
        cJSON_Delete(root);
        return false;
    }

    cJSON* email = cJSON_GetObjectItem(reporting, "email");
    if (!(email && cJSON_IsObject(email))) {
        cJSON_Delete(root);
        return false;
    }

    bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(email, "enabled"));
    if (!enabled) {
        LOG_INFO("EMAIL", "Email reporter disabled in configuration. Skipping initialization.");
        cJSON_Delete(root);
        return false;
    }

    ReportingEngine::ChannelConfig email_cfg;
    email_cfg.enabled = true;

    cJSON* format = cJSON_GetObjectItem(email, "format");
    if (format && cJSON_IsString(format)) {
        std::string fmt_str = format->valuestring;
        if (fmt_str == "JSON") email_cfg.format = EventFormat::JSON;
        else if (fmt_str == "CEE") email_cfg.format = EventFormat::CEE;
        else if (fmt_str == "LEEF") email_cfg.format = EventFormat::LEEF;
        else if (fmt_str == "CEF") email_cfg.format = EventFormat::CEF;
    }

    cJSON* verbosity = cJSON_GetObjectItem(email, "verbosity");
    if (verbosity && cJSON_IsString(verbosity)) {
        std::string verb_str = verbosity->valuestring;
        email_cfg.verbosity = (verb_str == "VERBOSE") ? VerbosityLevel::VERBOSE : VerbosityLevel::REPORTS_ONLY;
    }

    ReportingEngine::populateChannelFiltersFromJSON(email, email_cfg);

    const char* smtp_server = nullptr; int smtp_port = 465; bool use_tls = true;
    const char* smtp_username = nullptr; const char* smtp_password = nullptr;
    const char* from_address = nullptr; const char* subject_prefix = nullptr;
    int timeout_ms = 10000;
    const char* to_addresses[10] = {0}; int to_count = 0;

    cJSON* config_obj = cJSON_GetObjectItem(email, "configuration");
    if (config_obj && cJSON_IsObject(config_obj)) {
        cJSON* server = cJSON_GetObjectItem(config_obj, "smtp_server");
        if (server && cJSON_IsString(server)) smtp_server = server->valuestring;

        cJSON* port = cJSON_GetObjectItem(config_obj, "smtp_port");
        if (port && cJSON_IsNumber(port)) smtp_port = port->valueint;

        cJSON* tls = cJSON_GetObjectItem(config_obj, "use_tls");
        if (tls && cJSON_IsBool(tls)) use_tls = cJSON_IsTrue(tls);

        cJSON* username = cJSON_GetObjectItem(config_obj, "username");
        if (username && cJSON_IsString(username)) smtp_username = username->valuestring;

        cJSON* password = cJSON_GetObjectItem(config_obj, "password");
        if (password && cJSON_IsString(password)) smtp_password = password->valuestring;

        cJSON* from_addr = cJSON_GetObjectItem(config_obj, "from_address");
        if (from_addr && cJSON_IsString(from_addr)) from_address = from_addr->valuestring;

        cJSON* subject = cJSON_GetObjectItem(config_obj, "subject_prefix");
        if (subject && cJSON_IsString(subject)) subject_prefix = subject->valuestring;

        cJSON* timeout = cJSON_GetObjectItem(config_obj, "timeout_ms");
        if (timeout && cJSON_IsNumber(timeout)) timeout_ms = timeout->valueint;
        cJSON* addresses = cJSON_GetObjectItem(config_obj, "to_addresses");
        if (addresses && cJSON_IsArray(addresses)) {
            cJSON* addr = nullptr;
            cJSON_ArrayForEach(addr, addresses) {
                if (cJSON_IsString(addr) && to_count < 10) to_addresses[to_count++] = addr->valuestring;
            }
        }
    }

    EmailReporter* email_reporter = new EmailReporter();
    if (!email_reporter) {
        cJSON_Delete(root);
        return false;
    }

    EmailConfig email_config;
    email_config.host = PSRAMUtils::createPSRAMString(smtp_server ? smtp_server : "smtp.gmail.com");
    email_config.port = smtp_port;
    email_config.tls = use_tls;
    email_config.username = PSRAMUtils::createPSRAMString(smtp_username ? smtp_username : "");
    email_config.password = PSRAMUtils::createPSRAMString(smtp_password ? smtp_password : "");
    email_config.from = PSRAMUtils::createPSRAMString(from_address ? from_address : "esp32@localhost");
    email_config.subject = PSRAMUtils::createPSRAMString(subject_prefix ? subject_prefix : "ESP32 Alert");
    email_config.timeout_ms = timeout_ms;

    std::vector<psram_string> captured_addresses;
    captured_addresses.reserve(to_count);
    for (int i = 0; i < to_count; ++i) {
        captured_addresses.push_back(PSRAMUtils::createPSRAMString(to_addresses[i] ? to_addresses[i] : ""));
    }
    if (!captured_addresses.empty()) {
        email_config.to = captured_addresses[0];
    } else {
        email_config.to = PSRAMUtils::createPSRAMString("admin@localhost");
    }

    EmailConfig captured_config = email_config;
    int captured_count = static_cast<int>(captured_addresses.size());
    EmailReporter* email_reporter_ptr = email_reporter;
    auto email_sender_psram = [email_reporter_ptr, captured_config, captured_addresses, captured_count](const psram_string& payload) -> bool {
        if (!email_reporter_ptr) return false;
        size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (free_heap < 4096) return false;

        const char* payload_raw = payload.c_str();
        size_t payload_size = payload.size();
        bool is_threat_json = (strstr(payload_raw, "threat_detected")!=nullptr) && (strstr(payload_raw, "cve_id")!=nullptr);
        const char* payload_to_send = payload_raw;
        bool is_truncated = false;
        char* truncated_buf = nullptr;
        if (!is_threat_json && payload_size > 4096) {
            is_truncated = true;
            size_t ts = 4096 + 40;
            truncated_buf = (char*)heap_caps_malloc(ts, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!truncated_buf) return false;
            memcpy(truncated_buf, payload_raw, 4096);
            strcpy(truncated_buf + 4096, "\n[...truncated due to size limit]");
            payload_to_send = truncated_buf;
        }

        if (is_threat_json) {
            LOG_INFOF("EMAIL", "THREAT EMAIL: JSON size %u bytes, will send as MIME attachment (no truncation)", (unsigned)payload_size);
        }

        bool success = false;
        for (int i = 0; i < captured_count; ++i) {
            if (captured_addresses[i].empty()) continue;
            EmailConfig tmp = captured_config;
            tmp.to = captured_addresses[i];
            const char* base_subject = (!captured_config.subject.empty()) ? captured_config.subject.c_str() : "ESP32 Alert";
            size_t subject_len = strlen(base_subject) + (is_truncated ? 15 : 5);
            char* subject_buf = (char*)heap_caps_malloc(subject_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (subject_buf) {
                strcpy(subject_buf, base_subject);
                if (is_truncated) strcat(subject_buf, " [TRUNCATED]");
                tmp.subject = PSRAMUtils::createPSRAMString(subject_buf);
                heap_caps_free(subject_buf);
            }
            bool send_ok = is_threat_json ? email_reporter_ptr->enqueueThreatAlert(tmp, payload_to_send)
                                          : email_reporter_ptr->enqueueEmail(tmp, payload_to_send);
            success = success || send_ok;
        }

        if (truncated_buf) heap_caps_free(truncated_buf);
        return success;
    };

    rep->setChannel(PSRAMUtils::createPSRAMString("email"), email_cfg, email_sender_psram);
    email_reporter_registered = true;

    cJSON_Delete(root);
    return true;
}

} // namespace ReportingConfig
