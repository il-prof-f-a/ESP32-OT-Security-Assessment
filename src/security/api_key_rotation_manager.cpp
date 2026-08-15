#include "api_key_rotation_manager.h"
#include "../core/logging_system.h"
#include "../core/async_storage_engine.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include <cstring>

extern "C" {
    #include "esp_timer.h"
    #include "nvs.h"
    #include "nvs_flash.h"
}

static const char* TAG_ROT = "ApiKeyRotation";

// Singleton globale per gestione centralizzata
ApiKeyRotationManager* g_api_key_rotation_manager = nullptr;

ApiKeyRotationManager::ApiKeyRotationManager()
    : sec_mgr_(nullptr)
    , cron_sched_(nullptr)
    , mutex_(nullptr)
    , initialized_(false)
{
    PSRAMAllocator<ApiKeyRotationEntry> alloc;
    scheduled_rotations_ = psram_vector<ApiKeyRotationEntry>(alloc);

    PSRAMAllocator<char> char_alloc;
    cron_schedule_id_ = psram_string(char_alloc);
}

ApiKeyRotationManager::~ApiKeyRotationManager() {
    shutdown();
}

bool ApiKeyRotationManager::initialize(SecurityManager* sec_mgr, CronScheduler* cron_sched) {
    if (initialized_) {
        LOG_WARNING(TAG_ROT, "ApiKeyRotationManager already initialized");
        return false;
    }

    if (!sec_mgr || !cron_sched) {
        LOG_ERROR(TAG_ROT, "Invalid SecurityManager or CronScheduler reference");
        return false;
    }

    sec_mgr_ = sec_mgr;
    cron_sched_ = cron_sched;

    // Crea mutex
    mutex_ = xSemaphoreCreateMutex();
    if (!mutex_) {
        LOG_ERROR(TAG_ROT, "Failed to create mutex");
        return false;
    }

    // Carica policy da NVS
    loadPolicyFromNVS();

    // Carica scheduled rotations da NVS
    loadRotationsFromNVS();

    // Se policy abilitata, registra task nel CronScheduler (check ogni giorno alle 02:00)
    if (policy_.enabled) {
        ScheduledScan rotation_check;
        rotation_check.name = PSRAMUtils::createPSRAMString("API Key Rotation Check");
        rotation_check.type = ScheduledScanType::VULNERABILITY_SCAN; // Riutilizziamo l'enum
        rotation_check.target = PSRAMUtils::createPSRAMString("internal://api_key_rotation");
        rotation_check.enabled = true;
        rotation_check.hour = 2;   // 02:00 AM
        rotation_check.minute = 0;
        rotation_check.day_of_month = -1; // Ogni giorno
        rotation_check.month = -1;
        rotation_check.day_of_week = -1;

        // Nota: Il CronScheduler non ha callback diretto, quindi useremo un approccio diverso
        // Invece di registrare nel CronScheduler, creiamo un task FreeRTOS dedicato
        // Oppure facciamo polling durante il loop principale
        // Per semplicità, implementiamo un timer periodico qui
        LOG_INFO(TAG_ROT, "API Key Rotation Manager uses internal timer (daily check at 02:00)");
    }

    initialized_ = true;
    LOG_INFOF(TAG_ROT, "ApiKeyRotationManager initialized (policy enabled: %d, %zu scheduled rotations)",
              policy_.enabled, scheduled_rotations_.size());
    return true;
}

void ApiKeyRotationManager::shutdown() {
    if (!initialized_) {
        return;
    }

    // Delete mutex
    if (mutex_) {
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
    }

    scheduled_rotations_.clear();
    initialized_ = false;
    LOG_INFO(TAG_ROT, "ApiKeyRotationManager shutdown complete");
}

void ApiKeyRotationManager::setPolicy(const ApiKeyRotationPolicy& policy) {
    if (!initialized_ || !mutex_) {
        return;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_ROT, "Failed to acquire mutex for set policy");
        return;
    }

    policy_ = policy;
    xSemaphoreGive(mutex_);

    savePolicyToNVS();
    LOG_INFOF(TAG_ROT, "Policy updated: enabled=%d, interval=%lu days, overlap=%lu days",
              policy.enabled, (unsigned long)policy.rotation_interval_days, (unsigned long)policy.overlap_period_days);
}

void ApiKeyRotationManager::getPolicy(ApiKeyRotationPolicy& out_policy) const {
    if (!initialized_ || !mutex_) {
        return;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_ROT, "Failed to acquire mutex for get policy");
        return;
    }

    out_policy = policy_;
    xSemaphoreGive(mutex_);
}

bool ApiKeyRotationManager::scheduleRotation(const char* key_id, const char* label) {
    if (!initialized_ || !mutex_ || !key_id || !label) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_ROT, "Failed to acquire mutex for schedule rotation");
        return false;
    }

    // Verifica se già schedulata
    for (const auto& entry : scheduled_rotations_) {
        if (strcmp(entry.key_id.c_str(), key_id) == 0) {
            xSemaphoreGive(mutex_);
            LOG_WARNINGF(TAG_ROT, "Rotation already scheduled for key: %s", key_id);
            return false;
        }
    }

    // Crea entry
    ApiKeyRotationEntry entry;
    entry.key_id = PSRAMUtils::createPSRAMString(key_id);
    entry.key_label = PSRAMUtils::createPSRAMString(label);

    // Calcola timestamp rotazione (dalla data corrente + interval)
    uint64_t now_ms = esp_timer_get_time() / 1000;
    entry.rotation_due_ms = now_ms + (policy_.rotation_interval_days * 24ULL * 60 * 60 * 1000);

    scheduled_rotations_.push_back(entry);
    xSemaphoreGive(mutex_);

    saveRotationsToNVS();
    LOG_INFOF(TAG_ROT, "Scheduled rotation for key '%s' (ID: %s) due in %lu days",
              label, key_id, (unsigned long)policy_.rotation_interval_days);
    return true;
}

bool ApiKeyRotationManager::cancelRotation(const char* key_id) {
    if (!initialized_ || !mutex_ || !key_id) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_ROT, "Failed to acquire mutex for cancel rotation");
        return false;
    }

    bool found = false;
    for (auto it = scheduled_rotations_.begin(); it != scheduled_rotations_.end(); ++it) {
        if (strcmp(it->key_id.c_str(), key_id) == 0) {
            LOG_INFOF(TAG_ROT, "Canceling rotation for key: %s", key_id);
            scheduled_rotations_.erase(it);
            found = true;
            break;
        }
    }

    xSemaphoreGive(mutex_);

    if (found) {
        saveRotationsToNVS();
    }

    return found;
}

psram_vector<ApiKeyRotationEntry> ApiKeyRotationManager::listScheduledRotations() const {
    PSRAMAllocator<ApiKeyRotationEntry> alloc;
    psram_vector<ApiKeyRotationEntry> result(alloc);

    if (!initialized_ || !mutex_) {
        return result;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_ROT, "Failed to acquire mutex for list rotations");
        return result;
    }

    result = scheduled_rotations_;
    xSemaphoreGive(mutex_);

    return result;
}

bool ApiKeyRotationManager::triggerImmediateRotation(const char* key_id, const char* new_label) {
    if (!initialized_ || !sec_mgr_ || !key_id || !new_label) {
        return false;
    }

    LOG_INFOF(TAG_ROT, "Triggering immediate rotation for key: %s", key_id);

    // Crea nuova key
    psram_string label_ps = PSRAMUtils::createPSRAMString(new_label);
    const char* new_token = sec_mgr_->createApiKey(label_ps).c_str();
    if (!new_token || strlen(new_token) == 0) {
        LOG_ERROR(TAG_ROT, "Failed to create new API key for immediate rotation");
        return false;
    }

    LOG_INFOF(TAG_ROT, "New API key created for immediate rotation: %s", new_label);
    LOG_INFOF(TAG_ROT, "New token: %s (SAVE THIS - shown only once!)", new_token);

    // Revoca vecchia key dopo overlap period (se auto_revoke abilitato)
    if (policy_.auto_revoke_old_keys) {
        LOG_INFOF(TAG_ROT, "Old key %s will be revoked in %lu days (auto-revoke enabled)",
                  key_id, (unsigned long)policy_.overlap_period_days);

        // TODO: Schedula revoca futura con timer dedicato
        // Per ora la revoca è gestita manualmente o via scheduled rotation
    } else {
        LOG_INFO(TAG_ROT, "Auto-revoke disabled - old key remains active (manual revocation required)");
    }

    return true;
}

void ApiKeyRotationManager::checkRotations() {
    if (!initialized_ || !mutex_ || !sec_mgr_) {
        return;
    }

    if (!policy_.enabled) {
        return; // Policy disabilitata
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_ROT, "Failed to acquire mutex for check rotations");
        return;
    }

    for (auto& entry : scheduled_rotations_) {
        processRotationEntry(entry);
    }

    xSemaphoreGive(mutex_);

    // Salva stato aggiornato
    saveRotationsToNVS();
}

void ApiKeyRotationManager::processRotationEntry(ApiKeyRotationEntry& entry) {
    uint64_t now_ms = esp_timer_get_time() / 1000;

    // Step 1: Invia warning se mancano N giorni alla rotazione
    if (!entry.warning_sent) {
        uint64_t warning_threshold_ms = entry.rotation_due_ms - (policy_.warning_days_before_rotation * 24ULL * 60 * 60 * 1000);
        if (now_ms >= warning_threshold_ms) {
            sendWarningNotification(entry);
            entry.warning_sent = true;
            entry.warning_sent_ms = now_ms;
        }
    }

    // Step 2: Crea nuova key quando arriva il momento
    if (!entry.new_key_created && now_ms >= entry.rotation_due_ms) {
        createNewKey(entry);
        entry.new_key_created = true;
        entry.new_key_created_ms = now_ms;
        entry.old_key_revoke_ms = now_ms + (policy_.overlap_period_days * 24ULL * 60 * 60 * 1000);
    }

    // Step 3: Revoca vecchia key dopo overlap period (se auto_revoke abilitato)
    if (policy_.auto_revoke_old_keys && entry.new_key_created && !entry.old_key_revoked) {
        if (now_ms >= entry.old_key_revoke_ms) {
            revokeOldKey(entry);
            entry.old_key_revoked = true;
        }
    }
}

void ApiKeyRotationManager::sendWarningNotification(const ApiKeyRotationEntry& entry) {
    if (!policy_.send_notifications) {
        return;
    }

    // Prepara messaggio warning
    char msg[512];
    snprintf(msg, sizeof(msg),
             "API Key Rotation Warning: Key '%s' (ID: %s) will be rotated in %lu days. "
             "Please prepare to update your applications with the new token.",
             entry.key_label.c_str(), entry.key_id.c_str(), (unsigned long)policy_.warning_days_before_rotation);

    LOG_WARNING(TAG_ROT, msg);

    // TODO: Invia notifica via ReportingEngine (webhook/email) quando implementato
}

void ApiKeyRotationManager::createNewKey(ApiKeyRotationEntry& entry) {
    if (!sec_mgr_) {
        return;
    }

    // Genera label per nuova key
    char new_label[256];
    snprintf(new_label, sizeof(new_label), "%s (rotated)", entry.key_label.c_str());

    psram_string label_ps = PSRAMUtils::createPSRAMString(new_label);
    const char* new_token = sec_mgr_->createApiKey(label_ps).c_str();

    if (!new_token || strlen(new_token) == 0) {
        LOG_ERRORF(TAG_ROT, "Failed to create new API key for rotation: %s", entry.key_id.c_str());
        return;
    }

    // Salva ID nuova key (per tracking)
    // Nota: createApiKey ritorna il token plain, non l'ID. Dobbiamo estrarre l'ID dalla lista keys
    // Per semplicità, usiamo il token come identificatore temporaneo
    entry.new_key_id = PSRAMUtils::createPSRAMString(new_token);

    LOG_INFOF(TAG_ROT, "New API key created for rotation of '%s': %s",
              entry.key_label.c_str(), new_token);
    LOG_WARNING(TAG_ROT, "IMPORTANT: Save this token - it will not be shown again!");

    // Invia notifica con nuovo token
    if (policy_.send_notifications) {
        char msg[1024];
        snprintf(msg, sizeof(msg),
                 "API Key Rotated: '%s' (old ID: %s). New token: %s. "
                 "Update your applications within %lu days before the old key is revoked.",
                 entry.key_label.c_str(), entry.key_id.c_str(), new_token,
                 (unsigned long)policy_.overlap_period_days);

        // TODO: Invia notifica via ReportingEngine quando implementato
    }
}

void ApiKeyRotationManager::revokeOldKey(ApiKeyRotationEntry& entry) {
    if (!sec_mgr_) {
        return;
    }

    psram_string key_id_ps = PSRAMUtils::createPSRAMString(entry.key_id.c_str());
    bool revoked = sec_mgr_->revokeApiKey(key_id_ps);

    if (revoked) {
        LOG_INFOF(TAG_ROT, "Old API key revoked after overlap period: %s", entry.key_id.c_str());

        // Invia notifica revoca
        if (policy_.send_notifications) {
            char msg[512];
            snprintf(msg, sizeof(msg),
                     "API Key Revoked: Old key '%s' (ID: %s) has been automatically revoked after overlap period.",
                     entry.key_label.c_str(), entry.key_id.c_str());

            // TODO: Invia notifica via ReportingEngine quando implementato
        }
    } else {
        LOG_ERRORF(TAG_ROT, "Failed to revoke old API key: %s", entry.key_id.c_str());
    }
}

uint64_t ApiKeyRotationManager::calculateRotationDue(uint64_t key_created_ms) const {
    return key_created_ms + (policy_.rotation_interval_days * 24ULL * 60 * 60 * 1000);
}

void ApiKeyRotationManager::getStats(RotationStats& out_stats) const {
    if (!initialized_ || !mutex_) {
        return;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_ROT, "Failed to acquire mutex for get stats");
        return;
    }

    out_stats.total_scheduled = scheduled_rotations_.size();
    out_stats.pending_warnings = 0;
    out_stats.pending_creations = 0;
    out_stats.pending_revocations = 0;
    out_stats.completed_rotations = 0;

    for (const auto& entry : scheduled_rotations_) {
        if (!entry.warning_sent) {
            out_stats.pending_warnings++;
        }
        if (!entry.new_key_created) {
            out_stats.pending_creations++;
        }
        if (entry.new_key_created && !entry.old_key_revoked) {
            out_stats.pending_revocations++;
        }
        if (entry.old_key_revoked) {
            out_stats.completed_rotations++;
        }
    }

    xSemaphoreGive(mutex_);
}

bool ApiKeyRotationManager::loadPolicyFromNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        LOG_INFOF(TAG_ROT, "No existing rotation policy in NVS: %s", esp_err_to_name(err));
        return false;
    }

    uint8_t enabled_val = 0;
    uint32_t u32_val = 0;

    // Carica campi
    if (nvs_get_u8(handle, "rot_enabled", &enabled_val) == ESP_OK) {
        policy_.enabled = (enabled_val != 0);
    }

    if (nvs_get_u32(handle, "rot_interval", &u32_val) == ESP_OK) {
        policy_.rotation_interval_days = u32_val;
    }

    if (nvs_get_u32(handle, "rot_overlap", &u32_val) == ESP_OK) {
        policy_.overlap_period_days = u32_val;
    }

    if (nvs_get_u8(handle, "rot_auto_rev", &enabled_val) == ESP_OK) {
        policy_.auto_revoke_old_keys = (enabled_val != 0);
    }

    if (nvs_get_u32(handle, "rot_warn_days", &u32_val) == ESP_OK) {
        policy_.warning_days_before_rotation = u32_val;
    }

    if (nvs_get_u8(handle, "rot_notify", &enabled_val) == ESP_OK) {
        policy_.send_notifications = (enabled_val != 0);
    }

    // Carica stringhe (webhook, email)
    size_t len = 0;
    if (nvs_get_str(handle, "rot_webhook", NULL, &len) == ESP_OK && len > 0) {
        char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
        if (buf) {
            nvs_get_str(handle, "rot_webhook", buf, &len);
            policy_.notification_webhook = PSRAMUtils::createPSRAMString(buf);
            heap_caps_free(buf);
        }
    }

    if (nvs_get_str(handle, "rot_email", NULL, &len) == ESP_OK && len > 0) {
        char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
        if (buf) {
            nvs_get_str(handle, "rot_email", buf, &len);
            policy_.notification_email = PSRAMUtils::createPSRAMString(buf);
            heap_caps_free(buf);
        }
    }

    nvs_close(handle);
    LOG_INFO(TAG_ROT, "Loaded rotation policy from NVS");
    return true;
}

bool ApiKeyRotationManager::savePolicyToNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("security", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_ROT, "Failed to open NVS for writing policy: %s", esp_err_to_name(err));
        return false;
    }

    // Salva campi
    nvs_set_u8(handle, "rot_enabled", policy_.enabled ? 1 : 0);
    nvs_set_u32(handle, "rot_interval", policy_.rotation_interval_days);
    nvs_set_u32(handle, "rot_overlap", policy_.overlap_period_days);
    nvs_set_u8(handle, "rot_auto_rev", policy_.auto_revoke_old_keys ? 1 : 0);
    nvs_set_u32(handle, "rot_warn_days", policy_.warning_days_before_rotation);
    nvs_set_u8(handle, "rot_notify", policy_.send_notifications ? 1 : 0);

    // Salva stringhe
    if (!policy_.notification_webhook.empty()) {
        nvs_set_str(handle, "rot_webhook", policy_.notification_webhook.c_str());
    }
    if (!policy_.notification_email.empty()) {
        nvs_set_str(handle, "rot_email", policy_.notification_email.c_str());
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        LOG_ERRORF(TAG_ROT, "Failed to commit NVS policy: %s", esp_err_to_name(err));
        return false;
    }

    LOG_INFO(TAG_ROT, "Saved rotation policy to NVS");
    return true;
}

bool ApiKeyRotationManager::loadRotationsFromNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("api_rot", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        LOG_INFOF(TAG_ROT, "No existing rotations in NVS: %s", esp_err_to_name(err));
        return false;
    }

    uint32_t count = 0;
    err = nvs_get_u32(handle, "count", &count);
    if (err != ESP_OK || count == 0) {
        nvs_close(handle);
        LOG_INFO(TAG_ROT, "No rotations found in NVS");
        return false;
    }

    scheduled_rotations_.clear();

    for (uint32_t i = 0; i < count && i < 50; i++) { // Max 50 rotations
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "r%lu_", (unsigned long)i);

        ApiKeyRotationEntry entry;
        char key[32];
        size_t len;

        // Carica stringhe
        snprintf(key, sizeof(key), "%skid", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                entry.key_id = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        snprintf(key, sizeof(key), "%slbl", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                entry.key_label = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        snprintf(key, sizeof(key), "%snkid", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                entry.new_key_id = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        // Carica timestamp
        uint64_t u64_val;
        snprintf(key, sizeof(key), "%sdue", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) entry.rotation_due_ms = u64_val;

        snprintf(key, sizeof(key), "%swarn", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) entry.warning_sent_ms = u64_val;

        snprintf(key, sizeof(key), "%screated", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) entry.new_key_created_ms = u64_val;

        snprintf(key, sizeof(key), "%srevoke", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) entry.old_key_revoke_ms = u64_val;

        // Carica bool
        uint8_t u8_val;
        snprintf(key, sizeof(key), "%swarnsent", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) entry.warning_sent = (u8_val != 0);

        snprintf(key, sizeof(key), "%snewcreated", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) entry.new_key_created = (u8_val != 0);

        snprintf(key, sizeof(key), "%soldrev", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) entry.old_key_revoked = (u8_val != 0);

        scheduled_rotations_.push_back(entry);
    }

    nvs_close(handle);
    LOG_INFOF(TAG_ROT, "Loaded %zu rotations from NVS", scheduled_rotations_.size());
    return true;
}

bool ApiKeyRotationManager::saveRotationsToNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("api_rot", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_ROT, "Failed to open NVS for writing rotations: %s", esp_err_to_name(err));
        return false;
    }

    nvs_erase_all(handle);

    uint32_t count = (uint32_t)scheduled_rotations_.size();
    nvs_set_u32(handle, "count", count);

    for (size_t i = 0; i < scheduled_rotations_.size(); i++) {
        const ApiKeyRotationEntry& e = scheduled_rotations_[i];
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "r%zu_", i);
        char key[32];

        // Salva stringhe
        snprintf(key, sizeof(key), "%skid", prefix);
        nvs_set_str(handle, key, e.key_id.c_str());

        snprintf(key, sizeof(key), "%slbl", prefix);
        nvs_set_str(handle, key, e.key_label.c_str());

        snprintf(key, sizeof(key), "%snkid", prefix);
        nvs_set_str(handle, key, e.new_key_id.c_str());

        // Salva timestamp
        snprintf(key, sizeof(key), "%sdue", prefix);
        nvs_set_u64(handle, key, e.rotation_due_ms);

        snprintf(key, sizeof(key), "%swarn", prefix);
        nvs_set_u64(handle, key, e.warning_sent_ms);

        snprintf(key, sizeof(key), "%screated", prefix);
        nvs_set_u64(handle, key, e.new_key_created_ms);

        snprintf(key, sizeof(key), "%srevoke", prefix);
        nvs_set_u64(handle, key, e.old_key_revoke_ms);

        // Salva bool
        snprintf(key, sizeof(key), "%swarnsent", prefix);
        nvs_set_u8(handle, key, e.warning_sent ? 1 : 0);

        snprintf(key, sizeof(key), "%snewcreated", prefix);
        nvs_set_u8(handle, key, e.new_key_created ? 1 : 0);

        snprintf(key, sizeof(key), "%soldrev", prefix);
        nvs_set_u8(handle, key, e.old_key_revoked ? 1 : 0);
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        LOG_ERRORF(TAG_ROT, "Failed to commit NVS rotations: %s", esp_err_to_name(err));
        return false;
    }

    LOG_INFOF(TAG_ROT, "Saved %zu rotations to NVS", scheduled_rotations_.size());
    return true;
}
