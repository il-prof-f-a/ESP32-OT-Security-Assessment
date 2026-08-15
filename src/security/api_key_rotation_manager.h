#pragma once

#include "../core/psram_allocator.h"
#include "../core/types.h"
#include "../core/cron_scheduler.h"
#include "security_manager.h"
#include <cstdint>
#include <mutex>

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/semphr.h"
}

class ApiKeyRotationManager;
extern ApiKeyRotationManager* g_api_key_rotation_manager;

// Policy di rotazione API Keys
struct ApiKeyRotationPolicy {
    bool enabled;                          // Rotazione automatica abilitata
    uint32_t rotation_interval_days;       // Intervallo rotazione (default: 90 giorni)
    uint32_t overlap_period_days;          // Periodo overlap prima revoca vecchia key (default: 7 giorni)
    bool auto_revoke_old_keys;             // Auto-revoca vecchie keys dopo overlap
    uint32_t warning_days_before_rotation; // Giorni prima della rotazione per inviare warning (default: 7)
    bool send_notifications;               // Invia notifiche email/webhook
    psram_string notification_webhook;     // URL webhook per notifiche
    psram_string notification_email;       // Email destinatario notifiche

    ApiKeyRotationPolicy() {
        PSRAMAllocator<char> alloc;
        enabled = false;
        rotation_interval_days = 90;
        overlap_period_days = 7;
        auto_revoke_old_keys = false;
        warning_days_before_rotation = 7;
        send_notifications = false;
        notification_webhook = psram_string(alloc);
        notification_email = psram_string(alloc);
    }
};

// Entry di una scheduled rotation
struct ApiKeyRotationEntry {
    psram_string key_id;           // ID della key da ruotare
    psram_string key_label;        // Label per tracking
    psram_string new_key_id;       // ID della nuova key creata
    uint64_t rotation_due_ms;      // Timestamp quando la rotazione è dovuta
    uint64_t warning_sent_ms;      // Timestamp invio warning
    uint64_t new_key_created_ms;   // Timestamp creazione nuova key
    uint64_t old_key_revoke_ms;    // Timestamp quando revocare vecchia key
    bool warning_sent;
    bool new_key_created;
    bool old_key_revoked;

    ApiKeyRotationEntry() {
        PSRAMAllocator<char> alloc;
        key_id = psram_string(alloc);
        key_label = psram_string(alloc);
        new_key_id = psram_string(alloc);
        rotation_due_ms = 0;
        warning_sent_ms = 0;
        new_key_created_ms = 0;
        old_key_revoke_ms = 0;
        warning_sent = false;
        new_key_created = false;
        old_key_revoked = false;
    }
};

class ApiKeyRotationManager {
public:
    ApiKeyRotationManager();
    ~ApiKeyRotationManager();

    // Inizializzazione
    bool initialize(SecurityManager* sec_mgr, CronScheduler* cron_sched);
    void shutdown();

    // Configurazione policy
    void setPolicy(const ApiKeyRotationPolicy& policy);
    void getPolicy(ApiKeyRotationPolicy& out_policy) const;

    // Gestione rotazioni
    bool scheduleRotation(const char* key_id, const char* label);
    bool cancelRotation(const char* key_id);
    psram_vector<ApiKeyRotationEntry> listScheduledRotations() const;

    // Trigger manuale
    bool triggerImmediateRotation(const char* key_id, const char* new_label);

    // Persistenza
    bool loadPolicyFromNVS();
    bool savePolicyToNVS();
    bool loadRotationsFromNVS();
    bool saveRotationsToNVS();

    // Stats
    struct RotationStats {
        uint32_t total_scheduled;
        uint32_t pending_warnings;
        uint32_t pending_creations;
        uint32_t pending_revocations;
        uint32_t completed_rotations;
    };
    void getStats(RotationStats& out_stats) const;

private:
    // Cron task callback (chiamato periodicamente dal CronScheduler)
    void checkRotations();

    // Helper per singola rotazione
    void processRotationEntry(ApiKeyRotationEntry& entry);
    void sendWarningNotification(const ApiKeyRotationEntry& entry);
    void createNewKey(ApiKeyRotationEntry& entry);
    void revokeOldKey(ApiKeyRotationEntry& entry);

    // Calcola timestamp rotazione per una key
    uint64_t calculateRotationDue(uint64_t key_created_ms) const;

    SecurityManager* sec_mgr_;
    CronScheduler* cron_sched_;

    ApiKeyRotationPolicy policy_;
    psram_vector<ApiKeyRotationEntry> scheduled_rotations_;

    mutable SemaphoreHandle_t mutex_;
    bool initialized_;

    psram_string cron_schedule_id_; // ID della scheduled task nel CronScheduler

    static constexpr const char* TAG = "ApiKeyRotation";
};
