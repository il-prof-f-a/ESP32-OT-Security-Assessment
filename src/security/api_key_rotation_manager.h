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

// API key rotation policy
struct ApiKeyRotationPolicy {
    bool enabled;                          // Automatic rotation enabled
    uint32_t rotation_interval_days;       // Rotation interval (default: 90 days)
    uint32_t overlap_period_days;          // Overlap period before revoking the old key (default: 7 days)
    bool auto_revoke_old_keys;             // Auto-revoke old keys after overlap
    uint32_t warning_days_before_rotation; // Days before rotation to send a warning (default: 7)
    bool send_notifications;               // Send email/webhook notifications
    psram_string notification_webhook;     // Webhook URL for notifications
    psram_string notification_email;       // Notification recipient email

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

// Entry of a scheduled rotation
struct ApiKeyRotationEntry {
    psram_string key_id;           // ID of the key to rotate
    psram_string key_label;        // Label for tracking
    psram_string new_key_id;       // ID of the newly created key
    uint64_t rotation_due_ms;      // Timestamp when the rotation is due
    uint64_t warning_sent_ms;      // Timestamp when the warning is sent
    uint64_t new_key_created_ms;   // Timestamp when the new key is created
    uint64_t old_key_revoke_ms;    // Timestamp when to revoke the old key
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

    // Initialization
    bool initialize(SecurityManager* sec_mgr, CronScheduler* cron_sched);
    void shutdown();

    // Policy configuration
    void setPolicy(const ApiKeyRotationPolicy& policy);
    void getPolicy(ApiKeyRotationPolicy& out_policy) const;

    // Rotation management
    bool scheduleRotation(const char* key_id, const char* label);
    bool cancelRotation(const char* key_id);
    psram_vector<ApiKeyRotationEntry> listScheduledRotations() const;

    // Manual trigger
    bool triggerImmediateRotation(const char* key_id, const char* new_label);

    // Persistence
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
    // Cron task callback (called periodically by CronScheduler)
    void checkRotations();

    // Helper for a single rotation
    void processRotationEntry(ApiKeyRotationEntry& entry);
    void sendWarningNotification(const ApiKeyRotationEntry& entry);
    void createNewKey(ApiKeyRotationEntry& entry);
    void revokeOldKey(ApiKeyRotationEntry& entry);

    // Calculate the rotation timestamp for a key
    uint64_t calculateRotationDue(uint64_t key_created_ms) const;

    SecurityManager* sec_mgr_;
    CronScheduler* cron_sched_;

    ApiKeyRotationPolicy policy_;
    psram_vector<ApiKeyRotationEntry> scheduled_rotations_;

    mutable SemaphoreHandle_t mutex_;
    bool initialized_;

    psram_string cron_schedule_id_; // ID of the scheduled task in CronScheduler

    static constexpr const char* TAG = "ApiKeyRotation";
};
