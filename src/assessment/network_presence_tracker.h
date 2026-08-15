#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include "../core/types.h"
#include "../core/configuration_manager.h"
#include "../core/psram_allocator.h"

// Enhanced structure to track network presence and trust
struct NetworkDeviceInfo {
    psram_string ip_address;
    psram_string mac_address;

    // Traffic statistics
    uint64_t total_packets = 0;
    uint64_t total_read_packets = 0;
    uint64_t total_write_packets = 0;
    uint64_t last_seen_ms = 0;
    uint64_t first_seen_ms = 0;

    // Protocol and port diversity
    psram_map<ProtocolType, uint64_t> protocol_counts;
    psram_map<uint16_t, uint64_t> port_usage;

    // Trust and presence scoring
    double presence_score = 0.0;           // Calculated trust score based on network presence
    bool is_continuously_present = false;   // Has been present consistently
    bool is_learned_sender = false;         // Automatically learned as trusted sender
    bool is_learned_writer = false;         // Automatically learned as trusted writer
    bool is_whitelisted = false;           // Manually whitelisted
    uint64_t inactive_since_ms = 0;        // When device went inactive (0 = active)

    // Persistence flags
    bool is_persistent = false;             // Should survive reboot
    uint64_t learned_timestamp_ms = 0;     // When device was first learned as trusted
};

class NetworkPresenceTracker {
public:
    NetworkPresenceTracker();
    ~NetworkPresenceTracker();

    // Initialize persistent storage
    bool initialize();
    void shutdown();

    // Configuration management
    void setConfig(const NetworkPresenceConfig& config);
    NetworkPresenceConfig getConfig() const;
    psram_string getConfigJSON() const;
    bool loadConfigFromJSON(const psram_string& json);
    bool loadConfigFromJSON(const std::string& json); // Backward compatibility
    bool loadConfigFromJSON(const char* json, size_t len = 0); // PSRAM-friendly version

    // Network presence and trust management
    void addTrustedDevice(const psram_string& identifier, bool is_persistent = true);
    void addTrustedDevice(const std::string& identifier, bool is_persistent = true); // Backward compatibility
    void removeTrustedDevice(const psram_string& identifier);
    void removeTrustedDevice(const std::string& identifier); // Backward compatibility
    bool isTrustedSender(const psram_string& ip, const psram_string& mac) const;
    bool isTrustedSender(const psram_string& ip) const;
    bool isTrustedSender(const std::string& ip, const std::string& mac = "") const; // Backward compatibility
    bool isTrustedWriter(const psram_string& ip, const psram_string& mac) const;
    bool isTrustedWriter(const psram_string& ip) const;
    bool isTrustedWriter(const std::string& ip, const std::string& mac = "") const; // Backward compatibility
    psram_vector<psram_string> getTrustedDevices() const;

    // Learning system
    void promoteToTrusted(const psram_string& ip);
    void promoteToTrusted(const std::string& ip); // Backward compatibility
    void demoteFromTrusted(const psram_string& ip);
    void demoteFromTrusted(const std::string& ip); // Backward compatibility
    psram_vector<NetworkDeviceInfo> getLearnedDevices() const;
    void clearLearningData();

    // Packet tracking
    void trackPacket(const NetworkPacket& packet);
    void trackWritePacket(const NetworkPacket& packet, bool is_write_operation = true);

    // Statistics and monitoring
    psram_vector<NetworkDeviceInfo> getAllDevices() const;
    NetworkDeviceInfo* getDeviceInfo(const psram_string& ip);
    NetworkDeviceInfo* getDeviceInfo(const std::string& ip); // Backward compatibility
    const NetworkDeviceInfo* getDeviceInfo(const psram_string& ip) const;
    const NetworkDeviceInfo* getDeviceInfo(const std::string& ip) const; // Backward compatibility
    psram_string getDevicesStatsJSON() const;
    psram_string getLearnedDevicesJSON() const;

    // Cleanup and maintenance
    void cleanupInactiveDevices();
    void runRetentionCleanup();
    void clearAllDevices();

    // Learning mode management
    bool isInLearningMode() const;
    void notifyLearningComplete(); // Call this when learning phase ends

    // Persistent storage
    bool saveToPersistentStorage();
    bool loadFromPersistentStorage();

    // Status methods
    size_t getTotalDevices() const;
    size_t getTrustedDevicesCount() const;
    size_t getLearnedDevicesCount() const;
    size_t getUntrustedDevicesCount() const;
    uint64_t getTotalTrackedPackets() const;
    uint64_t getTotalWritePackets() const;

    // Learning mode detection (declaration moved to "Learning mode management" section above)

    // Normalizers
    psram_string normalizeIp(const psram_string& ip);
    psram_string normalizeIp(const std::string& ip); // Backward compatibility
    psram_string normalizeMac(const psram_string& mac);
    psram_string normalizeMac(const std::string& mac); // Backward compatibility
    bool macMatchesPattern(const psram_string& mac, const psram_string& pattern);
    bool macMatchesPattern(const std::string& mac, const std::string& pattern); // Backward compatibility

    // Load whitelist from external sources (backward compatibility)
    void loadAuthorized(const psram_vector<psram_string>& ips,
                        const psram_vector<psram_string>& macs,
                        const psram_vector<psram_string>& wl_ips,
                        const psram_vector<psram_string>& wl_macs);
    void loadAuthorized(const std::vector<std::string>& ips,
                        const std::vector<std::string>& macs,
                        const std::vector<std::string>& wl_ips,
                        const std::vector<std::string>& wl_macs); // Backward compatibility

    // Check if device is whitelisted OR learned as trusted
    bool isWhitelisted(const psram_string& ip, const psram_string& mac) const;
    bool isWhitelisted(const std::string& ip, const std::string& mac) const; // Backward compatibility
    bool isActive();

private:
    mutable std::mutex mutex_;
    NetworkPresenceConfig config_;

    bool active_ = false;

    // Device tracking data
    psram_map<psram_string, NetworkDeviceInfo> devices_; // keyed by IP address
    psram_string_set whitelisted_devices_;               // Static whitelist
    psram_string_set learned_trusted_sender_devices_;    // Dynamically learned sender trust
    psram_string_set learned_trusted_writer_devices_;    // Dynamically learned writer trust

    // Statistics
    uint64_t total_tracked_packets_ = 0;
    uint64_t total_write_packets_ = 0;
    uint64_t last_cleanup_ms_ = 0;
    uint64_t last_retention_cleanup_ms_ = 0;

    // Learning mode tracking
    uint64_t system_start_time_ms_ = 0;

    // Persistent storage
    bool persistent_storage_initialized_ = false;
    bool devices_dirty_ = false;              // Flag for unsaved changes
    uint64_t last_auto_save_ms_ = 0;          // Last auto-save timestamp
    uint64_t last_auto_save_check_ms_ = 0;    // Last auto-save check to throttle checkAutoSave() calls

    // Helper methods
    double calculatePresenceScore(const NetworkDeviceInfo& device) const;
    bool shouldPromoteToTrustedSender(const NetworkDeviceInfo& device) const;
    bool shouldPromoteToTrustedWriter(const NetworkDeviceInfo& device) const;
    void updatePresenceScore(NetworkDeviceInfo& device);
    bool matchesTrustedDevice(const psram_string& ip, const psram_string& mac) const;
    bool matchesTrustedDevice(const std::string& ip, const std::string& mac) const; // Backward compatibility
    bool matchesWriterTrustedDevice(const psram_string& ip, const psram_string& mac) const;
    bool matchesWriterTrustedDevice(const std::string& ip, const std::string& mac) const; // Backward compatibility
    void promoteTrustedSenderByIp(const psram_string& ip);
    void promoteTrustedWriterByIp(const psram_string& ip);
    uint64_t getCurrentTimeMs() const;
    void parseWhitelistedDevices(const psram_string_vector& allowed_list);

    // Device lookup helpers
    psram_map<psram_string, NetworkDeviceInfo>::iterator findDeviceByIp(const psram_string& ip);
    psram_map<psram_string, NetworkDeviceInfo>::iterator findDeviceByIp(const std::string& ip); // Backward compatibility
    psram_map<psram_string, NetworkDeviceInfo>::const_iterator findDeviceByIp(const psram_string& ip) const;
    psram_map<psram_string, NetworkDeviceInfo>::const_iterator findDeviceByIp(const std::string& ip) const; // Backward compatibility

    // Persistent storage helpers
    psram_string getStorageKey(const psram_string& ip) const;
    psram_string getStorageKey(const std::string& ip) const; // Backward compatibility
    bool saveDeviceToNVS(const NetworkDeviceInfo& device);
    bool loadDeviceFromNVS(const psram_string& ip, NetworkDeviceInfo& device);
    bool loadDeviceFromNVS(const std::string& ip, NetworkDeviceInfo& device); // Backward compatibility
    void removeDeviceFromNVS(const psram_string& ip);
    void removeDeviceFromNVS(const std::string& ip); // Backward compatibility

    // File-based persistent storage
    struct PersistentDeviceRecord {
        char ip_address[16];          // "192.168.1.100"
        char mac_address[18];         // "AA:BB:CC:DD:EE:FF"
        uint64_t first_seen_ms;
        uint64_t last_seen_ms;
        uint64_t learned_timestamp_ms;
        uint64_t total_packets;
        uint64_t total_write_packets;
        double presence_score;
        bool is_whitelisted;
        bool is_learned_writer;
        bool is_learned_sender;
        bool is_persistent;
        bool is_continuously_present;
        uint8_t padding[2];           // Align to 8 bytes
    };

    struct PersistentStorageHeader {
        uint32_t magic;               // 'NPDB' (Network Presence Database)
        uint32_t version;             // Format version (1)
        uint32_t device_count;        // Number of stored devices
        uint32_t checksum;            // CRC32 of device records
        uint64_t last_updated_ms;     // Last save timestamp
        uint64_t reserved[3];         // Future expansion
    };

    static constexpr const char* PERSISTENT_STORAGE_FILE = "/data/network/learned_devices.bin";
    static constexpr uint32_t STORAGE_MAGIC = 0x4E504442; // 'NPDB'
    static constexpr uint32_t STORAGE_VERSION = 1;
    static constexpr size_t MIN_DEVICES_FOR_SKIP_LEARNING = 3;
    static constexpr uint64_t AUTO_SAVE_INTERVAL_MS = 30000; // 30 seconds

    // Auto-save helpers
    void markDevicesDirty();
    void checkAutoSave();
    uint32_t calculateChecksum(const uint8_t* data, size_t size) const;
};
