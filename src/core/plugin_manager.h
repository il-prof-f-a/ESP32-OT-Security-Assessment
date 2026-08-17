
#pragma once
#include <vector>
#include <memory>
#include <string>
#include <functional>
#include <mutex>
#include <algorithm>
#include "types.h"
#include "psram_allocator.h"

class ConfigurationManager;
class ReportingEngine;
class NetworkEngine;
#include "../protocols/base_plugin.h"

struct PluginStatus {
    std::string name;
    uint64_t events_generated = 0;
};

struct ProtocolInfo {
    ProtocolType type;
    const char*  key;   // e.g. "modbus", "s7", "opcua", "ethernetip", "profinet"
    std::string  name;  // human-friendly, e.g. "Modbus TCP"
};

class PluginManager {
public:
    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep, NetworkEngine* net);
    void shutdown();

    void registerPlugin(std::unique_ptr<BasePlugin> plugin);

    // Template overload to accept plugins with custom deleters (e.g., PSRAM plugins)
    template<typename Deleter>
    void registerPlugin(std::unique_ptr<BasePlugin, Deleter> psram_plugin) {
        if (!psram_plugin) return;

        // Initialize plugin with configuration and reporting engine
        psram_plugin->initialize(cfg_, rep_);

        // Convert to standard unique_ptr with PSRAM-aware deleter preserved
        BasePlugin* raw_ptr = psram_plugin.release();
        Deleter deleter = psram_plugin.get_deleter();

        auto standard_plugin = std::unique_ptr<BasePlugin, std::function<void(BasePlugin*)>>(
            raw_ptr,
            [deleter](BasePlugin* ptr) { deleter(ptr); }
        );

        plugins_.push_back(std::move(standard_plugin));
    }
    std::vector<PluginStatus, PSRAMAllocator<PluginStatus>> getAllPluginStatus() const;

    BasePlugin* findByProtocol(ProtocolType p) const;
    void forEach(const std::function<void(BasePlugin&)>& fn) const;
    size_t pluginCount() const;
    template<typename Allocator>
    void getAllPlugins(std::vector<BasePlugin*, Allocator>& out_plugins) const {
        out_plugins.clear();
        for (auto const& up : plugins_) {
            out_plugins.push_back(up.get());
        }
    }

    // Helper function to convert ProtocolType to string
    static const char* protocolTypeToString(ProtocolType proto) {
        switch (proto) {
            case ProtocolType::MODBUS_TCP:   return "MODBUS_TCP";
            case ProtocolType::S7_COMM:      return "S7_COMM";
            case ProtocolType::OPC_UA:       return "OPC_UA";
            case ProtocolType::ETHERNET_IP:  return "ETHERNET_IP";
            case ProtocolType::PROFINET:     return "PROFINET";
            case ProtocolType::CUSTOM:       return "CUSTOM";
            case ProtocolType::UNKNOWN:
            default:                         return "UNKNOWN";
        }
    }

    static const char* protocolTypeToFriendly(ProtocolType p){
        switch (p) {
            case ProtocolType::MODBUS_TCP:   return "Modbus TCP";
            case ProtocolType::S7_COMM:      return "S7 Communication";
            case ProtocolType::OPC_UA:       return "OPC UA";
            case ProtocolType::ETHERNET_IP:  return "EtherNet/IP";
            case ProtocolType::PROFINET:     return "PROFINET";
            case ProtocolType::CUSTOM:       return "Custom";
            case ProtocolType::UNKNOWN:
            default:                         return "Unknown";
        }
    }

    std::vector<ProtocolInfo, PSRAMAllocator<ProtocolInfo>> listProtocols() const;

private:
    void cacheProtocolInfo(const ProtocolInfo& info);
    mutable std::mutex plugins_mutex_;

private:
    ConfigurationManager* cfg_ = nullptr;
    ReportingEngine* rep_ = nullptr;
    NetworkEngine* net_ = nullptr;
    std::vector<std::unique_ptr<BasePlugin, std::function<void(BasePlugin*)>>, PSRAMAllocator<std::unique_ptr<BasePlugin, std::function<void(BasePlugin*)>>>> plugins_;
    std::vector<ProtocolInfo, PSRAMAllocator<ProtocolInfo>> protocol_cache_;
};
