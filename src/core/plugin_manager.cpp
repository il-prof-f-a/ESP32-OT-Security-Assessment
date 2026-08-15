
#include "plugin_manager.h"
#include "logging_system.h"
#include "../protocols/base_plugin.h"
#include "psram_allocator.h"
#include "audit_manager.h"
#include <algorithm>

bool PluginManager::initialize(ConfigurationManager* cfg, ReportingEngine* rep, NetworkEngine* net) {
    cfg_=cfg; rep_=rep; net_=net;
    LOG_INFO("Plugins","PluginManager initialized");
    return true;
}

void PluginManager::shutdown() {
    LOG_INFO("Plugins","PluginManager shutdown");

    // AUDIT: Log each plugin shutdown event
    {
        std::lock_guard<std::mutex> lock(plugins_mutex_);
        for (const auto& plugin : plugins_) {
            if (plugin) {
                const char* plugin_name = plugin->getName().empty() ? "unnamed_plugin" : plugin->getName().c_str();
                AuditManager::getInstance().logPluginEvent(plugin_name, "stopped", "Plugin shutdown during PluginManager shutdown");
            }
        }
        plugins_.clear();
        protocol_cache_.clear();
    }
}

void PluginManager::registerPlugin(std::unique_ptr<BasePlugin> plugin){
    if (!plugin) return;

    // AUDIT: Log plugin start event
    const char* plugin_name = plugin->getName().empty() ? "unnamed_plugin" : plugin->getName().c_str();
    AuditManager::getInstance().logPluginEvent(plugin_name, "registered", "Plugin registered and initialized in PluginManager");

    // Initialize plugin with configuration and reporting engine
    plugin->initialize(cfg_, rep_);

    const ProtocolType type = plugin->getProtocolType();
    const std::string friendly = plugin->getName().empty()
        ? std::string(protocolTypeToFriendly(type))
        : plugin->getName();
    ProtocolInfo info{ type, protocolTypeToString(type), friendly };

    // Convert to uniform internal storage format with standard deleter
    BasePlugin* raw_ptr = plugin.release();
    auto standard_plugin = std::unique_ptr<BasePlugin, std::function<void(BasePlugin*)>>(
        raw_ptr,
        [](BasePlugin* ptr) { delete ptr; }
    );

    {
        std::lock_guard<std::mutex> lock(plugins_mutex_);
        plugins_.push_back(std::move(standard_plugin));
        cacheProtocolInfo(info);
    }
}

std::vector<ProtocolInfo, PSRAMAllocator<ProtocolInfo>> PluginManager::listProtocols() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    LOG_INFOF("Plugins", "Listing protocols from %zu plugin slots", plugins_.size());
    LOG_INFOF("Plugins", "Returning %zu cached protocol entries", protocol_cache_.size());
    return protocol_cache_;
}

std::vector<PluginStatus, PSRAMAllocator<PluginStatus>> PluginManager::getAllPluginStatus() const {
    std::vector<PluginStatus, PSRAMAllocator<PluginStatus>> v;
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    for (auto const& up : plugins_) {
        PluginStatus st;
        st.name = up->getName();
        st.events_generated = up->getEventsGenerated();
        v.push_back(st);
    }
    return v;
}

BasePlugin* PluginManager::findByProtocol(ProtocolType p) const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    for (auto const& up : plugins_) {
        if (up->getProtocolType() == p) return up.get();
    }
    return nullptr;
}

void PluginManager::forEach(const std::function<void(BasePlugin&)>& fn) const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    size_t slot = 0;
    for (auto const& up : plugins_) {
        if (!up) {
            LOG_WARNINGF("Plugins", "Skipping null plugin pointer at slot %zu", slot);
        } else {
            fn(*up);
        }
        ++slot;
    }
}

size_t PluginManager::pluginCount() const {
    std::lock_guard<std::mutex> lock(plugins_mutex_);
    return plugins_.size();
}

void PluginManager::cacheProtocolInfo(const ProtocolInfo& info) {
    const auto cmp = [](const ProtocolInfo& a, const ProtocolInfo& b) {
        return (uint8_t)a.type < (uint8_t)b.type;
    };

    auto it = std::lower_bound(protocol_cache_.begin(), protocol_cache_.end(), info, cmp);
    if (it == protocol_cache_.end() || it->type != info.type) {
        protocol_cache_.insert(it, info);
    } else if (!info.name.empty()) {
        it->name = info.name;
    }
}
