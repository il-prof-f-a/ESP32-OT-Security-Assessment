#include "core/startup_status.h"
#include <string>

int main() {
    const StartupServiceStatus all_running[] = {
        {"network_engine", StartupServiceState::Running, true, "ready"},
        {"plugin_manager", StartupServiceState::Running, true, "ready"},
        {"ids", StartupServiceState::Disabled, false, "disabled by configuration"},
        {"vulnerability_scanner", StartupServiceState::Running, true, "ready"},
        {"web_server", StartupServiceState::Running, true, "accepting connections"},
        {"reporting_engine", StartupServiceState::Running, true, "ready"},
    };
    const StartupStatusSnapshot ready{all_running, sizeof(all_running) / sizeof(all_running[0])};
    if (!startupSnapshotFullyOperational(ready) ||
        startupSnapshotGlobalState(ready) != std::string("fully_operational")) return 1;

    const StartupServiceStatus web_failed[] = {
        {"network_engine", StartupServiceState::Running, true, "ready"},
        {"web_server", StartupServiceState::Failed, true, "server failed to start"},
        {"reporting_engine", StartupServiceState::Running, true, "ready"},
    };
    const StartupStatusSnapshot failed{web_failed, sizeof(web_failed) / sizeof(web_failed[0])};
    if (startupSnapshotFullyOperational(failed) ||
        startupSnapshotGlobalState(failed) != std::string("degraded")) return 2;

    const StartupServiceStatus web_starting[] = {
        {"network_engine", StartupServiceState::Running, true, "ready"},
        {"web_server", StartupServiceState::Starting, true, "waiting for management interface"},
    };
    const StartupStatusSnapshot starting{web_starting, sizeof(web_starting) / sizeof(web_starting[0])};
    if (startupSnapshotFullyOperational(starting) ||
        startupSnapshotGlobalState(starting) != std::string("starting")) return 3;

    return 0;
}
