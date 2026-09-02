#pragma once

#include <cstddef>

// The startup lifecycle event is built from this small, SDK-independent model.
// Keeping the state machine independent from ESP-IDF makes the readiness rules
// executable in host tests and prevents a future service from being advertised
// merely because it appears in a static list.
enum class StartupServiceState {
    Disabled,
    Starting,
    Running,
    Failed,
};

struct StartupServiceStatus {
    const char* name = "";
    StartupServiceState state = StartupServiceState::Disabled;
    bool requested = false;
    const char* reason = "";
};

struct StartupStatusSnapshot {
    const StartupServiceStatus* services = nullptr;
    std::size_t count = 0;
};

constexpr const char* startupServiceStateName(StartupServiceState state) {
    switch (state) {
        case StartupServiceState::Disabled: return "disabled";
        case StartupServiceState::Starting: return "starting";
        case StartupServiceState::Running: return "running";
        case StartupServiceState::Failed: return "failed";
    }
    return "failed";
}

constexpr bool startupSnapshotFullyOperational(StartupStatusSnapshot snapshot) {
    if (!snapshot.services || snapshot.count == 0) return false;
    for (std::size_t i = 0; i < snapshot.count; ++i) {
        const StartupServiceStatus& service = snapshot.services[i];
        if (service.requested && service.state != StartupServiceState::Running) return false;
    }
    return true;
}

constexpr bool startupSnapshotHasFailure(StartupStatusSnapshot snapshot) {
    if (!snapshot.services) return false;
    for (std::size_t i = 0; i < snapshot.count; ++i) {
        if (snapshot.services[i].requested &&
            snapshot.services[i].state == StartupServiceState::Failed) return true;
    }
    return false;
}

constexpr bool startupSnapshotIsStarting(StartupStatusSnapshot snapshot) {
    if (!snapshot.services) return false;
    for (std::size_t i = 0; i < snapshot.count; ++i) {
        if (snapshot.services[i].requested &&
            snapshot.services[i].state == StartupServiceState::Starting) return true;
    }
    return false;
}

constexpr const char* startupSnapshotGlobalState(StartupStatusSnapshot snapshot) {
    if (startupSnapshotFullyOperational(snapshot)) return "fully_operational";
    if (startupSnapshotHasFailure(snapshot)) return "degraded";
    if (startupSnapshotIsStarting(snapshot)) return "starting";
    return "degraded";
}
