#pragma once

#include <cstddef>
#include <cstdint>

#include "core/boot_services.h"

// SDK-independent startup model.  It keeps the production boot order in
// app_main while making lifecycle outcomes and reverse cleanup testable on a
// native host with injected operations and a deterministic clock.
enum class BootPhaseState {
    Pending,
    Starting,
    Running,
    Failed,
    Skipped,
};

struct BootPhaseSnapshot {
    const char* name = "";
    BootPhaseState state = BootPhaseState::Pending;
    bool required = true;
    const char* reason = "";
    std::uint32_t started_at_ms = 0;
    std::uint32_t completed_at_ms = 0;
};

class BootSequence {
public:
    using ClockFn = std::uint32_t (*)(void* context);
    using StartFn = bool (*)(void* context);
    using CleanupFn = BootRollback::CleanupFn;

    static constexpr std::size_t kMaxPhases = 16;

    explicit BootSequence(ClockFn clock = nullptr, void* clock_context = nullptr);

    // Registers cleanup before invoking a start operation.  This preserves the
    // partial-initialization safety rule used by the production startup path.
    bool runRequired(const char* name, StartFn start, CleanupFn cleanup, void* context,
                     const char* failure_reason = "initialization failed");

    // Records the outcome of a production phase whose initializer is kept in
    // app_main.  A false outcome stops the caller; abort() performs cleanup.
    bool recordRequired(const char* name, bool succeeded,
                        const char* failure_reason = "initialization failed");

    bool trackCleanup(CleanupFn cleanup, void* context);
    void abort();

    bool aborted() const { return aborted_; }
    std::size_t phaseCount() const { return phase_count_; }
    const BootPhaseSnapshot* phases() const { return phases_; }

private:
    std::uint32_t now() const;
    BootPhaseSnapshot* beginPhase(const char* name, bool required);
    bool completePhase(BootPhaseSnapshot* phase, bool succeeded, const char* reason);

    BootRollback rollback_;
    ClockFn clock_ = nullptr;
    void* clock_context_ = nullptr;
    BootPhaseSnapshot phases_[kMaxPhases]{};
    std::size_t phase_count_ = 0;
    bool aborted_ = false;
};
