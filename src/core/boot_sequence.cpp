#include "core/boot_sequence.h"

BootSequence::BootSequence(ClockFn clock, void* clock_context)
    : clock_(clock), clock_context_(clock_context) {}

std::uint32_t BootSequence::now() const {
    return clock_ ? clock_(clock_context_) : 0;
}

BootPhaseSnapshot* BootSequence::beginPhase(const char* name, bool required) {
    if (aborted_ || !name || phase_count_ >= kMaxPhases) {
        return nullptr;
    }

    BootPhaseSnapshot& phase = phases_[phase_count_++];
    phase.name = name;
    phase.required = required;
    phase.state = BootPhaseState::Starting;
    phase.started_at_ms = now();
    return &phase;
}

bool BootSequence::completePhase(BootPhaseSnapshot* phase, bool succeeded, const char* reason) {
    if (!phase) {
        return false;
    }
    phase->completed_at_ms = now();
    phase->state = succeeded ? BootPhaseState::Running : BootPhaseState::Failed;
    phase->reason = succeeded ? "ready" : (reason ? reason : "initialization failed");
    return succeeded || !phase->required;
}

bool BootSequence::trackCleanup(CleanupFn cleanup, void* context) {
    return !aborted_ && rollback_.track(cleanup, context);
}

bool BootSequence::runRequired(const char* name, StartFn start, CleanupFn cleanup, void* context,
                               const char* failure_reason) {
    BootPhaseSnapshot* phase = beginPhase(name, true);
    if (!phase) {
        return false;
    }

    if (!start || !trackCleanup(cleanup, context)) {
        (void)completePhase(phase, false, "startup contract unavailable");
        abort();
        return false;
    }

    const bool succeeded = start(context);
    if (!completePhase(phase, succeeded, failure_reason)) {
        abort();
        return false;
    }
    return true;
}

bool BootSequence::recordRequired(const char* name, bool succeeded, const char* failure_reason) {
    return completePhase(beginPhase(name, true), succeeded, failure_reason);
}

void BootSequence::abort() {
    if (aborted_) {
        return;
    }
    aborted_ = true;
    rollback_.rollback();
}
