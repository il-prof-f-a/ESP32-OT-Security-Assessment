#include "core/boot_sequence.h"

#include <cassert>
#include <cstdint>
#include <vector>

namespace {
struct Context {
    std::vector<int>* events;
    int start_event;
    int stop_event;
    bool start_result;
};

std::uint32_t testClock(void* context) {
    auto* ticks = static_cast<std::uint32_t*>(context);
    return (*ticks)++;
}

bool startPhase(void* opaque) {
    auto* context = static_cast<Context*>(opaque);
    context->events->push_back(context->start_event);
    return context->start_result;
}

void stopPhase(void* opaque) {
    auto* context = static_cast<Context*>(opaque);
    context->events->push_back(context->stop_event);
}
}  // namespace

int main() {
    std::uint32_t ticks = 100;
    std::vector<int> events;
    Context storage{&events, 1, 101, true};
    Context network{&events, 2, 102, false};

    BootSequence sequence(&testClock, &ticks);
    assert(sequence.runRequired("storage", &startPhase, &stopPhase, &storage));
    assert(!sequence.runRequired("network", &startPhase, &stopPhase, &network));
    assert(sequence.aborted());
    assert((events == std::vector<int>{1, 2, 102, 101}));

    const BootPhaseSnapshot* phases = sequence.phases();
    assert(sequence.phaseCount() == 2);
    assert(phases[0].state == BootPhaseState::Running);
    assert(phases[0].started_at_ms == 100);
    assert(phases[0].completed_at_ms == 101);
    assert(phases[1].state == BootPhaseState::Failed);
    assert(phases[1].started_at_ms == 102);
    assert(phases[1].completed_at_ms == 103);

    // A failed boot remains terminal: the injected operation must not be retried.
    assert(!sequence.runRequired("retry", &startPhase, &stopPhase, &storage));
    assert((events == std::vector<int>{1, 2, 102, 101}));
    return 0;
}
