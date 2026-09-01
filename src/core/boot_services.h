#pragma once

#include <cstddef>

/**
 * Fixed-size rollback stack for app_main startup.
 *
 * Startup must be able to unwind partially-created services without allocating
 * more memory.  Callbacks are registered in startup order and executed exactly
 * once in reverse order.  The context is owned by the caller and must remain
 * valid until rollback() returns.
 */
class BootRollback {
public:
    using CleanupFn = void (*)(void* context);
    static constexpr std::size_t kMaxActions = 24;

    bool track(CleanupFn cleanup, void* context);
    void rollback();

    std::size_t pending() const { return count_; }
    bool rolledBack() const { return rolled_back_; }

private:
    struct Action {
        CleanupFn cleanup = nullptr;
        void* context = nullptr;
    };

    Action actions_[kMaxActions]{};
    std::size_t count_ = 0;
    bool rolled_back_ = false;
};
