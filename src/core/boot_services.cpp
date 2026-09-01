#include "boot_services.h"

bool BootRollback::track(CleanupFn cleanup, void* context) {
    if (rolled_back_ || !cleanup || count_ >= kMaxActions) {
        return false;
    }
    actions_[count_++] = Action{cleanup, context};
    return true;
}

void BootRollback::rollback() {
    if (rolled_back_) {
        return;
    }
    rolled_back_ = true;

    while (count_ > 0) {
        Action action = actions_[--count_];
        actions_[count_] = Action{};
        if (action.cleanup) {
            action.cleanup(action.context);
        }
    }
}
