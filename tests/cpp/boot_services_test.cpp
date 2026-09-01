#include "core/boot_services.h"

#include <cassert>
#include <vector>

namespace {
struct Context {
    std::vector<int>* order;
    int id;
};

void record(void* opaque) {
    auto* ctx = static_cast<Context*>(opaque);
    ctx->order->push_back(ctx->id);
}
}

int main() {
    std::vector<int> order;
    Context first{&order, 1};
    Context second{&order, 2};
    Context third{&order, 3};
    BootRollback rollback;

    assert(rollback.track(&record, &first));
    assert(rollback.track(&record, &second));
    assert(rollback.track(&record, &third));
    assert(rollback.pending() == 3);

    rollback.rollback();
    assert((order == std::vector<int>{3, 2, 1}));
    assert(rollback.pending() == 0);

    rollback.rollback();
    assert((order == std::vector<int>{3, 2, 1}));
    assert(!rollback.track(&record, &first));

    BootRollback bounded;
    Context extra{&order, 4};
    for (std::size_t i = 0; i < BootRollback::kMaxActions; ++i) {
        assert(bounded.track(&record, &extra));
    }
    assert(!bounded.track(&record, &extra));
    bounded.rollback();

    return 0;
}
