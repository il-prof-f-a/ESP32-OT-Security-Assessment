#include "assessment/passive_detection_policy.h"
#include <cassert>
#include <vector>
#include <map>
#include <string>

int main() {
    using PassiveDetection::Flags;
    for (unsigned bits = 0; bits < 8; ++bits) {
        const Flags flags = Flags::fromBits(static_cast<uint8_t>(bits));
        assert(flags.bits() == bits);
        for (const bool trusted : {false, true}) {
            std::vector<int> order;
            const bool bypass = PassiveDetection::dispatch(flags,
                [&] { order.push_back(1); },
                [&] { order.push_back(2); return trusted; },
                [&] { order.push_back(3); });
            std::vector<int> expected;
            if (flags.network_presence_enabled) expected.push_back(1);
            if (flags.ids_enabled) expected.push_back(2);
            if (flags.signatures_enabled) expected.push_back(3);
            assert(order == expected); // exactly once, also for unclassified packets
            assert(bypass == (flags.ids_enabled && trusted));
        }
    }
    assert(Flags{}.bits() == 7); // backwards-compatible defaults
    std::map<std::string, bool> configuration;
    auto load = [&] {
        return PassiveDetection::loadFlags([&](const char* path, bool& out) {
            const auto it = configuration.find(path);
            if (it == configuration.end()) return false;
            out = it->second;
            return true;
        });
    };
    assert(load().bits() == 7);
    configuration = {{"advanced_ids.enabled", false}, {"network_presence.enabled", false}};
    assert(load().bits() == 2); // old config does not disable signature matching
    configuration["ids.general.enabled"] = true;
    configuration["ids.network_presence.enabled"] = true;
    configuration["ids.signatures.enabled"] = false;
    assert(load().bits() == 5); // canonical values win over conflicting legacy keys
    configuration.clear();
    assert(load().bits() == 7); // missing values never retain a previous import
    // Toggle each consumer repeatedly; no flag changes either of the others.
    Flags flags{};
    for (unsigned cycle = 0; cycle < 20; ++cycle) {
        flags.ids_enabled = !flags.ids_enabled;
        assert(flags.signatures_enabled && flags.network_presence_enabled);
        flags.signatures_enabled = false;
        flags.network_presence_enabled = false;
        unsigned ids_calls = 0;
        PassiveDetection::dispatch(flags, [] { assert(false); },
            [&] { ++ids_calls; return false; }, [] { assert(false); });
        assert(ids_calls == (flags.ids_enabled ? 1u : 0u));
        flags.signatures_enabled = flags.network_presence_enabled = true;
    }
}
