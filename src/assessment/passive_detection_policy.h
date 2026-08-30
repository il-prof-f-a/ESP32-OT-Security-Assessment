#pragma once
#include <cstdint>

// One immutable snapshot per packet; no SDK or heap dependencies in the policy.
namespace PassiveDetection {
struct Flags {
    bool ids_enabled = true;
    bool signatures_enabled = true;
    bool network_presence_enabled = true;

    constexpr uint8_t bits() const {
        return static_cast<uint8_t>((ids_enabled ? 1 : 0) |
            (signatures_enabled ? 2 : 0) | (network_presence_enabled ? 4 : 0));
    }
    static constexpr Flags fromBits(uint8_t bits) {
        return {(bits & 1) != 0, (bits & 2) != 0, (bits & 4) != 0};
    }
};

// Global consumers run even for packets without a protocol plugin. Only IDS may
// return a writer-policy bypass; presence alone cannot authorize observed writes.
// A reader returns false for missing/non-boolean fields. Defaults are fresh for
// each import, and canonical keys take precedence over legacy aliases.
template<class ReadBoolean>
Flags loadFlags(ReadBoolean&& read) {
    Flags flags;
    if (!read("ids.general.enabled", flags.ids_enabled))
        read("advanced_ids.enabled", flags.ids_enabled);
    read("ids.signatures.enabled", flags.signatures_enabled);
    if (!read("ids.network_presence.enabled", flags.network_presence_enabled))
        read("network_presence.enabled", flags.network_presence_enabled);
    return flags;
}

template<class Presence, class IDS, class Signatures>
bool dispatch(Flags flags, Presence&& presence, IDS&& ids, Signatures&& signatures) {
    if (flags.network_presence_enabled) presence();
    const bool bypass = flags.ids_enabled ? ids() : false;
    if (flags.signatures_enabled) signatures();
    return bypass;
}
} // namespace PassiveDetection
