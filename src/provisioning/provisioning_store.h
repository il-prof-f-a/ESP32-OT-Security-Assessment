#pragma once

#include "provisioning_types.h"

class ConfigurationManager;


class ProvisioningStore {
public:
    enum class FaultPoint : uint8_t {
        NONE,
        AFTER_CONFIG_WRITE,
        AFTER_HASH_WRITE,
        AFTER_READBACK,
        BEFORE_COMPLETE_MARKER,
    };

    ProvisioningState inspect(ConfigurationManager& config) const;
    bool migrateLegacyIfValid(ConfigurationManager& config);
    bool commit(const ProvisioningSubmission& submission,
                const psram_string& admin_hash,
                ConfigurationManager& config);
    bool clearCompletionMarker();
    bool factoryReset();
    void setFaultPointForTesting(FaultPoint point) { fault_point_ = point; }

private:
    bool shouldFail(FaultPoint point) const { return fault_point_ == point; }
    FaultPoint fault_point_ = FaultPoint::NONE;
};
