#pragma once

class ConfigurationManager;


class ProvisioningCoordinator {
public:
    static bool continueOperationalBoot(ConfigurationManager& config);
};
