#pragma once

#include <cstddef>

struct OffensiveTestingBoardProfile {
    const char* board_id;
    int default_gpio;
    bool active_high;
    int pull_mode;
    const int* reserved_gpios;
    std::size_t reserved_gpio_count;
};

// Returns the single profile selected by the active PlatformIO board macro.
const OffensiveTestingBoardProfile& getOffensiveTestingBoardProfile();

// Runtime validation for a user-selected interlock pin. Unknown or reserved
// pins are rejected so a configuration cannot silently steal a peripheral pin.
bool isAllowedOffensiveTestingGpio(int gpio);
