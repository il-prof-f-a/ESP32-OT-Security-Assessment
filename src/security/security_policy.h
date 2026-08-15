#pragma once
#include <string>

struct SecurityPolicy {
    bool block_s7_plc_stop = true;   // if true, try to kill sessions where PLC_STOP is observed
    // future: blocklists per IP, protocol-specific toggles
};
