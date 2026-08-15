#pragma once

#include <map>
#include "psram_allocator.h"

struct EventRecord {
    // canonical fields stored in PSRAM
    psram_string channel;    // "ids","modbus","s7","fuzz","audit"...
    psram_string type;       // "critical","warning","info","anomaly","rate_limit","sandbox_denied"...
    psram_string severity;   // "CRITICAL","HIGH","MEDIUM","LOW","DEBUG" (optional)
    uint64_t    timestamp_ms = 0;
    psram_string src_ip;
    psram_string dst_ip;
    psram_string protocol;   // "MODBUS","S7","OPCUA","PROFINET","ENIP"
    psram_string signature;  // signature ID or code mapping
    psram_string name;       // human title
    psram_string_map ext;    // extra key/values (flat strings)
    psram_string raw_json;   // original JSON payload (optional)
};

enum class EventFormat {
    JSON = 0,
    CEE  = 1,
    LEEF = 2,
    CEF  = 3
};

class EventFormatter {
public:
    static psram_string toJSON(const EventRecord& ev);
    static psram_string toCEE(const EventRecord& ev);   // CEE: {json}
    static psram_string toLEEF(const EventRecord& ev);  // LEEF:2.0|Vendor|Product|Version|EventID| ext
    static psram_string toCEF(const EventRecord& ev);   // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity| extensions

    static psram_string format(const EventRecord& ev, EventFormat f);
};
