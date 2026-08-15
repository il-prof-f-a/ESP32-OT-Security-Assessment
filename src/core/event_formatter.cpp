#include "event_formatter.h"
#include <cstdio>
#include <cstring>
extern "C" {
    #include "esp_heap_caps.h"
}

// STL esc() function removed - replaced with C-style escape_json_string()

// C-style JSON string escaping with bounds checking
static int escape_json_string(char* dest, size_t dest_size, const char* src, size_t src_len) {
    if (!dest || !src || dest_size == 0) return -1;

    size_t dest_pos = 0;
    for (size_t i = 0; i < src_len && dest_pos < dest_size - 1; ++i) {
        char c = src[i];

        if (c == '\\' || c == '\"') {
            if (dest_pos + 1 >= dest_size - 1) break; // Need space for \, char, and \0
            dest[dest_pos++] = '\\';
            dest[dest_pos++] = c;
        } else if ((unsigned char)c < 0x20) {
            // Replace control characters with space
            dest[dest_pos++] = ' ';
        } else {
            dest[dest_pos++] = c;
        }
    }

    dest[dest_pos] = '\0';
    return (int)dest_pos;
}

// Static buffer for JSON formatting - allocated in PSRAM for large events
static char* json_format_buffer = nullptr;
static const size_t JSON_FORMAT_BUFFER_SIZE = 8192; // 8KB for event JSON

static void init_json_buffer() {
    if (!json_format_buffer) {
        json_format_buffer = (char*)heap_caps_malloc_prefer(
            JSON_FORMAT_BUFFER_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT, MALLOC_CAP_8BIT);
        if (!json_format_buffer) {
            // Fallback to internal RAM if PSRAM fails
            json_format_buffer = (char*)malloc(JSON_FORMAT_BUFFER_SIZE);
        }
    }
}

psram_string EventFormatter::toJSON(const EventRecord& ev) {
    init_json_buffer();
    if (!json_format_buffer) {
        // Emergency fallback - return minimal JSON
        return PSRAMUtils::createPSRAMString("{\"error\":\"json_buffer_unavailable\"}");
    }

    // Build JSON using snprintf with bounds checking (STL-free core logic)
    size_t offset = 0;
    int written;

    // Helper buffer for escaped strings - use PSRAM to save internal RAM
    static char* escaped_temp = nullptr;
    const size_t ESCAPED_TEMP_SIZE = 512;

    // Start JSON object
    written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset, "{");
    if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
    offset += written;
    if (!escaped_temp) {
        escaped_temp = (char*)heap_caps_malloc(ESCAPED_TEMP_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!escaped_temp) {
            return "[PSRAM_ERROR]"; // Critical: no memory for string escaping
        }
    }

    // Channel field with escaping
    if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                          ev.channel.c_str(), ev.channel.length()) >= 0) {
        written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                          "\"channel\":\"%s\",", escaped_temp);
    } else {
        written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                          "\"channel\":\"[escape_error]\",");
    }
    if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
    offset += written;

    // Type field with escaping
    if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                          ev.type.c_str(), ev.type.length()) >= 0) {
        written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                          "\"type\":\"%s\",", escaped_temp);
    } else {
        written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                          "\"type\":\"[escape_error]\",");
    }
    if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
    offset += written;

    // Optional fields with bounds checking and escaping
    if (!ev.severity.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.severity.c_str(), ev.severity.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"severity\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"severity\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    // Timestamp
    written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                      "\"ts\":%llu,", (unsigned long long)ev.timestamp_ms);
    if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
    offset += written;

    // Optional network fields with escaping
    if (!ev.src_ip.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.src_ip.c_str(), ev.src_ip.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"src\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"src\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    if (!ev.dst_ip.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.dst_ip.c_str(), ev.dst_ip.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"dst\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"dst\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    if (!ev.protocol.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.protocol.c_str(), ev.protocol.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"proto\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"proto\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    // Signature field with escaping
    if (!ev.signature.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.signature.c_str(), ev.signature.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"sig\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"sig\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    // Name field with escaping
    if (!ev.name.empty()) {
        if (escape_json_string(escaped_temp, ESCAPED_TEMP_SIZE,
                              ev.name.c_str(), ev.name.length()) >= 0) {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"name\":\"%s\",", escaped_temp);
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"name\":\"[escape_error]\",");
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    // Raw JSON field - potentially large, truncate if necessary
    if (!ev.raw_json.empty()) {
        size_t remaining = JSON_FORMAT_BUFFER_SIZE - offset - 100; // Reserve 100 bytes for closing
        if (ev.raw_json.length() > remaining - 20) {
            // Truncate raw_json if too large
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"raw\":\"{truncated}\",");
        } else {
            written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset,
                              "\"raw\":%s,", ev.raw_json.c_str());
        }
        if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
        offset += written;
    }

    // Remove trailing comma and close JSON
    if (offset > 1 && json_format_buffer[offset-1] == ',') {
        offset--; // Remove trailing comma
    }
    written = snprintf(json_format_buffer + offset, JSON_FORMAT_BUFFER_SIZE - offset, "}");
    if (written < 0 || offset + written >= JSON_FORMAT_BUFFER_SIZE) goto overflow;
    offset += written;

    return psram_string(json_format_buffer, json_format_buffer + offset);

overflow:
    // Buffer overflow - return truncated JSON
    return PSRAMUtils::createPSRAMString("{\"error\":\"json_too_large\",\"truncated\":true}");
}
psram_string EventFormatter::toCEE(const EventRecord& ev) {
    psram_string result = PSRAMUtils::createPSRAMString("CEE: ");
    result += toJSON(ev);
    return result;
}

static psram_string make_psram_string_from_uint64(uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    return psram_string(buf);
}

static psram_string_map buildExtendedMap(const EventRecord& ev) {
    psram_string_map ext = ev.ext;
    if (!ev.severity.empty()) ext[psram_string("sev")] = ev.severity;
    if (!ev.src_ip.empty())   ext[psram_string("src")] = ev.src_ip;
    if (!ev.dst_ip.empty())   ext[psram_string("dst")] = ev.dst_ip;
    if (!ev.protocol.empty()) ext[psram_string("proto")] = ev.protocol;
    ext[psram_string("channel")] = ev.channel;
    ext[psram_string("ts")] = make_psram_string_from_uint64(ev.timestamp_ms);
    return ext;
}

psram_string EventFormatter::toLEEF(const EventRecord& ev) {
    psram_string out = PSRAMUtils::createPSRAMString("LEEF:2.0|ICSGuard|TPOE-Pro|1.0|");
    const psram_string& event_id = ev.signature.empty() ? ev.type : ev.signature;
    out += event_id;
    out += '|';

    psram_string_map ext = buildExtendedMap(ev);
    if (!ev.name.empty()) {
        ext[psram_string("name")] = ev.name;
    }

    bool first = true;
    for (const auto& kv : ext) {
        if (!first) out += '\t';
        first = false;
        out += kv.first;
        out += '=';
        out += kv.second;
    }
    return out;
}

static psram_string cef_escape(const psram_string& in) {
    psram_string out;
    out.reserve(in.size() * 2);
    for (char c : in) {
        if (c == '|' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

psram_string EventFormatter::toCEF(const EventRecord& ev) {
    psram_string out = PSRAMUtils::createPSRAMString("CEF:0|ICSGuard|TPOE-Pro|1.0|");
    psram_string sig = ev.signature.empty() ? ev.type : ev.signature;
    out += cef_escape(sig);
    out += '|';
    psram_string name = ev.name.empty() ? ev.type : ev.name;
    out += cef_escape(name);
    out += '|';
    if (ev.severity.empty()) {
        out += PSRAMUtils::createPSRAMString("Low|");
    } else {
        out += ev.severity;
        out += '|';
    }

    psram_string_map ext = buildExtendedMap(ev);
    bool first = true;
    for (const auto& kv : ext) {
        if (!first) out += ' ';
        first = false;
        out += kv.first;
        out += '=';
        out += kv.second;
    }
    return out;
}

psram_string EventFormatter::format(const EventRecord& ev, EventFormat f) {
    switch (f) {
        case EventFormat::CEE:  return toCEE(ev);
        case EventFormat::LEEF: return toLEEF(ev);
        case EventFormat::CEF:  return toCEF(ev);
        case EventFormat::JSON:
        default: return toJSON(ev);
    }
}
