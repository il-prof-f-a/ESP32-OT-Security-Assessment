#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <set>
#include <memory>
using psram_string = std::string;
template<class T> using psram_vector = std::vector<T>;
using psram_string_vector = std::vector<psram_string>;
using psram_string_set = std::set<psram_string>;
namespace PSRAMUtils {
inline psram_string createPSRAMString(const char* value) { return value ? value : ""; }
inline std::string fromPSRAMString(const psram_string& value) { return value; }
struct ScopedBuffer {
    std::unique_ptr<uint8_t[]> data;
    explicit ScopedBuffer(size_t n) : data(new uint8_t[n]) {}
    bool valid() const { return !!data; }
    void* get() { return data.get(); }
};
}
template<class... T> void ignoreLog(T&&...) {}
#define LOG_ERROR(...) ignoreLog(__VA_ARGS__)
#define LOG_ERRORF(...) ignoreLog(__VA_ARGS__)
#define LOG_WARNING(...) ignoreLog(__VA_ARGS__)
#define LOG_WARNINGF(...) ignoreLog(__VA_ARGS__)
#define LOG_INFO(...) ignoreLog(__VA_ARGS__)
#define LOG_INFOF(...) ignoreLog(__VA_ARGS__)
