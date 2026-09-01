#pragma once
#include <cstddef>
#ifdef __cplusplus
extern "C" {
#endif

void fs_print_littlefs_report(const char* base_path, const char* part_label);
// Explicit maintenance helper only. It is never invoked automatically during boot.
// whitelist: array of path prefixes to preserve (can be NULL/0 to delete everything)
void fs_purge_littlefs(const char* base_path, const char* const* whitelist, size_t wl_count);

#ifdef __cplusplus
}
#endif
