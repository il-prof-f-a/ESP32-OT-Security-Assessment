#pragma once
#include <cstddef>
#ifdef __cplusplus
extern "C" {
#endif

void fs_print_littlefs_report(const char* base_path, const char* part_label);
// whitelist: array di prefissi di percorso da preservare (può essere NULL/0 per cancellare tutto)
void fs_purge_littlefs(const char* base_path, const char* const* whitelist, size_t wl_count);

#ifdef __cplusplus
}
#endif
