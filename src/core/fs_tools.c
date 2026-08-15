// fs_tools.c
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "esp_log.h"
#include "esp_littlefs.h"
#include "esp_err.h"
#include "esp_vfs.h"
#include "esp_system.h"
#include "logging_macros_c.h"


static const char *TAG = "FS_TOOLS";

typedef struct {
    char   path[256];
    size_t size;
} top_file_t;

typedef struct {
    size_t files;
    size_t dirs;
    size_t bytes;
    top_file_t top[5]; // top 5 per dimensione
} fs_stats_t;

static void insert_top(top_file_t top[], const char* path, size_t size){
    for (int i=0;i<5;i++){
        if (size > top[i].size){
            for (int j=4;j>i;j--) top[j] = top[j-1];
            strncpy(top[i].path, path, sizeof(top[i].path)-1);
            top[i].path[sizeof(top[i].path)-1] = '\0';
            top[i].size = size;
            break;
        }
    }
}

static esp_err_t is_in_whitelist(const char* path, const char* const* whitelist, size_t wl_count){
    if (!whitelist || wl_count==0) return ESP_FAIL;
    for (size_t i=0;i<wl_count;i++){
        if (!whitelist[i]) continue;
        if (strncmp(path, whitelist[i], strlen(whitelist[i]))==0) return ESP_OK;
    }
    return ESP_FAIL;
}

static esp_err_t fs_scan_dir(const char* base, fs_stats_t* st){
    DIR *dir = opendir(base);
    if (!dir) return ESP_FAIL;

    struct dirent *ent;
    char path[300];
    while ((ent = readdir(dir)) != NULL){
        if (strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0) continue;
        int n = snprintf(path, sizeof(path), "%s/%s", base, ent->d_name);
        if (n < 0 || n >= (int)sizeof(path)) continue;

        struct stat sb;
        if (stat(path, &sb) == 0){
            if (S_ISDIR(sb.st_mode)){
                st->dirs++;
                fs_scan_dir(path, st);
            } else if (S_ISREG(sb.st_mode)){
                st->files++;
                st->bytes += sb.st_size;
                insert_top(st->top, path, (size_t)sb.st_size);
            }
        }
    }
    closedir(dir);
    return ESP_OK;
}

static esp_err_t fs_rm_rf(const char* base, const char* const* whitelist, size_t wl_count){
    DIR *dir = opendir(base);
    if (!dir) return ESP_FAIL;

    struct dirent *ent;
    char path[300];
    // Prima: rimuovi file
    rewinddir(dir);
    while ((ent = readdir(dir)) != NULL){
        if (strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0) continue;
        snprintf(path, sizeof(path), "%s/%s", base, ent->d_name);
        struct stat sb;
        if (stat(path, &sb) == 0 && S_ISREG(sb.st_mode)){
            if (is_in_whitelist(path, whitelist, wl_count) == ESP_OK){
                LOG_INFOF(TAG, "Preservato (whitelist): %s", path);
                continue;
            }
            if (unlink(path) != 0){
                LOG_WARNINGF(TAG, "unlink fallita: %s", path);
            } else {
                LOG_INFOF(TAG, "Rimosso file: %s", path);
            }
        }
    }
    // Poi: rimuovi directory ricorsivamente
    rewinddir(dir);
    while ((ent = readdir(dir)) != NULL){
        if (strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0) continue;
        snprintf(path, sizeof(path), "%s/%s", base, ent->d_name);
        struct stat sb;
        if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)){
            if (is_in_whitelist(path, whitelist, wl_count) == ESP_OK){
                LOG_INFOF(TAG, "Preservata dir (whitelist): %s", path);
                continue;
            }
            fs_rm_rf(path, whitelist, wl_count);
            if (rmdir(path) != 0){
                LOG_WARNINGF(TAG, "rmdir fallita: %s", path);
            } else {
                LOG_INFOF(TAG, "Rimossa dir: %s", path);
            }
        }
    }
    closedir(dir);
    return ESP_OK;
}

void fs_print_littlefs_report(const char* base_path, const char* part_label){
    size_t total=0, used=0;
    esp_littlefs_info(part_label, &total, &used);
    size_t free = total - used;

    fs_stats_t st = {0};
    memset(&st, 0, sizeof(st));
    fs_scan_dir(base_path, &st);

    LOG_INFOF(TAG, "LittleFS '%s' @ %s", part_label, base_path);
    LOG_INFOF(TAG, " Volume: total=%u, used=%u, free=%u", (unsigned)total, (unsigned)used, (unsigned)free);
    LOG_INFOF(TAG, " Contenuto: files=%u, dirs=%u, bytes_totali=%u", (unsigned)st.files, (unsigned)st.dirs, (unsigned)st.bytes);

    for (int i=0;i<5;i++){
        if (st.top[i].size > 0){
            LOG_INFOF(TAG, "  Top%u: %u B  %s", i+1, (unsigned)st.top[i].size, st.top[i].path);
        }
    }
}

void fs_purge_littlefs(const char* base_path, const char* const* whitelist, size_t wl_count){
    LOG_WARNINGF(TAG, "Pulizia LittleFS in corso su %s ...", base_path);
    fs_rm_rf(base_path, whitelist, wl_count);
    LOG_WARNINGF(TAG, "Pulizia completata.");
}
