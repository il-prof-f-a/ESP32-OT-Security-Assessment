#pragma once

#include "../core/psram_allocator.h"
#include "esp_err.h"
#include <cstddef>

extern "C" {
#include "cJSON.h"
}

namespace SignatureReloadAPI {

inline constexpr size_t NVS_CHUNK_SIZE = 3800;

esp_err_t saveChunkedToNVS(const char* ns, const char* base_key, const psram_string& data);
esp_err_t loadChunkedFromNVS(const char* ns, const char* base_key, psram_string& output);

cJSON* handleSignatureList();
cJSON* handleSignatureUpload(const char* json_data, size_t data_len, bool append = true);
cJSON* handleSignatureDownload();
cJSON* handleSignatureClear();
cJSON* handleSignatureReload(const char* client_ip = nullptr);
cJSON* handleSignatureStats();
cJSON* handleSignatureSave(const char* json_data, size_t data_len, const char* client_ip = nullptr);

} // namespace SignatureReloadAPI
