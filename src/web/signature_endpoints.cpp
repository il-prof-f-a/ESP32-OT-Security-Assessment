#include "signature_reload_api.h"

#include "../assessment/signature_detector.h"
#include "../core/audit_manager.h"
#include "../core/async_storage_engine.h"
#include "../core/psram_allocator.h"
#include "../core/types.h"

#include <cstring>

namespace SignatureReloadAPI {

namespace {

const char* mapProtocolName(const char* name) {
    if (!name) {
        return "";
    }
    if (strcmp(name, "Modbus_TCP") == 0) return "Modbus TCP";
    if (strcmp(name, "S7comm") == 0 || strcmp(name, "S7_Comm") == 0) return "S7comm/S7comm+";
    if (strcmp(name, "OPC_UA") == 0) return "OPC UA";
    if (strcmp(name, "EtherNet_IP") == 0) return "EtherNet/IP";
    if (strcmp(name, "PROFINET") == 0) return "PROFINET";
    return name;
}

} // namespace

esp_err_t saveChunkedToNVS(const char* ns, const char* base_key, const psram_string& data) {
    (void)base_key; // base key retained for compatibility but not used in chunked variant

    const size_t data_len = data.size();
    const size_t num_chunks = (data_len + NVS_CHUNK_SIZE - 1) / NVS_CHUNK_SIZE;

    char meta_key[16];
    snprintf(meta_key, sizeof(meta_key), "sig_cnt");
    esp_err_t err = AsyncStorage::Global::nvsSet(ns, meta_key, (uint32_t)num_chunks);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < num_chunks; ++i) {
        const size_t offset = i * NVS_CHUNK_SIZE;
        const size_t chunk_len = (i == num_chunks - 1) ? (data_len - offset) : NVS_CHUNK_SIZE;

        psram_string chunk = PSRAMUtils::createPSRAMString(data.c_str() + offset, chunk_len);

        char chunk_key[16];
        snprintf(chunk_key, sizeof(chunk_key), "sig_%u", (unsigned)i);

        err = AsyncStorage::Global::nvsSet(ns, chunk_key, chunk);
        if (err != ESP_OK) {
            for (size_t j = 0; j < i; ++j) {
                char cleanup_key[16];
                snprintf(cleanup_key, sizeof(cleanup_key), "sig_%u", (unsigned)j);
                AsyncStorage::Global::nvsEraseKey(ns, cleanup_key);
            }
            AsyncStorage::Global::nvsEraseKey(ns, meta_key);
            return err;
        }
    }

    return ESP_OK;
}

esp_err_t loadChunkedFromNVS(const char* ns, const char* base_key, psram_string& output) {
    (void)base_key;

    char meta_key[16];
    snprintf(meta_key, sizeof(meta_key), "sig_cnt");

    uint32_t num_chunks = 0;
    esp_err_t err = AsyncStorage::Global::nvsGet(ns, meta_key, num_chunks);
    if (err != ESP_OK) {
        return err;
    }

    if (num_chunks == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    output.clear();
    output.reserve(num_chunks * NVS_CHUNK_SIZE);

    for (uint32_t i = 0; i < num_chunks; ++i) {
        char chunk_key[16];
        snprintf(chunk_key, sizeof(chunk_key), "sig_%lu", static_cast<unsigned long>(i));

        psram_string chunk;
        err = AsyncStorage::Global::nvsGet(ns, chunk_key, chunk);
        if (err != ESP_OK) {
            output.clear();
            return err;
        }

        output += chunk;
    }

    return ESP_OK;
}

cJSON* handleSignatureList() {
    psram_string signatures_json;
    esp_err_t err = loadChunkedFromNVS("signatures", "signatures_db", signatures_json);

    if (err != ESP_OK) {
        err = AsyncStorage::Global::nvsGet("signatures", "signatures_db", signatures_json);
    }

    if (err != ESP_OK) {
        cJSON* response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No signatures found in NVS");
        return response;
    }

    if (signatures_json.empty()) {
        cJSON* response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Empty signatures data");
        return response;
    }

    cJSON* root = cJSON_Parse(signatures_json.c_str());
    if (!root) {
        cJSON* response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    return root;
}

cJSON* handleSignatureUpload(const char* json_data, size_t data_len, bool append) {
    cJSON* response = cJSON_CreateObject();

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* uploaded = cJSON_ParseWithLength(json_data, data_len);
    if (!uploaded) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* signatures_data = cJSON_GetObjectItem(uploaded, "signatures");
    cJSON* original_uploaded = uploaded;
    if (signatures_data) {
        uploaded = cJSON_Duplicate(signatures_data, true);
        cJSON_Delete(original_uploaded);
    }

    cJSON* final_json = nullptr;
    uint32_t signatures_added = 0;

    if (append) {
        psram_string existing_json;
        esp_err_t err = loadChunkedFromNVS("signatures", "signatures_db", existing_json);

        if (err != ESP_OK) {
            err = AsyncStorage::Global::nvsGet("signatures", "signatures_db", existing_json);
        }

        if (err == ESP_OK && !existing_json.empty()) {
            final_json = cJSON_Parse(existing_json.c_str());
        }

        if (!final_json) {
            final_json = cJSON_CreateObject();
        }

        cJSON* protocol = nullptr;
        cJSON_ArrayForEach(protocol, uploaded) {
            const char* original_name = protocol->string;
            if (!original_name) {
                continue;
            }

            const char* mapped_name = mapProtocolName(original_name);

            cJSON* existing_protocol = cJSON_GetObjectItem(final_json, mapped_name);
            if (!existing_protocol) {
                existing_protocol = cJSON_CreateObject();
                cJSON_AddItemToObject(final_json, mapped_name, existing_protocol);
            }

            cJSON* existing_vulns = cJSON_GetObjectItem(existing_protocol, "Vulnerabilities");
            if (!existing_vulns) {
                existing_vulns = cJSON_CreateArray();
                cJSON_AddItemToObject(existing_protocol, "Vulnerabilities", existing_vulns);
            }

            cJSON* uploaded_vulns = cJSON_GetObjectItem(protocol, "Vulnerabilities");
            if (uploaded_vulns && cJSON_IsArray(uploaded_vulns)) {
                cJSON* vuln = nullptr;
                cJSON_ArrayForEach(vuln, uploaded_vulns) {
                    cJSON_AddItemToArray(existing_vulns, cJSON_Duplicate(vuln, true));
                    signatures_added++;
                }
            }
        }
    } else {
        final_json = cJSON_CreateObject();

        cJSON* protocol = nullptr;
        cJSON_ArrayForEach(protocol, uploaded) {
            const char* original_name = protocol->string;
            if (!original_name) {
                continue;
            }

            const char* mapped_name = mapProtocolName(original_name);
            cJSON_AddItemToObject(final_json, mapped_name, cJSON_Duplicate(protocol, true));

            cJSON* vulns = cJSON_GetObjectItem(protocol, "Vulnerabilities");
            if (vulns && cJSON_IsArray(vulns)) {
                signatures_added += cJSON_GetArraySize(vulns);
            }
        }
    }

    char* json_string = cJSON_Print(final_json);
    if (json_string) {
        psram_string psram_json = PSRAMUtils::createPSRAMString(json_string);
        esp_err_t save_err = saveChunkedToNVS("signatures", "signatures_db", psram_json);

        if (save_err == ESP_OK) {
            cJSON_AddBoolToObject(response, "success", true);
            cJSON_AddStringToObject(response, "message", append ? "Signatures uploaded and merged" : "Signatures uploaded and replaced");
            cJSON_AddNumberToObject(response, "signatures_added", signatures_added);

            SignatureDetection::SignatureDetector::getInstance().reloadSignatures();
        } else {
            cJSON_AddBoolToObject(response, "success", false);
            cJSON_AddStringToObject(response, "message", "Failed to save to NVS");
        }

        free(json_string);
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "JSON generation failed");
    }

    if (!signatures_data) {
        cJSON_Delete(uploaded);
    }
    cJSON_Delete(final_json);

    return response;
}

cJSON* handleSignatureDownload() {
    return handleSignatureList();
}

cJSON* handleSignatureClear() {
    cJSON* response = cJSON_CreateObject();

    psram_string empty_json = PSRAMUtils::createPSRAMString("{}");
    esp_err_t err = saveChunkedToNVS("signatures", "signatures_db", empty_json);

    if (err == ESP_OK) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "All signatures cleared");
        SignatureDetection::SignatureDetector::getInstance().reloadSignatures();
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to clear signatures");
    }

    return response;
}

cJSON* handleSignatureReload(const char* client_ip) {
    cJSON* response = cJSON_CreateObject();

    auto& detector = SignatureDetection::SignatureDetector::getInstance();
    bool success = detector.reloadSignatures();

    cJSON_AddBoolToObject(response, "success", success);

    if (success) {
        uint32_t total = detector.getTotalSignatures();
        cJSON_AddStringToObject(response, "message", "Signatures reloaded successfully");
        cJSON_AddNumberToObject(response, "signatures_loaded", total);
        AuditManager::getInstance().logSecurityEvent("signature_reload", "api", client_ip, "Hot-reload successful");
    } else {
        cJSON_AddStringToObject(response, "message", "Failed to reload signatures from NVS");
        cJSON_AddNumberToObject(response, "signatures_loaded", 0);
        AuditManager::getInstance().logSecurityEvent("signature_reload_failed", "api", client_ip, "Hot-reload failed");
    }

    return response;
}

cJSON* handleSignatureStats() {
    cJSON* response = cJSON_CreateObject();
    auto& detector = SignatureDetection::SignatureDetector::getInstance();

    uint32_t total = detector.getTotalSignatures();
    cJSON_AddNumberToObject(response, "total", total);

    cJSON* by_protocol = cJSON_CreateObject();
    cJSON_AddNumberToObject(by_protocol, "Modbus_TCP", detector.getSignaturesForProtocol(ProtocolType::MODBUS_TCP));
    cJSON_AddNumberToObject(by_protocol, "PROFINET", detector.getSignaturesForProtocol(ProtocolType::PROFINET));
    cJSON_AddNumberToObject(by_protocol, "S7comm", detector.getSignaturesForProtocol(ProtocolType::S7_COMM));
    cJSON_AddNumberToObject(by_protocol, "OPC_UA", detector.getSignaturesForProtocol(ProtocolType::OPC_UA));
    cJSON_AddNumberToObject(by_protocol, "EtherNet_IP", detector.getSignaturesForProtocol(ProtocolType::ETHERNET_IP));

    cJSON_AddItemToObject(response, "by_protocol", by_protocol);

    return response;
}

cJSON* handleSignatureSave(const char* json_data, size_t data_len, const char* client_ip) {
    cJSON* response = cJSON_CreateObject();

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* new_signatures = cJSON_ParseWithLength(json_data, data_len);
    if (!new_signatures) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* signatures_obj = cJSON_GetObjectItem(new_signatures, "signatures");
    if (!signatures_obj) {
        cJSON_Delete(new_signatures);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing 'signatures' field");
        return response;
    }

    uint32_t signatures_saved = 0;

    char* json_string = cJSON_Print(signatures_obj);
    if (json_string) {
        psram_string psram_json = PSRAMUtils::createPSRAMString(json_string);
        esp_err_t save_err = saveChunkedToNVS("signatures", "signatures_db", psram_json);

        if (save_err == ESP_OK) {
            cJSON* protocol = nullptr;
            cJSON_ArrayForEach(protocol, signatures_obj) {
                cJSON* vulns = cJSON_GetObjectItem(protocol, "Vulnerabilities");
                if (vulns && cJSON_IsArray(vulns)) {
                    signatures_saved += cJSON_GetArraySize(vulns);
                }
            }

            cJSON_AddBoolToObject(response, "success", true);
            cJSON_AddStringToObject(response, "message", "Signatures saved successfully");
            cJSON_AddNumberToObject(response, "signatures_saved", signatures_saved);

            SignatureDetection::SignatureDetector::getInstance().reloadSignatures();
            AuditManager::getInstance().logSecurityEvent("signature_save", "api", client_ip, "Manual save successful");
        } else {
            cJSON_AddBoolToObject(response, "success", false);
            cJSON_AddStringToObject(response, "message", "Failed to save to NVS");
        }

        free(json_string);
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "JSON generation failed");
    }

    cJSON_Delete(new_signatures);
    return response;
}

} // namespace SignatureReloadAPI
