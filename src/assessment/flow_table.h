/**
 * @file flow_table.h
 * @brief Tabella hash di flussi di rete in PSRAM
 *
 * Gestisce una hashtable thread-safe di flussi (FlowData) allocata in PSRAM.
 * Fornisce:
 * - Get/Create flussi by key
 * - Cleanup automatico flussi scaduti
 * - Iterazione thread-safe
 * - Statistiche utilizzo
 *
 * ALLOCAZIONE: PSRAM (hashtable + tutti i flussi)
 * THREAD-SAFETY: Mutex-protected per accesso concorrente
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "flow_data.h"
#include "core/psram_allocator.h"
#include "esp_log.h"
#include <unordered_map>
#include <mutex>
#include <functional>

static const char* FLOW_TABLE_TAG = "FlowTable";

/**
 * @brief Tabella hash di flussi allocata in PSRAM
 *
 * Gestisce una collezione di flussi di rete con:
 * - Chiave: psram_string (FlowKey.toString())
 * - Valore: FlowData (struttura completa flusso)
 * - Allocator: PSRAMAllocator (tutta la hashtable in PSRAM)
 * - Thread-safety: std::mutex per protezione accesso concorrente
 *
 * Configurazione:
 * - max_flows: Numero massimo flussi simultanei (default: 1000)
 * - flow_timeout_ms: Timeout inattività prima rimozione (default: 5 min)
 * - cleanup_interval_ms: Intervallo cleanup automatico (default: 1 min)
 *
 * Utilizzo:
 * ```cpp
 * FlowTable table(1000, 300000, 60000);
 *
 * // Get or create flow
 * FlowKey key(...);
 * FlowData* flow = table.getOrCreateFlow(key);
 * if (flow) {
 *     flow->metrics.onPacketReceived(packet_size);
 *     // ...
 * }
 *
 * // Cleanup periodico (da task dedicato)
 * table.periodicCleanup();
 *
 * // Iterazione (es: per export/report)
 * table.forEach([](const FlowData& flow) {
 *     ESP_LOGI("", "Flow: %s", flow.key.toString().c_str());
 * });
 * ```
 */
class FlowTable {
private:
    /**
     * Tipo hashtable con allocatore PSRAM
     *
     * std::unordered_map con:
     * - Key: psram_string
     * - Value: FlowData
     * - Allocator: PSRAMAllocator per pair<const psram_string, FlowData>
     */
    using FlowMap = std::unordered_map<
        psram_string,
        FlowData,
        std::hash<psram_string>,
        std::equal_to<psram_string>,
        PSRAMAllocator<std::pair<const psram_string, FlowData>>
    >;

    /**
     * Hashtable dei flussi (PSRAM)
     */
    FlowMap flows_;

    /**
     * Mutex per protezione accesso concorrente
     */
    mutable std::mutex mutex_;

    // ==================== CONFIGURAZIONE ====================

    /**
     * Numero massimo di flussi simultanei
     * Quando raggiunto, cleanup forzato per liberare spazio
     */
    uint32_t max_flows_;

    /**
     * Intervallo cleanup automatico (millisecondi)
     * Default: 60000 (1 minuto)
     */
    uint32_t cleanup_interval_ms_;

    /**
     * Timeout flusso per inattività (millisecondi)
     * Flussi inattivi > timeout vengono rimossi
     * Default: 300000 (5 minuti)
     */
    uint32_t flow_timeout_ms_;

    /**
     * Timestamp ultimo cleanup (millisecondi da boot)
     */
    uint64_t last_cleanup_ms_;

    // ==================== STATISTICHE ====================

    /**
     * Numero totale flussi creati (dall'avvio)
     */
    uint32_t total_flows_created_;

    /**
     * Numero totale flussi scaduti/rimossi (dall'avvio)
     */
    uint32_t total_flows_expired_;

    /**
     * Numero cleanup forzati per raggiungimento max_flows
     */
    uint32_t forced_cleanups_;

public:
    // ==================== COSTRUTTORE ====================

    /**
     * @brief Costruttore FlowTable
     *
     * @param max_flows Numero massimo flussi (default: 1000)
     * @param flow_timeout_ms Timeout inattività ms (default: 300000 = 5 min)
     * @param cleanup_interval_ms Intervallo cleanup ms (default: 60000 = 1 min)
     */
    FlowTable(uint32_t max_flows = 1000,
              uint32_t flow_timeout_ms = 300000,
              uint32_t cleanup_interval_ms = 60000)
        : flows_(PSRAMAllocator<std::pair<const psram_string, FlowData>>()),
          max_flows_(max_flows),
          cleanup_interval_ms_(cleanup_interval_ms),
          flow_timeout_ms_(flow_timeout_ms),
          last_cleanup_ms_(0),
          total_flows_created_(0),
          total_flows_expired_(0),
          forced_cleanups_(0) {

        ESP_LOGI(FLOW_TABLE_TAG, "FlowTable created: max_flows=%u, timeout=%ums, cleanup_interval=%ums",
                 max_flows_, flow_timeout_ms_, cleanup_interval_ms_);
    }

    /**
     * @brief Distruttore
     *
     * Cleanup di tutti i flussi (chiamate cleanup_func per protocol_specific_data)
     */
    ~FlowTable() {
        std::lock_guard<std::mutex> lock(mutex_);
        flows_.clear();  // Chiama distruttori FlowData che fanno cleanup
        ESP_LOGI(FLOW_TABLE_TAG, "FlowTable destroyed: total_created=%u, total_expired=%u",
                 total_flows_created_, total_flows_expired_);
    }

    // Disabilita copia e move (singleton-like)
    FlowTable(const FlowTable&) = delete;
    FlowTable& operator=(const FlowTable&) = delete;
    FlowTable(FlowTable&&) = delete;
    FlowTable& operator=(FlowTable&&) = delete;

    // ==================== ACCESSO FLUSSI ====================

    /**
     * @brief Ottieni o crea flusso (thread-safe)
     *
     * Se il flusso esiste, aggiorna last_packet_ms.
     * Se non esiste, lo crea e inizializza.
     * Se raggiunto max_flows, forza cleanup prima di creare.
     *
     * @param key Chiave del flusso
     * @return Puntatore al flusso, nullptr se errore
     */
    FlowData* getOrCreateFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Verifica chiave valida
        if (!key.isValid()) {
            ESP_LOGW(FLOW_TABLE_TAG, "getOrCreateFlow: invalid key");
            return nullptr;
        }

        psram_string key_str = key.toString();

        // Cerca flusso esistente
        auto it = flows_.find(key_str);
        if (it != flows_.end()) {
            // Aggiorna last_packet_ms
            it->second.metrics.last_packet_ms = esp_timer_get_time() / 1000;
            return &it->second;
        }

        // Verifica limite
        if (flows_.size() >= max_flows_) {
            ESP_LOGW(FLOW_TABLE_TAG, "Max flows reached (%u), forcing cleanup", max_flows_);
            cleanupExpiredFlows_NoLock(true);  // Force cleanup
            forced_cleanups_++;
        }

        // Crea nuovo flusso
        PSRAMAllocator<char> alloc;
        FlowData new_flow(alloc);
        new_flow.key = key;

        uint64_t now_ms = esp_timer_get_time() / 1000;
        new_flow.metrics.first_packet_ms = now_ms;
        new_flow.metrics.last_packet_ms = now_ms;
        new_flow.state = FlowState::INIT;

        // Inserisci in mappa (move)
        auto insert_result = flows_.emplace(std::move(key_str), std::move(new_flow));
        total_flows_created_++;

        if (!insert_result.second) {
            ESP_LOGE(FLOW_TABLE_TAG, "Failed to insert flow");
            return nullptr;
        }

        ESP_LOGD(FLOW_TABLE_TAG, "Flow created: %s (total active: %u)",
                 key.toDirectionString().c_str(), flows_.size());

        return &insert_result.first->second;
    }

    /**
     * @brief Cleanup periodico dei flussi scaduti
     *
     * Chiamare periodicamente da task dedicato o da main loop.
     * Rimuove flussi:
     * - Inattivi > flow_timeout_ms
     * - In stato terminale (CLOSED, ERROR, TIMEOUT)
     *
     * Thread-safe.
     */
    void periodicCleanup() {
        uint64_t now_ms = esp_timer_get_time() / 1000;

        // Verifica intervallo cleanup
        if ((now_ms - last_cleanup_ms_) < cleanup_interval_ms_) {
            return;  // Troppo presto
        }

        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredFlows_NoLock(false);
        last_cleanup_ms_ = now_ms;
    }

    /**
     * @brief Iterazione thread-safe sui flussi
     *
     * Chiama callback per ogni flusso nella tabella.
     * Il lock è mantenuto durante tutta l'iterazione.
     *
     * ATTENZIONE: Non chiamare getOrCreateFlow() dal callback
     * (deadlock per lock ricorsivo).
     *
     * @param callback Funzione da chiamare per ogni flusso
     */
    template<typename Func>
    void forEach(Func callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : flows_) {
            callback(pair.first, pair.second);
        }
    }

    /**
     * @brief Iterazione thread-safe (const)
     *
     * @param callback Funzione da chiamare per ogni flusso (const ref)
     */
    template<typename Func>
    void forEach(Func callback) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pair : flows_) {
            callback(pair.first, pair.second);
        }
    }

    /**
     * @brief Cerca flusso per chiave (thread-safe)
     *
     * @param key Chiave del flusso
     * @return Puntatore al flusso, nullptr se non trovato
     */
    FlowData* findFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        auto it = flows_.find(key_str);
        return (it != flows_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Cerca flusso per chiave (const)
     *
     * @param key Chiave del flusso
     * @return Puntatore const al flusso, nullptr se non trovato
     */
    const FlowData* findFlow(const FlowKey& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        auto it = flows_.find(key_str);
        return (it != flows_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Rimuovi flusso per chiave (thread-safe)
     *
     * @param key Chiave del flusso
     * @return true se rimosso, false se non trovato
     */
    bool removeFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        size_t removed = flows_.erase(key_str);
        if (removed > 0) {
            total_flows_expired_++;
            ESP_LOGD(FLOW_TABLE_TAG, "Flow removed: %s", key.toDirectionString().c_str());
        }
        return removed > 0;
    }

    // ==================== STATISTICHE ====================

    /**
     * @brief Numero flussi attivi
     *
     * @return Numero flussi nella tabella
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.size();
    }

    /**
     * @brief Verifica se tabella vuota
     *
     * @return true se vuota, false altrimenti
     */
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.empty();
    }

    /**
     * @brief Totale flussi creati (dall'avvio)
     *
     * @return Numero totale flussi creati
     */
    uint32_t getTotalCreated() const { return total_flows_created_; }

    /**
     * @brief Totale flussi scaduti/rimossi (dall'avvio)
     *
     * @return Numero totale flussi rimossi
     */
    uint32_t getTotalExpired() const { return total_flows_expired_; }

    /**
     * @brief Numero cleanup forzati
     *
     * @return Numero volte che cleanup è stato forzato per max_flows
     */
    uint32_t getForcedCleanups() const { return forced_cleanups_; }

    /**
     * @brief Utilizzo percentuale tabella
     *
     * @return Percentuale utilizzo [0.0-1.0]
     */
    float getUsagePercent() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (max_flows_ == 0) return 0.0f;
        return static_cast<float>(flows_.size()) / static_cast<float>(max_flows_);
    }

    // ==================== CONFIGURAZIONE RUNTIME ====================

    /**
     * @brief Imposta numero massimo flussi
     *
     * @param max Nuovo massimo
     */
    void setMaxFlows(uint32_t max) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_flows_ = max;
        ESP_LOGI(FLOW_TABLE_TAG, "Max flows updated: %u", max_flows_);
    }

    /**
     * @brief Imposta timeout flusso
     *
     * @param timeout_ms Nuovo timeout in millisecondi
     */
    void setFlowTimeout(uint32_t timeout_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        flow_timeout_ms_ = timeout_ms;
        ESP_LOGI(FLOW_TABLE_TAG, "Flow timeout updated: %ums", flow_timeout_ms_);
    }

    /**
     * @brief Imposta intervallo cleanup
     *
     * @param interval_ms Nuovo intervallo in millisecondi
     */
    void setCleanupInterval(uint32_t interval_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_interval_ms_ = interval_ms;
        ESP_LOGI(FLOW_TABLE_TAG, "Cleanup interval updated: %ums", cleanup_interval_ms_);
    }

    /**
     * @brief Ottieni configurazione corrente
     *
     * @param max_flows Output: numero massimo flussi
     * @param timeout_ms Output: timeout flusso
     * @param cleanup_interval_ms Output: intervallo cleanup
     */
    void getConfig(uint32_t& max_flows, uint32_t& timeout_ms, uint32_t& cleanup_interval_ms) const {
        std::lock_guard<std::mutex> lock(mutex_);
        max_flows = max_flows_;
        timeout_ms = flow_timeout_ms_;
        cleanup_interval_ms = cleanup_interval_ms_;
    }

    /**
     * @brief Clear completo della tabella (per testing/reset)
     */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = flows_.size();
        flows_.clear();
        total_flows_expired_ += count;
        ESP_LOGI(FLOW_TABLE_TAG, "Table cleared: %u flows removed", count);
    }

private:
    /**
     * @brief Cleanup flussi scaduti (NO LOCK - uso interno)
     *
     * Rimuove flussi:
     * 1. Stati terminali (CLOSED, ERROR, TIMEOUT)
     * 2. Inattivi > flow_timeout_ms
     * 3. Se force=true, rimuove anche flussi > timeout/2 per liberare spazio
     *
     * IMPORTANTE: Il lock DEVE essere già acquisito prima di chiamare.
     *
     * @param force Se true, cleanup aggressivo per liberare spazio
     */
    void cleanupExpiredFlows_NoLock(bool force) {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        auto it = flows_.begin();
        uint32_t removed = 0;

        while (it != flows_.end()) {
            bool should_remove = false;
            FlowData& flow = it->second;

            // Criterio 1: Stato terminale
            if (flow.isTerminal()) {
                should_remove = true;
            }

            // Criterio 2: Timeout normale
            else if (flow.isExpired(flow_timeout_ms_)) {
                should_remove = true;
                // Aggiorna stato prima rimozione
                if (flow.state != FlowState::TIMEOUT) {
                    flow.state = FlowState::TIMEOUT;
                }
            }

            // Criterio 3: Cleanup forzato (se vicini a max_flows)
            else if (force && flows_.size() > max_flows_ * 0.9) {
                // Rimuovi flussi più vecchi (timeout ridotto a metà)
                if (flow.isExpired(flow_timeout_ms_ / 2)) {
                    should_remove = true;
                }
            }

            if (should_remove) {
                ESP_LOGD(FLOW_TABLE_TAG, "Removing flow: %s (state=%s, age=%llums)",
                         flow.key.toDirectionString().c_str(),
                         flowStateToString(flow.state),
                         flow.metrics.getAge());

                it = flows_.erase(it);
                removed++;
                total_flows_expired_++;
            } else {
                ++it;
            }
        }

        if (removed > 0) {
            ESP_LOGI(FLOW_TABLE_TAG, "Cleanup: removed %u flows (active: %u, created: %u, expired: %u)",
                     removed, flows_.size(), total_flows_created_, total_flows_expired_);
        }
    }
};

#endif // FLOW_TABLE_H
