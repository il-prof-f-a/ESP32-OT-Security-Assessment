#pragma once

#include "../core/types.h"
#include "../core/psram_allocator.h"
#include "flow_data.h"
#include <cstdint>

/**
 * @brief Evento anomalo per correlazione
 */
struct CorrelationEvent {
    uint64_t timestamp_ms = 0;
    psram_string source_ip;
    psram_string dest_ip;
    psram_string attack_type;      // es: "port_scan", "brute_force", "flooding"
    ProtocolType protocol = ProtocolType::UNKNOWN;
    float severity = 0.0f;

    CorrelationEvent()
        : source_ip(PSRAMAllocator<char>()),
          dest_ip(PSRAMAllocator<char>()),
          attack_type(PSRAMAllocator<char>()) {}
};

/**
 * @brief Pattern di attacco correlato rilevato
 */
struct CorrelatedAttack {
    psram_string attack_pattern;   // es: "distributed_scan", "coordinated_flood"
    psram_vector<psram_string> involved_sources;
    psram_vector<psram_string> involved_targets;
    uint32_t event_count = 0;
    uint64_t first_seen_ms = 0;
    uint64_t last_seen_ms = 0;
    float combined_severity = 0.0f;

    CorrelatedAttack()
        : attack_pattern(PSRAMAllocator<char>()),
          involved_sources(PSRAMAllocator<psram_string>()),
          involved_targets(PSRAMAllocator<psram_string>()) {}
};

/**
 * @brief Configurazione correlation engine
 */
struct CorrelationConfig {
    bool enabled = true;
    uint32_t time_window_ms = 60000;          // Finestra temporale correlazione (default: 60s)
    uint32_t min_events_for_correlation = 3;   // Eventi minimi per correlazione
    uint32_t max_events_tracked = 1000;        // Massimo eventi in memoria
    float severity_threshold = 0.5f;           // Soglia severità per considerare evento
    uint32_t event_retention_ms = 300000;      // Ritenzione eventi (default: 5 min)
};

/**
 * @brief Correlation Engine per rilevamento attacchi distribuiti
 *
 * Correla eventi anomali da sessioni/flussi diversi per rilevare:
 * - Port scanning distribuito
 * - Brute-force attacks coordinati
 * - Flooding attacks da più sorgenti
 * - Reconnaissance distribuito
 */
class CorrelationEngine {
public:
    CorrelationEngine();
    ~CorrelationEngine() = default;

    void setConfig(const CorrelationConfig& cfg);
    const CorrelationConfig& getConfig() const { return config_; }

    /**
     * @brief Registra nuovo evento anomalo per correlazione
     */
    void recordEvent(const CorrelationEvent& event);

    /**
     * @brief Esegue analisi correlazione e rileva pattern
     * @param out_attacks Attacchi correlati rilevati
     * @return Numero di attacchi correlati trovati
     */
    uint32_t analyzeCorrelations(psram_vector<CorrelatedAttack>& out_attacks);

    /**
     * @brief Pulisce eventi vecchi oltre retention period
     */
    void cleanupOldEvents();

    /**
     * @brief Reset completo stato correlazione
     */
    void reset();

    /**
     * @brief Ottieni statistiche correlation engine
     */
    uint32_t getTrackedEventCount() const { return events_.size(); }
    uint32_t getTotalEventsProcessed() const { return total_events_processed_; }
    uint32_t getTotalCorrelatedAttacks() const { return total_correlated_attacks_; }

private:
    // Pattern detection helpers
    bool detectDistributedScan(const psram_vector<CorrelationEvent>& events,
                              CorrelatedAttack& out_attack) const;
    bool detectCoordinatedFlood(const psram_vector<CorrelationEvent>& events,
                               CorrelatedAttack& out_attack) const;
    bool detectBruteForceDistributed(const psram_vector<CorrelationEvent>& events,
                                    CorrelatedAttack& out_attack) const;

    // Event grouping helpers
    void groupEventsByTarget(const psram_vector<CorrelationEvent>& events,
                            psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const;
    void groupEventsBySource(const psram_vector<CorrelationEvent>& events,
                            psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const;

    CorrelationConfig config_;
    psram_vector<CorrelationEvent> events_;
    uint32_t total_events_processed_ = 0;
    uint32_t total_correlated_attacks_ = 0;
    uint64_t last_cleanup_ms_ = 0;
};
