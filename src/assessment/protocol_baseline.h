/**
 * @file protocol_baseline.h
 * @brief Sistema di baseline per rilevamento anomalie nei protocolli industriali
 *
 * Questo modulo mantiene una baseline del comportamento normale per ciascun protocollo,
 * apprendendo da traffico legittimo e rilevando deviazioni anomale.
 *
 * ALLOCAZIONE: PSRAM (tutte le strutture dati)
 *
 * @date 2025-10-25
 * @version 1.0
 */

#pragma once

#include <cstdint>
#include <map>
#include "../core/psram_allocator.h"
#include "../core/types.h"
#include "flow_state.h"
#include "flow_label.h"

/**
 * @brief Statistiche baseline per un singolo endpoint
 *
 * Traccia il comportamento normale di un dispositivo nella rete industriale
 */
struct EndpointBaseline {
    // Identificazione endpoint
    psram_string ip_address;
    psram_string mac_address;

    // Contatori traffico normale
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

    // Distribuzione operazioni (READ/WRITE/CONTROL)
    uint32_t read_operations = 0;
    uint32_t write_operations = 0;
    uint32_t control_operations = 0;
    uint32_t diagnostic_operations = 0;

    // Tasso di errori normale
    uint32_t error_responses = 0;
    float normal_error_rate = 0.0f;  // Percentuale di errori attesa

    // Stati visitati normalmente (bitmap)
    uint16_t normal_states_bitmap = 0;  // Bit per ogni FlowState

    // Intensità traffico normale (packets per second)
    float avg_pps = 0.0f;
    float max_pps = 0.0f;

    // Peer normali (dispositivi con cui comunica)
    psram_vector<psram_string> known_peers;

    // Timestamp statistiche
    uint64_t first_seen_ms = 0;
    uint64_t last_updated_ms = 0;
    uint32_t learning_samples = 0;  // Numero di campioni usati per learning

    // Flag
    bool is_writer = false;        // Dispositivo autorizzato a scrivere
    bool learning_complete = false;  // Baseline stabilizzata

    EndpointBaseline() {
        PSRAMAllocator<char> alloc;
        ip_address = psram_string(alloc);
        mac_address = psram_string(alloc);
        known_peers = psram_vector<psram_string>(alloc);
    }
};

/**
 * @brief Baseline globale per un protocollo
 *
 * Contiene statistiche aggregate e pattern normali per l'intero protocollo
 */
struct ProtocolBaseline {
    ProtocolType protocol;

    // Endpoint tracciati (IP -> baseline)
    psram_map<psram_string, EndpointBaseline> endpoints;

    // Transizioni di stato normali (state_from << 8 | state_to) -> count
    psram_map<uint16_t, uint32_t> normal_state_transitions;

    // Sequenze di operazioni comuni (hash -> count)
    // Hash calcolato da sequenza tipo: "READ,READ,WRITE"
    psram_map<uint32_t, uint32_t> operation_sequences;

    // Statistiche globali
    uint64_t total_flows = 0;
    uint64_t total_packets = 0;

    // Threshold anomalie (deviazioni standard)
    float pps_threshold_factor = 3.0f;       // Soglia per rate anomalo (mean + N*stddev)
    float error_rate_threshold = 0.1f;       // Soglia percentuale errori
    float peer_change_threshold = 0.3f;      // Soglia cambio peer (30% nuovi peer)

    // Learning
    uint32_t min_learning_samples = 100;     // Campioni minimi per baseline
    uint64_t learning_window_ms = 3600000;   // Finestra learning (1 ora)
    bool learning_enabled = true;

    // Persistenza
    uint64_t last_saved_ms = 0;
    uint32_t save_interval_ms = 300000;      // Salva ogni 5 minuti

    ProtocolBaseline() {
        PSRAMAllocator<char> alloc;
        endpoints = psram_map<psram_string, EndpointBaseline>(alloc);
        normal_state_transitions = psram_map<uint16_t, uint32_t>(alloc);
        operation_sequences = psram_map<uint32_t, uint32_t>(alloc);
    }
};

/**
 * @brief Tipo di anomalia rilevata
 */
enum class AnomalyType : uint8_t {
    NONE = 0,

    // Anomalie di traffico
    UNUSUAL_TRAFFIC_RATE,      // Rate pacchetti anomalo (troppo alto/basso)
    EXCESSIVE_ERRORS,          // Troppi errori
    FLOODING,                  // Flooding rilevato

    // Anomalie comportamentali
    UNEXPECTED_WRITER,         // Dispositivo non autorizzato scrive
    UNUSUAL_PEER,              // Comunicazione con peer sconosciuto
    STATE_VIOLATION,           // Transizione stato invalida
    OPERATION_SEQUENCE_ANOMALY, // Sequenza operazioni anomala

    // Anomalie temporali
    TRAFFIC_AT_UNUSUAL_TIME,   // Traffico in orari insoliti
    SUDDEN_TRAFFIC_SPIKE,      // Picco improvviso

    // Anomalie di protocollo
    MALFORMED_PATTERN,         // Pattern malformato
    PROTOCOL_DOWNGRADE,        // Tentativo downgrade sicurezza

    // Anomalie di sicurezza
    RECONNAISSANCE,            // Scanning/enumeration
    PRIVILEGE_ESCALATION,      // Tentativo escalation privilegi
    DATA_EXFILTRATION          // Possibile esfiltrazione dati
};

/**
 * @brief Dettagli anomalia rilevata
 */
struct AnomalyDetection {
    AnomalyType type;
    float severity;            // 0.0-1.0 (0=info, 1=critico)
    float confidence;          // 0.0-1.0 (fiducia nella detection)

    psram_string endpoint_ip;
    psram_string description;
    psram_string evidence;     // Dati evidenza (es: "rate=1000pps, baseline=10pps")

    uint64_t timestamp_ms;

    AnomalyDetection() {
        PSRAMAllocator<char> alloc;
        endpoint_ip = psram_string(alloc);
        description = psram_string(alloc);
        evidence = psram_string(alloc);
    }
};

/**
 * @brief Gestore baseline e anomaly detection per protocolli industriali
 */
class ProtocolBaselineManager {
public:
    ProtocolBaselineManager();
    ~ProtocolBaselineManager() = default;

    /**
     * @brief Inizializza il baseline manager per un protocollo
     */
    bool initialize(ProtocolType protocol);

    /**
     * @brief Carica baseline da storage persistente
     */
    bool loadBaseline(const char* filepath);

    /**
     * @brief Salva baseline su storage persistente
     */
    bool saveBaseline(const char* filepath);

    /**
     * @brief Aggiorna baseline con nuovi dati (learning)
     *
     * @param endpoint_ip IP endpoint
     * @param mac_address MAC endpoint
     * @param packet_size Dimensione pacchetto
     * @param operation_type Tipo operazione (READ/WRITE/etc)
     * @param is_error true se risposta errore
     * @param current_state Stato flusso corrente
     * @param peer_ip IP peer comunicazione
     */
    bool updateBaseline(const psram_string& endpoint_ip,
                        const psram_string& mac_address,
                        uint32_t packet_size,
                        const psram_string& operation_type,
                        bool is_error,
                        FlowState current_state,
                        const psram_string& peer_ip);

    /**
     * @brief Rileva anomalie confrontando con baseline
     *
     * @param endpoint_ip IP da analizzare
     * @param current_pps Rate pacchetti corrente
     * @param error_rate Tasso errori corrente
     * @param operation_type Tipo operazione
     * @param current_state Stato flusso
     * @param peer_ip IP peer
     * @param anomalies [out] Anomalie rilevate
     * @return Numero anomalie rilevate
     */
    uint32_t detectAnomalies(const psram_string& endpoint_ip,
                            float current_pps,
                            float error_rate,
                            const psram_string& operation_type,
                            FlowState current_state,
                            const psram_string& peer_ip,
                            psram_vector<AnomalyDetection>& anomalies);

    /**
     * @brief Verifica se endpoint è in fase learning
     */
    bool isLearning(const psram_string& endpoint_ip) const;

    /**
     * @brief Forza completamento learning per endpoint
     */
    void completeLearning(const psram_string& endpoint_ip);

    /**
     * @brief Resetta baseline (per testing o dopo incident)
     */
    void resetBaseline();

    /**
     * @brief Ottieni baseline corrente (read-only)
     */
    const ProtocolBaseline& getBaseline() const { return baseline_; }

    /**
     * @brief Abilita/disabilita learning automatico
     */
    void setLearningEnabled(bool enabled) { baseline_.learning_enabled = enabled; }

    /**
     * @brief Imposta threshold detection
     */
    void setThresholds(float pps_factor, float error_rate, float peer_change) {
        baseline_.pps_threshold_factor = pps_factor;
        baseline_.error_rate_threshold = error_rate;
        baseline_.peer_change_threshold = peer_change;
    }

    /**
     * @brief Taratura automatica soglie basata su baseline appreso
     * @param endpoint_ip Endpoint da calibrare (vuoto = tutti)
     * @return true se almeno un endpoint è stato calibrato
     */
    bool autoTuneThresholds(const psram_string& endpoint_ip = psram_string(PSRAMAllocator<char>()));

    /**
     * @brief Ottieni statistiche learning per endpoint
     */
    bool getLearningStats(const psram_string& endpoint_ip,
                         float& out_avg_pps,
                         float& out_stddev_pps,
                         float& out_error_rate,
                         uint32_t& out_samples) const;

private:
    ProtocolBaseline baseline_;

    // Helper per calcolo hash sequenze operazioni
    uint32_t hashOperationSequence(const psram_vector<psram_string>& ops) const;

    // Helper per verifica transizioni stato
    bool isNormalStateTransition(FlowState from, FlowState to) const;

    // Helper per calcolo statistiche
    float calculateMean(const psram_vector<float>& values) const;
    float calculateStdDev(const psram_vector<float>& values, float mean) const;
};
