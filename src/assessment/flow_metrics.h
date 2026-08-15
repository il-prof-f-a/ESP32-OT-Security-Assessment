/**
 * @file flow_metrics.h
 * @brief Metriche comuni per flussi di rete
 *
 * Struttura dati che raccoglie tutte le metriche quantitative di un flusso:
 * - Contatori temporali (first/last packet, duration)
 * - Contatori pacchetti e bytes
 * - Contatori operazioni (read/write/control/error)
 * - Velocità calcolate (pps, bps, rps)
 * - Statistiche (avg packet size, request/response ratio)
 * - Classificazione (intensity, labels)
 *
 * ALLOCAZIONE: Stack o PSRAM (nessuna stringa, solo dati numerici)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_METRICS_H
#define FLOW_METRICS_H

#include "flow_label.h"
#include "flow_intensity.h"
#include <cstdint>
#include <cstring>
#include "esp_timer.h"

/**
 * @brief Metriche comuni per tutti i flussi di rete
 *
 * Struttura che contiene tutti i contatori e le metriche calcolate
 * per un flusso. Utilizzata da tutti i protocolli.
 *
 * ALLOCAZIONE: Questa struttura è POD (Plain Old Data) e può essere
 * allocata sia su stack che in PSRAM. Non contiene puntatori o stringhe.
 */
struct FlowMetrics {
    // ==================== TEMPORALE ====================

    /**
     * Timestamp primo pacchetto (millisecondi da boot)
     */
    uint64_t first_packet_ms;

    /**
     * Timestamp ultimo pacchetto (millisecondi da boot)
     */
    uint64_t last_packet_ms;

    /**
     * Calcola durata flusso in millisecondi
     * @return Durata in ms
     */
    uint32_t duration_ms() const {
        if (last_packet_ms < first_packet_ms) return 0;
        return static_cast<uint32_t>(last_packet_ms - first_packet_ms);
    }

    /**
     * Calcola durata flusso in secondi
     * @return Durata in secondi
     */
    float duration_sec() const {
        return duration_ms() / 1000.0f;
    }

    // ==================== CONTATORI PACCHETTI ====================

    /**
     * Numero totale di pacchetti ricevuti
     */
    uint32_t packet_count;

    /**
     * Numero totale di bytes ricevuti
     */
    uint64_t byte_count;

    // ==================== CONTATORI OPERAZIONI ====================

    /**
     * Numero di operazioni di lettura rilevate
     * (es: Modbus Read, S7 Read Variable, OPC UA Read)
     */
    uint32_t read_operations;

    /**
     * Numero di operazioni di scrittura rilevate
     * (es: Modbus Write, S7 Write Variable, OPC UA Write)
     */
    uint32_t write_operations;

    /**
     * Numero di operazioni di controllo rilevate
     * (es: S7 STOP/RESTART, OPC UA Call, ENIP Reset)
     */
    uint32_t control_operations;

    /**
     * Numero di risposte di errore ricevute
     * (es: Modbus Exception, S7 Error, OPC UA Bad StatusCode)
     */
    uint32_t error_responses;

    /**
     * Numero di pacchetti malformati rilevati
     */
    uint32_t malformed_packets;

    // ==================== VELOCITÀ (calcolate) ====================

    /**
     * Packets per second (calcolato su finestra temporale)
     */
    float packets_per_second;

    /**
     * Bytes per second (calcolato su finestra temporale)
     */
    float bytes_per_second;

    /**
     * Requests per second (read + write + control)
     */
    float requests_per_second;

    // ==================== STATISTICHE ====================

    /**
     * Dimensione media pacchetto in bytes
     */
    float avg_packet_size;

    /**
     * Ratio request/response per protocolli request-response
     * Valore atteso ~1.0 per traffico bilanciato
     * > 1.0 indica più request che response (possibile timeout/loss)
     * < 1.0 indica più response che request (anomalo)
     */
    float request_response_ratio;

    // ==================== CLASSIFICAZIONE ====================

    /**
     * Intensità del traffico (calcolata da pps)
     */
    FlowIntensity intensity;

    /**
     * Label primaria assegnata dal plugin
     */
    FlowLabel primary_label;

    /**
     * Label secondaria (opzionale, per classificazione multipla)
     * Default: NORMAL_OPERATION se non usata
     */
    FlowLabel secondary_label;

    // ==================== COSTRUTTORI ====================

    /**
     * Costruttore default: azzera tutte le metriche
     */
    FlowMetrics() {
        memset(this, 0, sizeof(FlowMetrics));
        intensity = FlowIntensity::IDLE;
        primary_label = FlowLabel::NORMAL_OPERATION;
        secondary_label = FlowLabel::NORMAL_OPERATION;
        request_response_ratio = 1.0f;
    }

    // ==================== METODI ====================

    /**
     * @brief Aggiorna velocità calcolate
     *
     * Ricalcola pps, bps, rps basandosi sulla finestra temporale specificata.
     * Tipicamente chiamato periodicamente (es: ogni 60 secondi).
     *
     * @param window_ms Finestra temporale in millisecondi (default: 60000 = 1 min)
     */
    void updateRates(uint32_t window_ms = 60000) {
        if (window_ms == 0) {
            // Evita divisione per zero
            packets_per_second = 0.0f;
            bytes_per_second = 0.0f;
            requests_per_second = 0.0f;
            return;
        }

        float window_sec = window_ms / 1000.0f;

        // Calcola velocità
        packets_per_second = static_cast<float>(packet_count) / window_sec;
        bytes_per_second = static_cast<float>(byte_count) / window_sec;

        uint32_t total_requests = read_operations + write_operations + control_operations;
        requests_per_second = static_cast<float>(total_requests) / window_sec;

        // Calcola avg packet size
        if (packet_count > 0) {
            avg_packet_size = static_cast<float>(byte_count) / static_cast<float>(packet_count);
        } else {
            avg_packet_size = 0.0f;
        }

        // Aggiorna intensità
        intensity = calculateIntensity(packets_per_second);
    }

    /**
     * @brief Aggiorna velocità su rolling window
     *
     * Calcola velocità considerando solo la durata effettiva del flusso,
     * non una finestra fissa. Più preciso per flussi giovani.
     */
    void updateRatesRolling() {
        uint32_t duration = duration_ms();
        if (duration < 1000) {
            // Flusso troppo giovane, usa almeno 1 secondo
            duration = 1000;
        }
        updateRates(duration);
    }

    /**
     * @brief Incrementa contatori per pacchetto ricevuto
     *
     * @param packet_size Dimensione pacchetto in bytes
     */
    void onPacketReceived(uint16_t packet_size) {
        packet_count++;
        byte_count += packet_size;
        last_packet_ms = esp_timer_get_time() / 1000;
    }

    /**
     * @brief Incrementa contatore read operations
     */
    void onReadOperation() {
        read_operations++;
    }

    /**
     * @brief Incrementa contatore write operations
     */
    void onWriteOperation() {
        write_operations++;
    }

    /**
     * @brief Incrementa contatore control operations
     */
    void onControlOperation() {
        control_operations++;
    }

    /**
     * @brief Incrementa contatore error responses
     */
    void onErrorResponse() {
        error_responses++;
    }

    /**
     * @brief Incrementa contatore malformed packets
     */
    void onMalformedPacket() {
        malformed_packets++;
    }

    /**
     * @brief Calcola error rate (% di errori sul totale operazioni)
     *
     * @return Error rate [0.0-1.0], 0.0 = nessun errore, 1.0 = tutti errori
     */
    float getErrorRate() const {
        uint32_t total_ops = read_operations + write_operations + control_operations;
        if (total_ops == 0) return 0.0f;
        return static_cast<float>(error_responses) / static_cast<float>(total_ops);
    }

    /**
     * @brief Calcola write ratio (% di write sul totale r/w)
     *
     * @return Write ratio [0.0-1.0], 0.0 = solo read, 1.0 = solo write
     */
    float getWriteRatio() const {
        uint32_t total_rw = read_operations + write_operations;
        if (total_rw == 0) return 0.0f;
        return static_cast<float>(write_operations) / static_cast<float>(total_rw);
    }

    /**
     * @brief Verifica se il flusso è principalmente reader
     *
     * @return true se > 90% read operations, false altrimenti
     */
    bool isReader() const {
        return write_operations == 0 && read_operations > 0;
    }

    /**
     * @brief Verifica se il flusso è principalmente writer
     *
     * @return true se contiene almeno una write, false altrimenti
     */
    bool isWriter() const {
        return write_operations > 0;
    }

    /**
     * @brief Verifica se il flusso ha troppi errori
     *
     * @param threshold Soglia error rate (default: 0.1 = 10%)
     * @return true se error rate > threshold
     */
    bool hasTooManyErrors(float threshold = 0.1f) const {
        return getErrorRate() > threshold;
    }

    /**
     * @brief Verifica se il flusso è in flooding
     *
     * @return true se intensity == FLOODING
     */
    bool isFlooding() const {
        return intensity == FlowIntensity::FLOODING;
    }

    /**
     * @brief Verifica se il flusso è idle
     *
     * @return true se intensity == IDLE
     */
    bool isIdle() const {
        return intensity == FlowIntensity::IDLE;
    }

    /**
     * @brief Verifica se il flusso è attivo (ha traffico recente)
     *
     * @param timeout_ms Timeout in ms (default: 60000 = 1 min)
     * @return true se ultimo pacchetto < timeout_ms fa
     */
    bool isActive(uint32_t timeout_ms = 60000) const {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        return (now_ms - last_packet_ms) < timeout_ms;
    }

    /**
     * @brief Ottieni età del flusso (tempo dall'ultimo pacchetto)
     *
     * @return Millisecondi dall'ultimo pacchetto
     */
    uint64_t getAge() const {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        if (now_ms < last_packet_ms) return 0;
        return now_ms - last_packet_ms;
    }

    /**
     * @brief Reset metriche (per testing o riutilizzo)
     */
    void reset() {
        memset(this, 0, sizeof(FlowMetrics));
        intensity = FlowIntensity::IDLE;
        primary_label = FlowLabel::NORMAL_OPERATION;
        secondary_label = FlowLabel::NORMAL_OPERATION;
        request_response_ratio = 1.0f;
    }

    /**
     * @brief Merge con altre metriche (per aggregazione)
     *
     * Utile per sommare metriche di più flussi (es: tutti i flussi di un IP).
     *
     * @param other Metriche da sommare
     */
    void merge(const FlowMetrics& other) {
        // Temporale: prendi min/max
        if (other.first_packet_ms < first_packet_ms || first_packet_ms == 0) {
            first_packet_ms = other.first_packet_ms;
        }
        if (other.last_packet_ms > last_packet_ms) {
            last_packet_ms = other.last_packet_ms;
        }

        // Contatori: somma
        packet_count += other.packet_count;
        byte_count += other.byte_count;
        read_operations += other.read_operations;
        write_operations += other.write_operations;
        control_operations += other.control_operations;
        error_responses += other.error_responses;
        malformed_packets += other.malformed_packets;

        // Ricalcola velocità
        updateRatesRolling();
    }
};

#endif // FLOW_METRICS_H
