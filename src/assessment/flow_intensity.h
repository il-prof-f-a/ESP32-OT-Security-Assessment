/**
 * @file flow_intensity.h
 * @brief Classificazione intensità del traffico di rete
 *
 * Sistema di classificazione dell'intensità di un flusso basato su
 * packets per second (pps). Utilizzato per identificare traffico
 * normale, intenso o flooding.
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_INTENSITY_H
#define FLOW_INTENSITY_H

#include <cstdint>

/**
 * @brief Livelli di intensità del traffico
 *
 * Classificazione basata su packets per second (pps).
 * Le soglie sono configurabili e possono variare per protocollo,
 * ma questi sono i valori di default tipici per reti industriali.
 */
enum class FlowIntensity : uint8_t {
    /**
     * Nessun traffico o traffico sporadico
     * < 1 pps
     *
     * Tipico per:
     * - Connessioni inattive
     * - Polling molto lento
     */
    IDLE = 0,

    /**
     * Traffico basso/normale
     * 1-10 pps
     *
     * Tipico per:
     * - Polling SCADA standard (1-5 sec)
     * - Letture periodiche normali
     */
    LOW = 1,

    /**
     * Traffico medio
     * 10-50 pps
     *
     * Tipico per:
     * - Polling veloce (< 1 sec)
     * - Multiple operazioni per secondo
     * - HMI attivo
     */
    MEDIUM = 2,

    /**
     * Traffico alto
     * 50-200 pps
     *
     * Tipico per:
     * - Real-time control loops
     * - Fast polling multiple devices
     * - Burst di operazioni
     */
    HIGH = 3,

    /**
     * Traffico molto alto
     * 200-1000 pps
     *
     * Tipico per:
     * - Motion control
     * - Multiple concurrent clients
     * - Potenziale scanning intensivo
     */
    VERY_HIGH = 4,

    /**
     * Flooding: traffico anomalo eccessivo
     * > 1000 pps
     *
     * Indica:
     * - Possibile DoS attack
     * - Malfunzionamento client
     * - Loop di rete
     * - Scanning aggressivo
     */
    FLOODING = 5
};

/**
 * @brief Soglie default per classificazione intensità (pps)
 */
struct FlowIntensityThresholds {
    float idle_max;         ///< Max pps per IDLE (default: 1.0)
    float low_max;          ///< Max pps per LOW (default: 10.0)
    float medium_max;       ///< Max pps per MEDIUM (default: 50.0)
    float high_max;         ///< Max pps per HIGH (default: 200.0)
    float very_high_max;    ///< Max pps per VERY_HIGH (default: 1000.0)
    // > very_high_max = FLOODING

    /**
     * Costruttore con valori default
     */
    FlowIntensityThresholds()
        : idle_max(1.0f),
          low_max(10.0f),
          medium_max(50.0f),
          high_max(200.0f),
          very_high_max(1000.0f) {}
};

/**
 * @brief Calcola intensità da packets per second con soglie custom
 *
 * @param pps Velocità del flusso in pps
 * @param thresholds Soglie personalizzate
 * @return FlowIntensity classificato
 */
inline FlowIntensity calculateIntensity(float pps, const FlowIntensityThresholds& thresholds) {
    if (pps < thresholds.idle_max) {
        return FlowIntensity::IDLE;
    } else if (pps < thresholds.low_max) {
        return FlowIntensity::LOW;
    } else if (pps < thresholds.medium_max) {
        return FlowIntensity::MEDIUM;
    } else if (pps < thresholds.high_max) {
        return FlowIntensity::HIGH;
    } else if (pps < thresholds.very_high_max) {
        return FlowIntensity::VERY_HIGH;
    } else {
        return FlowIntensity::FLOODING;
    }
}

/**
 * @brief Calcola intensità da packets per second
 *
 * Usa soglie default per classificazione.
 *
 * @param packets_per_second Velocità del flusso in pps
 * @return FlowIntensity classificato
 */
inline FlowIntensity calculateIntensity(float packets_per_second) {
    FlowIntensityThresholds thresholds;
    return calculateIntensity(packets_per_second, thresholds);
}

/**
 * @brief Converte FlowIntensity in stringa
 *
 * @param intensity Intensità da convertire
 * @return Nome intensità come stringa
 */
inline const char* flowIntensityToString(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "IDLE";
        case FlowIntensity::LOW:        return "LOW";
        case FlowIntensity::MEDIUM:     return "MEDIUM";
        case FlowIntensity::HIGH:       return "HIGH";
        case FlowIntensity::VERY_HIGH:  return "VERY_HIGH";
        case FlowIntensity::FLOODING:   return "FLOODING";
        default:                        return "UNKNOWN";
    }
}

/**
 * @brief Ottieni range pps per intensità
 *
 * @param intensity Intensità
 * @return Stringa descrittiva del range (es: "1-10 pps")
 */
inline const char* flowIntensityRange(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "< 1 pps";
        case FlowIntensity::LOW:        return "1-10 pps";
        case FlowIntensity::MEDIUM:     return "10-50 pps";
        case FlowIntensity::HIGH:       return "50-200 pps";
        case FlowIntensity::VERY_HIGH:  return "200-1000 pps";
        case FlowIntensity::FLOODING:   return "> 1000 pps";
        default:                        return "unknown";
    }
}

/**
 * @brief Verifica se intensità indica possibile anomalia
 *
 * VERY_HIGH e FLOODING sono considerati anomali per reti OT tipiche.
 *
 * @param intensity Intensità da verificare
 * @return true se anomalo, false se normale
 */
inline bool isFlowIntensityAnomalous(FlowIntensity intensity) {
    return intensity == FlowIntensity::VERY_HIGH ||
           intensity == FlowIntensity::FLOODING;
}

/**
 * @brief Verifica se intensità indica flooding
 *
 * @param intensity Intensità da verificare
 * @return true se flooding, false altrimenti
 */
inline bool isFlowIntensityFlooding(FlowIntensity intensity) {
    return intensity == FlowIntensity::FLOODING;
}

/**
 * @brief Ottieni colore suggerito per UI (CSS class)
 *
 * @param intensity Intensità
 * @return Nome classe CSS suggerita
 */
inline const char* flowIntensityColorClass(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "intensity-idle";       // grigio
        case FlowIntensity::LOW:        return "intensity-low";        // verde
        case FlowIntensity::MEDIUM:     return "intensity-medium";     // giallo
        case FlowIntensity::HIGH:       return "intensity-high";       // arancione
        case FlowIntensity::VERY_HIGH:  return "intensity-very-high";  // rosso chiaro
        case FlowIntensity::FLOODING:   return "intensity-flooding";   // rosso scuro
        default:                        return "intensity-unknown";
    }
}

/**
 * @brief Soglie specifiche per protocolli industriali
 *
 * Ogni protocollo può avere caratteristiche di traffico diverse.
 * Queste sono soglie suggerite basate su best practices OT.
 */
namespace ProtocolIntensityThresholds {
    /**
     * Modbus TCP
     * Tipicamente polling lento (1-5 sec), raro > 10 pps
     */
    inline FlowIntensityThresholds modbusDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 0.5f;
        t.low_max = 5.0f;
        t.medium_max = 20.0f;
        t.high_max = 50.0f;
        t.very_high_max = 200.0f;
        return t;
    }

    /**
     * S7 Communication
     * Polling più veloce possibile, ma < 100 pps tipico
     */
    inline FlowIntensityThresholds s7Defaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 100.0f;
        t.very_high_max = 500.0f;
        return t;
    }

    /**
     * PROFINET DCP
     * Discovery burst-based, normale < 10 pps, > 50 anomalo
     */
    inline FlowIntensityThresholds profinetDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 0.1f;
        t.low_max = 5.0f;
        t.medium_max = 20.0f;
        t.high_max = 50.0f;
        t.very_high_max = 100.0f;
        return t;
    }

    /**
     * EtherNet/IP
     * Può avere I/O real-time veloce, > 200 pps possibile
     */
    inline FlowIntensityThresholds ethernetipDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 200.0f;
        t.very_high_max = 1000.0f;
        return t;
    }

    /**
     * OPC UA
     * Subscriptions possono generare traffico sostenuto
     */
    inline FlowIntensityThresholds opcuaDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 200.0f;
        t.very_high_max = 1000.0f;
        return t;
    }
}

#endif // FLOW_INTENSITY_H
