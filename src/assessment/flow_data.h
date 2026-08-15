/**
 * @file flow_data.h
 * @brief Struttura dati unificata per flussi di rete
 *
 * Combina tutti gli elementi di un flusso:
 * - Chiave identificativa (FlowKey)
 * - Stato macchina (FlowState)
 * - Metriche (FlowMetrics)
 * - Buffer circolare operazioni recenti (PSRAM)
 * - Dati specifici del protocollo (puntatore opaco)
 *
 * ALLOCAZIONE: PSRAM (tutte le stringhe e buffer)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_DATA_H
#define FLOW_DATA_H

#include "flow_key.h"
#include "flow_metrics.h"
#include "flow_label.h"
#include "flow_state.h"
#include "core/psram_allocator.h"
#include <deque>
#include <cstdint>

/**
 * @brief Singola operazione tracciata nel flusso
 *
 * Rappresenta un'azione significativa rilevata nel flusso
 * (es: READ, WRITE, CONTROL, ERROR).
 *
 * ALLOCAZIONE: PSRAM (stringhe usano PSRAMAllocator)
 */
struct FlowOperation {
    /**
     * Tipo operazione (es: "READ", "WRITE", "CONTROL", "ERROR", "DIAGNOSTIC")
     */
    psram_string type;

    /**
     * Dettagli specifici protocollo (es: "FC=0x03 addr=100", "Browse /Root")
     */
    psram_string details;

    /**
     * Timestamp operazione (millisecondi da boot)
     */
    uint32_t timestamp_ms;

    /**
     * Success flag
     */
    bool success;

    /**
     * Costruttore default PSRAM-safe
     */
    FlowOperation(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : type(alloc),
          details(alloc),
          timestamp_ms(0),
          success(true) {}

    /**
     * Costruttore con parametri
     */
    FlowOperation(const char* op_type, const char* op_details,
                 uint32_t timestamp, bool op_success = true,
                 PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : type(op_type, alloc),
          details(op_details, alloc),
          timestamp_ms(timestamp),
          success(op_success) {}
};

/**
 * @brief Struttura dati completa per un flusso di rete
 *
 * Contiene:
 * - Identificazione (FlowKey)
 * - Stato corrente (FlowState)
 * - Metriche accumulate (FlowMetrics)
 * - Buffer circolare operazioni recenti (std::deque in PSRAM)
 * - Puntatore opaco a dati specifici del protocollo
 *
 * ALLOCAZIONE: PSRAM per tutte le allocazioni dinamiche
 */
struct FlowData {
    // ==================== IDENTIFICAZIONE ====================

    /**
     * Chiave identificativa del flusso
     */
    FlowKey key;

    // ==================== STATO ====================

    /**
     * Stato corrente della macchina a stati
     */
    FlowState state;

    // ==================== METRICHE ====================

    /**
     * Metriche accumulate del flusso
     */
    FlowMetrics metrics;

    // ==================== OPERAZIONI RECENTI ====================

    /**
     * Buffer circolare di operazioni recenti
     * Usa std::deque con PSRAMAllocator per allocazione in PSRAM
     * FIFO: quando raggiunge max_operations, rimuove le più vecchie
     */
    std::deque<FlowOperation, PSRAMAllocator<FlowOperation>> recent_operations;

    /**
     * Numero massimo di operazioni da mantenere nel buffer
     * Configurabile (default: 50)
     */
    uint16_t max_operations;

    // ==================== DATI SPECIFICI PROTOCOLLO ====================

    /**
     * Puntatore opaco a dati specifici del protocollo
     *
     * Ogni plugin può allocare la propria struttura dati in PSRAM
     * e memorizzare il puntatore qui.
     *
     * Esempi:
     * - Modbus: ModbusSessionData* (indirizzo unit, registri acceduti, etc.)
     * - S7: S7SessionData* (rack/slot, PDU ref, SZL reads, etc.)
     * - OPC UA: OPCUASessionData* (channel_id, token_id, endpoints, etc.)
     *
     * IMPORTANTE: Il plugin è responsabile di allocare e deallocare
     * questi dati usando heap_caps_malloc(MALLOC_CAP_SPIRAM).
     */
    void* protocol_specific_data;

    /**
     * Funzione di cleanup per protocol_specific_data
     *
     * Il plugin fornisce questa funzione per deallocare i propri dati.
     * Chiamata automaticamente nel distruttore di FlowData.
     *
     * Esempio:
     * void cleanupModbusData(void* data) {
     *     if (data) {
     *         ModbusSessionData* mdata = static_cast<ModbusSessionData*>(data);
     *         heap_caps_free(data);
     *     }
     * }
     */
    typedef void (*CleanupFunc)(void*);
    CleanupFunc cleanup_func;

    // ==================== COSTRUTTORI E DISTRUTTORE ====================

    /**
     * Costruttore default PSRAM-safe
     */
    FlowData(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : key(alloc),
          state(FlowState::INIT),
          metrics(),
          recent_operations(PSRAMAllocator<FlowOperation>()),
          max_operations(50),
          protocol_specific_data(nullptr),
          cleanup_func(nullptr) {}

    /**
     * Distruttore: chiama cleanup function se presente
     */
    ~FlowData() {
        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
            protocol_specific_data = nullptr;
        }
    }

    // Disabilita copia (ha puntatore opaco)
    FlowData(const FlowData&) = delete;
    FlowData& operator=(const FlowData&) = delete;

    // Abilita move
    FlowData(FlowData&& other) noexcept
        : key(std::move(other.key)),
          state(other.state),
          metrics(other.metrics),
          recent_operations(std::move(other.recent_operations)),
          max_operations(other.max_operations),
          protocol_specific_data(other.protocol_specific_data),
          cleanup_func(other.cleanup_func) {
        // Previeni double-free
        other.protocol_specific_data = nullptr;
        other.cleanup_func = nullptr;
    }

    FlowData& operator=(FlowData&& other) noexcept {
        if (this != &other) {
            // Cleanup dati esistenti
            if (protocol_specific_data && cleanup_func) {
                cleanup_func(protocol_specific_data);
            }

            // Move
            key = std::move(other.key);
            state = other.state;
            metrics = other.metrics;
            recent_operations = std::move(other.recent_operations);
            max_operations = other.max_operations;
            protocol_specific_data = other.protocol_specific_data;
            cleanup_func = other.cleanup_func;

            // Previeni double-free
            other.protocol_specific_data = nullptr;
            other.cleanup_func = nullptr;
        }
        return *this;
    }

    // ==================== METODI ====================

    /**
     * @brief Aggiungi operazione al buffer (FIFO)
     *
     * Se il buffer è pieno, rimuove l'operazione più vecchia.
     *
     * @param type Tipo operazione (es: "READ", "WRITE")
     * @param details Dettagli operazione (es: "FC=0x03 addr=100")
     * @param timestamp Timestamp in millisecondi
     * @param success Success flag
     */
    void addOperation(const psram_string& type, const psram_string& details,
                     uint32_t timestamp, bool success = true) {
        PSRAMAllocator<char> alloc;
        FlowOperation op(alloc);
        op.type = type;
        op.details = details;
        op.timestamp_ms = timestamp;
        op.success = success;

        recent_operations.push_back(std::move(op));

        // Mantieni dimensione massima (FIFO)
        while (recent_operations.size() > max_operations) {
            recent_operations.pop_front();
        }
    }

    /**
     * @brief Aggiungi operazione (versione const char*)
     *
     * @param type Tipo operazione
     * @param details Dettagli operazione
     * @param timestamp Timestamp in millisecondi
     * @param success Success flag
     */
    void addOperation(const char* type, const char* details,
                     uint32_t timestamp, bool success = true) {
        PSRAMAllocator<char> alloc;
        psram_string type_str(type, alloc);
        psram_string details_str(details, alloc);
        addOperation(type_str, details_str, timestamp, success);
    }

    /**
     * @brief Cleanup operazioni vecchie (> age_ms)
     *
     * Rimuove operazioni più vecchie di age_ms dal buffer.
     *
     * @param age_ms Età massima in millisecondi
     */
    void cleanupOldOperations(uint32_t age_ms) {
        uint32_t now_ms = esp_timer_get_time() / 1000;

        while (!recent_operations.empty()) {
            const FlowOperation& oldest = recent_operations.front();
            if ((now_ms - oldest.timestamp_ms) > age_ms) {
                recent_operations.pop_front();
            } else {
                break;  // Ordinate per timestamp, se prima non scaduta stop
            }
        }
    }

    /**
     * @brief Ottieni numero operazioni nel buffer
     *
     * @return Numero operazioni presenti
     */
    size_t getOperationCount() const {
        return recent_operations.size();
    }

    /**
     * @brief Verifica se buffer operazioni è pieno
     *
     * @return true se pieno, false altrimenti
     */
    bool isOperationBufferFull() const {
        return recent_operations.size() >= max_operations;
    }

    /**
     * @brief Ottieni ultima operazione
     *
     * @return Puntatore all'ultima operazione, nullptr se buffer vuoto
     */
    const FlowOperation* getLastOperation() const {
        if (recent_operations.empty()) return nullptr;
        return &recent_operations.back();
    }

    /**
     * @brief Conta operazioni per tipo
     *
     * @param type Tipo operazione da contare (es: "READ", "WRITE")
     * @return Numero occorrenze
     */
    uint32_t countOperations(const char* type) const {
        uint32_t count = 0;
        for (const auto& op : recent_operations) {
            if (op.type == type) {
                count++;
            }
        }
        return count;
    }

    /**
     * @brief Conta operazioni fallite
     *
     * @return Numero operazioni con success=false
     */
    uint32_t countFailedOperations() const {
        uint32_t count = 0;
        for (const auto& op : recent_operations) {
            if (!op.success) {
                count++;
            }
        }
        return count;
    }

    /**
     * @brief Alloca dati specifici protocollo
     *
     * Helper per allocare dati in PSRAM.
     *
     * Esempio:
     * ModbusSessionData* data = flow.allocateProtocolData<ModbusSessionData>(cleanupModbusData);
     *
     * @tparam T Tipo struttura dati
     * @param cleanup Funzione di cleanup
     * @return Puntatore alla struttura allocata in PSRAM
     */
    template<typename T>
    T* allocateProtocolData(CleanupFunc cleanup) {
        // Cleanup vecchi dati se presenti
        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
        }

        // Alloca in PSRAM
        T* data = static_cast<T*>(heap_caps_malloc(sizeof(T), MALLOC_CAP_SPIRAM));
        if (data) {
            new (data) T();  // Placement new
            protocol_specific_data = data;
            cleanup_func = cleanup;
        }

        return data;
    }

    /**
     * @brief Ottieni dati specifici protocollo
     *
     * @tparam T Tipo struttura dati
     * @return Puntatore ai dati, nullptr se non allocati
     */
    template<typename T>
    T* getProtocolData() {
        return static_cast<T*>(protocol_specific_data);
    }

    /**
     * @brief Ottieni dati specifici protocollo (const)
     *
     * @tparam T Tipo struttura dati
     * @return Puntatore const ai dati, nullptr se non allocati
     */
    template<typename T>
    const T* getProtocolData() const {
        return static_cast<const T*>(protocol_specific_data);
    }

    /**
     * @brief Verifica se il flusso è scaduto
     *
     * @param timeout_ms Timeout in millisecondi
     * @return true se scaduto, false altrimenti
     */
    bool isExpired(uint32_t timeout_ms) const {
        return metrics.getAge() > timeout_ms;
    }

    /**
     * @brief Verifica se il flusso è in stato terminale
     *
     * @return true se stato terminale (CLOSED, ERROR, TIMEOUT)
     */
    bool isTerminal() const {
        return isFlowStateTerminal(state);
    }

    /**
     * @brief Clear buffer operazioni (mantiene max_operations)
     */
    void clearOperations() {
        recent_operations.clear();
    }

    /**
     * @brief Reset completo del flusso (per riutilizzo)
     */
    void reset() {
        state = FlowState::INIT;
        metrics.reset();
        recent_operations.clear();

        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
            protocol_specific_data = nullptr;
            cleanup_func = nullptr;
        }
    }
};

#endif // FLOW_DATA_H
