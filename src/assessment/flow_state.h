/**
 * @file flow_state.h
 * @brief Stati generici per macchina a stati di flussi di rete
 *
 * Definisce gli stati comuni per la state machine dei flussi.
 * Ogni protocollo può estendere con stati specifici nel proprio
 * protocol_specific_data, ma usa questi stati base per tracking generico.
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_STATE_H
#define FLOW_STATE_H

#include <cstdint>

/**
 * @brief Stati generici di una sessione/flusso di rete
 *
 * State machine generico applicabile a tutti i protocolli TCP/IP.
 * Rappresenta gli stati principali del ciclo di vita di un flusso.
 *
 * Transizioni tipiche:
 * INIT -> CONNECTING -> ESTABLISHED -> AUTHENTICATED -> DATA_EXCHANGE -> CLOSING -> CLOSED
 *
 * Stati di errore:
 * - ERROR: errore durante handshake o comunicazione
 * - TIMEOUT: scaduto per inattività
 */
enum class FlowState : uint8_t {
    /**
     * Flusso appena creato, primo pacchetto ricevuto
     * Transizione tipica: INIT -> CONNECTING
     */
    INIT = 0,

    /**
     * Handshake di connessione in corso
     *
     * Esempi:
     * - TCP SYN inviato
     * - OPC UA HEL inviato, ACK non ancora ricevuto
     * - S7 COTP CR inviato, CC non ancora ricevuto
     *
     * Transizione tipica: CONNECTING -> ESTABLISHED
     */
    CONNECTING = 1,

    /**
     * Connessione stabilita a livello trasporto
     *
     * Esempi:
     * - TCP three-way handshake completato
     * - OPC UA HEL/ACK scambiato
     * - S7 COTP connection established
     * - EtherNet/IP RegisterSession ricevuto
     *
     * Transizione tipica: ESTABLISHED -> AUTHENTICATED (se auth richiesta)
     *                     ESTABLISHED -> DATA_EXCHANGE (se no auth)
     */
    ESTABLISHED = 2,

    /**
     * Scambio dati attivo (per protocolli senza autenticazione)
     *
     * Esempi:
     * - Modbus TCP: immediatamente dopo connessione TCP
     * - PROFINET DCP: stateless, sempre in questo stato
     *
     * Transizione tipica: DATA_EXCHANGE -> CLOSING
     */
    DATA_EXCHANGE = 3,

    /**
     * Autenticazione completata con successo
     *
     * Esempi:
     * - OPC UA ActivateSession ACK ricevuto
     * - S7 Setup Communication ACK ricevuto
     *
     * Transizione tipica: AUTHENTICATED -> DATA_EXCHANGE
     */
    AUTHENTICATED = 4,

    /**
     * Procedura di chiusura in corso
     *
     * Esempi:
     * - TCP FIN inviato/ricevuto
     * - OPC UA CloseSecureChannel inviato
     * - EtherNet/IP UnregisterSession ricevuto
     *
     * Transizione tipica: CLOSING -> CLOSED
     */
    CLOSING = 5,

    /**
     * Flusso chiuso correttamente
     * Questo è uno stato finale, il flusso sarà rimosso dalla tabella
     * dopo il timeout di cleanup.
     */
    CLOSED = 6,

    /**
     * Errore durante handshake o comunicazione
     *
     * Esempi:
     * - Pacchetti malformati ripetuti
     * - OPC UA ERR message ricevuto
     * - TCP RST ricevuto
     * - Troppi errori di protocollo
     *
     * Stato finale, il flusso sarà marcato come errore nei log.
     */
    ERROR = 7,

    /**
     * Flusso scaduto per inattività
     *
     * Nessun pacchetto ricevuto per tempo > timeout configurato.
     * Stato finale, il flusso sarà rimosso al prossimo cleanup.
     */
    TIMEOUT = 8
};

/**
 * @brief Converte FlowState in stringa leggibile
 *
 * @param state Stato da convertire
 * @return Nome dello stato come stringa costante
 */
inline const char* flowStateToString(FlowState state) {
    switch (state) {
        case FlowState::INIT:           return "INIT";
        case FlowState::CONNECTING:     return "CONNECTING";
        case FlowState::ESTABLISHED:    return "ESTABLISHED";
        case FlowState::DATA_EXCHANGE:  return "DATA_EXCHANGE";
        case FlowState::AUTHENTICATED:  return "AUTHENTICATED";
        case FlowState::CLOSING:        return "CLOSING";
        case FlowState::CLOSED:         return "CLOSED";
        case FlowState::ERROR:          return "ERROR";
        case FlowState::TIMEOUT:        return "TIMEOUT";
        default:                        return "UNKNOWN";
    }
}

/**
 * @brief Verifica se lo stato è terminale (flusso può essere rimosso)
 *
 * Stati terminali: CLOSED, ERROR, TIMEOUT
 *
 * @param state Stato da verificare
 * @return true se stato terminale, false altrimenti
 */
inline bool isFlowStateTerminal(FlowState state) {
    return state == FlowState::CLOSED ||
           state == FlowState::ERROR ||
           state == FlowState::TIMEOUT;
}

/**
 * @brief Verifica se lo stato indica connessione attiva
 *
 * Stati attivi: ESTABLISHED, DATA_EXCHANGE, AUTHENTICATED
 *
 * @param state Stato da verificare
 * @return true se connessione attiva, false altrimenti
 */
inline bool isFlowStateActive(FlowState state) {
    return state == FlowState::ESTABLISHED ||
           state == FlowState::DATA_EXCHANGE ||
           state == FlowState::AUTHENTICATED;
}

/**
 * @brief Verifica se lo stato indica errore o problema
 *
 * Stati problema: ERROR, TIMEOUT, CLOSING (potenzialmente)
 *
 * @param state Stato da verificare
 * @return true se stato indica problema, false altrimenti
 */
inline bool isFlowStateProblematic(FlowState state) {
    return state == FlowState::ERROR ||
           state == FlowState::TIMEOUT;
}

/**
 * @brief Ottieni descrizione estesa dello stato
 *
 * @param state Stato da descrivere
 * @return Descrizione testuale dello stato
 */
inline const char* flowStateDescription(FlowState state) {
    switch (state) {
        case FlowState::INIT:
            return "Flow just created, first packet received";

        case FlowState::CONNECTING:
            return "Connection handshake in progress";

        case FlowState::ESTABLISHED:
            return "Connection established at transport level";

        case FlowState::DATA_EXCHANGE:
            return "Active data exchange (no authentication required)";

        case FlowState::AUTHENTICATED:
            return "Authentication completed successfully";

        case FlowState::CLOSING:
            return "Connection closing procedure in progress";

        case FlowState::CLOSED:
            return "Connection closed normally";

        case FlowState::ERROR:
            return "Error occurred during handshake or communication";

        case FlowState::TIMEOUT:
            return "Flow expired due to inactivity";

        default:
            return "Unknown state";
    }
}

/**
 * @brief Esempio di transizioni comuni per protocolli
 *
 * Questa enum documenta le transizioni tipiche per ogni protocollo.
 * Non è usata nel codice ma serve come riferimento per implementazioni.
 */
enum class ProtocolStateTransition {
    // Modbus TCP (stateless)
    // INIT -> ESTABLISHED -> DATA_EXCHANGE -> (TIMEOUT|CLOSED)

    // S7
    // INIT -> CONNECTING (COTP CR) -> ESTABLISHED (COTP CC) ->
    // CONNECTING (S7 Setup) -> AUTHENTICATED (S7 Setup ACK) ->
    // DATA_EXCHANGE -> CLOSING -> CLOSED

    // OPC UA
    // INIT -> CONNECTING (HEL) -> ESTABLISHED (ACK) ->
    // CONNECTING (OPN) -> ESTABLISHED (OPN ACK) ->
    // CONNECTING (CreateSession) -> AUTHENTICATED (ActivateSession) ->
    // DATA_EXCHANGE -> CLOSING (CLO) -> CLOSED

    // EtherNet/IP
    // INIT -> CONNECTING (RegisterSession) -> ESTABLISHED (Session OK) ->
    // DATA_EXCHANGE (SendRRData) -> CLOSING (UnregisterSession) -> CLOSED

    // PROFINET DCP (stateless L2)
    // INIT -> DATA_EXCHANGE -> (TIMEOUT)
};

#endif // FLOW_STATE_H
