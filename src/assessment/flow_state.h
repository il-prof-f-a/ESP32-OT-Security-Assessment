/**
 * @file flow_state.h
 * @brief Generic states for the network flow state machine
 *
 * Defines the common states for the flow state machine.
 * Each protocol can extend with specific states in its own
 * protocol_specific_data, but uses these base states for generic tracking.
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_STATE_H
#define FLOW_STATE_H

#include <cstdint>

/**
 * @brief Generic states of a network session/flow
 *
 * Generic state machine applicable to all TCP/IP protocols.
 * Represents the main states of the life cycle of a flow.
 *
 * Typical transitions:
 * INIT -> CONNECTING -> ESTABLISHED -> AUTHENTICATED -> DATA_EXCHANGE -> CLOSING -> CLOSED
 *
 * Error states:
 * - ERROR: error during handshake or communication
 * - TIMEOUT: expired due to inactivity
 */
enum class FlowState : uint8_t {
    /**
     * Flow just created, first packet received
     * Typical transition: INIT -> CONNECTING
     */
    INIT = 0,

    /**
     * Connection handshake in progress
     *
     * Examples:
     * - TCP SYN sent
     * - OPC UA HEL sent, ACK not yet received
     * - S7 COTP CR sent, CC not yet received
     *
     * Typical transition: CONNECTING -> ESTABLISHED
     */
    CONNECTING = 1,

    /**
     * Connection established at transport level
     *
     * Examples:
     * - TCP three-way handshake completed
     * - OPC UA HEL/ACK exchanged
     * - S7 COTP connection established
     * - EtherNet/IP RegisterSession received
     *
     * Typical transition: ESTABLISHED -> AUTHENTICATED (if auth required)
     *                     ESTABLISHED -> DATA_EXCHANGE (if no auth)
     */
    ESTABLISHED = 2,

    /**
     * Active data exchange (for protocols without authentication)
     *
     * Examples:
     * - Modbus TCP: immediately after TCP connection
     * - PROFINET DCP: stateless, always in this state
     *
     * Typical transition: DATA_EXCHANGE -> CLOSING
     */
    DATA_EXCHANGE = 3,

    /**
     * Authentication completed successfully
     *
     * Examples:
     * - OPC UA ActivateSession ACK received
     * - S7 Setup Communication ACK received
     *
     * Typical transition: AUTHENTICATED -> DATA_EXCHANGE
     */
    AUTHENTICATED = 4,

    /**
     * Closing procedure in progress
     *
     * Examples:
     * - TCP FIN sent/received
     * - OPC UA CloseSecureChannel sent
     * - EtherNet/IP UnregisterSession received
     *
     * Typical transition: CLOSING -> CLOSED
     */
    CLOSING = 5,

    /**
     * Flow closed correctly
     * This is a final state, the flow will be removed from the table
     * after the cleanup timeout.
     */
    CLOSED = 6,

    /**
     * Error during handshake or communication
     *
     * Examples:
     * - Repeated malformed packets
     * - OPC UA ERR message received
     * - TCP RST received
     * - Too many protocol errors
     *
     * Final state, the flow will be marked as an error in the logs.
     */
    ERROR = 7,

    /**
     * Flow expired due to inactivity
     *
     * No packet received for a time > configured timeout.
     * Final state, the flow will be removed at the next cleanup.
     */
    TIMEOUT = 8
};

/**
 * @brief Convert FlowState to a readable string
 *
 * @param state State to convert
 * @return Name of the state as a constant string
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
 * @brief Check whether the state is terminal (flow can be removed)
 *
 * Terminal states: CLOSED, ERROR, TIMEOUT
 *
 * @param state State to check
 * @return true if terminal state, false otherwise
 */
inline bool isFlowStateTerminal(FlowState state) {
    return state == FlowState::CLOSED ||
           state == FlowState::ERROR ||
           state == FlowState::TIMEOUT;
}

/**
 * @brief Check whether the state indicates an active connection
 *
 * Active states: ESTABLISHED, DATA_EXCHANGE, AUTHENTICATED
 *
 * @param state State to check
 * @return true if active connection, false otherwise
 */
inline bool isFlowStateActive(FlowState state) {
    return state == FlowState::ESTABLISHED ||
           state == FlowState::DATA_EXCHANGE ||
           state == FlowState::AUTHENTICATED;
}

/**
 * @brief Check whether the state indicates an error or problem
 *
 * Problem states: ERROR, TIMEOUT, CLOSING (potentially)
 *
 * @param state State to check
 * @return true if the state indicates a problem, false otherwise
 */
inline bool isFlowStateProblematic(FlowState state) {
    return state == FlowState::ERROR ||
           state == FlowState::TIMEOUT;
}

/**
 * @brief Get the extended description of the state
 *
 * @param state State to describe
 * @return Textual description of the state
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
 * @brief Example of common transitions for protocols
 *
 * This enum documents the typical transitions for each protocol.
 * It is not used in the code but serves as a reference for implementations.
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
