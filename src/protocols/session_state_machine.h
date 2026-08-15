#pragma once

#include <cstdint>
#include "../core/psram_allocator.h"
#include "../assessment/flow_state.h"  // Import FlowState enum

// Forward declarations
struct FlowData;
struct NetworkPacket;

/**
 * SessionStateMachine: Centralized state machine for industrial protocol sessions
 *
 * This module provides a unified state machine that can be shared across all
 * industrial protocol plugins (Modbus TCP, S7, EtherNet/IP, PROFINET, OPC UA).
 * It manages the lifecycle of a protocol session from initialization to closure.
 *
 * State Transitions (uses FlowState from flow_state.h):
 * INIT -> CONNECTING -> ESTABLISHED -> AUTHENTICATED -> DATA_EXCHANGE -> CLOSING -> CLOSED
 *                    \-> ERROR
 *                    \-> TIMEOUT
 *
 * Each protocol plugin can customize the state machine by providing protocol-specific
 * transition logic through callback functions.
 */

enum class SessionEvent : uint8_t {
    // Connection events
    CONNECTION_REQUEST,     // Initial connection attempt (e.g., TCP SYN, RegisterSession)
    CONNECTION_ACCEPTED,    // Connection accepted by server (e.g., TCP SYN-ACK, session handle assigned)
    CONNECTION_REJECTED,    // Connection rejected (e.g., server busy, authentication failed)

    // Authentication events
    AUTH_REQUEST,           // Authentication credentials sent
    AUTH_SUCCESS,           // Authentication successful
    AUTH_FAILURE,           // Authentication failed

    // Data exchange events
    DATA_REQUEST,           // Read/write/diagnostic request sent
    DATA_RESPONSE,          // Valid response received
    DATA_ERROR,             // Error response received (e.g., exception code)

    // Session management events
    KEEPALIVE,              // Keepalive/heartbeat packet
    CLOSE_REQUEST,          // Graceful shutdown initiated
    CLOSE_COMPLETE,         // Shutdown completed

    // Error events
    PROTOCOL_VIOLATION,     // Malformed packet or protocol violation
    TIMEOUT_OCCURRED,       // No activity within timeout period
    UNEXPECTED_PACKET       // Packet received in wrong state
};

struct SessionTransition {
    FlowState from_state;
    SessionEvent event;
    FlowState to_state;
    bool is_valid;

    SessionTransition() : from_state(FlowState::INIT), event(SessionEvent::CONNECTION_REQUEST),
                          to_state(FlowState::INIT), is_valid(false) {}

    SessionTransition(FlowState from, SessionEvent evt, FlowState to)
        : from_state(from), event(evt), to_state(to), is_valid(true) {}
};

/**
 * Protocol-specific callback for validating state transitions
 * Returns true if the transition is allowed for this specific protocol
 */
typedef bool (*ProtocolTransitionValidator)(FlowState current_state,
                                            SessionEvent event,
                                            const NetworkPacket& packet);

/**
 * Protocol-specific callback for extracting events from packets
 * Returns the SessionEvent corresponding to this packet
 */
typedef SessionEvent (*ProtocolEventExtractor)(const NetworkPacket& packet,
                                                FlowState current_state);

class SessionStateMachine {
public:
    SessionStateMachine();
    ~SessionStateMachine() = default;

    /**
     * Register protocol-specific callbacks (optional)
     * If not registered, uses default generic state machine
     */
    void registerProtocolCallbacks(ProtocolEventExtractor extractor,
                                   ProtocolTransitionValidator validator);

    /**
     * Process a packet and update session state
     * Returns true if state changed
     */
    bool processPacket(const NetworkPacket& packet, FlowData& flow);

    /**
     * Manually trigger a state transition (for timeout handling, etc.)
     * Returns true if transition was valid and applied
     */
    bool triggerEvent(SessionEvent event, FlowData& flow);

    /**
     * Check if a transition is valid in the current state
     */
    bool isValidTransition(FlowState current_state, SessionEvent event) const;

    /**
     * Get the next state given current state and event
     * Returns INIT if transition is invalid
     */
    FlowState getNextState(FlowState current_state, SessionEvent event) const;

    /**
     * Get human-readable state name
     */
    static const char* getStateName(FlowState state);

    /**
     * Get human-readable event name
     */
    static const char* getEventName(SessionEvent event);

    /**
     * Check if session is in a terminal state (CLOSED, ERROR, TIMEOUT)
     */
    static bool isTerminalState(FlowState state);

    /**
     * Check if session is in an active data exchange state
     */
    static bool isActiveState(FlowState state);

private:
    // Protocol-specific callbacks (nullptr = use defaults)
    ProtocolEventExtractor event_extractor_;
    ProtocolTransitionValidator transition_validator_;

    // Default state machine transition table
    static const SessionTransition default_transitions_[];
    static const size_t num_default_transitions_;

    /**
     * Default event extraction (generic TCP-based protocol)
     */
    static SessionEvent defaultEventExtractor(const NetworkPacket& packet,
                                              FlowState current_state);

    /**
     * Default transition validation (allows all transitions in default table)
     */
    static bool defaultTransitionValidator(FlowState current_state,
                                          SessionEvent event,
                                          const NetworkPacket& packet);

    /**
     * Apply state transition to flow
     */
    void applyTransition(FlowState new_state, FlowData& flow);
};

// Helper functions for protocol plugins to create SessionEvent from packet data
namespace SessionEventHelpers {
    // Modbus TCP event detection
    SessionEvent extractModbusEvent(const NetworkPacket& packet, FlowState current_state);

    // S7 event detection
    SessionEvent extractS7Event(const NetworkPacket& packet, FlowState current_state);

    // EtherNet/IP event detection
    SessionEvent extractEtherNetIPEvent(const NetworkPacket& packet, FlowState current_state);

    // PROFINET event detection
    SessionEvent extractPROFINETEvent(const NetworkPacket& packet, FlowState current_state);

    // OPC UA event detection
    SessionEvent extractOPCUAEvent(const NetworkPacket& packet, FlowState current_state);
}
