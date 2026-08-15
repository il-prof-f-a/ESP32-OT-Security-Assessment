#include "session_state_machine.h"
#include "../assessment/flow_table.h"
#include <cstring>

// Default state machine transition table
// This covers the most common transitions for industrial protocols
const SessionTransition SessionStateMachine::default_transitions_[] = {
    // From INIT
    {FlowState::INIT, SessionEvent::CONNECTION_REQUEST, FlowState::CONNECTING},
    {FlowState::INIT, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // From CONNECTING
    {FlowState::CONNECTING, SessionEvent::CONNECTION_ACCEPTED, FlowState::ESTABLISHED},
    {FlowState::CONNECTING, SessionEvent::CONNECTION_REJECTED, FlowState::ERROR},
    {FlowState::CONNECTING, SessionEvent::TIMEOUT_OCCURRED, FlowState::TIMEOUT},
    {FlowState::CONNECTING, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // From ESTABLISHED
    {FlowState::ESTABLISHED, SessionEvent::AUTH_REQUEST, FlowState::ESTABLISHED},
    {FlowState::ESTABLISHED, SessionEvent::AUTH_SUCCESS, FlowState::AUTHENTICATED},
    {FlowState::ESTABLISHED, SessionEvent::AUTH_FAILURE, FlowState::ERROR},
    {FlowState::ESTABLISHED, SessionEvent::DATA_REQUEST, FlowState::DATA_EXCHANGE},
    {FlowState::ESTABLISHED, SessionEvent::DATA_RESPONSE, FlowState::DATA_EXCHANGE},
    {FlowState::ESTABLISHED, SessionEvent::KEEPALIVE, FlowState::ESTABLISHED},
    {FlowState::ESTABLISHED, SessionEvent::CLOSE_REQUEST, FlowState::CLOSING},
    {FlowState::ESTABLISHED, SessionEvent::TIMEOUT_OCCURRED, FlowState::TIMEOUT},
    {FlowState::ESTABLISHED, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // From AUTHENTICATED
    {FlowState::AUTHENTICATED, SessionEvent::DATA_REQUEST, FlowState::DATA_EXCHANGE},
    {FlowState::AUTHENTICATED, SessionEvent::DATA_RESPONSE, FlowState::DATA_EXCHANGE},
    {FlowState::AUTHENTICATED, SessionEvent::KEEPALIVE, FlowState::AUTHENTICATED},
    {FlowState::AUTHENTICATED, SessionEvent::CLOSE_REQUEST, FlowState::CLOSING},
    {FlowState::AUTHENTICATED, SessionEvent::TIMEOUT_OCCURRED, FlowState::TIMEOUT},
    {FlowState::AUTHENTICATED, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // From DATA_EXCHANGE
    {FlowState::DATA_EXCHANGE, SessionEvent::DATA_REQUEST, FlowState::DATA_EXCHANGE},
    {FlowState::DATA_EXCHANGE, SessionEvent::DATA_RESPONSE, FlowState::DATA_EXCHANGE},
    {FlowState::DATA_EXCHANGE, SessionEvent::DATA_ERROR, FlowState::DATA_EXCHANGE},
    {FlowState::DATA_EXCHANGE, SessionEvent::KEEPALIVE, FlowState::DATA_EXCHANGE},
    {FlowState::DATA_EXCHANGE, SessionEvent::CLOSE_REQUEST, FlowState::CLOSING},
    {FlowState::DATA_EXCHANGE, SessionEvent::TIMEOUT_OCCURRED, FlowState::TIMEOUT},
    {FlowState::DATA_EXCHANGE, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // From CLOSING
    {FlowState::CLOSING, SessionEvent::CLOSE_COMPLETE, FlowState::CLOSED},
    {FlowState::CLOSING, SessionEvent::TIMEOUT_OCCURRED, FlowState::CLOSED},
    {FlowState::CLOSING, SessionEvent::PROTOCOL_VIOLATION, FlowState::ERROR},

    // Terminal states (no transitions out)
    // CLOSED, ERROR, TIMEOUT are terminal
};

const size_t SessionStateMachine::num_default_transitions_ =
    sizeof(default_transitions_) / sizeof(default_transitions_[0]);

SessionStateMachine::SessionStateMachine()
    : event_extractor_(nullptr), transition_validator_(nullptr) {
}

void SessionStateMachine::registerProtocolCallbacks(ProtocolEventExtractor extractor,
                                                   ProtocolTransitionValidator validator) {
    event_extractor_ = extractor;
    transition_validator_ = validator;
}

bool SessionStateMachine::processPacket(const NetworkPacket& packet, FlowData& flow) {
    // Extract event from packet
    SessionEvent event;
    if (event_extractor_) {
        event = event_extractor_(packet, flow.state);
    } else {
        event = defaultEventExtractor(packet, flow.state);
    }

    // Validate transition
    bool valid = false;
    if (transition_validator_) {
        valid = transition_validator_(flow.state, event, packet);
    } else {
        valid = defaultTransitionValidator(flow.state, event, packet);
    }

    if (!valid) {
        // Invalid transition - trigger error
        applyTransition(FlowState::ERROR, flow);
        return true;
    }

    // Get next state
    FlowState next_state = getNextState(flow.state, event);
    if (next_state == FlowState::INIT && flow.state != FlowState::INIT) {
        // Invalid transition (getNextState returns INIT for invalid)
        return false;
    }

    // Apply transition if state changed
    if (next_state != flow.state) {
        applyTransition(next_state, flow);
        return true;
    }

    return false;
}

bool SessionStateMachine::triggerEvent(SessionEvent event, FlowData& flow) {
    // Validate transition
    if (!isValidTransition(flow.state, event)) {
        return false;
    }

    // Get next state
    FlowState next_state = getNextState(flow.state, event);
    if (next_state == FlowState::INIT && flow.state != FlowState::INIT) {
        return false;
    }

    // Apply transition
    if (next_state != flow.state) {
        applyTransition(next_state, flow);
        return true;
    }

    return false;
}

bool SessionStateMachine::isValidTransition(FlowState current_state, SessionEvent event) const {
    for (size_t i = 0; i < num_default_transitions_; ++i) {
        if (default_transitions_[i].from_state == current_state &&
            default_transitions_[i].event == event) {
            return true;
        }
    }
    return false;
}

FlowState SessionStateMachine::getNextState(FlowState current_state, SessionEvent event) const {
    for (size_t i = 0; i < num_default_transitions_; ++i) {
        if (default_transitions_[i].from_state == current_state &&
            default_transitions_[i].event == event) {
            return default_transitions_[i].to_state;
        }
    }
    return FlowState::INIT; // Invalid transition
}

const char* SessionStateMachine::getStateName(FlowState state) {
    switch (state) {
        case FlowState::INIT: return "INIT";
        case FlowState::CONNECTING: return "CONNECTING";
        case FlowState::ESTABLISHED: return "ESTABLISHED";
        case FlowState::AUTHENTICATED: return "AUTHENTICATED";
        case FlowState::DATA_EXCHANGE: return "DATA_EXCHANGE";
        case FlowState::CLOSING: return "CLOSING";
        case FlowState::CLOSED: return "CLOSED";
        case FlowState::ERROR: return "ERROR";
        case FlowState::TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}

const char* SessionStateMachine::getEventName(SessionEvent event) {
    switch (event) {
        case SessionEvent::CONNECTION_REQUEST: return "CONNECTION_REQUEST";
        case SessionEvent::CONNECTION_ACCEPTED: return "CONNECTION_ACCEPTED";
        case SessionEvent::CONNECTION_REJECTED: return "CONNECTION_REJECTED";
        case SessionEvent::AUTH_REQUEST: return "AUTH_REQUEST";
        case SessionEvent::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case SessionEvent::AUTH_FAILURE: return "AUTH_FAILURE";
        case SessionEvent::DATA_REQUEST: return "DATA_REQUEST";
        case SessionEvent::DATA_RESPONSE: return "DATA_RESPONSE";
        case SessionEvent::DATA_ERROR: return "DATA_ERROR";
        case SessionEvent::KEEPALIVE: return "KEEPALIVE";
        case SessionEvent::CLOSE_REQUEST: return "CLOSE_REQUEST";
        case SessionEvent::CLOSE_COMPLETE: return "CLOSE_COMPLETE";
        case SessionEvent::PROTOCOL_VIOLATION: return "PROTOCOL_VIOLATION";
        case SessionEvent::TIMEOUT_OCCURRED: return "TIMEOUT_OCCURRED";
        case SessionEvent::UNEXPECTED_PACKET: return "UNEXPECTED_PACKET";
        default: return "UNKNOWN";
    }
}

bool SessionStateMachine::isTerminalState(FlowState state) {
    return state == FlowState::CLOSED ||
           state == FlowState::ERROR ||
           state == FlowState::TIMEOUT;
}

bool SessionStateMachine::isActiveState(FlowState state) {
    return state == FlowState::DATA_EXCHANGE ||
           state == FlowState::AUTHENTICATED;
}

void SessionStateMachine::applyTransition(FlowState new_state, FlowData& flow) {
    flow.state = new_state;
    // State change timestamp is managed automatically by FlowData
}

SessionEvent SessionStateMachine::defaultEventExtractor(const NetworkPacket& packet,
                                                       FlowState current_state) {
    // Generic TCP-based protocol event extraction
    // This is a simple fallback - protocols should register their own extractors

    if (current_state == FlowState::INIT) {
        return SessionEvent::CONNECTION_REQUEST;
    }

    if (current_state == FlowState::CONNECTING) {
        // Assume first packet after CONNECTING is acceptance
        return SessionEvent::CONNECTION_ACCEPTED;
    }

    if (current_state == FlowState::ESTABLISHED ||
        current_state == FlowState::AUTHENTICATED ||
        current_state == FlowState::DATA_EXCHANGE) {
        // Assume data exchange
        return SessionEvent::DATA_REQUEST;
    }

    return SessionEvent::UNEXPECTED_PACKET;
}

bool SessionStateMachine::defaultTransitionValidator(FlowState current_state,
                                                    SessionEvent event,
                                                    const NetworkPacket& packet) {
    // Default validator just checks if transition exists in table
    for (size_t i = 0; i < num_default_transitions_; ++i) {
        if (default_transitions_[i].from_state == current_state &&
            default_transitions_[i].event == event) {
            return true;
        }
    }
    return false;
}

// ===== Protocol-specific event extractors =====

namespace SessionEventHelpers {

static bool locateIpv4L4Payload(const NetworkPacket& packet,
                                uint8_t expected_proto,
                                const uint8_t*& out,
                                size_t& out_len) {
    out = nullptr;
    out_len = 0;
    if (!packet.data || packet.length == 0) return false;

    // Direct L4 payload (ingestIP / reassembly path)
    if ((packet.data[0] >> 4) != 4 || packet.length < 20) {
        out = packet.data;
        out_len = packet.length;
        return true;
    }

    // IPv4 payload (ingestL2 path)
    const uint8_t* ip = packet.data;
    size_t ip_len = packet.length;
    size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || ihl > ip_len) return false;
    if (expected_proto != 0 && ip[9] != expected_proto) return false;

    if (ip[9] == 6) { // TCP
        if (ip_len < ihl + 20) return false;
        const uint8_t* tcp = ip + ihl;
        size_t doff = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4U;
        if (doff < 20 || ip_len < ihl + doff) return false;
        out = tcp + doff;
        out_len = ip_len - (ihl + doff);
        return true;
    }

    if (ip[9] == 17) { // UDP
        if (ip_len < ihl + 8) return false;
        out = ip + ihl + 8;
        out_len = ip_len - (ihl + 8);
        return true;
    }

    return false;
}

static bool locateOpcuaFrameForState(const NetworkPacket& packet,
                                     const uint8_t*& out,
                                     size_t& out_len) {
    out = nullptr;
    out_len = 0;
    const uint8_t* p = nullptr;
    size_t n = 0;
    if (!locateIpv4L4Payload(packet, 6, p, n) || n < 8) return false;

    uint32_t declared_len = static_cast<uint32_t>(p[4]) |
                            (static_cast<uint32_t>(p[5]) << 8) |
                            (static_cast<uint32_t>(p[6]) << 16) |
                            (static_cast<uint32_t>(p[7]) << 24);
    if (declared_len < 8 || declared_len > 65536 || declared_len > n) return false;
    out = p;
    out_len = n;
    return true;
}

SessionEvent extractModbusEvent(const NetworkPacket& packet, FlowState current_state) {
    if (packet.length < 8) {
        return SessionEvent::PROTOCOL_VIOLATION;
    }

    const uint8_t* data = packet.data;
    // MBAP header: TransactionID(2) + ProtocolID(2) + Length(2) + UnitID(1) + FunctionCode(1)
    uint8_t function_code = data[7];

    // Check for exception response (function code with high bit set)
    if (function_code & 0x80) {
        return SessionEvent::DATA_ERROR;
    }

    // Modbus doesn't have explicit connection management (uses TCP)
    if (current_state == FlowState::INIT || current_state == FlowState::CONNECTING) {
        return SessionEvent::CONNECTION_ACCEPTED;
    }

    // All Modbus packets in established state are data requests/responses
    return SessionEvent::DATA_REQUEST;
}

SessionEvent extractS7Event(const NetworkPacket& packet, FlowState current_state) {
    if (packet.length < 10) {
        return SessionEvent::PROTOCOL_VIOLATION;
    }

    const uint8_t* data = packet.data;
    // TPKT header: Version(1) + Reserved(1) + Length(2)
    // COTP header: Length(1) + PDU-Type(1) + ...
    uint8_t cotp_pdu_type = data[5];

    // Connection Request (0xE0) / Connection Confirm (0xD0)
    if (cotp_pdu_type == 0xE0) {
        return SessionEvent::CONNECTION_REQUEST;
    }
    if (cotp_pdu_type == 0xD0) {
        return SessionEvent::CONNECTION_ACCEPTED;
    }

    // Data Transfer (0xF0)
    if (cotp_pdu_type == 0xF0) {
        if (packet.length < 12) {
            return SessionEvent::PROTOCOL_VIOLATION;
        }
        uint8_t s7_rosctr = data[8]; // S7 ROSCTR (PDU type)

        // 0x01 = Job (request), 0x03 = Ack_Data (response)
        if (s7_rosctr == 0x01) {
            return SessionEvent::DATA_REQUEST;
        }
        if (s7_rosctr == 0x03) {
            return SessionEvent::DATA_RESPONSE;
        }
    }

    // Disconnect Request (0x80)
    if (cotp_pdu_type == 0x80) {
        return SessionEvent::CLOSE_REQUEST;
    }

    return SessionEvent::UNEXPECTED_PACKET;
}

SessionEvent extractEtherNetIPEvent(const NetworkPacket& packet, FlowState current_state) {
    (void)current_state;
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    uint8_t expected_proto = packet.is_tcp ? 6 : (packet.is_udp ? 17 : 0);
    if (!locateIpv4L4Payload(packet, expected_proto, data, data_len) || data_len < 24) {
        return SessionEvent::PROTOCOL_VIOLATION;
    }

    // Encapsulation header: Command(2) + Length(2) + SessionHandle(4) + Status(4) + ...
    uint16_t command = data[0] | (data[1] << 8);
    uint32_t session_handle = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
    uint32_t status = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);

    // RegisterSession (0x0065)
    if (command == 0x0065) {
        if (session_handle == 0) {
            return SessionEvent::CONNECTION_REQUEST;
        } else if (status == 0) {
            return SessionEvent::CONNECTION_ACCEPTED;
        } else {
            return SessionEvent::CONNECTION_REJECTED;
        }
    }

    // UnRegisterSession (0x0066)
    if (command == 0x0066) {
        return SessionEvent::CLOSE_REQUEST;
    }

    // SendRRData (0x006F) - actual data exchange
    if (command == 0x006F) {
        if (status != 0) {
            return SessionEvent::DATA_ERROR;
        }
        return SessionEvent::DATA_REQUEST;
    }

    // ListServices (0x0004), ListIdentity (0x0063) - diagnostic
    if (command == 0x0004 || command == 0x0063) {
        return SessionEvent::DATA_REQUEST;
    }

    return SessionEvent::UNEXPECTED_PACKET;
}

SessionEvent extractPROFINETEvent(const NetworkPacket& packet, FlowState current_state) {
    const uint16_t pn_ethertype_nbo = static_cast<uint16_t>((0x8892u << 8) | (0x8892u >> 8));
    if (packet.ether_type != pn_ethertype_nbo || packet.length < 4) {
        return SessionEvent::PROTOCOL_VIOLATION;
    }

    const uint8_t* data = packet.data;
    // L2 ingest path exposes PROFINET payload directly:
    // FrameID(2) + ServiceID(1) + ServiceType(1) + ...
    uint16_t frame_id = (data[0] << 8) | data[1];

    // DCP frames (0xFEFC - 0xFEFF)
    if (frame_id >= 0xFEFC && frame_id <= 0xFEFF) {
        if (packet.length < 4) {
            return SessionEvent::PROTOCOL_VIOLATION;
        }
        uint8_t service_id = data[2];

        // DCP Identify (0x05) - discovery
        if (service_id == 0x05) {
            return SessionEvent::DATA_REQUEST;
        }

        // DCP Set (0x04) - configuration
        if (service_id == 0x04) {
            return SessionEvent::DATA_REQUEST;
        }

        // DCP Get (0x03) - read configuration
        if (service_id == 0x03) {
            return SessionEvent::DATA_REQUEST;
        }
    }

    // RT Class 1 cyclic data (0xC000 - 0xFAFF)
    if (frame_id >= 0xC000 && frame_id <= 0xFAFF) {
        return SessionEvent::DATA_REQUEST;
    }

    // PROFINET doesn't have explicit session management like TCP protocols
    // All DCP and RT frames are considered data exchange
    if (current_state == FlowState::INIT) {
        return SessionEvent::CONNECTION_ACCEPTED;
    }

    return SessionEvent::DATA_REQUEST;
}

SessionEvent extractOPCUAEvent(const NetworkPacket& packet, FlowState current_state) {
    const uint8_t* data = nullptr;
    size_t data_len = 0;
    if (!locateOpcuaFrameForState(packet, data, data_len) || data_len < 8) {
        return SessionEvent::PROTOCOL_VIOLATION;
    }

    // Hello (HEL)
    if (data[0] == 'H' && data[1] == 'E' && data[2] == 'L') {
        return SessionEvent::CONNECTION_REQUEST;
    }

    // Acknowledge (ACK)
    if (data[0] == 'A' && data[1] == 'C' && data[2] == 'K') {
        return SessionEvent::CONNECTION_ACCEPTED;
    }

    // Error (ERR)
    if (data[0] == 'E' && data[1] == 'R' && data[2] == 'R') {
        if (current_state == FlowState::CONNECTING) {
            return SessionEvent::CONNECTION_REJECTED;
        }
        return SessionEvent::DATA_ERROR;
    }

    // OpenSecureChannel (OPN)
    if (data[0] == 'O' && data[1] == 'P' && data[2] == 'N') {
        if (current_state == FlowState::ESTABLISHED) {
            return SessionEvent::AUTH_REQUEST;
        }
        return SessionEvent::CONNECTION_REQUEST;
    }

    // Message (MSG) - requires payload inspection
    if (data[0] == 'M' && data[1] == 'S' && data[2] == 'G') {
        // Try to detect service type from payload
        std::string payload_str((const char*)data, std::min(data_len, static_cast<size_t>(256)));

        if (payload_str.find("CreateSession") != std::string::npos) {
            if (current_state == FlowState::ESTABLISHED) {
                return SessionEvent::AUTH_REQUEST;
            }
        }

        if (payload_str.find("ActivateSession") != std::string::npos) {
            return SessionEvent::AUTH_SUCCESS;
        }

        if (payload_str.find("CloseSession") != std::string::npos) {
            return SessionEvent::CLOSE_REQUEST;
        }

        // Default to data request
        return SessionEvent::DATA_REQUEST;
    }

    // Close (CLO)
    if (data[0] == 'C' && data[1] == 'L' && data[2] == 'O') {
        return SessionEvent::CLOSE_COMPLETE;
    }

    return SessionEvent::UNEXPECTED_PACKET;
}

} // namespace SessionEventHelpers
