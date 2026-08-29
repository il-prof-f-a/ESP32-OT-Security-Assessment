#include "opcua_binary_codec.h"
#include "opcua_x509_parser.h"
#include "../core/logging_system.h"
#include <cstring>
#include <ctime>

extern "C" {
    #include "esp_timer.h"
}

#define TAG_OPCUA_CODEC "OPCUACodec"

// ==================== ENCODING PRIMITIVES ====================

void OPCUABinaryCodec::encodeUInt8(psram_vector<uint8_t>& buf, uint8_t value) {
    buf.push_back(value);
}

void OPCUABinaryCodec::encodeUInt16(psram_vector<uint8_t>& buf, uint16_t value) {
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void OPCUABinaryCodec::encodeUInt32(psram_vector<uint8_t>& buf, uint32_t value) {
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void OPCUABinaryCodec::encodeUInt64(psram_vector<uint8_t>& buf, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void OPCUABinaryCodec::encodeInt32(psram_vector<uint8_t>& buf, int32_t value) {
    encodeUInt32(buf, static_cast<uint32_t>(value));
}

void OPCUABinaryCodec::encodeInt64(psram_vector<uint8_t>& buf, int64_t value) {
    encodeUInt64(buf, static_cast<uint64_t>(value));
}

void OPCUABinaryCodec::encodeString(psram_vector<uint8_t>& buf, const char* str) {
    if (!str) {
        // Null string -> length = -1
        encodeInt32(buf, -1);
        return;
    }

    int32_t len = static_cast<int32_t>(strlen(str));
    encodeInt32(buf, len);
    if (len > 0) {
        for (int32_t i = 0; i < len; ++i) {
            buf.push_back(static_cast<uint8_t>(str[i]));
        }
    }
}

void OPCUABinaryCodec::encodeString(psram_vector<uint8_t>& buf, const psram_string& str) {
    if (str.empty()) {
        encodeInt32(buf, 0);
        return;
    }
    encodeString(buf, str.c_str());
}

void OPCUABinaryCodec::encodeByteString(psram_vector<uint8_t>& buf, const uint8_t* data, int32_t len) {
    if (!data || len < 0) {
        encodeInt32(buf, -1);
        return;
    }

    encodeInt32(buf, len);
    for (int32_t i = 0; i < len; ++i) {
        buf.push_back(data[i]);
    }
}

void OPCUABinaryCodec::encodeArrayLength(psram_vector<uint8_t>& buf, int32_t count) {
    encodeInt32(buf, count);
}

// ==================== DECODING PRIMITIVES ====================

uint8_t OPCUABinaryCodec::decodeUInt8(const uint8_t* data, size_t& offset) {
    return data[offset++];
}

uint16_t OPCUABinaryCodec::decodeUInt16(const uint8_t* data, size_t& offset) {
    uint16_t value = static_cast<uint16_t>(data[offset])
                   | (static_cast<uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    return value;
}

uint32_t OPCUABinaryCodec::decodeUInt32(const uint8_t* data, size_t& offset) {
    uint32_t value = static_cast<uint32_t>(data[offset])
                   | (static_cast<uint32_t>(data[offset + 1]) << 8)
                   | (static_cast<uint32_t>(data[offset + 2]) << 16)
                   | (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
}

uint64_t OPCUABinaryCodec::decodeUInt64(const uint8_t* data, size_t& offset) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= (static_cast<uint64_t>(data[offset + i]) << (i * 8));
    }
    offset += 8;
    return value;
}

int32_t OPCUABinaryCodec::decodeInt32(const uint8_t* data, size_t& offset) {
    return static_cast<int32_t>(decodeUInt32(data, offset));
}

int64_t OPCUABinaryCodec::decodeInt64(const uint8_t* data, size_t& offset) {
    return static_cast<int64_t>(decodeUInt64(data, offset));
}

psram_string OPCUABinaryCodec::decodeString(const uint8_t* data, size_t& offset, size_t max_len) {
    if (offset + 4 > max_len) {
        LOG_ERROR(TAG_OPCUA_CODEC, "decodeString: offset out of bounds");
        return PSRAMUtils::createPSRAMString("");
    }

    int32_t len = decodeInt32(data, offset);

    // Null string
    if (len == -1) {
        return PSRAMUtils::createPSRAMString("");
    }

    // Empty string
    if (len == 0) {
        return PSRAMUtils::createPSRAMString("");
    }

    // Invalid length
    if (len < 0 || offset + len > max_len) {
        LOG_ERRORF(TAG_OPCUA_CODEC, "decodeString: invalid length %d", len);
        offset = max_len;
        return PSRAMUtils::createPSRAMString("");
    }

    // Use stack buffer for temporary storage
    char temp_buf[4096];
    if (len >= sizeof(temp_buf)) {
        LOG_ERRORF(TAG_OPCUA_CODEC, "decodeString: string too long %d", len);
        offset = max_len;
        return PSRAMUtils::createPSRAMString("");
    }

    memcpy(temp_buf, data + offset, len);
    temp_buf[len] = '\0';
    offset += len;

    return PSRAMUtils::createPSRAMString(temp_buf);
}

psram_string OPCUABinaryCodec::decodeByteStringAsHex(const uint8_t* data, size_t& offset, size_t max_len) {
    if (offset + 4 > max_len) {
        LOG_ERROR(TAG_OPCUA_CODEC, "decodeByteStringAsHex: offset out of bounds");
        return PSRAMUtils::createPSRAMString("");
    }

    int32_t len = decodeInt32(data, offset);

    if (len == -1 || len == 0) {
        return PSRAMUtils::createPSRAMString("");
    }

    if (len < 0 || offset + len > max_len) {
        LOG_ERRORF(TAG_OPCUA_CODEC, "decodeByteStringAsHex: invalid length %d", len);
        offset = max_len;
        return PSRAMUtils::createPSRAMString("");
    }

    // Convert to hex string (use PSRAM buffer)
    PSRAMUtils::ScopedBuffer hex_buf(len * 2 + 1);
    if (!hex_buf.valid()) {
        LOG_ERROR(TAG_OPCUA_CODEC, "decodeByteStringAsHex: PSRAM allocation failed");
        offset += len;
        return PSRAMUtils::createPSRAMString("");
    }

    char* hex_ptr = (char*)hex_buf.get();
    for (int32_t i = 0; i < len; ++i) {
        snprintf(hex_ptr + (i * 2), 3, "%02X", data[offset + i]);
    }
    hex_ptr[len * 2] = '\0';
    offset += len;

    return PSRAMUtils::createPSRAMString(hex_ptr);
}

bool OPCUABinaryCodec::decodeByteString(const uint8_t* data, size_t& offset, size_t max_len,
                                       psram_vector<uint8_t>& out_bytes) {
    out_bytes.clear();

    if (offset + 4 > max_len) {
        return false;
    }

    int32_t len = decodeInt32(data, offset);

    if (len == -1) {
        return true; // Null byte string
    }

    if (len == 0) {
        return true; // Empty byte string
    }

    if (len < 0 || offset + len > max_len) {
        LOG_ERRORF(TAG_OPCUA_CODEC, "decodeByteString: invalid length %d", len);
        return false;
    }

    out_bytes.reserve(len);
    for (int32_t i = 0; i < len; ++i) {
        out_bytes.push_back(data[offset + i]);
    }
    offset += len;

    return true;
}

int32_t OPCUABinaryCodec::decodeArrayLength(const uint8_t* data, size_t& offset) {
    return decodeInt32(data, offset);
}

bool OPCUABinaryCodec::skipByteString(const uint8_t* data, size_t& offset, size_t max_len) {
    if (offset + 4 > max_len) {
        return false;
    }

    int32_t len = decodeInt32(data, offset);

    if (len == -1 || len == 0) {
        return true;
    }

    if (len < 0 || offset + len > max_len) {
        return false;
    }

    offset += len;
    return true;
}

// ==================== MESSAGE BUILDERS ====================

void OPCUABinaryCodec::buildMessageHeader(psram_vector<uint8_t>& buf, const char* msg_type,
                                          char chunk_type, uint32_t message_size) {
    // Message type (3 bytes)
    buf.push_back(static_cast<uint8_t>(msg_type[0]));
    buf.push_back(static_cast<uint8_t>(msg_type[1]));
    buf.push_back(static_cast<uint8_t>(msg_type[2]));

    // Chunk type (1 byte)
    buf.push_back(static_cast<uint8_t>(chunk_type));

    // Message size (4 bytes, little endian)
    encodeUInt32(buf, message_size);
}

void OPCUABinaryCodec::buildRequestHeader(psram_vector<uint8_t>& buf,
                                          uint64_t timestamp_utc,
                                          uint32_t request_handle,
                                          uint32_t timeout_ms) {
    // RequestHeader structure:
    // - AuthenticationToken (NodeId) - we use 2-byte NodeId with value 0
    // - Timestamp (DateTime - Int64)
    // - RequestHandle (UInt32)
    // - ReturnDiagnostics (UInt32) - 0 for none
    // - AuditEntryId (String) - null
    // - TimeoutHint (UInt32)
    // - AdditionalHeader (ExtensionObject) - null

    // AuthenticationToken - NodeId (2-byte, namespace 0, identifier 0)
    encodeUInt8(buf, OPCUA::TWOBYTE);
    encodeUInt8(buf, 0); // Identifier = 0

    // Timestamp
    encodeUInt64(buf, timestamp_utc);

    // RequestHandle
    encodeUInt32(buf, request_handle);

    // ReturnDiagnostics
    encodeUInt32(buf, 0);

    // AuditEntryId (null string)
    encodeInt32(buf, -1);

    // TimeoutHint
    encodeUInt32(buf, timeout_ms);

    // AdditionalHeader (null ExtensionObject)
    // TypeId (2-byte NodeId = 0)
    encodeUInt8(buf, OPCUA::TWOBYTE);
    encodeUInt8(buf, 0);
    // Encoding (0 = no body)
    encodeUInt8(buf, 0);
}

bool OPCUABinaryCodec::buildOpenSecureChannelRequest(psram_vector<uint8_t>& out_msg,
                                                     const char* endpoint_url,
                                                     const char* security_policy_uri,
                                                     uint32_t requested_lifetime_ms) {
    out_msg.clear();

    // Reserve space for message (estimate ~300 bytes)
    out_msg.reserve(512);

    // We'll build the message body first, then prepend headers

    psram_vector<uint8_t> body;
    body.reserve(400);

    // ========== Asymmetric Security Header ==========
    // SecurityPolicyUri
    encodeString(body, security_policy_uri);

    // SenderCertificate (null for #None)
    encodeByteString(body, nullptr, -1);

    // ReceiverCertificateThumbprint (null for #None)
    encodeByteString(body, nullptr, -1);

    // ========== Sequence Header ==========
    uint32_t sequence_number = 1;
    uint32_t request_id = 1;

    encodeUInt32(body, sequence_number);
    encodeUInt32(body, request_id);

    // ========== Message Body (OpenSecureChannelRequest) ==========

    // TypeId (service type - 4-byte NodeId, namespace 0, identifier 446)
    encodeUInt8(body, OPCUA::FOURBYTE);
    encodeUInt8(body, 0); // Namespace
    encodeUInt16(body, 446); // OpenSecureChannelRequest service type

    // RequestHeader
    uint64_t timestamp = getCurrentTimestamp();
    buildRequestHeader(body, timestamp, request_id, 10000); // 10s timeout

    // ClientProtocolVersion (UInt32) - version 0
    encodeUInt32(body, 0);

    // SecurityTokenRequestType (0=Issue, 1=Renew)
    encodeUInt32(body, OPCUA::ISSUE);

    // MessageSecurityMode (1=None, 2=Sign, 3=SignAndEncrypt)
    encodeUInt32(body, OPCUA::SECURITY_MODE_NONE);

    // ClientNonce (ByteString) - null for #None
    encodeByteString(body, nullptr, -1);

    // RequestedLifetime (UInt32) - in milliseconds
    encodeUInt32(body, requested_lifetime_ms);

    // ========== Now build complete message with TCP header ==========

    // Secure channel ID (0 for new connection)
    uint32_t secure_channel_id = 0;

    // Total message size = TCP header (8) + SecureChannelId (4) + body size
    uint32_t total_size = 8 + 4 + static_cast<uint32_t>(body.size());

    // Build TCP header
    buildMessageHeader(out_msg, OPCUA::MSG_OPEN, OPCUA::CHUNK_FINAL, total_size);

    // SecureChannelId
    encodeUInt32(out_msg, secure_channel_id);

    // Append body
    out_msg.insert(out_msg.end(), body.begin(), body.end());

    LOG_INFOF(TAG_OPCUA_CODEC, "Built OpenSecureChannel request: %zu bytes", out_msg.size());
    return true;
}

bool OPCUABinaryCodec::buildGetEndpointsRequest(psram_vector<uint8_t>& out_msg,
                                               uint32_t secure_channel_id,
                                               uint32_t security_token_id,
                                               uint32_t sequence_number,
                                               uint32_t request_id,
                                               const char* endpoint_url) {
    out_msg.clear();
    out_msg.reserve(512);

    psram_vector<uint8_t> body;
    body.reserve(400);

    // ========== Symmetric Security Header ==========
    // SecurityTokenId
    encodeUInt32(body, security_token_id);

    // ========== Sequence Header ==========
    encodeUInt32(body, sequence_number);
    encodeUInt32(body, request_id);

    // ========== Message Body (GetEndpointsRequest) ==========

    // TypeId (service type - 4-byte NodeId, namespace 0, identifier 428)
    encodeUInt8(body, OPCUA::FOURBYTE);
    encodeUInt8(body, 0);
    encodeUInt16(body, OPCUA::SERVICE_GETENDPOINTS);

    // RequestHeader
    uint64_t timestamp = getCurrentTimestamp();
    buildRequestHeader(body, timestamp, request_id, 10000);

    // EndpointUrl (String)
    encodeString(body, endpoint_url);

    // LocaleIds (Array of String) - empty array
    encodeArrayLength(body, 0);

    // ProfileUris (Array of String) - empty array (returns all)
    encodeArrayLength(body, 0);

    // ========== Complete message ==========
    uint32_t total_size = 8 + 4 + static_cast<uint32_t>(body.size());

    buildMessageHeader(out_msg, OPCUA::MSG_MESSAGE, OPCUA::CHUNK_FINAL, total_size);
    encodeUInt32(out_msg, secure_channel_id);
    out_msg.insert(out_msg.end(), body.begin(), body.end());

    LOG_INFOF(TAG_OPCUA_CODEC, "Built GetEndpoints request: %zu bytes", out_msg.size());
    return true;
}

bool OPCUABinaryCodec::buildCreateSessionRequest(psram_vector<uint8_t>& out_msg,
                                                 uint32_t secure_channel_id,
                                                 uint32_t security_token_id,
                                                 uint32_t sequence_number,
                                                 uint32_t request_id,
                                                 const char* endpoint_url,
                                                 const char* session_name) {
    out_msg.clear();
    out_msg.reserve(1024);

    psram_vector<uint8_t> body;
    body.reserve(800);

    // ========== Symmetric Security Header ==========
    encodeUInt32(body, security_token_id);

    // ========== Sequence Header ==========
    encodeUInt32(body, sequence_number);
    encodeUInt32(body, request_id);

    // ========== Message Body (CreateSessionRequest) ==========

    // TypeId (service type - 4-byte NodeId, namespace 0, identifier 461)
    encodeUInt8(body, OPCUA::FOURBYTE);
    encodeUInt8(body, 0);
    encodeUInt16(body, OPCUA::SERVICE_CREATESESSION);

    // RequestHeader
    uint64_t timestamp = getCurrentTimestamp();
    buildRequestHeader(body, timestamp, request_id, 10000);

    // ClientDescription (ApplicationDescription)
    // - ApplicationUri
    encodeString(body, "urn:ESP32:OPCUASecurityScanner");
    // - ProductUri
    encodeString(body, "urn:ESP32:SecurityScanner:1.0");
    // - ApplicationName (LocalizedText: encoding byte + locale + text)
    encodeUInt8(body, 0x03); // Has locale and text
    encodeString(body, "en-US");
    encodeString(body, session_name);
    // - ApplicationType (0=Server, 1=Client)
    encodeUInt32(body, 1); // Client
    // - GatewayServerUri (null)
    encodeString(body, nullptr);
    // - DiscoveryProfileUri (null)
    encodeString(body, nullptr);
    // - DiscoveryUrls (empty array)
    encodeArrayLength(body, 0);

    // ServerUri (null)
    encodeString(body, nullptr);

    // EndpointUrl
    encodeString(body, endpoint_url);

    // SessionName
    encodeString(body, session_name);

    // ClientNonce (ByteString) - 32 random bytes (use simple pseudo-random)
    uint8_t nonce[32];
    uint64_t now_us = esp_timer_get_time();
    for (int i = 0; i < 32; ++i) {
        nonce[i] = static_cast<uint8_t>((now_us + i) & 0xFF);
    }
    encodeByteString(body, nonce, 32);

    // ClientCertificate (null for now)
    encodeByteString(body, nullptr, -1);

    // RequestedSessionTimeout (Double) - 60000ms = 60s
    double session_timeout = 60000.0;
    encodeUInt64(body, *reinterpret_cast<uint64_t*>(&session_timeout));

    // MaxResponseMessageSize (UInt32) - 64KB
    encodeUInt32(body, 65536);

    // ========== Complete message ==========
    uint32_t total_size = 8 + 4 + static_cast<uint32_t>(body.size());

    buildMessageHeader(out_msg, OPCUA::MSG_MESSAGE, OPCUA::CHUNK_FINAL, total_size);
    encodeUInt32(out_msg, secure_channel_id);
    out_msg.insert(out_msg.end(), body.begin(), body.end());

    LOG_INFOF(TAG_OPCUA_CODEC, "Built CreateSession request: %zu bytes", out_msg.size());
    return true;
}

bool OPCUABinaryCodec::buildCloseSecureChannelRequest(psram_vector<uint8_t>& out_msg,
                                                      uint32_t secure_channel_id,
                                                      uint32_t security_token_id,
                                                      uint32_t sequence_number,
                                                      uint32_t request_id) {
    out_msg.clear();
    out_msg.reserve(256);

    psram_vector<uint8_t> body;
    body.reserve(200);

    // ========== Symmetric Security Header ==========
    encodeUInt32(body, security_token_id);

    // ========== Sequence Header ==========
    encodeUInt32(body, sequence_number);
    encodeUInt32(body, request_id);

    // ========== Message Body (CloseSecureChannelRequest) ==========

    // TypeId (service type - 4-byte NodeId, namespace 0, identifier 452)
    encodeUInt8(body, OPCUA::FOURBYTE);
    encodeUInt8(body, 0);
    encodeUInt16(body, 452); // CloseSecureChannelRequest

    // RequestHeader
    uint64_t timestamp = getCurrentTimestamp();
    buildRequestHeader(body, timestamp, request_id, 5000);

    // No additional parameters for CloseSecureChannel

    // ========== Complete message ==========
    uint32_t total_size = 8 + 4 + static_cast<uint32_t>(body.size());

    buildMessageHeader(out_msg, OPCUA::MSG_CLOSE, OPCUA::CHUNK_FINAL, total_size);
    encodeUInt32(out_msg, secure_channel_id);
    out_msg.insert(out_msg.end(), body.begin(), body.end());

    LOG_INFOF(TAG_OPCUA_CODEC, "Built CloseSecureChannel request: %zu bytes", out_msg.size());
    return true;
}

// ==================== TIMESTAMP HELPERS ====================

uint64_t OPCUABinaryCodec::getCurrentTimestamp() {
    // Get current Unix time in milliseconds
    uint64_t unix_ms = esp_timer_get_time() / 1000;
    return unixToOPCUA(unix_ms);
}

uint64_t OPCUABinaryCodec::unixToOPCUA(uint64_t unix_timestamp_ms) {
    // OPC UA time: 100-nanosecond intervals since January 1, 1601 UTC
    // Unix time: milliseconds since January 1, 1970 UTC
    // Difference: 11644473600 seconds = 116444736000000000 * 100ns

    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    return (unix_timestamp_ms * 10000) + EPOCH_DIFF;
}

uint64_t OPCUABinaryCodec::opcuaToUnix(uint64_t opcua_timestamp) {
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    if (opcua_timestamp < EPOCH_DIFF) {
        return 0;
    }
    return (opcua_timestamp - EPOCH_DIFF) / 10000;
}

// ==================== MESSAGE PARSERS ====================

bool OPCUABinaryCodec::parseOpenSecureChannelResponse(const uint8_t* data, size_t len,
                                                      uint32_t& out_secure_channel_id,
                                                      uint32_t& out_security_token_id,
                                                      psram_string& out_error) {
    // OpenSecureChannelResponse structure (OPN message):
    // TCP Header (8 bytes): MSG_OPEN[3] + CHUNK_FINAL[1] + MessageSize[4]
    // SecureChannelId (4 bytes)
    // Asymmetric Security Header:
    //   - SecurityPolicyUri (String)
    //   - SenderCertificate (ByteString)
    //   - ReceiverCertificateThumbprint (ByteString)
    // Sequence Header:
    //   - SequenceNumber (UInt32)
    //   - RequestId (UInt32)
    // Message Body:
    //   - TypeId (NodeId) - 4-byte: ns=0, id=449 (OpenSecureChannelResponse)
    //   - ResponseHeader (...)
    //   - ServerProtocolVersion (UInt32)
    //   - SecurityToken (ChannelSecurityToken):
    //     - ChannelId (UInt32) <-- we need this
    //     - TokenId (UInt32) <-- we need this
    //     - CreatedAt (DateTime)
    //     - RevisedLifetime (UInt32)
    //   - ServerNonce (ByteString)

    out_secure_channel_id = 0;
    out_security_token_id = 0;
    out_error = PSRAMUtils::createPSRAMString("");

    if (len < 12) {
        out_error = PSRAMUtils::createPSRAMString("Response too short");
        return false;
    }

    size_t offset = 0;

    // Parse TCP header
    char msg_type[4] = {0};
    msg_type[0] = data[offset++];
    msg_type[1] = data[offset++];
    msg_type[2] = data[offset++];
    offset++; // chunk_type (not used)
    uint32_t msg_size = decodeUInt32(data, offset);
    if (msg_size < 8 || msg_size > len || msg_size > 64 * 1024) {
        out_error = PSRAMUtils::createPSRAMString("Invalid OPC UA message size");
        return false;
    }

    if (strncmp(msg_type, OPCUA::MSG_OPEN, 3) != 0) {
        // Check for error message
        if (strncmp(msg_type, OPCUA::MSG_ERROR, 3) == 0) {
            out_error = PSRAMUtils::createPSRAMString("Server returned ERR message");
            return false;
        }
        out_error = PSRAMUtils::createPSRAMString("Invalid message type (expected OPN)");
        return false;
    }

    if (msg_size != len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated OPC UA message");
        return false;
    }

    // SecureChannelId
    out_secure_channel_id = decodeUInt32(data, offset);

    // Skip Asymmetric Security Header
    if (!skipByteString(data, offset, len)) { // SecurityPolicyUri
        out_error = PSRAMUtils::createPSRAMString("Failed to parse SecurityPolicyUri");
        return false;
    }
    if (!skipByteString(data, offset, len)) { // SenderCertificate
        out_error = PSRAMUtils::createPSRAMString("Failed to parse SenderCertificate");
        return false;
    }
    if (!skipByteString(data, offset, len)) { // ReceiverCertificateThumbprint
        out_error = PSRAMUtils::createPSRAMString("Failed to parse ReceiverCertificateThumbprint");
        return false;
    }

    // Skip Sequence Header
    offset += 4; // SequenceNumber
    offset += 4; // RequestId

    if (offset + 4 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated message (sequence header)");
        return false;
    }

    // Skip TypeId (NodeId - assume 4-byte)
    uint8_t node_id_type = data[offset++];
    if (node_id_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else if (node_id_type == OPCUA::FOURBYTE) {
        offset += 3; // namespace(1) + identifier(2)
    } else {
        out_error = PSRAMUtils::createPSRAMString("Unsupported NodeId type");
        return false;
    }

    // Skip ResponseHeader structure
    // - Timestamp (DateTime - 8 bytes)
    // - RequestHandle (UInt32 - 4 bytes)
    // - ServiceResult (StatusCode - UInt32 - 4 bytes) <-- check this
    // - ServiceDiagnostics (DiagnosticInfo - variable)
    // - StringTable (array of String)
    // - AdditionalHeader (ExtensionObject)

    if (offset + 16 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated message (response header)");
        return false;
    }

    offset += 8; // Timestamp

    uint32_t request_handle = decodeUInt32(data, offset);
    (void)request_handle; // Unused

    uint32_t status_code = decodeUInt32(data, offset);
    if (status_code != 0) {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "Service returned error: 0x%08lX", (unsigned long)status_code);
        out_error = PSRAMUtils::createPSRAMString(err_buf);
        return false;
    }

    // Skip ServiceDiagnostics (DiagnosticInfo - encoding byte)
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated message (diagnostics)");
        return false;
    }

    uint8_t diag_encoding = data[offset++];
    if (diag_encoding != 0) {
        // Has diagnostic info - skip it (complex structure, just try to skip strings)
        // For simplicity, assume it's empty or very short
        LOG_WARNING(TAG_OPCUA_CODEC, "DiagnosticInfo present but not fully parsed");
    }

    // Skip StringTable (array)
    int32_t string_table_count = decodeArrayLength(data, offset);
    if (string_table_count < 0 || string_table_count > 100) {
        out_error = PSRAMUtils::createPSRAMString("Invalid StringTable length");
        return false;
    }
    for (int32_t i = 0; i < string_table_count; ++i) {
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip StringTable");
            return false;
        }
    }

    // Skip AdditionalHeader (ExtensionObject - TypeId + Encoding)
    if (offset + 2 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated message (additional header)");
        return false;
    }
    uint8_t ext_node_type = data[offset++];
    if (ext_node_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else if (ext_node_type == OPCUA::FOURBYTE) {
        offset += 3;
    } else {
        offset += 1; // Assume minimal
    }
    uint8_t ext_encoding = data[offset++];
    if (ext_encoding != 0) {
        // Has body - skip ByteString
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip ExtensionObject body");
            return false;
        }
    }

    // Now we're at the OpenSecureChannelResponse body:
    // - ServerProtocolVersion (UInt32)
    // - SecurityToken (ChannelSecurityToken):
    //   - ChannelId (UInt32)
    //   - TokenId (UInt32)
    //   - CreatedAt (DateTime - UInt64)
    //   - RevisedLifetime (UInt32)
    // - ServerNonce (ByteString)

    if (offset + 4 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated message (ServerProtocolVersion)");
        return false;
    }

    uint32_t server_protocol_version = decodeUInt32(data, offset);
    (void)server_protocol_version; // Unused

    // SecurityToken structure
    if (offset + 20 > len) { // 4+4+8+4 = 20 bytes minimum
        out_error = PSRAMUtils::createPSRAMString("Truncated message (SecurityToken)");
        return false;
    }

    uint32_t channel_id = decodeUInt32(data, offset);
    uint32_t token_id = decodeUInt32(data, offset);
    uint64_t created_at = decodeUInt64(data, offset);
    uint32_t revised_lifetime = decodeUInt32(data, offset);

    (void)created_at;
    (void)revised_lifetime;

    out_secure_channel_id = channel_id;
    out_security_token_id = token_id;

    LOG_INFOF(TAG_OPCUA_CODEC, "Parsed OpenSecureChannelResponse: ChannelId=%u, TokenId=%u",
              out_secure_channel_id, out_security_token_id);

    return true;
}

bool OPCUABinaryCodec::parseGetEndpointsResponse(const uint8_t* data, size_t len,
                                                 psram_vector<OPCUAEndpoint>& out_endpoints,
                                                 psram_string& out_error) {
    // GetEndpointsResponse structure (MSG message):
    // TCP Header (8 bytes)
    // SecureChannelId (4 bytes)
    // Symmetric Security Header:
    //   - TokenId (UInt32)
    // Sequence Header:
    //   - SequenceNumber (UInt32)
    //   - RequestId (UInt32)
    // Message Body:
    //   - TypeId (NodeId) - 4-byte: ns=0, id=431 (GetEndpointsResponse)
    //   - ResponseHeader (...)
    //   - Endpoints (Array of EndpointDescription)

    out_endpoints.clear();
    out_error = PSRAMUtils::createPSRAMString("");

    if (len < 20) {
        out_error = PSRAMUtils::createPSRAMString("Response too short");
        return false;
    }

    size_t offset = 0;

    // Parse TCP header
    char msg_type[4] = {0};
    msg_type[0] = data[offset++];
    msg_type[1] = data[offset++];
    msg_type[2] = data[offset++];
    offset++; // chunk_type (not used)
    uint32_t msg_size = decodeUInt32(data, offset);
    if (msg_size < 8 || msg_size > len || msg_size > 64 * 1024) {
        out_error = PSRAMUtils::createPSRAMString("Invalid OPC UA message size");
        return false;
    }
    if (msg_size != len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated OPC UA message");
        return false;
    }

    if (strncmp(msg_type, OPCUA::MSG_MESSAGE, 3) != 0) {
        if (strncmp(msg_type, OPCUA::MSG_ERROR, 3) == 0) {
            out_error = PSRAMUtils::createPSRAMString("Server returned ERR message");
            return false;
        }
        out_error = PSRAMUtils::createPSRAMString("Invalid message type (expected MSG)");
        return false;
    }

    // SecureChannelId
    uint32_t secure_channel_id = decodeUInt32(data, offset);
    (void)secure_channel_id;

    // Symmetric Security Header
    uint32_t token_id = decodeUInt32(data, offset);
    (void)token_id;

    // Sequence Header
    uint32_t sequence_number = decodeUInt32(data, offset);
    uint32_t request_id = decodeUInt32(data, offset);
    (void)sequence_number;
    (void)request_id;

    // TypeId (NodeId)
    uint8_t node_id_type = data[offset++];
    if (node_id_type == OPCUA::FOURBYTE) {
        offset += 3; // namespace + identifier
    } else if (node_id_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else {
        out_error = PSRAMUtils::createPSRAMString("Unsupported TypeId NodeId format");
        return false;
    }

    // ResponseHeader - same as OpenSecureChannel
    if (offset + 16 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated ResponseHeader");
        return false;
    }

    offset += 8; // Timestamp
    uint32_t request_handle = decodeUInt32(data, offset);
    (void)request_handle;

    uint32_t status_code = decodeUInt32(data, offset);
    if (status_code != 0) {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "Service error: 0x%08lX", (unsigned long)status_code);
        out_error = PSRAMUtils::createPSRAMString(err_buf);
        return false;
    }

    // Skip ServiceDiagnostics
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated after status code");
        return false;
    }
    uint8_t diag_encoding = data[offset++];
    if (diag_encoding != 0) {
        LOG_WARNING(TAG_OPCUA_CODEC, "DiagnosticInfo present (not fully parsed)");
    }

    // Skip StringTable
    if (offset + 4 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at StringTable");
        return false;
    }
    int32_t string_table_count = decodeArrayLength(data, offset);
    if (string_table_count < 0 || string_table_count > 100) {
        out_error = PSRAMUtils::createPSRAMString("Invalid StringTable length");
        return false;
    }
    for (int32_t i = 0; i < string_table_count; ++i) {
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip StringTable entry");
            return false;
        }
    }

    // Skip AdditionalHeader (ExtensionObject)
    if (offset + 2 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at AdditionalHeader");
        return false;
    }
    uint8_t ext_node_type = data[offset++];
    if (ext_node_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else if (ext_node_type == OPCUA::FOURBYTE) {
        offset += 3;
    } else {
        offset += 1;
    }
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at ExtensionObject encoding");
        return false;
    }
    uint8_t ext_encoding = data[offset++];
    if (ext_encoding != 0) {
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip ExtensionObject body");
            return false;
        }
    }

    // Now parse Endpoints array
    if (offset + 4 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at Endpoints array length");
        return false;
    }

    int32_t endpoint_count = decodeArrayLength(data, offset);

    if (endpoint_count < 0 || endpoint_count > 100) {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "Invalid endpoint count: %ld", (long)endpoint_count);
        out_error = PSRAMUtils::createPSRAMString(err_buf);
        return false;
    }

    LOG_INFOF(TAG_OPCUA_CODEC, "Parsing %d endpoints...", endpoint_count);

    for (int32_t ep_idx = 0; ep_idx < endpoint_count; ++ep_idx) {
        OPCUAEndpoint endpoint;

        // EndpointDescription structure:
        // - EndpointUrl (String)
        // - Server (ApplicationDescription)
        // - ServerCertificate (ByteString)
        // - SecurityMode (UInt32)
        // - SecurityPolicyUri (String)
        // - UserIdentityTokens (Array of UserTokenPolicy)
        // - TransportProfileUri (String)
        // - SecurityLevel (Byte)

        // EndpointUrl
        endpoint.endpoint_url = decodeString(data, offset, len);

        // Server (ApplicationDescription):
        // - ApplicationUri (String)
        endpoint.server_application_uri = decodeString(data, offset, len);

        // - ProductUri (String)
        endpoint.server_product_uri = decodeString(data, offset, len);

        // - ApplicationName (LocalizedText: encoding + locale + text)
        if (offset >= len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at ApplicationName");
            return false;
        }
        uint8_t localized_encoding = data[offset++];
        if (localized_encoding & 0x01) { // Has locale
            psram_string locale = decodeString(data, offset, len);
            (void)locale;
        }
        if (localized_encoding & 0x02) { // Has text
            endpoint.server_application_name = decodeString(data, offset, len);
        }

        // - ApplicationType (UInt32)
        if (offset + 4 > len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at ApplicationType");
            return false;
        }
        endpoint.server_application_type = decodeUInt32(data, offset);

        // - GatewayServerUri (String)
        endpoint.server_gateway_server_uri = decodeString(data, offset, len);

        // - DiscoveryProfileUri (String)
        endpoint.server_discovery_profile_uri = decodeString(data, offset, len);

        // - DiscoveryUrls (Array of String)
        if (offset + 4 > len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at DiscoveryUrls");
            return false;
        }
        int32_t discovery_url_count = decodeArrayLength(data, offset);
        if (discovery_url_count < 0 || discovery_url_count > 10) {
            out_error = PSRAMUtils::createPSRAMString("Invalid DiscoveryUrls length");
            return false;
        }
        for (int32_t i = 0; i < discovery_url_count; ++i) {
            psram_string url = decodeString(data, offset, len);
            endpoint.server_discovery_urls.push_back(url);
        }

        // ServerCertificate (ByteString) - store as hex and parse
        endpoint.server_certificate_der_hex = decodeByteStringAsHex(data, offset, len);

        // Parse X.509 certificate if present
        if (!endpoint.server_certificate_der_hex.empty()) {
            psram_string parse_error;
            if (!X509DER::Parser::parseCertificate(endpoint.server_certificate_der_hex,
                                                   endpoint.server_certificate_info,
                                                   parse_error)) {
                LOG_WARNING(TAG_OPCUA_CODEC, "Failed to parse certificate");
            }
        }

        // SecurityMode (UInt32)
        if (offset + 4 > len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at SecurityMode");
            return false;
        }
        endpoint.security_mode = decodeUInt32(data, offset);

        // SecurityPolicyUri (String)
        endpoint.security_policy_uri = decodeString(data, offset, len);

        // UserIdentityTokens (Array of UserTokenPolicy)
        if (offset + 4 > len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at UserIdentityTokens");
            return false;
        }
        int32_t token_count = decodeArrayLength(data, offset);
        if (token_count < 0 || token_count > 20) {
            out_error = PSRAMUtils::createPSRAMString("Invalid UserIdentityTokens length");
            return false;
        }

        endpoint.allows_anonymous = false;
        endpoint.allows_username_password = false;
        endpoint.allows_certificate = false;

        for (int32_t t = 0; t < token_count; ++t) {
            UserIdentityTokenPolicy token_policy;

            // PolicyId (String)
            token_policy.policy_id = decodeString(data, offset, len);

            // TokenType (UInt32)
            if (offset + 4 > len) {
                out_error = PSRAMUtils::createPSRAMString("Truncated at TokenType");
                return false;
            }
            token_policy.token_type = decodeUInt32(data, offset);

            // IssuedTokenType (String)
            token_policy.issued_token_type = decodeString(data, offset, len);

            // IssuerEndpointUrl (String)
            token_policy.issuer_endpoint_url = decodeString(data, offset, len);

            // SecurityPolicyUri (String)
            token_policy.security_policy_uri = decodeString(data, offset, len);

            endpoint.user_identity_tokens.push_back(token_policy);

            // Set flags
            if (token_policy.token_type == OPCUA::ANONYMOUS) {
                endpoint.allows_anonymous = true;
            } else if (token_policy.token_type == OPCUA::USERNAME) {
                endpoint.allows_username_password = true;
            } else if (token_policy.token_type == OPCUA::CERTIFICATE) {
                endpoint.allows_certificate = true;
            }
        }

        // TransportProfileUri (String)
        endpoint.transport_profile_uri = decodeString(data, offset, len);

        // SecurityLevel (Byte)
        if (offset >= len) {
            out_error = PSRAMUtils::createPSRAMString("Truncated at SecurityLevel");
            return false;
        }
        endpoint.security_level = data[offset++];

        // Security assessment
        endpoint.requires_encryption = (endpoint.security_mode == OPCUA::SECURITY_MODE_SIGNANDENCRYPT);
        endpoint.is_secure = (endpoint.security_mode != OPCUA::SECURITY_MODE_NONE) &&
                            !endpoint.allows_anonymous;

        // Add certificate vulnerabilities to endpoint vulnerabilities
        for (const auto& cert_vuln : endpoint.server_certificate_info.vulnerabilities) {
            endpoint.vulnerabilities.push_back(cert_vuln);
        }

        // Additional security checks
        if (endpoint.security_mode == OPCUA::SECURITY_MODE_NONE) {
            endpoint.vulnerabilities.push_back(PSRAMUtils::createPSRAMString("HIGH: No message security (SecurityMode=None)"));
        }

        if (endpoint.allows_anonymous && endpoint.security_mode == OPCUA::SECURITY_MODE_NONE) {
            endpoint.vulnerabilities.push_back(PSRAMUtils::createPSRAMString("CRITICAL: Anonymous access with no encryption"));
        }

        out_endpoints.push_back(endpoint);
    }

    LOG_INFOF(TAG_OPCUA_CODEC, "Successfully parsed %zu endpoints", out_endpoints.size());
    return true;
}

bool OPCUABinaryCodec::parseCreateSessionResponse(const uint8_t* data, size_t len,
                                                  psram_vector<uint8_t>& out_session_id,
                                                  psram_vector<uint8_t>& out_auth_token,
                                                  psram_string& out_error) {
    // CreateSessionResponse structure:
    // TCP Header + SecureChannelId + Symmetric Header + Sequence Header
    // TypeId (NodeId)
    // ResponseHeader
    // SessionId (NodeId as ByteString typically)
    // AuthenticationToken (NodeId as ByteString)
    // ... other fields we don't need for now

    out_session_id.clear();
    out_auth_token.clear();
    out_error = PSRAMUtils::createPSRAMString("");

    if (len < 20) {
        out_error = PSRAMUtils::createPSRAMString("Response too short");
        return false;
    }

    size_t offset = 0;

    // Parse TCP header
    char msg_type[4] = {0};
    msg_type[0] = data[offset++];
    msg_type[1] = data[offset++];
    msg_type[2] = data[offset++];
    offset++; // chunk_type

    uint32_t msg_size = decodeUInt32(data, offset);
    (void)msg_size;

    if (strncmp(msg_type, OPCUA::MSG_MESSAGE, 3) != 0) {
        out_error = PSRAMUtils::createPSRAMString("Invalid message type");
        return false;
    }

    // SecureChannelId
    offset += 4;

    // Symmetric Security Header (TokenId)
    offset += 4;

    // Sequence Header
    offset += 8;

    // TypeId (NodeId) - skip
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at TypeId");
        return false;
    }
    uint8_t node_id_type = data[offset++];
    if (node_id_type == OPCUA::FOURBYTE) {
        offset += 3;
    } else if (node_id_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else {
        offset += 1;
    }

    // ResponseHeader
    if (offset + 16 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated ResponseHeader");
        return false;
    }
    offset += 8; // Timestamp
    offset += 4; // RequestHandle

    uint32_t status_code = decodeUInt32(data, offset);
    if (status_code != 0) {
        char err_buf[64];
        snprintf(err_buf, sizeof(err_buf), "Service error: 0x%08lX", (unsigned long)status_code);
        out_error = PSRAMUtils::createPSRAMString(err_buf);
        return false;
    }

    // Skip DiagnosticInfo
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at DiagnosticInfo");
        return false;
    }
    uint8_t diag_encoding = data[offset++];
    if (diag_encoding != 0) {
        LOG_WARNING(TAG_OPCUA_CODEC, "DiagnosticInfo present");
    }

    // Skip StringTable
    if (offset + 4 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at StringTable");
        return false;
    }
    int32_t string_table_count = decodeArrayLength(data, offset);
    for (int32_t i = 0; i < string_table_count; ++i) {
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip StringTable");
            return false;
        }
    }

    // Skip AdditionalHeader
    if (offset + 2 > len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at AdditionalHeader");
        return false;
    }
    uint8_t ext_node_type = data[offset++];
    if (ext_node_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else if (ext_node_type == OPCUA::FOURBYTE) {
        offset += 3;
    } else {
        offset += 1;
    }
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at ExtensionObject");
        return false;
    }
    uint8_t ext_encoding = data[offset++];
    if (ext_encoding != 0) {
        if (!skipByteString(data, offset, len)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to skip ExtensionObject");
            return false;
        }
    }

    // Now parse CreateSessionResponse body:
    // - SessionId (NodeId) - usually ByteString
    // - AuthenticationToken (NodeId) - usually ByteString

    // SessionId (NodeId)
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at SessionId");
        return false;
    }
    uint8_t session_id_type = data[offset++];
    if (session_id_type == OPCUA::BYTESTRING) {
        offset += 1; // namespace
        if (!decodeByteString(data, offset, len, out_session_id)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to decode SessionId");
            return false;
        }
    } else {
        // Numeric or other - just skip for now
        if (session_id_type == OPCUA::FOURBYTE) {
            offset += 3;
        } else {
            offset += 1;
        }
    }

    // AuthenticationToken (NodeId)
    if (offset >= len) {
        out_error = PSRAMUtils::createPSRAMString("Truncated at AuthenticationToken");
        return false;
    }
    uint8_t auth_token_type = data[offset++];
    if (auth_token_type == OPCUA::BYTESTRING) {
        offset += 1; // namespace
        if (!decodeByteString(data, offset, len, out_auth_token)) {
            out_error = PSRAMUtils::createPSRAMString("Failed to decode AuthenticationToken");
            return false;
        }
    } else {
        if (auth_token_type == OPCUA::FOURBYTE) {
            offset += 3;
        } else {
            offset += 1;
        }
    }

    LOG_INFOF(TAG_OPCUA_CODEC, "Parsed CreateSessionResponse: SessionId=%zu bytes, AuthToken=%zu bytes",
              out_session_id.size(), out_auth_token.size());

    return true;
}

bool OPCUABinaryCodec::parseServiceFault(const uint8_t* data, size_t len,
                                        uint32_t& out_status_code,
                                        psram_string& out_diagnostic_info) {
    // ServiceFault is a special response with error information
    // It has the same structure as any response, but TypeId = ServiceFault (395)

    out_status_code = 0;
    out_diagnostic_info = PSRAMUtils::createPSRAMString("");

    if (len < 20) {
        out_diagnostic_info = PSRAMUtils::createPSRAMString("Response too short");
        return false;
    }

    size_t offset = 0;

    // TCP Header
    offset += 8;

    // SecureChannelId
    offset += 4;

    // For MSG messages: Symmetric Security Header
    if (len > 16) {
        char msg_type[4] = {0};
        msg_type[0] = data[0];
        msg_type[1] = data[1];
        msg_type[2] = data[2];

        if (strncmp(msg_type, OPCUA::MSG_MESSAGE, 3) == 0 ||
            strncmp(msg_type, OPCUA::MSG_OPEN, 3) == 0) {
            offset += 4; // TokenId (for MSG) or skip AsymmetricSecurityHeader start
        }
    }

    // Sequence Header (if MSG or OPN)
    offset += 8;

    if (offset >= len) {
        out_diagnostic_info = PSRAMUtils::createPSRAMString("Truncated before ResponseHeader");
        return false;
    }

    // TypeId - skip
    uint8_t node_id_type = data[offset++];
    if (node_id_type == OPCUA::FOURBYTE) {
        offset += 3;
    } else if (node_id_type == OPCUA::TWOBYTE) {
        offset += 1;
    } else {
        offset += 1;
    }

    // ResponseHeader
    if (offset + 16 > len) {
        out_diagnostic_info = PSRAMUtils::createPSRAMString("Truncated ResponseHeader");
        return false;
    }

    offset += 8; // Timestamp
    offset += 4; // RequestHandle

    out_status_code = decodeUInt32(data, offset);

    // Try to decode ServiceDiagnostics for more info
    if (offset >= len) {
        char buf[64];
        snprintf(buf, sizeof(buf), "StatusCode: 0x%08lX", (unsigned long)out_status_code);
        out_diagnostic_info = PSRAMUtils::createPSRAMString(buf);
        return true;
    }

    uint8_t diag_encoding = data[offset++];
    if (diag_encoding != 0) {
        out_diagnostic_info = PSRAMUtils::createPSRAMString("DiagnosticInfo present (detailed parsing not implemented)");
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "StatusCode: 0x%08lX", (unsigned long)out_status_code);
        out_diagnostic_info = PSRAMUtils::createPSRAMString(buf);
    }

    return true;
}
