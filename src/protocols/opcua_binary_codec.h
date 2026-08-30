#pragma once

#include "../core/psram_allocator.h"
#include <cstdint>
#include <cstddef>

// OPC UA Binary Protocol Constants
namespace OPCUA {
    // Message Types
    constexpr char MSG_HELLO[] = "HEL";
    constexpr char MSG_ACK[] = "ACK";
    constexpr char MSG_ERROR[] = "ERR";
    constexpr char MSG_OPEN[] = "OPN";
    constexpr char MSG_CLOSE[] = "CLO";
    constexpr char MSG_MESSAGE[] = "MSG";

    // Chunk Types
    constexpr char CHUNK_FINAL = 'F';
    constexpr char CHUNK_INTERMEDIATE = 'C';
    constexpr char CHUNK_ABORT = 'A';

    // Security Policies
    constexpr char POLICY_NONE[] = "http://opcfoundation.org/UA/SecurityPolicy#None";
    constexpr char POLICY_BASIC128RSA15[] = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
    constexpr char POLICY_BASIC256[] = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
    constexpr char POLICY_BASIC256SHA256[] = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
    constexpr char POLICY_AES128SHA256RSAOAEP[] = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";
    constexpr char POLICY_AES256SHA256RSAPSS[] = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

    // Message Security Modes
    enum SecurityMode : uint32_t {
        SECURITY_MODE_INVALID = 0,
        SECURITY_MODE_NONE = 1,
        SECURITY_MODE_SIGN = 2,
        SECURITY_MODE_SIGNANDENCRYPT = 3
    };

    // User Identity Token Types
    enum UserTokenType : uint32_t {
        ANONYMOUS = 0,
        USERNAME = 1,
        CERTIFICATE = 2,
        ISSUEDTOKEN = 3,
        KERBEROS = 4
    };

    // Service Type IDs (from UA Part 4 & 6)
    constexpr uint16_t SERVICE_GETENDPOINTS = 428;
    constexpr uint16_t SERVICE_FINDSERVERS = 422;
    constexpr uint16_t SERVICE_CREATESESSION = 461;
    constexpr uint16_t SERVICE_ACTIVATESESSION = 467;
    constexpr uint16_t SERVICE_CLOSESESSION = 473;
    constexpr uint16_t SERVICE_READ = 631;
    constexpr uint16_t SERVICE_WRITE = 673;
    constexpr uint16_t SERVICE_BROWSE = 527;
    constexpr uint16_t SERVICE_CALL = 712;
    constexpr uint16_t SERVICE_CREATESUBSCRIPTION = 785;
    constexpr uint16_t SERVICE_CREATEMONITOREDITEM = 751;
    constexpr uint16_t SERVICE_PUBLISH = 826;

    // Security Token Request Type
    enum SecurityTokenRequestType : uint32_t {
        ISSUE = 0,
        RENEW = 1
    };

    // Node ID Encoding
    enum NodeIdType : uint8_t {
        TWOBYTE = 0x00,
        FOURBYTE = 0x01,
        NUMERIC = 0x02,
        STRING = 0x03,
        GUID = 0x04,
        BYTESTRING = 0x05
    };
}

// X.509 Certificate Info (DER parsed)
struct X509CertificateInfo {
    psram_string subject_common_name;
    psram_string subject_organization;
    psram_string issuer_common_name;
    psram_string issuer_organization;
    psram_string serial_number;          // Hex string
    int64_t not_before_timestamp = 0;    // UTC Unix milliseconds (may predate 1970)
    int64_t not_after_timestamp = 0;
    psram_string signature_algorithm;    // "sha256WithRSAEncryption", etc.
    uint16_t key_size_bits = 0;
    bool key_size_known = false;
    bool is_self_signed = false;        // Never inferred from matching names
    bool is_self_issued = false;        // Exact issuer/subject DER match; not trust
    bool is_expired = false;
    bool is_not_yet_valid = false;
    bool is_ca = false;
    bool parse_ok = false;
    uint16_t certificates_in_blob = 0;  // Leaf metadata only; appended issuers are not trusted.
    bool time_checked = false;
    psram_string parse_error;
    psram_string_vector san_dns_names;   // Subject Alternative Names
    psram_string_vector san_ip_addresses;

    // Security assessment flags
    bool has_weak_key = false;           // RSA <2048 bits; unknown algorithms not guessed
    bool has_weak_signature = false;     // MD5, SHA1
    psram_string_vector vulnerabilities; // "WEAK_KEY_SIZE", "EXPIRED", etc.
};

// User Identity Token Policy
struct UserIdentityTokenPolicy {
    psram_string policy_id;
    uint32_t token_type;                 // OPCUA::UserTokenType
    psram_string issued_token_type;      // For ISSUEDTOKEN
    psram_string issuer_endpoint_url;
    psram_string security_policy_uri;
};

// Endpoint Description (from GetEndpoints response)
struct OPCUAEndpoint {
    psram_string endpoint_url;           // "opc.tcp://192.168.1.100:4840"
    psram_string server_application_uri;
    psram_string server_product_uri;
    psram_string server_application_name;
    uint32_t server_application_type;    // 0=Server, 1=Client, 2=ClientAndServer, 3=DiscoveryServer
    psram_string server_gateway_server_uri;
    psram_string server_discovery_profile_uri;
    psram_string_vector server_discovery_urls;

    psram_string security_policy_uri;    // Full URI
    uint32_t security_mode;              // OPCUA::SecurityMode
    psram_string transport_profile_uri;
    uint8_t security_level;              // 0-255

    // Server Certificate (DER binary -> hex string + parsed)
    psram_string server_certificate_der_hex;
    X509CertificateInfo server_certificate_info;

    // User Identity Tokens
    psram_vector<UserIdentityTokenPolicy> user_identity_tokens;

    // Derived flags for vulnerability assessment
    bool allows_anonymous;
    bool allows_username_password;
    bool allows_certificate;
    bool requires_encryption;
    bool is_secure;                      // Overall assessment

    // Vulnerabilities detected
    psram_string_vector vulnerabilities;

    OPCUAEndpoint() : server_application_type(0), security_mode(0), security_level(0),
                     allows_anonymous(false), allows_username_password(false),
                     allows_certificate(false), requires_encryption(false), is_secure(false) {}
};

// Server Info (aggregated from discovery)
struct OPCUAServerInfo {
    psram_string target_ip;
    uint16_t target_port;

    psram_string server_uri;
    psram_string product_uri;
    psram_string server_name;
    uint32_t application_type;           // Server=0, Client=1, etc.

    // Connection state
    bool hello_ack_success;
    bool secure_channel_opened;
    uint32_t secure_channel_id;
    uint32_t security_token_id;
    uint32_t sequence_number;
    uint32_t request_id;

    // Discovery results
    psram_vector<OPCUAEndpoint> endpoints;
    uint64_t discovery_timestamp_ms;

    // Vulnerability summary
    uint32_t critical_count;
    uint32_t high_count;
    uint32_t medium_count;
    uint32_t low_count;
    float cvss_score;
    psram_string risk_level;             // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"

    OPCUAServerInfo() : target_port(4840), application_type(0),
                       hello_ack_success(false), secure_channel_opened(false),
                       secure_channel_id(0), security_token_id(0),
                       sequence_number(0), request_id(0),
                       discovery_timestamp_ms(0),
                       critical_count(0), high_count(0), medium_count(0), low_count(0),
                       cvss_score(0.0f) {}
};

// GetEndpoints Response structure
namespace OPCUA {
    struct GetEndpointsResponse {
        psram_string application_uri;
        psram_vector<OPCUAEndpoint> endpoints;

        GetEndpointsResponse() {}
    };

    enum class MessageType {
        HELLO,
        ACK,
        ERROR,
        OPEN,
        CLOSE,
        MESSAGE,
        UNKNOWN
    };

    // Message builder namespace
    class MessageBuilder {
    public:
        static psram_vector<uint8_t> buildHelloMessage(const char* endpoint_url);
        static psram_vector<uint8_t> buildGetEndpointsRequest(const char* endpoint_url);
    };

    // Binary codec namespace
    class BinaryCodec {
    public:
        static bool parseGetEndpointsResponse(const uint8_t* data, size_t len,
                                             GetEndpointsResponse& out_response,
                                             MessageType& out_msg_type,
                                             psram_string& out_error);
    };
}

// OPC UA Binary Codec - Encoding/Decoding utilities
class OPCUABinaryCodec {
public:
    // ==================== ENCODING ====================

    // Encode primitives (Little Endian)
    static void encodeUInt8(psram_vector<uint8_t>& buf, uint8_t value);
    static void encodeUInt16(psram_vector<uint8_t>& buf, uint16_t value);
    static void encodeUInt32(psram_vector<uint8_t>& buf, uint32_t value);
    static void encodeUInt64(psram_vector<uint8_t>& buf, uint64_t value);
    static void encodeInt32(psram_vector<uint8_t>& buf, int32_t value);
    static void encodeInt64(psram_vector<uint8_t>& buf, int64_t value);

    // Encode string (Int32 length + UTF-8 bytes, -1 for null)
    static void encodeString(psram_vector<uint8_t>& buf, const char* str);
    static void encodeString(psram_vector<uint8_t>& buf, const psram_string& str);

    // Encode ByteString (Int32 length + bytes, -1 for null)
    static void encodeByteString(psram_vector<uint8_t>& buf, const uint8_t* data, int32_t len);

    // Encode Array length
    static void encodeArrayLength(psram_vector<uint8_t>& buf, int32_t count);

    // ==================== DECODING ====================

    static uint8_t decodeUInt8(const uint8_t* data, size_t& offset);
    static uint16_t decodeUInt16(const uint8_t* data, size_t& offset);
    static uint32_t decodeUInt32(const uint8_t* data, size_t& offset);
    static uint64_t decodeUInt64(const uint8_t* data, size_t& offset);
    static int32_t decodeInt32(const uint8_t* data, size_t& offset);
    static int64_t decodeInt64(const uint8_t* data, size_t& offset);

    // Decode string (returns psram_string, handles null as empty)
    static psram_string decodeString(const uint8_t* data, size_t& offset, size_t max_len);

    // Decode ByteString to hex string
    static psram_string decodeByteStringAsHex(const uint8_t* data, size_t& offset, size_t max_len);

    // Decode ByteString to PSRAM buffer
    static bool decodeByteString(const uint8_t* data, size_t& offset, size_t max_len,
                                 psram_vector<uint8_t>& out_bytes);

    // Decode array length
    static int32_t decodeArrayLength(const uint8_t* data, size_t& offset);

    // Skip ByteString without decoding
    static bool skipByteString(const uint8_t* data, size_t& offset, size_t max_len);

    // ==================== MESSAGE BUILDERS ====================

    // Build OPC UA TCP header (8 bytes: type[3] + chunk[1] + length[4])
    static void buildMessageHeader(psram_vector<uint8_t>& buf, const char* msg_type,
                                   char chunk_type, uint32_t message_size);

    // Build RequestHeader structure (common to all services)
    static void buildRequestHeader(psram_vector<uint8_t>& buf,
                                   uint64_t timestamp_utc,
                                   uint32_t request_handle,
                                   uint32_t timeout_ms);

    // Build OpenSecureChannel request
    static bool buildOpenSecureChannelRequest(psram_vector<uint8_t>& out_msg,
                                             const char* endpoint_url,
                                             const char* security_policy_uri,
                                             uint32_t requested_lifetime_ms);

    // Build GetEndpoints request
    static bool buildGetEndpointsRequest(psram_vector<uint8_t>& out_msg,
                                        uint32_t secure_channel_id,
                                        uint32_t security_token_id,
                                        uint32_t sequence_number,
                                        uint32_t request_id,
                                        const char* endpoint_url);

    // Build CreateSession request
    static bool buildCreateSessionRequest(psram_vector<uint8_t>& out_msg,
                                         uint32_t secure_channel_id,
                                         uint32_t security_token_id,
                                         uint32_t sequence_number,
                                         uint32_t request_id,
                                         const char* endpoint_url,
                                         const char* session_name);

    // Build CloseSecureChannel request
    static bool buildCloseSecureChannelRequest(psram_vector<uint8_t>& out_msg,
                                              uint32_t secure_channel_id,
                                              uint32_t security_token_id,
                                              uint32_t sequence_number,
                                              uint32_t request_id);

    // ==================== MESSAGE PARSERS ====================

    // Parse OpenSecureChannel response
    static bool parseOpenSecureChannelResponse(const uint8_t* data, size_t len,
                                              uint32_t& out_secure_channel_id,
                                              uint32_t& out_security_token_id,
                                              psram_string& out_error);

    // Parse GetEndpoints response
    static bool parseGetEndpointsResponse(const uint8_t* data, size_t len,
                                         psram_vector<OPCUAEndpoint>& out_endpoints,
                                         psram_string& out_error);

    // Parse CreateSession response
    static bool parseCreateSessionResponse(const uint8_t* data, size_t len,
                                          psram_vector<uint8_t>& out_session_id,
                                          psram_vector<uint8_t>& out_auth_token,
                                          psram_string& out_error);

    // Parse service fault (error response)
    static bool parseServiceFault(const uint8_t* data, size_t len,
                                 uint32_t& out_status_code,
                                 psram_string& out_diagnostic_info);

    // ==================== HELPERS ====================

    // Get current timestamp in OPC UA format (100-nanosecond intervals since 1601-01-01)
    static uint64_t getCurrentTimestamp();

    // Convert Unix timestamp to OPC UA timestamp
    static uint64_t unixToOPCUA(uint64_t unix_timestamp_ms);

    // Convert OPC UA timestamp to Unix
    static uint64_t opcuaToUnix(uint64_t opcua_timestamp);
};
