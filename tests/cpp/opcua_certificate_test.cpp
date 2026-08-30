#include "opcua_x509_parser.h"
#include "opcua_vulnerability_tests.h"
#include <cassert>
#include <fstream>
#include <iterator>
#include <iostream>
#include <ctime>
extern "C" int64_t esp_timer_get_time() { return 399000; }

int main(int argc, char** argv) {
    assert(argc == 2);
    auto load = [&](const char* name) {
        std::ifstream in(std::string(argv[1]) + "/" + name + ".der", std::ios::binary);
        return psram_vector<uint8_t>(std::istreambuf_iterator<char>(in), {});
    };
    X509CertificateInfo info{};
    psram_string error;
    auto der = load("v3");
    bool ok = X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error);
    if (!ok) std::cerr << "Valid v3 certificate rejected: " << error << '\n';
    assert(ok);
    assert(info.subject_common_name == "Test PLC");
    assert(info.issuer_common_name == "Test issuer");
    assert(info.serial_number == "1234");
    assert(info.not_before_timestamp == 1704067200000LL);
    assert(info.not_after_timestamp == 1893456000000LL);
    assert(info.key_size_bits == 2048 && !info.has_weak_key);
    assert(info.parse_ok && info.parse_error.empty());
    X509DER::Parser::evaluateValidity(info, 0);
    assert(!info.time_checked && !info.is_expired && !info.is_not_yet_valid);
    X509DER::Parser::evaluateValidity(info, 1800000000000LL);
    assert(info.time_checked && !info.is_expired && !info.is_not_yet_valid);
    X509DER::Parser::evaluateValidity(info, 2000000000000LL);
    assert(info.time_checked && info.is_expired);
    X509DER::Parser::evaluateValidity(info, 1600000000000LL);
    assert(info.time_checked && info.is_not_yet_valid && !info.is_expired);
    assert(!info.is_self_signed); // Names/metadata are not a signature verification.
    assert(!info.is_ca);
    assert(info.san_dns_names.at(0) == "plc.example.test");
    assert(info.san_ip_addresses.at(0) == "192.0.2.1");
    for (const char* name : {"v1", "future", "past"}) {
        der = load(name);
        assert(X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error));
    }
    for (const char* name : {"bad_date", "reversed", "bad_key", "bad_extension"}) {
        der = load(name);
        assert(!X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error));
        assert(info.not_before_timestamp == 0 && info.not_after_timestamp == 0);
    }
    der = load("v3");
    for (size_t length = 0; length < der.size(); ++length) {
        assert(!X509DER::Parser::parseCertificateFromBinary(der.data(), length, info, error));
        assert(info.not_before_timestamp == 0 && info.not_after_timestamp == 0);
    }
    // The shared request encoder must use Unix time, not the fake 399ms uptime.
    const auto ua_now = OPCUABinaryCodec::getCurrentTimestamp();
    const auto unix_now = OPCUABinaryCodec::opcuaToUnix(ua_now);
    assert(unix_now / 1000 >= static_cast<uint64_t>(time(nullptr)) - 2);
    OPCUAVulnerabilityTests::VulnerabilityScanner scanner;
    OPCUA::GetEndpointsResponse endpoints;
    OPCUAEndpoint ep;
    ep.security_mode = OPCUA::SECURITY_MODE_SIGNANDENCRYPT;
    ep.security_policy_uri = OPCUA::POLICY_BASIC256SHA256;
    ep.server_certificate_der_hex = "fixture-cert";
    der = load("v3");
    assert(X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), ep.server_certificate_info, error));
    endpoints.endpoints.push_back(ep);
    endpoints.endpoints.push_back(ep); // Same cert across endpoints is normal.
    assert(!scanner.testWeakSecurityPolicies(endpoints).vulnerable);
    assert(!scanner.testCertificateChainLoop(endpoints).vulnerable);
    assert(scanner.testCertificateChainLoop(endpoints).inconclusive);
    endpoints.endpoints[0].security_policy_uri = OPCUA::POLICY_BASIC256;
    assert(scanner.testWeakSecurityPolicies(endpoints).vulnerable);
    endpoints.endpoints.clear();
    assert(scanner.testCertificateIssues(endpoints).inconclusive);
    der = load("endpoints");
    psram_vector<OPCUAEndpoint> parsed;
    assert(OPCUABinaryCodec::parseGetEndpointsResponse(der.data(), der.size(), parsed, error));
    assert(parsed.size() == 3);
    assert(!parsed[0].requires_encryption && parsed[1].requires_encryption);
    assert(parsed[0].server_certificate_info.parse_ok);
    assert(parsed[0].server_certificate_info.not_after_timestamp == 1893456000000LL);
    assert(parsed[2].server_certificate_info.parse_ok == false);
    assert(!parsed[2].server_certificate_info.parse_error.empty());
    assert(parsed[2].server_certificate_info.not_after_timestamp == 0);
    for (const auto& endpoint : parsed) {
        assert(endpoint.server_application_name == "Test PLC");
        assert(endpoint.security_policy_uri == OPCUA::POLICY_BASIC256SHA256);
        assert(endpoint.allows_anonymous);
        for (const auto& issue : endpoint.vulnerabilities) assert(issue.find("CRITICAL") == psram_string::npos);
    }
    endpoints.endpoints = parsed;
    const auto anonymous = scanner.assessAnonymousAccess(endpoints);
    assert(anonymous.inconclusive && !anonymous.vulnerable && anonymous.cvss_score == 0);
    assert(anonymous.evidence_source == "get_endpoints");
    // The malformed endpoint always makes evidence incomplete, even if the
    // otherwise valid fixture eventually expires as the host clock advances.
    assert(scanner.testCertificateIssues(endpoints).evidence_incomplete);
    endpoints.endpoints.at(0).server_certificate_info.has_weak_key = true;
    const auto partial = scanner.testCertificateIssues(endpoints);
    assert(partial.vulnerable && !partial.inconclusive && partial.evidence_incomplete);
    der = load("self_issued");
    assert(X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error));
    assert(info.is_self_issued && !info.is_self_signed);
    const auto issuer = der;
    der = load("v3");
    der.insert(der.end(), issuer.begin(), issuer.end());
    assert(X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error));
    assert(info.issuer_common_name == "Test issuer"); // Preserve the leaf, not issuer metadata.
    assert(info.certificates_in_blob == 2);
    psram_vector<size_t> lengths;
    assert(X509DER::Parser::certificateChainLengths(der.data(), der.size(), lengths));
    assert(lengths.size() == 2 && lengths[0] + lengths[1] == der.size());
    der.pop_back();
    assert(!X509DER::Parser::parseCertificateFromBinary(der.data(), der.size(), info, error));
    assert(info.certificates_in_blob == 0 && info.not_after_timestamp == 0);
    assert(!X509DER::Parser::parseCertificate("not-hex", info, error));
    assert(!info.parse_ok && !info.time_checked && info.not_after_timestamp == 0);
    der.clear();
    for (unsigned i = 0; i < 17; ++i) der.insert(der.end(), issuer.begin(), issuer.end());
    assert(!X509DER::Parser::certificateChainLengths(der.data(), der.size(), lengths));
    assert(lengths.empty());
    der.assign(65537, 0);
    assert(!X509DER::Parser::certificateChainLengths(der.data(), der.size(), lengths));
    std::cout << "OPC UA certificate regressions passed\n";
}
