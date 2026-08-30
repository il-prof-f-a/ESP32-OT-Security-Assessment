"""Execute the firmware X.509/UA decoder on deterministic, public DER fixtures.

Only ESP allocation/logging/time platform headers are replaced in the temporary
host build. Decoder implementation and ASN.1 inputs are not mocked.
"""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from test_management_policy_cpp import _visual_studio_compiler

ROOT = Path(__file__).resolve().parents[1]


def tlv(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([0x82, length >> 8, length & 255])
    return bytes([tag]) + encoded + value


def certificate(before=b"240101000000Z", after=b"300101000000Z", version=True,
                bad_key=False, bad_extension=False, self_issued=False):
    # Structural fixture, deliberately not a cryptographic trust anchor.
    oid = lambda value: tlv(6, bytes.fromhex(value))
    seq = lambda value: tlv(0x30, value)
    name = lambda cn: seq(tlv(0x31, seq(oid("550403") + tlv(0x0c, cn))))
    sigalg = seq(oid("2a864886f70d01010b") + tlv(5, b""))
    validity = seq(tlv(0x17 if len(before) == 13 else 0x18, before)
                   + tlv(0x17 if len(after) == 13 else 0x18, after))
    modulus = tlv(2, b"\x00\x80" + b"\x55" * 255)
    rsa = seq(modulus + (b"" if bad_key else tlv(2, b"\x01\x00\x01")))
    spki = seq(seq(oid("2a864886f70d010101") + tlv(5, b"")) + tlv(3, b"\x00" + rsa))
    san = seq(tlv(0x82, b"plc.example.test") + tlv(0x87, bytes([192, 0, 2, 1])))
    extensions = tlv(0xa3, seq(seq(oid("551d13") + tlv(1, b"\xff") + (b"" if bad_extension else tlv(4, seq(b""))))
                              + seq(oid("551d11") + tlv(4, san))))
    tbs = ((tlv(0xa0, tlv(2, b"\x02")) if version else b"") + tlv(2, b"\x12\x34")
           + sigalg + name(b"Test PLC" if self_issued else b"Test issuer") + validity + name(b"Test PLC") + spki
           + (extensions if version else b""))
    return seq(seq(tbs) + sigalg + tlv(3, b"\x00" + b"\x55" * 256))


class OpcuaCertificateCppTests(unittest.TestCase):
    def test_firmware_certificate_and_endpoint_regressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for name in ("opcua_binary_codec.h", "opcua_binary_codec.cpp",
                         "opcua_x509_parser.h", "opcua_x509_parser.cpp"):
                source = (ROOT / "src/protocols" / name).read_text(encoding="utf-8")
                source = source.replace('../core/psram_allocator.h', 'host_platform.h')
                source = source.replace('../core/logging_system.h', 'host_platform.h')
                (work / name).write_text(source, encoding="utf-8")
            shutil.copyfile(ROOT / "tests/cpp/opcua_host_platform.h", work / "host_platform.h")
            header = (ROOT / "src/protocols/opcua_vulnerability_tests.h").read_text(encoding="utf-8")
            (work / "opcua_vulnerability_tests.h").write_text(
                header.replace('../core/psram_allocator.h', 'host_platform.h'), encoding="utf-8")
            # Isolate the existing pure assessments from the socket transport for
            # host execution. The function bodies are copied without changes.
            source = (ROOT / "src/protocols/opcua_vulnerability_tests.cpp").read_text(encoding="utf-8")
            bodies = []
            for name in ("assessAnonymousAccess", "testWeakSecurityPolicies", "testCertificateIssues", "testCertificateChainLoop",
                         "calculateCVSS", "cvssToSeverity"):
                pos = source.index("VulnerabilityScanner::" + name + "(")
                start = source.rfind("\n", 0, pos) + 1
                end = source.index("\n}", pos) + 2
                bodies.append(source[start:end])
            (work / "assessment.cpp").write_text(
                '#include "opcua_vulnerability_tests.h"\n#include "opcua_x509_parser.h"\n#include <cmath>\n#include <algorithm>\n'
                'namespace OPCUAVulnerabilityTests {\n' + '\n'.join(bodies)
                + '\nVulnerabilityScanner::VulnerabilityScanner() {}\n'
                + 'VulnerabilityScanner::~VulnerabilityScanner() {}\n}\n', encoding="utf-8")
            (work / "esp_timer.h").write_text("#pragma once\n#include <stdint.h>\nint64_t esp_timer_get_time();\n")
            fixtures = {"v3": certificate(), "v1": certificate(version=False),
                        "future": certificate(b"20510101000000Z", b"20600101000000Z"),
                        "past": certificate(b"500101000000Z", b"690101000000Z"),
                        "bad_date": certificate(b"240230000000Z"),
                        "reversed": certificate(b"300101000000Z", b"240101000000Z"),
                        "bad_key": certificate(bad_key=True),
                        "bad_extension": certificate(bad_extension=True),
                        "self_issued": certificate(self_issued=True)}
            for name, data in fixtures.items():
                (work / (name + ".der")).write_bytes(data)
            def string(value):
                value = value.encode() if isinstance(value, str) else value
                return struct.pack('<i', len(value)) + value

            def endpoint(cert, mode):
                return (string('opc.tcp://192.0.2.1:4840') + string('urn:test:plc')
                        + string('urn:test:product') + b'\x02' + string('Test PLC')
                        + struct.pack('<I', 0) + string('') * 2 + struct.pack('<I', 0)
                        + string(cert) + struct.pack('<I', mode)
                        + string('http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256')
                        + struct.pack('<I', 1) + string('anonymous') + struct.pack('<I', 0)
                        + string('') * 3 + string('ua-tcp') + b'\x01')

            # Sign-only, encrypted, then a malformed certificate: later fields
            # and endpoints must remain aligned when DER metadata fails.
            body = (struct.pack('<IIII', 1, 1, 2, 2) + b'\x01\x00\xaf\x01'
                    + struct.pack('<QII', 0, 1, 0) + b'\x00' + struct.pack('<i', 0)
                    + b'\x00\x00\x00' + struct.pack('<i', 3)
                    + endpoint(fixtures['v3'], 2) + endpoint(fixtures['v3'], 3)
                    + endpoint(b'\x30\x00', 1))
            (work / 'endpoints.der').write_bytes(b'MSGF' + struct.pack('<I', len(body) + 8) + body)
            output = work / ("test.exe" if os.name == "nt" else "test")
            sources = [str(ROOT / "tests/cpp/opcua_certificate_test.cpp"),
                       str(work / "opcua_x509_parser.cpp"), str(work / "opcua_binary_codec.cpp"),
                       str(work / "assessment.cpp")]
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run([cxx, "-std=c++17", "-I" + str(work), *sources, "-o", str(output)], check=True)
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                script = work / "compile.cmd"
                quoted = " ".join('"' + value + '"' for value in sources)
                script.write_text(f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc '
                                  f'/I"{work}" {quoted} /Fe:"{output}"\n', encoding="utf-8")
                subprocess.run(["cmd", "/d", "/c", str(script)], cwd=work, check=True)
            else:
                self.fail("A C++17 compiler is required")
            subprocess.run([str(output), str(work)], check=True)


if __name__ == "__main__":
    unittest.main()
