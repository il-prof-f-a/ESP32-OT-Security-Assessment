# Tests

This directory contains two distinct groups of tests: offline repository tests and live-device security validation tools.

> [!WARNING]
> Run live-device tests only in an isolated laboratory and only against equipment you own or are explicitly authorized to assess. Several scripts generate malformed, hostile, or high-rate traffic. They can interrupt services or alter test-device state.

## Offline tests

Run these tests from the repository root; no ESP32 hardware is required:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

They cover credential-directory resolution, secure first-build provisioning, idempotency, recovery from partial TLS state, certificate/key validation, build integration, board metadata, transport-policy selection, packet-dispatch policy, L2 ingress coverage, and isolation of generated secrets from tracked source paths.

## Live-device tools

Install the HTTP client dependency in a virtual environment:

```bash
python -m pip install requests
```

| Script | Purpose | Typical invocation |
|---|---|---|
| `api_security_pentest.py` | Authentication, authorization, input-validation, information-disclosure, TLS, session, and rate-limit checks | `python tests/api_security_pentest.py --url https://DEVICE_IP` |
| `rate_limiter_load_test.py` | Normal, burst, sustained-load, recovery, and memory-stability scenarios | `python tests/rate_limiter_load_test.py --url https://DEVICE_IP --quick` |
| `ids_integration_test.py` | Baseline, auto-tuning, correlation, persistence, and IDS workflow checks | `python tests/ids_integration_test.py https://DEVICE_IP` |
| `enip_soak_validation.py` | Repeated EtherNet/IP discovery, scanner/fuzzer jobs, and memory-trend reporting | `python tests/enip_soak_validation.py --url https://DEVICE_IP --iterations 3 --skip-fuzz` |
| `memory_telemetry.py` | Periodic DRAM and PSRAM telemetry sampling | `python tests/memory_telemetry.py https://DEVICE_IP --samples 10` |
| `opcua_security_test.py` | OPC UA configuration, discovery, scan, and presence API checks | `python tests/opcua_security_test.py https://DEVICE_IP` |

Use `--help` on any script for all options. Pass credentials at runtime with the relevant `--api-key` or `--admin-password` option. Never commit real credentials or include them in a public issue.

The generated certificate is self-signed. Some tools disable certificate verification by default for lab use; that is not suitable for production. Prefer a trusted certificate or explicit certificate pinning when extending the project beyond a controlled test environment.
