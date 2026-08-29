# Modbus TCP Reference Scans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the safe Modbus-TCP assessment matrix described by `docs/vuln-ass modbustcp.txt`, expose each check in the public scanner UI, and retain explicit safety gates for active or potentially disruptive operations.

**Architecture:** Extend the existing Modbus vulnerability scanner rather than creating a second scanner. A selected scan type maps to one bounded operation; the default profile enables only read-only probes and non-invasive exposure assessments. Device-identification metadata is collected through FC43/MEI 0x0E, while CVE/firmware-age checks produce correlation data and recommendations without contacting an external database or attempting exploits.

**Tech Stack:** C++17 ESP-IDF/FreeRTOS, PlatformIO, cJSON/PSRAM containers, HTML/JavaScript UI, Python `unittest` static-contract tests.

---

### Task 1: Define the reference scan contract in tests

**Files:**
- Modify: `tests/test_build_integration.py`
- Test: `tests/test_build_integration.py`

- [x] **Step 1: Write failing tests**

  Add a test that requires the Modbus implementation and UI to contain:

  - FC43/14 Basic, Regular, Extended and individual-object probes;
  - bounded Unit-ID enumeration;
  - TCP/502 versus TCP/802 security-profile assessment;
  - read-only exception-behaviour probing;
  - cleartext, authentication, allow-list and CVE-correlation result fields;
  - UI entries for every safe matrix item and explicit write exclusion.

- [x] **Step 2: Run the focused test and verify RED**

  ```powershell
  python -m unittest tests.test_build_integration.BuildIntegrationTests.test_modbus_reference_scan_matrix -v
  ```

  Expected: FAIL because the current scanner exposes only the original six read probes and does not implement the reference-matrix controls.

### Task 2: Add bounded Modbus reference probes

**Files:**
- Modify: `src/protocols/modbus_tcp_plugin.h`
- Modify: `src/protocols/modbus_tcp_plugin.cpp`

- [x] **Step 1: Add PDU builders and bounded helpers**

  Add `pduDeviceIdentification(level, object_id)` for FC43/MEI 0x0E, preserving `pduDeviceIdentificationBasic()` as a compatibility wrapper. Add a helper for a single read-only operation on a specified Unit-ID and a helper that opens/closes TCP/802 with the existing socket timeout.

- [x] **Step 2: Map scan types to operations**

  Update `legacyDoVulnerabilityScan()` so `wants(name)` gates each operation. Implement:

  - MB-001: report the established TCP/502 service;
  - MB-002/003/004: FC43 levels 0x01/0x02/0x03;
  - MB-005: optional FC43 object-level request (0x04, object 0);
  - MB-006: report and validate the conformity level from the FC43 response when present;
  - MB-007: enumerate only `cfg_.discovery_unit_ids`, capped at 16 IDs and using read-only Device Identification;
  - MB-008: connect-only comparison of TCP/502 and TCP/802;
  - MB-009/013/014: explicit non-invasive capability/inference results;
  - MB-010: existing read-only function probes;
  - MB-011: optional FC03 address `0xFFFF`, enabled only when explicitly selected;
  - MB-012/015: emit vendor/product/revision correlation fields and a recommendation to perform an external CPE/CVE/age lookup, without network access to a CVE service.

  No reference scan may call `pduWriteSingleRegister`; that remains controlled solely by `cfg_.enable_test_write`.

- [x] **Step 3: Run focused tests and one compile**

  ```powershell
  python -m unittest tests.test_build_integration.BuildIntegrationTests.test_modbus_reference_scan_matrix -v
  pio run -e t-poe-pro
  ```

  Expected: focused test passes and the firmware compiles.

### Task 3: Expose the complete safe matrix in the UI

**Files:**
- Modify: `src/web/ui/scanner.html`

- [x] **Step 1: Add protocol-1 entries**

  Add labels and help text for the matrix IDs used by the backend. Defaults are enabled only for read-only and inference checks; Unit-ID enumeration, invalid-address exception probing, individual-object probing and allow-list assessment are opt-in. Do not add a write checkbox.

- [x] **Step 2: Regenerate embedded assets**

  ```powershell
  python scripts/convert_html_in_code.py
  ```

- [x] **Step 3: Re-run the UI contract test**

  ```powershell
  python -m unittest tests.test_build_integration.BuildIntegrationTests.test_modbus_reference_scan_matrix -v
  ```

### Task 4: Full verification and documentation

**Files:**
- Modify: `docs/superpowers/plans/2026-08-29-modbus-reference-scans.md`
- Generated (ignored): `src/web/ui/gen/*_html_gen.hpp`

- [x] **Step 1: Run all firmware builds**

  ```powershell
  pio run -e t-poe-pro
  pio run -e esp32-s3-eth
  pio run -e waveshare-esp32p4-eth
  pio run -e guition-jc-esp32p4-m3-dev
  ```

- [x] **Step 2: Run the full host suite and diff checks**

  ```powershell
  python -m unittest discover -s tests -p "test_*.py" -v
  git diff --check
  ```

- [x] **Step 3: Record limitations**

  Document that CVE/firmware-age correlation is metadata-only, Modbus Security/TLS is detected by connect-only port probing, and no destructive write or exploit payload is enabled by the reference matrix.
