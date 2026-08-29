# Central Offensive-Testing Interlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce one fail-closed authorization policy for every potentially disruptive scanner or fuzzer operation, controlled by authenticated software state and a board-specific physical GPIO interlock.

**Architecture:** A central `OffensiveTestingPolicy` owned by `SecurityManager` will combine the persisted software authorization, the physical gate, and the active board profile. Scanner and protocol plugins will receive the same policy dependency and must re-evaluate it immediately before every state-changing network transmission. Public builds will default to offensive testing disabled and an active-low, pull-up physical gate; explicitly authorized embedded configurations may override this only through a guarded build-time mechanism.

**Tech Stack:** ESP-IDF 5.x, C++17, PlatformIO, NVS, LittleFS, embedded HTML/JavaScript, Python host tests, four ESP32 target environments plus the ESP32-C6 coprocessor.

---

## Hardware decision record

The GPIO gate is active-low with the internal pull-up enabled. The safe/open state therefore reads high. The user enables the physical interlock by connecting the selected GPIO to GND; no external voltage must be injected into the pin.

| Board                     | Default GPIO | Physical choice                                                        | Conflicts checked | Special acceptance requirement |
| ------------------------- | ------------:| ---------------------------------------------------------------------- | ----------------- | ------------------------------ |
| LILYGO T-POE Pro          | GPIO15       | Outermost usable screw-terminal signal, immediately adjacent to GND    | -                 | -                              |
| Waveshare ESP32-S3-ETH    | GPIO16       | Outermost usable signal at the center of the expansion header          | -                 | -                              |
| Waveshare ESP32-P4-ETH    | GPIO16       | Outermost usable signal at the center of the expansion header          | -                 | -                              |
| GUITION JC-ESP32P4-M3-DEV | GPIO1        | First externally exposed P4 GPIO at the end of JP1, close to a GND pin | -                 | -                              |

These selections are defaults, not irrevocable wiring assignments. A board profile will expose the default and the configuration validator will permit a different safe GPIO only after checking a board-specific deny list.

## Policy invariants

- `scanner.enabled` controls whether the scanner/fuzzer module exists; it is not authorization to write to a target.
- Per-job `safe_mode` controls the selected fuzzing profile; it is not the global authorization switch.
- `allowed_writers` remains exclusively an IDS trust concept and must never authorize offensive actions.
- Read-only discovery and vulnerability probes require the module and job to be enabled, but do not require offensive authorization.
- A state-changing or disruptive transmission requires all of the following at send time:
  1. the relevant module and job are enabled;
  2. the user explicitly selected an unsafe test;
  3. the global software authorization is enabled;
  4. the physical GPIO gate is asserted when the gate is configured as required.
- Authorization is checked again immediately before each unsafe network send. Opening the physical contact during a running job blocks the next unsafe step.
- Missing, invalid or corrupt authorization state always fails closed.
- Enabling software authorization or weakening physical-gate settings requires re-entry of the current administrator password.
- Disabling software authorization is immediate and does not require a password.

## Task 1: Add board-specific offensive-testing GPIO profiles

**Files:**

- Create: `src/security/offensive_testing_board_profile.h`

- Create: `src/security/offensive_testing_board_profile.cpp`

- Modify: `platformio.ini`

- Modify: `tests/test_build_integration.py`

- Create: `tests/test_offensive_board_profiles.py`

- [ ] Add a compile-time `OffensiveTestingBoardProfile` containing the board identifier, default GPIO, active level, pull mode, and a deny list of pins already used by onboard peripherals.

- [ ] Select exactly one profile from the existing PlatformIO board macros. Fail the build when no supported profile or more than one profile is selected.

- [ ] Encode these defaults from the hardware decision record: T-POE Pro GPIO15, ESP32-S3-ETH GPIO16, Waveshare ESP32-P4-ETH GPIO16, and GUITION JC-ESP32P4-M3-DEV GPIO1.

- [ ] Add `isAllowedOffensiveTestingGpio(int gpio)` so runtime configuration cannot select an Ethernet, SD, coprocessor, flash/PSRAM, console, or other reserved pin.

- [ ] Keep the deny list conservative. Reject an unknown pin rather than accepting it solely because it is numerically valid.

- [ ] Add host tests that parse all four PlatformIO environments and prove each has one profile, one expected default and no collision with its declared peripherals.

- [ ] Add compile-time assertions for GPIO range and default-pin allow-list membership.

## Task 2: Make generated and embedded configuration board-aware

**Files:**

- Modify: `scripts/build_assets.py`

- Modify: `config.example.json`

- Modify: `src/core/configuration_manager.h`

- Modify: `src/core/configuration_manager.cpp`

- Modify: `tests/test_build_assets.py`

- Modify: `tests/test_build_integration.py`

- [ ] Add this configuration shape under `security.offensive_testing`:

```json
{
  "software_enabled": false,
  "boot_policy": "seed_if_absent",
  "gpio_gate": {
    "enabled": true,
    "required": true,
    "gpio": 15,
    "active_high": false,
    "pull_mode": 1
  }
}
```

- [ ] Make `_public_defaults()` receive the target environment or resolved board profile and emit that board's GPIO instead of a universal number.
- [ ] Preserve public defaults as software disabled, physical gate enabled and required, active-low, internal pull-up.
- [ ] Define `seed_if_absent` as: seed the policy only when no valid persisted record exists; later UI changes survive reboot.
- [ ] Define `force_config` as: reapply embedded policy at every boot and identify the source as `config_override` in status and audit output.
- [ ] Permit a test/release-specific relaxation only when both `ESP32_OT_EMBEDDED_CONFIG=1` and `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE=1` are present during asset generation.
- [ ] Make generation fail if an embedded configuration enables offensive testing, disables the gate, makes it optional, or changes the safe boot policy without the second environment variable.
- [ ] Ensure public CI and release workflows never set `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE`.
- [ ] Document PowerShell setup and cleanup for the two environment variables so an override cannot accidentally remain in the shell.
- [ ] Test all four generated configurations, rejection of an unguarded override, acceptance of an explicitly guarded override and cleanup of generated secrets.

## Task 3: Centralize policy evaluation and robust persistence

**Files:**

- Create: `src/security/offensive_testing_policy.h`

- Create: `src/security/offensive_testing_policy.cpp`

- Modify: `src/security/security_manager.h`

- Modify: `src/security/security_manager.cpp`

- Modify: `src/core/async_storage_engine.h`

- Modify: `src/core/async_storage_engine.cpp`

- Create: `tests/test_offensive_testing_policy.py`

- [ ] Model distinct values for software authorization, GPIO enabled, GPIO required, pin, active level, pull mode, configuration source and effective authorization.

- [ ] Return a structured decision with `allowed`, `reason`, `software_enabled`, `gpio_asserted`, `gpio_required` and `source`, rather than a bare boolean.

- [ ] Initialize the GPIO only after validating it against the active board profile. On validation or driver failure, keep authorization blocked.

- [ ] Replace the existing long GPIO NVS keys with one versioned blob stored in namespace `security` under the short key `off_policy_v1`.

- [ ] Store a magic value, schema version, all policy fields and CRC32 in the blob. Validate length, version, field domains and CRC before applying it.

- [ ] Use the existing asynchronous storage path for blob reads and writes, and ensure the commit result is returned to the API caller.

- [ ] Migrate the legacy `fuzzing_allowed` value once: preserve only its software bit and seed all physical settings from the board profile. Never depend on the legacy long keys.

- [ ] On missing state, seed from configuration. On corrupt state, fail closed, use the board's required GPIO gate and emit one bounded diagnostic/audit event.

- [ ] Expose one `SecurityManager::evaluateOffensiveTesting()` entry point and keep compatibility wrappers only while callers are migrated.

- [ ] Add tests for default denial, all software/GPIO combinations, active-low behavior, invalid GPIO rejection, CRC corruption, legacy migration, seed persistence and `force_config` behavior.

## Task 4: Apply the policy to every disruptive protocol path

**Files:**

- Modify: `src/protocols/base_plugin.h`

- Modify: `src/protocols/plugin_manager.h`

- Modify: `src/protocols/plugin_manager.cpp`

- Modify: `src/main.cpp`

- Modify: `src/assessment/vulnerability_scanner.h`

- Modify: `src/assessment/vulnerability_scanner.cpp`

- Modify: `src/assessment/fuzzing_engine.h`

- Modify: `src/assessment/fuzzing_engine.cpp`

- Modify: `src/protocols/modbus_tcp_plugin.cpp`

- Modify: `src/protocols/s7comm_plugin.cpp`

- Modify: `src/protocols/ethernet_ip_plugin.cpp`

- Modify: `src/protocols/profinet_plugin.cpp`

- Modify: `src/protocols/opcua_plugin.cpp`

- Modify: `tests/test_build_integration.py`

- Create: `tests/test_offensive_gate_coverage.py`

- [ ] Pass `SecurityManager*` into `PluginManager`, inject it into every `BasePlugin`, and remove the S7-only special injection from `main.cpp`.

- [ ] Pass the same dependency into `VulnerabilityScanner`; retain it in `FuzzingEngine` but replace its one-time job-start decision with per-operation checks.

- [ ] Add a small common helper that audits and returns a terminal blocked result without transmitting when authorization is absent.

- [ ] Classify and guard Modbus write-capability probes, unauthorized writes, Force Listen Only, broadcast writes and vulnerability exploits.

- [ ] Require three independent conditions for the Modbus write-capability probe: plugin configuration opt-in, explicit job scan-type selection and the central offensive policy. Supersede the current two-condition local edit.

- [ ] Classify and guard S7 variable writes, STOP, hot/cold restart and unsafe fuzz cases.

- [ ] Classify and guard EtherNet/IP `SetAttributeSingle`, Reset and unsafe fuzz cases.

- [ ] Classify and guard PROFINET DCP Set Name/IP, device replacement, factory reset and unsafe fuzz cases.

- [ ] Classify and guard OPC UA disruptive denial-of-service payloads and unsafe fuzz profiles while leaving read-only endpoint discovery available.

- [ ] Re-evaluate immediately before each unsafe send, not only when creating or starting a job.

- [ ] Return a distinct `BLOCKED_BY_OFFENSIVE_POLICY` result to the UI and reports; do not misreport this as a target vulnerability or network failure.

- [ ] Add source-level coverage tests that enumerate every known unsafe operation and prove that it calls the central policy directly before its transport send.

## Task 5: Add authenticated policy APIs and audit behavior

**Files:**

- Modify: `src/web/security_api.h`

- Modify: `src/web/security_api.cpp`

- Modify: `src/web/web_server.cpp`

- Modify: `src/security/auth_manager.h`

- Modify: `src/security/auth_manager.cpp`

- Modify: `tests/test_build_integration.py`

- Create: `tests/test_offensive_testing_api.py`

- [ ] Add `GET /api/security/offensive-testing` returning software state, GPIO configuration, sampled GPIO state, effective authorization, policy source and a machine-readable blocking reason.

- [ ] Add `POST /api/security/offensive-testing` for changes. Do not overload the IDS writer or generic scanner endpoints.

- [ ] Require `admin_password` when changing `software_enabled` from false to true or when weakening/changing the physical interlock.

- [ ] Verify the password using the existing administrator password hash path. Never persist, echo or log the plaintext password; overwrite its request buffer as soon as practical.

- [ ] Rate-limit failed confirmations and emit a security audit event without including the password.

- [ ] Allow immediate unauthenticated transition from enabled to disabled for emergency shutdown.

- [ ] Reject invalid or reserved GPIO values before scheduling persistence.

- [ ] Return a storage error only when the asynchronous NVS transaction actually fails; return the resulting effective state after a successful commit.

- [ ] Preserve the existing `/security` view by adapting it to the new API and removing writes to the over-length legacy NVS GPIO keys.

- [ ] Add tests for authorization, password failure, rate limiting, weakening attempts, safe disable, reserved pins, persistence errors and response redaction.

## Task 6: Present one shared control in Scanner & Fuzzing UI

**Files:**

- Modify: `web/scanner.html`

- Modify: `web/security.html`

- Modify: `scripts/convert_html_in_code.py`

- Regenerate: `src/web/generated/scanner_html.h`

- Regenerate: `src/web/generated/security_html.h`

- Modify: `tests/test_web_ui.py`

- Modify: `tests/test_build_integration.py`

- [ ] Place an `Offensive Testing` switch directly below `Enable Scanner & Fuzzing Module` and above `Enable Scheduled Scans (Cron)`.

- [ ] Because `/scanner`, `/vulnerability-scanner` and `/fuzzing` share `scanner.html`, ensure the control and behavior appear consistently on all aliases.

- [ ] Show separate badges for software authorization, physical contact and effective authorization, plus a concise blocking reason.

- [ ] On enable, open a password modal and submit only after explicit confirmation. Do not leave the switch visually enabled if the backend rejects the password or cannot persist state.

- [ ] On disable, update immediately and cancel or block the next unsafe operation in active jobs.

- [ ] Keep unsafe scan types visible but disabled with an explanation while effective authorization is false.

- [ ] Clearly distinguish module enablement, global offensive authorization and per-job Safe Mode.

- [ ] Show a warning that password re-authentication on the T-POE Pro HTTP-only management interface is not confidential in transit; recommend an isolated management network.

- [ ] Update `security.html` to use the same status terminology and API rather than presenting an independent flag.

- [ ] Regenerate all embedded HTML headers and run the repository-wide HTML synchronization test for every page, not just these two files.

## Task 7: Document wiring, security model and controlled overrides

**Files:**

- Modify: `README.md`

- Modify: `docs/user-guide/scanner-and-fuzzing.md`

- Modify: `docs/user-guide/security.md`

- Modify: `docs/devices/lilygo-t-poe-pro.md`

- Modify: `docs/devices/waveshare-esp32-s3-eth.md`

- Modify: `docs/devices/waveshare-esp32-p4-eth.md`

- Modify: `docs/devices/guition-jc-esp32p4-m3-dev.md`

- Modify: `config.example.json`

- Create: `docs/security/offensive-testing-interlock.md`

- [ ] Explain the two-part interlock, fail-closed behavior, per-send revalidation and the difference from IDS `allowed_writers` and job Safe Mode.

- [ ] Add one wiring section per board with the selected pin, adjacent GND, active-low behavior and the instruction to use a dry contact or jumper to GND only.

- [ ] Add a prominent GUITION warning: do not connect 3.3 V from the CH340 or another external supply while the USB power path is attached.

- [ ] Add the T-POE Pro GPIO15 boot-strapping caveat and the verified open/closed boot results after hardware acceptance.

- [ ] Document how to select a non-default pin, list the reserved categories and explain that validation may reject exposed-looking pins used by onboard peripherals.

- [ ] Document `seed_if_absent`, `force_config`, the guarded embedded-config override and the exact environment-variable cleanup procedure.

- [ ] State that a production/public release must never ship with software authorization forced on or the physical gate weakened.

- [ ] Link the new security page from the README and relevant device pages.

## Task 8: Run the full automated validation matrix

**Files:**

- Verify only; fix the responsible task before proceeding if any command fails.

- [ ] Regenerate embedded web assets:

```powershell
python scripts/convert_html_in_code.py
```

- [ ] Run all host tests:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

- [ ] Build application firmware and LittleFS for every target with local embedded configuration excluded:

```powershell
$env:ESP32_OT_EMBEDDED_CONFIG='0'
pio run -e t-poe-pro
pio run -e t-poe-pro -t buildfs
pio run -e esp32-s3-eth
pio run -e esp32-s3-eth -t buildfs
pio run -e waveshare-esp32p4-eth
pio run -e waveshare-esp32p4-eth -t buildfs
pio run -e guition-jc-esp32p4-m3-dev
pio run -e guition-jc-esp32p4-m3-dev -t buildfs
Remove-Item Env:ESP32_OT_EMBEDDED_CONFIG
```

- [ ] Build the GUITION ESP32-C6 coprocessor firmware:

```powershell
pio run --project-dir coprocessor/esp32c6 -e esp32c6-coprocessor
```

- [ ] Run the same secret-scan and release-policy commands used by GitHub Actions and confirm that local credentials and embedded configurations are excluded.
- [ ] Run `git diff --check` and confirm generated HTML headers match their source pages.

## Task 9: Perform hardware and browser acceptance tests

**Files:**

- Record verified results in: `docs/security/offensive-testing-interlock.md`

- Update board pages only with observed results.

- [ ] On every available board, verify the default GPIO reads safe while open and asserted when jumpered directly to GND.

- [ ] Verify boot, cold power-up and reset with the contact open and closed. Treat any bootloop, peripheral failure or pin contention as a board-profile blocker.

- [ ] Specifically verify the T-POE Pro GPIO15 behavior and serial boot visibility in both states.

- [ ] Verify a wrong password cannot enable software authorization and a correct password cannot make the policy effective while a required physical contact is open.

- [ ] Verify closing the contact makes the already-authorized policy effective and opening it removes authorization without a reboot.

- [ ] Verify disabling the software switch takes effect immediately and persists in normal `seed_if_absent` mode.

- [ ] Verify read-only Modbus and OPC UA scans still work while offensive authorization is blocked.

- [ ] Select the Modbus write-capability test while blocked and capture traffic proving that no FC06 write is transmitted.

- [ ] Enable both gates, run the bounded Modbus write-capability test and verify it writes back the existing value and leaves the PLC value unchanged.

- [ ] Start a bounded unsafe fuzz job, open the physical contact before the next case and verify that the next unsafe packet is not sent and the job reports `BLOCKED_BY_OFFENSIVE_POLICY`.

- [ ] Exercise normal NVS persistence across reboot and a deliberately authorized `force_config` development build across reboot.

- [ ] On GUITION, repeat the gate test with Ethernet and ESP32-C6 Wi-Fi active concurrently.

## Final review checklist

- [ ] Search the source tree for every state-changing protocol primitive and confirm it is either centrally guarded or explicitly documented as read-only.
- [ ] Search for direct reads of `fuzzing_allowed`, legacy GPIO keys and plugin-local write-enable flags; retain none as standalone authorization decisions.
- [ ] Confirm no API response, audit record, serial log, report or crash dump contains an administrator password.
- [ ] Confirm public defaults and all release artifacts remain fail-closed.
- [ ] Confirm the board pin table in documentation matches the compile-time profiles and generated configuration for all four boards.
- [ ] Review all staged changes before any commit; do not include local credentials, device configuration or unrelated working-tree modifications.
