# Hardware Interlock Build-Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the fuzzing GPIO hardware interlock mandatory in release/public firmware and allow configuration bypass only in an explicitly authorized development build.

**Architecture:** Keep `ESP32_OT_EMBEDDED_CONFIG` responsible only for selecting embedded versus provisioning configuration. Reuse the existing guarded `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE` build authorization and expose its decision to the firmware through a generated build-assets macro. In firmware, enforce the gate in `SecurityManager` and the security API; in the UI, render the controls locked when the build does not authorize bypass. Keep `fuzzing_allowed_effective` fail-closed and report the blocking reason.

**Tech Stack:** ESP-IDF C++, PlatformIO build scripts, generated C++ asset headers, browser JavaScript, Python unittest suite, Markdown documentation.

---

### Task 1: Add failing policy and API tests

**Files:**
- Modify: `tests/test_offensive_config_assets.py`
- Modify: `tests/test_offensive_api_contract.py`
- Modify: `tests/test_offensive_config_assets.py`
- Modify: `tests/test_dashboard_ui.py`

- [x] Add assertions that a non-authorized build rejects gate disable/optional values and that an authorized build exposes the development bypass marker.
- [x] Add source/UI assertions that the Security page distinguishes build authorization from runtime switch state and locks the gate controls in release mode.
- [x] Run the focused tests and confirm they failed before implementation, then passed after implementation.

### Task 2: Propagate an explicit build authorization marker

**Files:**
- Modify: `scripts/build_assets.py`
- Modify: `scripts/convert_html_in_code.py` only if required by generated metadata
- Modify: `src/security/security_manager.h`
- Modify: `src/security/security_manager.cpp`

- [x] Define a generated boolean indicating whether `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE=1` was explicitly present during asset generation.
- [x] Keep the marker false when the environment variable is absent or embedded configuration is disabled, including all CI/release builds.
- [x] Add `SecurityManager::isOffensiveInterlockBypassAuthorized()` and use the marker rather than `ESP32_OT_EMBEDDED_CONFIG` to authorize runtime relaxation.

### Task 3: Enforce the mandatory gate server-side

**Files:**
- Modify: `src/security/security_manager.cpp`
- Modify: `src/web/security_api.h`
- Modify: `src/web/web_server.cpp` only if response plumbing requires it

- [x] In non-authorized builds, force `gpio_gate.enabled=true` and `gpio_gate.required=true` during load and configuration updates.
- [x] Reject API attempts to disable or weaken the gate with a machine-readable error and preserve the previous safe policy.
- [x] Ensure `evaluateOffensiveTesting()` never returns `allowed=true` in a non-authorized build while the physical gate is absent, disabled, optional, invalid, or not asserted.
- [x] Preserve password verification for all offensive-policy changes and keep `force_config` restricted to authorized development builds.
- [x] Expose build authorization and a clear blocking reason through `/api/security/config`.

### Task 4: Lock and explain the Security UI

**Files:**
- Modify: `src/web/ui/security.html`
- Regenerate: ignored `src/web/ui/gen/*.hpp` through `scripts/convert_html_in_code.py`

- [x] Disable the gate enable/required/configuration controls when the build marker is false.
- [x] Keep the current switch state visible and explain that an OFF/open GPIO blocks effective authorization in release builds.
- [x] Show an explicit development-only bypass notice when the marker is true.
- [x] Do not rely on UI locking for security; the API remains authoritative.

### Task 5: Update security guide, user guide, README and related references

**Files:**
- Modify: `docs/security/offensive-testing-interlock.md`
- Modify: `docs/user-guide/security-settings.md`
- Modify: `docs/user-guide/vulnerability-scanner.md`
- Modify: `README.md`

- [x] Document `fuzzing_allowed`, `fuzzing_gpio_gate_enabled`, `fuzzing_gpio_gate_required`, `fuzzing_gpio_gate_state` and `fuzzing_allowed_effective`.
- [x] Explain `ESP32_OT_EMBEDDED_CONFIG` versus `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE` and the `seed_if_absent`/`force_config` policies.
- [x] State that public/release firmware cannot bypass the hardware interlock and requires the configured pin asserted.
- [x] Document the development-only command sequence and cleanup of the authorization variable.

### Task 6: Full verification

**Files:**
- Test: all `tests/test_*.py`
- Build: all four PlatformIO environments

- [x] Run the focused red/green tests, then the complete host suite.
- [x] Regenerate web assets and run `git diff --check`.
- [x] Build `t-poe-pro`, `esp32-s3-eth`, `waveshare-esp32p4-eth` and `guition-jc-esp32p4-m3-dev`.
- [x] Verify no credentials or development authorization are present in public/release generated assets.
