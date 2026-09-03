# Single Active Web Session Token Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace permissive `sid` validation with one volatile, server-held session token that rotates on login, expires after 600 seconds without an authenticated request, and invalidates on logout or server shutdown.

**Architecture:** Keep the existing `sid` query-string transport and Bearer header used by the UI. Add one process-wide session record protected by a C++ mutex in `WebServer`; API keys remain independent. HTML page handlers continue redirecting unauthenticated requests to `/login`, while API handlers continue returning `401`.

**Tech Stack:** ESP-IDF HTTP server, C++17, `std::mutex`, monotonic `esp_timer_get_time()`, Python `unittest`, PlatformIO asset generation.

---

### Task 1: Write failing session-contract tests

**Files:** create `tests/test_single_session_contract.py`; inspect `src/web/web_server.h`, `src/web/web_server.cpp`, and `src/web/ui/login.html`.

- [x] Add tests asserting `kSessionIdleTimeoutMs == 600000`, active token state, mutex protection, exact active-token validation, login replacement, logout invalidation, shutdown invalidation, and retained `?sid=` transport.
- [x] Run `python -m unittest tests.test_single_session_contract -v` from the public repository. The initial RED run failed because the current firmware had no server-side session registry and still accepted arbitrary long development tokens.

### Task 2: Add server-side single-session state

**Files:** modify `src/web/web_server.h` and `src/web/web_server.cpp`; test with `tests/test_single_session_contract.py`.

- [x] Declare `static constexpr uint64_t kSessionIdleTimeoutMs = 600000ULL`, `session_mutex_`, `active_session_token_[64]`, `active_session_last_activity_ms_`, `active_session_valid_`, plus `isActiveSessionToken`, `replaceActiveSession`, and `invalidateActiveSession` beside `check_session()`.
- [x] Define the static state near `WebServer::self_`.
- [x] Implement `isActiveSessionToken` under the mutex: reject null/empty values, expire when `now_ms - last_activity >= kSessionIdleTimeoutMs`, compare the complete token, and refresh activity only on an exact match. Never accept a prefix, length, or development-token naming convention.
- [x] Implement `replaceActiveSession` to overwrite the fixed buffer and set validity/time; implement `invalidateActiveSession` to clear buffer, validity, and timestamp while logging only a non-secret reason.

### Task 3: Enforce rotation, expiry, and logout

**Files:** modify `src/web/web_server.cpp`; test with `tests/test_single_session_contract.py`.

- [x] In `check_session`, retain API-key validation but replace the development fallback with `isActiveSessionToken(sid)`.
- [x] In `check_api_auth`, retain API-key validation but replace `is_dev_token || strlen(token) >= 16` with `isActiveSessionToken(token)`.
- [x] In `h_login_post`, call `replaceActiveSession(tok_buf, esp_timer_get_time()/1000ULL)` immediately after generating the token and before redirecting to the existing `/?sid=%s` location. Do not persist the token.
- [x] In `h_logout`, extract `sid` from the query string first, then Bearer header as a compatibility fallback; invalidate only when it matches the active token. Preserve cookie clearing and prevent stale tokens from revoking newer sessions.
- [x] Invalidate the active token at the beginning of `WebServer::shutdown()`.
- [x] Run `python -m unittest tests.test_single_session_contract -v` and `python -m unittest discover -s tests -p 'test_*.py' -v`; all pass.

### Task 4: Document the browser-visible behavior

**Files:** modify `docs/user-guide/login.md`.

- [x] Document one volatile web token per device, immediate revocation by a new login, the 600-second idle timer refreshed by authenticated requests, revocation on logout/restart, independent API keys, and the continued `sid` query transport.
- [x] Run the session-contract test again.

### Task 5: Regenerate assets and perform full verification

**Files:** generated `src/web/ui/gen/*`; verification across all environments.

- [x] Run `python scripts/convert_html_in_code.py`.
- [x] Run `python -m unittest discover -s tests -p 'test_*.py' -v`.
- [x] Build `t-poe-pro`, `esp32-s3-eth`, `waveshare-esp32p4-eth`, and `guition-jc-esp32p4-m3-dev` with `platformio run -e <environment>`.
- [x] Run `git diff --check` and inspect the diff to confirm no full token is logged or persisted, API-key behavior is unchanged, and permissive length/prefix acceptance is gone.
