# Reporting UI and filter catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Reporting page a complete, understandable editor for every reporting channel, with a discoverable log-pattern catalog, explicit save feedback, and a compact tabbed layout while preserving the existing reporting APIs and file-log ownership in `/logging`.

**Architecture:** Keep the current `/api/report/channels`, `/api/report/filters`, `/api/report/filter/add`, `/api/report/filter/remove`, `/api/report/endpoints`, `/api/report/queue`, and `/api/logs/sse` contracts unchanged. The page will render a tab per runtime channel, use an embedded catalog generated from the source's stable logging tags and event types for autocomplete/help, and route all mutations through the existing POST handlers with one visible status banner. Endpoint APIs remain compatibility-only; their editor is hidden, and the file channel remains hidden because `/logging` owns persistent-file configuration.

**Tech Stack:** ESP32 embedded C++ reporting engine, static HTML/CSS/JavaScript WebUI, Python unittest contract tests, PlatformIO asset conversion/builds.

---

## Task 1: Establish the source-backed pattern catalog and regression tests

- [x] Extract the stable `LOG_*` tags and report event types from `src/` and document the selected prefixes, keywords, and examples in `docs/user-guide/reporting-filters.md`.
- [x] Add `tests/test_reporting_ui.py` covering: tabbed channels, hidden endpoints/file editor, collapsed stream/queue cards, explicit save controls/status banner, datalist/autocomplete hooks, precedence/help text, and representative catalog entries.
- [x] Run the focused test before implementation and record the expected failures.

## Task 2: Rework the Reporting page layout without changing API semantics

- [x] Make Live Stream and Queue Status `<details>` panels default closed with a prominent left collapse indicator and preserve their existing controls/JavaScript behavior.
- [x] Replace the single channel list with accessible channel tabs and one visible panel at a time; keep the runtime channel names and existing channel/filter identifiers stable.
- [x] Hide the Reporting Endpoints editor and the file channel panel while retaining endpoint loading for compatibility/status metadata.
- [x] Add per-channel configuration/help sections for enabled state, format, verbosity, filter enablement, case sensitivity, include/exclude precedence, and safe examples.

## Task 3: Add pattern discovery and explicit persistence feedback

- [x] Add an escaped static catalog of source-backed tags/event keywords with simple and regular-expression examples.
- [x] Attach `<datalist>` suggestions and a keyboard-friendly suggestion list to include/exclude inputs for every visible channel.
- [x] Add channel and filter Save buttons that invoke the existing POST paths, keep current auto-save behavior where present, and show success/error results in a persistent banner and status area.
- [x] Ensure rendering uses DOM text APIs or escaped values for catalog/filter text and does not introduce HTML/script injection.

## Task 4: Regenerate assets and verify end-to-end contracts

- [x] Regenerate `src/web/ui/gen` with `python scripts/convert_html_in_code.py`.
- [x] Run focused reporting tests, then `python -m unittest discover -s tests -p 'test_*.py' -v`, secret scan, and `git diff --check`.
- [x] Build all four PlatformIO environments with `ESP32_OT_EMBEDDED_CONFIG=0`; record any pre-existing board warning separately.
- [x] Update the private memory files `.ai/tasks-todo.md` and `.ai/session-handoff.md` with the catalog/layout/API decisions and verification results.
- [x] Commit public code/docs/tests and private memory separately; do not push.
