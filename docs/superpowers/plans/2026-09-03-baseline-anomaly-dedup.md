# Baseline Anomaly Deduplication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve real IDS baseline anomalies while preventing duplicate packet/flow evaluation and repeated reports for one persistent condition.

**Architecture:** A packet continues to perform the baseline comparison once. Flow analysis remains responsible for flow-specific findings (malformed traffic, flooding and operation-sequence anomalies), without repeating the baseline comparison. Each protocol baseline manager keeps a volatile PSRAM-backed timestamp keyed by endpoint and anomaly type; the first occurrence is emitted immediately and identical occurrences are suppressed for 60 seconds. This state is not persisted and is cleared with the baseline reset.

**Tech Stack:** C++17, ESP-IDF, PSRAM-backed containers, Python `unittest` contract tests.

---

### Task 1: Lock down the intended anomaly-evaluation contract

**Files:**

- Create: `tests/test_baseline_anomaly_dedup.py`
- Modify: `src/assessment/anomaly_detection_engine.cpp`
- Modify: `src/assessment/protocol_baseline.h`
- Modify: `src/assessment/protocol_baseline.cpp`

- [x] **Step 1: Write failing regression tests**

Add Python tests that require exactly one `baseline.detectAnomalies(...)` invocation in `AnomalyDetectionEngine`, and require `ProtocolBaselineManager` to expose a per-endpoint/type cooldown state and helper.

- [x] **Step 2: Verify that the tests fail**

Run: `python -m unittest tests.test_baseline_anomaly_dedup -v`

Expected: failures because flow analysis currently calls `baseline.detectAnomalies(...)` a second time and no cooldown helper exists.

- [x] **Step 3: Remove the duplicate baseline evaluation**

Keep this packet path unchanged:

```cpp
baseline.detectAnomalies(..., baseline_findings);
```

Remove the equivalent call from `AnomalyDetectionEngine::analyzeFlow()`. Retain flow-specific calls to `appendMalformedFlowAnomaly`, `appendFloodingIndicators`, and `appendSequenceAnomaly`.

- [x] **Step 4: Add a bounded repeat suppression helper**

Add a `psram_map<psram_string, uint64_t>` to `ProtocolBaselineManager`, keyed by `<endpoint>|<AnomalyType>`, and a 60,000 ms cooldown. Before appending each baseline anomaly, call the helper; append and report only when the key is absent or expired. Clear this volatile state in `resetBaseline()`.

- [x] **Step 5: Verify the focused test**

Run: `python -m unittest tests.test_baseline_anomaly_dedup -v`

Expected: all focused tests pass.

### Task 2: Verify firmware and host integration

**Files:**

- Modify: `tests/test_baseline_anomaly_dedup.py`
- Modify: `src/assessment/anomaly_detection_engine.cpp`
- Modify: `src/assessment/protocol_baseline.h`
- Modify: `src/assessment/protocol_baseline.cpp`

- [x] **Step 1: Run the complete host suite**

Run: `python -m unittest discover -s tests -q`

Expected: all tests pass.

- [x] **Step 2: Compile the GUITION firmware without upload**

Run: `platformio run --environment guition-jc-esp32p4-m3-dev`

Expected: successful firmware build; no serial-port access, upload, or erase action.

- [x] **Step 3: Commit the isolated correction**

Run:

```text
git add docs/superpowers/plans/2026-09-03-baseline-anomaly-dedup.md tests/test_baseline_anomaly_dedup.py src/assessment/anomaly_detection_engine.cpp src/assessment/protocol_baseline.h src/assessment/protocol_baseline.cpp
git commit -m "fix(ids): deduplicate repeated baseline anomalies"
```

**Manual validation:** Start one Modbus discovery against a known PLC. The first qualifying baseline anomaly may be reported; identical endpoint/type detections must not recur for 60 seconds, and the previous packet/flow duplicate pair must be absent.
