#!/usr/bin/env python3
"""
EtherNet/IP soak validator.

Runs repeated ENIP discovery/scanner/fuzzing API cycles and collects memory
telemetry to detect progressive degradation.
"""

import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_json_maybe(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
    return None


class EnipSoakValidator:
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str],
        sid: Optional[str],
        verify_tls: bool,
        request_timeout_s: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.sid = sid
        self.verify_tls = verify_tls
        self.request_timeout_s = request_timeout_s
        self.session = requests.Session()
        self.http_errors: List[str] = []

    def _build_url(self, path: str) -> str:
        url = f"{self.base_url}{path}"
        if not self.sid:
            return url
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}sid={self.sid}"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request_json(
        self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], int, str]:
        url = self._build_url(path)
        try:
            if method == "GET":
                resp = self.session.get(
                    url,
                    headers=self._headers(),
                    timeout=self.request_timeout_s,
                    verify=self.verify_tls,
                )
            else:
                resp = self.session.post(
                    url,
                    headers=self._headers(),
                    json=payload or {},
                    timeout=self.request_timeout_s,
                    verify=self.verify_tls,
                )
            status = resp.status_code
            text = resp.text or ""
            if status < 200 or status >= 300:
                err = f"{method} {path} -> HTTP {status}: {text[:180]}"
                self.http_errors.append(err)
                return False, None, status, err
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    return True, parsed, status, ""
                return False, None, status, f"{method} {path} -> JSON root is not object"
            except Exception as exc:
                err = f"{method} {path} -> invalid JSON: {exc}"
                self.http_errors.append(err)
                return False, None, status, err
        except Exception as exc:
            err = f"{method} {path} -> request failed: {exc}"
            self.http_errors.append(err)
            return False, None, 0, err

    def get_selftest_memory(self) -> Optional[Dict[str, Any]]:
        ok, data, _, _ = self._request_json("GET", "/api/diagnostics/selftest")
        if not ok or not data:
            return None
        mem = data.get("memory")
        return mem if isinstance(mem, dict) else None

    def start_discovery(
        self, target: str, timeout_ms: int
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]], str]:
        ok, data, _, err = self._request_json(
            "POST",
            "/api/discovery/start",
            {"protocol": "ethernetip", "target": target, "timeout": timeout_ms},
        )
        if not ok or not data:
            return False, None, None, err
        if not data.get("success"):
            return False, None, data, data.get("message", "discovery_start_failed")
        did = data.get("discovery_id")
        if not isinstance(did, str) or not did:
            return False, None, data, "missing_discovery_id"
        return True, did, data, ""

    def wait_discovery_completion(
        self, discovery_id: str, wait_timeout_s: int, poll_s: float
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        t_end = time.time() + wait_timeout_s
        while time.time() < t_end:
            ok, data, _, err = self._request_json("GET", "/api/discovery/list")
            if not ok or not data:
                time.sleep(poll_s)
                continue
            discoveries = data.get("discoveries")
            if not isinstance(discoveries, list):
                time.sleep(poll_s)
                continue
            for disc in discoveries:
                if not isinstance(disc, dict):
                    continue
                if disc.get("id") != discovery_id:
                    continue
                status = disc.get("status", "")
                if status in ("completed", "failed", "cancelled"):
                    if status == "completed":
                        return True, disc, ""
                    return False, disc, f"discovery_status={status}"
            time.sleep(poll_s)
        return False, None, "discovery_timeout"

    def create_scanner_job(
        self, target: str, scan_types: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[int], str]:
        payload: Dict[str, Any] = {
            "name": "ENIP_Soak",
            "protocol": 4,
            "target": target,
            "enabled": False,
            "interval_sec": 3600,
        }
        if scan_types:
            payload["scan_types"] = scan_types
        ok, data, _, err = self._request_json("POST", "/api/scanner/jobs", payload)
        if not ok or not data:
            return False, None, err
        jid = data.get("id")
        if not isinstance(jid, int):
            return False, None, "scanner_job_id_missing"
        return True, jid, ""

    def run_scanner_job(self, job_id: int) -> Tuple[bool, str]:
        ok, _, _, err = self._request_json("POST", f"/api/scanner/run?id={job_id}")
        return ok, "" if ok else err

    def wait_scanner_result(
        self, job_id: int, wait_timeout_s: int, poll_s: float
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        t_end = time.time() + wait_timeout_s
        while time.time() < t_end:
            ok, data, status, err = self._request_json("GET", f"/api/scanner/result?id={job_id}")
            if ok and data:
                return True, data, ""
            if status == 404:
                time.sleep(poll_s)
                continue
            if err:
                time.sleep(poll_s)
                continue
        return False, None, "scanner_result_timeout"

    def delete_scanner_job(self, job_id: int) -> None:
        # Best effort: endpoint is DELETE, keep simple by requests directly.
        try:
            self.session.delete(
                self._build_url(f"/api/scanner/jobs?id={job_id}"),
                headers=self._headers(),
                timeout=self.request_timeout_s,
                verify=self.verify_tls,
            )
        except Exception:
            pass

    def create_fuzz_job(self, target: str) -> Tuple[bool, Optional[int], str]:
        payload = {
            "protocol": 4,
            "target": target,
            "profile": "default",
            "safe_mode": True,
            "rate_per_sec": 4,
            "max_cases": 8,
            "duration_ms": 20000,
        }
        ok, data, _, err = self._request_json("POST", "/api/fuzz/jobs", payload)
        if not ok or not data:
            return False, None, err
        jid = data.get("job_id")
        if not isinstance(jid, int):
            return False, None, "fuzz_job_id_missing"
        return True, jid, ""

    def run_fuzz_job(self, job_id: int) -> Tuple[bool, str]:
        ok, _, _, err = self._request_json("POST", "/api/fuzz/run", {"job_id": job_id})
        return ok, "" if ok else err

    def wait_fuzz_result(
        self, job_id: int, wait_timeout_s: int, poll_s: float
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        t_end = time.time() + wait_timeout_s
        while time.time() < t_end:
            ok, data, _, _ = self._request_json("GET", f"/api/fuzz/result?job_id={job_id}")
            if ok and data:
                if data.get("error") == "no_result":
                    time.sleep(poll_s)
                    continue
                return True, data, ""
            time.sleep(poll_s)
        return False, None, "fuzz_result_timeout"

    def delete_fuzz_job(self, job_id: int) -> None:
        try:
            self.session.delete(
                self._build_url(f"/api/fuzz/jobs?id={job_id}"),
                headers=self._headers(),
                timeout=self.request_timeout_s,
                verify=self.verify_tls,
            )
        except Exception:
            pass


def _extract_discovery_result(discovery_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    res = discovery_entry.get("results")
    return parse_json_maybe(res)


def _guess_enip_target_from_discovery(discovery_result: Optional[Dict[str, Any]]) -> Optional[str]:
    if not discovery_result:
        return None
    devices = discovery_result.get("devices")
    if not isinstance(devices, list) or not devices:
        return None
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        ip = dev.get("ip")
        port = dev.get("port", 44818)
        if isinstance(ip, str) and ip:
            return f"{ip}:{int(port)}"
    return None


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def build_summary(
    iterations: List[Dict[str, Any]],
    http_errors: List[str],
    dram_drop_warn_bytes: int,
) -> Dict[str, Any]:
    dram_samples: List[int] = []
    psram_samples: List[int] = []
    scanner_internal_after: List[int] = []
    discovery_internal_after: List[int] = []
    failed_iterations = 0

    for item in iterations:
        if not item.get("ok", False):
            failed_iterations += 1
        mem_before = item.get("memory_before") or {}
        mem_after = item.get("memory_after") or {}
        if isinstance(mem_before, dict):
            dram_samples.append(_safe_int(mem_before.get("dram_free"), -1))
            psram_samples.append(_safe_int(mem_before.get("psram_free"), -1))
        if isinstance(mem_after, dict):
            dram_samples.append(_safe_int(mem_after.get("dram_free"), -1))
            psram_samples.append(_safe_int(mem_after.get("psram_free"), -1))

        dmem = item.get("discovery_memory") or {}
        if isinstance(dmem, dict):
            discovery_internal_after.append(_safe_int(dmem.get("internal_after"), -1))
        smem = item.get("scanner_memory") or {}
        if isinstance(smem, dict):
            scanner_internal_after.append(_safe_int(smem.get("internal_after"), -1))

    dram_samples = [x for x in dram_samples if x >= 0]
    psram_samples = [x for x in psram_samples if x >= 0]
    discovery_internal_after = [x for x in discovery_internal_after if x >= 0]
    scanner_internal_after = [x for x in scanner_internal_after if x >= 0]

    dram_initial = dram_samples[0] if dram_samples else -1
    dram_final = dram_samples[-1] if dram_samples else -1
    dram_min = min(dram_samples) if dram_samples else -1
    psram_initial = psram_samples[0] if psram_samples else -1
    psram_final = psram_samples[-1] if psram_samples else -1
    psram_min = min(psram_samples) if psram_samples else -1

    warnings: List[str] = []
    if dram_initial >= 0 and dram_final >= 0:
        drop = dram_initial - dram_final
        if drop > dram_drop_warn_bytes:
            warnings.append(
                f"dram_free dropped by {drop} bytes (threshold {dram_drop_warn_bytes})"
            )

    if discovery_internal_after:
        if (max(discovery_internal_after) - min(discovery_internal_after)) > dram_drop_warn_bytes:
            warnings.append("discovery internal_after variance is high")
    if scanner_internal_after:
        if (max(scanner_internal_after) - min(scanner_internal_after)) > dram_drop_warn_bytes:
            warnings.append("scanner internal_after variance is high")
    if http_errors:
        warnings.append(f"http_errors={len(http_errors)}")
    if failed_iterations > 0:
        warnings.append(f"failed_iterations={failed_iterations}")

    return {
        "iterations_total": len(iterations),
        "iterations_failed": failed_iterations,
        "http_errors": len(http_errors),
        "memory": {
            "dram_initial": dram_initial,
            "dram_final": dram_final,
            "dram_min": dram_min,
            "psram_initial": psram_initial,
            "psram_final": psram_final,
            "psram_min": psram_min,
        },
        "warnings": warnings,
    }


def run() -> int:
    parser = argparse.ArgumentParser(description="EtherNet/IP soak validator")
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://10.2.232.48")
    parser.add_argument("--api-key", default="", help="Optional X-API-Key")
    parser.add_argument("--sid", default="", help="Optional sid query parameter")
    parser.add_argument("--verify-tls", action="store_true", help="Enable TLS certificate verification")
    parser.add_argument("--iterations", type=int, default=8, help="Number of soak iterations")
    parser.add_argument("--pause-s", type=float, default=1.5, help="Pause between iterations")
    parser.add_argument("--discovery-target", default="eth", help="Discovery target for ENIP")
    parser.add_argument("--discovery-timeout-ms", type=int, default=2000)
    parser.add_argument("--wait-discovery-s", type=int, default=35)
    parser.add_argument("--wait-scanner-s", type=int, default=40)
    parser.add_argument("--wait-fuzz-s", type=int, default=50)
    parser.add_argument("--poll-s", type=float, default=1.0)
    parser.add_argument("--target-override", default="", help="Force scanner/fuzz target (IP:PORT)")
    parser.add_argument("--skip-scanner", action="store_true")
    parser.add_argument("--skip-fuzz", action="store_true")
    parser.add_argument("--dram-drop-warn-bytes", type=int, default=16384)
    parser.add_argument("--output", default="tests/enip_soak_report.json")
    args = parser.parse_args()

    cli = EnipSoakValidator(
        base_url=args.url,
        api_key=args.api_key or None,
        sid=args.sid or None,
        verify_tls=args.verify_tls,
        request_timeout_s=12.0,
    )

    iterations: List[Dict[str, Any]] = []
    print(f"[SOAK] start iterations={args.iterations} url={args.url}")
    for idx in range(args.iterations):
        it: Dict[str, Any] = {"iteration": idx + 1, "ok": True, "errors": []}
        print(f"[SOAK] iteration {idx + 1}/{args.iterations}")

        it["memory_before"] = cli.get_selftest_memory()

        ok, did, _, err = cli.start_discovery(args.discovery_target, args.discovery_timeout_ms)
        if not ok or not did:
            it["ok"] = False
            it["errors"].append(f"discovery_start: {err}")
            iterations.append(it)
            time.sleep(args.pause_s)
            continue

        ok, disc_entry, err = cli.wait_discovery_completion(did, args.wait_discovery_s, args.poll_s)
        if not ok or not disc_entry:
            it["ok"] = False
            it["errors"].append(f"discovery_wait: {err}")
            iterations.append(it)
            time.sleep(args.pause_s)
            continue

        it["discovery_status"] = disc_entry.get("status")
        disc_result = _extract_discovery_result(disc_entry)
        it["discovery_result"] = disc_result
        it["discovery_memory"] = (disc_result or {}).get("memory")

        enip_target = args.target_override.strip() or _guess_enip_target_from_discovery(disc_result)
        if not enip_target:
            it["ok"] = False
            it["errors"].append("no_enip_target_from_discovery")
            iterations.append(it)
            time.sleep(args.pause_s)
            continue
        it["enip_target"] = enip_target

        if not args.skip_scanner:
            scan_types = [
                "identity_integrity",
                "session_security",
                "cip_security_advertisement",
                "list_services_consistency",
                "io_channel_exposure",
            ]
            ok, sid, err = cli.create_scanner_job(enip_target, scan_types)
            if not ok or sid is None:
                it["ok"] = False
                it["errors"].append(f"scanner_create: {err}")
            else:
                ok, err = cli.run_scanner_job(sid)
                if not ok:
                    it["ok"] = False
                    it["errors"].append(f"scanner_run: {err}")
                else:
                    ok, scanner_result, err = cli.wait_scanner_result(sid, args.wait_scanner_s, args.poll_s)
                    if not ok or not scanner_result:
                        it["ok"] = False
                        it["errors"].append(f"scanner_result: {err}")
                    else:
                        it["scanner_result"] = scanner_result
                        it["scanner_memory"] = scanner_result.get("memory")
                        it["scanner_risk"] = (scanner_result.get("risk_assessment") or {}).get("overall_risk")
                cli.delete_scanner_job(sid)

        if not args.skip_fuzz:
            ok, fid, err = cli.create_fuzz_job(enip_target)
            if not ok or fid is None:
                it["ok"] = False
                it["errors"].append(f"fuzz_create: {err}")
            else:
                ok, err = cli.run_fuzz_job(fid)
                if not ok:
                    it["ok"] = False
                    it["errors"].append(f"fuzz_run: {err}")
                else:
                    ok, fuzz_result, err = cli.wait_fuzz_result(fid, args.wait_fuzz_s, args.poll_s)
                    if not ok or not fuzz_result:
                        it["ok"] = False
                        it["errors"].append(f"fuzz_result: {err}")
                    else:
                        it["fuzz_result"] = fuzz_result
                cli.delete_fuzz_job(fid)

        it["memory_after"] = cli.get_selftest_memory()
        iterations.append(it)
        time.sleep(args.pause_s)

    report = {
        "target": args.url,
        "iterations": iterations,
        "summary": build_summary(iterations, cli.http_errors, args.dram_drop_warn_bytes),
        "http_error_details": cli.http_errors,
    }

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=True)

    print(f"[SOAK] report written: {args.output}")
    print(json.dumps(report["summary"], indent=2, ensure_ascii=True))

    warnings = report["summary"].get("warnings") or []
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(run())
