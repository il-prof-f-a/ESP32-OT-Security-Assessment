#!/usr/bin/env python3
"""
Memory Telemetry Monitor

Polls the device self-test endpoint to collect PSRAM/DRAM usage samples.
Useful while running external stress tests (e.g. reporting queue flood,
fuzzing jobs) to verify that low-memory alerts are emitted correctly.
"""

import argparse
import sys
import time
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_memory_snapshot(base_url: str, api_key: Optional[str]) -> Optional[dict]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}/api/diagnostics/selftest",
            headers=headers,
            timeout=10,
            verify=False,
        )
        if resp.status_code != 200:
            print(f"[WARN] HTTP {resp.status_code} while querying selftest")
            return None
        data = resp.json()
        return data.get("memory")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[ERROR] request failed: {exc}")
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory telemetry sampler")
    parser.add_argument("target", help="Target base URL (e.g. https://192.168.4.1)")
    parser.add_argument("--api-key", help="API key for authenticated endpoints")
    parser.add_argument("--samples", type=int, default=10, help="Number of samples to collect")
    parser.add_argument("--interval", type=float, default=2.0, help="Interval between samples (seconds)")
    args = parser.parse_args()

    psram_min = None
    dram_min = None

    for idx in range(args.samples):
        snapshot = fetch_memory_snapshot(args.target, args.api_key)
        if snapshot:
            psram_free = snapshot.get("psram_free", 0)
            dram_free = snapshot.get("dram_free", 0)
            psram_min = psram_free if psram_min is None else min(psram_min, psram_free)
            dram_min = dram_free if dram_min is None else min(dram_min, dram_free)
            print(
                f"[{idx + 1}/{args.samples}] "
                f"psram_free={psram_free}B psram_min={snapshot.get('psram_min', 0)}B "
                f"dram_free={dram_free}B dram_min={snapshot.get('dram_min', 0)}B"
            )
        else:
            print(f"[{idx + 1}/{args.samples}] no data")
        if idx + 1 < args.samples:
            time.sleep(args.interval)

    print("\nSummary:")
    print(f"  Lowest PSRAM free : {psram_min if psram_min is not None else 'n/a'} bytes")
    print(f"  Lowest DRAM free  : {dram_min if dram_min is not None else 'n/a'} bytes")


if __name__ == "__main__":
    main()
