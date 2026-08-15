#!/usr/bin/env python3
"""
OPC UA Security Integration Test Suite

This script exercises the key OPC UA management APIs exposed by the firmware:
  * Protocol configuration retrieval and update
  * Security configuration inspection (enforcement flag)
  * IDS configuration with OPC UA rate limits
  * Network presence configuration endpoint
  * OPC UA discovery API

The goal is to provide automated coverage for the features described in the
project plan update (subscription hardening, policy enforcement, baseline
tracking). Each test uses HTTPS REST calls against the device web API.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import List, Optional

import requests
import urllib3


# Allow self-signed certificates (device usually exposes one)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    name: str
    passed: bool
    severity: str
    message: str
    details: str = ""


class OPCUASecurityTest:
    def __init__(self, target: str, api_key: Optional[str]):
        self.base_url = target.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.results: List[TestResult] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _record(self, result: TestResult) -> None:
        self.results.append(result)
        status = "PASS" if result.passed else "FAIL"
        line = f"[{status}] {result.name} - {result.message}"
        print(line)
        if result.details:
            print(f"       {result.details}")

    def _request_json(self, method: str, path: str, *, params=None, payload=None):
        url = f"{self.base_url}{path}"
        response = self.session.request(
            method,
            url,
            headers=self._headers(),
            params=params,
            data=json.dumps(payload) if payload is not None else None,
            timeout=10,
            verify=False,
        )
        return response

    # ------------------------------------------------------------------
    # Individual tests
    # ------------------------------------------------------------------
    def test_protocol_config_get(self) -> None:
        name = "Fetch OPC UA protocol configuration"
        try:
            resp = self._request_json("GET", "/api/protocols/opcua/config")
            if resp.status_code != 200:
                self._record(TestResult(name, False, "high", "Unexpected HTTP status", f"Status {resp.status_code}"))
                return

            data = resp.json()
            required_keys = {"enabled", "port", "connect_timeout_ms", "session_timeout_ms"}
            missing = [key for key in required_keys if key not in data]
            if missing:
                self._record(
                    TestResult(
                        name,
                        False,
                        "medium",
                        "Missing expected keys in configuration",
                        f"Missing: {', '.join(missing)}",
                    )
                )
                return

            # Store for later reuse
            self._protocol_config_snapshot = data
            self._record(TestResult(name, True, "info", "Configuration retrieved successfully"))
        except Exception as exc:
            self._record(TestResult(name, False, "high", "Exception during request", str(exc)))

    def test_protocol_config_post_noop(self) -> None:
        name = "Round trip OPC UA protocol configuration"
        snapshot = getattr(self, "_protocol_config_snapshot", None)
        if not snapshot:
            self._record(TestResult(name, False, "high", "Configuration snapshot unavailable (previous test failed)"))
            return

        try:
            resp = self._request_json("POST", "/api/protocols/opcua/config", payload=snapshot)
            if resp.status_code == 200 and resp.text.strip().upper() == "OK":
                self._record(TestResult(name, True, "info", "POST accepted with existing configuration"))
            else:
                detail = f"Status {resp.status_code}, body '{resp.text[:120]}'"
                self._record(TestResult(name, False, "medium", "Unexpected response from POST", detail))
        except Exception as exc:
            self._record(TestResult(name, False, "high", "Exception during POST", str(exc)))

    def test_security_config_flag(self) -> None:
        name = "Security config exposes OPC UA enforcement flag"
        try:
            resp = self._request_json("GET", "/api/security/config")
            if resp.status_code != 200:
                self._record(TestResult(name, False, "high", "Unexpected HTTP status", f"Status {resp.status_code}"))
                return

            data = resp.json()
            config = data.get("config", {})
            if "opcua_enforce_security" not in config:
                self._record(
                    TestResult(
                        name,
                        False,
                        "medium",
                        "opcua_enforce_security flag missing",
                        f"Keys present: {', '.join(sorted(config.keys()))}" if isinstance(config, dict) else "N/A",
                    )
                )
                return

            value = config["opcua_enforce_security"]
            self._record(
                TestResult(name, True, "info", "Security flag present", f"opcua_enforce_security={value}")
            )
        except Exception as exc:
            self._record(TestResult(name, False, "high", "Exception while reading security config", str(exc)))

    def test_ids_general_config(self) -> None:
        name = "IDS general config exposes OPC UA rate limit"
        try:
            resp = self._request_json("GET", "/api/ids/advanced/config")
            if resp.status_code != 200:
                self._record(TestResult(name, False, "high", "Unexpected HTTP status", f"Status {resp.status_code}"))
                return

            data = resp.json()
            if "max_per_sec_opcua" not in data:
                self._record(
                    TestResult(
                        name,
                        False,
                        "medium",
                        "max_per_sec_opcua missing from IDS config",
                        f"Keys present: {', '.join(sorted(data.keys()))}",
                    )
                )
                return

            limit = data["max_per_sec_opcua"]
            self._record(
                TestResult(name, True, "info", "Rate limit available", f"max_per_sec_opcua={limit}")
            )
        except Exception as exc:
            self._record(TestResult(name, False, "high", "Exception while reading IDS config", str(exc)))

    def test_network_presence_config(self) -> None:
        name = "Network presence config reachable"
        try:
            resp = self._request_json("GET", "/api/ids/presence/config")
            if resp.status_code != 200:
                self._record(TestResult(name, False, "medium", "Unexpected HTTP status", f"Status {resp.status_code}"))
                return

            data = resp.json()
            required = {"enabled", "learning_mode", "trust_threshold_score"}
            missing = [key for key in required if key not in data]
            if missing:
                self._record(
                    TestResult(
                        name,
                        False,
                        "low",
                        "Missing keys in presence config",
                        f"Missing: {', '.join(missing)}",
                    )
                )
                return

            self._record(TestResult(name, True, "info", "Presence configuration retrieved"))
        except Exception as exc:
            self._record(TestResult(name, False, "medium", "Exception while reading presence config", str(exc)))

    def test_opcua_discovery_endpoint(self) -> None:
        name = "OPC UA discovery endpoint responds"
        try:
            params = {"target": "127.0.0.1:4840", "timeout": "2000"}
            resp = self._request_json("POST", "/api/discovery/opcua", params=params)

            if resp.status_code == 200:
                body = resp.text.strip()
                summary = "empty response (no devices)" if not body else f"{len(body)} bytes"
                self._record(TestResult(name, True, "info", f"Discovery call succeeded: {summary}"))
            else:
                self._record(TestResult(name, False, "medium", "Unexpected HTTP status", f"Status {resp.status_code}"))
        except Exception as exc:
            self._record(TestResult(name, False, "medium", "Exception during discovery call", str(exc)))

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------
    def run(self) -> None:
        self.test_protocol_config_get()
        self.test_protocol_config_post_noop()
        self.test_security_config_flag()
        self.test_ids_general_config()
        self.test_network_presence_config()
        self.test_opcua_discovery_endpoint()

    def summary(self) -> bool:
        total = len(self.results)
        passed = sum(1 for item in self.results if item.passed)
        failed = total - passed

        print("\nSummary")
        print("-------")
        print(f"Total tests: {total}")
        print(f"Passed     : {passed}")
        print(f"Failed     : {failed}")

        if failed:
            print("\nFailures:")
            for item in self.results:
                if not item.passed:
                    print(f"- {item.name} ({item.severity}) -> {item.message}")
                    if item.details:
                        print(f"  {item.details}")

        return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="OPC UA Security Integration Tests")
    parser.add_argument("target", help="Target base URL (e.g. https://192.168.4.1)")
    parser.add_argument("--api-key", help="API key for authenticated endpoints")
    args = parser.parse_args()

    tester = OPCUASecurityTest(args.target, args.api_key)
    tester.run()
    success = tester.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
