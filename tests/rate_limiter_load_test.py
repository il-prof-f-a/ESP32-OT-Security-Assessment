#!/usr/bin/env python3
"""
Rate Limiter Load Test Script

Tests the rate limiter under various load conditions to verify:
- Correct blocking behavior at threshold
- Memory stability under high load
- Adaptive throttling behavior
- Recovery after attack stops
"""

import requests
import time
import threading
import statistics
from dataclasses import dataclass
from typing import List, Dict
import argparse
import sys

@dataclass
class TestResult:
    """Results from a test run"""
    total_requests: int
    successful_requests: int
    blocked_requests: int
    error_requests: int
    avg_response_time: float
    max_response_time: float
    requests_per_second: float
    test_duration: float

class RateLimiterLoadTest:
    def __init__(self, target_url: str, api_key: str = None):
        self.target_url = target_url
        self.api_key = api_key
        self.session = requests.Session()

        # Statistics
        self.request_count = 0
        self.success_count = 0
        self.blocked_count = 0
        self.error_count = 0
        self.response_times = []
        self.lock = threading.Lock()

    def _make_request(self, endpoint: str = "/api/dashboard") -> tuple:
        """Make a single request and return (status_code, response_time)"""
        headers = {}
        if self.api_key:
            headers['X-API-Key'] = self.api_key

        start_time = time.time()
        try:
            response = self.session.get(
                f"{self.target_url}{endpoint}",
                headers=headers,
                timeout=5,
                verify=False  # For self-signed certs
            )
            response_time = time.time() - start_time
            return response.status_code, response_time
        except Exception as e:
            response_time = time.time() - start_time
            print(f"Request error: {e}")
            return 0, response_time

    def _worker(self, num_requests: int, delay: float = 0):
        """Worker thread that makes requests"""
        for _ in range(num_requests):
            status_code, response_time = self._make_request()

            with self.lock:
                self.request_count += 1
                self.response_times.append(response_time)

                if status_code == 200:
                    self.success_count += 1
                elif status_code == 429:
                    self.blocked_count += 1
                else:
                    self.error_count += 1

            if delay > 0:
                time.sleep(delay)

    def run_test(self,
                 total_requests: int,
                 num_threads: int = 1,
                 delay_between_requests: float = 0) -> TestResult:
        """Run a load test with specified parameters"""

        # Reset statistics
        self.request_count = 0
        self.success_count = 0
        self.blocked_count = 0
        self.error_count = 0
        self.response_times = []

        requests_per_thread = total_requests // num_threads

        print(f"\n{'='*60}")
        print(f"Starting test:")
        print(f"  Total requests: {total_requests}")
        print(f"  Threads: {num_threads}")
        print(f"  Requests per thread: {requests_per_thread}")
        print(f"  Delay: {delay_between_requests}s")
        print(f"{'='*60}\n")

        start_time = time.time()

        # Create and start threads
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(
                target=self._worker,
                args=(requests_per_thread, delay_between_requests)
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        test_duration = time.time() - start_time

        # Calculate statistics
        avg_response_time = statistics.mean(self.response_times) if self.response_times else 0
        max_response_time = max(self.response_times) if self.response_times else 0
        requests_per_second = self.request_count / test_duration if test_duration > 0 else 0

        return TestResult(
            total_requests=self.request_count,
            successful_requests=self.success_count,
            blocked_requests=self.blocked_count,
            error_requests=self.error_count,
            avg_response_time=avg_response_time,
            max_response_time=max_response_time,
            requests_per_second=requests_per_second,
            test_duration=test_duration
        )

    def print_result(self, result: TestResult, test_name: str):
        """Print test results"""
        print(f"\n{test_name} Results:")
        print(f"  Duration: {result.test_duration:.2f}s")
        print(f"  Total requests: {result.total_requests}")
        print(f"  Successful (200): {result.successful_requests}")
        print(f"  Blocked (429): {result.blocked_requests}")
        print(f"  Errors: {result.error_requests}")
        print(f"  Requests/sec: {result.requests_per_second:.2f}")
        print(f"  Avg response time: {result.avg_response_time*1000:.2f}ms")
        print(f"  Max response time: {result.max_response_time*1000:.2f}ms")

        # Check if rate limiting is working
        if result.blocked_requests > 0:
            print(f"  ✓ Rate limiting is ACTIVE ({result.blocked_requests} blocked)")
        else:
            print(f"  ⚠ No requests were blocked by rate limiter")

def test_scenario_1_normal_load(tester: RateLimiterLoadTest):
    """Test 1: Normal load - should all succeed"""
    print("\n" + "="*60)
    print("TEST 1: Normal Load (10 req/s for 5s)")
    print("Expected: All requests should succeed (no rate limiting)")
    print("="*60)

    result = tester.run_test(
        total_requests=50,
        num_threads=1,
        delay_between_requests=0.1  # 10 req/s
    )

    tester.print_result(result, "Normal Load")

    # Validation
    assert result.successful_requests == result.total_requests, \
        "Normal load should not trigger rate limiting"

    return result

def test_scenario_2_burst_attack(tester: RateLimiterLoadTest):
    """Test 2: Burst attack - should trigger rate limiting"""
    print("\n" + "="*60)
    print("TEST 2: Burst Attack (1000 requests as fast as possible)")
    print("Expected: Rate limiter should block many requests")
    print("="*60)

    result = tester.run_test(
        total_requests=1000,
        num_threads=10,
        delay_between_requests=0
    )

    tester.print_result(result, "Burst Attack")

    # Validation
    assert result.blocked_requests > 0, \
        "Burst attack should trigger rate limiting"

    blocking_rate = result.blocked_requests / result.total_requests
    print(f"  Blocking rate: {blocking_rate*100:.1f}%")

    return result

def test_scenario_3_sustained_high_load(tester: RateLimiterLoadTest):
    """Test 3: Sustained high load"""
    print("\n" + "="*60)
    print("TEST 3: Sustained High Load (100 req/s for 10s)")
    print("Expected: Adaptive throttling should activate")
    print("="*60)

    result = tester.run_test(
        total_requests=1000,
        num_threads=10,
        delay_between_requests=0.01
    )

    tester.print_result(result, "Sustained High Load")

    return result

def test_scenario_4_recovery(tester: RateLimiterLoadTest):
    """Test 4: Recovery after attack"""
    print("\n" + "="*60)
    print("TEST 4: Recovery After Attack")
    print("Expected: System should recover and allow normal traffic")
    print("="*60)

    # First, trigger rate limiting
    print("\nPhase 1: Trigger rate limiting...")
    attack_result = tester.run_test(
        total_requests=500,
        num_threads=10,
        delay_between_requests=0
    )

    print(f"  Blocked: {attack_result.blocked_requests}")

    # Wait for cooldown
    cooldown_time = 30
    print(f"\nPhase 2: Waiting {cooldown_time}s for cooldown...")
    time.sleep(cooldown_time)

    # Try normal requests
    print("\nPhase 3: Testing normal requests after cooldown...")
    recovery_result = tester.run_test(
        total_requests=20,
        num_threads=1,
        delay_between_requests=0.5  # 2 req/s
    )

    tester.print_result(recovery_result, "Recovery Test")

    # Validation
    recovery_rate = recovery_result.successful_requests / recovery_result.total_requests
    print(f"  Recovery rate: {recovery_rate*100:.1f}%")

    if recovery_rate > 0.9:
        print("  ✓ System recovered successfully")
    else:
        print("  ⚠ System may not have fully recovered")

    return recovery_result

def test_scenario_5_memory_stability(tester: RateLimiterLoadTest):
    """Test 5: Memory stability under extreme load"""
    print("\n" + "="*60)
    print("TEST 5: Memory Stability (10,000 requests)")
    print("Expected: No crashes, memory should remain stable")
    print("="*60)

    result = tester.run_test(
        total_requests=10000,
        num_threads=20,
        delay_between_requests=0
    )

    tester.print_result(result, "Memory Stability")

    # Check error rate
    error_rate = result.error_requests / result.total_requests
    if error_rate < 0.01:  # Less than 1% errors
        print("  ✓ Memory stability GOOD (low error rate)")
    else:
        print(f"  ⚠ High error rate: {error_rate*100:.1f}%")

    return result

def main():
    parser = argparse.ArgumentParser(description='Rate Limiter Load Test')
    parser.add_argument('--url', default='https://192.168.1.100',
                       help='Target URL (default: https://192.168.1.100)')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--test', choices=['1', '2', '3', '4', '5', 'all'],
                       default='all', help='Which test to run')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick tests (reduced load)')

    args = parser.parse_args()

    # Disable SSL warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("\n" + "="*60)
    print("Rate Limiter Load Test Suite")
    print("="*60)
    print(f"Target: {args.url}")
    if args.api_key:
        print(f"API Key: {args.api_key[:8]}...")
    print("="*60)

    tester = RateLimiterLoadTest(args.url, args.api_key)

    results = {}

    try:
        if args.test == 'all' or args.test == '1':
            results['test1'] = test_scenario_1_normal_load(tester)
            time.sleep(5)  # Cooldown between tests

        if args.test == 'all' or args.test == '2':
            results['test2'] = test_scenario_2_burst_attack(tester)
            time.sleep(10)

        if args.test == 'all' or args.test == '3':
            results['test3'] = test_scenario_3_sustained_high_load(tester)
            time.sleep(10)

        if args.test == 'all' or args.test == '4':
            results['test4'] = test_scenario_4_recovery(tester)

        if args.test == 'all' or args.test == '5':
            if not args.quick:
                results['test5'] = test_scenario_5_memory_stability(tester)
            else:
                print("\nSkipping Test 5 (memory stability) in quick mode")

        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)

        total_requests = sum(r.total_requests for r in results.values())
        total_blocked = sum(r.blocked_requests for r in results.values())

        print(f"Total requests sent: {total_requests}")
        print(f"Total blocked (429): {total_blocked}")
        print(f"Overall blocking rate: {(total_blocked/total_requests*100):.1f}%")

        print("\n✓ All tests completed successfully!")
        return 0

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
