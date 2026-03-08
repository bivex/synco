#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "time_watchdog_crc32"

CASES = [
    {
        "name": "date_header_fallback",
        "args": ["https://example.com", "5000", "10000", "3000"],
        "expected": {
            "remote_time_source": "http_date_header",
            "remote_time_field": "Date",
            "anomaly_detected": "0",
        },
        "nonempty": ["http_date_header", "smart_crc32"],
    },
    {
        "name": "json_timestamp_binance",
        "args": ["https://api.binance.com/api/v3/time", "5000", "10000", "3000"],
        "expected": {
            "remote_time_source": "json_body_timestamp",
            "remote_time_field": "serverTime",
            "remote_time_precision_ms": "1",
            "anomaly_detected": "0",
        },
        "nonempty": ["smart_crc32"],
    },
]


def parse_key_values(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_case(case: dict[str, object]) -> None:
    command = [str(BINARY), *case["args"]]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"{case['name']} failed with rc={completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    fields = parse_key_values(completed.stdout)
    status_code = int(fields.get("http_status_code", "0"))
    assert_true(200 <= status_code < 400, f"{case['name']} unexpected http_status_code={status_code}")
    assert_true(fields.get("time_source") == "commpage_https_watchdog", f"{case['name']} wrong time_source")

    for key, expected_value in case["expected"].items():
        actual_value = fields.get(key)
        assert_true(actual_value == expected_value, f"{case['name']} expected {key}={expected_value}, got {actual_value}")

    for key in case["nonempty"]:
        assert_true(bool(fields.get(key)), f"{case['name']} expected non-empty {key}")

    print(f"[PASS] {case['name']}")


def main() -> int:
    if not BINARY.exists():
        print(f"missing binary: {BINARY}", file=sys.stderr)
        return 1

    try:
        for case in CASES:
            run_case(case)
    except Exception as exc:  # noqa: BLE001
        print(f"integration test failed: {exc}", file=sys.stderr)
        return 1

    print("time_watchdog_crc32 integration tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())