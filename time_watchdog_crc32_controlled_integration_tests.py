#!/usr/bin/env python3

from __future__ import annotations

import email.utils
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "time_watchdog_crc32"


def http_date(epoch_seconds: float | int | None = None) -> str:
    return email.utils.formatdate(epoch_seconds, usegmt=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        now_ms = time.time_ns() // 1_000_000
        if self.path == "/redirect-json":
            self._send(302, b"redirect", {"Location": "/json-precise", "Date": http_date()})
        elif self.path == "/redirect-step-1":
            self._send(302, b"redirect1", {"Location": "/redirect-step-2", "Date": http_date()})
        elif self.path == "/redirect-step-2":
            self._send(302, b"redirect2", {"Location": "/json-precise", "Date": http_date()})
        elif self.path == "/redirect-loop-a":
            self._send(302, b"loopa", {"Location": "/redirect-loop-b", "Date": http_date()})
        elif self.path == "/redirect-loop-b":
            self._send(302, b"loopb", {"Location": "/redirect-loop-a", "Date": http_date()})
        elif self.path == "/json-precise":
            self._send_json(200, {"serverTime": now_ms}, {"Date": http_date()})
        elif self.path == "/status-429":
            self._send_json(429, {"error": "rate limit"}, {"Date": http_date()})
        elif self.path == "/status-500":
            self._send_json(500, {"error": "internal"}, {"Date": http_date()})
        elif self.path == "/malformed-json":
            self._send(200, b"{not-json", {"Content-Type": "application/json", "Date": http_date()})
        elif self.path == "/invalid-date":
            self._send(200, b"plain body", {"Content-Type": "text/plain", "Date": "not-a-date"})
        elif self.path == "/no-date":
            self._send(200, b"plain body", {"Content-Type": "text/plain"}, include_date=False)
        elif self.path == "/conflict":
            self._send_json(200, {"serverTime": now_ms}, {"Date": http_date(0)})
        elif self.path == "/timeout":
            time.sleep(2.0)
            self._send_json(200, {"serverTime": now_ms}, {"Date": http_date()})
        else:
            self._send(404, b"missing", {"Date": http_date()})

    def _send_json(self, status: int, payload: dict[str, object], headers: dict[str, str]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        merged = {"Content-Type": "application/json", **headers}
        self._send(status, body, merged)

    def _send(self, status: int, body: bytes, headers: dict[str, str], include_date: bool = True) -> None:
        self.send_response_only(status)
        if include_date and "Date" not in headers:
            self.send_header("Date", http_date())
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


def make_cert(tmp: Path) -> tuple[Path, Path]:
    cert = tmp / "cert.pem"
    key = tmp / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return cert, key


def parse_fields(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_case(name: str, url: str, expected_rc: int, env: dict[str, str], **checks: object) -> None:
    completed = subprocess.run(
        [str(BINARY), url, "5000", "10000", "3000"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert_true(completed.returncode == expected_rc, f"{name}: expected rc={expected_rc}, got {completed.returncode}")
    fields = parse_fields(completed.stdout)

    if "stderr_contains" in checks:
        assert_true(checks["stderr_contains"] in completed.stderr, f"{name}: missing stderr fragment")
    for key, expected in checks.get("fields", {}).items():
        assert_true(fields.get(key) == expected, f"{name}: expected {key}={expected}, got {fields.get(key)}")
    for key, fragment in checks.get("contains", {}).items():
        assert_true(fragment in fields.get(key, ""), f"{name}: expected {key} to contain {fragment}")
    if "resolved_suffix" in checks:
        assert_true(fields.get("resolved_url", "").endswith(str(checks["resolved_suffix"])), f"{name}: wrong resolved_url")

    print(f"[PASS] {name}")


def main() -> int:
    if not BINARY.exists():
        print(f"missing binary: {BINARY}", file=sys.stderr)
        return 1

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert, key = make_cert(Path(tmpdir))
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert, keyfile=key)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            base = f"https://127.0.0.1:{httpd.server_address[1]}"
            env = {**os.environ, "TIME_WATCHDOG_ALLOW_INSECURE_LOCALHOST": "1"}

            run_case("redirect_json", f"{base}/redirect-json", 0, env,
                     fields={"remote_time_source": "json_body_timestamp", "remote_time_field": "serverTime", "anomaly_detected": "0"},
                     resolved_suffix="/json-precise")
            run_case("redirect_multi_hop", f"{base}/redirect-step-1", 0, env,
                     fields={"remote_time_source": "json_body_timestamp", "remote_time_field": "serverTime", "anomaly_detected": "0"},
                     resolved_suffix="/json-precise")
            run_case("redirect_loop_errors", f"{base}/redirect-loop-a", 1, env,
                     stderr_contains="too many HTTP redirects")
            run_case("status_429", f"{base}/status-429", 2, env,
                     fields={"http_status_code": "429", "remote_time_source": "http_date_header", "anomaly_detected": "1"},
                     contains={"anomaly_reasons": "http_status_out_of_range"})
            run_case("status_500", f"{base}/status-500", 2, env,
                     fields={"http_status_code": "500", "remote_time_source": "http_date_header", "anomaly_detected": "1"},
                     contains={"anomaly_reasons": "http_status_out_of_range"})
            run_case("malformed_json_falls_back_to_date", f"{base}/malformed-json", 0, env,
                     fields={"remote_time_source": "http_date_header", "remote_time_field": "Date", "anomaly_detected": "0"})
            run_case("invalid_date_errors", f"{base}/invalid-date", 1, env,
                     stderr_contains="Could not parse HTTPS Date header")
            run_case("no_date_errors", f"{base}/no-date", 1, env,
                     stderr_contains="HTTPS response did not include a Date header")
            run_case("json_beats_conflicting_date", f"{base}/conflict", 0, env,
                     fields={"remote_time_source": "json_body_timestamp", "remote_time_field": "serverTime", "anomaly_detected": "0"})
            run_case("timeout_errors", f"{base}/timeout", 1,
                     {**env, "TIME_WATCHDOG_REQUEST_TIMEOUT_MS": "500"},
                     stderr_contains="NSURLErrorDomain error -1001")

            httpd.shutdown()
            httpd.server_close()
    except Exception as exc:  # noqa: BLE001
        print(f"controlled integration test failed: {exc}", file=sys.stderr)
        return 1

    print("time_watchdog_crc32 controlled integration tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())