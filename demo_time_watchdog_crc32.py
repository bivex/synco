#!/usr/bin/env python3

from __future__ import annotations

import os
import ssl
import subprocess
import sys
import tempfile
import threading

from http.server import ThreadingHTTPServer

from time_watchdog_crc32_controlled_integration_tests import BINARY, Handler, ROOT, make_cert, parse_fields


def ensure_binary() -> None:
    source = ROOT / "time_watchdog_crc32.cpp"
    if BINARY.exists() and BINARY.stat().st_mtime >= source.stat().st_mtime:
        return
    subprocess.run(["make", "time_watchdog_crc32"], cwd=ROOT, check=True)


def run_case(label: str, url: str, expected_exit: int, env: dict[str, str]) -> None:
    cmd = [str(BINARY), url, "5000", "5000", "1500"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    print(f"\n=== {label} ===")
    print(f"$ {' '.join(cmd)}")

    if proc.stdout.strip():
        fields = parse_fields(proc.stdout)
        for key in (
            "http_status_code",
            "remote_time_source",
            "remote_time_field",
            "thread_watchdog_mode",
            "thread_watchdog_threads",
            "thread_watchdog_ready_threads",
            "thread_watchdog_layout_fingerprint",
            "anomaly_detected",
            "anomaly_reasons",
            "smart_crc32",
        ):
            if key in fields:
                print(f"{key}={fields[key]}")

    if proc.stderr.strip():
        print("stderr:")
        print(proc.stderr.strip())

    print(f"exit_code={proc.returncode}")
    if proc.returncode != expected_exit:
        raise RuntimeError(
            f"{label}: expected exit {expected_exit}, got {proc.returncode}"
        )


def main() -> int:
    try:
        ensure_binary()
    except subprocess.CalledProcessError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        cert, key = make_cert(ROOT.__class__(tmpdir))
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        base = f"https://127.0.0.1:{httpd.server_address[1]}"
        env = {**os.environ, "TIME_WATCHDOG_ALLOW_INSECURE_LOCALHOST": "1"}

        print("time_watchdog_crc32 quick demo")
        print(f"local demo server: {base}")

        try:
            run_case("OK / precise JSON time", f"{base}/json-precise", 0, env)
            run_case("ANOMALY / HTTP 500", f"{base}/status-500", 2, env)
        finally:
            httpd.shutdown()
            httpd.server_close()
            server_thread.join(timeout=1.0)

    print("\ndemo: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())