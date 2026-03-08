# synco

Time synchronization tools for macOS arm64.

## Overview

This project provides utilities for reading time from the macOS commpage (kernel-shared memory) and comparing it with remote time sources via WebSocket.

## Tools

### commpage_time_probe

Reads local time from the macOS commpage and optionally fetches remote time from a WebSocket server to calculate the time delta (server_time - local_time).

**Features:**
- Direct commpage access for ultra-low latency local time
- WebSocket client for remote time fetching
- Support for various timestamp formats (standard `seconds/nanoseconds`, Binance `E` field)
- Microsecond precision

**Supported only on:** macOS arm64 (Apple Silicon)

### time_watchdog_crc32

Reads local time from the macOS commpage, fetches remote HTTPS server time, measures elapsed monotonic time, and computes a CRC32 fingerprint over the verification sample.

**Features:**
- Direct commpage local time sampling
- HTTPS time verification via JSON body timestamp when available, otherwise HTTP `Date` header
- Monotonic elapsed / wall elapsed comparison
- CRC32 fingerprint of the verification sample
- Threshold-based runtime anomaly detection for stalls, clock jumps, or large remote drift
- Internal `tricky-shot` watchdog swarm: 5 background watchdog threads sampling delta windows in parallel
- Deliberately scattered watchdog memory layout with guard gaps, split control/metrics mappings, and a layout fingerprint folded into the final CRC payload
- Post-`ready` watchdog kill detection for cases where a thread is alive long enough to arm, but gets terminated before producing samples

Note: the tool prefers a timestamp found in a JSON response body. When it falls back to the HTTP `Date` header, effective remote drift checks include an extra precision allowance because `Date` is usually only second-precision.

## Building

```bash
make
```

This builds `computer_id_probe`, `commpage_time_probe`, and `time_watchdog_crc32`.

Run the edge-case watchdog tests with:
```bash
make test
```

Run live network integration tests with:
```bash
make integration-test
```

Run controlled localhost HTTPS integration tests with:
```bash
make controlled-integration-test
```

### Testing matrix

| Command | Layer | Purpose |
|---|---|---|
| `make test` | Edge-case / logic | Fast local checks for timestamp parsing, threshold handling, anomaly evaluation, and parser edge cases without real network dependencies. |
| `make integration-test` | Live network integration | Verifies real public HTTPS endpoints still work for both `http_date_header` fallback and precise `json_body_timestamp` paths. |
| `make controlled-integration-test` | Controlled localhost HTTPS integration | Verifies deterministic negative and redirect scenarios under a local TLS server: redirects, redirect loop, `429/500`, malformed JSON, invalid/missing `Date`, timeout, and JSON-vs-Date precedence. |

Current live endpoints covered:
- `https://example.com` for `http_date_header` fallback
- `https://api.binance.com/api/v3/time` for precise `json_body_timestamp`

Controlled localhost HTTPS cases covered:
- redirect to a precise JSON timestamp endpoint
- multi-hop redirect to a precise JSON timestamp endpoint
- redirect loop / redirect limit error path
- `429` and `500` responses
- malformed JSON with `Date` fallback
- invalid `Date` header parse error
- missing `Date` error path
- timeout error path
- conflicting JSON timestamp vs `Date` header (JSON wins)

## Usage

### Basic: Local time from commpage

```bash
./commpage_time_probe
```

Output:
```
time_source=commpage_direct
user_timebase_mode=3
local_time_sec=1772917702
local_time_nsec=31637583
# No WebSocket URL provided. Usage: commpage_time_probe <ws://url>
```

### With WebSocket: Compare with remote time

```bash
./commpage_time_probe <websocket_url> [request_json]
```

#### Examples

**Local WebSocket server for development only (see below):**
```bash
./commpage_time_probe ws://localhost:8765
```

This localhost example is `dev-only` and is **not** included in `config.json`.

**Binance trade stream (uses event timestamp):**
```bash
./commpage_time_probe wss://stream.binance.com:9443/ws/btcusdt@trade
```

Output:
```
time_source=commpage_direct
user_timebase_mode=3
local_time_sec=1772917702
local_time_nsec=31637583
websocket_url=wss://stream.binance.com:9443/ws/btcusdt@trade
server_time_sec=1772917704
server_time_nsec=795000000
delta_sec=2
delta_nsec=763362417
delta_human=2.763362417s
```

## Output Format

| Field | Description |
|-------|-------------|
| `time_source` | Always `commpage_direct` |
| `user_timebase_mode` | Timebase mode (1=CNTVCT, 3=CoreAnimation) |
| `local_time_sec` | Local Unix timestamp from commpage |
| `local_time_nsec` | Nanoseconds component |
| `websocket_url` | Remote WebSocket URL (if provided) |
| `server_time_sec` | Remote Unix timestamp |
| `server_time_nsec` | Remote nanoseconds |
| `delta_sec` | Time difference (server - local) in seconds |
| `delta_nsec` | Time difference in nanoseconds |
| `delta_human` | Human-readable delta (e.g., `2.763362417s`) |

## HTTPS Watchdog Usage

```bash
./time_watchdog_crc32 <https_url> [max_remote_delta_ms] [max_elapsed_ms] [max_clock_gap_ms]
```

Example:
```bash
./time_watchdog_crc32 https://example.com 5000 5000 1500
```

Exit codes:
- `0` — verification succeeded and no anomaly crossed thresholds
- `1` — request or parsing failure
- `2` — verification succeeded but anomaly thresholds were exceeded

Important output fields:
- `remote_time_source` — either `json_body_timestamp` or `http_date_header`
- `remote_time_field` — JSON field path used for remote time, or `Date` for header fallback
- `remote_time_precision_ms` — estimated precision of the remote time source
- `effective_remote_threshold_ms` — remote drift threshold after adding source precision allowance
- `thread_watchdog_mode` — current internal watchdog implementation (`tricky_shot_swarm`)
- `thread_watchdog_threads` / `thread_watchdog_ready_threads` — configured watchdog worker count and how many armed successfully
- `thread_watchdog_samples` — total per-thread delta samples collected during the request window
- `thread_watchdog_post_ready_stall_threads` — threads that became `ready` but never produced a sample before shutdown
- `thread_watchdog_layout_fingerprint` — hash-like fingerprint of the scattered watchdog memory layout, included in the CRC32 payload

### Tricky-shot watchdog internals

`time_watchdog_crc32` now runs an internal watchdog swarm during the HTTPS verification window:

- `5` watchdog threads are spawned for each verification
- each thread keeps its own local delta window (`local_before/after` vs monotonic `before/after`)
- watchdog state is intentionally scattered in memory:
  - separate `mmap` regions for control and metrics
  - `PROT_NONE` guard gaps around the active page
  - per-replica page jitter and in-page offset jitter
  - shuffled thread startup order
- the aggregate watchdog layout is folded into `thread_watchdog_layout_fingerprint`, which is then included in the canonical CRC payload

This is meant to make the watchdog less linear and easier to notice if something tampers with thread execution or memory placement.

### Post-ready thread kill detection

There is now an explicit detector for the case where a watchdog thread:

1. becomes `ready`
2. survives startup checks
3. gets killed before producing even a single sample

When that happens, and enough elapsed time passed for at least one normal watchdog tick, the tool reports:

- `thread_watchdog_killed_after_ready`

This plugs the previous gap where a debugger or external kill could terminate watchdog workers after arming without setting `thread_watchdog_failed`.

### Quick local demo

A one-command demo helper is included:

```bash
./demo_time_watchdog_crc32.py
```

It:

- builds `time_watchdog_crc32` if needed
- starts a local HTTPS test server
- runs a clean `OK` case and an `ANOMALY` case
- prints the key watchdog fields including `thread_watchdog_mode`, `thread_watchdog_threads`, `thread_watchdog_layout_fingerprint`, and `smart_crc32`

### Debug stall verification

Observed LLDB check: a forced `2.0s` pause inside the measured window causes `anomaly_detected=1`.

Practical interpretation:
- `elapsed_exceeded` is the primary stall/pause signal
- `remote_delta_exceeded` may also trigger when the remote source is precise (for example a JSON millisecond timestamp)
- `clock_gap_ms` usually stays small during a simple debugger pause, so it is a secondary signal rather than the main stall detector
- `thread_delta_exceeded` may also trigger because the watchdog threads themselves observe an abnormally large per-thread elapsed delta while the process is paused in the debugger
- if watchdog workers are killed after reaching `ready`, `thread_watchdog_killed_after_ready` is expected once the post-ready grace window has passed

## Server Configuration

A `config.json` file contains pre-configured WebSocket time servers for shared/remote testing.

`localhost` development endpoints are intentionally **not** included in `config.json`.

### Using test_servers.sh

Test all configured servers:
```bash
./test_servers.sh all
```

Test specific groups:
```bash
./test_servers.sh fast      # Fast servers (recommended)
./test_servers.sh binance   # All Binance servers
./test_servers.sh crypto    # Cryptocurrency streams
```

List all available servers:
```bash
./test_servers.sh list
```

List all available groups:
```bash
./test_servers.sh groups
```

Current benchmark note: in the latest full run, the smallest absolute `delta` was observed on `Coinbase BTC-USD Feed` at about `0.25s`.

`delta` here reflects the difference between local commpage time and the timestamp in the first matching server message, so treat it as a practical freshness indicator rather than a pure network RTT.

### config.json Structure

```json
{
  "servers": [
    {
      "name": "Server Name",
      "url": "wss://example.com/stream",
      "type": "stream",
      "request_message": "{\"type\":\"subscribe\"}",
      "timestamp_field": "E",
      "timestamp_unit": "milliseconds"
    }
  ],
  "groups": {
    "fast": ["Server Name", ...]
  }
}
```

### Pre-configured Servers

| Server | URL | Type | Latency |
|--------|-----|------|---------|
| Binance BTC/USDT Trade | `wss://stream.binance.com:9443/ws/btcusdt@trade` | Stream | ~50-200ms |
| Binance ETH/USDT Trade | `wss://stream.binance.com:9443/ws/ethusdt@trade` | Stream | ~50-200ms |
| Binance All Tickers | `wss://stream.binance.com:9443/ws/!ticker@arr` | Stream | ~50-200ms |

## Setting up a local WebSocket time server

This section is for **local development/debugging only**. The localhost server is not part of the shared `config.json` server list and will not appear in `./test_servers.sh list`.

A simple Python WebSocket time server is included:

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install websockets

# Run server
python simple_ws_time_server.py
```

The server listens on `ws://localhost:8765` and responds to `{"type":"time_request"}` with:
```json
{
  "type": "time_response",
  "seconds": 1772917702,
  "nanoseconds": 31637583
}
```

## WebSocket Timestamp Formats

The client supports multiple timestamp formats:

1. **Standard format:**
   ```json
   {"seconds": 1772917702, "nanoseconds": 31637583}
   ```

2. **Binance format (milliseconds):**
   ```json
   {"E": 1772917702795, "s": "BTCUSDT", ...}
   ```

Stream endpoints (URLs containing `@`) automatically receive data without sending a request.

## Technical Details

### Commpage Timebase Modes

| Mode | Description |
|------|-------------|
| 0 | Kernel timebase |
| 1 | CNTVCT_EL0 (virtual counter) |
| 3 | CoreAnimation counter |

### Time Calculation

The commpage contains a snapshot of kernel time with:
- `timestamp_tick`: Hardware counter value at snapshot
- `timestamp_sec`: Seconds at snapshot
- `timestamp_frac`: Fractional nanoseconds
- `ticks_scale`: Scale factor for counter conversion
- `ticks_per_sec`: Counter frequency

Local time is calculated by reading the current hardware counter and interpolating from the snapshot.

## License

MIT License - Copyright (c) 2026 Bivex

## Author

Bivex - support@b-b.top - https://github.com/bivex
