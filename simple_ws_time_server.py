#!/usr/bin/env python3
"""Simple WebSocket time server for testing commpage_time_probe"""

import asyncio
import json
from datetime import datetime

try:
    import websockets
except ImportError:
    print("Installing websockets...")
    import subprocess
    subprocess.check_call(['pip3', 'install', '--user', 'websockets'])
    import websockets


async def time_handler(websocket):
    """Handle WebSocket connections and respond to time requests"""
    print(f"Client connected from {websocket.remote_address}")
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                print(f"Received: {data}")

                if data.get("type") == "time_request":
                    # Get current time with microsecond precision
                    now = datetime.utcnow()
                    timestamp = now.timestamp()
                    seconds = int(timestamp)
                    nanoseconds = int((timestamp - seconds) * 1_000_000_000)

                    response = {
                        "type": "time_response",
                        "seconds": seconds,
                        "nanoseconds": nanoseconds
                    }

                    await websocket.send(json.dumps(response))
                    print(f"Sent time: {seconds}.{nanoseconds:09d}")
                else:
                    # Echo back unknown messages
                    await websocket.send(json.dumps({"error": "unknown request type"}))
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"error": "invalid JSON"}))
    except websockets.exceptions.ConnectionClosed:
        print(f"Client disconnected")
    except Exception as e:
        print(f"Error: {e}")


async def main():
    """Start the WebSocket server"""
    host = "localhost"
    port = 8765

    print(f"Starting WebSocket time server on ws://{host}:{port}")
    print("Waiting for connections...")

    async with websockets.serve(time_handler, host, port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped")
