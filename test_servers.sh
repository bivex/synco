#!/bin/bash
# Test WebSocket time servers from config.json
#    • binance: 9
#     • crypto: 21
#     • fast: 4
#     • us: 4
#     • eu: 3
#     • asia: 4
#     • exchange: 6
#     • altcoins: 7
CONFIG_FILE="config.json"
PROBE_BIN="./commpage_time_probe"

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found"
    exit 1
fi

# Check if commpage_time_probe exists
if [ ! -f "$PROBE_BIN" ]; then
    echo "Error: $PROBE_BIN not found. Run 'make' first."
    exit 1
fi

get_urls() {
    python3 -c "
import json
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)

    for server in config.get('servers', []):
        request = server.get('request_message', '')
        print(f\"{server['url']}|{server.get('name', 'Unknown')}|{request}\")
except Exception as e:
    sys.stderr.write(f'Error reading config: {e}\\n')
    sys.exit(1)
" 2>/dev/null || echo "Error: Python 3 required for JSON parsing"
}

get_urls_by_group() {
    local group="$1"
    python3 -c "
import json
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)

    group_servers = config.get('groups', {}).get('$group', [])
    server_names = {s.get('name', ''): s for s in config.get('servers', [])}

    for name in group_servers:
        if name in server_names:
            server = server_names[name]
            request = server.get('request_message', '')
            print(f\"{server['url']}|{name}|{request}\")
except Exception as e:
    sys.stderr.write(f'Error: {e}\\n')
    sys.exit(1)
" 2>/dev/null
}

group_exists() {
    local group="$1"
    python3 -c "
import json
import sys

with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)

sys.exit(0 if '$group' in config.get('groups', {}) else 1)
" 2>/dev/null
}

test_server() {
    local url="$1"
    local name="$2"
    local request_message="$3"

    echo "Testing: $name"
    echo "URL: $url"
    echo "---"

    if [ -n "$request_message" ]; then
        $PROBE_BIN "$url" "$request_message" 2>&1
    else
        $PROBE_BIN "$url" 2>&1
    fi
    local result=$?

    echo ""
    if [ $result -eq 0 ]; then
        echo "✓ Success"
    else
        echo "✗ Failed (exit code: $result)"
    fi
    echo ""
}

case "${1:-all}" in
    "all")
        echo "Testing all servers from config..."
        echo ""
        while IFS='|' read -r url name request_message; do
            test_server "$url" "$name" "$request_message"
        done < <(get_urls)
        ;;
    "groups")
        echo "Available groups:"
        echo ""
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)
for group, servers in config.get('groups', {}).items():
    print(f'{group}: {len(servers)} servers')
"
        ;;
    "list")
        echo "Available servers:"
        echo ""
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    config = json.load(f)
for i, server in enumerate(config.get('servers', []), 1):
    print(f'{i}. {server.get(\"name\", \"Unknown\")}')
    print(f'   URL: {server[\"url\"]}')
    print(f'   Type: {server.get(\"type\", \"unknown\")}')
    print()
"
        ;;
    *)
        if group_exists "$1"; then
            echo "Testing $1 group..."
            echo ""
            while IFS='|' read -r url name request_message; do
                test_server "$url" "$name" "$request_message"
            done < <(get_urls_by_group "$1")
        else
            echo "Testing: $1"
            echo ""
            $PROBE_BIN "$1"
        fi
        ;;
esac
