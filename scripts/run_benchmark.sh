#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"

source .venv/bin/activate 2>/dev/null || { echo "ERROR: virtualenv not found — run 'uv venv && uv pip install ...' first"; exit 1; }

mkdir -p evidence/logs evidence/server_traces evidence/server_traces_s8

# --- Trap: kill background servers on exit ---
FETCH_PID=""
AUTH_PID=""
FETCH_S8_PID=""
cleanup() {
    echo "=== Stopping servers ==="
    for pid in "$FETCH_PID" "$AUTH_PID" "$FETCH_S8_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
        fi
    done
}
trap cleanup EXIT

# --- Start HTTP servers in background ---
echo "=== Starting fetch_http_server on :8001 (tracing enabled) ==="
EMIT_DENIAL_TRACE=1 TRACE_DIR=evidence/server_traces python servers/fetch_http_server/server.py &
FETCH_PID=$!

echo "=== Starting auth_http_server on :8002 ==="
python servers/auth_http_server/server.py &
AUTH_PID=$!

echo "=== Starting fetch_http_server on :8003 (tracing disabled, S8 only) ==="
EMIT_DENIAL_TRACE=0 TRACE_DIR=evidence/server_traces_s8 FETCH_SERVER_PORT=8003 python servers/fetch_http_server/server.py &
FETCH_S8_PID=$!

# --- Wait for servers to be ready ---
echo "=== Waiting for servers to be ready ==="
READY_8001=0; READY_8002=0; READY_8003=0
for i in $(seq 1 15); do
    curl -sf http://127.0.0.1:8001/ >/dev/null 2>&1 && READY_8001=1
    curl -sf http://127.0.0.1:8002/ >/dev/null 2>&1 && READY_8002=1
    curl -sf http://127.0.0.1:8003/ >/dev/null 2>&1 && READY_8003=1
    if [ "$READY_8001" -eq 1 ] && [ "$READY_8002" -eq 1 ] && [ "$READY_8003" -eq 1 ]; then
        echo "All servers ready."
        break
    fi
    sleep 1
done

[ "$READY_8001" -ne 1 ] && { echo "ERROR: fetch_http_server on :8001 did not come up."; exit 1; }
[ "$READY_8002" -ne 1 ] && { echo "ERROR: auth_http_server on :8002 did not come up."; exit 1; }
[ "$READY_8003" -ne 1 ] && { echo "ERROR: fetch_http_server on :8003 (S8) did not come up."; exit 1; }

# --- Unit tests (no servers needed) ---
echo ""
echo "=== Running unit tests ==="
python -m pytest tests/test_benchmark.py -v -k "not integration" --tb=short 2>&1 | tee evidence/logs/pytest_unit.log

# --- Integration tests ---
echo ""
echo "=== Running integration benchmark ==="
python -m pytest tests/test_benchmark.py -v -m "integration" --tb=short 2>&1 | tee evidence/logs/pytest_integration.log

echo ""
echo "=== Results in evidence/results/ ==="
ls -lh evidence/results/ 2>/dev/null || echo "(no results yet)"
