#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"

source .venv/bin/activate 2>/dev/null || { echo "ERROR: virtualenv not found — run 'uv venv && uv pip install ...' first"; exit 1; }

mkdir -p evidence/logs

# --- Trap: kill background servers on exit ---
FETCH_PID=""
AUTH_PID=""
cleanup() {
    echo "=== Stopping servers ==="
    if [ -n "$FETCH_PID" ] && kill -0 "$FETCH_PID" 2>/dev/null; then
        kill "$FETCH_PID"
    fi
    if [ -n "$AUTH_PID" ] && kill -0 "$AUTH_PID" 2>/dev/null; then
        kill "$AUTH_PID"
    fi
}
trap cleanup EXIT

# --- Start HTTP servers in background ---
echo "=== Starting fetch_http_server on :8001 ==="
python servers/fetch_http_server/server.py &
FETCH_PID=$!

echo "=== Starting auth_http_server on :8002 ==="
python servers/auth_http_server/server.py &
AUTH_PID=$!

# --- Wait for servers to be ready ---
echo "=== Waiting for servers to be ready ==="
READY_8001=0
READY_8002=0
for i in $(seq 1 15); do
    if curl -sf http://127.0.0.1:8001/health >/dev/null 2>&1 || curl -sf http://127.0.0.1:8001/ >/dev/null 2>&1; then
        READY_8001=1
    fi
    if curl -sf http://127.0.0.1:8002/health >/dev/null 2>&1 || curl -sf http://127.0.0.1:8002/ >/dev/null 2>&1; then
        READY_8002=1
    fi
    if [ "$READY_8001" -eq 1 ] && [ "$READY_8002" -eq 1 ]; then
        echo "Both servers ready."
        break
    fi
    sleep 1
done

if [ "$READY_8001" -ne 1 ]; then
    echo "ERROR: fetch_http_server on :8001 did not come up in time."
    exit 1
fi
if [ "$READY_8002" -ne 1 ]; then
    echo "ERROR: auth_http_server on :8002 did not come up in time."
    exit 1
fi

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
