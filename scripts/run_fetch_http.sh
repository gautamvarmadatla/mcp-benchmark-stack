#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true
export FETCH_SERVER_PORT="${FETCH_SERVER_PORT:-8001}"
export FETCH_SERVER_ALLOWED_HOSTS="${FETCH_SERVER_ALLOWED_HOSTS:-example.com,httpbin.org}"
echo "[fetch_http_server] Starting on port $FETCH_SERVER_PORT..."
python servers/fetch_http_server/server.py
