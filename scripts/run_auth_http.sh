#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true
export AUTH_SERVER_PORT="${AUTH_SERVER_PORT:-8002}"
echo "[auth_http_server] Starting on port $AUTH_SERVER_PORT..."
python servers/auth_http_server/server.py
