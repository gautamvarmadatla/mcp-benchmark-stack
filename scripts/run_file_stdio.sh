#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true
export FILE_SERVER_ALLOWED_DIR="./sandbox"
echo "[file_stdio_server] Starting (logs to stderr)..."
python servers/file_stdio_server/server.py
