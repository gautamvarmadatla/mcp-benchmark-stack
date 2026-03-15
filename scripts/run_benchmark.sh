#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
cd "$ROOT"
source .venv/bin/activate 2>/dev/null || true
echo "=== MCP Benchmark Runner ==="
echo "Running unit + policy tests first..."
python -m pytest tests/test_benchmark.py -v -k "not integration" 2>&1 | tee evidence/logs/pytest_unit.log
echo ""
echo "Running integration benchmark (requires servers on 8001 and 8002)..."
python -m pytest tests/test_benchmark.py -v -k "integration" -m "integration" --no-header 2>&1 | tee evidence/logs/pytest_integration.log || true
echo ""
echo "Results in evidence/results/"
ls -lh evidence/results/ 2>/dev/null || echo "(no results yet)"
