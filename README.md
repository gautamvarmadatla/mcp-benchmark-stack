# MCP Benchmark Stack

A security benchmark stack for the **Model Context Protocol (MCP)**. Tests whether security controls correctly detect and localize violations across scope, identity, metadata, integrity, authorization, and observability.

Built with the official Python MCP SDK. Produces evidence logs and scored metrics for research paper evaluation.

---

## What It Does

Runs 10 scenarios (8 attacks + 2 clean) against 3 real MCP servers and scores:

- **Violation Detection Rate** — how many attacks were caught
- **False Positive Rate** — how many clean requests were wrongly blocked
- **Localization Accuracy** — was the correct component + lifecycle phase identified
- **Evidence Completeness** — was a full evidence artifact saved

---

## Scenarios

| ID | Attack | Type |
|----|--------|------|
| S1 | Read `/etc/passwd` (outside sandbox) | Scope |
| S2 | Fetch blocked host (`evil.example.org`) | Identity/Egress |
| S3 | Tool description with `<script>` injection | Metadata |
| S4 | Tool hash doesn't match approved hash | Integrity |
| S5 | Token with wrong scope reads secrets | AuthZ |
| S6 | Blacklisted user reads secrets | AuthZ |
| S7 | Tool definition changed after approval | Drift |
| S8 | Fetch to attacker-controlled host | Observability |
| S9 | Normal file read (benign) | — |
| S10 | Authorized user reads secret (benign) | — |

---

## Stack

| Layer | What |
|-------|------|
| `servers/file_stdio_server` | Local stdio server, sandbox file access, tool integrity hash |
| `servers/fetch_http_server` | HTTP server on :8001, egress allowlist enforcement |
| `servers/auth_http_server` | HTTP server on :8002, Bearer token + scope enforcement |
| `client/benchmark_client.py` | Async MCP client, runs all scenarios, scores and exports results |
| `client/policy_baselines.py` | Pure policy check functions (scope, metadata, host) |
| `scenarios/scenarios.yaml` | All 10 scenario definitions |
| `tests/test_benchmark.py` | pytest suite — unit + integration tests |
| `evidence/` | Logs, traces, and result CSVs saved here after each run |

---

## Setup

**Requirements:** Python 3.11+, Node.js (for conformance checks)

```bash
# 1. Install uv
pip install uv

# 2. Create virtualenv and install dependencies
uv venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
uv pip install "mcp[cli]" fastapi "uvicorn[standard]" pytest pytest-asyncio httpx python-dotenv pydantic pyyaml anyio starlette

# 3. Copy env file
cp .env.example .env
```

---

## Running

### Step 1 — Start HTTP servers (two separate terminals)

```bash
# Terminal 1
python servers/fetch_http_server/server.py

# Terminal 2
python servers/auth_http_server/server.py
```

### Step 2 — Run unit tests (no servers needed)

```bash
pytest tests/test_benchmark.py -v -k "not integration"
```

### Step 3 — Run full benchmark

```bash
pytest tests/test_benchmark.py -v
```

### Step 4 — View results

```
evidence/results/metrics_*.json          # overall scores
evidence/results/scenario_outcomes_*.csv # per-scenario detected/not
evidence/results/results_*.csv           # full detail rows
evidence/logs/S*_*.json                  # per-scenario evidence artifacts
```

---

## Results (latest run)

| Metric | Score |
|--------|-------|
| Violation Detection Rate | **100%** (8/8) |
| False Positive Rate | **0%** |
| Localization Accuracy | **100%** |
| Evidence Completeness | **87.5%** |

---

## Project Structure

```
mcp-benchmark-stack/
  pyproject.toml
  .env.example
  scenarios/scenarios.yaml
  servers/
    file_stdio_server/server.py
    fetch_http_server/server.py
    auth_http_server/server.py
  client/
    benchmark_client.py
    policy_baselines.py
  tests/test_benchmark.py
  scripts/
    run_benchmark.sh
    run_conformance.sh
  evidence/
    logs/
    traces/
    results/
```
