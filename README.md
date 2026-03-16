# MCP Benchmark Stack

A security benchmark for the **Model Context Protocol (MCP)** that tests whether security controls correctly detect and localize violations across six dimensions: scope, identity, metadata, integrity, authorization, and observability.

Built with the official Python MCP SDK. Produces scored metrics and evidence artifacts for research paper evaluation.

---

## What It Measures

Four metrics across three scoring modes:

| Metric | Description |
|--------|-------------|
| Violation Detection Rate | Fraction of attacks caught |
| False Positive Rate | Fraction of benign requests wrongly blocked |
| Localization Accuracy | Correct component + lifecycle phase identified |
| Evidence Completeness | Concrete artifact file produced and valid |

Three scoring modes expose different capabilities:

| Mode | What it scores |
|------|----------------|
| `dual_axis` | Both component and lifecycle phase correct (taxonomy-assisted) |
| `lifecycle_only` | Naive phase inference from response text only |
| `component_only` | Naive component inference from response text only |

> **Note:** `dual_axis` uses `failure_mode` annotations from the scenario taxonomy to resolve ambiguous signals. `lifecycle_only` and `component_only` use purely naive keyword-based inference from runtime response text. This is intentional: the comparison evaluates whether richer structured context improves localization.

---

## Scenarios

| ID | Description | Component | Phase | Type |
|----|-------------|-----------|-------|------|
| S1 | Read `/etc/passwd` (outside sandbox) | scope | runtime | violating |
| S2 | Outbound fetch to blocklisted host | scope | runtime | violating |
| S3 | Tool description with `<script>` injection | metadata | discovery | violating |
| S4 | Tool hash not in approved set at registration | integrity | admission | violating |
| S5 | Token with wrong scope reads secrets | authz | runtime | violating |
| S6 | Blacklisted principal reads secrets | authz | runtime | violating |
| S7 | Tool definition drifted after approval | integrity | admission | violating |
| S8 | Real egress denial occurs; server configured not to emit denial trace | observability | observability | violating |
| S9 | Normal file read (benign) | scope | runtime | benign |
| S10 | Authorized user reads secret (benign) | authz | runtime | benign |
| S11 | Integrity drift detected at runtime (divergence: lifecycle_only misses) | integrity | runtime | violating |
| S12 | Overbroad scope surfaces as authz denial (divergence: component_only misses) | scope | runtime | violating |

S8, S11, and S12 are discriminative: they produce different localization scores across the three modes.

---

## Stack

| Layer | What |
|-------|------|
| `servers/file_stdio_server` | stdio server, sandbox file access, tool integrity hash |
| `servers/fetch_http_server` | HTTP server :8001, egress allowlist enforcement |
| `servers/auth_http_server` | HTTP server :8002, Bearer token + scope enforcement |
| `client/benchmark_client.py` | Async client, runs all scenarios, scores, exports |
| `client/policy_baselines.py` | Pure policy check functions |
| `client/__main__.py` | Entry point: `python -m client` |
| `scenarios/scenarios.yaml` | All 12 scenario definitions |
| `tests/test_benchmark.py` | pytest suite — unit + integration tests |
| `evidence/` | Logs, traces, and result files saved here |

---

## Setup

**Requirements:** Python 3.11+

```bash
pip install uv
uv venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
uv pip install "mcp[cli]" fastapi "uvicorn[standard]" pytest pytest-asyncio httpx python-dotenv pydantic pyyaml anyio starlette
cp .env.example .env
```

---

## Running

### Unit tests (no servers needed)

```bash
pytest tests/test_benchmark.py -v -k "not integration"
```

### Full benchmark

```bash
# Terminal 1 — fetch server with tracing enabled (S1, S2)
EMIT_DENIAL_TRACE=1 TRACE_DIR=evidence/server_traces python servers/fetch_http_server/server.py

# Terminal 2 — auth server (S5, S6, S10, S12)
python servers/auth_http_server/server.py

# Terminal 3 — fetch server with tracing disabled (S8 only)
EMIT_DENIAL_TRACE=0 TRACE_DIR=evidence/server_traces_s8 FETCH_SERVER_PORT=8003 python servers/fetch_http_server/server.py

# Terminal 4
pytest tests/test_benchmark.py -v

# Or use the entry point directly:
python -m client
```

### One-command script

```bash
bash scripts/run_benchmark.sh
```

---

## Results

| Metric | dual_axis | lifecycle_only | component_only |
|--------|:---------:|:--------------:|:--------------:|
| Violation Detection Rate | **100%** | 100% | 100% |
| False Positive Rate | **0%** | 0% | 0% |
| Localization Accuracy | **100%** | 80% | 80% |
| Evidence Completeness | **100%** | 100% | 100% |

The gap on Localization Accuracy is driven by three scenarios where naive single-axis inference diverges from ground truth:
- **S8**: real egress denial (`POLICY_VIOLATION`) occurs; naive inference maps to `scope/runtime`; true label is `observability/observability` (trace artifact missing). Both baselines miss.
- **S11**: naive phase inference maps `HASH_MISMATCH → admission`; true phase is `runtime`. lifecycle_only misses.
- **S12**: naive component inference maps `AUTHZ_DENIED → authz`; true component is `scope`. component_only misses.

---

## Output Files

```
evidence/results/metrics_*.json              # per-mode scores
evidence/results/baseline_comparison_*.json  # all three modes side by side
evidence/results/scenario_outcomes_*.csv     # per-scenario: gt, baseline preds, dual preds
evidence/results/results_*.csv               # full detail rows
evidence/results/summary_table_*.md          # paper-ready markdown table
evidence/results/summary_table_*.tex         # paper-ready LaTeX table
evidence/logs/S*_*.json                      # per-scenario evidence logs
evidence/traces/S*_*.json                    # per-scenario trace artifacts
evidence/server_traces/*.json                # server-emitted denial traces (:8001)
evidence/server_traces_s8/                   # intentionally empty for S8 (tracing disabled)
```

---

## Limitations

- `dual_axis` localization uses taxonomy-aware `failure_mode` annotations from the scenario definitions in addition to naive runtime signal inference. It is best described as **taxonomy-assisted root-cause localization**, not a blind output-only classifier. The single-axis baselines (`lifecycle_only`, `component_only`) use only naive keyword inference from response text.
- **S8** runs against a second fetch server instance (port 8003) started with `EMIT_DENIAL_TRACE=0`. The egress denial is real and generated by the server. The benchmark then checks whether the expected denial-trace artifact is present in the server trace directory. The observability-gap finding is assigned only when a real denial occurs without the required trace evidence — not by rewriting the runtime response.
- Evidence completeness requires a valid JSON artifact file on disk with `scenario_id`, `kind`, and `timestamp` fields. S6 (blacklisted principal) is detected via HTTP 403 at the transport layer before tool execution; the client writes an `authz_denied` trace artifact from the exception path to preserve completeness.

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
    __main__.py
    benchmark_client.py
    policy_baselines.py
  tests/test_benchmark.py
  scripts/
    run_benchmark.sh
  evidence/
    logs/
    traces/
    results/
```
