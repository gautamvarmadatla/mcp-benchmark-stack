import asyncio, json, logging, sys
from pathlib import Path
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from client.benchmark_client import (
    run_stdio_scenario, run_http_scenario, score_results, export_results, BenchmarkResult
)
from client.policy_baselines import check_metadata, check_scope_path, check_scope_host

log = logging.getLogger("test_benchmark")

SCENARIOS_PATH = Path("scenarios/scenarios.yaml")

def load_scenarios():
    with open(SCENARIOS_PATH) as f:
        data = yaml.safe_load(f)
    return data["scenarios"]

ALL_SCENARIOS = load_scenarios()

# --- Unit policy checks (no server needed) ---

def test_scope_policy_absolute_path():
    ok, reason = check_scope_path("/etc/passwd")
    assert not ok
    assert "SCOPE_VIOLATION" in reason

def test_scope_policy_traversal():
    ok, reason = check_scope_path("../../secret")
    assert not ok
    assert "SCOPE_VIOLATION" in reason

def test_scope_policy_valid():
    ok, reason = check_scope_path("hello.txt")
    assert ok

def test_metadata_policy_script_injection():
    ok, reason = check_metadata("<script>alert(1)</script> Read a file")
    assert not ok
    assert "METADATA_VIOLATION" in reason

def test_metadata_policy_valid():
    ok, reason = check_metadata("Read a file within the allowed sandbox directory")
    assert ok

def test_host_policy_blocked():
    ok, reason = check_scope_host("evil.example.org")
    assert not ok
    assert "SCOPE_VIOLATION" in reason

def test_host_policy_allowed():
    ok, reason = check_scope_host("example.com")
    assert ok

# --- Scoring logic tests ---

def test_score_all_detected():
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False),
        BenchmarkResult("S9", False, False, "scope", "runtime", "clean_execution", False),
    ]
    metrics = score_results(results)
    assert metrics["violation_detection_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0

def test_score_false_positive():
    results = [
        BenchmarkResult("S9", False, False, "scope", "runtime", "clean_execution", True),
    ]
    metrics = score_results(results)
    assert metrics["false_positive_rate"] == 1.0

# --- Dual-axis mode comparison ---

def test_dual_axis_localization():
    """Dual-axis result must have both component and lifecycle_phase."""
    r = BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False)
    assert r.component != ""
    assert r.lifecycle_phase != ""

def test_lifecycle_only_mode():
    """lifecycle-only: only check lifecycle_phase."""
    r = BenchmarkResult("S1", True, True, "", "runtime", "policy_violation", False)
    lifecycle_score = 1 if r.lifecycle_phase else 0
    assert lifecycle_score == 1

def test_component_only_mode():
    """component-only: only check component."""
    r = BenchmarkResult("S1", True, True, "scope", "", "policy_violation", False)
    component_score = 1 if r.component else 0
    assert component_score == 1

# --- Integration: stdio S1 (over-broad scope, no server needed for policy check) ---

@pytest.mark.asyncio
async def test_s1_scope_violation_unit():
    """S1: read_file with absolute path must trigger SCOPE_VIOLATION."""
    from client.policy_baselines import check_scope_path
    ok, reason = check_scope_path("/etc/passwd")
    assert not ok
    assert "SCOPE_VIOLATION" in reason

@pytest.mark.asyncio
async def test_s3_metadata_violation_unit():
    """S3: poisoned metadata description triggers METADATA_VIOLATION."""
    ok, reason = check_metadata("<script>alert(1)</script> Read a file")
    assert not ok
    assert "METADATA_VIOLATION" in reason

# --- Full integration test (requires servers running) ---
# Mark these as integration and skip by default

@pytest.mark.integration
@pytest.mark.asyncio
async def test_s9_benign_stdio():
    """S9: benign stdio call should succeed without violations."""
    scenario = next(s for s in ALL_SCENARIOS if s["id"] == "S9")
    result = await run_stdio_scenario(scenario)
    assert not result.false_positive
    assert not result.detected or not result.violating

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_benchmark():
    """Run all scenarios and export results."""
    results = []
    for scenario in ALL_SCENARIOS:
        if scenario["transport"] == "stdio":
            r = await run_stdio_scenario(scenario)
        else:
            r = await run_http_scenario(scenario)
        results.append(r)
    metrics = score_results(results)
    csv_path, metrics_path, summary_path = export_results(results, metrics)
    log.info(f"Metrics: {json.dumps(metrics, indent=2)}")
    assert metrics["total_scenarios"] == len(ALL_SCENARIOS)
    assert csv_path.exists()
    assert metrics_path.exists()
