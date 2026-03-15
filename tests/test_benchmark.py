import asyncio, json, logging, sys
from pathlib import Path
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from client.benchmark_client import (
    run_stdio_scenario, run_http_scenario, score_results, score_results_by_mode,
    export_results, BenchmarkResult
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
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       evidence_found=True, produced_evidence_path="fake/path"),
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
    """Dual-axis result must have both gt_component and gt_lifecycle_phase."""
    r = BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True)
    assert r.gt_component != ""
    assert r.gt_lifecycle_phase != ""

def test_lifecycle_only_mode():
    """lifecycle-only: only check lifecycle_phase."""
    r = BenchmarkResult("S1", True, True, "", "runtime", "policy_violation", False,
                       predicted_phase="runtime")
    lifecycle_score = 1 if r.predicted_phase else 0
    assert lifecycle_score == 1

def test_component_only_mode():
    """component-only: only check component."""
    r = BenchmarkResult("S1", True, True, "scope", "", "policy_violation", False,
                       predicted_component="scope")
    component_score = 1 if r.predicted_component else 0
    assert component_score == 1

# --- Baseline comparison tests ---

def test_dual_axis_beats_lifecycle_only():
    """Dual-axis localization cannot be worse than lifecycle-only (it is strictly more demanding)."""
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       evidence_found=True, produced_evidence_path="fake/path"),
        BenchmarkResult("S3", True, True, "metadata", "discovery", "metadata_violation", False,
                       predicted_component="metadata", predicted_phase="discovery", localization_correct=True,
                       evidence_found=True, produced_evidence_path="fake/path"),
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="WRONG", localization_correct=False,
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    # Dual axis is at most as good as both individual axes
    assert dual["localization_accuracy"] <= lifecycle["localization_accuracy"]
    assert dual["localization_accuracy"] <= component["localization_accuracy"]


def test_component_only_misses_phase_errors():
    """Component-only passes even when phase is wrong; dual-axis catches it."""
    results = [
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="admission",  # wrong phase
                       localization_correct=False,
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    component = score_results_by_mode(results, "component_only")
    assert component["localization_accuracy"] == 1.0   # component-only passes
    assert dual["localization_accuracy"] == 0.0        # dual-axis catches wrong phase


def test_lifecycle_only_misses_component_errors():
    """Lifecycle-only passes even when component is wrong; dual-axis catches it."""
    results = [
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="authz", predicted_phase="runtime",  # wrong component
                       localization_correct=False,
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    assert lifecycle["localization_accuracy"] == 1.0   # lifecycle-only passes
    assert dual["localization_accuracy"] == 0.0        # dual-axis catches wrong component


def test_evidence_completeness_requires_real_artifact():
    """Evidence completeness is 0 when no trace file path is set."""
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       evidence_found=False, produced_evidence_path=""),  # no artifact
    ]
    m = score_results_by_mode(results, "dual_axis")
    assert m["evidence_completeness"] == 0.0


def test_benign_produces_no_false_positive():
    results = [
        BenchmarkResult("S9", False, False, "scope", "runtime", "clean_execution", False,
                       predicted_component="", predicted_phase="", localization_correct=False,
                       evidence_found=False),
    ]
    m = score_results_by_mode(results, "dual_axis")
    assert m["false_positive_rate"] == 0.0

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

    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")

    csv_path, *_ = export_results(results, dual, lifecycle, component)

    log.info(f"dual_axis: {json.dumps(dual, indent=2)}")
    log.info(f"lifecycle_only: {json.dumps(lifecycle, indent=2)}")
    log.info(f"component_only: {json.dumps(component, indent=2)}")

    assert dual["total_scenarios"] == len(ALL_SCENARIOS)
    assert csv_path.exists()
    # Dual-axis localization is at most as permissive as each individual axis
    assert dual["localization_accuracy"] <= lifecycle["localization_accuracy"] + 0.01
    assert dual["localization_accuracy"] <= component["localization_accuracy"] + 0.01
