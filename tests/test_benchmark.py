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


def test_score_all_detected():
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="scope", baseline_phase="runtime",
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


def test_dual_axis_localization():
    r = BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="scope", baseline_phase="runtime")
    assert r.gt_component != ""
    assert r.gt_lifecycle_phase != ""

def test_lifecycle_only_mode():
    r = BenchmarkResult("S1", True, True, "", "runtime", "policy_violation", False,
                       predicted_phase="runtime", baseline_phase="runtime")
    lifecycle_score = 1 if r.baseline_phase else 0
    assert lifecycle_score == 1

def test_component_only_mode():
    r = BenchmarkResult("S1", True, True, "scope", "", "policy_violation", False,
                       predicted_component="scope", baseline_component="scope")
    component_score = 1 if r.baseline_component else 0
    assert component_score == 1


def test_dual_axis_beats_lifecycle_only():
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="scope", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
        BenchmarkResult("S11", True, True, "integrity", "runtime", "hash_mismatch", False,
                       predicted_component="integrity", predicted_phase="runtime", localization_correct=True,
                       baseline_component="integrity", baseline_phase="admission",
                       evidence_found=True, produced_evidence_path="fake/path"),
        BenchmarkResult("S12", True, True, "scope", "runtime", "authz_denied", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="authz", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    assert dual["localization_accuracy"] >= lifecycle["localization_accuracy"]
    assert dual["localization_accuracy"] >= component["localization_accuracy"]


def test_component_only_misses_phase_errors():
    results = [
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="admission",
                       localization_correct=False,
                       baseline_component="scope", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    component = score_results_by_mode(results, "component_only")
    assert component["localization_accuracy"] == 1.0
    assert dual["localization_accuracy"] == 0.0


def test_lifecycle_only_misses_component_errors():
    results = [
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="authz", predicted_phase="runtime",
                       localization_correct=False,
                       baseline_component="authz", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    assert lifecycle["localization_accuracy"] == 1.0
    assert dual["localization_accuracy"] == 0.0


def test_evidence_completeness_requires_real_artifact():
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="scope", baseline_phase="runtime",
                       evidence_found=False, produced_evidence_path=""),
    ]
    m = score_results_by_mode(results, "dual_axis")
    assert m["evidence_completeness"] == 0.0


def test_benign_produces_no_false_positive():
    results = [
        BenchmarkResult("S9", False, False, "scope", "runtime", "clean_execution", False,
                       predicted_component="", predicted_phase="", localization_correct=False,
                       baseline_component="", baseline_phase="",
                       evidence_found=False),
    ]
    m = score_results_by_mode(results, "dual_axis")
    assert m["false_positive_rate"] == 0.0


@pytest.mark.asyncio
async def test_s1_scope_violation_unit():
    from client.policy_baselines import check_scope_path
    ok, reason = check_scope_path("/etc/passwd")
    assert not ok
    assert "SCOPE_VIOLATION" in reason

@pytest.mark.asyncio
async def test_s3_metadata_violation_unit():
    ok, reason = check_metadata("<script>alert(1)</script> Read a file")
    assert not ok
    assert "METADATA_VIOLATION" in reason


@pytest.mark.integration
@pytest.mark.asyncio
async def test_s9_benign_stdio():
    scenario = next(s for s in ALL_SCENARIOS if s["id"] == "S9")
    result = await run_stdio_scenario(scenario)
    assert not result.false_positive
    assert not result.detected or not result.violating

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_benchmark():
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
    assert dual["localization_accuracy"] >= lifecycle["localization_accuracy"] - 0.01
    assert dual["localization_accuracy"] >= component["localization_accuracy"] - 0.01
    assert dual["localized"] > lifecycle["localized"], \
           "dual_axis should localize more than lifecycle_only (S11: hash_mismatch at runtime, naive infers admission)"
    assert dual["localized"] > component["localized"], \
           "dual_axis should localize more than component_only (S12: authz_denied from scope misconfiguration, naive infers authz)"

    assert dual["localized"] == 10, f"dual_axis: expected 10 localized, got {dual['localized']}"
    assert lifecycle["localized"] == 8, f"lifecycle_only: expected 8 localized, got {lifecycle['localized']}"
    assert component["localized"] == 8, f"component_only: expected 8 localized, got {component['localized']}"
    assert dual["evidence_complete"] == 10, f"dual_axis: expected 10 evidence_complete, got {dual['evidence_complete']}"


# --- Inference unit tests ---

def test_infer_component_hash_mismatch():
    from client.benchmark_client import _infer_component
    assert _infer_component("HASH_MISMATCH: expected=X actual=Y") == "integrity"

def test_infer_component_metadata_violation():
    from client.benchmark_client import _infer_component
    assert _infer_component("METADATA_VIOLATION: disallowed pattern") == "metadata"

def test_infer_component_authz_denied():
    from client.benchmark_client import _infer_component
    assert _infer_component("AUTHZ_DENIED: scope required") == "authz"

def test_infer_component_policy_violation_egress():
    from client.benchmark_client import _infer_component
    assert _infer_component("POLICY_VIOLATION: host 'evil.com' not in egress allowlist") == "scope"

def test_infer_component_observability_gap():
    from client.benchmark_client import _infer_component
    assert _infer_component("OBSERVABILITY_GAP: no server trace") == "observability"

def test_infer_phase_hash_mismatch():
    from client.benchmark_client import _infer_phase
    assert _infer_phase("HASH_MISMATCH: expected=X actual=Y", "integrity_check") == "admission"

def test_infer_phase_metadata_violation():
    from client.benchmark_client import _infer_phase
    assert _infer_phase("METADATA_VIOLATION: bad pattern", "metadata_check") == "discovery"

def test_infer_phase_observability_gap():
    from client.benchmark_client import _infer_phase
    assert _infer_phase("OBSERVABILITY_GAP: no trace", "") == "observability"

def test_infer_phase_authz_denied():
    from client.benchmark_client import _infer_phase
    assert _infer_phase("AUTHZ_DENIED: scope mismatch", "get_secret") == "runtime"

def test_infer_component_dual_overbroad_scope():
    from client.benchmark_client import _infer_component_dual
    assert _infer_component_dual("AUTHZ_DENIED: scope mismatch", "overbroad_scope_manifests_as_authz_denial") == "scope"

def test_infer_component_dual_fallback():
    from client.benchmark_client import _infer_component_dual
    assert _infer_component_dual("AUTHZ_DENIED: scope mismatch", "unauthorized_principal") == "authz"

def test_infer_phase_dual_at_runtime():
    from client.benchmark_client import _infer_phase_dual
    assert _infer_phase_dual("HASH_MISMATCH: expected=X actual=Y", "integrity_check", "integrity_drift_detected_at_runtime") == "runtime"

def test_infer_phase_dual_fallback():
    from client.benchmark_client import _infer_phase_dual
    assert _infer_phase_dual("HASH_MISMATCH: expected=X actual=Y", "integrity_check", "unapproved_tool_at_admission") == "admission"

# --- Golden tests: S11 and S12 create exactly the right divergence ---

def test_s11_golden_divergence():
    results = [
        BenchmarkResult("S11", True, True, "integrity", "runtime", "hash_mismatch", False,
                       predicted_component="integrity", predicted_phase="runtime", localization_correct=True,
                       baseline_component="integrity", baseline_phase="admission",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    assert dual["localization_accuracy"] == 1.0
    assert lifecycle["localization_accuracy"] == 0.0
    assert component["localization_accuracy"] == 1.0

def test_s12_golden_divergence():
    results = [
        BenchmarkResult("S12", True, True, "scope", "runtime", "authz_denied", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="authz", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    assert dual["localization_accuracy"] == 1.0
    assert lifecycle["localization_accuracy"] == 1.0
    assert component["localization_accuracy"] == 0.0

# --- Regression: baselines use baseline_* fields, not expected_evidence_kind ---

def test_baselines_do_not_use_metadata():
    results = [
        BenchmarkResult("SX", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="authz", baseline_phase="admission",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    assert lifecycle["localization_accuracy"] == 0.0
    assert component["localization_accuracy"] == 0.0

# --- Artifact validation test ---

def test_artifact_validation_missing_path():
    from client.benchmark_client import _validate_artifact
    assert not _validate_artifact("")
    assert not _validate_artifact("nonexistent/path/file.json")

def test_artifact_validation_real_file(tmp_path):
    from client.benchmark_client import _validate_artifact
    import json
    f = tmp_path / "trace.json"
    f.write_text(json.dumps({"scenario_id": "S1", "kind": "policy_violation", "timestamp": "2026-01-01"}))
    assert _validate_artifact(str(f))

def test_artifact_validation_missing_fields(tmp_path):
    from client.benchmark_client import _validate_artifact
    import json
    f = tmp_path / "trace.json"
    f.write_text(json.dumps({"scenario_id": "S1"}))
    assert not _validate_artifact(str(f))

# --- Determinism test ---

def test_scoring_determinism():
    results = [
        BenchmarkResult("S1", True, True, "scope", "runtime", "policy_violation", False,
                       predicted_component="scope", predicted_phase="runtime", localization_correct=True,
                       baseline_component="scope", baseline_phase="runtime",
                       evidence_found=True, produced_evidence_path="fake/path"),
    ]
    m1 = score_results_by_mode(results, "dual_axis")
    m2 = score_results_by_mode(results, "dual_axis")
    assert m1 == m2
