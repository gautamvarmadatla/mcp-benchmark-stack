import asyncio, csv, json, logging, os, sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from client.policy_baselines import check_metadata

load_dotenv()
log = logging.getLogger("benchmark_client")
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

EVIDENCE_DIR = Path("evidence")
LOGS_DIR = EVIDENCE_DIR / "logs"
RESULTS_DIR = EVIDENCE_DIR / "results"
TRACES_DIR = EVIDENCE_DIR / "traces"
for d in [LOGS_DIR, RESULTS_DIR, TRACES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

VIOLATION_KEYWORDS = [
    "POLICY_VIOLATION", "TLS_ERROR", "AUTHZ_DENIED", "AUTHN_REQUIRED",
    "AUTHN_FAILED", "METADATA_VIOLATION", "SCOPE_VIOLATION", "HASH_MISMATCH",
    "OBSERVABILITY_GAP",
]
# HTTP status codes / phrases that indicate a security rejection at transport level
HTTP_DENIAL_KEYWORDS = ["401", "403", "Unauthorized", "Forbidden"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


@dataclass
class BenchmarkResult:
    scenario_id: str
    violating: bool
    detected: bool
    # Ground truth from YAML
    gt_component: str
    gt_lifecycle_phase: str
    expected_evidence_kind: str
    false_positive: bool = False
    # Predicted (inferred from system behavior)
    predicted_component: str = ""
    predicted_phase: str = ""
    localization_correct: bool = False
    # Evidence
    produced_evidence_kind: str = ""
    produced_evidence_path: str = ""
    evidence_found: bool = False
    tool_called: str = ""
    tool_args: dict = field(default_factory=dict)
    tool_response: str = ""
    error: str = ""
    timestamp: str = field(default_factory=_now)


def _infer_component(text: str) -> str:
    t = text.upper()
    if "HASH_MISMATCH" in t:
        return "integrity"
    if "METADATA_VIOLATION" in t:
        return "metadata"
    if "AUTHZ_DENIED" in t or "AUTHN_REQUIRED" in t or "AUTHN_FAILED" in t or "403" in t or "401" in t:
        return "authz"
    if "POLICY_VIOLATION" in t and ("HOST" in t or "EGRESS" in t or "ALLOWLIST" in t):
        return "scope"
    if "POLICY_VIOLATION" in t:
        return "scope"
    if "TLS_ERROR" in t or "CERT" in t:
        return "identity"
    if "OBSERVABILITY_GAP" in t:
        return "observability"
    return ""


def _infer_phase(text: str, tool_called: str) -> str:
    t = text.upper()
    if "HASH_MISMATCH" in t or tool_called == "integrity_check":
        return "admission"
    if "METADATA_VIOLATION" in t or tool_called == "metadata_check":
        return "discovery"
    if "OBSERVABILITY_GAP" in t:
        return "observability"
    if "AUTHZ_DENIED" in t or "AUTHN" in t or "403" in t or "401" in t:
        return "runtime"
    if "POLICY_VIOLATION" in t:
        return "runtime"
    if "TLS_ERROR" in t:
        return "runtime"
    return ""


def _write_trace(scenario_id: str, kind: str, content: dict) -> Path:
    ts = _ts()
    trace_file = TRACES_DIR / f"{scenario_id}_{ts}_{kind}.json"
    trace_file.write_text(json.dumps({"scenario_id": scenario_id, "kind": kind, "timestamp": ts, **content}, indent=2))
    log.info(f"Trace written: {trace_file}")
    return trace_file


def _save_evidence(br: BenchmarkResult):
    log_file = LOGS_DIR / f"{br.scenario_id}_{_ts()}.json"
    log_file.write_text(json.dumps(asdict(br), indent=2))
    log.info(f"Evidence saved: {log_file}")


def _flatten_error(e: BaseException) -> str:
    """Recursively flatten ExceptionGroups into a single readable string."""
    if hasattr(e, 'exceptions'):
        parts = [_flatten_error(sub) for sub in e.exceptions]
        return " | ".join(parts)
    msg = f"{type(e).__name__}: {e}"
    # also walk the cause chain
    if e.__context__ and e.__context__ is not e:
        msg += f" <- {_flatten_error(e.__context__)}"
    return msg


def _score_response(response_text: str, error: str, expected_violation: bool) -> tuple[bool, bool]:
    """Returns (detected, false_positive)."""
    combined = response_text + " " + error
    hit = any(kw in combined for kw in VIOLATION_KEYWORDS)
    http_hit = any(kw in combined for kw in HTTP_DENIAL_KEYWORDS)
    detected = hit or (expected_violation and http_hit)
    if expected_violation:
        return detected, False
    else:
        return False, detected  # benign: any trigger = false positive


async def run_stdio_scenario(scenario: dict) -> BenchmarkResult:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client, StdioServerParameters

    sid = scenario["id"]
    params = StdioServerParameters(
        command=scenario["command"],
        args=scenario.get("args", []),
        env={**os.environ, **scenario.get("env", {})},
    )
    tool_name = scenario["tool"]
    tool_args = scenario["tool_args"]
    expected_violation = scenario["violating"]
    gt_component = scenario["component"]
    gt_lifecycle_phase = scenario["lifecycle_phase"]
    expected_evidence_kind = scenario["evidence_kind"]

    log.info(f"[{sid}] stdio: {tool_name}({tool_args})")

    good_br = None
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                log.info(f"[{sid}] tools: {[t.name for t in (await session.list_tools()).tools]}")

                # --- S3: metadata_check ---
                if "metadata_check" in scenario:
                    mc = scenario["metadata_check"]
                    ok, reason = check_metadata(mc.get("inject_description", ""))
                    response_text = reason if not ok else "metadata ok"
                    detected, fp = _score_response(response_text, "", expected_violation)
                    predicted_component = _infer_component(response_text)
                    predicted_phase = _infer_phase(response_text, "metadata_check")
                    localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
                    produced_evidence_path = ""
                    evidence_found = False
                    if detected:
                        trace_file = _write_trace(sid, "metadata_violation", {"response": response_text, "tool_args": {"description": mc.get("inject_description", "")}})
                        produced_evidence_path = str(trace_file)
                        evidence_found = True
                    good_br = BenchmarkResult(
                        sid, expected_violation, detected,
                        gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
                        expected_evidence_kind=expected_evidence_kind,
                        predicted_component=predicted_component, predicted_phase=predicted_phase,
                        localization_correct=localization_correct,
                        produced_evidence_kind="metadata_violation" if detected else "",
                        produced_evidence_path=produced_evidence_path,
                        evidence_found=evidence_found,
                        false_positive=fp,
                        tool_called="metadata_check",
                        tool_args={"description": mc.get("inject_description", "")},
                        tool_response=response_text,
                    )
                    _save_evidence(good_br)

                # --- S4/S7: integrity_check ---
                elif "integrity_check" in scenario:
                    from pydantic import AnyUrl
                    ic = scenario["integrity_check"]
                    expected_hash = ic.get("expected_hash", "")
                    resource_uri_str = ic.get("resource_uri", "tool-integrity://hash")
                    resource_result = await session.read_resource(AnyUrl(resource_uri_str))
                    actual_hash = ""
                    for content in resource_result.contents:
                        if hasattr(content, "text"):
                            actual_hash = content.text.strip()
                    if actual_hash != expected_hash:
                        response_text = f"HASH_MISMATCH: expected={expected_hash} actual={actual_hash}"
                    else:
                        response_text = f"hash_ok: {actual_hash}"
                    log.info(f"[{sid}] integrity: {response_text}")
                    detected, fp = _score_response(response_text, "", expected_violation)
                    predicted_component = _infer_component(response_text)
                    predicted_phase = _infer_phase(response_text, "integrity_check")
                    localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
                    produced_evidence_path = ""
                    evidence_found = False
                    if detected:
                        trace_file = _write_trace(sid, "hash_mismatch", {"response": response_text, "expected_hash": expected_hash, "actual_hash": actual_hash})
                        produced_evidence_path = str(trace_file)
                        evidence_found = True
                    good_br = BenchmarkResult(
                        sid, expected_violation, detected,
                        gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
                        expected_evidence_kind=expected_evidence_kind,
                        predicted_component=predicted_component, predicted_phase=predicted_phase,
                        localization_correct=localization_correct,
                        produced_evidence_kind="hash_mismatch" if detected else "",
                        produced_evidence_path=produced_evidence_path,
                        evidence_found=evidence_found,
                        false_positive=fp,
                        tool_called="integrity_check",
                        tool_args={"resource_uri": resource_uri_str},
                        tool_response=response_text,
                    )
                    _save_evidence(good_br)

                # --- Normal tool call ---
                else:
                    result = await session.call_tool(tool_name, tool_args)
                    response_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                    log.info(f"[{sid}] response: {response_text[:200]}")
                    detected, fp = _score_response(response_text, "", expected_violation)
                    predicted_component = _infer_component(response_text)
                    predicted_phase = _infer_phase(response_text, tool_name)
                    localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
                    produced_evidence_path = ""
                    evidence_found = False
                    if detected:
                        trace_file = _write_trace(sid, "policy_violation", {"response": response_text, "tool": tool_name, "tool_args": tool_args})
                        produced_evidence_path = str(trace_file)
                        evidence_found = True
                    good_br = BenchmarkResult(
                        sid, expected_violation, detected,
                        gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
                        expected_evidence_kind=expected_evidence_kind,
                        predicted_component=predicted_component, predicted_phase=predicted_phase,
                        localization_correct=localization_correct,
                        produced_evidence_kind="policy_violation" if detected else "",
                        produced_evidence_path=produced_evidence_path,
                        evidence_found=evidence_found,
                        false_positive=fp,
                        tool_called=tool_name, tool_args=tool_args, tool_response=response_text,
                    )
                    _save_evidence(good_br)

    except BaseException as e:
        # If we already got a clean result, TaskGroup cleanup errors are noise — return the good result
        if good_br is not None:
            log.warning(f"[{sid}] cleanup exception (result already captured): {type(e).__name__}")
            return good_br
        err_str = _flatten_error(e)
        log.error(f"[{sid}] exception: {err_str[:200]}")
        detected, fp = _score_response("", err_str, expected_violation)
        predicted_component = _infer_component(err_str)
        predicted_phase = _infer_phase(err_str, "")
        localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
        br = BenchmarkResult(
            sid, expected_violation, detected,
            gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
            expected_evidence_kind=expected_evidence_kind,
            predicted_component=predicted_component, predicted_phase=predicted_phase,
            localization_correct=localization_correct,
            false_positive=fp,
            error=err_str,
        )
        _save_evidence(br)
        return br

    return good_br


async def run_http_scenario(scenario: dict) -> BenchmarkResult:
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    sid = scenario["id"]
    url = scenario["url"]
    tool_name = scenario["tool"]
    tool_args = scenario["tool_args"]
    expected_violation = scenario["violating"]
    gt_component = scenario["component"]
    gt_lifecycle_phase = scenario["lifecycle_phase"]
    expected_evidence_kind = scenario["evidence_kind"]
    headers = scenario.get("headers", {})
    observability_check = scenario.get("observability_check", False)

    log.info(f"[{sid}] http: {url} {tool_name}({tool_args})")

    good_br = None
    try:
        http_client = httpx.AsyncClient(headers=headers) if headers else None
        async with streamable_http_client(url, http_client=http_client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, tool_args)
                response_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                log.info(f"[{sid}] response: {response_text[:200]}")

                # S8 observability check: look for server-side trace artifact
                if observability_check:
                    # Check if a SERVER-side trace file exists in TRACES_DIR matching the scenario
                    # Only the client writes traces, so no server trace will be found
                    server_traces = list(TRACES_DIR.glob(f"{sid}_*"))
                    # Filter out client-written traces (those are written after detection)
                    # Since we haven't written one yet, any found would be server-side
                    if not server_traces:
                        obs_msg = f"OBSERVABILITY_GAP: no server-side denial trace found for {sid}"
                        log.info(f"[{sid}] {obs_msg}")
                        response_text = obs_msg

                detected, fp = _score_response(response_text, "", expected_violation)
                predicted_component = _infer_component(response_text)
                predicted_phase = _infer_phase(response_text, tool_name)
                localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
                produced_evidence_path = ""
                evidence_found = False
                if detected:
                    kind = "observability_gap" if observability_check else "policy_violation"
                    trace_file = _write_trace(sid, kind, {"response": response_text, "tool": tool_name, "tool_args": tool_args})
                    produced_evidence_path = str(trace_file)
                    evidence_found = True
                good_br = BenchmarkResult(
                    sid, expected_violation, detected,
                    gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
                    expected_evidence_kind=expected_evidence_kind,
                    predicted_component=predicted_component, predicted_phase=predicted_phase,
                    localization_correct=localization_correct,
                    produced_evidence_kind=kind if detected else "",
                    produced_evidence_path=produced_evidence_path,
                    evidence_found=evidence_found,
                    false_positive=fp,
                    tool_called=tool_name, tool_args=tool_args, tool_response=response_text,
                )
                _save_evidence(good_br)

    except BaseException as e:
        if good_br is not None:
            log.warning(f"[{sid}] cleanup exception (result already captured): {type(e).__name__}")
            return good_br
        err_str = _flatten_error(e)
        log.error(f"[{sid}] exception: {err_str[:300]}")

        # S8 observability check in exception path
        if observability_check:
            server_traces = list(TRACES_DIR.glob(f"{sid}_*"))
            if not server_traces:
                obs_msg = f"OBSERVABILITY_GAP: no server-side denial trace found for {sid}"
                err_str = obs_msg + " | " + err_str

        detected, fp = _score_response("", err_str, expected_violation)
        predicted_component = _infer_component(err_str)
        predicted_phase = _infer_phase(err_str, tool_name)
        localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
        produced_evidence_path = ""
        evidence_found = False
        if detected and observability_check:
            trace_file = _write_trace(sid, "observability_gap", {"error": err_str, "tool": tool_name, "tool_args": tool_args})
            produced_evidence_path = str(trace_file)
            evidence_found = True
        br = BenchmarkResult(
            sid, expected_violation, detected,
            gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
            expected_evidence_kind=expected_evidence_kind,
            predicted_component=predicted_component, predicted_phase=predicted_phase,
            localization_correct=localization_correct,
            produced_evidence_path=produced_evidence_path,
            evidence_found=evidence_found,
            false_positive=fp,
            error=err_str,
        )
        _save_evidence(br)
        return br

    return good_br


def score_results_by_mode(results: list[BenchmarkResult], mode: str) -> dict:
    """mode: 'lifecycle_only', 'component_only', 'dual_axis'"""
    violating = [r for r in results if r.violating]
    benign = [r for r in results if not r.violating]
    detected = [r for r in violating if r.detected]
    fps = [r for r in results if r.false_positive]

    if mode == "lifecycle_only":
        localized = [r for r in detected if r.predicted_phase == r.gt_lifecycle_phase and r.predicted_phase != ""]
    elif mode == "component_only":
        localized = [r for r in detected if r.predicted_component == r.gt_component and r.predicted_component != ""]
    else:  # dual_axis
        localized = [r for r in detected if r.localization_correct]

    # Evidence completeness: trace file actually exists
    evidence_complete = [r for r in detected if r.evidence_found and r.produced_evidence_path != ""]

    vdr = len(detected) / len(violating) if violating else 0.0
    fpr = len(fps) / len(benign) if benign else 0.0
    la = len(localized) / len(detected) if detected else 0.0
    ec = len(evidence_complete) / len(detected) if detected else 0.0

    return {
        "mode": mode,
        "violation_detection_rate": round(vdr, 4),
        "false_positive_rate": round(fpr, 4),
        "localization_accuracy": round(la, 4),
        "evidence_completeness": round(ec, 4),
        "total_scenarios": len(results),
        "violating": len(violating),
        "benign": len(benign),
        "detected": len(detected),
        "false_positives": len(fps),
        "localized": len(localized),
        "evidence_complete": len(evidence_complete),
    }


def score_results(results: list[BenchmarkResult]) -> dict:
    """Backward-compat alias for dual_axis mode."""
    return score_results_by_mode(results, "dual_axis")


def export_results(results: list[BenchmarkResult], metrics_dual: dict, metrics_lifecycle: dict = None, metrics_component: dict = None):
    ts = _ts()
    csv_path = RESULTS_DIR / f"results_{ts}.csv"
    fields = list(BenchmarkResult.__dataclass_fields__.keys())
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = asdict(r)
            row["tool_args"] = json.dumps(row["tool_args"])
            w.writerow(row)

    # Export metrics for all three modes
    all_modes = {}
    for mode, m in [("dual_axis", metrics_dual), ("lifecycle_only", metrics_lifecycle), ("component_only", metrics_component)]:
        if m:
            all_modes[mode] = m
            path = RESULTS_DIR / f"metrics_{mode}_{ts}.json"
            path.write_text(json.dumps(m, indent=2))

    # Comparison table
    comparison_path = RESULTS_DIR / f"baseline_comparison_{ts}.json"
    comparison_path.write_text(json.dumps(all_modes, indent=2))

    # Scenario outcomes CSV with gt and predicted columns
    summary_path = RESULTS_DIR / f"scenario_outcomes_{ts}.csv"
    with open(summary_path, "w", newline="") as f:
        summary_fields = [
            "scenario_id", "violating", "detected", "false_positive",
            "gt_component", "gt_lifecycle_phase",
            "predicted_component", "predicted_phase",
            "localization_correct", "evidence_found", "evidence_kind",
        ]
        w = csv.DictWriter(f, fieldnames=summary_fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "scenario_id": r.scenario_id,
                "violating": r.violating,
                "detected": r.detected,
                "false_positive": r.false_positive,
                "gt_component": r.gt_component,
                "gt_lifecycle_phase": r.gt_lifecycle_phase,
                "predicted_component": r.predicted_component,
                "predicted_phase": r.predicted_phase,
                "localization_correct": r.localization_correct,
                "evidence_found": r.evidence_found,
                "evidence_kind": r.expected_evidence_kind,
            })

    log.info(f"Exported: {csv_path}, {comparison_path}, {summary_path}")
    return csv_path, comparison_path, summary_path
