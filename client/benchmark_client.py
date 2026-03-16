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
    gt_component: str
    gt_lifecycle_phase: str
    expected_evidence_kind: str
    false_positive: bool = False
    predicted_component: str = ""
    predicted_phase: str = ""
    localization_correct: bool = False
    baseline_component: str = ""
    baseline_phase: str = ""
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
        return "tools"
    if "METADATA_VIOLATION" in t:
        return "tools"
    if "AUTHZ_DENIED" in t or "AUTHN_REQUIRED" in t or "AUTHN_FAILED" in t or "403" in t or "401" in t:
        return "auth_infra"
    if "POLICY_VIOLATION" in t:
        return "tools"
    if "TLS_ERROR" in t or "CERT" in t:
        return "tools"
    if "OBSERVABILITY_GAP" in t:
        return "server"
    return ""


def _infer_phase(text: str, tool_called: str) -> str:
    t = text.upper()
    if "HASH_MISMATCH" in t or tool_called == "integrity_check":
        return "creation_registration"
    if "METADATA_VIOLATION" in t or tool_called == "metadata_check":
        return "discovery"
    if "OBSERVABILITY_GAP" in t:
        return "update_maintenance"
    if "AUTHZ_DENIED" in t or "AUTHN" in t or "403" in t or "401" in t:
        return "invocation_execution"
    if "POLICY_VIOLATION" in t:
        return "invocation_execution"
    if "TLS_ERROR" in t:
        return "invocation_execution"
    return ""


def _infer_component_dual(text: str, failure_mode: str = "") -> str:
    if "overbroad_scope" in failure_mode or "over_broad" in failure_mode:
        return "tools"
    if "missing_server_trace" in failure_mode:
        return "server"
    return _infer_component(text)


def _infer_phase_dual(text: str, tool_called: str, failure_mode: str = "") -> str:
    if "over_broad" in failure_mode or "overbroad_scope" in failure_mode:
        return "creation_registration"
    if "integrity_drift" in failure_mode or "drifted_after" in failure_mode:
        return "update_maintenance"
    if "missing_server_trace" in failure_mode:
        return "update_maintenance"
    if "at_runtime" in failure_mode:
        return "invocation_execution"
    return _infer_phase(text, tool_called)


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
    if hasattr(e, 'exceptions'):
        parts = [_flatten_error(sub) for sub in e.exceptions]
        return " | ".join(parts)
    msg = f"{type(e).__name__}: {e}"
    if e.__context__ and e.__context__ is not e:
        msg += f" <- {_flatten_error(e.__context__)}"
    return msg


def _find_server_trace(trace_dir: str, kind: str) -> str:
    td = Path(trace_dir)
    if not td.exists():
        return ""
    matches = sorted(td.glob(f"*{kind}*.json"))
    return str(matches[-1]) if matches else ""


def _validate_artifact(path: str) -> bool:
    if not path:
        return False
    p = Path(path)
    if not p.exists() or p.stat().st_size < 10:
        return False
    try:
        data = json.loads(p.read_text())
        return all(k in data for k in ("scenario_id", "kind", "timestamp"))
    except Exception:
        return False


def _score_response(response_text: str, error: str, expected_violation: bool) -> tuple[bool, bool]:
    combined = response_text + " " + error
    hit = any(kw in combined for kw in VIOLATION_KEYWORDS)
    http_hit = any(kw in combined for kw in HTTP_DENIAL_KEYWORDS)
    detected = hit or (expected_violation and http_hit)
    if expected_violation:
        return detected, False
    else:
        return False, detected


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
    failure_mode = scenario.get("failure_mode", "")

    log.info(f"[{sid}] stdio: {tool_name}({tool_args})")

    good_br = None
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                log.info(f"[{sid}] tools: {[t.name for t in (await session.list_tools()).tools]}")

                if "metadata_check" in scenario:
                    mc = scenario["metadata_check"]
                    ok, reason = check_metadata(mc.get("inject_description", ""))
                    response_text = reason if not ok else "metadata ok"
                    detected, fp = _score_response(response_text, "", expected_violation)
                    baseline_component = _infer_component(response_text)
                    baseline_phase = _infer_phase(response_text, "metadata_check")
                    predicted_component = _infer_component_dual(response_text, failure_mode)
                    predicted_phase = _infer_phase_dual(response_text, "metadata_check", failure_mode)
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
                        baseline_component=baseline_component, baseline_phase=baseline_phase,
                        produced_evidence_kind="metadata_violation" if detected else "",
                        produced_evidence_path=produced_evidence_path,
                        evidence_found=evidence_found,
                        false_positive=fp,
                        tool_called="metadata_check",
                        tool_args={"description": mc.get("inject_description", "")},
                        tool_response=response_text,
                    )
                    _save_evidence(good_br)

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
                    baseline_component = _infer_component(response_text)
                    baseline_phase = _infer_phase(response_text, "integrity_check")
                    predicted_component = _infer_component_dual(response_text, failure_mode)
                    predicted_phase = _infer_phase_dual(response_text, "integrity_check", failure_mode)
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
                        baseline_component=baseline_component, baseline_phase=baseline_phase,
                        produced_evidence_kind="hash_mismatch" if detected else "",
                        produced_evidence_path=produced_evidence_path,
                        evidence_found=evidence_found,
                        false_positive=fp,
                        tool_called="integrity_check",
                        tool_args={"resource_uri": resource_uri_str},
                        tool_response=response_text,
                    )
                    _save_evidence(good_br)

                else:
                    result = await session.call_tool(tool_name, tool_args)
                    response_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                    log.info(f"[{sid}] response: {response_text[:200]}")
                    detected, fp = _score_response(response_text, "", expected_violation)
                    baseline_component = _infer_component(response_text)
                    baseline_phase = _infer_phase(response_text, tool_name)
                    predicted_component = _infer_component_dual(response_text, failure_mode)
                    predicted_phase = _infer_phase_dual(response_text, tool_name, failure_mode)
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
                        baseline_component=baseline_component, baseline_phase=baseline_phase,
                        produced_evidence_kind="policy_violation" if detected else "",
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
        log.error(f"[{sid}] exception: {err_str[:200]}")
        detected, fp = _score_response("", err_str, expected_violation)
        baseline_component = _infer_component(err_str)
        baseline_phase = _infer_phase(err_str, "")
        predicted_component = _infer_component_dual(err_str, failure_mode)
        predicted_phase = _infer_phase_dual(err_str, "", failure_mode)
        localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
        br = BenchmarkResult(
            sid, expected_violation, detected,
            gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
            expected_evidence_kind=expected_evidence_kind,
            predicted_component=predicted_component, predicted_phase=predicted_phase,
            localization_correct=localization_correct,
            baseline_component=baseline_component, baseline_phase=baseline_phase,
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
    failure_mode = scenario.get("failure_mode", "")

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

                detected, fp = _score_response(response_text, "", expected_violation)
                baseline_component = _infer_component(response_text)
                baseline_phase = _infer_phase(response_text, tool_name)

                observability_gap = False
                if detected and observability_check:
                    server_trace_dir = scenario.get("server_trace_dir", "evidence/server_traces")
                    server_trace = _find_server_trace(server_trace_dir, "policy_violation")
                    observability_gap = (server_trace == "")
                    if observability_gap:
                        log.info(f"[{sid}] OBSERVABILITY_GAP: real denial detected, expected server trace missing in {server_trace_dir}")
                    else:
                        log.info(f"[{sid}] server trace found: {server_trace}")

                if observability_gap:
                    predicted_component = "server"
                    predicted_phase = "update_maintenance"
                else:
                    predicted_component = _infer_component_dual(response_text, failure_mode)
                    predicted_phase = _infer_phase_dual(response_text, tool_name, failure_mode)
                localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
                produced_evidence_path = ""
                evidence_found = False
                if detected:
                    kind = "observability_gap" if observability_gap else "policy_violation"
                    trace_file = _write_trace(sid, kind, {
                        "response": response_text, "tool": tool_name, "tool_args": tool_args,
                        **({"observability_gap": True, "server_trace_found": False} if observability_gap else {}),
                    })
                    produced_evidence_path = str(trace_file)
                    evidence_found = True
                good_br = BenchmarkResult(
                    sid, expected_violation, detected,
                    gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
                    expected_evidence_kind=expected_evidence_kind,
                    predicted_component=predicted_component, predicted_phase=predicted_phase,
                    localization_correct=localization_correct,
                    baseline_component=baseline_component, baseline_phase=baseline_phase,
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

        detected, fp = _score_response("", err_str, expected_violation)
        baseline_component = _infer_component(err_str)
        baseline_phase = _infer_phase(err_str, tool_name)

        observability_gap = False
        if detected and observability_check:
            server_trace_dir = scenario.get("server_trace_dir", "evidence/server_traces")
            server_trace = _find_server_trace(server_trace_dir, "policy_violation")
            observability_gap = (server_trace == "")

        if observability_gap:
            predicted_component = "observability"
            predicted_phase = "observability"
        else:
            predicted_component = _infer_component_dual(err_str, failure_mode)
            predicted_phase = _infer_phase_dual(err_str, tool_name, failure_mode)
        localization_correct = (predicted_component == gt_component and predicted_phase == gt_lifecycle_phase)
        produced_evidence_path = ""
        evidence_found = False
        if detected:
            kind = "observability_gap" if observability_gap else "authz_denied"
            trace_file = _write_trace(sid, kind, {"error": err_str, "tool": tool_name, "tool_args": tool_args,
                                                   **({"observability_gap": True, "server_trace_found": False} if observability_gap else {})})
            produced_evidence_path = str(trace_file)
            evidence_found = True
        br = BenchmarkResult(
            sid, expected_violation, detected,
            gt_component=gt_component, gt_lifecycle_phase=gt_lifecycle_phase,
            expected_evidence_kind=expected_evidence_kind,
            predicted_component=predicted_component, predicted_phase=predicted_phase,
            localization_correct=localization_correct,
            baseline_component=baseline_component, baseline_phase=baseline_phase,
            produced_evidence_path=produced_evidence_path,
            evidence_found=evidence_found,
            false_positive=fp,
            error=err_str,
        )
        _save_evidence(br)
        return br

    return good_br


def score_results_by_mode(results: list[BenchmarkResult], mode: str) -> dict:
    violating = [r for r in results if r.violating]
    benign = [r for r in results if not r.violating]
    detected = [r for r in violating if r.detected]
    fps = [r for r in results if r.false_positive]

    if mode == "lifecycle_only":
        localized = [r for r in detected
                     if r.baseline_phase == r.gt_lifecycle_phase and r.baseline_phase != ""]
    elif mode == "component_only":
        localized = [r for r in detected
                     if r.baseline_component == r.gt_component and r.baseline_component != ""]
    else:
        localized = [r for r in detected if r.localization_correct]

    evidence_complete = [r for r in detected if _validate_artifact(r.produced_evidence_path)]

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

    all_modes = {}
    for mode, m in [("dual_axis", metrics_dual), ("lifecycle_only", metrics_lifecycle), ("component_only", metrics_component)]:
        if m:
            all_modes[mode] = m
            path = RESULTS_DIR / f"metrics_{mode}_{ts}.json"
            path.write_text(json.dumps(m, indent=2))

    comparison_path = RESULTS_DIR / f"baseline_comparison_{ts}.json"
    comparison_path.write_text(json.dumps(all_modes, indent=2))

    summary_path = RESULTS_DIR / f"scenario_outcomes_{ts}.csv"
    with open(summary_path, "w", newline="") as f:
        summary_fields = [
            "scenario_id", "violating", "detected", "false_positive",
            "gt_component", "gt_lifecycle_phase",
            "predicted_component", "predicted_phase", "localization_correct",
            "baseline_component", "baseline_phase",
            "evidence_found", "evidence_kind",
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
                "baseline_component": r.baseline_component,
                "baseline_phase": r.baseline_phase,
                "evidence_found": r.evidence_found,
                "evidence_kind": r.expected_evidence_kind,
            })

    def _pct(val):
        return f"{round(val * 100)}%"

    def _frac(m, key_loc, key_det):
        return f"{m.get(key_loc, 0)}/{m.get(key_det, 0)}"

    md_table_path = RESULTS_DIR / f"summary_table_{ts}.md"
    dual_m = all_modes.get("dual_axis", {})
    lc_m = all_modes.get("lifecycle_only", {})
    co_m = all_modes.get("component_only", {})
    md_lines = [
        "# Benchmark Results",
        "",
        "| Metric | dual_axis | lifecycle_only | component_only |",
        "|---|:-:|:-:|:-:|",
        f"| Violation Detection Rate | {_pct(dual_m.get('violation_detection_rate', 0))} | {_pct(lc_m.get('violation_detection_rate', 0))} | {_pct(co_m.get('violation_detection_rate', 0))} |",
        f"| False Positive Rate | {_pct(dual_m.get('false_positive_rate', 0))} | {_pct(lc_m.get('false_positive_rate', 0))} | {_pct(co_m.get('false_positive_rate', 0))} |",
        f"| Localization Accuracy | {_pct(dual_m.get('localization_accuracy', 0))} | {_pct(lc_m.get('localization_accuracy', 0))} | {_pct(co_m.get('localization_accuracy', 0))} |",
        f"| Evidence Completeness | {_pct(dual_m.get('evidence_completeness', 0))} | {_pct(lc_m.get('evidence_completeness', 0))} | {_pct(co_m.get('evidence_completeness', 0))} |",
        f"| Localized / Detected | {_frac(dual_m, 'localized', 'detected')} | {_frac(lc_m, 'localized', 'detected')} | {_frac(co_m, 'localized', 'detected')} |",
        "",
        "> dual_axis uses taxonomy-assisted root-cause localization with failure_mode annotations.",
        "> lifecycle_only and component_only use naive signal-based inference from response text only.",
    ]
    md_table_path.write_text("\n".join(md_lines))

    tex_table_path = RESULTS_DIR / f"summary_table_{ts}.tex"
    tex_lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\begin{tabular}{lrrr}",
        r"\hline",
        r"Metric & dual\_axis & lifecycle\_only & component\_only \\",
        r"\hline",
        f"Violation Detection Rate & {_pct(dual_m.get('violation_detection_rate', 0))} & {_pct(lc_m.get('violation_detection_rate', 0))} & {_pct(co_m.get('violation_detection_rate', 0))} \\\\",
        f"False Positive Rate & {_pct(dual_m.get('false_positive_rate', 0))} & {_pct(lc_m.get('false_positive_rate', 0))} & {_pct(co_m.get('false_positive_rate', 0))} \\\\",
        f"Localization Accuracy & {_pct(dual_m.get('localization_accuracy', 0))} & {_pct(lc_m.get('localization_accuracy', 0))} & {_pct(co_m.get('localization_accuracy', 0))} \\\\",
        f"Evidence Completeness & {_pct(dual_m.get('evidence_completeness', 0))} & {_pct(lc_m.get('evidence_completeness', 0))} & {_pct(co_m.get('evidence_completeness', 0))} \\\\",
        f"Localized / Detected & {_frac(dual_m, 'localized', 'detected')} & {_frac(lc_m, 'localized', 'detected')} & {_frac(co_m, 'localized', 'detected')} \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\caption{MCP Benchmark Results. dual\_axis uses taxonomy-assisted root-cause localization; baselines use naive signal inference.}",
        r"\label{tab:benchmark}",
        r"\end{table}",
    ]
    tex_table_path.write_text("\n".join(tex_lines))

    log.info(f"Exported: {csv_path}, {comparison_path}, {summary_path}, {md_table_path}, {tex_table_path}")
    return csv_path, comparison_path, summary_path, md_table_path, tex_table_path
