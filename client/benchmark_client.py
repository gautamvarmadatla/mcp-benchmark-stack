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
    component: str
    lifecycle_phase: str
    evidence_kind: str
    false_positive: bool
    tool_called: str = ""
    tool_args: dict = field(default_factory=dict)
    tool_response: str = ""
    error: str = ""
    timestamp: str = field(default_factory=_now)


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
    component = scenario["component"]
    phase = scenario["lifecycle_phase"]
    evidence_kind = scenario["evidence_kind"]

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
                    good_br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp,
                                             tool_called="metadata_check",
                                             tool_args={"description": mc.get("inject_description", "")},
                                             tool_response=response_text)
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
                    good_br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp,
                                             tool_called="integrity_check",
                                             tool_args={"resource_uri": resource_uri_str},
                                             tool_response=response_text)
                    _save_evidence(good_br)

                # --- Normal tool call ---
                else:
                    result = await session.call_tool(tool_name, tool_args)
                    response_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                    log.info(f"[{sid}] response: {response_text[:200]}")
                    detected, fp = _score_response(response_text, "", expected_violation)
                    good_br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp,
                                             tool_called=tool_name, tool_args=tool_args, tool_response=response_text)
                    _save_evidence(good_br)

    except BaseException as e:
        # If we already got a clean result, TaskGroup cleanup errors are noise — return the good result
        if good_br is not None:
            log.warning(f"[{sid}] cleanup exception (result already captured): {type(e).__name__}")
            return good_br
        err_str = _flatten_error(e)
        log.error(f"[{sid}] exception: {err_str[:200]}")
        detected, fp = _score_response("", err_str, expected_violation)
        br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp, error=err_str)
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
    component = scenario["component"]
    phase = scenario["lifecycle_phase"]
    evidence_kind = scenario["evidence_kind"]
    headers = scenario.get("headers", {})

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
                good_br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp,
                                         tool_called=tool_name, tool_args=tool_args, tool_response=response_text)
                _save_evidence(good_br)

    except BaseException as e:
        if good_br is not None:
            log.warning(f"[{sid}] cleanup exception (result already captured): {type(e).__name__}")
            return good_br
        err_str = _flatten_error(e)
        log.error(f"[{sid}] exception: {err_str[:300]}")
        detected, fp = _score_response("", err_str, expected_violation)
        br = BenchmarkResult(sid, expected_violation, detected, component, phase, evidence_kind, fp, error=err_str)
        _save_evidence(br)
        return br

    return good_br


def score_results(results: list[BenchmarkResult]) -> dict:
    violating = [r for r in results if r.violating]
    benign = [r for r in results if not r.violating]
    detected = [r for r in violating if r.detected]
    fps = [r for r in results if r.false_positive]
    localized = [r for r in detected if r.component and r.lifecycle_phase]
    evidence_complete = [r for r in detected if r.evidence_kind and not r.error]

    vdr = len(detected) / len(violating) if violating else 0.0
    fpr = len(fps) / len(benign) if benign else 0.0
    la = len(localized) / len(detected) if detected else 0.0
    ec = len(evidence_complete) / len(detected) if detected else 0.0

    return {
        "violation_detection_rate": round(vdr, 4),
        "false_positive_rate": round(fpr, 4),
        "localization_accuracy": round(la, 4),
        "evidence_completeness": round(ec, 4),
        "total_scenarios": len(results),
        "violating": len(violating),
        "benign": len(benign),
        "detected": len(detected),
        "false_positives": len(fps),
    }


def export_results(results: list[BenchmarkResult], metrics: dict):
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
    metrics_path = RESULTS_DIR / f"metrics_{ts}.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    summary_path = RESULTS_DIR / f"scenario_outcomes_{ts}.csv"
    with open(summary_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario_id","violating","detected","false_positive","component","lifecycle_phase","evidence_kind"])
        w.writeheader()
        for r in results:
            w.writerow({k: getattr(r, k) for k in ["scenario_id","violating","detected","false_positive","component","lifecycle_phase","evidence_kind"]})
    log.info(f"Exported: {csv_path}, {metrics_path}, {summary_path}")
    return csv_path, metrics_path, summary_path
