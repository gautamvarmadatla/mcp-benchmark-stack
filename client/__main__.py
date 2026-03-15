import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from client.benchmark_client import run_stdio_scenario, run_http_scenario, score_results_by_mode, export_results
import yaml

async def main():
    with open("scenarios/scenarios.yaml") as f:
        scenarios = yaml.safe_load(f)["scenarios"]
    results = []
    for s in scenarios:
        if s["transport"] == "stdio":
            r = await run_stdio_scenario(s)
        else:
            r = await run_http_scenario(s)
        results.append(r)
    dual = score_results_by_mode(results, "dual_axis")
    lifecycle = score_results_by_mode(results, "lifecycle_only")
    component = score_results_by_mode(results, "component_only")
    paths = export_results(results, dual, lifecycle, component)
    print(json.dumps({"dual_axis": dual, "lifecycle_only": lifecycle, "component_only": component}, indent=2))
    print(f"Results written to: {paths[0]}")

if __name__ == "__main__":
    asyncio.run(main())
