from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from agentguard_core import ScanRequest, scan


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure AgentGuard's complete offline scanner without weakening analysis.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--budget-seconds", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    durations = []
    last = None
    for _ in range(args.runs):
        started = time.perf_counter()
        last = scan(ScanRequest(args.path))
        durations.append(time.perf_counter() - started)

    assert last is not None
    report = {
        "schema": "agentguard-performance-benchmark/1.0",
        "path": str(args.path.resolve()),
        "runs": args.runs,
        "analysis_profile": "complete-offline-defaults",
        "durations_seconds": [round(value, 6) for value in durations],
        "minimum_seconds": round(min(durations), 6),
        "median_seconds": round(statistics.median(durations), 6),
        "maximum_seconds": round(max(durations), 6),
        "files_scanned": last.metrics.files_scanned,
        "findings": len(last.findings),
        "inventory_entities": len(last.inventory),
        "analysis_errors": len(last.errors),
        "status": last.scan.status,
        "budget_seconds": args.budget_seconds,
        "within_budget": args.budget_seconds is None or max(durations) <= args.budget_seconds,
    }
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["within_budget"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
