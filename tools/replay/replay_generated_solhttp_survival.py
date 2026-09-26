#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import os
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOLHTTP_ROOT = pathlib.Path(os.environ.get("SOLHTTP_ROOT", "submission"))
RUN_LABEL = os.environ.get("SOLHTTP_RUN_LABEL", "solhttp_0.1.0")
GUNDLE = ROOT / "contracts" / "guzzle" / "guzzle_8.1.0_survival_from_merged_common_119.json"
OUT = ROOT / "contracts" / "solhttp" / f"{RUN_LABEL}_survival_from_guzzle_common_114.json"
OUT_MD = ROOT / "contracts" / "solhttp" / f"{RUN_LABEL}_survival_from_guzzle_common_114.md"


def main() -> int:
    sys.path.insert(0, str(SOLHTTP_ROOT))
    sys.path.insert(0, str(ROOT / "tools" / "replay"))

    solhttp = importlib.import_module("solhttp")
    base = importlib.import_module("replay_requests_survival")
    merged = importlib.import_module("replay_merged_common_requests_latest")
    shim = importlib.import_module("solhttp_requests_shim")
    requests_like = shim.make_requests_like(solhttp)

    base.requests = requests_like
    base.HTTPAdapter = requests_like.HTTPAdapter
    merged.requests = requests_like
    merged.HTTPAdapter = requests_like.HTTPAdapter
    merged.base.requests = requests_like
    merged.base.HTTPAdapter = requests_like.HTTPAdapter

    guzzle = json.loads(GUNDLE.read_text())
    rows = [row for row in guzzle["results"] if row.get("guzzle_status") == "passed"]
    requested_tests = sorted({merged.test_name_for(row) for row in rows if merged.test_name_for(row)})
    raw_tests = {name: base.run_test(name, merged.fn_for(name)) for name in requested_tests}

    results = []
    for row in rows:
        test_name = merged.test_name_for(row)
        result = {
            "origin": row["origin"],
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
            "solhttp_test": test_name or "",
        }
        if not test_name:
            result.update({
                "solhttp_status": "failed_absent_or_unmapped",
                "error": "no executed solhttp equivalent mapped for this common contract",
            })
        else:
            test = raw_tests[test_name]
            result.update({
                "solhttp_status": "passed" if test["passed"] else "failed",
                "error": test["error"],
            })
        results.append(result)

    survived = sum(1 for row in results if row["solhttp_status"] == "passed")
    summary = {
        "source_project": "guzzle_surviving_merged_common",
        "source_baseline": str(GUNDLE.relative_to(ROOT)),
        "target_project": "solhttp",
        "target_workspace": str(SOLHTTP_ROOT),
        "target_version": getattr(solhttp, "__version__", "unknown"),
        "total_common_114": len(results),
        "solhttp_survived": survived,
        "solhttp_failed": len(results) - survived,
        "adapter_tests": {
            "total": len(raw_tests),
            "passed": sum(1 for test in raw_tests.values() if test["passed"]),
            "failed": sum(1 for test in raw_tests.values() if not test["passed"]),
        },
        "rule": "A 114-core contract counts as surviving solhttp only when its executed replay test passed. There is no not-applicable bucket.",
    }

    payload = {"summary": summary, "raw_runner": {"tests": list(raw_tests.values())}, "results": results}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    lines = [
        f"# {RUN_LABEL} survival from Guzzle-surviving common 114",
        "",
        f"- total_common_114: {summary['total_common_114']}",
        f"- solhttp_survived: {summary['solhttp_survived']}",
        f"- solhttp_failed: {summary['solhttp_failed']}",
        f"- adapter_tests: {summary['adapter_tests']['total']} total, {summary['adapter_tests']['passed']} passed, {summary['adapter_tests']['failed']} failed",
        "",
        "## Adapter Test Failures",
        "",
        "| test | error |",
        "|---|---|",
    ]
    for test in raw_tests.values():
        if not test["passed"]:
            err = test["error"].replace("|", "\\|")
            if len(err) > 220:
                err = err[:217] + "..."
            lines.append(f"| `{test['name']}` | {err} |")
    lines += ["", "## Failed Contracts", "", "| contract | capability | solhttp_test | error |", "|---|---|---|---|"]
    for row in results:
        if row["solhttp_status"] != "passed":
            err = row["error"].replace("|", "\\|")
            if len(err) > 220:
                err = err[:217] + "..."
            lines.append(f"| `{row['contract']}` | `{row['capability']}` | `{row['solhttp_test']}` | {err} |")
    OUT_MD.write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
