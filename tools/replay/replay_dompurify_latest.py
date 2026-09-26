#!/usr/bin/env python3
"""Replay extracted DOMPurify contracts against latest DOMPurify and kill mutants."""

from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "html_sanitizer" / "dompurify"
IN_JSON = BASE / "all_releases_maximal_language_independent.summary.json"
RUNNER_DIR = ROOT / "tools" / "replay" / "dompurify_latest_runner"
RUNNER = RUNNER_DIR / "replay_latest.mjs"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        params = json.dumps(row["params"], ensure_ascii=False, sort_keys=True)
        expected = json.dumps(row["expected"], ensure_ascii=False, sort_keys=True)
        lines.append(f"contract {json.dumps(row['name'])} {{")
        lines.append(f"  version {json.dumps(row['version'])}")
        lines.append(f"  capability {json.dumps(row['capability'])}")
        lines.append("  op sanitize")
        lines.append(f"  params {params}")
        lines.append(f"  expected {expected}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    data = load_json(IN_JSON)
    contracts = data["contracts"]
    if not (RUNNER_DIR / "node_modules").exists():
        subprocess.check_call(["npm", "install"], cwd=RUNNER_DIR)
    out = subprocess.check_output(["node", str(RUNNER), str(IN_JSON)], cwd=ROOT, text=True, stderr=subprocess.STDOUT)
    runner_payload = json.loads(out)
    results = runner_payload["results"]
    by_name = {row["name"]: row for row in results}
    survivors = [contract for contract in contracts if by_name[contract["name"]]["status"] == "passed"]
    counts = Counter(row["status"] for row in results)
    by_cap = defaultdict(Counter)
    by_kind = defaultdict(Counter)
    for row in results:
        by_cap[row["capability"]][row["status"]] += 1
        by_kind[row["source_kind"]][row["status"]] += 1
    summary = {
        "domain": "HTML Sanitizer",
        "project": "cure53/DOMPurify",
        "latest_version": data["latest_version"],
        "input_contracts": len(contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_replay_failed": sum(1 for row in results if not row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["replay_passed"] and row["mutant_rejected"]),
        "mutant_rejected_total": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "pass_rate": round(counts["passed"] / len(contracts), 4) if contracts else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_cap.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
    }
    payload = {**summary, "survivors": survivors, "results": results}
    (BASE / "latest_replay_mutant_verified.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")
    lines = [
        "# DOMPurify Latest Replay and Mutant Verification",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['latest_replay_passed']}",
        f"Replay failed: {summary['latest_replay_failed']}",
        f"Mutants rejected: {summary['latest_mutant_killed']}",
        f"Latest survivors: {summary['latest_survivors']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Capability",
        "",
        "| Capability | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for cap, counter in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## By Source Kind", "", "| Source kind | Passed | Failed |", "| --- | ---: | ---: |"])
    for kind, counter in summary["by_source_kind"].items():
        lines.append(f"| `{kind}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Miss |", "| --- | --- | --- |"])
    for row in [r for r in results if r["status"] == "failed"][:80]:
        miss = "; ".join(row["misses"]).replace("|", "\\|")
        if len(miss) > 240:
            miss = miss[:237] + "..."
        lines.append(f"| `{row['name']}` | `{row['capability']}` | {miss} |")
    (BASE / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
