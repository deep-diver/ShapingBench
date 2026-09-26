#!/usr/bin/env python3
"""Replay pulldown-cmark contracts against latest pulldown-cmark and kill mutants."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "markdown" / "pulldown-cmark"
IN_JSON = BASE / "all_releases_excluding_markdown_it.summary.json"
RUNNER_DIR = ROOT / "tools" / "replay" / "pulldown_cmark_latest_runner"
def cargo_bin() -> str:
    found = shutil.which("cargo")
    if found:
        return found
    raise RuntimeError("cargo not found")


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    source = json.loads(IN_JSON.read_text(encoding="utf-8"))
    contracts = source["contracts"]
    env = os.environ.copy()
    cargo = cargo_bin()
    env["PATH"] = str(Path(cargo).parent) + os.pathsep + env.get("PATH", "")
    output = subprocess.check_output(
        [cargo, "run", "--quiet", "--", str(IN_JSON)],
        cwd=RUNNER_DIR,
        text=True,
        stderr=subprocess.STDOUT,
        env=env,
    )
    payload = json.loads(output)
    results = payload["results"]
    by_name = {row["name"]: row for row in results}
    survivors = [contract for contract in contracts if by_name[contract["name"]]["status"] == "passed"]
    failed = [{"contract": contract, "result": by_name[contract["name"]]} for contract in contracts if by_name[contract["name"]]["status"] != "passed"]

    by_cap = defaultdict(Counter)
    by_kind = defaultdict(Counter)
    for row in results:
        by_cap[row["capability"]][row["status"]] += 1
        by_kind[row["source_kind"]][row["status"]] += 1
    summary = {
        "domain": source["domain"],
        "project": source["project"],
        "latest_version": source["latest_version"],
        "input_contracts": len(contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_replay_failed": sum(1 for row in results if not row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["replay_passed"] and row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "pass_rate": round(len(survivors) / len(contracts), 4) if contracts else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_cap.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
    }
    out = {**summary, "survivors": survivors, "failed": failed, "results": results}
    (BASE / "latest_replay_mutant_verified.json").write_text(
        json.dumps(out, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")

    lines = [
        "# pulldown-cmark Latest Replay and Mutant Verification",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['latest_replay_passed']}",
        f"Replay failed: {summary['latest_replay_failed']}",
        f"Mutants killed after replay pass: {summary['latest_mutant_killed']}",
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
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Actual sample |", "| --- | --- | --- |"])
    for row in failed[:80]:
        actual = str(row["result"].get("actual", {}).get("html", "")).replace("\n", "\\n").replace("|", "\\|")
        if len(actual) > 240:
            actual = actual[:237] + "..."
        lines.append(f"| `{row['contract']['name']}` | `{row['contract']['capability']}` | {actual} |")
    (BASE / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {k: summary[k] for k in [
        "latest_version", "input_contracts", "latest_replay_passed",
        "latest_replay_failed", "latest_mutant_killed", "latest_survivors",
        "by_capability", "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
