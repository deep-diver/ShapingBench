#!/usr/bin/env python3
"""Replay extracted go-yaml/yaml contracts against gopkg.in/yaml.v3@v3.0.1."""

from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "yaml" / "go-yaml"
IN_JSON = BASE / "all_releases_excluding_pyyaml_eemeli.summary.json"
RUNNER_DIR = ROOT / "tools" / "replay" / "go_yaml_latest_runner"


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
    raw = subprocess.check_output(
        ["go", "run", ".", str(IN_JSON)],
        cwd=RUNNER_DIR,
        text=True,
        stderr=subprocess.STDOUT,
    )
    go_result = json.loads(raw)
    results = go_result["results"]
    survivors = go_result["survivors"]
    by_cap = defaultdict(Counter)
    by_kind = defaultdict(Counter)
    failure_kinds = Counter()
    for row in results:
        by_cap[row["capability"]][row["status"]] += 1
        by_kind[row["source_kind"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            failure_kinds[miss.split(":", 1)[0]] += 1

    summary = {
        "domain": source["domain"],
        "project": source["project"],
        "package": source["package"],
        "latest_version": source["latest_version"],
        "runtime_package": go_result["runtime_package"],
        "runtime_version": go_result["runtime_version"],
        "input_contracts": go_result["input_contracts"],
        "latest_replay_passed": go_result["latest_replay_passed"],
        "latest_replay_failed": go_result["latest_replay_failed"],
        "latest_mutant_killed": go_result["latest_mutant_killed"],
        "latest_survivors": go_result["latest_survivors"],
        "pass_rate": round(go_result["latest_survivors"] / go_result["input_contracts"], 4)
        if go_result["input_contracts"]
        else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_cap.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
        "failure_kinds": dict(failure_kinds.most_common()),
    }
    out = {
        **summary,
        "survivors": survivors,
        "failed": [
            {"contract": contract, "result": result}
            for contract, result in zip(source["contracts"], results)
            if result["status"] != "passed"
        ],
        "results": results,
    }
    (BASE / "latest_replay_mutant_verified.json").write_text(
        json.dumps(out, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")

    lines = [
        "# go-yaml/yaml Latest Replay and Mutant Verification",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Runtime package: `{summary['runtime_package']}@{summary['runtime_version']}`",
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
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Miss |", "| --- | --- | --- |"])
    for row in out["failed"][:120]:
        miss = (row["result"].get("misses") or [""])[0].replace("|", "\\|")
        lines.append(f"| `{row['contract']['name']}` | `{row['contract']['capability']}` | {miss} |")
    (BASE / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {key: summary[key] for key in [
        "latest_version",
        "runtime_package",
        "runtime_version",
        "input_contracts",
        "latest_replay_passed",
        "latest_replay_failed",
        "latest_mutant_killed",
        "latest_survivors",
        "failure_kinds",
        "by_capability",
        "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
