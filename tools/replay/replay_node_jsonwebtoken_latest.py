#!/usr/bin/env python3
"""Replay auth0/node-jsonwebtoken contracts against jsonwebtoken 9.0.3."""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "jwt" / "node-jsonwebtoken"
INPUT = BASE / "all_releases_language_independent.summary.json"
OUT_JSON = BASE / "latest_replay_mutant_verified.json"
OUT_MD = BASE / "latest_replay_mutant_verified.md"
OUT_RPL = BASE / "latest_replay_mutant_verified.rpl"
RUNNER_DIR = ROOT / "tools" / "replay" / "node_jsonwebtoken_latest_runner"
RUNNER = RUNNER_DIR / "replay_node_jsonwebtoken_latest.js"


def write_rpl(contracts: list[dict], path: Path) -> None:
    lines: list[str] = []
    for contract in contracts:
        lines.append(f"contract {json.dumps(contract['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(contract['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(contract['capability'], ensure_ascii=True)}")
        lines.append(f"  op {contract['op']}")
        lines.append(f"  params {json.dumps(contract['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(contract['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def ensure_deps() -> None:
    if (RUNNER_DIR / "node_modules" / "jsonwebtoken" / "package.json").exists():
        return
    subprocess.run(["npm", "install", "--silent", "--package-lock=false"], cwd=RUNNER_DIR, check=True)


def main() -> int:
    ensure_deps()
    env = os.environ.copy()
    completed = subprocess.run(
        ["node", str(RUNNER), str(INPUT)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    OUT_JSON.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    survivors = result["survivor_contracts"]
    write_rpl(survivors, OUT_RPL)

    by_cap = Counter(contract["capability"] for contract in survivors)
    fail_reasons = Counter()
    for row in result["results"]:
        if row["survived"]:
            continue
        if row.get("runner_error"):
            fail_reasons["runner_error"] += 1
        elif not row.get("replay_pass"):
            fail_reasons["replay_fail"] += 1
        elif not row.get("mutant_rejected"):
            fail_reasons["mutant_accept"] += 1

    rows = [
        "# auth0/node-jsonwebtoken Latest Replay + Mutant Verification",
        "",
        f"- Implementation: auth0/node-jsonwebtoken `{result['version']}`",
        f"- Contracts attempted: {result['contracts_total']}",
        f"- Replay passed: {result['replay_pass']}",
        f"- Mutant rejected: {result['mutant_rejected']}",
        f"- Latest surviving replay/mutant-verified contracts: {result['survivors']}",
        "",
        "## Survivors by Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for capability, count in sorted(by_cap.items()):
        rows.append(f"| `{capability}` | {count} |")
    rows.extend(["", "## Non-Survivor Reasons", "", "| Reason | Count |", "| --- | ---: |"])
    for reason, count in sorted(fail_reasons.items()):
        rows.append(f"| `{reason}` | {count} |")
    OUT_MD.write_text("\n".join(rows) + "\n", encoding="utf-8")

    print(json.dumps({
        "version": result["version"],
        "contracts_total": result["contracts_total"],
        "replay_pass": result["replay_pass"],
        "mutant_rejected": result["mutant_rejected"],
        "survivors": result["survivors"],
        "non_survivor_reasons": dict(fail_reasons),
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
