#!/usr/bin/env python3
"""Replay auth0/java-jwt contracts against com.auth0:java-jwt 4.6.0."""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "jwt" / "auth0-java-jwt"
INPUT = BASE / "all_releases_language_independent.summary.json"
OUT_JSON = BASE / "latest_replay_mutant_verified.json"
OUT_MD = BASE / "latest_replay_mutant_verified.md"
OUT_RPL = BASE / "latest_replay_mutant_verified.rpl"
RUNNER = ROOT / "tools" / "replay" / "java_jwt_latest_runner"
JAVA_HOME = "/opt/homebrew/Cellar/openjdk/26.0.2.1/libexec/openjdk.jdk/Contents/Home"


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


def main() -> int:
    env = os.environ.copy()
    if Path(JAVA_HOME).exists():
        env["JAVA_HOME"] = JAVA_HOME
    cmd = [
        "mvn",
        "-q",
        "compile",
        "exec:java",
        "-Dexec.mainClass=shapingbench.jwt.ReplayJavaJwt",
        f"-Dexec.args={INPUT}",
    ]
    raw = subprocess.check_output(cmd, cwd=RUNNER, env=env, text=True, stderr=subprocess.STDOUT)
    result = json.loads(raw.strip().splitlines()[-1])
    OUT_JSON.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    survivors = result["survivor_contracts"]
    write_rpl(survivors, OUT_RPL)

    by_cap = Counter(contract["capability"] for contract in survivors)
    by_source = Counter(contract["source_kind"] for contract in survivors)
    failed = [row for row in result["results"] if not row["survived"]]
    lines = [
        "# auth0/java-jwt Latest Replay + Mutant Verification",
        "",
        "- Implementation: `com.auth0:java-jwt`",
        "- Latest version tested: `4.6.0`",
        f"- Contracts evaluated: {result['contracts_total']}",
        f"- Replay passed: {result['replay_pass']}",
        f"- Mutant rejected: {result['mutant_rejected']}",
        f"- Latest surviving contracts: {result['survivors']}",
        "",
        "## Survivors By Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for key, value in sorted(by_cap.items()):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Survivors By Source Kind", "", "| Source kind | Survivors |", "| --- | ---: |"])
    for key, value in sorted(by_source.items()):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Reason |", "| --- | --- |"])
    for row in failed[:20]:
        reason = row.get("runner_error") or "replay/mutant mismatch"
        lines.append(f"| `{row['name']}` | {reason} |")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["contracts_total", "replay_pass", "mutant_rejected", "survivors"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
