#!/usr/bin/env python3
"""Replay curl/libcurl URL API contracts against latest curl and kill mutants."""

from __future__ import annotations

import copy
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "url_iri" / "curl" / "all_releases_maximal_language_independent.summary.json"
OUT_DIR = ROOT / "contracts" / "url_iri" / "curl"
OUT_JSON = OUT_DIR / "latest_replay_mutant_verified.json"
OUT_MD = OUT_DIR / "latest_replay_mutant_verified.md"
OUT_RPL = OUT_DIR / "latest_replay_mutant_verified.rpl"
RUNNER = ROOT / ".replay" / "url_iri" / "curl_urlapi_runner"
LATEST_VERSION = "8.21.0"


def execute(contract: dict[str, Any]) -> dict[str, Any]:
    raw = subprocess.check_output([str(RUNNER), contract["op"], *contract["args"]], cwd=ROOT, text=True)
    return json.loads(raw)


def mutate_scalar(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "__mutant__"
    if value is None:
        return "__mutant__"
    return "__mutant__"


def mutate_first_leaf(value: Any) -> Any:
    if isinstance(value, dict):
        if not value:
            return {"__mutant__": True}
        clone = copy.deepcopy(value)
        key = sorted(clone.keys())[0]
        clone[key] = mutate_first_leaf(clone[key])
        return clone
    if isinstance(value, list):
        if not value:
            return ["__mutant__"]
        clone = copy.deepcopy(value)
        clone[0] = mutate_first_leaf(clone[0])
        return clone
    return mutate_scalar(value)


def contract_to_rpl(contract: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {contract['name']} {{",
            f"  version = {json.dumps(contract['version'])}",
            f"  capability = {json.dumps(contract['capability'])}",
            f"  op = {json.dumps(contract['op'])}",
            f"  args = {json.dumps(contract['args'], ensure_ascii=False)}",
            f"  expect = {json.dumps(contract['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant = {json.dumps(contract['mutant'])}",
            "}",
        ]
    )


def main() -> None:
    data = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    contracts = data["contracts"]
    survivors = []
    replay_failures = []
    mutant_survivors = []
    for contract in contracts:
        actual = execute(contract)
        replay_passed = actual == contract["expected"]
        mutant_expected = mutate_first_leaf(contract["expected"])
        mutant_passed = actual == mutant_expected
        row = {
            **contract,
            "latest_version": LATEST_VERSION,
            "actual": actual,
            "mutant_expected": mutant_expected,
            "replay_passed": replay_passed,
            "mutant_killed": not mutant_passed,
        }
        if replay_passed and not mutant_passed:
            survivors.append(contract)
        elif not replay_passed:
            replay_failures.append(row)
        else:
            mutant_survivors.append(row)

    by_capability = Counter(contract["capability"] for contract in survivors)
    by_op = Counter(contract["op"] for contract in survivors)
    OUT_JSON.write_text(
        json.dumps(
            {
                "project": data["project"],
                "latest_version": LATEST_VERSION,
                "input_contracts": len(contracts),
                "latest_replay_passed": len(contracts) - len(replay_failures),
                "mutant_killed": len(contracts) - len(mutant_survivors),
                "latest_survivors": len(survivors),
                "replay_failures": replay_failures,
                "mutant_survivors": mutant_survivors,
                "survivors": survivors,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(contract) for contract in survivors) + "\n", encoding="utf-8")
    md = [
        "# curl URL API Latest Replay + Mutant Verification",
        "",
        f"- Target: `libcurl=={LATEST_VERSION}` via Homebrew curl bottle",
        f"- Input contracts: `{len(contracts)}`",
        f"- Latest replay passed: `{len(contracts) - len(replay_failures)}`",
        f"- Mutant killed: `{len(contracts) - len(mutant_survivors)}`",
        f"- Latest survivors: `{len(survivors)}`",
        "",
        "## Survivors by Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for capability, count in by_capability.most_common():
        md.append(f"| `{capability}` | {count} |")
    md.extend(["", "## Survivors by Operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in by_op.most_common():
        md.append(f"| `{op}` | {count} |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "input_contracts": len(contracts),
                "latest_replay_passed": len(contracts) - len(replay_failures),
                "mutant_killed": len(contracts) - len(mutant_survivors),
                "latest_survivors": len(survivors),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
