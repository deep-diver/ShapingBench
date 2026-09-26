#!/usr/bin/env python3
"""Replay servo/rust-url contracts against latest crates.io url crate."""

from __future__ import annotations

import copy
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "url_iri" / "rust-url" / "all_releases_maximal_language_independent.summary.json"
OUT_DIR = ROOT / "contracts" / "url_iri" / "rust-url"
OUT_JSON = OUT_DIR / "latest_replay_mutant_verified.json"
OUT_MD = OUT_DIR / "latest_replay_mutant_verified.md"
OUT_RPL = OUT_DIR / "latest_replay_mutant_verified.rpl"
RUNNER = ROOT / ".replay" / "url_iri" / "rust_url_runner_target" / "release" / "rust_url_runner"
LATEST_VERSION = "2.5.8"


def run_contract(contract: dict[str, Any]) -> dict[str, Any]:
    proc = subprocess.run(
        [str(RUNNER)],
        input=json.dumps(contract, ensure_ascii=False),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": {"name": "RunnerProcessError", "message": proc.stderr.strip()}}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": {"name": "JSONDecodeError", "message": str(exc), "stdout": proc.stdout, "stderr": proc.stderr}}


def expected_matches(actual: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, list[str]]:
    misses: list[str] = []
    for key, value in expected.items():
        if key.endswith("Contains"):
            actual_key = key[: -len("Contains")]
            actual_value = actual.get(actual_key)
            if isinstance(actual_value, str):
                if value not in actual_value:
                    misses.append(f"{key}: {value!r} not in {actual_value!r}")
            elif isinstance(actual_value, list):
                if value not in actual_value:
                    misses.append(f"{key}: {value!r} not in {actual_value!r}")
            else:
                misses.append(f"{key}: actual {actual_key!r} is not searchable ({actual_value!r})")
        elif actual.get(key) != value:
            misses.append(f"{key}: expected {value!r}, got {actual.get(key)!r}")
    return not misses, misses


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return list(reversed(value)) if len(value) > 1 else value + ["__mutant__"]
    if value is None:
        return "__mutant__"
    if isinstance(value, dict):
        mutated = copy.deepcopy(value)
        if mutated:
            first = next(iter(mutated))
            mutated[first] = mutate_value(mutated[first])
        else:
            mutated["__mutant__"] = True
        return mutated
    return "__mutant__"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = copy.deepcopy(expected)
    key = next(iter(mutated))
    mutated[key] = mutate_value(mutated[key])
    return mutated


def contract_to_rpl(contract: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {contract['name']} {{",
            f"  version = {json.dumps(contract['version'])}",
            f"  capability = {json.dumps(contract['capability'])}",
            f"  op = {json.dumps(contract['op'])}",
            f"  params = {json.dumps(contract['params'], ensure_ascii=False, sort_keys=True)}",
            f"  expect = {json.dumps(contract['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant = {json.dumps(contract['mutant'])}",
            "}",
        ]
    )


def main() -> None:
    data = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    contracts = data["contracts"]
    results = []
    survivors = []

    for contract in contracts:
        result = run_contract(contract)
        if not result.get("ok"):
            actual = {}
            replay_ok = False
            failures = [result.get("error", result.get("error", "unknown runner failure")) if isinstance(result.get("error"), str) else result.get("error", {}).get("message", "unknown runner failure")]
        else:
            actual = result["actual"]
            replay_ok, failures = expected_matches(actual, contract["expected"])

        mutant_expected = mutate_expected(contract["expected"])
        mutant_ok, mutant_failures = expected_matches(actual, mutant_expected)
        mutant_killed = not mutant_ok
        survived = replay_ok and mutant_killed
        row = {
            "name": contract["name"],
            "version": contract["version"],
            "capability": contract["capability"],
            "op": contract["op"],
            "source": contract.get("source"),
            "replay_ok": replay_ok,
            "mutant_killed": mutant_killed,
            "survived_latest": survived,
            "expected": contract["expected"],
            "actual": actual,
            "failures": failures,
            "mutant_expected": mutant_expected,
            "mutant_failures": mutant_failures,
        }
        results.append(row)
        if survived:
            survivors.append(contract)

    failing = [row for row in results if not row["survived_latest"]]
    counts_by_source = Counter(contract.get("source", "unknown") for contract in survivors)
    counts_by_op = Counter(contract["op"] for contract in survivors)
    counts_by_capability = Counter(contract["capability"] for contract in survivors)

    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "servo/rust-url",
                "crate": "url",
                "latest_version": LATEST_VERSION,
                "input_contracts": len(contracts),
                "latest_replay_passed": sum(1 for row in results if row["replay_ok"]),
                "latest_mutant_killed": sum(1 for row in results if row["mutant_killed"]),
                "latest_survivors": len(survivors),
                "survivors": survivors,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(contract) for contract in survivors) + "\n", encoding="utf-8")

    md = [
        "# rust-url latest replay + mutant verification",
        "",
        f"- Latest target: `url@{LATEST_VERSION}`",
        f"- Input contracts: `{len(contracts)}`",
        f"- Replay passed: `{sum(1 for row in results if row['replay_ok'])}`",
        f"- Mutant killed: `{sum(1 for row in results if row['mutant_killed'])}`",
        f"- Latest survivors: `{len(survivors)}`",
        "",
        "## Survivors by source",
        "",
        "| Source | Count |",
        "| --- | ---: |",
    ]
    for source, count in counts_by_source.most_common():
        md.append(f"| `{source}` | {count} |")
    md.extend(["", "## Survivors by operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in counts_by_op.most_common():
        md.append(f"| `{op}` | {count} |")
    md.extend(["", "## Survivors by capability", "", "| Capability | Count |", "| --- | ---: |"])
    for capability, count in counts_by_capability.most_common():
        md.append(f"| `{capability}` | {count} |")
    md.extend(["", "## Non-survivors", "", "| Contract | Reason |", "| --- | --- |"])
    for row in failing[:200]:
        reason = "; ".join(row["failures"]) if row["failures"] else "mutant was not killed"
        md.append(f"| `{row['name']}` | {reason.replace('|', '\\|')} |")
    if len(failing) > 200:
        md.append(f"| ... | {len(failing) - 200} more rows in JSON artifact |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "input_contracts": len(contracts),
                "latest_replay_passed": sum(1 for row in results if row["replay_ok"]),
                "latest_mutant_killed": sum(1 for row in results if row["mutant_killed"]),
                "latest_survivors": len(survivors),
                "non_survivors": len(failing),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
