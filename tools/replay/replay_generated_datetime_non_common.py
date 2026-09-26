#!/usr/bin/env python3
"""Replay Date/Time/Timezone non-common contracts against generated ./dtlib snapshots."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from replay_generated_datetime import compare, mutate_expected, run_contract, write_hashes


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "generated_non_common"

COMMON = ROOT / "contracts" / "datetime_timezone" / "blind_cross_validation" / "merged_377_rank4_rank5_survivors.summary.json"
MERGED_377 = ROOT / "contracts" / "datetime_timezone" / "merged_common" / "merged_common.summary.json"
JODA = ROOT / "contracts" / "datetime_timezone" / "joda-time" / "all_releases_maximal_language_independent.summary.json"
NODA = ROOT / "contracts" / "datetime_timezone" / "nodatime" / "all_releases_excluding_joda_common.summary.json"
DATEUTIL = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "all_releases_excluding_merged_343.summary.json"
BLIND_CROSS = ROOT / "contracts" / "datetime_timezone" / "blind_cross_validation" / "merged_377_rank4_rank5_cross.json"
CARBON = ROOT / "contracts" / "datetime_timezone" / "carbon" / "origin_latest_replay_mutant_verified.summary.json"
DATEFNS = ROOT / "contracts" / "datetime_timezone" / "date-fns" / "origin_latest_replay_mutant_verified.summary.json"

DEFAULT_SNAPSHOT_ROOT = Path(os.environ.get("SHAPINGBENCH_TARGET_SNAPSHOT", "submission"))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def corpus_minus_common(path: Path, origin: str, common_names: set[str]) -> list[dict[str, Any]]:
    contracts = load_json(path)["contracts"]
    return [
        {**contract, "origin": origin, "non_common_basis": "origin-corpus-minus-confirmed-common-250"}
        for contract in contracts
        if contract["name"] not in common_names
    ]


def source_contracts() -> dict[str, list[dict[str, Any]]]:
    common_names = {contract["name"] for contract in load_json(COMMON)["contracts"]}

    sources = {
        "joda-time": corpus_minus_common(JODA, "joda-time", common_names),
        "nodatime": corpus_minus_common(NODA, "nodatime", common_names),
        "python-dateutil": corpus_minus_common(DATEUTIL, "python-dateutil", common_names),
    }

    for origin, path in (("carbon", CARBON), ("date-fns", DATEFNS)):
        sources[origin] = [
            {**contract, "origin": origin, "non_common_basis": "origin-corpus-minus-confirmed-common-250"}
            for contract in load_json(path)["non_common_contracts"]
            if contract["name"] not in common_names
        ]
    return sources


def evaluate_contract(dtlib: Path, cwd: Path, contract: dict[str, Any]) -> dict[str, Any]:
    errored, actual = run_contract(dtlib, cwd, contract)
    replay_ok, reason = compare(actual, contract["expected"], errored)
    mutant = mutate_expected(contract["expected"], actual)
    mutant_ok, mutant_reason = compare(actual, mutant, errored)
    verified = replay_ok and not mutant_ok
    return {
        "name": contract["name"],
        "origin": contract["origin"],
        "capability": contract.get("capability"),
        "replay": contract.get("replay"),
        "status": "passed" if verified else "failed",
        "replay_passed": replay_ok,
        "mutant_rejected": not mutant_ok,
        "reason": reason,
        "mutant_reason": mutant_reason,
        "actual": actual,
        "expected": contract["expected"],
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row["status"] for row in results)
    by_origin: dict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        by_origin[row["origin"]][row["status"]] += 1
    total = len(results)
    return {
        "total": total,
        "passed": counts["passed"],
        "failed": counts["failed"],
        "pass_rate": round(counts["passed"] / total, 4) if total else 0,
        "by_origin": {
            origin: {
                "total": sum(counter.values()),
                "passed": counter["passed"],
                "failed": counter["failed"],
                "pass_rate": round(counter["passed"] / sum(counter.values()), 4) if sum(counter.values()) else 0,
            }
            for origin, counter in sorted(by_origin.items())
        },
    }


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Generated Date/Time Non-Common Replay",
        "",
        "## Iteration Summary",
        "",
        "| Iteration | Total | Passed | Failed | Pass rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for item in payload["iterations"]:
        summary = item["summary"]
        lines.append(
            f"| {item['iteration']} | {summary['total']} | {summary['passed']} | {summary['failed']} | {summary['pass_rate']:.2%} |"
        )

    lines.extend(
        [
            "",
            "## Final Iteration By OSS",
            "",
            "| OSS-related set | Total | Passed | Failed | Pass rate |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    final = payload["iterations"][-1]
    for origin, row in final["summary"]["by_origin"].items():
        lines.append(f"| {origin} | {row['total']} | {row['passed']} | {row['failed']} | {row['pass_rate']:.2%} |")

    lines.extend(
        [
            "",
            "## Final Iteration Failure Clusters",
            "",
            "| OSS-related set | Capability | Count |",
            "| --- | --- | ---: |",
        ]
    )
    for origin, clusters in final["failure_clusters"]["capability_by_origin"].items():
        for capability, count in clusters[:12]:
            lines.append(f"| {origin} | `{capability}` | {count} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-root", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--iterations", default="1,2,3,4,5,6,7,8")
    parser.add_argument("--label", default="gpt56sol_high_datetime_non_common_20260829")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sources = source_contracts()
    all_contracts = [contract for contracts in sources.values() for contract in contracts]
    source_counts = {origin: len(contracts) for origin, contracts in sorted(sources.items())}

    payload: dict[str, Any] = {
        "label": args.label,
        "source_counts": source_counts,
        "iterations": [],
    }
    for iteration in [int(item) for item in args.iterations.split(",") if item.strip()]:
        impl_dir = (args.snapshot_root / f"iter{iteration}").resolve()
        dtlib = impl_dir / "dtlib"
        if not dtlib.exists():
            raise SystemExit(f"missing executable {dtlib}")
        results = [evaluate_contract(dtlib, impl_dir, contract) for contract in all_contracts]
        failed = [row for row in results if row["status"] == "failed"]
        cap_by_origin: dict[str, Counter[str]] = defaultdict(Counter)
        reason_by_origin: dict[str, Counter[str]] = defaultdict(Counter)
        for row in failed:
            cap_by_origin[row["origin"]][str(row.get("capability") or "")] += 1
            reason_by_origin[row["origin"]][str(row.get("reason") or "")] += 1
        payload["iterations"].append(
            {
                "iteration": iteration,
                "implementation": str(impl_dir),
                "summary": summarize(results),
                "failure_clusters": {
                    "capability_by_origin": {
                        origin: counter.most_common()
                        for origin, counter in sorted(cap_by_origin.items())
                    },
                    "reason_by_origin": {
                        origin: counter.most_common(20)
                        for origin, counter in sorted(reason_by_origin.items())
                    },
                },
                "results": results,
            }
        )
        write_hashes(impl_dir, OUT_DIR / f"{args.label}_iter{iteration}_source_hashes.sha256")

    out_json = OUT_DIR / f"{args.label}.json"
    out_md = OUT_DIR / f"{args.label}.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown(out_md, payload)
    final_summary = payload["iterations"][-1]["summary"]
    print(json.dumps({"source_counts": source_counts, "final_iteration": final_summary}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
