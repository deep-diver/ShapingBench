#!/usr/bin/env python3
"""Cross-replay Markdown contracts across mature parser/renderers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "markdown" / "common"
SOURCES = {
    "markdown-it": ROOT / "contracts" / "markdown" / "markdown-it" / "latest_replay_mutant_verified.json",
    "pulldown-cmark": ROOT / "contracts" / "markdown" / "pulldown-cmark" / "latest_replay_mutant_verified.json",
    "goldmark": ROOT / "contracts" / "markdown" / "goldmark" / "latest_replay_mutant_verified.json",
}
RUNNERS = {
    "markdown-it": ["node", str(ROOT / "tools" / "replay" / "markdown_it_latest_runner" / "replay_latest.mjs")],
    "pulldown-cmark": [
        shutil.which("cargo") or "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(ROOT / "tools" / "replay" / "pulldown_cmark_latest_runner" / "Cargo.toml"),
        "--",
    ],
    "goldmark": [
        shutil.which("go") or "go",
        "run",
        ".",
    ],
    "commonmark.js": [
        "node",
        str(ROOT / "tools" / "replay" / "markdown_hidden_node_runner" / "replay_hidden.mjs"),
        "commonmark",
    ],
    "marked": [
        "node",
        str(ROOT / "tools" / "replay" / "markdown_hidden_node_runner" / "replay_hidden.mjs"),
        "marked",
    ],
}
RUNNER_CWDS = {
    "markdown-it": ROOT,
    "pulldown-cmark": ROOT,
    "goldmark": ROOT / "tools" / "replay" / "goldmark_latest_runner",
    "commonmark.js": ROOT / "tools" / "replay" / "markdown_hidden_node_runner",
    "marked": ROOT / "tools" / "replay" / "markdown_hidden_node_runner",
}
HIDDEN_TARGETS = ["commonmark.js", "marked"]


def load_survivors(name: str) -> list[dict[str, Any]]:
    data = json.loads(SOURCES[name].read_text(encoding="utf-8"))
    return data["survivors"]


def env_for(target: str) -> dict[str, str]:
    env = os.environ.copy()
    return env


def run_target(target: str, contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = {
        "domain": "Markdown Parser/Renderer",
        "project": f"cross-replay:{target}",
        "contracts": contracts,
    }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as fp:
        json.dump(payload, fp, ensure_ascii=True)
        path = fp.name
    try:
        cmd = RUNNERS[target] + [path]
        output = subprocess.check_output(
            cmd,
            cwd=RUNNER_CWDS[target],
            text=True,
            stderr=subprocess.STDOUT,
            env=env_for(target),
        )
        return json.loads(output)["results"]
    finally:
        Path(path).unlink(missing_ok=True)


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


def contract_identity(contract: dict[str, Any]) -> str:
    return json.dumps(
        [
            contract.get("op"),
            contract.get("params", {}).get("markdown"),
            contract.get("expected", {}).get("html"),
        ],
        ensure_ascii=True,
        sort_keys=True,
    )


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    status = Counter(row["status"] for row in results)
    by_capability = defaultdict(Counter)
    errors = Counter()
    for row in results:
        by_capability[row["capability"]][row["status"]] += 1
        actual = row.get("actual", {})
        if "error" in actual:
            errors[str(actual.get("error"))] += 1
    return {
        "passed": status.get("passed", 0),
        "failed": status.get("failed", 0),
        "runner_errors": dict(errors),
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_capability.items())},
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sources = {name: load_survivors(name) for name in SOURCES}
    origin_reports = {}
    cross_details = {}
    common_candidates = []
    for origin, contracts in sources.items():
        targets = [name for name in SOURCES if name != origin]
        per_target_results = {target: run_target(target, contracts) for target in targets}
        cross_details[origin] = per_target_results
        by_name = {
            target: {row["name"]: row for row in rows}
            for target, rows in per_target_results.items()
        }
        passed = [
            contract for contract in contracts
            if all(by_name[target][contract["name"]]["status"] == "passed" for target in targets)
        ]
        common_candidates.extend({**contract, "common_origin": origin} for contract in passed)
        origin_reports[origin] = {
            "input_survivors": len(contracts),
            "targets": targets,
            "cross_replay_passed_all_targets": len(passed),
            "cross_replay_failed_any_target": len(contracts) - len(passed),
            "per_target": {
                target: summarize_results(per_target_results[target])
                for target in targets
            },
            "passed_contract_names": [contract["name"] for contract in passed],
        }
    unique = {}
    duplicate_identities = 0
    for contract in common_candidates:
        key = contract_identity(contract)
        if key in unique:
            duplicate_identities += 1
            continue
        unique[key] = contract
    common = sorted(unique.values(), key=lambda row: (row["common_origin"], row["name"]))
    by_cap = Counter(row["capability"] for row in common)
    hidden_results = {target: run_target(target, common) for target in HIDDEN_TARGETS}
    hidden_by_name = {target: {row["name"]: row for row in rows} for target, rows in hidden_results.items()}
    final_common = [
        contract for contract in common
        if all(hidden_by_name[target][contract["name"]]["status"] == "passed" for target in HIDDEN_TARGETS)
    ]
    final_by_cap = Counter(row["capability"] for row in final_common)
    out = {
        "domain": "Markdown Parser/Renderer",
        "definition": "Rank 1/2/3 common candidates are latest-surviving origin contracts that replay and kill mutants on the other two Rank 1/2/3 implementations.",
        "rank_order": ["markdown-it", "pulldown-cmark", "goldmark"],
        "origin_reports": origin_reports,
        "common_candidate_total_before_identity_dedupe": len(common_candidates),
        "duplicate_identities_removed": duplicate_identities,
        "common_candidates": len(common),
        "by_capability": dict(sorted(by_cap.items())),
        "hidden_targets": HIDDEN_TARGETS,
        "hidden_filter_reports": {
            target: summarize_results(hidden_results[target])
            for target in HIDDEN_TARGETS
        },
        "final_common": len(final_common),
        "final_by_capability": dict(sorted(final_by_cap.items())),
        "contracts": common,
        "final_contracts": final_common,
    }
    (OUT_DIR / "rank1_2_3_cross_replay_common_candidates.json").write_text(
        json.dumps(out, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT_DIR / "rank1_2_3_cross_replay_details.json").write_text(
        json.dumps(cross_details, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT_DIR / "hidden_filter_details.json").write_text(
        json.dumps(hidden_results, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(common, OUT_DIR / "rank1_2_3_cross_replay_common_candidates.rpl")
    (OUT_DIR / "final_hidden_filtered_common.json").write_text(
        json.dumps({**out, "contracts": final_common}, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(final_common, OUT_DIR / "final_hidden_filtered_common.rpl")
    lines = [
        "# Markdown Rank 1/2/3 Cross-Replay Common Candidates",
        "",
        "| Origin | Input latest survivors | Target A | Target A passed | Target B | Target B passed | Passed both |",
        "| --- | ---: | --- | ---: | --- | ---: | ---: |",
    ]
    for origin, report in origin_reports.items():
        a, b = report["targets"]
        lines.append(
            f"| `{origin}` | {report['input_survivors']} | `{a}` | {report['per_target'][a]['passed']} | "
            f"`{b}` | {report['per_target'][b]['passed']} | {report['cross_replay_passed_all_targets']} |"
        )
    lines.extend([
        "",
        f"Common candidates before identity dedupe: {len(common_candidates)}",
        f"Duplicate identities removed: {duplicate_identities}",
        f"Common candidates after identity dedupe: {len(common)}",
        "",
        "## Hidden Filter",
        "",
        "| Hidden target | Input candidates | Passed | Failed | Runner errors |",
        "| --- | ---: | ---: | ---: | ---: |",
    ])
    for target in HIDDEN_TARGETS:
        report = summarize_results(hidden_results[target])
        lines.append(
            f"| `{target}` | {len(common)} | {report['passed']} | {report['failed']} | {sum(report['runner_errors'].values())} |"
        )
    lines.extend([
        "",
        f"Final common after hidden filter: {len(final_common)}",
        "",
        "## By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ])
    for cap, count in sorted(by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Final By Capability", "", "| Capability | Count |", "| --- | ---: |"])
    for cap, count in sorted(final_by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "rank1_2_3_cross_replay_common_candidates.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    final_lines = [
        "# Markdown Final Hidden-Filtered Common",
        "",
        "| Stage | Count |",
        "| --- | ---: |",
        f"| Rank 1/2/3 candidates before identity dedupe | {len(common_candidates)} |",
        f"| Duplicate identities removed | {duplicate_identities} |",
        f"| Rank 1/2/3 candidates after identity dedupe | {len(common)} |",
        f"| Passed Rank 4 `commonmark.js` | {summarize_results(hidden_results['commonmark.js'])['passed']} |",
        f"| Passed Rank 5 `marked` | {summarize_results(hidden_results['marked'])['passed']} |",
        f"| Final common after both hidden filters | {len(final_common)} |",
        "",
        "## Final By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(final_by_cap.items()):
        final_lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "final_hidden_filtered_common.md").write_text("\n".join(final_lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "origin_reports": {
            origin: {
                "input_survivors": report["input_survivors"],
                "cross_replay_passed_all_targets": report["cross_replay_passed_all_targets"],
                "per_target_passed": {target: report["per_target"][target]["passed"] for target in report["targets"]},
                "runner_errors": {target: report["per_target"][target]["runner_errors"] for target in report["targets"]},
            }
            for origin, report in origin_reports.items()
        },
        "common_candidate_total_before_identity_dedupe": len(common_candidates),
        "duplicate_identities_removed": duplicate_identities,
        "common_candidates": len(common),
        "hidden_filter": {
            target: {
                "passed": summarize_results(hidden_results[target])["passed"],
                "failed": summarize_results(hidden_results[target])["failed"],
                "runner_errors": summarize_results(hidden_results[target])["runner_errors"],
            }
            for target in HIDDEN_TARGETS
        },
        "final_common": len(final_common),
        "by_capability": dict(sorted(by_cap.items())),
        "final_by_capability": dict(sorted(final_by_cap.items())),
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
