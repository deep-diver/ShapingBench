#!/usr/bin/env python3
"""Build the reproducibility report and manifest for executable contracts."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    report = json.loads((HERE / "execution_coverage_report.json").read_text())
    inventory = load_csv(HERE / "executable_contract_inventory.csv")
    summary = load_csv(HERE / "executable_contract_summary.csv")
    verdicts = Counter(row["verdict"] for row in inventory)
    mutants = Counter(row["mutant_control"] for row in inventory)
    if len(inventory) != report["contracts"] or report["validation_errors"]:
        raise SystemExit("validated inventory and coverage report disagree")
    if any(row["verdict"].startswith("UNKNOWN") for row in inventory):
        raise SystemExit("inventory still contains unresolved contracts")

    result_files = sorted({ROOT / row["result_file"] for row in inventory})
    scripts = sorted(path for path in HERE.rglob("*.py") if "__pycache__" not in path.parts)
    generated = [
        HERE / "execution_coverage_report.json",
        HERE / "execution_coverage_summary.csv",
        HERE / "execution_validation_errors.csv",
        HERE / "executable_contract_inventory.csv",
        HERE / "executable_contract_inventory.jsonl",
        HERE / "executable_contract_summary.csv",
    ]
    snapshots = sorted({row["target_snapshot"] for row in inventory})
    git_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository_root": str(ROOT),
        "repository_head": git_head,
        "scope": {
            "classification": "non-common scoring contracts",
            "domains": report["domains"],
            "scoring_rows": report["contracts"],
            "identity_rule": "The original scoring_id and source contract semantics are immutable.",
        },
        "execution_model": {
            "behavior_replay": report["behavior_execution"],
            "executable_capability_absence_test": report["capability_execution"],
            "unknown": report["unknown"],
            "behavior_replay_definition": "The target is invoked and all projected observable requirements are compared with the original oracle.",
            "capability_absence_definition": "Equivalent native interfaces are resolved and invoked with contract-shaped inputs, with a target-native positive control; it is used only when the target does not expose the required semantic primitive.",
            "prohibited_adapter_behavior": [
                "implementing the missing target algorithm",
                "synthesizing the expected result",
                "dropping required observations",
                "treating an absent source API name as capability absence",
            ],
        },
        "verdicts": dict(sorted(verdicts.items())),
        "mutant_controls": dict(sorted(mutants.items())),
        "target_snapshots": snapshots,
        "result_files": [{"path": rel(path), "sha256": sha256(path)} for path in result_files],
        "generated_files": [{"path": rel(path), "sha256": sha256(path)} for path in generated],
        "scripts": [{"path": rel(path), "sha256": sha256(path)} for path in scripts],
        "commands": [
            "python analysis/executable_contract_system/validate_all.py",
            "python analysis/executable_contract_system/build_inventory.py",
            "python analysis/executable_contract_system/build_system_report.py",
            "python -m pytest analysis/executable_contract_system/tests -q",
            "python analysis/executable_contract_system/run_domain.py --domain <domain> --snapshot <path> --output <path>",
            "python analysis/executable_contract_system/run_contract.py --domain <domain> --contract-id <id> --snapshot <path>",
        ],
        "runtime": {
            "python": sys.version,
            "platform": " ".join(os.uname()),
            "requirements": rel(HERE / "requirements-analysis.txt"),
        },
        "validation": {
            "identity_and_evidence_errors": report["validation_errors"],
            "unknown_contracts": report["unknown"],
            "all_rows_have_replay_command": all(bool(row["replay_command"]) for row in inventory),
            "all_rows_have_source_hash": all(bool(row["source_contract_hash"]) for row in inventory),
            "all_rows_have_snapshot": all(bool(row["target_snapshot"]) for row in inventory),
            "all_pass_rows_have_traceable_oracle_control": all(
                row["verdict"] != "PASS" or row["oracle_control_traceable"] == "True"
                for row in inventory
            ),
        },
        "limitations": [
            "This system measures preserved final agent snapshots; it does not regenerate agent implementations.",
            "Executable capability-absence tests establish that the preserved target lacks an equivalent exposed primitive; they are not full algorithm replays.",
            "Some target replays reuse validated historical execution evidence. Their source mutant is preserved, while a target-level mutant field may be absent.",
            "The current inventory covers non-common scoring contracts. Existing common-contract evaluators remain separate frozen benchmark artifacts.",
        ],
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Executable Contract System",
        "",
        "This analysis-side system makes every non-common scoring contract enter an executable path without changing its frozen identity, inputs, expected observations, or core/extended membership.",
        "",
        "## Coverage",
        "",
        f"- Domains: **{report['domains']}**",
        f"- Immutable scoring rows: **{report['contracts']:,}**",
        f"- Full behavior replays: **{report['behavior_execution']:,}**",
        f"- Executable capability-absence tests: **{report['capability_execution']:,}**",
        f"- UNKNOWN or unmapped rows: **{report['unknown']}**",
        f"- Identity/evidence validation errors: **{report['validation_errors']}**",
        "",
        "A semantic mismatch is a valid executed failure. A missing execution path is not. When the target does not expose the semantic primitive, the compiler emits a capability-absence program that checks equivalent native interfaces with contract-shaped calls and a target-native positive control.",
        "",
        "## Domain Results",
        "",
        "| Domain | Contracts | Behavior replay | Capability test | PASS | Semantic FAIL | Capability absence | UNKNOWN |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    by_domain = {row["domain"]: row for row in report["by_domain"]}
    for row in summary:
        coverage = by_domain[row["domain"]]
        lines.append(
            f"| {row['domain']} | {int(row['contracts']):,} | {int(row['behavior_replay']):,} | "
            f"{int(row['executable_capability_absence_test']):,} | {int(row['pass']):,} | "
            f"{int(row['semantic_fail']):,} | {int(row['capability_absence_fail']):,} | {coverage['unknown']} |"
        )
    lines += [
        "",
        "## Reproduction",
        "",
        "```bash",
        "python analysis/executable_contract_system/run_domain.py --domain url_iri --snapshot /path/to/snapshot --output /tmp/url-results",
        "python analysis/executable_contract_system/run_contract.py --domain url_iri --contract-id <scoring-id> --snapshot /path/to/snapshot",
        "python analysis/executable_contract_system/validate_all.py",
        "python analysis/executable_contract_system/build_inventory.py",
        "```",
        "",
        "The inventory provides the exact command for every row. Exit code `0` means PASS and `1` means an executed FAIL. Result JSON contains the verdict class and traceable evidence.",
        "",
        "## Files",
        "",
        "- `executable_contract_inventory.csv`: one row per immutable scoring contract",
        "- `executable_contract_inventory.jsonl`: the same inventory in lossless JSON Lines form",
        "- `execution_coverage_summary.csv`: per-domain coverage and verdict counts",
        "- `execution_validation_errors.csv`: must contain only its header for a valid build",
        "- `manifest.json`: hashes, snapshots, commands, assumptions, and limitations",
        "- `requirements-analysis.txt`: analysis runtime dependencies",
        "",
        "Frozen contracts and previous benchmark results are read-only inputs. All compiler, adapter, replay, and derived evidence changes live in this directory.",
    ]
    (HERE / "README.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({
        "contracts": report["contracts"],
        "behavior_replay": report["behavior_execution"],
        "capability_tests": report["capability_execution"],
        "unknown": report["unknown"],
        "validation_errors": report["validation_errors"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
