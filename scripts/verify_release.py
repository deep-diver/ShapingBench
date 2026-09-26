#!/usr/bin/env python3
"""Verify the immutable public-release inventory and referenced payloads."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SUPPORT = {1: 4138, 2: 1223, 3: 1618, 4: 2804, 5: 4754}


def main() -> int:
    with (ROOT / "benchmark/scoring_contracts.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    with (ROOT / "benchmark/reference_implementations.csv").open(newline="", encoding="utf-8") as handle:
        references = list(csv.DictReader(handle))
    ids = [row["canonical_contract_family_id"] for row in rows]
    support = Counter(int(row["exact_support_count"]) for row in rows)
    domains = Counter(row["domain"] for row in rows)
    errors = []
    if len(rows) != 14537:
        errors.append(f"scoring rows: {len(rows)} != 14537")
    if len(ids) != len(set(ids)):
        errors.append("duplicate scoring IDs")
    if dict(sorted(support.items())) != EXPECTED_SUPPORT:
        errors.append(f"support distribution: {dict(support)}")
    if len(domains) != 9:
        errors.append(f"domain count: {len(domains)} != 9")
    if len(references) != 45 or Counter(row["domain"] for row in references) != Counter({d: 5 for d in domains}):
        errors.append("reference inventory is not exactly five OSS implementations per domain")
    if any(row["support_fully_known"].lower() != "true" or int(row["unknown_target_count"]) for row in rows):
        errors.append("UNKNOWN OSS-support cells found")
    missing = sorted({row["source_artifact"] for row in rows if not (ROOT / row["source_artifact"]).is_file()})
    if missing:
        errors.append(f"missing source artifacts: {missing[:10]}")
    tasks = sorted((ROOT / "benchmark/tasks").glob("*.md"))
    if len(tasks) != 9:
        errors.append(f"public tasks: {len(tasks)} != 9")
    summary = {
        "status": "PASS" if not errors else "FAIL",
        "domains": len(domains),
        "reference_implementations": len(references),
        "scoring_contracts": len(rows),
        "shared_core_5_of_5": support[5],
        "variable_surface_1_to_4_of_5": sum(support[k] for k in range(1, 5)),
        "support_distribution": dict(sorted(support.items())),
        "public_tasks": len(tasks),
        "errors": errors,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
