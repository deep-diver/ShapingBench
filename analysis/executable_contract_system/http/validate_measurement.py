#!/usr/bin/env python3
"""Validate identity, evidence shape, and publication readiness of HTTP results."""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
RESULTS_PATH = Path(os.environ.get("SHAPINGBENCH_HTTP_RESULTS", HERE / "solhttp_measurement_results.jsonl"))
FINAL_SNAPSHOT = os.environ.get("SHAPINGBENCH_HTTP_FINAL_LABEL", "iter7_rerun_from_iter2")
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))


def main() -> int:
    contracts = list(map(json.loads, (HERE / "http_non_common_contract_ir.jsonl").read_text().splitlines()))
    results = list(map(json.loads, RESULTS_PATH.read_text().splitlines()))
    contract_ids = {row["scoring_id"] for row in contracts}
    if len(contract_ids) != 519 or len(contracts) != 519:
        raise AssertionError("HTTP corpus must preserve exactly 519 distinct scoring rows")
    by_snapshot: dict[str, list[dict]] = defaultdict(list)
    for row in results:
        by_snapshot[row["snapshot"]].append(row)
    for snapshot, rows in by_snapshot.items():
        ids = [row["scoring_id"] for row in rows]
        if len(ids) != 519 or set(ids) != contract_ids or len(set(ids)) != len(ids):
            raise AssertionError(f"{snapshot}: scoring identity mismatch")
        for row in rows:
            verdict = row["verdict"]
            if verdict == "PASS":
                if not row["actual_observations"] or not row["oracle_comparisons"]:
                    raise AssertionError(f"{snapshot}/{row['scoring_id']}: zero-observation PASS")
                if not all(item.get("matched") is True for item in row["oracle_comparisons"]):
                    raise AssertionError(f"{snapshot}/{row['scoring_id']}: contradictory PASS")
            elif verdict == "FAIL_SEMANTIC_MISMATCH":
                if not row["actual_observations"]:
                    raise AssertionError(f"{snapshot}/{row['scoring_id']}: execution-free semantic FAIL")
            elif verdict == "FAIL_CAPABILITY_ABSENCE":
                probe = row.get("capability_probe") or {}
                if probe.get("probe_observation", {}).get("present") is not False:
                    raise AssertionError(f"{snapshot}/{row['scoring_id']}: unproven capability FAIL")
                positive = probe.get("positive_control", {})
                if positive.get("recognized") is not True and positive.get("passed") is not True:
                    raise AssertionError(f"{snapshot}/{row['scoring_id']}: broken capability control")

    final = by_snapshot[FINAL_SNAPSHOT]
    counts = Counter(row["verdict"] for row in final)
    incomplete = counts["UNKNOWN_ADAPTER_GAP"] + counts["UNKNOWN_PROVENANCE"] + counts["UNKNOWN_INFRASTRUCTURE"] + counts["UNKNOWN_UNSTABLE"]
    report = {
        "identity_checks": "PASS",
        "evidence_shape_checks": "PASS",
        "final_snapshot_counts": dict(sorted(counts.items())),
        "publication_ready": incomplete == 0,
        "incomplete_contracts": incomplete,
        "rule": "Non-common score publication is blocked until every scoring row has executable behavioral or capability-absence evidence.",
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "validation_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if incomplete == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
