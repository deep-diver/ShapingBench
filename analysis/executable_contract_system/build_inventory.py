#!/usr/bin/env python3
"""Build the canonical executable non-common scoring inventory."""

from __future__ import annotations

import csv
import hashlib
import json
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RESULTS = {
    "HTTP Client": HERE / "http/solhttp_measurement_results.jsonl",
    "JSON Schema": HERE / "jsonschema/strict_results.jsonl",
    "Date/time & timezone": HERE / "datetime/strict_results.jsonl",
    "URL/IRI": HERE / "url_iri/strict_results.jsonl",
    "HTML Sanitization": HERE / "direct_domains/html_sanitizer/strict_results.jsonl",
    "Markdown": HERE / "direct_domains/markdown/strict_results.jsonl",
    "YAML": HERE / "direct_domains/yaml/strict_results.jsonl",
    "JWT": HERE / "jwt/strict_results.jsonl",
    "Template Engine": HERE / "direct_domains/template/strict_results.jsonl",
    "Cron": HERE / "cron/strict_results.jsonl",
    "Rate Limiting": HERE / "rate_limiter/strict_results.jsonl",
    "Resilience Policy": HERE / "resilience/strict_results.jsonl",
}
DOMAIN_SLUG = {
    "HTTP Client": "http", "JSON Schema": "jsonschema", "Date/time & timezone": "datetime",
    "URL/IRI": "url_iri", "HTML Sanitization": "html_sanitizer", "Markdown": "markdown",
    "YAML": "yaml", "JWT": "jwt", "Template Engine": "template", "Cron": "cron",
    "Rate Limiting": "rate_limiter", "Resilience Policy": "resilience",
}


def stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def execution_kind(row: dict[str, Any]) -> str:
    evidence = row.get("evidence") or {}
    kind = str(evidence.get("kind") or row.get("projection_kind") or "unknown")
    if "capability" in kind or "native_probe" in kind:
        return "executable_capability_absence_test"
    return "behavior_replay"


def mutant_status(row: dict[str, Any]) -> str:
    evidence = row.get("evidence") or {}
    value = evidence.get("mutant_rejected")
    if value is True:
        return "REJECTED"
    if value is False:
        return "NOT_REJECTED"
    control = row.get("control_validation") or evidence.get("control_validation")
    if control == "PASS":
        return "REJECTED"
    return "NOT_RECORDED_FOR_TARGET_REPLAY"


def source_status(contract: dict[str, Any]) -> str:
    value = contract.get("pass")
    if value in {True, "passed", "pass", "pass1", "pass2"}:
        return "SOURCE_REPLAY_VALIDATED"
    latest = contract.get("latest_replay") or {}
    if latest.get("replay_passed") is True:
        return "SOURCE_REPLAY_VALIDATED"
    return "SOURCE_VALIDATION_NOT_NORMALIZED"


def source_contract(row: dict[str, Any], http_ir: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if isinstance(row.get("source_contract"), dict):
        return row["source_contract"]
    return http_ir.get(row.get("scoring_id"), {})


def main() -> int:
    http_ir = {
        row["scoring_id"]: row
        for row in map(json.loads, (HERE / "http/http_non_common_contract_ir.jsonl").read_text().splitlines())
    }
    inventory = []
    for domain, path in RESULTS.items():
        for row in map(json.loads, path.read_text().splitlines()):
            contract = source_contract(row, http_ir)
            evidence = row.get("evidence") or {}
            probe = evidence.get("probe") or row.get("capability_probe") or {}
            source_hash = row.get("contract_hash") or hashlib.sha256(stable(contract).encode()).hexdigest()
            kind = execution_kind(row)
            required = evidence.get("required_observation_count")
            executed = evidence.get("executed_observation_count")
            if required is None and kind == "behavior_replay":
                required = len(row.get("actual_observations") or []) or None
            if executed is None and kind == "behavior_replay":
                executed = len(row.get("actual_observations") or []) or required
            scoring_id = row.get("scoring_id") or row.get("contract_id")
            snapshot = row.get("target_snapshot") or row.get("snapshot_path")
            replay_command = shlex.join([
                "python", str(HERE / "run_contract.py"), "--domain", DOMAIN_SLUG[domain],
                "--contract-id", str(scoring_id), "--snapshot", str(snapshot),
            ])
            inventory.append({
                "domain": domain,
                "scoring_id": scoring_id,
                "origin": row.get("origin") or contract.get("origin") or contract.get("project"),
                "source_version": contract.get("version") or contract.get("origin_release"),
                "source_operation": contract.get("source_op") or contract.get("op") or contract.get("canonical_op"),
                "capability": contract.get("capability") or row.get("capability"),
                "source_contract_hash": source_hash,
                "source_contract_embedded": bool(contract),
                "source_validation_status": source_status(contract),
                "source_mutant_defined": contract.get("mutant") is not None,
                "execution_class": kind,
                "evidence_kind": evidence.get("kind") or row.get("projection_kind"),
                "verdict": row.get("verdict"),
                "required_observation_count": required,
                "executed_observation_count": executed,
                "mutant_control": mutant_status(row),
                "oracle_control_traceable": (
                    mutant_status(row) == "REJECTED"
                    or row.get("control_validation") == "PASS"
                    or (evidence.get("positive_control") or {}).get("passed") is True
                    or evidence.get("kind") == "reused_historical_behavior_replay"
                ),
                "target": row.get("target") or "solhttp",
                "target_version": row.get("target_version"),
                "target_snapshot": snapshot,
                "adapter_revision": row.get("adapter_revision"),
                "required_primitive": probe.get("required_semantic_primitive") or evidence.get("required_operation") or evidence.get("required_capability"),
                "result_file": str(path.relative_to(ROOT)),
                "replay_command": replay_command,
            })

    fields = list(inventory[0])
    with (HERE / "executable_contract_inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(inventory)
    (HERE / "executable_contract_inventory.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in inventory)
    )

    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in inventory:
        grouped[row["domain"]]["contracts"] += 1
        grouped[row["domain"]][row["execution_class"]] += 1
        grouped[row["domain"]][row["verdict"]] += 1
        grouped[row["domain"]]["target_mutant_recorded"] += row["mutant_control"] != "NOT_RECORDED_FOR_TARGET_REPLAY"
        grouped[row["domain"]]["oracle_control_traceable"] += bool(row["oracle_control_traceable"])
    summary = []
    for domain, counts in grouped.items():
        summary.append({
            "domain": domain,
            "contracts": counts["contracts"],
            "behavior_replay": counts["behavior_replay"],
            "executable_capability_absence_test": counts["executable_capability_absence_test"],
            "pass": counts["PASS"],
            "semantic_fail": counts["FAIL_SEMANTIC_MISMATCH"],
            "capability_absence_fail": counts["FAIL_CAPABILITY_ABSENCE"],
            "unknown": counts["UNKNOWN_ADAPTER_GAP"] + counts["UNKNOWN_INFRASTRUCTURE"] + counts["UNKNOWN_PROVENANCE"] + counts["UNKNOWN_UNSTABLE"],
            "target_mutant_recorded": counts["target_mutant_recorded"],
            "oracle_control_traceable": counts["oracle_control_traceable"],
        })
    with (HERE / "executable_contract_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    print(json.dumps({
        "domains": len(summary),
        "contracts": len(inventory),
        "behavior_replay": sum(row["behavior_replay"] for row in summary),
        "capability_tests": sum(row["executable_capability_absence_test"] for row in summary),
        "unknown": sum(row["unknown"] for row in summary),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
