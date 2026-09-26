#!/usr/bin/env python3
"""Validate identity, execution evidence, and verdict completeness for all domains."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

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

EXPECTED = {
    "HTTP Client": 519,
    "JSON Schema": 15533,
    "Date/time & timezone": 404,
    "URL/IRI": 1927,
    "HTML Sanitization": 1472,
    "Markdown": 1282,
    "YAML": 2548,
    "JWT": 1273,
    "Template Engine": 1187,
    "Cron": 1383,
    "Rate Limiting": 776,
    "Resilience Policy": 441,
}

KNOWN = {"PASS", "FAIL_SEMANTIC_MISMATCH", "FAIL_CAPABILITY_ABSENCE"}


def load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def evidence_kind(row: dict[str, Any]) -> str:
    evidence = row.get("evidence") or {}
    return str(evidence.get("kind") or row.get("projection_kind") or row.get("execution_kind") or "unknown")


def validate_row(domain: str, row: dict[str, Any]) -> list[str]:
    errors = []
    if not row.get("scoring_id") and not row.get("contract_id"):
        errors.append("missing identity")
    verdict = row.get("verdict")
    if hasattr(verdict, "value"):
        verdict = verdict.value
    if verdict not in KNOWN:
        errors.append(f"unresolved verdict {verdict!r}")
    kind = evidence_kind(row)
    evidence = row.get("evidence") or {}
    contract = row.get("source_contract") or {}
    if kind == "unknown":
        errors.append("missing execution kind")
    if domain != "HTTP Client" and not contract:
        errors.append("missing full source contract")
    if "capability" in kind or "native_probe" in kind:
        probe = evidence.get("probe") or row.get("capability_probe") or evidence
        attempts = (probe.get("attempts") or probe.get("target_native_attempts")
                    or probe.get("target_native_invocations") or [])
        control = probe.get("positive_control") or evidence.get("positive_control") or {}
        control_ok = control.get("passed")
        if control_ok is None and isinstance(control, dict):
            control_ok = control.get("recognized")
        if control_ok is None and isinstance(control, dict):
            policy = control.get("policy") or {}
            limiter = control.get("limiter") or {}
            control_ok = policy.get("ok") and limiter.get("ok")
        if not attempts:
            errors.append("capability result has no target-native attempts")
        if not control_ok:
            errors.append("capability result has no passing positive control")
    else:
        if ("actual" not in evidence and "actual_observation" not in evidence
                and not row.get("actual_observations")):
            errors.append("behavior result has no actual observation")
        if verdict == "PASS" and evidence.get("mutant_rejected") is False:
            errors.append("behavior PASS has a non-discriminating target mutant")
        control = evidence.get("positive_control") or {}
        has_control = (
            evidence.get("mutant_rejected") is True
            or row.get("control_validation") == "PASS"
            or control.get("passed") is True
            or evidence.get("kind") == "reused_historical_behavior_replay"
        )
        if verdict == "PASS" and not has_control:
            errors.append("behavior PASS has no traceable oracle control")
    return errors


def main() -> int:
    summary_rows = []
    all_errors = []
    all_ids = set()
    for domain, path in RESULTS.items():
        rows = load(path)
        counts = Counter()
        kinds = Counter()
        local_ids = set()
        for row in rows:
            verdict = row.get("verdict")
            if hasattr(verdict, "value"):
                verdict = verdict.value
            counts[str(verdict)] += 1
            kinds[evidence_kind(row)] += 1
            row_id = row.get("scoring_id") or row.get("contract_id")
            if row_id in local_ids:
                all_errors.append({"domain": domain, "scoring_id": row_id, "error": "duplicate identity"})
            local_ids.add(row_id)
            for error in validate_row(domain, row):
                all_errors.append({"domain": domain, "scoring_id": row_id, "error": error})
        if len(rows) != EXPECTED[domain]:
            all_errors.append({"domain": domain, "scoring_id": "", "error": f"expected {EXPECTED[domain]}, got {len(rows)}"})
        summary_rows.append({
            "domain": domain,
            "contracts": len(rows),
            "pass": counts["PASS"],
            "semantic_fail": counts["FAIL_SEMANTIC_MISMATCH"],
            "capability_absence_fail": counts["FAIL_CAPABILITY_ABSENCE"],
            "unknown": sum(value for key, value in counts.items() if key not in KNOWN),
            "behavior_execution": sum(value for key, value in kinds.items() if "capability" not in key and "native_probe" not in key),
            "capability_execution": sum(value for key, value in kinds.items() if "capability" in key or "native_probe" in key),
            "result_file": str(path.relative_to(ROOT)),
        })
        all_ids.update((domain, row_id) for row_id in local_ids)

    with (HERE / "execution_coverage_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)
    with (HERE / "execution_validation_errors.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "scoring_id", "error"])
        writer.writeheader()
        writer.writerows(all_errors)
    report = {
        "domains": len(summary_rows),
        "contracts": sum(row["contracts"] for row in summary_rows),
        "behavior_execution": sum(row["behavior_execution"] for row in summary_rows),
        "capability_execution": sum(row["capability_execution"] for row in summary_rows),
        "unknown": sum(row["unknown"] for row in summary_rows),
        "validation_errors": len(all_errors),
        "by_domain": summary_rows,
    }
    (HERE / "execution_coverage_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if all_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
