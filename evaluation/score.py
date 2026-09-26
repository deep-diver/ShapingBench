#!/usr/bin/env python3
"""Aggregate one ShapingBench replay by empirical OSS recurrence."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "benchmark/scoring_contracts.csv"

DOMAIN_NAMES = {
    "http": "HTTP Client",
    "datetime": "Date, Time, and Time Zones",
    "url_iri": "URL and IRI Processing",
    "html_sanitizer": "HTML Sanitization",
    "markdown": "Markdown Parsing and Rendering",
    "yaml": "YAML Parsing and Emission",
    "jwt": "JWT Signing and Verification",
    "cron": "Cron and Schedule Expressions",
    "resilience": "Retry, Backoff, and Resilience Policies",
}


def source_oss(value: str) -> str:
    text = value.lower().replace("_", "-")
    aliases = [
        ("auth0-java-jwt", "java-jwt"), ("java-jwt", "java-jwt"),
        ("node-jsonwebtoken", "node-jsonwebtoken"), ("pyjwt", "pyjwt"),
        ("golang-jwt", "golang-jwt"), ("nimbus", "nimbus-jose-jwt"),
        ("resilience4j", "resilience4j"), ("exponential-backoff", "exponential-backoff"),
        ("async-retry", "async-retry"), ("failsafe", "failsafe"), ("backoff", "backoff"),
        ("commonmark", "commonmark.js"),
        ("dragonmantank", "cron-expression"), ("cron-expression", "cron-expression"),
    ]
    for needle, replacement in aliases:
        if needle in text:
            return replacement
    for prefix in ("rank1-", "rank2-", "rank3-", "rank4-", "rank5-"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return text


def record_identity(record: dict[str, Any]) -> tuple[str, list[str], str]:
    source = record.get("source_contract") if isinstance(record.get("source_contract"), dict) else {}
    origin = source_oss(str(
        record.get("origin") or record.get("oss") or record.get("bucket")
        or record.get("originBucket") or record.get("source_origin")
        or source.get("origin") or source.get("project") or ""
    ))
    candidates: list[str] = []
    for mapping in (source, record):
        for key in ("id", "cross_id", "source_key", "source_id", "source_name", "name", "contract_id", "scoring_id"):
            value = mapping.get(key)
            if isinstance(value, str) and value and value not in candidates:
                candidates.append(value)
    version = str(
        record.get("source_version") or record.get("version")
        or source.get("source_version") or source.get("version") or ""
    )
    return origin, candidates, version


def record_pass(record: dict[str, Any]) -> int:
    verdict = str(record.get("verdict", "")).upper()
    if verdict:
        return int(verdict == "PASS")
    status = str(record.get("status", "")).lower()
    if status:
        return int(status in {"pass", "passed", "ok", "survived"} and record.get("mutant_rejected") is not False)
    if isinstance(record.get("replay_passed"), bool):
        return int(record["replay_passed"] and record.get("mutant_rejected", True))
    raise ValueError(f"record lacks a verdict: {sorted(record)}")


def parse_common_counts(domain: str, path: Path) -> tuple[int, int]:
    value = json.loads(path.read_text(encoding="utf-8"))
    summary = value.get("summary", value)
    fields = {
        "http": ("total_common_114", "solhttp_survived"),
        "datetime": ("contract_total", "passed"),
        "url_iri": ("common_contract_total", "passed"),
        "html_sanitizer": ("input_contracts", "survivors"),
        "markdown": ("common_contract_total", "passed"),
        "yaml": ("common_contract_total", "passed"),
        "jwt": ("common_contract_total", "passed"),
        "cron": ("total", "passed"),
        "resilience": ("common_contracts", "passed"),
    }
    total_key, pass_key = fields[domain]
    return int(summary[total_key]), int(summary[pass_key])


def score(domain: str, common_json: Path, variable_jsonl: Path, output: Path) -> dict[str, Any]:
    domain_name = DOMAIN_NAMES[domain]
    with INVENTORY.open(newline="", encoding="utf-8") as handle:
        inventory = [row for row in csv.DictReader(handle) if row["domain"] == domain_name]
    construction_core = [row for row in inventory if row["construction_classification"] == "core"]
    construction_variable = [row for row in inventory if row["construction_classification"] == "extended"]

    exact: dict[tuple[str, str, str], str] = {}
    loose: dict[tuple[str, str], list[str]] = defaultdict(list)
    by_id = {row["canonical_contract_family_id"]: row for row in construction_variable}
    for row in construction_variable:
        cid = row["canonical_contract_family_id"]
        origin = source_oss(row["source_oss"])
        native = row["repository_native_id"]
        exact[(origin, native, row["source_version"])] = cid
        loose[(origin, native)].append(cid)

    records = [json.loads(line) for line in variable_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    seen: set[str] = set()
    mapped: list[dict[str, Any]] = []
    for position, record in enumerate(records):
        origin, candidates, version = record_identity(record)
        match = None
        for candidate in candidates:
            match = exact.get((origin, candidate, version))
            if match:
                break
            possible = loose.get((origin, candidate), [])
            if len(possible) == 1:
                match = possible[0]
                break
            version_matches = [cid for cid in possible if by_id[cid]["source_version"] == version]
            if len(version_matches) == 1:
                match = version_matches[0]
                break
        if not match:
            raise AssertionError(
                f"identity join failed at row {position}: origin={origin!r} version={version!r} candidates={candidates!r}"
            )
        if match in seen:
            raise AssertionError(f"duplicate mapped contract: {match}")
        seen.add(match)
        row = by_id[match]
        mapped.append({
            "canonical_contract_family_id": match,
            "support_count": int(row["exact_support_count"]),
            "passed": record_pass(record),
            "verdict": record.get("verdict") or record.get("status"),
            "source_result_position": position,
        })

    if len(mapped) != len(construction_variable):
        raise AssertionError(f"mapped {len(mapped)} variable contracts; expected {len(construction_variable)}")
    common_total, common_passed = parse_common_counts(domain, common_json)
    if common_total != len(construction_core):
        raise AssertionError(f"common total {common_total}; expected {len(construction_core)}")

    totals = Counter(int(row["exact_support_count"]) for row in inventory)
    passes = Counter({5: common_passed})
    for row in mapped:
        passes[row["support_count"]] += row["passed"]
    score_rows = []
    for support in range(1, 6):
        total = totals[support]
        passed = passes[support]
        score_rows.append({
            "support": f"{support}/5",
            "passed": passed,
            "failed": total - passed,
            "total": total,
            "coverage": passed / total,
            "partition": "Shared Core" if support == 5 else "Variable Surface",
        })
    shared = score_rows[4]
    variable_total = sum(row["total"] for row in score_rows[:4])
    variable_passed = sum(row["passed"] for row in score_rows[:4])
    full_total = variable_total + shared["total"]
    full_passed = variable_passed + shared["passed"]
    summary = {
        "domain_key": domain,
        "domain": domain_name,
        "shared_core": {"passed": shared["passed"], "total": shared["total"], "coverage": shared["coverage"]},
        "variable_surface": {"passed": variable_passed, "total": variable_total, "coverage": variable_passed / variable_total},
        "full_surface": {"passed": full_passed, "total": full_total, "coverage": full_passed / full_total},
        "support_strata": score_rows,
        "construction_core_component": {"passed": common_passed, "total": common_total},
        "mapped_variable_contracts": len(mapped),
        "unknown": 0,
    }

    output.mkdir(parents=True, exist_ok=True)
    with (output / "support_scores.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(score_rows[0]))
        writer.writeheader()
        writer.writerows(score_rows)
    with gzip.open(output / "mapped_variable_results.jsonl.gz", "wt", encoding="utf-8") as handle:
        for row in mapped:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, choices=sorted(DOMAIN_NAMES))
    parser.add_argument("--common-json", required=True, type=Path)
    parser.add_argument("--variable-jsonl", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = score(args.domain, args.common_json, args.variable_jsonl, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
