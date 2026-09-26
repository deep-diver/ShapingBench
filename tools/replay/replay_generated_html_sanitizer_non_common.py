#!/usr/bin/env python3
"""Evaluate generated solsanitize against per-OSS HTML Sanitizer non-common contracts."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
COMMON_MATRIX = ROOT / "contracts" / "html_sanitizer" / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "generated_non_common"
ORIGIN_FILES = {
    "dompurify": ROOT / "contracts" / "html_sanitizer" / "dompurify" / "latest_replay_mutant_verified.json",
    "java-html-sanitizer": ROOT / "contracts" / "html_sanitizer" / "java-html-sanitizer" / "latest_replay_mutant_verified.json",
    "jsoup": ROOT / "contracts" / "html_sanitizer" / "jsoup" / "latest_replay_mutant_verified.json",
    "bleach": ROOT / "contracts" / "html_sanitizer" / "bleach" / "non_common_latest_replay_mutant_verified.json",
    "sanitize-html": ROOT / "contracts" / "html_sanitizer" / "sanitize-html" / "non_common_latest_replay_mutant_verified.json",
}
COMMON_ORIGIN = {
    "dompurify": "dompurify",
    "java-html-sanitizer": "owasp",
    "jsoup": "jsoup",
}


def load_common_evaluator() -> Any:
    path = ROOT / "tools" / "replay" / "replay_generated_html_sanitizer_common.py"
    spec = importlib.util.spec_from_file_location("html_sanitizer_common_eval", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load common evaluator from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMMON_EVAL = load_common_evaluator()


def contract_id(contract: dict[str, Any]) -> tuple[str, str]:
    return (str(contract.get("origin") or ""), str(contract.get("name") or ""))


def origin_contract_id(origin: str, contract: dict[str, Any]) -> tuple[str, str]:
    return (COMMON_ORIGIN.get(origin, origin), str(contract.get("name") or ""))


def load_origin_residuals(matrix: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    common_ids = {contract_id(contract) for contract in matrix["final_common_contracts"]}
    buckets: dict[str, list[dict[str, Any]]] = {}
    for origin, path in ORIGIN_FILES.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        source_rows = data.get("non_common") or data.get("survivors") or data.get("contracts") or []
        rows = []
        for contract in source_rows:
            enriched = dict(contract)
            enriched["origin"] = origin
            if origin_contract_id(origin, enriched) not in common_ids:
                rows.append(enriched)
        buckets[origin] = rows
    return buckets


def load_hidden_residuals(matrix: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    buckets = {"bleach": [], "sanitize-html": []}
    for row in matrix.get("hidden", {}).get("failed", []):
        contract = row.get("contract")
        if not isinstance(contract, dict):
            continue
        targets = row.get("targets") or {}
        for target in buckets:
            result = targets.get(target) or {}
            if not result.get("replay_passed") or not result.get("mutant_rejected"):
                enriched = dict(contract)
                enriched["non_common_reason"] = f"failed hidden filter on {target}"
                buckets[target].append(enriched)
    return buckets


def evaluate_contract(api: Any, contract: dict[str, Any]) -> dict[str, Any]:
    row = {
        "name": contract.get("name"),
        "origin": contract.get("origin"),
        "capability": contract.get("capability"),
        "op": contract.get("op"),
    }
    try:
        replay = evaluate_one(api, contract, mutant=False)
        mutant = evaluate_one(api, contract, mutant=True) if replay["passed"] else {"passed": False, "actual": {}}
        row["replay_passed"] = replay["passed"]
        row["mutant_rejected"] = replay["passed"] and not mutant["passed"]
        row["actual"] = replay["actual"]
    except Exception as exc:
        row["replay_passed"] = False
        row["mutant_rejected"] = False
        row["actual"] = {"error": exc.__class__.__name__, "message": str(exc)}
    return row


def evaluate_one(api: Any, contract: dict[str, Any], mutant: bool = False) -> dict[str, Any]:
    op = contract["op"]
    params = contract.get("params", {})
    expected = contract["mutant" if mutant else "expected"]
    if op == "strip_banned":
        clean = COMMON_EVAL.call_sanitize(api, params.get("text") or "")
        actual = {"text": COMMON_EVAL.text_content(clean)}
        return {"passed": actual["text"] == expected.get("text"), "actual": actual}
    if op == "decode_html":
        html = params.get("html") or ""
        if params.get("in_attribute"):
            dirty = f'<span title="{COMMON_EVAL.attr_escape(html)}">x</span>'
            clean = COMMON_EVAL.call_sanitize(api, dirty, config={"ALLOWED_TAGS": ["span"], "ALLOWED_ATTR": ["title"]})
            actual = {"text": COMMON_EVAL.first_attr(clean, "title")}
        else:
            clean = COMMON_EVAL.call_sanitize(api, html)
            actual = {"text": COMMON_EVAL.text_content(clean)}
        return {"passed": actual["text"] == expected.get("text"), "actual": actual}
    if op == "antisamy_contains":
        clean = COMMON_EVAL.call_sanitize(
            api,
            params.get("html") or "",
            policy={"kind": "owasp_antisamy"},
        )
        actual = {"contains": (params.get("needle") or "") in clean}
        return {"passed": actual["contains"] == expected.get("contains"), "actual": actual}
    return COMMON_EVAL.evaluate_one(api, contract, mutant=mutant)


def summarize_bucket(results: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [row for row in results if row["replay_passed"] and row["mutant_rejected"]]
    replay_passed = sum(1 for row in results if row["replay_passed"])
    failed = [row for row in results if not row["replay_passed"]]
    return {
        "input_contracts": len(results),
        "replay_passed": replay_passed,
        "replay_failed": len(results) - replay_passed,
        "mutant_killed": len(passed),
        "survivors": len(passed),
        "by_capability": dict(sorted(Counter(row["capability"] for row in passed).items())),
        "by_op": dict(sorted(Counter(row["op"] for row in passed).items())),
        "failed_by_capability": dict(sorted(Counter(row["capability"] for row in failed).items())),
        "failed_by_op": dict(sorted(Counter(row["op"] for row in failed).items())),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()

    impl = Path(args.implementation).resolve()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    src_dir = impl / "src"
    if src_dir.exists():
        sys.path.insert(0, str(src_dir))
    sys.path.insert(0, str(impl))
    COMMON_EVAL.install_if_needed(impl)
    api = importlib.import_module("solsanitize")

    matrix = json.loads(COMMON_MATRIX.read_text(encoding="utf-8"))
    buckets = load_origin_residuals(matrix)

    bucket_summaries: dict[str, Any] = {}
    for name, contracts in buckets.items():
        results = [evaluate_contract(api, contract) for contract in contracts]
        bucket_summaries[name] = summarize_bucket(results)

    totals = {
        "input_contracts": sum(bucket["input_contracts"] for bucket in bucket_summaries.values()),
        "replay_passed": sum(bucket["replay_passed"] for bucket in bucket_summaries.values()),
        "replay_failed": sum(bucket["replay_failed"] for bucket in bucket_summaries.values()),
        "mutant_killed": sum(bucket["mutant_killed"] for bucket in bucket_summaries.values()),
        "survivors": sum(bucket["survivors"] for bucket in bucket_summaries.values()),
    }
    summary = {
        "domain": "HTML Sanitizer",
        "implementation": str(impl),
        "label": args.label,
        "common_baseline": len(matrix["final_common_contracts"]),
        "definition": {
            "all five OSS": "latest replay+mutant survivor contracts from that OSS minus final common contract identities",
        },
        "totals": totals,
        "by_oss": bucket_summaries,
    }

    out_json = OUT_DIR / f"{args.label}_non_common_by_oss.json"
    out_md = OUT_DIR / f"{args.label}_non_common_by_oss.md"
    out_hash = OUT_DIR / f"{args.label}_source_hashes.sha256"
    out_json.write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    out_hash.write_text("\n".join(COMMON_EVAL.source_hashes(impl)) + "\n", encoding="utf-8")

    lines = [
        f"# {args.label} HTML Sanitizer Non-Common Evaluation",
        "",
        f"Implementation: `{impl}`",
        f"Common baseline excluded: {summary['common_baseline']}",
        "",
        "| OSS bucket | Input | Replay passed | Replay failed | Mutants killed | Survivors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, bucket in bucket_summaries.items():
        lines.append(
            f"| `{name}` | {bucket['input_contracts']} | {bucket['replay_passed']} | "
            f"{bucket['replay_failed']} | {bucket['mutant_killed']} | {bucket['survivors']} |"
        )
    lines.append(
        f"| **Total** | **{totals['input_contracts']}** | **{totals['replay_passed']}** | "
        f"**{totals['replay_failed']}** | **{totals['mutant_killed']}** | **{totals['survivors']}** |"
    )
    lines.extend(["", "## Survivor Surface By OSS", ""])
    for name, bucket in bucket_summaries.items():
        lines.extend([f"### {name}", "", "| Capability | Survivors |", "| --- | ---: |"])
        for cap, count in bucket["by_capability"].items():
            lines.append(f"| `{cap}` | {count} |")
        if not bucket["by_capability"]:
            lines.append("| _none_ | 0 |")
        lines.append("")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {
        "common_baseline": summary["common_baseline"],
        "totals": totals,
        "by_oss": {
            name: {
                key: bucket[key]
                for key in ["input_contracts", "replay_passed", "replay_failed", "mutant_killed", "survivors"]
            }
            for name, bucket in bucket_summaries.items()
        },
    }
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
