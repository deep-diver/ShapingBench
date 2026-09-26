#!/usr/bin/env python3
"""Remove rust-url survivor contracts already covered by whatwg-url survivors."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WHATWG = ROOT / "contracts" / "url_iri" / "whatwg-url" / "latest_replay_mutant_verified.json"
RUST = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_replay_mutant_verified.json"
OUT_JSON = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_survivors_minus_whatwg_overlap.json"
OUT_MD = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_survivors_minus_whatwg_overlap.md"
OUT_RPL = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_survivors_minus_whatwg_overlap.rpl"


PARSE_LIKE = {"parse_url", "static_parse"}
FAILURE_LIKE = {"construct_failure"}


def op_family(contract: dict[str, Any]) -> str:
    op = contract["op"]
    if op in PARSE_LIKE:
        return "parse"
    if op in FAILURE_LIKE:
        return "failure"
    if op == "origin":
        return "origin"
    if op == "set_component":
        return "set_component"
    return op


def stimulus(contract: dict[str, Any]) -> dict[str, Any] | None:
    params = dict(contract.get("params") or {})
    family = op_family(contract)
    if family == "parse":
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "failure":
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "origin":
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "set_component":
        return {
            "input": params.get("input"),
            "base": params.get("base"),
            "component": params.get("component"),
            "value": params.get("value"),
        }
    return None


def comparable_expected(contract: dict[str, Any]) -> dict[str, Any]:
    expected = dict(contract.get("expected") or {})
    family = op_family(contract)
    if family == "failure":
        return {"ok": False}
    if family == "origin":
        if "origin" in expected:
            return {"origin": expected["origin"]}
        if "value" in expected:
            return {"origin": expected["value"]}
    return expected


def rust_family(contract: dict[str, Any]) -> str:
    op = contract["op"]
    if op in {"parse_url", "join"}:
        return "parse"
    if op == "parse_failure":
        return "failure"
    if op == "set_component":
        return "set_component"
    return op


def rust_stimulus(contract: dict[str, Any]) -> dict[str, Any] | None:
    params = dict(contract.get("params") or {})
    family = rust_family(contract)
    if family == "parse":
        if contract["op"] == "join":
            return {"input": params.get("input"), "base": params.get("base")}
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "failure":
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "set_component":
        component = params.get("component")
        component = {
            "path": "pathname",
            "query": "search",
            "fragment": "hash",
            "scheme": "protocol",
        }.get(component, component)
        return {
            "input": params.get("input"),
            "base": params.get("base"),
            "component": component,
            "value": params.get("value"),
        }
    return None


def expected_subset(whatwg_expected: dict[str, Any], rust_expected: dict[str, Any]) -> bool:
    if not whatwg_expected:
        return False
    for key, value in whatwg_expected.items():
        if key.endswith("Contains"):
            return False
        if key not in rust_expected:
            return False
        if rust_expected[key] != value:
            return False
    return True


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
    whatwg = json.loads(WHATWG.read_text(encoding="utf-8"))["survivors"]
    rust = json.loads(RUST.read_text(encoding="utf-8"))["survivors"]

    whatwg_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for contract in whatwg:
        stim = stimulus(contract)
        if stim is None:
            continue
        family = op_family(contract)
        key = (family, json.dumps(stim, ensure_ascii=False, sort_keys=True))
        whatwg_index.setdefault(key, []).append(contract)

    kept = []
    removed = []
    for contract in rust:
        stim = rust_stimulus(contract)
        if stim is None:
            kept.append(contract)
            continue
        family = rust_family(contract)
        keys = [(family, json.dumps(stim, ensure_ascii=False, sort_keys=True))]
        if family == "parse":
            keys.append(("origin", json.dumps(stim, ensure_ascii=False, sort_keys=True)))
        matched = None
        for key in keys:
            for candidate in whatwg_index.get(key, []):
                if expected_subset(comparable_expected(candidate), contract["expected"]):
                    matched = candidate
                    break
            if matched:
                break
        if matched:
            removed.append(
                {
                    "rust_contract": contract,
                    "overlaps_whatwg_contract": matched["name"],
                    "overlap_family": op_family(matched),
                }
            )
        else:
            kept.append(contract)

    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "servo/rust-url",
                "basis": "latest survivors minus semantic overlap with jsdom/whatwg-url latest survivors",
                "whatwg_survivors": len(whatwg),
                "rust_latest_survivors": len(rust),
                "removed_as_whatwg_overlap": len(removed),
                "rust_new_origin_survivors": len(kept),
                "removed": removed,
                "survivors": kept,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(contract) for contract in kept) + "\n", encoding="utf-8")

    by_source = Counter(contract.get("source", "unknown") for contract in kept)
    by_op = Counter(contract["op"] for contract in kept)
    by_overlap = Counter(row["overlap_family"] for row in removed)
    md = [
        "# rust-url survivors minus whatwg-url overlap",
        "",
        f"- whatwg-url latest survivors: `{len(whatwg)}`",
        f"- rust-url latest survivors before filtering: `{len(rust)}`",
        f"- removed as overlap with whatwg-url: `{len(removed)}`",
        f"- rust-url new origin survivors: `{len(kept)}`",
        "",
        "## Kept by source",
        "",
        "| Source | Count |",
        "| --- | ---: |",
    ]
    for source, count in by_source.most_common():
        md.append(f"| `{source}` | {count} |")
    md.extend(["", "## Kept by operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in by_op.most_common():
        md.append(f"| `{op}` | {count} |")
    md.extend(["", "## Removed Overlap Family", "", "| Family | Count |", "| --- | ---: |"])
    for family, count in by_overlap.most_common():
        md.append(f"| `{family}` | {count} |")
    md.extend(["", "## Removed", "", "| rust-url contract | whatwg-url contract |", "| --- | --- |"])
    for row in removed:
        md.append(f"| `{row['rust_contract']['name']}` | `{row['overlaps_whatwg_contract']}` |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "whatwg_survivors": len(whatwg),
                "rust_latest_survivors": len(rust),
                "removed_as_whatwg_overlap": len(removed),
                "rust_new_origin_survivors": len(kept),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
