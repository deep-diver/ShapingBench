#!/usr/bin/env python3
"""Filter ada-url survivors to avoid semantic overlap with prior URL/IRI origins."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WHATWG = ROOT / "contracts" / "url_iri" / "whatwg-url" / "latest_replay_mutant_verified.json"
RUST = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_survivors_minus_whatwg_overlap.json"
YARL = ROOT / "contracts" / "url_iri" / "yarl" / "latest_survivors_minus_prior_overlap.json"
ADA = ROOT / "contracts" / "url_iri" / "ada-url" / "latest_replay_mutant_verified.json"
OUT_JSON = ROOT / "contracts" / "url_iri" / "ada-url" / "latest_survivors_minus_prior_overlap.json"
OUT_MD = ROOT / "contracts" / "url_iri" / "ada-url" / "latest_survivors_minus_prior_overlap.md"
OUT_RPL = ROOT / "contracts" / "url_iri" / "ada-url" / "latest_survivors_minus_prior_overlap.rpl"


GENERIC_CAPABILITIES = {
    "ada.url.parse-components",
    "ada.url.parse-failure",
    "ada.url.setters",
    "ada.url.origin-and-host-flags",
    "ada.url.traits",
}


def load(path: Path, key: str = "survivors") -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))[key]


def prior_stimulus(contract: dict[str, Any]) -> tuple[str, str] | None:
    params = contract.get("params") or {}
    op = contract.get("op")
    if op in {"parse_url", "static_parse", "parse", "props"}:
        return "parse", json.dumps({"input": params.get("input"), "base": params.get("base")}, ensure_ascii=False, sort_keys=True)
    if op in {"construct_failure", "parse_failure"}:
        return "failure", json.dumps({"input": params.get("input"), "base": params.get("base")}, ensure_ascii=False, sort_keys=True)
    if op in {"set_component", "transform"}:
        component = params.get("component")
        value = params.get("value")
        if op == "transform":
            method = params.get("method")
            component = {
                "with_scheme": "protocol",
                "with_host": "host",
                "with_port": "port",
                "with_user": "username",
                "with_password": "password",
                "with_path": "pathname",
                "with_fragment": "hash",
            }.get(method, method)
            args = params.get("args") or []
            value = args[0] if args else None
        return "set", json.dumps({"input": params.get("input"), "base": params.get("base"), "component": component, "value": value}, ensure_ascii=False, sort_keys=True)
    if op == "searchparams":
        return "search_params", json.dumps(params, ensure_ascii=False, sort_keys=True)
    return None


def ada_stimulus(contract: dict[str, Any]) -> tuple[str, str] | None:
    params = contract.get("params") or {}
    op = contract.get("op")
    if op == "parse":
        family = "failure" if contract["expected"].get("ok") is False else "parse"
        return family, json.dumps({"input": params.get("input"), "base": params.get("base")}, ensure_ascii=False, sort_keys=True)
    if op == "set_component":
        return "set", json.dumps({"input": params.get("input"), "base": params.get("base"), "component": params.get("component"), "value": params.get("value")}, ensure_ascii=False, sort_keys=True)
    if op == "search_params":
        return "search_params", json.dumps(params, ensure_ascii=False, sort_keys=True)
    return None


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
    prior = [*load(WHATWG), *load(RUST), *load(YARL)]
    ada = load(ADA)
    index: dict[tuple[str, str], list[str]] = {}
    for contract in prior:
        stim = prior_stimulus(contract)
        if stim:
            index.setdefault(stim, []).append(contract["name"])

    kept = []
    removed = []
    for contract in ada:
        stim = ada_stimulus(contract)
        exact = index.get(stim, []) if stim else []
        if exact:
            removed.append({"contract": contract, "reason": "exact prior stimulus overlap", "prior_contracts": exact[:5]})
        elif contract["capability"] in GENERIC_CAPABILITIES:
            removed.append({"contract": contract, "reason": "generic parser/setter surface already covered by prior origins", "prior_contracts": []})
        else:
            kept.append(contract)

    by_capability = Counter(contract["capability"] for contract in kept)
    by_op = Counter(contract["op"] for contract in kept)
    removed_by_reason = Counter(row["reason"] for row in removed)
    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "ada-url/ada",
                "basis": "latest survivors minus exact and generic semantic overlap with whatwg-url, rust-url, and yarl",
                "prior_survivors": len(prior),
                "ada_latest_survivors_before_filter": len(ada),
                "removed_as_prior_overlap": len(removed),
                "ada_new_origin_survivors": len(kept),
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
    md = [
        "# ada-url Survivors Minus Prior URL/IRI Overlap",
        "",
        f"- prior latest/new-origin survivors: `{len(prior)}`",
        f"- ada-url latest survivors before filtering: `{len(ada)}`",
        f"- removed as prior overlap: `{len(removed)}`",
        f"- ada-url new-origin survivors: `{len(kept)}`",
        "",
        "## Removed by Reason",
        "",
        "| Reason | Count |",
        "| --- | ---: |",
    ]
    for reason, count in removed_by_reason.most_common():
        md.append(f"| {reason} | {count} |")
    md.extend(["", "## Kept by Capability", "", "| Capability | Count |", "| --- | ---: |"])
    for capability, count in by_capability.most_common():
        md.append(f"| `{capability}` | {count} |")
    md.extend(["", "## Kept by Operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in by_op.most_common():
        md.append(f"| `{op}` | {count} |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"ada_latest_survivors_before_filter": len(ada), "removed_as_prior_overlap": len(removed), "ada_new_origin_survivors": len(kept)}, sort_keys=True))


if __name__ == "__main__":
    main()
