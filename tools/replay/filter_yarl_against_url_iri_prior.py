#!/usr/bin/env python3
"""Filter yarl survivors to avoid semantic overlap with prior URL/IRI origins."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
WHATWG = ROOT / "contracts" / "url_iri" / "whatwg-url" / "latest_replay_mutant_verified.json"
RUST = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_survivors_minus_whatwg_overlap.json"
YARL = ROOT / "contracts" / "url_iri" / "yarl" / "latest_replay_mutant_verified.json"
OUT_JSON = ROOT / "contracts" / "url_iri" / "yarl" / "latest_survivors_minus_prior_overlap.json"
OUT_MD = ROOT / "contracts" / "url_iri" / "yarl" / "latest_survivors_minus_prior_overlap.md"
OUT_RPL = ROOT / "contracts" / "url_iri" / "yarl" / "latest_survivors_minus_prior_overlap.rpl"


GENERIC_CAPABILITIES = {
    "url.object.parse-properties",
    "url.join",
    "url.i18n-authority",
    "url.origin-relative-port",
}


def prior_family(contract: dict[str, Any]) -> str | None:
    op = contract["op"]
    if op in {"parse_url", "static_parse"}:
        return "parse"
    if op in {"construct_failure", "parse_failure"}:
        return "failure"
    if op == "join":
        return "join"
    if op == "set_component":
        return "set_component"
    if op == "origin":
        return "origin"
    return None


def prior_stimulus(contract: dict[str, Any]) -> dict[str, Any] | None:
    params = contract.get("params") or {}
    family = prior_family(contract)
    if family in {"parse", "failure", "origin"}:
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "join":
        return {"base": params.get("base"), "input": params.get("input")}
    if family == "set_component":
        return {
            "input": params.get("input"),
            "base": params.get("base"),
            "component": params.get("component"),
            "value": params.get("value"),
        }
    return None


def yarl_family(contract: dict[str, Any]) -> str | None:
    op = contract["op"]
    capability = contract["capability"]
    if op == "props":
        if capability in {"url.host.validation"}:
            return "failure" if contract["expected"].get("ok") is False else "parse"
        return "parse"
    if op == "join":
        return "join"
    if op == "transform":
        method = (contract.get("params") or {}).get("method")
        if method in {"with_scheme", "with_host", "with_port", "with_user", "with_password"}:
            return "set_component"
    return None


def yarl_stimulus(contract: dict[str, Any]) -> dict[str, Any] | None:
    params = contract.get("params") or {}
    family = yarl_family(contract)
    if family in {"parse", "failure"}:
        return {"input": params.get("input"), "base": params.get("base")}
    if family == "join":
        return {"base": params.get("base"), "input": params.get("input")}
    if family == "set_component":
        method = params.get("method")
        component = {
            "with_scheme": "protocol",
            "with_host": "hostname",
            "with_port": "port",
            "with_user": "username",
            "with_password": "password",
        }.get(method)
        args = params.get("args") or []
        return {
            "input": params.get("input"),
            "base": params.get("base"),
            "component": component,
            "value": args[0] if args else None,
        }
    return None


def key(family: str, stimulus: dict[str, Any]) -> tuple[str, str]:
    return family, json.dumps(stimulus, ensure_ascii=False, sort_keys=True)


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
    yarl = json.loads(YARL.read_text(encoding="utf-8"))["survivors"]

    prior_index: dict[tuple[str, str], list[str]] = {}
    for contract in [*whatwg, *rust]:
        family = prior_family(contract)
        stimulus = prior_stimulus(contract)
        if family and stimulus:
            prior_index.setdefault(key(family, stimulus), []).append(contract["name"])

    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for contract in yarl:
        family = yarl_family(contract)
        stimulus = yarl_stimulus(contract)
        exact_matches: list[str] = []
        if family and stimulus:
            exact_matches = prior_index.get(key(family, stimulus), [])
        if exact_matches:
            removed.append(
                {
                    "contract": contract,
                    "reason": "exact prior stimulus overlap",
                    "prior_contracts": exact_matches[:5],
                }
            )
        elif contract["capability"] in GENERIC_CAPABILITIES:
            removed.append(
                {
                    "contract": contract,
                    "reason": "generic URL parser/resolution surface already covered by whatwg-url and rust-url",
                    "prior_contracts": [],
                }
            )
        else:
            kept.append(contract)

    by_capability = Counter(contract["capability"] for contract in kept)
    by_op = Counter(contract["op"] for contract in kept)
    removed_by_reason = Counter(row["reason"] for row in removed)
    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "aio-libs/yarl",
                "basis": "latest survivors minus exact and generic semantic overlap with whatwg-url and rust-url",
                "whatwg_survivors": len(whatwg),
                "rust_new_origin_survivors": len(rust),
                "yarl_latest_survivors_before_filter": len(yarl),
                "removed_as_prior_overlap": len(removed),
                "yarl_new_origin_survivors": len(kept),
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
        "# yarl Survivors Minus Prior URL/IRI Overlap",
        "",
        f"- whatwg-url latest survivors: `{len(whatwg)}`",
        f"- rust-url new-origin survivors: `{len(rust)}`",
        f"- yarl latest survivors before filtering: `{len(yarl)}`",
        f"- removed as prior overlap: `{len(removed)}`",
        f"- yarl new-origin survivors: `{len(kept)}`",
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

    print(
        json.dumps(
            {
                "yarl_latest_survivors_before_filter": len(yarl),
                "removed_as_prior_overlap": len(removed),
                "yarl_new_origin_survivors": len(kept),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
