#!/usr/bin/env python3
"""Replay URL/IRI common contracts against a generated Python `solurl` library."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "url_iri" / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_DIR = ROOT / "contracts" / "url_iri" / "generated"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "target", "venv", ".venv"} for part in candidate.parts):
            continue
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        rel = candidate.relative_to(impl_dir)
        rows.append(f"{sha256(candidate)}  {rel}\n")
    path.write_text("".join(rows), encoding="utf-8")


def as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def common_from_url(url: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "href": as_text(getattr(url, "href", str(url))),
        "origin": as_text(getattr(url, "origin", "")),
        "protocol": as_text(getattr(url, "protocol", "")),
        "username": as_text(getattr(url, "username", "")),
        "password": as_text(getattr(url, "password", "")),
        "host": as_text(getattr(url, "host", "")),
        "hostname": as_text(getattr(url, "hostname", "")),
        "port": as_text(getattr(url, "port", "")),
        "pathname": as_text(getattr(url, "pathname", "")),
        "search": as_text(getattr(url, "search", "")),
        "hash": as_text(getattr(url, "hash", "")),
    }


def make_url(solurl: Any, input_value: str, base: Any = None) -> Any:
    return solurl.URL(input_value, base) if base is not None else solurl.URL(input_value)


def run_contract(solurl: Any, contract: dict[str, Any]) -> dict[str, Any]:
    kind = contract["kind"]
    params = contract.get("params") or {}
    try:
        if kind == "parse":
            return common_from_url(make_url(solurl, params.get("input", ""), params.get("base")))
        if kind == "parse_failure":
            try:
                url = make_url(solurl, params.get("input", ""), params.get("base"))
                return common_from_url(url)
            except Exception as ex:
                return {"ok": False, "throws": type(ex).__name__, "message": str(ex)}
        if kind == "set_component":
            url = make_url(solurl, params.get("input", ""), params.get("base"))
            try:
                setattr(url, params["component"], "" if params.get("value") is None else params.get("value"))
                out = common_from_url(url)
                out["set_ok"] = True
                return out
            except Exception as ex:
                out = common_from_url(url)
                out["set_ok"] = False
                out["throws"] = type(ex).__name__
                out["message"] = str(ex)
                return out
        if kind == "can_parse":
            fn = getattr(solurl.URL, "can_parse", None) or getattr(solurl, "can_parse")
            return {"value": bool(fn(params.get("input", ""), params.get("base")))}
        if kind == "roundtrip":
            first = make_url(solurl, params.get("input", ""), params.get("base"))
            second = make_url(solurl, getattr(first, "href", str(first)))
            first_href = as_text(getattr(first, "href", str(first)))
            second_href = as_text(getattr(second, "href", str(second)))
            return {"stable": first_href == second_href, "href": second_href}
        return {"unsupported": True, "message": kind}
    except Exception as ex:
        return {"ok": False, "throws": type(ex).__name__, "message": str(ex)}


def expected_matches(expected: dict[str, Any], actual: dict[str, Any]) -> tuple[bool, list[str]]:
    misses = []
    if actual.get("unsupported"):
        return False, [f"unsupported: {actual.get('message')}"]
    for key, value in expected.items():
        if actual.get(key) != value:
            misses.append(f"{key}: expected {value!r}, got {actual.get(key)!r}")
    return not misses, misses


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(expected, ensure_ascii=False))
    for key, value in list(out.items()):
        if isinstance(value, bool):
            out[key] = not value
            return out
        if isinstance(value, int):
            out[key] = value + 1
            return out
        if isinstance(value, str):
            out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def load_solurl(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    try:
        return importlib.import_module("solurl")
    except Exception as ex:
        raise SystemExit(f"failed to import generated solurl from {impl_dir}: {type(ex).__name__}: {ex}") from ex


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter1_20260829")
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / f"solurl_{safe_label}_survival_from_common_245.json"
    out_md = OUT_DIR / f"solurl_{safe_label}_survival_from_common_245.md"
    hashes = OUT_DIR / f"solurl_{safe_label}_source_hashes.sha256"

    solurl = load_solurl(impl_dir)
    contracts = json.loads(IN_JSON.read_text(encoding="utf-8"))["final_common_contracts"]
    results = []
    survivors = []
    for contract in contracts:
        actual = run_contract(solurl, contract)
        replay_ok, misses = expected_matches(contract["expected"], actual)
        mutant_expected = mutate_expected(contract["expected"])
        mutant_ok, mutant_misses = expected_matches(mutant_expected, actual)
        verified = replay_ok and not mutant_ok
        row = {
            "origin": contract.get("origin"),
            "name": contract["name"],
            "capability": contract.get("capability"),
            "kind": contract["kind"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "misses": misses,
            "mutant_misses": mutant_misses,
            "expected": contract["expected"],
            "actual": actual,
        }
        results.append(row)
        if verified:
            survivors.append(contract["name"])

    counts = Counter(row["status"] for row in results)
    by_kind = defaultdict(lambda: Counter())
    by_capability = defaultdict(lambda: Counter())
    for row in results:
        by_kind[row["kind"]][row["status"]] += 1
        by_capability[row["capability"]][row["status"]] += 1
    summary = {
        "domain": "URL/IRI",
        "implementation": str(impl_dir),
        "implementation_module": getattr(solurl, "__file__", "unknown"),
        "common_contract_total": len(contracts),
        "passed": counts["passed"],
        "failed": counts["failed"],
        "pass_rate": round(counts["passed"] / len(contracts), 4) if contracts else 0,
        "by_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_capability.items())},
    }

    payload = {"summary": summary, "survivors": survivors, "results": results}
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, hashes)

    lines = [
        "# Generated URL/IRI Library Survival",
        "",
        f"Implementation: `{impl_dir}`",
        f"Module: `{summary['implementation_module']}`",
        f"Contracts: {summary['common_contract_total']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Kind",
        "",
        "| Kind | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for kind, counter in summary["by_kind"].items():
        lines.append(f"| `{kind}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines += [
        "",
        "## Failed Contracts",
        "",
        "| Contract | Kind | Capability | Misses |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        if row["status"] == "passed":
            continue
        misses = "; ".join(row["misses"]) or "mutant survived"
        misses = misses.replace("|", "\\|")
        if len(misses) > 260:
            misses = misses[:257] + "..."
        lines.append(f"| `{row['name']}` | `{row['kind']}` | `{row['capability']}` | {misses} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
