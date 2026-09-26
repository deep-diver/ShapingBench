#!/usr/bin/env python3
"""Replay Cron final common contracts against a generated Python `solcron` library."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "cron" / "common" / "cron_final_common.json"
OUT_DIR = ROOT / "contracts" / "cron" / "generated"


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "target",
        "venv",
        ".venv",
        "dist",
        "build",
    }
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in ignored or part.endswith(".egg-info") for part in candidate.parts):
            continue
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        rows.append(f"{sha256(candidate)}  {candidate.relative_to(impl_dir)}\n")
    path.write_text("".join(rows), encoding="utf-8")


def load_solcron(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    for name in list(sys.modules):
        if name == "solcron" or name.startswith("solcron."):
            del sys.modules[name]
    try:
        return importlib.import_module("solcron")
    except Exception as exc:
        raise SystemExit(f"failed to import generated solcron from {impl_dir}: {type(exc).__name__}: {exc}") from exc


def normalize(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in sorted(value.items())}
    return value


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(normalize(left), sort_keys=True, ensure_ascii=True) == json.dumps(
        normalize(right), sort_keys=True, ensure_ascii=True
    )


def options_for(params: dict[str, Any]) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if "timezone" in params:
        options["timezone"] = params["timezone"]
    if "tz" in params:
        options["timezone"] = params["tz"]
    if "day_or" in params:
        options["day_match"] = "or" if params["day_or"] else "and"
    if "second_at_beginning" in params:
        options["seconds_at_beginning"] = bool(params["second_at_beginning"])
    elif len(str(params.get("expression", "")).split()) == 6:
        options["seconds_at_beginning"] = True
    return options


def include_seconds(params: dict[str, Any], expected: dict[str, Any]) -> bool:
    if "includeSeconds" in params:
        return bool(params["includeSeconds"])
    if "include_seconds" in params:
        return bool(params["include_seconds"])
    text = expected.get("string")
    return isinstance(text, str) and len(text.split()) == 6


def run_contract(solcron: Any, contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    op = contract["canonical_op"]
    params = contract.get("params") or {}
    expression = params.get("expression")
    options = options_for(params)

    if op == "next_dates":
        return {"dates": solcron.next_dates(expression, params.get("start"), int(params.get("count", 1)), options=options)}
    if op == "prev_dates":
        return {"dates": solcron.prev_dates(expression, params.get("start"), int(params.get("count", 1)), options=options)}
    if op == "match":
        return {"value": bool(solcron.match(expression, params.get("date"), options=options))}
    if op == "parse_valid":
        return {"value": bool(solcron.is_valid(expression, options=options))}
    if op == "parse_error":
        try:
            solcron.parse(expression, options=options)
            if params.get("use_next"):
                solcron.next_dates(expression, params.get("start") or "2024-01-01T00:00:00Z", 1, options=options)
            return {"error": False}
        except Exception as exc:
            return {"error": True, "message": str(exc), "throws": type(exc).__name__}
    if op == "parse_normalize":
        return {"string": solcron.normalize(expression, include_seconds=include_seconds(params, expected), options=options)}
    return {"unsupported": True, "message": op}


def expected_matches(solcron: Any, contract: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, dict[str, Any], list[str]]:
    try:
        actual = run_contract(solcron, contract, expected)
    except Exception as exc:
        return False, {"error": type(exc).__name__, "message": str(exc)}, [f"{type(exc).__name__}: {exc}"]
    if actual.get("unsupported"):
        return False, actual, [f"unsupported: {actual.get('message')}"]
    misses = []
    for key, value in expected.items():
        if key not in actual:
            if key == "error" and actual.get("throws"):
                continue
            misses.append(f"{key}: missing")
        elif not deep_equal(actual[key], value):
            misses.append(f"{key}: expected {value!r}, got {actual[key]!r}")
    return not misses, actual, misses


def load_contracts() -> list[dict[str, Any]]:
    data = json.loads(IN_JSON.read_text(encoding="utf-8"))
    return data["contracts"]


def write_md(summary: dict[str, Any], results: list[dict[str, Any]], path: Path) -> None:
    by_op = Counter(row["canonical_op"] for row in results if row["status"] == "passed")
    fail_by_op = Counter(row["canonical_op"] for row in results if row["status"] != "passed")
    lines = [
        f"# Generated Cron Replay, {summary['label']}",
        "",
        f"Implementation: `{summary['implementation']}`",
        f"Model: `{summary['model']}` / reasoning `{summary['reasoning']}`",
        f"Prompt style: {summary['prompt_style']}",
        "",
        f"Result: {summary['passed']}/{summary['total']} common contracts",
        "",
        "## Passed By Op",
        "",
        "| Op | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for op in sorted(set(by_op) | set(fail_by_op)):
        lines.append(f"| `{op}` | {by_op[op]} | {fail_by_op[op]} |")
    lines.extend(["", "## Failure Samples", "", "| Contract | Op | Miss |", "| --- | --- | --- |"])
    for row in [item for item in results if item["status"] != "passed"][:25]:
        miss = "; ".join(row.get("misses") or row.get("mutant_misses") or [])
        lines.append(f"| `{row['name']}` | `{row['canonical_op']}` | {miss} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="solcron_gpt56sol_high_iter1_20260831")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--prompt-style", default="generic implementation prompt; no contract corpus; no failure hints")
    parser.add_argument("--prompt", type=Path)
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    label = safe_label(args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    contracts = load_contracts()
    total = len(contracts)

    out_json = OUT_DIR / f"{label}_survival_from_common_{total}.json"
    out_md = OUT_DIR / f"{label}_survival_from_common_{total}.md"
    out_hashes = OUT_DIR / f"{label}_source_hashes.sha256"
    out_metadata = OUT_DIR / f"{label}_metadata.json"

    solcron = load_solcron(impl_dir)
    results = []
    survivors = []
    for contract in contracts:
        replay_ok, actual, misses = expected_matches(solcron, contract, contract["expected"])
        mutant_ok, mutant_actual, mutant_misses = (
            expected_matches(solcron, contract, contract["mutant"])
            if replay_ok
            else (False, {}, ["mutant not evaluated because replay failed"])
        )
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "origin": contract.get("origin"),
            "capability": contract.get("capability"),
            "canonical_op": contract["canonical_op"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "expected": contract["expected"],
            "mutant": contract["mutant"],
            "actual": actual,
            "mutant_actual": mutant_actual,
            "misses": misses,
            "mutant_misses": mutant_misses,
        }
        if verified:
            survivors.append(contract)
        results.append(row)

    by_op = defaultdict(Counter)
    by_origin = defaultdict(Counter)
    for row in results:
        by_op[row["canonical_op"]][row["status"]] += 1
        by_origin[row.get("origin", "unknown")][row["status"]] += 1

    summary = {
        "label": label,
        "implementation": str(impl_dir),
        "model": args.model,
        "reasoning": args.reasoning,
        "prompt_style": args.prompt_style,
        "prompt": str(args.prompt.resolve()) if args.prompt else None,
        "common_contracts": str(IN_JSON),
        "total": total,
        "passed": len(survivors),
        "failed": total - len(survivors),
        "by_canonical_op": {key: dict(value) for key, value in sorted(by_op.items())},
        "by_origin": {key: dict(value) for key, value in sorted(by_origin.items())},
    }
    out = {**summary, "results": results, "survivors": survivors}
    out_json.write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_md(summary, results, out_md)
    write_hashes(impl_dir, out_hashes)
    out_metadata.write_text(
        json.dumps(
            {
                **summary,
                "result_json": str(out_json),
                "result_md": str(out_md),
                "source_hashes": str(out_hashes),
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
