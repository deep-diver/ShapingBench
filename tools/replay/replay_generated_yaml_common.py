#!/usr/bin/env python3
"""Replay YAML final common contracts against a generated Python `solyaml` library."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import re
import signal
import sys
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "yaml" / "common" / "yaml_cross_common_summary.json"
OUT_DIR = ROOT / "contracts" / "yaml" / "generated"


class ContractTimeoutError(TimeoutError):
    pass


@contextmanager
def contract_timeout(seconds: float):
    if seconds <= 0:
        yield
        return

    def raise_timeout(_signum: int, _frame: Any) -> None:
        raise ContractTimeoutError(f"contract execution exceeded {seconds:.3g}s")

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    signal.signal(signal.SIGALRM, raise_timeout)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    ignored = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "target", "venv", ".venv"}
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


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"special": "nan"}
        if math.isinf(value):
            return {"special": "inf" if value > 0 else "-inf"}
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {str(key): normalize(item) for key, item in sorted(value.items())}
        pairs = [[normalize(key), normalize(item)] for key, item in value.items()]
        return {"__pairs__": sorted(pairs, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))}
    if hasattr(value, "isoformat"):
        text = value.isoformat()
        return text[:10] if text.endswith("00:00:00") else text
    return str(value)


def canonical(value: Any) -> Any:
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    return value


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(canonical(left), sort_keys=True, ensure_ascii=True) == json.dumps(canonical(right), sort_keys=True, ensure_ascii=True)


def load_solyaml(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    try:
        for name in list(sys.modules):
            if name == "solyaml" or name.startswith("solyaml."):
                del sys.modules[name]
        return importlib.import_module("solyaml")
    except Exception as exc:
        raise SystemExit(f"failed to import generated solyaml from {impl_dir}: {type(exc).__name__}: {exc}") from exc


def parse_docs(solyaml: Any, text: str | bytes | None) -> list[Any]:
    if hasattr(solyaml, "parse_all"):
        return [normalize(item) for item in solyaml.parse_all(text)]
    return [normalize(solyaml.parse(text))]


def parse_one(solyaml: Any, text: str | bytes | None) -> Any:
    if hasattr(solyaml, "parse"):
        return normalize(solyaml.parse(text))
    docs = parse_docs(solyaml, text)
    return docs[0] if len(docs) == 1 else docs


def dump_one(solyaml: Any, value: Any) -> str:
    if hasattr(solyaml, "dump"):
        return str(solyaml.dump(value))
    raise AttributeError("solyaml.dump is required")


def dump_docs(solyaml: Any, values: list[Any]) -> str:
    if hasattr(solyaml, "dump_all"):
        return str(solyaml.dump_all(values))
    return "".join(dump_one(solyaml, value) for value in values)


def scalar_kind(value: Any) -> dict[str, Any]:
    value = normalize(value)
    if isinstance(value, bool):
        return {"kind": "bool", "value": value}
    if value is None:
        return {"kind": "null", "value": None}
    if isinstance(value, int):
        return {"kind": "int", "value": value}
    if isinstance(value, float):
        if math.isnan(value):
            return {"kind": "float", "special": "nan"}
        if math.isinf(value):
            return {"kind": "float", "special": "inf" if value > 0 else "-inf"}
        return {"kind": "float", "value": value}
    if isinstance(value, dict) and "special" in value:
        return {"kind": "float", "special": value["special"]}
    return {"kind": "str", "value": str(value)}


def lookup(value: Any, path: list[Any]) -> Any:
    current = value
    for step in path:
        if isinstance(current, dict):
            current = current.get(str(step))
        else:
            return None
    return current


def strip_dump(text: str) -> str:
    if text.endswith("\n...\n"):
        text = text[:-5] + "\n"
    return text[:-1] if text.endswith("\n") else text


def run_contract(solyaml: Any, contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    params = contract.get("params") or {}
    op = contract["op"]
    if op in {"safe_load_json_value", "parse_to_value"}:
        return {"value": parse_one(solyaml, params.get("yaml") or "")}
    if op == "parse_to_value_at_path":
        return {"value": lookup(parse_one(solyaml, params.get("yaml") or ""), params.get("path") or [])}
    if op in {"parse_to_json_docs", "decode_stream_values"}:
        return {"value": parse_docs(solyaml, params.get("yaml") or "")}
    if op == "json_parse_success":
        return {"value": parse_one(solyaml, params.get("json") or "")}
    if op == "json_stringify_reparse_success":
        return {"value": parse_one(solyaml, json.dumps(parse_one(solyaml, params.get("json") or "")))}
    if op == "stringify_reparse_json_docs":
        rendered = dump_docs(solyaml, parse_docs(solyaml, params.get("yaml") or ""))
        return {"value": parse_docs(solyaml, rendered)}
    if op == "emitted_yaml_matches_json":
        return {"value": parse_docs(solyaml, params.get("emitted_yaml") or "")}
    if op in {"load_all_error", "load_single_error", "parse_error_presence"}:
        try:
            parse_docs(solyaml, params.get("yaml") or "")
        except Exception:
            return {"error": True, "errors": True}
        return {"error": False, "errors": False}
    if op == "schema_safe_load_scalar":
        return scalar_kind(parse_one(solyaml, params.get("yaml") or ""))
    if op == "schema_safe_dump_loaded_scalar":
        return {"dump": strip_dump(dump_one(solyaml, parse_one(solyaml, params.get("yaml") or "")))}
    if op in {"parse_canonical_equivalence", "compose_canonical_equivalence"}:
        left = parse_docs(solyaml, params.get("yaml") or "")
        right = parse_docs(solyaml, expected.get("canonical") or params.get("canonical") or "")
        return {"value": deep_equal(left, right)}
    if op == "emit_parse_roundtrip":
        docs = parse_docs(solyaml, params.get("yaml") or "")
        rendered = dump_docs(solyaml, docs)
        return {"value": deep_equal(docs, parse_docs(solyaml, rendered))}
    if op.startswith("load_unicode_"):
        docs = parse_docs(solyaml, params.get("text") or "")
        return {"value": docs[0] if len(docs) == 1 else docs}
    if op in {"scan_tokens", "parse_structure", "cst_roundtrip_source", "parse_node_signature"}:
        return {"error": "nonportable-surface"}
    if op == "marshal_to_yaml":
        return {"yaml": dump_one(solyaml, params.get("value"))}
    return {"error": "UnsupportedOperation", "message": op}


def expected_matches(
    solyaml: Any,
    contract: dict[str, Any],
    expected: dict[str, Any],
    timeout_seconds: float = 1.0,
) -> tuple[bool, dict[str, Any], list[str]]:
    try:
        with contract_timeout(timeout_seconds):
            actual = run_contract(solyaml, contract, expected)
    except ContractTimeoutError as exc:
        return False, {"error": "TimeoutError", "message": str(exc)}, [f"TimeoutError: {exc}"]
    except Exception as exc:
        return False, {"error": type(exc).__name__, "message": str(exc)}, [f"{type(exc).__name__}: {exc}"]
    if "error" in actual and "error" not in expected and "errors" not in expected:
        return False, actual, [f"{actual.get('error')}: {actual.get('message', '')}"]
    for key, value in expected.items():
        if key in {"comparison", "error_regex"}:
            continue
        if not deep_equal(actual.get(key), value):
            return False, actual, [f"{key} mismatch: expected {value!r}, got {actual.get(key)!r}"]
    return True, actual, []


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def load_contracts() -> list[dict[str, Any]]:
    data = json.loads(IN_JSON.read_text(encoding="utf-8"))
    return data["final_common_contracts"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter1_20260830")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--prompt-style", default="generic implementation prompt; no contract corpus; no failure hints")
    parser.add_argument("--timeout-seconds", type=float, default=1.0)
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    label = safe_label(args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / f"solyaml_{label}_survival_from_common_1172.json"
    out_md = OUT_DIR / f"solyaml_{label}_survival_from_common_1172.md"
    out_hashes = OUT_DIR / f"solyaml_{label}_source_hashes.sha256"
    out_metadata = OUT_DIR / f"solyaml_{label}_metadata.json"

    solyaml = load_solyaml(impl_dir)
    contracts = load_contracts()
    results = []
    survivors = []
    for contract in contracts:
        replay_ok, actual, misses = expected_matches(solyaml, contract, contract["expected"], args.timeout_seconds)
        mutant_ok, mutant_actual, mutant_misses = (
            expected_matches(solyaml, contract, contract["mutant"], args.timeout_seconds)
            if replay_ok
            else (False, {}, ["mutant not evaluated because replay failed"])
        )
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "origin": contract.get("origin"),
            "version": contract.get("version"),
            "capability": contract.get("capability"),
            "source_kind": contract.get("source_kind"),
            "op": contract.get("op"),
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "misses": misses,
            "mutant_misses": mutant_misses,
            "expected": contract.get("expected"),
            "actual": actual,
            "mutant_actual": mutant_actual,
        }
        results.append(row)
        if verified:
            survivors.append(contract["name"])

    counts = Counter(row["status"] for row in results)
    by_capability = defaultdict(Counter)
    by_origin = defaultdict(Counter)
    by_op = defaultdict(Counter)
    by_failure = Counter()
    for row in results:
        by_capability[row["capability"]][row["status"]] += 1
        by_origin[row["origin"]][row["status"]] += 1
        by_op[row["op"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            by_failure[miss.split(":", 1)[0]] += 1

    summary = {
        "domain": "YAML Parser/Emitter",
        "run_label": label,
        "implementation": str(impl_dir),
        "implementation_module": getattr(solyaml, "__file__", "unknown"),
        "model": args.model,
        "reasoning": args.reasoning,
        "prompt_style": args.prompt_style,
        "timeout_seconds": args.timeout_seconds,
        "common_contract_total": len(contracts),
        "passed": counts["passed"],
        "failed": counts["failed"],
        "mutants_killed": sum(1 for row in results if row["mutant_rejected"]),
        "survivors": len(survivors),
        "pass_rate": round(counts["passed"] / len(contracts), 4) if contracts else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_capability.items())},
        "by_origin": {str(origin): dict(counter) for origin, counter in sorted(by_origin.items())},
        "by_op": {op: dict(counter) for op, counter in sorted(by_op.items())},
        "failure_kinds": dict(by_failure.most_common()),
    }
    payload = {"summary": summary, "survivors": survivors, "results": results}
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, out_hashes)
    out_metadata.write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Generated YAML Library Survival",
        "",
        f"Implementation: `{impl_dir}`",
        f"Module: `{summary['implementation_module']}`",
        f"Model: `{summary['model']}`",
        f"Reasoning: `{summary['reasoning']}`",
        f"Prompt style: {summary['prompt_style']}",
        f"Contracts: {summary['common_contract_total']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Mutants killed: {summary['mutants_killed']}",
        f"Survivors: {summary['survivors']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Capability",
        "",
        "| Capability | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for cap, counter in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## By Origin", "", "| Origin | Passed | Failed |", "| --- | ---: | ---: |"])
    for origin, counter in summary["by_origin"].items():
        lines.append(f"| `{origin}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Miss |", "| --- | --- | --- |"])
    for row in [row for row in results if row["status"] != "passed"][:120]:
        miss = (row.get("misses") or [""])[0].replace("|", "\\|")
        lines.append(f"| `{row['name']}` | `{row['capability']}` | {miss} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
