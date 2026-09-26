#!/usr/bin/env python3
"""Replay YAML non-common contracts against a generated Python `solyaml` library."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import signal
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
COMMON_JSON = ROOT / "contracts" / "yaml" / "common" / "yaml_cross_common_summary.json"
ORIGIN_FILES = {
    "pyyaml": ROOT / "contracts" / "yaml" / "pyyaml" / "latest_replay_mutant_verified.json",
    "eemeli-yaml": ROOT / "contracts" / "yaml" / "eemeli-yaml" / "latest_replay_mutant_verified.json",
    "go-yaml": ROOT / "contracts" / "yaml" / "go-yaml" / "latest_replay_mutant_verified.json",
    "js-yaml": ROOT / "contracts" / "yaml" / "js-yaml" / "latest_replay_mutant_verified.json",
    "ruamel-yaml": ROOT / "contracts" / "yaml" / "ruamel-yaml" / "latest_replay_mutant_verified.json",
}
OUT_DIR = ROOT / "contracts" / "yaml" / "generated_non_common"
COMMON_EVAL = ROOT / "tools" / "replay" / "replay_generated_yaml_common.py"


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


def load_common_eval() -> Any:
    spec = importlib.util.spec_from_file_location("yaml_common_eval", COMMON_EVAL)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {COMMON_EVAL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def safe_cell(value: Any) -> str:
    text = str(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    return text.replace("|", "\\|").replace("\n", "<br>")


def origin_rows(path: Path, origin: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("survivors", [])
    out = []
    for index, row in enumerate(rows):
        copied = dict(row)
        copied["origin"] = origin
        copied["bucket"] = origin
        copied["cross_id"] = f"{origin}:{index}:{row['name']}"
        out.append(copied)
    return out


def load_non_common_buckets() -> dict[str, list[dict[str, Any]]]:
    common = json.loads(COMMON_JSON.read_text(encoding="utf-8"))
    final_common_ids = {row["cross_id"] for row in common["final_common_contracts"]}
    buckets: dict[str, list[dict[str, Any]]] = {}

    for origin, path in ORIGIN_FILES.items():
        rows = origin_rows(path, origin)
        buckets[origin] = [row for row in rows if row["cross_id"] not in final_common_ids]

    return buckets


def expected_matches(
    common_eval: Any,
    solyaml: Any,
    contract: dict[str, Any],
    expected: dict[str, Any],
    timeout_seconds: float,
) -> tuple[bool, dict[str, Any], list[str]]:
    try:
        with contract_timeout(timeout_seconds):
            actual = common_eval.run_contract(solyaml, contract, expected)
    except ContractTimeoutError as exc:
        return False, {"error": "TimeoutError", "message": str(exc)}, [f"TimeoutError: {exc}"]
    except Exception as exc:
        return False, {"error": type(exc).__name__, "message": str(exc)}, [f"{type(exc).__name__}: {exc}"]
    if "error" in actual and "error" not in expected and "errors" not in expected:
        return False, actual, [f"{actual.get('error')}: {actual.get('message', '')}"]
    if "canonical" in expected:
        ok = actual.get("value") is True
        return ok, actual, [] if ok else ["canonical semantic equivalence mismatch"]
    for key, value in expected.items():
        if key in {"comparison", "error_regex"}:
            continue
        if not common_eval.deep_equal(actual.get(key), value):
            return False, actual, [f"{key} mismatch: expected {value!r}, got {actual.get(key)!r}"]
    return True, actual, []


def result_row(
    common_eval: Any,
    solyaml: Any,
    contract: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    replay_ok, actual, misses = expected_matches(common_eval, solyaml, contract, contract["expected"], timeout_seconds)
    mutant_ok, mutant_actual, mutant_misses = (
        expected_matches(common_eval, solyaml, contract, contract["mutant"], timeout_seconds)
        if replay_ok
        else (False, {}, ["mutant not evaluated because replay failed"])
    )
    verified = replay_ok and not mutant_ok
    return {
        "name": contract["name"],
        "cross_id": contract.get("cross_id"),
        "bucket": contract.get("bucket"),
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


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_bucket = defaultdict(Counter)
    by_capability = defaultdict(Counter)
    by_op = defaultdict(Counter)
    failures = Counter()
    for row in results:
        status = row["status"]
        by_bucket[row["bucket"]][status] += 1
        by_capability[row["capability"]][status] += 1
        by_op[row["op"]][status] += 1
        if status != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            failures[miss.split(":", 1)[0]] += 1
    passed = sum(1 for row in results if row["status"] == "passed")
    failed = len(results) - passed
    return {
        "total_non_common": len(results),
        "attempted": len(results),
        "unmapped": 0,
        "passed": passed,
        "failed": failed,
        "mutants_killed": sum(1 for row in results if row["mutant_rejected"]),
        "survivors": passed,
        "pass_rate": round(passed / len(results), 4) if results else 0,
        "by_bucket": {key: dict(counter) for key, counter in sorted(by_bucket.items())},
        "by_capability": {key: dict(counter) for key, counter in sorted(by_capability.items())},
        "by_op": {key: dict(counter) for key, counter in sorted(by_op.items())},
        "failure_kinds": dict(failures.most_common()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter4_20260830")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--timeout-seconds", type=float, default=1.0)
    args = parser.parse_args()

    label = safe_label(args.label)
    impl_dir = args.implementation_dir.resolve()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    common_eval = load_common_eval()
    solyaml = common_eval.load_solyaml(impl_dir)
    buckets = load_non_common_buckets()

    results = []
    for bucket, contracts in buckets.items():
        for contract in contracts:
            row = result_row(common_eval, solyaml, contract, args.timeout_seconds)
            row["bucket"] = bucket
            results.append(row)

    summary = {
        "domain": "YAML Parser/Emitter",
        "run_label": label,
        "implementation": str(impl_dir),
        "implementation_module": getattr(solyaml, "__file__", "unknown"),
        "model": args.model,
        "reasoning": args.reasoning,
        "timeout_seconds": args.timeout_seconds,
        "definition": "All five OSS latest replay+mutant survivors minus final_common_1172 by origin cross_id.",
        **summarize(results),
    }
    payload = {
        "summary": summary,
        "buckets": {bucket: len(rows) for bucket, rows in buckets.items()},
        "results": results,
    }

    out_json = OUT_DIR / f"solyaml_{label}_non_common_by_oss.json"
    out_md = OUT_DIR / f"solyaml_{label}_non_common_by_oss.md"
    out_hashes = OUT_DIR / f"solyaml_{label}_source_hashes.sha256"
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, out_hashes)

    lines = [
        "# Generated YAML Library Non-Common Replay",
        "",
        f"Implementation: `{impl_dir}`",
        f"Module: `{summary['implementation_module']}`",
        f"Model: `{summary['model']}`",
        f"Reasoning: `{summary['reasoning']}`",
        f"Definition: {summary['definition']}",
        f"Total non-common: {summary['total_non_common']}",
        f"Attempted: {summary['attempted']}",
        f"Unmapped: {summary['unmapped']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Mutants killed: {summary['mutants_killed']}",
        f"Survivors: {summary['survivors']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By OSS Bucket",
        "",
        "| OSS bucket | Input non-common | Passed | Failed |",
        "| --- | ---: | ---: | ---: |",
    ]
    for bucket, counter in summary["by_bucket"].items():
        total = counter.get("passed", 0) + counter.get("failed", 0)
        lines.append(f"| `{bucket}` | {total} | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## Failure Kinds", "", "| Failure kind | Count |", "| --- | ---: |"])
    for kind, count in summary["failure_kinds"].items():
        lines.append(f"| `{safe_cell(kind)}` | {count} |")
    lines.extend(["", "## Failed Samples", "", "| Bucket | Contract | Capability | Miss |", "| --- | --- | --- | --- |"])
    for row in [row for row in results if row["status"] != "passed"][:160]:
        miss = safe_cell((row.get("misses") or [""])[0])
        lines.append(f"| `{safe_cell(row['bucket'])}` | `{safe_cell(row['name'])}` | `{safe_cell(row['capability'])}` | {miss} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
