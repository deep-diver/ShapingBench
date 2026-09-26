#!/usr/bin/env python3
"""Replay Markdown common contracts against a generated Python `solmarkdown` library."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import html
import importlib
import json
import re
import signal
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "markdown" / "common" / "final_hidden_filtered_common.json"
OUT_DIR = ROOT / "contracts" / "markdown" / "generated"


class ContractTimeout(TimeoutError):
    pass


@contextlib.contextmanager
def time_limit(seconds: int):
    if seconds <= 0:
        yield
        return

    def handle_timeout(_signum: int, _frame: Any) -> None:
        raise ContractTimeout(f"contract exceeded {seconds}s timeout")

    previous = signal.signal(signal.SIGALRM, handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
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


def html_standardize(text: Any) -> str:
    normalized = str(text or "")
    normalized = normalized.replace("<br>", "<br />").replace("<br/>", "<br />")
    normalized = normalized.replace("<hr>", "<hr />").replace("<hr/>", "<hr />")
    normalized = normalized.replace(">\n<", "><").strip()
    return html.unescape(normalized)


def expected_matches(expected: dict[str, Any], actual: dict[str, Any]) -> tuple[bool, list[str]]:
    if "error" in actual:
        return False, [f"{actual.get('error')}: {actual.get('message', '')}"]
    comparison = expected.get("comparison") or "html_trim_standardize"
    if comparison not in {"html_standardize", "html_trim_standardize"}:
        return False, [f"unsupported comparison: {comparison}"]
    expected_html = html_standardize(expected.get("html"))
    actual_html = html_standardize(actual.get("html"))
    if expected_html == actual_html:
        return True, []
    return False, [f"html mismatch: expected {expected_html!r}, got {actual_html!r}"]


def run_contract(solmarkdown: Any, contract: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    try:
        with time_limit(timeout_seconds):
            params = contract.get("params") or {}
            markdown = params.get("markdown") or ""
            options = dict(params.get("options") or {})
            if params.get("actions"):
                options.setdefault("actions", params["actions"])
            if contract.get("op") == "render_inline":
                return {"html": solmarkdown.render_inline(markdown, options=options)}
            if contract.get("op") == "render":
                return {"html": solmarkdown.render(markdown, options=options)}
            return {"error": "UnsupportedOperation", "message": str(contract.get("op"))}
    except Exception as ex:
        return {"error": type(ex).__name__, "message": str(ex)}


def load_solmarkdown(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    try:
        if "solmarkdown" in sys.modules:
            del sys.modules["solmarkdown"]
        return importlib.import_module("solmarkdown")
    except Exception as ex:
        raise SystemExit(f"failed to import generated solmarkdown from {impl_dir}: {type(ex).__name__}: {ex}") from ex


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def load_contracts() -> list[dict[str, Any]]:
    data = json.loads(IN_JSON.read_text(encoding="utf-8"))
    return data.get("final_contracts") or data.get("contracts") or []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter1_20260830")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument(
        "--prompt-style",
        default="generic implementation prompt; no contract corpus; no failure hints",
    )
    parser.add_argument("--timeout-seconds", type=int, default=3)
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    label = safe_label(args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / f"solmarkdown_{label}_survival_from_common_877.json"
    out_md = OUT_DIR / f"solmarkdown_{label}_survival_from_common_877.md"
    out_hashes = OUT_DIR / f"solmarkdown_{label}_source_hashes.sha256"
    out_metadata = OUT_DIR / f"solmarkdown_{label}_metadata.json"

    solmarkdown = load_solmarkdown(impl_dir)
    contracts = load_contracts()
    results = []
    survivors = []
    for contract in contracts:
        actual = run_contract(solmarkdown, contract, args.timeout_seconds)
        replay_ok, misses = expected_matches(contract["expected"], actual)
        mutant_ok, mutant_misses = (
            expected_matches(contract["mutant"], actual)
            if replay_ok
            else (False, ["mutant not evaluated because replay failed"])
        )
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "version": contract.get("version"),
            "capability": contract.get("capability"),
            "common_origin": contract.get("common_origin"),
            "source_kind": contract.get("source_kind"),
            "op": contract.get("op"),
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "misses": misses,
            "mutant_misses": mutant_misses,
            "expected": contract.get("expected"),
            "actual": actual,
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
        by_origin[row["common_origin"]][row["status"]] += 1
        by_op[row["op"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            by_failure[miss.split(":", 1)[0]] += 1

    summary = {
        "domain": "Markdown Parser/Renderer",
        "run_label": label,
        "implementation": str(impl_dir),
        "implementation_module": getattr(solmarkdown, "__file__", "unknown"),
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
        "by_origin": {origin: dict(counter) for origin, counter in sorted(by_origin.items())},
        "by_op": {op: dict(counter) for op, counter in sorted(by_op.items())},
        "failure_kinds": dict(by_failure.most_common()),
    }
    payload = {"summary": summary, "survivors": survivors, "results": results}
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, out_hashes)
    out_metadata.write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Generated Markdown Library Survival",
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
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Actual sample |", "| --- | --- | --- |"])
    for row in [row for row in results if row["status"] != "passed"][:80]:
        actual = row.get("actual", {}).get("html")
        if actual is None:
            actual = json.dumps(row.get("actual"), ensure_ascii=False)
        sample = str(actual).replace("\n", "\\n").replace("|", "\\|")
        if len(sample) > 240:
            sample = sample[:237] + "..."
        lines.append(f"| `{row['name']}` | `{row['capability']}` | {sample} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
