#!/usr/bin/env python3
"""Evaluate generated solmarkdown against per-OSS Markdown non-common contracts."""

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
BASE = ROOT / "contracts" / "markdown"
COMMON_JSON = BASE / "common" / "final_hidden_filtered_common.json"
CANDIDATES_JSON = BASE / "common" / "rank1_2_3_cross_replay_common_candidates.json"
HIDDEN_DETAILS_JSON = BASE / "common" / "hidden_filter_details.json"
OUT_DIR = BASE / "generated_non_common"
ORIGIN_FILES = {
    "markdown-it": BASE / "markdown-it" / "latest_replay_mutant_verified.json",
    "pulldown-cmark": BASE / "pulldown-cmark" / "latest_replay_mutant_verified.json",
    "goldmark": BASE / "goldmark" / "latest_replay_mutant_verified.json",
    "commonmark.js": BASE / "commonmark-js" / "latest_non_common.json",
    "marked": BASE / "marked" / "latest_non_common.json",
}
HIDDEN_TARGETS = {
    "commonmark.js": "commonmark.js",
    "marked": "marked",
}


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


def source_hashes(impl_dir: Path) -> list[str]:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "target",
        "venv",
        ".venv",
    }
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in ignored or part.endswith(".egg-info") for part in candidate.parts):
            continue
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        rows.append(f"{sha256(candidate)}  {candidate.relative_to(impl_dir)}")
    return rows


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


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_solmarkdown(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    if "solmarkdown" in sys.modules:
        del sys.modules["solmarkdown"]
    try:
        return importlib.import_module("solmarkdown")
    except Exception as ex:
        raise SystemExit(f"failed to import generated solmarkdown from {impl_dir}: {type(ex).__name__}: {ex}") from ex


def run_contract(solmarkdown: Any, contract: dict[str, Any]) -> dict[str, Any]:
    try:
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


def contract_identity(contract: dict[str, Any]) -> str:
    return json.dumps(
        [
            contract.get("op"),
            contract.get("params", {}).get("markdown"),
            contract.get("expected", {}).get("html"),
        ],
        ensure_ascii=True,
        sort_keys=True,
    )


def load_origin_residuals() -> dict[str, list[dict[str, Any]]]:
    common = load_json(COMMON_JSON)["final_contracts"]
    common_names_by_origin = defaultdict(set)
    for contract in common:
        origin = contract.get("common_origin")
        if origin:
            common_names_by_origin[origin].add(contract.get("name"))

    buckets: dict[str, list[dict[str, Any]]] = {}
    for origin, path in ORIGIN_FILES.items():
        data = load_json(path)
        rows = []
        source_rows = data.get("contracts") or data.get("survivors") or []
        for contract in source_rows:
            if contract.get("name") in common_names_by_origin[origin]:
                continue
            enriched = dict(contract)
            enriched["oss_bucket"] = origin
            enriched["non_common_kind"] = "origin_latest_survivor_minus_final_common"
            rows.append(enriched)
        buckets[origin] = rows
    return buckets


def load_hidden_residuals() -> dict[str, list[dict[str, Any]]]:
    candidates = {row["name"]: row for row in load_json(CANDIDATES_JSON)["contracts"]}
    hidden = load_json(HIDDEN_DETAILS_JSON)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for target, bucket_name in HIDDEN_TARGETS.items():
        rows = []
        for result in hidden[target]:
            if result.get("status") == "passed":
                continue
            base = candidates.get(result.get("name"))
            actual_html = (result.get("actual") or {}).get("html")
            if not base or actual_html is None:
                continue
            contract = dict(base)
            contract["oss_bucket"] = bucket_name
            contract["non_common_kind"] = "hidden_filter_target_actual_minus_final_common"
            contract["expected"] = {
                "html": actual_html,
                "comparison": "html_trim_standardize",
            }
            contract["mutant"] = {
                "html": f"{actual_html}__mutant__",
                "comparison": "html_trim_standardize",
            }
            rows.append(contract)
        buckets[bucket_name] = rows
    return buckets


def evaluate_contract(solmarkdown: Any, contract: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    try:
        with time_limit(timeout_seconds):
            actual = run_contract(solmarkdown, contract)
    except ContractTimeout as ex:
        actual = {"error": "ContractTimeout", "message": str(ex)}
    replay_ok, misses = expected_matches(contract["expected"], actual)
    mutant_ok, mutant_misses = (
        expected_matches(contract["mutant"], actual)
        if replay_ok
        else (False, ["mutant not evaluated because replay failed"])
    )
    verified = replay_ok and not mutant_ok
    return {
        "name": contract.get("name"),
        "version": contract.get("version"),
        "oss_bucket": contract.get("oss_bucket"),
        "non_common_kind": contract.get("non_common_kind"),
        "capability": contract.get("capability"),
        "source_kind": contract.get("source_kind"),
        "op": contract.get("op"),
        "status": "passed" if verified else "failed",
        "replay_passed": replay_ok,
        "mutant_rejected": replay_ok and not mutant_ok,
        "misses": misses,
        "mutant_misses": mutant_misses,
        "actual": actual,
    }


def summarize_bucket(results: list[dict[str, Any]]) -> dict[str, Any]:
    status = Counter(row["status"] for row in results)
    failed = [row for row in results if row["status"] != "passed"]
    by_capability = defaultdict(Counter)
    by_kind = defaultdict(Counter)
    by_failure = Counter()
    for row in results:
        by_capability[row["capability"]][row["status"]] += 1
        by_kind[row["non_common_kind"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            by_failure[miss.split(":", 1)[0]] += 1
    return {
        "input_contracts": len(results),
        "passed": status["passed"],
        "failed": status["failed"],
        "replay_passed": sum(1 for row in results if row["replay_passed"]),
        "mutants_killed": sum(1 for row in results if row["mutant_rejected"]),
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_capability.items())},
        "by_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
        "failure_kinds": dict(by_failure.most_common()),
        "failed_samples": failed[:20],
    }


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter6_20260830")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--timeout-seconds", type=int, default=3)
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    label = safe_label(args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    solmarkdown = load_solmarkdown(impl_dir)

    buckets = load_origin_residuals()

    bucket_results = {
        bucket: [evaluate_contract(solmarkdown, contract, args.timeout_seconds) for contract in contracts]
        for bucket, contracts in buckets.items()
    }
    bucket_summaries = {
        bucket: summarize_bucket(results)
        for bucket, results in bucket_results.items()
    }
    totals = {
        "input_contracts": sum(row["input_contracts"] for row in bucket_summaries.values()),
        "passed": sum(row["passed"] for row in bucket_summaries.values()),
        "failed": sum(row["failed"] for row in bucket_summaries.values()),
        "replay_passed": sum(row["replay_passed"] for row in bucket_summaries.values()),
        "mutants_killed": sum(row["mutants_killed"] for row in bucket_summaries.values()),
    }
    payload = {
        "domain": "Markdown Parser/Renderer",
        "label": label,
        "implementation": str(impl_dir),
        "implementation_module": getattr(solmarkdown, "__file__", "unknown"),
        "model": args.model,
        "reasoning": args.reasoning,
        "timeout_seconds": args.timeout_seconds,
        "common_baseline": len(load_json(COMMON_JSON)["final_contracts"]),
        "definition": {
            "all five OSS": "latest replay+mutant survivor contracts from that OSS minus final common contracts contributed by the same origin",
        },
        "totals": totals,
        "by_oss": bucket_summaries,
        "results": bucket_results,
    }

    out_json = OUT_DIR / f"solmarkdown_{label}_non_common_by_oss.json"
    out_md = OUT_DIR / f"solmarkdown_{label}_non_common_by_oss.md"
    out_hashes = OUT_DIR / f"solmarkdown_{label}_source_hashes.sha256"
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    out_hashes.write_text("\n".join(source_hashes(impl_dir)) + "\n", encoding="utf-8")

    lines = [
        f"# {label} Markdown Non-Common Evaluation",
        "",
        f"Implementation: `{impl_dir}`",
        f"Common baseline excluded: {payload['common_baseline']}",
        "",
        "| OSS bucket | Input | Replay passed | Failed | Mutants killed | Survivors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for bucket, summary in bucket_summaries.items():
        lines.append(
            f"| `{bucket}` | {summary['input_contracts']} | {summary['replay_passed']} | "
            f"{summary['failed']} | {summary['mutants_killed']} | {summary['passed']} |"
        )
    lines.append(
        f"| **Total** | **{totals['input_contracts']}** | **{totals['replay_passed']}** | "
        f"**{totals['failed']}** | **{totals['mutants_killed']}** | **{totals['passed']}** |"
    )
    lines.extend(["", "## Failure Kinds", "", "| OSS bucket | Failure kind | Count |", "| --- | --- | ---: |"])
    for bucket, summary in bucket_summaries.items():
        for kind, count in summary["failure_kinds"].items():
            lines.append(f"| `{bucket}` | `{kind}` | {count} |")
    lines.extend(["", "## Survivor Surface", ""])
    for bucket, summary in bucket_summaries.items():
        lines.extend([f"### {bucket}", "", "| Capability | Survivors | Failed |", "| --- | ---: | ---: |"])
        for cap, counter in summary["by_capability"].items():
            lines.append(f"| `{cap}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
        lines.append("")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {
        "common_baseline": payload["common_baseline"],
        "totals": totals,
        "by_oss": {
            bucket: {
                key: summary[key]
                for key in ["input_contracts", "replay_passed", "failed", "mutants_killed", "passed"]
            }
            for bucket, summary in bucket_summaries.items()
        },
    }
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
