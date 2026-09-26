#!/usr/bin/env python3
"""Re-execute the direct HTML, Markdown, and YAML evaluators.

Outputs are analysis-only and retain the complete source contract beside each
actual observation.  Legacy files are neither overwritten nor treated as the
execution evidence for this pass.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import signal
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
REPLAY = ROOT / "tools/replay"

SNAPSHOTS = {
    "html_sanitizer": Path(os.environ.get("SHAPINGBENCH_HTML_SANITIZER_SNAPSHOT", "submission")),
    "markdown": Path(os.environ.get("SHAPINGBENCH_MARKDOWN_SNAPSHOT", "submission")),
    "yaml": Path(os.environ.get("SHAPINGBENCH_YAML_SNAPSHOT", "submission")),
}
OUTPUT_ROOT = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))
sys.path.insert(0, str(ROOT))
from analysis.executable_contract_system.import_target import add_snapshot_import_roots


class ContractExecutionTimeout(BaseException):
    pass


@contextmanager
def contract_timeout(seconds: float = 0.2):
    def raise_timeout(signum: int, frame: Any) -> None:
        raise ContractExecutionTimeout(f"target call exceeded {seconds:.1f}s")

    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def execute_bounded(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        with contract_timeout():
            return call()
    except ContractExecutionTimeout as exc:
        return {"replay_passed": False, "mutant_rejected": False,
                "actual": {"status": "execution_timeout", "message": str(exc)},
                "misses": [str(exc)]}


def load(filename: str, name: str):
    sys.path.insert(0, str(REPLAY))
    path = REPLAY / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def identity(domain: str, bucket: str, contract: dict[str, Any], index: int) -> str:
    raw = f"{domain}\0{bucket}\0{contract.get('name')}\0{index}"
    return f"{domain}-noncommon-" + hashlib.sha256(raw.encode()).hexdigest()[:20]


def write(domain: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    directory = OUTPUT_ROOT / domain
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "strict_results.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows)
    )
    summary = {"total": len(rows), "verdicts": dict(Counter(row["verdict"] for row in rows)),
               "execution_kinds": dict(Counter(row["evidence"]["kind"] for row in rows))}
    (directory / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def html() -> dict[str, Any]:
    module = load("replay_generated_html_sanitizer_non_common.py", "strict_html_direct")
    snapshot = SNAPSHOTS["html_sanitizer"]
    sys.path[:0] = [str(snapshot / "src"), str(snapshot)]
    for name in tuple(sys.modules):
        if name == "solsanitize" or name.startswith("solsanitize."):
            del sys.modules[name]
    api = importlib.import_module("solsanitize")
    matrix = json.loads(module.COMMON_MATRIX.read_text())
    buckets = module.load_origin_residuals(matrix)
    rows = []
    index = 0
    for bucket, contracts in buckets.items():
        for contract in contracts:
            result = execute_bounded(lambda: module.evaluate_contract(api, contract))
            passed = result["replay_passed"] and result["mutant_rejected"]
            rows.append({"scoring_id": identity("html", bucket, contract, index), "origin": bucket,
                         "source_name": contract.get("name"), "source_contract": contract,
                         "target": "solsanitize", "target_snapshot": str(snapshot),
                         "verdict": "PASS" if passed else "FAIL_SEMANTIC_MISMATCH",
                         "evidence": {"kind": "sanitize_behavior_replay", "actual": result["actual"],
                                      "expected": contract.get("expected"), "mutant_rejected": result["mutant_rejected"]},
                         "adapter_revision": "html-executable-contract-v1"})
            index += 1
    assert len(rows) == 1472
    return write("html_sanitizer", rows)


def markdown() -> dict[str, Any]:
    module = load("replay_generated_markdown_non_common.py", "strict_markdown_direct")
    snapshot = SNAPSHOTS["markdown"]
    add_snapshot_import_roots(snapshot)
    api = module.load_solmarkdown(snapshot)
    buckets = module.load_origin_residuals()
    rows = []
    index = 0
    for bucket, contracts in buckets.items():
        for contract in contracts:
            result = execute_bounded(lambda: module.evaluate_contract(api, contract, 3))
            passed = result["replay_passed"] and result["mutant_rejected"]
            rows.append({"scoring_id": identity("markdown", bucket, contract, index), "origin": bucket,
                         "source_name": contract.get("name"), "source_contract": contract,
                         "target": "solmarkdown", "target_snapshot": str(snapshot),
                         "verdict": "PASS" if passed else "FAIL_SEMANTIC_MISMATCH",
                         "evidence": {"kind": "render_behavior_replay", "actual": result["actual"],
                                      "expected": contract.get("expected"), "misses": result["misses"],
                                      "mutant_rejected": result["mutant_rejected"]},
                         "adapter_revision": "markdown-executable-contract-v1"})
            index += 1
    assert len(rows) == 1282
    return write("markdown", rows)


def yaml_domain() -> dict[str, Any]:
    module = load("replay_generated_yaml_non_common.py", "strict_yaml_direct")
    snapshot = SNAPSHOTS["yaml"]
    add_snapshot_import_roots(snapshot)
    common = module.load_common_eval()
    api = common.load_solyaml(snapshot)
    buckets = module.load_non_common_buckets()
    rows = []
    index = 0
    for bucket, contracts in buckets.items():
        for contract in contracts:
            result = execute_bounded(lambda: module.result_row(common, api, contract, 0.02))
            passed = result["replay_passed"] and result["mutant_rejected"]
            rows.append({"scoring_id": contract.get("cross_id") or identity("yaml", bucket, contract, index),
                         "origin": bucket, "source_name": contract.get("name"), "source_contract": contract,
                         "target": "solyaml", "target_snapshot": str(snapshot),
                         "verdict": "PASS" if passed else "FAIL_SEMANTIC_MISMATCH",
                         "evidence": {"kind": "yaml_behavior_replay", "actual": result["actual"],
                                      "expected": contract.get("expected"), "misses": result["misses"],
                                      "mutant_rejected": result["mutant_rejected"]},
                         "adapter_revision": "yaml-executable-contract-v1"})
            index += 1
    assert len(rows) == 2548
    return write("yaml", rows)


def main() -> int:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    runners = {"html_sanitizer": html, "markdown": markdown, "yaml": yaml_domain}
    selected = os.environ.get("SHAPINGBENCH_DIRECT_DOMAIN")
    if selected and selected not in runners:
        raise SystemExit(f"unknown direct domain: {selected}")
    summaries = {name: function() for name, function in runners.items() if not selected or name == selected}
    (OUTPUT_ROOT / "strict_summary.json").write_text(json.dumps(summaries, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summaries, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
