#!/usr/bin/env python3
"""Re-execute all date/time non-common contracts against final dtlib."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OLD = ROOT / "tools/replay/replay_generated_datetime_non_common.py"
SNAPSHOT = Path(os.environ.get(
    "SHAPINGBENCH_TARGET_SNAPSHOT",
    "submission",
))
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))


def registry_executor(snapshot: Path) -> Callable[[dict[str, Any]], tuple[bool, dict[str, Any]]] | None:
    """Adapt import-only ``dtl`` snapshots to the benchmark operation protocol."""

    package_roots = [snapshot, snapshot / "src"]
    if not any((root / "dtl").is_dir() for root in package_roots):
        return None
    for root in reversed(package_roots):
        if root.is_dir():
            sys.path.insert(0, str(root))
    for name in tuple(sys.modules):
        if name == "dtl" or name.startswith("dtl."):
            del sys.modules[name]
    try:
        import dtl.ops  # noqa: F401
        from dtl.base import OPS
        from dtl.util import Params, Throw, norm
    except ImportError:
        return None

    throw_aliases = {"zone": "unknown-zone"}

    def execute(contract: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        operation = OPS.get(norm(contract.get("replay", "")))
        if operation is None:
            return True, {"throws": "unsupported", "message": "operation is absent from dtl registry"}
        try:
            actual = operation(Params(contract.get("params") or {}))
            if isinstance(actual, dict):
                return "throws" in actual, actual
            return False, {"value": actual}
        except Throw as exc:
            kind = throw_aliases.get(str(exc.kind), str(exc.kind))
            return True, {"throws": kind, "message": str(getattr(exc, "detail", "") or exc)}
        except BaseException as exc:
            return True, {"throws": "process-error", "message": f"{type(exc).__name__}: {exc}"}

    return execute


def load_old():
    sys.path.insert(0, str(ROOT / "tools/replay"))
    spec = importlib.util.spec_from_file_location("strict_datetime_old", OLD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old = load_old()
    contracts = [row for values in old.source_contracts().values() for row in values]
    assert len(contracts) == 404
    dtlib = SNAPSHOT / "dtlib"
    execute_registry = None if dtlib.is_file() else registry_executor(SNAPSHOT)
    output = []
    for index, contract in enumerate(contracts):
        if dtlib.is_file():
            result = old.evaluate_contract(dtlib, SNAPSHOT, contract)
            evidence_kind = "process_behavior_replay"
            command = [str(dtlib)]
        elif execute_registry is not None:
            errored, actual = execute_registry(contract)
            replay_ok, reason = old.compare(actual, contract["expected"], errored)
            mutant = old.mutate_expected(contract["expected"], actual)
            mutant_ok, _ = old.compare(actual, mutant, errored)
            result = {"status": "passed" if replay_ok and not mutant_ok else "failed",
                      "actual": actual, "expected": contract["expected"], "reason": reason,
                      "mutant_rejected": replay_ok and not mutant_ok}
            evidence_kind = "imported_registry_behavior_replay"
            command = ["import", "dtl.base.OPS", contract.get("replay")]
        else:
            result = {"status": "failed", "actual": {"throws": "capability-absence",
                      "message": "no dtlib executable or dtl registry package"},
                      "expected": contract["expected"], "reason": "target exposes no date/time operation protocol",
                      "mutant_rejected": False}
            evidence_kind = "target_capability_probe"
            command = ["probe", str(SNAPSHOT / "dtlib"), str(SNAPSHOT / "dtl")]
        verdict = "PASS" if result["status"] == "passed" else "FAIL_SEMANTIC_MISMATCH"
        identity = f"{contract['origin']}\0{contract['name']}\0{index}"
        output.append({"scoring_id": "datetime-noncommon-" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                       "origin": contract["origin"], "source_name": contract["name"], "source_contract": contract,
                       "target": "dtlib", "target_snapshot": str(SNAPSHOT), "verdict": verdict,
                       "evidence": {"kind": evidence_kind, "command": command,
                                    "actual": result["actual"], "expected": result["expected"],
                                    "oracle_reason": result["reason"], "mutant_rejected": result["mutant_rejected"]},
                       "adapter_revision": "datetime-executable-contract-v1"})
    (OUTPUT_DIR / "strict_results.jsonl").write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in output))
    summary = {"total": len(output), "verdicts": dict(Counter(x["verdict"] for x in output)),
               "execution_kinds": dict(Counter(x["evidence"]["kind"] for x in output))}
    (OUTPUT_DIR / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
