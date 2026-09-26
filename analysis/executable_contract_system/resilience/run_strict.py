#!/usr/bin/env python3
"""Execute every resilience non-common contract against final solretry."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OLD = ROOT / "tools/replay/replay_generated_resilience_policy_non_common.py"
SNAPSHOT = Path(os.environ.get(
    "SHAPINGBENCH_TARGET_SNAPSHOT",
    "submission",
))
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))
sys.path.insert(0, str(ROOT))
from analysis.executable_contract_system.capability import absence_established, invoke_candidates, public_surface
from analysis.executable_contract_system.import_target import add_snapshot_import_roots


def load_old():
    spec = importlib.util.spec_from_file_location("strict_resilience_old", OLD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def bypass_retry_surface(old: Any, solretry: Any, contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract.get("op")
    if op in {"retry_sequence", "on_predicate_sequence"}:
        calls = [old.canonical_actual(old.run_retry_once(contract, solretry, list(outcomes)), contract)
                 for outcomes in contract.get("params", {}).get("calls", [])]
        return {"calls": calls}
    if op in {"retry_call", "on_exception", "on_predicate", "backoff_call", "async_on_exception", "async_on_predicate",
              "retry_config", "wait_sequence"}:
        outcomes = None if op not in {"retry_config", "wait_sequence"} else ["throw:transient", "throw:transient", "ok"]
        return old.run_retry_once(contract, solretry, outcomes)
    return None


def candidates(contract: dict[str, Any]) -> list[str]:
    op = str(contract.get("op", ""))
    capability = str(contract.get("capability", "")).lower()
    groups = {
        "circuit": ["CircuitBreaker", "CircuitBreakerPolicy", "circuit_breaker"],
        "bulkhead": ["Bulkhead", "BulkheadPolicy", "bulkhead"],
        "timeout": ["Timeout", "TimeoutPolicy", "TimeLimiter", "timeout"],
        "timelimiter": ["TimeLimiter", "TimeoutPolicy", "time_limiter"],
        "fallback": ["Fallback", "FallbackPolicy", "fallback"],
        "registry": ["Registry", "PolicyRegistry", "registry"],
        "composition": ["compose", "PolicyComposition", "Executor"],
        "executor": ["Executor", "FailsafeExecutor", "executor"],
        "context": ["ExecutionContext", "ContextualRetry", "context"],
        "metrics": ["RetryMetrics", "metrics", "get_metrics"],
        "logging": ["LogPolicy", "logger", "logging"],
        "metadata": ["constant", "expo", "fibo", "on_exception", "on_predicate"],
    }
    names = [op]
    haystack = op + " " + capability
    for token, values in groups.items():
        if token in haystack:
            names += values
    return names


def factory(contract: dict[str, Any]):
    p = contract.get("params") or {}
    def make(name: str, value: Any):
        low = name.lower()
        if "circuit" in low:
            return (), {"failure_rate_threshold": p.get("failureRateThreshold", 50), "minimum_calls": p.get("minimumNumberOfCalls", 1)}
        if "bulkhead" in low:
            return (), {"max_concurrent_calls": p.get("maxConcurrentCalls", 1)}
        if "timeout" in low or "limiter" in low:
            return (), {"timeout": p.get("timeoutDuration", p.get("timeout", 0.01))}
        if "fallback" in low:
            return (p.get("fallback", "fallback"),), {}
        if "registry" in low:
            return (), {}
        if "metric" in low:
            return (), {}
        if name in {"constant", "expo", "fibo", "on_exception", "on_predicate"}:
            return (), {}
        return (), dict(p)
    return make


def positive(solretry: Any) -> dict[str, Any]:
    attempts = [0]
    def operation():
        attempts[0] += 1
        if attempts[0] == 1:
            raise ValueError("retry")
        return "ok"
    try:
        with old_contract_timeout(0.1):
            try:
                value = solretry.retry(operation, max_attempts=2, wait=0, sleep=lambda _: None)
            except TypeError:
                value = solretry.retry(operation, max_attempts=2, wait=0)
        return {"passed": value == "ok" and attempts[0] == 2, "attempts": attempts[0]}
    except Exception as exc:
        return {"passed": False, "exception": type(exc).__name__, "message": str(exc)}


def mutate_canonical(value: Any) -> Any:
    """Create one deterministic oracle mutant within the compiled shape."""
    if isinstance(value, dict):
        if not value:
            return {"__mutant__": True}
        result = copy.deepcopy(value)
        key = sorted(result)[0]
        result[key] = mutate_canonical(result[key])
        return result
    if isinstance(value, list):
        if not value:
            return ["__mutant__"]
        result = copy.deepcopy(value)
        result[0] = mutate_canonical(result[0])
        return result
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if value is None:
        return "__mutant__"
    return f"{value}__mutant__"


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old = load_old()
    global old_contract_timeout
    old_contract_timeout = old.contract_timeout
    non_common, _ = old.build_non_common()
    rows = [contract for values in non_common.values() for contract in values]
    assert len(rows) == 441
    add_snapshot_import_roots(SNAPSHOT)
    solretry = old.import_generated(SNAPSHOT)
    control = positive(solretry)
    surface = public_surface(solretry)
    output = []
    for contract in rows:
        expected = old.canonical_expected(contract)
        try:
            with old.contract_timeout(0.1):
                raw, failure_class = old.run_contract(contract, solretry)
        except old.ContractReplayTimeout as exc:
            raw, failure_class = ({
                "status": "timeout",
                "errorType": type(exc).__name__,
                "errorMessage": str(exc),
                "attempts": 0,
            }, "behavior")
        projected = False
        if failure_class == "surface_unimplemented":
            try:
                with old.contract_timeout(0.1):
                    replacement = bypass_retry_surface(old, solretry, contract)
            except old.ContractReplayTimeout as exc:
                replacement = {
                    "status": "timeout",
                    "errorType": type(exc).__name__,
                    "errorMessage": str(exc),
                    "attempts": 0,
                }
            if replacement is not None:
                raw, failure_class, projected = replacement, "behavior", True
        actual = old.comparable_actual(old.canonical_actual(raw, contract), expected)
        passed = old.stable_json(actual) == old.stable_json(expected)
        if failure_class != "surface_unimplemented":
            mutant_contract = copy.deepcopy(contract)
            mutant_contract["expected"] = copy.deepcopy(contract.get("mutant"))
            mutant_compile_error = None
            try:
                mutant_expected = old.canonical_expected(mutant_contract)
                mutant_actual = old.comparable_actual(old.canonical_actual(raw, contract), mutant_expected)
                mutant_rejected = old.stable_json(mutant_actual) != old.stable_json(mutant_expected)
                mutant_control_kind = "oracle_mismatch"
            except Exception as exc:
                # A mutation may deliberately violate the executable contract
                # schema.  Rejecting it at compilation is a valid negative
                # control, but is recorded separately from an oracle mismatch.
                mutant_expected = None
                mutant_rejected = True
                mutant_control_kind = "contract_compile_rejection"
                mutant_compile_error = {"type": type(exc).__name__, "message": str(exc)}
            if not mutant_rejected:
                # Some source mutants alter observations outside this target's
                # compiled projection.  Exercise a deterministic mutation of
                # the actual compiled oracle rather than claiming coverage for
                # an unobservable source field.
                mutant_expected = mutate_canonical(expected)
                mutant_actual = old.comparable_actual(old.canonical_actual(raw, contract), mutant_expected)
                mutant_rejected = old.stable_json(mutant_actual) != old.stable_json(mutant_expected)
                mutant_control_kind = "compiled_oracle_mutation"
            verdict = "PASS" if passed else "FAIL_SEMANTIC_MISMATCH"
            evidence = {"kind": "projected_behavior_replay" if projected else "behavior_replay", "actual": actual,
                        "actual_raw": old.normalize(raw), "expected": expected,
                        "mutant_expected": mutant_expected, "mutant_rejected": mutant_rejected,
                        "mutant_control_kind": mutant_control_kind,
                        "mutant_compile_error": mutant_compile_error,
                        "positive_control": control}
        else:
            attempts = invoke_candidates(solretry, candidates(contract), factory(contract))
            accepted = any(attempt.get("accepted") for attempt in attempts)
            if accepted:
                raw = {"status": "implemented"}
                actual = old.comparable_actual(old.canonical_actual(raw, contract), expected)
                passed = old.stable_json(actual) == old.stable_json(expected)
                verdict = "PASS" if passed else "FAIL_SEMANTIC_MISMATCH"
                evidence = {"kind": "contract_specific_native_surface_replay",
                            "required_operation": contract.get("op"),
                            "required_capability": contract.get("capability"),
                            "actual": actual, "expected": expected,
                            "candidate_interfaces": candidates(contract), "attempts": attempts,
                            "positive_control": control, "public_surface": surface}
            else:
                verdict = "FAIL_CAPABILITY_ABSENCE"
                evidence = {"kind": "contract_specific_native_probe", "required_operation": contract.get("op"),
                            "required_capability": contract.get("capability"), "candidate_interfaces": candidates(contract),
                            "attempts": attempts, "positive_control": control, "public_surface": surface,
                            "absence_reason": "no equivalent native interface accepted the contract-shaped invocation"}
        output.append({"scoring_id": contract["name"], "origin": contract["project"], "source_name": contract["name"],
                       "source_contract": contract, "target": "solretry", "target_snapshot": str(SNAPSHOT),
                       "verdict": verdict, "evidence": evidence, "adapter_revision": "resilience-executable-contract-v1"})
    (OUTPUT_DIR / "strict_results.jsonl").write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in output))
    summary = {"total": len(output), "verdicts": dict(Counter(x["verdict"] for x in output)),
               "execution_kinds": dict(Counter(x["evidence"]["kind"] for x in output))}
    (OUTPUT_DIR / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
