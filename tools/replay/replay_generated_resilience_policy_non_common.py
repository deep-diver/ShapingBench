#!/usr/bin/env python3
"""Replay per-OSS non-common resilience-policy contracts against generated solretry."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import signal
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "resilience_policy"
COMMON = BASE / "common" / "confirmed_common_after_rank4_rank5.json"
OUT = BASE / "generated"

ORIGIN_FILES = {
    "resilience4j": BASE / "resilience4j" / "latest_replay_mutant_verified.json",
    "failsafe": BASE / "failsafe" / "latest_replay_mutant_verified.json",
    "backoff": BASE / "backoff" / "latest_replay_mutant_verified.json",
    "exponential-backoff": BASE / "exponential-backoff" / "latest_replay_mutant_verified.json",
    "async-retry": BASE / "async-retry" / "latest_replay_mutant_verified.json",
}


class TransientFailure(Exception):
    pass


class FatalFailure(Exception):
    pass


class IgnoredFailure(Exception):
    pass


class RuntimeFailure(Exception):
    pass


class CheckedFailure(Exception):
    pass


class BailFailure(Exception):
    pass


class ContractReplayTimeout(TimeoutError):
    pass


@contextmanager
def contract_timeout(seconds: float = 1.0):
    def _raise_timeout(signum: int, frame: Any) -> None:
        raise ContractReplayTimeout(f"contract replay exceeded {seconds:.1f}s")

    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


EXCEPTION_TYPES: dict[str, type[BaseException]] = {
    "transient": TransientFailure,
    "fatal": FatalFailure,
    "ignored": IgnoredFailure,
    "runtime": RuntimeFailure,
    "checked": CheckedFailure,
}
ALL_RETRY_EXCEPTIONS = tuple(EXCEPTION_TYPES.values())


SURFACE_OPS = {
    "bulkhead_sequence",
    "circuitbreaker_config",
    "circuitbreaker_sequence",
    "composition_call",
    "contextual_retry",
    "executor_listeners",
    "fallback_call",
    "policy_composition",
    "registry_probe",
    "timeout_call",
    "timelimiter_future",
}
SURFACE_CAPABILITY_TOKENS = [
    "bulkhead",
    "circuitbreaker",
    "completion-event",
    "config",
    "context",
    "decorator-surface",
    "delay-function",
    "executor",
    "fallback",
    "handler-details",
    "logging",
    "metadata",
    "metrics",
    "runtime-config",
    "timeout",
    "timelimiter",
]


def stable_json(value: Any) -> str:
    return json.dumps(normalize(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def normalize(value: Any) -> Any:
    if isinstance(value, BaseException):
        return {
            "errorType": type(value).__name__,
            "errorMessage": str(value),
        }
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, tuple):
        return [normalize(v) for v in value]
    if isinstance(value, set):
        return sorted(normalize(v) for v in value)
    if isinstance(value, float):
        return round(value, 6)
    return value


def status_kind(status: str | None) -> str:
    if status == "returned":
        return "returned"
    if status in {"raised", "thrown"}:
        return "failed"
    return status or "unknown"


def load_contracts(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["contracts"]


def retry_notification_count(payload: dict[str, Any]) -> int | None:
    if isinstance(payload.get("events"), dict):
        events = payload["events"]
        if "retry" in events:
            return int(events["retry"])
        if isinstance(events.get("backoff"), list):
            return len(events["backoff"])
    if isinstance(payload.get("listeners"), dict):
        listeners = payload["listeners"]
        if "retry" in listeners:
            return int(listeners["retry"])
        if "retryScheduled" in listeners:
            return int(listeners["retryScheduled"])
    if isinstance(payload.get("retryCalls"), list):
        return len(payload["retryCalls"])
    if isinstance(payload.get("onRetryCalls"), list):
        return len(payload["onRetryCalls"])
    return None


def attempts_value(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int):
        return value
    return None


def expected_waits(expected: dict[str, Any]) -> list[Any] | None:
    if "waits" in expected:
        return expected["waits"]
    if "intervalsMillis" in expected:
        return expected["intervalsMillis"]
    if "values" in expected:
        return expected["values"]
    return None


def callback_attempt_numbers(payload: dict[str, Any]) -> list[int] | None:
    calls = payload.get("onRetryCalls")
    if not isinstance(calls, list):
        calls = payload.get("retryCalls")
    if not isinstance(calls, list):
        return None
    values = []
    for call in calls:
        if isinstance(call, dict):
            if "attemptNumber" in call:
                values.append(int(call["attemptNumber"]))
            elif "attempt" in call:
                values.append(int(call["attempt"]))
    return values


def should_compare_retry_notifications(contract: dict[str, Any]) -> bool:
    capability = contract.get("capability", "").lower()
    expected = contract.get("expected", {})
    return (
        any(token in capability for token in ["event", "listener", "onretry", "callback"])
        or retry_notification_count(expected) is not None
    )


def canonical_expected(contract: dict[str, Any]) -> dict[str, Any]:
    expected = contract.get("expected", {})
    out: dict[str, Any] = {}
    if surface_required(contract):
        out["surface"] = "implemented"
    if "status" in expected:
        out["status"] = status_kind(expected.get("status"))
    attempts = attempts_value(expected.get("attempts"))
    if attempts is not None:
        out["attempts"] = attempts
    if "value" in expected and out.get("status") == "returned":
        out["value"] = expected["value"]
    waits = expected_waits(expected)
    if waits is not None:
        out["waits"] = waits
    if should_compare_retry_notifications(contract):
        count = retry_notification_count(expected)
        if count is not None:
            out["retryNotifications"] = count
        numbers = callback_attempt_numbers(expected)
        if numbers is not None and "attempt-number" in contract.get("capability", "").lower():
            out["retryAttemptNumbers"] = numbers
    if "calls" in expected:
        out["calls"] = [
            canonical_expected({"expected": call, "capability": contract.get("capability", "")})
            for call in expected["calls"]
        ]
    return normalize(out)


def comparable_actual(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return normalize({key: actual.get(key) for key in expected.keys()})


def source_kind(contract: dict[str, Any]) -> str:
    op = contract.get("op")
    params = contract.get("params", {})
    capability = contract.get("capability", "").lower()
    if op in SURFACE_OPS or any(token in capability for token in SURFACE_CAPABILITY_TOKENS):
        return "surface_policy"
    if op in {"retry_call", "on_exception", "async_on_exception", "backoff_call"}:
        if params.get("retryOnResult") or params.get("handleResult") or params.get("handleResultPrefix"):
            return "retry_result"
        return "retry_exception"
    if op in {"on_predicate", "async_on_predicate", "on_predicate_sequence"}:
        return "retry_result"
    if op in {"retry_config", "wait_sequence"}:
        return "wait_sequence"
    return "surface_policy"


def common_signature(contract: dict[str, Any]) -> tuple[Any, ...]:
    return (
        source_kind(contract),
        max_attempts_for(contract),
        stable_json(outcomes_for(contract)),
        stable_json(handled_kinds(contract)),
        stable_json(canonical_expected(contract)),
    )


def build_non_common() -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    common_contracts = load_contracts(COMMON)
    common_names = {contract["name"] for contract in common_contracts}
    common_sigs = {common_signature(contract) for contract in common_contracts}
    non_common: dict[str, list[dict[str, Any]]] = {}
    excluded: dict[str, int] = {}
    for origin, path in ORIGIN_FILES.items():
        contracts = load_contracts(path)
        kept = []
        dropped = 0
        for contract in contracts:
            if contract["name"] in common_names or common_signature(contract) in common_sigs:
                dropped += 1
            else:
                kept.append(contract)
        non_common[origin] = kept
        excluded[origin] = dropped
    return non_common, excluded


def import_generated(implementation: Path) -> Any:
    if (implementation / "src" / "solretry").exists():
        import_root = implementation / "src"
    elif (implementation / "solretry").exists():
        import_root = implementation
    else:
        raise FileNotFoundError(
            f"missing generated solretry package under {implementation}/src or {implementation}"
        )
    sys.path.insert(0, str(import_root))
    try:
        return importlib.import_module("solretry")
    finally:
        sys.path.pop(0)


def max_attempts_for(contract: dict[str, Any]) -> int:
    params = contract.get("params", {})
    if "maxAttempts" in params:
        return max(1, int(params["maxAttempts"]))
    if "maxRetries" in params:
        return max(1, int(params["maxRetries"]) + 1)
    if params.get("max_tries") is not None:
        return max(1, int(params["max_tries"]))
    if "numOfAttempts" in params:
        return max(1, int(params["numOfAttempts"]))
    if "retries" in params:
        return max(1, int(params["retries"]) + 1)
    attempts = attempts_value(contract.get("expected", {}).get("attempts"))
    return max(1, int(attempts or 3))


def outcomes_for(contract: dict[str, Any]) -> list[Any]:
    params = contract.get("params", {})
    if "calls" in params:
        return list(params["calls"][0] or ["ok"])
    return list(params.get("outcomes") or ["ok"])


def handled_kinds(contract: dict[str, Any]) -> list[str]:
    params = contract.get("params", {})
    if "retryExceptions" in params:
        return list(params.get("retryExceptions") or ["transient"])
    if "handle" in params:
        return list(params.get("handle") or ["transient"])
    if "exceptions" in params:
        return list(params.get("exceptions") or ["transient"])
    if contract.get("project") in {"coveooss/exponential-backoff", "vercel/async-retry"}:
        return list(EXCEPTION_TYPES)
    return ["transient"]


def fixed_wait_for(contract: dict[str, Any]) -> float:
    params = contract.get("params", {})
    for key in ["waitMillis", "interval", "startingDelay", "minTimeout"]:
        if key in params:
            value = params[key]
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
    return 0.0


def retry_predicate_for(contract: dict[str, Any]) -> Any:
    params = contract.get("params", {})
    if "retryOnResult" in params:
        value = params["retryOnResult"]
        return lambda result: result == value
    if "handleResult" in params:
        value = params["handleResult"]
        return lambda result: result == value
    if params.get("predicate") == "equals":
        value = params.get("predicate_value")
        return lambda result: result == value
    if contract.get("op") in {"on_predicate", "async_on_predicate", "on_predicate_sequence"}:
        return lambda result: not bool(result)
    return None


def policy_supports(solretry: Any, **kwargs: Any) -> bool:
    try:
        solretry.RetryPolicy(max_attempts=1, **kwargs)
        return True
    except Exception:
        return False


def retry_kwargs_from_params(contract: dict[str, Any], solretry: Any) -> dict[str, Any]:
    params = contract.get("params", {})
    kwargs: dict[str, Any] = {}

    for key in ["timeMultiple", "factor", "multiplier"]:
        value = params.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            if policy_supports(solretry, backoff=float(value)):
                kwargs["backoff"] = float(value)
            break

    for key in ["maxDelay", "maxTimeout", "maxInterval", "cap", "ceiling"]:
        value = params.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            if policy_supports(solretry, max_wait=float(value)):
                kwargs["max_wait"] = float(value)
            break

    if params.get("jitter") is not None or params.get("randomize") is not None:
        if policy_supports(solretry, jitter=lambda delay, attempt: delay):
            kwargs["jitter"] = lambda delay, attempt: delay

    if "retryMode" in params and policy_supports(solretry, retry_on_exception=lambda exc: True):
        mode = params.get("retryMode")
        if mode in {"never", "abort", "none"}:
            kwargs["retry_on_exception"] = lambda exc: False
        elif mode in {"onlyTransient", "transient"}:
            kwargs["retry_on_exception"] = lambda exc: isinstance(exc, TransientFailure)
        elif mode in {"ignoreFatal", "nonFatal"}:
            kwargs["retry_on_exception"] = lambda exc: not isinstance(exc, FatalFailure)

    if "maxElapsedTime" in params:
        value = params["maxElapsedTime"]
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            if policy_supports(solretry, max_elapsed_time=float(value), clock=lambda: 0.0):
                kwargs["max_elapsed_time"] = float(value)
                kwargs["clock"] = lambda: 0.0
    return kwargs


def make_exception(kind: str, attempt: int) -> BaseException:
    if kind == "bail":
        return BailFailure("Aborted")
    exc_type = EXCEPTION_TYPES.get(kind, TransientFailure)
    return exc_type(f"{kind}-{attempt}")


def outcome_value(outcome: Any, attempt: int) -> Any:
    if not isinstance(outcome, str):
        return outcome
    if outcome.startswith("throw:"):
        raise make_exception(outcome.split(":", 1)[1], attempt)
    if outcome.startswith("reject:"):
        raise make_exception(outcome.split(":", 1)[1], attempt)
    if outcome.startswith("bail:"):
        kind = outcome.split(":", 1)[1]
        exc = make_exception(kind, attempt)
        raise BailFailure(str(exc))
    if outcome == "bail":
        raise BailFailure("Aborted")
    if outcome.startswith("throw_bail_flag:"):
        kind = outcome.split(":", 1)[1]
        exc = make_exception(kind, attempt)
        raise BailFailure(str(exc))
    return outcome


def has_surface(solretry: Any, contract: dict[str, Any]) -> bool:
    op = contract.get("op")
    capability = contract.get("capability", "").lower()
    if "circuitbreaker" in capability or op == "circuitbreaker_sequence":
        return any(hasattr(solretry, name) for name in ["CircuitBreaker", "CircuitBreakerPolicy"])
    elif "bulkhead" in capability or op == "bulkhead_sequence":
        return any(hasattr(solretry, name) for name in ["Bulkhead", "BulkheadPolicy"])
    elif "timeout" in capability or "timelimiter" in capability or op in {"timeout_call", "timelimiter_future"}:
        return any(hasattr(solretry, name) for name in ["Timeout", "TimeoutPolicy", "TimeLimiter"])
    elif "fallback" in capability or op == "fallback_call":
        return any(hasattr(solretry, name) for name in ["Fallback", "FallbackPolicy"])
    elif "registry" in capability or op == "registry_probe":
        return any(hasattr(solretry, name) for name in ["Registry", "PolicyRegistry"])
    elif op == "package_metadata":
        return all(hasattr(solretry, name) for name in ["constant", "expo", "fibo", "on_exception", "on_predicate", "__version__"])
    elif "metrics" in capability:
        return any(hasattr(solretry, name) for name in ["metrics", "get_metrics", "RetryMetrics"])
    elif "logging" in capability:
        return any(hasattr(solretry, name) for name in ["logger", "logging", "LogPolicy"])
    elif "handler-details" in capability:
        return any(hasattr(solretry, name) for name in ["on_backoff", "on_giveup", "HandlerDetails"])
    elif "runtime-config" in capability:
        return any(hasattr(solretry, name) for name in ["runtime", "runtime_config", "RuntimeConfig"]) or policy_supports(
            solretry, wait=lambda attempt: 0
        )
    elif "decorator-surface" in capability:
        return all(hasattr(solretry, name) for name in ["on_exception", "on_predicate"])
    elif "jitter" in capability or "delay-function" in capability or "backoff" in capability:
        return (
            any(hasattr(solretry, name) for name in ["backoff", "BackoffPolicy", "jitter"])
            or policy_supports(solretry, backoff=2)
            or policy_supports(solretry, wait=lambda attempt: 0)
            or policy_supports(solretry, jitter=lambda delay, attempt: delay)
        )
    elif "config" in capability:
        return hasattr(solretry, "RetryPolicy") and capability.startswith("retry.config")
    return hasattr(solretry, "retry")


def surface_required(contract: dict[str, Any]) -> bool:
    op = contract.get("op")
    capability = contract.get("capability", "").lower()
    if op in SURFACE_OPS or op == "package_metadata":
        return True
    return any(token in capability for token in SURFACE_CAPABILITY_TOKENS)


def run_retry_once(contract: dict[str, Any], solretry: Any, outcomes: list[Any] | None = None) -> dict[str, Any]:
    attempts = 0
    retry_calls: list[dict[str, Any]] = []
    sleeps: list[float] = []
    sequence = list(outcomes if outcomes is not None else outcomes_for(contract))

    def sleep(value: float) -> None:
        sleeps.append(value)

    def on_retry(*args: Any, **kwargs: Any) -> None:
        exc = kwargs.get("exception", kwargs.get("exc"))
        attempt = kwargs.get("attempt", kwargs.get("attemptNumber"))
        for value in args:
            if attempt is None and isinstance(value, int) and not isinstance(value, bool):
                attempt = value
            elif exc is None and isinstance(value, BaseException):
                exc = value
        event = {
            "errorType": type(exc).__name__ if exc is not None else None,
            "errorMessage": str(exc) if exc is not None else None,
        }
        if attempt is not None:
            event.update({"attempt": int(attempt), "attemptNumber": int(attempt)})
        retry_calls.append(event)

    def fn() -> Any:
        nonlocal attempts
        attempts += 1
        return outcome_value(sequence[min(attempts - 1, len(sequence) - 1)], attempts)

    params = contract.get("params", {})
    retry_exceptions: tuple[type[BaseException], ...]
    if any(str(item).startswith(("bail", "throw_bail_flag")) for item in sequence):
        retry_exceptions = ALL_RETRY_EXCEPTIONS
    else:
        retry_exceptions = tuple(EXCEPTION_TYPES.get(kind, TransientFailure) for kind in handled_kinds(contract))

    kwargs: dict[str, Any] = {
        "max_attempts": max_attempts_for(contract),
        "wait": fixed_wait_for(contract),
        "retry_exceptions": retry_exceptions,
        "retry_on_result": retry_predicate_for(contract),
        "on_retry": on_retry,
        "sleep": sleep,
    }
    if "raise_on_giveup" in params:
        kwargs["raise_on_giveup"] = bool(params["raise_on_giveup"])
    if "max_time" in params and int(params["max_time"]) == 0:
        kwargs["max_attempts"] = 1
    kwargs.update(retry_kwargs_from_params(contract, solretry))

    supports_sleep_injection = policy_supports(solretry, sleep=sleep)
    supports_sleeper_injection = not supports_sleep_injection and policy_supports(solretry, sleeper=sleep)
    if supports_sleeper_injection:
        kwargs["sleeper"] = sleep
    if not supports_sleep_injection:
        kwargs.pop("sleep", None)
    original_sleep = time.sleep
    if not supports_sleep_injection and not supports_sleeper_injection:
        time.sleep = sleep
    try:
        value = solretry.retry(fn, **kwargs)
        return {
            "status": "returned",
            "value": value,
            "attempts": attempts,
            "waits": sleeps,
            "retryCalls": retry_calls,
            "onRetryCalls": retry_calls,
        }
    except BaseException as exc:  # noqa: BLE001 - replay records observable failure.
        return {
            "status": "raised",
            "errorType": type(exc).__name__,
            "errorMessage": str(exc),
            "attempts": attempts,
            "waits": sleeps,
            "retryCalls": retry_calls,
            "onRetryCalls": retry_calls,
        }
    finally:
        time.sleep = original_sleep


def run_contract(contract: dict[str, Any], solretry: Any) -> tuple[dict[str, Any], str]:
    if surface_required(contract):
        if not has_surface(solretry, contract):
            return {"status": "surface_unimplemented", "attempts": 0}, "surface_unimplemented"
    op = contract.get("op")
    if op in {"retry_sequence", "on_predicate_sequence"}:
        calls = []
        for outcomes in contract.get("params", {}).get("calls", []):
            calls.append(canonical_actual(run_retry_once(contract, solretry, list(outcomes)), contract))
        return {"calls": calls}, "behavior"
    if op in {"retry_call", "on_exception", "on_predicate", "backoff_call", "async_on_exception", "async_on_predicate"}:
        return run_retry_once(contract, solretry), "behavior"
    if op in {"retry_config", "wait_sequence"}:
        if not has_surface(solretry, contract):
            return {"status": "surface_unimplemented", "attempts": 0}, "surface_unimplemented"
        return run_retry_once(contract, solretry, ["throw:transient", "throw:transient", "ok"]), "behavior"
    return {"status": "surface_unimplemented", "attempts": 0}, "surface_unimplemented"


def canonical_actual(actual: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    expected = canonical_expected(contract)
    if "surface" in expected:
        out["surface"] = "unimplemented" if actual.get("status") == "surface_unimplemented" else "implemented"
    if "status" in expected:
        out["status"] = status_kind(actual.get("status"))
    if "attempts" in expected:
        out["attempts"] = attempts_value(actual.get("attempts"))
    if "value" in expected and out.get("status") == "returned":
        out["value"] = actual.get("value")
    if "waits" in expected:
        out["waits"] = actual.get("waits")
    if "retryNotifications" in expected:
        out["retryNotifications"] = retry_notification_count(actual)
    if "retryAttemptNumbers" in expected:
        out["retryAttemptNumbers"] = callback_attempt_numbers(actual)
    if "calls" in expected:
        out["calls"] = actual.get("calls")
    return normalize(out)


def file_hashes(implementation: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(implementation.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(implementation).as_posix()
        if ".pytest_cache" in rel or "__pycache__" in rel or rel.endswith((".pyc", ".pyo")):
            continue
        hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def replay(label: str, implementation: Path) -> dict[str, Any]:
    non_common, excluded = build_non_common()
    solretry = import_generated(implementation)
    rows = []
    for origin, contracts in non_common.items():
        for contract in contracts:
            expected = canonical_expected(contract)
            try:
                with contract_timeout():
                    raw, failure_class = run_contract(contract, solretry)
            except ContractReplayTimeout as exc:
                raw, failure_class = (
                    {"status": "timeout", "errorType": type(exc).__name__, "errorMessage": str(exc), "attempts": 0},
                    "behavior",
                )
            actual = comparable_actual(canonical_actual(raw, contract), expected)
            passed = stable_json(actual) == stable_json(expected)
            rows.append(
                {
                    "originBucket": origin,
                    "name": contract["name"],
                    "project": contract["project"],
                    "capability": contract["capability"],
                    "op": contract["op"],
                    "semanticKind": source_kind(contract),
                    "expectedCanonical": expected,
                    "actualCanonical": actual,
                    "actualRaw": normalize(raw),
                    "failureClass": "pass" if passed else failure_class,
                    "pass": passed,
                    "human": contract.get("human", ""),
                }
            )

    by_origin: dict[str, dict[str, Any]] = {}
    for origin in ORIGIN_FILES:
        origin_rows = [row for row in rows if row["originBucket"] == origin]
        by_origin[origin] = {
            "latest_survivor_contracts": len(load_contracts(ORIGIN_FILES[origin])),
            "excluded_common_overlap": excluded[origin],
            "non_common_evaluated": len(origin_rows),
            "mapped": len(origin_rows),
            "passed": sum(1 for row in origin_rows if row["pass"]),
            "failed": sum(1 for row in origin_rows if not row["pass"]),
            "surface_unimplemented_fail": sum(1 for row in origin_rows if row["failureClass"] == "surface_unimplemented"),
            "behavior_fail": sum(1 for row in origin_rows if row["failureClass"] == "behavior"),
        }
    summary = {
        "label": label,
        "domain": "retry_backoff_resilience_policy_engine",
        "common_contracts_excluded": len(load_contracts(COMMON)),
        "total_latest_survivor_contracts": sum(len(load_contracts(path)) for path in ORIGIN_FILES.values()),
        "excluded_common_overlap_total": sum(excluded.values()),
        "non_common_evaluated": len(rows),
        "mapped": len(rows),
        "passed": sum(1 for row in rows if row["pass"]),
        "failed": sum(1 for row in rows if not row["pass"]),
        "surface_unimplemented_fail": sum(1 for row in rows if row["failureClass"] == "surface_unimplemented"),
        "behavior_fail": sum(1 for row in rows if row["failureClass"] == "behavior"),
        "unmapped": 0,
        "by_origin": by_origin,
        "failures_by_capability": dict(Counter(row["capability"] for row in rows if not row["pass"])),
        "passes_by_capability": dict(Counter(row["capability"] for row in rows if row["pass"])),
        "source_hashes": file_hashes(implementation),
    }
    return {"summary": summary, "contracts": rows}


def write_report(result: dict[str, Any], output_json: Path) -> None:
    summary = result["summary"]
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    output_json.with_name(output_json.stem + "_source_hashes.sha256").write_text(
        "\n".join(f"{digest}  {path}" for path, digest in sorted(summary["source_hashes"].items())) + "\n",
        encoding="utf-8",
    )
    lines = [
        f"# {summary['label']} resilience-policy non-common replay",
        "",
        f"- Common contracts excluded: `{summary['common_contracts_excluded']}`",
        f"- Latest survivor contracts across five OSS: `{summary['total_latest_survivor_contracts']}`",
        f"- Excluded as common overlap: `{summary['excluded_common_overlap_total']}`",
        f"- Non-common evaluated: `{summary['non_common_evaluated']}`",
        f"- Mapped: `{summary['mapped']}`",
        f"- Passed: `{summary['passed']}`",
        f"- Failed: `{summary['failed']}`",
        f"- Surface/unimplemented fail: `{summary['surface_unimplemented_fail']}`",
        f"- Behavior fail: `{summary['behavior_fail']}`",
        f"- Unmapped: `{summary['unmapped']}`",
        "",
        "## By OSS",
        "",
        "| OSS | Latest survivors | Common overlap excluded | Non-common evaluated | Passed | Failed | Surface/unimplemented fail | Behavior fail |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for origin, values in summary["by_origin"].items():
        lines.append(
            f"| `{origin}` | {values['latest_survivor_contracts']} | {values['excluded_common_overlap']} | "
            f"{values['non_common_evaluated']} | {values['passed']} | {values['failed']} | "
            f"{values['surface_unimplemented_fail']} | {values['behavior_fail']} |"
        )
    lines.extend(["", "## Passed Capabilities", ""])
    for capability, count in sorted(summary["passes_by_capability"].items()):
        lines.append(f"- `{capability}`: {count}")
    lines.extend(["", "## Top Failure Capabilities", ""])
    for capability, count in Counter(summary["failures_by_capability"]).most_common(40):
        lines.append(f"- `{capability}`: {count}")
    output_json.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementation", type=Path, required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    result = replay(args.label, args.implementation.resolve())
    output_json = OUT / f"{args.label}_noncommon_by_oss.json"
    write_report(result, output_json)
    print(json.dumps(result["summary"], ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
