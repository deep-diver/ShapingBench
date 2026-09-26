#!/usr/bin/env python3
"""Replay confirmed resilience-policy common contracts against generated solretry."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "contracts" / "resilience_policy" / "common" / "confirmed_common_after_rank4_rank5.json"
OUT = ROOT / "contracts" / "resilience_policy" / "generated"


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


EXCEPTION_TYPES: dict[str, type[BaseException]] = {
    "transient": TransientFailure,
    "fatal": FatalFailure,
    "ignored": IgnoredFailure,
    "runtime": RuntimeFailure,
    "checked": CheckedFailure,
}


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def status_kind(status: str | None) -> str:
    if status == "returned":
        return "returned"
    if status in {"raised", "thrown"}:
        return "failed"
    return status or "unknown"


def retry_notification_count(payload: dict[str, Any]) -> int | None:
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("events"), dict):
        if "retry" in payload["events"]:
            return int(payload["events"]["retry"])
        if isinstance(payload["events"].get("backoff"), list):
            return len(payload["events"]["backoff"])
    if isinstance(payload.get("listeners"), dict) and "retry" in payload["listeners"]:
        return int(payload["listeners"]["retry"])
    if isinstance(payload.get("retryCalls"), list):
        return len(payload["retryCalls"])
    if isinstance(payload.get("onRetryCalls"), list):
        return len(payload["onRetryCalls"])
    return None


def requires_retry_notification(capability: str) -> bool:
    lowered = capability.lower()
    return any(token in lowered for token in ["event", "listener", "onretry"])


def canonical_expected(contract: dict[str, Any]) -> dict[str, Any]:
    expected = contract.get("expected", {})
    out: dict[str, Any] = {}
    if "status" in expected:
        out["status"] = status_kind(expected.get("status"))
    if "attempts" in expected:
        attempts = expected["attempts"]
        out["attempts"] = len(attempts) if isinstance(attempts, list) else attempts
    if "value" in expected and out.get("status") == "returned":
        out["value"] = expected["value"]
    if requires_retry_notification(contract.get("capability", "")):
        count = retry_notification_count(expected)
        if count is not None:
            out["retryNotifications"] = count
    return normalize(out)


def comparable_actual(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return normalize({key: actual.get(key) for key in expected.keys()})


def max_attempts_for(contract: dict[str, Any]) -> int:
    params = contract.get("params", {})
    if "maxAttempts" in params:
        return int(params["maxAttempts"])
    if "maxRetries" in params:
        return int(params["maxRetries"]) + 1
    if params.get("max_tries") is not None:
        return int(params["max_tries"])
    return int(canonical_expected(contract).get("attempts", 3) or 3)


def outcomes_for(contract: dict[str, Any]) -> list[Any]:
    return list(contract.get("params", {}).get("outcomes") or ["ok"])


def handled_kinds(contract: dict[str, Any]) -> list[str]:
    params = contract.get("params", {})
    if "retryExceptions" in params:
        return list(params.get("retryExceptions") or ["transient"])
    if "handle" in params:
        return list(params.get("handle") or ["transient"])
    if "exceptions" in params:
        return list(params.get("exceptions") or ["transient"])
    return ["transient"]


def source_kind(contract: dict[str, Any]) -> str:
    op = contract.get("op")
    params = contract.get("params", {})
    capability = contract.get("capability", "").lower()
    if op in {"retry_call", "on_exception", "async_on_exception"}:
        if params.get("retryOnResult") or params.get("handleResult") or params.get("handleResultPrefix"):
            return "retry_result"
        return "retry_exception"
    if op in {"on_predicate", "async_on_predicate"}:
        return "retry_result"
    if op == "retry_config":
        return "wait_sequence"
    if "retry" in capability:
        return "retry_exception"
    return "unsupported"


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


def make_exception(kind: str, attempt: int) -> BaseException:
    exc_type = EXCEPTION_TYPES.get(kind, TransientFailure)
    return exc_type(f"{kind}-{attempt}")


def run_contract(contract: dict[str, Any], solretry: Any) -> dict[str, Any]:
    attempts = 0
    retry_calls: list[dict[str, Any]] = []
    outcomes = outcomes_for(contract)
    handled = tuple(EXCEPTION_TYPES.get(kind, TransientFailure) for kind in handled_kinds(contract))

    def on_retry(exc: BaseException | None, attempt: int) -> None:
        retry_calls.append(
            {
                "attempt": attempt,
                "errorType": type(exc).__name__ if exc is not None else None,
                "errorMessage": str(exc) if exc is not None else None,
            }
        )

    def fn() -> Any:
        nonlocal attempts
        attempts += 1
        outcome = outcomes[min(attempts - 1, len(outcomes) - 1)]
        if isinstance(outcome, str) and outcome.startswith("throw:"):
            raise make_exception(outcome.split(":", 1)[1], attempts)
        return outcome

    params = contract.get("params", {})
    kwargs: dict[str, Any] = {
        "max_attempts": max_attempts_for(contract),
        "wait": 0,
        "retry_exceptions": handled,
        "on_retry": on_retry,
    }
    if "raise_on_giveup" in params:
        kwargs["raise_on_giveup"] = bool(params["raise_on_giveup"])

    try:
        value = solretry.retry(fn, **kwargs)
        return {
            "status": "returned",
            "value": value,
            "attempts": attempts,
            "retryCalls": retry_calls,
        }
    except BaseException as exc:  # noqa: BLE001 - replay records the observable exception.
        return {
            "status": "raised",
            "errorType": type(exc).__name__,
            "errorMessage": str(exc),
            "attempts": attempts,
            "retryCalls": retry_calls,
        }


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
    data = json.loads(COMMON.read_text(encoding="utf-8"))
    contracts = data["contracts"]
    solretry = import_generated(implementation)
    rows = []
    for contract in contracts:
        expected = canonical_expected(contract)
        raw = run_contract(contract, solretry)
        actual = comparable_actual(
            {
                "status": status_kind(raw.get("status")),
                "attempts": raw.get("attempts"),
                "value": raw.get("value"),
                "retryNotifications": retry_notification_count(raw),
            },
            expected,
        )
        passed = stable_json(actual) == stable_json(expected)
        rows.append(
            {
                "name": contract["name"],
                "origin": contract["project"],
                "capability": contract["capability"],
                "semanticKind": source_kind(contract),
                "human": contract.get("human", ""),
                "expectedCanonical": expected,
                "actualCanonical": actual,
                "actualRaw": raw,
                "pass": passed,
            }
        )
    summary = {
        "label": label,
        "domain": "retry_backoff_resilience_policy_engine",
        "common_contracts": len(contracts),
        "attempted": len(rows),
        "passed": sum(1 for row in rows if row["pass"]),
        "failed": sum(1 for row in rows if not row["pass"]),
        "by_capability": dict(Counter(row["capability"] for row in rows)),
        "failures_by_capability": dict(Counter(row["capability"] for row in rows if not row["pass"])),
        "source_hashes": file_hashes(implementation),
    }
    return {"summary": summary, "contracts": rows}


def write_report(result: dict[str, Any], output_json: Path) -> None:
    summary = result["summary"]
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    output_json.with_suffix(".sha256").write_text(
        "\n".join(f"{digest}  {path}" for path, digest in sorted(summary["source_hashes"].items())) + "\n",
        encoding="utf-8",
    )
    lines = [
        f"# {summary['label']} resilience-policy common replay",
        "",
        f"- Confirmed common contracts: `{summary['common_contracts']}`",
        f"- Attempted: `{summary['attempted']}`",
        f"- Passed: `{summary['passed']}`",
        f"- Failed: `{summary['failed']}`",
        "",
        "## Failures By Capability",
        "",
    ]
    if summary["failures_by_capability"]:
        for capability, count in sorted(summary["failures_by_capability"].items()):
            lines.append(f"- `{capability}`: {count}")
    else:
        lines.append("- none")
    failures = [row for row in result["contracts"] if not row["pass"]]
    if failures:
        lines.extend(["", "## Failed Contracts", ""])
        for row in failures:
            lines.append(f"- `{row['name']}`: {row['human']}")
            lines.append(f"  - expected: `{stable_json(row['expectedCanonical'])}`")
            lines.append(f"  - actual: `{stable_json(row['actualCanonical'])}`")
    output_json.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementation", type=Path, required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()

    result = replay(args.label, args.implementation.resolve())
    output_json = OUT / f"{args.label}_survival_from_resilience_common_78.json"
    write_report(result, output_json)
    print(json.dumps(result["summary"], ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
