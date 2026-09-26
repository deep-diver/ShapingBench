"""Strict, executable capability probes for generated implementations.

These probes are a last-resort projection for a contract whose behavioral
scenario cannot enter the target through an equivalent public interface.  A
missing attribute name alone is never a verdict: every candidate interface is
resolved and, when callable, invoked with contract-derived arguments.  The
same target must also pass a domain-specific positive control.
"""

from __future__ import annotations

import inspect
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class CallAttempt:
    interface: str
    resolved: bool
    callable: bool
    invoked: bool
    accepted: bool
    result_type: str | None = None
    exception: str | None = None
    message: str | None = None


def resolve(root: Any, dotted: str) -> Any:
    value = root
    for component in dotted.split("."):
        value = getattr(value, component)
    return value


def invoke_candidates(
    root: Any,
    candidates: Iterable[str],
    argument_factory: Callable[[str, Any], tuple[tuple[Any, ...], dict[str, Any]]],
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for name in dict.fromkeys(candidates):
        try:
            value = resolve(root, name)
        except Exception as exc:
            attempts.append(asdict(CallAttempt(
                interface=name, resolved=False, callable=False, invoked=False,
                accepted=False, exception=type(exc).__name__, message=str(exc)[:500],
            )))
            continue
        if not callable(value):
            attempts.append(asdict(CallAttempt(
                interface=name, resolved=True, callable=False, invoked=False,
                accepted=False, result_type=type(value).__name__,
            )))
            continue
        try:
            args, kwargs = argument_factory(name, value)
            result = value(*args, **kwargs)
            attempts.append(asdict(CallAttempt(
                interface=name, resolved=True, callable=True, invoked=True,
                accepted=True, result_type=type(result).__name__,
            )))
        except Exception as exc:
            attempts.append(asdict(CallAttempt(
                interface=name, resolved=True, callable=True, invoked=True,
                accepted=False, exception=type(exc).__name__, message=str(exc)[:500],
            )))
    return attempts


def public_surface(root: Any) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    for name in sorted(item for item in dir(root) if not item.startswith("_")):
        value = getattr(root, name)
        item: dict[str, Any] = {"kind": type(value).__name__}
        if callable(value):
            try:
                item["signature"] = str(inspect.signature(value))
            except (TypeError, ValueError):
                item["signature"] = "unknown"
        if inspect.isclass(value):
            item["methods"] = sorted(method for method in dir(value) if not method.startswith("_"))
        surface[name] = item
    return surface


def absence_established(attempts: list[dict[str, Any]], positive_control: dict[str, Any]) -> bool:
    return bool(positive_control.get("passed")) and bool(attempts) and not any(
        attempt["accepted"] for attempt in attempts
    )
