#!/usr/bin/env python3
"""Replay litl/backoff contracts against backoff 2.2.1."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BACKOFF_PATH = ROOT / ".replay" / "backoff_latest"
sys.path.insert(0, str(BACKOFF_PATH))

import backoff  # noqa: E402
import backoff._async as backoff_async  # noqa: E402
import backoff._sync as backoff_sync  # noqa: E402


class TransientError(Exception):
    pass


class FatalError(Exception):
    pass


class OtherError(Exception):
    pass


def err(kind: str) -> Exception:
    if kind == "fatal":
        return FatalError("fatal")
    if kind == "other":
        return OtherError("other")
    return TransientError("transient")


def stable_details(details: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ["tries", "wait", "value"]:
        if key in details:
            value = details[key]
            if key in {"wait"} and isinstance(value, (int, float)):
                value = round(float(value), 6)
            out[key] = value
    if "exception" in details:
        out["exceptionType"] = type(details["exception"]).__name__
        out["exceptionMessage"] = str(details["exception"])
    if "args" in details:
        out["args"] = list(details["args"])
    if "kwargs" in details:
        out["kwargs"] = dict(details["kwargs"])
    return out


def make_wait_gen(params: dict[str, Any]):
    kind = params.get("wait_gen", "constant")
    if kind == "expo":
        return backoff.expo
    if kind == "fibo":
        return backoff.fibo
    if kind == "runtime":
        return backoff.runtime
    return backoff.constant


def wait_kwargs(params: dict[str, Any]) -> dict[str, Any]:
    kind = params.get("wait_gen", "constant")
    if kind == "expo":
        out: dict[str, Any] = {"base": params.get("base", 2), "factor": params.get("factor", 1)}
        if params.get("max_value") is not None:
            out["max_value"] = params["max_value"]
        return out
    if kind == "fibo":
        return {"max_value": params["max_value"]} if params.get("max_value") is not None else {}
    if kind == "runtime":
        source = params.get("runtime_source", "value")
        if source == "exception_attr":
            return {"value": lambda exc: getattr(exc, "retry_after", 0)}
        return {"value": lambda value: value.get("retry_after", 0) if isinstance(value, dict) else value}
    interval = params.get("interval", 1)
    if params.get("interval_callable"):
        interval = lambda: params.get("interval", 1)
    return {"interval": interval}


def maybe_callable(value: Any, enabled: bool):
    if not enabled:
        return value
    return lambda: value


class CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[dict[str, Any]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append({"level": record.levelname, "message": record.getMessage()})


def logger_for(params: dict[str, Any]) -> tuple[Any, CaptureHandler | None]:
    if not params.get("logger_capture"):
        return None, None
    logger = logging.getLogger(f"shapingbench.backoff.{id(params)}")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = CaptureHandler()
    logger.addHandler(handler)
    return logger, handler


def make_jitter(params: dict[str, Any]):
    kind = params.get("jitter", "none")
    if kind == "none":
        return None
    if kind == "identity":
        return lambda value: value
    if kind == "plus_one":
        return lambda value: value + 1
    if kind == "zero":
        return lambda value: 0
    if kind == "nullary":
        return lambda: params.get("nullary_value", 0.25)
    if kind == "full":
        return backoff.full_jitter
    if kind == "random":
        return backoff.random_jitter
    return None


def next_outcome(outcomes: list[Any], index: int) -> Any:
    if not outcomes:
        return "ok"
    return outcomes[min(index, len(outcomes) - 1)]


def apply_outcome(outcome: Any) -> Any:
    if isinstance(outcome, str) and outcome.startswith("throw:"):
        ex = err(outcome.split(":", 1)[1])
        if "retry_after=" in outcome:
            try:
                ex.retry_after = float(outcome.rsplit("retry_after=", 1)[1])
            except ValueError:
                ex.retry_after = 0
        raise ex
    return outcome


def outcome_status(fn) -> dict[str, Any]:
    try:
        value = fn()
        return {"status": "returned", "value": value}
    except Exception as exc:
        return {"status": "raised", "errorType": type(exc).__name__, "errorMessage": str(exc)}


def run_wait_sequence(params: dict[str, Any]) -> dict[str, Any]:
    gen = make_wait_gen(params)(**wait_kwargs(params))
    next(gen)
    sends = params.get("sends", [None])
    values = []
    for send in sends:
        try:
            values.append(gen.send(send))
        except StopIteration:
            values.append("__stop__")
            break
    return {"values": values}


def run_on_exception(params: dict[str, Any], async_mode: bool = False) -> dict[str, Any]:
    outcomes = params.get("outcomes", ["ok"])
    attempts = {"count": 0}
    waits: list[float] = []
    events: dict[str, list[dict[str, Any]]] = {"success": [], "backoff": [], "giveup": []}

    def sleep(seconds: float) -> None:
        waits.append(round(float(seconds), 6))

    async def async_sleep(seconds: float) -> None:
        waits.append(round(float(seconds), 6))

    def on_success(details):
        events["success"].append(stable_details(details))

    def on_backoff(details):
        events["backoff"].append(stable_details(details))

    def on_giveup(details):
        events["giveup"].append(stable_details(details))

    def giveup(exc: Exception) -> bool:
        return params.get("giveup_on") == type(exc).__name__ or (params.get("giveup_message") and params["giveup_message"] in str(exc))

    logger, log_handler = logger_for(params)
    decorator = backoff.on_exception(
        make_wait_gen(params),
        tuple({"transient": TransientError, "fatal": FatalError, "other": OtherError}.get(k, TransientError) for k in params.get("exceptions", ["transient"])),
        max_tries=maybe_callable(params.get("max_tries"), params.get("max_tries_callable", False)),
        max_time=maybe_callable(params.get("max_time"), params.get("max_time_callable", False)),
        jitter=make_jitter(params),
        giveup=giveup,
        on_success=on_success,
        on_backoff=on_backoff,
        on_giveup=on_giveup,
        raise_on_giveup=params.get("raise_on_giveup", True),
        logger=logger,
        backoff_log_level=getattr(logging, params.get("backoff_log_level", "INFO")),
        giveup_log_level=getattr(logging, params.get("giveup_log_level", "ERROR")),
        **wait_kwargs(params),
    )

    if async_mode:
        async def target(*args, **kwargs):
            idx = attempts["count"]
            attempts["count"] += 1
            return apply_outcome(next_outcome(outcomes, idx))

        async def invoke():
            old_sleep = backoff_async.asyncio.sleep
            backoff_async.asyncio.sleep = async_sleep
            try:
                wrapped = decorator(target)
                return await wrapped(*params.get("args", []), **params.get("kwargs", {}))
            finally:
                backoff_async.asyncio.sleep = old_sleep

        status = outcome_status(lambda: asyncio.run(invoke()))
    else:
        def target(*args, **kwargs):
            idx = attempts["count"]
            attempts["count"] += 1
            return apply_outcome(next_outcome(outcomes, idx))

        old_sleep = backoff_sync.time.sleep
        backoff_sync.time.sleep = sleep
        try:
            wrapped = decorator(target)
            status = outcome_status(lambda: wrapped(*params.get("args", []), **params.get("kwargs", {})))
        finally:
            backoff_sync.time.sleep = old_sleep

    out = {**status, "attempts": attempts["count"], "waits": waits, "events": events}
    if log_handler is not None:
        out["logs"] = log_handler.records
    return out


def run_on_predicate(params: dict[str, Any], async_mode: bool = False) -> dict[str, Any]:
    outcomes = params.get("outcomes", ["ok"])
    attempts = {"count": 0}
    waits: list[float] = []
    events: dict[str, list[dict[str, Any]]] = {"success": [], "backoff": [], "giveup": []}

    def pred(value: Any) -> bool:
        mode = params.get("predicate", "falsey")
        if mode == "equals":
            return value == params.get("predicate_value")
        if mode == "dict_retry_after":
            return isinstance(value, dict) and value.get("retry_after", 0) > 0
        return not bool(value)

    def on_success(details):
        events["success"].append(stable_details(details))

    def on_backoff(details):
        events["backoff"].append(stable_details(details))

    def on_giveup(details):
        events["giveup"].append(stable_details(details))

    def sleep(seconds: float) -> None:
        waits.append(round(float(seconds), 6))

    async def async_sleep(seconds: float) -> None:
        waits.append(round(float(seconds), 6))

    logger, log_handler = logger_for(params)
    decorator = backoff.on_predicate(
        make_wait_gen(params),
        predicate=pred,
        max_tries=maybe_callable(params.get("max_tries"), params.get("max_tries_callable", False)),
        max_time=maybe_callable(params.get("max_time"), params.get("max_time_callable", False)),
        jitter=make_jitter(params),
        on_success=on_success,
        on_backoff=on_backoff,
        on_giveup=on_giveup,
        logger=logger,
        backoff_log_level=getattr(logging, params.get("backoff_log_level", "INFO")),
        giveup_log_level=getattr(logging, params.get("giveup_log_level", "ERROR")),
        **wait_kwargs(params),
    )

    if async_mode:
        async def target(*args, **kwargs):
            idx = attempts["count"]
            attempts["count"] += 1
            return apply_outcome(next_outcome(outcomes, idx))

        async def invoke():
            old_sleep = backoff_async.asyncio.sleep
            backoff_async.asyncio.sleep = async_sleep
            try:
                wrapped = decorator(target)
                return await wrapped(*params.get("args", []), **params.get("kwargs", {}))
            finally:
                backoff_async.asyncio.sleep = old_sleep

        status = outcome_status(lambda: asyncio.run(invoke()))
    else:
        def target(*args, **kwargs):
            idx = attempts["count"]
            attempts["count"] += 1
            return apply_outcome(next_outcome(outcomes, idx))

        old_sleep = backoff_sync.time.sleep
        backoff_sync.time.sleep = sleep
        try:
            wrapped = decorator(target)
            status = outcome_status(lambda: wrapped(*params.get("args", []), **params.get("kwargs", {})))
        finally:
            backoff_sync.time.sleep = old_sleep

    out = {**status, "attempts": attempts["count"], "waits": waits, "events": events}
    if log_handler is not None:
        out["logs"] = log_handler.records
    return out


def run_decorator_sequence(params: dict[str, Any], predicate_mode: bool = False) -> dict[str, Any]:
    calls = []
    for outcomes in params.get("calls", []):
        call_params = dict(params)
        call_params["outcomes"] = outcomes
        call_params.pop("calls", None)
        calls.append(run_on_predicate(call_params) if predicate_mode else run_on_exception(call_params))
    return {"calls": calls}


def run_package_metadata(params: dict[str, Any]) -> dict[str, Any]:
    return {"version": getattr(backoff, "__version__", None), "exports": sorted(name for name in dir(backoff) if not name.startswith("_"))}


def run_contract(contract: dict[str, Any]) -> dict[str, Any]:
    op = contract.get("op")
    params = contract.get("params", {})
    if op == "wait_sequence":
        return run_wait_sequence(params)
    if op == "on_exception":
        return run_on_exception(params)
    if op == "on_predicate":
        return run_on_predicate(params)
    if op == "async_on_exception":
        return run_on_exception(params, async_mode=True)
    if op == "async_on_predicate":
        return run_on_predicate(params, async_mode=True)
    if op == "on_exception_sequence":
        return run_decorator_sequence(params, predicate_mode=False)
    if op == "on_predicate_sequence":
        return run_decorator_sequence(params, predicate_mode=True)
    if op == "package_metadata":
        return run_package_metadata(params)
    return {"status": "unsupported", "error": f"unknown op {op}"}


def main() -> int:
    fill = False
    path = None
    for arg in sys.argv[1:]:
        if arg == "--fill":
            fill = True
        else:
            path = arg
    if path is None:
        raise SystemExit("missing contract path")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    contracts = data if isinstance(data, list) else data.get("contracts", [])
    out = []
    for row in contracts:
        row = dict(row)
        try:
            actual = run_contract(row)
        except Exception as exc:
            actual = {"status": "raised", "errorType": type(exc).__name__, "errorMessage": str(exc)}
        row["actual"] = actual
        if fill:
            row["expected"] = actual
        out.append(row)
    print(json.dumps({"contracts": out}, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
