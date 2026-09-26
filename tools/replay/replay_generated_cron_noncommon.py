#!/usr/bin/env python3
"""Replay Cron non-common contracts against a generated Python `solcron` library."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "cron" / "generated"
COMMON_JSON = ROOT / "contracts" / "cron" / "common" / "cron_final_common.json"
SOURCE_FILES = {
    "cron-parser": ROOT / "contracts" / "cron" / "cron-parser" / "latest_replay_mutant_verified.json",
    "cron-utils": ROOT / "contracts" / "cron" / "cron-utils" / "latest_replay_mutant_verified.json",
    "croniter": ROOT / "contracts" / "cron" / "croniter" / "latest_replay_mutant_verified.json",
    "dragonmantank-cron-expression": ROOT / "contracts" / "cron" / "dragonmantank-cron-expression" / "latest_replay_mutant_verified.json",
    "fugit": ROOT / "contracts" / "cron" / "fugit" / "latest_replay_mutant_verified.json",
}

sys.path.insert(0, str(ROOT / "tools" / "replay"))
import cron_cross_common as cross  # type: ignore  # noqa: E402
import replay_generated_cron_common as common_eval  # type: ignore  # noqa: E402


FIELD_ATTRS = {
    "second": "seconds",
    "seconds": "seconds",
    "minute": "minutes",
    "minutes": "minutes",
    "hour": "hours",
    "hours": "hours",
    "day": "days_of_month",
    "day_of_month": "days_of_month",
    "monthday": "days_of_month",
    "monthdays": "days_of_month",
    "month": "months",
    "months": "months",
    "weekday": "days_of_week",
    "day_of_week": "days_of_week",
    "weekdays": "days_of_week",
    "year": "years",
    "years": "years",
}
FIELD_ORDER = ["seconds", "minutes", "hours", "days_of_month", "months", "days_of_week", "years"]


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    ignored = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "target", "venv", ".venv", "dist", "build"}
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


def load_solcron(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    for name in list(sys.modules):
        if name == "solcron" or name.startswith("solcron."):
            del sys.modules[name]
    return importlib.import_module("solcron")


def load_raw(path: Path, origin: str) -> list[dict[str, Any]]:
    return cross.load_rows(path, origin)


def normalize(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in sorted(value.items())}
    return value


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(normalize(left), sort_keys=True, ensure_ascii=True) == json.dumps(normalize(right), sort_keys=True, ensure_ascii=True)


def parse_dt(value: Any) -> datetime:
    if isinstance(value, dict):
        value = value.get("local") or value.get("date") or value.get("at")
    text = str(value)
    text = text.split(" rweek=", 1)[0]
    text = re.sub(r"\[[^\]]+\]$", "", text)
    text = re.sub(r"\s+[A-Za-z_]+/[A-Za-z_]+$", "", text)
    text = re.sub(r"\s+[A-Z]{2,5}$", "", text)
    text = re.sub(r"(?<=[+-]\d\d:\d\d)\s+[+-]\d\d$", "", text)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = datetime.fromisoformat(text + "+00:00")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).replace(microsecond=0)


def canonical_time(value: Any) -> str:
    return parse_dt(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_dates(values: list[Any]) -> list[str]:
    return [canonical_time(value) for value in values]


def options_for(params: dict[str, Any]) -> dict[str, Any]:
    options = common_eval.options_for(params)
    if "second_at_beginning" in params:
        options["seconds_at_beginning"] = bool(params["second_at_beginning"])
    if params.get("second_field_position") == "last":
        options["second_field_position"] = "last"
    return options


def sol_date(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return canonical_time(value)
    except Exception:
        return value


def sol_params(params: dict[str, Any]) -> dict[str, Any]:
    out = dict(params)
    for key in ["start", "stop", "end", "date", "at"]:
        if key in out:
            out[key] = sol_date(out[key])
    return out


def with_cron_parser_default_zone(contract: dict[str, Any]) -> dict[str, Any]:
    if contract["canonical_op"] in {"next_dates", "prev_dates", "match"} and "timezone" not in contract["params"]:
        copy = json.loads(json.dumps(contract))
        copy["params"]["timezone"] = "Asia/Seoul"
        copy["mutant"] = mutant_expected(copy["expected"])
        return copy
    return contract


def include_seconds(params: dict[str, Any], expected: dict[str, Any]) -> bool:
    return common_eval.include_seconds(params, expected)


def mutant_expected(expected: dict[str, Any]) -> dict[str, Any]:
    return cross.mutate_expected(expected)


def compact_params(params: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in params.items() if value is not None}


def base_contract(row: dict[str, Any], canonical_op: str, params: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row["name"],
        "cross_id": row["cross_id"],
        "origin": row["origin"],
        "version": row.get("version"),
        "capability": row.get("capability"),
        "source_op": row.get("op"),
        "canonical_op": canonical_op,
        "params": compact_params(params),
        "expected": expected,
        "mutant": mutant_expected(expected),
        "human": row.get("human"),
    }


def unsupported_contract(row: dict[str, Any], reason: str) -> dict[str, Any]:
    return base_contract(row, "public_surface_missing", {"reason": reason, "origin_op": row.get("op")}, {"supported": True})


def source_options(params: dict[str, Any]) -> dict[str, Any]:
    return dict(params.get("options") or {})


def compile_cron_parser(row: dict[str, Any]) -> dict[str, Any]:
    op = row["op"]
    params = dict(row.get("params") or {})
    expected = row.get("expected") or {}
    options = source_options(params)
    if op == "fields_values":
        c_params = {"expression": params["expression"], "fields": params.get("fields"), "timezone": options.get("tz")}
        return base_contract(row, "fields_values", c_params, {"fields": expected.get("fields", {})})
    if op == "crontab_parse":
        return unsupported_contract(row, "crontab file parsing API is outside the generated library surface")
    if op == "has_next_prev":
        return base_contract(row, "has_next_prev", {"expression": params["expression"], "start": options.get("currentDate")}, {"value": bool(expected.get("value", True))})
    compiled = cross.compile_contract(row)
    if compiled["canonical_op"] != "unsupported":
        return with_cron_parser_default_zone(compiled)
    return unsupported_contract(row, compiled["params"].get("reason", "unsupported"))


def compile_cron_utils(row: dict[str, Any]) -> dict[str, Any]:
    op = row["op"]
    params = dict(row.get("params") or {})
    expected = row.get("expected") or {}
    if op == "time_to_next":
        return base_contract(row, "time_to_next", {"expression": params["expression"], "start": params["at"]}, {"durationSeconds": expected.get("durationSeconds")})
    if op == "time_from_last":
        return base_contract(row, "time_from_last", {"expression": params["expression"], "start": params["at"]}, {"durationSeconds": expected.get("durationSeconds")})
    if op == "equivalent":
        return base_contract(row, "equivalent", {"left": params.get("left"), "right": params.get("right")}, {"value": bool(expected.get("value"))})
    if op == "weekday_map":
        return unsupported_contract(row, "weekday constant mapper API is outside the generated library surface")
    if op == "map":
        return unsupported_contract(row, "cron definition mapper API is outside the generated library surface")
    if op == "describe":
        return unsupported_contract(row, "human-language cron description API is outside the generated library surface")
    if op == "builder_predefined":
        return unsupported_contract(row, "cron builder/predefined expression API is outside the generated library surface")
    compiled = cross.compile_contract(row)
    return compiled if compiled["canonical_op"] != "unsupported" else unsupported_contract(row, compiled["params"].get("reason", "unsupported"))


def compile_croniter(row: dict[str, Any]) -> dict[str, Any]:
    op = row["op"]
    params = dict(row.get("params") or {})
    expected = row.get("expected") or {}
    if op == "expand":
        return base_contract(row, "croniter_expand", {"expression": params["expression"], "second_at_beginning": params.get("second_at_beginning")}, expected)
    if op == "expanded_instance":
        return base_contract(row, "croniter_expanded_instance", {"expression": params["expression"], "start": params.get("start"), "second_at_beginning": params.get("second_at_beginning")}, expected)
    if op == "random_invariant":
        return unsupported_contract(row, "randomized R-expression semantics are outside the generated library surface")
    compiled = cross.compile_contract(row)
    return compiled if compiled["canonical_op"] != "unsupported" else unsupported_contract(row, compiled["params"].get("reason", "unsupported"))


def compile_dragon(row: dict[str, Any]) -> dict[str, Any]:
    op = row["op"]
    params = dict(row.get("params") or {})
    expected = row.get("expected") or {}
    if op == "parse":
        return base_contract(row, "dragon_parse", {"expression": params["expression"]}, expected)
    if op == "next_run":
        return base_contract(row, "next_date_maybe_current", {"expression": params["expression"], "start": params["start"], "allow_current": params.get("allow_current", False)}, {"date": canonical_time(expected.get("date"))})
    if op == "previous_run":
        return base_contract(row, "prev_date_maybe_current", {"expression": params["expression"], "start": params["start"], "allow_current": params.get("allow_current", False)}, {"date": canonical_time(expected.get("date"))})
    if op == "multiple_run_dates":
        return base_contract(row, "multiple_run_dates", {"expression": params["expression"], "start": params["start"], "total": params.get("total", 1), "allow_current": params.get("allow_current", False), "invert": params.get("invert", False)}, {"dates": canonical_dates(expected.get("dates", []))})
    if op == "is_due":
        return base_contract(row, "match", {"expression": params["expression"], "date": params["date"]}, {"value": bool(expected.get("value"))})
    if op == "is_valid":
        return base_contract(row, "parse_valid", {"expression": params["expression"]}, {"value": bool(expected.get("value"))})
    if op in {"parse_error", "alias_error"}:
        return base_contract(row, "parse_error", {"expression": params["expression"]}, {"error": True})
    if op == "field_validate":
        return base_contract(row, "field_validate", {"field": params["field"], "value": params["value"]}, {"value": bool(expected.get("value"))})
    if op == "field_satisfied":
        return base_contract(row, "field_satisfied", {"field": params["field"], "value": params["value"], "date": params.get("date")}, {"value": bool(expected.get("value"))})
    if op == "field_range":
        return base_contract(row, "field_range", {"field": params["field"], "expression": params["expression"], "max": params.get("max")}, {"range": expected.get("range")})
    if op in {"set_part", "set_expression"}:
        return base_contract(row, "dragon_mutation_surface", params, expected)
    return unsupported_contract(row, f"{op} is an internal field/control API outside the generated library surface")


def split_fugit_timezone(expression: str) -> tuple[str, str | None]:
    parts = str(expression).strip().split()
    if len(parts) >= 6 and re.match(r"^[A-Za-z_]+/[A-Za-z_]+$|^UTC$", parts[-1]):
        return " ".join(parts[:-1]), parts[-1]
    return str(expression), None


def compile_fugit(row: dict[str, Any]) -> dict[str, Any]:
    op = row["op"]
    params = dict(row.get("params") or {})
    expected = row.get("expected") or {}
    expression = params.get("expression")
    cron_expression, zone = split_fugit_timezone(expression) if expression is not None else (None, None)
    base = {"expression": cron_expression, "timezone": zone}
    if op == "parse_cron":
        c_expected = {key: expected[key] for key in ["cron", "array", "hash", "zone", "timezone"] if key in expected}
        return base_contract(row, "fugit_parse_cron", base, c_expected)
    if op == "next_times":
        return base_contract(row, "next_dates", {**base, "start": params.get("start"), "count": params.get("count", 1)}, {"dates": canonical_dates(expected.get("dates", []))})
    if op == "previous_times":
        return base_contract(row, "prev_dates", {**base, "start": params.get("start"), "count": params.get("count", 1)}, {"dates": canonical_dates(expected.get("dates", []))})
    if op == "match":
        return base_contract(row, "match", {**base, "date": params.get("date")}, {"value": bool(expected.get("value"))})
    if op == "within":
        return base_contract(row, "range_dates", {**base, "start": params.get("start"), "stop": params.get("stop")}, {"dates": canonical_dates(expected.get("dates", []))})
    if op in {"parse_cron_nil", "do_parse_error"}:
        return base_contract(row, "parse_error" if expected.get("value", True) else "parse_valid", base, {"error": True} if expected.get("value", True) else {"value": True})
    if op == "seconds":
        return base_contract(row, "fugit_seconds", base, {"seconds": expected.get("seconds")})
    if op == "equality":
        return base_contract(row, "equivalent", {"left": params.get("left"), "right": params.get("right")}, {"value": bool(expected.get("value"))})
    if op in {"parse_kind", "parse_cronish", "determine_type"}:
        return unsupported_contract(row, "natural-language or type-detection parser API is outside the generated library surface")
    if op in {"rough_frequency", "brute_frequency"}:
        return base_contract(row, "frequency_seconds", base, {"seconds": expected.get("seconds")})
    return unsupported_contract(row, f"{op} is outside the generated library surface")


def compile_any(row: dict[str, Any]) -> dict[str, Any]:
    if row["origin"] == "cron-parser":
        return compile_cron_parser(row)
    if row["origin"] == "cron-utils":
        return compile_cron_utils(row)
    if row["origin"] == "croniter":
        return compile_croniter(row)
    if row["origin"] == "dragonmantank-cron-expression":
        return compile_dragon(row)
    if row["origin"] == "fugit":
        return compile_fugit(row)
    return unsupported_contract(row, "unknown origin")


def unique_key(contract: dict[str, Any]) -> str:
    return json.dumps([contract["canonical_op"], contract["params"], contract["expected"]], sort_keys=True, ensure_ascii=True)


def common_keys() -> set[str]:
    data = json.loads(COMMON_JSON.read_text(encoding="utf-8"))
    return {unique_key(contract) for contract in data["contracts"]}


def field_values(solcron: Any, expression: str, options: dict[str, Any]) -> dict[str, list[int]]:
    cron = solcron.parse(expression, options=options)
    return {field: sorted(getattr(cron, attr)) for field, attr in FIELD_ATTRS.items() if hasattr(cron, attr)}


def selected_fields(solcron: Any, expression: str, fields: list[str] | None, options: dict[str, Any]) -> dict[str, list[int]]:
    values = field_values(solcron, expression, options)
    if fields:
        return {field: values[FIELD_ATTRS[field]] for field in fields if field in FIELD_ATTRS}
    return {field: values[attr] for field, attr in FIELD_ATTRS.items() if field == attr}


def synth_expression(field: str, value: str) -> str:
    parts = ["*", "*", "*", "*", "*"]
    idx = {"minute": 0, "hour": 1, "day_of_month": 2, "month": 3, "day_of_week": 4, "weekday": 4}.get(field)
    if idx is None:
        raise ValueError(f"unknown field {field}")
    parts[idx] = str(value)
    return " ".join(parts)


def attrs_to_fugit_shape(solcron: Any, expression: str, options: dict[str, Any]) -> dict[str, Any]:
    cron = solcron.parse(expression, options=options)
    seconds = sorted(cron.seconds)
    minutes = None if len(cron.minutes) == 60 else sorted(cron.minutes)
    hours = None if len(cron.hours) == 24 else sorted(cron.hours)
    monthdays = None if len(cron.days_of_month) == 31 else sorted(cron.days_of_month)
    months = None if len(cron.months) == 12 else sorted(cron.months)
    weekdays = None if set(cron.days_of_week) in ({0, 1, 2, 3, 4, 5, 6}, {0, 1, 2, 3, 4, 5, 6, 7}) else sorted(cron.days_of_week)
    return {
        "cron": solcron.normalize(expression, include_seconds=cron.has_seconds, options=options),
        "array": [seconds, minutes, hours, monthdays, months, weekdays],
        "hash": {
            "seconds": seconds,
            "minutes": minutes,
            "hours": hours,
            "monthdays": monthdays,
            "months": months,
            "weekdays": weekdays,
        },
        "zone": options.get("timezone"),
        "timezone": options.get("timezone"),
    }


def run_range(solcron: Any, expression: str, start: Any, stop: Any, options: dict[str, Any]) -> list[str]:
    start_dt = parse_dt(start)
    stop_dt = parse_dt(stop)
    if start_dt > stop_dt:
        cursor = (start_dt + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[str] = []
        for _ in range(10000):
            prev = solcron.prev_dates(expression, cursor, 1, options=options)[0]
            prev_dt = parse_dt(prev)
            if prev_dt < stop_dt:
                break
            if prev_dt <= start_dt:
                out.append(canonical_time(prev))
            cursor = prev
        return out
    cursor = (start_dt - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out: list[str] = []
    for _ in range(10000):
        nxt = solcron.next_dates(expression, cursor, 1, options=options)[0]
        nxt_dt = parse_dt(nxt)
        if nxt_dt > stop_dt:
            break
        if nxt_dt >= start_dt:
            out.append(canonical_time(nxt))
        cursor = nxt
    return out


def run_contract(solcron: Any, contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    op = contract["canonical_op"]
    params = sol_params(contract.get("params") or {})
    expression = params.get("expression")
    options = options_for(params)
    if op == "public_surface_missing":
        return {"supported": False, "reason": params.get("reason")}
    if op in {"next_dates", "prev_dates", "match", "parse_valid", "parse_error", "parse_normalize"}:
        return common_eval.run_contract(solcron, {**contract, "params": params}, expected)
    if op == "fields_values":
        return {"fields": selected_fields(solcron, expression, params.get("fields"), options)}
    if op == "has_next_prev":
        solcron.next_dates(expression, params.get("start") or "2024-01-01T00:00:00Z", 1, options=options)
        solcron.prev_dates(expression, params.get("start") or "2024-01-01T00:00:00Z", 1, options=options)
        return {"value": True}
    if op == "time_to_next":
        nxt = solcron.next_dates(expression, params["start"], 1, options=options)[0]
        return {"durationSeconds": int((parse_dt(nxt) - parse_dt(params["start"])).total_seconds())}
    if op == "time_from_last":
        prev = solcron.prev_dates(expression, params["start"], 1, options=options)[0]
        return {"durationSeconds": int((parse_dt(params["start"]) - parse_dt(prev)).total_seconds())}
    if op == "range_dates":
        return {"dates": run_range(solcron, expression, params["start"], params["stop"], options)}
    if op == "match_range":
        return {"value": bool(run_range(solcron, expression, params["start"], params["stop"], options))}
    if op == "count_executions":
        return {"value": len(run_range(solcron, expression, params["start"], params["stop"], options))}
    if op == "equivalent":
        return {"value": solcron.normalize(params["left"], options=options) == solcron.normalize(params["right"], options=options)}
    if op == "croniter_expand":
        cron = solcron.parse(expression, options=options)
        expanded = [sorted(cron.minutes), sorted(cron.hours), sorted(cron.days_of_month), sorted(cron.months), sorted(cron.days_of_week)]
        if cron.has_seconds:
            expanded.append(sorted(cron.seconds))
        return {"expanded": expanded, "nth_weekday": {}}
    if op == "croniter_expanded_instance":
        return run_contract(solcron, {**contract, "canonical_op": "croniter_expand"}, expected)
    if op == "dragon_parse":
        normalized = solcron.normalize(expression, include_seconds=len(str(expression).split()) == 6, options=options)
        return {"expression": expression, "parts": normalized.split(), "string": normalized, "missingPart": None}
    if op == "next_date_maybe_current":
        if params.get("allow_current") and solcron.match(expression, params["start"], options=options):
            return {"date": canonical_time(params["start"])}
        return {"date": canonical_time(solcron.next_dates(expression, params["start"], 1, options=options)[0])}
    if op == "prev_date_maybe_current":
        if params.get("allow_current") and solcron.match(expression, params["start"], options=options):
            return {"date": canonical_time(params["start"])}
        return {"date": canonical_time(solcron.prev_dates(expression, params["start"], 1, options=options)[0])}
    if op == "multiple_run_dates":
        count = int(params.get("total", 1))
        direction = "prev_dates" if params.get("invert") else "next_dates"
        dates: list[str] = []
        cursor = params["start"]
        if params.get("allow_current") and solcron.match(expression, cursor, options=options):
            dates.append(canonical_time(cursor))
            count -= 1
        if count > 0:
            dates.extend(getattr(solcron, direction)(expression, cursor, count, options=options))
        return {"dates": canonical_dates(dates)}
    if op == "field_validate":
        return {"value": bool(solcron.is_valid(synth_expression(params["field"], params["value"]), options=options))}
    if op == "field_satisfied":
        return {"value": bool(solcron.match(synth_expression(params["field"], params["value"]), params["date"], options=options))}
    if op == "field_range":
        attr = FIELD_ATTRS.get(params["field"])
        if attr is None:
            raise ValueError(f"unknown field {params['field']}")
        cron = solcron.parse(synth_expression(params["field"], params["expression"]), options=options)
        return {"range": sorted(getattr(cron, attr))}
    if op == "dragon_mutation_surface":
        return {"supported": False, "reason": "mutable cron expression part setters are outside the generated library surface"}
    if op == "fugit_parse_cron":
        return attrs_to_fugit_shape(solcron, expression, options)
    if op == "fugit_seconds":
        cron = solcron.parse(expression, options=options)
        return {"seconds": None if len(cron.seconds) == 60 else sorted(cron.seconds)}
    if op == "frequency_seconds":
        dates = solcron.next_dates(expression, "2024-01-01T00:00:00Z", 2, options=options)
        return {"seconds": int((parse_dt(dates[1]) - parse_dt(dates[0])).total_seconds())}
    return {"supported": False, "reason": f"unsupported evaluator op {op}"}


def expected_matches(solcron: Any, contract: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, dict[str, Any], list[str]]:
    try:
        actual = run_contract(solcron, contract, expected)
    except Exception as exc:
        return False, {"error": type(exc).__name__, "message": str(exc)}, [f"{type(exc).__name__}: {exc}"]
    misses = []
    for key, value in expected.items():
        if key not in actual:
            misses.append(f"{key}: missing")
        elif not deep_equal(actual[key], value):
            misses.append(f"{key}: expected {value!r}, got {actual[key]!r}")
    return not misses, actual, misses


def failure_kind(row: dict[str, Any]) -> str:
    if row["status"] == "passed":
        return "passed"
    if row["canonical_op"] == "public_surface_missing":
        return "public_surface_missing"
    actual = row.get("actual") or {}
    if actual.get("supported") is False:
        return "public_surface_missing"
    if "error" in actual:
        return "runtime_error"
    return "semantic_mismatch"


def evaluate(solcron: Any, contracts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = []
    survivors = []
    for contract in contracts:
        replay_ok, actual, misses = expected_matches(solcron, contract, contract["expected"])
        mutant_ok, mutant_actual, mutant_misses = (
            expected_matches(solcron, contract, contract["mutant"])
            if replay_ok
            else (False, {}, ["mutant not evaluated because replay failed"])
        )
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "origin": contract["origin"],
            "version": contract.get("version"),
            "capability": contract.get("capability"),
            "source_op": contract.get("source_op"),
            "canonical_op": contract["canonical_op"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "expected": contract["expected"],
            "mutant": contract["mutant"],
            "actual": actual,
            "mutant_actual": mutant_actual,
            "misses": misses,
            "mutant_misses": mutant_misses,
        }
        row["failure_kind"] = failure_kind(row)
        if verified:
            survivors.append(contract)
        results.append(row)
    return results, survivors


def stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_op = defaultdict(Counter)
    by_source_op = defaultdict(Counter)
    kinds = Counter()
    for row in rows:
        by_op[row["canonical_op"]][row["status"]] += 1
        by_source_op[row.get("source_op") or "unknown"][row["status"]] += 1
        kinds[row["failure_kind"]] += 1
    return {
        "attempted": len(rows),
        "passed": sum(1 for row in rows if row["status"] == "passed"),
        "failed": sum(1 for row in rows if row["status"] != "passed"),
        "failure_kinds": dict(kinds),
        "by_canonical_op": {key: dict(value) for key, value in sorted(by_op.items())},
        "by_source_op": {key: dict(value) for key, value in sorted(by_source_op.items())},
    }


def build_noncommon() -> dict[str, list[dict[str, Any]]]:
    common = common_keys()
    out: dict[str, list[dict[str, Any]]] = {}
    for origin, path in SOURCE_FILES.items():
        compiled = [compile_any(row) for row in load_raw(path, origin)]
        keep = []
        for contract in compiled:
            key = unique_key(contract)
            if key in common:
                continue
            keep.append(contract)
        out[origin] = keep
    return out


def write_md(summary: dict[str, Any], results_by_oss: dict[str, list[dict[str, Any]]], path: Path) -> None:
    lines = [
        f"# Generated Cron Non-Common Replay, {summary['label']}",
        "",
        f"Implementation: `{summary['implementation']}`",
        f"Common removed: {summary['common_removed_count']}",
        "",
        "| OSS | Latest survivors | Non-common attempted | Passed | Failed | Public surface missing | Runtime errors | Semantic mismatches |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for origin, item in summary["by_oss"].items():
        kinds = item["failure_kinds"]
        lines.append(
            f"| `{origin}` | {item['latest_survivors']} | {item['attempted']} | {item['passed']} | {item['failed']} | "
            f"{kinds.get('public_surface_missing', 0)} | {kinds.get('runtime_error', 0)} | {kinds.get('semantic_mismatch', 0)} |"
        )
    lines.extend(["", "## Passed By OSS And Source Op", "", "| OSS | Source op | Passed | Failed |", "| --- | --- | ---: | ---: |"])
    for origin, item in summary["by_oss"].items():
        for op, counts in item["by_source_op"].items():
            lines.append(f"| `{origin}` | `{op}` | {counts.get('passed', 0)} | {counts.get('failed', 0)} |")
    lines.extend(["", "## Failure Samples", "", "| OSS | Contract | Source op | Kind | Miss |", "| --- | --- | --- | --- | --- |"])
    for origin, rows in results_by_oss.items():
        for row in [item for item in rows if item["status"] != "passed"][:8]:
            miss = "; ".join(row.get("misses") or row.get("mutant_misses") or [])
            lines.append(f"| `{origin}` | `{row['name']}` | `{row.get('source_op')}` | `{row['failure_kind']}` | {miss} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="solcron_gpt56sol_high_iter5_hinted_20260831")
    args = parser.parse_args()
    label = safe_label(args.label)
    impl_dir = args.implementation_dir.resolve()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    noncommon = build_noncommon()
    solcron = load_solcron(impl_dir)
    results_by_oss: dict[str, list[dict[str, Any]]] = {}
    survivors_by_oss: dict[str, list[dict[str, Any]]] = {}
    for origin, contracts in noncommon.items():
        rows, survivors = evaluate(solcron, contracts)
        results_by_oss[origin] = rows
        survivors_by_oss[origin] = survivors

    latest_counts = {origin: len(load_raw(path, origin)) for origin, path in SOURCE_FILES.items()}
    summary = {
        "label": label,
        "implementation": str(impl_dir),
        "common_contracts": str(COMMON_JSON),
        "common_removed_count": len(common_keys()),
        "by_oss": {
            origin: {
                "latest_survivors": latest_counts[origin],
                **stats(rows),
            }
            for origin, rows in results_by_oss.items()
        },
    }
    out = {**summary, "results_by_oss": results_by_oss, "survivors_by_oss": survivors_by_oss}
    out_json = OUT_DIR / f"{label}_noncommon_by_oss.json"
    out_md = OUT_DIR / f"{label}_noncommon_by_oss.md"
    out_hashes = OUT_DIR / f"{label}_noncommon_source_hashes.sha256"
    out_json.write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_md(summary, results_by_oss, out_md)
    write_hashes(impl_dir, out_hashes)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
