#!/usr/bin/env python3
"""Replay croniter DSL contracts against the installed latest croniter package."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from croniter import croniter, croniter_range
import croniter as croniter_module


def stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: stable(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [stable(v) for v in value]
    if isinstance(value, tuple):
        return [stable(v) for v in value]
    if isinstance(value, set):
        return sorted(value)
    return value


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(stable(left), sort_keys=True, separators=(",", ":")) == json.dumps(
        stable(right), sort_keys=True, separators=(",", ":")
    )


def parse_dt(value: Any) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict) and "local" in value and "zone" in value:
        return datetime.fromisoformat(str(value["local"])).replace(tzinfo=ZoneInfo(str(value["zone"])))
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def ctor_kwargs(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in [
        "day_or",
        "max_years_between_matches",
        "is_prev",
        "hash_id",
        "implement_cron_bug",
        "second_at_beginning",
        "expand_from_start_time",
    ]:
        if key in params:
            value = params[key]
            if key == "hash_id" and isinstance(value, dict) and value.get("bytes_hex"):
                value = bytes.fromhex(value["bytes_hex"])
            out[key] = value
    return out


def hash_value(value: Any) -> Any:
    if isinstance(value, dict) and value.get("bytes_hex"):
        return bytes.fromhex(value["bytes_hex"])
    if isinstance(value, str):
        return value.encode("UTF-8")
    return value


def ret_type(name: str | None) -> Any:
    if name == "datetime":
        return datetime
    if name == "float":
        return float
    return None


def make_iter(params: dict[str, Any]) -> croniter:
    return croniter(params["expression"], parse_dt(params.get("start")), **ctor_kwargs(params))


def run(contract: dict[str, Any]) -> dict[str, Any]:
    params = contract.get("params", {})
    op = contract.get("op")
    try:
        if op == "next_dates":
            itr = make_iter(params)
            out = []
            rtype = ret_type(params.get("ret_type")) or datetime
            for _ in range(int(params.get("count", 1))):
                out.append(iso(itr.get_next(rtype, update_current=params.get("update_current", True))))
            return {"dates": out}
        if op == "prev_dates":
            itr = make_iter(params)
            out = []
            rtype = ret_type(params.get("ret_type")) or datetime
            for _ in range(int(params.get("count", 1))):
                out.append(iso(itr.get_prev(rtype, update_current=params.get("update_current", True))))
            return {"dates": out}
        if op == "all_next_dates":
            itr = make_iter(params)
            gen = itr.all_next(ret_type(params.get("ret_type")) or datetime)
            out = []
            for _ in range(int(params.get("count", 1))):
                out.append(iso(next(gen)))
            return {"dates": out}
        if op == "range_dates":
            kwargs = {
                "day_or": params.get("day_or", True),
                "exclude_ends": params.get("exclude_ends", False),
                "second_at_beginning": params.get("second_at_beginning", False),
                "expand_from_start_time": params.get("expand_from_start_time", False),
            }
            dates = croniter_range(
                parse_dt(params.get("start")),
                parse_dt(params.get("stop")),
                params["expression"],
                ret_type=ret_type(params.get("ret_type")),
                **kwargs,
            )
            return {"dates": [iso(v) for v in dates]}
        if op == "expanded_instance":
            itr = make_iter(params)
            return {"expanded": stable(itr.expanded), "nth_weekday": stable(getattr(itr, "nth_weekday_of_month", {}))}
        if op == "expand":
            kwargs = {
                "hash_id": hash_value(params.get("hash_id")),
                "second_at_beginning": params.get("second_at_beginning", False),
                "strict": params.get("strict", False),
            }
            if "from_timestamp" in params:
                kwargs["from_timestamp"] = float(params["from_timestamp"])
            if "strict_year" in params:
                kwargs["strict_year"] = params["strict_year"]
            expanded, nth_weekday = croniter.expand(params["expression"], **kwargs)
            return {"expanded": stable(expanded), "nth_weekday": stable(nth_weekday)}
        if op == "random_invariant":
            itr = make_iter(params)
            dates = [itr.get_next(datetime) for _ in range(int(params.get("count", 2)))]
            if params.get("field") == "dom_range":
                value = all(int(params.get("day_min", 1)) <= d.day <= int(params.get("day_max", 31)) for d in dates)
            elif params.get("field") == "year_range":
                value = all(int(params.get("year_min", 1970)) <= d.year <= int(params.get("year_max", 2099)) for d in dates)
            else:
                value = len({(d.hour, d.minute, d.second) for d in dates}) == 1
            return {"value": bool(value), "count": len(dates)}
        if op == "is_valid":
            kwargs = {
                "hash_id": params.get("hash_id"),
                "second_at_beginning": params.get("second_at_beginning", False),
                "strict": params.get("strict", False),
            }
            if "strict_year" in params:
                kwargs["strict_year"] = params["strict_year"]
            return {"value": bool(croniter.is_valid(params["expression"], **kwargs))}
        if op == "match":
            kwargs = {
                "day_or": params.get("day_or", True),
                "second_at_beginning": params.get("second_at_beginning", False),
            }
            if "precision_in_seconds" in params:
                kwargs["precision_in_seconds"] = params["precision_in_seconds"]
            return {"value": bool(croniter.match(params["expression"], parse_dt(params["date"]), **kwargs))}
        if op == "match_range":
            kwargs = {
                "day_or": params.get("day_or", True),
                "second_at_beginning": params.get("second_at_beginning", False),
            }
            if "precision_in_seconds" in params:
                kwargs["precision_in_seconds"] = params["precision_in_seconds"]
            return {
                "value": bool(
                    croniter.match_range(
                        params["expression"],
                        parse_dt(params["start"]),
                        parse_dt(params["stop"]),
                        **kwargs,
                    )
                )
            }
        if op == "parse_error":
            try:
                if params.get("use_expand", False):
                    croniter.expand(
                        params["expression"],
                        hash_id=params.get("hash_id"),
                        second_at_beginning=params.get("second_at_beginning", False),
                        strict=params.get("strict", False),
                        strict_year=params.get("strict_year"),
                    )
                else:
                    make_iter(params)
                    if params.get("use_next", False):
                        make_iter(params).get_next(datetime)
                return {"error": False}
            except Exception as error:
                return {"error": True, "messageContains": str(error)}
        if op == "timestamp_roundtrip":
            value = parse_dt(params["date"])
            ts = croniter_module.datetime_to_timestamp(value)
            back = croniter_module.timestamp_to_datetime(ts, value)
            return {"timestamp": ts, "datetime": iso(back)}
        return {"error": True, "messageContains": f"unsupported op {op}"}
    except Exception as error:
        return {"error": True, "messageContains": str(error)}


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return value + ["__mutant__"]
    if isinstance(value, dict):
        out = dict(value)
        out["__mutant__"] = True
        return out
    if value is None:
        return "__mutant__"
    return str(value) + "__mutant__"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    for key in [
        "error",
        "value",
        "dates",
        "expanded",
        "nth_weekday",
        "timestamp",
        "datetime",
        "messageContains",
    ]:
        if key in out:
            out[key] = mutate_value(out[key])
            return out
    out["__mutant__"] = True
    return out


def matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    if not isinstance(expected, dict):
        return False
    for key, expected_value in expected.items():
        if key not in actual:
            return False
        actual_value = actual[key]
        if key == "messageContains":
            if str(expected_value) not in str(actual_value):
                return False
        elif not deep_equal(expected_value, actual_value):
            return False
    return True


def main() -> None:
    mode = "fill" if "--fill" in sys.argv else "replay"
    paths = [arg for arg in sys.argv[1:] if arg != "--fill"]
    raw = open(paths[0], encoding="utf-8").read() if paths else sys.stdin.read()
    payload = json.loads(raw)
    rows = payload if isinstance(payload, list) else payload["contracts"]
    if mode == "fill":
        contracts = []
        for contract in rows:
            copy = dict(contract)
            actual = run(contract)
            copy["expected"] = actual
            copy["mutant"] = mutate_expected(actual)
            contracts.append(copy)
        print(json.dumps({"contracts": contracts}, ensure_ascii=True, indent=2))
        return
    results = []
    for contract in rows:
        actual = run(contract)
        replay_passed = matches(contract.get("expected"), actual)
        mutant_passed = replay_passed and matches(contract.get("mutant"), actual)
        results.append(
            {
                "name": contract["name"],
                "version": contract["version"],
                "capability": contract["capability"],
                "op": contract["op"],
                "status": "passed" if replay_passed and not mutant_passed else "failed",
                "replay_passed": replay_passed,
                "mutant_rejected": replay_passed and not mutant_passed,
                "expected": contract.get("expected"),
                "mutant": contract.get("mutant"),
                "actual": actual,
            }
        )
    print(json.dumps({"results": results}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
