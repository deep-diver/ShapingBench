#!/usr/bin/env python3
"""Cross-replay Cron/Schedule Expression contracts across five mature engines."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "cron" / "common"
SOURCES = {
    "cron-parser": ROOT / "contracts" / "cron" / "cron-parser" / "latest_replay_mutant_verified.json",
    "cron-utils": ROOT / "contracts" / "cron" / "cron-utils" / "latest_replay_mutant_verified.json",
    "croniter": ROOT / "contracts" / "cron" / "croniter" / "latest_replay_mutant_verified.json",
}
HIDDEN_TARGETS = ["dragonmantank-cron-expression", "fugit"]
NODE_RUNNER = ROOT / "tools" / "replay" / "cron_cross_node_runner.mjs"
CRON_UTILS_POM = ROOT / "tools" / "replay" / "cron_utils_latest_runner" / "pom.xml"
DRAGON_RUNNER = ROOT / "tools" / "replay" / "dragonmantank_cron_expression_latest_runner" / "replay_dragonmantank_cron_expression.php"
FUGIT_RUNNER = ROOT / "tools" / "replay" / "fugit_latest_runner" / "replay_fugit.rb"
CRONITER_VENDOR = ROOT / ".cache" / "croniter-6.2.4-site"

sys.path.insert(0, str(CRONITER_VENDOR))
from croniter import croniter, croniter_range  # type: ignore  # noqa: E402


def load_rows(path: Path, origin: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("survivor_contracts") if isinstance(data, dict) else None
    if rows is None and isinstance(data, dict):
        rows = data.get("contracts")
    if rows is None:
        rows = data
    out = []
    for index, row in enumerate(rows):
        copy = dict(row)
        copy["origin"] = origin
        copy["cross_id"] = f"{origin}:{index}:{row['name']}"
        out.append(copy)
    return out


def split_expr(expression: str) -> list[str]:
    return str(expression).strip().split()


def clean_expression(expression: str, kind: str | None = None, target: str | None = None) -> tuple[str, dict[str, Any]]:
    parts = [part if part != "?" else "*" for part in split_expr(expression)]
    meta: dict[str, Any] = {}
    if len(parts) == 7 and parts[-1] == "*":
        parts = parts[:-1]
    if target in {"dragonmantank-cron-expression", "fugit"} and len(parts) == 6 and parts[0] == "0":
        parts = parts[1:]
    if target in {"dragonmantank-cron-expression", "fugit"} and len(parts) != 5:
        meta["unsupported"] = f"{target} adapter only accepts 5-field cron after lossless zero-seconds conversion"
    if target == "croniter" and len(parts) in {6, 7}:
        meta["second_at_beginning"] = True
    return " ".join(parts), meta


def infer_cron_utils_params(params: dict[str, Any]) -> dict[str, Any]:
    expression = str(params["expression"])
    parts = split_expr(expression)
    out = dict(params)
    for key in ["start", "stop", "end", "date", "at"]:
        if key in out:
            out[key] = ensure_zoned(out[key])
    if "type" in out or "definition" in out:
        return out
    if len(parts) == 5:
        out["type"] = "UNIX"
    else:
        out["definition"] = "CUSTOM_SECONDS_FIRST_LENIENT"
    return out


def parse_dt(value: Any) -> datetime:
    if isinstance(value, dict):
        value = value.get("local") or value.get("date") or value.get("at")
    text = str(value)
    text = text.split(" rweek=", 1)[0]
    text = re.sub(r"\[[^\]]+\]$", "", text)
    text = re.sub(r"\s+[A-Za-z_]+/[A-Za-z_]+$", "", text)
    text = re.sub(r"\s+[A-Z]{2,5}$", "", text)
    if text.endswith("Z"):
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


def ensure_zoned(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.endswith("Z") or re.search(r"[+-]\d\d:?\d\d(?:\[[^\]]+\])?$", value):
        return value
    if re.match(r"^\d{4}-\d{2}-\d{2}T", value):
        return value + "Z"
    return value


def normalize(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize(value[key]) for key in sorted(value)}
    return value


def normalize_actual(actual: dict[str, Any], target: str | None = None, contract: dict[str, Any] | None = None) -> dict[str, Any]:
    out = dict(actual)
    if target == "fugit" and contract is not None:
        if contract["canonical_op"] == "parse_valid" and "value" in out:
            out = {"value": out["value"] is False}
        elif contract["canonical_op"] == "parse_error" and "value" in out:
            out = {"error": out["value"] is True}
        elif contract["canonical_op"] == "parse_normalize" and "cron" in out:
            out = {"string": out["cron"]}
    if "dates" in out and isinstance(out["dates"], list):
        try:
            out["dates"] = [canonical_time(item) for item in out["dates"]]
        except Exception:
            pass
    for key in ["date", "instant"]:
        if key in out and out[key] is not None:
            try:
                out[key] = canonical_time(out[key])
            except Exception:
                pass
    return out


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(normalize(left), sort_keys=True, ensure_ascii=True) == json.dumps(
        normalize(right), sort_keys=True, ensure_ascii=True
    )


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        if re.search(r"\d", value):
            return re.sub(r"\d+", lambda m: str(int(m.group(0)) + 1), value, count=1)
        return value + "__mutant__"
    if isinstance(value, list):
        return value + ["__mutant__"]
    if isinstance(value, dict):
        out = dict(value)
        key = next(iter(out), "__mutant__")
        out[key] = mutate_value(out.get(key))
        return out
    return "__mutant__"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    for key in ["error", "value", "dates", "date", "instant", "string"]:
        if key in out:
            out[key] = mutate_value(out[key])
            return out
    out["__mutant__"] = True
    return out


def canonical_expected(op: str, expected: dict[str, Any]) -> dict[str, Any]:
    if op in {"next_dates", "prev_dates", "range_dates"} and "dates" in expected:
        return {"dates": [canonical_time(item) for item in expected["dates"]]}
    if op in {"next_dates", "prev_dates"} and "instant" in expected:
        return {"dates": [canonical_time(expected["instant"])] if expected["instant"] else []}
    if op in {"next_dates", "prev_dates"} and "date" in expected:
        return {"dates": [canonical_time(expected["date"])]}
    if op == "match":
        return {"value": bool(expected.get("value"))}
    if op == "match_range":
        return {"value": bool(expected.get("value"))}
    if op == "count_executions":
        return {"value": expected.get("value")}
    if op == "parse_valid":
        return {"value": bool(expected.get("value", True))}
    if op == "parse_error":
        return {"error": bool(expected.get("error", True))}
    if op == "parse_normalize":
        return {"string": str(expected.get("string", expected.get("expression", "")))}
    return dict(expected)


def compile_contract(row: dict[str, Any]) -> dict[str, Any]:
    origin = row["origin"]
    op = row["op"]
    params = dict(row.get("params") or {})
    c_op = "unsupported"
    reason = f"origin op {op} is implementation-specific"

    if origin == "cron-parser":
        options = dict(params.get("options") or {})
        if op in {"next_dates", "take_dates"}:
            c_op = "next_dates"
            params = {"expression": params["expression"], "count": params.get("count", 1), "start": options.get("currentDate")}
            if options.get("tz"):
                params["timezone"] = options["tz"]
        elif op == "reset_next":
            c_op = "next_dates"
            params = {"expression": params["expression"], "count": 1, "start": params.get("resetDate")}
        elif op == "prev_dates":
            c_op = "prev_dates"
            params = {"expression": params["expression"], "count": params.get("count", 1), "start": options.get("currentDate")}
            if options.get("tz"):
                params["timezone"] = options["tz"]
        elif op == "includes_date":
            c_op = "match"
            params = {"expression": params["expression"], "date": params["date"]}
            if options.get("tz"):
                params["timezone"] = options["tz"]
        elif op == "parse_error":
            c_op = "parse_error"
            params = {"expression": params["expression"]}
        elif op == "next_error":
            c_op = "parse_error"
            params = {"expression": params["expression"], "start": options.get("currentDate"), "use_next": True}
        elif op == "stringify":
            c_op = "parse_normalize"
            params = {"expression": params["expression"], "includeSeconds": params.get("includeSeconds", False)}
    elif origin == "cron-utils":
        if op == "next_execution":
            c_op = "next_dates"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition"), "count": 1, "start": params["at"]}
        elif op == "last_execution":
            c_op = "prev_dates"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition"), "count": 1, "start": params["at"]}
        elif op == "execution_dates":
            c_op = "range_dates"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition"), "start": params["at"], "stop": params["end"]}
        elif op == "is_match":
            c_op = "match"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition"), "date": params["at"]}
        elif op == "count_executions":
            c_op = "count_executions"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition"), "start": params["at"], "stop": params["end"]}
        elif op == "parse_valid":
            c_op = "parse_valid"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition")}
        elif op == "parse_error":
            c_op = "parse_error"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition")}
        elif op == "parse_as_string":
            c_op = "parse_normalize"
            params = {"expression": params["expression"], "type": params.get("type"), "definition": params.get("definition")}
    elif origin == "croniter":
        if op in {"next_dates", "all_next_dates"}:
            c_op = "next_dates"
            params = {"expression": params["expression"], "count": params.get("count", 1), "start": params.get("start"), **{k: params[k] for k in ["day_or", "second_at_beginning", "max_years_between_matches", "expand_from_start_time"] if k in params}}
        elif op == "prev_dates":
            c_op = "prev_dates"
            params = {"expression": params["expression"], "count": params.get("count", 1), "start": params.get("start"), **{k: params[k] for k in ["day_or", "second_at_beginning"] if k in params}}
        elif op == "range_dates":
            c_op = "range_dates"
            params = {"expression": params["expression"], "start": params["start"], "stop": params["stop"], **{k: params[k] for k in ["day_or", "second_at_beginning", "expand_from_start_time"] if k in params}}
        elif op == "match":
            c_op = "match"
            params = {"expression": params["expression"], "date": params["date"], **{k: params[k] for k in ["day_or", "second_at_beginning", "precision_in_seconds"] if k in params}}
        elif op == "match_range":
            c_op = "match_range"
            params = {"expression": params["expression"], "start": params["start"], "stop": params["stop"], **{k: params[k] for k in ["day_or", "second_at_beginning", "precision_in_seconds"] if k in params}}
        elif op == "is_valid":
            c_op = "parse_valid"
            params = {"expression": params["expression"], **{k: params[k] for k in ["second_at_beginning", "strict"] if k in params}}
        elif op == "parse_error":
            c_op = "parse_error"
            params = {"expression": params["expression"], "start": params.get("start"), "use_next": params.get("use_next", False), **{k: params[k] for k in ["day_or", "second_at_beginning", "max_years_between_matches"] if k in params}}

    if c_op == "unsupported":
        params = {"reason": reason, "origin_op": op}
        expected = {"error": False}
    else:
        params = {k: v for k, v in params.items() if v is not None}
        expected = canonical_expected(c_op, row.get("expected") or {})
    return {
        "name": row["name"],
        "cross_id": row["cross_id"],
        "origin": origin,
        "version": row["version"],
        "capability": row["capability"],
        "source_op": op,
        "canonical_op": c_op,
        "params": params,
        "expected": expected,
        "mutant": mutate_expected(expected),
        "human": row.get("human"),
    }


def run_subprocess(cmd: list[str], contracts: list[dict[str, Any]], cwd: Path | None = None, env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump({"contracts": contracts}, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        raw = subprocess.check_output(cmd + [str(path)], cwd=cwd or ROOT, text=True, stderr=subprocess.STDOUT, env=env)
        start = raw.find("{")
        return json.loads(raw[start:])["results"]
    finally:
        path.unlink(missing_ok=True)


def run_fill_subprocess(cmd: list[str], contracts: list[dict[str, Any]], cwd: Path | None = None) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(contracts, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        raw = subprocess.check_output(cmd + [str(path)], cwd=cwd or ROOT, text=True, stderr=subprocess.STDOUT)
        start_obj = raw.find("{")
        start_arr = raw.find("[")
        starts = [idx for idx in [start_obj, start_arr] if idx >= 0]
        data = json.loads(raw[min(starts):])
        if isinstance(data, dict) and "contracts" in data:
            return data["contracts"]
        return data
    finally:
        path.unlink(missing_ok=True)


def node_contract(c: dict[str, Any]) -> dict[str, Any]:
    return {**c, "op": c["canonical_op"]}


def croniter_run(c: dict[str, Any]) -> dict[str, Any]:
    params = dict(c["params"])
    if c["canonical_op"] == "unsupported" or "expression" not in params:
        return {"error": True, "unsupported": True, "messageContains": params.get("reason", "unsupported canonical op")}
    expression, meta = clean_expression(params["expression"], params.get("type"), "croniter")
    params["expression"] = expression
    params.update(meta)
    op = c["canonical_op"]
    try:
        if op == "next_dates":
            it = croniter(expression, parse_dt(params.get("start")), day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False), max_years_between_matches=params.get("max_years_between_matches"))
            return {"dates": [it.get_next(datetime).isoformat() for _ in range(int(params.get("count", 1)))]}
        if op == "prev_dates":
            it = croniter(expression, parse_dt(params.get("start")), day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False))
            return {"dates": [it.get_prev(datetime).isoformat() for _ in range(int(params.get("count", 1)))]}
        if op == "range_dates":
            dates = croniter_range(parse_dt(params["start"]), parse_dt(params["stop"]), expression, day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False))
            return {"dates": [item.isoformat() for item in dates]}
        if op == "match":
            return {"value": bool(croniter.match(expression, parse_dt(params.get("date")), day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False)))}
        if op == "match_range":
            return {"value": bool(croniter.match_range(expression, parse_dt(params["start"]), parse_dt(params["stop"]), day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False)))}
        if op == "parse_valid":
            return {"value": bool(croniter.is_valid(expression, second_at_beginning=params.get("second_at_beginning", False)))}
        if op == "parse_error":
            try:
                it = croniter(expression, parse_dt(params.get("start") or "2024-01-01T00:00:00Z"), day_or=params.get("day_or", True), second_at_beginning=params.get("second_at_beginning", False), max_years_between_matches=params.get("max_years_between_matches"))
                if params.get("use_next"):
                    it.get_next(datetime)
                return {"error": False}
            except Exception as error:
                return {"error": True, "messageContains": str(error)}
        if op == "parse_normalize":
            if not croniter.is_valid(expression, second_at_beginning=params.get("second_at_beginning", False)):
                return {"error": True, "messageContains": "invalid expression"}
            return {"string": expression}
        return {"error": True, "unsupported": True, "messageContains": f"unsupported canonical op {op}"}
    except Exception as error:
        return {"error": True, "messageContains": str(error)}


def eval_croniter(contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"name": c["name"], "cross_id": c["cross_id"], "actual": croniter_run(c)} for c in contracts]


def cron_utils_contract(c: dict[str, Any]) -> dict[str, Any]:
    op_map = {
        "next_dates": "cross_next_dates",
        "prev_dates": "cross_prev_dates",
        "range_dates": "cross_range_dates",
        "match": "cross_match",
        "parse_valid": "cross_parse_valid",
        "parse_error": "cross_parse_error",
        "parse_normalize": "cross_parse_normalize",
        "count_executions": "cross_count_executions",
    }
    if c["canonical_op"] == "unsupported" or c["canonical_op"] not in op_map:
        return {**c, "op": "parse_error", "params": {"type": "UNIX", "expression": "$ * * * *"}, "expected": {"error": False}}
    params = infer_cron_utils_params(dict(c["params"]))
    return {**c, "op": op_map[c["canonical_op"]], "params": params}


def dragon_contract(c: dict[str, Any]) -> dict[str, Any]:
    params = dict(c["params"])
    if c["canonical_op"] == "unsupported":
        return {**c, "op": "parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}
    expression, meta = clean_expression(params.get("expression", ""), params.get("type"), "dragonmantank-cron-expression")
    if meta.get("unsupported"):
        return {**c, "op": "parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}
    base = {"expression": expression}
    if c["canonical_op"] == "next_dates":
        return {**c, "op": "multiple_run_dates", "params": {**base, "total": params.get("count", 1), "start": params.get("start"), "allow_current": False}}
    if c["canonical_op"] == "prev_dates":
        return {**c, "op": "multiple_run_dates", "params": {**base, "total": params.get("count", 1), "start": params.get("start"), "invert": True, "allow_current": False}}
    if c["canonical_op"] == "match":
        return {**c, "op": "is_due", "params": {**base, "date": params.get("date")}}
    if c["canonical_op"] == "parse_valid":
        return {**c, "op": "is_valid", "params": base}
    if c["canonical_op"] == "parse_error":
        return {**c, "op": "parse_error", "params": base}
    if c["canonical_op"] == "parse_normalize":
        return {**c, "op": "parse", "params": base}
    return {**c, "op": "parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}


def fugit_contract(c: dict[str, Any]) -> dict[str, Any]:
    params = dict(c["params"])
    if c["canonical_op"] == "unsupported":
        return {**c, "op": "do_parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}
    expression, meta = clean_expression(params.get("expression", ""), params.get("type"), "fugit")
    if meta.get("unsupported"):
        return {**c, "op": "do_parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}
    base = {"expression": expression}
    if c["canonical_op"] == "next_dates":
        return {**c, "op": "next_times", "params": {**base, "count": params.get("count", 1), "start": params.get("start")}}
    if c["canonical_op"] == "prev_dates":
        return {**c, "op": "previous_times", "params": {**base, "count": params.get("count", 1), "start": params.get("start")}}
    if c["canonical_op"] == "match":
        return {**c, "op": "match", "params": {**base, "date": params.get("date")}}
    if c["canonical_op"] == "parse_valid":
        return {**c, "op": "parse_cron_nil", "params": base, "expected": {"value": False}}
    if c["canonical_op"] == "parse_error":
        return {**c, "op": "parse_cron_nil", "params": base}
    if c["canonical_op"] == "parse_normalize":
        return {**c, "op": "parse_cron", "params": base}
    return {**c, "op": "do_parse_error", "params": {"expression": "$ * * * *"}, "expected": {"error": False}}


def eval_target(target: str, contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if target == "cron-parser":
        return run_subprocess(["node", "--no-warnings", str(NODE_RUNNER)], [node_contract(c) for c in contracts])
    if target == "croniter":
        return eval_croniter(contracts)
    if target == "cron-utils":
        translated = [cron_utils_contract(c) for c in contracts]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump({"contracts": translated}, handle, ensure_ascii=True)
            path = Path(handle.name)
        try:
            raw = subprocess.check_output([
                "mvn", "-q", "-f", str(CRON_UTILS_POM), "compile", "exec:java",
                "-Dexec.mainClass=shapingbench.CronUtilsReplay",
                f"-Dexec.args=--fill {path}",
            ], cwd=ROOT, text=True, stderr=subprocess.STDOUT)
            start = raw.find("{")
            rows = json.loads(raw[start:])["contracts"]
            return [{"name": row["name"], "cross_id": row["cross_id"], "actual": row["expected"]} for row in rows]
        finally:
            path.unlink(missing_ok=True)
    if target == "dragonmantank-cron-expression":
        translated = [dragon_contract(c) for c in contracts]
        rows = run_fill_subprocess(["php", str(DRAGON_RUNNER), "--fill"], translated)
        return [{"name": row["name"], "cross_id": row.get("cross_id"), "actual": row["expected"]} for row in rows]
    if target == "fugit":
        translated = [fugit_contract(c) for c in contracts]
        rows = run_fill_subprocess(["ruby", str(FUGIT_RUNNER), "--fill"], translated, cwd=FUGIT_RUNNER.parent)
        return [{"name": row["name"], "cross_id": row.get("cross_id"), "actual": row["expected"]} for row in rows]
    raise ValueError(target)


def evaluate_results(target: str, contracts: list[dict[str, Any]], actual_rows: list[dict[str, Any]]) -> dict[str, Any]:
    actual_by_id = {row["cross_id"]: row["actual"] for row in actual_rows}
    results = []
    survivors = []
    for contract in contracts:
        actual = normalize_actual(actual_by_id.get(contract["cross_id"], {"error": "missing result"}), target, contract)
        expected = contract["expected"]
        mutant = contract["mutant"]
        replay_ok = all(key in actual and deep_equal(actual[key], value) for key, value in expected.items())
        mutant_ok = replay_ok and all(key in actual and deep_equal(actual[key], value) for key, value in mutant.items())
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "cross_id": contract["cross_id"],
            "origin": contract["origin"],
            "capability": contract["capability"],
            "source_op": contract["source_op"],
            "canonical_op": contract["canonical_op"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "expected": expected,
            "mutant": mutant,
            "actual": actual,
        }
        if verified:
            survivors.append(contract)
        results.append(row)
    return {"results": results, "survivors": survivors}


def run_and_eval(target: str, contracts: list[dict[str, Any]]) -> dict[str, Any]:
    actual_rows = eval_target(target, contracts)
    return evaluate_results(target, contracts, actual_rows)


def stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_op = defaultdict(Counter)
    by_origin = defaultdict(Counter)
    failures = Counter()
    for row in results:
        by_op[row["canonical_op"]][row["status"]] += 1
        by_origin[row["origin"]][row["status"]] += 1
        if row["status"] != "passed":
            actual = row.get("actual") or {}
            if actual.get("unsupported"):
                failures["unsupported"] += 1
            elif actual.get("error") is True:
                failures["runtime_error"] += 1
            else:
                failures["semantic_mismatch"] += 1
    return {
        "attempted": len(results),
        "passed": sum(1 for row in results if row["status"] == "passed"),
        "failed": sum(1 for row in results if row["status"] != "passed"),
        "by_canonical_op": {key: dict(value) for key, value in sorted(by_op.items())},
        "by_origin": {key: dict(value) for key, value in sorted(by_origin.items())},
        "failure_kinds": dict(failures.most_common()),
    }


def unique_key(contract: dict[str, Any]) -> str:
    return json.dumps([contract["canonical_op"], contract["params"], contract["expected"]], sort_keys=True, ensure_ascii=True)


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  origin {json.dumps(row['origin'], ensure_ascii=True)}")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  canonical_op {row['canonical_op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_summary_md(summary: dict[str, Any], path: Path) -> None:
    lines = [
        "# Cron Cross-Replay Common",
        "",
        f"Final common: {summary['final_common']}",
        "",
        "## Rank 1/2/3 Cross Replay",
        "",
        "| Origin | Input | Target A | A passed | Target B | B passed | Passed both |",
        "| --- | ---: | --- | ---: | --- | ---: | ---: |",
    ]
    for origin, report in summary["origin_reports"].items():
        a, b = report["targets"]
        lines.append(
            f"| `{origin}` | {report['input']} | `{a}` | {report['per_target'][a]['passed']} | "
            f"`{b}` | {report['per_target'][b]['passed']} | {report['passed_both']} |"
        )
    lines.extend([
        "",
        f"Common candidates before semantic dedupe: {summary['common_candidates_before_dedupe']}",
        f"Semantic duplicates removed: {summary['semantic_duplicates_removed']}",
        f"Common candidates before hidden filter: {summary['common_candidates_before_hidden']}",
        "",
        "## Hidden Filter",
        "",
        "| Target | Input | Passed | Failed |",
        "| --- | ---: | ---: | ---: |",
    ])
    for target, report in summary["hidden_filter"].items():
        lines.append(f"| `{target}` | {report['attempted']} | {report['passed']} | {report['failed']} |")
    lines.extend(["", "## Final By Canonical Op", "", "| Canonical op | Count |", "| --- | ---: |"])
    for op, count in sorted(summary["final_by_canonical_op"].items()):
        lines.append(f"| `{op}` | {count} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    origins_raw = {name: load_rows(path, name) for name, path in SOURCES.items()}
    origins = {name: [compile_contract(row) for row in rows] for name, rows in origins_raw.items()}

    cross_details: dict[str, Any] = {}
    origin_reports: dict[str, Any] = {}
    candidates: list[dict[str, Any]] = []
    for origin, contracts in origins.items():
        targets = [name for name in SOURCES if name != origin]
        per_target = {target: run_and_eval(target, contracts) for target in targets}
        cross_details[origin] = per_target
        passed_ids = [
            {row["cross_id"] for row in per_target[target]["results"] if row["status"] == "passed"}
            for target in targets
        ]
        both = passed_ids[0] & passed_ids[1]
        selected = [contract for contract in contracts if contract["cross_id"] in both]
        candidates.extend(selected)
        origin_reports[origin] = {
            "input": len(contracts),
            "targets": targets,
            "passed_both": len(selected),
            "per_target": {target: stats(per_target[target]["results"]) for target in targets},
            "by_canonical_op_input": dict(Counter(c["canonical_op"] for c in contracts)),
            "by_canonical_op_passed_both": dict(Counter(c["canonical_op"] for c in selected)),
        }

    deduped: dict[str, dict[str, Any]] = {}
    duplicate_count = 0
    for contract in candidates:
        key = unique_key(contract)
        if key in deduped:
            duplicate_count += 1
        else:
            deduped[key] = contract
    common_candidates = list(deduped.values())

    hidden_runs = {target: run_and_eval(target, common_candidates) for target in HIDDEN_TARGETS}
    hidden_pass_ids = [
        {row["cross_id"] for row in hidden_runs[target]["results"] if row["status"] == "passed"}
        for target in HIDDEN_TARGETS
    ]
    final_ids = hidden_pass_ids[0] & hidden_pass_ids[1] if hidden_pass_ids else set()
    final = [contract for contract in common_candidates if contract["cross_id"] in final_ids]

    summary = {
        "domain": "Cron / schedule expression engine",
        "rank_1": "harrisiirak/cron-parser 5.10.0",
        "rank_2": "jmrozanec/cron-utils 9.2.1",
        "rank_3": "pallets-eco/croniter 6.2.4",
        "rank_4_hidden": "dragonmantank/cron-expression 3.6.0",
        "rank_5_hidden": "floraison/fugit 1.13.0",
        "input_latest_survivors": {name: len(rows) for name, rows in origins.items()},
        "origin_reports": origin_reports,
        "common_candidates_before_dedupe": len(candidates),
        "semantic_duplicates_removed": duplicate_count,
        "common_candidates_before_hidden": len(common_candidates),
        "hidden_filter": {target: stats(hidden_runs[target]["results"]) for target in HIDDEN_TARGETS},
        "final_common": len(final),
        "final_by_origin": dict(Counter(contract["origin"] for contract in final)),
        "final_by_canonical_op": dict(Counter(contract["canonical_op"] for contract in final)),
        "final_by_capability": dict(Counter(contract["capability"] for contract in final)),
    }
    out = {
        **summary,
        "common_candidates": common_candidates,
        "final_common_contracts": final,
        "rank_1_2_3_cross_details": cross_details,
        "hidden_filter_details": hidden_runs,
    }
    (OUT_DIR / "cron_cross_common_summary.json").write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "cron_rank1_2_3_cross_details.json").write_text(json.dumps(cross_details, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "cron_hidden_filter_details.json").write_text(json.dumps(hidden_runs, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "cron_final_common.json").write_text(json.dumps({"contracts": final, **summary}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(common_candidates, OUT_DIR / "cron_common_candidates_before_hidden.rpl")
    write_rpl(final, OUT_DIR / "cron_final_common.rpl")
    write_summary_md(summary, OUT_DIR / "cron_cross_common_summary.md")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
