#!/usr/bin/env python3
"""Extract dragonmantank/cron-expression contracts and verify them on v3.6.0."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / ".cache" / "dragonmantank-cron-expression-src-20260831"
CHANGELOG = SRC / "CHANGELOG.md"
OUT_DIR = ROOT / "contracts" / "cron" / "dragonmantank-cron-expression"
RUNNER = ROOT / "tools" / "replay" / "dragonmantank_cron_expression_latest_runner" / "replay_dragonmantank_cron_expression.php"
PHP = Path("/opt/homebrew/bin/php")
LATEST = "v3.6.0"
PROJECT = "dragonmantank/cron-expression"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:84]


def fetch_github_releases() -> list[dict[str, Any]]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cache = OUT_DIR / "release_notes.github.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    req = urllib.request.Request(
        "https://api.github.com/repos/dragonmantank/cron-expression/releases?per_page=100",
        headers={"User-Agent": "ShapingBench"},
    )
    with urllib.request.urlopen(req, timeout=30) as res:
        data = json.loads(res.read().decode("utf-8"))
    cache.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
    return data


def fetch_packagist_versions() -> list[str]:
    cache = OUT_DIR / "packagist_versions.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))["stable_versions"]
    req = urllib.request.Request(
        "https://repo.packagist.org/p2/dragonmantank/cron-expression.json",
        headers={"User-Agent": "ShapingBench"},
    )
    with urllib.request.urlopen(req, timeout=30) as res:
        data = json.loads(res.read().decode("utf-8"))
    versions = [pkg["version"] for pkg in data["packages"]["dragonmantank/cron-expression"]]
    stable = [v for v in versions if not any(marker in v.lower() for marker in ["dev", "alpha", "beta", "rc"])]
    cache.write_text(json.dumps({"stable_versions": stable}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return stable


def git_tags() -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(SRC), "tag", "--sort=v:refname"],
        check=True,
        text=True,
        capture_output=True,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def parse_changelog() -> dict[str, str]:
    text = CHANGELOG.read_text(encoding="utf-8")
    matches = list(re.finditer(r"^## \[?([0-9][0-9A-Za-z.]*|Unreleased)\]?[^\n]*\n", text, flags=re.M))
    out: dict[str, str] = {}
    for idx, match in enumerate(matches):
        version = match.group(1)
        if version == "Unreleased":
            continue
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        out[version] = text[start:end].strip()
    return out


def add(rows: list[dict[str, Any]], version: str, capability: str, op: str, params: dict[str, Any], evidence: str, human: str) -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"dragonmantank_cron_expression_{version.replace('.', '_').replace('v', 'v_')}_{slug(capability)}_{key}",
            "version": version,
            "project": PROJECT,
            "domain": "cron_schedule_expression",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence,
            "human": human,
        }
    )


def parse(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str = "cron_expression.parsing") -> None:
    add(rows, version, capability, "parse", {"expression": expr}, evidence, f"Parse and round-trip expression `{expr}`.")


def valid(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "is_valid", {"expression": expr}, evidence, f"Validity of `{expr}` is observable.")


def invalid(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **extra: Any) -> None:
    params = {"expression": expr}
    params.update(extra)
    add(rows, version, capability, "parse_error", params, evidence, f"`{expr}` is rejected.")


def due(rows: list[dict[str, Any]], version: str, expr: str, date: Any, evidence: str, capability: str, **extra: Any) -> None:
    params = {"expression": expr, "date": date}
    params.update(extra)
    add(rows, version, capability, "is_due", params, evidence, f"`{expr}` due check at `{date}`.")


def next_run(rows: list[dict[str, Any]], version: str, expr: str, start: Any, evidence: str, capability: str, **extra: Any) -> None:
    params = {"expression": expr, "start": start}
    params.update(extra)
    add(rows, version, capability, "next_run", params, evidence, f"Next run for `{expr}` after `{start}`.")


def previous_run(rows: list[dict[str, Any]], version: str, expr: str, start: Any, evidence: str, capability: str, **extra: Any) -> None:
    params = {"expression": expr, "start": start}
    params.update(extra)
    add(rows, version, capability, "previous_run", params, evidence, f"Previous run for `{expr}` before `{start}`.")


def multiple(rows: list[dict[str, Any]], version: str, expr: str, start: Any, total: int, evidence: str, capability: str, **extra: Any) -> None:
    params = {"expression": expr, "start": start, "total": total}
    params.update(extra)
    add(rows, version, capability, "multiple_run_dates", params, evidence, f"{total} run dates for `{expr}` from `{start}`.")


def field_validate(rows: list[dict[str, Any]], version: str, field: str, value: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "field_validate", {"field": field, "value": value}, evidence, f"{field} accepts/rejects `{value}`.")


def field_satisfied(rows: list[dict[str, Any]], version: str, field: str, value: str, date: str, evidence: str, capability: str, **extra: Any) -> None:
    params = {"field": field, "value": value, "date": date}
    params.update(extra)
    add(rows, version, capability, "field_satisfied", params, evidence, f"{field} `{value}` satisfaction at `{date}`.")


def field_range(rows: list[dict[str, Any]], version: str, field: str, expr: str, max_value: int, evidence: str, capability: str) -> None:
    add(rows, version, capability, "field_range", {"field": field, "expression": expr, "max": max_value}, evidence, f"{field} range expansion for `{expr}`.")


def field_increment(rows: list[dict[str, Any]], version: str, field: str, date: str, evidence: str, capability: str, **extra: Any) -> None:
    params = {"field": field, "date": date}
    params.update(extra)
    add(rows, version, capability, "field_increment", params, evidence, f"{field} increments `{date}`.")


def build_candidates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    ev = "1.0.0 README/core API exposes parsing, getExpression, stringification, due, next, previous, and multiple run dates."
    for expr in ["*/5 * * * *", "1 2-4 * 4,5,6 */3", "0 0 * * MON,SUN", "0 0 * JAN 0", "0-12/4 * * * *"]:
        parse(rows, "v1.0.0", expr, ev)
    for expr, start in [
        ("*/2 */2 * * *", "2015-08-10 21:47:27"),
        ("* * * * *", "2015-08-10 21:50:37"),
        ("* 20,22 * * *", "2015-08-10 21:50:00"),
        ("7-9 * */9 * *", "2015-08-10 22:02:33"),
        ("1 * * * 7", "2015-08-10 21:47:27"),
        ("* * * * 0", "2011-06-15 23:09:00"),
        ("* * * * 7", "2011-06-15 23:09:00"),
        ("0 0 * * 0-4", "2011-06-15 23:09:00"),
        ("0 0 * * 7-4", "2011-06-15 23:09:00"),
        ("0 0 * * 3-7", "2011-06-18 23:09:00"),
        ("0-12/4 * * * *", "2011-06-20 12:04:00"),
        ("4-59/3 * * * *", "2011-06-20 12:06:00"),
    ]:
        next_run(rows, "v1.0.0", expr, start, ev, "cron_expression.next_run.core", allow_current=True)
        due(rows, "v1.0.0", expr, start, ev, "cron_expression.is_due.core")
    for expr, start in [
        ("* * * * *", "2015-08-10 21:51:00"),
        ("* */2 * * *", "2015-08-10 23:00:00"),
        ("* * * */2 *", "2015-08-10 21:51:00"),
        ("@weekly", "2013-03-17 00:00:00"),
        ("0 0 27 JAN *", "2011-08-22 00:00:00"),
    ]:
        previous_run(rows, "v1.0.0", expr, start, ev, "cron_expression.previous_run.core")
    multiple(rows, "v1.0.0", "*/2 * * * *", "2008-11-09 00:00:00", 4, ev, "cron_expression.multiple_run_dates", allow_current=True)
    for nth in [0, 1, 2, 3]:
        next_run(rows, "v1.0.0", "@weekly", "2008-11-09 00:00:00", ev, "cron_expression.nth_next_run", nth=nth, allow_current=True)

    ev = "1.0.3 release fixes extra whitespace separators, static factory, hyphen ranges, and timezone/default-date behavior."
    for expr in ["*\t*\t*\t*\t*\t", "*  *  *  *  *  ", "* \t * \t * \t * \t * \t"]:
        parse(rows, "v1.0.3", expr, ev, "cron_expression.whitespace_separators")
    for expr, start in [
        ("3-59/15 6-12 */15 1 2-5", "2017-01-08 00:00:00"),
        ("0 0 * * 4-7", "2011-07-19 00:00:00"),
        ("0 0 * * 2-7", "2011-06-18 23:09:00"),
    ]:
        next_run(rows, "v1.0.3", expr, start, ev, "cron_expression.range_and_step_regression")

    ev = "1.1.0 release fixes non-hourly timezone offsets, valid expression checks, max iteration count, DateTimeImmutable, and last weekday loop behavior."
    for timezone in ["UTC", "Europe/Amsterdam", "Asia/Tokyo"]:
        due(rows, "v1.1.0", "0 15 * * 3", "2014-01-01 15:00:00", ev, "cron_expression.is_due.timezone_argument", timezone=timezone, date_timezone=timezone)
    for expr in ["* * * 1", "* * * * 1", "* * * 13 *", "90 * * * *", "0 24 1 12 0"]:
        valid(rows, "v1.1.0", expr, ev, "cron_expression.static_validation")
    multiple(rows, "v1.1.0", "0 0 12 1 *", "2015-04-28 00:00:00", 9, ev, "cron_expression.max_iteration_count", allow_current=True, max_iterations=2000)
    previous_run(rows, "v1.1.0", "0 7 * * *", "2017-10-17 10:00:00", ev, "cron_expression.timezone_in_datetime", date_timezone="Europe/London", timezone="America/New_York", allow_current=True, with_zone_name=True)
    for expr, start in [
        ("* * * * 5L", "2011-07-01 00:00:00"),
        ("* * * * 6L", "2011-07-01 00:00:00"),
        ("* * * * 7L", "2011-07-01 00:00:00"),
        ("* * * 1 5L", "2011-12-25 00:00:00"),
    ]:
        next_run(rows, "v1.1.0", expr, start, ev, "cron_expression.last_weekday_of_month")

    ev = "1.2.0 release handles zero-step syntax better and tightens day-of-month validation."
    for expr in ["*/0 * * * *", "0 0 0 * *", "0 0 32 * *", "0 0 31 * *"]:
        valid(rows, "v1.2.0", expr, ev, "cron_expression.day_of_month_and_step_validation")
    for value in ["1", "01", "*", "L", "5W", "?", "5W,L", "0", "1."]:
        field_validate(rows, "v1.2.0", "day_of_month", value, ev, "field.day_of_month.validation")

    ev = "2.0.0 release drops the year field, reworks validation, and fixes steps for one-indexed fields like month."
    for expr in ["0 0 1 1 * 2020", "0 0 1 1 *", "0 0 * */2 *", "* * * */123 *"]:
        valid(rows, "v2.0.0", expr, ev, "cron_expression.year_field_and_month_steps")
    next_run(rows, "v2.0.0", "* * * */123 *", "2014-05-07 00:00:00", ev, "cron_expression.month_large_step_wraparound")
    field_range(rows, "v2.0.0", "month", "*/123", 12, ev, "field.month.large_step_wraparound")
    for value in ["12", "*", "*/10,2,1-12", "1.fix-regexp", "1/10", "JAN", "Jan", "jan"]:
        field_validate(rows, "v2.0.0", "month", value, ev, "field.month.validation")

    ev = "2.1.0 release fixes timezone behavior, ranges and lists in same expression, and literal conversion regressions."
    for expr in ["2,17,35,47 5-7,11-13 * * *", "0 0 * * MON-FRI", "0 1 15 JUL mon,Wed,FRi"]:
        valid(rows, "v2.1.0", expr, ev, "cron_expression.range_list_and_literals_validation")
        next_run(rows, "v2.1.0", expr, "2019-11-14 00:00:00", ev, "cron_expression.range_list_and_literals_next")
    for expr, max_value in [("5-7,11-13", 23), ("*/6", 23), ("5-13/6", 23), ("1-4,11-14/2,21-27/3,40-59/10", 59)]:
        field_range(rows, "v2.1.0", "hour", expr, max_value, ev, "field.hour.range_list_expansion")

    ev = "2.2.0 release fixes steps larger than field ranges and leading zero validation."
    for expr in ["00 * * * *", "01 * * * *", "* 00 * * *", "* 01 * * *", "0-59/65 10 * * *", "41-59/24 5 * * *"]:
        valid(rows, "v2.2.0", expr, ev, "cron_expression.leading_zero_and_large_step_validation")
        next_run(rows, "v2.2.0", expr, "2021-08-25 10:01:00", ev, "cron_expression.leading_zero_and_large_step_next", allow_current=True)
    for field, value in [("minute", "00"), ("minute", "01"), ("hour", "00"), ("hour", "01"), ("minute", "0/5"), ("minute", "1/10")]:
        field_validate(rows, "v2.2.0", field, value, ev, "field.leading_zero_and_range_start_validation")

    ev = "2.3.0 release accepts DateTimeInterface/DateTimeImmutable and reports human-readable field positions."
    next_run(rows, "v2.3.0", "@weekly", "2019-03-03 08:00:00", ev, "cron_expression.datetime_interface_input")
    invalid(rows, "v2.3.0", "0 * * * * ? *", ev, "cron_expression.human_readable_field_position")

    ev = "3.0.0 release changes DOM+DOW resolution from AND to OR and improves literals/seconds/timezone behavior."
    multiple(rows, "v3.0.0", "30 0 1 * 1", "2019-10-10 23:20:00", 5, ev, "cron_expression.dom_dow_or_semantics", allow_current=True)
    next_run(rows, "v3.0.0", "0 0 13 * 3", "2021-07-15 00:00:00", ev, "cron_expression.dom_dow_closest_next")
    previous_run(rows, "v3.0.0", "0 0 13 * 3", "2021-07-15 00:00:00", ev, "cron_expression.dom_dow_closest_previous")
    for expr in ["0 1 15 JUL mon,Wed,FRi", "0 1 15 jul mon,Wed,FRi", "@Weekly", "@WEEKLY", "@WeeklY"]:
        next_run(rows, "v3.0.0", expr, "2019-11-14 00:00:00", ev, "cron_expression.case_insensitive_literals_and_aliases")
    invalid(rows, "v3.0.0", "0 0 * * 1/10", ev, "cron_expression.single_number_range_rejected")
    next_run(rows, "v3.0.0", "* * * * *", "2011-09-27 10:10:54", ev, "cron_expression.seconds_are_dropped")

    ev = "3.0.1 release fixes casted step ranges and missing checks for question marks in DOM/DOW."
    for expr in ["0 12 * * ?", "0 12 ? * *", "0 8 ? * ?", "? * * * *", "* ? * * *", "* * * ? *"]:
        valid(rows, "3.0.1", expr, ev, "cron_expression.question_mark_validation")
    next_run(rows, "3.0.1", "0 12 * * ?", "2020-08-20 00:00:00", ev, "cron_expression.question_mark_dow_next")
    next_run(rows, "3.0.1", "0 12 ? * *", "2020-08-20 00:00:00", ev, "cron_expression.question_mark_dom_next")

    ev = "3.1.0 release adds CronExpression::getParts()."
    add(rows, "v3.1.0", "cron_expression.get_parts", "get_parts", {"expression": "0 22 * * 1-5"}, ev, "Return expression parts as an ordered array.")
    add(rows, "v3.1.0", "cron_expression.set_part", "set_part", {"initial": "0 22 * * 1-5", "position": 1, "value": "23"}, ev, "Mutating an expression part is observable.")
    add(rows, "v3.1.0", "cron_expression.set_expression", "set_expression", {"initial": "0 22 * * 1-5", "expression": "15 1 * * MON"}, ev, "Replacing an expression is observable.")

    ev = "3.2.1 release fixes mixtures of ranges, steps, lists, inverted multiple-date order, and DST handling."
    for expr in ["1,3,5-7,11-15/1,17-22/2,23 * * * *", "2,17,35,47 5-7,11-13 * * *", "0 20 L 6,12 ?", "0 20 L 6,12 0-6"]:
        valid(rows, "v3.2.1", expr, ev, "cron_expression.complex_range_step_list_validation")
        next_run(rows, "v3.2.1", expr, "2022-08-20 03:44:02", ev, "cron_expression.complex_range_step_list_next")
    multiple(rows, "v3.2.1", "*/2 * * * *", "2008-11-09 00:06:00", 4, ev, "cron_expression.inverted_multiple_order", invert=True, allow_current=True)

    ev = "3.2.3 and 3.2.4 releases change minute/hour/day-of-week increments to handle DST transitions better."
    for expr, zone, start in [
        ("0 1 * * 0", "Europe/London", "2021-03-21 02:00+00:00"),
        ("15 2 * * 0", "America/Winnipeg", "2021-03-08 08:15-06:00"),
        ("* * * * 2", "Europe/Berlin", "2020-10-23 15:31:45"),
        ("30 07 * * *", "America/New_York", "2023-03-10 08:00-05:00"),
        ("0 10 * * *", "America/Chicago", "2025-03-08 09:00-06:00"),
    ]:
        next_run(rows, "v3.2.4", expr, start, ev, "cron_expression.dst_transition_next", timezone=zone, date_timezone=zone, with_zone_name=True)
        previous_run(rows, "v3.2.4", expr, start, ev, "cron_expression.dst_transition_previous", timezone=zone, date_timezone=zone, with_zone_name=True)
    for field, date, zone in [
        ("minute", "2021-03-28 01:59:00", "Europe/Berlin"),
        ("minute", "2021-03-28 00:59:00", "Europe/London"),
        ("day_of_month", "2021-03-28 01:59:00", "Europe/Berlin"),
        ("day_of_month", "2021-03-28 00:59:00", "Europe/London"),
        ("month", "2011-03-31 11:59:59", "America/St_Johns"),
    ]:
        field_increment(rows, "v3.2.4", field, date, ev, "field.dst_and_offset_increment", date_timezone=zone, with_zone_name=True)

    ev = "3.2.2 release fixes small ranges with large steps and wraparound high-bound handling."
    for expr in ["0-59/59 10 * * *", "0-59/65 10 * * *", "41-59/24 5 * * *", "4-59/3 * * * *"]:
        next_run(rows, "v3.2.2", expr, "2021-08-25 10:01:00", ev, "cron_expression.large_step_high_bound")

    ev = "3.2.0 release adds @midnight alias and optimizes multiple run dates."
    for expr in ["@midnight", "@hourly", "@daily", "@weekly", "@monthly", "@yearly", "@annually"]:
        parse(rows, "v3.2.0", expr, ev, "cron_expression.built_in_aliases")
        next_run(rows, "v3.2.0", expr, "2021-04-10 00:00:00", ev, "cron_expression.built_in_alias_next", allow_current=True)

    ev = "3.3.0 release adds custom expression aliases and adjusts DOM/DOW when one side is * or ?."
    add(rows, "v3.3.0", "cron_expression.custom_alias_lifecycle", "alias_lifecycle", {"alias": "@every_custom_minute", "expression": "* * * * *"}, ev, "Register, resolve, unregister, and reject an unregistered custom alias.")
    for alias, expression, action in [
        ("every", "* * * * *", "register"),
        ("@daily", "* * * * *", "register"),
        ("@évery", "* * * * *", "register"),
        ("@bad_expression", "foobar", "register"),
        ("@daily", "", "unregister"),
    ]:
        add(rows, "v3.3.0", "cron_expression.custom_alias_errors", "alias_error", {"alias": alias, "expression": expression, "action": action}, ev, "Invalid custom alias operation fails.")
    for expr in ["0 20 L 6,12 ?", "0 20 * 6,12 *", "0 20 L 6,12 0-6"]:
        for nth in [0, 1, 2]:
            next_run(rows, "v3.3.0", expr, "2022-08-20 03:44:02", ev, "cron_expression.dom_dow_star_question_resolution", nth=nth)
        previous_run(rows, "v3.3.0", expr, "2022-08-20 03:44:02", ev, "cron_expression.dom_dow_star_question_resolution_prev")

    ev = "3.3.3 release fixes question marks in both DOM/DOW and minute sorting for next execution."
    invalid(rows, "v3.3.3", "0 8 ? * ?", ev, "cron_expression.reject_both_dom_dow_question")
    for expr in ["3,1,2 * * * *", "2,1,3 * * * *", "41-59/24 5 * * *"]:
        next_run(rows, "v3.3.3", expr, "2024-08-10 00:00:00", ev, "cron_expression.minute_sorting_next_execution")

    ev = "v3.5.0 release fixes skipped run after daylight-saving turnover point; v3.6.0 preserves behavior on PHP 8.2+."
    dst_multiple = [
        ("0 1 * * 0", "Europe/London", "2021-03-13 00:00+00:00", 5),
        ("30 07 * * *", "America/New_York", "2023-03-10 08:00-05:00", 3),
        ("0 10 * * *", "America/Chicago", "2025-03-08 09:00-06:00", 3),
        ("30 */1 * * *", "America/Chicago", "2025-03-09 00:00-06:00", 4),
        ("30 */1 * * *", "America/Chicago", "2025-11-02 00:00-05:00", 4),
        ("30 2 * * *", "America/Chicago", "2025-03-08 01:30-06:00", 3),
        ("0 */2 * * *", "Europe/London", "2021-03-27 22:00+00:00", 5),
        ("0 1-23/2 * * *", "Europe/London", "2021-03-27 23:00+00:00", 5),
        ("@hourly", "America/Asuncion", "2021-03-27 22:00-03:00", 5),
        ("@hourly", "America/Asuncion", "2020-10-03 22:00-04:00", 5),
    ]
    for expr, zone, start, total in dst_multiple:
        multiple(rows, "v3.5.0", expr, start, total, ev, "cron_expression.dst_multiple_run_dates", timezone=zone, date_timezone=zone, allow_current=True, with_zone_name=True)

    ev = "Public field classes expose validation/satisfaction behavior for special DOM/DOW syntax used in release fixes."
    for value in ["1", "01", "00", "*", "?", "*/3,1,1-12", "SUN-2", "1.", "MON#1", "TUE#2", "WED#3", "THU#4", "FRI#5", "SAT#1", "SUN#3", "MON#1,MON#3", "mon,", "mon-", "*/2,", "-mon", ",1", "*-", ",-"]:
        field_validate(rows, "v3.5.0", "day_of_week", value, ev, "field.day_of_week.validation")
    for value, date in [
        ("0-2", "2011-09-04 00:00:00"),
        ("6-0", "2011-09-04 00:00:00"),
        ("SUN", "2014-04-20 00:00:00"),
        ("SUN#3", "2014-04-20 00:00:00"),
        ("0#3", "2014-04-20 00:00:00"),
        ("7#3", "2014-04-20 00:00:00"),
        ("FRIL", "2018-12-28 00:00:00"),
        ("5L", "2018-12-28 00:00:00"),
        ("FRIL", "2018-12-21 00:00:00"),
        ("5L", "2018-12-21 00:00:00"),
        ("?", "2024-01-01 00:00:00"),
    ]:
        field_satisfied(rows, "v3.5.0", "day_of_week", value, date, ev, "field.day_of_week.satisfaction")
    for value, date in [("?", "2024-01-01 00:00:00"), ("L", "2024-02-29 00:00:00"), ("LW", "2024-03-29 00:00:00"), ("5W", "2024-04-05 00:00:00")]:
        field_satisfied(rows, "v3.5.0", "day_of_month", value, date, ev, "field.day_of_month.satisfaction")
    for field, date in [
        ("minute", "2011-03-15 11:15:00"),
        ("hour", "2011-03-15 11:15:00"),
        ("day_of_week", "2011-03-15 11:15:00"),
        ("day_of_month", "2011-03-15 11:15:00"),
        ("month", "2011-03-15 11:15:00"),
    ]:
        field_increment(rows, "v3.5.0", field, date, ev, "field.basic_increment")
        field_increment(rows, "v3.5.0", field, date, ev, "field.basic_decrement", invert=True)

    return dedupe(rows)


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = stable_json([row["op"], row["params"]])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def run_php(args: list[str], payload: Any) -> Any:
    proc = subprocess.run(
        [str(PHP), str(RUNNER), *args],
        input=json.dumps(payload, ensure_ascii=True),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr + proc.stdout[-2000:])
    return json.loads(proc.stdout)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def write_rpl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = []
    for row in rows:
        lines.append(f"contract {row['name']} {{")
        lines.append(f"  domain: {row['domain']}")
        lines.append(f"  project: {row['project']}")
        lines.append(f"  release: {row['version']}")
        lines.append(f"  capability: {row['capability']}")
        lines.append(f"  op: {row['op']}")
        lines.append(f"  params: {stable_json(row['params'])}")
        if "expected" in row:
            lines.append(f"  expect: {stable_json(row['expected'])}")
        lines.append("}")
    path.write_text("\n\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    releases = fetch_github_releases()
    packagist_versions = fetch_packagist_versions()
    tags = git_tags()
    changelog = parse_changelog()
    candidates = build_candidates()

    filled = run_php(["--fill"], candidates)
    viable = [
        row
        for row in filled
        if not (isinstance(row.get("expected"), dict) and row["expected"].get("error") is True and row["op"] not in {"parse_error", "alias_error"})
    ]

    replay = run_php([], viable)
    if not replay["ok"]:
        bad = [r["name"] for r in replay["results"] if not r["ok"]][:10]
        raise RuntimeError(f"replay failed for {bad}")

    mutant = run_php(["--mutant"], viable)
    survivors = [row for row, result in zip(viable, mutant["results"]) if result["ok"]]

    summary = {
        "project": PROJECT,
        "latest": LATEST,
        "github_release_count": len(releases),
        "packagist_stable_version_count": len(packagist_versions),
        "git_tag_count": len(tags),
        "changelog_release_count": len(changelog),
        "candidate_count": len(candidates),
        "viable_latest_replay_count": len(viable),
        "latest_replay_mutant_survivor_count": len(survivors),
        "excluded_runtime_error_count": len(filled) - len(viable),
        "mutant_survived_count": len(viable) - len(survivors),
        "by_op": dict(Counter(row["op"] for row in survivors)),
        "by_version": dict(Counter(row["version"] for row in survivors)),
        "by_capability": dict(Counter(row["capability"] for row in survivors)),
        "audited_tags": tags,
        "audited_packagist_versions": packagist_versions,
        "audited_github_releases": [r.get("tag_name") for r in releases],
    }

    write_json(OUT_DIR / "all_releases_maximal_language_independent.json", candidates)
    write_rpl(OUT_DIR / "all_releases_maximal_language_independent.rpl", candidates)
    write_json(OUT_DIR / "latest_replay_mutant_verified.json", survivors)
    write_rpl(OUT_DIR / "latest_replay_mutant_verified.rpl", survivors)
    write_json(OUT_DIR / "latest_replay_mutant_verified.summary.json", summary)

    md = [
        "# dragonmantank/cron-expression Contract Extraction",
        "",
        f"- Latest tested release: `{LATEST}`",
        f"- GitHub releases audited: `{len(releases)}`",
        f"- Packagist stable versions audited: `{len(packagist_versions)}`",
        f"- Git tags audited: `{len(tags)}`",
        f"- Changelog releases audited: `{len(changelog)}`",
        f"- Candidate contracts extracted: `{len(candidates)}`",
        f"- Latest replay-viable contracts: `{len(viable)}`",
        f"- Replay + mutant verified latest survivors: `{len(survivors)}`",
        "",
        "## Survivors by Operation",
        "",
    ]
    for op, count in Counter(row["op"] for row in survivors).most_common():
        md.append(f"- `{op}`: {count}")
    md.extend(["", "## Survivors by Version", ""])
    for version, count in Counter(row["version"] for row in survivors).most_common():
        md.append(f"- `{version}`: {count}")
    md.extend(["", "## Human-Readable Contracts", ""])
    for row in survivors:
        md.append(f"- `{row['name']}`: {row['human']}")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    audit = [
        "# Extraction Audit",
        "",
        "Source review pass 1: GitHub releases, Packagist latest metadata, CHANGELOG, README API surface, and upstream public tests.",
        "Source review pass 2: field-level public syntax tests, DST tests, alias lifecycle tests, validation regressions, and DOM/DOW semantics were revisited for extra externally observable contracts.",
        "",
        "Internal implementation-only changes such as CI, dependency-only, doc-only, PHPStan-only, and minimum PHP support changes were not converted into contracts unless they preserved an executable public behavior.",
        "",
        "## Audited Tags",
        "",
    ]
    audit.extend(f"- `{tag}`" for tag in tags)
    audit.extend(["", "## Packagist Stable Versions", ""])
    audit.extend(f"- `{version}`" for version in packagist_versions)
    audit.extend(["", "## GitHub Releases", ""])
    for rel in releases:
        audit.append(f"- `{rel.get('tag_name')}` published `{rel.get('published_at')}`")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
