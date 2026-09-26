#!/usr/bin/env python3
"""Extract croniter release-history contracts and verify them on the latest release."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / ".cache" / "croniter-src-20260831"
CHANGELOG = SRC / "CHANGELOG.rst"
SITE = ROOT / ".cache" / "croniter-6.2.4-site"
RUNNER = ROOT / "tools" / "replay" / "croniter_latest_runner" / "replay_croniter.py"
OUT_DIR = ROOT / "contracts" / "cron" / "croniter"
PY = Path("/opt/miniconda3/bin/python3.12")
LATEST = "6.2.4"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:88]


def fetch_pypi_release_count() -> int:
    cache = OUT_DIR / "pypi_releases.json"
    if cache.exists():
        return len(json.loads(cache.read_text(encoding="utf-8")).get("releases", {}))
    req = urllib.request.Request("https://pypi.org/pypi/croniter/json", headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        data = json.loads(res.read().decode("utf-8"))
    cache.write_text(json.dumps({"info": data["info"], "releases": data["releases"]}, ensure_ascii=True, indent=2), encoding="utf-8")
    return len(data["releases"])


def parse_changelog() -> list[dict[str, Any]]:
    text = CHANGELOG.read_text(encoding="utf-8")
    matches = list(re.finditer(r"^([0-9][0-9A-Za-z.]*)(?:\s+\([^)]*\))?\n[-]{3,}\n", text, flags=re.M))
    releases: list[dict[str, Any]] = []
    for i, match in enumerate(matches):
        version = match.group(1)
        if version == "6.3.0":
            continue
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        releases.append({"version": version, "body": text[start:end].strip()})
    return releases


def add(rows: list[dict[str, Any]], version: str, capability: str, op: str, params: dict[str, Any], evidence: str, human: str) -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"croniter_{version.replace('.', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "pallets-eco/croniter",
            "domain": "cron_schedule_expression",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence,
            "human": human,
        }
    )


def nexts(rows: list[dict[str, Any]], version: str, expr: str, start: Any, count: int, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "count": count}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "next_dates", params, evidence, f"{expr} yields next {count} dates from {start}")


def prevs(rows: list[dict[str, Any]], version: str, expr: str, start: Any, count: int, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "count": count}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "prev_dates", params, evidence, f"{expr} yields previous {count} dates from {start}")


def expand(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "expand", params, evidence, f"{expr} expands deterministically")


def expanded_instance(rows: list[dict[str, Any]], version: str, expr: str, start: Any, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "expanded_instance", params, evidence, f"{expr} instance expansion from {start}")


def valid(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "is_valid", params, evidence, f"{expr} validity is observable")


def invalid(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "parse_error", params, evidence, f"{expr} is rejected")


def match(rows: list[dict[str, Any]], version: str, expr: str, date: Any, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "date": date}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "match", params, evidence, f"{expr} match({date}) is observable")


def match_range(rows: list[dict[str, Any]], version: str, expr: str, start: Any, stop: Any, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "stop": stop}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "match_range", params, evidence, f"{expr} match_range({start}, {stop}) is observable")


def range_dates(rows: list[dict[str, Any]], version: str, expr: str, start: Any, stop: Any, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "stop": stop}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "range_dates", params, evidence, f"{expr} iterates over range {start}..{stop}")


def build_candidates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    ev = "pre-0.3/README core constructor, get_next, get_prev and day_or behavior"
    for expr in ["*/5 * * * *", "2 4 * * mon,fri", "0 0 1 * *", "0 0 * * sat#1", "0 0 * * 5#3,L5"]:
        nexts(rows, "0.3.3", expr, "2010-01-25T04:46:00", 4, ev, "croniter.core.next")
    prevs(rows, "0.3.3", "0 0 1 * *", "2010-08-25T00:00:00", 4, ev, "croniter.core.prev")
    for expr, start in [
        ("*/1 * * * *", "2010-08-25T15:56:00"),
        ("*/1 * * * *", "2010-08-25T15:00:00"),
        ("*/1 * * * *", "2010-08-25T00:00:00"),
        ("0 0 22 * *", "2012-03-15T00:00:00"),
        ("0 0 * * sat,sun", "2010-08-25T15:56:00"),
        ("0 0 * * sat#1,sun#2", "2010-08-25T15:56:00"),
        ("10 0 * * 0", "2010-08-25T15:56:00"),
    ]:
        prevs(rows, "0.3.3", expr, start, 3, ev, "croniter.core.prev-edge-cases")
    for expr, start in [
        ("5 0 */2 * *", "2012-02-24T00:00:00"),
        ("0 * * 3 *", "2012-01-01T00:00:00"),
        ("00 03 16,30 * *", "2013-03-01T12:17:34.257877"),
        ("0 0 * * 6", "2010-02-25T00:00:00"),
    ]:
        nexts(rows, "0.3.3", expr, start, 5, ev, "croniter.core.calendar-edge-cases")
    nexts(rows, "0.3.3", "2 4 1 * wed", "2010-01-25T00:00:00", 5, ev, "croniter.day-or.default-or")
    nexts(rows, "0.3.3", "2 4 1 * wed", "2010-01-25T00:00:00", 5, ev, "croniter.day-or.false-and", day_or=False)

    ev = "0.3.18 README documents is_valid class method"
    for expr in ["0 0 1 * *", "*/15 9-17 * * mon-fri", "0 wrong_value 1 * *", "0 0 32 * *"]:
        valid(rows, "0.3.18", expr, ev, "croniter.validation.is-valid")

    ev = "0.3.32 implements match(), seconds repeats documentation, and DST previous boundary fix"
    for expr, date in [
        ("0 0 * * *", "2019-01-14T00:00:00"),
        ("0 0 * * *", "2019-01-14T00:00:59"),
        ("0 0 * * *", "2019-01-14T00:02:00"),
        ("2 4 1 * wed", "2019-01-01T04:02:00"),
        ("2 4 1 * wed", "2019-01-02T04:02:00"),
    ]:
        match(rows, "0.3.32", expr, date, ev, "croniter.match.basic-and-day-or")
    match(rows, "0.3.32", "2 4 1 * wed", "2019-01-01T04:02:00", ev, "croniter.match.day-or-false", day_or=False)
    for expr in ["* * * * * 15,25", "* * * * * *", "0 1 8 1,15,l wed 15,45"]:
        nexts(rows, "0.3.32", expr, "2012-04-06T13:26:10", 5, ev, "croniter.seconds.sixth-field")

    ev = "0.3.33 adds/supports explicit day_or and dateutil-tz behavior"
    for expr in ["1 1 1-7 * 2", "1 1 */32,1-7 * 2"]:
        nexts(rows, "0.3.33", expr, "2024-07-12T00:00:00", 6, ev, "croniter.day-or.first-weekday-and", day_or=False)
    nexts(rows, "0.3.33", "0 0 * * *", {"local": "2017-03-26T00:00:00", "zone": "Asia/Tokyo"}, 4, ev, "croniter.timezone.aware-datetime")

    ev = "0.3.34 adds croniter_range(start, stop, cron)"
    range_dates(rows, "0.3.34", "0 0 * * sat#1", "2019-01-01T00:00:00", "2019-12-31T00:00:00", ev, "croniter.range.first-saturday")
    range_dates(rows, "0.3.34", "0 0 * * *", "2016-12-02T00:00:00", "2016-12-10T00:00:00", ev, "croniter.range.inclusive")
    range_dates(rows, "0.3.34", "0 0 * * *", "2016-12-10T00:00:00", "2016-12-02T00:00:00", ev, "croniter.range.reverse")
    range_dates(rows, "0.3.34", "0 0 * * *", "2016-12-02T00:00:00", "2016-12-10T00:00:00", ev, "croniter.range.exclude-ends", exclude_ends=True)

    ev = "0.3.35 adds L-in-ranges, max_years_between_matches and StopIteration iterable behavior"
    for expr in ["0 13 8 1,4,7,10 wed", "0 0 l * *", "0 0 1,l * *"]:
        nexts(rows, "0.3.35", expr, "2020-09-24T00:00:00", 4, ev, "croniter.sparse-and-last-day", day_or=False, max_years_between_matches=15)
        range_dates(rows, "0.3.35", expr, "2020-01-01T00:00:00", "2020-12-31T00:00:00", ev, "croniter.range.sparse-and-last-day", day_or=False)
    invalid(rows, "0.3.35", "0 13 8 1,4,7,10 wed", ev, "croniter.sparse.max-years-error", day_or=False, max_years_between_matches=1, use_next=True)

    ev = "1.0.2 fixes match when datetime has microseconds"
    for micros in [1, 999999, 123456]:
        match(rows, "1.0.2", "0 0 * * *", f"2019-01-14T00:00:00.{micros:06d}", ev, "croniter.match.microseconds")

    ev = "1.0.3/1.0.6/1.0.7 harden invalid syntax handling"
    for expr in ["* * * * * * * *", "0 0 1__2 * *", "0 0 32 * *", "* * R/0 * *", "0 0 10-L * *", "0 0 * * 15,sat#1", "0 0 * * 1,L6"]:
        invalid(rows, "1.0.7", expr, ev, "croniter.validation.invalid-syntax-hardening", use_expand=True)

    ev = "1.0.8 lowercases expression components and accepts mixed-case alpha ranges"
    for expr in ["0 0 10-L * *", "0 0 * JAN-MAR MON-FRI", "0 0 * jan-mar mon-fri", "0 0 l * *"]:
        expand(rows, "1.0.8", expr, ev, "croniter.expand.alpha-and-last-case")
        nexts(rows, "1.0.8", expr, "2021-03-01T00:00:00", 4, ev, "croniter.alpha-and-last-case.next")

    ev = "1.0.11 adds L in day-of-week and unsupported-syntax rejection for mixed nth/last DOW"
    for expr in ["0 0 * * L4", "0 0 * * L5", "0 0 * * 5#3,L5", "0 0 * * sat#1,sun#2"]:
        nexts(rows, "1.0.11", expr, "2021-01-01T00:00:00", 6, ev, "croniter.dow.nth-and-last")
        expand(rows, "1.0.11", expr, ev, "croniter.expand.nth-and-last-dow")
    for expr in ["0 0 * * 1,L6", "0 0 * * 15,sat#1"]:
        invalid(rows, "1.0.11", expr, ev, "croniter.validation.unsupported-mixed-dow", use_expand=True)

    ev = "1.0.12 adds hashed, random, and keyword expressions"
    for expr in ["H * * * *", "H H * * *", "H H * * H", "H H H * *", "H H H H *", "H H * * * H"]:
        nexts(rows, "1.0.12", expr, "2020-01-01T00:00:00", 3, ev, "croniter.hash.deterministic", hash_id="hello")
        expand(rows, "1.0.12", expr, ev, "croniter.hash.expand", hash_id="hello")
    for expr in ["@midnight", "@hourly", "@daily", "@weekly", "@monthly", "@yearly", "@annually"]:
        nexts(rows, "1.0.12", expr, "2021-04-10T00:00:00", 3, ev, "croniter.keyword.vixie")
        nexts(rows, "1.0.12", expr, "2021-04-10T00:00:00", 3, ev, "croniter.keyword.jenkins-hash", hash_id="hello")
    for expr, params in [
        ("R R * * *", {"field": "time_of_day"}),
        ("R R R(10-20) * *", {"field": "dom_range", "day_min": 10, "day_max": 20}),
        ("* * * * * * R(2025-2030)", {"field": "year_range", "year_min": 2025, "year_max": 2030}),
    ]:
        add(
            rows,
            "1.0.12",
            "croniter.random.instance-invariant",
            "random_invariant",
            {"expression": expr, "start": "2020-01-01T00:00:00", "count": 2, **params},
            ev,
            f"{expr} random expansion obeys stable in-instance invariant",
        )

    ev = "1.1.0 and 1.2.0 enforce month/day zero validation"
    for expr in ["0 0 * 0 *", "0 0 0 * *", "0 0 0 0 *", "0 0 1 0 *"]:
        invalid(rows, "1.2.0", expr, ev, "croniter.validation.zero-day-month", use_next=True)

    ev = "1.3.7 fixes croniter_range infinite loop"
    for expr in ["0 13 8 1,4,7,10 wed", "0 0 31 2 *", "0 0 29 2 *"]:
        range_dates(rows, "1.3.7", expr, "2020-01-01T00:00:00", "2025-12-31T00:00:00", ev, "croniter.range.no-infinite-loop", day_or=False)

    ev = "1.3.10/1.3.13 fix DOW hash parsing and range begin/end checks"
    for expr in ["H H * * H", "H H * * H(1-5)", "H H * * H/3", "H H * * H(5-6)/2"]:
        nexts(rows, "1.3.10", expr, "2020-01-01T00:00:00", 4, ev, "croniter.hash.day-of-week", hash_id="hello")
        expand(rows, "1.3.10", expr, ev, "croniter.hash.day-of-week-expand", hash_id="hello")
    for expr in ["H(11-10) H * * *", "10-5 * * * *", "5-5/0 * * * *"]:
        invalid(rows, "1.3.13", expr, ev, "croniter.validation.range-begin-end", use_expand=True, hash_id="hello")

    ev = "1.3.15 fixes hashed expressions omitting entries and enhances match precision for 6-field expressions"
    for expr in ["H(30-59)/10 H * * *", "H/15 * * * *", "H H H H * H H/2"]:
        nexts(rows, "1.3.15", expr, "2020-01-01T00:00:00", 5, ev, "croniter.hash.range-division", hash_id="hello")
        expand(rows, "1.3.15", expr, ev, "croniter.hash.range-division-expand", hash_id="hello")
    for date in ["2019-01-14T00:00:00", "2019-01-14T00:00:00.500000", "2019-01-14T00:00:01"]:
        match(rows, "1.3.15", "0 0 * * * *", date, ev, "croniter.match.six-field-precision")

    ev = "1.4.0/1.4.1 add implement_cron_bug compatibility flag"
    for bug in [True, False]:
        nexts(rows, "1.4.1", "1 1 */32,1-7 * 2", "2024-07-12T00:00:00", 5, ev, "croniter.vixie-cron-bug-compat", implement_cron_bug=bug)
        match(rows, "1.4.1", "1 1 */32,1-7 * 2", "2024-08-06T01:01:00", ev, "croniter.vixie-cron-bug-match", implement_cron_bug=bug)

    ev = "2.0.2 fixes leap year and 2.0.3 adds match_range"
    for expr in ["0 0 29 2 *", "0 0 l 2 *", "0 0 29 2 * 0 2020/4"]:
        nexts(rows, "2.0.2", expr, "2019-01-01T00:00:00", 4, ev, "croniter.leap-year")
        prevs(rows, "2.0.2", expr, "2025-01-01T00:00:00", 3, ev, "croniter.leap-year-prev")
    for expr, start, stop in [
        ("0 0 * * *", "2019-01-13T00:59:00", "2019-01-14T00:01:00"),
        ("0 0 * * *", "2019-01-13T00:01:00", "2019-01-13T00:59:00"),
        ("2 4 1 * wed", "2019-01-01T03:02:00", "2019-01-01T05:01:00"),
    ]:
        match_range(rows, "2.0.3", expr, start, stop, ev, "croniter.match-range")
    match_range(rows, "2.0.3", "2 4 1 * wed", "2019-01-01T03:02:00", "2019-01-01T05:02:00", ev, "croniter.match-range.day-or-false", day_or=False)

    ev = "2.0.4 supports hash_id strings in is_valid and avoids expansion over-optimization"
    for expr in ["H H * * *", "H H * * H", "H(30-59)/10 H * * *"]:
        valid(rows, "2.0.4", expr, ev, "croniter.validation.hash-id-string", hash_id="hello")
        expand(rows, "2.0.4", expr, ev, "croniter.hash.expand-no-overoptimization", hash_id="hello")

    ev = "2.0.6 implements second_at_beginning, question mark wildcard, and expand_from_start_time"
    for expr in ["15,25 * * * * *", "*/20 * * * * *"]:
        nexts(rows, "2.0.6", expr, "2012-04-06T13:26:10", 5, ev, "croniter.seconds.second-at-beginning", second_at_beginning=True)
        range_dates(rows, "2.0.6", expr, "2016-12-02T00:00:00", "2016-12-02T00:01:00", ev, "croniter.range.second-at-beginning", second_at_beginning=True)
    for expr in ["? * * * *", "0 ? * * *", "0 0 ? * mon"]:
        nexts(rows, "2.0.6", expr, "2024-01-01T00:00:00", 4, ev, "croniter.question-mark-wildcard")
        expand(rows, "2.0.6", expr, ev, "croniter.expand.question-mark-wildcard")
    for expr in ["*/15 * * * *", "0 0 */7 * *", "0 */5 * * *", "* * * * * */15"]:
        nexts(rows, "2.0.6", expr, "2024-07-11T10:07:13", 6, ev, "croniter.expand-from-start-time.next", expand_from_start_time=True)
        expanded_instance(rows, "2.0.6", expr, "2024-07-11T10:07:13", ev, "croniter.expand-from-start-time.expanded", expand_from_start_time=True)

    ev = "3.0.0 adds year field, better 6/7-field support, hash fixes and false match when no time is available"
    for expr in ["0 0 1 1 * 0 2020/2", "0 0 29 2 * 0 2024/4", "H H * * * H H", "* * * * * * 2025-2030"]:
        nexts(rows, "3.0.0", expr, "2012-04-06T02:06:59", 5, ev, "croniter.year-field")
        expand(rows, "3.0.0", expr, ev, "croniter.expand.year-field", hash_id="hello" if "H" in expr else None)
    for expr in ["0 0 1 1 * 0 1969", "0 0 1 1 * 0 2100"]:
        invalid(rows, "3.0.0", expr, ev, "croniter.validation.year-range", use_expand=True)
    match(rows, "3.0.0", "0 0 1 1 * 0 2020", "2021-01-01T00:00:00", ev, "croniter.match.false-when-unavailable")

    ev = "3.0.1/3.0.2 add update_current and fix explicit start_time on next/prev/all_next/all_prev"
    for update_current in [True, False]:
        nexts(rows, "3.0.1", "*/10 * * * *", "2024-07-23T10:01:00", 4, ev, "croniter.update-current-option", update_current=update_current)
        prevs(rows, "3.0.1", "*/10 * * * *", "2024-07-23T10:59:00", 4, ev, "croniter.update-current-option-prev", update_current=update_current)
    add(rows, "3.0.2", "croniter.all-next.start-time-respected", "all_next_dates", {"expression": "0 4 1 1 fri", "start": "2000-01-01T00:00:00", "count": 5, "day_or": False, "max_years_between_matches": 15}, ev, "all_next respects configured start_time")

    ev = "4.0.0/5.0.1 day-of-week 7 compatibility and Sunday range calculations"
    for expr in ["0 0 * * 7", "0 0 * * 6-7", "0 0 * * 6,7", "0 0 * * sun-sun", "0 0 * * sat-sun"]:
        nexts(rows, "5.0.1", expr, "2024-10-01T00:00:00", 5, ev, "croniter.sunday-seven-and-ranges")
        expand(rows, "5.0.1", expr, ev, "croniter.expand.sunday-seven-and-ranges")

    ev = "6.1.0 supports zoneinfo timezones and rewrites DST logic"
    for zone, local, expr in [
        ("Europe/Berlin", "2017-03-26T00:00:00", "0 0 * * *"),
        ("America/New_York", "2020-03-07T00:00:00", "0 3 * * *"),
        ("America/New_York", "2020-10-30T00:00:00", "0 0 * * *"),
        ("Europe/Rome", "2020-10-25T01:10:00", "*/30 * * * *"),
    ]:
        nexts(rows, "6.1.0", expr, {"local": local, "zone": zone}, 5, ev, "croniter.timezone.zoneinfo-dst")
        range_dates(rows, "6.1.0", expr, {"local": local, "zone": zone}, {"local": "2020-11-10T00:00:00", "zone": zone} if zone == "America/New_York" else {"local": "2017-03-30T00:00:00", "zone": zone}, ev, "croniter.range.zoneinfo-dst")

    ev = "6.2.0 adds nearest weekday W, precision_in_seconds, and strict day/month validation"
    for expr in ["0 9 15W * *", "0 9 W15 * *", "0 9 1W * *", "0 9 31W * *", "0 9 30W * *"]:
        nexts(rows, "6.2.0", expr, "2024-01-01T00:00:00", 8, ev, "croniter.nearest-weekday-w")
        prevs(rows, "6.2.0", expr, "2024-06-30T00:00:00", 4, ev, "croniter.nearest-weekday-w-prev")
        expand(rows, "6.2.0", expr, ev, "croniter.expand.nearest-weekday-w")
    for expr in ["0 9 1-5W * *", "0 9 1W,15W * *", "0 9 15W,16 * *", "0 9 1,15W * *", "0 9 0W * *", "0 9 32W * *"]:
        valid(rows, "6.2.0", expr, ev, "croniter.validation.nearest-weekday-w-singleton")
        invalid(rows, "6.2.0", expr, ev, "croniter.validation.nearest-weekday-w-singleton-error", use_expand=True)
    for expr, strict, strict_year in [
        ("0 0 31 2 *", False, None),
        ("0 0 31 2 *", True, None),
        ("0 0 29 2 *", True, 2024),
        ("0 0 29 2 *", True, 2023),
        ("0 0 29 2 * 0 2023-2025", True, None),
        ("0 0 30 2 *", True, None),
        ("0 0 31 4 *", True, None),
        ("0 0 31 6 *", True, None),
        ("0 0 31 1 *", True, None),
        ("0 0 31 1,2 *", True, None),
        ("0 0 30 2,4 *", True, None),
        ("0 0 31 * *", True, None),
        ("0 0 * 2 *", True, None),
        ("0 0 l * *", True, None),
        ("*/5 * * * *", True, None),
        ("0 0 29 2 * 0 2024", True, None),
        ("0 0 29 2 * 0 2028", True, None),
        ("0 0 29 2 * 0 2023", True, None),
        ("0 0 29 2 * 0 2025", True, None),
        ("0 0 29 2 * 0 2023,2024", True, None),
        ("0 0 29 2 * 0 2025-2027", True, None),
        ("0 0 31 2 * 0 2024", True, None),
        ("0 0 30 2 * 0 2024", True, None),
        ("0 0 29 2 * 0 *", True, None),
        ("0 0 29 2 *", True, 2000),
        ("0 0 29 2 *", True, 1900),
        ("0 0 29 2 *", True, [2023, 2024]),
        ("0 0 29 2 *", True, [2023, 2025]),
        ("0 0 31 1 *", True, 2023),
        ("0 0 31 2 *", False, 2024),
    ]:
        valid(rows, "6.2.0", expr, ev, "croniter.validation.strict-day-month", strict=strict, strict_year=strict_year)
    for precision in [None, 1, 60, 120]:
        match(rows, "6.2.0", "0 0 * * *", "2019-01-14T00:00:59", ev, "croniter.match.precision-in-seconds", precision_in_seconds=precision)
        match_range(rows, "6.2.0", "0 0 * * *", "2019-01-13T23:59:30", "2019-01-14T00:00:59", ev, "croniter.match-range.precision-in-seconds", precision_in_seconds=precision)

    ev = "6.2.1 fixes get_prev skipping Feb 29 on leap years"
    for expr in ["0 0 29 2 *", "0 0 l 2 *", "0 0 29 2 * 0 2020/4"]:
        prevs(rows, "6.2.1", expr, "2025-01-01T00:00:00", 4, ev, "croniter.prev.leap-day")

    ev = "6.2.3 rejects zero step in equal/reversed ranges and fixes expand_from_start_time month low bound"
    for expr in ["5-5/0 * * * *", "10-5/0 * * * *", "0 0 * JAN-JAN/0 *"]:
        invalid(rows, "6.2.3", expr, ev, "croniter.validation.zero-step-ranges", use_expand=True)
    for expr in ["0 0 * */3 *", "0 0 * 3/4 *", "0 0 * JAN/3 *"]:
        expanded_instance(rows, "6.2.3", expr, "2024-02-10T00:00:00", ev, "croniter.expand-from-start-time.month-low-bound", expand_from_start_time=True)
        nexts(rows, "6.2.3", expr, "2024-02-10T00:00:00", 5, ev, "croniter.expand-from-start-time.month-low-bound-next", expand_from_start_time=True)

    ev = "6.2.4 fixes expand_from_start_time day-of-week low bound so Sunday wraps correctly"
    for expr in ["0 0 * * */2", "0 0 * * 0/2", "0 0 * * sun/2", "0 0 * * 5-0/2"]:
        expanded_instance(rows, "6.2.4", expr, {"local": "2026-07-05T00:00:00", "zone": "UTC"}, ev, "croniter.expand-from-start-time.sunday-dow-low-bound", expand_from_start_time=True)
        nexts(rows, "6.2.4", expr, {"local": "2026-07-05T00:00:00", "zone": "UTC"}, 6, ev, "croniter.expand-from-start-time.sunday-dow-next", expand_from_start_time=True)

    return rows


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = stable_json([row["capability"], row["op"], row["params"]])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def ensure_latest_site() -> None:
    if (SITE / "croniter").exists():
        return
    subprocess.run([str(PY), "-m", "pip", "install", "--quiet", "--target", str(SITE), f"croniter=={LATEST}"], cwd=ROOT, check=True)


def run_runner(payload: dict[str, Any], fill: bool) -> dict[str, Any]:
    ensure_latest_site()
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
        json.dump(payload, tmp, ensure_ascii=True)
        tmp_path = tmp.name
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SITE)
    cmd = [str(PY), str(RUNNER)]
    if fill:
        cmd.append("--fill")
    cmd.append(tmp_path)
    proc = subprocess.run(cmd, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    Path(tmp_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    start = proc.stdout.find("{")
    if start < 0:
        raise RuntimeError(f"runner produced no JSON:\n{proc.stdout}\n{proc.stderr}")
    return json.loads(proc.stdout[start:])


def latest_survivors(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    filled = run_runner({"contracts": candidates}, fill=True)["contracts"]
    viable: list[dict[str, Any]] = []
    rejected_at_fill: list[dict[str, Any]] = []
    for row in filled:
        expected = row.get("expected", {})
        if row["op"] == "parse_error":
            ok = expected.get("error") is True
        else:
            ok = expected.get("error") is not True
        if ok:
            viable.append(row)
        else:
            rejected_at_fill.append(row)
    replay = run_runner({"contracts": viable}, fill=False)["results"]
    passed_names = {r["name"] for r in replay if r.get("replay_passed") and r.get("mutant_rejected")}
    survivors = [row for row in viable if row["name"] in passed_names]
    failed = [r for r in replay if r["name"] not in passed_names]
    return survivors, {
        "filled": len(filled),
        "viable_after_latest_fill": len(viable),
        "rejected_at_fill": len(rejected_at_fill),
        "replay_passed_and_mutant_killed": len(survivors),
        "failed_after_fill": len(failed),
        "failed_examples": failed[:10],
        "rejected_examples": rejected_at_fill[:10],
    }


def write_rpl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    for row in rows:
        lines.append(f"contract {row['name']} {{")
        lines.append(f"  domain: {row['domain']}")
        lines.append(f"  project: {row['project']}")
        lines.append(f"  introduced_by_release: {row['version']}")
        lines.append(f"  capability: {row['capability']}")
        lines.append(f"  op: {row['op']}")
        lines.append(f"  params: {stable_json(row['params'])}")
        if "expected" in row:
            lines.append(f"  expect: {stable_json(row['expected'])}")
            lines.append(f"  mutant: {stable_json(row['mutant'])}")
        lines.append(f"  evidence: {json.dumps(row['evidence'], ensure_ascii=True)}")
        lines.append(f"  human: {json.dumps(row['human'], ensure_ascii=True)}")
        lines.append("}")
    path.write_text("\n\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pypi_release_count = fetch_pypi_release_count()
    changelog_releases = parse_changelog()
    tags = subprocess.check_output(["git", "-C", str(SRC), "tag", "--sort=v:refname"], text=True).splitlines()
    candidates = dedupe(build_candidates())
    survivors, replay_report = latest_survivors(candidates)

    (OUT_DIR / "all_releases_maximal_language_independent.json").write_text(
        json.dumps({"contracts": candidates}, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    write_rpl(OUT_DIR / "all_releases_maximal_language_independent.rpl", candidates)
    (OUT_DIR / "latest_replay_mutant_verified.json").write_text(
        json.dumps({"contracts": survivors}, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    write_rpl(OUT_DIR / "latest_replay_mutant_verified.rpl", survivors)

    by_release = Counter(row["version"] for row in survivors)
    by_capability = Counter(row["capability"] for row in survivors)
    by_op = Counter(row["op"] for row in survivors)
    releases_with_candidates = len({row["version"] for row in candidates})
    summary = {
        "project": "pallets-eco/croniter",
        "latest_release_tested": LATEST,
        "pypi_releases_seen": pypi_release_count,
        "git_tags_seen": len(tags),
        "changelog_releases_seen": len(changelog_releases),
        "releases_with_extracted_contracts": releases_with_candidates,
        "candidate_contracts_before_latest_filter": len(candidates),
        **replay_report,
        "latest_surviving_contracts": len(survivors),
        "survivors_by_release": dict(sorted(by_release.items(), key=lambda kv: kv[0])),
        "survivors_by_capability": dict(sorted(by_capability.items())),
        "survivors_by_op": dict(sorted(by_op.items())),
    }
    (OUT_DIR / "latest_replay_mutant_verified.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    lines = [
        "# croniter Latest-Surviving Contracts",
        "",
        f"- PyPI releases seen: `{pypi_release_count}`",
        f"- Git tags seen: `{len(tags)}`",
        f"- Changelog releases seen: `{len(changelog_releases)}`",
        f"- Latest release tested: `{LATEST}`",
        f"- Candidate contracts before latest filter: `{len(candidates)}`",
        f"- Viable after latest fill: `{replay_report['viable_after_latest_fill']}`",
        f"- Replay passed and mutant killed: `{len(survivors)}`",
        "",
        "## By Capability",
        "",
    ]
    for capability, count in sorted(by_capability.items()):
        lines.append(f"- `{capability}`: `{count}`")
    lines.extend(["", "## By Release", ""])
    for version, count in sorted(by_release.items()):
        lines.append(f"- `{version}`: `{count}`")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit = [
        "# croniter Extraction Audit",
        "",
        "Scope: release-history-derived, language-independent cron schedule contracts for `pallets-eco/croniter`, avoiding simple `cron-parser` and `cron-utils` duplicate surface where practical.",
        "",
        "Included surfaces: `day_or` OR/AND semantics, `implement_cron_bug`, match/match_range precision, croniter_range inclusivity and reverse iteration, max-years sparse schedules, `L`, `W`, nth/last day-of-week, hashed/random/keyword expressions, second/year fields, second-at-beginning, update_current, expand_from_start_time, strict validation, and timezone-aware DST behavior.",
        "",
        "Latest filtering: every candidate DSL contract was executed on PyPI `croniter==6.2.4`; non-error ops that produced runtime errors were excluded; surviving contracts had to replay successfully and reject an artificial mutant.",
        "",
        "Release-note caveat: PyPI lists more historical release files than git tags/changelog entries. Contract extraction uses the repository changelog plus README-documented public behavior because GitHub Releases only cover recent releases.",
    ]
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
