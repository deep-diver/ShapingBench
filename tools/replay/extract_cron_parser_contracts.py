#!/usr/bin/env python3
"""Extract cron-parser release-history contracts and verify them on the latest release."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / ".cache" / "cron-parser-src-20260831"
CHANGELOG = SRC / "CHANGELOG.md"
RUNNER = ROOT / "tools" / "replay" / "cron_parser_latest_runner" / "replay_cron_parser.mjs"
OUT_DIR = ROOT / "contracts" / "cron" / "cron-parser"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def parse_changelog() -> list[dict[str, Any]]:
    text = CHANGELOG.read_text(encoding="utf-8")
    matches = list(re.finditer(r"^##\s+v?([0-9][^\s]*)\s*(?:-\s*([0-9-]+))?", text, flags=re.M))
    releases = []
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        releases.append({"version": match.group(1), "date": match.group(2) or "", "body": body})
    if not any(release["version"] == "5.6.0" for release in releases):
        releases.insert(
            7,
            {
                "version": "5.6.0",
                "date": "2026-06-20",
                "body": (
                    "GitHub release body only: fix ES6 iterator done flag handling; "
                    "fix CronExpressionParser.#parseRepeat ranges parsing; "
                    "stop hour-step loop early on spring-forward DST days to prevent day skip; "
                    "preserve timezone in CronExpression.reset()."
                ),
            },
        )
    return releases


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:90]


def add(rows: list[dict[str, Any]], version: str, capability: str, op: str, params: dict[str, Any], evidence: str, human: str) -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"cron_parser_{version.replace('.', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "harrisiirak/cron-parser",
            "domain": "cron_schedule_expression",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence,
            "human": human,
        }
    )


def opt(**kwargs: Any) -> dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v is not None}


def build_candidates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def nexts(version: str, capability: str, expression: str, current: str, count: int, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "next_dates", {"expression": expression, "count": count, "options": opt(currentDate=current, **options)}, evidence, f"{expression} yields next {count} dates from {current}")

    def prevs(version: str, capability: str, expression: str, current: str, count: int, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "prev_dates", {"expression": expression, "count": count, "options": opt(currentDate=current, **options)}, evidence, f"{expression} yields previous {count} dates from {current}")

    def take(version: str, capability: str, expression: str, current: str, count: int, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "take_dates", {"expression": expression, "count": count, "options": opt(currentDate=current, **options)}, evidence, f"{expression} take({count}) from {current}")

    def stringify(version: str, capability: str, expression: str, evidence: str, include_seconds: bool = False, **options: Any) -> None:
        add(rows, version, capability, "stringify", {"expression": expression, "includeSeconds": include_seconds, "options": opt(**options)}, evidence, f"{expression} stringifies deterministically")

    def fields(version: str, capability: str, expression: str, field_names: list[str], evidence: str, **options: Any) -> None:
        add(rows, version, capability, "fields_values", {"expression": expression, "fields": field_names, "options": opt(**options)}, evidence, f"{expression} exposes parsed fields {field_names}")

    def perror(version: str, capability: str, expression: str, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "parse_error", {"expression": expression, "options": opt(**options)}, evidence, f"{expression} is rejected")

    def nerror(version: str, capability: str, expression: str, current: str, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "next_error", {"expression": expression, "options": opt(currentDate=current, **options)}, evidence, f"{expression} throws while iterating")

    def includes(version: str, capability: str, expression: str, date: str, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "includes_date", {"expression": expression, "date": date, "options": opt(**options)}, evidence, f"{expression} includesDate({date}) is observable")

    def has(version: str, capability: str, expression: str, current: str, evidence: str, **options: Any) -> None:
        add(rows, version, capability, "has_next_prev", {"expression": expression, "options": opt(currentDate=current, **options)}, evidence, f"{expression} exposes hasNext/hasPrev around {current}")

    def reset(version: str, capability: str, expression: str, current: str, reset_date: str, evidence: str, skip_next: int = 1, **options: Any) -> None:
        add(rows, version, capability, "reset_next", {"expression": expression, "skipNext": skip_next, "resetDate": reset_date, "options": opt(currentDate=current, **options)}, evidence, f"{expression} reset preserves subsequent schedule")

    def crontab(version: str, capability: str, content: str, evidence: str) -> None:
        add(rows, version, capability, "crontab_parse", {"content": content}, evidence, "crontab content is parsed into variables, expressions and errors")

    ev_initial = "v0.3.0 initial release / package surface"
    for expr in ["* * * * *", "*/5 * * * *", "1,2,3 * * * *", "10-15 * * * *", "0 12 * JAN MON", "0 0 1 1 *", "*/10 */2 * * *", "0 9-17/2 * * 1-5"]:
        nexts("0.3.0", "cron.iteration.basic-next", expr, "2023-01-01T00:00:00.000Z", 4, ev_initial)
        stringify("0.3.0", "cron.stringify.basic", expr, ev_initial)
    for expr in ["*/10 * * * * *", "5,10,15 * * * * *", "10-30/5 * * * * *"]:
        nexts("0.3.0", "cron.iteration.seconds-field", expr, "2023-01-01T00:00:01.000Z", 5, ev_initial)
        fields("0.3.0", "cron.fields.seconds-field", expr, ["second", "minute"], ev_initial)

    ev = "v0.4 day-of-execution can be specified by two fields"
    nexts("0.4", "cron.dom-dow.combined-day-fields", "0 12 15 * MON", "2023-05-01T00:00:00.000Z", 6, ev)
    nexts("0.4", "cron.dom-dow.combined-day-fields", "0 0 1 * SUN", "2023-01-01T00:00:00.000Z", 8, ev)
    ev = "v0.4.4 supports 0-7 (0 and 7 is sunday) as weekday values"
    for expr in ["0 0 * * 0", "0 0 * * 7", "0 0 * * 0,7", "0 0 * * SUN"]:
        nexts("0.4.4", "cron.weekday.sunday-zero-seven", expr, "2023-01-02T00:00:00.000Z", 3, ev)

    ev = "v0.5.0 days in month constraints validation and DST fixes"
    for expr in ["0 0 31 4 *", "0 0 30 2 *", "0 0 31 6 *"]:
        nerror("0.5.0", "cron.day-of-month.month-length-validation", expr, "2023-01-01T00:00:00.000Z", ev)
    nexts("0.5.0", "cron.dst.spring-forward", "0 3 * * *", "2016-03-27 00:00:01", 3, ev, tz="Europe/Athens")
    nexts("0.5.0", "cron.dst.fall-back", "0 3 * * *", "2016-10-30 00:00:01", 4, ev, tz="Europe/Athens")

    ev = "v0.6.0 iterator option returns ES6 compatible iterator"
    for count in [3, 5, -3]:
        take("0.6.0", "cron.iterator.take", "0 0 1 * *", "2023-01-01T00:00:00.000Z", count, ev)

    ev = "v1.0.0 UTC support"
    for expr in ["0 0 * * *", "0 12 * * MON", "30 2 * * *"]:
        nexts("1.0.0", "cron.timezone.utc", expr, "2023-01-01T00:00:00.000Z", 4, ev, tz="UTC")

    ev = "v1.1.0 first second iteration increases correctly"
    for expr in ["*/10 * * * * *", "1/10 * * * * *", "59 * * * * *"]:
        nexts("1.1.0", "cron.iteration.first-second-increment", expr, "2023-01-01T00:00:00.000Z", 5, ev)

    ev = "v2.0.0 adds support for timezones and DST transitions"
    for tz in ["Europe/Athens", "America/New_York", "Australia/Melbourne"]:
        nexts("2.0.0", "cron.timezone.named-zone", "0 9 * * 1-5", "2026-03-27T12:00:00.000Z", 5, ev, tz=tz)
    nexts("2.0.0", "cron.dst.named-zone-spring", "0 2 * * *", "2026-03-07T12:00:00.000Z", 4, ev, tz="America/Chicago")
    prevs("2.0.0", "cron.dst.named-zone-reverse", "0 2 * * *", "2026-03-08T23:00:00.000Z", 4, ev, tz="America/Chicago")

    ev = "v2.1.0 restricted dayOfWeek and dayOfMonth matching intervals are not skipped"
    for expr in ["0 12 1-31 * 1", "0 0 31 2 1-5", "0 0 16,18 * 3#3"]:
        nexts("2.1.0", "cron.dom-dow.or-semantics", expr, "2022-10-30T14:00:00.000Z", 8, ev, tz="UTC")

    ev = "v2.3.0 complete whitespace and tab support"
    for expr in ["*/10\t*\t*\t*\t*", "  */15   *   *   *   *  ", "0\t9-17\t*\t*\t1-5"]:
        nexts("2.3.0", "cron.parser.whitespace-tabs", expr, "2023-01-01T00:00:00.000Z", 4, ev)
        stringify("2.3.0", "cron.parser.whitespace-normalization", expr, ev)

    ev = "v2.4.0 reverse directional cron date searching capabilities"
    for expr in ["0 0 1 * *", "*/15 * * * *", "59 * * * * *", "0 9 * * 1-5"]:
        prevs("2.4.0", "cron.iteration.previous", expr, "2023-03-15T12:34:56.789Z", 5, ev)
    ev = "v2.4.1 fix prev when current date milliseconds are not zero"
    prevs("2.4.1", "cron.iteration.prev-milliseconds", "* * * * *", "2017-06-13T18:21:25.002Z", 3, ev)
    prevs("2.4.1", "cron.iteration.prev-milliseconds", "*/10 * * * * *", "2020-03-06T10:02:01.002Z", 3, ev)
    ev = "v2.4.3 restrict days in month validation only for February"
    nexts("2.4.3", "cron.day-of-month.february-specific-validation", "0 0 31 4 1", "2023-01-01T00:00:00.000Z", 5, ev)
    nerror("2.4.3", "cron.day-of-month.february-specific-validation", "0 0 30 2 *", "2023-01-01T00:00:00.000Z", ev)

    ev = "v2.6.0 partial question mark support"
    for expr in ["? * * * *", "0 ? * * * *", "0 0 ? * MON", "0 0 * * ?"]:
        nexts("2.6.0", "cron.parser.question-mark-alias", expr, "2023-01-01T00:00:00.000Z", 4, ev)
        stringify("2.6.0", "cron.stringify.question-mark-preserved", expr, ev)

    ev = "v2.7.0 TZ sensitive iterations and leap year expression parsing"
    nexts("2.7.0", "cron.calendar.leap-year", "0 0 29 2 *", "2015-01-01T00:00:00.000Z", 4, ev)
    nexts("2.7.0", "cron.timezone.tz-sensitive-iteration", "0 0 * * *", "2018-10-30T02:59:00+02:00", 4, ev, tz="Europe/Athens")
    ev = "v2.7.1 fix issues with DST boundaries and revert previous release breaking changes"
    nexts("2.7.1", "cron.dst.boundary-regression", "0 * * * *", "2016-03-27 00:00:01", 5, ev, tz="Europe/Athens")
    nexts("2.7.1", "cron.dst.boundary-regression", "*/20 3 * * *", "2016-10-30 02:00:01", 5, ev, tz="Europe/Athens")
    prevs("2.7.1", "cron.dst.boundary-regression-reverse", "0 3 * * *", "2016-10-30 05:00:00", 4, ev, tz="Europe/Athens")
    ev = "v2.7.2 fix bug with sequences"
    for expr in ["0 0 1,15,31 * *", "0 0 1-5,10-12 * *", "0 0 * JAN,MAR,DEC *"]:
        nexts("2.7.2", "cron.parser.sequences", expr, "2023-01-01T00:00:00.000Z", 8, ev)

    ev = "v2.8.0 fix invalid range parsing"
    for expr in ["30-20 * * * * *", "10 0-z 12 8 0", "10 */A 12 8 0"]:
        perror("2.8.0", "cron.validation.invalid-range-and-characters", expr, ev)
    ev = "v2.9.0 validation for too many fields and day of month"
    perror("2.9.0", "cron.validation.too-many-fields", "* * * * * * * *ASD", ev)
    for expr in ["61 * * * * *", "* * 12-36 * * *", "* * * 10-15,40 * *", "* * * * */10,12-13 *", "* * * * * 9"]:
        perror("2.9.0", "cron.validation.field-range", expr, ev)
    ev = "v2.10.0 parser loop limit"
    for expr in ["0 0 31 2 *", "0 0 31 4 *", "0 0 30 2 *"]:
        nerror("2.10.0", "cron.iteration.unsatisfiable-loop-limit", expr, "2023-01-01T00:00:00.000Z", ev)
    ev = "v2.11.0 adds support for # character in the dayOfWeek field"
    for expr in ["0 0 * * 1#1", "0 0 * * 5#3", "0 0 0 ? MAY 0#2", "0 0 0 16,18 * 3#3"]:
        nexts("2.11.0", "cron.day-of-week.nth-occurrence", expr, "2019-04-01T00:00:00.000Z", 6, ev)
        stringify("2.11.0", "cron.stringify.nth-day-of-week", expr, ev, include_seconds=expr.count(" ") == 5)
    for expr in ["0 0 0 ? * 2-4#2", "0 0 0 ? * 1/2#3", "0 0 0 ? * 0,6#4", "0 0 0 ? * 4#6"]:
        perror("2.11.0", "cron.validation.nth-day-of-week", expr, ev)

    ev = "v2.12.0 explicit day of month definition handling and validation"
    for expr in ["0 0 31 1 *", "0 0 31 3 *", "0 0 31 5 *", "0 0 31 7 *"]:
        nexts("2.12.0", "cron.day-of-month.explicit-valid-months", expr, "2023-01-01T00:00:00.000Z", 3, ev)
    for expr in ["0 0 31 4 *", "0 0 31 6 *", "0 0 31 9 *", "0 0 31 11 *"]:
        nerror("2.12.0", "cron.day-of-month.explicit-invalid-months", expr, "2023-01-01T00:00:00.000Z", ev)
    ev = "v2.13.0 reset() accepts arbitrary input date"
    for reset_date in ["2024-05-01T00:00:00.000Z", "2022-01-01T12:34:56.000Z", "2023-06-15T08:00:00.000Z"]:
        reset("2.13.0", "cron.iterator.reset-arbitrary-date", "0 9 * * 1-5", "2023-01-01T00:00:00.000Z", reset_date, ev)
    ev = "v2.14.0 sort input atoms in ascending order"
    for expr in ["30,10,20 * * * *", "0 17,9,12 * * 5,1,3", "0 0 12 12,1,6 *"]:
        stringify("2.14.0", "cron.stringify.sort-atoms", expr, ev)
        fields("2.14.0", "cron.fields.sorted-atoms", expr, ["minute", "hour", "month", "dayOfWeek"], ev)
    ev = "v2.15.0 repeat value parsing and handling"
    for expr in ["5/15 * * * *", "10-30/2 2 12 8 0", "*/20 3 * * *"]:
        nexts("2.15.0", "cron.parser.repeat-values", expr, "2023-01-01T00:00:00.000Z", 8, ev)
    for expr in ["0 */0 * * *", "0 */-5 * * *", "0 5/5/5 * * *"]:
        perror("2.15.0", "cron.validation.repeat-values", expr, ev)
    ev = "v2.16.0 remove limitation for range values"
    for expr in ["1-59 * * * *", "0 0 1-31 * *", "0 0 * 1-12 *", "0 0 * * 0-7"]:
        nexts("2.16.0", "cron.parser.range-values", expr, "2023-01-01T00:00:00.000Z", 6, ev)
    ev = "v2.17.0 support last day of month"
    for expr in ["0 0 L * *", "0 0 L 2 *", "0 0 L 1,2,3 *"]:
        nexts("2.17.0", "cron.day-of-month.last-day", expr, "2023-01-01T00:00:00.000Z", 8, ev)
        stringify("2.17.0", "cron.stringify.last-day-of-month", expr, ev)
    ev = "v2.18.0 validation for empty comma separated values"
    for expr in ["*/10 * * * * ,", "*/10 * * * * ,2", "0 0,,2 * * *", "0 0 1, * *"]:
        perror("2.18.0", "cron.validation.empty-comma-values", expr, ev)

    ev = "v3.2.0 expose parsed fields"
    for expr in ["0,30 9-17/2 1,15 */2 1-5", "0 0 L 2 *", "H(5-10)/3 * * * * *"]:
        fields("3.2.0", "cron.fields.exposed-parsed-fields", expr, ["second", "minute", "hour", "dayOfMonth", "month", "dayOfWeek"], ev, hashSeed="F00D")
    ev = "v3.3.0 serializing a cron expression instance into a string"
    for expr in ["0,30 9-17/2 1,15 */2 1-5", "0 0 16 * 0-7", "0 0 16 * */1", "0 0 1-31 * 5", "0 0 16 * ?", "0 0 * * 5"]:
        stringify("3.3.0", "cron.stringify.expression-instance", expr, ev)
    ev = "v3.4.0 wildcard day of month handling"
    for expr in ["0 0 * * 1", "0 0 * * *", "0 0 1-31 * 1"]:
        nexts("3.4.0", "cron.day-of-month.wildcard-handling", expr, "2021-01-01T00:00:00.000Z", 8, ev)
    ev = "v3.5.0 prev() issue when cron expression contains 59 seconds"
    prevs("3.5.0", "cron.iteration.prev-contains-second-59", "59 * * * * *", "2021-04-26T12:00:00.000Z", 5, ev)
    prevs("3.5.0", "cron.iteration.prev-contains-second-59", "0,59 * * * * *", "2021-04-26T12:00:00.000Z", 5, ev)

    ev = "v4.1.0 support last weekday of the month expressions"
    for expr in ["0 0 0 * * 1L", "0 0 0 * * 5L", "0 0 0 * * 1,3L"]:
        nexts("4.1.0", "cron.day-of-week.last-weekday-of-month", expr, "2021-09-01T00:00:00.000Z", 6, ev)
        stringify("4.1.0", "cron.stringify.last-weekday-of-month", expr, ev, include_seconds=True)
    ev = "v4.3.0 fix last weekday of month handling"
    for expr in ["0 0 0 * * 1L", "0 0 0 * * 6L"]:
        nexts("4.3.0", "cron.day-of-week.last-weekday-of-month-regression", expr, "2022-01-01T00:00:00.000Z", 8, ev)
    includes("4.3.0", "cron.day-of-week.last-weekday-of-month-regression", "0 0 0 * * 1L", "2023-01-30T00:00:00.000Z", ev, tz="UTC")
    ev = "v4.4.0 multiple dayofmonth ranges handling"
    for expr in ["0 0 1-5,10-15 * *", "0 0 1-3,7-9,20-22 * *", "0 0 28-31 1,3,5 *"]:
        nexts("4.4.0", "cron.day-of-month.multiple-ranges", expr, "2023-01-01T00:00:00.000Z", 8, ev)
        stringify("4.4.0", "cron.stringify.multiple-day-of-month-ranges", expr, ev)
    ev = "v4.6.0 fix day of month stringify output handling with single month input"
    for expr in ["0 0 1-31 2 5", "0 0 L 2 *", "0 0 6-20/2 2 *"]:
        stringify("4.6.0", "cron.stringify.day-of-month-single-month", expr, ev)
        nexts("4.6.0", "cron.day-of-month.single-month-iteration", expr, "2024-01-01T00:00:00.000Z", 4, ev)
    ev = "v4.7.0 allow same value for range start and end, Sunday DOW range, stricter repeat validation, duplicate DOW stringify"
    for expr in ["0 0 5-5 * *", "0 0 * * 0-7", "0 0 * * 7-7", "0 0 16 * 0-7"]:
        nexts("4.7.0", "cron.parser.same-value-and-sunday-ranges", expr, "2023-01-01T00:00:00.000Z", 5, ev)
        stringify("4.7.0", "cron.stringify.sunday-ranges", expr, ev)
    for expr in ["0 */0 * * *", "0 5/5/5 * * *"]:
        perror("4.7.0", "cron.validation.stricter-repeat-values", expr, ev)
    ev = "v4.8.0 expression stringify range step handling"
    for expr in ["10-30/2 2 12 8 0", "0 9-17/2 * * 1-5", "0 0 1-5,10-12 * *", "0 0 6-20/2,L 2 *"]:
        stringify("4.8.0", "cron.stringify.range-step", expr, ev)
        nexts("4.8.0", "cron.iteration.range-step", expr, "2023-01-01T00:00:00.000Z", 6, ev)
    ev = "v4.8.1 fix multiple value ranges serialisation"
    for expr in ["0 0 1-5,10-12 * *", "0 0 1-3,7-9,20-22 * *", "0,15,30,45 9-11,13-17 * * 1-5"]:
        stringify("4.8.1", "cron.stringify.multiple-value-ranges", expr, ev)

    ev = "v5.0.0 strict mode, includesDate, CronFileParser, range/repeat fixes"
    for expr in ["0 0 12 1-31 * 1", "0 20 15 * *", "", "0 H(1-5)/10 * * * *"]:
        perror("5.0.0", "cron.strict.validation", expr, ev, strict=True, hashSeed="F00D")
    for expr, date in [("0 0 0 1 * *", "2023-01-01T00:00:00.000Z"), ("0 0 0 * * 1L", "2023-01-30T00:00:00.000Z"), ("0 0 0 * * 1#3", "2023-01-16T00:00:00.000Z"), ("0 0 0 8 * 5#3", "2024-01-19T00:00:00.000Z")]:
        includes("5.0.0", "cron.includes-date", expr, date, ev, tz="UTC")
    crontab("5.0.0", "cron.crontab-file.parse", "# comment\nENV1=\"test1\"\nENV2='test2'\n*/10 * * * * /path/to/exe\n0 09-18 * * 1-5 /path/to/exe\n", ev)
    crontab("5.0.0", "cron.crontab-file.errors", "FOO=bar\n*/5 * * * * valid-command\ninvalid expression here\n* * * * * another-valid\n", ev)
    for expr in ["0 0 31 4 *", "0 0 1-31 * 1", "10-30/2 2 12 8 0"]:
        nexts("5.0.0", "cron.iteration.v5-regressions", expr, "2023-01-01T00:00:00.000Z", 5, ev)

    ev = "v5.0.3 day of week should allow 0 or SUN values"
    for expr in ["0 0 * * SUN", "0 0 * * 0", "0 0 0 ? * SUN"]:
        nexts("5.0.3", "cron.weekday.sun-alias", expr, "2025-01-01T00:00:00.000Z", 4, ev)
    ev = "v5.0.4 set milliseconds to 0 before returning schedule"
    nexts("5.0.4", "cron.iteration.zero-milliseconds", "* * * * *", "2020-03-06T10:02:01.002Z", 3, ev)
    prevs("5.0.4", "cron.iteration.zero-milliseconds", "* * * * *", "2020-03-06T10:02:01.002Z", 3, ev)
    ev = "v5.1.0 includesDate handles L and #"
    for expr, date in [("0 0 0 * * 1L", "2023-01-30T00:00:00.000Z"), ("0 0 0 * * 1L", "2023-01-23T00:00:00.000Z"), ("0 0 0 * * 1#3", "2023-01-16T00:00:00.000Z"), ("0 0 0 * * 1#3", "2023-01-09T00:00:00.000Z")]:
        includes("5.1.0", "cron.includes-date.special-day", expr, date, ev, tz="UTC")
    ev = "v5.1.1 fix last day of month handling when explicit month is set"
    for expr in ["0 0 L 2 *", "0 0 L 4 *", "0 0 L 12 *"]:
        nexts("5.1.1", "cron.day-of-month.last-day-explicit-month", expr, "2024-01-01T00:00:00.000Z", 5, ev)
    ev = "v5.2.0 H syntax and extended serialization for cron fields"
    for expr in ["H * * * *", "H(0-10) * * * *", "H(0-29)/5 * * * *", "* * * * H#3"]:
        nexts("5.2.0", "cron.hash.randomized-values", expr, "2025-01-01T00:00:00.000Z", 5, ev, hashSeed="main-backup")
        stringify("5.2.0", "cron.stringify.hash-seeded", expr, ev, include_seconds=True, hashSeed="F00D")
    ev = "v5.3.0 hashed values ranges and steps support"
    for expr in ["H(10-20) * * * *", "H(0-29)/10 * * * *", "H(5-10)/3 * * * * *", "* H H(9-20)/3 * * 1-5"]:
        stringify("5.3.0", "cron.hash.range-step-stringify", expr, ev, include_seconds=True, hashSeed="F00D")
        fields("5.3.0", "cron.hash.range-step-fields", expr, ["second", "minute", "hour", "dayOfMonth", "month", "dayOfWeek"], ev, hashSeed="F00D")
    ev = "v5.3.1 invalid start and end time span validation plus special chars in field collection"
    has("5.3.1", "cron.range.start-end-validation", "0 0 1 * *", "2023-01-01T00:00:00.000Z", ev, endDate="2023-01-02T00:00:00.000Z")
    has("5.3.1", "cron.range.start-end-validation", "0 0 1 * *", "2023-01-01T00:00:00.000Z", ev, startDate="2023-01-01T00:00:00.000Z", endDate="2024-01-01T00:00:00.000Z")
    ev = "v5.4.0 clamp currentDate value when startDate or endDate are provided"
    nexts("5.4.0", "cron.range.current-date-clamp", "0 0 * * *", "2021-01-01T00:00:00.000Z", 3, ev, startDate="2022-01-01T00:00:00.000Z", endDate="2022-01-04T00:00:00.000Z")
    prevs("5.4.0", "cron.range.current-date-clamp", "0 0 * * *", "2023-01-01T00:00:00.000Z", 3, ev, startDate="2021-12-29T00:00:00.000Z", endDate="2022-01-01T00:00:00.000Z")
    nexts("5.4.0", "cron.range.start-date-fallback", "0 0 * * *", None, 3, ev, startDate="2022-01-01T00:00:00.000Z", endDate="2022-01-04T00:00:00.000Z")

    ev = "v5.6.0 GitHub release: iterator done flag, repeat range parsing, spring-forward hour-step, reset timezone"
    take("5.6.0", "cron.iterator.es6-done-flag", "0 0 * * *", "2026-06-20T00:00:00.000Z", 3, ev, endDate="2026-06-23T00:00:00.000Z")
    for expr in ["0 9-17/2 * * 1-5", "0 */15 9-17 * * 1-5", "0 10-30/2 2 12 8 0"]:
        nexts("5.6.0", "cron.parser.repeat-range-parsing", expr, "2026-06-20T00:00:00.000Z", 6, ev)
    nexts("5.6.0", "cron.dst.spring-forward-hour-step-no-day-skip", "0 */2 * * *", "2026-03-07T12:00:00.000Z", 6, ev, tz="America/Chicago")
    reset("5.6.0", "cron.reset.preserve-timezone", "0 9,12,15,18 * * 1-5", "2026-05-06T00:00:00.000Z", "2026-05-06T02:00:00.000Z", ev, tz="Australia/Melbourne")

    ev = "v5.6.1 handle DST gap correctly and preserve restricted day-of-week rescue"
    nexts("5.6.1", "cron.dst.gap-does-not-stop", "30 2 * * *", "2025-03-29T00:00:00.000Z", 3, ev, tz="Europe/Rome", endDate="2025-03-31T00:00:00.000Z")
    nexts("5.6.1", "cron.dom-dow.out-of-range-rescued", "0 0 31 2 1-5", "2026-02-01T00:00:00.000Z", 6, ev, tz="UTC")
    reset("5.6.1", "cron.reset.preserve-timezone", "0 9,12,15,18 * * 1-5", "2026-05-06T00:00:00.000Z", "2026-05-06T02:00:00.000Z", ev, tz="Australia/Melbourne")
    reset("5.6.1", "cron.reset.preserve-timezone", "0 9,12,15,18 * * 1-5", "2026-05-06T00:00:00.000Z", "2026-05-07T00:00:00.000Z", ev, skip_next=0, tz="America/New_York")
    ev = "v5.7.0 loop limit, nth occurrence DOM/DOW interaction, standalone L rejection"
    for expr in ["0 0 0 * * 1,L", "0 0 0 * * L", "0 0 0 ? * 1.2#2"]:
        perror("5.7.0", "cron.validation.standalone-last-weekday", expr, ev)
    nexts("5.7.0", "cron.nth-dow.dom-match-retained", "0 0 0 8 * 5#3", "2024-01-01T00:00:00.000Z", 5, ev, tz="UTC")
    nerror("5.7.0", "cron.iteration.loop-limit", "0 0 31 2 *", "2025-01-01T00:00:00.000Z", ev)
    ev = "v5.8.0 drop day of month values the month does not have; keep whole-range day fields; end date occurrence returned; DOW step no Sunday"
    for expr in ["0 0 31 2,3 *", "0 0 30 2,4 *", "0 0 29 2 *"]:
        nexts("5.8.0", "cron.day-of-month.drop-invalid-for-month", expr, "2024-01-01T00:00:00.000Z", 4, ev)
    for expr in ["0 0 16 * 0-6", "0 0 16 * 0-7", "0 0 16 * */1", "0 0 16 * 1-6/2"]:
        stringify("5.8.0", "cron.stringify.day-field-whole-range", expr, ev)
    nexts("5.8.0", "cron.range.end-date-inclusive-whole-second", "* * * * * *", "2025-01-01T00:00:09.151Z", 1, ev, endDate="2025-01-01T00:00:10.000Z")
    ev = "v5.9.0 keep explicit range bounds when stringifying stepped fields; compensate DST transitions wider than one hour; hashed step wider than range fallback"
    for expr in ["10-30/2 2 12 8 0", "1-5/2 * * * *", "0 0 6-20/2,L 2 *"]:
        stringify("5.9.0", "cron.stringify.stepped-field-range-bounds", expr, ev)
    nexts("5.9.0", "cron.hash.step-wider-than-range-fallback", "H(1-5)/10 * * * *", "2025-01-01T00:00:00.000Z", 5, ev, hashSeed="F00D")
    fields("5.9.0", "cron.hash.narrow-range-before-step", "H(50-100)/60 * * * *", ["minute"], ev, hashSeed="F00D")
    nexts("5.9.0", "cron.dst.transition-wider-than-one-hour", "0 0 * * *", "2026-04-05T12:00:00.000Z", 5, ev, tz="Australia/Lord_Howe")
    ev = "v5.10.0 pad short expressions from the leading field slot"
    for expr in ["5 4 3 2 1", "*/5 * * * *", "0 12 * * MON"]:
        stringify("5.10.0", "cron.parser.short-expression-leading-padding", expr, ev)
        nexts("5.10.0", "cron.parser.short-expression-leading-padding", expr, "2026-01-01T00:00:00.000Z", 4, ev, tz="UTC")

    return rows


def run_node(contracts: list[dict[str, Any]], fill: bool) -> dict[str, Any]:
    args = ["node", str(RUNNER)]
    if fill:
        args.append("--fill")
    proc = subprocess.run(
        args,
        input=json.dumps({"contracts": contracts}, ensure_ascii=False),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(ROOT),
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"node runner failed: {proc.stderr[:1000]}")
    return json.loads(proc.stdout)


def write_rpl(path: Path, contracts: list[dict[str, Any]]) -> None:
    lines = []
    for contract in contracts:
        lines.append(f"contract {contract['name']} {{")
        lines.append(f"  version {json.dumps(contract['version'])}")
        lines.append(f"  capability {json.dumps(contract['capability'])}")
        lines.append(f"  op {json.dumps(contract['op'])}")
        lines.append(f"  params {stable_json(contract['params'])}")
        lines.append(f"  expect {stable_json(contract['expected'])}")
        lines.append(f"  mutant {stable_json(contract['mutant'])}")
        lines.append("}")
    path.write_text("\n\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    releases = parse_changelog()
    candidates = build_candidates()
    seen: set[str] = set()
    unique = []
    for row in candidates:
        key = stable_json([row["capability"], row["op"], row["params"]])
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)

    filled = run_node(unique, fill=True)["contracts"]
    replayed = run_node(filled, fill=False)["results"]
    survivors = []
    failed = []
    result_by_name = {row["name"]: row for row in replayed}
    for contract in filled:
        result = result_by_name[contract["name"]]
        if result["status"] == "passed":
            survivors.append(contract)
        else:
            failed.append({**contract, "replay_result": result})

    release_counts = Counter(row["version"] for row in survivors)
    release_all = Counter(row["version"] for row in unique)
    capability_counts = Counter(row["capability"] for row in survivors)
    op_counts = Counter(row["op"] for row in survivors)
    releases_with_contracts = sum(1 for r in releases if release_all[r["version"]])

    summary = {
        "domain": "Cron / schedule expression engine",
        "project": "harrisiirak/cron-parser",
        "latest_version": "5.10.0",
        "release_note_versions_seen": len(releases),
        "releases_with_extracted_contracts": releases_with_contracts,
        "raw_candidates": len(candidates),
        "unique_candidates": len(unique),
        "latest_replay_passed": len([r for r in replayed if r["replay_passed"]]),
        "latest_mutant_killed": len(survivors),
        "survivors": len(survivors),
        "failed": len(failed),
        "by_release": {r["version"]: {"candidates": release_all[r["version"]], "survivors": release_counts[r["version"]]} for r in releases},
        "by_capability": dict(sorted(capability_counts.items())),
        "by_op": dict(sorted(op_counts.items())),
        "contracts": survivors,
        "failed_contracts": failed,
    }

    (OUT_DIR / "all_releases_maximal_language_independent.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (OUT_DIR / "latest_replay_mutant_verified.json").write_text(
        json.dumps(
            {
                "domain": summary["domain"],
                "project": summary["project"],
                "latest_version": summary["latest_version"],
                "input_contracts": len(unique),
                "latest_replay_passed": summary["latest_replay_passed"],
                "latest_mutant_killed": summary["latest_mutant_killed"],
                "survivors": len(survivors),
                "survivor_contracts": survivors,
                "results": replayed,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_rpl(OUT_DIR / "all_releases_maximal_language_independent.rpl", filled)
    write_rpl(OUT_DIR / "latest_replay_mutant_verified.rpl", survivors)

    lines = [
        "# cron-parser Contract Extraction Audit",
        "",
        "Extraction used two passes over the release history:",
        "",
        "1. Changelog pass: behavior-bearing release bullets were mapped to cron-domain DSL operations.",
        "2. Replayability pass: README/current regression-test examples were used only to supply concrete executable inputs for those release-note surfaces.",
        "",
        f"- Release versions seen: `{len(releases)}`",
        f"- Releases with extracted contracts: `{releases_with_contracts}`",
        f"- Raw candidates: `{len(candidates)}`",
        f"- Semantic unique candidates: `{len(unique)}`",
        f"- Latest replay passed: `{summary['latest_replay_passed']}`",
        f"- Latest replay + mutant verified survivors: `{len(survivors)}`",
        "",
        "## By Release",
        "",
        "| Release | Candidates | Survivors |",
        "| --- | ---: | ---: |",
    ]
    for release in releases:
        version = release["version"]
        lines.append(f"| `{version}` | {release_all[version]} | {release_counts[version]} |")
    lines += ["", "## By Operation", "", "| Operation | Survivors |", "| --- | ---: |"]
    for op, count in sorted(op_counts.items()):
        lines.append(f"| `{op}` | {count} |")
    lines += ["", "## By Capability", "", "| Capability | Survivors |", "| --- | ---: |"]
    for cap, count in sorted(capability_counts.items()):
        lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    verified_lines = [
        "# cron-parser Latest Replay/Mutant Verified Contracts",
        "",
        f"- Project: `harrisiirak/cron-parser`",
        f"- Latest version: `{summary['latest_version']}`",
        f"- Input contracts: `{len(unique)}`",
        f"- Replay passed: `{summary['latest_replay_passed']}`",
        f"- Mutants killed: `{summary['latest_mutant_killed']}`",
        f"- Survivors: `{len(survivors)}`",
        "",
        "## By Operation",
        "",
        "| Operation | Survivors |",
        "| --- | ---: |",
    ]
    for op, count in sorted(op_counts.items()):
        verified_lines.append(f"| `{op}` | {count} |")
    verified_lines += ["", "## Sample Contracts", "", "| Contract | Release | Capability | Operation | What It Tests |", "| --- | --- | --- | --- | --- |"]
    for contract in survivors[:80]:
        human = str(contract.get("human", "")).replace("|", "\\|")
        verified_lines.append(
            f"| `{contract['name']}` | `{contract['version']}` | `{contract['capability']}` | `{contract['op']}` | {human} |"
        )
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(verified_lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "release_note_versions_seen": len(releases),
                "releases_with_extracted_contracts": releases_with_contracts,
                "unique_candidates": len(unique),
                "survivors": len(survivors),
                "failed": len(failed),
                "by_op": dict(sorted(op_counts.items())),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
