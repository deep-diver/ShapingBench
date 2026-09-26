#!/usr/bin/env python3
"""Extract cron-utils release-history contracts and verify them on the latest release."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "cron" / "cron-utils"
RUNNER_DIR = ROOT / "tools" / "replay" / "cron_utils_latest_runner"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:86]


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


def fetch_release_notes() -> list[dict[str, Any]]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cache = OUT_DIR / "release_notes.github.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))

    releases: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = fetch_json(f"https://api.github.com/repos/jmrozanec/cron-utils/releases?per_page=100&page={page}")
        if not batch:
            break
        releases.extend(batch)
        page += 1

    normalized: list[dict[str, Any]] = []
    for release in releases:
        body = release.get("body") or ""
        normalized.append(
            {
                "tag_name": release.get("tag_name") or "",
                "name": release.get("name") or "",
                "published_at": release.get("published_at") or "",
                "body": body,
                "milestone_refs": re.findall(r"/milestone/([0-9]+)", body),
            }
        )
    cache.write_text(json.dumps(normalized, ensure_ascii=True, indent=2), encoding="utf-8")
    return normalized


def add(rows: list[dict[str, Any]], version: str, capability: str, op: str, params: dict[str, Any], evidence: str, human: str) -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"cron_utils_{version.replace('.', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "jmrozanec/cron-utils",
            "domain": "cron_schedule_expression",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence,
            "human": human,
        }
    )


def parse(rows: list[dict[str, Any]], version: str, typ: str, expr: str, evidence: str, capability: str = "cron.definition.parse-normalize") -> None:
    add(rows, version, capability, "parse_as_string", {"type": typ, "expression": expr}, evidence, f"{typ} expression parses and normalizes: {expr}")


def valid(rows: list[dict[str, Any]], version: str, typ: str, expr: str, evidence: str, capability: str = "cron.definition.validation") -> None:
    add(rows, version, capability, "parse_valid", {"type": typ, "expression": expr}, evidence, f"{typ} expression is accepted: {expr}")


def invalid(rows: list[dict[str, Any]], version: str, typ: str, expr: str, evidence: str, capability: str = "cron.definition.rejection") -> None:
    add(rows, version, capability, "parse_error", {"type": typ, "expression": expr}, evidence, f"{typ} expression is rejected: {expr}")


def describe(rows: list[dict[str, Any]], version: str, typ: str, expr: str, locale: str, evidence: str, capability: str = "cron.description.locale") -> None:
    add(rows, version, capability, "describe", {"type": typ, "expression": expr, "locale": locale}, evidence, f"{typ} expression is described in {locale}: {expr}")


def execution(rows: list[dict[str, Any]], version: str, op: str, typ: str, expr: str, at: str, evidence: str, capability: str, end: str | None = None) -> None:
    params = {"type": typ, "expression": expr, "at": at}
    if end is not None:
        params["end"] = end
    add(rows, version, capability, op, params, evidence, f"{op} for {typ} {expr} at {at}")


def custom_execution(rows: list[dict[str, Any]], version: str, op: str, definition: str, expr: str, at: str, evidence: str, capability: str, end: str | None = None) -> None:
    params = {"definition": definition, "expression": expr, "at": at}
    if end is not None:
        params["end"] = end
    add(rows, version, capability, op, params, evidence, f"{op} for {definition} {expr} at {at}")


def mapping(rows: list[dict[str, Any]], version: str, mapper: str, typ: str, expr: str, evidence: str) -> None:
    add(rows, version, "cron.definition.mapping", "map", {"mapper": mapper, "type": typ, "expression": expr}, evidence, f"{mapper} maps {expr}")


def equiv(rows: list[dict[str, Any]], version: str, left_type: str, left: str, right_type: str, right: str, evidence: str, mapper: str | None = None) -> None:
    params = {"leftType": left_type, "left": left, "rightType": right_type, "right": right}
    if mapper:
        params["mapper"] = mapper
    add(rows, version, "cron.definition.equivalence", "equivalent", params, evidence, f"{left} equivalence against {right}")


def build_candidates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    ev = "1.0.0 initial public parsing model"
    for typ, exprs in {
        "UNIX": ["* * * * *", "0 12 * * MON", "15 9-17/2 * JAN,MAR MON-FRI", "0 0 1 1 *", "*/20 * * * *"],
        "CRON4J": ["* * * * *", "0 12 * * MON", "15 9-17/2 * JAN,MAR MON-FRI", "0 0 1 1 *"],
        "QUARTZ": ["0 * * * * ?", "0 0/30 * * * ?", "0 15 10 ? * MON-FRI", "0 0 12 1/5 * ? *", "0 0 12 ? JAN MON *"],
        "SPRING": ["0 * * * * *", "0 0/30 * * * *", "0 15 10 * * MON-FRI", "0 0 12 1/5 * *"],
        "SPRING53": ["0 * * * * *", "0 0/30 * * * *", "0 15 10 * * MON-FRI", "0 0 12 1/5 * *"],
    }.items():
        for expr in exprs:
            parse(rows, "1.0.0", typ, expr, ev)
            valid(rows, "1.0.0", typ, expr, ev)

    ev = "1.1.0 adds ExecutionTime, DateTimeFormatBuilder and ConstantsMapper"
    for typ, expr in [
        ("UNIX", "0 12 * * MON"),
        ("UNIX", "*/15 * * * *"),
        ("QUARTZ", "0 0/30 * * * ?"),
        ("QUARTZ", "0 15 10 ? * MON-FRI"),
        ("SPRING", "0 0/20 9-17 * * MON-FRI"),
    ]:
        execution(rows, "1.1.0", "next_execution", typ, expr, "2024-01-01T00:00:00Z", ev, "cron.execution.next")
        execution(rows, "1.1.0", "last_execution", typ, expr, "2024-01-10T12:34:56Z", ev, "cron.execution.last")
        execution(rows, "1.1.0", "time_to_next", typ, expr, "2024-01-01T00:00:00Z", ev, "cron.execution.duration-to-next")
        execution(rows, "1.1.0", "time_from_last", typ, expr, "2024-01-10T12:34:56Z", ev, "cron.execution.duration-from-last")
    for source, target in [
        ("QUARTZ_WEEK_DAY", "JAVA8"),
        ("JAVA8", "QUARTZ_WEEK_DAY"),
        ("CRONTAB_WEEK_DAY", "JAVA8"),
        ("JAVA8", "CRONTAB_WEEK_DAY"),
        ("QUARTZ_WEEK_DAY", "CRONTAB_WEEK_DAY"),
    ]:
        for value in [1, 2, 6, 7]:
            add(rows, "1.1.0", "cron.weekday.constants-mapping", "weekday_map", {"source": source, "target": target, "value": value}, ev, f"weekday {value} maps from {source} to {target}")

    ev = "1.1.1 fixes month/day-of-week execution and multiple blank-space parsing"
    for expr in ["0   12   *   *   MON", "*/15    *    *    *    *", "0 0 1    JAN    *"]:
        parse(rows, "1.1.1", "UNIX", expr, ev, "cron.parser.multiple-blank-spaces")
        execution(rows, "1.1.1", "next_execution", "UNIX", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.month-dow")

    ev = "1.1.2 validates expected strings/chars and wraps parse errors"
    for typ, expr in [
        ("UNIX", "$ * * * *"),
        ("UNIX", "0 0 32 * *"),
        ("UNIX", "0 0 * FOO *"),
        ("QUARTZ", "0 0 12 ? * FUNDAY"),
        ("QUARTZ", "0 0 12 ? * 8"),
    ]:
        invalid(rows, "1.1.2", typ, expr, ev, "cron.parser.invalid-characters-and-ranges")

    ev = "2.0.0 visitor API, parser/model decoupling, mapping, offset from last day ranges, and lastExecution"
    for typ, name in [("UNIX", "yearly"), ("UNIX", "monthly"), ("UNIX", "weekly"), ("UNIX", "daily"), ("UNIX", "hourly"), ("QUARTZ", "yearly"), ("QUARTZ", "monthly"), ("QUARTZ", "daily"), ("QUARTZ", "hourly")]:
        add(rows, "2.0.0", "cron.builder.predefined", "builder_predefined", {"type": typ, "builder": name}, ev, f"{typ} predefined builder {name} emits an expression")
    for mapper, typ, expr in [
        ("fromUnixToQuartz", "UNIX", "0 12 * * MON"),
        ("fromUnixToQuartz", "UNIX", "*/15 * * * *"),
        ("fromQuartzToUnix", "QUARTZ", "0 0 12 ? * MON *"),
        ("fromQuartzToUnix", "QUARTZ", "0 0/15 * * * ? *"),
        ("fromQuartzToCron4j", "QUARTZ", "0 0 12 ? * MON *"),
        ("fromCron4jToQuartz", "CRON4J", "0 12 * * MON"),
    ]:
        mapping(rows, "2.0.0", mapper, typ, expr, ev)
    for typ, expr, at in [
        ("QUARTZ", "0 0 12 L-3 * ?", "2024-01-01T00:00:00Z"),
        ("QUARTZ", "0 0 12 L * ?", "2024-01-01T00:00:00Z"),
        ("UNIX", "0 12 * * MON", "2024-01-10T12:34:56Z"),
    ]:
        execution(rows, "2.0.0", "last_execution", typ, expr, at, ev, "cron.execution.last-and-last-day-offset")

    ev = "3.0.0 supports Quartz L option and corrects nextExecution"
    for expr in ["0 0 12 L * ?", "0 0 12 ? * 6L", "0 0 12 LW * ?"]:
        parse(rows, "3.0.0", "QUARTZ", expr, ev, "cron.quartz.last-special-character")
        describe(rows, "3.0.0", "QUARTZ", expr, "en-GB", ev, "cron.description.last-special-character")
        execution(rows, "3.0.0", "next_execution", "QUARTZ", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.quartz-last-special-character")

    ev = "3.1.0 adds ? special char support and German/Korean translations"
    for expr in ["0 0 12 ? * MON", "0 0 12 * * ?", "0 0 12 ? JAN MON"]:
        parse(rows, "3.1.0", "QUARTZ", expr, ev, "cron.quartz.question-mark")
        execution(rows, "3.1.0", "is_match", "QUARTZ", expr, "2024-01-01T12:00:00Z", ev, "cron.execution.match-question-mark")
    for locale in ["de-DE", "ko-KR"]:
        for expr in ["0 0/30 * * * ?", "0 15 10 ? * MON-FRI", "0 0 12 L * ?"]:
            describe(rows, "3.1.0", "QUARTZ", expr, locale, ev, "cron.description.de-ko-locale")

    ev = "3.1.2 fixes optional ? with always fields, future lastExecution, and comma-separated DOW"
    for expr in ["0 0 12 ? * MON,WED,FRI", "0 0 12 * * ?", "0 0 12 ? * MON,TUE,WED"]:
        execution(rows, "3.1.2", "last_execution", "QUARTZ", expr, "2024-02-01T12:00:00Z", ev, "cron.execution.last-with-question-and-dow-list")
        describe(rows, "3.1.2", "QUARTZ", expr, "en-GB", ev, "cron.description.comma-separated-dow")

    ev = "3.1.4 describes weekday lists and parses day-of-week cases"
    for typ, expr in [
        ("UNIX", "0 12 * * MON,WED,FRI"),
        ("QUARTZ", "0 0 12 ? * MON,WED,FRI"),
        ("QUARTZ", "0 0 12 ? * 2,4,6"),
    ]:
        describe(rows, "3.1.4", typ, expr, "en-GB", ev, "cron.description.weekday-list")
        parse(rows, "3.1.4", typ, expr, ev, "cron.parser.weekday-list-cases")

    ev = "3.1.6 fixes month/day-of-week, ranges, fixed-month last, leap-year DOW and validates illegal ?"
    for typ, expr, at in [
        ("UNIX", "0 0 29 2 MON", "2020-01-01T00:00:00Z"),
        ("QUARTZ", "0 0 12 29 FEB MON ?", "2020-01-01T00:00:00Z"),
        ("QUARTZ", "0 0 12 ? MAR-SEP MON-FRI", "2024-01-01T00:00:00Z"),
    ]:
        execution(rows, "3.1.6", "next_execution", typ, expr, at, ev, "cron.execution.leap-and-ranges")
    for expr in ["? ? ? ? ?", "0 0 ? ? ? ?", "0 0 12 ? ? ?"]:
        invalid(rows, "3.1.6", "QUARTZ", expr, ev, "cron.validation.illegal-question-mark")

    ev = "3.1.7 supports W flag, Quartz constant mapping, and valid range/multiple candidates"
    for expr in ["0 0 12 1W * ?", "0 0 12 15W * ?", "0 0 12 31W * ?"]:
        parse(rows, "3.1.7", "QUARTZ", expr, ev, "cron.quartz.nearest-weekday")
        describe(rows, "3.1.7", "QUARTZ", expr, "en-GB", ev, "cron.description.nearest-weekday")
        execution(rows, "3.1.7", "next_execution", "QUARTZ", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.nearest-weekday")

    ev = "4.0.0 adds CronBuilder, equivalence, mapper fixes, DST fixes, range validation and enhanced ranges"
    for left, right, mapper_name in [
        ("0 0 12 ? * MON *", "0 12 * * MON", "fromUnixToQuartz"),
        ("0 0/15 * * * ? *", "*/15 * * * *", "fromUnixToQuartz"),
    ]:
        equiv(rows, "4.0.0", "QUARTZ", left, "UNIX", right, ev, mapper_name)
    for left, right in [
        ("0 0/30 * * * ?", "0 0/30 * * * ?"),
        ("0 0 12 ? * MON", "0 0 12 ? * TUE"),
    ]:
        equiv(rows, "4.0.0", "QUARTZ", left, "QUARTZ", right, ev)
    for expr in ["0 0 12 ? * MON-FRI", "0 0 12 ? * 5-1", "0 0 12 L-3 * ?"]:
        parse(rows, "4.0.0", "QUARTZ", expr, ev, "cron.quartz.enhanced-ranges")
        execution(rows, "4.0.0", "next_execution", "QUARTZ", expr, "2024-03-29T00:00:00Z", ev, "cron.execution.enhanced-ranges")
    execution(rows, "4.0.0", "next_execution", "QUARTZ", "0 0/30 * * * ?", "2016-03-13T01:00:00-05:00[America/New_York]", ev, "cron.execution.dst-next")
    execution(rows, "4.0.0", "last_execution", "QUARTZ", "0 0/30 * * * ?", "2016-11-06T03:00:00-05:00[America/New_York]", ev, "cron.execution.dst-last")
    invalid(rows, "4.0.0", "QUARTZ", "0 0 12 1 * MON", ev, "cron.validation.quartz-dom-dow-exclusive")

    ev = "4.0.1 fixes unexpected extra execution times and error reporting"
    execution(rows, "4.0.1", "execution_dates", "QUARTZ", "0 0 9-17 ? * MON-FRI", "2024-01-01T00:00:00Z", ev, "cron.execution.no-extra-times", "2024-01-03T00:00:00Z")
    for expr in ["0 $ 12 * * ?", "0 0 12 ? * BAD"]:
        invalid(rows, "4.0.1", "QUARTZ", expr, ev, "cron.parser.error-reporting")

    ev = "4.1.0 adds Russian localization"
    for expr in ["0 0/30 * * * ?", "0 15 10 ? * MON-FRI", "0 0 12 L * ?"]:
        describe(rows, "4.1.0", "QUARTZ", expr, "ru-RU", ev, "cron.description.ru-locale")

    ev = "5.0.0 updates Java time support and supports MON/TUE/WED in CronBuilder fluent API"
    for expr in ["0 0 0 ? * MON,TUE,WED", "0 0 0 ? * 2,3,4"]:
        parse(rows, "5.0.0", "QUARTZ", expr, ev, "cron.builder-and-parser.weekday-names")
        execution(rows, "5.0.0", "next_execution", "QUARTZ", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.weekday-names")

    ev = "5.0.1 fixes Quartz last day of month being skipped"
    execution(rows, "5.0.1", "next_execution", "QUARTZ", "0 0 12 L * ?", "2024-01-30T00:00:00Z", ev, "cron.execution.last-day-not-skipped")
    execution(rows, "5.0.1", "last_execution", "QUARTZ", "0 0 12 L * ?", "2024-03-01T00:00:00Z", ev, "cron.execution.last-day-not-skipped")

    ev = "5.0.2 falls back to property file for unknown locales"
    for locale in ["es-AR", "pt-BR", "nl-NL"]:
        describe(rows, "5.0.2", "QUARTZ", "0 0/30 * * * ?", locale, ev, "cron.description.locale-fallback")

    ev = "5.0.5 fixes next/last execution, Quartz 31 day-of-month, stack traces, and every-expression minute handling"
    for expr, at in [
        ("0 0 12 31 * ?", "2024-01-01T00:00:00Z"),
        ("0 */5 * * * ?", "2024-01-01T00:02:30Z"),
        ("0 0 12 ? * MON", "2024-01-10T12:34:56Z"),
    ]:
        execution(rows, "5.0.5", "next_execution", "QUARTZ", expr, at, ev, "cron.execution.issue-fixes-5-0-5")
        execution(rows, "5.0.5", "last_execution", "QUARTZ", expr, "2024-04-01T00:00:00Z", ev, "cron.execution.issue-fixes-5-0-5")

    ev = "6.0.x release train: execution-time and parser refinements from milestone-only release notes"
    for typ, expr in [
        ("SPRING", "0 0 1 * * MON-FRI"),
        ("SPRING53", "0 0 1 * * MON-FRI"),
        ("QUARTZ", "0 0 1 ? * MON-FRI"),
        ("QUARTZ", "0 0/10 8-18 ? * MON-FRI"),
    ]:
        execution(rows, "6.0.0", "next_execution", typ, expr, "2024-01-05T03:00:00Z", ev, "cron.execution.spring-and-quartz-weekday")
        execution(rows, "6.0.0", "count_executions", typ, expr, "2024-01-01T00:00:00Z", ev, "cron.execution.count-between", "2024-01-08T00:00:00Z")

    ev = "8.0.0/8.1.1 maintain latest public surface after parser and execution changes"
    for typ in ["UNIX", "CRON4J", "QUARTZ", "SPRING", "SPRING53"]:
        for builder in ["daily", "hourly", "monthly"]:
            add(rows, "8.0.0", "cron.builder.predefined-current-surface", "builder_predefined", {"type": typ, "builder": builder}, ev, f"{typ} {builder} predefined expression remains executable")

    ev = "9.1.2 fixes descriptions, next/last execution, Quartz constraints, builder invalid values, and empty descriptions"
    for expr in ["0 0 12 ? * MON#2", "0 0 12 ? * 2#1", "0 0 12 LW * ?", "0 0 12 1W * ?", "0 0 12 ? * 6L"]:
        describe(rows, "9.1.2", "QUARTZ", expr, "en-GB", ev, "cron.description.quartz-specials")
        execution(rows, "9.1.2", "next_execution", "QUARTZ", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.quartz-specials")
        execution(rows, "9.1.2", "last_execution", "QUARTZ", expr, "2024-06-30T23:59:00Z", ev, "cron.execution.quartz-specials")
    for expr in ["0 0 12 ? * MON#6", "0 0 12 ? * 8#1", "0 0 12 0 * ?", "0 0 12 32 * ?"]:
        invalid(rows, "9.1.2", "QUARTZ", expr, ev, "cron.validation.quartz-tightened-constraints")

    ev = "9.1.3 updates Spring cron definition to match Spring documentation"
    for expr in ["0 0 12 * * MON-FRI", "0 0 12 1 * *", "0 0/15 9-17 * * MON"]:
        parse(rows, "9.1.3", "SPRING", expr, ev, "cron.spring.definition-docs")
        parse(rows, "9.1.3", "SPRING53", expr, ev, "cron.spring53.definition-docs")
        execution(rows, "9.1.3", "next_execution", "SPRING", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.spring-definition")
        execution(rows, "9.1.3", "next_execution", "SPRING53", expr, "2024-01-01T00:00:00Z", ev, "cron.execution.spring53-definition")
    for mapper, typ, expr in [
        ("fromSpringToQuartz", "SPRING", "0 0 12 * * MON-FRI"),
        ("fromQuartzToSpring", "QUARTZ", "0 0 12 ? * MON-FRI"),
        ("fromSpringToQuartz", "SPRING", "0 0/15 9-17 * * MON"),
    ]:
        mapping(rows, "9.1.3", mapper, typ, expr, ev)

    ev = "9.x regression tests and milestone-linked release notes: execution, descriptor, validation and mapping fixes"
    custom_execution(rows, "9.1.7", "is_match", "CUSTOM_MIN_HOUR_DOW_OPTIONAL", "0-59 7-16 MON-FRI", "2024-01-03T08:30:00Z", ev, "cron.custom-definition.optional-dow-match")
    for expr in ["0 9 1-7 * 1", "0 9 1-7 * 1-5", "0 9 1-7 * 6-7", "0 9 8-14 * 1-5", "0 9 22-28 * 6-7"]:
        custom_execution(rows, "9.1.7", "next_execution", "CUSTOM_UNIX_DOM_DOW_AND", expr, "2017-09-29T14:46:01.166-07:00", ev, "cron.custom-definition.dom-and-dow")
    for params in [
        {"definition": "CUSTOM_MONTH_INTERVAL", "builder": "custom_month_every", "minute": 0, "hour": 0, "dayOfMonth": 10, "every": 5},
        {"definition": "CUSTOM_MONTH_INTERVAL", "builder": "custom_month_every_from", "minute": 0, "hour": 0, "dayOfMonth": 10, "month": 2, "every": 5},
        {"definition": "CUSTOM_MONTH_INTERVAL", "builder": "custom_month_every_from", "minute": 0, "hour": 0, "dayOfMonth": 25, "month": 4, "every": 6},
        {"definition": "CUSTOM_MONTH_INTERVAL_WITH_YEAR", "builder": "custom_weekly", "minute": 0, "hour": 0, "dayOfWeek": 7},
    ]:
        add(rows, "9.1.7", "cron.custom-definition.builder-composed-fields", "builder_predefined", params, ev, f"custom builder emits cron for {params['definition']}")
    for expr in ["0 0 0 ? * ? * 47/91", "0 0 0 ? * ? 2017 47/91"]:
        custom_execution(rows, "9.1.7", "execution_dates", "CUSTOM_DAY_OF_YEAR", expr, "2017-01-01T00:00:00Z", ev, "cron.custom-definition.day-of-year", "2018-01-01T00:00:00Z")
    custom_execution(rows, "9.1.7", "last_execution", "CUSTOM_YEAR_MONTH_DOM_HMS", "2022 3 30 9 55 0", "2022-03-30T09:54:00Z", ev, "cron.custom-definition.exact-date-last-empty")
    for op in ["parse_as_string", "describe", "next_execution", "last_execution"]:
        params = {"definition": "CUSTOM_REBOOT", "expression": "@reboot"}
        if op in {"next_execution", "last_execution"}:
            params["at"] = "2024-01-01T00:00:00Z"
        add(rows, "9.1.7", "cron.custom-definition.reboot-nickname", op, params, ev, "@reboot custom definition behavior")
    for at in ["1999-07-18T10:00:00.000000003Z", "1999-07-18T10:00:00Z"]:
        execution(rows, "9.1.7", "is_match", "QUARTZ", "00 00 10 * * ?", at, ev, "cron.execution.nanoseconds-do-not-break-match")
    for typ, expr, dates in [
        ("QUARTZ", "0 0 8 ? * MON-FRI", ["2017-07-07T10:00:00Z", "2017-08-31T10:00:00Z", "2017-06-30T10:00:00Z", "2017-09-29T10:00:00Z"]),
        ("CRON4J", "0 8 * * MON-FRI", ["2017-07-07T10:00:00Z", "2017-08-31T10:00:00Z", "2017-06-30T10:00:00Z", "2017-09-29T10:00:00Z"]),
        ("QUARTZ", "0 0 8 ? * FRI-SAT", ["2017-03-28T00:00:00Z", "2017-03-31T09:00:00Z", "2010-12-31T09:00:00Z"]),
        ("CRON4J", "0 8 * * FRI-SAT", ["2017-03-28T00:00:00Z", "2017-03-31T09:00:00Z", "2010-12-31T09:00:00Z"]),
    ]:
        for at in dates:
            execution(rows, "9.1.7", "next_execution", typ, expr, at, ev, "cron.execution.weekday-range-boundary")
    for expr in ["* * * * 3", "* * */1 * 3"]:
        execution(rows, "9.1.7", "next_execution", "UNIX", expr, "2017-09-05T11:31:55.407-05:00", ev, "cron.execution.day-of-week-with-day-division")
    for expr in ["15 18 * 1-11 *", "15 18 * 1-11 0-5", "15 18 * 1-11 4-5", "15 18 * 1-11 1-5"]:
        execution(rows, "9.1.7", "last_execution", "UNIX", expr, "2017-12-01T09:30:00Z", ev, "cron.execution.month-range-last-valid-date")
    execution(rows, "9.1.7", "execution_dates", "QUARTZ", "0 0 0 15 8 ? 2015-2099/2", "2015-01-01T00:00:00Z", ev, "cron.execution.year-step-range", "2020-12-31T00:00:00Z")
    execution(rows, "9.1.7", "last_execution", "UNIX", "00 02 * * *", "2018-03-25T02:00:00+01:00[Europe/Berlin]", ev, "cron.execution.dst-last-no-loop")
    execution(rows, "9.1.7", "is_match", "UNIX", "0 6 * * *", "2018-08-12T03:00:00-04:00[America/Santiago]", ev, "cron.execution.dst-is-match-no-loop")
    describe(rows, "9.1.7", "QUARTZ", "* * * * * ? *", "fr-FR", ev, "cron.description.fr-locale")
    for expr in ["0 0 * ? * MON-SUN *", "0 0 5 ? * FRI-TUE *"]:
        execution(rows, "9.1.7", "time_from_last", "QUARTZ", expr, "2024-01-03T06:00:00Z", ev, "cron.execution.weekday-rollover-range")
        execution(rows, "9.1.7", "next_execution", "QUARTZ", expr, "2024-01-03T06:00:00Z", ev, "cron.execution.weekday-rollover-range")
    for expr, at in [
        ("* 1 * * * ?", "2019-01-01T00:00:00Z"),
        ("0 1 * * * ?", "2019-01-01T00:01:00Z"),
    ]:
        execution(rows, "9.1.2", "next_execution", "QUARTZ", expr, at, ev, "cron.execution.minute-one-boundary")
    execution(rows, "9.1.2", "last_execution", "UNIX", "0 0 * * WED", "2019-06-12T00:00:00.300Z", ev, "cron.execution.last-with-millis")
    for typ, expr in [("SPRING", "0 0 8 1-7 * SAT"), ("QUARTZ", "0 0 8 ? * SAT#1")]:
        execution(rows, "9.1.2", "next_execution", typ, expr, "2019-07-01T08:00:00Z", ev, "cron.execution.first-weekday-in-month")
        execution(rows, "9.1.2", "last_execution", typ, expr, "2019-07-01T08:00:00Z", ev, "cron.execution.first-weekday-in-month")
    execution(rows, "9.1.2", "next_execution", "SPRING", "0 0 9 * * MON", "2024-01-02T00:00:00Z", ev, "cron.execution.spring-weekly")
    for expr in ["0 * 0/2 * * ?", "0 0 0/2 * * ?"]:
        execution(rows, "9.1.2", "next_execution", "QUARTZ", expr, "2019-10-30T18:08:50-05:00[US/Central]", ev, "cron.execution.incremental-hours")
    execution(rows, "9.1.2", "next_execution", "SPRING", "0 0 1 * * MON-FRI", "2019-01-05T03:00:00Z", ev, "cron.execution.spring-weekday-after-saturday")
    invalid(rows, "9.1.2", "UNIX", "* * * */12 *", ev, "cron.validation.period-range")
    execution(rows, "9.1.2", "next_execution", "QUARTZ", "0 0 2 ? * 1/7 *", "2020-04-01T03:00:00Z", ev, "cron.execution.day-of-week-step")
    for expr in ["0 0 2 ? * 0/7 *", "0 0 2 ? * 1/8 *"]:
        invalid(rows, "9.1.2", "QUARTZ", expr, ev, "cron.validation.day-of-week-step-range")
    for expr in ["* 0 * * * ?", "* 2,1/31 * * * ?", "2,1/31 * * * *", "* */30 * * * *", "0 */30 * * * *", "*/2 */2 * * *", "* */2 * * *", "*/1 */2 * * *"]:
        typ = "SPRING" if len(expr.split()) == 6 and expr.endswith("* * *") else ("QUARTZ" if len(expr.split()) == 6 else "UNIX")
        describe(rows, "9.1.2", typ, expr, "en-GB", ev, "cron.description.edge-formatting")
    execution(rows, "9.1.2", "next_execution", "QUARTZ", "0 40 08 ? * *", "2020-09-30T02:58:11.898Z", ev, "cron.execution.same-day-next")
    for expr in ["0 0 0 23 3 ? *", "0 0 0 23 3 ? 2021"]:
        execution(rows, "9.1.3", "next_execution", "QUARTZ", expr, "2021-03-23T00:00:00Z", ev, "cron.execution.year-presence")
        execution(rows, "9.1.3", "last_execution", "QUARTZ", expr, "2021-03-23T00:00:00Z", ev, "cron.execution.year-presence")
        execution(rows, "9.1.3", "is_match", "QUARTZ", expr, "2021-03-23T00:00:00Z", ev, "cron.execution.year-presence")
    invalid(rows, "9.1.3", "UNIX", "12 1 * ? *", ev, "cron.validation.unix-question-mark-rejected")
    for mapper_name, typ, expr in [
        ("fromQuartzToCron4j", "QUARTZ", "0 0 0 ? * 5#1"),
        ("fromQuartzToSpring", "QUARTZ", "0 0 0 ? * 5#1"),
        ("fromQuartzToUnix", "QUARTZ", "0 0 0 ? * 5#1"),
        ("fromSpringToQuartz", "SPRING", "0 0 0 ? * 5#1"),
    ]:
        mapping(rows, "9.2.0", mapper_name, typ, expr, ev)
    for expr in ["0 0/1 * * *", "0 1/2 * * *", "0/1 * * * *", "1/2 * * * *"]:
        parse(rows, "4.0.0", "UNIX", expr, "4.0.0 issue #58 step values are parsed without losing the lower bound", "cron.parser.step-normalization")

    ev = "9.2.x latest releases keep the mature public surface intact"
    for typ, expr in [
        ("UNIX", "0 0 29 2 *"),
        ("QUARTZ", "0 0 0 29 FEB ? *"),
        ("SPRING53", "0 0 0 29 FEB *"),
        ("QUARTZ", "0 0 0 ? * MON-FRI *"),
    ]:
        execution(rows, "9.2.1", "execution_dates", typ, expr, "2020-01-01T00:00:00Z", ev, "cron.execution.latest-calendar-surface", "2030-12-31T00:00:00Z")
        describe(rows, "9.2.1", typ, expr, "en-GB", ev, "cron.description.latest-calendar-surface")

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


def run_runner(input_payload: dict[str, Any], fill: bool) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
        json.dump(input_payload, tmp, ensure_ascii=True)
        tmp_path = tmp.name
    args = f"{'--fill ' if fill else ''}{tmp_path}"
    cmd = [
        "mvn",
        "-q",
        "-f",
        str(RUNNER_DIR / "pom.xml"),
        "compile",
        "exec:java",
        "-Dexec.mainClass=shapingbench.CronUtilsReplay",
        f"-Dexec.args={args}",
    ]
    proc = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
    report = {
        "filled": len(filled),
        "viable_after_latest_fill": len(viable),
        "rejected_at_fill": len(rejected_at_fill),
        "replay_passed_and_mutant_killed": len(survivors),
        "failed_after_fill": len(failed),
        "failed_examples": failed[:10],
        "rejected_examples": rejected_at_fill[:10],
    }
    return survivors, report


def write_rpl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = []
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
    releases = fetch_release_notes()
    candidates = dedupe(build_candidates())
    survivors, replay_report = latest_survivors(candidates)

    all_path = OUT_DIR / "all_releases_maximal_language_independent.json"
    all_path.write_text(json.dumps({"contracts": candidates}, ensure_ascii=True, indent=2), encoding="utf-8")
    write_rpl(OUT_DIR / "all_releases_maximal_language_independent.rpl", candidates)

    verified_path = OUT_DIR / "latest_replay_mutant_verified.json"
    verified_path.write_text(json.dumps({"contracts": survivors}, ensure_ascii=True, indent=2), encoding="utf-8")
    write_rpl(OUT_DIR / "latest_replay_mutant_verified.rpl", survivors)

    by_release = Counter(row["version"] for row in survivors)
    by_capability = Counter(row["capability"] for row in survivors)
    by_op = Counter(row["op"] for row in survivors)
    release_tags = [r["tag_name"].lstrip("v") for r in releases]
    summary = {
        "project": "jmrozanec/cron-utils",
        "latest_release_tested": "9.2.1",
        "github_releases_seen": len(releases),
        "release_tags_seen": release_tags,
        "candidate_contracts_before_latest_filter": len(candidates),
        **replay_report,
        "latest_surviving_contracts": len(survivors),
        "survivors_by_release": dict(sorted(by_release.items(), key=lambda kv: kv[0])),
        "survivors_by_capability": dict(sorted(by_capability.items())),
        "survivors_by_op": dict(sorted(by_op.items())),
    }
    (OUT_DIR / "latest_replay_mutant_verified.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    md_lines = [
        "# cron-utils Latest-Surviving Contracts",
        "",
        f"- GitHub releases seen: `{len(releases)}`",
        "- Latest release tested: `9.2.1`",
        f"- Candidate contracts before latest filter: `{len(candidates)}`",
        f"- Viable after latest fill: `{replay_report['viable_after_latest_fill']}`",
        f"- Replay passed and mutant killed: `{len(survivors)}`",
        "",
        "## By Capability",
        "",
    ]
    for capability, count in sorted(by_capability.items()):
        md_lines.append(f"- `{capability}`: `{count}`")
    md_lines.extend(["", "## By Release", ""])
    for version, count in sorted(by_release.items()):
        md_lines.append(f"- `{version}`: `{count}`")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    audit = [
        "# cron-utils Extraction Audit",
        "",
        "Scope: release-history-derived, language-independent cron schedule contracts for `jmrozanec/cron-utils`, avoiding simple `cron-parser` duplicate surface where practical.",
        "",
        "Included surfaces: multi-definition parsing/normalization, validation/rejection, locale descriptions, CronMapper migrations, equivalence, predefined builders, weekday constant mapping, and execution-time calculations.",
        "",
        "Latest filtering: each DSL contract was executed on `com.cronutils:cron-utils:9.2.1`; non-error ops that produced runtime errors were excluded; surviving contracts had to replay successfully and reject an artificial mutant.",
        "",
        "Release-note caveat: several GitHub releases are empty or milestone-link-only. Those releases are counted as reviewed, but only releases with externally observable behavior in notes/issues/feature descriptions contributed contracts.",
    ]
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
