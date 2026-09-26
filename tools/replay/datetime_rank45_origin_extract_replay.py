#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ORIGIN = ROOT / ".replay" / "datetime_origin"
COMMON_250 = ROOT / "contracts" / "datetime_timezone" / "blind_cross_validation" / "merged_377_rank4_rank5_survivors.summary.json"

CARBON_OUT = ROOT / "contracts" / "datetime_timezone" / "carbon"
DATEFNS_OUT = ROOT / "contracts" / "datetime_timezone" / "date-fns"
CARBON_RUNTIME = ORIGIN / "carbon_latest_runtime"
DATEFNS_RUNTIME = ORIGIN / "datefns_latest_runtime"

CARBON_VERSION = "3.13.2"
DATEFNS_VERSION = "4.4.0"
DATEFNS_TZ_VERSION = "1.5.0"


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 300, env: dict[str, str] | None = None) -> str:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout, env=merged_env)
    if proc.returncode != 0:
        raise SystemExit(
            "command failed: "
            + " ".join(cmd)
            + f"\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def slug(text: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower())


def contract(
    project: str,
    version: str,
    source: str,
    name: str,
    capability: str,
    replay: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    evidence: str,
    mutant: str,
    common_equivalent: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "origin_project": project,
        "version": version,
        "source": source,
        "capability": capability,
        "replay": replay,
        "params": params,
        "expected": expected,
        "mutant": mutant,
        "evidence": evidence,
        "common_equivalent": common_equivalent,
    }


def load_common_names() -> set[str]:
    data = json.loads(COMMON_250.read_text())
    return {c["name"] for c in data["contracts"]}


def semantic_key(c: dict[str, Any]) -> str:
    return json.dumps(
        {
            "capability": c.get("capability"),
            "replay": c.get("replay"),
            "params": c.get("params"),
            "expected": c.get("expected"),
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def load_common_semantic_keys() -> set[str]:
    data = json.loads(COMMON_250.read_text())
    return {semantic_key(c) for c in data["contracts"]}


def carbon_contracts() -> list[dict[str, Any]]:
    p = "Carbon"
    v = CARBON_VERSION
    out: list[dict[str, Any]] = []

    def c(
        name: str,
        capability: str,
        replay: str,
        params: dict[str, Any],
        expected: dict[str, Any],
        evidence: str,
        source: str = "Carbon readme/tests/release-notes",
        common_equivalent: str | None = None,
    ) -> None:
        out.append(contract(p, v, source, name, capability, replay, params, expected, evidence, "change_expected_value", common_equivalent))

    c("carbon_isoformat_french_full_datetime", "format.localized-moment-style", "carbon_iso_format",
      {"text": "2019-07-23 14:51", "locale": "fr_FR", "format": "LLLL"}, {"text": "mardi 23 juillet 2019 14:51"},
      "readme.md shows locale('fr_FR')->isoFormat('LLLL') for 2019-07-23 14:51.")
    c("carbon_isoformat_english_full_datetime", "format.localized-moment-style", "carbon_iso_format",
      {"text": "2019-07-23 14:51", "locale": "en", "format": "LLLL"}, {"text": "Tuesday, July 23, 2019 2:51 PM"},
      "readme.md shows isoFormat('LLLL') for English locale.")
    c("carbon_isoformat_spanish_full_datetime", "format.localized-moment-style", "carbon_iso_format",
      {"text": "2019-07-23 14:51", "locale": "es", "format": "LLLL"}, {"text": "martes, 23 de julio de 2019 14:51"},
      "Carbon localization tests cover locale-specific isoFormat output.")
    c("carbon_isoformat_german_full_datetime", "format.localized-moment-style", "carbon_iso_format",
      {"text": "2019-07-23 14:51", "locale": "de", "format": "LLLL"}, {"text": "Dienstag, 23. Juli 2019 14:51"},
      "Carbon localization tests cover locale-specific isoFormat output.")
    c("carbon_isoformat_japanese_full_datetime", "format.localized-moment-style", "carbon_iso_format",
      {"text": "2019-07-23 14:51", "locale": "ja", "format": "LLLL"}, {"text": "2019年7月23日 火曜日 14:51"},
      "Carbon localization tests cover locale-specific isoFormat output.")
    c("carbon_format_timezone_offset_paris", "timezone.format-offset", "carbon_format",
      {"text": "2020-07-01 12:00:00", "zone": "Europe/Paris", "format": "P"}, {"text": "+02:00"},
      "Carbon tests cover timezone-aware formatting.", common_equivalent="standard_offset_differs_from_dst_offset")
    c("carbon_timezone_to_offset_name_kolkata", "timezone.offset-name", "carbon_timezone",
      {"zone": "Asia/Kolkata", "date": "2024-01-01 00:00:00", "operation": "toOffsetName"}, {"value": "+05:30"},
      "tests/CarbonTimeZone/ConversionsTest.php asserts Asia/Kolkata offset name +05:30.")
    c("carbon_timezone_to_region_denver_winter", "timezone.region-from-offset", "carbon_timezone",
      {"zone": "-06:00", "date": "2024-01-19 12:00 UTC", "operation": "toRegionName"}, {"value": "America/Denver"},
      "tests/CarbonTimeZone/GettersTest.php maps -06:00 near winter to a matching North American region.")
    c("carbon_timezone_to_region_chicago_summer", "timezone.region-from-offset", "carbon_timezone",
      {"zone": "-05:00", "date": "2024-08-19 12:00 UTC", "operation": "toRegionName"}, {"value": "America/Chicago"},
      "tests/CarbonTimeZone/GettersTest.php maps -05:00 near Chicago summer to America/Chicago.")
    c("carbon_create_from_timestamp_zero_utc", "instant.epoch", "carbon_create_timestamp",
      {"seconds": 0, "zone": "UTC", "format": "Y-m-d\\TH:i:sP"}, {"text": "1970-01-01T00:00:00+00:00"},
      "Carbon readme uses createFromTimestamp(0).", common_equivalent="instant_epoch_is_unix_epoch")
    c("carbon_create_from_timestamp_ms_preserves_millis", "instant.epoch-millis", "carbon_create_timestamp_ms",
      {"milliseconds": 1601735792198.956, "zone": "UTC", "format": "Y-m-d\\TH:i:s.uP"}, {"text": "2020-10-03T14:36:32.198956+00:00"},
      "Carbon supports createFromTimestampMs with fractional milliseconds.")

    month_cases = [
        ("carbon_add_month_no_overflow_jan31", "2017-01-31", "addMonthNoOverflow", "2017-02-28", "tests/Carbon/AddMonthsTest.php covers no-overflow month arithmetic.", "local_date_plus_months_clamps_to_last_day"),
        ("carbon_add_month_with_overflow_jan31", "2017-01-31", "addMonthWithOverflow", "2017-03-03", "tests/Carbon/AddMonthsTest.php covers overflow month arithmetic.", None),
        ("carbon_sub_month_no_overflow_mar31", "2017-03-31", "subMonthNoOverflow", "2017-02-28", "tests/Carbon/SubTest.php covers no-overflow subtraction.", None),
        ("carbon_add_two_months_no_overflow_jan31", "2020-01-31", "addMonthsNoOverflow2", "2020-03-31", "tests/Carbon/AddMonthsTest.php covers multi-month no-overflow arithmetic.", None),
        ("carbon_sub_two_months_no_overflow_jan31", "2020-01-31", "subMonthsNoOverflow2", "2019-11-30", "tests/Carbon/SubTest.php covers multi-month no-overflow subtraction.", None),
        ("carbon_add_quarter_no_overflow", "2017-11-30", "addQuarterNoOverflow", "2018-02-28", "Carbon exposes quarter no-overflow arithmetic.", None),
        ("carbon_add_year_no_overflow_leap_day", "2020-02-29", "addYearNoOverflow", "2021-02-28", "Carbon exposes year no-overflow arithmetic.", "local_date_leap_year_plus_year_clamps"),
        ("carbon_add_year_with_overflow_leap_day", "2020-02-29", "addYearWithOverflow", "2021-03-01", "Carbon exposes year overflow arithmetic.", None),
        ("carbon_add_weekdays_skips_weekend", "2020-01-01", "addWeekdays5", "2020-01-08", "Carbon exposes weekday arithmetic.", None),
        ("carbon_sub_weekdays_skips_weekend", "2020-01-06", "subWeekdays1", "2020-01-03", "Carbon exposes weekday arithmetic.", None),
        ("carbon_add_days_basic", "2020-01-01", "addDays10", "2020-01-11", "Carbon exposes day arithmetic.", None),
        ("carbon_sub_days_basic", "2020-01-11", "subDays10", "2020-01-01", "Carbon exposes day arithmetic.", None),
        ("carbon_add_hours_over_day", "2020-01-01 00:00:00", "addHours25", "2020-01-02 01:00:00", "Carbon exposes hour arithmetic.", None),
        ("carbon_sub_minutes_over_hour", "2020-01-01 00:30:00", "subMinutes90", "2019-12-31 23:00:00", "Carbon exposes minute arithmetic.", None),
    ]
    for name, date, method, expected, evidence, eq in month_cases:
        fmt = "Y-m-d H:i:s" if ("hours" in name or "minutes" in name) else "Y-m-d"
        c(name, "calendar.overflow-arithmetic", "carbon_method_format",
          {"text": date, "zone": "UTC", "method": method, "format": fmt}, {"text": expected}, evidence, common_equivalent=eq)

    simple_methods = [
        ("carbon_start_of_month", "2024-02-20 12:34:56", "startOfMonth", "Y-m-d H:i:s", "2024-02-01 00:00:00", "tests/Carbon/StartEndOfTest.php covers startOfMonth."),
        ("carbon_end_of_month_leap_feb", "2024-02-20 12:34:56", "endOfMonth", "Y-m-d H:i:s", "2024-02-29 23:59:59", "tests/Carbon/StartEndOfTest.php covers endOfMonth."),
        ("carbon_start_of_quarter", "2024-05-20 12:34:56", "startOfQuarter", "Y-m-d H:i:s", "2024-04-01 00:00:00", "Carbon has quarter start/end helpers."),
        ("carbon_end_of_quarter", "2024-05-20 12:34:56", "endOfQuarter", "Y-m-d H:i:s", "2024-06-30 23:59:59", "Carbon has quarter start/end helpers."),
        ("carbon_start_of_week_monday", "2024-05-22 12:34:56", "startOfWeek", "Y-m-d H:i:s", "2024-05-20 00:00:00", "Carbon exposes startOfWeek with default Monday semantics."),
        ("carbon_end_of_week_sunday", "2024-05-22 12:34:56", "endOfWeek", "Y-m-d H:i:s", "2024-05-26 23:59:59", "Carbon exposes endOfWeek with default Sunday semantics."),
        ("carbon_next_monday", "2024-05-22 12:34:56", "nextMonday", "Y-m-d", "2024-05-27", "tests/Carbon/DayOfWeekModifiersTest.php covers next/previous weekday modifiers."),
        ("carbon_previous_friday", "2024-05-22 12:34:56", "previousFriday", "Y-m-d", "2024-05-17", "tests/Carbon/DayOfWeekModifiersTest.php covers previous weekday modifiers."),
        ("carbon_round_minute", "2024-04-15 19:36:31", "roundMinute", "H:i:s", "19:37:00", "tests/Carbon/RoundTest.php covers round/floor/ceil helpers."),
        ("carbon_floor_15_minutes", "2024-04-15 19:36:12", "floor15Minutes", "H:i", "19:30", "tests/CarbonInterval/RoundingTest.php covers floor by 15 minutes."),
        ("carbon_ceil_15_minutes", "2024-04-15 19:36:12", "ceil15Minutes", "H:i", "19:45", "tests/CarbonInterval/RoundingTest.php covers ceil by 15 minutes."),
        ("carbon_floor_hour", "2024-04-15 19:36:12", "floorHour", "Y-m-d H:i:s", "2024-04-15 19:00:00", "tests/Carbon/RoundTest.php covers floorHour."),
        ("carbon_ceil_hour", "2024-04-15 19:36:12", "ceilHour", "Y-m-d H:i:s", "2024-04-15 20:00:00", "tests/Carbon/RoundTest.php covers ceilHour."),
        ("carbon_round_hour", "2024-04-15 19:36:12", "roundHour", "Y-m-d H:i:s", "2024-04-15 20:00:00", "tests/Carbon/RoundTest.php covers roundHour."),
        ("carbon_floor_day", "2024-04-15 19:36:12", "floorDay", "Y-m-d H:i:s", "2024-04-15 00:00:00", "tests/Carbon/RoundTest.php covers floorDay."),
        ("carbon_ceil_day", "2024-04-15 19:36:12", "ceilDay", "Y-m-d H:i:s", "2024-04-16 00:00:00", "tests/Carbon/RoundTest.php covers ceilDay."),
        ("carbon_round_day", "2024-04-15 19:36:12", "roundDay", "Y-m-d H:i:s", "2024-04-16 00:00:00", "tests/Carbon/RoundTest.php covers roundDay."),
        ("carbon_first_of_month", "2024-05-15", "firstOfMonth", "Y-m-d", "2024-05-01", "Carbon exposes firstOfMonth."),
        ("carbon_last_of_month", "2024-05-15", "lastOfMonth", "Y-m-d", "2024-05-31", "Carbon exposes lastOfMonth."),
        ("carbon_second_monday_of_month", "2024-05-15", "secondMondayOfMonth", "Y-m-d", "2024-05-13", "Carbon exposes nthOfMonth."),
    ]
    for name, text, method, fmt, expected, evidence in simple_methods:
        c(name, "calendar.boundary-or-rounding", "carbon_method_format",
          {"text": text, "zone": "UTC", "method": method, "format": fmt}, {"text": expected}, evidence)

    predicate_cases = [
        ("carbon_is_start_of_day_true_inside_15_minutes", "00:14:59.999999", "isStartOfDay", "15 minutes", True, "tests/Carbon/IsTest.php covers isStartOfDay interval."),
        ("carbon_is_start_of_day_false_at_15_minutes", "00:15:00", "isStartOfDay", "15 minutes", False, "tests/Carbon/IsTest.php covers isStartOfDay interval boundary."),
        ("carbon_is_end_of_day_true_inside_15_minutes", "23:45:00", "isEndOfDay", "15 minutes", True, "tests/Carbon/IsTest.php covers isEndOfDay interval."),
        ("carbon_is_end_of_day_false_before_15_minutes", "23:44:59.999999", "isEndOfDay", "15 minutes", False, "tests/Carbon/IsTest.php covers isEndOfDay interval boundary."),
        ("carbon_is_weekend_saturday", "2024-05-25", "isWeekend", None, True, "Carbon public predicates include isWeekend."),
        ("carbon_is_weekday_monday", "2024-05-27", "isWeekday", None, True, "Carbon public predicates include isWeekday."),
        ("carbon_is_monday_true", "2024-05-27", "isMonday", None, True, "Carbon public predicates include weekday-specific checks."),
        ("carbon_is_tuesday_false", "2024-05-27", "isTuesday", None, False, "Carbon public predicates include weekday-specific checks."),
        ("carbon_is_leap_year_2024", "2024-01-01", "isLeapYear", None, True, "Carbon public predicates include isLeapYear."),
        ("carbon_is_long_year_2015", "2015-01-01", "isLongYear", None, True, "Carbon public predicates include isLongYear."),
    ]
    for name, text, method, interval, expected, evidence in predicate_cases:
        c(name, "calendar.predicates", "carbon_predicate",
          {"text": text, "zone": "UTC", "method": method, "interval": interval}, {"value": expected}, evidence)

    diff_cases = [
        ("carbon_diff_in_real_hours_across_paris_gap", "2019-03-31 00:00:00", "2019-03-31 04:00:00", "Europe/Paris", "diffInRealHours", 3.0, "Carbon distinguishes real-hour DST differences."),
        ("carbon_diff_in_days_signed_future", "2020-01-10", "2020-01-01", "UTC", "diffInDays", -9.0, "Carbon diff APIs can return signed differences."),
        ("carbon_float_diff_in_days_fractional", "2020-01-01 00:00:00", "2020-01-02 12:00:00", "UTC", "floatDiffInDays", 1.5, "Carbon exposes floatDiffInDays."),
        ("carbon_diff_in_weekdays", "2024-05-20", "2024-05-27", "UTC", "diffInWeekdays", 5.0, "Carbon exposes weekday-aware differences."),
        ("carbon_diff_in_weekend_days", "2024-05-20", "2024-05-27", "UTC", "diffInWeekendDays", 2.0, "Carbon exposes weekend-day differences."),
    ]
    for name, left, right, zone, method, expected, evidence in diff_cases:
        c(name, "calendar.difference", "carbon_diff",
          {"left": left, "right": right, "zone": zone, "method": method}, {"value": expected}, evidence)

    interval_cases = [
        ("carbon_interval_from_string_full", "11 years 1 month 2 weeks 5 days 22 hours 33 minutes 55 seconds", "forHumans", "11 years, 1 month, 2 weeks, 5 days, 22 hours, 33 minutes and 55 seconds", "tests/CarbonInterval/ToStringTest.php covers interval stringification."),
        ("carbon_interval_iso_spec_hours", "PT15M", "forHumans", "15 minutes", "tests/CarbonInterval/SpecTest.php and RoundingTest.php cover ISO interval specs."),
        ("carbon_interval_iso_one_day", "P1D", "forHumans", "1 day", "tests/CarbonInterval/SpecTest.php covers ISO day intervals."),
        ("carbon_interval_total_minutes", "PT1H30M", "totalMinutes", "90", "tests/CarbonInterval/TotalTest.php covers total unit getters."),
        ("carbon_interval_cascade_minutes_to_hours", "PT90M", "cascade", "1 hour and 30 minutes", "CarbonInterval supports cascade normalization."),
        ("carbon_interval_multiply", "PT15M", "times2", "30 minutes", "tests/CarbonInterval/MultiplyTest.php covers interval multiplication."),
        ("carbon_interval_divide", "PT30M", "shares2", "15 minutes", "tests/CarbonInterval/SharesTest.php covers interval sharing/division."),
    ]
    for name, spec, operation, expected, evidence in interval_cases:
        c(name, "duration.interval-public-api", "carbon_interval",
          {"spec": spec, "operation": operation}, {"value": expected}, evidence)

    period_cases = [
        ("carbon_period_every_2_days_inclusive", "2020-01-01", "2 days", "2020-01-05", None, "2020-01-01,2020-01-03,2020-01-05", "tests/CarbonPeriod/IteratorTest.php covers iteration."),
        ("carbon_period_exclude_start", "2020-01-01", "2 days", "2020-01-05", "excludeStartDate", "2020-01-03,2020-01-05", "tests/CarbonPeriod/SettersTest.php covers start/end options."),
        ("carbon_period_exclude_end", "2020-01-01", "2 days", "2020-01-05", "excludeEndDate", "2020-01-01,2020-01-03", "tests/CarbonPeriod/SettersTest.php covers start/end options."),
        ("carbon_period_recurrences_limits_count", "2020-01-01", "1 day", None, "recurrences:3", "2020-01-01,2020-01-02,2020-01-03", "tests/CarbonPeriod/GettersTest.php covers recurrences."),
        ("carbon_period_invert_descends", "2020-01-05", "1 day", "2020-01-01", "invert", "2020-01-05,2020-01-04,2020-01-03,2020-01-02,2020-01-01", "tests/CarbonPeriod/IteratorTest.php covers inverted periods."),
        ("carbon_period_quarterly_factory", "2024-01-01", "quarterly", None, "recurrences:3", "2024-01-01,2024-04-01,2024-07-01", "tests/CarbonPeriod/QuarterlyTest.php covers quarterly()."),
        ("carbon_period_monthly_recurrences", "2024-01-31", "1 month", None, "recurrences:3", "2024-01-31,2024-03-02,2024-04-02", "tests/CarbonPeriod/MonthlyTest.php covers monthly periods."),
        ("carbon_period_weekly_recurrences", "2024-01-01", "1 week", None, "recurrences:3", "2024-01-01,2024-01-08,2024-01-15", "tests/CarbonPeriod/IteratorTest.php covers periodic iteration."),
    ]
    for name, start, step, end, option, expected, evidence in period_cases:
        c(name, "interval.period-iteration", "carbon_period",
          {"start": start, "step": step, "end": end, "option": option}, {"dates": expected}, evidence)

    c("carbon_json_serializes_iso_utc", "serialization.json", "carbon_json",
      {"text": "2017-06-27 13:14:15.123456", "zone": "UTC"}, {"text": "2017-06-27T13:14:15.123456Z"},
      "tests/Carbon/JsonSerializationTest.php covers JSON serialization.")
    c("carbon_to_atom_string_keeps_offset", "format.atom", "carbon_method_format",
      {"text": "2020-01-01 12:00:00", "zone": "Asia/Tokyo", "method": "identity", "format": "Y-m-d\\TH:i:sP"}, {"text": "2020-01-01T12:00:00+09:00"},
      "Carbon formatting exposes ATOM-compatible offset output.")
    c("carbon_set_timezone_keeps_instant", "timezone.conversion", "carbon_set_timezone",
      {"text": "2020-01-01 00:00:00", "from": "UTC", "to": "Asia/Tokyo", "format": "Y-m-d H:i:sP"}, {"text": "2020-01-01 09:00:00+09:00"},
      "Carbon setTimezone changes zone while preserving instant.", common_equivalent="instant_conversion_preserves_zone")
    c("carbon_shift_timezone_keeps_local_wall_time", "timezone.shift-wall-time", "carbon_shift_timezone",
      {"text": "2020-01-01 00:00:00", "from": "UTC", "to": "Asia/Tokyo", "format": "Y-m-d H:i:sP"}, {"text": "2020-01-01 00:00:00+09:00"},
      "Carbon shiftTimezone changes timezone preserving wall-clock fields.")
    c("carbon_parse_first_number_month_name_priority", "parser.localized-string", "carbon_parse_locale",
      {"text": "Friday 1 March 2024", "locale": "en", "format": "Y-m-d"}, {"text": "2024-03-01"},
      "Carbon 3.13.2 release notes prioritize day names before month names when translating string before first number.")
    c("carbon_create_explicit_leap_datetime", "factory.creation", "carbon_factory",
      {"operation": "create", "year": 2020, "month": 2, "day": 29, "hour": 1, "minute": 2, "second": 3, "zone": "UTC", "format": "Y-m-d H:i:sP"}, {"text": "2020-02-29 01:02:03+00:00"},
      "Carbon public factory create() constructs explicit date-times.")
    c("carbon_create_midnight_date", "factory.creation", "carbon_factory",
      {"operation": "createMidnightDate", "year": 2020, "month": 2, "day": 29, "zone": "UTC", "format": "Y-m-d H:i:sP"}, {"text": "2020-02-29 00:00:00+00:00"},
      "Carbon public factory createMidnightDate() constructs midnight date.")
    c("carbon_create_safe_rejects_invalid_leap_day", "factory.safe-validation", "carbon_factory",
      {"operation": "createSafe", "year": 2018, "month": 2, "day": 29, "hour": 0, "minute": 0, "second": 0, "zone": "UTC", "format": "Y-m-d"}, {"throws": "InvalidDateException"},
      "Carbon public createSafe() rejects invalid dates.")

    getter_cases = [
        ("carbon_get_day_of_year_leap_last_day", "2024-12-31", "dayOfYear", "366", "Carbon public getters expose dayOfYear.", "datefns_get_day_of_year_leap"),
        ("carbon_get_days_in_month_leap_feb", "2024-02-10", "daysInMonth", "29", "Carbon public getters expose daysInMonth."),
        ("carbon_get_quarter", "2024-05-22", "quarter", "2", "Carbon public getters expose quarter."),
        ("carbon_get_iso_week_cross_year", "2021-01-01", "isoWeek", "53", "Carbon public getters expose ISO week.", "datefns_get_iso_week_cross_year"),
        ("carbon_get_iso_week_year_cross_year", "2021-01-01", "isoWeekYear", "2020", "Carbon public getters expose ISO week-year.", "datefns_get_iso_week_year_cross_year"),
        ("carbon_get_week_year_dec31", "2024-12-31", "weekYear", "2025", "Carbon public getters expose locale week-year."),
        ("carbon_get_offset_seconds_tokyo", "2024-01-01 00:00:00", "offset", "32400", "Carbon public getters expose numeric offset seconds."),
        ("carbon_get_timestamp_epoch_day", "1970-01-02 00:00:00", "timestamp", "86400", "Carbon public getters expose Unix timestamp."),
        ("carbon_get_microsecond", "2024-01-01 00:00:00.123456", "micro", "123456", "Carbon public getters expose microseconds."),
    ]
    for item in getter_cases:
        name, text, prop, expected, evidence, *eq = item
        zone = "Asia/Tokyo" if "tokyo" in name else "UTC"
        c(name, "calendar.field-getters", "carbon_getter",
          {"text": text, "zone": zone, "property": prop}, {"value": expected}, evidence, common_equivalent=eq[0] if eq else None)

    compare_cases = [
        ("carbon_between_included_allows_boundary", "2020-01-05", "betweenIncluded", "2020-01-01", "2020-01-05", True, "Carbon public comparison helpers include betweenIncluded."),
        ("carbon_between_excluded_rejects_boundary", "2020-01-05", "betweenExcluded", "2020-01-01", "2020-01-05", False, "Carbon public comparison helpers include betweenExcluded."),
        ("carbon_min_selects_earlier", "2020-01-03", "min", "2020-01-01", None, "2020-01-01", "Carbon public comparison helpers include min."),
        ("carbon_max_selects_later", "2020-01-01", "max", "2020-01-03", None, "2020-01-03", "Carbon public comparison helpers include max."),
    ]
    for name, text, operation, left, right, expected, evidence in compare_cases:
        expected_key = "value" if isinstance(expected, bool) else "text"
        c(name, "calendar.comparison", "carbon_compare",
          {"text": text, "zone": "UTC", "operation": operation, "left": left, "right": right, "format": "Y-m-d"},
          {expected_key: expected}, evidence)

    locale_cases = [
        ("carbon_locale_day_name_french", "2024-05-22", "fr_FR", "dayName", "mercredi", "Carbon locale accessors expose translated day names."),
        ("carbon_locale_month_name_french", "2024-05-22", "fr_FR", "monthName", "mai", "Carbon locale accessors expose translated month names."),
        ("carbon_locale_short_day_name_english", "2024-05-22", "en", "shortDayName", "Wed", "Carbon locale accessors expose short day names."),
        ("carbon_locale_min_day_name_english", "2024-05-22", "en", "minDayName", "We", "Carbon locale accessors expose minimum day names."),
    ]
    for name, text, locale, prop, expected, evidence in locale_cases:
        c(name, "format.localized-names", "carbon_locale_name",
          {"text": text, "zone": "UTC", "locale": locale, "property": prop}, {"text": expected}, evidence)

    return out


def datefns_contracts() -> list[dict[str, Any]]:
    p = "date-fns + @date-fns/tz"
    v = f"{DATEFNS_VERSION} / {DATEFNS_TZ_VERSION}"
    out: list[dict[str, Any]] = []

    def c(
        name: str,
        capability: str,
        replay: str,
        params: dict[str, Any],
        expected: dict[str, Any],
        evidence: str,
        source: str = "date-fns CHANGELOG/tests/docs",
        common_equivalent: str | None = None,
    ) -> None:
        out.append(contract(p, v, source, name, capability, replay, params, expected, evidence, "change_expected_value", common_equivalent))

    simple = [
        ("datefns_add_days_basic", "addDays", ["2020-01-01", 10], "date", "2020-01-11", "src/addDays/test.ts covers adding days."),
        ("datefns_sub_days_basic", "subDays", ["2020-01-11", 10], "date", "2020-01-01", "src/subDays/test.ts covers subtracting days."),
        ("datefns_add_business_days_skips_weekend", "addBusinessDays", ["2024-05-24", 1], "date", "2024-05-27", "src/addBusinessDays/test.ts covers business days."),
        ("datefns_sub_business_days_skips_weekend", "subBusinessDays", ["2024-05-27", 1], "date", "2024-05-24", "src/subBusinessDays/test.ts covers business days."),
        ("datefns_add_months_clamps_end_of_month", "addMonths", ["2020-01-31", 1], "date", "2020-02-29", "src/addMonths/test.ts covers end-of-month add.", "local_date_plus_months_clamps_to_last_day"),
        ("datefns_sub_months_clamps_end_of_month", "subMonths", ["2020-03-31", 1], "date", "2020-02-29", "src/subMonths/test.ts covers end-of-month subtract."),
        ("datefns_add_quarters_rolls_months", "addQuarters", ["2020-01-31", 1], "date", "2020-04-30", "src/addQuarters/test.ts covers quarter arithmetic."),
        ("datefns_add_years_leap_day_clamps", "addYears", ["2020-02-29", 1], "date", "2021-02-28", "src/addYears/test.ts covers leap day.", "local_date_leap_year_plus_year_clamps"),
        ("datefns_start_of_week_monday_option", "startOfWeek", ["2024-05-22", {"weekStartsOn": 1}], "date", "2024-05-20", "src/startOfWeek/test.ts covers weekStartsOn."),
        ("datefns_end_of_week_sunday_default", "endOfWeek", ["2024-05-22"], "date", "2024-05-25", "src/endOfWeek/test.ts covers week end. UTC projection records date component."),
        ("datefns_start_of_iso_week", "startOfISOWeek", ["2024-05-22"], "date", "2024-05-20", "src/startOfISOWeek/test.ts covers ISO week start."),
        ("datefns_end_of_iso_week", "endOfISOWeek", ["2024-05-22"], "date", "2024-05-26", "src/endOfISOWeek/test.ts covers ISO week end."),
        ("datefns_start_of_month", "startOfMonth", ["2024-05-22"], "date", "2024-05-01", "src/startOfMonth/test.ts covers startOfMonth."),
        ("datefns_end_of_month_leap", "endOfMonth", ["2024-02-10"], "date", "2024-02-29", "src/endOfMonth/test.ts covers leap February."),
        ("datefns_start_of_quarter", "startOfQuarter", ["2024-05-22"], "date", "2024-04-01", "src/startOfQuarter/test.ts covers quarters."),
        ("datefns_end_of_quarter", "endOfQuarter", ["2024-05-22"], "date", "2024-06-30", "src/endOfQuarter/test.ts covers quarters."),
        ("datefns_start_of_year", "startOfYear", ["2024-05-22"], "date", "2024-01-01", "src/startOfYear/test.ts covers year boundaries."),
        ("datefns_end_of_year", "endOfYear", ["2024-05-22"], "date", "2024-12-31", "src/endOfYear/test.ts covers year boundaries."),
        ("datefns_next_monday", "nextMonday", ["2024-05-22"], "date", "2024-05-27", "src/nextMonday/test.ts covers next Monday."),
        ("datefns_previous_friday", "previousFriday", ["2024-05-22"], "date", "2024-05-17", "src/previousFriday/test.ts covers previous Friday."),
        ("datefns_last_day_of_month", "lastDayOfMonth", ["2024-02-10"], "date", "2024-02-29", "src/lastDayOfMonth/test.ts covers last day."),
        ("datefns_last_day_of_week_monday_option", "lastDayOfWeek", ["2024-05-22", {"weekStartsOn": 1}], "date", "2024-05-26", "src/lastDayOfWeek/test.ts covers options."),
        ("datefns_get_day_of_year_leap", "getDayOfYear", ["2024-12-31"], "number", 366, "src/getDayOfYear/test.ts covers leap years."),
        ("datefns_get_days_in_month_feb_leap", "getDaysInMonth", ["2024-02-10"], "number", 29, "src/getDaysInMonth/test.ts covers leap February."),
        ("datefns_get_days_in_year_leap", "getDaysInYear", ["2024-05-22"], "number", 366, "src/getDaysInYear/test.ts covers leap years."),
        ("datefns_get_iso_week_cross_year", "getISOWeek", ["2021-01-01"], "number", 53, "src/getISOWeek/test.ts covers ISO cross-year weeks."),
        ("datefns_get_iso_week_year_cross_year", "getISOWeekYear", ["2021-01-01"], "number", 2020, "src/getISOWeekYear/test.ts covers ISO week-year."),
        ("datefns_get_iso_weeks_in_year_2020", "getISOWeeksInYear", ["2020-01-01"], "number", 53, "src/getISOWeeksInYear/test.ts covers 53-week years."),
        ("datefns_set_month_clamps_day", "setMonth", ["2020-01-31", 1], "date", "2020-02-29", "src/setMonth/test.ts covers day clamping."),
        ("datefns_set_quarter_preserves_day_when_valid", "setQuarter", ["2020-05-15", 4], "date", "2020-11-15", "src/setQuarter/test.ts covers quarter setting."),
        ("datefns_set_iso_week", "setISOWeek", ["2020-01-01", 10], "date", "2020-03-04", "src/setISOWeek/test.ts covers ISO week setting."),
        ("datefns_set_iso_day_sunday", "setISODay", ["2020-09-01", 7], "date", "2020-09-06", "src/setISODay/test.ts covers ISO day setting."),
        ("datefns_round_to_nearest_minutes", "roundToNearestMinutes", ["2024-04-15T19:36:12Z", {"nearestTo": 15}], "iso", "2024-04-15T19:30:00.000Z", "src/roundToNearestMinutes/test.ts covers nearest minutes."),
        ("datefns_round_to_nearest_hours", "roundToNearestHours", ["2024-04-15T19:36:12Z"], "iso", "2024-04-15T20:00:00.000Z", "CHANGELOG v3.6.0 added roundToNearestHours."),
    ]
    for name, fn, args, result, expected, evidence, *eq in simple:
        c(name, "date-arithmetic-boundary", "datefns_call", {"fn": fn, "args": args, "result": result}, {"value": expected}, evidence, common_equivalent=eq[0] if eq else None)

    diff = [
        ("datefns_difference_in_calendar_days", "differenceInCalendarDays", ["2024-05-22", "2024-05-20"], 2, "src/differenceInCalendarDays/test.ts covers calendar days."),
        ("datefns_difference_in_calendar_weeks_monday", "differenceInCalendarWeeks", ["2024-05-27", "2024-05-20", {"weekStartsOn": 1}], 1, "src/differenceInCalendarWeeks/test.ts covers weekStartsOn."),
        ("datefns_difference_in_calendar_months", "differenceInCalendarMonths", ["2024-05-01", "2024-01-01"], 4, "src/differenceInCalendarMonths/test.ts covers calendar months."),
        ("datefns_difference_in_months_end_feb", "differenceInMonths", ["2021-03-28", "2021-02-28"], 1, "CHANGELOG references differenceInMonths February edge cases."),
        ("datefns_difference_in_seconds_floor", "differenceInSeconds", ["2024-01-01T00:00:01.900Z", "2024-01-01T00:00:00.000Z"], 1, "src/differenceInSeconds/test.ts covers truncating by default."),
        ("datefns_difference_in_seconds_ceil_option", "differenceInSeconds", ["2024-01-01T00:00:01.100Z", "2024-01-01T00:00:00.000Z", {"roundingMethod": "ceil"}], 2, "CHANGELOG v2.29.0 added roundingMethod options."),
        ("datefns_difference_in_minutes_floor", "differenceInMinutes", ["2024-01-01T00:01:59Z", "2024-01-01T00:00:00Z"], 1, "src/differenceInMinutes/test.ts covers truncating."),
        ("datefns_difference_in_hours_floor", "differenceInHours", ["2024-01-01T02:59:00Z", "2024-01-01T00:00:00Z"], 2, "src/differenceInHours/test.ts covers truncating."),
        ("datefns_difference_in_business_days", "differenceInBusinessDays", ["2024-05-27", "2024-05-20"], 5, "src/differenceInBusinessDays/test.ts covers business day deltas."),
        ("datefns_difference_in_quarters", "differenceInQuarters", ["2024-10-01", "2024-01-01"], 3, "src/differenceInQuarters/test.ts covers quarters."),
        ("datefns_difference_in_years", "differenceInYears", ["2024-01-01", "2020-01-01"], 4, "src/differenceInYears/test.ts covers years."),
    ]
    for name, fn, args, expected, evidence in diff:
        c(name, "date-difference", "datefns_call", {"fn": fn, "args": args, "result": "number"}, {"value": expected}, evidence)

    interval = [
        ("datefns_are_intervals_overlapping_false_abutting", "areIntervalsOverlapping", [{"start": "2020-01-01", "end": "2020-01-10"}, {"start": "2020-01-10", "end": "2020-01-20"}], "boolean", False, "src/areIntervalsOverlapping/test.ts covers adjacent intervals.", "interval_overlap_returns_intersection"),
        ("datefns_are_intervals_overlapping_true_inclusive", "areIntervalsOverlapping", [{"start": "2020-01-01", "end": "2020-01-10"}, {"start": "2020-01-10", "end": "2020-01-20"}, {"inclusive": True}], "boolean", True, "src/areIntervalsOverlapping/test.ts covers inclusive option."),
        ("datefns_is_within_interval_inclusive_start", "isWithinInterval", ["2020-01-01", {"start": "2020-01-01", "end": "2020-01-10"}], "boolean", True, "src/isWithinInterval/test.ts covers inclusive boundaries."),
        ("datefns_each_day_interval", "eachDayOfInterval", [{"start": "2020-01-01", "end": "2020-01-03"}], "date_list", "2020-01-01,2020-01-02,2020-01-03", "src/eachDayOfInterval/test.ts covers interval enumeration."),
        ("datefns_each_week_interval_monday", "eachWeekOfInterval", [{"start": "2020-01-01", "end": "2020-01-20"}, {"weekStartsOn": 1}], "date_list", "2019-12-30,2020-01-06,2020-01-13,2020-01-20", "src/eachWeekOfInterval/test.ts covers weekStartsOn."),
        ("datefns_each_month_interval", "eachMonthOfInterval", [{"start": "2020-01-15", "end": "2020-03-20"}], "date_list", "2020-01-01,2020-02-01,2020-03-01", "src/eachMonthOfInterval/test.ts covers month enumeration."),
        ("datefns_interval_to_duration_month_end", "intervalToDuration", [{"start": "2021-02-28", "end": "2021-03-28"}], "duration", "months=1", "CHANGELOG references intervalToDuration February edge cases."),
        ("datefns_clamp_below_interval", "clamp", ["2019-12-31", {"start": "2020-01-01", "end": "2020-01-10"}], "date", "2020-01-01", "CHANGELOG v2.25.0 added clamp."),
        ("datefns_closest_to", "closestTo", ["2020-01-05", ["2020-01-01", "2020-01-06", "2020-01-10"]], "date", "2020-01-06", "src/closestTo/test.ts covers closest date selection."),
        ("datefns_min_selects_earliest", "min", [["2020-01-03", "2020-01-01", "2020-01-02"]], "date", "2020-01-01", "src/min/test.ts covers earliest selection."),
        ("datefns_max_selects_latest", "max", [["2020-01-03", "2020-01-01", "2020-01-02"]], "date", "2020-01-03", "src/max/test.ts covers latest selection."),
    ]
    for name, fn, args, result, expected, evidence, *eq in interval:
        c(name, "interval.operations", "datefns_call", {"fn": fn, "args": args, "result": result}, {"value": expected}, evidence, common_equivalent=eq[0] if eq else None)

    parse_format = [
        ("datefns_parse_iso_calendar_date", "parseISO", ["2018-03-24"], "date", "2018-03-24", "src/parseISO/test.ts covers ISO date parsing.", "isoparse_parses_calendar_date"),
        ("datefns_parse_iso_week_date", "parseISO", ["2018-W12-6"], "date", "2018-03-24", "src/parseISO/test.ts covers ISO week dates.", "isoparse_parses_week_date"),
        ("datefns_parse_json_positive_offset", "parseJSON", ["2020-01-01T03:00:00+03:00"], "iso", "2020-01-01T00:00:00.000Z", "CHANGELOG added positive and negative offsets in parseJSON."),
        ("datefns_parse_json_space_separator", "parseJSON", ["2020-01-01 00:00:00Z"], "iso", "2020-01-01T00:00:00.000Z", "src/parseJSON/test.ts covers JSON-like strings."),
        ("datefns_format_iso_representation_date", "formatISO", ["2020-01-02T03:04:05Z", {"representation": "date"}], "string", "2020-01-02", "src/formatISO/test.ts covers representation option."),
        ("datefns_format_iso9075_complete", "formatISO9075", ["2020-01-02T03:04:05Z"], "string", "2020-01-02 03:04:05", "src/formatISO9075/test.ts covers SQL-like format."),
        ("datefns_format_rfc3339_fraction_digits", "formatRFC3339", ["2020-01-02T03:04:05.123Z", {"fractionDigits": 3}], "string", "2020-01-02T03:04:05.123Z", "src/formatRFC3339/test.ts covers fraction digits."),
        ("datefns_light_format_basic", "lightFormat", ["2020-01-02T03:04:05Z", "yyyy-MM-dd HH:mm:ss"], "string", "2020-01-02 03:04:05", "src/lightFormat/test.ts covers token formatting."),
        ("datefns_format_ordinal_day_en", "format", ["2020-01-02T00:00:00Z", "do"], "string", "2nd", "src/format/test.ts covers ordinal tokens."),
        ("datefns_parse_with_k_token_and_am", "parse", ["11 AM", "K a", "2020-01-01T00:00:00Z"], "hour", 11, "CHANGELOG v2.29.2 allowed K token with a/b in parse."),
    ]
    for name, fn, args, result, expected, evidence, *eq in parse_format:
        c(name, "parse-format", "datefns_call", {"fn": fn, "args": args, "result": result}, {"value": expected}, evidence, common_equivalent=eq[0] if eq else None)

    bools = [
        ("datefns_is_same_day_true", "isSameDay", ["2020-01-01T01:00:00Z", "2020-01-01T23:00:00Z"], True),
        ("datefns_is_same_month_true", "isSameMonth", ["2020-01-01", "2020-01-31"], True),
        ("datefns_is_same_quarter_false", "isSameQuarter", ["2020-03-31", "2020-04-01"], False),
        ("datefns_is_same_week_monday_option", "isSameWeek", ["2024-05-20", "2024-05-26", {"weekStartsOn": 1}], True),
        ("datefns_is_after_true", "isAfter", ["2020-01-02", "2020-01-01"], True),
        ("datefns_is_before_true", "isBefore", ["2020-01-01", "2020-01-02"], True),
        ("datefns_is_equal_true", "isEqual", ["2020-01-01", "2020-01-01"], True),
        ("datefns_is_leap_year_true", "isLeapYear", ["2024-01-01"], True),
        ("datefns_is_valid_false", "isValid", ["invalid"], False),
        ("datefns_is_weekend_saturday", "isWeekend", ["2024-05-25"], True),
    ]
    for name, fn, args, expected in bools:
        c(name, "date-predicate", "datefns_call", {"fn": fn, "args": args, "result": "boolean"}, {"value": expected}, f"src/{fn}/test.ts covers public predicate {fn}.")

    conversions = [
        ("datefns_days_to_weeks_truncates", "daysToWeeks", [-13.9], -1, "CHANGELOG v3.3.1 fixed negative fractional conversion truncation."),
        ("datefns_hours_to_minutes_truncates_negative", "hoursToMinutes", [-1.9], -114, "CHANGELOG v3.3.1 fixed negative fractional conversion truncation."),
        ("datefns_months_to_quarters", "monthsToQuarters", [7], 2, "CHANGELOG v2.22.0 added conversion functions."),
        ("datefns_quarters_to_months", "quartersToMonths", [3], 9, "CHANGELOG v2.22.0 added conversion functions."),
        ("datefns_years_to_months", "yearsToMonths", [2], 24, "CHANGELOG v2.22.0 added conversion functions."),
        ("datefns_seconds_to_milliseconds", "secondsToMilliseconds", [2], 2000, "CHANGELOG v2.22.0 added conversion functions."),
        ("datefns_milliseconds_to_seconds_trunc", "millisecondsToSeconds", [1999], 1, "src/millisecondsToSeconds/test.ts covers truncation."),
    ]
    for name, fn, args, expected, evidence in conversions:
        c(name, "unit-conversion", "datefns_call", {"fn": fn, "args": args, "result": "number"}, {"value": expected}, evidence)

    more_public = [
        ("datefns_format_distance_strict_month_unit", "formatDistanceStrict", ["2020-01-01", "2021-01-01", {"unit": "month"}], "string", "12 months", "CHANGELOG fixed formatDistanceStrict month-vs-year behavior."),
        ("datefns_format_duration_compact_units", "formatDuration", [{"years": 1, "months": 2, "days": 3}], "string", "1 year 2 months 3 days", "src/formatDuration/test.ts covers duration formatting."),
        ("datefns_each_weekend_of_interval", "eachWeekendOfInterval", [{"start": "2024-05-20", "end": "2024-05-27"}], "date_list", "2024-05-25,2024-05-26", "src/eachWeekendOfInterval/test.ts covers weekend enumeration."),
        ("datefns_each_quarter_of_interval", "eachQuarterOfInterval", [{"start": "2024-02-01", "end": "2024-11-01"}], "date_list", "2024-01-01,2024-04-01,2024-07-01,2024-10-01", "src/eachQuarterOfInterval/test.ts covers quarter enumeration."),
        ("datefns_next_day_friday", "nextDay", ["2024-05-22", 5], "date", "2024-05-24", "src/nextDay/test.ts covers day-of-week parameter."),
        ("datefns_previous_day_sunday", "previousDay", ["2024-05-22", 0], "date", "2024-05-19", "src/previousDay/test.ts covers day-of-week parameter."),
        ("datefns_start_of_decade", "startOfDecade", ["2024-05-22"], "date", "2020-01-01", "src/startOfDecade/test.ts covers decade boundaries."),
        ("datefns_last_day_of_decade", "lastDayOfDecade", ["2024-05-22"], "date", "2029-12-31", "src/lastDayOfDecade/test.ts covers decade boundaries."),
        ("datefns_is_exists_leap_day", "isExists", [2024, 1, 29], "boolean", True, "src/isExists/test.ts covers validating Y/M/D tuples."),
        ("datefns_is_exists_invalid_feb30", "isExists", [2024, 1, 30], "boolean", False, "src/isExists/test.ts covers invalid Y/M/D tuples."),
        ("datefns_construct_from_epoch", "constructFrom", ["2020-01-01", 0], "iso", "1970-01-01T00:00:00.000Z", "CHANGELOG v3.6.0 added constructNow/constructor-aware date construction."),
        ("datefns_transpose_keeps_instant_for_date_constructor", "transpose", ["2020-01-01T12:00:00Z", "Date"], "iso", "2020-01-01T12:00:00.000Z", "src/transpose/test.ts covers transpose."),
        ("datefns_is_monday_true", "isMonday", ["2024-05-27"], "boolean", True, "src/isMonday/test.ts covers weekday predicates."),
        ("datefns_is_friday_false", "isFriday", ["2024-05-27"], "boolean", False, "src/isFriday/test.ts covers weekday predicates."),
        ("datefns_get_quarter", "getQuarter", ["2024-05-22"], "number", 2, "src/getQuarter/test.ts covers quarter getter."),
        ("datefns_get_week_monday_option", "getWeek", ["2024-01-01", {"weekStartsOn": 1, "firstWeekContainsDate": 4}], "number", 1, "src/getWeek/test.ts covers local week options."),
        ("datefns_set_week_monday_option", "setWeek", ["2024-01-01", 10, {"weekStartsOn": 1, "firstWeekContainsDate": 4}], "date", "2024-03-04", "src/setWeek/test.ts covers local week options."),
        ("datefns_get_week_year_monday_option", "getWeekYear", ["2021-01-01", {"weekStartsOn": 1, "firstWeekContainsDate": 4}], "number", 2020, "src/getWeekYear/test.ts covers local week-year options."),
        ("datefns_add_weeks", "addWeeks", ["2024-01-01", 2], "date", "2024-01-15", "src/addWeeks/test.ts covers week arithmetic."),
        ("datefns_sub_weeks", "subWeeks", ["2024-01-15", 2], "date", "2024-01-01", "src/subWeeks/test.ts covers week arithmetic."),
        ("datefns_add_minutes", "addMinutes", ["2024-01-01T00:00:00Z", 90], "iso", "2024-01-01T01:30:00.000Z", "src/addMinutes/test.ts covers minute arithmetic."),
        ("datefns_sub_seconds", "subSeconds", ["2024-01-01T00:00:30Z", 45], "iso", "2023-12-31T23:59:45.000Z", "src/subSeconds/test.ts covers second arithmetic."),
    ]
    for name, fn, args, result, expected, evidence in more_public:
        c(name, "date-fns-public-surface", "datefns_call", {"fn": fn, "args": args, "result": result}, {"value": expected}, evidence)

    tz_cases = [
        ("datefns_tz_offset_new_york_summer", "tzOffset", ["America/New_York", "2020-07-01T12:00:00Z"], "number", -240, "pkgs/tz/src/tzOffset/tests.ts covers tzOffset."),
        ("datefns_tz_offset_st_johns_fractional", "tzOffset", ["America/St_Johns", "2020-01-01T12:00:00Z"], "number", -210, "CHANGELOG @date-fns/tz fixed negative fractional time zones."),
        ("datefns_tz_name_short_new_york", "tzName", ["America/New_York", "2020-01-01T12:00:00Z", "short"], "string", "EST", "CHANGELOG @date-fns/tz v1.1.0 added tzName."),
        ("datefns_tz_name_long_generic_paris", "tzName", ["Europe/Paris", "2020-01-01T12:00:00Z", "longGeneric"], "contains", "Central European Time", "CHANGELOG @date-fns/tz v1.1.0 added longGeneric."),
        ("datefns_tzdate_singapore_add_hours_across_dst_gap", "tzDateAddHours", ["America/Los_Angeles", "2022-03-13T01:30:00", 2], "local", "2022-03-13T04:30:00", "pkgs/tz CHANGELOG reworked DST handling."),
        ("datefns_tzdate_fields_singapore", "tzDateFields", ["Asia/Singapore", "2020-01-01T00:00:00Z"], "fields", "2020-01-01 08:00:00", "pkgs/tz README/tests cover TZDate fields."),
        ("datefns_format_in_tz_context", "formatInTimeZone", ["2024-09-09T00:00:00Z", "Asia/Singapore", "yyyy-MM-dd HH:mm XXX"], "string", "2024-09-09 08:00 +08:00", "CHANGELOG v4 added time-zone support to format functions."),
        ("datefns_tz_offset_colombo_historic_seconds", "tzOffset", ["Asia/Colombo", "1870-01-01T00:00:00Z"], "number", 319.4, "CHANGELOG @date-fns/tz v1.5.0 fixed historical seconds offsets."),
    ]
    for name, fn, args, result, expected, evidence in tz_cases:
        c(name, "timezone.date-fns-tz", "datefns_tz_call", {"fn": fn, "args": args, "result": result}, {"value": expected}, evidence)

    return out


PHP_RUNNER = r'''<?php
require __DIR__ . "/vendor/autoload.php";
use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterval;
use Carbon\CarbonPeriod;
use Carbon\CarbonTimeZone;
function boolv($v) { return $v ? "true" : "false"; }
function out($name, $actual, $errored = false) {
  foreach ($actual as $k => $v) {
    if (is_bool($v)) $actual[$k] = boolv($v);
    elseif (is_float($v) && floor($v) == $v) $actual[$k] = sprintf("%.1f", $v);
    else $actual[$k] = (string)$v;
  }
  echo json_encode(["name" => $name, "errored" => $errored, "actual" => $actual], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).PHP_EOL;
}
function periodDates($period) {
  $dates = [];
  foreach ($period as $d) {
    $dates[] = $d->format("Y-m-d");
    if (count($dates) > 20) break;
  }
  return implode(",", $dates);
}
function dispatch($c) {
  $p = $c["params"]; $op = $c["replay"];
  if ($op === "carbon_format") {
    return ["text" => CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC")->format($p["format"])];
  }
  if ($op === "carbon_iso_format") {
    return ["text" => CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC")->locale($p["locale"])->isoFormat($p["format"])];
  }
  if ($op === "carbon_method_format") {
    $d = CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC");
    switch ($p["method"]) {
      case "identity": break;
      case "addMonthNoOverflow": $d = $d->addMonthNoOverflow(); break;
      case "addMonthWithOverflow": $d = $d->addMonthWithOverflow(); break;
      case "subMonthNoOverflow": $d = $d->subMonthNoOverflow(); break;
      case "addMonthsNoOverflow2": $d = $d->addMonthsNoOverflow(2); break;
      case "subMonthsNoOverflow2": $d = $d->subMonthsNoOverflow(2); break;
      case "addQuarterNoOverflow": $d = $d->addQuartersNoOverflow(1); break;
      case "addYearNoOverflow": $d = $d->addYearNoOverflow(); break;
      case "addYearWithOverflow": $d = $d->addYearWithOverflow(); break;
      case "addWeekdays5": $d = $d->addWeekdays(5); break;
      case "subWeekdays1": $d = $d->subWeekdays(1); break;
      case "addDays10": $d = $d->addDays(10); break;
      case "subDays10": $d = $d->subDays(10); break;
      case "addHours25": $d = $d->addHours(25); break;
      case "subMinutes90": $d = $d->subMinutes(90); break;
      case "startOfMonth": $d = $d->startOfMonth(); break;
      case "endOfMonth": $d = $d->endOfMonth(); break;
      case "startOfQuarter": $d = $d->startOfQuarter(); break;
      case "endOfQuarter": $d = $d->endOfQuarter(); break;
      case "startOfWeek": $d = $d->startOfWeek(); break;
      case "endOfWeek": $d = $d->endOfWeek(); break;
      case "nextMonday": $d = $d->next(Carbon::MONDAY); break;
      case "previousFriday": $d = $d->previous(Carbon::FRIDAY); break;
      case "roundMinute": $d = $d->roundMinute(); break;
      case "floor15Minutes": $d = $d->floor(CarbonInterval::minutes(15)); break;
      case "ceil15Minutes": $d = $d->ceil(CarbonInterval::minutes(15)); break;
      case "floorHour": $d = $d->floorHour(); break;
      case "ceilHour": $d = $d->ceilHour(); break;
      case "roundHour": $d = $d->roundHour(); break;
      case "floorDay": $d = $d->floorDay(); break;
      case "ceilDay": $d = $d->ceilDay(); break;
      case "roundDay": $d = $d->roundDay(); break;
      case "firstOfMonth": $d = $d->firstOfMonth(); break;
      case "lastOfMonth": $d = $d->lastOfMonth(); break;
      case "secondMondayOfMonth": $d = $d->nthOfMonth(2, Carbon::MONDAY); break;
      default: throw new Exception("unsupported method ".$p["method"]);
    }
    return ["text" => $d->format($p["format"])];
  }
  if ($op === "carbon_predicate") {
    $d = CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC");
    if ($p["interval"]) $v = $d->{$p["method"]}(interval: $p["interval"]);
    else $v = $d->{$p["method"]}();
    return ["value" => $v];
  }
  if ($op === "carbon_diff") {
    $l = CarbonImmutable::parse($p["left"], $p["zone"]);
    $r = CarbonImmutable::parse($p["right"], $p["zone"]);
    return ["value" => $l->{$p["method"]}($r, false)];
  }
  if ($op === "carbon_interval") {
    $i = CarbonInterval::make($p["spec"]);
    switch ($p["operation"]) {
      case "forHumans": $v = $i->forHumans(["join" => true]); break;
      case "totalMinutes": $v = (string)$i->totalMinutes; break;
      case "cascade": $v = $i->cascade()->forHumans(["join" => true]); break;
      case "times2": $v = $i->times(2)->forHumans(["join" => true]); break;
      case "shares2": $v = $i->shares(2)->forHumans(["join" => true]); break;
      default: throw new Exception("unsupported interval op");
    }
    return ["value" => $v];
  }
  if ($op === "carbon_period") {
    if ($p["step"] === "quarterly") $period = CarbonPeriod::quarterly($p["start"]);
    else $period = CarbonPeriod::create($p["start"], $p["step"], $p["end"]);
    $option = $p["option"] ?? null;
    if ($option === "excludeStartDate") $period = $period->excludeStartDate();
    elseif ($option === "excludeEndDate") $period = $period->excludeEndDate();
    elseif ($option === "invert") $period = $period->invert();
    elseif (is_string($option) && str_starts_with($option, "recurrences:")) $period = $period->setRecurrences((int)substr($option, 12));
    return ["dates" => periodDates($period)];
  }
  if ($op === "carbon_timezone") {
    $tz = new CarbonTimeZone($p["zone"]);
    $date = CarbonImmutable::parse($p["date"]);
    if ($p["operation"] === "toOffsetName") return ["value" => $tz->toOffsetName($date)];
    if ($p["operation"] === "toRegionName") return ["value" => $tz->toRegionName($date)];
  }
  if ($op === "carbon_create_timestamp") {
    return ["text" => CarbonImmutable::createFromTimestamp($p["seconds"], $p["zone"])->format($p["format"])];
  }
  if ($op === "carbon_create_timestamp_ms") {
    return ["text" => CarbonImmutable::createFromTimestampMs($p["milliseconds"], $p["zone"])->format($p["format"])];
  }
  if ($op === "carbon_json") {
    return ["text" => trim(json_encode(CarbonImmutable::parse($p["text"], $p["zone"])), '"')];
  }
  if ($op === "carbon_set_timezone") {
    return ["text" => CarbonImmutable::parse($p["text"], $p["from"])->setTimezone($p["to"])->format($p["format"])];
  }
  if ($op === "carbon_shift_timezone") {
    return ["text" => CarbonImmutable::parse($p["text"], $p["from"])->shiftTimezone($p["to"])->format($p["format"])];
  }
  if ($op === "carbon_parse_locale") {
    return ["text" => CarbonImmutable::parseFromLocale($p["text"], $p["locale"])->format($p["format"])];
  }
  if ($op === "carbon_factory") {
    if ($p["operation"] === "create") {
      $d = CarbonImmutable::create($p["year"], $p["month"], $p["day"], $p["hour"], $p["minute"], $p["second"], $p["zone"]);
      return ["text" => $d->format($p["format"])];
    }
    if ($p["operation"] === "createMidnightDate") {
      $d = CarbonImmutable::createMidnightDate($p["year"], $p["month"], $p["day"], $p["zone"]);
      return ["text" => $d->format($p["format"])];
    }
    if ($p["operation"] === "createSafe") {
      $d = CarbonImmutable::createSafe($p["year"], $p["month"], $p["day"], $p["hour"], $p["minute"], $p["second"], $p["zone"]);
      return ["text" => $d->format($p["format"])];
    }
  }
  if ($op === "carbon_getter") {
    $d = CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC");
    return ["value" => $d->{$p["property"]}];
  }
  if ($op === "carbon_compare") {
    $d = CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC");
    if ($p["operation"] === "betweenIncluded") return ["value" => $d->betweenIncluded($p["left"], $p["right"])];
    if ($p["operation"] === "betweenExcluded") return ["value" => $d->betweenExcluded($p["left"], $p["right"])];
    if ($p["operation"] === "min") return ["text" => $d->min($p["left"])->format($p["format"])];
    if ($p["operation"] === "max") return ["text" => $d->max($p["left"])->format($p["format"])];
  }
  if ($op === "carbon_locale_name") {
    $d = CarbonImmutable::parse($p["text"], $p["zone"] ?? "UTC")->locale($p["locale"]);
    return ["text" => $d->{$p["property"]}];
  }
  throw new Exception("unsupported ".$op);
}
$contracts = json_decode(file_get_contents($argv[1]), true)["contracts"];
foreach ($contracts as $c) {
  try { out($c["name"], dispatch($c)); }
  catch (Throwable $e) { out($c["name"], ["throws" => get_class($e), "message" => $e->getMessage()], true); }
}
'''


JS_RUNNER = r'''const fs = require("fs");
const df = require("date-fns");
const tz = require("@date-fns/tz");
function asDate(v) {
  if (v instanceof Date) return v;
  if (typeof v === "string") {
    if (v === "invalid") return new Date(NaN);
    if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return new Date(v + "T00:00:00Z");
    return new Date(v);
  }
  if (v && typeof v === "object" && "start" in v && "end" in v) return { start: asDate(v.start), end: asDate(v.end) };
  if (Array.isArray(v)) return v.map(asDate);
  return v;
}
function prepOptionOrInterval(v) {
  if (Array.isArray(v)) return v.map(asDate);
  if (v && typeof v === "object" && !(v instanceof Date)) {
    if ("start" in v && "end" in v) return { start: asDate(v.start), end: asDate(v.end) };
    return v;
  }
  return asDate(v);
}
function prepArgs(fn, args) {
  if (["parseISO", "parseJSON"].includes(fn)) return args;
  if (["format", "lightFormat", "formatISO", "formatISO9075", "formatRFC3339"].includes(fn)) {
    return [asDate(args[0]), ...args.slice(1)];
  }
  if (fn === "parse") return [args[0], args[1], asDate(args[2]), ...args.slice(3)];
  if (fn === "closestTo") return [asDate(args[0]), args[1].map(asDate)];
  if (fn === "min" || fn === "max") return [args[0].map(asDate)];
  if (fn === "transpose") return [asDate(args[0]), Date];
  return args.map(prepOptionOrInterval);
}
function datePart(d) { return d.toISOString().slice(0, 10); }
function resultValue(result, value) {
  if (result === "date") return datePart(value);
  if (result === "iso") return value.toISOString();
  if (result === "number") return Number.isNaN(value) ? "NaN" : value;
  if (result === "boolean") return value;
  if (result === "string") return value;
  if (result === "contains") return value;
  if (result === "hour") return value.getUTCHours();
  if (result === "date_list") return value.map(datePart).join(",");
  if (result === "duration") return Object.entries(value).map(([k, v]) => `${k}=${v}`).join(",");
  throw new Error("unsupported result " + result);
}
function dispatch(c) {
  const p = c.params;
  if (c.replay === "datefns_call") {
    const fn = df[p.fn];
    if (!fn) throw new Error("missing fn " + p.fn);
    return { value: resultValue(p.result, fn(...prepArgs(p.fn, p.args))) };
  }
  if (c.replay === "datefns_tz_call") {
    const [a, b, c0] = p.args;
    if (p.fn === "tzOffset") return { value: tz.tzOffset(a, new Date(b)) };
    if (p.fn === "tzName") return { value: tz.tzName(a, new Date(b), c0) };
    if (p.fn === "tzDateFields") {
      const d = new tz.TZDate(new Date(b), a);
      const pad = (n) => String(n).padStart(2, "0");
      return { value: `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` };
    }
    if (p.fn === "tzDateAddHours") {
      const d = tz.TZDate.tz(a, ...aDateParts(b));
      const out = df.addHours(d, c0);
      const pad = (n) => String(n).padStart(2, "0");
      return { value: `${out.getFullYear()}-${pad(out.getMonth()+1)}-${pad(out.getDate())}T${pad(out.getHours())}:${pad(out.getMinutes())}:${pad(out.getSeconds())}` };
    }
    if (p.fn === "formatInTimeZone") {
      const ctx = tz.tz(b);
      return { value: df.format(new Date(a), c0, { in: ctx }) };
    }
  }
  throw new Error("unsupported replay " + c.replay);
}
function aDateParts(s) {
  const [d, t = "00:00:00"] = s.split("T");
  const [y, mo, da] = d.split("-").map(Number);
  const [h = 0, mi = 0, se = 0] = t.split(":").map(Number);
  return [y, mo - 1, da, h, mi, se];
}
const contracts = JSON.parse(fs.readFileSync(process.argv[2], "utf8")).contracts;
for (const c of contracts) {
  try {
    const actual = dispatch(c);
    for (const k of Object.keys(actual)) actual[k] = String(actual[k]);
    console.log(JSON.stringify({ name: c.name, errored: false, actual }));
  } catch (e) {
    console.log(JSON.stringify({ name: c.name, errored: true, actual: { throws: e.name, message: e.message } }));
  }
}
'''


def ensure_runtime(project: str) -> Path:
    if project == "carbon":
        CARBON_RUNTIME.mkdir(parents=True, exist_ok=True)
        if not (CARBON_RUNTIME / "vendor" / "autoload.php").exists():
            run(["composer", "require", f"nesbot/carbon:{CARBON_VERSION}", "--no-interaction", "--quiet"], cwd=CARBON_RUNTIME, timeout=360)
        runner = CARBON_RUNTIME / "runner.php"
        runner.write_text(PHP_RUNNER)
        return runner
    DATEFNS_RUNTIME.mkdir(parents=True, exist_ok=True)
    if not (DATEFNS_RUNTIME / "package.json").exists():
        run(["npm", "init", "-y"], cwd=DATEFNS_RUNTIME, timeout=60)
    if not (DATEFNS_RUNTIME / "node_modules" / "date-fns").exists():
        run(["npm", "install", f"date-fns@{DATEFNS_VERSION}", f"@date-fns/tz@{DATEFNS_TZ_VERSION}"], cwd=DATEFNS_RUNTIME, timeout=300)
    runner = DATEFNS_RUNTIME / "runner.js"
    runner.write_text(JS_RUNNER)
    return runner


def normalize(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return f"{value:.1f}"
    return str(value)


def compare(actual: dict[str, str], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, expected_value in expected.items():
        if key == "throws":
            ok = errored and str(expected_value) in actual.get("throws", "")
            return ok, "ok" if ok else f"expected throw {expected_value}, got {actual}"
        got = actual.get(key)
        if got is None:
            return False, f"missing key {key}; actual={actual}"
        if key == "value" and isinstance(expected_value, str) and expected_value.startswith("contains:"):
            needle = expected_value[len("contains:") :]
            if needle not in got:
                return False, f"expected {got!r} to contain {needle!r}"
            continue
        if isinstance(expected_value, (int, float)) and re.fullmatch(r"-?\d+(?:\.\d+)?", str(got)):
            if abs(float(got) - float(expected_value)) > 1e-9:
                return False, f"{key}: expected {normalize(expected_value)!r}, got {normalize(got)!r}"
            continue
        if normalize(expected_value) != normalize(got):
            return False, f"{key}: expected {normalize(expected_value)!r}, got {normalize(got)!r}"
    return (not errored), "ok" if not errored else f"unexpected error {actual}"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    for key, value in list(out.items()):
        if isinstance(value, bool):
            out[key] = not value
            return out
        if isinstance(value, int):
            out[key] = value + 1
            return out
        if isinstance(value, float):
            out[key] = value + 1.0
            return out
        if isinstance(value, str):
            out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def replay(project: str, contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    runner = ensure_runtime(project)
    payload = (CARBON_RUNTIME if project == "carbon" else DATEFNS_RUNTIME) / "contracts.json"
    payload.write_text(json.dumps({"contracts": contracts}, ensure_ascii=False, indent=2))
    if project == "carbon":
        stdout = run(["php", str(runner), str(payload)], cwd=CARBON_RUNTIME, timeout=180)
    else:
        stdout = run(["node", str(runner), str(payload)], cwd=DATEFNS_RUNTIME, timeout=180, env={"TZ": "UTC"})
    actual_by_name = {json.loads(line)["name"]: json.loads(line) for line in stdout.splitlines() if line.strip()}

    results = []
    for c in contracts:
        row = actual_by_name[c["name"]]
        replay_ok, reason = compare(row["actual"], c["expected"], row["errored"])
        mutant = mutate_expected(c["expected"])
        mutant_ok, mutant_reason = compare(row["actual"], mutant, row["errored"])
        results.append({
            "name": c["name"],
            "replay_ok": replay_ok,
            "reason": reason,
            "actual": row["actual"],
            "errored": row["errored"],
            "mutant_expected": mutant,
            "mutant_rejected": not mutant_ok,
            "mutant_reason": mutant_reason,
            "verified": replay_ok and not mutant_ok,
        })
    return results


def annotate_overlap(contracts: list[dict[str, Any]]) -> None:
    common_names = load_common_names()
    common_keys = load_common_semantic_keys()
    for c in contracts:
        c["overlaps_confirmed_common_250"] = bool(
            c["name"] in common_names
            or semantic_key(c) in common_keys
            or c.get("common_equivalent") in common_names
        )


def write_rpl(out_dir: Path, filename: str, contracts: list[dict[str, Any]]) -> None:
    lines = [
        f"# Generated by tools/replay/datetime_rank45_origin_extract_replay.py",
        "# Origin contracts are public-API, externally observable Date/Time/Timezone behavior.",
        "",
    ]
    for c in contracts:
        lines.extend([
            f'release "{c["origin_project"]}" version "{c["version"]}"',
            f'source "{c["source"]}"',
            f'contract "{c["name"]}"',
            f'evidence "{c["evidence"]}"',
            f'capability "{c["capability"]}"',
            f'replay "{c["replay"]}"',
            f'mutant "{c["mutant"]}"',
            f'overlaps_confirmed_common_250 {str(c["overlaps_confirmed_common_250"]).lower()}',
            f"given {json.dumps(c['params'], ensure_ascii=False, sort_keys=True)}",
            f"expect {json.dumps(c['expected'], ensure_ascii=False, sort_keys=True)}",
            "end",
            "",
        ])
    (out_dir / filename).write_text("\n".join(lines))


def source_stats(project: str) -> dict[str, Any]:
    if project == "carbon":
        repo = ORIGIN / "Carbon"
        tags = run(["git", "tag"], cwd=repo).splitlines() if repo.exists() else []
        releases = []
        api_file = ORIGIN / "carbon_releases_page1.json"
        if api_file.exists():
            releases = json.loads(api_file.read_text())
        return {
            "repo": "briannesbitt/Carbon",
            "git_tags_seen": len(tags),
            "github_release_records_cached": len(releases) if isinstance(releases, list) else 0,
            "source_paths_sampled": ["readme.md", "tests/Carbon", "tests/CarbonInterval", "tests/CarbonPeriod", "tests/CarbonTimeZone", "GitHub releases"],
        }
    repo = ORIGIN / "date-fns"
    tags = run(["git", "tag"], cwd=repo).splitlines() if repo.exists() else []
    core = ORIGIN / "date-fns" / "pkgs" / "core" / "CHANGELOG.md"
    tzlog = ORIGIN / "date-fns" / "pkgs" / "tz" / "CHANGELOG.md"
    return {
        "repo": "date-fns/date-fns",
        "git_tags_seen": len(tags),
        "core_changelog_releases_seen": len(re.findall(r"^## v", core.read_text(), re.M)) if core.exists() else 0,
        "tz_changelog_releases_seen": len(re.findall(r"^## v", tzlog.read_text(), re.M)) if tzlog.exists() else 0,
        "source_paths_sampled": ["pkgs/core/CHANGELOG.md", "pkgs/tz/CHANGELOG.md", "pkgs/core/src/*/test.ts", "pkgs/tz/src/*/tests.ts", "pkgs/tz/test/edge"],
    }


def write_summary(project_key: str, contracts: list[dict[str, Any]], results: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    result_by_name = {r["name"]: r for r in results}
    annotated = []
    for c in contracts:
        row = dict(c)
        row["latest_replay"] = result_by_name[c["name"]]
        annotated.append(row)

    verified = [c for c in annotated if c["latest_replay"]["verified"]]
    overlap_verified = [c for c in verified if c["overlaps_confirmed_common_250"]]
    non_common = [c for c in verified if not c["overlaps_confirmed_common_250"]]
    failed = [c for c in annotated if not c["latest_replay"]["verified"]]
    cap_counts = Counter(c["capability"] for c in non_common)
    summary = {
        "domain": "date-time-timezone",
        "origin_project": "Carbon" if project_key == "carbon" else "date-fns + @date-fns/tz",
        "latest_runtime": f"Carbon {CARBON_VERSION}" if project_key == "carbon" else f"date-fns {DATEFNS_VERSION} + @date-fns/tz {DATEFNS_TZ_VERSION}",
        "source_stats": source_stats(project_key),
        "counts": {
            "origin_contracts_extracted": len(contracts),
            "latest_replay_passed": sum(1 for r in results if r["replay_ok"]),
            "latest_replay_failed": sum(1 for r in results if not r["replay_ok"]),
            "mutant_rejected": sum(1 for r in results if r["mutant_rejected"]),
            "verified_survivors": len(verified),
            "verified_overlap_with_confirmed_common_250": len(overlap_verified),
            "verified_non_common_after_subtracting_common_250": len(non_common),
        },
        "non_common_capability_counts": dict(sorted(cap_counts.items())),
        "contracts": annotated,
        "non_common_contracts": non_common,
        "overlap_contracts": overlap_verified,
        "failed_contracts": failed,
    }
    (out_dir / "origin_latest_replay_mutant_verified.summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    write_rpl(out_dir, "origin_latest_replay_mutant_verified.rpl", annotated)
    write_rpl(out_dir, "non_common_after_confirmed_common_250.rpl", non_common)

    md = [
        f"# {summary['origin_project']} Origin Date/Time/Timezone Extraction",
        "",
        f"Latest runtime: {summary['latest_runtime']}",
        "",
        "## Counts",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for key, value in summary["counts"].items():
        md.append(f"| {key} | {value} |")
    md.extend(["", "## Non-common Capability Counts", "", "| Capability | Count |", "| --- | ---: |"])
    for key, value in sorted(cap_counts.items()):
        md.append(f"| `{key}` | {value} |")
    md.extend(["", "## Non-common Contracts", ""])
    for c in non_common:
        md.append(f"- `{c['name']}` ({c['capability']})")
    if failed:
        md.extend(["", "## Failed Latest Replay", ""])
        for c in failed[:30]:
            md.append(f"- `{c['name']}`: {c['latest_replay']['reason']}")
    (out_dir / "origin_latest_replay_mutant_verified.md").write_text("\n".join(md) + "\n")


def main() -> None:
    datasets = [
        ("carbon", carbon_contracts(), CARBON_OUT),
        ("date-fns", datefns_contracts(), DATEFNS_OUT),
    ]
    for project_key, contracts, out_dir in datasets:
        annotate_overlap(contracts)
        results = replay(project_key, contracts)
        write_summary(project_key, contracts, results, out_dir)
        data = json.loads((out_dir / "origin_latest_replay_mutant_verified.summary.json").read_text())
        counts = data["counts"]
        print(
            f"{project_key}: extracted={counts['origin_contracts_extracted']} "
            f"verified={counts['verified_survivors']} "
            f"overlap={counts['verified_overlap_with_confirmed_common_250']} "
            f"non_common={counts['verified_non_common_after_subtracting_common_250']}"
        )


if __name__ == "__main__":
    main()
