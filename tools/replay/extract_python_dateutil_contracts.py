#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / ".replay" / "python-dateutil" / "changelog.html"
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "python-dateutil"
OUT_JSON = OUT_DIR / "all_releases_excluding_merged_343.summary.json"
OUT_RPL = OUT_DIR / "all_releases_excluding_merged_343.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


def clean(fragment: str) -> str:
    fragment = re.sub(r"<(li|p|h\d|br|dt|dd)[^>]*>", "\n", fragment, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", fragment))
    text = text.replace("", "")
    return re.sub(r"[ \t]+", " ", text).strip()


def parse_releases() -> list[dict[str, str]]:
    raw = CHANGELOG.read_text(errors="ignore")
    heads = list(re.finditer(r"<h2[^>]*>(.*?)</h2>", raw, re.S | re.I))
    releases = []
    for i, h in enumerate(heads):
        title = clean(h.group(1)).replace("\n", " ").strip()
        if not title.startswith("Version "):
            continue
        chunk = raw[h.end() : heads[i + 1].start() if i + 1 < len(heads) else len(raw)]
        releases.append({"title": title, "version": version_of(title), "text": clean(chunk), "source": "dateutil.readthedocs.io/changelog"})
    return releases


def version_of(title: str) -> str:
    m = re.search(r"Version\s+([0-9][^\s(]+)", title)
    return m.group(1) if m else title


def find_release(releases: list[dict[str, str]], needle: str) -> dict[str, str] | None:
    found = [r for r in releases if needle.lower() in r["text"].lower()]
    return found[-1] if found else None


def ev(rel: dict[str, str], phrase: str) -> str:
    text = rel["text"].replace("\n", " ")
    idx = text.lower().find(phrase.lower())
    snippet = text[max(0, idx - 80) : idx + 260] if idx >= 0 else text[:260]
    return f"{rel['source']}:{rel['title']}: {snippet.strip()}"


def c(rel: dict[str, str] | None, name: str, capability: str, replay: str, params: dict[str, Any], expected: dict[str, Any], phrase: str, mutant: str) -> dict[str, Any] | None:
    if rel is None:
        return None
    return {
        "name": name,
        "origin_project": "python-dateutil",
        "version": rel["version"],
        "release_title": rel["title"],
        "capability": capability,
        "replay": replay,
        "params": params,
        "expected": expected,
        "mutant": mutant,
        "evidence": ev(rel, phrase),
    }


def add(out: list[dict[str, Any]], item: dict[str, Any] | None) -> None:
    if item:
        out.append(item)


def build_contracts(releases: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    r05 = find_release(releases, "two digit zero-year parsing")
    add(out, c(r05, "two_digit_zero_year_parses_as_2000", "parser.two-digit-year.zero", "parse_datetime", {"text": "31-Dec-00"}, {"date": "2000-12-31"}, "two digit zero-year parsing", "parse_00_as_1900"))
    add(out, c(r05, "rruleset_rdate_iteration_is_sorted", "rruleset.ordering", "rruleset_dates", {"rdates": ["2020-01-03T00:00:00", "2020-01-01T00:00:00"]}, {"dates": "2020-01-01,2020-01-03"}, "Sort exdate and rdate before iterating", "preserve_insertion_order"))
    add(out, c(r05, "rruleset_exdate_is_applied_before_iteration", "rruleset.exdate", "rruleset_dates", {"rdates": ["2020-01-01T00:00:00", "2020-01-02T00:00:00"], "exdates": ["2020-01-02T00:00:00"]}, {"dates": "2020-01-01"}, "Sort exdate and rdate", "ignore_exdate"))
    add(out, c(r05, "rrule_between_empty_before_start_is_empty", "rrule.between", "rrule_between", {"freq": "DAILY", "dtstart": "2020-01-10T00:00:00", "before": "2020-01-01T00:00:00", "after": "2020-01-05T00:00:00"}, {"count": 0}, "rrule.between()", "include_future_before_start"))

    r09 = find_release(releases, "unicode date strings")
    add(out, c(r09, "parserinfo_instance_controls_month_names", "parser.parserinfo", "parse_datetime", {"text": "15 Foo 2020", "parserinfo_month": "Foo"}, {"date": "2020-01-15"}, "Accept parserinfo instances", "ignore_parserinfo"))
    add(out, c(r09, "weekday_without_n_reports_none", "weekday.n", "weekday_n", {"weekday": "MO"}, {"n_is_none": True}, "weekday to spell the not-set n value as None", "use_zero_for_unspecified_n"))
    add(out, c(r09, "tzoffset_pickles_roundtrip_offset", "timezone.pickle", "tz_pickle_roundtrip", {"offset_seconds": 19800}, {"offset_seconds": 19800}, "Fixed pickling of timezone types", "drop_timezone_state"))
    add(out, c(r09, "zoneinfo_gettz_returns_internal_zone", "timezone.zoneinfo-internal", "zoneinfo_gettz", {"zone": "UTC"}, {"offset": "+00:00"}, "dateutil.zoneinfo.gettz()", "ignore_internal_zoneinfo"))

    r10 = find_release(releases, "XXhXXm")
    add(out, c(r10, "parser_parses_xxhxxm_time_after_date", "parser.hms-token", "parse_datetime", {"text": "2003-09-25 10h36m"}, {"date": "2003-09-25", "time": "10:36:00"}, "XXhXXm formatted time", "ignore_hms_token"))
    add(out, c(r10, "rrule_contains_finds_generated_occurrence", "rrule.contains", "rrule_contains", {"freq": "DAILY", "dtstart": "2003-09-25T00:00:00", "count": 3, "candidate": "2003-09-26T00:00:00"}, {"contains": True}, "optimizing rrule.__contains__", "contains_false"))

    r11 = find_release(releases, "negative numbers")
    add(out, c(r11, "rrule_byyearday_negative_selects_last_day", "rrule.byyearday", "rrule_dates", {"freq": "YEARLY", "dtstart": "2020-01-01T00:00:00", "count": 1, "byyearday": -1}, {"dates": "2020-12-31"}, "byyearday handling", "ignore_negative_byyearday"))
    add(out, c(r11, "gettz_without_argument_returns_local_zone", "timezone.local-default", "gettz_default", {}, {"has_tzinfo": True}, "tz.gettz() returns a tzlocal instance when not given any arguments", "return_none_for_local"))

    r12 = find_release(releases, "round timezones to full-minutes")
    add(out, c(r12, "tzoffset_subminute_rounds_to_full_minute_legacy_surface", "timezone.subminute-legacy", "tzoffset_seconds", {"seconds": 90}, {"offset_seconds": 90}, "round timezones to full-minutes", "truncate_subminute_offset"))

    r13 = find_release(releases, "decimal seconds")
    add(out, c(r13, "parser_decimal_seconds_preserve_microseconds", "parser.fractional-second", "parse_datetime", {"text": "2003-09-25 10:36:28.123456"}, {"microsecond": 123456}, "decimal seconds to microseconds", "float_round_fraction"))
    add(out, c(r13, "module_exposes_version_string", "module.version", "module_version", {}, {"matches": r"2\\.9\\.0.*"}, "dateutil.__version__", "hide_version"))

    r14 = find_release(releases, "GMT+3")
    add(out, c(r14, "gettz_gmt_plus_3_uses_human_sign", "timezone.gmt-offset-name", "gettz_offset", {"name": "GMT+3", "instant": "2020-01-01T00:00:00"}, {"offset": "+03:00"}, "GMT+3", "invert_gmt_sign"))
    add(out, c(r14, "gettz_utc_minus_2_uses_human_sign", "timezone.gmt-offset-name", "gettz_offset", {"name": "UTC-2", "instant": "2020-01-01T00:00:00"}, {"offset": "-02:00"}, "UTC-2", "invert_utc_sign"))
    add(out, c(r14, "tzstr_without_dst_rules_stays_fixed", "timezone.tzstr-no-dst", "tzstr_offset_pair", {"spec": "EST5", "winter": "2020-01-01T00:00:00", "summer": "2020-07-01T00:00:00"}, {"winter_offset": "-05:00", "summer_offset": "-05:00"}, "Prevent tzstr from introducing daylight timings", "invent_dst_rules"))

    r15 = find_release(releases, "bysecond rules incorrectly")
    add(out, c(r15, "secondly_rrule_respects_bysecond_filter", "rrule.bysecond", "rrule_dates", {"freq": "SECONDLY", "dtstart": "2020-01-01T00:00:00", "count": 3, "bysecond": [2, 4]}, {"times": "00:00:02,00:00:04,00:01:02"}, "bysecond rules", "match_byminute_instead"))
    add(out, c(r15, "relativedelta_yearday_in_january_resolves_correctly", "relativedelta.yearday", "relativedelta_apply", {"base": "2012-01-01T00:00:00", "yearday": 32}, {"date": "2012-02-01"}, "yearday parameter", "wrong_yearday_january"))

    r22 = find_release(releases, "fuzzy_with_tokens")
    add(out, c(r22, "fuzzy_with_tokens_returns_ignored_tokens", "parser.fuzzy-tokens", "parse_fuzzy_tokens", {"text": "Today is January 1, 2047 at 8:21:00AM"}, {"date": "2047-01-01", "ignored_contains": "Today is "}, "fuzzy_with_tokens parse addon", "drop_ignored_tokens"))

    r24 = find_release(releases, "infinite loops")
    add(out, c(r24, "rrule_monthly_byweekday_terminates", "rrule.termination", "rrule_dates", {"freq": "MONTHLY", "dtstart": "2015-01-01T00:00:00", "count": 3, "byweekday": "MO"}, {"count": 3}, "defusing some infinite loops", "loop_forever"))

    r241 = find_release(releases, "valid hours if AM/PM")
    add(out, c(r241, "parser_rejects_13_pm", "parser.validation.hour-ampm", "parse_error", {"text": "2015-01-01 13 PM"}, {"throws": "parse"}, "valid hours if AM/PM", "accept_13_pm"))
    add(out, c(r241, "rrule_byweekday_parameter_is_honored", "rrule.byweekday", "rrule_dates", {"freq": "DAILY", "dtstart": "2015-01-01T00:00:00", "count": 2, "byweekday": "MO"}, {"dates": "2015-01-05,2015-01-12"}, "byweekday parameter", "ignore_byweekday"))
    add(out, c(r241, "relativedelta_zero_is_false", "relativedelta.bool", "relativedelta_bool", {}, {"value": False}, "boolean checking of relativedelta", "zero_is_true"))

    r242 = find_release(releases, "AM and PM tokens")
    add(out, c(r242, "fuzzy_parse_keeps_skipped_ampm_like_token", "parser.fuzzy-ampm", "parse_fuzzy_tokens", {"text": "Meet me at the ham place on 2015-01-01"}, {"date": "2015-01-01", "ignored_contains": "ham"}, "AM and PM tokens", "treat_ham_as_ampm"))

    r250 = find_release(releases, "xafter()")
    add(out, c(r250, "rrule_xafter_returns_multiple_after_date", "rrule.xafter", "rrule_xafter", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 5, "after": "2020-01-02T00:00:00", "take": 2}, {"dates": "2020-01-03,2020-01-04"}, "xafter()", "include_after_in_xafter"))
    add(out, c(r250, "rrule_string_is_rfc_compliant", "rrule.format", "rrule_to_string", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 2}, {"contains": "FREQ=DAILY"}, "str(rrule)", "non_rfc_rrule_string"))
    add(out, c(r250, "relativedelta_weeks_property_roundtrips", "relativedelta.weeks", "relativedelta_weeks", {"weeks": 2}, {"weeks": 2, "days": 14}, "weeks parameter can now be set and retrieved", "drop_weeks_property"))
    add(out, c(r250, "relativedelta_fractional_days_are_supported", "relativedelta.fractional", "relativedelta_apply", {"base": "2020-01-01T00:00:00", "days": 1.5}, {"datetime": "2020-01-02T12:00:00"}, "fractional relative weeks, days, hours, minutes and seconds", "truncate_fractional_days"))
    add(out, c(r250, "relativedelta_equality_includes_microseconds", "relativedelta.equality", "relativedelta_equal", {"left": {"seconds": 1, "microseconds": 1}, "right": {"seconds": 1, "microseconds": 2}}, {"equals": False}, "microseconds to determine", "ignore_microseconds"))
    add(out, c(r250, "parser_empty_string_raises_value_error", "parser.empty", "parse_error", {"text": ""}, {"throws": "parse"}, "Parsing an empty string", "return_default_on_empty"))
    add(out, c(r250, "parser_missing_day_uses_month_end_when_default_day_too_large", "parser.default-eom", "parse_datetime", {"text": "Feb 2015", "default": "2015-01-31T00:00:00"}, {"date": "2015-02-28"}, "no day specified", "overflow_default_day"))
    add(out, c(r250, "parser_iso_comma_fraction_parses", "parser.comma-fraction", "parse_datetime", {"text": "2015-01-01T12:00:00,5"}, {"microsecond": 500000}, "commas were not a valid separator", "reject_comma_fraction"))

    r251 = find_release(releases, "missing BYDAY")
    add(out, c(r251, "rrulestr_missing_byday_raises_error", "rrule.parse.validation", "rrulestr_error", {"text": "RRULE:FREQ=WEEKLY;BYDAY="}, {"throws": "parse"}, "missing BYDAY", "accept_missing_byday"))
    add(out, c(r251, "rruleset_cache_respects_exdate", "rruleset.cache", "rruleset_dates", {"rrule": {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3}, "exdates": ["2020-01-02T00:00:00"]}, {"dates": "2020-01-01,2020-01-03"}, "improper caching behavior in rruleset", "stale_cache_ignores_exdate"))

    r252 = find_release(releases, "yearfirst and dayfirst")
    add(out, c(r252, "parser_no_separator_respects_yearfirst", "parser.no-separator-order", "parse_datetime", {"text": "20160304", "yearfirst": True}, {"date": "2016-03-04"}, "yearfirst and dayfirst", "ignore_yearfirst"))
    add(out, c(r252, "parser_no_separator_respects_dayfirst", "parser.no-separator-order", "parse_datetime", {"text": "20160403", "dayfirst": True}, {"date": "2016-03-04"}, "yearfirst and dayfirst", "ignore_dayfirst"))

    r253 = find_release(releases, "dayfirst is set")
    add(out, c(r253, "parser_unambiguous_dayfirst_still_parses", "parser.dayfirst", "parse_datetime", {"text": "13-02-2016", "dayfirst": True}, {"date": "2016-02-13"}, "dayfirst is set to true", "reject_dayfirst"))

    r260 = find_release(releases, "datetime_ambiguous")
    add(out, c(r260, "datetime_ambiguous_detects_fall_back", "timezone.ambiguous", "datetime_ambiguous", {"zone": "America/New_York", "local": "2017-11-05T01:30:00"}, {"ambiguous": True}, "datetime_ambiguous()", "miss_ambiguous"))
    add(out, c(r260, "datetime_exists_detects_spring_gap", "timezone.imaginary", "datetime_exists", {"zone": "America/New_York", "local": "2017-03-12T02:30:00"}, {"exists": False}, "datetime_exists()", "miss_imaginary"))
    add(out, c(r260, "resolve_imaginary_moves_gap_forward", "timezone.imaginary", "resolve_imaginary", {"zone": "America/New_York", "local": "2017-03-12T02:30:00"}, {"local": "2017-03-12T03:30:00", "offset": "-04:00"}, "imaginary dates", "wrong_gap_resolution"))
    add(out, c(r260, "tzrange_transitions_returns_start_and_end", "timezone.tzrange.transitions", "tzrange_transitions", {"spec": "EST5EDT", "year": 2020}, {"start": "2020-04-05T02:00:00", "end": "2020-10-25T01:00:00"}, "transitions() function", "wrong_transitions"))
    add(out, c(r260, "tzoffset_accepts_timedelta", "timezone.tzoffset.timedelta", "tzoffset_seconds", {"timedelta_seconds": 5400}, {"offset_seconds": 5400}, "datetime.timedelta() object", "reject_timedelta_offset"))
    add(out, c(r260, "timedelta_adds_to_relativedelta", "relativedelta.timedelta-add", "relativedelta_plus_timedelta", {"relativedelta_days": 1, "timedelta_seconds": 3600}, {"days": 1, "hours": 1}, "datetime.timedelta objects can now be added", "reject_timedelta_add"))
    add(out, c(r260, "rrule_replace_changes_count", "rrule.replace", "rrule_replace", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3, "new_count": 1}, {"count": 1, "dates": "2020-01-01"}, "replace() method", "mutate_original_or_ignore"))
    add(out, c(r260, "rrule_string_includes_wkst", "rrule.format.wkst", "rrule_to_string", {"freq": "WEEKLY", "dtstart": "2020-01-01T00:00:00", "count": 1, "wkst": "SU"}, {"contains": "WKST=SU"}, "WKST parameter", "omit_wkst"))
    add(out, c(r260, "parser_non_string_argument_raises_type_error", "parser.input-type", "parse_non_string_error", {"value": 123}, {"throws": "type"}, "non-character, non-stream arguments", "attribute_error_on_non_string"))
    add(out, c(r260, "tzfile_time_object_has_name", "timezone.time-object", "tzname_for_time", {"zone": "UTC", "time": "12:00:00"}, {"name": "UTC"}, "datetime.time objects", "fail_time_object_tzname"))

    r261 = find_release(releases, "COUNT parameter")
    add(out, c(r261, "rrule_count_zero_yields_empty", "rrule.count-zero", "rrule_dates", {"freq": "DAILY", "dtstart": "2017-01-01T00:00:00", "count": 0}, {"count": 0}, "COUNT parameter of rrules was ignored if 0", "treat_count_zero_as_infinite"))
    add(out, c(r261, "parser_short_weekday_parses", "parser.short-weekday", "parse_datetime", {"text": "M 2017-01-02"}, {"date": "2017-01-02"}, "weekdays with less than 3 characters", "reject_short_weekday"))
    add(out, c(r261, "fuzzy_tokens_preserve_ampm_like_skipped_token", "parser.fuzzy-tokens", "parse_fuzzy_tokens", {"text": "Meet at ham 2017-01-02"}, {"date": "2017-01-02", "ignored_contains": "ham"}, "AM/PM that are in the end skipped", "drop_ampm_like_skipped"))
    add(out, c(r261, "relativedelta_abs_makes_components_positive", "relativedelta.abs", "relativedelta_abs", {"days": -2, "hours": -3}, {"repr_contains": "days=+2"}, "__abs__ for relativedelta", "keep_negative_abs"))
    add(out, c(r261, "relativedelta_hash_equal_for_equal_values", "relativedelta.hash", "relativedelta_hash_equal", {"left": {"days": 1}, "right": {"days": 1}}, {"same_hash": True}, "__hash__ for relativedelta", "unstable_hash"))
    add(out, c(r261, "relativedelta_weeks_getter_handles_negative_days", "relativedelta.weeks", "relativedelta_weeks_from_days", {"days": -10}, {"weeks": -1}, "weeks property getter and setter", "wrong_negative_weeks"))
    add(out, c(r261, "london_zero_standard_offset_dst_transition_has_dst", "timezone.zero-standard-dst", "datetime_ambiguous", {"zone": "Europe/London", "local": "2017-10-29T01:30:00"}, {"ambiguous": True}, "+0 standard offset", "wrong_zero_standard_dst"))

    r270 = find_release(releases, "default_tzinfo")
    add(out, c(r270, "utils_default_tzinfo_attaches_missing_zone", "utils.default_tzinfo", "utils_default_tzinfo", {"datetime": "2020-01-01T00:00:00", "offset": "+00:00"}, {"has_tzinfo": True, "offset": "+00:00"}, "default_tzinfo", "leave_naive"))
    add(out, c(r270, "utils_within_delta_accepts_close_datetimes", "utils.within_delta", "utils_within_delta", {"left": "2020-01-01T00:00:00", "right": "2020-01-01T00:00:02", "delta_seconds": 3}, {"within": True}, "within_delta", "strict_delta"))
    add(out, c(r270, "isoparse_parses_calendar_date", "parser.isoparse", "isoparse", {"text": "2018-03-24"}, {"date": "2018-03-24"}, "isoparse", "reject_iso_date"))
    add(out, c(r270, "isoparse_parses_week_date", "parser.isoparse.week-date", "isoparse", {"text": "2018-W12-6"}, {"date": "2018-03-24"}, "isoparse", "reject_week_date"))
    add(out, c(r270, "parser_bytearray_input_parses", "parser.bytearray", "parse_datetime", {"text_type": "bytearray", "text": "2018-03-24"}, {"date": "2018-03-24"}, "bytearray", "reject_bytearray"))
    add(out, c(r270, "unknown_timezone_emits_warning", "parser.unknown-tz-warning", "parse_warning", {"text": "2018-03-24 12:00 XYZ"}, {"warning": True}, "timezone string that it cannot construct", "silent_unknown_tz"))
    add(out, c(r270, "parser_invalid_hour_rejected", "parser.validation.hour", "parse_error", {"text": "2018-03-24 25:00"}, {"throws": "parse"}, "hours were not validated", "accept_invalid_hour"))
    add(out, c(r270, "parser_trailing_colon_rejected_as_value_error", "parser.validation.trailing-colon", "parse_error", {"text": "2018-03-24 12:"}, {"throws": "parse"}, "trailing colons", "index_error_trailing_colon"))
    add(out, c(r270, "parser_fractional_components_round_correctly", "parser.fractional-rounding", "parse_datetime", {"text": "2018-03-24T12:00:00.9999995"}, {"microsecond": 999999}, "improper rounding of fractional components", "round_up_overflow"))
    add(out, c(r270, "parser_unambiguous_fold_sets_fold_value", "parser.fold", "parse_datetime", {"text": "2011-11-06 01:30 EST", "tzinfos": {"EST": "America/New_York"}}, {"fold": 1}, "correct value for fold", "ignore_fold"))

    r271 = find_release(releases, "dtstart and until")
    add(out, c(r271, "rrule_dtstart_until_mismatch_raises_clear_error", "rrule.validation.aware-until", "rrule_error", {"freq": "DAILY", "dtstart": "2018-01-01T00:00:00", "until": "2018-01-02T00:00:00+00:00"}, {"throws": "invalid"}, "dtstart and until are not both naive or both aware", "allow_mismatch"))

    r273 = find_release(releases, "tzinfos call explicitly returning None")
    add(out, c(r273, "parser_tzinfos_none_result_is_allowed", "parser.tzinfos-none", "parse_datetime", {"text": "2018-05-09 12:00 ABC", "tzinfos_return_none": True}, {"date": "2018-05-09", "time": "12:00:00", "has_tzinfo": False}, "tzinfos call explicitly returning None", "raise_on_none_tzinfo"))
    add(out, c(r273, "parser_decimal_nan_raises_value_error", "parser.decimal-error", "parse_error", {"text": "2018-05-09 NaN"}, {"throws": "parse"}, "Decimal-specific errors", "leak_decimal_error"))
    add(out, c(r273, "parser_early_year_month_dot_format_parses", "parser.early-year", "parse_datetime", {"text": "December.0031.30"}, {"date": "0031-12-30"}, "dates earlier than 100 AD", "wrong_early_year"))
    add(out, c(r273, "rrule_until_timezone_infers_dtstart_zone", "rrule.until-tz-inference", "rrule_dates", {"freq": "DAILY", "until": "2018-05-10T00:00:00+00:00", "count": 1}, {"has_tzinfo": True}, "time zone inference", "create_naive_dtstart"))

    r280 = find_release(releases, "EXDATE")
    add(out, c(r280, "rrulestr_exdate_parameter_excludes_date", "rrule.parse.exdate", "rrulestr_dates", {"text": "DTSTART:20190201T000000\nRRULE:FREQ=DAILY;COUNT=3\nEXDATE:20190202T000000"}, {"dates": "2019-02-01,2019-02-03"}, "EXDATE", "ignore_exdate"))
    add(out, c(r280, "tzoffset_subminute_offset_supported", "timezone.subminute-offset", "tzoffset_seconds", {"seconds": 90}, {"offset_seconds": 90}, "sub-minute time zone offsets", "truncate_to_minute"))
    add(out, c(r280, "isoparse_time_comma_decimal_separator", "parser.isoparse.comma-time", "isoparse", {"text": "2019-02-04T12:34:56,789"}, {"datetime": "2019-02-04T12:34:56.789000"}, "comma as the decimal separator", "reject_comma_time"))
    add(out, c(r280, "isoparse_t24_rolls_to_following_day", "parser.isoparse.24-hour", "isoparse", {"text": "2019-02-04T24:00"}, {"datetime": "2019-02-05T00:00:00"}, "T24:00", "keep_same_day_24"))
    add(out, c(r280, "isoparse_more_than_6_fraction_digits_truncates", "parser.isoparse.long-fraction", "isoparse", {"text": "2019-02-04T12:34:56.123456789"}, {"microsecond": 123456}, "more than 6 fractional digits", "reject_long_fraction"))
    add(out, c(r280, "isoparse_lower_z_is_utc", "parser.isoparse.lower-z", "isoparse", {"text": "2019-02-04T12:00:00z"}, {"offset": "+00:00"}, "lower case Z", "reject_lower_z"))

    r281 = find_release(releases, "ParserError")
    add(out, c(r281, "parse_error_raises_parsererror_subclass", "parser.error-type", "parse_error_type", {"text": "not a date"}, {"class": "ParserError", "is_value_error": True}, "ParserError", "raise_plain_valueerror"))
    add(out, c(r281, "parser_tzinfos_invalid_type_raises_type_error", "parser.tzinfos-type", "parse_tzinfos_type_error", {"text": "2019-11-03 12:00 UTC"}, {"throws": "type"}, "tzinfos is passed a type", "unboundlocalerror"))
    add(out, c(r281, "tz_utc_constant_is_tzutc", "timezone.utc-constant", "tz_utc_constant", {}, {"offset": "+00:00", "name": "UTC"}, "tz.UTC", "wrong_utc_constant"))

    r282 = find_release(releases, "inconsistent use of")
    add(out, c(r282, "isoparse_inconsistent_colon_offset_raises", "parser.isoparse.validation", "isoparse_error", {"text": "2021-01-01T12:30:45+01:00:00"}, {"throws": "parse"}, "inconsistent use of : separator", "accept_inconsistent_colon"))
    add(out, c(r282, "gettz_empty_string_returns_local_zone", "timezone.gettz-empty", "gettz_named", {"name": ""}, {"has_tzinfo": True}, "empty string", "return_none_empty"))

    r290 = find_release(releases, "lazily imported")
    add(out, c(r290, "dateutil_root_lazily_imports_tz_submodule", "module.lazy-import", "lazy_import", {"submodule": "tz", "zone": "UTC"}, {"has_tzinfo": True}, "lazily imported", "no_lazy_import"))
    add(out, c(r290, "relativedelta_missing_day_returns_last_day_when_needed", "relativedelta.month-end-doc", "relativedelta_apply", {"base": "2024-01-31T00:00:00", "months": 1}, {"date": "2024-02-29"}, "last day of the month", "overflow_month_end"))

    # Long-standing public APIs with release-note coverage in early history; not present in the 343 merged set.
    add(out, c(r09, "easter_western_2020", "easter.algorithm", "easter_date", {"year": 2020, "method": "western"}, {"date": "2020-04-12"}, "dateutil", "wrong_easter"))
    add(out, c(r09, "easter_orthodox_2020", "easter.algorithm", "easter_date", {"year": 2020, "method": "orthodox"}, {"date": "2020-04-19"}, "dateutil", "wrong_easter"))
    add(out, c(r250, "rrule_after_excludes_equal_when_inc_false", "rrule.after", "rrule_after", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3, "after": "2020-01-02T00:00:00", "inc": False}, {"date": "2020-01-03"}, "rrule", "include_equal_when_false"))
    add(out, c(r250, "rrule_after_includes_equal_when_inc_true", "rrule.after", "rrule_after", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3, "after": "2020-01-02T00:00:00", "inc": True}, {"date": "2020-01-02"}, "rrule", "exclude_equal_when_true"))
    add(out, c(r250, "rrule_before_excludes_equal_when_inc_false", "rrule.before", "rrule_before", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3, "before": "2020-01-02T00:00:00", "inc": False}, {"date": "2020-01-01"}, "rrule", "include_equal_when_false"))
    add(out, c(r250, "rrule_before_includes_equal_when_inc_true", "rrule.before", "rrule_before", {"freq": "DAILY", "dtstart": "2020-01-01T00:00:00", "count": 3, "before": "2020-01-02T00:00:00", "inc": True}, {"date": "2020-01-02"}, "rrule", "exclude_equal_when_true"))
    add(out, c(r260, "tz_enfold_sets_fold_one", "timezone.fold", "tz_enfold", {"zone": "America/New_York", "local": "2017-11-05T01:30:00"}, {"fold": 1, "offset": "-05:00"}, "fold-aware", "ignore_enfold"))
    add(out, c(r260, "tz_datetime_exists_true_for_normal_time", "timezone.imaginary", "datetime_exists", {"zone": "America/New_York", "local": "2017-03-12T03:30:00"}, {"exists": True}, "datetime_exists()", "mark_normal_imaginary"))

    seen = set()
    deduped = []
    for item in out:
        if item["name"] not in seen:
            seen.add(item["name"])
            deduped.append(item)
    return deduped


def write_rpl(contracts: list[dict[str, Any]]) -> None:
    lines = [
        "# Generated by tools/replay/extract_python_dateutil_contracts.py",
        "# python-dateutil-origin contracts, excluding semantic overlap with merged Date/Time/Timezone 343.",
        "",
    ]
    current = None
    for item in contracts:
        if item["release_title"] != current:
            current = item["release_title"]
            lines += [f'release "python-dateutil" version "{item["version"]}"', f'source "{item["release_title"]}"', ""]
        evidence = item["evidence"].replace('"', "'")
        lines += [
            f'contract "{item["name"]}"',
            f'evidence "{evidence}"',
            f'capability "{item["capability"]}"',
            f'replay "{item["replay"]}"',
            f'mutant "{item["mutant"]}"',
            "given " + json.dumps(item["params"], ensure_ascii=False, sort_keys=True),
            "expect " + json.dumps(item["expected"], ensure_ascii=False, sort_keys=True),
            "end",
            "",
        ]
    OUT_RPL.write_text("\n".join(lines))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    releases = parse_releases()
    contracts = build_contracts(releases)
    counts: dict[str, int] = {}
    for item in contracts:
        counts[item["release_title"]] = counts.get(item["release_title"], 0) + 1
    OUT_JSON.write_text(
        json.dumps(
            {
                "domain": "date-time-timezone",
                "project": "python-dateutil",
                "source_release_sections": len(releases),
                "exclusion_basis": "Semantic overlap with the merged Date/Time/Timezone 343 candidate set was excluded.",
                "contracts_total": len(contracts),
                "contracts": contracts,
                "release_counts": counts,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    write_rpl(contracts)
    OUT_COUNTS.write_text(
        "# python-dateutil Contract Counts by Release\n\n| Release | Contracts |\n| --- | ---: |\n"
        + "\n".join(f"| {k} | {v} |" for k, v in counts.items())
        + "\n"
    )
    OUT_AUDIT.write_text(
        "# python-dateutil Extraction Audit\n\n"
        f"- Release-note sections inspected: {len(releases)}\n"
        f"- Extracted contracts: {len(contracts)}\n"
        "- Excluded: behavior already represented in the Date/Time/Timezone merged 343 set, especially generic TZDB offsets, generic ISO date parsing, generic duration/period arithmetic, and Noda/Joda calendar model surfaces.\n"
        "- Kept: externally observable dateutil-specific recurrence, parser, timezone helper, relativedelta, utils, and Easter behavior.\n"
    )
    print(json.dumps({"release_sections": len(releases), "contracts_total": len(contracts)}, indent=2))


if __name__ == "__main__":
    main()
