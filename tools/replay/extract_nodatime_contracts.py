#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
VERSIONS_HTML = ROOT / ".replay" / "nodatime" / "versions.html"
GITHUB_RELEASES = ROOT / ".replay" / "nodatime" / "github_releases_page1.json"
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "nodatime"
OUT_JSON = OUT_DIR / "all_releases_excluding_joda_common.summary.json"
OUT_RPL = OUT_DIR / "all_releases_excluding_joda_common.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


def clean_html(fragment: str) -> str:
    fragment = re.sub(r"<(li|p|h\d|br)[^>]*>", r" \n", fragment, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", fragment))
    return re.sub(r"[ \t]+", " ", text).strip()


def parse_release_notes() -> list[dict[str, Any]]:
    raw = VERSIONS_HTML.read_text(errors="ignore")
    start = raw.find("<h1>Version history</h1>")
    body = raw[start:] if start >= 0 else raw
    heads = list(re.finditer(r"<h2[^>]*>(.*?)</h2>", body, re.S | re.I))
    releases: list[dict[str, Any]] = []
    for i, head in enumerate(heads):
        title = clean_html(head.group(1)).replace("\n", " ").strip()
        chunk = body[head.end() : heads[i + 1].start() if i + 1 < len(heads) else len(body)]
        text = clean_html(chunk)
        releases.append({"title": title, "text": text, "source": "nodatime.org/versions"})
    if GITHUB_RELEASES.exists():
        by_tag = {r.get("tag_name"): r for r in json.loads(GITHUB_RELEASES.read_text())}
        for rel in releases:
            versions = extract_versions(rel["title"])
            for version in versions:
                gh = by_tag.get(version)
                if gh and gh.get("body") and gh["body"] not in rel["text"]:
                    rel["text"] += "\n" + gh["body"]
                    rel["source"] += "+github-releases"
    return releases


def extract_versions(title: str) -> list[str]:
    left = title.split(", released", 1)[0].split(", release", 1)[0]
    return re.findall(r"\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?|\d+\.\d+", left)


def version_key(rel: dict[str, Any]) -> str:
    versions = extract_versions(rel["title"])
    return versions[0] if versions else rel["title"]


def evidence(rel: dict[str, Any], phrase: str) -> str:
    title = rel["title"]
    text = rel["text"].replace("\n", " ")
    idx = text.lower().find(phrase.lower())
    if idx >= 0:
        snippet = text[max(0, idx - 80) : idx + 240]
    else:
        snippet = text[:260]
    return f"{rel['source']}:{title}: {snippet.strip()}"


def contract(rel: dict[str, Any], name: str, capability: str, replay: str, params: dict[str, Any], expected: dict[str, Any], phrase: str, mutant: str) -> dict[str, Any]:
    return {
        "name": name,
        "origin_project": "Noda Time",
        "version": version_key(rel),
        "release_title": rel["title"],
        "capability": capability,
        "replay": replay,
        "params": params,
        "expected": expected,
        "mutant": mutant,
        "evidence": evidence(rel, phrase),
    }


def find_releases(releases: list[dict[str, Any]], needle: str) -> list[dict[str, Any]]:
    return [r for r in releases if needle.lower() in r["text"].lower()]


def first_release(releases: list[dict[str, Any]], needle: str) -> dict[str, Any] | None:
    found = find_releases(releases, needle)
    return found[-1] if found else None


def add_if(out: list[dict[str, Any]], rel: dict[str, Any] | None, *args: Any) -> None:
    if rel:
        out.append(contract(rel, *args))


def build_contracts(releases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    r100 = first_release(releases, "CalendarSystem.Id")
    for cal, expected_id in [
        ("ISO", "ISO"),
        ("Coptic", "Coptic"),
        ("Julian", "Julian"),
        ("IslamicBcl", "Hijri Astronomical-Base16"),
    ]:
        add_if(out, r100, f"calendar_{cal.lower()}_has_stable_id", "calendar.id", "calendar_id", {"calendar": cal}, {"id": expected_id}, "CalendarSystem.Id", "change_calendar_id")
    add_if(out, r100, "calendar_for_id_roundtrips_iso", "calendar.lookup", "calendar_for_id", {"id": "ISO"}, {"calendar": "ISO"}, "ForId() factory", "lookup_wrong_calendar")
    add_if(out, r100, "calendar_ids_include_iso", "calendar.lookup", "calendar_ids", {}, {"contains": "ISO"}, "Ids static property", "omit_iso_calendar")
    add_if(out, r100, "local_date_calendar_pattern_includes_calendar_id", "local-date.format.calendar", "format_local_date_calendar", {"date": "2012-11-07", "calendar": "ISO"}, {"text": "2012-11-07 (ISO)"}, "custom format specifier", "drop_calendar_id")
    add_if(out, r100, "local_time_fraction_accepts_comma_separator", "local-time.parse.fraction-separator", "parse_local_time", {"text": "12:34:56,789", "format": "extended_iso"}, {"time": "12:34:56.789"}, "parse both comma and period", "reject_comma_fraction")
    add_if(out, r100, "local_datetime_fraction_accepts_comma_separator", "local-datetime.parse.fraction-separator", "parse_local_datetime", {"text": "2012-11-07T12:34:56,789", "format": "extended_iso"}, {"local": "2012-11-07T12:34:56.789"}, "parse both comma and period", "reject_comma_fraction")
    add_if(out, r100, "local_datetime_roundtrip_pattern_preserves_calendar", "local-datetime.format.calendar", "format_local_datetime_calendar", {"local": "2012-11-07T01:02:03", "calendar": "ISO"}, {"contains": "ISO"}, "standard pattern", "drop_calendar_id")

    rrc1 = first_release(releases, "FromWeekYearWeekAndDay")
    add_if(out, rrc1, "iso_weekyear_week_day_creates_expected_date", "week-year.creation", "weekyear_date", {"week_year": 2020, "week": 1, "day": "Monday"}, {"date": "2019-12-30"}, "FromWeekYearWeekAndDay", "miscompute_weekyear")
    add_if(out, rrc1, "negative_absolute_year_parses", "local-date.parse.signed-year", "parse_local_date_pattern", {"text": "-0001-01-02", "pattern": "uuuu-MM-dd"}, {"year": -1, "month": 1, "day": 2}, "parse negative values", "reject_negative_year")
    add_if(out, rrc1, "tzdb_source_exposes_aliases", "timezone.metadata.aliases", "tzdb_aliases", {"canonical": "Europe/London"}, {"contains": "GB"}, "Aliases and CanonicalIdMap", "omit_aliases")
    add_if(out, rrc1, "tzdb_source_exposes_canonical_map", "timezone.metadata.aliases", "tzdb_canonical_map", {"id": "UTC"}, {"canonical": "Etc/UTC"}, "CanonicalIdMap", "wrong_canonical_map")
    add_if(out, rrc1, "tzdb_source_exposes_windows_mapping", "timezone.metadata.windows", "windows_mapping", {"windows": "GMT Standard Time"}, {"contains": "Europe/London"}, "WindowsMapping", "drop_windows_mapping")
    add_if(out, rrc1, "tzdb_source_exposes_zone_locations", "timezone.metadata.locations", "zone_locations", {"zone": "Europe/London"}, {"country": "GB"}, "ZoneLocations", "drop_zone_locations")
    add_if(out, rrc1, "tzdb_source_version_is_exposed", "timezone.metadata.version", "tzdb_version", {}, {"matches": r"\\d{4}[a-z].*"}, "TzdbVersion", "hide_tzdb_version")
    add_if(out, rrc1, "local_datetime_24_hour_rolls_to_next_day", "local-datetime.parse.24-hour", "parse_local_datetime_24", {"text": "2013-03-28T24:00:00"}, {"local": "2013-03-29T00:00:00"}, "24:00:00", "reject_24_hour")
    add_if(out, rrc1, "instant_from_unix_ticks_roundtrips", "instant.factory.unix", "instant_from_unix", {"unit": "ticks", "value": 1234567890}, {"iso": "1970-01-01T00:02:03.456789Z"}, "From(Ticks,Milliseconds,Seconds)SinceUnixEpoch", "wrong_unix_ticks")
    add_if(out, rrc1, "instant_from_unix_milliseconds_roundtrips", "instant.factory.unix", "instant_from_unix", {"unit": "milliseconds", "value": 123456789}, {"iso": "1970-01-02T10:17:36.789Z"}, "From(Ticks,Milliseconds,Seconds)SinceUnixEpoch", "wrong_unix_millis")
    add_if(out, rrc1, "local_time_from_milliseconds_since_midnight", "local-time.factory.day-unit", "local_time_from_day_unit", {"unit": "milliseconds", "value": 45296789}, {"time": "12:34:56.789"}, "From(Ticks,Milliseconds,Seconds)SinceMidnight", "wrong_day_millis")
    add_if(out, rrc1, "local_time_from_seconds_since_midnight", "local-time.factory.day-unit", "local_time_from_day_unit", {"unit": "seconds", "value": 45296}, {"time": "12:34:56"}, "From(Ticks,Milliseconds,Seconds)SinceMidnight", "wrong_day_seconds")
    add_if(out, rrc1, "local_datetime_in_utc_keeps_local_fields", "local-datetime.conversion.utc", "local_datetime_in_utc", {"local": "2013-03-28T12:00:00"}, {"instant": "2013-03-28T12:00:00Z"}, "LocalDateTime.InUtc()", "shift_local_datetime")
    add_if(out, rrc1, "local_datetime_with_offset_uses_supplied_offset", "local-datetime.conversion.offset", "local_datetime_with_offset", {"local": "2013-03-28T12:00:00", "offset": "+02:00"}, {"instant": "2013-03-28T10:00:00Z", "offset": "+02:00"}, "WithOffset()", "ignore_offset")

    rb2 = first_release(releases, "OffsetDateTime representing")
    add_if(out, rb2, "offset_datetime_preserves_local_and_offset", "offset-datetime.core", "offset_datetime_create", {"local": "2012-08-04T12:00:00", "offset": "+02:30"}, {"local": "2012-08-04T12:00:00", "offset": "+02:30"}, "OffsetDateTime representing", "drop_offset")
    add_if(out, rb2, "offset_pattern_general_with_z_prints_z_for_zero", "offset.pattern.zero", "format_offset", {"offset": "+00:00", "pattern": "G"}, {"text": "Z"}, "using \"Z\" for zero", "print_zero_numeric")
    add_if(out, rb2, "period_zero_fields_are_omitted", "period.format.zero-omission", "format_period", {"period": "P0Y2M0DT0H"}, {"text": "P2M"}, "omits all zero values", "print_zero_fields")
    add_if(out, rb2, "duration_epsilon_is_one_nanosecond", "duration.constant.epsilon", "duration_constant", {"constant": "Epsilon"}, {"nanoseconds": 1}, "added Epsilon", "wrong_epsilon")

    r110 = first_release(releases, "OffsetDateTime.Comparer")
    add_if(out, r110, "offset_datetime_instant_comparer_ignores_local_offset_difference", "offset-datetime.compare.instant", "offset_datetime_compare", {"left": "2013-04-06T12:00:00+02:00", "right": "2013-04-06T10:00:00Z", "mode": "instant"}, {"comparison": 0}, "compare values by either the local date/time or the underlying instant", "compare_by_local")
    add_if(out, r110, "offset_datetime_local_comparer_uses_local_time", "offset-datetime.compare.local", "offset_datetime_compare", {"left": "2013-04-06T12:00:00+02:00", "right": "2013-04-06T10:00:00Z", "mode": "local"}, {"comparison": 1}, "compare values by either the local date/time or the underlying instant", "compare_by_instant")

    r120 = first_release(releases, "DurationPattern")
    add_if(out, r120, "duration_pattern_parses_iso_seconds", "duration.pattern.parse", "parse_duration_pattern", {"text": "0:00:01:02.003"}, {"millis": 62003}, "DurationPattern", "wrong_duration_pattern")
    add_if(out, r120, "duration_default_string_is_descriptive", "duration.format.default", "format_duration_default", {"millis": 1500}, {"contains": "0:00:00:01.5"}, "Duration.ToString()", "wrong_duration_string")
    add_if(out, r120, "offset_datetime_pattern_parses_embedded_offset", "offset-datetime.pattern.parse", "parse_offset_datetime_pattern", {"text": "2013-11-16T12:00:00+02:00"}, {"instant": "2013-11-16T10:00:00Z", "offset": "+02:00"}, "OffsetDateTimePattern", "ignore_embedded_offset")
    add_if(out, r120, "zoned_datetime_pattern_parses_embedded_zone_id", "zoned-datetime.pattern.parse", "parse_zoned_datetime_pattern", {"text": "2013-11-16T12:00:00 Europe/London"}, {"zone": "Europe/London", "local": "2013-11-16T12:00:00"}, "ZonedDateTimePattern", "ignore_embedded_zone")
    add_if(out, r120, "local_datetime_general_iso_pattern_outputs_t_separator", "local-datetime.pattern.general", "format_local_datetime_pattern", {"local": "2013-11-16T12:34:56", "pattern": "general_iso"}, {"text": "2013-11-16T12:34:56"}, "GeneralIsoPattern", "wrong_general_iso")
    add_if(out, r120, "local_datetime_full_roundtrip_contains_calendar", "local-datetime.pattern.full-roundtrip", "format_local_datetime_pattern", {"local": "2013-11-16T12:34:56", "pattern": "full_roundtrip", "calendar": "ISO"}, {"contains": "ISO"}, "FullRoundtripPattern", "drop_calendar_id")
    add_if(out, r120, "five_digit_year_formats_without_ambiguity", "local-date.format.large-year", "format_large_year_date", {"year": -9998, "month": 6, "day": 7}, {"text": "-9998-06-07"}, "five-digit years", "truncate_large_year")
    add_if(out, r120, "instant_min_label_can_be_replaced", "instant.pattern.minmax-label", "instant_minmax_label", {"which": "min", "label": "START"}, {"text": "START"}, "WithMinMaxLabels", "ignore_min_label")
    add_if(out, r120, "instant_with_offset_converts_to_offset_datetime", "instant.conversion.offset", "instant_with_offset", {"instant": "2013-11-16T12:00:00Z", "offset": "+02:00"}, {"local": "2013-11-16T14:00:00", "offset": "+02:00"}, "Instant.WithOffset()", "ignore_offset")
    add_if(out, r120, "offset_datetime_with_calendar_changes_calendar_not_instant", "offset-datetime.calendar", "offset_datetime_with_calendar", {"local": "2013-11-16T12:00:00", "offset": "+00:00", "calendar": "Julian"}, {"offset": "+00:00", "calendar": "Julian"}, "WithCalendar()", "drop_calendar")
    add_if(out, r120, "interval_contains_instant_inside", "interval.contains.instant", "interval_contains", {"interval": "2013-11-16T12:00:00Z/2013-11-16T13:00:00Z", "instant": "2013-11-16T12:30:00Z"}, {"contains": True}, "Interval.Contains()", "invert_contains")
    add_if(out, r120, "zoned_datetime_exposes_calendar", "zoned-datetime.calendar", "zoned_datetime_calendar", {"local": "2013-11-16T12:00:00", "zone": "UTC", "calendar": "Julian"}, {"calendar": "Julian"}, "ZonedDateTime.Calendar", "drop_calendar")
    add_if(out, r120, "zoned_datetime_get_zone_interval_returns_interval_name", "zoned-datetime.zone-interval", "zoned_zone_interval", {"instant": "2013-07-01T12:00:00Z", "zone": "Europe/London"}, {"name": "BST"}, "GetZoneInterval()", "wrong_zone_interval")

    r130 = first_release(releases, "Persian/Solar Hijri")
    for cal in ["PersianSimple", "PersianArithmetic", "PersianAstronomical"]:
        add_if(out, r130, f"{cal.lower()}_calendar_month_one_has_31_days", "calendar.persian", "calendar_days_in_month", {"calendar": cal, "year": 1393, "month": 1}, {"days": 31}, "Persian/Solar Hijri calendar", "wrong_days_in_month")
    for cal in ["HebrewCivil", "HebrewScriptural"]:
        add_if(out, r130, f"{cal.lower()}_calendar_month_one_has_30_days", "calendar.hebrew", "calendar_days_in_month", {"calendar": cal, "year": 5774, "month": 1}, {"days": 30}, "Hebrew calendar", "wrong_days_in_month")
    add_if(out, r130, "local_date_at_local_time_combines_fields", "local-date.combine", "local_date_at_time", {"date": "2014-06-27", "time": "12:34:56"}, {"local": "2014-06-27T12:34:56"}, "LocalDate.At(LocalTime)", "swap_date_time")
    add_if(out, r130, "local_time_on_local_date_combines_fields", "local-date.combine", "local_time_on_date", {"date": "2014-06-27", "time": "12:34:56"}, {"local": "2014-06-27T12:34:56"}, "LocalTime.On(LocalDate)", "swap_date_time")
    add_if(out, r130, "offset_datetime_with_offset_preserves_instant", "offset-datetime.with-offset", "offset_datetime_with_offset", {"local": "2014-06-27T12:00:00", "offset": "+00:00", "new_offset": "+02:00"}, {"local": "2014-06-27T14:00:00", "offset": "+02:00"}, "WithOffset()", "preserve_local_not_instant")
    add_if(out, r130, "zoned_datetime_reports_dst_in_london_summer", "zoned-datetime.dst", "zoned_is_dst", {"instant": "2014-07-01T12:00:00Z", "zone": "Europe/London"}, {"is_dst": True}, "IsDaylightSavingTime()", "ignore_dst")
    add_if(out, r130, "offset_datetime_rfc3339_pattern_roundtrips", "offset-datetime.pattern.rfc3339", "format_offset_datetime_rfc3339", {"local": "2014-06-27T12:34:56", "offset": "+02:00"}, {"text": "2014-06-27T12:34:56+02:00"}, "Rfc3339Pattern", "wrong_rfc3339")
    add_if(out, r130, "zoned_pattern_g_parses_era_when_provider_supplied", "zoned-datetime.pattern.era", "parse_zoned_era_pattern", {"text": "AD 2014-06-27T12:00:00 Europe/London"}, {"zone": "Europe/London", "year": 2014}, "G and F standard patterns", "ignore_era")
    add_if(out, r130, "interval_to_string_uses_iso_interval", "interval.format.iso", "format_interval", {"interval": "2014-06-27T12:00:00Z/2014-06-27T13:00:00Z"}, {"text": "2014-06-27T12:00:00Z/2014-06-27T13:00:00Z"}, "Interval.ToString() to ISO-8601 interval format", "wrong_interval_format")

    r131 = first_release(releases, "Russian time zones before 2014-10-26")
    add_if(out, r131, "moscow_pre_2014_uses_correct_offset", "timezone.bcl-russian-history", "zone_offset", {"zone": "Europe/Moscow", "instant": "2014-10-25T12:00:00Z"}, {"offset": "+04:00"}, "Russian time zones before 2014-10-26", "wrong_moscow_offset")
    add_if(out, r131, "bcl_timezone_wrappers_compare_by_underlying_zone", "timezone.bcl-equality", "zone_equality", {"zone": "UTC"}, {"equals": True}, "considered equal if they wrap the same underlying TimeZoneInfo", "always_not_equal")

    r132 = first_release(releases, "month number of 0")
    add_if(out, r132, "date_parse_month_zero_returns_failed_parse", "local-date.parse.validation", "parse_result_local_date", {"text": "2016-00-01"}, {"success": False}, "month number of 0", "throw_on_parse_result")

    r20 = first_release(releases, "Nanosecond precision")
    add_if(out, r20, "instant_supports_nanosecond_fraction", "instant.precision.nanosecond", "instant_nanosecond_fraction", {"text": "2017-03-31T12:00:00.123456789Z"}, {"nanosecond_of_second": 123456789}, "Nanosecond precision", "truncate_to_millis")
    add_if(out, r20, "duration_supports_nanosecond_component", "duration.precision.nanosecond", "duration_from_nanoseconds", {"nanoseconds": 123456789}, {"nanoseconds": 123456789}, "Nanosecond precision", "truncate_to_millis")
    add_if(out, r20, "date_adjuster_end_of_month_moves_to_last_day", "local-date.adjuster", "date_adjuster", {"date": "2017-02-10", "adjuster": "end_of_month"}, {"date": "2017-02-28"}, "Date and time adjusters", "wrong_end_of_month")
    add_if(out, r20, "annual_date_matches_same_month_day", "annual-date.core", "annual_date_match", {"annual_date": "--06-19", "date": "1976-06-19"}, {"matches": True}, "AnnualDate", "wrong_annual_date")
    add_if(out, r20, "date_interval_contains_end_date_inclusively", "date-interval.contains", "date_interval_contains", {"start": "2017-03-01", "end": "2017-03-03", "date": "2017-03-03"}, {"contains": True}, "DateInterval", "exclude_end_date")
    add_if(out, r20, "date_interval_length_counts_inclusive_days", "date-interval.length", "date_interval_length", {"start": "2017-03-01", "end": "2017-03-03"}, {"days": 3}, "DateInterval", "exclusive_length")
    add_if(out, r20, "week_year_rule_iso_week_one_crosses_year_boundary", "week-year.rule", "weekyear_date", {"week_year": 2017, "week": 1, "day": "Sunday"}, {"date": "2017-01-08"}, "WeekYearRules", "wrong_week_rule")
    add_if(out, r20, "lenient_resolver_maps_gap_forward", "timezone.resolver.lenient", "lenient_resolver", {"zone": "Europe/London", "local": "2017-03-26T01:30:00"}, {"local": "2017-03-26T02:30:00", "offset": "+01:00"}, "LenientResolver", "wrong_gap_resolver")
    add_if(out, r20, "calendar_system_exposes_coptic_property", "calendar.property", "calendar_id", {"calendar": "Coptic"}, {"id": "Coptic"}, "Simpler calendar access", "wrong_calendar_property")
    add_if(out, r20, "local_date_day_of_week_is_iso_named_value", "local-date.day-of-week", "local_date_day_of_week", {"date": "2017-03-31"}, {"day": "Friday"}, "DayOfWeek", "wrong_day_of_week")
    add_if(out, r20, "culture_provider_rejects_non_culture_format_provider", "text.culture-validation", "invalid_format_provider", {}, {"throws": "invalid"}, "only CultureInfo and DateTimeFormatInfo", "accept_any_provider")

    r210 = first_release(releases, "LocalDate.MinIsoValue")
    add_if(out, r210, "local_date_min_iso_value_has_year_minus_9998", "local-date.bounds", "local_date_bound", {"which": "min"}, {"year": -9998}, "LocalDate.MinIsoValue", "wrong_min_date")
    add_if(out, r210, "local_date_max_iso_value_has_year_9999", "local-date.bounds", "local_date_bound", {"which": "max"}, {"year": 9999}, "LocalDate.MinIsoValue", "wrong_max_date")
    add_if(out, r210, "parse_result_success_exposes_value", "text.parse-result", "parse_result_local_date", {"text": "2017-07-09"}, {"success": True, "date": "2017-07-09"}, "ParseResult", "drop_parse_value")

    r221 = first_release(releases, "Etc/GMT-12")
    add_if(out, r221, "timezone_parser_accepts_etc_gmt_minus_12", "timezone.parse.prefix", "zone_id", {"id": "Etc/GMT-12"}, {"canonical_id": "Etc/GMT-12"}, "Etc/GMT-12", "prefix_match_wrong_zone")
    add_if(out, r221, "etc_gmt_minus_12_has_positive_12_offset", "timezone.parse.prefix", "zone_offset", {"zone": "Etc/GMT-12", "instant": "2017-10-14T00:00:00Z"}, {"offset": "+12:00"}, "Etc/GMT-12", "wrong_etc_gmt_sign")
    add_if(out, r221, "instant_subtract_duration_checks_lower_bound", "instant.bounds", "instant_minus_duration_bound", {"instant": "min", "duration_days": 1}, {"throws": "overflow"}, "bounds checking bypassed", "allow_underflow")
    add_if(out, r221, "unknown_standard_pattern_error_mentions_percent", "text.pattern.error", "unknown_pattern_error", {"pattern": "%"}, {"contains": "%"}, "unknown standard patterns", "vague_pattern_error")

    r230 = first_release(releases, "Badí")
    add_if(out, r230, "badi_calendar_has_19_day_months", "calendar.badi", "calendar_days_in_month", {"calendar": "Badi", "year": 1, "month": 1}, {"days": 19}, "Badí", "wrong_badi_month")
    add_if(out, r230, "offset_date_preserves_date_and_offset", "offset-date.core", "offset_date_create", {"date": "2018-05-19", "offset": "+03:00"}, {"date": "2018-05-19", "offset": "+03:00"}, "OffsetDate", "drop_offset")
    add_if(out, r230, "offset_time_preserves_time_and_offset", "offset-time.core", "offset_time_create", {"time": "12:34:56", "offset": "-03:00"}, {"time": "12:34:56", "offset": "-03:00"}, "OffsetTime", "drop_offset")
    add_if(out, r230, "offset_datetime_in_zone_converts_to_zone", "offset-datetime.in-zone", "offset_datetime_in_zone", {"local": "2018-05-19T12:00:00", "offset": "+00:00", "zone": "Europe/London"}, {"local": "2018-05-19T13:00:00", "zone": "Europe/London"}, "OffsetDateTime.InZone", "retain_wrong_local")
    add_if(out, r230, "date_interval_contains_nested_interval", "date-interval.contains-interval", "date_interval_contains_interval", {"outer_start": "2018-05-01", "outer_end": "2018-05-31", "inner_start": "2018-05-10", "inner_end": "2018-05-20"}, {"contains": True}, "Contains(DateInterval)", "wrong_interval_contains")
    add_if(out, r230, "date_interval_intersection_returns_overlap", "date-interval.intersection", "date_interval_intersection", {"left_start": "2018-05-01", "left_end": "2018-05-10", "right_start": "2018-05-05", "right_end": "2018-05-20"}, {"start": "2018-05-05", "end": "2018-05-10"}, "Intersection", "wrong_intersection")
    add_if(out, r230, "date_interval_union_returns_covering_interval", "date-interval.union", "date_interval_union", {"left_start": "2018-05-01", "left_end": "2018-05-10", "right_start": "2018-05-11", "right_end": "2018-05-20"}, {"start": "2018-05-01", "end": "2018-05-20"}, "Union", "wrong_union")
    add_if(out, r230, "date_interval_iteration_is_inclusive", "date-interval.iteration", "date_interval_iterate", {"start": "2018-05-01", "end": "2018-05-03"}, {"dates": "2018-05-01,2018-05-02,2018-05-03"}, "iteration", "exclusive_iteration")
    add_if(out, r230, "annual_date_text_roundtrips_month_day", "annual-date.text", "annual_date_parse_format", {"text": "--05-19"}, {"text": "--05-19"}, "Text handling for AnnualDate", "wrong_annual_text")
    add_if(out, r230, "local_date_min_method_returns_earlier_date", "local-date.minmax", "local_date_minmax", {"left": "2018-05-20", "right": "2018-05-19", "mode": "min"}, {"date": "2018-05-19"}, "Min / Max methods", "wrong_min")
    add_if(out, r230, "local_time_max_method_returns_later_time", "local-time.minmax", "local_time_minmax", {"left": "12:00:00", "right": "13:00:00", "mode": "max"}, {"time": "13:00:00"}, "Min / Max methods", "wrong_max")
    add_if(out, r230, "local_datetime_deconstruct_exposes_date_and_time", "local-datetime.deconstruct", "local_datetime_deconstruct", {"local": "2018-05-19T12:34:56"}, {"date": "2018-05-19", "time": "12:34:56"}, "Deconstruct", "swap_deconstruct")

    r300 = first_release(releases, "LocalTime.FromHoursSinceMidnight")
    add_if(out, r300, "local_time_from_hours_since_midnight", "local-time.factory.day-unit", "local_time_from_day_unit", {"unit": "hours", "value": 12}, {"time": "12:00:00"}, "FromHoursSinceMidnight", "wrong_hour_factory")
    add_if(out, r300, "local_time_from_minutes_since_midnight", "local-time.factory.day-unit", "local_time_from_day_unit", {"unit": "minutes", "value": 754}, {"time": "12:34:00"}, "FromMinutesSinceMidnight", "wrong_minute_factory")
    add_if(out, r300, "date_adjuster_add_period_applies_month_then_day", "local-date.adjuster.period", "date_adjuster_add_period", {"date": "2020-01-31", "period": "P1M1D"}, {"date": "2020-03-01"}, "date adjuster to add a period", "wrong_period_adjuster")
    add_if(out, r300, "local_time_roundtrip_o_preserves_nanos", "local-time.pattern.roundtrip", "format_local_time_pattern", {"time": "12:34:56.123456789", "pattern": "o"}, {"text": "12:34:56.123456789"}, "o and O invariant round-trip", "truncate_nanos")
    add_if(out, r300, "local_date_iso_standard_pattern_formats_date", "local-date.pattern.iso", "format_local_date_pattern", {"date": "2020-05-22", "pattern": "D"}, {"text": "2020-05-22"}, "standard LocalDate patterns for ISO", "wrong_iso_date_pattern")
    add_if(out, r300, "instant_pattern_template_supplies_missing_date", "instant.pattern.template", "parse_instant_with_template", {"text": "12:34:56Z", "template": "2020-05-22T00:00:00Z"}, {"iso": "2020-05-22T12:34:56Z"}, "template value to InstantPattern", "ignore_template")
    add_if(out, r300, "duration_roundtrip_pattern_preserves_fractional_seconds", "duration.pattern.roundtrip", "format_duration_roundtrip", {"nanoseconds": 1234567890}, {"text": "0:00:00:01.23456789"}, "roundtrip pattern for durations", "wrong_duration_roundtrip")
    add_if(out, r300, "local_time_general_iso_formats_hh_mm_ss", "local-time.pattern.general", "format_local_time_pattern", {"time": "12:34:56", "pattern": "general_iso"}, {"text": "12:34:56"}, "GeneralIso", "wrong_general_iso")
    add_if(out, r300, "local_date_month_day_pattern_uses_culture_month_day", "local-date.pattern.month-day", "format_local_date_pattern", {"date": "2020-05-22", "pattern": "M", "locale": "en-US"}, {"contains": "May"}, "month/day pattern", "wrong_month_day_pattern")
    add_if(out, r300, "period_equality_operators_compare_components", "period.equality", "period_equals", {"left": "P1DT2H", "right": "P1DT2H"}, {"equals": True}, "equality operators to Period", "wrong_period_equality")
    add_if(out, r300, "year_month_comparison_orders_by_year_then_month", "year-month.compare", "year_month_compare", {"left": "2020-05", "right": "2020-06"}, {"comparison": -1}, "comparison operators to YearMonth", "wrong_year_month_compare")
    add_if(out, r300, "year_month_type_converter_roundtrips_text", "year-month.text", "year_month_parse_format", {"text": "2020-05"}, {"text": "2020 May"}, "type converter for YearMonth", "wrong_year_month_text")

    r310 = first_release(releases, "YearMonth.PlusMonths")
    add_if(out, r310, "year_month_to_string_uses_year_and_month_name", "year-month.format", "year_month_parse_format", {"text": "2022-04"}, {"text": "2022 April"}, "ToString method for YearMonth", "wrong_year_month_string")
    add_if(out, r310, "period_between_year_months_counts_years_and_months", "period.between.year-month", "period_between_year_month", {"start": "2022-04", "end": "2024-06"}, {"iso": "P2Y2M"}, "Period.Between overload accepting YearMonth", "wrong_period_between")
    add_if(out, r310, "period_days_between_counts_date_difference", "period.days-between", "period_days_between", {"start": "2022-04-18", "end": "2022-04-21"}, {"days": 3}, "Period.DaysBetween", "wrong_days_between")
    add_if(out, r310, "local_datetime_min_iso_value_has_min_year", "local-datetime.bounds", "local_datetime_bound", {"which": "min"}, {"year": -9998}, "LocalDateTime.MinIsoValue", "wrong_min_local_datetime")
    add_if(out, r310, "local_date_max_iso_value_has_max_year", "local-date.bounds", "local_date_bound", {"which": "max"}, {"year": 9999}, "LocalDate.MaxIsoValue", "wrong_max_local_date")
    add_if(out, r310, "bad_pattern_error_reports_bad_specifier", "text.pattern.error", "bad_pattern_error", {"pattern": "uuuu-QQ-dd"}, {"contains": "Q"}, "Improved error messages for bad format specifiers", "vague_bad_pattern")

    r320 = first_release(releases, "reduced precision")
    add_if(out, r320, "local_datetime_iso_reduced_precision_year_month_parses", "local-datetime.pattern.reduced-precision", "parse_local_datetime_reduced", {"text": "2024-10", "precision": "year_month"}, {"local": "2024-10-01T00:00:00"}, "reduced precision", "reject_reduced_precision")
    add_if(out, r320, "local_datetime_iso_reduced_precision_date_parses", "local-datetime.pattern.reduced-precision", "parse_local_datetime_reduced", {"text": "2024-10-13", "precision": "date"}, {"local": "2024-10-13T00:00:00"}, "reduced precision", "reject_date_only")
    add_if(out, r320, "local_time_iso_hour_minute_parses", "local-time.pattern.reduced-precision", "parse_local_time_reduced", {"text": "12:34"}, {"time": "12:34:00"}, "More LocalTime ISO formats", "reject_hour_minute")
    add_if(out, r320, "local_time_iso_hour_only_parses", "local-time.pattern.reduced-precision", "parse_local_time_reduced", {"text": "12"}, {"time": "12:00:00"}, "More LocalTime ISO formats", "reject_hour_only")
    add_if(out, r320, "two_digit_year_max_value_controls_century_low", "local-date.parse.two-digit-year-max", "parse_two_digit_year_max", {"text": "49-01-02", "max": 49}, {"date": "2049-01-02"}, "2 digit year max value", "wrong_two_digit_window")
    add_if(out, r320, "two_digit_year_max_value_controls_century_high", "local-date.parse.two-digit-year-max", "parse_two_digit_year_max", {"text": "50-01-02", "max": 49}, {"date": "1950-01-02"}, "2 digit year max value", "wrong_two_digit_window")
    add_if(out, r320, "unparsable_exception_exposes_value", "text.parse-error.detail", "parse_error_detail", {"text": "not-a-date"}, {"contains": "not-a-date"}, "unparsed value", "drop_error_value")
    add_if(out, r320, "instant_unix_seconds_and_nanoseconds_splits_fraction", "instant.unix.split", "instant_unix_seconds_nanos", {"instant": "2024-10-13T00:00:01.234567890Z"}, {"seconds": 1728777601, "nanoseconds": 234567890}, "ToUnixTimeSecondsAndNanoseconds", "drop_nanos")
    add_if(out, r320, "duration_from_nanoseconds_int128_preserves_value", "duration.nanoseconds", "duration_from_nanoseconds", {"nanoseconds": 1234567890123}, {"nanoseconds": 1234567890123}, "Duration.FromNanoseconds", "truncate_nanos")
    add_if(out, r320, "period_min_value_is_less_than_zero_period", "period.bounds", "period_bound_compare", {"which": "min"}, {"less_than_zero": True}, "Period.MinValue", "wrong_period_min")
    add_if(out, r320, "period_max_value_is_greater_than_zero_period", "period.bounds", "period_bound_compare", {"which": "max"}, {"greater_than_zero": True}, "Period.MaxValue", "wrong_period_max")

    r330 = first_release(releases, "NanosecondsBetween")
    add_if(out, r330, "period_nanoseconds_between_counts_difference", "period.nanoseconds-between", "period_nanoseconds_between", {"start": "2026-01-03T00:00:00.000000001", "end": "2026-01-03T00:00:00.000000010"}, {"nanoseconds": 9}, "Period.NanosecondsBetween", "wrong_nanoseconds_between")
    add_if(out, r330, "duration64_preserves_small_nanosecond_duration", "high-performance.duration64", "duration64", {"nanoseconds": 123456789}, {"nanoseconds": 123456789}, "Duration64", "wrong_duration64")
    add_if(out, r330, "instant64_preserves_unix_epoch_nanoseconds", "high-performance.instant64", "instant64", {"epoch_nanoseconds": 123456789}, {"epoch_nanoseconds": 123456789}, "Instant64", "wrong_instant64")

    seen: set[str] = set()
    deduped = []
    for c in out:
        if c["name"] in seen:
            continue
        seen.add(c["name"])
        deduped.append(c)
    return deduped


def write_rpl(contracts: list[dict[str, Any]]) -> None:
    lines = [
        "# Generated by tools/replay/extract_nodatime_contracts.py",
        "# Noda Time-origin contracts, excluding semantic overlap with the 223 Joda-origin Rank2/3 common contracts.",
        "",
    ]
    current_release = None
    for c in contracts:
        if c["release_title"] != current_release:
            current_release = c["release_title"]
            lines += [f'release "nodatime" version "{c["version"]}"', f'source "{c["release_title"]}"', ""]
        lines += [
            f'contract "{c["name"]}"',
            f'evidence "{c["evidence"].replace(chr(34), chr(39))}"',
            f'capability "{c["capability"]}"',
            f'replay "{c["replay"]}"',
            f'mutant "{c["mutant"]}"',
            "given " + json.dumps(c["params"], ensure_ascii=False, sort_keys=True),
            "expect " + json.dumps(c["expected"], ensure_ascii=False, sort_keys=True),
            "end",
            "",
        ]
    OUT_RPL.write_text("\n".join(lines))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    releases = parse_release_notes()
    contracts = build_contracts(releases)
    counts: dict[str, int] = {}
    for c in contracts:
        counts[c["release_title"]] = counts.get(c["release_title"], 0) + 1
    OUT_JSON.write_text(
        json.dumps(
            {
                "domain": "date-time-timezone",
                "project": "Noda Time",
                "source_release_sections": len(releases),
                "exclusion_basis": "Semantic overlap with 223 Joda-Time-origin contracts that survived both Noda Time and python-dateutil latest cross-validation.",
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
        "# Noda Time Contract Counts by Release\n\n"
        "| Release | Contracts |\n| --- | ---: |\n"
        + "\n".join(f"| {k} | {v} |" for k, v in counts.items())
        + "\n"
    )
    OUT_AUDIT.write_text(
        "# Noda Time Extraction Audit\n\n"
        f"- Release-note sections inspected: {len(releases)}\n"
        f"- Extracted contracts: {len(contracts)}\n"
        "- Excluded: generic TZDB offset/presence contracts, generic interval/duration/period basics, docs/build/runtime-target-only changes, and other behavior already represented by the 223 Joda-origin common contracts.\n"
        "- Kept: externally observable Noda Time date/time/timezone model behavior that can be replayed through the latest NodaTime package.\n"
    )
    print(json.dumps({"release_sections": len(releases), "contracts_total": len(contracts)}, indent=2))


if __name__ == "__main__":
    main()
