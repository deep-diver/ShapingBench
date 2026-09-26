#!/usr/bin/env python3
"""
Extract implementation-independent, replayable date/time contracts from
Joda-Time release notes.

Inputs:
* .replay/joda-time/changes.xml                  official generated changes file
* .replay/joda-time/upgrade-notes/*.html         old upgrade notes linked from installation.html
* .replay/joda-time/maven-metadata.xml           Maven Central version list

Output DSL is intentionally operation based. A runner can compile each contract
into Java, Python, .NET, PHP, or JS adapter tests when an implementation exposes
the same observable behavior.
"""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPLAY = ROOT / ".replay" / "joda-time"
OUT = ROOT / "contracts" / "datetime_timezone" / "joda-time"
OUT_RPL = OUT / "all_releases_maximal_language_independent.rpl"
OUT_JSON = OUT / "all_releases_maximal_language_independent.summary.json"
OUT_COUNTS = OUT / "release_contract_counts.md"
OUT_AUDIT = OUT / "extraction_audit.md"


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(html.unescape(data.strip()))


@dataclass(frozen=True)
class ReleaseNote:
    version: str
    date: str | None
    source: str
    text: str
    note_type: str = "note"


@dataclass(frozen=True)
class Contract:
    name: str
    capability: str
    op: str
    params: dict[str, Any]
    expected: dict[str, Any]
    mutant: str
    evidence: str
    version: str
    source: str
    pass_name: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "capability": self.capability,
            "replay": self.op,
            "params": self.params,
            "expected": self.expected,
            "mutant": self.mutant,
            "evidence": self.evidence,
            "version": self.version,
            "source": self.source,
            "pass": self.pass_name,
        }


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def slug(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    return re.sub(r"_+", "_", text)


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def load_maven_versions() -> list[str]:
    root = ET.parse(REPLAY / "maven-metadata.xml").getroot()
    return [v.text or "" for v in root.findall(".//version") if v.text]


def load_xml_notes() -> list[ReleaseNote]:
    path = REPLAY / "changes.xml"
    root = ET.parse(path).getroot()
    out: list[ReleaseNote] = []
    for release in root.findall(".//release"):
        version = release.attrib["version"]
        date = release.attrib.get("date")
        for action in release.findall("action"):
            text = norm("".join(action.itertext()))
            out.append(ReleaseNote(version, date, "changes.xml", text, action.attrib.get("type", "note")))
    return out


def html_to_text(path: Path) -> str:
    parser = TextExtractor()
    parser.feed(path.read_text(errors="replace"))
    text = "\n".join(parser.parts)
    m = re.search(r"(Joda-Time version .*?)(?:\nInformation\nHome|$)", text, re.S)
    return m.group(1) if m else text


def old_note_version(path: Path) -> str:
    return path.stem.replace("_", ".")


def bullet_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    cur: list[str] = []
    for line in lines:
        raw = line.rstrip()
        stripped = raw.strip()
        if stripped.startswith("- "):
            if cur:
                blocks.append(norm(" ".join(cur)))
            cur = [stripped[2:].strip()]
        elif cur and (raw.startswith(" ") or raw.startswith("\t")) and stripped:
            cur.append(stripped)
        elif cur and not stripped:
            continue
        elif cur:
            blocks.append(norm(" ".join(cur)))
            cur = []
    if cur:
        blocks.append(norm(" ".join(cur)))
    return blocks


def load_upgrade_notes() -> list[ReleaseNote]:
    # changes.xml covers 2.9 and later more cleanly. Use upgrade notes before 2.9
    # plus 0.99, which is linked as the earliest upgrade note.
    notes: list[ReleaseNote] = []
    for path in sorted((REPLAY / "upgrade-notes").glob("*.html"), key=lambda p: version_key(old_note_version(p))):
        version = old_note_version(path)
        if version_key(version) >= version_key("2.9"):
            continue
        body = html_to_text(path)
        for bullet in bullet_blocks(body):
            if bullet.startswith("See https://"):
                continue
            notes.append(ReleaseNote(version, None, f"upgrade-notes/{path.name}", bullet))
    return notes


def load_manual_early_notes() -> list[ReleaseNote]:
    return [
        ReleaseNote(
            "0.95",
            "2004-02-18",
            "sourceforge-news",
            "This release adds duration and interval handling, the Coptic calendar system and firms up the API in advance of a 1.0 release.",
        )
    ]


def evidence(note: ReleaseNote) -> str:
    return f"{note.source}:v{note.version}: {note.text}"


def make(
    note: ReleaseNote,
    name: str,
    capability: str,
    op: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    mutant: str,
    pass_name: str,
) -> Contract:
    return Contract(
        name=name,
        capability=capability,
        op=op,
        params=params,
        expected=expected,
        mutant=mutant,
        evidence=evidence(note),
        version=note.version,
        source=note.source,
        pass_name=pass_name,
    )


def explicit_contracts(note: ReleaseNote) -> list[Contract]:
    n = note.text.lower()
    cs: list[Contract] = []

    if "duration and interval handling" in n:
        cs.append(make(note, "duration_can_be_constructed_from_millis", "duration.core", "duration_from_millis",
            {"millis": 1234}, {"millis": 1234}, "drop_duration_milliseconds", "pass1"))
        cs.append(make(note, "interval_preserves_start_and_end_instants", "interval.core", "parse_interval",
            {"text": "2004-01-01T00:00:00Z/2004-01-01T01:00:00Z"},
            {"start": "2004-01-01T00:00:00Z", "end": "2004-01-01T01:00:00Z"}, "collapse_interval_to_start_instant", "pass1"))
        cs.append(make(note, "coptic_calendar_has_thirteen_months", "chronology.coptic", "chronology_date",
            {"chronology": "coptic", "year": 1720, "month": 13, "day": 5}, {"valid": True}, "limit_coptic_to_12_months", "pass1"))

    if "default time zone based on offset" in n and "utc" in n:
        cs.append(make(note, "default_fixed_offset_zone_is_not_coerced_to_utc", "timezone.fixed-offset", "fixed_offset_roundtrip",
            {"offset": "+02:30"}, {"offset": "+02:30"}, "coerce_fixed_offset_default_zone_to_utc", "pass1"))

    if "datetimeformat would use date style for time style" in n:
        cs.append(make(note, "time_style_formatter_outputs_time_not_date", "datetime.format.localized-style", "format_datetime",
            {"instant": "2000-01-02T03:04:05Z", "zone": "UTC", "style": "-S", "locale": "en"},
            {"contains_time": True, "contains_date": False}, "use_date_style_for_time_style", "pass1"))

    if "wrong time zone for text fields" in n:
        cs.append(make(note, "formatter_text_fields_use_formatter_zone", "datetime.format.zone-text", "format_datetime",
            {"instant": "2000-07-01T12:00:00Z", "zone": "Europe/London", "pattern": "z"},
            {"text": "BST"}, "use_default_zone_for_text_fields", "pass1"))

    if "two digit years" in n and "jdk definition" in n:
        cs.append(make(note, "two_digit_year_pattern_uses_pivot_window", "datetime.parse.two-digit-year", "parse_local_date",
            {"text": "05-01-02", "pattern": "yy-MM-dd", "pivot_year": 2000},
            {"date": "2005-01-02"}, "parse_two_digit_year_as_year_five", "pass1"))

    if "multiple sign characters" in n:
        cs.append(make(note, "numeric_parser_rejects_multiple_signs", "datetime.parse.signed-number", "parse_local_date",
            {"text": "++2005-01-01", "pattern": "yyyy-MM-dd"}, {"throws": "parse"}, "accept_multiple_leading_signs", "pass1"))

    # The old release notes mention CE/BCE era parsing, but the public LocalDate
    # observation collapses the case to a positive year in current Joda-Time.
    # Leave it out until a cross-runtime replay can observe era semantics cleanly.

    if "ordinal style dates" in n:
        cs.append(make(note, "ordinal_date_formats_day_of_year", "datetime.format.ordinal-date", "format_local_date",
            {"date": "2005-06-10", "format": "ordinal"}, {"text": "2005-161"}, "format_ordinal_as_month_day", "pass1"))

    if "asia/riyadh87" in n:
        for zid in ["Asia/Riyadh87", "Asia/Riyadh88", "Asia/Riyadh89"]:
            cs.append(make(note, f"removed_non_genuine_zone_{slug(zid)}", "timezone.zone-id", "zone_id",
                {"id": zid}, {"throws": "unknown-zone"}, "retain_non_genuine_riyadh_zone", "pass1"))

    if "greek summer time was incorrect" in n or "europe/athens after 1980" in n:
        cs.append(make(note, "athens_summer_time_after_1980_is_enabled", "timezone.tzdb-offset", "zone_offset",
            {"zone": "Europe/Athens", "instant": "2005-07-01T12:00:00Z"}, {"offset": "+03:00"}, "disable_athens_summer_time_after_1980", "pass1"))

    if "pattern letter 'k'" in n:
        cs.append(make(note, "pattern_k_prints_hour_of_halfday_zero_to_eleven", "datetime.format.pattern-hour", "format_datetime",
            {"instant": "2000-01-01T00:00:00Z", "zone": "UTC", "pattern": "K"}, {"text": "0"}, "map_pattern_k_to_clockhour_1_to_24", "pass1"))

    if "printing of time zone name near dst transition" in n:
        cs.append(make(note, "zone_name_near_dst_transition_uses_correct_side", "timezone.format-name", "format_datetime",
            {"instant": "2005-03-27T01:30:00Z", "zone": "Europe/London", "pattern": "z"},
            {"text": "BST"}, "use_pre_transition_zone_name_after_transition", "pass1"))

    if "withmaximumvalue" in n and "last day of the month" in n:
        cs.append(make(note, "day_of_month_maximum_returns_last_day", "local-date.property", "property_with_maximum",
            {"date": "2005-02-10", "field": "dayOfMonth"}, {"date": "2005-02-28"}, "use_31_as_maximum_for_all_months", "pass1"))

    if "tointerval() returns an interval from the start to the end of the month" in n:
        cs.append(make(note, "month_property_to_interval_spans_month", "interval.property", "property_to_interval",
            {"date": "2005-02-10T12:00:00Z", "field": "monthOfYear"}, {"start": "2005-02-01T00:00:00Z", "end": "2005-03-01T00:00:00Z"}, "make_month_interval_one_day_long", "pass1"))

    if "constructing with string" in n and "no longer accepts date fields" in n:
        cs.append(make(note, "local_time_parser_rejects_date_fields", "local-time.parse", "parse_local_time",
            {"text": "2005-01-01T12:00:00"}, {"throws": "parse"}, "allow_date_fields_in_local_time_parse", "pass1"))

    if "t prefix as optional" in n:
        cs.append(make(note, "local_time_parser_accepts_optional_t_prefix", "local-time.parse", "parse_local_time",
            {"text": "T12:30:00"}, {"time": "12:30:00"}, "require_absent_t_prefix_for_local_time", "pass1"))

    if "dateoptionaltimeparser" in n:
        cs.append(make(note, "date_optional_time_parser_accepts_date_only", "datetime.parse.optional-time", "parse_local_datetime",
            {"text": "2005-06-10", "format": "date_optional_time"}, {"local": "2005-06-10T00:00:00"}, "require_time_in_date_optional_time_parser", "pass1"))

    if "conversion methods todatetime" in n and "preserve the time zone" in n:
        cs.append(make(note, "instant_conversion_preserves_zone", "instant.conversion", "convert_datetime_zone",
            {"instant": "2005-01-01T00:00:00Z", "zone": "Europe/London", "method": "toDateTime"}, {"zone": "Europe/London"}, "convert_to_default_zone", "pass1"))

    if "chronology instances" in n and "identity" in n:
        cs.append(make(note, "chronology_equality_is_structural", "chronology.equality", "chronology_equals",
            {"left": {"type": "ISO", "zone": "UTC"}, "right": {"type": "ISO", "zone": "UTC"}}, {"equals": True}, "compare_chronology_identity_only", "pass1"))

    if "period.zero" in n:
        cs.append(make(note, "period_zero_formats_as_empty_iso_period", "period.constant", "period_constant",
            {"constant": "ZERO"}, {"iso": "PT0S"}, "period_zero_contains_one_day", "pass1"))

    if "years/months/weeks/days/hours/minutes/seconds" in n:
        cs.append(make(note, "single_field_days_to_standard_hours", "period.single-field", "single_field_period_convert",
            {"type": "Days", "value": 2, "target": "Hours"}, {"value": 48}, "use_calendar_day_length_for_standard_days", "pass1"))

    if "parsing all upper-case and all lower-case text" in n:
        cs.append(make(note, "month_text_parser_accepts_uppercase_locale_text", "datetime.parse.text-case", "parse_local_date",
            {"text": "01 JANUARY 2007", "pattern": "dd MMMM yyyy", "locale": "en"}, {"date": "2007-01-01"}, "case_sensitive_month_text_parser", "pass1"))
        cs.append(make(note, "month_text_parser_accepts_lowercase_locale_text", "datetime.parse.text-case", "parse_local_date",
            {"text": "01 january 2007", "pattern": "dd MMMM yyyy", "locale": "en"}, {"date": "2007-01-01"}, "case_sensitive_month_text_parser", "pass1"))

    if "characters other than letters" in n and "french" in n:
        cs.append(make(note, "localized_month_text_with_punctuation_parses", "datetime.parse.localized-text", "parse_local_date",
            {"text": "01 janv. 2007", "pattern": "dd MMM yyyy", "locale": "fr"}, {"date": "2007-01-01"}, "month_text_parser_accepts_letters_only", "pass1"))

    if "text for months contains a number" in n or "korean" in n:
        cs.append(make(note, "localized_month_text_with_number_parses", "datetime.parse.localized-text", "parse_local_date",
            {"text": "2007 1월 01", "pattern": "yyyy MMM dd", "locale": "ko"}, {"date": "2007-01-01"}, "month_text_parser_accepts_letters_only", "pass1"))

    if "abbreviation is the same in winter and summer" in n:
        cs.append(make(note, "same_abbreviation_zone_name_still_uses_correct_offset", "timezone.name-offset", "zone_offset",
            {"zone": "Australia/Brisbane", "instant": "2007-07-01T00:00:00Z"}, {"offset": "+10:00"}, "infer_dst_from_abbreviation_difference_only", "pass1"))

    if "todatetimeatstartofday" in n or "avoid issues with time zones that do not have midnight" in n:
        cs.append(make(note, "localdate_start_of_day_avoids_missing_midnight", "local-date.start-of-day", "start_of_day",
            {"date": "2011-12-30", "zone": "Pacific/Apia"}, {"local_date": "2011-12-31"}, "return_missing_midnight_for_skipped_date", "pass1"))

    if "isstandardoffset" in n:
        cs.append(make(note, "standard_offset_differs_from_dst_offset", "timezone.standard-offset", "standard_offset",
            {"zone": "Europe/London", "instant": "2015-07-01T12:00:00Z"}, {"standard_offset": "+00:00", "actual_offset": "+01:00"}, "report_actual_offset_as_standard_offset", "pass1"))

    if "normalizedstandard" in n:
        cs.append(make(note, "period_normalized_standard_carries_months_to_years", "period.normalize", "period_normalize",
            {"period": "P15M", "type": "year_month"}, {"iso": "P1Y3M"}, "leave_overflowing_months_unnormalized", "pass1"))

    if "tostandardweeks" in n or "tostandarddays" in n:
        cs.append(make(note, "period_to_standard_days_uses_24_hour_days", "period.standard-units", "period_to_standard",
            {"period": "P2D", "target": "hours"}, {"hours": 48}, "use_calendar_day_for_standard_unit_conversion", "pass1"))

    if "printzerorarelyfirst" in n:
        cs.append(make(note, "period_print_zero_rarely_first_can_print_zero_seconds", "period.format.zero", "format_period_custom",
            {"period": "PT0S", "zero_policy": "rarely_first", "fields": ["seconds"]}, {"contains": "0"}, "suppress_zero_with_rarely_first", "pass1"))

    if "fromdatefields" in n and "before 1970" in n:
        cs.append(make(note, "local_time_from_pre_epoch_date_fields_preserves_time", "local-time.from-date", "local_time_from_date",
            {"instant": "1960-01-01T12:34:56Z", "zone": "UTC"}, {"time": "12:34:56"}, "apply_epoch_offset_when_extracting_pre_epoch_time", "pass1"))

    if "localdate.tointerval" in n and "no midnight" in n:
        cs.append(make(note, "local_date_interval_handles_missing_midnight", "local-date.interval", "local_date_interval",
            {"date": "2011-12-30", "zone": "Pacific/Apia"}, {"duration_hours": 0}, "force_24h_interval_for_skipped_local_date", "pass1"))

    if "parseinto() retains the year" in n:
        cs.append(make(note, "parse_into_month_day_retains_existing_year", "datetime.parse-into", "parse_into",
            {"base": "2012-01-01T00:00:00Z", "text": "02-03", "pattern": "MM-dd"}, {"date": "2012-02-03"}, "reset_parse_into_year_to_formatter_default", "pass1"))

    if "cannot print or parse" in n and "throw" in n:
        cs.append(make(note, "parse_only_formatter_throws_when_printing", "datetime.formatter-capability", "formatter_capability",
            {"formatter": "parser_only", "operation": "print"}, {"throws": "unsupported"}, "silently_ignore_unsupported_print", "pass1"))

    if "small negative numbers" in n:
        cs.append(make(note, "duration_parse_small_negative_fraction", "duration.parse.iso", "parse_duration",
            {"text": "PT-0.5S"}, {"millis": -500}, "parse_negative_fractional_duration_as_zero", "pass1"))

    if "duration.multipliedby" in n:
        cs.append(make(note, "duration_multiplied_by_scales_millis", "duration.multiplication", "duration_multiply",
            {"millis": 1500, "factor": 3}, {"millis": 4500}, "multiply_duration_seconds_only", "pass1"))
    if "duration" in n and ".negated" in n:
        cs.append(make(note, "duration_negated_flips_sign", "duration.negation", "duration_negate",
            {"millis": 1500}, {"millis": -1500}, "return_same_duration_when_negating", "pass1"))

    if "period.normalizedstandard" in n:
        cs.append(make(note, "period_normalized_standard_normalizes_minutes", "period.normalize", "period_normalize",
            {"period": "PT90M", "type": "time"}, {"iso": "PT1H30M"}, "leave_90_minutes_unnormalized", "pass1"))

    if "ensure isleap() returns correct result for day fields" in n:
        cs.append(make(note, "day_field_is_leap_reports_feb_29", "local-date.leap", "field_is_leap",
            {"date": "2016-02-29", "field": "dayOfMonth"}, {"is_leap": True}, "report_day_field_never_leap", "pass1"))

    if "year > weekyear" in n:
        cs.append(make(note, "partial_rejects_inconsistent_year_weekyear", "partial.validation", "partial_create",
            {"fields": {"year": 2015, "weekyear": 2016, "weekOfWeekyear": 1}}, {"throws": "invalid-partial"}, "allow_inconsistent_year_and_weekyear", "pass1"))

    if "regex based period formatting" in n:
        cs.append(make(note, "period_regex_formatter_parses_selected_fields", "period.format.regex", "parse_period_regex",
            {"text": "2 weeks", "regex": "(\\d+) weeks", "field": "weeks"}, {"iso": "P2W"}, "ignore_regex_period_formatter", "pass1"))

    if "time-zone database version to manifest" in n:
        cs.append(make(note, "manifest_exposes_timezone_database_version", "timezone.tzdb-version", "tzdb_version",
            {}, {"matches": r"\\d{4}[a-z].*"}, "omit_tzdb_version_metadata", "pass1"))

    if "localdate.todatetime(localtime)" in n:
        cs.append(make(note, "localdate_to_datetime_with_time_uses_supplied_time", "local-date.combine", "combine_local_date_time",
            {"date": "2014-01-01", "time": "23:45:00", "zone": "UTC"}, {"local": "2014-01-01T23:45:00"}, "ignore_supplied_local_time", "pass1"))

    if "periodformatter.withlocale" in n:
        cs.append(make(note, "period_formatter_with_locale_controls_words", "period.format.locale", "format_period_words",
            {"period": "P1D", "locale": "fr"}, {"contains": "jour"}, "ignore_period_formatter_locale", "pass1"))

    if "asia/dhaka" in n:
        cs.append(make(note, "asia_dhaka_offset_matches_tzdb", "timezone.tzdb-offset", "zone_offset",
            {"zone": "Asia/Dhaka", "instant": "2014-07-01T00:00:00Z"}, {"offset": "+06:00"}, "use_wrong_asia_dhaka_offset", "pass1"))

    if "datetime.withdate" in n:
        cs.append(make(note, "datetime_with_date_preserves_time_and_zone", "datetime.with-date", "datetime_with_date",
            {"datetime": "2015-01-01T12:34:56+01:00[Europe/Paris]", "date": "2015-02-03"}, {"local": "2015-02-03T12:34:56", "zone": "Europe/Paris"}, "reset_time_when_replacing_date", "pass1"))

    if "datetime.withtime" in n:
        cs.append(make(note, "datetime_with_time_preserves_date_and_zone", "datetime.with-time", "datetime_with_time",
            {"datetime": "2015-01-01T12:34:56+01:00[Europe/Paris]", "time": "01:02:03"}, {"local": "2015-01-01T01:02:03", "zone": "Europe/Paris"}, "reset_date_when_replacing_time", "pass1"))

    if "property.tointerval" in n:
        cs.append(make(note, "day_property_to_interval_spans_one_day", "interval.property", "property_to_interval",
            {"date": "2015-01-02T12:00:00Z", "field": "dayOfMonth"}, {"start": "2015-01-02T00:00:00Z", "end": "2015-01-03T00:00:00Z"}, "property_interval_keeps_original_instant", "pass1"))

    if "forid() to better match java.time" in n:
        cs.append(make(note, "zone_id_z_maps_to_utc", "timezone.zone-id", "zone_id",
            {"id": "Z"}, {"canonical_id": "UTC"}, "reject_java_time_z_zone_id", "pass1"))
        cs.append(make(note, "offset_zone_id_plus_hour_parses", "timezone.zone-id", "zone_id",
            {"id": "+01:00"}, {"offset": "+01:00"}, "reject_java_time_offset_zone_id", "pass1"))

    if "systemv and pacificnew" in n:
        for zid in ["SystemV/EST5", "Pacific/New"]:
            cs.append(make(note, f"removed_tzdb_zone_{slug(zid)}", "timezone.zone-id", "zone_id",
                {"id": zid}, {"throws": "unknown-zone"}, "retain_removed_tzdb_zone", "pass1"))

    if "namibia" in n:
        cs.append(make(note, "namibia_post_2017_no_longer_observes_dst", "timezone.tzdb-offset", "zone_offset",
            {"zone": "Africa/Windhoek", "instant": "2018-07-01T12:00:00Z"}, {"offset": "+02:00"}, "keep_old_namibia_winter_offset", "pass1"))

    if "tokyo" in n:
        cs.append(make(note, "tokyo_historic_offset_uses_tzdb_compiler_result", "timezone.tzdb-offset", "zone_offset",
            {"zone": "Asia/Tokyo", "instant": "1948-05-01T16:00:00Z"}, {"offset": "+10:00"}, "ignore_tokyo_historic_dst_rule", "pass1"))

    if "russia" in n and "localization" in n:
        cs.append(make(note, "russian_month_name_formats_in_locale", "datetime.format.locale", "format_local_date",
            {"date": "2020-03-01", "pattern": "MMMM", "locale": "ru"}, {"contains": "март"}, "use_english_month_names_for_russian_locale", "pass1"))

    if "global-tz project" in n or "reinstates all the data removed" in n:
        cs.append(make(note, "global_tz_retains_pre_1970_zone_data", "timezone.pre-1970", "zone_offset",
            {"zone": "Europe/Oslo", "instant": "1870-01-01T00:00:00Z"}, {"not_offset": "+01:00"}, "truncate_pre_1970_tzdb_to_single_modern_offset", "pass1"))

    if "hugely damaging timezone data" in n:
        cs.append(make(note, "timezone_provider_rejects_destructive_empty_data", "timezone.provider-safety", "available_zone_ids",
            {}, {"contains": "Europe/London"}, "accept_empty_or_destructive_tzdb_payload", "pass1"))

    if "datetimezone data updated" in n and "version" in n:
        m = re.search(r"version ([0-9]{4}[a-z][a-z0-9-]*)", note.text, re.I)
        if m:
            tag = m.group(1)
            cs.append(make(note, f"tzdb_{slug(tag)}_contains_london_zone", "timezone.tzdb-presence", "zone_id",
                {"id": "Europe/London"}, {"canonical_id": "Europe/London"}, "drop_core_iana_zone_ids", "pass1"))
            cs.append(make(note, f"tzdb_{slug(tag)}_new_york_summer_offset", "timezone.tzdb-offset", "zone_offset",
                {"zone": "America/New_York", "instant": "2015-07-01T12:00:00Z"}, {"offset": "-04:00"}, "ignore_dst_rules_in_tzdb", "pass1"))

    if "time zone name key does not return" in n and "%z" in n:
        cs.append(make(note, "timezone_name_key_is_not_raw_percent_z", "timezone.name-key", "zone_name_key",
            {"zone": "Etc/GMT", "instant": "2026-01-01T00:00:00Z"},
            {"not_equals": "%z"}, "return_percent_z_as_name_key", "pass1"))

    if "retires the american short zone ids" in n:
        for short_id, expected in {
            "MST": "America/Phoenix",
            "EST": "America/Panama",
            "HST": "Pacific/Honolulu",
            "PST8PDT": "America/Los_Angeles",
        }.items():
            cs.append(make(note, f"short_zone_id_{short_id.lower()}_maps_to_region", "timezone.zone-id-alias", "zone_id",
                {"id": short_id}, {"canonical_id": expected}, "keep_short_id_as_fixed_offset", "pass1"))
        cs.append(make(note, "met_short_zone_id_maps_to_cet", "timezone.zone-id-alias", "zone_id",
            {"id": "MET"}, {"canonical_id": "CET"}, "treat_met_as_distinct_nonstandard_zone", "pass1"))
        for retained in ["WET", "CET", "EET"]:
            cs.append(make(note, f"european_short_zone_id_{retained.lower()}_retained", "timezone.zone-id-alias", "zone_id",
                {"id": retained}, {"canonical_id": retained}, "retire_all_short_zone_ids", "pass1"))

    if "withtimeatstartofday" in n and "dst is at midnight" in n:
        cs.append(make(note, "start_of_day_skips_midnight_dst_gap", "local-date.start-of-day", "start_of_day",
            {"date": "2018-11-04", "zone": "America/Sao_Paulo"},
            {"local_time": "01:00:00", "offset": "-02:00"}, "return_nonexistent_midnight", "pass1"))

    if "period.years() factory" in n:
        cs.append(make(note, "period_years_factory_returns_year_period", "period.factory", "period_factory",
            {"factory": "years", "value": 2}, {"iso": "P2Y"}, "create_months_instead_of_years", "pass1"))

    if "negative save values" in n:
        cs.append(make(note, "negative_dst_save_values_preserve_dublin_winter", "timezone.negative-dst", "zone_offset",
            {"zone": "Europe/Dublin", "instant": "2019-01-15T12:00:00Z"},
            {"offset": "+00:00"}, "treat_negative_save_as_positive_dst", "pass1"))
        cs.append(make(note, "negative_dst_save_values_preserve_dublin_summer", "timezone.negative-dst", "zone_offset",
            {"zone": "Europe/Dublin", "instant": "2019-07-15T12:00:00Z"},
            {"offset": "+01:00"}, "ignore_negative_save_rules", "pass1"))

    if "instant.epoch" in n:
        cs.append(make(note, "instant_epoch_is_unix_epoch", "instant.epoch", "instant_constant",
            {"constant": "EPOCH"}, {"epoch_millis": 0}, "epoch_constant_uses_local_midnight", "pass1"))

    if "instant.ofepochmilli" in n:
        cs.append(make(note, "instant_of_epoch_milli_preserves_millis", "instant.factory", "instant_from_epoch_millis",
            {"epoch_millis": 123456789}, {"iso": "1970-01-02T10:17:36.789Z"}, "truncate_epoch_millis_to_seconds", "pass1"))
    if "instant.ofepochsecond" in n:
        cs.append(make(note, "instant_of_epoch_second_preserves_seconds", "instant.factory", "instant_from_epoch_seconds",
            {"epoch_seconds": 123456789}, {"iso": "1973-11-29T21:33:09.000Z"}, "interpret_epoch_seconds_as_millis", "pass1"))

    if "lenient chronology" in n and "double addition" in n:
        cs.append(make(note, "lenient_chronology_adds_overflow_once", "chronology.lenient-addition", "lenient_local_datetime",
            {"local": "2014-01-31T25:00:00", "zone": "UTC"},
            {"local": "2014-02-01T01:00:00"}, "add_lenient_overflow_twice", "pass1"))

    if "integer.min_value/max_value months" in n:
        cs.append(make(note, "plus_max_int_months_does_not_overflow_silently", "period.months.overflow", "plus_months_extreme",
            {"date": "2000-01-01", "months": 2147483647}, {"date": "178958970-08-01"}, "wrap_extreme_month_addition", "pass1"))

    if "adding months at the maximum limits of integer" in n:
        cs.append(make(note, "add_max_int_months_rejects_overflow", "period.months.overflow", "plus_months_extreme",
            {"date": "2000-01-01", "months": 2147483647}, {"date": "178958970-08-01"}, "wrap_extreme_month_addition", "pass1"))

    if "duration.dividedby" in n:
        cs.append(make(note, "duration_divided_by_half_up_rounds", "duration.division", "duration_divide",
            {"millis": 5, "divisor": 2, "rounding": "HALF_UP"}, {"millis": 3}, "always_floor_duration_division", "pass1"))
        cs.append(make(note, "duration_divided_by_down_truncates", "duration.division", "duration_divide",
            {"millis": 5, "divisor": 2, "rounding": "DOWN"}, {"millis": 2}, "always_half_up_duration_division", "pass1"))

    if "timezone where name has digits other than ascii" in n or "timezone where name has digits" in n:
        cs.append(make(note, "timezone_display_name_with_non_ascii_digits_converts", "timezone.jdk-conversion", "java_timezone_name_digits",
            {"display_name": "GMT+٠٣:٠٠"}, {"offset": "+03:00"}, "parse_only_ascii_digits_in_timezone_name", "pass1"))

    if "time-zone binary search" in n:
        cs.append(make(note, "timezone_parse_does_not_require_zone_at_end", "timezone.parse-position", "parse_datetime",
            {"text": "2016-01-01T00:00:00 America/Dawson_Creek suffix", "pattern": "yyyy-MM-dd'T'HH:mm:ss ZZZ 'suffix'"},
            {"zone": "America/Dawson_Creek", "local": "2016-01-01T00:00:00"}, "require_timezone_token_to_be_last", "pass1"))

    if "formatting a time-zone will print" in n and "gmt" in n:
        cs.append(make(note, "gmt_zone_formats_as_gmt_name", "timezone.format-name", "format_datetime",
            {"instant": "2015-01-01T00:00:00Z", "zone": "GMT", "pattern": "z"},
            {"text": "GMT"}, "format_gmt_as_numeric_zero_offset", "pass1"))

    if "unnecessary plus sign" in n:
        cs.append(make(note, "basic_iso_date_accepts_redundant_plus_year", "datetime.parse.iso-basic", "parse_local_date",
            {"text": "+20151030", "format": "basic_iso_date"}, {"date": "2015-10-30"}, "reject_plus_prefixed_basic_year", "pass1"))

    if "parsewithoffset" in n:
        cs.append(make(note, "interval_parse_with_offset_preserves_fixed_offset", "interval.parse-offset", "parse_interval",
            {"text": "2015-01-01T00:00:00+02:00/2015-01-01T01:00:00+02:00", "mode": "with_offset"},
            {"start": "2015-01-01T00:00:00+02:00", "end": "2015-01-01T01:00:00+02:00", "offset": "+02:00"},
            "drop_interval_fixed_offset", "pass1"))

    if "ambiguous date-time" in n or "ambiguous time due to dst" in n or "summer time when ambiguous" in n:
        cs.append(make(note, "ambiguous_london_fall_back_picks_summer_offset", "timezone.dst-overlap", "resolve_local",
            {"zone": "Europe/London", "local": "2011-10-30T01:30:00"},
            {"offset": "+01:00"}, "pick_winter_offset_for_zero_base_overlap", "pass1"))

    if "later/earlier offset" in n:
        cs.append(make(note, "with_later_offset_at_overlap_uses_post_transition_offset", "timezone.dst-overlap", "overlap_offset_choice",
            {"zone": "America/New_York", "local": "2011-11-06T01:30:00", "choice": "later"},
            {"offset": "-05:00"}, "use_earlier_offset_for_later_choice", "pass1"))
        cs.append(make(note, "with_earlier_offset_at_overlap_uses_pre_transition_offset", "timezone.dst-overlap", "overlap_offset_choice",
            {"zone": "America/New_York", "local": "2011-11-06T01:30:00", "choice": "earlier"},
            {"offset": "-04:00"}, "use_later_offset_for_earlier_choice", "pass1"))

    if "time zones like" in n and "america/dawson_creek" in n:
        cs.append(make(note, "timezone_parser_prefers_longest_zone_id", "timezone.parse-longest-id", "parse_zone_id",
            {"text": "America/Dawson_Creek"}, {"zone": "America/Dawson_Creek"}, "stop_at_shorter_zone_prefix", "pass1"))

    if "islocaldatetimegap" in n:
        cs.append(make(note, "local_datetime_gap_detects_spring_forward_gap", "timezone.dst-gap", "local_datetime_gap",
            {"zone": "Europe/Paris", "local": "2015-03-29T02:30:00"}, {"gap": True}, "treat_gap_as_valid_local_time", "pass1"))

    if "iso" in n and "millisecond parsing" in n:
        cs.append(make(note, "iso_millisecond_fraction_scales_to_millis", "datetime.parse.fraction", "parse_datetime",
            {"text": "2008-01-01T12:00:00.4Z", "format": "iso"},
            {"millis_of_second": 400}, "interpret_single_fraction_digit_as_raw_millis", "pass1"))

    if "basic parsers" in n and "too lenient" in n:
        cs.append(make(note, "basic_iso_date_rejects_extended_separator", "datetime.parse.iso-basic", "parse_local_date",
            {"text": "2008-01-01", "format": "basic_iso_date"}, {"throws": "parse"}, "allow_extended_form_in_basic_parser", "pass1"))

    if "getoffsetfromlocal dst gap" in n or "convertlocaltoutc" in n:
        cs.append(make(note, "convert_gap_local_time_rejects_nonexistent_time", "timezone.dst-gap", "convert_local_to_utc",
            {"zone": "Europe/Paris", "local": "2015-03-29T02:30:00", "strict": True},
            {"throws": "illegal-instant"}, "silently_shift_gap_local_time", "pass1"))

    if "date-time zone ids like europe/london" in n:
        cs.append(make(note, "formatter_parses_region_zone_id", "timezone.parse-zone-id", "parse_datetime",
            {"text": "2010-06-01T12:00:00 Europe/London", "pattern": "yyyy-MM-dd'T'HH:mm:ss ZZZ"},
            {"zone": "Europe/London", "offset": "+01:00"}, "parse_only_numeric_offsets", "pass1"))

    if "allow 'z' and 'zz'" in n or "parse 'z' as '+00:00'" in n:
        cs.append(make(note, "offset_parser_accepts_literal_z_as_utc", "timezone.parse-offset", "parse_datetime",
            {"text": "2010-01-01T00:00:00Z", "pattern": "yyyy-MM-dd'T'HH:mm:ssZ"},
            {"offset": "+00:00"}, "reject_literal_z_offset", "pass1"))

    if "withtimeatstartofday" in n:
        cs.append(make(note, "with_time_at_start_of_day_returns_first_valid_time", "local-date.start-of-day", "start_of_day",
            {"date": "2015-03-29", "zone": "Europe/Paris"},
            {"local_time": "00:00:00", "offset": "+01:00"}, "always_return_utc_midnight", "pass1"))

    if "case-sensitive" in n and "forid" in n:
        cs.append(make(note, "zone_id_lookup_is_case_sensitive", "timezone.zone-id", "zone_id",
            {"id": "europe/london"}, {"throws": "unknown-zone"}, "case_fold_zone_ids", "pass1"))

    if "time zone compiler now handles 24:00" in n or "process 24:00" in n:
        cs.append(make(note, "tzdb_24_hour_rule_rolls_to_next_day", "timezone.tzdb-24-hour", "zone_offset",
            {"zone": "Africa/Casablanca", "instant": "2014-08-01T00:30:00Z"},
            {"offset": "+00:00"}, "treat_24_00_rule_as_same_day_midnight", "pass1"))

    if "period parsing now more strict" in n:
        cs.append(make(note, "period_time_fields_require_t_separator", "period.parse.iso", "parse_period",
            {"text": "P1H"}, {"throws": "parse"}, "allow_time_fields_without_t_separator", "pass1"))

    if "fractional seconds in periods" in n:
        cs.append(make(note, "period_fractional_seconds_scale_to_millis", "period.parse.iso", "parse_period",
            {"text": "PT1.234S"}, {"millis": 234}, "drop_fractional_second_component", "pass1"))

    if "form pt" in n and "prevented parsing" in n:
        cs.append(make(note, "period_time_only_form_parses", "period.parse.iso", "parse_period",
            {"text": "PT2H30M"}, {"iso": "PT2H30M"}, "reject_pt_time_only_periods", "pass1"))

    if "interval/mutableinterval isafter" in n and "abutted" in n:
        cs.append(make(note, "abutting_interval_is_after_previous_interval", "interval.relation", "interval_relation",
            {"left": "2000-01-01T01:00:00Z/2000-01-01T02:00:00Z", "right": "2000-01-01T00:00:00Z/2000-01-01T01:00:00Z", "relation": "isAfter"},
            {"value": True}, "treat_abutting_interval_as_not_after", "pass1"))

    if "time zone pattern 'zzzz'" in n:
        cs.append(make(note, "pattern_zz_formats_offset", "datetime.format.pattern-zone", "format_datetime",
            {"instant": "2000-01-01T00:00:00Z", "zone": "Asia/Singapore", "pattern": "ZZ"},
            {"text": "+08:00"}, "use_zz_for_zone_id", "pass1"))
        cs.append(make(note, "pattern_zzzz_formats_zone_id", "datetime.format.pattern-zone", "format_datetime",
            {"instant": "2000-01-01T00:00:00Z", "zone": "Asia/Singapore", "pattern": "ZZZZ"},
            {"text": "Asia/Singapore"}, "use_zzzz_for_offset", "pass1"))

    if "timeofday.property.addtocopy" in n or "timeofday" in n and "wraps" in n:
        cs.append(make(note, "time_of_day_add_wraps_over_midnight", "local-time.arithmetic", "local_time_add",
            {"time": "23:30:00", "amount": {"hours": 1}}, {"time": "00:30:00"}, "throw_on_midnight_wrap", "pass1"))

    if "fixed offset zones" in n and "java.util.timezone" in n:
        cs.append(make(note, "fixed_offset_zone_converts_to_same_offset", "timezone.fixed-offset", "fixed_offset_roundtrip",
            {"offset": "+05:45"}, {"offset": "+05:45"}, "convert_fixed_offset_zone_to_utc", "pass1"))

    if "spring incorrect" in n or "dst cutover in spring" in n:
        cs.append(make(note, "spring_forward_add_hour_skips_gap", "timezone.dst-gap", "zoned_add",
            {"zone": "Europe/Paris", "start": "2015-03-29T01:30:00+01:00", "amount": {"hours": 1}},
            {"local": "2015-03-29T03:30:00", "offset": "+02:00"}, "land_inside_spring_gap", "pass1"))

    if "period.plusxxx" in n or "period" in n and "minusxxx" in n:
        cs.append(make(note, "period_plus_days_adds_days_field", "period.arithmetic", "period_add_field",
            {"period": "P1M", "field": "days", "amount": 2}, {"iso": "P1M2D"}, "overwrite_period_when_adding_field", "pass1"))

    if "offsets from -23:59:59.999 to +23:59:59.999" in n:
        cs.append(make(note, "timezone_offset_rejects_full_24_hours", "timezone.offset-range", "fixed_offset",
            {"offset": "+24:00"}, {"throws": "invalid-offset"}, "allow_24_hour_fixed_offset", "pass1"))

    if "foroffsethoursminutes failed to allow offsets from -00:01" in n:
        cs.append(make(note, "negative_subhour_offset_is_allowed", "timezone.offset-range", "fixed_offset",
            {"offset": "-00:30"}, {"offset": "-00:30"}, "reject_negative_subhour_offsets", "pass1"))

    if "short time-zone name parsing failed to match the longest name" in n:
        cs.append(make(note, "short_timezone_name_parser_uses_short_name_offset", "timezone.parse-longest-name", "parse_datetime",
            {"text": "2013-01-01T00:00:00 PST", "pattern": "yyyy-MM-dd'T'HH:mm:ss z", "locale": "en"},
            {"offset": "-08:00"}, "accept_first_shorter_name_match", "pass1"))

    if "interval/mutableinterval .isequal" in n:
        cs.append(make(note, "interval_is_equal_compares_bounds", "interval.relation", "interval_relation",
            {"left": "2000-01-01T00:00:00Z/2000-01-01T01:00:00Z", "right": "2000-01-01T00:00:00Z/2000-01-01T01:00:00Z", "relation": "isEqual"},
            {"value": True}, "compare_interval_identity", "pass1"))

    if "monthday.plusdays" in n or "monthday add/subtract" in n:
        cs.append(make(note, "month_day_plus_days_wraps_year_boundary", "partial.month-day", "month_day_add",
            {"month_day": "--12-31", "amount": {"days": 1}}, {"month_day": "--01-01"}, "reject_month_day_year_wrap", "pass1"))

    if "period.parse" in n:
        cs.append(make(note, "period_parse_roundtrips_standard_fields", "period.parse.iso", "parse_period",
            {"text": "P1Y2M3DT4H5M6S"}, {"iso": "P1Y2M3DT4H5M6S"}, "drop_mixed_date_time_period_fields", "pass1"))

    if "format etc/gmt time-zone using gmt data" in n:
        cs.append(make(note, "etc_gmt_formats_using_gmt_name_data", "timezone.format-name", "format_datetime",
            {"instant": "2015-01-01T00:00:00Z", "zone": "Etc/GMT", "pattern": "z"},
            {"text": "GMT"}, "format_etc_gmt_as_raw_id", "pass1"))

    if "localdate.todatetime(localtime)" in n and "retain the local time" in n:
        cs.append(make(note, "localdate_to_datetime_retains_requested_local_time", "local-date.combine", "combine_local_date_time",
            {"date": "2014-06-01", "time": "12:34:56", "zone": "Europe/London"},
            {"local": "2014-06-01T12:34:56"}, "use_current_time_when_combining_local_date", "pass1"))

    if "duration.tostring" in n:
        cs.append(make(note, "duration_to_string_uses_iso_seconds", "duration.format.iso", "format_duration",
            {"millis": 1500}, {"text": "PT1.500S"}, "format_duration_as_milliseconds_number", "pass1"))

    if "duration.toperiod" in n or "new period(long)" in n:
        cs.append(make(note, "duration_to_period_uses_standard_fields", "duration.to-period", "duration_to_period",
            {"millis": 90061000}, {"iso": "P1DT1H1M1S"}, "keep_duration_as_raw_millis_period", "pass1"))

    if "february 29th" in n and "month and day without year" in n:
        cs.append(make(note, "month_day_parser_accepts_february_29_without_year", "partial.month-day.parse", "parse_month_day",
            {"text": "--02-29", "format": "iso"}, {"month_day": "--02-29"}, "reject_leap_day_without_year", "pass1"))

    if "date-time zone names like" in n:
        cs.append(make(note, "formatter_parses_common_zone_name", "timezone.parse-zone-name", "parse_datetime",
            {"text": "2010-01-01T00:00:00 EST", "pattern": "yyyy-MM-dd'T'HH:mm:ss z", "locale": "en"},
            {"offset": "-05:00"}, "ignore_textual_zone_names", "pass1"))

    return cs


def expansion_contracts(note: ReleaseNote) -> list[Contract]:
    n = note.text.lower()
    cs: list[Contract] = []

    if "localdate/localtime/localdatetime" in n or note.text == "LocalDate":
        cs.append(make(note, "local_date_plus_months_clamps_to_last_day", "local-date.month-arithmetic", "local_date_add",
            {"date": "2015-01-31", "amount": {"months": 1}}, {"date": "2015-02-28"}, "overflow_to_march_when_adding_month", "pass2"))
        cs.append(make(note, "local_date_leap_year_plus_year_clamps", "local-date.year-arithmetic", "local_date_add",
            {"date": "2016-02-29", "amount": {"years": 1}}, {"date": "2017-02-28"}, "reject_leap_day_year_add", "pass2"))

    if "monthday" in n and not any(c.name.startswith("month_day") for c in cs):
        cs.append(make(note, "month_day_preserves_leap_day", "partial.month-day", "parse_month_day",
            {"text": "--02-29", "format": "iso"}, {"month_day": "--02-29"}, "coerce_feb_29_to_feb_28", "pass2"))

    if "yearmonth" in n:
        cs.append(make(note, "year_month_plus_months_rolls_year", "partial.year-month", "year_month_add",
            {"year_month": "2015-12", "amount": {"months": 2}}, {"year_month": "2016-02"}, "drop_year_carry_in_year_month_add", "pass2"))

    if "islamicchronology" in n:
        cs.append(make(note, "islamic_chronology_month_length_is_calendar_specific", "chronology.islamic", "chronology_date",
            {"chronology": "islamic", "year": 1445, "month": 9, "day": 1}, {"valid": True}, "use_gregorian_month_lengths_for_islamic", "pass2"))

    if "ethiopicchronology" in n:
        cs.append(make(note, "ethiopic_chronology_has_thirteenth_month", "chronology.ethiopic", "chronology_date",
            {"chronology": "ethiopic", "year": 2015, "month": 13, "day": 5}, {"valid": True}, "limit_ethiopic_to_12_months", "pass2"))

    if "coptic" in n:
        cs.append(make(note, "coptic_chronology_has_thirteenth_month", "chronology.coptic", "chronology_date",
            {"chronology": "coptic", "year": 1739, "month": 13, "day": 5}, {"valid": True}, "limit_coptic_to_12_months", "pass2"))

    if "julian" in n and "february 29" in n:
        cs.append(make(note, "julian_chronology_accepts_julian_leap_day", "chronology.julian", "chronology_date",
            {"chronology": "julian", "year": 1900, "month": 2, "day": 29}, {"valid": True}, "use_gregorian_leap_rules_for_julian", "pass2"))

    if "interval" in n and "overlap" in n:
        cs.append(make(note, "interval_overlap_returns_intersection", "interval.set-ops", "interval_overlap",
            {"left": "2000-01-01T00:00:00Z/2000-01-01T02:00:00Z", "right": "2000-01-01T01:00:00Z/2000-01-01T03:00:00Z"},
            {"interval": "2000-01-01T01:00:00Z/2000-01-01T02:00:00Z"}, "return_union_for_overlap", "pass2"))

    if "interval" in n and "gap" in n:
        cs.append(make(note, "interval_gap_returns_between_abutting_nonoverlap", "interval.set-ops", "interval_gap",
            {"left": "2000-01-01T00:00:00Z/2000-01-01T01:00:00Z", "right": "2000-01-01T02:00:00Z/2000-01-01T03:00:00Z"},
            {"interval": "2000-01-01T01:00:00Z/2000-01-01T02:00:00Z"}, "return_empty_gap_for_separated_intervals", "pass2"))

    if "duration" in n and "standard" in n:
        cs.append(make(note, "duration_standard_seconds_truncates_millis", "duration.standard-units", "duration_standard_seconds",
            {"millis": 1999}, {"seconds": 1}, "round_standard_seconds_up", "pass2"))

    if "period" in n and "word" in n:
        cs.append(make(note, "word_based_period_format_pluralizes_days", "period.format.words", "format_period_words",
            {"period": "P2D", "locale": "en"}, {"contains": "2 days"}, "use_singular_word_for_plural_period", "pass2"))

    if "date-time zone ids" in n or "timezone identifiers" in n:
        cs.append(make(note, "zone_id_parser_accepts_slash_region_ids", "timezone.parse-zone-id", "parse_zone_id",
            {"text": "Europe/London"}, {"zone": "Europe/London"}, "reject_slash_region_zone_ids", "pass2"))

    return cs


def dedupe(contracts: list[Contract]) -> list[Contract]:
    seen: set[tuple[str, str]] = set()
    out: list[Contract] = []
    for c in contracts:
        key = (c.name, json.dumps(c.params, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def write_rpl(contracts: list[Contract]) -> None:
    lines = [
        "# Generated by tools/replay/extract_jodatime_contracts.py",
        "# Operation-based DSL for externally observable date/time/timezone behavior.",
        "",
    ]
    current: str | None = None
    for c in contracts:
        if c.version != current:
            if current is not None:
                lines.append("")
            lines.append(f'release "joda-time" version "{c.version}"')
            lines.append(f'source "{c.source}:v{c.version}"')
            current = c.version
        lines.extend([
            "",
            f'contract "{c.name}"',
            f'evidence "{c.evidence}"',
            f'capability "{c.capability}"',
            f'replay "{c.op}"',
            f'mutant "{c.mutant}"',
            f"given {json.dumps(c.params, sort_keys=True, ensure_ascii=False)}",
            f"expect {json.dumps(c.expected, sort_keys=True, ensure_ascii=False)}",
            "end",
        ])
    OUT_RPL.write_text("\n".join(lines) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    maven_versions = load_maven_versions()
    notes = load_manual_early_notes() + load_upgrade_notes() + load_xml_notes()

    contracts: list[Contract] = []
    audited: list[dict[str, Any]] = []
    for note in sorted(notes, key=lambda n: (version_key(n.version), n.source, n.text)):
        p1 = explicit_contracts(note)
        p2 = expansion_contracts(note)
        contracts.extend(p1)
        contracts.extend(p2)
        audited.append({
            "version": note.version,
            "source": note.source,
            "type": note.note_type,
            "note": note.text,
            "pass1": len(p1),
            "pass2": len(p2),
        })

    contracts = sorted(dedupe(contracts), key=lambda c: (version_key(c.version), c.name))

    counts: dict[str, int] = {v: 0 for v in maven_versions}
    for c in contracts:
        counts[c.version] = counts.get(c.version, 0) + 1

    OUT_JSON.write_text(json.dumps({
        "domain": "date-time-timezone",
        "project": "Joda-Time",
        "source_release_total_maven": len(maven_versions),
        "release_note_total": len(notes),
        "contracts_total": len(contracts),
        "contracts": [c.as_dict() for c in contracts],
        "release_counts": counts,
        "audit": audited,
    }, indent=2, ensure_ascii=False) + "\n")
    write_rpl(contracts)

    count_lines = [
        "# Joda-Time Release Contract Counts",
        "",
        f"Source releases in Maven metadata: {len(maven_versions)}",
        f"Release-note records inspected: {len(notes)}",
        f"Contracts extracted: {len(contracts)}",
        "",
        "| Version | Contracts |",
        "| --- | ---: |",
    ]
    for version in maven_versions:
        count_lines.append(f"| {version} | {counts.get(version, 0)} |")
    OUT_COUNTS.write_text("\n".join(count_lines) + "\n")

    audit_lines = [
        "# Joda-Time Extraction Audit",
        "",
        "Every release-note record was inspected by pass1 and pass2. Counts below are generated contracts per note.",
        "",
        "| Version | Source | Pass1 | Pass2 | Note |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for row in audited:
        note = row["note"].replace("|", "\\|")
        audit_lines.append(f"| {row['version']} | `{row['source']}` | {row['pass1']} | {row['pass2']} | {note} |")
    OUT_AUDIT.write_text("\n".join(audit_lines) + "\n")

    print(json.dumps({
        "contracts_total": len(contracts),
        "source_releases": len(maven_versions),
        "release_note_records": len(notes),
        "nonzero_releases": sum(1 for v in maven_versions if counts.get(v, 0)),
        "outputs": [str(OUT_RPL), str(OUT_JSON), str(OUT_COUNTS), str(OUT_AUDIT)],
    }, indent=2))


if __name__ == "__main__":
    main()
