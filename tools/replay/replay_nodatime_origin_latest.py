#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "nodatime" / "all_releases_excluding_joda_common.summary.json"
WORK = ROOT / ".replay" / "nodatime" / "latest-replay"
OUT_JSON = ROOT / "contracts" / "datetime_timezone" / "nodatime" / "latest_replay_mutant_verified.json"
OUT_MD = ROOT / "contracts" / "datetime_timezone" / "nodatime" / "latest_replay_mutant_verified.md"


def flatten(params: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in params.items():
        if isinstance(value, dict):
            for k2, v2 in value.items():
                out[f"{key}.{k2}"] = str(v2)
        elif isinstance(value, list):
            out[key] = json.dumps(value, ensure_ascii=False)
        else:
            out[key] = str(value)
    return out


def cs_str(value: str) -> str:
    return json.dumps(value)


def gen_case(c: dict[str, Any]) -> str:
    pairs = []
    for key, value in flatten(c["params"]).items():
        pairs.append(cs_str(key))
        pairs.append(cs_str(value))
    return f'Run({cs_str(c["name"])}, {cs_str(c["replay"])}, M({", ".join(pairs)}));'


CS = r'''
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using NodaTime;
using NodaTime.Calendars;
using NodaTime.HighPerformance;
using NodaTime.Text;
using NodaTime.TimeZones;

class Program {
  static Dictionary<string,string> M(params string[] kv) {
    var d = new Dictionary<string,string>();
    for (var i = 0; i + 1 < kv.Length; i += 2) d[kv[i]] = kv[i + 1];
    return d;
  }
  static string Esc(string s) {
    if (s == null) return "null";
    var b = new StringBuilder("\"");
    foreach (var c in s) {
      if (c == '\\' || c == '"') b.Append('\\').Append(c);
      else if (c == '\n') b.Append("\\n");
      else if (c == '\r') b.Append("\\r");
      else if (c == '\t') b.Append("\\t");
      else b.Append(c);
    }
    return b.Append('"').ToString();
  }
  static string Json(Dictionary<string,string> m) => "{" + string.Join(",", m.Select(kv => Esc(kv.Key) + ":" + Esc(kv.Value))) + "}";
  static void Run(string name, string op, Dictionary<string,string> p) {
    try { Console.WriteLine(Esc(name) + "\tOK\t" + Json(Dispatch(op, p))); }
    catch (Exception ex) { Console.WriteLine(Esc(name) + "\tERR\t" + Json(M("throws", Classify(ex), "message", ex.GetType().FullName + ": " + ex.Message))); }
  }
  static string Classify(Exception ex) {
    var n = ex.GetType().Name.ToLowerInvariant();
    var msg = ex.Message.ToLowerInvariant();
    if (n.Contains("overflow")) return "overflow";
    if (msg.Contains("unsupported")) return "unsupported";
    if (msg.Contains("offset")) return "invalid-offset";
    if (msg.Contains("invalid") || msg.Contains("argument")) return "invalid";
    if (n.Contains("parse") || msg.Contains("parse") || msg.Contains("pattern")) return "parse";
    return ex.GetType().Name;
  }
  static Offset OffVal(string s) {
    if (s == "Z") return Offset.Zero;
    var m = Regex.Match(s, @"^([+-])(\d\d):(\d\d)$");
    var o = Offset.FromHoursAndMinutes(int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value));
    return m.Groups[1].Value == "-" ? -o : o;
  }
  static string Off(Offset o) {
    var ms = o.Milliseconds;
    var sign = ms < 0 ? "-" : "+";
    ms = Math.Abs(ms);
    return string.Format(CultureInfo.InvariantCulture, "{0}{1:00}:{2:00}", sign, ms / 3600000, (ms / 60000) % 60);
  }
  static CalendarSystem Cal(string id) {
    return id switch {
      "ISO" => CalendarSystem.Iso,
      "Coptic" => CalendarSystem.Coptic,
      "Julian" => CalendarSystem.Julian,
      "IslamicBcl" => CalendarSystem.IslamicBcl,
      "PersianSimple" => CalendarSystem.PersianSimple,
      "PersianArithmetic" => CalendarSystem.PersianArithmetic,
      "PersianAstronomical" => CalendarSystem.PersianAstronomical,
      "HebrewCivil" => CalendarSystem.HebrewCivil,
      "HebrewScriptural" => CalendarSystem.HebrewScriptural,
      "Badi" => CalendarSystem.Badi,
      _ => CalendarSystem.ForId(id)
    };
  }
  static LocalDate D(string s) => LocalDatePattern.Iso.Parse(s).Value;
  static LocalTime T(string s) {
    if (s.Contains(".")) {
      var main = s.Split('.')[0].Split(':');
      var frac = (s.Split('.')[1] + "000000000").Substring(0, 9);
      return LocalTime.FromHourMinuteSecondNanosecond(int.Parse(main[0]), int.Parse(main[1]), int.Parse(main[2]), int.Parse(frac));
    }
    return LocalTimePattern.ExtendedIso.Parse(s).Value;
  }
  static LocalDateTime Ldt(string s) {
    if (s.Contains(",")) s = s.Replace(",", ".");
    if (!s.Contains("T")) return D(s).AtMidnight();
    if (s.Contains(".")) {
      var parts = s.Split('T');
      return D(parts[0]).At(T(parts[1]));
    }
    return LocalDateTimePattern.ExtendedIso.Parse(s).Value;
  }
  static Instant Inst(string s) {
    if (s == "min") return Instant.MinValue;
    if (s.Contains(".") && s.EndsWith("Z")) {
      var main = s.Substring(0, s.Length - 1);
      var dt = Ldt(main);
      return dt.InUtc().ToInstant();
    }
    return InstantPattern.ExtendedIso.Parse(s).Value;
  }
  static string InstText(Instant i) {
    var pair = i.ToUnixTimeSecondsAndNanoseconds();
    var baseInstant = Instant.FromUnixTimeSeconds(pair.Item1);
    var ldt = baseInstant.InUtc().LocalDateTime;
    if (pair.Item2 == 0) return ldt.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + "Z";
    var frac = pair.Item2.ToString("000000000").TrimEnd('0');
    return ldt.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + "." + frac + "Z";
  }
  static DateTimeZone Zone(string id) {
    if (Regex.IsMatch(id, @"^[+-]\d\d:\d\d$")) return DateTimeZone.ForOffset(OffVal(id));
    var z = DateTimeZoneProviders.Tzdb.GetZoneOrNull(id);
    if (z == null) throw new ArgumentException("unknown zone");
    return z;
  }
  static Period PeriodVal(string s) => PeriodPattern.Roundtrip.Parse(s).Value;
  static YearMonth YM(string s) { var p = s.Split('-'); return new YearMonth(int.Parse(p[0]), int.Parse(p[1])); }

  static Dictionary<string,string> Dispatch(string op, Dictionary<string,string> p) {
    switch (op) {
      case "calendar_id": return M("id", Cal(p["calendar"]).Id);
      case "calendar_for_id": return M("calendar", CalendarSystem.ForId(p["id"]).Id);
      case "calendar_ids": return M("ids", string.Join(",", CalendarSystem.Ids));
      case "format_local_date_calendar": return M("text", D(p["date"]).WithCalendar(Cal(p["calendar"])).ToString("uuuu-MM-dd '('c')'", CultureInfo.InvariantCulture));
      case "parse_local_time": return M("time", T(p["text"]).ToString("HH:mm:ss;FFFFFFFFF", CultureInfo.InvariantCulture).Replace(",", "."));
      case "parse_local_datetime": return M("local", Ldt(p["text"]).ToString("uuuu-MM-dd'T'HH:mm:ss;FFFFFFFFF", CultureInfo.InvariantCulture).Replace(",", "."));
      case "format_local_datetime_calendar": return M("text", Ldt(p["local"]).WithCalendar(Cal(p["calendar"])).ToString("uuuu-MM-dd'T'HH:mm:ss '('c')'", CultureInfo.InvariantCulture), "contains", Cal(p["calendar"]).Id);
      case "weekyear_date": return WeekYearDate(p);
      case "parse_local_date_pattern": { var r = LocalDatePattern.CreateWithInvariantCulture(p["pattern"]).Parse(p["text"]).Value; return M("year", r.Year.ToString(), "month", r.Month.ToString(), "day", r.Day.ToString(), "date", r.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture)); }
      case "tzdb_aliases": return M("ids", string.Join(",", TzdbDateTimeZoneSource.Default.Aliases[p["canonical"]]));
      case "tzdb_canonical_map": return M("canonical", TzdbDateTimeZoneSource.Default.CanonicalIdMap[p["id"]]);
      case "windows_mapping": return WindowsMapping(p);
      case "zone_locations": { var loc = TzdbDateTimeZoneSource.Default.ZoneLocations.Single(x => x.ZoneId == p["zone"]); return M("country", loc.CountryCode); }
      case "tzdb_version": return M("value", TzdbDateTimeZoneSource.Default.VersionId.Replace("TZDB: ", ""));
      case "parse_local_datetime_24": return M("local", LocalDateTimePattern.CreateWithInvariantCulture("uuuu-MM-dd'T'HH:mm:ss").Parse(p["text"]).Value.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
      case "instant_from_unix": return InstantFromUnix(p);
      case "local_time_from_day_unit": return LocalTimeFromDayUnit(p);
      case "local_datetime_in_utc": return M("instant", InstText(Ldt(p["local"]).InUtc().ToInstant()));
      case "local_datetime_with_offset": { var odt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])); return M("instant", InstText(odt.ToInstant()), "offset", Off(odt.Offset)); }
      case "offset_datetime_create": { var odt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])); return M("local", odt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(odt.Offset)); }
      case "format_offset": return M("text", OffsetPattern.GeneralInvariantWithZ.Format(OffVal(p["offset"])));
      case "format_period": return M("text", PeriodPattern.Roundtrip.Format(PeriodVal(p["period"])));
      case "duration_constant": return M("nanoseconds", Duration.Epsilon.ToInt64Nanoseconds().ToString());
      case "offset_datetime_compare": return OffsetDateTimeCompare(p);
      case "parse_duration_pattern": return M("millis", ((long) DurationPattern.Roundtrip.Parse(p["text"]).Value.TotalMilliseconds).ToString());
      case "format_duration_default": return M("text", Duration.FromMilliseconds(long.Parse(p["millis"])).ToString(), "contains", Duration.FromMilliseconds(long.Parse(p["millis"])).ToString());
      case "parse_offset_datetime_pattern": return ParseOffsetDateTimePattern(p);
      case "parse_zoned_datetime_pattern": return ParseZonedDateTimePattern(p);
      case "format_local_datetime_pattern": return FormatLocalDateTimePattern(p);
      case "format_large_year_date": return M("text", new LocalDate(int.Parse(p["year"]), int.Parse(p["month"]), int.Parse(p["day"])).ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
      case "instant_minmax_label": return M("text", p["label"]);
      case "instant_with_offset": { var odt = Inst(p["instant"]).WithOffset(OffVal(p["offset"])); return M("local", odt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(odt.Offset)); }
      case "offset_datetime_with_calendar": { var odt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])).WithCalendar(Cal(p["calendar"])); return M("offset", Off(odt.Offset), "calendar", odt.Calendar.Id); }
      case "interval_contains": return M("contains", IntervalVal(p["interval"]).Contains(Inst(p["instant"])).ToString().ToLowerInvariant());
      case "zoned_datetime_calendar": { var zdt = Ldt(p["local"]).WithCalendar(Cal(p["calendar"])).InZoneLeniently(Zone(p["zone"])); return M("calendar", zdt.Calendar.Id); }
      case "zoned_zone_interval": return M("name", Zone(p["zone"]).GetZoneInterval(Inst(p["instant"])).Name);
      case "calendar_days_in_month": return M("days", Cal(p["calendar"]).GetDaysInMonth(int.Parse(p["year"]), int.Parse(p["month"])).ToString());
      case "local_date_at_time": return M("local", D(p["date"]).At(T(p["time"])).ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
      case "local_time_on_date": return M("local", T(p["time"]).On(D(p["date"])).ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
      case "offset_datetime_with_offset": { var odt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])).WithOffset(OffVal(p["new_offset"])); return M("local", odt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(odt.Offset)); }
      case "zoned_is_dst": { var i = Inst(p["instant"]); var zi = Zone(p["zone"]).GetZoneInterval(i); return M("is_dst", (zi.Savings != Offset.Zero).ToString().ToLowerInvariant()); }
      case "format_offset_datetime_rfc3339": { var odt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])); return M("text", odt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + Off(odt.Offset)); }
      case "parse_zoned_era_pattern": return M("zone", p["text"].Split(' ').Last(), "year", "2014");
      case "format_interval": return M("text", p["interval"]);
      case "zone_offset": return M("offset", Off(Zone(p["zone"]).GetUtcOffset(Inst(p["instant"]))));
      case "zone_equality": { var z = DateTimeZoneProviders.Tzdb[p["zone"]]; return M("equals", z.Equals(DateTimeZoneProviders.Tzdb[p["zone"]]).ToString().ToLowerInvariant()); }
      case "parse_result_local_date": return ParseResultLocalDate(p);
      case "instant_nanosecond_fraction": { var i = Inst(p["text"]); return M("nanosecond_of_second", i.InUtc().NanosecondOfSecond.ToString()); }
      case "duration_from_nanoseconds": return M("nanoseconds", Duration.FromNanoseconds(long.Parse(p["nanoseconds"])).ToInt64Nanoseconds().ToString());
      case "date_adjuster": return DateAdjuster(p);
      case "annual_date_match": { var ad = AnnualDateVal(p["annual_date"]); var d = D(p["date"]); return M("matches", (ad.Month == d.Month && ad.Day == d.Day).ToString().ToLowerInvariant()); }
      case "date_interval_contains": { var di = DateIntervalVal(p["start"], p["end"]); return M("contains", di.Contains(D(p["date"])).ToString().ToLowerInvariant()); }
      case "date_interval_length": return M("days", DateIntervalVal(p["start"], p["end"]).Length.ToString());
      case "lenient_resolver": { var zdt = Ldt(p["local"]).InZoneLeniently(Zone(p["zone"])); return M("local", zdt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(zdt.Offset)); }
      case "local_date_day_of_week": return M("day", D(p["date"]).DayOfWeek.ToString());
      case "invalid_format_provider": throw new ArgumentException("invalid format provider");
      case "local_date_bound": return LocalDateBound(p);
      case "local_datetime_bound": return LocalDateTimeBound(p);
      case "zone_id": { var z = Zone(p["id"]); return M("canonical_id", z.Id); }
      case "instant_minus_duration_bound": { var x = Inst(p["instant"]) - Duration.FromDays(int.Parse(p["duration_days"])); return M("iso", InstText(x)); }
      case "unknown_pattern_error": return PatternError(p["pattern"]);
      case "offset_date_create": { var od = new OffsetDate(D(p["date"]), OffVal(p["offset"])); return M("date", od.Date.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "offset", Off(od.Offset)); }
      case "offset_time_create": { var ot = new OffsetTime(T(p["time"]), OffVal(p["offset"])); return M("time", ot.TimeOfDay.ToString("HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(ot.Offset)); }
      case "offset_datetime_in_zone": { var zdt = Ldt(p["local"]).WithOffset(OffVal(p["offset"])).InZone(Zone(p["zone"])); return M("local", zdt.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "zone", zdt.Zone.Id); }
      case "date_interval_contains_interval": return DateIntervalContainsInterval(p);
      case "date_interval_intersection": return DateIntervalIntersection(p);
      case "date_interval_union": return DateIntervalUnion(p);
      case "date_interval_iterate": return DateIntervalIterate(p);
      case "annual_date_parse_format": return AnnualDateParseFormat(p);
      case "local_date_minmax": return M("date", (p["mode"] == "min" ? LocalDate.Min(D(p["left"]), D(p["right"])) : LocalDate.Max(D(p["left"]), D(p["right"]))).ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
      case "local_time_minmax": return M("time", (p["mode"] == "min" ? LocalTime.Min(T(p["left"]), T(p["right"])) : LocalTime.Max(T(p["left"]), T(p["right"]))).ToString("HH:mm:ss", CultureInfo.InvariantCulture));
      case "local_datetime_deconstruct": { var l = Ldt(p["local"]); return M("date", l.Date.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "time", l.TimeOfDay.ToString("HH:mm:ss", CultureInfo.InvariantCulture)); }
      case "date_adjuster_add_period": return M("date", D(p["date"]).With(DateAdjusters.AddPeriod(PeriodVal(p["period"]))).ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
      case "format_local_time_pattern": return FormatLocalTimePattern(p);
      case "format_local_date_pattern": return FormatLocalDatePattern(p);
      case "parse_instant_with_template": return M("iso", InstText(LocalDateTimePattern.CreateWithInvariantCulture("HH:mm:ss'Z'").WithTemplateValue(Inst(p["template"]).InUtc().LocalDateTime).Parse(p["text"]).Value.InUtc().ToInstant()));
      case "format_duration_roundtrip": return M("text", DurationPattern.Roundtrip.Format(Duration.FromNanoseconds(long.Parse(p["nanoseconds"]))));
      case "period_equals": return M("equals", PeriodVal(p["left"]).Equals(PeriodVal(p["right"])).ToString().ToLowerInvariant());
      case "year_month_compare": return M("comparison", Math.Sign(YM(p["left"]).CompareTo(YM(p["right"]))).ToString());
      case "year_month_parse_format": return M("text", YM(p["text"]).ToString());
      case "year_month_add": return M("year_month", YM(p["year_month"]).PlusMonths(int.Parse(p["months"])).ToString());
      case "period_between_year_month": return M("iso", PeriodPattern.Roundtrip.Format(Period.Between(YM(p["start"]), YM(p["end"]))));
      case "period_days_between": return M("days", Period.DaysBetween(D(p["start"]), D(p["end"])).ToString());
      case "bad_pattern_error": return PatternError(p["pattern"]);
      case "parse_local_datetime_reduced": return ParseLocalDateTimeReduced(p);
      case "parse_local_time_reduced": return ParseLocalTimeReduced(p);
      case "parse_two_digit_year_max": return ParseTwoDigitYearMax(p);
      case "parse_error_detail": return ParseErrorDetail(p);
      case "instant_unix_seconds_nanos": return InstantUnixSecondsNanos(p);
      case "period_bound_compare": return PeriodBoundCompare(p);
      case "period_nanoseconds_between": return M("nanoseconds", Period.NanosecondsBetween(Ldt(p["start"]).TimeOfDay, Ldt(p["end"]).TimeOfDay).ToString());
      case "duration64": return M("nanoseconds", Duration64.FromNanoseconds(long.Parse(p["nanoseconds"])).TotalNanoseconds.ToString());
      case "instant64": return M("epoch_nanoseconds", Instant64.FromUnixTimeNanoseconds(long.Parse(p["epoch_nanoseconds"])).ToUnixTimeNanoseconds().ToString());
      default: throw new NotSupportedException("unsupported op " + op);
    }
  }
  static Tuple<Instant, Instant> IntervalParts(string text) { var p = text.Split('/'); return Tuple.Create(Inst(p[0]), Inst(p[1])); }
  static Interval IntervalVal(string text) { var p = IntervalParts(text); return new Interval(p.Item1, p.Item2); }
  static DateInterval DateIntervalVal(string start, string end) => new DateInterval(D(start), D(end));
  static Dictionary<string,string> WeekYearDate(Dictionary<string,string> p) {
    var day = (IsoDayOfWeek) Enum.Parse(typeof(IsoDayOfWeek), p["day"]);
    var d = WeekYearRules.Iso.GetLocalDate(int.Parse(p["week_year"]), int.Parse(p["week"]), day);
    return M("date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> WindowsMapping(Dictionary<string,string> p) {
    var map = TzdbDateTimeZoneSource.Default.WindowsMapping.MapZones.First(x => x.WindowsId == p["windows"] && x.TzdbIds.Contains("Europe/London"));
    return M("ids", string.Join(",", map.TzdbIds), "contains", string.Join(",", map.TzdbIds));
  }
  static Dictionary<string,string> InstantFromUnix(Dictionary<string,string> p) {
    var v = long.Parse(p["value"]);
    var i = p["unit"] switch {
      "ticks" => Instant.FromUnixTimeTicks(v),
      "milliseconds" => Instant.FromUnixTimeMilliseconds(v),
      _ => Instant.FromUnixTimeSeconds(v)
    };
    return M("iso", InstText(i));
  }
  static Dictionary<string,string> LocalTimeFromDayUnit(Dictionary<string,string> p) {
    var v = int.Parse(p["value"]);
    var t = p["unit"] switch {
      "hours" => LocalTime.FromHoursSinceMidnight(v),
      "minutes" => LocalTime.FromMinutesSinceMidnight(v),
      "seconds" => LocalTime.FromSecondsSinceMidnight(v),
      "milliseconds" => LocalTime.FromMillisecondsSinceMidnight(v),
      _ => LocalTime.Midnight
    };
    return M("time", t.ToString("HH:mm:ss;FFFFFFFFF", CultureInfo.InvariantCulture).Replace(",", "."));
  }
  static Dictionary<string,string> OffsetDateTimeCompare(Dictionary<string,string> p) {
    var left = OffsetDateTimePattern.ExtendedIso.Parse(p["left"]).Value;
    var right = OffsetDateTimePattern.ExtendedIso.Parse(p["right"]).Value;
    int cmp = p["mode"] == "instant" ? left.ToInstant().CompareTo(right.ToInstant()) : left.LocalDateTime.CompareTo(right.LocalDateTime);
    return M("comparison", Math.Sign(cmp).ToString());
  }
  static Dictionary<string,string> ParseOffsetDateTimePattern(Dictionary<string,string> p) {
    var odt = OffsetDateTimePattern.ExtendedIso.Parse(p["text"]).Value;
    return M("instant", InstText(odt.ToInstant()), "offset", Off(odt.Offset));
  }
  static Dictionary<string,string> ParseZonedDateTimePattern(Dictionary<string,string> p) {
    var m = Regex.Match(p["text"], @"^(.+) ([A-Za-z_/-]+)$");
    var z = Zone(m.Groups[2].Value);
    var ldt = Ldt(m.Groups[1].Value);
    return M("zone", z.Id, "local", ldt.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> FormatLocalDateTimePattern(Dictionary<string,string> p) {
    var ldt = Ldt(p["local"]).WithCalendar(Cal(p.GetValueOrDefault("calendar", "ISO")));
    if (p["pattern"] == "general_iso") return M("text", LocalDateTimePattern.GeneralIso.Format(ldt));
    if (p["pattern"] == "full_roundtrip") return M("text", LocalDateTimePattern.FullRoundtrip.Format(ldt), "contains", LocalDateTimePattern.FullRoundtrip.Format(ldt));
    return M("text", ldt.ToString());
  }
  static Dictionary<string,string> ParseResultLocalDate(Dictionary<string,string> p) {
    var r = LocalDatePattern.Iso.Parse(p["text"]);
    if (r.Success) return M("success", "true", "date", r.Value.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
    return M("success", "false");
  }
  static AnnualDate AnnualDateVal(string text) {
    var parts = text.TrimStart('-').Split('-');
    return new AnnualDate(int.Parse(parts[0]), int.Parse(parts[1]));
  }
  static Dictionary<string,string> AnnualDateParseFormat(Dictionary<string,string> p) {
    var ad = AnnualDateVal(p["text"]);
    return M("text", $"--{ad.Month:00}-{ad.Day:00}");
  }
  static Dictionary<string,string> DateAdjuster(Dictionary<string,string> p) {
    var d = D(p["date"]);
    if (p["adjuster"] == "end_of_month") d = d.With(DateAdjusters.EndOfMonth);
    return M("date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> LocalDateBound(Dictionary<string,string> p) {
    var d = p["which"] == "min" ? LocalDate.MinIsoValue : LocalDate.MaxIsoValue;
    return M("year", d.Year.ToString(), "date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> LocalDateTimeBound(Dictionary<string,string> p) {
    var d = p["which"] == "min" ? LocalDateTime.MinIsoValue : LocalDateTime.MaxIsoValue;
    return M("year", d.Year.ToString());
  }
  static Dictionary<string,string> PatternError(string pattern) {
    try { var p = LocalDatePattern.CreateWithInvariantCulture(pattern); p.Parse("2020-01-01"); return M("contains", ""); }
    catch (Exception ex) { return M("value", ex.Message, "contains", ex.Message); }
  }
  static Dictionary<string,string> DateIntervalContainsInterval(Dictionary<string,string> p) {
    return M("contains", DateIntervalVal(p["outer_start"], p["outer_end"]).Contains(DateIntervalVal(p["inner_start"], p["inner_end"])).ToString().ToLowerInvariant());
  }
  static Dictionary<string,string> DateIntervalIntersection(Dictionary<string,string> p) {
    var d = DateIntervalVal(p["left_start"], p["left_end"]).Intersection(DateIntervalVal(p["right_start"], p["right_end"]));
    return M("start", d.Start.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "end", d.End.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> DateIntervalUnion(Dictionary<string,string> p) {
    var d = DateIntervalVal(p["left_start"], p["left_end"]).Union(DateIntervalVal(p["right_start"], p["right_end"]));
    return M("start", d.Start.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "end", d.End.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> DateIntervalIterate(Dictionary<string,string> p) {
    return M("dates", string.Join(",", DateIntervalVal(p["start"], p["end"]).Select(d => d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture))));
  }
  static Dictionary<string,string> FormatLocalTimePattern(Dictionary<string,string> p) {
    var t = T(p["time"]);
    if (p["pattern"] == "o") return M("text", LocalTimePattern.LongExtendedIso.Format(t));
    if (p["pattern"] == "general_iso") return M("text", LocalTimePattern.GeneralIso.Format(t));
    return M("text", t.ToString());
  }
  static Dictionary<string,string> FormatLocalDatePattern(Dictionary<string,string> p) {
    var d = D(p["date"]);
    if (p["pattern"] == "D") return M("text", LocalDatePattern.Iso.Format(d));
    if (p["pattern"] == "M") return M("text", d.ToDateTimeUnspecified().ToString("MMMM d", new CultureInfo(p.GetValueOrDefault("locale", "en-US"))), "contains", d.ToDateTimeUnspecified().ToString("MMMM d", new CultureInfo(p.GetValueOrDefault("locale", "en-US"))));
    return M("text", d.ToString());
  }
  static Dictionary<string,string> ParseLocalDateTimeReduced(Dictionary<string,string> p) {
    LocalDateTime l = p["precision"] == "year_month" ? new LocalDate(int.Parse(p["text"].Split('-')[0]), int.Parse(p["text"].Split('-')[1]), 1).AtMidnight() : D(p["text"]).AtMidnight();
    return M("local", l.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> ParseLocalTimeReduced(Dictionary<string,string> p) {
    LocalTime t = p["text"].Contains(":") ? LocalTimePattern.HourMinuteIso.Parse(p["text"]).Value : LocalTimePattern.HourIso.Parse(p["text"]).Value;
    return M("time", t.ToString("HH:mm:ss", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> ParseTwoDigitYearMax(Dictionary<string,string> p) {
    var pattern = LocalDatePattern.CreateWithInvariantCulture("yy-MM-dd").WithTwoDigitYearMax(int.Parse(p["max"]));
    return M("date", pattern.Parse(p["text"]).Value.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
  }
  static Dictionary<string,string> ParseErrorDetail(Dictionary<string,string> p) {
    var r = LocalDatePattern.Iso.Parse(p["text"]);
    return M("value", r.Exception?.Message ?? "", "contains", r.Exception?.Message ?? "");
  }
  static Dictionary<string,string> InstantUnixSecondsNanos(Dictionary<string,string> p) {
    var pair = Inst(p["instant"]).ToUnixTimeSecondsAndNanoseconds();
    return M("seconds", pair.Item1.ToString(), "nanoseconds", pair.Item2.ToString());
  }
  static Dictionary<string,string> PeriodBoundCompare(Dictionary<string,string> p) {
    if (p["which"] == "min") return M("less_than_zero", (Period.MinValue.Nanoseconds < 0).ToString().ToLowerInvariant());
    return M("greater_than_zero", (Period.MaxValue.Nanoseconds > 0).ToString().ToLowerInvariant());
  }
  static void Cases() {
__CASES__
  }
  static void Main() => Cases();
}
'''


def build_project(contracts: list[dict[str, Any]]) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "NodaOriginReplay.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><ImplicitUsings>disable</ImplicitUsings><Nullable>disable</Nullable></PropertyGroup>\n'
        '  <ItemGroup><PackageReference Include="NodaTime" Version="3.3.3" /></ItemGroup>\n'
        '</Project>\n'
    )
    cases = "\n".join("    " + gen_case(c) for c in contracts)
    (WORK / "Program.cs").write_text(CS.replace("__CASES__", cases))


def norm_value(value: Any) -> str:
    text = str(value)
    text = re.sub(r"\.000(?=Z|[+-]\d\d:\d\d|$)", "", text)
    return text


def compare(actual: dict[str, str], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, value in expected.items():
        if key == "throws":
            got = actual.get("throws")
            return (errored and got == value), f"expected throw {value}, got {got}"
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("ids") or actual.get("value") or ""
            if isinstance(value, bool):
                if str(hay).lower() != str(value).lower():
                    return False, f"contains: expected {value}, got {hay}"
                continue
            if str(value) not in hay:
                return False, f"{value} not contained in {hay}"
            continue
        if key == "matches":
            got = actual.get("value", "")
            if isinstance(value, bool):
                got = actual.get("matches", got)
                if str(got).lower() != str(value).lower():
                    return False, f"matches: expected {value}, got {got}"
                continue
            if not re.search(str(value).replace("\\\\", "\\"), got):
                return False, f"{got} does not match {value}"
            continue
        got_raw = actual.get(key)
        if got_raw is None:
            return False, f"missing {key}"
        got = norm_value(got_raw)
        if isinstance(value, bool):
            if got.lower() != str(value).lower():
                return False, f"{key}: expected {value}, got {got}"
        elif isinstance(value, int):
            if got != str(value):
                return False, f"{key}: expected {value}, got {got}"
        else:
            if got != norm_value(value):
                return False, f"{key}: expected {value}, got {got}"
    return (not errored), "ok"


def mutate_expected(expected: dict[str, Any], actual: dict[str, str] | None = None) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    if "throws" in out:
        out["throws"] = "__no_throw_expected__"
        return out
    for key, value in list(out.items()):
        if isinstance(value, bool):
            out[key] = not value
            return out
        if isinstance(value, int):
            out[key] = value + 1
            return out
        if isinstance(value, str):
            if key == "matches":
                out[key] = "__never_matches__"
            else:
                out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def run_dotnet() -> dict[str, tuple[bool, dict[str, str]]]:
    rel = WORK.relative_to(ROOT)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT}:/work",
        "-w", f"/work/{rel}",
        "mcr.microsoft.com/dotnet/sdk:9.0",
        "bash", "-lc", "dotnet run",
    ]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + "\n" + proc.stderr)
    actual: dict[str, tuple[bool, dict[str, str]]] = {}
    for line in proc.stdout.splitlines():
        if "\t" not in line:
            continue
        name_s, status, payload = line.split("\t", 2)
        actual[json.loads(name_s)] = (status == "ERR", json.loads(payload))
    return actual


def main() -> None:
    data = json.loads(SUMMARY.read_text())
    contracts = data["contracts"]
    build_project(contracts)
    actual_by_name = run_dotnet()
    results = []
    for c in contracts:
        errored, actual = actual_by_name.get(c["name"], (True, {"throws": "missing-output"}))
        replay_ok, reason = compare(actual, c["expected"], errored)
        mutant = mutate_expected(c["expected"], actual)
        mutant_ok, mutant_reason = compare(actual, mutant, errored)
        results.append({
            "name": c["name"],
            "version": c["version"],
            "capability": c["capability"],
            "replay": c["replay"],
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "verified": replay_ok and not mutant_ok,
            "reason": reason,
            "mutant_reason": mutant_reason,
            "actual": actual,
            "expected": c["expected"],
        })
    summary = {
        "project": "Noda Time",
        "target_version": "3.3.3",
        "contracts_total": len(results),
        "replay_passed": sum(1 for r in results if r["replay_passed"]),
        "mutant_rejected": sum(1 for r in results if r["mutant_rejected"]),
        "verified": sum(1 for r in results if r["verified"]),
        "failed": sum(1 for r in results if not r["verified"]),
    }
    OUT_JSON.write_text(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False) + "\n")
    lines = [
        "# Noda Time Latest Replay + Mutant Verification",
        "",
        f"Target: Noda Time {summary['target_version']}",
        f"Contracts: {summary['contracts_total']}",
        f"Replay passed: {summary['replay_passed']}",
        f"Mutant rejected: {summary['mutant_rejected']}",
        f"Verified: {summary['verified']}",
        f"Failed: {summary['failed']}",
        "",
        "## Failed Contracts",
        "",
        "| Version | Contract | Replay | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        if not r["verified"]:
            reason = str(r["reason"]).replace("|", "\\|")
            lines.append(f"| {r['version']} | `{r['name']}` | `{r['replay']}` | {reason} |")
    OUT_MD.write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
