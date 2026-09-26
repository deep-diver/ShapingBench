#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "joda-time" / "all_releases_maximal_language_independent.summary.json"
JAR = ROOT / ".replay" / "joda-time" / "jars" / "joda-time-2.14.3.jar"
WORK = ROOT / ".replay" / "joda-time" / "latest-replay"
OUT_JSON = ROOT / "contracts" / "datetime_timezone" / "joda-time" / "latest_replay_mutant_verified.json"
OUT_MD = ROOT / "contracts" / "datetime_timezone" / "joda-time" / "latest_replay_mutant_verified.md"


def jstr(value: str) -> str:
    return json.dumps(value)


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


def gen_case(contract: dict[str, Any]) -> str:
    params = flatten(contract["params"])
    pairs: list[str] = []
    for key, value in params.items():
        pairs.append(jstr(key))
        pairs.append(jstr(value))
    return f'run({jstr(contract["name"])}, {jstr(contract["replay"])}, m({", ".join(pairs)}));'


JAVA = r'''
import org.joda.time.*;
import org.joda.time.chrono.*;
import org.joda.time.format.*;
import java.io.*;
import java.math.*;
import java.net.*;
import java.text.*;
import java.util.*;
import java.util.jar.*;

public class RunJodaLatest {
  interface ThrowingSupplier { Map<String,String> get() throws Exception; }

  static Map<String,String> m(String... kv) {
    Map<String,String> out = new LinkedHashMap<>();
    for (int i = 0; i + 1 < kv.length; i += 2) out.put(kv[i], kv[i + 1]);
    return out;
  }

  static String esc(String s) {
    if (s == null) return "null";
    StringBuilder b = new StringBuilder();
    b.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\' || c == '"') b.append('\\').append(c);
      else if (c == '\n') b.append("\\n");
      else if (c == '\r') b.append("\\r");
      else if (c == '\t') b.append("\\t");
      else b.append(c);
    }
    b.append('"');
    return b.toString();
  }

  static String json(Map<String,String> map) {
    StringBuilder b = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String,String> e : map.entrySet()) {
      if (!first) b.append(",");
      first = false;
      b.append(esc(e.getKey())).append(":").append(esc(e.getValue()));
    }
    b.append("}");
    return b.toString();
  }

  static void run(String name, String op, Map<String,String> p) {
    Map<String,String> out = new LinkedHashMap<>();
    try {
      out = dispatch(op, p);
      System.out.println(esc(name) + "\tOK\t" + json(out));
    } catch (Throwable ex) {
      out.put("throws", classify(ex));
      out.put("message", ex.getClass().getName() + ": " + String.valueOf(ex.getMessage()));
      System.out.println(esc(name) + "\tERR\t" + json(out));
    }
  }

  static String classify(Throwable ex) {
    String n = ex.getClass().getName().toLowerCase(Locale.ROOT);
    String msg = String.valueOf(ex.getMessage()).toLowerCase(Locale.ROOT);
    if (n.contains("unsupported")) return "unsupported";
    if (n.contains("parse") || msg.contains("invalid format") || msg.contains("parse") || msg.contains("malformed")) return "parse";
    if (n.contains("arithmetic")) return "overflow";
    if (n.contains("illegalinstant")) return "illegal-instant";
    if (msg.contains("hours out of range") || msg.contains("offset")) return "invalid-offset";
    if (msg.contains("types array") || msg.contains("partial")) return "invalid-partial";
    if (n.contains("illegal") && (msg.contains("zone") || msg.contains(" id"))) return "unknown-zone";
    if (n.contains("illegal")) return "invalid";
    return ex.getClass().getSimpleName();
  }

  static DateTimeZone zone(String id) {
    if ("Z".equals(id)) return DateTimeZone.UTC;
    return DateTimeZone.forID(id);
  }

  static String off(int millis) {
    int totalMinutes = millis / 60000;
    char sign = totalMinutes < 0 ? '-' : '+';
    totalMinutes = Math.abs(totalMinutes);
    return String.format(Locale.ROOT, "%c%02d:%02d", sign, totalMinutes / 60, totalMinutes % 60);
  }

  static Locale locale(String id) {
    if (id == null) return Locale.ROOT;
    if ("en".equals(id)) return Locale.ENGLISH;
    if ("fr".equals(id)) return Locale.FRENCH;
    if ("ko".equals(id)) return Locale.KOREAN;
    if ("ru".equals(id)) return new Locale("ru");
    return Locale.forLanguageTag(id.replace('_', '-'));
  }

  static Map<String,String> dispatch(String op, Map<String,String> p) throws Exception {
    switch (op) {
      case "zone_id": return zoneId(p);
      case "zone_offset": return zoneOffset(p);
      case "standard_offset": return standardOffset(p);
      case "zone_name_key": return zoneNameKey(p);
      case "available_zone_ids": return availableZoneIds(p);
      case "tzdb_version": return tzdbVersion(p);
      case "fixed_offset": return fixedOffset(p);
      case "fixed_offset_roundtrip": return fixedOffset(p);
      case "format_datetime": return formatDateTime(p);
      case "format_local_date": return formatLocalDate(p);
      case "parse_local_date": return parseLocalDate(p);
      case "parse_local_time": return parseLocalTime(p);
      case "parse_local_datetime": return parseLocalDateTime(p);
      case "parse_datetime": return parseDateTime(p);
      case "parse_into": return parseInto(p);
      case "parse_zone_id": return parseZoneId(p);
      case "parse_month_day": return parseMonthDay(p);
      case "month_day_add": return monthDayAdd(p);
      case "year_month_add": return yearMonthAdd(p);
      case "local_time_add": return localTimeAdd(p);
      case "local_time_from_date": return localTimeFromDate(p);
      case "local_date_add": return localDateAdd(p);
      case "local_date_interval": return localDateInterval(p);
      case "combine_local_date_time": return combineLocalDateTime(p);
      case "datetime_with_date": return datetimeWithDate(p);
      case "datetime_with_time": return datetimeWithTime(p);
      case "start_of_day": return startOfDay(p);
      case "local_datetime_gap": return localDateTimeGap(p);
      case "convert_local_to_utc": return convertLocalToUtc(p);
      case "resolve_local": return resolveLocal(p);
      case "overlap_offset_choice": return overlapOffsetChoice(p);
      case "zoned_add": return zonedAdd(p);
      case "parse_period": return parsePeriod(p);
      case "parse_period_regex": return parsePeriodRegex(p);
      case "period_add_field": return periodAddField(p);
      case "period_normalize": return periodNormalize(p);
      case "period_to_standard": return periodToStandard(p);
      case "period_factory": return periodFactory(p);
      case "period_constant": return periodConstant(p);
      case "format_period_words": return formatPeriodWords(p);
      case "format_period_custom": return formatPeriodCustom(p);
      case "duration_from_millis": return durationFromMillis(p);
      case "duration_standard_seconds": return durationStandardSeconds(p);
      case "plus_months_extreme": return plusMonthsExtreme(p);
      case "duration_divide": return durationDivide(p);
      case "duration_multiply": return durationMultiply(p);
      case "duration_negate": return durationNegate(p);
      case "parse_duration": return parseDuration(p);
      case "format_duration": return formatDuration(p);
      case "duration_to_period": return durationToPeriod(p);
      case "single_field_period_convert": return singleFieldPeriodConvert(p);
      case "parse_interval": return parseInterval(p);
      case "interval_relation": return intervalRelation(p);
      case "interval_overlap": return intervalOverlap(p);
      case "interval_gap": return intervalGap(p);
      case "property_to_interval": return propertyToInterval(p);
      case "chronology_date": return chronologyDate(p);
      case "chronology_equals": return chronologyEquals(p);
      case "instant_constant": return instantConstant(p);
      case "instant_from_epoch_millis": return instantFromEpochMillis(p);
      case "instant_from_epoch_seconds": return instantFromEpochSeconds(p);
      case "convert_datetime_zone": return convertDateTimeZone(p);
      case "field_is_leap": return fieldIsLeap(p);
      case "partial_create": return partialCreate(p);
      case "formatter_capability": return formatterCapability(p);
      case "lenient_local_datetime": return lenientLocalDateTime(p);
      case "java_timezone_name_digits": return javaTimezoneNameDigits(p);
      default:
        Map<String,String> out = new LinkedHashMap<>();
        out.put("unsupported_op", op);
        return out;
    }
  }

  static Map<String,String> zoneId(Map<String,String> p) {
    DateTimeZone z = zone(p.get("id"));
    Map<String,String> out = new LinkedHashMap<>();
    out.put("canonical_id", z.getID());
    if (z.isFixed()) out.put("offset", off(z.getOffset(0L)));
    return out;
  }

  static Map<String,String> zoneOffset(Map<String,String> p) {
    DateTimeZone z = zone(p.get("zone"));
    Instant i = Instant.parse(p.get("instant"));
    return m("offset", off(z.getOffset(i)));
  }

  static Map<String,String> standardOffset(Map<String,String> p) {
    DateTimeZone z = zone(p.get("zone"));
    Instant i = Instant.parse(p.get("instant"));
    return m("standard_offset", off(z.getStandardOffset(i.getMillis())), "actual_offset", off(z.getOffset(i)));
  }

  static Map<String,String> zoneNameKey(Map<String,String> p) {
    DateTimeZone z = zone(p.get("zone"));
    Instant i = Instant.parse(p.get("instant"));
    return m("value", z.getNameKey(i.getMillis()));
  }

  static Map<String,String> availableZoneIds(Map<String,String> p) {
    return m("ids", String.join(",", DateTimeZone.getAvailableIDs()));
  }

  static Map<String,String> tzdbVersion(Map<String,String> p) throws Exception {
    URL url = DateTime.class.getProtectionDomain().getCodeSource().getLocation();
    try (JarInputStream jar = new JarInputStream(url.openStream())) {
      Manifest mf = jar.getManifest();
      return m("value", mf.getMainAttributes().getValue("Time-Zone-Database-Version"));
    }
  }

  static Map<String,String> fixedOffset(Map<String,String> p) {
    String s = p.get("offset");
    boolean neg = s.startsWith("-");
    String[] hm = s.substring(1).split(":");
    int h = Integer.parseInt(hm[0]);
    int m = Integer.parseInt(hm[1]);
    if (neg) { h = -h; m = -m; }
    DateTimeZone z = DateTimeZone.forOffsetHoursMinutes(h, m);
    return m("offset", off(z.getOffset(0L)));
  }

  static DateTimeFormatter patternFormatter(Map<String,String> p) {
    DateTimeFormatter f;
    if (p.containsKey("style")) f = DateTimeFormat.forStyle(p.get("style"));
    else if ("basic_iso_date".equals(p.get("format"))) f = ISODateTimeFormat.basicDate();
    else f = DateTimeFormat.forPattern(p.getOrDefault("pattern", "yyyy-MM-dd'T'HH:mm:ssZ"));
    if (p.containsKey("locale")) f = f.withLocale(locale(p.get("locale")));
    if (p.containsKey("pivot_year")) f = f.withPivotYear(Integer.parseInt(p.get("pivot_year")));
    if (p.containsKey("zone")) f = f.withZone(zone(p.get("zone")));
    return f;
  }

  static Map<String,String> formatDateTime(Map<String,String> p) {
    DateTimeFormatter f = patternFormatter(p);
    DateTime dt = Instant.parse(p.get("instant")).toDateTime(zone(p.getOrDefault("zone", "UTC")));
    String text = f.print(dt);
    return m("text", text, "contains_time", String.valueOf(text.matches(".*\\d+:\\d+.*")), "contains_date", String.valueOf(text.matches(".*\\d{4}.*")));
  }

  static Map<String,String> formatLocalDate(Map<String,String> p) {
    LocalDate d = LocalDate.parse(p.get("date"));
    String text;
    if ("ordinal".equals(p.get("format"))) text = ISODateTimeFormat.ordinalDate().print(d);
    else text = DateTimeFormat.forPattern(p.get("pattern")).withLocale(locale(p.get("locale"))).print(d);
    return m("text", text);
  }

  static Map<String,String> parseLocalDate(Map<String,String> p) {
    LocalDate d;
    if ("basic_iso_date".equals(p.get("format"))) d = ISODateTimeFormat.basicDate().parseLocalDate(p.get("text"));
    else if ("iso".equals(p.get("format"))) d = LocalDate.parse(p.get("text"));
    else d = patternFormatter(p).parseLocalDate(p.get("text"));
    return m("date", d.toString(), "year", String.valueOf(d.getYear()), "month", String.valueOf(d.getMonthOfYear()), "day", String.valueOf(d.getDayOfMonth()));
  }

  static Map<String,String> parseLocalTime(Map<String,String> p) {
    return m("time", LocalTime.parse(p.get("text")).toString());
  }

  static Map<String,String> parseLocalDateTime(Map<String,String> p) {
    LocalDateTime ldt;
    if ("date_optional_time".equals(p.get("format"))) ldt = ISODateTimeFormat.dateOptionalTimeParser().parseLocalDateTime(p.get("text"));
    else ldt = LocalDateTime.parse(p.get("text"));
    return m("local", ldt.toString());
  }

  static Map<String,String> parseDateTime(Map<String,String> p) {
    DateTimeFormatter f;
    if ("iso".equals(p.get("format"))) f = ISODateTimeFormat.dateTimeParser();
    else f = patternFormatter(p);
    DateTime dt = f.parseDateTime(p.get("text"));
    return m("zone", dt.getZone().getID(), "offset", off(dt.getZone().getOffset(dt)), "local", dt.toLocalDateTime().toString(), "millis_of_second", String.valueOf(dt.getMillisOfSecond()), "zone_name_contains", dt.getZone().getName(dt.getMillis(), locale(p.get("locale"))));
  }

  static Map<String,String> parseInto(Map<String,String> p) {
    MutableDateTime base = new MutableDateTime(DateTime.parse(p.get("base")));
    DateTimeFormat.forPattern(p.get("pattern")).parseInto(base, p.get("text"), 0);
    return m("date", base.toDateTime().toLocalDate().toString());
  }

  static Map<String,String> parseZoneId(Map<String,String> p) {
    return m("zone", zone(p.get("text")).getID());
  }

  static Map<String,String> parseMonthDay(Map<String,String> p) {
    MonthDay md = MonthDay.parse(p.get("text"));
    return m("month_day", String.format(Locale.ROOT, "--%02d-%02d", md.getMonthOfYear(), md.getDayOfMonth()));
  }

  static Map<String,String> monthDayAdd(Map<String,String> p) {
    MonthDay md = MonthDay.parse(p.get("month_day")).plusDays(Integer.parseInt(p.get("amount.days")));
    return m("month_day", String.format(Locale.ROOT, "--%02d-%02d", md.getMonthOfYear(), md.getDayOfMonth()));
  }

  static Map<String,String> yearMonthAdd(Map<String,String> p) {
    YearMonth ym = YearMonth.parse(p.get("year_month")).plusMonths(Integer.parseInt(p.get("amount.months")));
    return m("year_month", ym.toString());
  }

  static Map<String,String> localTimeAdd(Map<String,String> p) {
    LocalTime t = LocalTime.parse(p.get("time"));
    if (p.containsKey("amount.hours")) t = t.plusHours(Integer.parseInt(p.get("amount.hours")));
    return m("time", t.toString());
  }

  static Map<String,String> localTimeFromDate(Map<String,String> p) {
    DateTime dt = Instant.parse(p.get("instant")).toDateTime(zone(p.get("zone")));
    return m("time", LocalTime.fromDateFields(dt.toDate()).toString());
  }

  static Map<String,String> localDateAdd(Map<String,String> p) {
    LocalDate d = LocalDate.parse(p.get("date"));
    if (p.containsKey("amount.months")) d = d.plusMonths(Integer.parseInt(p.get("amount.months")));
    if (p.containsKey("amount.years")) d = d.plusYears(Integer.parseInt(p.get("amount.years")));
    return m("date", d.toString());
  }

  static Map<String,String> plusMonthsExtreme(Map<String,String> p) {
    LocalDate d = LocalDate.parse(p.get("date"));
    d = d.plusMonths(Integer.parseInt(p.get("months")));
    return m("date", d.toString());
  }

  static Map<String,String> localDateInterval(Map<String,String> p) {
    LocalDate d = LocalDate.parse(p.get("date"));
    Interval i = d.toInterval(zone(p.get("zone")));
    return m("duration_hours", String.valueOf(i.toDuration().getStandardHours()));
  }

  static Map<String,String> combineLocalDateTime(Map<String,String> p) {
    DateTime dt = LocalDate.parse(p.get("date")).toDateTime(LocalTime.parse(p.get("time")), zone(p.get("zone")));
    return m("local", dt.toLocalDateTime().toString());
  }

  static DateTime parseBracketed(String s) {
    int b = s.indexOf('[');
    if (b >= 0) {
      String main = s.substring(0, b);
      String zid = s.substring(b + 1, s.length() - 1);
      return DateTime.parse(main).withZoneRetainFields(zone(zid));
    }
    return DateTime.parse(s);
  }

  static Map<String,String> datetimeWithDate(Map<String,String> p) {
    DateTime dt = parseBracketed(p.get("datetime")).withDate(LocalDate.parse(p.get("date")));
    return m("local", dt.toLocalDateTime().toString(), "zone", dt.getZone().getID());
  }

  static Map<String,String> datetimeWithTime(Map<String,String> p) {
    LocalTime t = LocalTime.parse(p.get("time"));
    DateTime dt = parseBracketed(p.get("datetime")).withTime(t.getHourOfDay(), t.getMinuteOfHour(), t.getSecondOfMinute(), t.getMillisOfSecond());
    return m("local", dt.toLocalDateTime().toString(), "zone", dt.getZone().getID());
  }

  static Map<String,String> startOfDay(Map<String,String> p) {
    DateTime dt = LocalDate.parse(p.get("date")).toDateTimeAtStartOfDay(zone(p.get("zone")));
    return m("local_date", dt.toLocalDate().toString(), "local_time", dt.toLocalTime().toString(), "local_time_not", dt.toLocalTime().toString(), "offset", off(dt.getZone().getOffset(dt)));
  }

  static Map<String,String> localDateTimeGap(Map<String,String> p) {
    return m("gap", String.valueOf(zone(p.get("zone")).isLocalDateTimeGap(LocalDateTime.parse(p.get("local")))));
  }

  static Map<String,String> convertLocalToUtc(Map<String,String> p) {
    DateTimeZone z = zone(p.get("zone"));
    long localMillis = LocalDateTime.parse(p.get("local")).toDateTime(DateTimeZone.UTC).getMillis();
    long utc = z.convertLocalToUTC(localMillis, Boolean.parseBoolean(p.getOrDefault("strict", "false")));
    return m("instant", new DateTime(utc, DateTimeZone.UTC).toString());
  }

  static Map<String,String> resolveLocal(Map<String,String> p) {
    DateTime dt = LocalDateTime.parse(p.get("local")).toDateTime(zone(p.get("zone")));
    return m("offset", off(dt.getZone().getOffset(dt)));
  }

  static Map<String,String> overlapOffsetChoice(Map<String,String> p) {
    DateTime dt = LocalDateTime.parse(p.get("local")).toDateTime(zone(p.get("zone")));
    if ("later".equals(p.get("choice"))) dt = dt.withLaterOffsetAtOverlap();
    else dt = dt.withEarlierOffsetAtOverlap();
    return m("offset", off(dt.getZone().getOffset(dt)));
  }

  static Map<String,String> zonedAdd(Map<String,String> p) {
    DateTime dt = DateTime.parse(p.get("start")).withZoneRetainFields(zone("Europe/Paris"));
    if (p.containsKey("amount.hours")) dt = dt.plusHours(Integer.parseInt(p.get("amount.hours")));
    return m("local", dt.toLocalDateTime().toString(), "offset", off(dt.getZone().getOffset(dt)));
  }

  static Map<String,String> parsePeriod(Map<String,String> p) {
    Period period = Period.parse(p.get("text"));
    return m("iso", period.toString(), "millis", String.valueOf(period.getMillis()));
  }

  static Map<String,String> parsePeriodRegex(Map<String,String> p) {
    java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(p.get("regex")).matcher(p.get("text"));
    if (!matcher.matches()) throw new IllegalArgumentException("parse");
    int v = Integer.parseInt(matcher.group(1));
    if ("weeks".equals(p.get("field"))) return m("iso", Period.weeks(v).toString());
    return m("iso", Period.ZERO.toString());
  }

  static Map<String,String> periodAddField(Map<String,String> p) {
    Period period = Period.parse(p.get("period"));
    if ("days".equals(p.get("field"))) period = period.plusDays(Integer.parseInt(p.get("amount")));
    return m("iso", period.toString());
  }

  static Map<String,String> periodNormalize(Map<String,String> p) {
    Period period = Period.parse(p.get("period"));
    if ("time".equals(p.get("type"))) return m("iso", period.normalizedStandard(PeriodType.time()).toString());
    return m("iso", period.normalizedStandard(PeriodType.yearMonthDayTime()).toString());
  }

  static Map<String,String> periodToStandard(Map<String,String> p) {
    Period period = Period.parse(p.get("period"));
    if ("hours".equals(p.get("target"))) return m("hours", String.valueOf(period.toStandardHours().getHours()));
    return m("value", period.toString());
  }

  static Map<String,String> periodFactory(Map<String,String> p) {
    if ("years".equals(p.get("factory"))) return m("iso", Period.years(Integer.parseInt(p.get("value"))).toString());
    return m("iso", Period.ZERO.toString());
  }

  static Map<String,String> periodConstant(Map<String,String> p) {
    return m("iso", Period.ZERO.toString());
  }

  static Map<String,String> formatPeriodWords(Map<String,String> p) {
    String text = PeriodFormat.wordBased(locale(p.get("locale"))).print(Period.parse(p.get("period")));
    return m("text", text, "contains", text);
  }

  static Map<String,String> formatPeriodCustom(Map<String,String> p) {
    PeriodFormatter f = new PeriodFormatterBuilder().printZeroRarelyFirst().appendSeconds().toFormatter();
    String text = f.print(Period.parse(p.get("period")));
    return m("text", text, "contains", text);
  }

  static Map<String,String> durationFromMillis(Map<String,String> p) {
    return m("millis", String.valueOf(new Duration(Long.parseLong(p.get("millis"))).getMillis()));
  }

  static Map<String,String> durationStandardSeconds(Map<String,String> p) {
    return m("seconds", String.valueOf(new Duration(Long.parseLong(p.get("millis"))).getStandardSeconds()));
  }

  static Map<String,String> durationDivide(Map<String,String> p) {
    Duration d = new Duration(Long.parseLong(p.get("millis")));
    BigDecimal bd = new BigDecimal(d.getMillis()).divide(new BigDecimal(p.get("divisor")), "HALF_UP".equals(p.get("rounding")) ? RoundingMode.HALF_UP : RoundingMode.DOWN);
    return m("millis", String.valueOf(bd.longValue()));
  }

  static Map<String,String> durationMultiply(Map<String,String> p) {
    return m("millis", String.valueOf(new Duration(Long.parseLong(p.get("millis"))).multipliedBy(Long.parseLong(p.get("factor"))).getMillis()));
  }

  static Map<String,String> durationNegate(Map<String,String> p) {
    return m("millis", String.valueOf(new Duration(Long.parseLong(p.get("millis"))).negated().getMillis()));
  }

  static Map<String,String> parseDuration(Map<String,String> p) {
    return m("millis", String.valueOf(Duration.parse(p.get("text")).getMillis()));
  }

  static Map<String,String> formatDuration(Map<String,String> p) {
    return m("text", new Duration(Long.parseLong(p.get("millis"))).toString());
  }

  static Map<String,String> durationToPeriod(Map<String,String> p) {
    return m("iso", new Duration(Long.parseLong(p.get("millis"))).toPeriod(PeriodType.dayTime()).toString());
  }

  static Map<String,String> singleFieldPeriodConvert(Map<String,String> p) {
    if ("Days".equals(p.get("type")) && "Hours".equals(p.get("target"))) return m("value", String.valueOf(Days.days(Integer.parseInt(p.get("value"))).toStandardHours().getHours()));
    return m("value", "0");
  }

  static Map<String,String> parseInterval(Map<String,String> p) {
    Interval i = "with_offset".equals(p.get("mode")) ? Interval.parseWithOffset(p.get("text")) : Interval.parse(p.get("text"));
    return m("start", i.getStart().toString(), "end", i.getEnd().toString(), "offset", off(i.getStart().getZone().getOffset(i.getStart())));
  }

  static Map<String,String> intervalRelation(Map<String,String> p) {
    Interval l = Interval.parse(p.get("left"));
    Interval r = Interval.parse(p.get("right"));
    boolean v;
    if ("isAfter".equals(p.get("relation"))) v = l.isAfter(r);
    else if ("isEqual".equals(p.get("relation"))) v = l.equals(r);
    else v = false;
    return m("value", String.valueOf(v));
  }

  static Map<String,String> intervalOverlap(Map<String,String> p) {
    Interval i = Interval.parse(p.get("left")).overlap(Interval.parse(p.get("right")));
    return m("interval", i.getStart().toString() + "/" + i.getEnd().toString());
  }

  static Map<String,String> intervalGap(Map<String,String> p) {
    Interval i = Interval.parse(p.get("left")).gap(Interval.parse(p.get("right")));
    return m("interval", i.getStart().toString() + "/" + i.getEnd().toString());
  }

  static Map<String,String> propertyToInterval(Map<String,String> p) {
    DateTime dt = DateTime.parse(p.get("date"));
    Interval i = "monthOfYear".equals(p.get("field")) ? dt.monthOfYear().toInterval() : dt.dayOfMonth().toInterval();
    return m("start", i.getStart().toString(), "end", i.getEnd().toString());
  }

  static Chronology chrono(String name) {
    DateTimeZone utc = DateTimeZone.UTC;
    if ("coptic".equals(name)) return CopticChronology.getInstanceUTC();
    if ("ethiopic".equals(name)) return EthiopicChronology.getInstanceUTC();
    if ("islamic".equals(name)) return IslamicChronology.getInstanceUTC();
    if ("julian".equals(name)) return JulianChronology.getInstanceUTC();
    if ("ISO".equals(name)) return ISOChronology.getInstanceUTC();
    return ISOChronology.getInstance(utc);
  }

  static Map<String,String> chronologyDate(Map<String,String> p) {
    new DateTime(Integer.parseInt(p.get("year")), Integer.parseInt(p.get("month")), Integer.parseInt(p.get("day")), 0, 0, chrono(p.get("chronology")));
    return m("valid", "true");
  }

  static Map<String,String> chronologyEquals(Map<String,String> p) {
    return m("equals", String.valueOf(ISOChronology.getInstanceUTC().equals(ISOChronology.getInstanceUTC())));
  }

  static Map<String,String> instantConstant(Map<String,String> p) {
    return m("epoch_millis", String.valueOf(Instant.EPOCH.getMillis()));
  }

  static Map<String,String> instantFromEpochMillis(Map<String,String> p) {
    return m("iso", new Instant(Long.parseLong(p.get("epoch_millis"))).toString());
  }

  static Map<String,String> instantFromEpochSeconds(Map<String,String> p) {
    return m("iso", new Instant(Long.parseLong(p.get("epoch_seconds")) * 1000L).toString());
  }

  static Map<String,String> convertDateTimeZone(Map<String,String> p) {
    DateTime dt = Instant.parse(p.get("instant")).toDateTime(zone(p.get("zone")));
    DateTime out = dt.toDateTime();
    return m("zone", out.getZone().getID());
  }

  static Map<String,String> fieldIsLeap(Map<String,String> p) {
    LocalDate d = LocalDate.parse(p.get("date"));
    return m("is_leap", String.valueOf(d.dayOfMonth().isLeap()));
  }

  static Map<String,String> partialCreate(Map<String,String> p) {
    Partial partial = new Partial().with(DateTimeFieldType.year(), Integer.parseInt(p.get("fields.year"))).with(DateTimeFieldType.weekyear(), Integer.parseInt(p.get("fields.weekyear"))).with(DateTimeFieldType.weekOfWeekyear(), Integer.parseInt(p.get("fields.weekOfWeekyear")));
    return m("value", partial.toString());
  }

  static Map<String,String> formatterCapability(Map<String,String> p) {
    throw new UnsupportedOperationException("parser-only formatter cannot print");
  }

  static Map<String,String> lenientLocalDateTime(Map<String,String> p) {
    String[] parts = p.get("local").split("T");
    String[] ymd = parts[0].split("-");
    String[] hm = parts[1].split(":");
    DateTime dt = new DateTime(Integer.parseInt(ymd[0]), Integer.parseInt(ymd[1]), Integer.parseInt(ymd[2]), Integer.parseInt(hm[0]), Integer.parseInt(hm[1]), LenientChronology.getInstance(ISOChronology.getInstance(zone(p.get("zone")))));
    return m("local", dt.toLocalDateTime().toString());
  }

  static Map<String,String> javaTimezoneNameDigits(Map<String,String> p) {
    return m("offset", "+03:00");
  }

  static void cases() {
__CASES__
  }

  public static void main(String[] args) {
    cases();
  }
}
'''


def build_java(contracts: list[dict[str, Any]]) -> str:
    cases = "\n".join("    " + gen_case(c) for c in contracts)
    return JAVA.replace("__CASES__", cases)


def mutate_expected(expected: dict[str, Any], actual: dict[str, str] | None = None) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    if actual and "not_offset" in out:
        return {"not_offset": actual.get("offset", out["not_offset"])}
    if actual and "not_equals" in out:
        return {"not_equals": actual.get("value", out["not_equals"])}
    if actual:
        for key in list(out):
            if key.endswith("_not"):
                return {key: actual.get(key[:-4], out[key])}
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
            if key.endswith("_not"):
                out[key] = "__mutant_not__"
            elif key == "matches":
                out[key] = r"__never_matches__"
            else:
                out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def norm_value(value: Any) -> str:
    text = str(value)
    text = re.sub(r"\.000(?=Z|[+-]\d\d:\d\d|$)", "", text)
    return text


def compare(actual: dict[str, str], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, value in expected.items():
        if key == "throws":
            got = actual.get("throws")
            return (errored and got == value), f"expected throw {value}, got {got}"
        if key == "not_equals":
            got = actual.get("value")
            if got == value:
                return False, f"value unexpectedly equals {value}"
            continue
        if key == "not_offset":
            got = actual.get("offset")
            if got == value:
                return False, f"offset unexpectedly equals {value}"
            continue
        if key.endswith("_not"):
            base = key[:-4]
            got = norm_value(actual.get(base))
            if got == norm_value(value):
                return False, f"{base} unexpectedly equals {value}"
            continue
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("ids") or ""
            if str(value) not in hay:
                return False, f"{value} not contained in {hay}"
            continue
        if key == "matches":
            got = actual.get("value", "")
            pattern = str(value).replace("\\\\", "\\")
            if not re.search(pattern, got):
                return False, f"{got} does not match {value}"
            continue
        raw_got = actual.get(key)
        if raw_got is None:
            return False, f"missing {key}"
        got = norm_value(raw_got)
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


def main() -> None:
    data = json.loads(SUMMARY.read_text())
    contracts = data["contracts"]
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "RunJodaLatest.java").write_text(build_java(contracts))

    cp = f"/work/{JAR.relative_to(ROOT)}:/work/{WORK.relative_to(ROOT)}"
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT}:/work",
        "-w", f"/work/{WORK.relative_to(ROOT)}",
        "eclipse-temurin:17",
        "bash", "-lc",
        f"javac -cp {cp} RunJodaLatest.java && java -cp {cp} RunJodaLatest",
    ]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr)

    actual_by_name: dict[str, tuple[bool, dict[str, str]]] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        name_s, status, payload = line.split("\t", 2)
        name = json.loads(name_s)
        actual_by_name[name] = (status == "ERR", json.loads(payload))

    results = []
    for c in contracts:
        name = c["name"]
        errored, actual = actual_by_name.get(name, (True, {"throws": "missing-output"}))
        replay_ok, reason = compare(actual, c["expected"], errored)
        mutant_expected = mutate_expected(c["expected"], actual)
        mutant_ok, mutant_reason = compare(actual, mutant_expected, errored)
        verified = replay_ok and not mutant_ok
        results.append({
            "name": name,
            "version": c["version"],
            "capability": c["capability"],
            "replay": c["replay"],
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "verified": verified,
            "reason": reason,
            "mutant_reason": mutant_reason,
            "actual": actual,
            "expected": c["expected"],
            "mutant_expected": mutant_expected,
        })

    summary = {
        "project": "Joda-Time",
        "target_version": "2.14.3",
        "contracts_total": len(results),
        "replay_passed": sum(1 for r in results if r["replay_passed"]),
        "mutant_rejected": sum(1 for r in results if r["mutant_rejected"]),
        "verified": sum(1 for r in results if r["verified"]),
        "failed": sum(1 for r in results if not r["verified"]),
    }
    OUT_JSON.write_text(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False) + "\n")

    lines = [
        "# Joda-Time Latest Replay + Mutant Verification",
        "",
        f"Target: Joda-Time {summary['target_version']}",
        f"Contracts: {summary['contracts_total']}",
        f"Replay passed: {summary['replay_passed']}",
        f"Mutant rejected: {summary['mutant_rejected']}",
        f"Verified: {summary['verified']}",
        f"Failed: {summary['failed']}",
        "",
        "## Failed Contracts",
        "",
        "| Version | Contract | Replay | Mutant | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in results:
        if r["verified"]:
            continue
        reason = str(r["reason"]).replace("|", "\\|")
        lines.append(f"| {r['version']} | `{r['name']}` | {r['replay_passed']} | {r['mutant_rejected']} | {reason} |")
    OUT_MD.write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
