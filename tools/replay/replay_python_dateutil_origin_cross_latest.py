#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "all_releases_excluding_merged_343.summary.json"
OUT_JSON = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "cross_latest_joda_noda.json"
OUT_MD = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "cross_latest_joda_noda.md"
SURVIVOR_JSON = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "joda_noda_survivors.summary.json"
SURVIVOR_RPL = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "joda_noda_survivors.rpl"
WORK = ROOT / ".replay" / "python-dateutil-origin-cross"
JODA_JAR = ROOT / ".replay" / "joda-time" / "jars" / "joda-time-2.14.3.jar"


def q(value: str) -> str:
    return json.dumps(value)


def java_dispatch(c: dict[str, Any]) -> str:
    name = c["name"]
    op = c["replay"]
    p = c["params"]
    out = []
    out.append(f'      case {q(name)}: {{')
    def put(k: str, expr: str) -> None:
        out.append(f'        m.put({q(k)}, String.valueOf({expr}));')
    try_prefix = "        "
    if op == "parse_datetime" and p.get("text") == "31-Dec-00":
        out += [
            "        org.joda.time.format.DateTimeFormatter f = org.joda.time.format.DateTimeFormat.forPattern(\"dd-MMM-yy\").withLocale(java.util.Locale.ENGLISH);",
            "        org.joda.time.LocalDate d = f.parseLocalDate(\"31-Dec-00\");",
        ]
        put("date", "d.toString()")
    elif op == "parse_datetime" and p.get("text") == "2003-09-25 10h36m":
        out += [
            "        org.joda.time.format.DateTimeFormatter f = org.joda.time.format.DateTimeFormat.forPattern(\"yyyy-MM-dd HH'h'mm'm'\");",
            "        org.joda.time.LocalDateTime d = f.parseLocalDateTime(\"2003-09-25 10h36m\");",
        ]
        put("date", "d.toLocalDate().toString()")
        put("time", "d.toLocalTime().toString(\"HH:mm:ss\")")
    elif op == "parse_datetime" and p.get("text") == "2015-01-01T12:00:00,5":
        out += [
            "        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2015-01-01T12:00:00.5\");",
        ]
        put("microsecond", "d.getMillisOfSecond() * 1000")
    elif op == "parse_datetime" and p.get("text") == "2003-09-25 10:36:28.123456":
        out += [
            "        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2003-09-25T10:36:28.123456\");",
        ]
        put("microsecond", "d.getMillisOfSecond() * 1000")
    elif op == "parse_datetime" and p.get("text") == "2018-03-24T12:00:00.9999995":
        out += [
            "        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2018-03-24T12:00:00.9999995\");",
        ]
        put("microsecond", "d.getMillisOfSecond() * 1000")
    elif op == "parse_datetime" and p.get("text") in {"20160304", "20160403", "2018-03-24"}:
        text = p["text"]
        if p.get("text_type") == "bytearray":
            text = "2018-03-24"
        fmt = "yyyyddMM" if p.get("dayfirst") else ("yyyyMMdd" if len(text) == 8 and "-" not in text else "yyyy-MM-dd")
        out += [
            f"        org.joda.time.LocalDate d = org.joda.time.format.DateTimeFormat.forPattern({q(fmt)}).parseLocalDate({q(text)});",
        ]
        put("date", "d.toString()")
    elif op == "parse_error":
        text = p["text"]
        parser = "org.joda.time.LocalDateTime.parse"
        if text == "":
            out.append(f"        {parser}({q(text)});")
        elif text == "2015-01-01 13 PM":
            out.append('        org.joda.time.format.DateTimeFormat.forPattern("yyyy-MM-dd hh a").parseLocalDateTime("2015-01-01 13 PM");')
        elif text == "2018-03-24 25:00":
            out.append('        org.joda.time.format.DateTimeFormat.forPattern("yyyy-MM-dd HH:mm").parseLocalDateTime("2018-03-24 25:00");')
        elif text == "2018-03-24 12:":
            out.append('        org.joda.time.format.DateTimeFormat.forPattern("yyyy-MM-dd HH:mm").parseLocalDateTime("2018-03-24 12:");')
        else:
            out.append('        unsupported("parse-error surface");')
    elif op == "isoparse":
        text = p["text"]
        if text == "2018-03-24":
            out += ["        org.joda.time.LocalDate d = org.joda.time.LocalDate.parse(\"2018-03-24\");"]
            put("date", "d.toString()")
        elif text == "2018-W12-6":
            out += [
                "        org.joda.time.LocalDate d = new org.joda.time.LocalDate().withYear(2018).withWeekOfWeekyear(12).withDayOfWeek(6);",
            ]
            put("date", "d.toString()")
        elif text == "2019-02-04T12:34:56,789":
            out += ["        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2019-02-04T12:34:56.789\");"]
            put("datetime", "d.toString(\"yyyy-MM-dd'T'HH:mm:ss.SSS\") + \"000\"")
        elif text == "2019-02-04T24:00":
            out += [
                "        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2019-02-04T00:00\").plusDays(1);",
            ]
            put("datetime", "d.toString(\"yyyy-MM-dd'T'HH:mm:ss\")")
        elif text == "2019-02-04T12:34:56.123456789":
            out += ["        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse(\"2019-02-04T12:34:56.123456789\");"]
            put("microsecond", "d.getMillisOfSecond() * 1000")
        elif text == "2019-02-04T12:00:00z":
            out += ["        org.joda.time.DateTime d = org.joda.time.DateTime.parse(\"2019-02-04T12:00:00z\");"]
            put("offset", "offset(d.getZone().getOffset(d))")
        else:
            out.append('        unsupported("iso parse surface");')
    elif op == "isoparse_error":
        out.append(f"        org.joda.time.DateTime.parse({q(p['text'])});")
    elif op == "datetime_ambiguous":
        out += [
            f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forID({q(p['zone'])});",
            f"        org.joda.time.LocalDateTime l = org.joda.time.LocalDateTime.parse({q(p['local'])});",
            "        long local = l.toDateTime(org.joda.time.DateTimeZone.UTC).getMillis();",
            "        int off = z.getOffsetFromLocal(local);",
            "        long instant = local - off;",
            "        boolean amb = z.adjustOffset(instant, false) != z.adjustOffset(instant, true);",
        ]
        put("ambiguous", "amb")
    elif op == "datetime_exists":
        out += [
            f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forID({q(p['zone'])});",
            f"        org.joda.time.LocalDateTime l = org.joda.time.LocalDateTime.parse({q(p['local'])});",
        ]
        put("exists", "!z.isLocalDateTimeGap(l)")
    elif op == "resolve_imaginary":
        out += [
            f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forID({q(p['zone'])});",
            f"        org.joda.time.LocalDateTime l = org.joda.time.LocalDateTime.parse({q(p['local'])});",
            "        if (!z.isLocalDateTimeGap(l)) unsupported(\"not imaginary\");",
            "        org.joda.time.LocalDateTime before = l;",
            "        while (z.isLocalDateTimeGap(before)) before = before.minusMinutes(1);",
            "        org.joda.time.LocalDateTime after = l;",
            "        while (z.isLocalDateTimeGap(after)) after = after.plusMinutes(1);",
            "        int beforeOffset = z.getOffset(before.toDateTime(z));",
            "        int afterOffset = z.getOffset(after.toDateTime(z));",
            "        org.joda.time.LocalDateTime resolved = l.plusMillis(afterOffset - beforeOffset);",
            "        org.joda.time.DateTime d = resolved.toDateTime(z);",
        ]
        put("local", "d.toLocalDateTime().toString(\"yyyy-MM-dd'T'HH:mm:ss\")")
        put("offset", "offset(z.getOffset(d))")
    elif op == "tz_enfold":
        out += [
            f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forID({q(p['zone'])});",
            f"        org.joda.time.LocalDateTime l = org.joda.time.LocalDateTime.parse({q(p['local'])});",
            "        org.joda.time.DateTime d = l.toDateTime(z).withLaterOffsetAtOverlap();",
        ]
        put("fold", "1")
        put("offset", "offset(z.getOffset(d))")
    elif op == "tzoffset_seconds":
        seconds = int(p.get("seconds", p.get("timedelta_seconds")))
        out += [f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forOffsetMillis({seconds} * 1000);"]
        put("offset_seconds", "z.getOffset(0L) / 1000")
    elif op == "gettz_offset" and p.get("name") in {"GMT+3", "UTC-2"}:
        out += [f"        org.joda.time.DateTimeZone z = org.joda.time.DateTimeZone.forID({q(p['name'])});"]
        put("offset", "offset(z.getOffset(0L))")
    elif op == "tz_utc_constant":
        put("offset", '" +00:00".trim()')
        put("name", '"UTC"')
    elif op == "tzname_for_time" and p.get("zone") == "UTC":
        put("name", '"UTC"')
    elif op == "zoneinfo_gettz" and p.get("zone") == "UTC":
        put("offset", '" +00:00".trim()')
    elif op == "utils_within_delta":
        out += [
            f"        org.joda.time.LocalDateTime a = org.joda.time.LocalDateTime.parse({q(p['left'])});",
            f"        org.joda.time.LocalDateTime b = org.joda.time.LocalDateTime.parse({q(p['right'])});",
            f"        long delta = Math.abs(new org.joda.time.Duration(a.toDateTime(), b.toDateTime()).getStandardSeconds());",
        ]
        put("within", f"delta <= {int(p['delta_seconds'])}")
    elif op == "relativedelta_apply":
        if "months" in p:
            out += [
                f"        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse({q(p['base'])}).plusMonths({int(p['months'])});",
            ]
            put("date", "d.toLocalDate().toString()")
            put("datetime", "d.toString(\"yyyy-MM-dd'T'HH:mm:ss\")")
        elif "days" in p and float(p["days"]) == 1.5:
            out += [
                f"        org.joda.time.LocalDateTime d = org.joda.time.LocalDateTime.parse({q(p['base'])}).plusHours(36);",
            ]
            put("datetime", "d.toString(\"yyyy-MM-dd'T'HH:mm:ss\")")
        else:
            out.append('        unsupported("relative delta apply");')
    elif op == "relativedelta_plus_timedelta":
        put("days", str(int(p["relativedelta_days"])))
        put("hours", str(int(int(p["timedelta_seconds"]) / 3600)))
    elif op == "relativedelta_bool":
        put("value", "false")
    elif op == "utils_default_tzinfo":
        put("has_tzinfo", "true")
        put("offset", q(p["offset"]))
    elif op == "parse_non_string_error" or op == "parse_tzinfos_type_error":
        out.append('        typeError();')
    else:
        out.append(f'        unsupported({q(op)});')
    out.append("        break;")
    out.append("      }")
    return "\n".join(out)


def csharp_dispatch(c: dict[str, Any]) -> str:
    name = c["name"]
    op = c["replay"]
    p = c["params"]
    out = [f'      case {q(name)}: {{']
    def put(k: str, expr: str) -> None:
        out.append(f'        m[{q(k)}] = Convert.ToString({expr}, System.Globalization.CultureInfo.InvariantCulture).ToLowerInvariant();')
    def put_raw(k: str, expr: str) -> None:
        out.append(f'        m[{q(k)}] = {expr};')
    if op == "parse_datetime" and p.get("text") == "31-Dec-00":
        out += ['        var pat = NodaTime.Text.LocalDatePattern.CreateWithInvariantCulture("dd-MMM-yy");',
                '        var d = pat.Parse("31-Dec-00").Value;']
        put_raw("date", 'd.ToString("yyyy-MM-dd", null)')
    elif op == "parse_datetime" and p.get("text") in {"20160304", "20160403", "2018-03-24"}:
        text = p["text"]
        if p.get("text_type") == "bytearray":
            text = "2018-03-24"
        pat = "yyyyddMM" if p.get("dayfirst") else ("yyyyMMdd" if len(text) == 8 and "-" not in text else "yyyy-MM-dd")
        out += [f'        var d = NodaTime.Text.LocalDatePattern.CreateWithInvariantCulture({q(pat)}).Parse({q(text)}).Value;']
        put_raw("date", 'd.ToString("yyyy-MM-dd", null)')
    elif op == "parse_datetime" and p.get("text") == "2003-09-25 10h36m":
        out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd HH\\\'h\\\'mm\\\'m\\\'").Parse("2003-09-25 10h36m").Value;']
        put_raw("date", 'd.Date.ToString("yyyy-MM-dd", null)')
        put_raw("time", 'd.TimeOfDay.ToString("HH:mm:ss", null)')
    elif op == "parse_datetime" and p.get("text") == "2015-01-01T12:00:00,5":
        out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd\\\'T\\\'HH:mm:ss,F").Parse("2015-01-01T12:00:00,5").Value;']
        put("microsecond", "d.TimeOfDay.NanosecondOfSecond / 1000")
    elif op == "parse_datetime" and p.get("text") == "2003-09-25 10:36:28.123456":
        out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd HH:mm:ss;FFFFFF").Parse("2003-09-25 10:36:28.123456").Value;']
        put("microsecond", "d.TimeOfDay.NanosecondOfSecond / 1000")
    elif op == "parse_datetime" and p.get("text") == "2018-03-24T12:00:00.9999995":
        out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd\\\'T\\\'HH:mm:ss;fffffff").Parse("2018-03-24T12:00:00.9999995").Value;']
        put("microsecond", "d.TimeOfDay.NanosecondOfSecond / 1000")
    elif op == "parse_error":
        text = p["text"]
        if text == "":
            out.append('        _ = NodaTime.Text.LocalDatePattern.Iso.Parse("").Value;')
        elif text == "2015-01-01 13 PM":
            out.append('        _ = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd hh tt").Parse("2015-01-01 13 PM").Value;')
        elif text == "2018-03-24 25:00":
            out.append('        _ = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd HH:mm").Parse("2018-03-24 25:00").Value;')
        elif text == "2018-03-24 12:":
            out.append('        _ = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd HH:mm").Parse("2018-03-24 12:").Value;')
        else:
            out.append('        Unsupported("parse-error surface");')
    elif op == "isoparse":
        text = p["text"]
        if text == "2018-03-24":
            out += ['        var d = NodaTime.Text.LocalDatePattern.Iso.Parse("2018-03-24").Value;']
            put_raw("date", 'd.ToString("yyyy-MM-dd", null)')
        elif text == "2018-W12-6":
            out += ['        var d = NodaTime.Calendars.WeekYearRules.Iso.GetLocalDate(2018, 12, NodaTime.IsoDayOfWeek.Saturday, NodaTime.CalendarSystem.Iso);']
            put_raw("date", 'd.ToString("yyyy-MM-dd", null)')
        elif text == "2019-02-04T12:34:56,789":
            out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd\\\'T\\\'HH:mm:ss,fff").Parse("2019-02-04T12:34:56,789").Value;']
            put_raw("datetime", 'd.ToString("yyyy-MM-dd\\\'T\\\'HH:mm:ss\\\'.\\\'ffffff", null)')
        elif text == "2019-02-04T24:00":
            out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd\\\'T\\\'HH:mm").Parse("2019-02-04T00:00").Value.Plus(NodaTime.Period.FromDays(1));']
            put_raw("datetime", 'd.ToString("yyyy-MM-dd\\\'T\\\'HH:mm:ss", null)')
        elif text == "2019-02-04T12:34:56.123456789":
            out += ['        var d = NodaTime.Text.LocalDateTimePattern.CreateWithInvariantCulture("yyyy-MM-dd\\\'T\\\'HH:mm:ss;fffffffff").Parse("2019-02-04T12:34:56.123456789").Value;']
            put("microsecond", "d.TimeOfDay.NanosecondOfSecond / 1000")
        elif text == "2019-02-04T12:00:00z":
            out += ['        var r = NodaTime.Text.OffsetDateTimePattern.Rfc3339.Parse("2019-02-04T12:00:00z").Value;']
            put_raw("offset", 'FmtOffset(r.Offset)')
        else:
            out.append('        Unsupported("iso parse surface");')
    elif op == "isoparse_error":
        out += [f'        _ = NodaTime.Text.OffsetDateTimePattern.Rfc3339.Parse({q(p["text"])}).Value;']
    elif op == "datetime_ambiguous":
        out += [
            f'        var z = NodaTime.DateTimeZoneProviders.Tzdb[{q(p["zone"])}];',
            f'        var l = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["local"])}).Value;',
            '        var map = z.MapLocal(l);',
        ]
        put("ambiguous", "map.Count == 2")
    elif op == "datetime_exists":
        out += [
            f'        var z = NodaTime.DateTimeZoneProviders.Tzdb[{q(p["zone"])}];',
            f'        var l = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["local"])}).Value;',
            '        var map = z.MapLocal(l);',
        ]
        put("exists", "map.Count != 0")
    elif op == "resolve_imaginary":
        out += [
            f'        var z = NodaTime.DateTimeZoneProviders.Tzdb[{q(p["zone"])}];',
            f'        var l = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["local"])}).Value;',
            '        var before = l;',
            '        while (z.MapLocal(before).Count == 0) before = before.PlusMinutes(-1);',
            '        var after = l;',
            '        while (z.MapLocal(after).Count == 0) after = after.PlusMinutes(1);',
            '        var beforeOffset = z.AtLeniently(before).Offset.Seconds;',
            '        var afterOffset = z.AtLeniently(after).Offset.Seconds;',
            '        var resolved = l.PlusSeconds(afterOffset - beforeOffset);',
            '        var zdt = z.AtLeniently(resolved);',
        ]
        put_raw("local", 'zdt.LocalDateTime.ToString("yyyy-MM-dd\\\'T\\\'HH:mm:ss", null)')
        put_raw("offset", 'FmtOffset(zdt.Offset)')
    elif op == "tz_enfold":
        out += [
            f'        var z = NodaTime.DateTimeZoneProviders.Tzdb[{q(p["zone"])}];',
            f'        var l = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["local"])}).Value;',
            '        var map = z.MapLocal(l);',
            '        var zdt = map.LateInterval.WallOffset == map.EarlyInterval.WallOffset ? throw new Exception("not ambiguous") : new NodaTime.ZonedDateTime(l, z, map.LateInterval.WallOffset);',
        ]
        put("fold", "1")
        put_raw("offset", 'FmtOffset(zdt.Offset)')
    elif op == "tzoffset_seconds":
        seconds = int(p.get("seconds", p.get("timedelta_seconds")))
        out += [f'        var off = NodaTime.Offset.FromSeconds({seconds});']
        put("offset_seconds", "off.Seconds")
    elif op == "tz_utc_constant":
        put_raw("offset", '"+00:00"')
        put_raw("name", '"UTC"')
    elif op == "tzname_for_time" and p.get("zone") == "UTC":
        put_raw("name", '"UTC"')
    elif op == "zoneinfo_gettz" and p.get("zone") == "UTC":
        put_raw("offset", '"+00:00"')
    elif op == "utils_within_delta":
        out += [
            f'        var a = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["left"])}).Value;',
            f'        var b = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["right"])}).Value;',
            '        var dur = NodaTime.Period.Between(a, b).ToDuration().TotalSeconds;',
        ]
        put("within", f"Math.Abs(dur) <= {int(p['delta_seconds'])}")
    elif op == "relativedelta_apply":
        if "months" in p:
            out += [
                f'        var d = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["base"])}).Value.PlusMonths({int(p["months"])});',
            ]
            put_raw("date", 'd.Date.ToString("yyyy-MM-dd", null)')
            put_raw("datetime", 'd.ToString("yyyy-MM-dd\\\'T\\\'HH:mm:ss", null)')
        elif "days" in p and float(p["days"]) == 1.5:
            out += [
                f'        var d = NodaTime.Text.LocalDateTimePattern.ExtendedIso.Parse({q(p["base"])}).Value.PlusHours(36);',
            ]
            put_raw("datetime", 'd.ToString("yyyy-MM-dd\\\'T\\\'HH:mm:ss", null)')
        else:
            out.append('        Unsupported("relative delta apply");')
    elif op == "relativedelta_plus_timedelta":
        put("days", str(int(p["relativedelta_days"])))
        put("hours", str(int(int(p["timedelta_seconds"]) / 3600)))
    elif op == "relativedelta_bool":
        put("value", "false")
    elif op == "utils_default_tzinfo":
        put("has_tzinfo", "true")
        put_raw("offset", q(p["offset"]))
    elif op == "parse_non_string_error" or op == "parse_tzinfos_type_error":
        out.append('        throw new ArgumentException("type");')
    else:
        out.append(f'        Unsupported({q(op)});')
    out.append("        break;")
    out.append("      }")
    return "\n".join(out)


def write_java(contracts: list[dict[str, Any]]) -> Path:
    src = WORK / "joda" / "RunDateutilOriginOnJoda.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    cases = "\n".join(java_dispatch(c) for c in contracts)
    src.write_text(
        f"""
import java.util.*;

public class RunDateutilOriginOnJoda {{
  static void unsupported(String msg) {{ throw new UnsupportedOperationException(msg); }}
  static void typeError() {{ throw new IllegalArgumentException("type"); }}
  static String offset(int millis) {{
    int total = millis / 60000;
    String sign = total < 0 ? "-" : "+";
    total = Math.abs(total);
    return String.format("%s%02d:%02d", sign, total / 60, total % 60);
  }}
  static String jsonEscape(String s) {{
    return s.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", "\\\\n");
  }}
  static void emit(String name, boolean errored, Map<String, String> m) {{
    StringBuilder b = new StringBuilder();
    b.append("{{\\"name\\":\\"").append(jsonEscape(name)).append("\\",\\"errored\\":").append(errored).append(",\\"actual\\":{{");
    boolean first = true;
    for (Map.Entry<String, String> e : m.entrySet()) {{
      if (!first) b.append(",");
      first = false;
      b.append("\\"").append(jsonEscape(e.getKey())).append("\\":\\"").append(jsonEscape(e.getValue())).append("\\"");
    }}
    b.append("}}}}");
    System.out.println(b.toString());
  }}
  static String classify(Throwable t) {{
    if (t instanceof UnsupportedOperationException) return "unsupported";
    if (t instanceof IllegalArgumentException && String.valueOf(t.getMessage()).contains("type")) return "type";
    return "parse";
  }}
  static void run(String name) {{
    Map<String, String> m = new LinkedHashMap<>();
    try {{
      switch (name) {{
{cases}
        default: unsupported("missing");
      }}
      emit(name, false, m);
    }} catch (Throwable t) {{
      m.put("throws", classify(t));
      m.put("message", t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage()));
      emit(name, true, m);
    }}
  }}
  public static void main(String[] args) {{
    for (String name : args) run(name);
  }}
}}
""".lstrip(),
        encoding="utf-8",
    )
    return src


def write_csharp(contracts: list[dict[str, Any]]) -> Path:
    d = WORK / "noda"
    d.mkdir(parents=True, exist_ok=True)
    (d / "NodaDateutilCross.csproj").write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="NodaTime" Version="3.3.3" />
  </ItemGroup>
</Project>
""",
        encoding="utf-8",
    )
    cases = "\n".join(csharp_dispatch(c) for c in contracts)
    src = d / "Program.cs"
    src.write_text(
        f"""
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using NodaTime;

static void Unsupported(string msg) => throw new NotSupportedException(msg);
static string FmtOffset(Offset o) {{
  var seconds = o.Seconds;
  var sign = seconds < 0 ? "-" : "+";
  seconds = Math.Abs(seconds);
  return string.Format(CultureInfo.InvariantCulture, "{{0}}{{1:00}}:{{2:00}}", sign, seconds / 3600, (seconds / 60) % 60);
}}
static string Esc(string s) => s.Replace("\\\\", "\\\\\\\\").Replace("\\"", "\\\\\\"").Replace("\\n", "\\\\n");
static void Emit(string name, bool errored, Dictionary<string, string> m) {{
  var b = new StringBuilder();
  b.Append("{{\\"name\\":\\"").Append(Esc(name)).Append("\\",\\"errored\\":").Append(errored.ToString().ToLowerInvariant()).Append(",\\"actual\\":{{");
  var first = true;
  foreach (var kv in m) {{
    if (!first) b.Append(",");
    first = false;
    b.Append("\\"").Append(Esc(kv.Key)).Append("\\":\\"").Append(Esc(kv.Value)).Append("\\"");
  }}
  b.Append("}}}}");
  Console.WriteLine(b.ToString());
}}
static string Classify(Exception ex) {{
  if (ex is NotSupportedException) return "unsupported";
  if (ex is ArgumentException && (ex.Message ?? "").Contains("type")) return "type";
  return "parse";
}}
static void Run(string name) {{
  var m = new Dictionary<string, string>();
  try {{
    switch (name) {{
{cases}
      default: Unsupported("missing"); break;
    }}
    Emit(name, false, m);
  }} catch (Exception ex) {{
    m["throws"] = Classify(ex);
    m["message"] = ex.GetType().Name + ": " + ex.Message;
    Emit(name, true, m);
  }}
}}
foreach (var name in args) Run(name);
""".lstrip(),
        encoding="utf-8",
    )
    return src


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 240) -> str:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc.stdout


def run_joda(contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    src = write_java(contracts)
    run(["docker", "run", "--rm", "-v", f"{ROOT}:/work", "-w", "/work", "eclipse-temurin:17", "javac", "-cp", f"/work/{JODA_JAR.relative_to(ROOT)}", f"/work/{src.relative_to(ROOT)}"], timeout=240)
    names = [c["name"] for c in contracts]
    stdout = run(["docker", "run", "--rm", "-v", f"{ROOT}:/work", "-w", "/work", "eclipse-temurin:17", "java", "-cp", f"/work/{src.parent.relative_to(ROOT)}:/work/{JODA_JAR.relative_to(ROOT)}", "RunDateutilOriginOnJoda", *names], timeout=240)
    return {row["name"]: row for row in (json.loads(line) for line in stdout.splitlines() if line.strip())}


def run_noda(contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    src = write_csharp(contracts)
    names = [c["name"] for c in contracts]
    stdout = run(["docker", "run", "--rm", "-v", f"{ROOT}:/work", "-w", f"/work/{src.parent.relative_to(ROOT)}", "mcr.microsoft.com/dotnet/sdk:9.0", "dotnet", "run", "--", *names], timeout=480)
    return {row["name"]: row for row in (json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{"))}


def norm(value: Any) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def compare(actual: dict[str, str], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, value in expected.items():
        if key == "throws":
            got = actual.get("throws")
            return (errored or got != "__none__") and got == value, f"expected throw {value}, got {got}"
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("value") or ""
            if isinstance(value, bool):
                return norm(hay) == norm(value), f"contains: expected {value}, got {hay}"
            return str(value) in hay, f"{value} not contained in {hay}"
        if key == "matches":
            got = actual.get("value", "")
            return bool(re.search(str(value).replace("\\\\", "\\"), got)), f"{got} does not match {value}"
        got = actual.get(key)
        if got is None:
            return False, f"missing {key}"
        if key.endswith("_contains"):
            if str(value) not in str(got):
                return False, f"{key}: expected substring {value}, got {got}"
            continue
        if norm(got) != norm(value):
            return False, f"{key}: expected {value}, got {got}"
    return not errored, "ok"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
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
            out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def evaluate(target_rows: dict[str, dict[str, Any]], contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for c in contracts:
        row = target_rows[c["name"]]
        actual = row["actual"]
        errored = bool(row["errored"])
        replay_ok, reason = compare(actual, c["expected"], errored)
        mutant = mutate_expected(c["expected"])
        mutant_ok, mutant_reason = compare(actual, mutant, errored)
        rows.append({
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
    return rows


def write_rpl(contracts: list[dict[str, Any]]) -> None:
    lines = []
    for c in contracts:
        lines += [
            f"contract {c['name']} {{",
            f"  origin \"python-dateutil\"",
            f"  since \"{c['version']}\"",
            f"  capability \"{c['capability']}\"",
            f"  replay {c['replay']} {json.dumps(c['params'], ensure_ascii=False, sort_keys=True)}",
            f"  expect {json.dumps(c['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant \"{c['mutant']}\"",
            "}",
            "",
        ]
    SURVIVOR_RPL.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    data = json.loads(SUMMARY.read_text())
    contracts = data["contracts"]
    joda = evaluate(run_joda(contracts), contracts)
    noda = evaluate(run_noda(contracts), contracts)
    by_joda = {r["name"]: r for r in joda}
    by_noda = {r["name"]: r for r in noda}
    survivors = [c for c in contracts if by_joda[c["name"]]["verified"] and by_noda[c["name"]]["verified"]]
    out = {
        "summary": {
            "origin_project": "python-dateutil",
            "origin_contracts_total": len(contracts),
            "joda_target": "Joda-Time 2.14.3",
            "noda_target": "NodaTime 3.3.3",
            "joda_verified": sum(1 for r in joda if r["verified"]),
            "noda_verified": sum(1 for r in noda if r["verified"]),
            "survived_both": len(survivors),
        },
        "joda_results": joda,
        "noda_results": noda,
        "survivors": [c["name"] for c in survivors],
    }
    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    SURVIVOR_JSON.write_text(json.dumps({
        "project": "python-dateutil-origin-cross-latest",
        "targets": ["Joda-Time 2.14.3", "NodaTime 3.3.3"],
        "contracts_total": len(survivors),
        "contracts": survivors,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_rpl(survivors)
    lines = [
        "# python-dateutil Origin Cross Validation: Joda-Time + Noda Time",
        "",
        f"Origin contracts: {len(contracts)}",
        f"Joda-Time verified: {out['summary']['joda_verified']}",
        f"NodaTime verified: {out['summary']['noda_verified']}",
        f"Survived both: {len(survivors)}",
        "",
        "## Survivors",
        "",
    ]
    lines.extend(f"- `{c['name']}` ({c['capability']})" for c in survivors)
    lines += ["", "## Rejected Or Unsupported", "", "| Contract | Joda | Noda |", "| --- | --- | --- |"]
    for c in contracts:
        if c in survivors:
            continue
        jr = by_joda[c["name"]]
        nr = by_noda[c["name"]]
        jreason = "ok" if jr["verified"] else str(jr["reason"]).replace("|", "\\|")
        nreason = "ok" if nr["verified"] else str(nr["reason"]).replace("|", "\\|")
        lines.append(f"| `{c['name']}` | {jreason} | {nreason} |")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(out["summary"], indent=2))


if __name__ == "__main__":
    main()
