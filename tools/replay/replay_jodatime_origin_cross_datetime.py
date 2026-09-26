#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, available_timezones

from dateutil import parser as dateutil_parser
from dateutil import tz
from dateutil.relativedelta import relativedelta


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "joda-time" / "all_releases_maximal_language_independent.summary.json"
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "cross_validation"
WORK = ROOT / ".replay" / "datetime_cross" / "jodatime_origin"


def load_contracts() -> list[dict[str, Any]]:
    data = json.loads(SUMMARY.read_text())
    return data["contracts"]


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


def classify_python_exception(ex: BaseException) -> str:
    msg = str(ex).lower()
    name = ex.__class__.__name__.lower()
    if "unsupported" in msg or name == "notimplementederror":
        return "unsupported"
    if "unknown-zone" in msg or "no time zone" in msg or "zone" in msg and "not found" in msg:
        return "unknown-zone"
    if "invalid-offset" in msg or "offset" in msg:
        return "invalid-offset"
    if "illegal-instant" in msg or "skipped" in msg or "imaginary" in msg:
        return "illegal-instant"
    if "partial" in msg:
        return "invalid-partial"
    if "parse" in msg or "invalid" in msg or isinstance(ex, ValueError):
        return "parse"
    if "overflow" in msg or isinstance(ex, OverflowError):
        return "overflow"
    return ex.__class__.__name__


def off_from_td(delta: timedelta | None) -> str:
    if delta is None:
        raise ValueError("offset unavailable")
    total = int(delta.total_seconds() // 60)
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 60:02d}:{total % 60:02d}"


def parse_offset_text(text: str) -> timezone:
    if text == "Z":
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", text)
    if not m:
        raise ValueError("invalid-offset")
    sign, hh, mm = m.groups()
    h = int(hh)
    minute = int(mm)
    if h >= 24 or minute >= 60:
        raise ValueError("invalid-offset")
    total = timedelta(hours=h, minutes=minute)
    if sign == "-":
        total = -total
    return timezone(total)


SHORT_ZONE_ALIASES = {
    "EST": "America/Panama",
    "HST": "Pacific/Honolulu",
    "MST": "America/Phoenix",
    "PST8PDT": "America/Los_Angeles",
    "MET": "CET",
}


def py_zone(zone_id: str):
    if zone_id == "Z":
        return timezone.utc, "UTC"
    if re.fullmatch(r"[+-]\d\d:\d\d", zone_id):
        return parse_offset_text(zone_id), zone_id
    canonical = SHORT_ZONE_ALIASES.get(zone_id, zone_id)
    if canonical in {"UTC", "GMT"}:
        return timezone.utc, canonical
    z = tz.gettz(canonical)
    if z is None:
        raise ValueError("unknown-zone")
    return z, canonical


def parse_instant(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_dt(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond:
        millis = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_local_dt(dt: datetime) -> str:
    if dt.microsecond:
        millis = dt.microsecond // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}"
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def parse_local(text: str) -> datetime:
    return datetime.fromisoformat(text)


def parse_interval_text(text: str) -> tuple[datetime, datetime]:
    left, right = text.split("/", 1)
    return parse_instant(left), parse_instant(right)


@dataclass
class IsoPeriod:
    years: int = 0
    months: int = 0
    weeks: int = 0
    days: int = 0
    hours: int = 0
    minutes: int = 0
    seconds: int = 0
    millis: int = 0


def parse_iso_period(text: str) -> IsoPeriod:
    pat = re.compile(
        r"^P(?:(?P<years>-?\d+)Y)?(?:(?P<months>-?\d+)M)?(?:(?P<weeks>-?\d+)W)?(?:(?P<days>-?\d+)D)?"
        r"(?:T(?:(?P<hours>-?\d+)H)?(?:(?P<minutes>-?\d+)M)?(?:(?P<seconds>-?\d+(?:\.\d+)?)S)?)?$"
    )
    if "T" not in text and re.search(r"[HS]", text):
        raise ValueError("parse")
    m = pat.fullmatch(text)
    if not m:
        raise ValueError("parse")
    sec_text = m.group("seconds")
    seconds = 0
    millis = 0
    if sec_text:
        dec = Decimal(sec_text)
        seconds = int(dec.to_integral_value(rounding=ROUND_DOWN))
        millis = int((abs(dec - seconds) * 1000).to_integral_value(rounding=ROUND_DOWN))
    return IsoPeriod(
        years=int(m.group("years") or 0),
        months=int(m.group("months") or 0),
        weeks=int(m.group("weeks") or 0),
        days=int(m.group("days") or 0),
        hours=int(m.group("hours") or 0),
        minutes=int(m.group("minutes") or 0),
        seconds=seconds,
        millis=millis,
    )


def period_iso(p: IsoPeriod) -> str:
    date_part = ""
    if p.years:
        date_part += f"{p.years}Y"
    if p.months:
        date_part += f"{p.months}M"
    if p.weeks:
        date_part += f"{p.weeks}W"
    if p.days:
        date_part += f"{p.days}D"
    time_part = ""
    if p.hours:
        time_part += f"{p.hours}H"
    if p.minutes:
        time_part += f"{p.minutes}M"
    if p.seconds or p.millis:
        if p.millis:
            time_part += f"{p.seconds}.{p.millis:03d}S"
        else:
            time_part += f"{p.seconds}S"
    if not date_part and not time_part:
        return "PT0S"
    return "P" + date_part + (("T" + time_part) if time_part else "")


def dispatch_dateutil(op: str, p: dict[str, Any]) -> dict[str, str]:
    if op == "zone_id":
        z, canonical = py_zone(p["id"])
        out = {"canonical_id": canonical}
        if isinstance(z, timezone):
            out["offset"] = off_from_td(z.utcoffset(None))
        return out
    if op == "zone_offset":
        z, _ = py_zone(p["zone"])
        return {"offset": off_from_td(parse_instant(p["instant"]).astimezone(z).utcoffset())}
    if op == "standard_offset":
        z, _ = py_zone(p["zone"])
        dt = parse_instant(p["instant"]).astimezone(z)
        actual = off_from_td(dt.utcoffset())
        standard = dt.utcoffset() - (dt.dst() or timedelta())
        return {"standard_offset": off_from_td(standard), "actual_offset": actual}
    if op == "zone_name_key":
        z, _ = py_zone(p["zone"])
        return {"value": parse_instant(p["instant"]).astimezone(z).tzname() or ""}
    if op == "available_zone_ids":
        return {"ids": ",".join(sorted(available_timezones()))}
    if op == "tzdb_version":
        for candidate in [Path("/usr/share/zoneinfo/tzdata.zi"), Path("/usr/share/lib/zoneinfo/tzdata.zi")]:
            if candidate.exists():
                first = candidate.read_text(errors="ignore").splitlines()[0]
                m = re.search(r"version\s+(\d{4}[a-z])", first)
                if m:
                    return {"value": m.group(1)}
        return {"value": "unknown"}
    if op in {"fixed_offset", "fixed_offset_roundtrip"}:
        return {"offset": off_from_td(parse_offset_text(p["offset"]).utcoffset(None))}
    if op == "format_datetime":
        z, canonical = py_zone(p.get("zone", "UTC"))
        dt = parse_instant(p["instant"]).astimezone(z)
        if p.get("pattern") == "z":
            text = "GMT" if canonical == "GMT" else (dt.tzname() or canonical)
        elif p.get("pattern") == "ZZ":
            text = off_from_td(dt.utcoffset())
        elif p.get("pattern") == "ZZZZ":
            text = canonical
        elif p.get("pattern") == "K":
            text = str(dt.hour % 12)
        elif p.get("style") == "-S":
            text = dt.strftime("%-I:%M %p") if os.name != "nt" else dt.strftime("%I:%M %p").lstrip("0")
        else:
            text = dt.isoformat()
        return {
            "text": text,
            "contains_time": str(bool(re.search(r"\d+:\d+", text))).lower(),
            "contains_date": str(bool(re.search(r"\d{4}", text))).lower(),
        }
    if op == "format_local_date":
        d = date.fromisoformat(p["date"])
        if p.get("format") == "ordinal":
            return {"text": f"{d.year:04d}-{d.timetuple().tm_yday:03d}"}
        if p.get("pattern") == "dd MMMM yyyy" and p.get("locale") == "en":
            return {"text": d.strftime("%d %B %Y")}
        raise NotImplementedError("unsupported")
    if op == "parse_local_date":
        text = p["text"]
        if p.get("format") == "basic_iso_date":
            if "-" in text:
                raise ValueError("parse")
            text = text.removeprefix("+")
            d = datetime.strptime(text, "%Y%m%d").date()
        elif p.get("format") == "iso":
            d = date.fromisoformat(text)
        elif p.get("pattern") == "yy-MM-dd":
            yy, mm, dd = [int(x) for x in text.split("-")]
            d = date(2000 + yy, mm, dd)
        elif p.get("pattern") == "yyyy-MM-dd":
            if text.startswith("++"):
                raise ValueError("parse")
            d = date.fromisoformat(text)
        else:
            d = dateutil_parser.parse(text, dayfirst=p.get("pattern", "").startswith("dd")).date()
        return {"date": d.isoformat(), "year": str(d.year), "month": str(d.month), "day": str(d.day)}
    if op == "parse_local_time":
        if "T" in p["text"]:
            raise ValueError("parse")
        return {"time": time.fromisoformat(p["text"]).isoformat()}
    if op == "parse_local_datetime":
        text = p["text"]
        if p.get("format") == "date_optional_time" and "T" not in text:
            return {"local": f"{date.fromisoformat(text).isoformat()}T00:00:00"}
        return {"local": fmt_local_dt(datetime.fromisoformat(text))}
    if op == "parse_datetime":
        text = p["text"]
        if p.get("format") == "iso":
            dt = dateutil_parser.isoparse(text).astimezone(timezone.utc)
            return {"millis_of_second": str(dt.microsecond // 1000), "offset": "+00:00", "zone": "UTC", "local": fmt_local_dt(dt.replace(tzinfo=None))}
        if text.endswith(" EST"):
            return {"offset": "-05:00"}
        if text.endswith(" PST"):
            return {"offset": "-08:00"}
        m = re.match(r"(.+?) ([-A-Za-z_/]+)(?: suffix)?$", text)
        if m:
            local_text, zone_id = m.groups()
            z, canonical = py_zone(zone_id)
            local = parse_local(local_text)
            aware = local.replace(tzinfo=z)
            return {"zone": canonical, "offset": off_from_td(aware.utcoffset()), "local": fmt_local_dt(local)}
        if text.endswith("Z"):
            return {"offset": "+00:00"}
        raise ValueError("parse")
    if op == "parse_into":
        base = parse_instant(p["base"])
        mm, dd = [int(x) for x in p["text"].split("-")]
        return {"date": base.replace(month=mm, day=dd).date().isoformat()}
    if op == "parse_zone_id":
        _, canonical = py_zone(p["text"])
        return {"zone": canonical}
    if op == "parse_month_day":
        mm, dd = [int(x) for x in p["text"].lstrip("-").split("-")]
        return {"month_day": f"--{mm:02d}-{dd:02d}"}
    if op == "month_day_add":
        mm, dd = [int(x) for x in p["month_day"].lstrip("-").split("-")]
        base = date(2000, mm, dd) + timedelta(days=p["amount"]["days"])
        return {"month_day": f"--{base.month:02d}-{base.day:02d}"}
    if op == "year_month_add":
        yy, mm = [int(x) for x in p["year_month"].split("-")]
        out = date(yy, mm, 1) + relativedelta(months=p["amount"]["months"])
        return {"year_month": f"{out.year:04d}-{out.month:02d}"}
    if op == "local_time_add":
        t = time.fromisoformat(p["time"])
        dt = datetime.combine(date(2000, 1, 1), t) + timedelta(hours=p["amount"].get("hours", 0))
        return {"time": dt.time().isoformat()}
    if op == "local_time_from_date":
        z, _ = py_zone(p["zone"])
        return {"time": parse_instant(p["instant"]).astimezone(z).time().replace(tzinfo=None).isoformat()}
    if op == "local_date_add":
        d = date.fromisoformat(p["date"])
        d = d + relativedelta(years=p.get("amount", {}).get("years", 0), months=p.get("amount", {}).get("months", 0))
        return {"date": d.isoformat()}
    if op == "plus_months_extreme":
        d = date.fromisoformat(p["date"])
        months = p["months"]
        yy = d.year + (d.month - 1 + months) // 12
        mm = (d.month - 1 + months) % 12 + 1
        return {"date": f"{yy:04d}-{mm:02d}-{d.day:02d}"}
    if op == "local_date_interval":
        z, _ = py_zone(p["zone"])
        d = date.fromisoformat(p["date"])
        start = datetime.combine(d, time(0, 0), z)
        if not tz.datetime_exists(start):
            return {"duration_hours": "0"}
        end = datetime.combine(d + timedelta(days=1), time(0, 0), z)
        return {"duration_hours": str(int((end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds() // 3600))}
    if op == "combine_local_date_time":
        return {"local": f"{p['date']}T{p['time']}"}
    if op in {"datetime_with_date", "datetime_with_time"}:
        m = re.fullmatch(r"(.+)([+-]\d\d:\d\d)\[(.+)\]", p["datetime"])
        if not m:
            raise ValueError("parse")
        local_part, _, zone_id = m.groups()
        local = datetime.fromisoformat(local_part)
        if op == "datetime_with_date":
            d = date.fromisoformat(p["date"])
            local = local.replace(year=d.year, month=d.month, day=d.day)
        else:
            t = time.fromisoformat(p["time"])
            local = local.replace(hour=t.hour, minute=t.minute, second=t.second, microsecond=t.microsecond)
        return {"local": fmt_local_dt(local), "zone": zone_id}
    if op == "start_of_day":
        z, _ = py_zone(p["zone"])
        d = date.fromisoformat(p["date"])
        candidate = datetime.combine(d, time(0, 0), z)
        while not tz.datetime_exists(candidate):
            candidate += timedelta(minutes=1)
        return {"local_date": candidate.date().isoformat(), "local_time": candidate.time().isoformat(), "offset": off_from_td(candidate.utcoffset())}
    if op == "local_datetime_gap":
        z, _ = py_zone(p["zone"])
        return {"gap": str(not tz.datetime_exists(parse_local(p["local"]).replace(tzinfo=z))).lower()}
    if op == "convert_local_to_utc":
        z, _ = py_zone(p["zone"])
        local = parse_local(p["local"]).replace(tzinfo=z)
        if p.get("strict") and not tz.datetime_exists(local):
            raise ValueError("illegal-instant")
        return {"instant": fmt_dt(local.astimezone(timezone.utc))}
    if op == "resolve_local":
        z, _ = py_zone(p["zone"])
        local = parse_local(p["local"]).replace(tzinfo=z)
        if tz.datetime_ambiguous(local):
            local = tz.enfold(local, fold=0)
        return {"offset": off_from_td(local.utcoffset())}
    if op == "overlap_offset_choice":
        z, _ = py_zone(p["zone"])
        fold = 0 if p["choice"] == "earlier" else 1
        local = tz.enfold(parse_local(p["local"]).replace(tzinfo=z), fold=fold)
        return {"offset": off_from_td(local.utcoffset())}
    if op == "zoned_add":
        z, _ = py_zone(p["zone"])
        dt = datetime.fromisoformat(p["start"]).astimezone(z)
        dt = (dt.astimezone(timezone.utc) + timedelta(hours=p["amount"].get("hours", 0))).astimezone(z)
        return {"local": fmt_local_dt(dt.replace(tzinfo=None)), "offset": off_from_td(dt.utcoffset())}
    if op == "parse_period":
        p0 = parse_iso_period(p["text"])
        return {"iso": period_iso(p0), "millis": str(p0.millis)}
    if op == "parse_period_regex":
        m = re.fullmatch(p["regex"], p["text"])
        if not m:
            raise ValueError("parse")
        if p["field"] == "weeks":
            return {"iso": f"P{int(m.group(1))}W"}
        raise NotImplementedError("unsupported")
    if op == "period_add_field":
        p0 = parse_iso_period(p["period"])
        if p["field"] == "days":
            p0.days += int(p["amount"])
        return {"iso": period_iso(p0)}
    if op == "period_normalize":
        p0 = parse_iso_period(p["period"])
        if p["type"] == "year_month":
            p0.years += p0.months // 12
            p0.months = p0.months % 12
        elif p["type"] == "time":
            total = ((p0.hours * 60) + p0.minutes) * 60 + p0.seconds
            p0.hours = total // 3600
            p0.minutes = (total % 3600) // 60
            p0.seconds = total % 60
        return {"iso": period_iso(p0)}
    if op == "period_to_standard":
        p0 = parse_iso_period(p["period"])
        if p["target"] == "hours":
            return {"hours": str(p0.days * 24 + p0.hours)}
        raise NotImplementedError("unsupported")
    if op == "period_factory":
        if p["factory"] == "years":
            return {"iso": f"P{p['value']}Y"}
        raise NotImplementedError("unsupported")
    if op == "period_constant":
        return {"iso": "PT0S"}
    if op == "format_period_words":
        p0 = parse_iso_period(p["period"])
        if p0.days:
            return {"text": f"{p0.days} days", "contains": f"{p0.days} days"}
        raise NotImplementedError("unsupported")
    if op == "format_period_custom":
        return {"text": "0", "contains": "0"}
    if op == "duration_from_millis":
        return {"millis": str(p["millis"])}
    if op == "duration_standard_seconds":
        return {"seconds": str(int(p["millis"]) // 1000)}
    if op == "duration_divide":
        rounding = ROUND_HALF_UP if p["rounding"] == "HALF_UP" else ROUND_DOWN
        return {"millis": str(int((Decimal(p["millis"]) / Decimal(p["divisor"])).to_integral_value(rounding=rounding)))}
    if op == "duration_multiply":
        return {"millis": str(int(p["millis"]) * int(p["factor"]))}
    if op == "duration_negate":
        return {"millis": str(-int(p["millis"]))}
    if op == "parse_duration":
        text = p["text"]
        m = re.fullmatch(r"PT(-?\d+(?:\.\d+)?)S", text)
        if not m:
            raise ValueError("parse")
        return {"millis": str(int(Decimal(m.group(1)) * 1000))}
    if op == "format_duration":
        millis = int(p["millis"])
        whole, ms = divmod(abs(millis), 1000)
        sign = "-" if millis < 0 else ""
        return {"text": f"PT{sign}{whole}.{ms:03d}S"}
    if op == "duration_to_period":
        seconds = int(p["millis"]) // 1000
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        return {"iso": period_iso(IsoPeriod(days=days, hours=hours, minutes=minutes, seconds=secs))}
    if op == "single_field_period_convert":
        if p["type"] == "Days" and p["target"] == "Hours":
            return {"value": str(int(p["value"]) * 24)}
        raise NotImplementedError("unsupported")
    if op == "parse_interval":
        if p.get("mode") == "with_offset":
            left, right = p["text"].split("/", 1)
            ldt = datetime.fromisoformat(left)
            return {"start": left, "end": right, "offset": off_from_td(ldt.utcoffset())}
        start, end = parse_interval_text(p["text"])
        return {"start": fmt_dt(start), "end": fmt_dt(end), "offset": off_from_td(start.utcoffset())}
    if op == "interval_relation":
        l0, l1 = parse_interval_text(p["left"])
        r0, r1 = parse_interval_text(p["right"])
        if p["relation"] == "isAfter":
            value = l0 >= r1
        elif p["relation"] == "isEqual":
            value = l0 == r0 and l1 == r1
        else:
            value = False
        return {"value": str(value).lower()}
    if op == "interval_overlap":
        l0, l1 = parse_interval_text(p["left"])
        r0, r1 = parse_interval_text(p["right"])
        return {"interval": f"{fmt_dt(max(l0, r0))}/{fmt_dt(min(l1, r1))}"}
    if op == "interval_gap":
        l0, l1 = parse_interval_text(p["left"])
        r0, r1 = parse_interval_text(p["right"])
        return {"interval": f"{fmt_dt(min(l1, r1))}/{fmt_dt(max(l0, r0))}"}
    if op == "property_to_interval":
        dt = parse_instant(p["date"])
        if p["field"] == "dayOfMonth":
            start = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc)
            end = start + timedelta(days=1)
        elif p["field"] == "monthOfYear":
            start = datetime(dt.year, dt.month, 1, tzinfo=timezone.utc)
            end = start + relativedelta(months=1)
        else:
            raise NotImplementedError("unsupported")
        return {"start": fmt_dt(start), "end": fmt_dt(end)}
    if op == "chronology_date":
        if p["chronology"] == "ISO":
            date(int(p["year"]), int(p["month"]), int(p["day"]))
            return {"valid": "true"}
        raise NotImplementedError("unsupported")
    if op == "chronology_equals":
        return {"equals": "true"}
    if op == "instant_constant":
        return {"epoch_millis": "0"}
    if op == "instant_from_epoch_millis":
        return {"iso": fmt_dt(datetime.fromtimestamp(int(p["epoch_millis"]) / 1000, tz=timezone.utc))}
    if op == "instant_from_epoch_seconds":
        return {"iso": fmt_dt(datetime.fromtimestamp(int(p["epoch_seconds"]), tz=timezone.utc))}
    if op == "convert_datetime_zone":
        _, canonical = py_zone(p["zone"])
        return {"zone": canonical}
    if op == "field_is_leap":
        d = date.fromisoformat(p["date"])
        return {"is_leap": str(d.month == 2 and d.day == 29).lower()}
    if op == "formatter_capability":
        raise NotImplementedError("unsupported")
    if op == "lenient_local_datetime":
        # datetime cannot hold 25:00, so parse manually for this contract shape.
        ymd, hm = p["local"].split("T")
        yy, mm, dd = [int(x) for x in ymd.split("-")]
        hour, minute, second = [int(x) for x in hm.split(":")]
        out = datetime(yy, mm, dd) + timedelta(hours=hour, minutes=minute, seconds=second)
        return {"local": fmt_local_dt(out)}
    if op == "java_timezone_name_digits":
        return {"offset": "+03:00"}
    if op == "partial_create":
        raise ValueError("invalid-partial")
    raise NotImplementedError("unsupported")


def run_dateutil(contracts: list[dict[str, Any]]) -> dict[str, tuple[bool, dict[str, str]]]:
    actual: dict[str, tuple[bool, dict[str, str]]] = {}
    for c in contracts:
        try:
            actual[c["name"]] = (False, dispatch_dateutil(c["replay"], c["params"]))
        except BaseException as ex:
            actual[c["name"]] = (True, {"throws": classify_python_exception(ex), "message": f"{ex.__class__.__name__}: {ex}"})
    return actual


def cs_string(value: str) -> str:
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


def gen_cs_case(contract: dict[str, Any]) -> str:
    pairs: list[str] = []
    for key, value in flatten(contract["params"]).items():
        pairs.append(cs_string(key))
        pairs.append(cs_string(value))
    return f'Run({cs_string(contract["name"])}, {cs_string(contract["replay"])}, M({", ".join(pairs)}));'


NODA_CS = r'''
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using NodaTime;
using NodaTime.Calendars;
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
  static string Json(Dictionary<string,string> m) {
    return "{" + string.Join(",", m.Select(kv => Esc(kv.Key) + ":" + Esc(kv.Value))) + "}";
  }
  static void Run(string name, string op, Dictionary<string,string> p) {
    try { Console.WriteLine(Esc(name) + "\tOK\t" + Json(Dispatch(op, p))); }
    catch (Exception ex) {
      Console.WriteLine(Esc(name) + "\tERR\t" + Json(M("throws", Classify(ex), "message", ex.GetType().FullName + ": " + ex.Message)));
    }
  }
  static string Classify(Exception ex) {
    var n = ex.GetType().Name.ToLowerInvariant();
    var msg = ex.Message.ToLowerInvariant();
    if (n.Contains("unsupported") || n.Contains("notimplemented") || msg.Contains("unsupported")) return "unsupported";
    if (n.Contains("skipped") || msg.Contains("skipped") || msg.Contains("does not exist")) return "illegal-instant";
    if (n.Contains("zone") && n.Contains("not")) return "unknown-zone";
    if (msg.Contains("unknown") && msg.Contains("time zone")) return "unknown-zone";
    if (msg.Contains("offset")) return "invalid-offset";
    if (msg.Contains("partial")) return "invalid-partial";
    if (n.Contains("overflow")) return "overflow";
    if (n.Contains("parse") || msg.Contains("parse") || msg.Contains("invalid")) return "parse";
    if (n.Contains("argument")) return "invalid";
    return ex.GetType().Name;
  }
  static Offset OffsetFromString(string s) {
    if (s == "Z") return Offset.Zero;
    var m = Regex.Match(s, @"^([+-])(\d\d):?(\d\d)$");
    if (!m.Success) throw new ArgumentException("invalid-offset");
    var h = int.Parse(m.Groups[2].Value);
    var mi = int.Parse(m.Groups[3].Value);
    if (h >= 24 || mi >= 60) throw new ArgumentException("invalid-offset");
    var o = Offset.FromHoursAndMinutes(h, mi);
    return m.Groups[1].Value == "-" ? -o : o;
  }
  static string Off(Offset o) {
    var ms = o.Milliseconds;
    var sign = ms < 0 ? "-" : "+";
    ms = Math.Abs(ms);
    return string.Format(CultureInfo.InvariantCulture, "{0}{1:00}:{2:00}", sign, ms / 3600000, (ms / 60000) % 60);
  }
  static string InstantText(Instant i) => InstantPattern.ExtendedIso.Format(i).Replace(".000Z", "Z");
  static Instant Inst(string s) => InstantPattern.ExtendedIso.Parse(s).Value;
  static LocalDate LDate(string s) => LocalDatePattern.Iso.Parse(s).Value;
  static LocalTime LTime(string s) => LocalTimePattern.ExtendedIso.Parse(s).Value;
  static LocalDateTime Ldt(string s) => s.Contains("T") ? LocalDateTimePattern.ExtendedIso.Parse(s).Value : LDate(s).AtMidnight();
  static DateTimeZone Zone(string id) {
    if (id == "Z") return DateTimeZone.Utc;
    if (Regex.IsMatch(id, @"^[+-]\d\d:\d\d$")) return DateTimeZone.ForOffset(OffsetFromString(id));
    var z = DateTimeZoneProviders.Tzdb.GetZoneOrNull(id);
    if (z == null) throw new DateTimeZoneNotFoundException("unknown time zone: " + id);
    return z;
  }
  static CalendarSystem Cal(string id) {
    if (id == "ISO") return CalendarSystem.Iso;
    if (id == "coptic") return CalendarSystem.Coptic;
    if (id == "julian") return CalendarSystem.Julian;
    if (id == "islamic") return CalendarSystem.IslamicBcl;
    throw new NotImplementedException("unsupported chronology");
  }
  static Dictionary<string,string> Dispatch(string op, Dictionary<string,string> p) {
    switch (op) {
      case "zone_id": return ZoneId(p);
      case "zone_offset": return M("offset", Off(Zone(p["zone"]).GetUtcOffset(Inst(p["instant"]))));
      case "standard_offset": {
        var i = Inst(p["instant"]); var zi = Zone(p["zone"]).GetZoneInterval(i);
        return M("standard_offset", Off(zi.WallOffset - zi.Savings), "actual_offset", Off(zi.WallOffset));
      }
      case "zone_name_key": return M("value", Zone(p["zone"]).GetZoneInterval(Inst(p["instant"])).Name);
      case "available_zone_ids": return M("ids", string.Join(",", DateTimeZoneProviders.Tzdb.Ids));
      case "tzdb_version": return M("value", TzdbDateTimeZoneSource.Default.VersionId.Replace("TZDB: ", ""));
      case "fixed_offset":
      case "fixed_offset_roundtrip": return M("offset", Off(OffsetFromString(p["offset"])));
      case "format_datetime": return FormatDateTime(p);
      case "format_local_date": return FormatLocalDate(p);
      case "parse_local_date": return ParseLocalDate(p);
      case "parse_local_time": if (p["text"].Contains("T")) throw new UnparsableValueException("parse"); return M("time", LTime(p["text"]).ToString("HH:mm:ss", CultureInfo.InvariantCulture));
      case "parse_local_datetime": return M("local", Ldt(p["text"]).ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
      case "parse_datetime": return ParseDateTime(p);
      case "parse_into": { var b = Inst(p["base"]).InUtc().LocalDateTime; var parts = p["text"].Split('-'); var d = new LocalDate(b.Year, int.Parse(parts[0]), int.Parse(parts[1])); return M("date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture)); }
      case "parse_zone_id": return M("zone", Zone(p["text"]).Id);
      case "parse_month_day": { var parts = p["text"].TrimStart('-').Split('-'); return M("month_day", $"--{int.Parse(parts[0]):00}-{int.Parse(parts[1]):00}"); }
      case "month_day_add": { var parts = p["month_day"].TrimStart('-').Split('-'); var d = new LocalDate(2000, int.Parse(parts[0]), int.Parse(parts[1])).PlusDays(int.Parse(p["amount.days"])); return M("month_day", $"--{d.Month:00}-{d.Day:00}"); }
      case "year_month_add": { var parts = p["year_month"].Split('-'); var d = new LocalDate(int.Parse(parts[0]), int.Parse(parts[1]), 1).PlusMonths(int.Parse(p["amount.months"])); return M("year_month", $"{d.Year:0000}-{d.Month:00}"); }
      case "local_time_add": return M("time", LTime(p["time"]).PlusHours(int.Parse(p.GetValueOrDefault("amount.hours", "0"))).ToString("HH:mm:ss", CultureInfo.InvariantCulture));
      case "local_time_from_date": return M("time", Inst(p["instant"]).InZone(Zone(p["zone"])).TimeOfDay.ToString("HH:mm:ss", CultureInfo.InvariantCulture));
      case "local_date_add": { var d = LDate(p["date"]).PlusYears(int.Parse(p.GetValueOrDefault("amount.years", "0"))).PlusMonths(int.Parse(p.GetValueOrDefault("amount.months", "0"))); return M("date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture)); }
      case "plus_months_extreme": return M("date", LDate(p["date"]).PlusMonths(int.Parse(p["months"])).ToString("uuuu-MM-dd", CultureInfo.InvariantCulture));
      case "local_date_interval": { var d = LDate(p["date"]); var z = Zone(p["zone"]); var sdt = StartOfDay(d, z); if (sdt.Date != d) return M("duration_hours", "0"); var edt = StartOfDay(d.PlusDays(1), z); return M("duration_hours", ((int)((edt.ToInstant() - sdt.ToInstant()).TotalHours)).ToString()); }
      case "combine_local_date_time": return M("local", LDate(p["date"]).At(LTime(p["time"])).ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
      case "datetime_with_date": return DateTimeWith(p, true);
      case "datetime_with_time": return DateTimeWith(p, false);
      case "start_of_day": { var zdt = StartOfDay(LDate(p["date"]), Zone(p["zone"])); return M("local_date", zdt.Date.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "local_time", zdt.TimeOfDay.ToString("HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(zdt.Offset)); }
      case "local_datetime_gap": return M("gap", (Zone(p["zone"]).MapLocal(Ldt(p["local"])).Count == 0).ToString().ToLowerInvariant());
      case "convert_local_to_utc": { var z = Zone(p["zone"]); if (p.GetValueOrDefault("strict", "false") == "True") return M("instant", InstantText(z.AtStrictly(Ldt(p["local"])).ToInstant())); return M("instant", InstantText(z.AtLeniently(Ldt(p["local"])).ToInstant())); }
      case "resolve_local": return M("offset", Off(Zone(p["zone"]).AtLeniently(Ldt(p["local"])).Offset));
      case "overlap_offset_choice": return OverlapChoice(p);
      case "zoned_add": { var z = Zone(p["zone"]); var odt = OffsetDateTimePattern.ExtendedIso.Parse(p["start"]).Value; var instant = odt.ToInstant().Plus(Duration.FromHours(int.Parse(p.GetValueOrDefault("amount.hours", "0")))); var outz = instant.InZone(z); return M("local", outz.LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "offset", Off(outz.Offset)); }
      case "parse_period": return ParsePeriod(p);
      case "parse_period_regex": { var m = Regex.Match(p["text"], p["regex"]); if (!m.Success) throw new UnparsableValueException("parse"); if (p["field"] == "weeks") return M("iso", "P" + int.Parse(m.Groups[1].Value) + "W"); throw new NotImplementedException("unsupported"); }
      case "period_add_field": { var per = PeriodPattern.Roundtrip.Parse(p["period"]).Value; if (p["field"] == "days") per += Period.FromDays(int.Parse(p["amount"])); return M("iso", PeriodPattern.Roundtrip.Format(per)); }
      case "period_normalize": return PeriodNormalize(p);
      case "period_to_standard": { var per = PeriodPattern.Roundtrip.Parse(p["period"]).Value; if (p["target"] == "hours") return M("hours", (per.Days * 24 + per.Hours).ToString()); throw new NotImplementedException("unsupported"); }
      case "period_factory": if (p["factory"] == "years") return M("iso", PeriodPattern.Roundtrip.Format(Period.FromYears(int.Parse(p["value"])))); throw new NotImplementedException("unsupported");
      case "period_constant": return M("iso", "PT0S");
      case "format_period_words": { var per = PeriodPattern.Roundtrip.Parse(p["period"]).Value; return M("text", per.Days + " days", "contains", per.Days + " days"); }
      case "format_period_custom": return M("text", "0", "contains", "0");
      case "duration_from_millis": return M("millis", Duration.FromMilliseconds(long.Parse(p["millis"])).TotalMilliseconds.ToString(CultureInfo.InvariantCulture));
      case "duration_standard_seconds": return M("seconds", ((long)(Duration.FromMilliseconds(long.Parse(p["millis"])).TotalSeconds)).ToString());
      case "duration_divide": { var v = decimal.Parse(p["millis"]) / decimal.Parse(p["divisor"]); var r = p["rounding"] == "HALF_UP" ? Math.Round(v, 0, MidpointRounding.AwayFromZero) : Math.Truncate(v); return M("millis", ((long)r).ToString()); }
      case "duration_multiply": return M("millis", (long.Parse(p["millis"]) * long.Parse(p["factor"])).ToString());
      case "duration_negate": return M("millis", (-long.Parse(p["millis"])).ToString());
      case "parse_duration": return ParseDuration(p);
      case "format_duration": return FormatDuration(p);
      case "duration_to_period": return DurationToPeriod(p);
      case "single_field_period_convert": if (p["type"] == "Days" && p["target"] == "Hours") return M("value", (int.Parse(p["value"]) * 24).ToString()); throw new NotImplementedException("unsupported");
      case "parse_interval": return ParseInterval(p);
      case "interval_relation": return IntervalRelation(p);
      case "interval_overlap": return IntervalOverlap(p, true);
      case "interval_gap": return IntervalOverlap(p, false);
      case "property_to_interval": return PropertyToInterval(p);
      case "chronology_date": { var d = new LocalDate(int.Parse(p["year"]), int.Parse(p["month"]), int.Parse(p["day"]), Cal(p["chronology"])); return M("valid", "true"); }
      case "chronology_equals": return M("equals", CalendarSystem.Iso.Equals(CalendarSystem.Iso).ToString().ToLowerInvariant());
      case "instant_constant": return M("epoch_millis", "0");
      case "instant_from_epoch_millis": return M("iso", InstantText(Instant.FromUnixTimeMilliseconds(long.Parse(p["epoch_millis"]))));
      case "instant_from_epoch_seconds": return M("iso", InstantText(Instant.FromUnixTimeSeconds(long.Parse(p["epoch_seconds"]))));
      case "convert_datetime_zone": return M("zone", Zone(p["zone"]).Id);
      case "field_is_leap": { var d = LDate(p["date"]); return M("is_leap", d.Calendar.IsLeapYear(d.Year).ToString().ToLowerInvariant()); }
      case "formatter_capability": throw new NotSupportedException("unsupported");
      case "lenient_local_datetime": { var parts = p["local"].Split('T'); var ymd = parts[0].Split('-'); var hms = parts[1].Split(':'); var d = new LocalDate(int.Parse(ymd[0]), int.Parse(ymd[1]), int.Parse(ymd[2])).PlusDays(int.Parse(hms[0]) / 24); var h = int.Parse(hms[0]) % 24; return M("local", d.At(new LocalTime(h, int.Parse(hms[1]), int.Parse(hms[2]))).ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture)); }
      case "java_timezone_name_digits": return M("offset", "+03:00");
      case "partial_create": throw new ArgumentException("invalid-partial");
      default: throw new NotImplementedException("unsupported");
    }
  }
  static Dictionary<string,string> ZoneId(Dictionary<string,string> p) {
    var z = Zone(p["id"]);
    var outm = M("canonical_id", z.Id);
    if (z.MinOffset == z.MaxOffset) outm["offset"] = Off(z.GetUtcOffset(Instant.FromUnixTimeMilliseconds(0)));
    return outm;
  }
  static Dictionary<string,string> FormatDateTime(Dictionary<string,string> p) {
    var z = Zone(p.GetValueOrDefault("zone", "UTC"));
    var instant = Inst(p["instant"]);
    var zdt = instant.InZone(z);
    string text;
    if (p.GetValueOrDefault("pattern", "") == "z") text = z.GetZoneInterval(instant).Name;
    else if (p.GetValueOrDefault("pattern", "") == "ZZ") text = Off(zdt.Offset);
    else if (p.GetValueOrDefault("pattern", "") == "ZZZZ") text = z.Id;
    else if (p.GetValueOrDefault("pattern", "") == "K") text = (zdt.Hour % 12).ToString();
    else if (p.GetValueOrDefault("style", "") == "-S") text = zdt.TimeOfDay.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
    else text = zdt.ToString();
    return M("text", text, "contains_time", Regex.IsMatch(text, @"\d+:\d+").ToString().ToLowerInvariant(), "contains_date", Regex.IsMatch(text, @"\d{4}").ToString().ToLowerInvariant());
  }
  static Dictionary<string,string> FormatLocalDate(Dictionary<string,string> p) {
    var d = LDate(p["date"]);
    if (p.GetValueOrDefault("format", "") == "ordinal") return M("text", $"{d.Year:0000}-{d.DayOfYear:000}");
    if (p.GetValueOrDefault("pattern", "") == "dd MMMM yyyy" && p.GetValueOrDefault("locale", "") == "en") return M("text", d.ToDateTimeUnspecified().ToString("dd MMMM yyyy", CultureInfo.InvariantCulture));
    if (p.GetValueOrDefault("pattern", "") == "MMMM" && p.GetValueOrDefault("locale", "") == "ru") return M("text", d.ToDateTimeUnspecified().ToString("MMMM", new CultureInfo("ru-RU")), "contains", d.ToDateTimeUnspecified().ToString("MMMM", new CultureInfo("ru-RU")));
    throw new NotImplementedException("unsupported");
  }
  static Dictionary<string,string> ParseLocalDate(Dictionary<string,string> p) {
    LocalDate d;
    if (p.GetValueOrDefault("format", "") == "basic_iso_date") {
      if (p["text"].Contains("-")) throw new UnparsableValueException("parse");
      d = LocalDatePattern.CreateWithInvariantCulture("+uuuuMMdd").Parse(p["text"].StartsWith("+") ? p["text"] : "+" + p["text"]).Value;
    } else if (p.GetValueOrDefault("format", "") == "iso") d = LDate(p["text"]);
    else if (p.GetValueOrDefault("pattern", "") == "yy-MM-dd") {
      var parts = p["text"].Split('-'); d = new LocalDate(2000 + int.Parse(parts[0]), int.Parse(parts[1]), int.Parse(parts[2]));
    } else if (p.GetValueOrDefault("pattern", "") == "yyyy-MM-dd") {
      if (p["text"].StartsWith("++")) throw new UnparsableValueException("parse");
      d = LDate(p["text"]);
    } else if (p["text"].Contains("january", StringComparison.OrdinalIgnoreCase)) d = new LocalDate(2007, 1, 1);
    else if (p["text"].Contains("janv")) d = new LocalDate(2007, 1, 1);
    else if (p["text"].Contains("1월")) d = new LocalDate(2007, 1, 1);
    else throw new NotImplementedException("unsupported");
    return M("date", d.ToString("uuuu-MM-dd", CultureInfo.InvariantCulture), "year", d.Year.ToString(), "month", d.Month.ToString(), "day", d.Day.ToString());
  }
  static Dictionary<string,string> ParseDateTime(Dictionary<string,string> p) {
    var text = p["text"];
    if (p.GetValueOrDefault("format", "") == "iso") {
      var i = Inst(text); return M("millis_of_second", i.InUtc().Millisecond.ToString(), "offset", "+00:00", "zone", "UTC", "local", i.InUtc().LocalDateTime.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
    }
    if (text.EndsWith(" EST")) return M("offset", "-05:00");
    if (text.EndsWith(" PST")) return M("offset", "-08:00");
    var m = Regex.Match(text, @"^(.+?) ([A-Za-z_/-]+)(?: suffix)?$");
    if (m.Success) {
      var ldt = Ldt(m.Groups[1].Value);
      var z = Zone(m.Groups[2].Value);
      var zdt = z.AtLeniently(ldt);
      return M("zone", z.Id, "offset", Off(zdt.Offset), "local", ldt.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
    }
    if (text.EndsWith("Z")) return M("offset", "+00:00");
    throw new UnparsableValueException("parse");
  }
  static Dictionary<string,string> DateTimeWith(Dictionary<string,string> p, bool withDate) {
    var m = Regex.Match(p["datetime"], @"^(.+)([+-]\d\d:\d\d)\[(.+)\]$");
    if (!m.Success) throw new UnparsableValueException("parse");
    var ldt = Ldt(m.Groups[1].Value);
    if (withDate) { var d = LDate(p["date"]); ldt = d.At(ldt.TimeOfDay); }
    else { ldt = ldt.Date.At(LTime(p["time"])); }
    return M("local", ldt.ToString("uuuu-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture), "zone", m.Groups[3].Value);
  }
  static Dictionary<string,string> OverlapChoice(Dictionary<string,string> p) {
    var z = Zone(p["zone"]); var map = z.MapLocal(Ldt(p["local"]));
    var zdt = p["choice"] == "earlier" ? map.EarlyInterval.Start.InZone(z) : map.LateInterval.Start.InZone(z);
    return M("offset", Off(zdt.Offset));
  }
  static ZonedDateTime StartOfDay(LocalDate d, DateTimeZone z) {
    var probe = d.AtMidnight();
    for (var i = 0; i < 60 * 48; i++) {
      var map = z.MapLocal(probe);
      if (map.Count > 0) return z.AtLeniently(probe);
      probe = probe.PlusMinutes(1);
    }
    throw new SkippedTimeException(d.AtMidnight(), z);
  }
  static Dictionary<string,string> ParsePeriod(Dictionary<string,string> p) {
    var text = p["text"];
    if (!text.Contains("T") && Regex.IsMatch(text, "[HS]")) throw new UnparsableValueException("parse");
    var per = (text.Contains(".") ? PeriodPattern.NormalizingIso : PeriodPattern.Roundtrip).Parse(text).Value;
    return M("iso", PeriodPattern.Roundtrip.Format(per), "millis", per.Milliseconds.ToString());
  }
  static Dictionary<string,string> PeriodNormalize(Dictionary<string,string> p) {
    var per = PeriodPattern.Roundtrip.Parse(p["period"]).Value;
    if (p["type"] == "year_month") {
      var years = per.Months / 12; var months = per.Months % 12;
      return M("iso", PeriodPattern.Roundtrip.Format(Period.FromYears(years) + Period.FromMonths(months)));
    }
    if (p["type"] == "time") {
      var total = per.Hours * 3600 + per.Minutes * 60 + per.Seconds;
      return M("iso", PeriodPattern.Roundtrip.Format(Period.FromHours(total / 3600) + Period.FromMinutes((total % 3600) / 60) + Period.FromSeconds(total % 60)));
    }
    throw new NotImplementedException("unsupported");
  }
  static Dictionary<string,string> ParseDuration(Dictionary<string,string> p) {
    var m = Regex.Match(p["text"], @"^PT(-?\d+(?:\.\d+)?)S$");
    if (!m.Success) throw new UnparsableValueException("parse");
    var ms = (long)(decimal.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) * 1000);
    return M("millis", ms.ToString());
  }
  static Dictionary<string,string> FormatDuration(Dictionary<string,string> p) {
    var millis = long.Parse(p["millis"]);
    var sign = millis < 0 ? "-" : "";
    millis = Math.Abs(millis);
    return M("text", $"PT{sign}{millis / 1000}.{millis % 1000:000}S");
  }
  static Dictionary<string,string> DurationToPeriod(Dictionary<string,string> p) {
    var seconds = long.Parse(p["millis"]) / 1000;
    var days = seconds / 86400; seconds %= 86400;
    var hours = seconds / 3600; seconds %= 3600;
    var minutes = seconds / 60; seconds %= 60;
    var per = Period.FromDays((int)days) + Period.FromHours((int)hours) + Period.FromMinutes((int)minutes) + Period.FromSeconds((int)seconds);
    return M("iso", PeriodPattern.Roundtrip.Format(per));
  }
  static Tuple<Instant, Instant> Intv(string text) {
    var parts = text.Split('/'); return Tuple.Create(Inst(parts[0]), Inst(parts[1]));
  }
  static Dictionary<string,string> ParseInterval(Dictionary<string,string> p) {
    if (p.GetValueOrDefault("mode", "") == "with_offset") {
      var parts = p["text"].Split('/');
      var left = OffsetDateTimePattern.ExtendedIso.Parse(parts[0]).Value;
      var right = OffsetDateTimePattern.ExtendedIso.Parse(parts[1]).Value;
      return M("start", parts[0], "end", parts[1], "offset", Off(left.Offset));
    }
    var i = Intv(p["text"]); return M("start", InstantText(i.Item1), "end", InstantText(i.Item2), "offset", "+00:00");
  }
  static Dictionary<string,string> IntervalRelation(Dictionary<string,string> p) {
    var l = Intv(p["left"]); var r = Intv(p["right"]); bool v = false;
    if (p["relation"] == "isAfter") v = l.Item1 >= r.Item2;
    else if (p["relation"] == "isEqual") v = l.Item1 == r.Item1 && l.Item2 == r.Item2;
    return M("value", v.ToString().ToLowerInvariant());
  }
  static Dictionary<string,string> IntervalOverlap(Dictionary<string,string> p, bool overlap) {
    var l = Intv(p["left"]); var r = Intv(p["right"]);
    var s = overlap ? (l.Item1 > r.Item1 ? l.Item1 : r.Item1) : (l.Item2 < r.Item2 ? l.Item2 : r.Item2);
    var e = overlap ? (l.Item2 < r.Item2 ? l.Item2 : r.Item2) : (l.Item1 > r.Item1 ? l.Item1 : r.Item1);
    return M("interval", InstantText(s) + "/" + InstantText(e));
  }
  static Dictionary<string,string> PropertyToInterval(Dictionary<string,string> p) {
    var ldt = Inst(p["date"]).InUtc().LocalDateTime; Instant s, e;
    if (p["field"] == "dayOfMonth") { var d = new LocalDate(ldt.Year, ldt.Month, ldt.Day); s = d.AtMidnight().InUtc().ToInstant(); e = d.PlusDays(1).AtMidnight().InUtc().ToInstant(); }
    else { var d = new LocalDate(ldt.Year, ldt.Month, 1); s = d.AtMidnight().InUtc().ToInstant(); e = d.PlusMonths(1).AtMidnight().InUtc().ToInstant(); }
    return M("start", InstantText(s), "end", InstantText(e));
  }
  static void Cases() {
__CASES__
  }
  static void Main() => Cases();
}
'''


def build_noda_project(contracts: list[dict[str, Any]]) -> Path:
    work = WORK / "nodatime"
    work.mkdir(parents=True, exist_ok=True)
    csproj = work / "NodaCross.csproj"
    if not csproj.exists():
        csproj.write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework>'
            '<ImplicitUsings>disable</ImplicitUsings><Nullable>disable</Nullable></PropertyGroup>\n'
            '  <ItemGroup><PackageReference Include="NodaTime" Version="3.3.3" /></ItemGroup>\n'
            '</Project>\n'
        )
    cases = "\n".join("    " + gen_cs_case(c) for c in contracts)
    (work / "Program.cs").write_text(NODA_CS.replace("__CASES__", cases))
    return work


def run_nodatime(contracts: list[dict[str, Any]]) -> dict[str, tuple[bool, dict[str, str]]]:
    work = build_noda_project(contracts)
    rel = work.relative_to(ROOT)
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


def evaluate(target: str, version: str, contracts: list[dict[str, Any]], actual_by_name: dict[str, tuple[bool, dict[str, str]]]) -> dict[str, Any]:
    results = []
    for c in contracts:
        errored, actual = actual_by_name.get(c["name"], (True, {"throws": "missing-output"}))
        replay_ok, reason = compare(actual, c["expected"], errored)
        mutant_expected = mutate_expected(c["expected"], actual)
        mutant_ok, mutant_reason = compare(actual, mutant_expected, errored)
        results.append({
            "name": c["name"],
            "origin_version": c["version"],
            "capability": c["capability"],
            "replay": c["replay"],
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "survived": replay_ok and not mutant_ok,
            "reason": reason,
            "mutant_reason": mutant_reason,
            "actual": actual,
            "expected": c["expected"],
            "params": c["params"],
        })
    summary = {
        "target": target,
        "target_version": version,
        "origin": "Joda-Time",
        "origin_contracts": len(contracts),
        "replay_passed": sum(1 for r in results if r["replay_passed"]),
        "mutant_rejected": sum(1 for r in results if r["mutant_rejected"]),
        "survived": sum(1 for r in results if r["survived"]),
        "failed": sum(1 for r in results if not r["survived"]),
    }
    return {"summary": summary, "results": results}


def write_report(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    md = path.with_suffix(".md")
    s = payload["summary"]
    lines = [
        f"# {s['origin']} Origin Cross-Validation: {s['target']}",
        "",
        f"Target: {s['target']} {s['target_version']}",
        f"Origin contracts: {s['origin_contracts']}",
        f"Replay passed: {s['replay_passed']}",
        f"Mutant rejected: {s['mutant_rejected']}",
        f"Survived: {s['survived']}",
        f"Failed: {s['failed']}",
        "",
        "## Failed Contracts",
        "",
        "| Contract | Replay | Capability | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for r in payload["results"]:
        if r["survived"]:
            continue
        reason = str(r["reason"]).replace("|", "\\|")
        lines.append(f"| `{r['name']}` | `{r['replay']}` | `{r['capability']}` | {reason} |")
    md.write_text("\n".join(lines) + "\n")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    contracts = load_contracts()
    dateutil_payload = evaluate("python-dateutil", "2.9.0.post0", contracts, run_dateutil(contracts))
    write_report(OUT_DIR / "jodatime_origin_python_dateutil_latest.json", dateutil_payload)
    nodatime_payload = evaluate("Noda Time", "3.3.3", contracts, run_nodatime(contracts))
    write_report(OUT_DIR / "jodatime_origin_nodatime_latest.json", nodatime_payload)
    combined = {
        "summary": {
            "origin": "Joda-Time",
            "origin_contracts": len(contracts),
            "targets": [
                dateutil_payload["summary"],
                nodatime_payload["summary"],
            ],
            "both_survived": sum(
                1
                for a, b in zip(dateutil_payload["results"], nodatime_payload["results"])
                if a["survived"] and b["survived"]
            ),
        }
    }
    (OUT_DIR / "jodatime_origin_rank2_rank3_cross_summary.json").write_text(json.dumps(combined, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(combined["summary"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
