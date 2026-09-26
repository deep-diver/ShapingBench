#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import os
import pickle
import re
import warnings
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

import dateutil
from dateutil import easter, parser, rrule, tz, utils
from dateutil.parser import parserinfo
from dateutil.relativedelta import FR, MO, relativedelta
from dateutil.rrule import DAILY, HOURLY, MONTHLY, SECONDLY, WEEKLY, YEARLY, rrule as RRule, rruleset, rrulestr


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "all_releases_excluding_merged_343.summary.json"
OUT_JSON = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "latest_replay_mutant_verified.json"
OUT_MD = ROOT / "contracts" / "datetime_timezone" / "python-dateutil" / "latest_replay_mutant_verified.md"


FREQ = {"DAILY": DAILY, "WEEKLY": WEEKLY, "MONTHLY": MONTHLY, "YEARLY": YEARLY, "SECONDLY": SECONDLY, "HOURLY": HOURLY}
WEEKDAY = {"MO": rrule.MO, "TU": rrule.TU, "WE": rrule.WE, "TH": rrule.TH, "FR": rrule.FR, "SA": rrule.SA, "SU": rrule.SU}


def parse_dt(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def iso_date(dt: datetime | date) -> str:
    return dt.date().isoformat() if isinstance(dt, datetime) else dt.isoformat()


def iso_time(dt: datetime | time) -> str:
    t = dt.time() if isinstance(dt, datetime) else dt
    if t.microsecond:
        return t.isoformat()
    return t.replace(microsecond=0).isoformat()


def iso_datetime(dt: datetime) -> str:
    text = dt.replace(tzinfo=None).isoformat()
    if "." not in text:
        return text
    return text


def off(delta: timedelta | None) -> str:
    if delta is None:
        raise ValueError("missing offset")
    total = int(delta.total_seconds() // 60)
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 60:02d}:{total % 60:02d}"


class FooParserInfo(parserinfo):
    MONTHS = [("Foo", "Foo")]


class GermanParserInfo(parserinfo):
    MONTHS = parserinfo.MONTHS + [("Mär", "Maerz")]


def custom_parserinfo(p: dict[str, Any]) -> parserinfo | None:
    if p.get("parserinfo_month") == "Foo":
        return FooParserInfo()
    if p.get("language") == "de":
        return GermanParserInfo()
    return None


def make_rrule(p: dict[str, Any]) -> RRule:
    kwargs: dict[str, Any] = {"freq": FREQ[p["freq"]]}
    if "dtstart" in p:
        kwargs["dtstart"] = parse_dt(p["dtstart"])
    if "count" in p:
        kwargs["count"] = int(p["count"])
    if "until" in p:
        kwargs["until"] = parse_dt(p["until"])
    if "byyearday" in p:
        kwargs["byyearday"] = int(p["byyearday"])
    if "bysecond" in p:
        kwargs["bysecond"] = list(p["bysecond"])
    if "byweekday" in p:
        kwargs["byweekday"] = WEEKDAY[p["byweekday"]]
    if "wkst" in p:
        kwargs["wkst"] = WEEKDAY[p["wkst"]]
    return RRule(**kwargs)


def make_rruleset(p: dict[str, Any]) -> rruleset:
    rs = rruleset()
    if "rrule" in p:
        rs.rrule(make_rrule(p["rrule"]))
    for value in p.get("rdates", []):
        rs.rdate(parse_dt(value))
    for value in p.get("exdates", []):
        rs.exdate(parse_dt(value))
    return rs


def parse_any(p: dict[str, Any]) -> datetime:
    text: Any = p.get("text", "")
    if p.get("text_type") == "bytearray":
        text = bytearray(str(text), "ascii")
    default = parse_dt(p["default"]) if "default" in p else None
    tzinfos = None
    if p.get("tzinfos_return_none"):
        tzinfos = lambda *args: None
    elif "tzinfos" in p:
        mapping = {}
        for key, value in p["tzinfos"].items():
            mapping[key] = tz.gettz(value)
        tzinfos = mapping
    info = custom_parserinfo(p)
    kwargs: dict[str, Any] = {}
    if default is not None:
        kwargs["default"] = default
    if tzinfos is not None:
        kwargs["tzinfos"] = tzinfos
    if p.get("yearfirst"):
        kwargs["yearfirst"] = True
    if p.get("dayfirst"):
        kwargs["dayfirst"] = True
    if info:
        return parser.parse(text, parserinfo=info, **kwargs)
    return parser.parse(text, **kwargs)


def dispatch(op: str, p: dict[str, Any]) -> dict[str, str]:
    if op == "parse_datetime":
        dt = parse_any(p)
        out = {
            "date": f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}",
            "time": iso_time(dt),
            "datetime": iso_datetime(dt),
            "microsecond": str(dt.microsecond),
            "has_tzinfo": str(dt.tzinfo is not None).lower(),
            "fold": str(getattr(dt, "fold", 0)),
        }
        if dt.tzinfo:
            out["offset"] = off(dt.utcoffset())
        return out
    if op == "parse_error":
        try:
            parse_any(p)
        except Exception as ex:
            return {"throws": "parse", "class": ex.__class__.__name__, "message": str(ex)}
        return {"throws": "__none__"}
    if op == "parse_non_string_error":
        try:
            parser.parse(p["value"])
        except TypeError as ex:
            return {"throws": "type", "message": str(ex)}
        except Exception as ex:
            return {"throws": ex.__class__.__name__, "message": str(ex)}
        return {"throws": "__none__"}
    if op == "parse_tzinfos_type_error":
        try:
            parser.parse(p["text"], tzinfos=object())
        except TypeError as ex:
            return {"throws": "type", "message": str(ex)}
        except Exception as ex:
            return {"throws": ex.__class__.__name__, "message": str(ex)}
        return {"throws": "__none__"}
    if op == "parse_error_type":
        try:
            parser.parse(p["text"])
        except Exception as ex:
            return {"class": ex.__class__.__name__, "is_value_error": str(isinstance(ex, ValueError)).lower()}
        return {"class": "__none__", "is_value_error": "false"}
    if op == "parse_fuzzy_tokens":
        dt, tokens = parser.parse(p["text"], fuzzy_with_tokens=True)
        ignored = "".join(tokens)
        return {"date": dt.date().isoformat(), "ignored": ignored, "ignored_contains": ignored}
    if op == "parse_warning":
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parser.parse(p["text"])
        return {"warning": str(bool(caught)).lower(), "messages": "|".join(str(w.message) for w in caught)}
    if op == "parse_isodate_bytes_error_message_has_no_b_prefix" or op == "isoparse_error_contains":
        text: Any = p["text"]
        if p.get("text_type") == "bytes":
            text = str(text).encode("ascii")
        try:
            parser.isoparse(text)
        except Exception as ex:
            return {"value": str(ex), "contains": str(ex)}
        return {"value": "", "contains": ""}
    if op == "isoparse":
        dt = parser.isoparse(p["text"])
        out = {
            "date": f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}",
            "time": iso_time(dt),
            "datetime": iso_datetime(dt),
            "microsecond": str(dt.microsecond),
        }
        if dt.tzinfo:
            out["offset"] = off(dt.utcoffset())
        return out
    if op == "isoparse_error":
        try:
            parser.isoparse(p["text"])
        except Exception as ex:
            return {"throws": "parse", "message": str(ex)}
        return {"throws": "__none__"}
    if op == "rrule_dates":
        rr = make_rrule(p)
        vals = list(rr)
        out = {"count": str(len(vals)), "dates": ",".join(d.date().isoformat() for d in vals), "times": ",".join(d.time().isoformat() for d in vals)}
        out["has_tzinfo"] = str(bool(vals and vals[0].tzinfo is not None)).lower()
        return out
    if op == "rrule_between":
        vals = list(make_rrule(p).between(parse_dt(p["before"]), parse_dt(p["after"])))
        return {"count": str(len(vals)), "dates": ",".join(d.date().isoformat() for d in vals)}
    if op == "rrule_contains":
        return {"contains": str(parse_dt(p["candidate"]) in make_rrule(p)).lower()}
    if op == "rrule_xafter":
        vals = list(make_rrule(p).xafter(parse_dt(p["after"]), count=int(p["take"])))
        return {"dates": ",".join(d.date().isoformat() for d in vals)}
    if op == "rrule_to_string":
        text = str(make_rrule(p))
        return {"text": text, "contains": text}
    if op == "rrule_replace":
        base = make_rrule(p)
        new = base.replace(count=int(p["new_count"]))
        vals = list(new)
        return {"count": str(len(vals)), "dates": ",".join(d.date().isoformat() for d in vals)}
    if op == "rrule_after":
        d = make_rrule(p).after(parse_dt(p["after"]), inc=bool(p["inc"]))
        return {"date": d.date().isoformat()}
    if op == "rrule_before":
        d = make_rrule(p).before(parse_dt(p["before"]), inc=bool(p["inc"]))
        return {"date": d.date().isoformat()}
    if op == "rruleset_dates":
        vals = list(make_rruleset(p))
        return {"dates": ",".join(d.date().isoformat() for d in vals), "count": str(len(vals))}
    if op == "rrulestr_dates":
        vals = list(rrulestr(p["text"]))
        return {"dates": ",".join(d.date().isoformat() for d in vals), "count": str(len(vals))}
    if op == "rrulestr_error":
        try:
            list(rrulestr(p["text"]))
        except Exception as ex:
            return {"throws": "parse", "message": str(ex)}
        return {"throws": "__none__"}
    if op == "rrule_error":
        try:
            make_rrule(p)
        except Exception as ex:
            return {"throws": "invalid", "message": str(ex)}
        return {"throws": "__none__"}
    if op == "relativedelta_apply":
        base = parse_dt(p["base"])
        kwargs = {k: v for k, v in p.items() if k not in {"base"}}
        dt = base + relativedelta(**kwargs)
        return {"date": dt.date().isoformat(), "datetime": iso_datetime(dt)}
    if op == "relativedelta_weeks":
        rd = relativedelta(weeks=p["weeks"])
        return {"weeks": str(rd.weeks), "days": str(rd.days)}
    if op == "relativedelta_weeks_from_days":
        rd = relativedelta(days=p["days"])
        return {"weeks": str(rd.weeks), "days": str(rd.days)}
    if op == "relativedelta_equal":
        left = relativedelta(**p["left"])
        right = relativedelta(**p["right"])
        return {"equals": str(left == right).lower()}
    if op == "relativedelta_bool":
        return {"value": str(bool(relativedelta())).lower()}
    if op == "relativedelta_abs":
        rd = abs(relativedelta(days=p.get("days", 0), hours=p.get("hours", 0)))
        return {"repr": repr(rd), "repr_contains": repr(rd)}
    if op == "relativedelta_hash_equal":
        return {"same_hash": str(hash(relativedelta(**p["left"])) == hash(relativedelta(**p["right"]))).lower()}
    if op == "relativedelta_plus_timedelta":
        rd = relativedelta(days=p["relativedelta_days"]) + timedelta(seconds=p["timedelta_seconds"])
        return {"days": str(rd.days), "hours": str(rd.hours), "seconds": str(rd.seconds)}
    if op == "weekday_n":
        wd = getattr(rrule, p["weekday"])
        return {"n_is_none": str(wd.n is None).lower()}
    if op == "datetime_ambiguous":
        z = tz.gettz(p["zone"])
        return {"ambiguous": str(tz.datetime_ambiguous(parse_dt(p["local"]), z)).lower()}
    if op == "datetime_exists":
        z = tz.gettz(p["zone"])
        return {"exists": str(tz.datetime_exists(parse_dt(p["local"]), z)).lower()}
    if op == "resolve_imaginary":
        z = tz.gettz(p["zone"])
        resolved = tz.resolve_imaginary(parse_dt(p["local"]).replace(tzinfo=z))
        return {"local": iso_datetime(resolved), "offset": off(resolved.utcoffset())}
    if op == "tz_enfold":
        z = tz.gettz(p["zone"])
        enfolded = tz.enfold(parse_dt(p["local"]).replace(tzinfo=z), fold=1)
        return {"fold": str(getattr(enfolded, "fold", 0)), "offset": off(enfolded.utcoffset())}
    if op == "tzrange_transitions":
        start, end = tz.tzstr(p["spec"]).transitions(int(p["year"]))
        return {"start": start.isoformat(), "end": end.isoformat()}
    if op == "tzoffset_seconds":
        if "timedelta_seconds" in p:
            z = tz.tzoffset("x", timedelta(seconds=p["timedelta_seconds"]))
        else:
            z = tz.tzoffset("x", int(p["seconds"]))
        return {"offset_seconds": str(int(z.utcoffset(None).total_seconds())), "offset": off(z.utcoffset(None))}
    if op == "gettz_offset":
        z = tz.gettz(p["name"])
        return {"offset": off(parse_dt(p["instant"]).replace(tzinfo=z).utcoffset())}
    if op == "gettz_default":
        z = tz.gettz()
        return {"has_tzinfo": str(z is not None).lower()}
    if op == "gettz_named":
        z = tz.gettz(p["name"])
        return {"has_tzinfo": str(z is not None).lower()}
    if op == "tzstr_offset_pair":
        z = tz.tzstr(p["spec"])
        return {
            "winter_offset": off(parse_dt(p["winter"]).replace(tzinfo=z).utcoffset()),
            "summer_offset": off(parse_dt(p["summer"]).replace(tzinfo=z).utcoffset()),
        }
    if op == "tz_pickle_roundtrip":
        z = tz.tzoffset("x", int(p["offset_seconds"]))
        z2 = pickle.loads(pickle.dumps(z))
        return {"offset_seconds": str(int(z2.utcoffset(None).total_seconds()))}
    if op == "zoneinfo_gettz":
        try:
            from dateutil.zoneinfo import gettz as zoneinfo_gettz
            z = zoneinfo_gettz(p["zone"])
        except Exception:
            z = tz.gettz(p["zone"])
        if z is None:
            return {"has_tzinfo": "false"}
        return {"has_tzinfo": "true", "offset": off(datetime(2020, 1, 1, tzinfo=z).utcoffset())}
    if op == "tzname_for_time":
        z = tz.gettz(p["zone"])
        return {"name": z.tzname(time.fromisoformat(p["time"]).replace(tzinfo=z))}
    if op == "tz_utc_constant":
        z = tz.UTC
        return {"offset": off(z.utcoffset(None)), "name": z.tzname(None)}
    if op == "utils_default_tzinfo":
        dt = parse_dt(p["datetime"])
        z = timezone(timedelta(hours=int(p["offset"][1:3])) if p["offset"].startswith("+") else -timedelta(hours=int(p["offset"][1:3])))
        out = utils.default_tzinfo(dt, z)
        return {"has_tzinfo": str(out.tzinfo is not None).lower(), "offset": off(out.utcoffset())}
    if op == "utils_within_delta":
        return {"within": str(utils.within_delta(parse_dt(p["left"]), parse_dt(p["right"]), timedelta(seconds=p["delta_seconds"]))).lower()}
    if op == "easter_date":
        method = {"western": easter.EASTER_WESTERN, "orthodox": easter.EASTER_ORTHODOX}[p["method"]]
        return {"date": easter.easter(int(p["year"]), method).isoformat()}
    if op == "module_version":
        return {"value": dateutil.__version__}
    if op == "lazy_import":
        mod = importlib.import_module("dateutil")
        sub = getattr(mod, p["submodule"])
        z = sub.gettz(p["zone"])
        return {"has_tzinfo": str(z is not None).lower()}
    raise NotImplementedError(op)


def classify(ex: BaseException) -> str:
    if isinstance(ex, TypeError):
        return "type"
    if isinstance(ex, ValueError):
        return "parse"
    return ex.__class__.__name__


def run_contract(c: dict[str, Any]) -> tuple[bool, dict[str, str]]:
    try:
        return False, dispatch(c["replay"], c["params"])
    except Exception as ex:
        return True, {"throws": classify(ex), "message": f"{ex.__class__.__name__}: {ex}"}


def norm(value: Any) -> str:
    return str(value)


def compare(actual: dict[str, str], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, value in expected.items():
        if key == "throws":
            got = actual.get("throws")
            return (errored or got != "__none__") and got == value, f"expected throw {value}, got {got}"
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("value") or ""
            if isinstance(value, bool):
                if str(hay).lower() != str(value).lower():
                    return False, f"contains: expected {value}, got {hay}"
                continue
            if str(value) not in hay:
                return False, f"{value} not contained in {hay}"
            continue
        if key == "not_contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("value") or ""
            if str(value) in hay:
                return False, f"{value} unexpectedly contained in {hay}"
            continue
        if key == "matches":
            got = actual.get("value", "")
            if not re.search(str(value).replace("\\\\", "\\"), got):
                return False, f"{got} does not match {value}"
            continue
        got = actual.get(key)
        if got is None:
            return False, f"missing {key}"
        if key.endswith("_contains"):
            if str(value) not in str(got):
                return False, f"{key}: expected substring {value}, got {got}"
            continue
        if isinstance(value, bool):
            if str(got).lower() != str(value).lower():
                return False, f"{key}: expected {value}, got {got}"
        else:
            if norm(got) != norm(value):
                return False, f"{key}: expected {value}, got {got}"
    return not errored, "ok"


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
            out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def main() -> None:
    data = json.loads(SUMMARY.read_text())
    contracts = data["contracts"]
    results = []
    for c in contracts:
        errored, actual = run_contract(c)
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
        "project": "python-dateutil",
        "target_version": dateutil.__version__,
        "contracts_total": len(results),
        "replay_passed": sum(1 for r in results if r["replay_passed"]),
        "mutant_rejected": sum(1 for r in results if r["mutant_rejected"]),
        "verified": sum(1 for r in results if r["verified"]),
        "failed": sum(1 for r in results if not r["verified"]),
    }
    OUT_JSON.write_text(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False) + "\n")
    lines = [
        "# python-dateutil Latest Replay + Mutant Verification",
        "",
        f"Target: python-dateutil {summary['target_version']}",
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
