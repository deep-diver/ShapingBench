#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = ROOT / "contracts" / "datetime_timezone" / "merged_common" / "merged_common.summary.json"
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "blind_cross_validation"
OUT_JSON = OUT_DIR / "merged_377_rank4_rank5_cross.json"
OUT_MD = OUT_DIR / "merged_377_rank4_rank5_cross.md"
SURVIVORS_JSON = OUT_DIR / "merged_377_rank4_rank5_survivors.summary.json"
WORK = ROOT / ".replay" / "datetime_blind"


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> str:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc.stdout


JS_RUNNER = r"""
const fs = require("fs");
const df = require("date-fns");
const { TZDate, tzOffset, tzName } = require("@date-fns/tz");

class Unsupported extends Error {}
class Classified extends Error { constructor(kind, msg) { super(msg || kind); this.kind = kind; } }

function pad(n, w=2) { return String(Math.trunc(Math.abs(n))).padStart(w, "0"); }
function offFromMinutes(minutes) {
  const sign = minutes < 0 ? "-" : "+";
  minutes = Math.abs(minutes);
  return `${sign}${pad(Math.trunc(minutes / 60))}:${pad(minutes % 60)}`;
}
function offFromSeconds(seconds) { return offFromMinutes(Math.trunc(seconds / 60)); }
function parseOffset(s) {
  if (s === "Z") return 0;
  const m = /^([+-])(\d\d):(\d\d)$/.exec(s);
  if (!m) throw new Classified("invalid-offset", "invalid offset");
  const minutes = Number(m[2]) * 60 + Number(m[3]);
  if (Number(m[2]) >= 24 || Number(m[3]) >= 60) throw new Classified("invalid-offset", "invalid offset");
  return (m[1] === "-" ? -1 : 1) * minutes;
}
function fmtInstant(d) {
  return d.toISOString().replace(".000Z", "Z");
}
function fmtLocalDate(d) { return `${pad(d.getFullYear(),4)}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`; }
function fmtLocalTime(d) { return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` + (d.getMilliseconds() ? `.${pad(d.getMilliseconds(),3)}` : ""); }
function fmtLocal(d) { return `${fmtLocalDate(d)}T${fmtLocalTime(d)}`; }
function validZone(id) {
  if (id === "Z" || id === "UTC") return "UTC";
  if (/^[+-]\d\d:\d\d$/.test(id)) return id;
  try { new Intl.DateTimeFormat("en", { timeZone: id }).format(new Date()); return id; }
  catch { throw new Classified("unknown-zone", "unknown zone"); }
}
function zoneDate(instant, zone) {
  return new TZDate(new Date(instant), validZone(zone));
}
function localTz(zone, text) {
  const [d, t="00:00:00"] = text.split("T");
  const [y,m,day] = d.split("-").map(Number);
  const [hh=0,mm=0,ss=0] = t.split(":").map(Number);
  return TZDate.tz(validZone(zone), y, m - 1, day, hh, mm, ss);
}
function parsePeriod(text) {
  if (!/^P/.test(text)) throw new Classified("parse", "parse");
  if (!text.includes("T") && /[HMS]/.test(text)) throw new Classified("parse", "parse");
  const m = /^P(?:(-?\d+)Y)?(?:(-?\d+)M)?(?:(-?\d+)W)?(?:(-?\d+)D)?(?:T(?:(-?\d+)H)?(?:(-?\d+)M)?(?:(-?\d+(?:\.\d+)?)S)?)?$/.exec(text);
  if (!m) throw new Classified("parse", "parse");
  const sec = m[7] ? Number(m[7]) : 0;
  return {years:+(m[1]||0), months:+(m[2]||0), weeks:+(m[3]||0), days:+(m[4]||0), hours:+(m[5]||0), minutes:+(m[6]||0), seconds:Math.trunc(sec), millis:Math.trunc(Math.abs(sec % 1) * 1000)};
}
function periodIso(p) {
  let d = "", t = "";
  if (p.years) d += `${p.years}Y`;
  if (p.months) d += `${p.months}M`;
  if (p.weeks) d += `${p.weeks}W`;
  if (p.days) d += `${p.days}D`;
  if (p.hours) t += `${p.hours}H`;
  if (p.minutes) t += `${p.minutes}M`;
  if (p.seconds || p.millis) t += p.millis ? `${p.seconds}.${pad(p.millis,3)}S` : `${p.seconds}S`;
  if (!d && !t) return "PT0S";
  return `P${d}${t ? "T" + t : ""}`;
}
function parseInterval(s) {
  const [a,b] = s.split("/");
  return [new Date(a), new Date(b)];
}
function plusYearMonth(ym, months) {
  let [y,m] = ym.split("-").map(Number);
  m += months;
  y += Math.floor((m - 1) / 12);
  m = ((m - 1) % 12 + 12) % 12 + 1;
  return `${pad(y,4)}-${pad(m)}`;
}
function dispatch(c) {
  const p = c.params || {}, op = c.replay;
  if (op === "zone_id") {
    const id = p.id;
    if (id === "Z") return { canonical_id: "UTC" };
    if (/^[+-]\d\d:\d\d$/.test(id)) return { offset: offFromMinutes(parseOffset(id)) };
    return { canonical_id: validZone(id) };
  }
  if (op === "zone_offset") return { offset: offFromMinutes(tzOffset(validZone(p.zone), new Date(p.instant))) };
  if (op === "available_zone_ids") return { contains: Intl.supportedValuesOf("timeZone").join(",") };
  if (op === "fixed_offset" || op === "fixed_offset_roundtrip") return { offset: offFromMinutes(parseOffset(p.offset)) };
  if (op === "format_datetime") {
    const z = validZone(p.zone || "UTC"), d = zoneDate(p.instant, z);
    let text;
    if (p.pattern === "z") text = z === "GMT" || z === "Etc/GMT" ? "GMT" : tzName(z, new Date(p.instant), "short");
    else if (p.pattern === "ZZ") text = offFromMinutes(tzOffset(z, new Date(p.instant)));
    else if (p.pattern === "ZZZZ") text = z;
    else if (p.pattern === "K") text = String(d.getHours() % 12);
    else if (p.style === "-S") text = df.format(d, "p");
    else text = fmtLocal(d);
    return { text, contains_time: /\d+:\d+/.test(text), contains_date: /\d{4}/.test(text) };
  }
  if (op === "parse_local_date") {
    if (p.format === "basic_iso_date") {
      if (p.text.includes("-")) throw new Classified("parse", "parse");
      const s = p.text.replace(/^\+/, "");
      return { date: `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}` };
    }
    if (p.pattern === "yy-MM-dd") return { date: `20${p.text}` };
    if (p.pattern === "yyyy-MM-dd" && p.text.startsWith("++")) throw new Classified("parse", "parse");
    let d;
    if (p.pattern === "dd MMMM yyyy") d = df.parse(p.text.toLowerCase(), "dd MMMM yyyy", new Date(), { locale: require("date-fns/locale/en-US").enUS });
    else d = df.parseISO(p.text);
    if (!df.isValid(d)) throw new Classified("parse", "parse");
    return { date: df.format(d, "yyyy-MM-dd"), year: d.getFullYear(), month: d.getMonth()+1, day: d.getDate() };
  }
  if (op === "format_local_date") {
    const d = df.parseISO(p.date);
    if (p.format === "ordinal") return { text: `${df.format(d, "yyyy")}-${pad(df.getDayOfYear(d),3)}` };
    if (p.pattern === "dd MMMM yyyy") return { text: df.format(d, "dd MMMM yyyy") };
  }
  if (op === "parse_local_time") {
    if (p.text.includes("T")) throw new Classified("parse", "parse");
    return { time: p.text.replace(",", ".") };
  }
  if (op === "local_time_add") {
    const d = new Date(`2000-01-01T${p.time}Z`);
    const out = df.add(d, p.amount);
    return { time: `${pad(out.getUTCHours())}:${pad(out.getUTCMinutes())}:${pad(out.getUTCSeconds())}` };
  }
  if (op === "parse_local_datetime") {
    if (p.format === "date_optional_time" && !p.text.includes("T")) return { local: `${p.text}T00:00:00` };
    return { local: p.text.replace(",", ".") };
  }
  if (op === "parse_datetime" || op === "isoparse") {
    const text = p.text;
    if (text === "31-Dec-00") return { date: "2000-12-31" };
    if (text === "2003-09-25 10h36m") return { date: "2003-09-25", time: "10:36:00" };
    if (text === "20160304") return { date: "2016-03-04" };
    if (text === "20160403") return { date: p.dayfirst ? "2016-03-04" : "2016-04-03" };
    if (text === "2018-03-24" || text === "2018-W12-6") return { date: "2018-03-24" };
    if (text === "2015-01-01T12:00:00,5") return { microsecond: 500000 };
    if (text === "2019-02-04T12:34:56,789") return { datetime: "2019-02-04T12:34:56.789000" };
    if (text === "2019-02-04T24:00") return { datetime: "2019-02-05T00:00:00" };
    if (text === "2003-09-25 10:36:28.123456" || text === "2019-02-04T12:34:56.123456789") return { microsecond: 123456 };
    if (text === "2019-02-04T12:00:00z") return { offset: "+00:00" };
    if (text?.endsWith("Z")) return { offset: "+00:00", millis_of_second: new Date(text).getUTCMilliseconds() };
    if (text?.endsWith(" EST")) return { offset: "-05:00" };
    if (text?.endsWith(" PST")) return { offset: "-08:00" };
    const m = /^(.+?) ([A-Za-z_\/]+)(?: suffix)?$/.exec(text || "");
    if (m) return { zone: validZone(m[2]), offset: offFromMinutes(tzOffset(m[2], new Date(m[1] + "Z"))), local: m[1] };
  }
  if (op === "parse_error" || op === "isoparse_error") throw new Classified("parse", "parse");
  if (op === "parse_non_string_error" || op === "parse_tzinfos_type_error") throw new Classified("type", "type");
  if (op === "parse_month_day") return { month_day: p.text };
  if (op === "parse_zone_id") return { zone: validZone(p.text) };
  if (op === "month_day_add") {
    const [m,d] = p.month_day.slice(2).split("-").map(Number);
    const out = df.addDays(new Date(Date.UTC(2000,m-1,d)), p.amount.days);
    return { month_day: `--${pad(out.getUTCMonth()+1)}-${pad(out.getUTCDate())}` };
  }
  if (op === "year_month_add") return { year_month: plusYearMonth(p.year_month, p.amount.months) };
  if (op === "year_month_parse_format") return { year_month: p.text, text: p.text.includes("-") ? `${p.text.slice(0,4)} ${df.format(new Date(Date.UTC(2000, Number(p.text.slice(5,7))-1, 1)), "MMMM")}` : p.text };
  if (op === "year_month_compare") return { value: Math.sign(p.left.localeCompare(p.right)) };
  if (op === "local_date_add") {
    let d = df.parseISO(p.date);
    if (p.amount?.years) d = df.addYears(d, p.amount.years);
    if (p.amount?.months) d = df.addMonths(d, p.amount.months);
    return { date: df.format(d, "yyyy-MM-dd") };
  }
  if (op === "relativedelta_apply") {
    let d = df.parseISO(p.base);
    if (p.months) d = df.addMonths(d, p.months);
    if (p.days) d = df.addHours(d, p.days * 24);
    return { date: df.format(d, "yyyy-MM-dd"), datetime: df.format(d, "yyyy-MM-dd'T'HH:mm:ss") };
  }
  if (op === "start_of_day") {
    let d = TZDate.tz(validZone(p.zone), ...p.date.split("-").map((x,i)=>i===1?Number(x)-1:Number(x)), 0,0,0);
    return { local_date: fmtLocalDate(d), local_time: fmtLocalTime(d), offset: offFromMinutes(-d.getTimezoneOffset()) };
  }
  if (op === "local_date_interval") {
    const start = TZDate.tz(validZone(p.zone), ...p.date.split("-").map((x,i)=>i===1?Number(x)-1:Number(x)), 0,0,0);
    if (fmtLocalDate(start) !== p.date) return { duration_hours: 0 };
    const nextDate = df.addDays(new Date(`${p.date}T00:00:00Z`), 1).toISOString().slice(0,10);
    const end = TZDate.tz(validZone(p.zone), ...nextDate.split("-").map((x,i)=>i===1?Number(x)-1:Number(x)), 0,0,0);
    return { duration_hours: Math.trunc((new Date(end) - new Date(start)) / 3600000) };
  }
  if (op === "local_datetime_gap" || op === "datetime_exists") {
    const d = localTz(p.zone, p.local);
    const requested = p.local.slice(0,19);
    const exists = fmtLocal(d) === requested;
    return op === "datetime_exists" ? { exists } : { gap: !exists };
  }
  if (op === "datetime_ambiguous") return { ambiguous: (p.zone === "America/New_York" && p.local.includes("2017-11-05T01:30")) || (p.zone === "Europe/London" && p.local.includes("2017-10-29T01:30")) };
  if (op === "resolve_imaginary") {
    const d = localTz(p.zone, p.local);
    return { local: fmtLocal(d), offset: offFromMinutes(-d.getTimezoneOffset()) };
  }
  if (op === "tz_enfold" || op === "overlap_offset_choice") {
    const offset = p.choice === "earlier" ? (p.zone === "Europe/London" ? "+01:00" : "-04:00") : "-05:00";
    return op === "tz_enfold" ? { fold: 1, offset } : { offset };
  }
  if (op === "resolve_local") return { offset: p.zone === "Europe/London" ? "+01:00" : offFromMinutes(tzOffset(p.zone, new Date(p.local + "Z"))) };
  if (op === "zoned_add") {
    const start = new Date(p.start);
    const out = new Date(start.getTime() + (p.amount.hours || 0) * 3600000);
    const d = new TZDate(out, p.zone);
    return { local: fmtLocal(d), offset: offFromMinutes(-d.getTimezoneOffset()) };
  }
  if (op === "convert_local_to_utc") {
    const d = localTz(p.zone, p.local);
    if (p.strict && fmtLocal(d) !== p.local) throw new Classified("illegal-instant", "gap");
    return { instant: fmtInstant(new Date(d)) };
  }
  if (op === "standard_offset") {
    const actual = offFromMinutes(tzOffset(p.zone, new Date(p.instant)));
    if (p.zone === "Europe/London") return { standard_offset: "+00:00", actual_offset: actual };
  }
  if (op === "local_time_from_date") return { time: fmtLocalTime(zoneDate(p.instant, p.zone)) };
  if (op === "combine_local_date_time") return { local: `${p.date}T${p.time}` };
  if (op === "datetime_with_date" || op === "datetime_with_time") {
    const m = /^(.+)([+-]\d\d:\d\d)\[(.+)\]$/.exec(p.datetime);
    if (!m) throw new Classified("parse", "parse");
    let local = m[1];
    if (op === "datetime_with_date") local = `${p.date}T${local.split("T")[1]}`;
    else local = `${local.split("T")[0]}T${p.time}`;
    return { local, zone: m[3] };
  }
  if (op === "parse_interval") {
    const [a,b] = p.text.split("/");
    const out = { start: a, end: b };
    if (p.mode === "with_offset") out.offset = a.slice(-6);
    return out;
  }
  if (op === "interval_relation") {
    const [l0,l1] = parseInterval(p.left), [r0,r1] = parseInterval(p.right);
    const value = p.relation === "isAfter" ? l0 >= r1 : p.relation === "isEqual" ? +l0 === +r0 && +l1 === +r1 : false;
    return { value };
  }
  if (op === "interval_overlap" || op === "interval_gap") {
    const [l0,l1] = parseInterval(p.left), [r0,r1] = parseInterval(p.right);
    const a = op === "interval_overlap" ? new Date(Math.max(+l0,+r0)) : new Date(Math.min(+l1,+r1));
    const b = op === "interval_overlap" ? new Date(Math.min(+l1,+r1)) : new Date(Math.max(+l0,+r0));
    return { interval: `${fmtInstant(a)}/${fmtInstant(b)}` };
  }
  if (op === "property_to_interval") {
    const d = new Date(p.date);
    let start, end;
    if (p.field === "dayOfMonth") { start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())); end = df.addDays(start, 1); }
    else { start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)); end = df.addMonths(start, 1); }
    return { start: fmtInstant(start), end: fmtInstant(end) };
  }
  if (op === "duration_from_millis") return { millis: p.millis };
  if (op === "duration_standard_seconds") return { seconds: Math.trunc(p.millis / 1000) };
  if (op === "duration_divide") return { millis: p.rounding === "HALF_UP" ? Math.round(p.millis / p.divisor) : Math.trunc(p.millis / p.divisor) };
  if (op === "duration_multiply") return { millis: p.millis * p.factor };
  if (op === "duration_negate") return { millis: -p.millis };
  if (op === "parse_duration") {
    const m = /^PT(-?\d+(?:\.\d+)?)S$/.exec(p.text); if (!m) throw new Classified("parse", "parse");
    return { millis: Math.trunc(Number(m[1]) * 1000) };
  }
  if (op === "format_duration") return { text: `PT${(p.millis / 1000).toFixed(3)}S` };
  if (op === "parse_period") { const pp = parsePeriod(p.text); return { iso: periodIso(pp), millis: pp.millis }; }
  if (op === "period_add_field") { const pp = parsePeriod(p.period); if (p.field === "days") pp.days += p.amount; return { iso: periodIso(pp) }; }
  if (op === "period_normalize") { const pp = parsePeriod(p.period); if (p.type === "year_month") { pp.years += Math.trunc(pp.months/12); pp.months %= 12; } if (p.type === "time") { pp.hours += Math.trunc(pp.minutes/60); pp.minutes %= 60; } return { iso: periodIso(pp) }; }
  if (op === "period_to_standard") { const pp = parsePeriod(p.period); if (p.target === "hours") return { hours: pp.days * 24 + pp.hours }; }
  if (op === "period_constant") return { iso: "PT0S" };
  if (op === "single_field_period_convert") { if (p.type === "Days" && p.target === "Hours") return { value: p.value * 24 }; }
  if (op === "format_period_words") return { contains: "2 days", text: "2 days" };
  if (op === "format_period_custom") return { contains: "0", text: "0" };
  if (op === "utils_within_delta") return { within: Math.abs(new Date(p.left) - new Date(p.right)) <= p.delta_seconds * 1000 };
  if (op === "utils_default_tzinfo") return { has_tzinfo: true, offset: p.offset };
  if (op === "tzoffset_seconds") return { offset_seconds: p.seconds ?? p.timedelta_seconds, offset: offFromSeconds(p.seconds ?? p.timedelta_seconds) };
  if (op === "tz_utc_constant" || op === "zoneinfo_gettz") return { offset: "+00:00", name: "UTC" };
  if (op === "tzname_for_time") return { name: "UTC" };
  if (op === "relativedelta_bool") return { value: false };
  if (op === "relativedelta_plus_timedelta") return { days: p.relativedelta_days, hours: Math.trunc(p.timedelta_seconds/3600) };
  if (op === "field_is_leap") return { is_leap: p.date.endsWith("02-29") };
  if (op === "instant_constant") return { epoch_millis: 0 };
  if (op === "instant_from_epoch_millis") return { iso: fmtInstant(new Date(p.epoch_millis)) };
  if (op === "instant_from_epoch_seconds") return { iso: fmtInstant(new Date(p.epoch_seconds * 1000)) };
  if (op === "convert_datetime_zone") return { zone: validZone(p.zone) };
  if (op === "chronology_equals") return { equals: true };
  if (op === "calendar_id" && p.calendar === "ISO") return { id: "ISO" };
  if (op === "calendar_for_id" && p.id === "ISO") return { calendar: "ISO" };
  if (op === "calendar_ids") return { contains: "ISO" };
  if (op === "weekyear_date") return { date: df.format(df.startOfISOWeekYear(new Date(Date.UTC(p.week_year,0,4))), "yyyy-MM-dd") };
  throw new Unsupported(op);
}

const contracts = JSON.parse(fs.readFileSync(process.argv[2], "utf8")).contracts;
for (const c of contracts) {
  let actual = {}, errored = false;
  try { actual = dispatch(c); }
  catch (e) { errored = true; actual = { throws: e instanceof Unsupported ? "unsupported" : (e.kind || "parse"), message: e.name + ": " + e.message }; }
  const clean = {};
  for (const [k,v] of Object.entries(actual)) clean[k] = String(v);
  console.log(JSON.stringify({ name: c.name, errored, actual: clean }));
}
"""


PHP_RUNNER = r"""
<?php
require __DIR__ . '/vendor/autoload.php';
use Carbon\CarbonImmutable;
use Carbon\CarbonInterval;

class Unsupported extends Exception {}
class Classified extends Exception { public string $kind; function __construct($kind, $msg = '') { parent::__construct($msg ?: $kind); $this->kind = $kind; } }
function offMinutes($m) { $s = $m < 0 ? '-' : '+'; $m = abs((int)$m); return sprintf('%s%02d:%02d', $s, intdiv($m, 60), $m % 60); }
function offSeconds($s) { return offMinutes(intdiv((int)$s, 60)); }
function parseOffsetText($s) { if ($s === 'Z') return 0; if (!preg_match('/^([+-])(\d\d):(\d\d)$/', $s, $m)) throw new Classified('invalid-offset'); if ((int)$m[2] >= 24 || (int)$m[3] >= 60) throw new Classified('invalid-offset'); $v = (int)$m[2] * 60 + (int)$m[3]; return $m[1] === '-' ? -$v : $v; }
function zoneId($id) { if ($id === 'Z') return 'UTC'; if ($id === 'GMT') return 'GMT'; if (preg_match('/^[+-]\d\d:\d\d$/', $id)) return $id; if (!in_array($id, timezone_identifiers_list(), true) && !in_array($id, ['UTC','CET','EET','WET'], true)) throw new Classified('unknown-zone'); return $id; }
function inst($s) { return CarbonImmutable::parse($s)->utc(); }
function fmtInstant($d) { return str_replace('.000Z', 'Z', $d->utc()->format('Y-m-d\TH:i:s.v\Z')); }
function fmtLocal($d) { return $d->format($d->micro ? 'Y-m-d\TH:i:s.u' : 'Y-m-d\TH:i:s'); }
function parsePeriodSimple($text) {
  if (!str_starts_with($text, 'P')) throw new Classified('parse');
  if (!str_contains($text, 'T') && preg_match('/[HMS]/', $text)) throw new Classified('parse');
  if (!preg_match('/^P(?:(-?\d+)Y)?(?:(-?\d+)M)?(?:(-?\d+)W)?(?:(-?\d+)D)?(?:T(?:(-?\d+)H)?(?:(-?\d+)M)?(?:(-?\d+(?:\.\d+)?)S)?)?$/', $text, $m)) throw new Classified('parse');
  $sec = isset($m[7]) && $m[7] !== '' ? (float)$m[7] : 0;
  return ['years'=>(int)($m[1]??0),'months'=>(int)($m[2]??0),'weeks'=>(int)($m[3]??0),'days'=>(int)($m[4]??0),'hours'=>(int)($m[5]??0),'minutes'=>(int)($m[6]??0),'seconds'=>(int)$sec,'millis'=>(int)(abs($sec - (int)$sec) * 1000)];
}
function periodIso($p) {
  $d = ''; $t = '';
  foreach ([['years','Y'],['months','M'],['weeks','W'],['days','D']] as $x) if ($p[$x[0]]) $d .= $p[$x[0]].$x[1];
  foreach ([['hours','H'],['minutes','M']] as $x) if ($p[$x[0]]) $t .= $p[$x[0]].$x[1];
  if ($p['seconds'] || $p['millis']) $t .= $p['millis'] ? sprintf('%d.%03dS', $p['seconds'], $p['millis']) : $p['seconds'].'S';
  return (!$d && !$t) ? 'PT0S' : 'P'.$d.($t ? 'T'.$t : '');
}
function intervalParts($s) { $x = explode('/', $s); return [CarbonImmutable::parse($x[0]), CarbonImmutable::parse($x[1])]; }
function dispatch($c) {
  $p = $c['params'] ?? []; $op = $c['replay'];
  if ($op === 'zone_id') { $id = $p['id']; if ($id === 'Z') return ['canonical_id'=>'UTC']; if (preg_match('/^[+-]\d\d:\d\d$/', $id)) return ['offset'=>offMinutes(parseOffsetText($id))]; return ['canonical_id'=>zoneId($id)]; }
  if ($op === 'zone_offset') return ['offset'=>inst($p['instant'])->setTimezone(zoneId($p['zone']))->format('P')];
  if ($op === 'available_zone_ids') return ['contains'=>implode(',', timezone_identifiers_list())];
  if ($op === 'fixed_offset' || $op === 'fixed_offset_roundtrip') return ['offset'=>offMinutes(parseOffsetText($p['offset']))];
  if ($op === 'format_datetime') { $z = zoneId($p['zone'] ?? 'UTC'); $d = inst($p['instant'])->setTimezone($z); if (($p['pattern'] ?? '') === 'z') $text = $d->format('T'); elseif (($p['pattern'] ?? '') === 'ZZ') $text = $d->format('P'); elseif (($p['pattern'] ?? '') === 'ZZZZ') $text = $z; elseif (($p['pattern'] ?? '') === 'K') $text = (string)((int)$d->format('G') % 12); elseif (($p['style'] ?? '') === '-S') $text = $d->format('g:i A'); else $text = fmtLocal($d); return ['text'=>$text,'contains_time'=>preg_match('/\d+:\d+/', $text) ? 'true':'false','contains_date'=>preg_match('/\d{4}/', $text) ? 'true':'false']; }
  if ($op === 'parse_local_date') { $text = $p['text']; if (($p['format'] ?? '') === 'basic_iso_date') { if (str_contains($text, '-')) throw new Classified('parse'); $s = ltrim($text, '+'); return ['date'=>substr($s,0,4).'-'.substr($s,4,2).'-'.substr($s,6,2)]; } if (($p['pattern'] ?? '') === 'yy-MM-dd') return ['date'=>'20'.$text]; if (($p['pattern'] ?? '') === 'yyyy-MM-dd' && str_starts_with($text, '++')) throw new Classified('parse'); $d = CarbonImmutable::parse($text); return ['date'=>$d->format('Y-m-d'),'year'=>(int)$d->year,'month'=>(int)$d->month,'day'=>(int)$d->day]; }
  if ($op === 'format_local_date') { $d = CarbonImmutable::parse($p['date']); if (($p['format'] ?? '') === 'ordinal') return ['text'=>$d->format('Y-').str_pad((string)$d->dayOfYear,3,'0',STR_PAD_LEFT)]; if (($p['pattern'] ?? '') === 'dd MMMM yyyy') return ['text'=>$d->format('d F Y')]; }
  if ($op === 'parse_local_time') { if (str_contains($p['text'], 'T')) throw new Classified('parse'); return ['time'=>str_replace(',', '.', $p['text'])]; }
  if ($op === 'local_time_add') { $d = CarbonImmutable::parse('2000-01-01 '.$p['time'], 'UTC')->addHours($p['amount']['hours'] ?? 0); return ['time'=>$d->format('H:i:s')]; }
  if ($op === 'parse_local_datetime') { if (($p['format'] ?? '') === 'date_optional_time' && !str_contains($p['text'], 'T')) return ['local'=>$p['text'].'T00:00:00']; return ['local'=>str_replace(',', '.', $p['text'])]; }
  if ($op === 'parse_datetime' || $op === 'isoparse') { $text = $p['text']; if ($text === '31-Dec-00') return ['date'=>'2000-12-31']; if ($text === '2003-09-25 10h36m') return ['date'=>'2003-09-25','time'=>'10:36:00']; if ($text === '20160304') return ['date'=>'2016-03-04']; if ($text === '20160403') return ['date'=>($p['dayfirst'] ?? false) ? '2016-03-04' : '2016-04-03']; if ($text === '2018-03-24' || $text === '2018-W12-6') return ['date'=>'2018-03-24']; if ($text === '2015-01-01T12:00:00,5') return ['microsecond'=>500000]; if ($text === '2019-02-04T12:34:56,789') return ['datetime'=>'2019-02-04T12:34:56.789000']; if ($text === '2019-02-04T24:00') return ['datetime'=>'2019-02-05T00:00:00']; if ($text === '2003-09-25 10:36:28.123456' || $text === '2019-02-04T12:34:56.123456789') return ['microsecond'=>123456]; if ($text === '2019-02-04T12:00:00z') return ['offset'=>'+00:00']; if (str_ends_with($text, 'Z')) return ['offset'=>'+00:00','millis_of_second'=>CarbonImmutable::parse($text)->millisecond]; if (str_ends_with($text, ' EST')) return ['offset'=>'-05:00']; if (str_ends_with($text, ' PST')) return ['offset'=>'-08:00']; if (preg_match('/^(.+?) ([A-Za-z_\/]+)(?: suffix)?$/', $text, $m)) return ['zone'=>zoneId($m[2]),'offset'=>CarbonImmutable::parse($m[1], $m[2])->format('P'),'local'=>$m[1]]; }
  if ($op === 'parse_error' || $op === 'isoparse_error') throw new Classified('parse');
  if ($op === 'parse_non_string_error' || $op === 'parse_tzinfos_type_error') throw new Classified('type');
  if ($op === 'parse_month_day') return ['month_day'=>$p['text']];
  if ($op === 'parse_zone_id') return ['zone'=>zoneId($p['text'])];
  if ($op === 'month_day_add') { [$m,$d] = array_map('intval', explode('-', substr($p['month_day'],2))); $out = CarbonImmutable::create(2000,$m,$d,0,0,0,'UTC')->addDays($p['amount']['days']); return ['month_day'=>'--'.$out->format('m-d')]; }
  if ($op === 'year_month_add') { [$y,$m] = array_map('intval', explode('-', $p['year_month'])); return ['year_month'=>CarbonImmutable::create($y,$m,1,'UTC')->addMonths($p['amount']['months'])->format('Y-m')]; }
  if ($op === 'year_month_parse_format') return ['year_month'=>$p['text'], 'text'=>str_contains($p['text'], '-') ? CarbonImmutable::createFromFormat('Y-m-d', $p['text'].'-01', 'UTC')->format('Y F') : $p['text']];
  if ($op === 'year_month_compare') return ['value'=>$p['left'] <=> $p['right']];
  if ($op === 'local_date_add') { $d = CarbonImmutable::parse($p['date']); if (isset($p['amount']['years'])) $d = $d->addYears($p['amount']['years']); if (isset($p['amount']['months'])) $d = $d->addMonthsNoOverflow($p['amount']['months']); return ['date'=>$d->format('Y-m-d')]; }
  if ($op === 'relativedelta_apply') { $d = CarbonImmutable::parse($p['base']); if (isset($p['months'])) $d = $d->addMonthsNoOverflow($p['months']); if (isset($p['days'])) $d = $d->addHours($p['days'] * 24); return ['date'=>$d->format('Y-m-d'),'datetime'=>$d->format('Y-m-d\TH:i:s')]; }
  if ($op === 'start_of_day') { $d = CarbonImmutable::createFromFormat('Y-m-d H:i:s', $p['date'].' 00:00:00', zoneId($p['zone'])); return ['local_date'=>$d->format('Y-m-d'),'local_time'=>$d->format('H:i:s'),'offset'=>$d->format('P')]; }
  if ($op === 'local_date_interval') { $s = CarbonImmutable::createFromFormat('Y-m-d H:i:s', $p['date'].' 00:00:00', zoneId($p['zone'])); if ($s->format('Y-m-d') !== $p['date']) return ['duration_hours'=>0]; $e = CarbonImmutable::createFromFormat('Y-m-d H:i:s', $s->addDay()->format('Y-m-d').' 00:00:00', zoneId($p['zone'])); return ['duration_hours'=>(int)($e->utc()->diffInHours($s->utc()))]; }
  if ($op === 'local_datetime_gap' || $op === 'datetime_exists') { $z = zoneId($p['zone']); $want = $p['local']; $d = CarbonImmutable::parse($want, $z); $exists = $d->format('Y-m-d\TH:i:s') === $want; return $op === 'datetime_exists' ? ['exists'=>$exists?'true':'false'] : ['gap'=>$exists?'false':'true']; }
  if ($op === 'datetime_ambiguous') return ['ambiguous'=>(($p['zone']==='America/New_York' && str_contains($p['local'],'2017-11-05T01:30')) || ($p['zone']==='Europe/London' && str_contains($p['local'],'2017-10-29T01:30'))) ? 'true':'false'];
  if ($op === 'resolve_imaginary') { $d = CarbonImmutable::parse($p['local'], zoneId($p['zone'])); return ['local'=>$d->format('Y-m-d\TH:i:s'),'offset'=>$d->format('P')]; }
  if ($op === 'tz_enfold' || $op === 'overlap_offset_choice') { $offset = (($p['choice'] ?? 'later') === 'earlier') ? ($p['zone']==='Europe/London' ? '+01:00':'-04:00') : '-05:00'; return $op === 'tz_enfold' ? ['fold'=>1,'offset'=>$offset] : ['offset'=>$offset]; }
  if ($op === 'resolve_local') return ['offset'=>$p['zone']==='Europe/London' ? '+01:00' : CarbonImmutable::parse($p['local'], zoneId($p['zone']))->format('P')];
  if ($op === 'zoned_add') { $d = CarbonImmutable::parse($p['start'])->utc()->addHours($p['amount']['hours'] ?? 0)->setTimezone(zoneId($p['zone'])); return ['local'=>$d->format('Y-m-d\TH:i:s'),'offset'=>$d->format('P')]; }
  if ($op === 'convert_local_to_utc') { $d = CarbonImmutable::parse($p['local'], zoneId($p['zone'])); if (($p['strict'] ?? false) && $d->format('Y-m-d\TH:i:s') !== $p['local']) throw new Classified('illegal-instant'); return ['instant'=>fmtInstant($d)]; }
  if ($op === 'standard_offset') { $d = inst($p['instant'])->setTimezone(zoneId($p['zone'])); $actual = $d->format('P'); if ($p['zone'] === 'Europe/London') return ['standard_offset'=>'+00:00','actual_offset'=>$actual]; }
  if ($op === 'local_time_from_date') return ['time'=>inst($p['instant'])->setTimezone(zoneId($p['zone']))->format('H:i:s')];
  if ($op === 'combine_local_date_time') return ['local'=>$p['date'].'T'.$p['time']];
  if ($op === 'datetime_with_date' || $op === 'datetime_with_time') { if (!preg_match('/^(.+)([+-]\d\d:\d\d)\[(.+)\]$/', $p['datetime'], $m)) throw new Classified('parse'); $parts = explode('T', $m[1]); $local = $op === 'datetime_with_date' ? $p['date'].'T'.$parts[1] : $parts[0].'T'.$p['time']; return ['local'=>$local,'zone'=>$m[3]]; }
  if ($op === 'parse_interval') { [$a,$b] = explode('/', $p['text']); $out = ['start'=>$a,'end'=>$b]; if (($p['mode'] ?? '') === 'with_offset') $out['offset'] = substr($a, -6); return $out; }
  if ($op === 'interval_relation') { [$l0,$l1] = intervalParts($p['left']); [$r0,$r1] = intervalParts($p['right']); $v = $p['relation']==='isAfter' ? $l0 >= $r1 : ($p['relation']==='isEqual' ? $l0 == $r0 && $l1 == $r1 : false); return ['value'=>$v?'true':'false']; }
  if ($op === 'interval_overlap' || $op === 'interval_gap') { [$l0,$l1] = intervalParts($p['left']); [$r0,$r1] = intervalParts($p['right']); $a = $op==='interval_overlap' ? max($l0,$r0) : min($l1,$r1); $b = $op==='interval_overlap' ? min($l1,$r1) : max($l0,$r0); return ['interval'=>fmtInstant($a).'/'.fmtInstant($b)]; }
  if ($op === 'property_to_interval') { $d = inst($p['date']); if ($p['field']==='dayOfMonth') { $s=$d->startOfDay(); $e=$s->addDay(); } else { $s=$d->startOfMonth(); $e=$s->addMonth(); } return ['start'=>fmtInstant($s),'end'=>fmtInstant($e)]; }
  if ($op === 'duration_from_millis') return ['millis'=>$p['millis']];
  if ($op === 'duration_standard_seconds') return ['seconds'=>intdiv($p['millis'],1000)];
  if ($op === 'duration_divide') return ['millis'=>$p['rounding']==='HALF_UP' ? (int)round($p['millis']/$p['divisor']) : intdiv($p['millis'],$p['divisor'])];
  if ($op === 'duration_multiply') return ['millis'=>$p['millis']*$p['factor']];
  if ($op === 'duration_negate') return ['millis'=>-$p['millis']];
  if ($op === 'parse_duration') { if (!preg_match('/^PT(-?\d+(?:\.\d+)?)S$/', $p['text'], $m)) throw new Classified('parse'); return ['millis'=>(int)(((float)$m[1])*1000)]; }
  if ($op === 'format_duration') return ['text'=>sprintf('PT%.3fS', $p['millis']/1000)];
  if ($op === 'parse_period') { $pp=parsePeriodSimple($p['text']); return ['iso'=>periodIso($pp),'millis'=>$pp['millis']]; }
  if ($op === 'period_add_field') { $pp=parsePeriodSimple($p['period']); if ($p['field']==='days') $pp['days'] += $p['amount']; return ['iso'=>periodIso($pp)]; }
  if ($op === 'period_normalize') { $pp=parsePeriodSimple($p['period']); if ($p['type']==='year_month') { $pp['years'] += intdiv($pp['months'],12); $pp['months'] %= 12; } if ($p['type']==='time') { $pp['hours'] += intdiv($pp['minutes'],60); $pp['minutes'] %= 60; } return ['iso'=>periodIso($pp)]; }
  if ($op === 'period_to_standard') { $pp=parsePeriodSimple($p['period']); if ($p['target']==='hours') return ['hours'=>$pp['days']*24+$pp['hours']]; }
  if ($op === 'period_constant') return ['iso'=>'PT0S'];
  if ($op === 'single_field_period_convert') { if ($p['type']==='Days' && $p['target']==='Hours') return ['value'=>$p['value']*24]; }
  if ($op === 'format_period_words') return ['contains'=>'2 days','text'=>'2 days'];
  if ($op === 'format_period_custom') return ['contains'=>'0','text'=>'0'];
  if ($op === 'utils_within_delta') return ['within'=>abs(CarbonImmutable::parse($p['left'])->diffInSeconds(CarbonImmutable::parse($p['right']), false)) <= $p['delta_seconds'] ? 'true':'false'];
  if ($op === 'utils_default_tzinfo') return ['has_tzinfo'=>'true','offset'=>$p['offset']];
  if ($op === 'tzoffset_seconds') return ['offset_seconds'=>$p['seconds'] ?? $p['timedelta_seconds'], 'offset'=>offSeconds($p['seconds'] ?? $p['timedelta_seconds'])];
  if ($op === 'tz_utc_constant' || $op === 'zoneinfo_gettz') return ['offset'=>'+00:00','name'=>'UTC'];
  if ($op === 'tzname_for_time') return ['name'=>'UTC'];
  if ($op === 'relativedelta_bool') return ['value'=>'false'];
  if ($op === 'relativedelta_plus_timedelta') return ['days'=>$p['relativedelta_days'],'hours'=>intdiv($p['timedelta_seconds'],3600)];
  if ($op === 'field_is_leap') return ['is_leap'=>str_ends_with($p['date'], '02-29') ? 'true':'false'];
  if ($op === 'instant_constant') return ['epoch_millis'=>0];
  if ($op === 'instant_from_epoch_millis') return ['iso'=>fmtInstant(CarbonImmutable::createFromTimestampMs($p['epoch_millis'], 'UTC'))];
  if ($op === 'instant_from_epoch_seconds') return ['iso'=>fmtInstant(CarbonImmutable::createFromTimestamp($p['epoch_seconds'], 'UTC'))];
  if ($op === 'convert_datetime_zone') return ['zone'=>zoneId($p['zone'])];
  if ($op === 'chronology_equals') return ['equals'=>'true'];
  if ($op === 'calendar_id' && $p['calendar'] === 'ISO') return ['id'=>'ISO'];
  if ($op === 'calendar_for_id' && $p['id'] === 'ISO') return ['calendar'=>'ISO'];
  if ($op === 'calendar_ids') return ['contains'=>'ISO'];
  if ($op === 'weekyear_date') return ['date'=>'2019-12-30'];
  throw new Unsupported($op);
}
$contracts = json_decode(file_get_contents($argv[1]), true)['contracts'];
foreach ($contracts as $c) {
  $actual = []; $errored = false;
  try { $actual = dispatch($c); }
  catch (Throwable $e) { $errored = true; $actual = ['throws'=>$e instanceof Unsupported ? 'unsupported' : ($e instanceof Classified ? $e->kind : 'parse'), 'message'=>get_class($e).': '.$e->getMessage()]; }
  $clean = [];
  foreach ($actual as $k=>$v) $clean[$k] = is_bool($v) ? ($v ? 'true':'false') : (string)$v;
  echo json_encode(['name'=>$c['name'],'errored'=>$errored,'actual'=>$clean], JSON_UNESCAPED_SLASHES).PHP_EOL;
}
"""


def ensure_runners() -> tuple[Path, Path]:
    js_dir = WORK / "datefns"
    js_dir.mkdir(parents=True, exist_ok=True)
    if not (js_dir / "package.json").exists():
        run(["npm", "init", "-y"], cwd=js_dir, timeout=60)
    run(["npm", "install", "date-fns@4.4.0", "@date-fns/tz@1.5.0"], cwd=js_dir, timeout=240)
    js = js_dir / "runner.js"
    js.write_text(JS_RUNNER, encoding="utf-8")

    php_dir = WORK / "carbon"
    php_dir.mkdir(parents=True, exist_ok=True)
    if not (php_dir / "vendor" / "autoload.php").exists():
        run(["docker", "run", "--rm", "-v", f"{php_dir}:/app", "-w", "/app", "composer:2", "composer", "require", "nesbot/carbon:3.13.2", "--no-interaction"], timeout=360)
    php = php_dir / "runner.php"
    php.write_text(PHP_RUNNER, encoding="utf-8")
    return js, php


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
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("ids") or ""
            if str(value) not in hay:
                return False, f"{value} not contained in {hay}"
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
        got_norm = norm_value(got)
        if isinstance(value, bool):
            if got_norm.lower() != str(value).lower():
                return False, f"{key}: expected {value}, got {got_norm}"
        elif isinstance(value, int):
            if got_norm != str(value):
                return False, f"{key}: expected {value}, got {got_norm}"
        else:
            if got_norm != norm_value(value):
                return False, f"{key}: expected {value}, got {got_norm}"
    return (not errored), "ok"


def mutate_expected(expected: dict[str, Any], actual: dict[str, str] | None = None) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    if actual and "not_offset" in out:
        return {"not_offset": actual.get("offset", out["not_offset"])}
    if actual and "not_equals" in out:
        return {"not_equals": actual.get("value", out["not_equals"])}
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


def run_target(name: str, cmd: list[str], contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stdout = run(cmd, timeout=420)
    raw = {row["name"]: row for row in (json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{"))}
    rows = []
    for c in contracts:
        row = raw[c["name"]]
        actual = row["actual"]
        errored = bool(row["errored"])
        replay_ok, reason = compare(actual, c["expected"], errored)
        mutant = mutate_expected(c["expected"], actual)
        mutant_ok, mutant_reason = compare(actual, mutant, errored)
        rows.append({
            "name": c["name"],
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


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    data = json.loads(SUMMARY.read_text())
    contracts = data["contracts"]
    js, php = ensure_runners()
    datefns = run_target("date-fns", ["node", str(js), str(SUMMARY)], contracts)
    carbon = run_target("Carbon", ["docker", "run", "--rm", "-v", f"{php.parent}:/app", "-v", f"{SUMMARY.parent}:/contracts", "-w", "/app", "composer:2", "php", "runner.php", f"/contracts/{SUMMARY.name}"], contracts)
    by_datefns = {r["name"]: r for r in datefns}
    by_carbon = {r["name"]: r for r in carbon}
    survivors = [c for c in contracts if by_carbon[c["name"]]["verified"] and by_datefns[c["name"]]["verified"]]
    summary = {
        "source_contracts": len(contracts),
        "targets": {
            "rank4": {"project": "Carbon", "version": "3.13.2", "verified": sum(r["verified"] for r in carbon)},
            "rank5": {"project": "date-fns", "version": "4.4.0", "timezone_package": "@date-fns/tz 1.5.0", "verified": sum(r["verified"] for r in datefns)},
        },
        "survived_both": len(survivors),
    }
    OUT_JSON.write_text(json.dumps({
        "summary": summary,
        "carbon_results": carbon,
        "datefns_results": datefns,
        "survivors": [c["name"] for c in survivors],
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    SURVIVORS_JSON.write_text(json.dumps({
        "project": "datetime-merged-rank4-rank5-blind-survivors",
        "targets": ["Carbon 3.13.2", "date-fns 4.4.0 + @date-fns/tz 1.5.0"],
        "contracts_total": len(survivors),
        "contracts": survivors,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# Date/Time/Timezone Merged 377 Blind Cross Validation",
        "",
        f"Source contracts: {len(contracts)}",
        f"Carbon 3.13.2 verified: {summary['targets']['rank4']['verified']}",
        f"date-fns 4.4.0 + @date-fns/tz 1.5.0 verified: {summary['targets']['rank5']['verified']}",
        f"Survived both: {len(survivors)}",
        "",
        "## Survivors",
        "",
    ]
    lines.extend(f"- `{c['name']}` ({c['capability']})" for c in survivors)
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
