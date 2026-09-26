#!/usr/bin/env python3
"""Extract floraison/fugit release-history contracts and verify them on v1.13.0."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / ".cache" / "floraison-fugit-src-20260831"
CHANGELOG = SRC / "CHANGELOG.md"
OUT_DIR = ROOT / "contracts" / "cron" / "fugit"
RUNNER = ROOT / "tools" / "replay" / "fugit_latest_runner" / "replay_fugit.rb"
RUBY = Path("/usr/bin/ruby")
PROJECT = "floraison/fugit"
LATEST = "1.13.0"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:84]


def fetch_rubygems_versions() -> list[str]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cache = OUT_DIR / "rubygems_versions.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))["stable_versions"]
    req = urllib.request.Request("https://rubygems.org/api/v1/versions/fugit.json", headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        data = json.loads(res.read().decode("utf-8"))
    stable = [item["number"] for item in data if not item.get("prerelease")]
    cache.write_text(json.dumps({"stable_versions": stable}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return stable


def git_tags() -> list[str]:
    proc = subprocess.run(["git", "-C", str(SRC), "tag", "--sort=v:refname"], check=True, text=True, capture_output=True)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def parse_changelog() -> dict[str, str]:
    text = CHANGELOG.read_text(encoding="utf-8")
    matches = list(re.finditer(r"^## fugit ([0-9][0-9A-Za-z.]*) [^\n]*\n", text, flags=re.M))
    out: dict[str, str] = {}
    for idx, match in enumerate(matches):
        version = match.group(1)
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        out[version] = text[start:end].strip()
    return out


def add(rows: list[dict[str, Any]], version: str, capability: str, op: str, params: dict[str, Any], evidence: str, human: str) -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"fugit_{version.replace('.', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": PROJECT,
            "domain": "cron_schedule_expression",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence,
            "human": human,
        }
    )


def parse(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str = "fugit.cron.parse-normalize", **opts: Any) -> None:
    params = {"expression": expr}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "parse_cron", params, evidence, f"Parse cron expression `{expr}` and expose normalized form and parsed fields.")


def parse_nil(rows: list[dict[str, Any]], version: str, expr: Any, evidence: str, capability: str) -> None:
    add(rows, version, capability, "parse_cron_nil", {"expression": expr}, evidence, f"`{expr}` is not accepted as a cron expression.")


def do_parse_error(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "do_parse_error", {"expression": expr}, evidence, f"`{expr}` raises through do_parse.")


def nexts(rows: list[dict[str, Any]], version: str, expr: str, start: str, count: int, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "count": count}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "next_times", params, evidence, f"`{expr}` yields next {count} occurrence(s) after `{start}`.")


def prevs(rows: list[dict[str, Any]], version: str, expr: str, start: str, count: int, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "count": count}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "previous_times", params, evidence, f"`{expr}` yields previous {count} occurrence(s) before `{start}`.")


def match(rows: list[dict[str, Any]], version: str, expr: str, date: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "date": date}
    params.update({k: v for k, v in opts.items() if v is not None})
    add(rows, version, capability, "match", params, evidence, f"`{expr}` match? at `{date}`.")


def rough(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "rough_frequency", {"expression": expr}, evidence, f"`{expr}` rough frequency is observable.")


def brute(rows: list[dict[str, Any]], version: str, expr: str, year: int, evidence: str, capability: str) -> None:
    add(rows, version, capability, "brute_frequency", {"expression": expr, "year": year}, evidence, f"`{expr}` brute frequency in {year} is observable.")


def seconds(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "seconds", {"expression": expr}, evidence, f"`{expr}` exposes parsed seconds.")


def parse_kind(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr}
    params.update(opts)
    add(rows, version, capability, "parse_kind", params, evidence, f"Fugit.parse maps `{expr}` to a schedule type.")


def parse_cronish(rows: list[dict[str, Any]], version: str, expr: str, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr}
    params.update(opts)
    add(rows, version, capability, "parse_cronish", params, evidence, f"Fugit.parse_cronish maps `{expr}` to cron or nil.")


def determine_type(rows: list[dict[str, Any]], version: str, expr: Any, evidence: str, capability: str) -> None:
    add(rows, version, capability, "determine_type", {"expression": expr}, evidence, f"Fugit.determine_type observes `{expr}`.")


def iterator(rows: list[dict[str, Any]], version: str, op: str, expr: str, start: str, count: int, evidence: str, capability: str, **opts: Any) -> None:
    params = {"expression": expr, "start": start, "count": count}
    params.update(opts)
    add(rows, version, capability, op, params, evidence, f"`{expr}` {op} iterator yields {count} values from `{start}`.")


def within(rows: list[dict[str, Any]], version: str, expr: str, start: str, end: str, evidence: str, capability: str, as_range: bool) -> None:
    add(rows, version, capability, "within", {"expression": expr, "start": start, "end": end, "range": as_range}, evidence, f"`{expr}` occurrences within `{start}`..`{end}`.")


def equality(rows: list[dict[str, Any]], version: str, left: str, right: str, evidence: str, capability: str) -> None:
    add(rows, version, capability, "equality", {"left": left, "right": right}, evidence, f"Cron equality between `{left}` and `{right}` is observable.")


def rweek(rows: list[dict[str, Any]], version: str, ref: str, expr: str, start: str, count: int, evidence: str, capability: str) -> None:
    add(rows, version, capability, "rweek_ref_sequence", {"ref": ref, "expression": expr, "start": start, "count": count}, evidence, f"Modulo week schedule `{expr}` under {ref} reference.")


def build_candidates() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    ev = "0.9.0 initial release and 0.9.1 introduce Fugit.parse/Fugit.parse_cron with Cron occurrence computing."
    for expr in ["* * * * *", "5 0 * * *", "15 14 1 * *", "0 0 1 1 *", "* * * * sun", "30 04 1,15 * 5"]:
        parse(rows, "0.9.1", expr, ev)
        nexts(rows, "0.9.1", expr, "2017-01-02 12:00:00 UTC", 3, ev, "fugit.cron.next-time.core")
    for expr in ["* * * * *", "0 0 * * sun", "0 0 27 JAN *"]:
        prevs(rows, "0.9.1", expr, "2017-03-17 00:00:00 UTC", 3, ev, "fugit.cron.previous-time.core")

    ev = "0.9.4 accepts cron strings with seconds."
    for expr in ["* * * * * *", "5 * * * * *", "5,10 * * * * *", "*/10 * * * * *", "15 5 0 * * *", "15,30 5 0 * * *"]:
        parse(rows, "0.9.4", expr, ev, "fugit.cron.seconds-field")
        seconds(rows, "0.9.4", expr, ev, "fugit.cron.seconds-reader")
        nexts(rows, "0.9.4", expr, "2017-01-01 00:00:00 UTC", 4, ev, "fugit.cron.seconds-next")
        prevs(rows, "0.9.4", expr, "2017-01-01 00:05:31 UTC", 3, ev, "fugit.cron.seconds-previous")

    ev = "0.9.5 implements Fugit.determine_type(s)."
    for expr in ["* * * * *", "* * * * * *", "1s", "2017-01-01", "nada", True]:
        determine_type(rows, "0.9.5", expr, ev, "fugit.determine-type")

    ev = "1.1.0 stores cron timezones and travels in the cron zone for next_time/previous_time."
    for expr in ["* * * * * Europe/Berlin", "5 0 * * * Europe/Rome", "0 22 * * 1-5 Asia/Tbilisi", "* * * * * +09:00", "* * * * * +0900"]:
        parse(rows, "1.1.0", expr, ev, "fugit.cron.timezone-parse")
    for expr, start in [
        ("0 0 * * * Europe/Berlin", "2019-01-01 00:00:00 UTC"),
        ("0 7 * * * America/New_York", "2017-10-17 10:00:00 Europe/London"),
        ("59 18 * * 2#2 UTC", "2021-02-09 17:41:10 UTC"),
    ]:
        nexts(rows, "1.1.0", expr, start, 3, ev, "fugit.cron.timezone-next")
        prevs(rows, "1.1.0", expr, start, 3, ev, "fugit.cron.timezone-previous")

    ev = "1.1.2 adds Fugit::Cron#seconds."
    for expr in ["* * * * *", "5 * * * * *", "5,10 * * * * *", "*/10 * * * * *"]:
        seconds(rows, "1.1.2", expr, ev, "fugit.cron.seconds-reader")

    ev = "1.1.4 uses timezone names when converting Fugit::Cron to cron strings and supports timezone in natural cron strings."
    for expr in ["every day at noon UTC", "every monday at midnight Europe/Berlin", "every day at 18:00 and 20:00 Asia/Tokyo"]:
        parse_kind(rows, "1.1.4", expr, ev, "fugit.nat.to-cron-with-timezone", multi=True)
    for expr in ["0 0 * * * Europe/Berlin", "0 18 * * fri-sun UTC", "0/10 * * * 1-5 Africa/Juba"]:
        parse(rows, "1.1.4", expr, ev, "fugit.cron.to-cron-preserves-zone")

    ev = "1.1.5 adds Fugit::Cron#rough_frequency."
    for expr in [
        "* * * * *", "* * * * * *", "0 0 * * *", "10,15 0 * * *", "0 0 * * sun",
        "0 0 1 1 *", "0 0 29 2 *", "0 0 28 2,3 *", "0 0 28 2,4 *",
        "*/15 * * * * *", "*/15 * * * *", "0 0 * * mon#2", "0 8 L * mon-thu",
    ]:
        rough(rows, "1.1.5", expr, ev, "fugit.cron.rough-frequency")

    ev = "1.1.7 adds breakers and rejects 0 month / day-of-month."
    for expr in ["* * 0 * *", "* * 00 * *", "* * * 0 *", "* * * 00 *", "* 25 * * *", "* * -32 * *"]:
        parse_nil(rows, "1.1.7", expr, ev, "fugit.cron.invalid-monthday-month")
        do_parse_error(rows, "1.1.7", expr, ev, "fugit.cron.do-parse-invalid")
    for expr in ["* * 1 * *", "0 9 29 feb *"]:
        nexts(rows, "1.1.7", expr, "2016-03-01 00:00:00 UTC", 1, ev, "fugit.cron.breaker-finite-next")

    ev = "1.1.9 fixes February 29 and previous_time endless-loop behavior."
    nexts(rows, "1.1.9", "0 9 29 feb *", "2016-01-23 00:00:00 UTC", 2, ev, "fugit.cron.leap-day-next")
    prevs(rows, "1.1.9", "0 9 29 feb *", "2016-03-01 00:00:00 UTC", 2, ev, "fugit.cron.leap-day-previous")
    prevs(rows, "1.1.9", "10 * * * * *", "2017-01-02 12:00:10 UTC", 3, ev, "fugit.cron.previous-time-matching-start")

    ev = "1.1.10 implements the weekday modulo extension like sun%2 and sun%2+1."
    for expr, start in [
        ("0 9 * * sat%2", "2019-01-01 09:00:00 UTC"),
        ("0 10 * * sun%2 Europe/Berlin", "2019-04-11 09:00:00 UTC"),
        ("0 10 * * sun%2+1 Europe/Berlin", "2019-04-11 09:00:00 UTC"),
        ("9 0 * * sun%2", "2019-01-01 00:00:00 UTC"),
        ("9 0 * * sun%2+1", "2019-01-01 00:00:00 UTC"),
    ]:
        parse(rows, "1.1.10", expr, ev, "fugit.cron.weekday-modulo-parse")
        nexts(rows, "1.1.10", expr, start, 6, ev, "fugit.cron.weekday-modulo-next", with_rweek=True)
        prevs(rows, "1.1.10", expr, "2024-03-21 22:00:00 UTC", 4, ev, "fugit.cron.weekday-modulo-previous", with_rweek=True)

    ev = "1.2.0 accepts slash-at-start cron syntax and follows semantic versioning."
    for expr in ["/15 * * * *", "/15 * * * * *", "/15 /4 * * *", "0/15 * * * *"]:
        parse(rows, "1.2.0", expr, ev, "fugit.cron.leading-slash-step")
        nexts(rows, "1.2.0", expr, "2019-04-22 00:00:00 UTC", 4, ev, "fugit.cron.leading-slash-step-next")

    ev = "1.2.1 returns nil for cron expressions with impossible calendar days."
    impossible = ["* * 32 1 *", "* * 30 2 *", "* * 30,31 2 *", "* * 31 4 *", "* * 31 6 *", "* * 31 9 *", "* * 31 11 *", "* * 31 2,4 *"]
    for expr in impossible:
        parse_nil(rows, "1.2.1", expr, ev, "fugit.cron.impossible-days")
    for expr in ["* * 30,31 2,3 *", "* * 30,31 4 *", "* * 31 3,4 *"]:
        parse(rows, "1.2.1", expr, ev, "fugit.cron.impossible-days-compacted")

    ev = "1.2.2 and 1.2.3 fix natural schedule parsing for every 15 minutes, weekday ranges, and multiple daily times."
    for expr in [
        "every 15 minutes", "from Monday to Friday at 19:22", "every Monday to Friday at 18:20",
        "every day at 18:00 and 20:00", "every day at 18:00, 18:15, 20:00, and 20:15",
        "every Fri-Sun at 18:00",
    ]:
        parse_kind(rows, "1.2.3", expr, ev, "fugit.nat.schedule-to-cron", multi=True)
        parse_cronish(rows, "1.2.3", expr, ev, "fugit.parse-cronish.schedule")

    ev = "1.3.0 reworks AM/PM and multi natural parsing."
    for expr in ["every day at 6pm", "every day at 06:00pm", "every day at 12am", "every day at 12pm", "every day at 18:00 and 19:15"]:
        parse_kind(rows, "1.3.0", expr, ev, "fugit.nat.ampm-and-multi", multi=True)

    ev = "1.3.2 allows hour value 24 in cron ranges."
    for expr in ["00 24 * * *", "* 0-24 * * *", "* 22-24 * * *"]:
        parse(rows, "1.3.2", expr, ev, "fugit.cron.hour-24-normalization")
        nexts(rows, "1.3.2", expr, "2017-01-01 12:00:00 UTC", 3, ev, "fugit.cron.hour-24-next")

    ev = "1.3.3 fixes Cron#match? with respect to cron timezone."
    for expr, date in [
        ("0 0 * * * Europe/Berlin", "2019-01-01 00:00:00 Europe/Berlin"),
        ("0 0 * * * Europe/Berlin", "2019-01-01 00:00:00 Europe/London"),
        ("0 12 * * mon#2", "2024-03-11 12:00:00 UTC"),
        ("0 12 * * mon#2", "2024-03-12 12:00:00 UTC"),
    ]:
        match(rows, "1.3.3", expr, date, ev, "fugit.cron.match-timezone-and-nth")

    ev = "1.3.4 prevents Cron#rough_frequency returning zero."
    for expr in ["0 0 */2 * *", "0 0 */3 * *", "0 0 * * */2", "0 0 29 2 *", "0 0 * * mon#-1"]:
        rough(rows, "1.3.4", expr, ev, "fugit.cron.rough-frequency-nonzero")

    ev = "1.3.5 implements @noon and normalizes every x natural schedules."
    for expr in ["@noon", "@noon Asia/Jakarta", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"]:
        parse(rows, "1.3.5", expr, ev, "fugit.cron.specials")
        nexts(rows, "1.3.5", expr, "2021-04-10 00:00:00 UTC", 3, ev, "fugit.cron.specials-next")
    for expr in ["every 12 hours", "every 2 days", "every 1 week"]:
        parse_kind(rows, "1.3.5", expr, ev, "fugit.nat.every-x-normalization")

    ev = "1.3.7 and 1.3.8 parse natural schedules with minute-qualified hours and 8:30 variants."
    for expr in ["every 12 hours at minute 50", "every day at 8:30", "at 8:30 pm", "every day at 8:30 pm"]:
        parse_kind(rows, "1.3.8", expr, ev, "fugit.nat.hour-minute-phrases")

    ev = "1.4.0 accepts 25-L monthday ranges and weekday work-hour natural expressions."
    for expr in ["0 0 25-L * *", "0 0 25-l * *", "0 0 -7-L * *", "* * last * *", "* * -7--1/2 * *"]:
        parse(rows, "1.4.0", expr, ev, "fugit.cron.last-day-ranges")
        nexts(rows, "1.4.0", expr, "2021-03-01 00:00:00 UTC", 5, ev, "fugit.cron.last-day-ranges-next")
    for expr in ["every weekday 8am to 5pm", "every day from the 25th to the last"]:
        parse_kind(rows, "1.4.0", expr, ev, "fugit.nat.weekday-workhour-and-last-day")

    ev = "1.4.2 fixes previous_time versus last day of month and lets empty cron parse return nil."
    parse_nil(rows, "1.4.2", "", ev, "fugit.cron.empty-string-nil")
    parse_nil(rows, "1.4.2", " ", ev, "fugit.cron.empty-string-nil")
    for expr in ["0 0 L * *", "0 0 -1 * *", "0 0 last * *"]:
        prevs(rows, "1.4.2", expr, "2021-05-01 00:00:00 UTC", 4, ev, "fugit.cron.previous-last-day")

    ev = "1.4.3/1.4.4/1.5.1/1.5.2 fix DST traversal issues."
    for expr, start in [
        ("* * * * * America/New_York", "2021-03-14 01:58:00 America/New_York"),
        ("0 0 * * * Europe/Zurich", "2021-03-27 00:00:00 Europe/Zurich"),
        ("0 0 * * * America/Santiago", "2021-09-04 00:00:00 America/Santiago"),
        ("0 0 1 jan * Australia/Melbourne", "2025-02-26 00:00:00 Australia/Melbourne"),
        ("0 0 1 jan * Europe/Zurich", "2025-02-27 00:00:00 Europe/Zurich"),
    ]:
        nexts(rows, "1.5.2", expr, start, 5, ev, "fugit.cron.dst-next")
        prevs(rows, "1.5.2", expr, start, 5, ev, "fugit.cron.dst-previous")

    ev = "1.4.5 accepts weekday modulo with offsets like Mon%2+2."
    for expr in ["0 8 * * 1%2+2", "0 8 * * Mon%2+2", "30 14 * * 4%4+3 Australia/Melbourne"]:
        parse(rows, "1.4.5", expr, ev, "fugit.cron.modulo-offset-parse")
        nexts(rows, "1.4.5", expr, "2021-04-21 07:00:00 UTC", 5, ev, "fugit.cron.modulo-offset-next", with_rweek=True)

    ev = "1.5.0 accepts noon/midday/12pm natural forms and normalizes 15/30 cron minute syntax."
    for expr in ["at 12 noon", "at 12 midday", "at 12pm", "every day at 12:15 am", "every day at 5:00pm"]:
        parse_kind(rows, "1.5.0", expr, ev, "fugit.nat.noon-midday-12pm")
    for expr in ["15/30 * * * *", "15-40/30 * * * *", "0 4/12 * * *", "0 8/4 * * *"]:
        parse(rows, "1.5.0", expr, ev, "fugit.cron.single-start-step-normalization")
        nexts(rows, "1.5.0", expr, "2021-02-09 19:00:00 UTC", 4, ev, "fugit.cron.single-start-step-next")

    ev = "1.5.3 fixes Fugit::Cron.to_s / to_cron_s with weekday modulo."
    for expr in ["0 13 * * wed%2", "0 13 * * wed%2+1", "0 13 * * 3%2", "0 13 * * 3%2+1"]:
        parse(rows, "1.5.3", expr, ev, "fugit.cron.modulo-to-cron-s")

    ev = "1.6.0 strips input strings before parsing."
    for expr in ["\n45 5 * * sun \n ", " *   *  last  * *\n", " 30 18 * * 2#5  Europe/Paris \n"]:
        parse(rows, "1.6.0", expr, ev, "fugit.cron.strip-input")

    ev = "1.7.0 introduces & day-of-month/day-of-week AND syntax, changes modulo offset handling, and accepts extra commas."
    for expr in ["0 0 */2 * 1-5", "0 0 */2 * 1-5&", "0 0 */2& * 1-5", "0 0 */2& * 1-5&", "59 6 1-7 * 2", "59 6 1-7 * 2&", "59 6 1-7& * 2", "59 6 1-7& * 2&"]:
        parse(rows, "1.7.0", expr, ev, "fugit.cron.day-and-syntax")
        nexts(rows, "1.7.0", expr, "2022-08-09 00:00:00 UTC", 4, ev, "fugit.cron.day-and-next")
    for expr in ["9,,19 * * * *", ",8 * * * *", ",,10,,20, * * * *", "10,,20 * 1,,11,,21, * *", ",,10,,22, * * * * Asia/Omsk"]:
        parse(rows, "1.7.0", expr, ev, "fugit.cron.extra-commas")

    ev = "1.7.1 changes 0/5 hour behavior to every five hours starting at zero."
    for expr in ["0 0/5 * * *", "0 /1 * * *", "0 */1 * * *", "0 7/5 * * *", "0 7-17/5 * * *", "0 7/5 * * * Asia/Kabul"]:
        parse(rows, "1.7.1", expr, ev, "fugit.cron.hour-slash-semantics")
        nexts(rows, "1.7.1", expr, "2022-09-21 00:00:00 UTC", 6, ev, "fugit.cron.hour-slash-next")

    ev = "1.8.0 introduces parse_cronish / do_parse_cronish."
    for expr in ["0 0 1 jan *", "every saturday at noon", "12y12M", "nada"]:
        parse_cronish(rows, "1.8.0", expr, ev, "fugit.parse-cronish")

    ev = "1.9.0 lets natural parser understand last and preserves every-27-hour schedule acceptance."
    for expr in ["every day from the 25th to the last", "every 27 hours", "* */27 * * *", "* */24 * * *", "* */23 * * *"]:
        parse_kind(rows, "1.9.0", expr, ev, "fugit.nat-and-cron.every-27-last")
        if "*" in expr:
            parse(rows, "1.9.0", expr, ev, "fugit.cron.every-27-hour-parse")

    ev = "1.10.0 implements #within, iterator-returning #next, and iterator-returning #prev."
    iterator(rows, "1.10.0", "next_iterator", "0 12 * * mon#2", "2024-02-16 12:00:00 UTC", 5, ev, "fugit.cron.next-iterator")
    iterator(rows, "1.10.0", "prev_iterator", "0 12 * * mon#2", "2024-02-16 12:00:00 UTC", 5, ev, "fugit.cron.prev-iterator")
    within(rows, "1.10.0", "0 12 * * mon#2", "2024-02-16 12:00 UTC", "2024-08-01 12:00 UTC", ev, "fugit.cron.within-range", True)
    within(rows, "1.10.0", "0 12 * * mon#2", "2024-01-16 12:00 UTC", "2024-07-01 12:00 UTC", ev, "fugit.cron.within-start-end", False)

    ev = "1.11.2 ensures specials like @yearly accept a timezone and fixes midnight natural timezone parsing."
    for expr in ["@yearly Asia/Kuala_Lumpur", "@monthly Asia/Jakarta", "@weekly America/Los_Angeles", "@daily Europe/Berlin", "@hourly Asia/Kabul"]:
        parse(rows, "1.11.2", expr, ev, "fugit.cron.specials-with-timezone")
        nexts(rows, "1.11.2", expr, "2025-08-22 00:00:00 UTC", 3, ev, "fugit.cron.specials-with-timezone-next")
    parse_kind(rows, "1.11.2", "every day at midnight America/Los_Angeles", ev, "fugit.nat.midnight-timezone")

    ev = "1.12.0 upgrades et-orbi rweek reference and fixes modulo schedules where one weekday was ignored."
    for ref in ["monday", "sunday"]:
        rweek(rows, "1.12.0", ref, "0 12 * * 0%2+1,3%2+1", "2025-09-25", 7, ev, "fugit.cron.rweek-reference-modulo")
    for expr in ["20 0 * * 2%4", "12 0 * * wed%4,wed%4+1", "12 0 * * wed%4+1,wed%4"]:
        iterator(rows, "1.12.0", "next_iterator", expr, "2025-09-25", 14, ev, "fugit.cron.rweek-modulo-long-sequence", with_rweek=True)

    ev = "1.12.1 fixes Fugit::Cron#to_cron_s to include & when @day_and is set."
    for expr in ["0 0 12,13 * 1-5&", "0 0 12,13& * 1-5", "0 0 12,13& * 1-5&"]:
        parse(rows, "1.12.1", expr, ev, "fugit.cron.to-cron-day-and-preserved")
        equality(rows, "1.12.1", expr, "0 0 12,13 * 1,2,3,4,5&", ev, "fugit.cron.day-and-equality")

    ev = "1.12.2 fixes divide-by-zero handling for zero slash steps."
    for expr in ["*/0 * * * *", "0/0 * * * *", "* */0 * * *", "* * */0 * *", "* * * */0 *", "*/0 * * * * *", "0/0 * * * * *", "* */0 * * * *", "* * */0 * * *", "* * * */0 * *", "* * * * */0 *"]:
        parse_nil(rows, "1.12.2", expr, ev, "fugit.cron.zero-step-rejected")
        do_parse_error(rows, "1.12.2", expr, ev, "fugit.cron.zero-step-do-parse-error")

    ev = "1.12.3 fixes wrap-around weekday ranges with step values."
    for expr in ["58-2/2 * * * 5-1/2", "0 23 * * 5-1/2", "0 0 * * 7-3/2", "0 0 * * fri-mon/2"]:
        parse(rows, "1.12.3", expr, ev, "fugit.cron.wraparound-weekday-range-step")
        nexts(rows, "1.12.3", expr, "2026-07-01 00:00:00 UTC", 7, ev, "fugit.cron.wraparound-weekday-range-step-next")

    ev = "1.13.0 adds random values support in cron strings with ~."
    for expr in ["~ ~ ~ ~ ~", "~30 * * * ~4", "~30/10 * * * ~4/2", "30~ * * * 4~", "30~/10 * * * 4~/2", "* * * 11~4 5~1", "* * * 11~4/2 *"]:
        parse(rows, "1.13.0", expr, ev, "fugit.cron.random-values-average", random="average")
        nexts(rows, "1.13.0", expr, "2026-07-10 00:00:00 UTC", 4, ev, "fugit.cron.random-values-next-average", random="average")
    parse(rows, "1.13.0", "~ ~ ~ ~ ~", ev, "fugit.cron.random-values-disabled", random=False)

    ev = "Public equality, brute frequency, match, and normalization tests preserve externally observable behavior."
    for left, right in [("* * * * *", "* * */1 * *"), ("0 0 * * 7", "0 0 * * 0"), ("0 13 * * wed", "0 13 * * 3")]:
        equality(rows, "1.13.0", left, right, ev, "fugit.cron.equality-normalized")
    for expr, year in [("* * * * *", 2017), ("0 0 * * *", 2017), ("0 0 * * sun", 2016), ("0 0 1 1 *", 2017), ("0 0 29 2 *", 2017)]:
        brute(rows, "1.13.0", expr, year, ev, "fugit.cron.brute-frequency")

    return dedupe(rows)


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = stable_json([row["op"], row["params"]])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def run_ruby(args: list[str], payload: Any) -> Any:
    proc = subprocess.run([str(RUBY), str(RUNNER), *args], input=json.dumps(payload, ensure_ascii=True), text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr + proc.stdout[-2000:])
    return json.loads(proc.stdout)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def write_rpl(path: Path, rows: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    for row in rows:
        lines.append(f"contract {row['name']} {{")
        lines.append(f"  domain: {row['domain']}")
        lines.append(f"  project: {row['project']}")
        lines.append(f"  release: {row['version']}")
        lines.append(f"  capability: {row['capability']}")
        lines.append(f"  op: {row['op']}")
        lines.append(f"  params: {stable_json(row['params'])}")
        if "expected" in row:
            lines.append(f"  expect: {stable_json(row['expected'])}")
        lines.append("}")
    path.write_text("\n\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rubygems_versions = fetch_rubygems_versions()
    tags = git_tags()
    changelog = parse_changelog()
    candidates = build_candidates()

    filled = run_ruby(["--fill"], candidates)
    viable = [
        row
        for row in filled
        if not (isinstance(row.get("expected"), dict) and row["expected"].get("error") is True and row["op"] not in {"do_parse_error"})
    ]

    replay = run_ruby([], viable)
    if not replay["ok"]:
        bad = [r["name"] for r in replay["results"] if not r["ok"]][:10]
        raise RuntimeError(f"replay failed for {bad}")

    mutant = run_ruby(["--mutant"], viable)
    survivors = [row for row, result in zip(viable, mutant["results"]) if result["ok"]]

    summary = {
        "project": PROJECT,
        "latest": LATEST,
        "rubygems_stable_version_count": len(rubygems_versions),
        "git_tag_count": len(tags),
        "changelog_release_count": len(changelog),
        "candidate_count": len(candidates),
        "viable_latest_replay_count": len(viable),
        "latest_replay_mutant_survivor_count": len(survivors),
        "excluded_runtime_error_count": len(filled) - len(viable),
        "mutant_survived_count": len(viable) - len(survivors),
        "by_op": dict(Counter(row["op"] for row in survivors)),
        "by_version": dict(Counter(row["version"] for row in survivors)),
        "by_capability": dict(Counter(row["capability"] for row in survivors)),
        "audited_rubygems_versions": rubygems_versions,
        "audited_tags": tags,
    }

    write_json(OUT_DIR / "all_releases_maximal_language_independent.json", candidates)
    write_rpl(OUT_DIR / "all_releases_maximal_language_independent.rpl", candidates)
    write_json(OUT_DIR / "latest_replay_mutant_verified.json", survivors)
    write_rpl(OUT_DIR / "latest_replay_mutant_verified.rpl", survivors)
    write_json(OUT_DIR / "latest_replay_mutant_verified.summary.json", summary)

    md = [
        "# floraison/fugit Contract Extraction",
        "",
        f"- Latest tested release: `{LATEST}`",
        f"- RubyGems stable versions audited: `{len(rubygems_versions)}`",
        f"- Git tags audited: `{len(tags)}`",
        f"- Changelog releases audited: `{len(changelog)}`",
        f"- Candidate contracts extracted: `{len(candidates)}`",
        f"- Latest replay-viable contracts: `{len(viable)}`",
        f"- Replay + mutant verified latest survivors: `{len(survivors)}`",
        "",
        "## Survivors by Operation",
        "",
    ]
    for op, count in Counter(row["op"] for row in survivors).most_common():
        md.append(f"- `{op}`: {count}")
    md.extend(["", "## Survivors by Version", ""])
    for version, count in Counter(row["version"] for row in survivors).most_common():
        md.append(f"- `{version}`: {count}")
    md.extend(["", "## Human-Readable Contracts", ""])
    for row in survivors:
        md.append(f"- `{row['name']}`: {row['human']}")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    audit = [
        "# Extraction Audit",
        "",
        "Source review pass 1: RubyGems versions, git tags, CHANGELOG, README schedule-expression documentation, and public cron tests.",
        "Source review pass 2: modulo-week, random, timezone, DST, natural schedule-to-cron, parser rejection, iterator, within, and frequency surfaces were revisited for extra externally observable contracts.",
        "",
        "Duration-only and at-time-only release-note items are intentionally excluded from the cron/schedule-expression domain. CI, dependency-only, warning-only, and Ruby-version support changes are audited but not converted into contracts unless they preserve public schedule behavior.",
        "",
        "## RubyGems Stable Versions",
        "",
    ]
    audit.extend(f"- `{version}`" for version in rubygems_versions)
    audit.extend(["", "## Git Tags", ""])
    audit.extend(f"- `{tag}`" for tag in tags)
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
