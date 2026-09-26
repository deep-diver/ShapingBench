#!/usr/bin/env python3
"""Extract litl/backoff release-history contracts and verify them on latest."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "resilience_policy" / "backoff"
RUNNER = ROOT / "tools" / "replay" / "backoff_latest_runner.py"
PRIOR = [
    ROOT / "contracts" / "resilience_policy" / "resilience4j" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "failsafe" / "latest_replay_mutant_verified.json",
]
PYTHON = "/opt/miniconda3/bin/python"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:90]


def version_sort(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)) or (0,)


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return res.read().decode("utf-8", errors="replace")


def fetch_release_history() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    OUT.mkdir(parents=True, exist_ok=True)
    pypi_cache = OUT / "pypi_releases.json"
    gh_cache = OUT / "release_notes.github.json"
    changelog_cache = OUT / "release_notes.changelog.json"
    if pypi_cache.exists() and gh_cache.exists() and changelog_cache.exists():
        pypi = json.loads(pypi_cache.read_text(encoding="utf-8"))
        gh = json.loads(gh_cache.read_text(encoding="utf-8"))
        changelog = json.loads(changelog_cache.read_text(encoding="utf-8"))
        return changelog, gh, pypi

    pypi = fetch_json("https://pypi.org/pypi/backoff/json")
    pypi_releases = [
        {"version": version, "files": files}
        for version, files in sorted(pypi.get("releases", {}).items(), key=lambda kv: version_sort(kv[0]))
    ]
    pypi_out = {
        "info": {
            "name": pypi.get("info", {}).get("name"),
            "version": pypi.get("info", {}).get("version"),
            "summary": pypi.get("info", {}).get("summary"),
        },
        "releases": pypi_releases,
    }
    pypi_cache.write_text(json.dumps(pypi_out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    gh_releases: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = fetch_json(f"https://api.github.com/repos/litl/backoff/releases?per_page=100&page={page}")
        if not batch:
            break
        gh_releases.extend(batch)
        page += 1
    gh = [
        {
            "tag_name": r.get("tag_name") or "",
            "version": (r.get("tag_name") or "").lstrip("v"),
            "published_at": r.get("published_at") or "",
            "body": r.get("body") or "",
            "name": r.get("name") or "",
        }
        for r in gh_releases
    ]
    gh = sorted(gh, key=lambda r: version_sort(r["version"]))
    gh_cache.write_text(json.dumps(gh, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    text = fetch_text("https://raw.githubusercontent.com/litl/backoff/master/CHANGELOG.md")
    parts = re.split(r"(?m)^##\s+\[(v?[^\]]+)\]\s*(?:-\s*([0-9-]+))?\s*$", text)
    changelog: list[dict[str, Any]] = []
    for idx in range(1, len(parts), 3):
        version = parts[idx].strip().lstrip("v")
        date = (parts[idx + 1] or "").strip()
        body = parts[idx + 2].strip()
        changelog.append({"version": version, "date": date, "body": body, "source": "CHANGELOG.md"})
    changelog = sorted(changelog, key=lambda r: version_sort(r["version"]))
    changelog_cache.write_text(json.dumps(changelog, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return changelog, gh, pypi_out


def release_rows() -> list[dict[str, Any]]:
    changelog, gh, pypi = fetch_release_history()
    bodies: dict[str, str] = {}
    dates: dict[str, str] = {}
    for row in changelog:
        bodies[row["version"]] = row.get("body", "")
        dates[row["version"]] = row.get("date", "")
    for row in gh:
        bodies.setdefault(row["version"], row.get("body", ""))
        dates.setdefault(row["version"], (row.get("published_at") or "")[:10])
    versions = [row["version"] for row in pypi["releases"]]
    rows = [
        {
            "version": version,
            "tag_name": f"v{version}",
            "date": dates.get(version, ""),
            "body": bodies.get(version, ""),
            "source": "PyPI+GitHub+CHANGELOG",
        }
        for version in versions
    ]
    return rows


def evidence(release: dict[str, Any], human: str) -> str:
    body = re.sub(r"\s+", " ", release.get("body") or "").strip()
    if body:
        return f"backoff release {release['version']}: {body[:300]}"
    return f"backoff release {release['version']} from PyPI: {human}"


def add(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, op: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    version = release["version"]
    rows.append(
        {
            "name": f"backoff_{version.replace('.', '_').replace('-', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "litl/backoff",
            "domain": "retry_backoff_resilience_policy_engine",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence(release, human),
            "human": human,
            "pass": pass_name,
        }
    )


def base_contracts(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    for kind, kwargs, sends in [
        ("constant", {"interval": 1}, [None, None, None, None]),
        ("constant", {"interval": [0, 1, 2]}, [None, None, None, None]),
        ("expo", {"base": 2, "factor": 1}, [None, None, None, None, None]),
        ("expo", {"base": 3, "factor": 2, "max_value": 20}, [None, None, None, None, None]),
        ("fibo", {}, [None, None, None, None, None, None]),
        ("fibo", {"max_value": 5}, [None, None, None, None, None, None]),
    ]:
        add(rows, release, f"backoff.wait-generator.{kind}", "wait_sequence", {"wait_gen": kind, **kwargs, "sends": sends}, f"{kind} wait generator yields deterministic retry intervals")
    for max_tries in [1, 2, 3, 4, 5]:
        for failures in range(0, min(5, max_tries + 2)):
            add(
                rows,
                release,
                "backoff.on-exception.max-tries",
                "on_exception",
                {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": max_tries, "exceptions": ["transient"], "outcomes": ["throw:transient"] * failures + ["ok"]},
                f"on_exception retries handled exceptions until max_tries={max_tries}, failures={failures}",
            )
    for failures in [1, 2, 3, 4]:
        add(
            rows,
            release,
            "backoff.on-exception.raise-on-giveup",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": failures, "exceptions": ["transient"], "raise_on_giveup": True, "outcomes": ["throw:transient"] * (failures + 1)},
            f"raise_on_giveup=True re-raises final handled exception after {failures} tries",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.on-exception.suppress-on-giveup",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": failures, "exceptions": ["transient"], "raise_on_giveup": False, "outcomes": ["throw:transient"] * (failures + 1)},
            f"raise_on_giveup=False returns None after giveup at {failures} tries",
            "pass2",
        )
    for kind in ["transient", "fatal", "other"]:
        add(
            rows,
            release,
            "backoff.on-exception.exception-classification",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 3, "exceptions": ["transient"], "outcomes": [f"throw:{kind}", "ok"]},
            f"on_exception only retries configured exception class, observed with {kind}",
            "pass2",
        )
    for value in [False, None, 0, "", [], "ok", 1]:
        add(
            rows,
            release,
            "backoff.on-predicate.default-falsey",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "outcomes": [value, "ok"]},
            f"default on_predicate retries falsey value {value!r} and succeeds on truthy value",
        )
    for bad_count in [1, 2, 3, 4]:
        add(
            rows,
            release,
            "backoff.on-predicate.custom-equals",
            "on_predicate",
            {"wait_gen": "expo", "base": 2, "factor": 1, "jitter": "none", "max_tries": bad_count + 1, "predicate": "equals", "predicate_value": "retry", "outcomes": ["retry"] * bad_count + ["ok"]},
            f"custom predicate retries matching result for {bad_count} retry values",
        )
    for args in [[1, 2], ["x"]]:
        add(
            rows,
            release,
            "backoff.handler-details.args-kwargs",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "exceptions": ["transient"], "args": args, "kwargs": {"flag": True}, "outcomes": ["throw:transient", "ok"]},
            f"handler details include target args={args} and kwargs during backoff",
            "pass2",
        )


def release_specific(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    version = release["version"]
    body = (release.get("body") or "").lower()
    if version == "1.0":
        base_contracts(rows, release)
    if "jitter" in body:
        for jitter in ["identity", "plus_one", "zero", "nullary"]:
            add(
                rows,
                release,
                "backoff.jitter.customized-wait",
                "on_exception",
                {"wait_gen": "constant", "interval": 2, "jitter": jitter, "max_tries": 3, "exceptions": ["transient"], "outcomes": ["throw:transient", "throw:transient", "ok"]},
                f"custom jitter={jitter} changes recorded wait without changing retry outcome",
            )
    if "log" in body or "logger" in body or "logging" in body:
        for backoff_level, giveup_level in [("INFO", "ERROR"), ("WARNING", "CRITICAL")]:
            add(
                rows,
                release,
                "backoff.logging.configurable-levels",
                "on_exception",
                {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "exceptions": ["transient"], "logger_capture": True, "backoff_log_level": backoff_level, "giveup_log_level": giveup_level, "outcomes": ["throw:transient", "throw:transient"]},
                f"configured logger records backoff/giveup levels {backoff_level}/{giveup_level}",
                "pass2",
            )
        add(
            rows,
            release,
            "backoff.logging.predicate-level-and-value",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "logger_capture": True, "backoff_log_level": "WARNING", "giveup_log_level": "ERROR", "outcomes": [False, False]},
            "predicate logging reports retried value and giveup attempt",
            "pass2",
        )
    if "stopiteration" in body or "wait generator" in body:
        add(
            rows,
            release,
            "backoff.wait-generator.stopiteration-giveup",
            "on_exception",
            {"wait_gen": "constant", "interval": [1], "jitter": "none", "max_tries": 4, "exceptions": ["transient"], "outcomes": ["throw:transient", "throw:transient", "ok"]},
            "finite iterable wait generator gives up when exhausted",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.wait-generator.iterable-intervals",
            "on_predicate",
            {"wait_gen": "constant", "interval": [1, 3, 5], "jitter": "none", "max_tries": 4, "outcomes": [False, False, False, True]},
            "constant wait generator accepts iterable interval sequences",
            "pass2",
        )
    if "full jitter" in body or "aws" in body:
        add(
            rows,
            release,
            "backoff.jitter.disabled-vs-default-surface",
            "on_predicate",
            {"wait_gen": "expo", "base": 2, "factor": 1, "jitter": "none", "max_tries": 3, "predicate": "equals", "predicate_value": "retry", "outcomes": ["retry", "retry", "ok"]},
            "jitter can be disabled to expose raw exponential intervals",
            "pass2",
        )
    if "runtime" in body or "retry-after" in body:
        for values in [[{"retry_after": 3}, {"retry_after": 0}], [{"retry_after": 1}, {"retry_after": 2}, {"retry_after": 0}]]:
            add(
                rows,
                release,
                "backoff.runtime.wait-from-return-value",
                "on_predicate",
                {"wait_gen": "runtime", "runtime_source": "value", "jitter": "none", "max_tries": 4, "predicate": "dict_retry_after", "outcomes": values},
                f"runtime wait generator derives wait from returned value sequence {values}",
            )
        add(
            rows,
            release,
            "backoff.runtime.wait-from-exception",
            "on_exception",
            {"wait_gen": "runtime", "runtime_source": "exception_attr", "jitter": "none", "max_tries": 3, "exceptions": ["transient"], "outcomes": ["throw:transient:retry_after=3", "ok"]},
            "runtime wait generator derives wait from exception attribute",
            "pass2",
        )
    if "max_time" in body or "max time" in body:
        add(
            rows,
            release,
            "backoff.max-time.immediate-giveup",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_time": 0, "exceptions": ["transient"], "raise_on_giveup": False, "outcomes": ["throw:transient", "ok"]},
            "max_time=0 gives up immediately without sleeping",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.predicate.max-time-immediate-giveup",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_time": 0, "outcomes": [False, True]},
            "predicate retry gives up immediately when max_time is already exhausted",
            "pass2",
        )
    if "giveup" in body or "give up" in body:
        for raise_on_giveup in [False, True]:
            add(
                rows,
                release,
                "backoff.on-exception.giveup-predicate",
                "on_exception",
                {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 4, "exceptions": ["transient"], "giveup_on": "TransientError", "raise_on_giveup": raise_on_giveup, "outcomes": ["throw:transient", "ok"]},
                f"giveup predicate stops retry immediately raise_on_giveup={raise_on_giveup}",
                "pass2",
            )
    if "handler" in body or "details" in body or "event" in body:
        add(
            rows,
            release,
            "backoff.handler-details.exception-included",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "exceptions": ["transient"], "outcomes": ["throw:transient", "ok"]},
            "on_backoff handler details include the caught exception",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.handler-details.value-included",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "outcomes": [False, True]},
            "predicate handler details include the retrying value",
            "pass2",
        )
    if "async" in body or "coroutine" in body or "asyncio" in body:
        for failures in [1, 2]:
            add(
                rows,
                release,
                "backoff.async.on-exception",
                "async_on_exception",
                {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": failures + 1, "exceptions": ["transient"], "outcomes": ["throw:transient"] * failures + ["ok"]},
                f"async on_exception retries coroutine failures={failures}",
            )
        add(
            rows,
            release,
            "backoff.async.on-predicate",
            "async_on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 3, "outcomes": [False, False, True]},
            "async on_predicate retries coroutine return values",
            "pass2",
        )
    if "callable" in body or "runtime configuration" in body:
        add(
            rows,
            release,
            "backoff.runtime-config.callable-max-tries-proxy",
            "on_exception",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 3, "exceptions": ["transient"], "outcomes": ["throw:transient", "throw:transient", "ok"]},
            "runtime configured max_tries preserves retry behavior",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.runtime-config.callable-wait-kwargs",
            "on_exception",
            {"wait_gen": "constant", "interval": 2, "interval_callable": True, "jitter": "none", "max_tries": 3, "exceptions": ["transient"], "outcomes": ["throw:transient", "throw:transient", "ok"]},
            "runtime callable wait_gen kwargs are evaluated before retrying",
            "pass2",
        )
        add(
            rows,
            release,
            "backoff.runtime-config.callable-max-time-immediate",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_time": 0, "max_time_callable": True, "outcomes": [False, True]},
            "runtime callable max_time can force immediate predicate giveup",
            "pass2",
        )
    if version in {"1.4.1", "1.11.1", "2.1.2", "2.2.1"} or "__version__" in body:
        add(
            rows,
            release,
            "backoff.package-metadata.version-export",
            "package_metadata",
            {},
            "package root exposes version and public decorator/wait-generator exports",
            "pass2",
        )
    if version in {"1.0.5"} or "extra sleep" in body or "stop condition" in body:
        add(
            rows,
            release,
            "backoff.on-predicate.no-extra-sleep-on-final-giveup",
            "on_predicate",
            {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "outcomes": [False, False]},
            "on_predicate stop condition gives up without an extra sleep after final try",
            "pass2",
        )
    if version in {"2.1.0", "2.1.1"} or "max_tries/max_time values for every call" in body or "max_tries/max_time callables" in body:
        add(
            rows,
            release,
            "backoff.runtime-config.callable-max-tries-each-call",
            "on_predicate_sequence",
            {"wait_gen": "constant", "interval": 1, "interval_callable": True, "jitter": "none", "max_tries": 2, "max_tries_callable": True, "calls": [[False, True], [False, False, True]]},
            "callable max_tries is evaluated for decorated predicate calls",
            "pass2",
        )
    if version in {"2.0.0", "2.1.0", "2.2.0", "2.2.1"}:
        for op in ["on_exception", "on_predicate", "async_on_exception", "async_on_predicate"]:
            params = {"wait_gen": "constant", "interval": 1, "jitter": "none", "max_tries": 2, "outcomes": ["throw:transient", "ok"] if "exception" in op else [False, True]}
            if "exception" in op:
                params["exceptions"] = ["transient"]
            add(rows, release, "backoff.latest.decorator-surface-stability", op, params, f"latest 2.x decorator surface remains replayable for {op}", "pass2")


def prior_overlap_key(row: dict[str, Any]) -> str:
    cap = row["capability"].lower()
    if "fallback" in cap or "circuitbreaker" in cap or "bulkhead" in cap or "timeout" in cap:
        return cap
    if "wait-generator" in cap or "runtime.wait" in cap or "jitter" in cap or "handler-details" in cap or "async" in cap:
        return "backoff-specific"
    if "on-predicate" in cap:
        return "backoff-specific-predicate"
    return cap


def dedupe_prior(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    prior_caps: set[str] = set()
    for path in PRIOR:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        prior_caps.update(str(row.get("capability", "")).lower() for row in data.get("contracts", []))
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    skipped = 0
    for row in rows:
        key = stable_json([row["capability"], row["op"], row["params"]])
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        semantic = prior_overlap_key(row)
        if semantic in prior_caps:
            skipped += 1
            continue
        out.append(row)
    return out, skipped


def build_candidates() -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    releases = release_rows()
    for release in releases:
        release_specific(rows, release)
    if not any(row["version"] == "1.0" for row in rows):
        base_contracts(rows, releases[0])
    candidates, skipped = dedupe_prior(rows)
    return candidates, releases, skipped


def run_runner(contracts: list[dict[str, Any]], fill: bool = False) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump({"contracts": contracts}, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        cmd = [PYTHON, str(RUNNER), *(["--fill"] if fill else []), str(path)]
        raw = subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.STDOUT)
        start = raw.find("{")
        if start < 0:
            raise RuntimeError(raw)
        return json.loads(raw[start:])["contracts"]
    finally:
        path.unlink(missing_ok=True)


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def deep_equal(a: Any, b: Any) -> bool:
    return stable_json(normalize(a)) == stable_json(normalize(b))


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return value + ["__mutant__"]
    if isinstance(value, dict):
        out = dict(value)
        key = next(iter(out), "__mutant__")
        out[key] = mutate_value(out.get(key))
        return out
    if value is None:
        return "__mutant__"
    return "__mutant__"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    for key in ["values", "waits", "events", "status", "value", "attempts", "errorType"]:
        if key in out:
            out[key] = mutate_value(out[key])
            return out
    out["__mutant__"] = True
    return out


def fill_and_verify(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    filled = run_runner(candidates, fill=True)
    with_expected: list[dict[str, Any]] = []
    for row in filled:
        actual = row.get("actual") or {}
        if actual.get("status") == "unsupported":
            continue
        row["expected"] = row.get("expected") or actual
        row["mutant"] = mutate_expected(row["expected"])
        with_expected.append(row)
    replayed = run_runner(with_expected, fill=False)
    mutants = [{**row, "expected": row["mutant"]} for row in with_expected]
    mutant_replayed = run_runner(mutants, fill=False)
    source_by_name = {row["name"]: row for row in with_expected}
    mutant_by_name = {row["name"]: row.get("actual") for row in mutant_replayed}
    results: list[dict[str, Any]] = []
    survivors: list[dict[str, Any]] = []
    for row in replayed:
        source = source_by_name[row["name"]]
        expected = source["expected"]
        mutant = source["mutant"]
        actual = row.get("actual")
        replay_ok = deep_equal(actual, expected)
        mutant_actual = mutant_by_name[row["name"]]
        mutant_ok = deep_equal(mutant_actual, mutant)
        verified = replay_ok and not mutant_ok
        result = {
            **source,
            "actual": actual,
            "mutant_actual": mutant_actual,
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "status": "passed" if verified else "failed",
        }
        results.append(result)
        if verified:
            survivors.append({k: result[k] for k in ["name", "version", "project", "domain", "capability", "op", "params", "expected", "mutant", "evidence", "human", "pass"]})
    return results, survivors


def write_rpl(rows: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in rows:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  project {json.dumps(row['project'], ensure_ascii=True)}")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  replay {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        if "expected" in row:
            lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_md(candidates: list[dict[str, Any]], results: list[dict[str, Any]], survivors: list[dict[str, Any]], releases: list[dict[str, Any]], skipped: int) -> None:
    by_release: dict[str, Counter[str]] = defaultdict(Counter)
    for row in candidates:
        by_release[row["version"]]["candidates"] += 1
    for row in survivors:
        by_release[row["version"]]["survivors"] += 1
    by_cap = Counter(row["capability"] for row in survivors)
    lines = [
        "# Backoff Contract Extraction",
        "",
        "Latest replay target: `backoff==2.2.1`.",
        "",
        f"PyPI releases inspected: {len(releases)}",
        f"Prior-overlap/dedupe skipped: {skipped}",
        f"Candidate contracts: {len(candidates)}",
        f"Latest replay + mutant survivors: {len(survivors)}",
        "",
        "Note: extraction focuses on `litl/backoff` decorator/wait-generator behavior and avoids generic retry-policy contracts already represented by resilience4j/Failsafe where practical.",
        "",
        "## By Release",
        "",
        "| Release | Candidates | Survivors |",
        "| --- | ---: | ---: |",
    ]
    for release in releases:
        counts = by_release[release["version"]]
        lines.append(f"| `{release['version']}` | {counts['candidates']} | {counts['survivors']} |")
    lines.extend(["", "## Survivors By Capability", "", "| Capability | Count |", "| --- | ---: |"])
    for cap, count in sorted(by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    failures = [row for row in results if row["status"] != "passed"]
    lines.extend(["", "## Failed Verification Samples", "", "| Contract | Capability | Replay | Mutant rejected |", "| --- | --- | ---: | ---: |"])
    for row in failures[:20]:
        lines.append(f"| `{row['name']}` | `{row['capability']}` | {row['replay_passed']} | {row['mutant_rejected']} |")
    (OUT / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    candidates, releases, skipped = build_candidates()
    changelog, gh, pypi = fetch_release_history()
    results, survivors = fill_and_verify(candidates)
    summary = {
        "project": "litl/backoff",
        "domain": "retry_backoff_resilience_policy_engine",
        "latest_replay_target": "backoff==2.2.1",
        "repository_archived": True,
        "pypi_releases_seen": len(releases),
        "github_releases_seen": len(gh),
        "changelog_sections_seen": len(changelog),
        "prior_overlap_dedupe_skipped": skipped,
        "candidate_contracts": len(candidates),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_mutant_rejected": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "by_capability": dict(Counter(row["capability"] for row in survivors)),
        "by_release": {
            release["version"]: {
                "candidates": sum(1 for row in candidates if row["version"] == release["version"]),
                "survivors": sum(1 for row in survivors if row["version"] == release["version"]),
            }
            for release in releases
        },
        "contracts": candidates,
    }
    (OUT / "all_releases_excluding_prior.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(candidates, OUT / "all_releases_excluding_prior.rpl")
    (OUT / "latest_replay_mutant_verified.json").write_text(
        json.dumps(
            {
                "summary": {k: v for k, v in summary.items() if k != "contracts"},
                "results": results,
                "contracts": survivors,
                "survivor_contracts": survivors,
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, OUT / "latest_replay_mutant_verified.rpl")
    write_md(candidates, results, survivors, releases, skipped)
    audit = [
        "# Backoff Extraction Audit",
        "",
        f"PyPI releases inspected: {len(releases)}.",
        f"GitHub releases inspected: {len(gh)}.",
        f"CHANGELOG sections inspected: {len(changelog)}.",
        "The repository is archived; this is retained as a maturity/history candidate but should be noted if the domain requires currently active projects.",
        "Extraction used two passes: direct release-note features, then adjacent externally observable decorator/wait-generator behavior.",
        "Sleep was monkeypatched in the latest runner so waits are observable without real delays.",
        "Prior resilience4j/Failsafe overlap was avoided where practical, retaining backoff-specific decorator, generator, jitter, runtime wait, handler details, and async behavior.",
        "",
        f"Candidate contracts after overlap/dedupe: {len(candidates)}.",
        f"Latest replay/mutant survivors: {len(survivors)}.",
    ]
    (OUT / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "contracts"}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
