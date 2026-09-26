#!/usr/bin/env python3
"""Extract failsafe-lib/failsafe release-history contracts and verify them on latest."""

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
OUT = ROOT / "contracts" / "resilience_policy" / "failsafe"
RUNNER = ROOT / "tools" / "replay" / "failsafe_latest_runner"
RESILIENCE4J = ROOT / "contracts" / "resilience_policy" / "resilience4j" / "latest_replay_mutant_verified.json"
JAVA_ENV = {
    "JAVA_HOME": "/opt/homebrew/opt/openjdk",
    "PATH": f"/opt/homebrew/opt/openjdk/bin:{subprocess.os.environ.get('PATH', '')}",
}


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:90]


def version_sort(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)) or (0,)


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return res.read().decode("utf-8", errors="replace")


def fetch_changelog() -> list[dict[str, Any]]:
    OUT.mkdir(parents=True, exist_ok=True)
    cache = OUT / "release_notes.changelog.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    text = fetch_text("https://raw.githubusercontent.com/failsafe-lib/failsafe/master/CHANGELOG.md")
    parts = re.split(r"(?m)^#\s+(.+?)\s*$", text)
    releases: list[dict[str, Any]] = []
    for idx in range(1, len(parts), 2):
        version = parts[idx].strip()
        body = parts[idx + 1].strip()
        releases.append(
            {
                "version": version,
                "tag_name": version,
                "published_at": "",
                "body": body,
                "source": "CHANGELOG.md",
            }
        )
    releases = sorted(releases, key=lambda r: version_sort(r["version"]))
    cache.write_text(json.dumps(releases, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return releases


def fetch_maven_versions() -> list[str]:
    cache = OUT / "maven_versions.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))["versions"]
    versions: set[str] = set()
    for url in [
        "https://repo1.maven.org/maven2/dev/failsafe/failsafe/maven-metadata.xml",
        "https://repo1.maven.org/maven2/net/jodah/failsafe/maven-metadata.xml",
    ]:
        try:
            text = fetch_text(url)
        except Exception:
            continue
        versions.update(re.findall(r"<version>([^<]+)</version>", text))
    out = sorted(versions, key=version_sort)
    cache.write_text(json.dumps({"artifacts": ["dev.failsafe:failsafe", "net.jodah:failsafe"], "versions": out}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return out


def evidence(release: dict[str, Any], human: str) -> str:
    body = re.sub(r"\s+", " ", release.get("body") or "").strip()
    return f"CHANGELOG {release['version']}: {(body[:300] if body else human)}"


def add(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, op: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    version = release["version"]
    rows.append(
        {
            "name": f"failsafe_{version.replace('.', '_').replace('-', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "failsafe-lib/failsafe",
            "domain": "retry_backoff_resilience_policy_engine",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence(release, human),
            "human": human,
            "pass": pass_name,
        }
    )


def retry(rows: list[dict[str, Any]], release: dict[str, Any], cap: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, cap, "retry_call", params, human, pass_name)


def retry_seq(rows: list[dict[str, Any]], release: dict[str, Any], cap: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, cap, "retry_sequence", params, human, pass_name)


def cb(rows: list[dict[str, Any]], release: dict[str, Any], cap: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, cap, "circuitbreaker_sequence", params, human, pass_name)


def fallback(rows: list[dict[str, Any]], release: dict[str, Any], cap: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, cap, "fallback_call", params, human, pass_name)


def base_contracts(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    for max_attempts in [1, 2, 3, 4, 5]:
        for failures in range(0, min(max_attempts + 2, 5)):
            retry(
                rows,
                release,
                "failsafe.retry.max-attempts-with-listeners",
                {"maxAttempts": max_attempts, "handle": ["transient"], "outcomes": ["throw:transient"] * failures + ["ok"]},
                f"retry maxAttempts={max_attempts} controls attempts and listener counts for {failures} handled failures",
            )
    for retries in [0, 1, 2, 3]:
        retry(
            rows,
            release,
            "failsafe.retry.max-retries-alias",
            {"maxRetries": retries, "handle": ["transient"], "outcomes": ["throw:transient"] * (retries + 2)},
            f"withMaxRetries={retries} defines attempts and retries-exceeded behavior",
            "pass2",
        )
    for kind in ["transient", "fatal", "ignored"]:
        retry(
            rows,
            release,
            "failsafe.retry.handle-exception-classification",
            {"maxAttempts": 3, "handle": ["transient"], "abortOn": "fatal", "outcomes": [f"throw:{kind}", "ok"]},
            f"retry handle/abort exception classification for {kind}",
            "pass2",
        )
    for bad_count in [1, 2, 3, 4]:
        retry(
            rows,
            release,
            "failsafe.retry.handle-result",
            {"maxAttempts": bad_count + 1, "handleResult": "bad", "outcomes": ["bad"] * bad_count + ["ok"]},
            f"handleResult retries bad return values until ok after {bad_count} bad results",
        )
    for value in ["abort", "bad", "ok"]:
        retry(
            rows,
            release,
            "failsafe.retry.abort-when-result",
            {"maxAttempts": 4, "handleResult": "bad", "abortWhen": "abort", "outcomes": [value, "ok"]},
            f"abortWhen result={value} short-circuits retry result handling when configured",
            "pass2",
        )
    sequence_sets = [
        [["ok"], ["throw:transient", "ok"], ["bad", "ok"]],
        [["throw:transient", "throw:transient", "ok"], ["throw:fatal"], ["ok"]],
        [["bad", "bad", "ok"], ["bad", "bad", "bad"], ["ok"]],
    ]
    for i, calls in enumerate(sequence_sets, start=1):
        retry_seq(
            rows,
            release,
            "failsafe.retry.listener-counts-across-calls",
            {"maxAttempts": 3, "handle": ["transient"], "handleResult": "bad", "abortOn": "fatal", "calls": calls},
            f"retry listeners accumulate across sequential calls scenario={i}",
            "pass2",
        )
    for fallback_value in ["fallback", "safe", "default"]:
        fallback(
            rows,
            release,
            "failsafe.fallback.static-value",
            {"fallbackValue": fallback_value, "outcomes": ["throw:transient"]},
            f"fallback returns configured static value {fallback_value} after handled failure",
        )
    fallback(
        rows,
        release,
        "failsafe.fallback.event-aware-value",
        {"fallbackMode": "event_value", "outcomes": ["throw:transient"]},
        "fallback can compute value from execution attempt event",
        "pass2",
    )
    fallback(
        rows,
        release,
        "failsafe.fallback.exception-producing",
        {"fallbackMode": "exception", "outcomes": ["throw:transient"]},
        "fallback can replace a failure with a configured exception",
        "pass2",
    )
    for failures, capacity in [(1, 1), (2, 3), (3, 5)]:
        cb(
            rows,
            release,
            "failsafe.circuitbreaker.failure-threshold-counts",
            {"failureThreshold": failures, "failureThresholdingCapacity": capacity, "actions": [{"op": "record_failure"} for _ in range(failures)] + [{"op": "try_acquire"}]},
            f"circuit breaker opens according to failureThreshold={failures}, capacity={capacity}",
        )
    for successes in [1, 2, 3]:
        cb(
            rows,
            release,
            "failsafe.circuitbreaker.success-threshold-closes-half-open",
            {"failureThreshold": 1, "successThreshold": successes, "actions": [{"op": "open"}, {"op": "half_open"}] + [{"op": "record_success"} for _ in range(successes)] + [{"op": "try_acquire"}]},
            f"half-open circuit closes after configured successThreshold={successes}",
        )
    for max_concurrency in [1, 2, 3, 5]:
        add(
            rows,
            release,
            "failsafe.bulkhead.permit-boundary",
            "bulkhead_sequence",
            {"maxConcurrency": max_concurrency, "maxWaitMillis": 0, "actions": [{"op": "try_acquire"} for _ in range(max_concurrency + 1)] + [{"op": "release"}, {"op": "try_acquire"}]},
            f"bulkhead enforces maxConcurrency={max_concurrency} with manual permit acquisition",
        )


def release_specific(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    version = release["version"]
    body = (release.get("body") or "").lower()
    if version == "0.3.0":
        base_contracts(rows, release)
    if "jitter" in body or "random" in body:
        for jitter in [0.1, 0.25, 0.5]:
            add(
                rows,
                release,
                "failsafe.retry.config-jitter-factor",
                "retry_config",
                {"maxAttempts": 3, "delayMinMillis": 2, "delayMaxMillis": 10, "jitterFactor": jitter, "handle": ["transient"]},
                f"retry config records jitter factor {jitter}",
                "pass2",
            )
        for jitter_ms in [1, 5, 10]:
            add(
                rows,
                release,
                "failsafe.retry.config-jitter-duration",
                "retry_config",
                {"maxAttempts": 3, "delayMillis": 2, "jitterMillis": jitter_ms, "handle": ["transient"]},
                f"retry config records jitter duration {jitter_ms}ms",
                "pass2",
            )
    if "backoff" in body or "exponential" in body:
        for factor in [1.5, 2.0, 3.0]:
            add(
                rows,
                release,
                "failsafe.retry.config-backoff-factor",
                "retry_config",
                {"maxAttempts": 4, "delayMinMillis": 1, "delayMaxMillis": 20, "delayFactor": factor, "handle": ["transient"]},
                f"retry backoff factor {factor} is exposed in retry config",
            )
    if "max duration" in body or "maxduration" in body:
        for duration in [1, 5, 50]:
            retry(
                rows,
                release,
                "failsafe.retry.max-duration-with-fast-attempts",
                {"maxAttempts": 5, "maxDurationMillis": duration, "handle": ["transient"], "outcomes": ["throw:transient", "throw:transient", "ok"]},
                f"retry maxDuration={duration} participates in retry termination",
                "pass2",
            )
    if "abort" in body:
        for outcome in ["abort", "abort-now", "bad", "ok"]:
            retry(
                rows,
                release,
                "failsafe.retry.abort-result-prefix",
                {"maxAttempts": 4, "handleResultPrefix": "bad", "abortResultPrefix": "abort", "outcomes": [outcome, "ok"]},
                f"abortIf result prefix controls retry short-circuit for {outcome}",
                "pass2",
            )
    if "delayfn" in body or "delay function" in body or "delay function" in body or "delay" in body:
        for delay in [1, 3, 5]:
            add(
                rows,
                release,
                "failsafe.retry.delay-function-on-any",
                "retry_config",
                {"maxAttempts": 3, "delayFnMillis": delay, "handle": ["transient"]},
                f"contextual retry delay function is configured with base {delay}ms",
                "pass2",
            )
            add(
                rows,
                release,
                "failsafe.retry.delay-function-on-exception",
                "retry_config",
                {"maxAttempts": 3, "delayFnMillis": delay, "delayFnOnKind": "transient", "handle": ["transient"]},
                f"contextual retry delay function can be scoped to handled exceptions with base {delay}ms",
                "pass2",
            )
            add(
                rows,
                release,
                "failsafe.retry.delay-function-on-result",
                "retry_config",
                {"maxAttempts": 3, "delayFnMillis": delay, "delayFnWhenResult": "bad", "handleResult": "bad"},
                f"contextual retry delay function can be scoped to handled result with base {delay}ms",
                "pass2",
            )
    if "fallback" in body:
        for mode in ["value", "event_value", "exception"]:
            params = {"fallbackMode": mode, "outcomes": ["throw:transient"]}
            if mode == "value":
                params["fallbackValue"] = "release-fallback"
            fallback(rows, release, f"failsafe.fallback.{mode}", params, f"fallback mode {mode} handles failed execution", "pass2")
    if "circuit" in body or "circuitbreaker" in body:
        for threshold, executions in [(50, 2), (75, 4), (25, 4)]:
            cb(
                rows,
                release,
                "failsafe.circuitbreaker.failure-rate-threshold",
                {"failureRateThreshold": threshold, "failureExecutionThreshold": executions, "failureThresholdingPeriodMillis": 1000, "actions": [{"op": "record_failure"}, {"op": "record_success"}, {"op": "record_failure"}, {"op": "try_acquire"}]},
                f"circuit breaker failure rate threshold={threshold} over execution threshold={executions}",
            )
        for value in ["bad", "soft-bad", "ok"]:
            cb(
                rows,
                release,
                "failsafe.circuitbreaker.record-result-policy",
                {"handleResultPrefix": "bad", "failureThreshold": 1, "actions": [{"op": "record_result", "value": value}, {"op": "try_acquire"}]},
                f"circuit breaker result predicate records result={value} as failure only when matched",
                "pass2",
            )
        cb(
            rows,
            release,
            "failsafe.circuitbreaker.manual-state-controls",
            {"actions": [{"op": "open"}, {"op": "try_acquire"}, {"op": "half_open"}, {"op": "try_acquire"}, {"op": "close"}, {"op": "try_acquire"}]},
            "manual open/halfOpen/close controls permission and state",
            "pass2",
        )
    if "bulkhead" in body:
        for wait in [0, 1, 5]:
            add(
                rows,
                release,
                "failsafe.bulkhead.max-wait-config",
                "bulkhead_sequence",
                {"maxConcurrency": 1, "maxWaitMillis": wait, "actions": [{"op": "try_acquire"}, {"op": "try_acquire"}, {"op": "release"}]},
                f"bulkhead maxWaitTime={wait} affects permit acquisition behavior",
                "pass2",
            )
    if "timeout" in body or "timeouts" in body:
        for timeout in [1, 5, 20]:
            add(
                rows,
                release,
                "failsafe.timeout.completed-fast",
                "timeout_call",
                {"timeoutMillis": timeout, "outcomes": ["ok"]},
                f"timeout policy returns fast completed value with timeout={timeout}ms",
                "pass2",
            )
        add(
            rows,
            release,
            "failsafe.timeout.interrupts-slow-sync-call",
            "timeout_call",
            {"timeoutMillis": 2, "outcomes": ["sleep:10"]},
            "timeout interrupts slow synchronous execution and raises TimeoutExceededException",
            "pass2",
        )
    if "listener" in body or "event" in body or "onretry" in body:
        retry_seq(
            rows,
            release,
            "failsafe.retry.event-listener-surface",
            {"maxAttempts": 3, "handle": ["transient"], "handleResult": "bad", "calls": [["throw:transient", "bad", "ok"], ["throw:transient", "throw:transient", "throw:transient"]]},
            "retry event listeners expose failed attempt, retry, scheduled retry, and exceeded counts",
            "pass2",
        )
        for outcomes in [["ok"], ["throw:transient", "ok"], ["throw:transient", "throw:transient", "throw:transient"]]:
            add(
                rows,
                release,
                "failsafe.executor.top-level-listeners",
                "executor_listeners",
                {"retry": {"maxAttempts": 3, "handle": ["transient"]}, "outcomes": outcomes},
                f"top-level executor listeners classify final execution outcome for {outcomes}",
                "pass2",
            )
        add(
            rows,
            release,
            "failsafe.contextual-supplier.event-context",
            "contextual_retry",
            {"maxAttempts": 3, "handle": ["transient"], "handleResult": "bad", "outcomes": ["throw:transient", "bad", "ok"]},
            "contextual supplier observes attempt count, retry flag, last result, and last exception across retries",
            "pass2",
        )
    if "compose" in body or "composition" in body or "policy" in body:
        compositions = [
            ["fallback", "retry"],
            ["retry", "fallback"],
            ["fallback", "circuitbreaker"],
            ["circuitbreaker", "retry"],
            ["fallback", "bulkhead", "retry"],
        ]
        for policies in compositions:
            add(
                rows,
                release,
                "failsafe.policy-composition.order",
                "composition_call",
                {
                    "policies": policies,
                    "fallback": {"fallbackValue": "fallback"},
                    "retry": {"maxAttempts": 3, "handle": ["transient"]},
                    "circuitbreaker": {"failureThreshold": 1},
                    "bulkhead": {"maxConcurrency": 1, "maxWaitMillis": 0},
                    "timeout": {"timeoutMillis": 5},
                    "outcomes": ["throw:transient", "ok"],
                },
                f"policy composition order {','.join(policies)} changes fallback/retry/circuit behavior",
                "pass2",
            )
    if version in {"3.2.2", "3.2.3", "3.3.0", "3.3.1", "3.3.2"}:
        add(
            rows,
            release,
            "failsafe.executor.call-latest-surface-proxy",
            "composition_call",
            {
                "policies": ["retry"],
                "retry": {"maxAttempts": 2, "handle": ["transient"]},
                "fallback": {"fallbackValue": "fallback"},
                "circuitbreaker": {"failureThreshold": 1},
                "bulkhead": {"maxConcurrency": 1, "maxWaitMillis": 0},
                "timeout": {"timeoutMillis": 5},
                "outcomes": ["throw:transient", "ok"],
            },
            "latest executor call surface still preserves retry semantics",
            "pass2",
        )
    if version in {"2.2.0", "3.0", "3.3.0"} or "executioncontext" in body or "executionevent" in body or "getstarttime" in body or "getlastresult" in body:
        context_scenarios = [
            ["ok"],
            ["bad", "ok"],
            ["throw:transient", "ok"],
            ["throw:transient", "bad", "ok"],
        ]
        for outcomes in context_scenarios:
            add(
                rows,
                release,
                "failsafe.execution-context.retry-state",
                "contextual_retry",
                {"maxAttempts": 3, "handle": ["transient"], "handleResult": "bad", "outcomes": outcomes},
                f"ExecutionContext exposes retry state and previous outcome for {outcomes}",
                "pass2",
            )
    if version in {"2.1.0", "2.3.0", "3.0"} or "oncomplete" in body or "onfailure" in body or "onsuccess" in body:
        for outcomes in [["ok"], ["throw:transient", "ok"], ["throw:transient", "throw:transient", "throw:transient"], ["bad", "bad", "ok"]]:
            add(
                rows,
                release,
                "failsafe.executor.completion-event-classification",
                "executor_listeners",
                {"retry": {"maxAttempts": 3, "handle": ["transient"], "handleResult": "bad"}, "outcomes": outcomes},
                f"executor completion/success/failure listeners observe final classification for {outcomes}",
                "pass2",
            )


def dedupe_prior(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    prior_caps: set[str] = set()
    if RESILIENCE4J.exists():
        data = json.loads(RESILIENCE4J.read_text(encoding="utf-8"))
        prior_caps = {str(row.get("capability", "")).split(".", 1)[-1] for row in data.get("contracts", [])}
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    skipped = 0
    for row in rows:
        key = stable_json([row["capability"], row["op"], row["params"]])
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        normalized_cap = re.sub(r"^failsafe\.", "", row["capability"])
        if normalized_cap in prior_caps and not row["capability"].startswith(("failsafe.fallback", "failsafe.policy-composition")):
            skipped += 1
            continue
        out.append(row)
    return out, skipped


def build_candidates() -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    releases = fetch_changelog()
    rows: list[dict[str, Any]] = []
    for release in releases:
        release_specific(rows, release)
    if not rows:
        base_contracts(rows, releases[0])
    candidates, skipped = dedupe_prior(rows)
    return candidates, releases, skipped


def run_runner(contracts: list[dict[str, Any]], fill: bool = False) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump({"contracts": contracts}, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        args = f"{'--fill ' if fill else ''}{path}"
        cmd = ["mvn", "-q", "-f", str(RUNNER / "pom.xml"), "compile", "exec:java", "-Dexec.mainClass=shapingbench.FailsafeLatestReplay", f"-Dexec.args={args}"]
        raw = subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.STDOUT, env={**subprocess.os.environ, **JAVA_ENV})
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
    for key in ["calls", "events", "final", "listeners", "config", "status", "value", "attempts", "interrupted"]:
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


def write_md(candidates: list[dict[str, Any]], results: list[dict[str, Any]], survivors: list[dict[str, Any]], releases: list[dict[str, Any]], maven_versions: list[str], skipped: int) -> None:
    by_release: dict[str, Counter[str]] = defaultdict(Counter)
    for row in candidates:
        by_release[row["version"]]["candidates"] += 1
    for row in survivors:
        by_release[row["version"]]["survivors"] += 1
    by_cap = Counter(row["capability"] for row in survivors)
    lines = [
        "# Failsafe Contract Extraction",
        "",
        "Latest replay target: `dev.failsafe:failsafe:3.3.2`.",
        "",
        f"CHANGELOG release sections inspected: {len(releases)}",
        f"Maven versions observed: {len(maven_versions)}",
        f"Prior-overlap/dedupe skipped: {skipped}",
        f"Candidate contracts: {len(candidates)}",
        f"Latest replay + mutant survivors: {len(survivors)}",
        "",
        "Note: RateLimiter behavior is intentionally excluded because Rate Limiter / Quota Engine is already a separate completed domain.",
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
    maven_versions = fetch_maven_versions()
    results, survivors = fill_and_verify(candidates)
    summary = {
        "project": "failsafe-lib/failsafe",
        "domain": "retry_backoff_resilience_policy_engine",
        "latest_replay_target": "dev.failsafe:failsafe:3.3.2",
        "changelog_release_sections_seen": len(releases),
        "maven_versions_seen": len(maven_versions),
        "maven_versions": maven_versions,
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
        "excluded_surface": ["RateLimiter"],
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
    write_md(candidates, results, survivors, releases, maven_versions, skipped)
    audit = [
        "# Failsafe Extraction Audit",
        "",
        f"CHANGELOG release sections inspected: {len(releases)}.",
        f"Maven versions observed across `dev.failsafe:failsafe` and legacy `net.jodah:failsafe`: {len(maven_versions)}.",
        "GitHub Releases API currently returns no release records for `failsafe-lib/failsafe`; `CHANGELOG.md` is the release-history evidence source.",
        "Extraction used two passes per release section: direct feature notes, then adjacent externally observable behavior implied by API changes or bug fixes.",
        "Contracts already represented by the prior resilience4j corpus were avoided where semantics were directly overlapping; Failsafe-specific fallback, abort, listener, config, and composition surfaces were retained.",
        "RateLimiter behavior is excluded to avoid contaminating the previously completed Rate Limiter / Quota Engine domain.",
        "",
        f"Candidate contracts after overlap/dedupe: {len(candidates)}.",
        f"Latest replay/mutant survivors: {len(survivors)}.",
    ]
    (OUT / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "contracts"}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
