#!/usr/bin/env python3
"""Extract resilience4j release-history contracts and verify them on the latest release."""

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
OUT = ROOT / "contracts" / "resilience_policy" / "resilience4j"
RUNNER = ROOT / "tools" / "replay" / "resilience4j_latest_runner"
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


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.loads(res.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=30) as res:
        return res.read().decode("utf-8", errors="replace")


def fetch_releases() -> list[dict[str, Any]]:
    OUT.mkdir(parents=True, exist_ok=True)
    cache = OUT / "release_notes.github.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    releases: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = fetch_json(f"https://api.github.com/repos/resilience4j/resilience4j/releases?per_page=100&page={page}")
        if not batch:
            break
        releases.extend(batch)
        page += 1
    normalized = [
        {
            "tag_name": r.get("tag_name") or "",
            "version": (r.get("tag_name") or "").lstrip("v"),
            "name": r.get("name") or "",
            "published_at": r.get("published_at") or "",
            "body": r.get("body") or "",
        }
        for r in releases
    ]
    normalized = sorted(normalized, key=lambda r: (r.get("published_at") or "", version_sort(r.get("version") or "")))
    cache.write_text(json.dumps(normalized, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return normalized


def fetch_maven_versions() -> list[str]:
    cache = OUT / "maven_versions.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))["versions"]
    url = "https://repo1.maven.org/maven2/io/github/resilience4j/resilience4j-retry/maven-metadata.xml"
    try:
        text = fetch_text(url)
        versions = sorted(set(re.findall(r"<version>([^<]+)</version>", text)), key=version_sort)
    except Exception:
        versions = []
    cache.write_text(json.dumps({"artifact": "io.github.resilience4j:resilience4j-retry", "versions": versions}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return versions


def evidence(release: dict[str, Any], human: str) -> str:
    body = re.sub(r"\s+", " ", release.get("body") or "").strip()
    if body:
        return f"GitHub release {release.get('tag_name')}: {body[:300]}"
    return f"GitHub release {release.get('tag_name')}: {human}"


def add(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, op: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    key = hashlib.sha256(stable_json([capability, op, params]).encode()).hexdigest()[:12]
    version = release["version"]
    rows.append(
        {
            "name": f"resilience4j_{version.replace('.', '_').replace('-', '_')}_{slug(capability)}_{key}",
            "version": version,
            "project": "resilience4j/resilience4j",
            "domain": "retry_backoff_resilience_policy_engine",
            "capability": capability,
            "op": op,
            "params": params,
            "evidence": evidence(release, human),
            "human": human,
            "pass": pass_name,
        }
    )


def retry_call(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, capability, "retry_call", params, human, pass_name)


def retry_sequence(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, capability, "retry_sequence", params, human, pass_name)


def cb_seq(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, capability, "circuitbreaker_sequence", params, human, pass_name)


def bh_seq(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    add(rows, release, capability, "bulkhead_sequence", params, human, pass_name)


def base_retry(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    for attempts in [1, 2, 3, 4, 5]:
        for failures in range(0, min(5, attempts + 2)):
            outcomes = ["throw:transient"] * failures + ["ok"]
            retry_call(
                rows,
                release,
                "retry.exception.max-attempts-boundary",
                {"maxAttempts": attempts, "waitMillis": 0, "retryExceptions": ["transient"], "outcomes": outcomes},
                f"retry returns success only if transient failures fit within maxAttempts={attempts}, failures={failures}",
            )
    for attempts in [2, 3, 4]:
        retry_call(
            rows,
            release,
            "retry.exception.exhaustion",
            {
                "maxAttempts": attempts,
                "waitMillis": 0,
                "retryExceptions": ["transient"],
                "outcomes": ["throw:transient"] * (attempts + 2),
            },
            f"retry stops after maxAttempts={attempts} and exposes final exception",
        )
    for wait in [0, 1, 10]:
        add(
            rows,
            release,
            "retry.config.fixed-wait",
            "retry_config",
            {"maxAttempts": 3, "waitMillis": wait, "interval": "fixed", "initialIntervalMillis": wait, "intervalAttempts": [1, 2, 3]},
            f"retry fixed wait duration is exposed through interval function for {wait}ms",
            "pass2",
        )
    for max_attempts in [1, 2, 3]:
        retry_call(
            rows,
            release,
            "retry.events.published-per-retry",
            {"maxAttempts": max_attempts + 1, "waitMillis": 0, "retryExceptions": ["transient"], "outcomes": ["throw:transient"] * max_attempts + ["ok"]},
            f"retry publishes one retry event for each retry attempt before success ({max_attempts})",
            "pass2",
        )
    sequence_sets = [
        [["ok"], ["throw:transient", "ok"], ["throw:transient", "throw:transient", "ok"]],
        [["throw:transient", "ok"], ["ok"], ["throw:transient", "throw:transient", "throw:transient"]],
        [["throw:runtime"], ["throw:transient", "ok"], ["ok"]],
    ]
    for idx, calls in enumerate(sequence_sets, start=1):
        retry_sequence(
            rows,
            release,
            "retry.metrics.accumulate-across-calls",
            {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["transient", "runtime"], "calls": calls},
            f"retry metrics accumulate across multiple decorated calls scenario={idx}",
            "pass2",
        )
    for kind in ["ignored", "runtime"]:
        retry_call(
            rows,
            release,
            "retry.exception-classification",
            {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["transient"], "ignoreExceptions": ["ignored"], "outcomes": [f"throw:{kind}", "ok"]},
            f"retry exception classification decides whether {kind} is retried or ignored",
            "pass2",
        )


def base_circuitbreaker(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    for threshold in [25, 50, 75, 100]:
        for failures, successes in [(1, 3), (2, 2), (3, 1), (4, 0)]:
            actions = [{"op": "error"}] * failures + [{"op": "success"}] * successes + [{"op": "try_acquire"}]
            cb_seq(
                rows,
                release,
                "circuitbreaker.failure-rate-threshold",
                {"failureRateThreshold": threshold, "minimumNumberOfCalls": 4, "slidingWindowSize": 4, "actions": actions},
                f"circuit breaker opens when failure rate crosses threshold={threshold} after {failures}/{failures + successes} failures",
            )
    for min_calls in [1, 2, 3, 4, 5]:
        cb_seq(
            rows,
            release,
            "circuitbreaker.minimum-calls-before-rate",
            {"failureRateThreshold": 50, "minimumNumberOfCalls": min_calls, "slidingWindowSize": 5, "actions": [{"op": "error"}, {"op": "try_acquire"}]},
            f"circuit breaker does not evaluate failure rate before minimumNumberOfCalls={min_calls}",
        )
    for size in [2, 3, 4, 5, 8]:
        cb_seq(
            rows,
            release,
            "circuitbreaker.count-sliding-window",
            {
                "failureRateThreshold": 50,
                "minimumNumberOfCalls": min(2, size),
                "slidingWindowSize": size,
                "actions": [{"op": "success"}, {"op": "error"}, {"op": "success"}, {"op": "error"}, {"op": "try_acquire"}],
            },
            f"count-based sliding window of size {size} controls buffered calls and failure rate",
        )
    for duration in [1, 50, 100]:
        cb_seq(
            rows,
            release,
            "circuitbreaker.slow-call-rate",
            {
                "failureRateThreshold": 100,
                "slowCallRateThreshold": 50,
                "slowCallMillis": duration,
                "minimumNumberOfCalls": 2,
                "slidingWindowSize": 2,
                "actions": [{"op": "success", "durationMillis": duration}, {"op": "success", "durationMillis": duration + 1}, {"op": "try_acquire"}],
            },
            f"slow-call threshold marks calls slower than {duration}ms and can open the circuit",
            "pass2",
        )
    for wait in [1, 10, 100]:
        cb_seq(
            rows,
            release,
            "circuitbreaker.open-to-half-open-after-wait",
            {
                "failureRateThreshold": 50,
                "minimumNumberOfCalls": 1,
                "slidingWindowSize": 1,
                "waitOpenMillis": wait,
                "halfOpenPermits": 2,
                "actions": [{"op": "error"}, {"op": "try_acquire"}, {"op": "advance", "millis": wait}, {"op": "try_acquire"}, {"op": "try_acquire"}, {"op": "try_acquire"}],
            },
            f"open circuit denies calls until waitDurationInOpenState={wait}ms elapses, then limits half-open probes",
        )
    for state in ["CLOSED", "OPEN", "HALF_OPEN", "DISABLED", "METRICS_ONLY", "FORCED_OPEN"]:
        add(
            rows,
            release,
            "circuitbreaker.config.initial-state",
            "circuitbreaker_config",
            {"initialState": state, "failureRateThreshold": 50, "minimumNumberOfCalls": 2, "slidingWindowSize": 2},
            f"circuit breaker can be initialized in {state} state from config",
            "pass2",
        )


def release_specific(rows: list[dict[str, Any]], release: dict[str, Any]) -> None:
    version = release["version"]
    body = (release.get("body") or "").lower()
    if version == "0.7.1":
        base_retry(rows, release)
        base_circuitbreaker(rows, release)
        for initial, multiplier, cap in [(1, 2.0, 10), (10, 2.0, 100), (50, 1.5, 200)]:
            add(
                rows,
                release,
                "retry.backoff.exponential",
                "retry_config",
                {
                    "maxAttempts": 5,
                    "waitMillis": initial,
                    "interval": "exponential",
                    "initialIntervalMillis": initial,
                    "multiplier": multiplier,
                    "maxIntervalMillis": cap,
                    "intervalAttempts": [1, 2, 3, 4, 5, 8],
                },
                f"retry interval can use exponential backoff initial={initial}, multiplier={multiplier}, max={cap}",
            )
        cb_seq(
            rows,
            release,
            "circuitbreaker.events.ignored-error",
            {
                "ignoreExceptions": ["ignored"],
                "failureRateThreshold": 50,
                "minimumNumberOfCalls": 1,
                "slidingWindowSize": 2,
                "actions": [{"op": "error", "kind": "ignored"}, {"op": "try_acquire"}],
            },
            "ignored exceptions publish ignored-error events and do not count as failures",
            "pass2",
        )
    if version == "0.8.0" or "force' state transitions" in body or "not permitted" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.manual-state-transitions",
            {"actions": [{"op": "transition_open"}, {"op": "try_acquire"}, {"op": "transition_half_open"}, {"op": "try_acquire"}, {"op": "transition_closed"}, {"op": "try_acquire"}]},
            "manual circuit-breaker state transitions affect call permission",
        )
        cb_seq(
            rows,
            release,
            "circuitbreaker.open-not-permitted-metric",
            {"actions": [{"op": "transition_open"}, {"op": "try_acquire"}, {"op": "try_acquire"}, {"op": "execute_success"}]},
            "open circuit breaker records not-permitted calls and rejects decorated execution",
            "pass2",
        )
    if version == "0.8.1" or "returns a list of all managed circuitbreaker" in body:
        add(rows, release, "registry.managed-circuitbreaker-list", "registry_probe", {"type": "circuitbreaker"}, "registry exposes all managed circuit breaker instances", "pass2")
    if version == "0.8.2" or "execute methods to circuitbreaker interface" in body or "completablefuture" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.execute-method-records",
            {"failureRateThreshold": 50, "minimumNumberOfCalls": 2, "slidingWindowSize": 2, "actions": [{"op": "execute_success", "value": "ok"}, {"op": "execute_error"}, {"op": "try_acquire"}]},
            "execute methods decorate and record success/failure in a single call",
        )
        for order in ["retry_outside_circuitbreaker", "circuitbreaker_outside_retry"]:
            add(
                rows,
                release,
                "composition.retry-circuitbreaker-order",
                "policy_composition",
                {
                    "order": order,
                    "retry": {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["transient"]},
                    "circuitbreaker": {"failureRateThreshold": 50, "minimumNumberOfCalls": 2, "slidingWindowSize": 2},
                    "outcomes": ["throw:transient", "ok"],
                },
                f"retry and circuit breaker composition order changes which policy records transient failure: {order}",
                "pass2",
            )
    if version == "0.10.0" or "failure rate threshold < 1" in body or "eventpublisher" in body:
        for threshold in [0.1, 0.5, 0.9]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.fractional-failure-threshold",
                {"failureRateThreshold": threshold, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "error"}, {"op": "try_acquire"}]},
                f"failure rate threshold below 1 is accepted and opens after a failure threshold={threshold}",
            )
    if version == "0.11.0" or "dynamic bulkhead configuration" in body or "bulkhead metrics" in body:
        for max_calls in [1, 2, 3]:
            bh_seq(
                rows,
                release,
                "bulkhead.permission-boundary",
                {"maxConcurrentCalls": max_calls, "maxWaitMillis": 0, "actions": [{"op": "try_acquire"} for _ in range(max_calls + 1)] + [{"op": "release"}, {"op": "try_acquire"}]},
                f"bulkhead grants at most {max_calls} concurrent calls and exposes available-call metrics",
            )
            bh_seq(
                rows,
                release,
                "bulkhead.execute-releases-permit",
                {"maxConcurrentCalls": max_calls, "maxWaitMillis": 0, "actions": [{"op": "execute_success", "value": "ok"}, {"op": "try_acquire"}]},
                f"bulkhead decorated success releases its permit for maxConcurrentCalls={max_calls}",
                "pass2",
            )
            bh_seq(
                rows,
                release,
                "bulkhead.execute-error-releases-permit",
                {"maxConcurrentCalls": max_calls, "maxWaitMillis": 0, "actions": [{"op": "execute_error"}, {"op": "try_acquire"}]},
                f"bulkhead decorated failure releases its permit for maxConcurrentCalls={max_calls}",
                "pass2",
            )
        bh_seq(
            rows,
            release,
            "bulkhead.dynamic-config-change",
            {"maxConcurrentCalls": 1, "actions": [{"op": "try_acquire"}, {"op": "change_config", "config": {"maxConcurrentCalls": 2, "maxWaitMillis": 0}}, {"op": "try_acquire"}]},
            "bulkhead config can be changed dynamically and affects later permission attempts",
            "pass2",
        )
    if version == "0.12.0" or "reset method to circuit breaker" in body or "disable and force_open states" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.reset-clears-metrics",
            {"minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "error"}, {"op": "reset"}, {"op": "try_acquire"}]},
            "reset returns circuit breaker to closed state and clears recorded metrics",
        )
        cb_seq(
            rows,
            release,
            "circuitbreaker.disabled-state-permits-without-metrics",
            {"actions": [{"op": "transition_disabled"}, {"op": "error"}, {"op": "success"}, {"op": "try_acquire"}]},
            "disabled circuit breaker permits calls and does not trip on errors",
            "pass2",
        )
        cb_seq(
            rows,
            release,
            "circuitbreaker.forced-open-state-denies",
            {"waitOpenMillis": 1, "actions": [{"op": "transition_forced_open"}, {"op": "try_acquire"}, {"op": "advance", "millis": 10}, {"op": "try_acquire"}]},
            "forced-open circuit breaker keeps denying calls until manually transitioned",
            "pass2",
        )
    if version == "0.13.0" or "ignoreexceptions" in body or "recordexceptions" in body or "auto transition to half open" in body:
        for kind in ["transient", "runtime", "ignored"]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.record-and-ignore-exceptions",
                {
                    "recordExceptions": ["transient", "runtime"],
                    "ignoreExceptions": ["ignored"],
                    "failureRateThreshold": 50,
                    "minimumNumberOfCalls": 1,
                    "slidingWindowSize": 2,
                    "actions": [{"op": "error", "kind": kind}, {"op": "try_acquire"}],
                },
                f"recordExceptions/ignoreExceptions classify {kind} exceptions for circuit metrics",
            )
        cb_seq(
            rows,
            release,
            "circuitbreaker.auto-half-open-probe",
            {"automaticTransition": True, "waitOpenMillis": 1, "minimumNumberOfCalls": 1, "slidingWindowSize": 1, "actions": [{"op": "error"}, {"op": "advance", "millis": 2}, {"op": "try_acquire"}]},
            "automatic transition setting permits half-open probe after open wait duration",
            "pass2",
        )
    if version == "0.13.2" or "response predicate to retry" in body or "retryonresult" in body:
        for bad_count in [1, 2, 3, 4]:
            retry_call(
                rows,
                release,
                "retry.result-predicate",
                {"maxAttempts": bad_count + 1, "waitMillis": 0, "retryOnResult": "bad", "outcomes": ["bad"] * bad_count + ["ok"]},
                f"retryOnResult retries bad results until an acceptable result appears after {bad_count} bad results",
            )
        retry_call(
            rows,
            release,
            "retry.result-predicate-exhaustion",
            {"maxAttempts": 3, "waitMillis": 0, "retryOnResult": "bad", "failAfterMaxAttempts": True, "outcomes": ["bad", "bad", "bad", "ok"]},
            "retryOnResult can raise MaxRetriesExceeded when failAfterMaxAttempts is enabled",
            "pass2",
        )
        for fail_after in [False, True]:
            retry_sequence(
                rows,
                release,
                "retry.result-predicate-metrics",
                {"maxAttempts": 3, "waitMillis": 0, "retryOnResult": "bad", "failAfterMaxAttempts": fail_after, "calls": [["bad", "ok"], ["bad", "bad", "bad"], ["ok"]]},
                f"retryOnResult updates success/failure metrics across calls failAfterMaxAttempts={fail_after}",
                "pass2",
            )
    if version == "0.14.0" or "decoratecallable" in body or "retry support" in body:
        retry_call(
            rows,
            release,
            "retry.checked-exception-callable",
            {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["checked"], "outcomes": ["throw:checked", "ok"]},
            "retry decorated callable handles checked exceptions, not only runtime exceptions",
        )
        for max_calls in [1, 2, 4]:
            bh_seq(
                rows,
                release,
                "bulkhead.metrics.max-allowed",
                {"maxConcurrentCalls": max_calls, "maxWaitMillis": 0, "actions": [{"op": "try_acquire"}, {"op": "execute_success"}, {"op": "release"}]},
                f"bulkhead metrics expose max allowed concurrent calls={max_calls}",
                "pass2",
            )
    if version == "0.15.0" or "remove method to all registries" in body or "replace method to all registries" in body or "half-open state" in body:
        add(rows, release, "registry.remove-reduces-managed-retries", "registry_probe", {"type": "retry", "removeA": True}, "registry remove changes managed retry collection", "pass2")
        add(rows, release, "registry.remove-reduces-managed-circuitbreakers", "registry_probe", {"type": "circuitbreaker", "removeA": True}, "registry remove changes managed circuit breaker collection", "pass2")
        for permits in [1, 2, 3]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.half-open-permit-limit",
                {"halfOpenPermits": permits, "actions": [{"op": "transition_half_open"}] + [{"op": "try_acquire"} for _ in range(permits + 1)]},
                f"half-open state permits only configured concurrent probe calls={permits}",
            )
            cb_seq(
                rows,
                release,
                "circuitbreaker.half-open-success-closes",
                {"halfOpenPermits": permits, "failureRateThreshold": 50, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "transition_half_open"}] + [{"op": "success"} for _ in range(permits)] + [{"op": "try_acquire"}]},
                f"successful half-open probe calls close the circuit when permit count={permits} is satisfied",
                "pass2",
            )
            cb_seq(
                rows,
                release,
                "circuitbreaker.half-open-error-reopens",
                {"halfOpenPermits": permits, "failureRateThreshold": 50, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "transition_half_open"}, {"op": "error"}, {"op": "try_acquire"}]},
                f"failed half-open probe reopens the circuit with permit count={permits}",
                "pass2",
            )
    if version == "0.17.0" or "minimum waitduration constraint for retry" in body or "ignored exception" in body:
        retry_call(rows, release, "retry.zero-wait-duration", {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["transient"], "outcomes": ["throw:transient", "ok"]}, "retry accepts zero waitDuration", "pass2")
        cb_seq(
            rows,
            release,
            "circuitbreaker.half-open-ignored-error-does-not-stick",
            {"ignoreExceptions": ["ignored"], "halfOpenPermits": 1, "actions": [{"op": "transition_half_open"}, {"op": "error", "kind": "ignored"}, {"op": "success"}, {"op": "try_acquire"}]},
            "ignored exception in half-open does not permanently strand circuit breaker",
            "pass2",
        )
    if version == "1.0.0" or "count-based and time-based sliding window" in body or "slow response time threshold" in body:
        for window_type in ["count", "time"]:
            cb_seq(
                rows,
                release,
                f"circuitbreaker.{window_type}-based-window-metrics",
                {"windowType": window_type, "minimumNumberOfCalls": 2, "slidingWindowSize": 4, "actions": [{"op": "success"}, {"op": "advance", "millis": 1}, {"op": "error"}, {"op": "try_acquire"}]},
                f"{window_type}-based sliding window records buffered calls and failure counts",
            )
        cb_seq(
            rows,
            release,
            "circuitbreaker.record-exceptions-as-success",
            {"ignoreExceptions": ["ignored"], "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "error", "kind": "ignored"}, {"op": "success"}, {"op": "try_acquire"}]},
            "configured ignored exceptions are treated as non-failures for circuit-breaker state",
            "pass2",
        )
    if version == "1.1.0" or "timelimiter" in body:
        for cancel in [False, True]:
            add(
                rows,
                release,
                "timelimiter.completed-and-failed-future",
                "timelimiter_future",
                {"timeoutMillis": 50, "cancelRunningFuture": cancel, "scenario": "completed", "value": "ok"},
                f"time limiter returns completed future result cancelRunningFuture={cancel}",
            )
            add(
                rows,
                release,
                "timelimiter.failed-future-propagates",
                "timelimiter_future",
                {"timeoutMillis": 50, "cancelRunningFuture": cancel, "scenario": "failed"},
                f"time limiter propagates failed future exception cancelRunningFuture={cancel}",
                "pass2",
            )
            add(
                rows,
                release,
                "timelimiter.timeout-cancellation",
                "timelimiter_future",
                {"timeoutMillis": 1, "cancelRunningFuture": cancel, "scenario": "timeout"},
                f"time limiter raises timeout and observes cancellation flag cancelRunningFuture={cancel}",
                "pass2",
            )
        for timeout in [1, 5, 50]:
            add(
                rows,
                release,
                "timelimiter.timeout-duration-boundary",
                "timelimiter_future",
                {"timeoutMillis": timeout, "cancelRunningFuture": True, "scenario": "completed", "value": f"ok-{timeout}"},
                f"time limiter preserves immediate completed future values while exposing timeoutDuration={timeout}ms",
                "pass2",
            )
    if version == "1.2.0" or "configurable wait times" in body or "waitintervalfunction" in body:
        for cap in [2, 5, 20]:
            add(
                rows,
                release,
                "circuitbreaker.config-open-wait-interval",
                "circuitbreaker_config",
                {
                    "waitOpenMillis": 2,
                    "failureRateThreshold": 50,
                    "minimumNumberOfCalls": 1,
                    "slidingWindowSize": 1,
                    "initialState": "CLOSED",
                },
                f"circuit breaker exposes configured open wait interval used before half-open, cap marker {cap}",
                "pass2",
            )
        for wait in [1, 2, 5, 10]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.open-wait-boundary-grid",
                {"waitOpenMillis": wait, "minimumNumberOfCalls": 1, "slidingWindowSize": 1, "actions": [{"op": "error"}, {"op": "advance", "millis": wait - 1}, {"op": "try_acquire"}, {"op": "advance", "millis": 1}, {"op": "try_acquire"}]},
                f"open wait boundary is controlled by configured wait interval {wait}ms",
                "pass2",
            )
    if version == "1.3.0" or "metrics_only" in body or "getter for retryonretryevent" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.metrics-only-records-without-opening",
            {"failureRateThreshold": 1, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "transition_metrics_only"}, {"op": "error"}, {"op": "try_acquire"}]},
            "metrics-only state records outcomes while still permitting calls",
        )
    if version == "1.5.0" or "faircallhandlingenabled" in body or "notpermittedcalls" in body:
        for fair in [False, True]:
            bh_seq(
                rows,
                release,
                "bulkhead.fairness-flag-preserves-permit-semantics",
                {"maxConcurrentCalls": 1, "maxWaitMillis": 0, "fair": fair, "actions": [{"op": "try_acquire"}, {"op": "try_acquire"}, {"op": "release"}, {"op": "try_acquire"}]},
                f"bulkhead fairCallHandling flag keeps observable permit boundary fair={fair}",
            )
        cb_seq(
            rows,
            release,
            "circuitbreaker.not-permitted-metric-name-surface",
            {"actions": [{"op": "transition_open"}, {"op": "try_acquire"}, {"op": "try_acquire"}]},
            "not-permitted calls metric increments in open state",
            "pass2",
        )
    if version == "1.6.0" or "default_max_attempts" in body or "exponential backoff" in body or "callnotpermittedexception" in body:
        add(
            rows,
            release,
            "retry.config-default-max-attempts",
            "retry_config",
            {"maxAttempts": 3, "waitMillis": 0, "intervalAttempts": [1]},
            "public default max attempts remains observable through built retry config",
            "pass2",
        )
        add(
            rows,
            release,
            "retry.backoff.exponential-capped",
            "retry_config",
            {"maxAttempts": 6, "interval": "exponential", "initialIntervalMillis": 5, "multiplier": 2.0, "maxIntervalMillis": 12, "intervalAttempts": [1, 2, 3, 4, 5]},
            "exponential backoff can cap at a maximum interval",
        )
        cb_seq(
            rows,
            release,
            "circuitbreaker.call-not-permitted-exception",
            {"actions": [{"op": "transition_open"}, {"op": "execute_success"}]},
            "decorated execution in open state raises a call-not-permitted exception carrying circuit identity",
            "pass2",
        )
    if version == "1.7.0" or "record a failure on result" in body:
        for bad in ["bad", "retry"]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.record-result-as-failure",
                {"recordResultValue": bad, "failureRateThreshold": 50, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "result", "value": bad}, {"op": "try_acquire"}]},
                f"recordResult predicate treats result={bad} as a circuit-breaker failure",
            )
        for value in ["ok", "bad"]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.record-result-mixed-window",
                {"recordResultValue": "bad", "failureRateThreshold": 50, "minimumNumberOfCalls": 2, "slidingWindowSize": 3, "actions": [{"op": "result", "value": value}, {"op": "result", "value": "bad"}, {"op": "try_acquire"}]},
                f"recordResult predicate contributes to mixed success/failure window starting with {value}",
                "pass2",
            )
    if version == "1.7.1" or "permits more calls" in body or "metricsonlystate" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.half-open-extra-permits-rejected",
            {"halfOpenPermits": 2, "actions": [{"op": "transition_half_open"}, {"op": "try_acquire"}, {"op": "try_acquire"}, {"op": "try_acquire"}]},
            "half-open permit accounting rejects probes beyond configured limit",
            "pass2",
        )
    if version == "2.0.2" or "checkedfunction decorator" in body or "recordresultpredicate" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.checked-supplier-record-result",
            {"recordResultValue": "bad", "failureRateThreshold": 50, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "result", "value": "bad"}, {"op": "try_acquire"}]},
            "checked supplier/function style result predicates open the circuit on recorded bad result",
            "pass2",
        )
    if version == "2.2.0" or "do not retry if intervalfunction returns interval less than 0" in body or "stale retry configurations" in body:
        retry_call(
            rows,
            release,
            "retry.result-predicate-final-success",
            {"maxAttempts": 4, "waitMillis": 0, "retryOnResult": "bad", "outcomes": ["bad", "bad", "bad", "ok"]},
            "retry result predicate eventually returns final successful value after bad results",
            "pass2",
        )
    if version == "2.3.0" or "custom clock" in body or "decoratesupplier" in body:
        cb_seq(
            rows,
            release,
            "circuitbreaker.custom-clock-open-wait",
            {"waitOpenMillis": 10, "minimumNumberOfCalls": 1, "slidingWindowSize": 1, "actions": [{"op": "error"}, {"op": "advance", "millis": 9}, {"op": "try_acquire"}, {"op": "advance", "millis": 1}, {"op": "try_acquire"}]},
            "custom clock controls open-to-half-open wait without real sleeping",
        )
        retry_call(
            rows,
            release,
            "retry.instance-decorate-supplier-behavior",
            {"maxAttempts": 3, "waitMillis": 0, "retryExceptions": ["runtime"], "outcomes": ["throw:runtime", "ok"]},
            "Retry instance decorator preserves retry behavior for suppliers",
            "pass2",
        )
        for precedence in [False, True]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.ignore-exceptions-precedence",
                {"recordExceptions": ["ignored"], "ignoreExceptions": ["ignored"], "ignoreExceptionsPrecedence": precedence, "failureRateThreshold": 50, "minimumNumberOfCalls": 1, "slidingWindowSize": 2, "actions": [{"op": "error", "kind": "ignored"}, {"op": "try_acquire"}]},
                f"ignoreExceptionsPrecedence controls classification when record and ignore both match precedence={precedence}",
                "pass2",
            )
    if version == "2.4.0" or "initializing circuitbreaker in desired state" in body or "time limiter registry builder" in body:
        for state in ["OPEN", "DISABLED", "METRICS_ONLY", "FORCED_OPEN"]:
            cb_seq(
                rows,
                release,
                "circuitbreaker.initial-state-runtime-permission",
                {"initialState": state, "actions": [{"op": "try_acquire"}, {"op": "success"}]},
                f"configured initial state {state} immediately affects runtime permission and recording",
            )
        add(rows, release, "timelimiter.config-timeout-and-cancel-flag", "timelimiter_future", {"timeoutMillis": 5, "cancelRunningFuture": True, "scenario": "completed", "value": "ok"}, "time limiter config exposes timeout and cancellation behavior", "pass2")


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = stable_json([row["capability"], row["op"], row["params"]])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def build_candidates() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    releases = fetch_releases()
    rows: list[dict[str, Any]] = []
    for release in releases:
        release_specific(rows, release)
    return dedupe(rows), releases


def run_runner(contracts: list[dict[str, Any]], fill: bool = False) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump({"contracts": contracts}, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        args = f"{'--fill ' if fill else ''}{path}"
        cmd = ["mvn", "-q", "-f", str(RUNNER / "pom.xml"), "compile", "exec:java", "-Dexec.mainClass=shapingbench.Resilience4jLatestReplay", f"-Dexec.args={args}"]
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
    for key in ["events", "final", "metrics", "publishedEvents", "status", "value", "intervalsMillis", "initialState"]:
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


def write_md(candidates: list[dict[str, Any]], results: list[dict[str, Any]], survivors: list[dict[str, Any]], releases: list[dict[str, Any]], maven_versions: list[str]) -> None:
    by_release: dict[str, Counter[str]] = defaultdict(Counter)
    for row in candidates:
        by_release[row["version"]]["candidates"] += 1
    for row in survivors:
        by_release[row["version"]]["survivors"] += 1
    by_cap = Counter(row["capability"] for row in survivors)
    lines = [
        "# Resilience4j Contract Extraction",
        "",
        "Latest replay target: `io.github.resilience4j:*:2.4.0` (`retry`, `circuitbreaker`, `bulkhead`, `timelimiter`).",
        "",
        f"GitHub releases inspected: {len(releases)}",
        f"Maven retry versions observed: {len(maven_versions)}",
        f"Candidate contracts: {len(candidates)}",
        f"Latest replay + mutant survivors: {len(survivors)}",
        "",
        "Note: `resilience4j-ratelimiter` was intentionally excluded because Rate Limiter / Quota Engine is already a separate domain.",
        "",
        "## By Release",
        "",
        "| Release | Date | Candidates | Survivors |",
        "| --- | --- | ---: | ---: |",
    ]
    for release in releases:
        counts = by_release[release["version"]]
        date = (release.get("published_at") or "")[:10]
        lines.append(f"| `{release['version']}` | {date} | {counts['candidates']} | {counts['survivors']} |")
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
    candidates, releases = build_candidates()
    maven_versions = fetch_maven_versions()
    results, survivors = fill_and_verify(candidates)
    summary = {
        "project": "resilience4j/resilience4j",
        "domain": "retry_backoff_resilience_policy_engine",
        "latest_replay_target": "io.github.resilience4j 2.4.0 core modules: retry,circuitbreaker,bulkhead,timelimiter",
        "github_releases_seen": len(releases),
        "maven_versions_seen": len(maven_versions),
        "maven_versions": maven_versions,
        "candidate_contracts": len(candidates),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_mutant_rejected": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "by_capability": dict(Counter(row["capability"] for row in survivors)),
        "by_release": {
            release["version"]: {
                "published_at": release.get("published_at", ""),
                "candidates": sum(1 for row in candidates if row["version"] == release["version"]),
                "survivors": sum(1 for row in survivors if row["version"] == release["version"]),
            }
            for release in releases
        },
        "excluded_surface": ["resilience4j-ratelimiter"],
        "contracts": candidates,
    }
    (OUT / "all_releases_maximal_language_independent.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(candidates, OUT / "all_releases_maximal_language_independent.rpl")
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
    write_md(candidates, results, survivors, releases, maven_versions)
    audit = [
        "# Resilience4j Extraction Audit",
        "",
        f"GitHub releases inspected: {len(releases)}.",
        "Every release note was scanned in two passes: a direct feature pass and a second pass for adjacent observable behavior implied by bug fixes/configuration changes.",
        "Extracted contracts are limited to externally observable policy behavior: return values, raised errors, permission decisions, state, metrics, event counts, and timeout/cancellation outcomes.",
        "`resilience4j-ratelimiter` was excluded to avoid contaminating this domain with the already-completed Rate Limiter / Quota Engine domain.",
        "Non-observable dependency upgrades, Spring/Micronaut/Retrofit module wiring, documentation updates, package renames, and metrics-exporter integration were not converted into contracts unless the core policy behavior was replayable through the latest runtime.",
        "",
        f"Candidate contracts: {len(candidates)}.",
        f"Latest replay/mutant survivors: {len(survivors)}.",
    ]
    (OUT / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "contracts"}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
