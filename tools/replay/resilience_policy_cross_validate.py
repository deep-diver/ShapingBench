#!/usr/bin/env python3
"""Cross-replay Retry/Backoff/Resilience Policy contracts across mature OSS targets."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "resilience_policy" / "common"
JAVA_ENV = {
    "JAVA_HOME": "/opt/homebrew/opt/openjdk",
    "PATH": f"/opt/homebrew/opt/openjdk/bin:{os.environ.get('PATH', '')}",
}

TARGETS = {
    "resilience4j": {
        "project": "resilience4j/resilience4j",
        "path": ROOT / "contracts" / "resilience_policy" / "resilience4j" / "latest_replay_mutant_verified.json",
    },
    "failsafe": {
        "project": "failsafe-lib/failsafe",
        "path": ROOT / "contracts" / "resilience_policy" / "failsafe" / "latest_replay_mutant_verified.json",
    },
    "backoff": {
        "project": "litl/backoff",
        "path": ROOT / "contracts" / "resilience_policy" / "backoff" / "latest_replay_mutant_verified.json",
    },
    "exponential-backoff": {
        "project": "coveooss/exponential-backoff",
        "path": ROOT / "contracts" / "resilience_policy" / "exponential-backoff" / "latest_replay_mutant_verified.json",
    },
    "async-retry": {
        "project": "vercel/async-retry",
        "path": ROOT / "contracts" / "resilience_policy" / "async-retry" / "latest_replay_mutant_verified.json",
    },
}


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def version_sort(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)) or (0,)


def load_contracts(target: str) -> list[dict[str, Any]]:
    data = json.loads(TARGETS[target]["path"].read_text(encoding="utf-8"))
    return data["contracts"]


def status_kind(status: str | None) -> str:
    if status == "returned":
        return "returned"
    if status in {"raised", "thrown"}:
        return "failed"
    return status or "unknown"


def canonical_expected(contract: dict[str, Any]) -> dict[str, Any]:
    expected = contract.get("expected", {})
    cap = contract.get("capability", "")
    out: dict[str, Any] = {}
    if "status" in expected:
        out["status"] = status_kind(expected.get("status"))
    if "attempts" in expected:
        attempts = expected["attempts"]
        out["attempts"] = len(attempts) if isinstance(attempts, list) else attempts
    if "value" in expected and out.get("status") == "returned":
        out["value"] = expected["value"]
    if "values" in expected:
        out["values"] = expected["values"]
    if "intervalsMillis" in expected:
        out["values"] = expected["intervalsMillis"]
    if requires_retry_notification(cap):
        count = retry_notification_count(expected)
        if count is not None:
            out["retryNotifications"] = count
    return normalize(out)


def canonical_actual(actual: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status_kind(actual.get("status"))}
    if "attempts" in actual:
        attempts = actual["attempts"]
        out["attempts"] = len(attempts) if isinstance(attempts, list) else attempts
    if "value" in actual and out.get("status") == "returned":
        out["value"] = actual["value"]
    if "values" in actual:
        out["values"] = actual["values"]
    if "intervalsMillis" in actual:
        out["values"] = actual["intervalsMillis"]
    count = retry_notification_count(actual)
    if count is not None:
        out["retryNotifications"] = count
    return normalize(out)


def comparable_actual(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return normalize({key: actual.get(key) for key in expected.keys()})


def requires_retry_notification(capability: str) -> bool:
    lowered = capability.lower()
    return any(token in lowered for token in ["event", "listener", "onretry"])


def retry_notification_count(payload: dict[str, Any]) -> int | None:
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("events"), dict):
        if "retry" in payload["events"]:
            return int(payload["events"]["retry"])
        if isinstance(payload["events"].get("backoff"), list):
            return len(payload["events"]["backoff"])
    if isinstance(payload.get("listeners"), dict) and "retry" in payload["listeners"]:
        return int(payload["listeners"]["retry"])
    if isinstance(payload.get("retryCalls"), list):
        return len(payload["retryCalls"])
    if isinstance(payload.get("onRetryCalls"), list):
        return len(payload["onRetryCalls"])
    return None


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def source_kind(contract: dict[str, Any]) -> str:
    op = contract.get("op")
    params = contract.get("params", {})
    cap = contract.get("capability", "")
    lowered = cap.lower()
    if any(token in lowered for token in ["handler-details", "logging", "runtime-config", "decorator-surface", "jitter.customized", "runtime.wait"]):
        return "feature_absent"
    if "async." in lowered:
        return "async_retry_exception"
    if op in {"retry_call", "on_exception", "async_on_exception"}:
        if params.get("retryOnResult") or params.get("handleResult") or params.get("handleResultPrefix"):
            return "retry_result"
        return "retry_exception"
    if op in {"on_predicate", "async_on_predicate"}:
        return "retry_result"
    if op == "retry_config" and ("intervalsMillis" in contract.get("expected", {}) or params.get("interval")):
        return "wait_sequence"
    if op == "wait_sequence":
        return "wait_sequence"
    if op in {"retry_sequence", "on_exception_sequence", "on_predicate_sequence"}:
        return "retry_sequence"
    if "retry" in cap and op in {"executor_listeners", "contextual_retry"}:
        return "retry_observability"
    return "feature_absent"


def max_attempts_for(contract: dict[str, Any]) -> int:
    p = contract.get("params", {})
    if "maxAttempts" in p:
        return int(p["maxAttempts"])
    if "maxRetries" in p:
        return int(p["maxRetries"]) + 1
    if "max_tries" in p and p["max_tries"] is not None:
        return int(p["max_tries"])
    return int(canonical_expected(contract).get("attempts", 3) or 3)


def outcomes_for(contract: dict[str, Any]) -> list[Any]:
    p = contract.get("params", {})
    return list(p.get("outcomes") or ["ok"])


def retry_value_for(contract: dict[str, Any]) -> Any:
    p = contract.get("params", {})
    if "retryOnResult" in p:
        return p.get("retryOnResult")
    if "handleResult" in p:
        return p.get("handleResult")
    if p.get("predicate") == "equals":
        return p.get("predicate_value")
    return False


def handled_kinds(contract: dict[str, Any]) -> list[str]:
    p = contract.get("params", {})
    if "retryExceptions" in p:
        return list(p.get("retryExceptions") or ["transient"])
    if "handle" in p:
        return list(p.get("handle") or ["transient"])
    if "exceptions" in p:
        return list(p.get("exceptions") or ["transient"])
    return ["transient"]


def has_classification(contract: dict[str, Any]) -> bool:
    p = contract.get("params", {})
    outcomes = outcomes_for(contract)
    handled = set(handled_kinds(contract))
    has_non_handled = any(isinstance(x, str) and x.startswith("throw:") and x.split(":", 1)[1] not in handled for x in outcomes)
    return has_non_handled or bool(p.get("ignoreExceptions") or p.get("abortOn") or p.get("giveup_on"))


def async_retry_classified_outcomes(contract: dict[str, Any]) -> list[Any]:
    handled = set(handled_kinds(contract))
    out = []
    for outcome in outcomes_for(contract):
        if isinstance(outcome, str) and outcome.startswith("throw:"):
            kind = outcome.split(":", 1)[1]
            if kind not in handled:
                out.append(f"bail:{kind}")
            else:
                out.append(outcome)
        else:
            out.append(outcome)
    return out


def to_target_contract(origin: dict[str, Any], target: str) -> tuple[dict[str, Any] | None, str]:
    kind = source_kind(origin)
    p = origin.get("params", {})
    attempts = max_attempts_for(origin)
    outcomes = outcomes_for(origin)

    if kind in {"retry_exception", "async_retry_exception"}:
        if kind == "async_retry_exception" and target in {"resilience4j", "failsafe"}:
            return None, "feature_absent"
        if target == "resilience4j":
            params = {"maxAttempts": attempts, "waitMillis": 0, "retryExceptions": handled_kinds(origin), "outcomes": outcomes}
            if p.get("ignoreExceptions"):
                params["ignoreExceptions"] = p["ignoreExceptions"]
            return {"name": origin["name"], "op": "retry_call", "params": params}, "projected"
        if target == "failsafe":
            params = {"maxAttempts": attempts, "handle": handled_kinds(origin), "outcomes": outcomes}
            if p.get("abortOn"):
                params["abortOn"] = p["abortOn"]
            return {"name": origin["name"], "op": "retry_call", "params": params}, "projected"
        if target == "backoff":
            return {
                "name": origin["name"],
                "op": "on_exception",
                "params": {"wait_gen": "constant", "interval": 0, "jitter": "none", "max_tries": attempts, "exceptions": handled_kinds(origin), "outcomes": outcomes, "raise_on_giveup": True},
            }, "projected"
        if target == "exponential-backoff":
            params = {"numOfAttempts": attempts, "startingDelay": 0, "timeMultiple": 1, "jitter": "none", "outcomes": outcomes}
            if has_classification(origin):
                params["retryMode"] = "onlyTransient"
            elif requires_retry_notification(origin.get("capability", "")):
                params["retryMode"] = "promiseTrue"
                params["retryDelayMs"] = 0
            return {"name": origin["name"], "op": "backoff_call", "params": params}, "projected"
        if target == "async-retry":
            params = {
                "retries": max(0, attempts - 1),
                "minTimeout": 1,
                "factor": 1,
                "randomize": False,
                "outcomes": async_retry_classified_outcomes(origin) if has_classification(origin) else outcomes,
            }
            if requires_retry_notification(origin.get("capability", "")):
                params["onRetryMode"] = "capture"
            return {"name": origin["name"], "op": "retry_call", "params": params}, "projected"

    if kind == "retry_result":
        retry_value = retry_value_for(origin)
        if target == "resilience4j":
            return {"name": origin["name"], "op": "retry_call", "params": {"maxAttempts": attempts, "waitMillis": 0, "retryOnResult": retry_value, "outcomes": outcomes}}, "projected"
        if target == "failsafe":
            return {"name": origin["name"], "op": "retry_call", "params": {"maxAttempts": attempts, "handleResult": retry_value, "outcomes": outcomes}}, "projected"
        if target == "backoff":
            return {"name": origin["name"], "op": "on_predicate", "params": {"wait_gen": "constant", "interval": 0, "jitter": "none", "max_tries": attempts, "predicate": "equals", "predicate_value": retry_value, "outcomes": outcomes}}, "projected"
        return None, "feature_absent"

    if kind == "wait_sequence":
        expected = canonical_expected(origin)
        values = expected.get("values")
        if not isinstance(values, list) or not values:
            return None, "feature_absent"
        if target == "resilience4j":
            params = {"maxAttempts": len(values) + 1, "waitMillis": 0, "intervalAttempts": list(range(1, len(values) + 1))}
            if origin.get("op") == "wait_sequence":
                wait_gen = p.get("wait_gen")
                if wait_gen == "constant":
                    params.update({"interval": "fixed", "initialIntervalMillis": values[0]})
                elif wait_gen == "expo":
                    params.update({"interval": "exponential", "initialIntervalMillis": values[0], "multiplier": p.get("base", 2), "maxIntervalMillis": p.get("max_value", 10_000)})
                else:
                    return None, "feature_absent"
            else:
                params.update({k: v for k, v in p.items() if k in {"interval", "initialIntervalMillis", "multiplier", "maxIntervalMillis"}})
            return {"name": origin["name"], "op": "retry_config", "params": params}, "projected"
        if target == "backoff" and origin.get("op") == "wait_sequence":
            return {"name": origin["name"], "op": "wait_sequence", "params": p}, "projected"
        return None, "feature_absent"

    return None, "feature_absent"


def run_java(target: str, contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if target == "resilience4j":
        pom = ROOT / "tools" / "replay" / "resilience4j_latest_runner" / "pom.xml"
        main = "shapingbench.Resilience4jLatestReplay"
    elif target == "failsafe":
        pom = ROOT / "tools" / "replay" / "failsafe_latest_runner" / "pom.xml"
        main = "shapingbench.FailsafeLatestReplay"
    else:
        raise ValueError(target)
    return run_command_json(["mvn", "-q", "-f", str(pom), "compile", "exec:java", f"-Dexec.mainClass={main}"], contracts, java=True)


def run_script(target: str, contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    runner = {
        "backoff": ["/opt/miniconda3/bin/python", str(ROOT / "tools" / "replay" / "backoff_latest_runner.py")],
        "exponential-backoff": ["node", str(ROOT / "tools" / "replay" / "exponential_backoff_latest_runner.mjs")],
        "async-retry": ["node", str(ROOT / "tools" / "replay" / "async_retry_latest_runner.mjs")],
    }[target]
    return run_command_json(runner, contracts, java=False)


def run_command_json(base_cmd: list[str], contracts: list[dict[str, Any]], java: bool) -> list[dict[str, Any]]:
    if not contracts:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        json.dump({"contracts": contracts}, handle, ensure_ascii=True)
        path = Path(handle.name)
    try:
        if java:
            args = f"--fill {path}"
            cmd = base_cmd + [f"-Dexec.args={args}"]
            try:
                raw = subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.STDOUT, env={**os.environ, **JAVA_ENV})
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(exc.output) from exc
        else:
            cmd = base_cmd + ["--fill", str(path)]
            try:
                raw = subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(exc.output) from exc
        start = raw.find("{")
        if start < 0:
            raise RuntimeError(raw)
        return json.loads(raw[start:])["contracts"]
    finally:
        path.unlink(missing_ok=True)


def run_target(target: str, projected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if target in {"resilience4j", "failsafe"}:
        return run_java(target, projected)
    return run_script(target, projected)


def evaluate_origin_against_targets(origin_name: str, target_names: list[str], contracts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows_by_name: dict[tuple[str, str], dict[str, Any]] = {}
    for target in target_names:
        projected: list[dict[str, Any]] = []
        metadata: dict[str, dict[str, Any]] = {}
        for origin in contracts:
            target_contract, projection_status = to_target_contract(origin, target)
            expected = canonical_expected(origin)
            row = {
                "origin": origin_name,
                "target": target,
                "name": origin["name"],
                "project": origin["project"],
                "capability": origin["capability"],
                "op": origin["op"],
                "semanticKind": source_kind(origin),
                "projectionStatus": projection_status,
                "expectedCanonical": expected,
            }
            if target_contract is None:
                row["actualCanonical"] = {"status": projection_status}
                row["pass"] = False
                rows_by_name[(target, origin["name"])] = row
                continue
            projected.append(target_contract)
            metadata[target_contract["name"]] = row
        actual_rows = run_target(target, projected)
        for actual_row in actual_rows:
            row = metadata[actual_row["name"]]
            actual = canonical_actual(actual_row.get("actual", {}))
            comparable = comparable_actual(actual, row["expectedCanonical"])
            row["targetActualRaw"] = actual_row.get("actual", {})
            row["actualCanonical"] = comparable
            row["pass"] = stable_json(comparable) == stable_json(row["expectedCanonical"])
            rows_by_name[(target, row["name"])] = row
    return list(rows_by_name.values())


def counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    return {
        "attempted": total,
        "projected": sum(1 for r in rows if r["projectionStatus"] == "projected"),
        "feature_absent": sum(1 for r in rows if r["projectionStatus"] == "feature_absent"),
        "passed": sum(1 for r in rows if r.get("pass")),
        "failed": sum(1 for r in rows if not r.get("pass")),
        "by_semantic_kind": dict(Counter(r["semanticKind"] for r in rows)),
    }


def common_from_phase(origin: str, contracts: list[dict[str, Any]], rows: list[dict[str, Any]], target_names: list[str]) -> list[dict[str, Any]]:
    by_contract: dict[str, dict[str, bool]] = defaultdict(dict)
    for row in rows:
        by_contract[row["name"]][row["target"]] = bool(row.get("pass"))
    out = []
    for contract in contracts:
        if all(by_contract.get(contract["name"], {}).get(target, False) for target in target_names):
            out.append(contract)
    return out


def hidden_filter(common: list[dict[str, Any]], hidden_targets: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = evaluate_origin_against_targets("common_candidate", hidden_targets, common)
    by_contract: dict[str, dict[str, bool]] = defaultdict(dict)
    for row in rows:
        by_contract[row["name"]][row["target"]] = bool(row.get("pass"))
    survivors = [c for c in common if all(by_contract.get(c["name"], {}).get(t, False) for t in hidden_targets)]
    return survivors, rows


def write_outputs(phase_rows: dict[str, list[dict[str, Any]]], phase_common: dict[str, list[dict[str, Any]]], hidden_rows: list[dict[str, Any]], final_common: list[dict[str, Any]]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    initial_common = []
    seen = set()
    for phase in ["r1_on_r2_r3", "r2_on_r1_r3", "r3_on_r1_r2"]:
        for c in phase_common[phase]:
            if c["name"] not in seen:
                initial_common.append(c)
                seen.add(c["name"])

    summary = {
        "rank1_source": TARGETS["resilience4j"]["project"],
        "rank2_source": TARGETS["failsafe"]["project"],
        "rank3_source": TARGETS["backoff"]["project"],
        "rank4_hidden": TARGETS["exponential-backoff"]["project"],
        "rank5_hidden": TARGETS["async-retry"]["project"],
        "origin_contracts": {
            "rank1": len(load_contracts("resilience4j")),
            "rank2": len(load_contracts("failsafe")),
            "rank3": len(load_contracts("backoff")),
        },
        "phase_counts": {phase: counts(rows) for phase, rows in phase_rows.items()},
        "phase_common_counts": {phase: len(cs) for phase, cs in phase_common.items()},
        "common_candidates_before_hidden_filter": len(initial_common),
        "hidden_filter_counts": counts(hidden_rows),
        "final_common_count": len(final_common),
        "final_common_by_origin": dict(Counter(c["project"] for c in final_common)),
        "final_common_by_semantic_kind": dict(Counter(source_kind(c) for c in final_common)),
    }
    (OUT / "rank1_rank2_rank3_cross_replay.json").write_text(json.dumps({"summary": summary, "phase_rows": phase_rows, "hidden_rows": hidden_rows}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "common_candidates_before_hidden_filter.json").write_text(json.dumps({"contracts": initial_common, "summary": summary}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "confirmed_common_after_rank4_rank5.json").write_text(json.dumps({"contracts": final_common, "summary": summary}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "confirmed_common_after_rank4_rank5.rpl").write_text(
        "\n".join(
            f"contract {c['name']} {{ origin: {c['project']}; op: {c['op']}; params: {stable_json(c['params'])}; expect: {stable_json(c['expected'])}; }}"
            for c in final_common
        )
        + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Retry / Backoff / Resilience Policy common cross replay",
        "",
        f"- Rank 1 origin contracts: `{summary['origin_contracts']['rank1']}`",
        f"- Rank 2 origin contracts: `{summary['origin_contracts']['rank2']}`",
        f"- Rank 3 origin contracts: `{summary['origin_contracts']['rank3']}`",
        f"- Common candidates before Rank 4/5 hidden filter: `{len(initial_common)}`",
        f"- Final common after Rank 4/5 replay filter: `{len(final_common)}`",
        "",
        "## Phase Counts",
        "",
        "| Phase | Attempted | Projected | Feature absent | Passed | Failed | Common survivors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for phase, rows in phase_rows.items():
        c = counts(rows)
        lines.append(f"| `{phase}` | {c['attempted']} | {c['projected']} | {c['feature_absent']} | {c['passed']} | {c['failed']} | {len(phase_common[phase])} |")
    c = counts(hidden_rows)
    lines.extend(
        [
            f"| `rank4_rank5_hidden_filter` | {c['attempted']} | {c['projected']} | {c['feature_absent']} | {c['passed']} | {c['failed']} | {len(final_common)} |",
            "",
            "## Final Common By Origin",
            "",
        ]
    )
    for project, count in Counter(c["project"] for c in final_common).items():
        lines.append(f"- `{project}`: {count}")
    lines.extend(["", "## Final Common By Semantic Kind", ""])
    for kind, count in Counter(source_kind(c) for c in final_common).items():
        lines.append(f"- `{kind}`: {count}")
    lines.extend(["", "## Final Common Contracts", ""])
    for c in final_common:
        lines.append(f"- `{c['name']}`: {c['human']}")
    (OUT / "confirmed_common_after_rank4_rank5.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    r1 = load_contracts("resilience4j")
    r2 = load_contracts("failsafe")
    r3 = load_contracts("backoff")
    phase_rows = {
        "r1_on_r2_r3": evaluate_origin_against_targets("resilience4j", ["failsafe", "backoff"], r1),
        "r2_on_r1_r3": evaluate_origin_against_targets("failsafe", ["resilience4j", "backoff"], r2),
        "r3_on_r1_r2": evaluate_origin_against_targets("backoff", ["resilience4j", "failsafe"], r3),
    }
    phase_common = {
        "r1_on_r2_r3": common_from_phase("resilience4j", r1, phase_rows["r1_on_r2_r3"], ["failsafe", "backoff"]),
        "r2_on_r1_r3": common_from_phase("failsafe", r2, phase_rows["r2_on_r1_r3"], ["resilience4j", "backoff"]),
        "r3_on_r1_r2": common_from_phase("backoff", r3, phase_rows["r3_on_r1_r2"], ["resilience4j", "failsafe"]),
    }
    common = []
    seen = set()
    for contracts in phase_common.values():
        for c in contracts:
            if c["name"] not in seen:
                common.append(c)
                seen.add(c["name"])
    final_common, hidden_rows = hidden_filter(common, ["exponential-backoff", "async-retry"])
    write_outputs(phase_rows, phase_common, hidden_rows, final_common)
    print(json.dumps({
        "phase_common_counts": {k: len(v) for k, v in phase_common.items()},
        "common_candidates_before_hidden_filter": len(common),
        "final_common_count": len(final_common),
        "hidden_counts": counts(hidden_rows),
    }, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
