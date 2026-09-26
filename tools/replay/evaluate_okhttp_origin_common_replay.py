#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
CANDIDATES = ROOT / "contracts" / "common" / "okhttp_origin_common_candidates.json"
PYTHON_REPLAY = ROOT / "contracts" / "common" / "okhttp_origin_python_cross_replay.json"
AXIOS_REPLAY = ROOT / "contracts" / "common" / "okhttp_origin_axios_cross_replay.json"
OKHTTP_LOG = pathlib.Path("/tmp/okhttp-survival-run.log")
URLLIB3_COMMON = ROOT / "contracts" / "common" / "canonical_common_evaluation.json"
OUT = ROOT / "contracts" / "common" / "okhttp_origin_common_verified.json"
OUT_MD = ROOT / "contracts" / "common" / "okhttp_origin_common_verified.md"
MERGED = ROOT / "contracts" / "common" / "merged_common.json"
MERGED_MD = ROOT / "contracts" / "common" / "merged_common.md"

NON_PORTABLE_OR_OPTIONAL = {
    "brotli_empty_body_is_not_decompressed": "optional Brotli codec/interceptor behavior, not present in the baseline latest clients without optional dependencies",
    "multipart_reader_streams_response_parts": "multipart response reader API, not a shared baseline HTTP client wire contract across urllib3, Requests, Axios, and OkHttp",
    "media_type_parameter_extracts_quoted_boundary": "media type parameter parser API, not a shared baseline HTTP client execution contract",
    "cleartext_forbidden_fails_with_unknown_service": "OkHttp/platform cleartext policy behavior, absent from urllib3, Requests, and Axios baseline clients",
}


def load_okhttp_tests() -> dict:
    text = OKHTTP_LOG.read_text()
    match = re.search(r'\{"okhttp_version".*\}\s*$', text, re.S)
    if not match:
        raise RuntimeError(f"OkHttp runner JSON not found in {OKHTTP_LOG}")
    data = json.loads(match.group(0))
    return {
        test["name"].removeprefix("okhttp_origin_"): {
            "passed": test["passed"],
            "error": test.get("error", ""),
        }
        for test in data["tests"]
        if test["name"].startswith("okhttp_origin_")
    }, data["okhttp_version"]


def verdict(test_name: str, target: str, replays: dict) -> dict:
    if target == "okhttp":
        tests = replays["okhttp"]
    elif target in {"urllib3", "requests"}:
        tests = replays["python"]["tests"].get(target, {})
    else:
        tests = replays["axios"]["tests"]
    row = tests.get(test_name)
    if not row:
        return {"verdict": "blocked_adapter", "error": "no executed adapter test for this contract"}
    return {"verdict": "pass_executed" if row["passed"] else "fail_behavior", "error": row.get("error", "")}


def make_markdown(payload: dict) -> str:
    lines = [
        "# OkHttp-Origin Common Verified",
        "",
        f"- candidates: {payload['candidate_contracts']}",
        f"- verified_common: {payload['okhttp_origin_common_verified']}",
        f"- behavior_failures: {payload['behavior_failures']}",
        f"- blocked_adapter: {payload['blocked_adapter']}",
        f"- non_portable_or_optional: {payload['non_portable_or_optional']}",
        "",
        "## Aggregate Counts",
        "",
        "| aggregate | count |",
        "|---|---:|",
    ]
    for key, count in payload["aggregate_counts"].items():
        lines.append(f"| `{key}` | {count} |")
    lines += ["", "## Verified", "", "| release | contract | capability |", "|---:|---|---|"]
    for row in payload["results"]:
        if row["aggregate"] == "okhttp_origin_common_verified":
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` |")
    lines += ["", "## Failed Or Excluded", "", "| release | contract | aggregate | failing_or_blocked_targets | reason |", "|---:|---|---|---|---|"]
    for row in payload["results"]:
        if row["aggregate"] != "okhttp_origin_common_verified":
            bad = [target for target, target_row in row["targets"].items() if target_row["verdict"] != "pass_executed"]
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['aggregate']}` | {','.join(bad)} | {row.get('reason', '')} |")
    return "\n".join(lines) + "\n"


def make_merged_markdown(payload: dict) -> str:
    lines = [
        "# Merged Common",
        "",
        f"- urllib3_origin_common: {payload['urllib3_origin_common']}",
        f"- okhttp_origin_common: {payload['okhttp_origin_common']}",
        f"- merged_common: {payload['merged_common']}",
        "",
        "## Contracts",
        "",
        "| origin | source | contract | capability |",
        "|---|---:|---|---|",
    ]
    for row in payload["results"]:
        lines.append(f"| `{row['origin']}` | {row['source_version']} | `{row['contract']}` | `{row['capability']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    candidates = json.loads(CANDIDATES.read_text())
    python_replay = json.loads(PYTHON_REPLAY.read_text())
    axios_replay = json.loads(AXIOS_REPLAY.read_text())
    okhttp_tests, okhttp_version = load_okhttp_tests()
    replays = {"python": python_replay, "axios": axios_replay, "okhttp": okhttp_tests}

    candidate_rows = [
        row for row in candidates["results"]
        if row["aggregate"] == "okhttp_origin_common_candidate_pending_adapter"
    ]
    rows = []
    counts = collections.Counter()
    for row in candidate_rows:
        aggregate = ""
        if row["name"] in NON_PORTABLE_OR_OPTIONAL:
            reason = NON_PORTABLE_OR_OPTIONAL[row["name"]]
            targets = {
                target: {"verdict": "not_portable_or_optional", "error": reason}
                for target in ("okhttp", "urllib3", "requests", "axios")
            }
            aggregate = "not_portable_or_optional"
        else:
            reason = ""
            targets = {
                target: verdict(row["name"], target, replays)
                for target in ("okhttp", "urllib3", "requests", "axios")
            }
        if all(target["verdict"] == "pass_executed" for target in targets.values()):
            aggregate = "okhttp_origin_common_verified"
        elif any(target["verdict"] == "fail_behavior" for target in targets.values()):
            aggregate = "behavior_divergence"
        elif aggregate != "not_portable_or_optional":
            aggregate = "blocked_adapter"
        counts[aggregate] += 1
        out = dict(row)
        out["targets"] = targets
        out["aggregate"] = aggregate
        if reason:
            out["reason"] = reason
        rows.append(out)

    verified = [row for row in rows if row["aggregate"] == "okhttp_origin_common_verified"]
    payload = {
        "rule": "OkHttp-origin common is verified only when the same contract has executed pass verdicts on latest OkHttp, urllib3, Requests, and Axios.",
        "candidate_contracts": len(candidate_rows),
        "okhttp_latest_version": okhttp_version,
        "target_versions": {
            "okhttp": okhttp_version,
            **python_replay["targets"],
            **axios_replay["targets"],
        },
        "okhttp_origin_common_verified": len(verified),
        "behavior_failures": counts["behavior_divergence"],
        "blocked_adapter": counts["blocked_adapter"],
        "non_portable_or_optional": counts["not_portable_or_optional"],
        "aggregate_counts": dict(sorted(counts.items())),
        "results": rows,
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    OUT_MD.write_text(make_markdown(payload))

    urllib3_common = json.loads(URLLIB3_COMMON.read_text())
    urllib3_rows = [
        {
            "origin": "urllib3",
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
        }
        for row in urllib3_common["results"]
        if row["aggregate"] == "common_confirmed"
    ]
    okhttp_rows = [
        {
            "origin": "okhttp",
            "source_version": row["source_version"],
            "contract": row["name"],
            "capability": row["capability"],
            "key": row["key"],
        }
        for row in verified
    ]
    merged = urllib3_rows + okhttp_rows
    merged_payload = {
        "rule": "merged_common = urllib3_origin_common union verified okhttp_origin_common.",
        "inputs": {
            "urllib3_origin_common": str(URLLIB3_COMMON.relative_to(ROOT)),
            "okhttp_origin_common_verified": str(OUT.relative_to(ROOT)),
        },
        "urllib3_origin_common": len(urllib3_rows),
        "okhttp_origin_common": len(okhttp_rows),
        "merged_common": len(merged),
        "results": merged,
    }
    MERGED.write_text(json.dumps(merged_payload, indent=2, sort_keys=True) + "\n")
    MERGED_MD.write_text(make_merged_markdown(merged_payload))
    print(json.dumps({
        "candidate_contracts": len(candidate_rows),
        "okhttp_origin_common_verified": len(verified),
        "behavior_failures": counts["behavior_divergence"],
        "blocked_adapter": counts["blocked_adapter"],
        "non_portable_or_optional": counts["not_portable_or_optional"],
        "merged_common": len(merged),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
