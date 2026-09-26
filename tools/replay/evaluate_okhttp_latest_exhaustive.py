#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
LATEST = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_survivors.json"
OKHTTP_LOG = pathlib.Path("/tmp/okhttp-survival-run.log")
OUT = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_executed_exhaustive.json"
OUT_MD = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_executed_exhaustive.md"


def load_okhttp_tests() -> tuple[dict[str, dict], str]:
    text = OKHTTP_LOG.read_text()
    match = re.search(r'\{"okhttp_version".*\}\s*$', text, re.S)
    if not match:
        raise RuntimeError(f"OkHttp runner JSON not found in {OKHTTP_LOG}")
    data = json.loads(match.group(0))
    tests = {}
    for test in data["tests"]:
        if not test["name"].startswith("okhttp_origin_"):
            continue
        tests[test["name"].removeprefix("okhttp_origin_")] = {
            "passed": test["passed"],
            "error": test.get("error", ""),
        }
    return tests, data["okhttp_version"]


def capability_bucket(capability: str) -> str:
    if capability.startswith("tls."):
        return "tls"
    parts = capability.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else capability


def markdown(payload: dict) -> str:
    lines = [
        "# OkHttp-Origin Latest Exhaustive Replay Ledger",
        "",
        f"- source_latest_survivor_rows: {payload['source_latest_survivor_rows']}",
        f"- latest_okhttp_version: {payload['latest_okhttp_version']}",
        f"- executed_rows: {payload['executed_rows']}",
        f"- executed_pass_rows: {payload['executed_pass_rows']}",
        f"- executed_fail_rows: {payload['executed_fail_rows']}",
        f"- not_executed_rows: {payload['not_executed_rows']}",
        "",
        "## Verdict Counts",
        "",
        "| verdict | rows |",
        "|---|---:|",
    ]
    for verdict, count in payload["verdict_counts"].items():
        lines.append(f"| `{verdict}` | {count} |")
    lines += ["", "## Not Executed By Capability Bucket", "", "| bucket | rows |", "|---|---:|"]
    for bucket, count in payload["not_executed_by_bucket"]:
        lines.append(f"| `{bucket}` | {count} |")
    lines += ["", "## Executed Failures", "", "| release | contract | capability | error |", "|---:|---|---|---|"]
    for row in payload["results"]:
        if row["latest_execution_verdict"] == "executed_fail":
            error = row["latest_execution_error"].replace("|", "\\|")
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` | {error} |")
    lines += ["", "## Not Executed", "", "| release | contract | capability |", "|---:|---|---|"]
    for row in payload["results"]:
        if row["latest_execution_verdict"] == "not_executed":
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    latest = json.loads(LATEST.read_text())
    tests, okhttp_version = load_okhttp_tests()
    source_rows = [row for row in latest["results"] if row["latest_survived"]]

    rows = []
    counts = collections.Counter()
    not_executed_bucket = collections.Counter()
    for row in source_rows:
        test = tests.get(row["name"])
        out = dict(row)
        if test is None:
            verdict = "not_executed"
            out["latest_execution_error"] = "no okhttp latest adapter test has been executed for this contract"
            not_executed_bucket[capability_bucket(row["capability"])] += 1
        elif test["passed"]:
            verdict = "executed_pass"
            out["latest_execution_error"] = ""
        else:
            verdict = "executed_fail"
            out["latest_execution_error"] = test["error"]
        out["latest_execution_verdict"] = verdict
        counts[verdict] += 1
        rows.append(out)

    payload = {
        "rule": "Every row previously treated as an OkHttp latest survivor must have an actual latest OkHttp replay result before it can be used for common-subset work.",
        "source": str(LATEST.relative_to(ROOT)),
        "latest_okhttp_version": okhttp_version,
        "source_latest_survivor_rows": len(source_rows),
        "executed_rows": counts["executed_pass"] + counts["executed_fail"],
        "executed_pass_rows": counts["executed_pass"],
        "executed_fail_rows": counts["executed_fail"],
        "not_executed_rows": counts["not_executed"],
        "verdict_counts": dict(sorted(counts.items())),
        "not_executed_by_bucket": not_executed_bucket.most_common(),
        "results": rows,
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    OUT_MD.write_text(markdown(payload))
    print(json.dumps({
        "source_latest_survivor_rows": payload["source_latest_survivor_rows"],
        "executed_rows": payload["executed_rows"],
        "executed_pass_rows": payload["executed_pass_rows"],
        "executed_fail_rows": payload["executed_fail_rows"],
        "not_executed_rows": payload["not_executed_rows"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
