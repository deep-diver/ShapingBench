#!/usr/bin/env python3
"""Replay nodeca/js-yaml origin contracts against latest js-yaml and kill mutants."""

from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from yaml_origin_common import ROOT, write_latest_markdown, write_rpl


BASE = ROOT / "contracts" / "yaml" / "js-yaml"
IN_JSON = BASE / "all_releases_excluding_common_1172.summary.json"
RUNNER = ROOT / "tools" / "replay" / "yaml_js_yaml_origin_runner.mjs"


def main() -> int:
    source = json.loads(IN_JSON.read_text(encoding="utf-8"))
    raw = subprocess.check_output(
        ["node", "--no-warnings", str(RUNNER), "replay", str(IN_JSON)],
        cwd=RUNNER.parent,
        text=True,
        stderr=subprocess.STDOUT,
    )
    node_result = json.loads(raw)
    results = node_result["results"]
    survivors = node_result["survivors"]
    by_cap = defaultdict(Counter)
    by_kind = defaultdict(Counter)
    failure_kinds = Counter()
    for row in results:
        by_cap[row["capability"]][row["status"]] += 1
        by_kind[row["source_kind"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            failure_kinds[miss.split(":", 1)[0]] += 1
    summary = {
        "domain": source["domain"],
        "project": source["project"],
        "package": source["package"],
        "latest_version": source["latest_version"],
        "runtime_package": node_result["runtime_package"],
        "runtime_version": node_result["runtime_version"],
        "input_contracts": node_result["input_contracts"],
        "latest_replay_passed": node_result["latest_replay_passed"],
        "latest_replay_failed": node_result["latest_replay_failed"],
        "latest_mutant_killed": node_result["latest_mutant_killed"],
        "latest_survivors": node_result["latest_survivors"],
        "pass_rate": round(node_result["latest_survivors"] / node_result["input_contracts"], 4) if node_result["input_contracts"] else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_cap.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
        "failure_kinds": dict(failure_kinds.most_common()),
    }
    out = {
        "summary": summary,
        "survivors": survivors,
        "failed": [{"contract": contract, "result": result} for contract, result in zip(source["contracts"], results) if result["status"] != "passed"],
        "results": results,
    }
    (BASE / "latest_replay_mutant_verified.json").write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")
    write_latest_markdown(BASE / "latest_replay_mutant_verified.md", "nodeca/js-yaml Latest Replay and Mutant Verification", out)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
