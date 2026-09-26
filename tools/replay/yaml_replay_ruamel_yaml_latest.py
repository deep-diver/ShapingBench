#!/usr/bin/env python3
"""Replay ruamel.yaml origin contracts against latest ruamel.yaml and kill mutants."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from yaml_origin_common import ROOT, deep_equal, normalize, write_latest_markdown, write_rpl


BASE = ROOT / "contracts" / "yaml" / "ruamel-yaml"
IN_JSON = BASE / "all_releases_excluding_common_1172.summary.json"
VENDOR = ROOT / "tools" / "replay" / "ruamel_yaml_runner" / "vendor"


def ensure_ruamel() -> Any:
    VENDOR.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(VENDOR))
    try:
        from ruamel.yaml import YAML  # type: ignore

        return YAML
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "--upgrade", "--target", str(VENDOR), "ruamel.yaml==0.19.1"])
        from ruamel.yaml import YAML  # type: ignore

        return YAML


def engine() -> Any:
    YAML = ensure_ruamel()
    y = YAML(typ="safe")
    y.default_flow_style = False
    return y


def parse_docs(yaml_engine: Any, text: str) -> list[Any]:
    return [normalize(item) for item in yaml_engine.load_all(text)]


def dump_docs(yaml_engine: Any, docs: list[Any]) -> str:
    chunks = []
    for item in docs:
        out = io.StringIO()
        yaml_engine.dump(item, out)
        chunks.append(out.getvalue())
    return "".join(chunks)


def run_contract(contract: dict[str, Any]) -> dict[str, Any]:
    yaml_engine = engine()
    params = contract.get("params") or {}
    op = contract["op"]
    text = params.get("yaml") or params.get("text") or ""
    if op in {"parse_to_value", "safe_load_json_value"}:
        docs = parse_docs(yaml_engine, text)
        return {"value": docs[0] if len(docs) == 1 else docs}
    if op in {"decode_stream_values", "parse_to_json_docs"}:
        return {"value": parse_docs(yaml_engine, text)}
    if op in {"parse_error_presence", "load_all_error", "load_single_error"}:
        try:
            parse_docs(yaml_engine, text)
        except Exception:
            return {"errors": True, "error": True}
        return {"errors": False, "error": False}
    if op in {"emit_parse_roundtrip", "stringify_reparse_json_docs"}:
        docs = parse_docs(yaml_engine, text)
        rendered = dump_docs(yaml_engine, docs)
        reparsed = parse_docs(yaml_engine, rendered)
        if op == "emit_parse_roundtrip":
            return {"value": deep_equal(docs, reparsed)}
        return {"value": reparsed}
    if op == "dump_value_to_yaml":
        out = io.StringIO()
        yaml_engine.dump(params.get("value"), out)
        return {"yaml": out.getvalue()}
    if op == "dump_value_roundtrip":
        out = io.StringIO()
        yaml_engine.dump(params.get("value"), out)
        docs = parse_docs(yaml_engine, out.getvalue())
        return {"value": docs[0] if len(docs) == 1 else docs}
    return {"error": f"unsupported op: {op}"}


def evaluate(contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    try:
        actual = run_contract(contract)
        if "error" in actual and "error" not in expected and "errors" not in expected:
            return {"ok": False, "actual": actual, "misses": [str(actual["error"])]}
        for key, value in expected.items():
            if key in {"comparison", "error_regex"}:
                continue
            if not deep_equal(actual.get(key), value):
                return {"ok": False, "actual": actual, "misses": [f"{key} mismatch"]}
        return {"ok": True, "actual": actual, "misses": []}
    except Exception as exc:
        return {"ok": False, "actual": {"error": type(exc).__name__, "message": str(exc)}, "misses": [f"{type(exc).__name__}: {exc}"]}


def main() -> int:
    source = json.loads(IN_JSON.read_text(encoding="utf-8"))
    contracts = source["contracts"]
    results = []
    survivors = []
    for contract in contracts:
        replay = evaluate(contract, contract["expected"])
        mutant = evaluate(contract, contract["mutant"]) if replay["ok"] else {"ok": False, "actual": {}, "misses": ["mutant not evaluated because replay failed"]}
        verified = replay["ok"] and not mutant["ok"]
        results.append(
            {
                "name": contract["name"],
                "version": contract["version"],
                "capability": contract["capability"],
                "source_kind": contract["source_kind"],
                "op": contract["op"],
                "status": "passed" if verified else "failed",
                "replay_passed": replay["ok"],
                "mutant_rejected": replay["ok"] and not mutant["ok"],
                "misses": replay["misses"],
                "mutant_misses": mutant["misses"],
                "actual": replay["actual"],
                "mutant_actual": mutant["actual"],
            }
        )
        if verified:
            survivors.append(contract)
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
        "runtime_package": "ruamel.yaml",
        "runtime_version": source["latest_version"],
        "input_contracts": len(contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_replay_failed": sum(1 for row in results if not row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "pass_rate": round(len(survivors) / len(contracts), 4) if contracts else 0,
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_cap.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_kind.items())},
        "failure_kinds": dict(failure_kinds.most_common()),
    }
    out = {
        "summary": summary,
        "survivors": survivors,
        "failed": [{"contract": contract, "result": result} for contract, result in zip(contracts, results) if result["status"] != "passed"],
        "results": results,
    }
    (BASE / "latest_replay_mutant_verified.json").write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")
    write_latest_markdown(BASE / "latest_replay_mutant_verified.md", "ruamel.yaml Latest Replay and Mutant Verification", out)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
