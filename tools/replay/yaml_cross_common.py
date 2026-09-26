#!/usr/bin/env python3
"""Cross-replay YAML Rank 1/2/3 contracts and hidden-filter with Rank 4/5."""

from __future__ import annotations

import json
import math
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "yaml" / "common"
PYAML = ROOT / "contracts" / "yaml" / "pyyaml" / "latest_replay_mutant_verified.json"
EEMELI = ROOT / "contracts" / "yaml" / "eemeli-yaml" / "latest_replay_mutant_verified.json"
GOYAML = ROOT / "contracts" / "yaml" / "go-yaml" / "latest_replay_mutant_verified.json"
NODE_RUNNER = ROOT / "tools" / "replay" / "yaml_cross_node_runner" / "replay.mjs"
GO_RUNNER_DIR = ROOT / "tools" / "replay" / "go_yaml_latest_runner"
RUAMEL_VENDOR = ROOT / "tools" / "replay" / "ruamel_yaml_runner" / "vendor"

sys.path.insert(0, str(ROOT / "tools" / "replay" / "pyyaml_latest_runner" / "vendor"))
import yaml as pyyaml  # noqa: E402


def ensure_ruamel() -> Any:
    RUAMEL_VENDOR.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(RUAMEL_VENDOR))
    try:
        from ruamel.yaml import YAML  # type: ignore
        return YAML
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "--upgrade", "--target", str(RUAMEL_VENDOR), "ruamel.yaml==0.19.1"])
        from ruamel.yaml import YAML  # type: ignore
        return YAML


def load(path: Path, origin: str) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("survivors", [])
    for index, row in enumerate(rows):
        row["origin"] = origin
        row["cross_id"] = f"{origin}:{index}:{row['name']}"
    return rows


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"special": "nan"}
        if math.isinf(value):
            return {"special": "inf" if value > 0 else "-inf"}
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {str(key): normalize(item) for key, item in sorted(value.items())}
        pairs = [[normalize(key), normalize(item)] for key, item in value.items()]
        return {"__pairs__": sorted(pairs, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))}
    if hasattr(value, "isoformat"):
        text = value.isoformat()
        return text[:10] if text.endswith("00:00:00") else text
    return str(value)


def pyyaml_input(text: str) -> str | bytes:
    if any(0xDC80 <= ord(char) <= 0xDCFF for char in text):
        return text.encode("utf-8", "surrogateescape")
    return text


def py_parse_docs(text: str) -> list[Any]:
    return [normalize(item) for item in pyyaml.safe_load_all(pyyaml_input(text))]


def py_scalar_kind(value: Any) -> dict[str, Any]:
    value = normalize(value)
    if isinstance(value, bool):
        return {"kind": "bool", "value": value}
    if value is None:
        return {"kind": "null", "value": None}
    if isinstance(value, int):
        return {"kind": "int", "value": value}
    if isinstance(value, float):
        if math.isnan(value):
            return {"kind": "float", "special": "nan"}
        if math.isinf(value):
            return {"kind": "float", "special": "inf" if value > 0 else "-inf"}
        return {"kind": "float", "value": value}
    if isinstance(value, dict) and "special" in value:
        return {"kind": "float", "special": value["special"]}
    return {"kind": "str", "value": str(value)}


def lookup(value: Any, path: list[Any]) -> Any:
    current = value
    for step in path:
        if isinstance(current, dict):
            current = current.get(str(step))
        else:
            return None
    return current


def strip_dump(text: str) -> str:
    if text.endswith("\n...\n"):
        text = text[:-5] + "\n"
    return text[:-1] if text.endswith("\n") else text


def py_run(contract: dict[str, Any], expected: dict[str, Any], engine: str) -> dict[str, Any]:
    params = contract.get("params") or {}
    op = contract["op"]
    if engine == "pyyaml":
        parse_docs = py_parse_docs
        dump = lambda value: pyyaml.safe_dump(value, sort_keys=True)
    else:
        YAML = ensure_ruamel()
        yaml_rt = YAML(typ="safe")
        yaml_rt.default_flow_style = False

        def parse_docs(text: str) -> list[Any]:
            return [normalize(item) for item in yaml_rt.load_all(text)]

        def dump(value: Any) -> str:
            from io import StringIO

            out = StringIO()
            yaml_rt.dump(value, out)
            return out.getvalue()

    if op in {"safe_load_json_value", "parse_to_value"}:
        docs = parse_docs(params.get("yaml") or "")
        return {"value": docs[0] if len(docs) == 1 else docs}
    if op == "parse_to_value_at_path":
        docs = parse_docs(params.get("yaml") or "")
        return {"value": lookup(docs[0] if len(docs) == 1 else docs, params.get("path") or [])}
    if op in {"parse_to_json_docs", "decode_stream_values"}:
        return {"value": parse_docs(params.get("yaml") or "")}
    if op == "json_parse_success":
        docs = parse_docs(params.get("json") or "")
        return {"value": docs[0] if len(docs) == 1 else docs}
    if op == "json_stringify_reparse_success":
        value = parse_docs(params.get("json") or "")[0]
        return {"value": parse_docs(json.dumps(value))[0]}
    if op == "stringify_reparse_json_docs":
        rendered = "".join(dump(item) for item in parse_docs(params.get("yaml") or ""))
        return {"value": parse_docs(rendered)}
    if op == "emitted_yaml_matches_json":
        return {"value": parse_docs(params.get("emitted_yaml") or "")}
    if op in {"load_all_error", "load_single_error", "parse_error_presence"}:
        try:
            parse_docs(params.get("yaml") or "")
        except Exception:
            return {"error": True, "errors": True}
        return {"error": False, "errors": False}
    if op == "schema_safe_load_scalar":
        docs = parse_docs(params.get("yaml") or "")
        return py_scalar_kind(docs[0] if docs else None)
    if op == "schema_safe_dump_loaded_scalar":
        docs = parse_docs(params.get("yaml") or "")
        return {"dump": strip_dump(dump(docs[0] if docs else None))}
    if op in {"parse_canonical_equivalence", "compose_canonical_equivalence"}:
        left = parse_docs(params.get("yaml") or "")
        right = parse_docs(expected.get("canonical") or params.get("canonical") or "")
        return {"value": canonical(left) == canonical(right)}
    if op == "emit_parse_roundtrip":
        docs = parse_docs(params.get("yaml") or "")
        rendered = "".join(dump(item) for item in docs)
        return {"value": canonical(docs) == canonical(parse_docs(rendered))}
    if op.startswith("load_unicode_"):
        docs = parse_docs(params.get("text") or "")
        return {"value": docs[0] if len(docs) == 1 else docs}
    if op in {"scan_tokens", "parse_structure", "cst_roundtrip_source", "parse_node_signature"}:
        return {"error": "nonportable-surface"}
    if op == "marshal_to_yaml":
        return {"yaml": dump(params.get("value"))}
    return {"error": f"unsupported op: {op}"}


def canonical(value: Any) -> Any:
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value)}
    return value


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(canonical(left), sort_keys=True, ensure_ascii=True) == json.dumps(canonical(right), sort_keys=True, ensure_ascii=True)


def eval_python(target: str, contracts: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    survivors = []
    for contract in contracts:
        replay = evaluate_one(lambda c, e: py_run(c, e, target), contract, contract["expected"])
        mutant = evaluate_one(lambda c, e: py_run(c, e, target), contract, contract["mutant"]) if replay["ok"] else {"ok": False, "actual": {}, "misses": ["mutant not evaluated because replay failed"]}
        verified = replay["ok"] and not mutant["ok"]
        row = result_row(contract, replay, mutant, verified)
        results.append(row)
        if verified:
            survivors.append(contract)
    return {"target": target, "input_contracts": len(contracts), "survivors": survivors, "results": results}


def evaluate_one(run: Any, contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    try:
        actual = run(contract, expected)
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


def result_row(contract: dict[str, Any], replay: dict[str, Any], mutant: dict[str, Any], verified: bool) -> dict[str, Any]:
    return {
        "name": contract["name"],
        "cross_id": contract["cross_id"],
        "origin": contract["origin"],
        "capability": contract["capability"],
        "op": contract["op"],
        "status": "passed" if verified else "failed",
        "replay_passed": replay["ok"],
        "mutant_rejected": replay["ok"] and not mutant["ok"],
        "misses": replay.get("misses") or [],
        "mutant_misses": mutant.get("misses") or [],
        "actual": replay.get("actual"),
        "mutant_actual": mutant.get("actual"),
    }


def eval_node(target: str, contracts: list[dict[str, Any]]) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump({"contracts": contracts}, handle)
        path = Path(handle.name)
    try:
        raw = subprocess.check_output(["node", "--no-warnings", str(NODE_RUNNER), target, str(path)], cwd=NODE_RUNNER.parent, text=True, stderr=subprocess.STDOUT)
        return json.loads(raw)
    finally:
        path.unlink(missing_ok=True)


def eval_go(contracts: list[dict[str, Any]]) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump({"contracts": contracts}, handle)
        path = Path(handle.name)
    try:
        raw = subprocess.check_output(["go", "run", ".", str(path)], cwd=GO_RUNNER_DIR, text=True, stderr=subprocess.STDOUT)
        data = json.loads(raw)
        data["target"] = "go-yaml"
        return data
    finally:
        path.unlink(missing_ok=True)


def result_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_origin = defaultdict(Counter)
    by_cap = defaultdict(Counter)
    failure = Counter()
    for row in results:
        by_origin[row.get("origin", "unknown")][row["status"]] += 1
        by_cap[row["capability"]][row["status"]] += 1
        if row["status"] != "passed":
            miss = row.get("misses", ["unknown"])[0] if row.get("misses") else "unknown"
            failure[miss.split(":", 1)[0]] += 1
    return {
        "passed": sum(1 for row in results if row["status"] == "passed"),
        "failed": sum(1 for row in results if row["status"] != "passed"),
        "by_origin": {key: dict(value) for key, value in sorted(by_origin.items())},
        "by_capability": {key: dict(value) for key, value in sorted(by_cap.items())},
        "failure_kinds": dict(failure.most_common()),
    }


def unique_key(contract: dict[str, Any]) -> str:
    return json.dumps([contract["origin"], contract["name"], contract["op"], contract["params"], contract["expected"]], sort_keys=True, ensure_ascii=True)


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  origin {json.dumps(row['origin'], ensure_ascii=True)}")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    origins = {
        "pyyaml": load(PYAML, "pyyaml"),
        "eemeli-yaml": load(EEMELI, "eemeli-yaml"),
        "go-yaml": load(GOYAML, "go-yaml"),
    }

    rank_results = {
        "pyyaml_on_eemeli": eval_node("eemeli", origins["pyyaml"]),
        "pyyaml_on_goyaml": eval_go(origins["pyyaml"]),
        "eemeli_on_pyyaml": eval_python("pyyaml", origins["eemeli-yaml"]),
        "eemeli_on_goyaml": eval_go(origins["eemeli-yaml"]),
        "goyaml_on_pyyaml": eval_python("pyyaml", origins["go-yaml"]),
        "goyaml_on_eemeli": eval_node("eemeli", origins["go-yaml"]),
    }

    origin_candidate_sets: dict[str, list[dict[str, Any]]] = {}
    for origin, left_name, right_name in [
        ("pyyaml", "pyyaml_on_eemeli", "pyyaml_on_goyaml"),
        ("eemeli-yaml", "eemeli_on_pyyaml", "eemeli_on_goyaml"),
        ("go-yaml", "goyaml_on_pyyaml", "goyaml_on_eemeli"),
    ]:
        left = {row["cross_id"] for row in rank_results[left_name]["results"] if row["status"] == "passed"}
        right = {row["cross_id"] for row in rank_results[right_name]["results"] if row["status"] == "passed"}
        origin_candidate_sets[origin] = [row for row in origins[origin] if row["cross_id"] in left and row["cross_id"] in right]

    candidates_by_key: dict[str, dict[str, Any]] = {}
    for rows in origin_candidate_sets.values():
        for row in rows:
            candidates_by_key.setdefault(unique_key(row), row)
    candidates = list(candidates_by_key.values())

    hidden_results = {
        "candidate_on_js_yaml": eval_node("js-yaml", candidates),
        "candidate_on_ruamel": eval_python("ruamel", candidates),
    }
    js_pass = {row["cross_id"] for row in hidden_results["candidate_on_js_yaml"]["results"] if row["status"] == "passed"}
    ruamel_pass = {row["cross_id"] for row in hidden_results["candidate_on_ruamel"]["results"] if row["status"] == "passed"}
    final = [row for row in candidates if row["cross_id"] in js_pass and row["cross_id"] in ruamel_pass]

    summary = {
        "domain": "YAML Parser/Emitter",
        "rank_1": "yaml/pyyaml 6.0.3",
        "rank_2": "eemeli/yaml 2.9.0",
        "rank_3": "go-yaml/yaml v3.0.1",
        "rank_4_hidden": "nodeca/js-yaml 5.4.1",
        "rank_5_hidden": "ruamel.yaml 0.19.1",
        "input_latest_survivors": {origin: len(rows) for origin, rows in origins.items()},
        "rank_1_2_3_cross": {name: result_stats(data["results"]) for name, data in rank_results.items()},
        "origin_common_candidates": {origin: len(rows) for origin, rows in origin_candidate_sets.items()},
        "common_candidates_before_hidden": len(candidates),
        "hidden_filter": {name: result_stats(data["results"]) for name, data in hidden_results.items()},
        "final_common": len(final),
        "final_by_origin": dict(Counter(row["origin"] for row in final)),
        "final_by_capability": dict(Counter(row["capability"] for row in final)),
    }
    out = {
        **summary,
        "origin_common_candidate_contracts": origin_candidate_sets,
        "common_candidates": candidates,
        "final_common_contracts": final,
        "rank_1_2_3_cross_details": rank_results,
        "hidden_filter_details": hidden_results,
    }
    (OUT_DIR / "yaml_cross_common_summary.json").write_text(json.dumps(out, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(final, OUT_DIR / "yaml_final_common.rpl")

    lines = [
        "# YAML Cross-Replay Common",
        "",
        f"Final common: {len(final)}",
        "",
        "## Rank 1/2/3 Cross Replay",
        "",
        "| Replay | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for name, stats in summary["rank_1_2_3_cross"].items():
        lines.append(f"| `{name}` | {stats['passed']} | {stats['failed']} |")
    lines.extend(["", "## Origin Candidates", "", "| Origin | Candidates |", "| --- | ---: |"])
    for origin, count in summary["origin_common_candidates"].items():
        lines.append(f"| `{origin}` | {count} |")
    lines.extend(["", "## Hidden Filter", "", "| Replay | Passed | Failed |", "| --- | ---: | ---: |"])
    for name, stats in summary["hidden_filter"].items():
        lines.append(f"| `{name}` | {stats['passed']} | {stats['failed']} |")
    lines.extend(["", "## Final Common By Capability", "", "| Capability | Count |", "| --- | ---: |"])
    for cap, count in sorted(summary["final_by_capability"].items()):
        lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "yaml_cross_common_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
