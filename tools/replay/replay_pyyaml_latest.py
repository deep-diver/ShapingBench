#!/usr/bin/env python3
"""Replay extracted PyYAML contracts against PyYAML 6.0.3 and kill mutants."""

from __future__ import annotations

import base64
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "yaml" / "pyyaml"
IN_JSON = BASE / "all_releases_language_independent.summary.json"
VENDOR = ROOT / "tools" / "replay" / "pyyaml_latest_runner" / "vendor"

sys.path.insert(0, str(VENDOR))
import yaml  # noqa: E402


TOKEN_MAP: dict[type[Any], str] = {
    yaml.DirectiveToken: "%",
    yaml.DocumentStartToken: "---",
    yaml.DocumentEndToken: "...",
    yaml.AliasToken: "*",
    yaml.AnchorToken: "&",
    yaml.TagToken: "!",
    yaml.ScalarToken: "_",
    yaml.BlockSequenceStartToken: "[[",
    yaml.BlockMappingStartToken: "{{",
    yaml.BlockEndToken: "]}",
    yaml.FlowSequenceStartToken: "[",
    yaml.FlowSequenceEndToken: "]",
    yaml.FlowMappingStartToken: "{",
    yaml.FlowMappingEndToken: "}",
    yaml.BlockEntryToken: ",",
    yaml.FlowEntryToken: ",",
    yaml.KeyToken: "?",
    yaml.ValueToken: ":",
}


def yaml_input(text: str) -> str | bytes:
    if any(0xDC80 <= ord(char) <= 0xDCFF for char in text):
        return text.encode("utf-8", "surrogateescape")
    return text


def scan_tokens(text: str) -> list[str]:
    tokens = []
    for token in yaml.scan(yaml_input(text)):
        if isinstance(token, (yaml.StreamStartToken, yaml.StreamEndToken)):
            continue
        tokens.append(TOKEN_MAP[token.__class__])
    return tokens


def events_equivalent(left: str, right: str, full: bool = False) -> bool:
    left_events = list(yaml.parse(yaml_input(left)))
    right_events = list(yaml.parse(yaml_input(right)))
    if len(left_events) != len(right_events):
        return False
    for left_event, right_event in zip(left_events, right_events):
        if left_event.__class__ is not right_event.__class__:
            return False
        if isinstance(left_event, yaml.AliasEvent) and full and left_event.anchor != right_event.anchor:
            return False
        if isinstance(left_event, (yaml.ScalarEvent, yaml.CollectionStartEvent)):
            both_explicit = left_event.tag not in {None, "!"} and right_event.tag not in {None, "!"}
            if (both_explicit or full) and left_event.tag != right_event.tag:
                return False
        if isinstance(left_event, yaml.ScalarEvent) and left_event.value != right_event.value:
            return False
    return True


def node_signature(node: Any) -> Any:
    if node is None:
        return None
    row: dict[str, Any] = {"type": node.__class__.__name__, "tag": node.tag}
    if isinstance(node, yaml.ScalarNode):
        row["value"] = node.value
    elif isinstance(node, yaml.SequenceNode):
        row["value"] = [node_signature(item) for item in node.value]
    elif isinstance(node, yaml.MappingNode):
        row["value"] = [[node_signature(key), node_signature(value)] for key, value in node.value]
    return row


def compose_signature(text: str) -> list[Any]:
    return [node_signature(node) for node in yaml.compose_all(yaml_input(text))]


def nodes_equivalent(left: str, right: str) -> bool:
    return compose_signature(left) == compose_signature(right)


def parse_structure(text: str) -> Any:
    loader = yaml.Loader(yaml_input(text))
    try:
        nodes = []
        while loader.check_event():
            if loader.check_event(
                yaml.StreamStartEvent,
                yaml.StreamEndEvent,
                yaml.DocumentStartEvent,
                yaml.DocumentEndEvent,
            ):
                loader.get_event()
                continue
            nodes.append(convert_structure(loader))
        return nodes[0] if len(nodes) == 1 else nodes
    finally:
        loader.dispose()


def convert_structure(loader: Any) -> Any:
    if loader.check_event(yaml.ScalarEvent):
        event = loader.get_event()
        return True if (event.tag or event.anchor or event.value) else None
    if loader.check_event(yaml.SequenceStartEvent):
        loader.get_event()
        sequence = []
        while not loader.check_event(yaml.SequenceEndEvent):
            sequence.append(convert_structure(loader))
        loader.get_event()
        return sequence
    if loader.check_event(yaml.MappingStartEvent):
        loader.get_event()
        mapping = []
        while not loader.check_event(yaml.MappingEndEvent):
            key = convert_structure(loader)
            value = convert_structure(loader)
            mapping.append([key, value])
        loader.get_event()
        return mapping
    if loader.check_event(yaml.AliasEvent):
        loader.get_event()
        return "*"
    loader.get_event()
    return "?"


def normalize_loaded(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"special": "nan"}
        if math.isinf(value):
            return {"special": "inf" if value > 0 else "-inf"}
        return value
    if isinstance(value, list):
        return [normalize_loaded(item) for item in value]
    if isinstance(value, tuple):
        return [normalize_loaded(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_loaded(item) for key, item in value.items()}
    return {"repr": str(value)}


def load_unicode(contract: dict[str, Any]) -> Any:
    params = contract.get("params") or {}
    raw = base64.b64decode(params.get("utf8_base64") or "")
    op = contract["op"]
    if op == "load_unicode_text":
        data: str | bytes = params.get("text") or ""
    elif op == "load_unicode_utf8_bytes":
        data = raw
    elif op == "load_unicode_utf8_bom_bytes":
        data = b"\xef\xbb\xbf" + raw
    elif op == "load_unicode_utf16be_bom_bytes":
        data = b"\xfe\xff" + raw.decode("utf-8").encode("utf-16-be")
    elif op == "load_unicode_utf16le_bom_bytes":
        data = b"\xff\xfe" + raw.decode("utf-8").encode("utf-16-le")
    else:
        raise ValueError(op)
    return yaml.full_load(data)


def strip_dump(text: str) -> str:
    if text.endswith("\n...\n"):
        text = text[:-5]
    if text.endswith("\n"):
        text = text[:-1]
    return text


def run_contract(contract: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    params = contract.get("params") or {}
    text = params.get("yaml") or ""
    op = contract["op"]
    try:
        if op == "scan_tokens":
            return {"tokens": scan_tokens(text)}
        if op == "parse_canonical_equivalence":
            return {"value": events_equivalent(text, expected.get("canonical") or "")}
        if op == "compose_canonical_equivalence":
            return {"value": nodes_equivalent(text, expected.get("canonical") or "")}
        if op == "emit_parse_roundtrip":
            output = yaml.emit(list(yaml.parse(yaml_input(text))))
            return {"value": events_equivalent(text, output)}
        if op == "parse_structure":
            return {"structure": parse_structure(text)}
        if op == "safe_load_json_value":
            docs = [normalize_loaded(item) for item in yaml.safe_load_all(yaml_input(text))]
            return {"value": docs[0] if len(docs) == 1 else docs}
        if op == "load_all_error":
            try:
                list(yaml.load_all(yaml_input(text), Loader=yaml.FullLoader))
            except yaml.YAMLError:
                return {"error": True}
            return {"error": False}
        if op == "load_single_error":
            try:
                yaml.load(yaml_input(text), Loader=yaml.FullLoader)
            except yaml.YAMLError:
                return {"error": True}
            return {"error": False}
        if op.startswith("load_unicode_"):
            return {"value": load_unicode(contract)}
        if op == "schema_safe_load_scalar":
            value = yaml.safe_load(yaml_input(text))
            if isinstance(value, bool):
                return {"kind": "bool", "value": value}
            if value is None:
                return {"kind": "null", "value": None}
            if isinstance(value, int) and not isinstance(value, bool):
                return {"kind": "int", "value": value}
            if isinstance(value, float):
                if math.isnan(value):
                    return {"kind": "float", "special": "nan"}
                if math.isinf(value):
                    return {"kind": "float", "special": "inf" if value > 0 else "-inf"}
                return {"kind": "float", "value": value}
            return {"kind": "str", "value": str(value)}
        if op == "schema_safe_dump_loaded_scalar":
            return {"dump": strip_dump(yaml.safe_dump(yaml.safe_load(yaml_input(text)), explicit_end=False))}
        return {"error": "UnsupportedOperation", "message": op}
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc)}


def expected_matches(contract: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, dict[str, Any], list[str]]:
    actual = run_contract(contract, expected)
    if "error" in actual and "error" not in expected:
        return False, actual, [f"{actual.get('error')}: {actual.get('message', '')}"]
    if "canonical" in expected:
        ok = actual.get("value") is True
        return ok, actual, [] if ok else ["canonical semantic equivalence mismatch"]
    for key, value in expected.items():
        if key == "comparison":
            continue
        if actual.get(key) != value:
            return False, actual, [f"{key} mismatch: expected {value!r}, got {actual.get(key)!r}"]
    return True, actual, []


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    source = json.loads(IN_JSON.read_text(encoding="utf-8"))
    contracts = source["contracts"]
    results = []
    survivors = []
    for contract in contracts:
        replay_ok, actual, misses = expected_matches(contract, contract["expected"])
        mutant_ok, mutant_actual, mutant_misses = (
            expected_matches(contract, contract["mutant"])
            if replay_ok
            else (False, {}, ["mutant not evaluated because replay failed"])
        )
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "version": contract.get("version"),
            "capability": contract.get("capability"),
            "source_kind": contract.get("source_kind"),
            "op": contract.get("op"),
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": replay_ok and not mutant_ok,
            "misses": misses,
            "mutant_misses": mutant_misses,
            "actual": actual,
            "mutant_actual": mutant_actual,
        }
        results.append(row)
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
        "latest_version": source["latest_version"],
        "pyyaml_runtime_version": yaml.__version__,
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
    out = {**summary, "survivors": survivors, "failed": [
        {"contract": contract, "result": result}
        for contract, result in zip(contracts, results)
        if result["status"] != "passed"
    ], "results": results}
    (BASE / "latest_replay_mutant_verified.json").write_text(
        json.dumps(out, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, BASE / "latest_replay_mutant_verified.rpl")

    lines = [
        "# PyYAML Latest Replay and Mutant Verification",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Runtime version: `{summary['pyyaml_runtime_version']}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['latest_replay_passed']}",
        f"Replay failed: {summary['latest_replay_failed']}",
        f"Mutants killed after replay pass: {summary['latest_mutant_killed']}",
        f"Latest survivors: {summary['latest_survivors']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Capability",
        "",
        "| Capability | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for cap, counter in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## By Source Kind", "", "| Source kind | Passed | Failed |", "| --- | ---: | ---: |"])
    for kind, counter in summary["by_source_kind"].items():
        lines.append(f"| `{kind}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Miss |", "| --- | --- | --- |"])
    for row in out["failed"][:80]:
        miss = (row["result"].get("misses") or [""])[0].replace("|", "\\|")
        lines.append(f"| `{row['contract']['name']}` | `{row['contract']['capability']}` | {miss} |")
    (BASE / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {key: summary[key] for key in [
        "latest_version",
        "pyyaml_runtime_version",
        "input_contracts",
        "latest_replay_passed",
        "latest_replay_failed",
        "latest_mutant_killed",
        "latest_survivors",
        "failure_kinds",
        "by_capability",
        "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
