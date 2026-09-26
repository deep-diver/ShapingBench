#!/usr/bin/env python3
"""Shared helpers for YAML Rank 4/5 origin extraction and replay."""

from __future__ import annotations

import json
import math
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FINAL_COMMON = ROOT / "contracts" / "yaml" / "common" / "yaml_cross_common_summary.json"


LANGUAGE_SPECIFIC_PATTERNS = [
    "!!python/",
    "tag:yaml.org,2002:python/",
    "!!js/",
    "tag:yaml.org,2002:js/",
    "!!javascript/",
    "function ",
]


def semver_key(version: str) -> tuple[int, int, int, int, str]:
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[-.]([0-9A-Za-z.-]+))?$", version)
    if not match:
        return (999, 999, 999, 1, version)
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    pre = match.group(4)
    return (major, minor, patch, 0 if pre else 1, pre or "")


def git_output(args: list[str], *, repo: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *args],
            text=True,
            stderr=subprocess.DEVNULL,
            errors="surrogateescape",
        )
    except subprocess.CalledProcessError:
        return None


def git_tags(repo: Path) -> set[str]:
    output = git_output(["tag", "--list"], repo=repo) or ""
    return {line.strip() for line in output.splitlines() if line.strip()}


def git_ls(repo: Path, rev_path: str) -> list[str]:
    output = git_output(["ls-tree", "-r", "--name-only", rev_path], repo=repo) or ""
    return [line.strip() for line in output.splitlines() if line.strip()]


def git_show(repo: Path, rev_path: str) -> str | None:
    return git_output(["show", rev_path], repo=repo)


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
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {str(key): normalize(item) for key, item in sorted(value.items())}
        pairs = [[normalize(key), normalize(item)] for key, item in value.items()]
        return {"__pairs__": sorted(pairs, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True))}
    if hasattr(value, "isoformat"):
        text = value.isoformat()
        return text[:10] if text.endswith("T00:00:00") or text.endswith(" 00:00:00") else text
    return str(value)


def has_language_specific_yaml(text: str) -> bool:
    return any(pattern in text for pattern in LANGUAGE_SPECIFIC_PATTERNS)


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = json.loads(json.dumps(expected, ensure_ascii=True))
    if "value" in mutated:
        value = mutated["value"]
        if isinstance(value, bool):
            mutated["value"] = not value
        elif isinstance(value, list):
            mutated["value"] = value + ["__mutant__"]
        elif isinstance(value, dict):
            mutated["value"]["__mutant__"] = True
        elif isinstance(value, str):
            mutated["value"] = value + "__mutant__"
        elif isinstance(value, (int, float)):
            mutated["value"] = value + 1
        else:
            mutated["value"] = "__mutant__"
    elif "yaml" in mutated:
        mutated["yaml"] = str(mutated["yaml"]) + "__mutant__"
    elif "errors" in mutated:
        mutated["errors"] = not bool(mutated["errors"])
    elif "error" in mutated:
        mutated["error"] = not bool(mutated["error"])
    else:
        mutated["mutant"] = True
    return mutated


def make_contract(
    *,
    project: str,
    version: str,
    tag: str,
    capability: str,
    op: str,
    stem: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    source: str,
    source_kind: str,
    published_at: str | None = None,
) -> dict[str, Any]:
    return {
        "name": f"{version}:{op}:{stem}",
        "version": version,
        "published_at": published_at,
        "capability": capability,
        "op": op,
        "params": params,
        "expected": expected,
        "mutant": mutate_expected(expected),
        "evidence": {"project": project, "tag": tag, "source": source},
        "source_kind": source_kind,
    }


def semantic_identity(row: dict[str, Any]) -> str:
    op = row.get("op")
    params = row.get("params") or {}
    expected = row.get("expected") or {}
    yaml_text = params.get("yaml") or params.get("text") or params.get("json") or ""
    schema = params.get("schema")
    if op in {"parse_to_value", "safe_load_json_value"}:
        return json.dumps(["parse-value", schema, yaml_text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"parse_to_json_docs", "decode_stream_values"}:
        return json.dumps(["parse-docs", schema, yaml_text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"parse_error_presence", "load_all_error", "load_single_error"}:
        return json.dumps(["parse-error", yaml_text, bool(expected.get("errors", expected.get("error")))], sort_keys=True, ensure_ascii=True)
    if op in {"stringify_reparse_json_docs", "emit_parse_roundtrip"}:
        return json.dumps(["roundtrip", schema, yaml_text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"dump_value_to_yaml", "dump_option_yaml"}:
        return json.dumps(["dump", schema, params.get("value"), params.get("options"), expected], sort_keys=True, ensure_ascii=True)
    if op == "emitted_yaml_matches_json":
        return json.dumps(["emit-equivalence", params.get("emitted_yaml"), expected], sort_keys=True, ensure_ascii=True)
    return json.dumps([op, params, expected], sort_keys=True, ensure_ascii=True)


def load_common_identity_set() -> set[str]:
    if not FINAL_COMMON.exists():
        return set()
    data = json.loads(FINAL_COMMON.read_text(encoding="utf-8"))
    return {semantic_identity(row) for row in data.get("final_common_contracts", [])}


def unique_rows(rows: list[dict[str, Any]], common: set[str]) -> tuple[list[dict[str, Any]], int, int]:
    seen: dict[str, dict[str, Any]] = {}
    overlap = 0
    duplicate = 0
    for row in rows:
        sid = semantic_identity(row)
        if sid in common:
            overlap += 1
            continue
        key = json.dumps([row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)
        if key in seen:
            duplicate += 1
            continue
        seen[key] = row
    return list(seen.values()), overlap, duplicate


def deep_equal(left: Any, right: Any) -> bool:
    return json.dumps(normalize(left), sort_keys=True, ensure_ascii=True) == json.dumps(normalize(right), sort_keys=True, ensure_ascii=True)


def write_rpl(rows: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in rows:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def counter_dict(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(row.get(key, "unknown") for row in rows).items()))


def write_extraction_markdown(
    *,
    path: Path,
    title: str,
    summary: dict[str, Any],
    release_counts: list[dict[str, Any]],
) -> None:
    lines = [
        f"# {title}",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Releases enumerated: {summary['releases_enumerated']}",
        f"Releases with extractable source: {summary['releases_with_extractable_source']}",
        f"Raw observed contracts: {summary['raw_observed_contracts']}",
        f"Overlap with final common 1172 skipped: {summary['final_common_overlap_skipped']}",
        f"Duplicate observed contracts skipped: {summary['duplicate_contracts_skipped']}",
        f"Extracted origin non-common candidates: {summary['extracted_contracts']}",
        "",
        "## By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Release Counts", "", "| Version | Tag | Seen | New | Overlap | Duplicate |", "| --- | --- | ---: | ---: | ---: | ---: |"])
    for row in release_counts:
        lines.append(
            f"| `{row['version']}` | `{row.get('tag') or ''}` | {row.get('seen', 0)} | "
            f"{row.get('new', 0)} | {row.get('overlap', 0)} | {row.get('duplicate', 0)} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latest_markdown(path: Path, title: str, payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    lines = [
        f"# {title}",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['latest_replay_passed']}",
        f"Replay failed: {summary['latest_replay_failed']}",
        f"Mutants killed: {summary['latest_mutant_killed']}",
        f"Latest survivors: {summary['latest_survivors']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Capability",
        "",
        "| Capability | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for cap, counts in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {counts.get('passed', 0)} | {counts.get('failed', 0)} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Miss |", "| --- | --- | --- |"])
    for row in payload.get("failed", [])[:160]:
        miss = (row["result"].get("misses") or [""])[0].replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| `{row['contract']['name']}` | `{row['contract']['capability']}` | {miss} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
