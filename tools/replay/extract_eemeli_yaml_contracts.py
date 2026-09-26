#!/usr/bin/env python3
"""Extract eemeli/yaml release-history contracts, excluding PyYAML overlap."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "yaml" / "eemeli-yaml"
YAML_TEST_SUITE = ROOT / ".cache" / "yaml" / "yaml-test-suite"
JSON_TEST_SUITE = ROOT / ".cache" / "yaml" / "json-test-suite"
PY_YAML_SURVIVORS = ROOT / "contracts" / "yaml" / "pyyaml" / "latest_replay_mutant_verified.json"
OUT_DIR = ROOT / "contracts" / "yaml" / "eemeli-yaml"
NPM = "https://registry.npmjs.org/yaml"


LANGUAGE_SPECIFIC_PATTERNS = [
    "!!js/",
    "tag:yaml.org,2002:js/",
]


def semver_key(version: str) -> tuple[int, int, int, int, str]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$", version)
    if not match:
        return (999, 999, 999, 1, version)
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    pre = match.group(4)
    return (major, minor, patch, 0 if pre else 1, pre or "")


def load_npm() -> dict[str, Any]:
    with urllib.request.urlopen(NPM, timeout=90) as response:
        return json.load(response)


def git_tags() -> set[str]:
    output = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in output.splitlines() if line.strip()}


def git_show(repo: Path, rev_path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "show", rev_path],
            text=True,
            stderr=subprocess.DEVNULL,
            errors="surrogateescape",
        )
    except subprocess.CalledProcessError:
        return None


def git_ls(repo: Path, rev_path: str) -> list[str]:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "--name-only", rev_path],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def submodule_sha(tag: str, path: str) -> str | None:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(REPO), "ls-tree", tag, path],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    match = re.search(r"\bcommit\s+([0-9a-f]{40})\b", output)
    return match.group(1) if match else None


def yts_unescape(value: Any) -> Any:
    if isinstance(value, str):
        value = value.replace("\u2423", " ")
        value = re.sub(r"\u2014*\u00bb", "\t", value)
        value = value.replace("\u2190", "\r")
        value = value.replace("\u21d4", "x{FEFF}")
        value = value.replace("\u21b5", "")
        value = value.replace("\u220e\n", "")
        return value
    if isinstance(value, list):
        return [yts_unescape(item) for item in value]
    if isinstance(value, dict):
        return {key: yts_unescape(item) for key, item in value.items()}
    return value


def has_language_specific_yaml(text: str) -> bool:
    return any(pattern in text for pattern in LANGUAGE_SPECIFIC_PATTERNS)


def normalize_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_json(item) for key, item in value.items()}
    return str(value)


def parse_json_docs(text: str) -> list[Any] | None:
    docs = []
    for part in text.splitlines():
        if not part.strip():
            continue
        try:
            docs.append(normalize_json(json.loads(part)))
        except json.JSONDecodeError:
            try:
                docs.append(normalize_json(json.loads(text)))
                break
            except json.JSONDecodeError:
                return None
    return docs or None


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = json.loads(json.dumps(expected))
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
    elif "errors" in mutated:
        mutated["errors"] = not bool(mutated["errors"])
    elif "yaml" in mutated:
        mutated["yaml"] = str(mutated["yaml"]) + "__mutant__"
    elif "text" in mutated:
        mutated["text"] = str(mutated["text"]) + "__mutant__"
    else:
        mutated["mutant"] = True
    return mutated


def contract(
    *,
    tag: str,
    version: str,
    published_at: str | None,
    capability: str,
    op: str,
    stem: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    source: str,
    source_kind: str,
) -> dict[str, Any]:
    name = f"{version}:{op}:{stem}"
    return {
        "name": name,
        "version": version,
        "published_at": published_at,
        "capability": capability,
        "op": op,
        "params": params,
        "expected": expected,
        "mutant": mutate_expected(expected),
        "evidence": {"tag": tag, "source": source},
        "source_kind": source_kind,
    }


def generic_identity(row: dict[str, Any]) -> str:
    op = row["op"]
    params = row.get("params") or {}
    expected = row.get("expected") or {}
    text = params.get("yaml") or params.get("json") or ""
    if op in {"safe_load_json_value", "schema_safe_load_scalar"}:
        return json.dumps(["parse-json", text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"load_all_error", "load_single_error"}:
        return json.dumps(["parse-error", text, True], sort_keys=True, ensure_ascii=True)
    if op in {"parse_to_json_docs", "json_parse_success"}:
        return json.dumps(["parse-json", text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"parse_error_presence"}:
        return json.dumps(["parse-error", text, expected.get("errors")], sort_keys=True, ensure_ascii=True)
    return json.dumps([op, text, expected], sort_keys=True, ensure_ascii=True)


def load_pyyaml_identity_set() -> set[str]:
    if not PY_YAML_SURVIVORS.exists():
        return set()
    data = json.loads(PY_YAML_SURVIVORS.read_text(encoding="utf-8"))
    return {generic_identity(row) for row in data.get("survivors", [])}


def identity(row: dict[str, Any]) -> str:
    return json.dumps([row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)


def extract_yaml_test_suite(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sha = submodule_sha(tag, "tests/yaml-test-suite")
    if not sha:
        return [], {"yaml_test_suite_sha": None, "yaml_suite_files": 0, "yaml_suite_seen": 0}
    names = sorted(name for name in git_ls(YAML_TEST_SUITE, f"{sha}:src") if name.endswith(".yaml"))
    contracts: list[dict[str, Any]] = []
    seen_count = 0
    parsed_files = 0
    test_skip: dict[str, set[str] | bool] = {
        "2JQS/0": {"errors"},
        "9MMA/0": {"errors"},
        "SF5V/0": {"errors"},
    }
    for name in names:
        text = git_show(YAML_TEST_SUITE, f"{sha}:src/{name}")
        if not text:
            continue
        try:
            data = yts_unescape(yaml.safe_load(text))
        except Exception:
            continue
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            continue
        metadata = data[0]
        if metadata.get("skip"):
            continue
        parsed_files += 1
        cases = data
        for case_index, case in enumerate(cases):
            if not isinstance(case, dict) or case.get("skip"):
                continue
            source = case.get("yaml")
            if not isinstance(source, str) or has_language_specific_yaml(source):
                continue
            fail = bool(case.get("fail"))
            stem = f"{Path(name).stem}_{case_index}"
            params = {
                "yaml": source,
                "yaml_test_id": Path(name).stem,
                "case_index": case_index,
            }
            skip = test_skip.get(f"{Path(name).stem}/{case_index}")
            if skip is not True and not (isinstance(skip, set) and "errors" in skip):
                expected_errors = {"errors": fail}
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.parse.errors",
                        op="parse_error_presence",
                        stem=stem,
                        params=params,
                        expected=expected_errors,
                        source=f"tests/yaml-test-suite/src/{name}",
                        source_kind="yaml-test-suite",
                    )
                )
            expected_json = parse_json_docs(case.get("json") or "")
            if expected_json is not None and not fail:
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.parse.json-value",
                        op="parse_to_json_docs",
                        stem=stem,
                        params=params,
                        expected={"value": expected_json},
                        source=f"tests/yaml-test-suite/src/{name}",
                        source_kind="yaml-test-suite",
                    )
                )
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.stringify.roundtrip",
                        op="stringify_reparse_json_docs",
                        stem=stem,
                        params=params,
                        expected={"value": expected_json},
                        source=f"tests/yaml-test-suite/src/{name}",
                        source_kind="yaml-test-suite",
                    )
                )
            if isinstance(case.get("emit"), str) and expected_json is not None and not fail:
                dump = case.get("emit")
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.emit.equivalence",
                        op="emitted_yaml_matches_json",
                        stem=stem,
                        params={**params, "emitted_yaml": dump},
                        expected={"value": expected_json},
                        source=f"tests/yaml-test-suite/src/{name}",
                        source_kind="yaml-test-suite",
                    )
                )
            if not fail:
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.cst.roundtrip",
                        op="cst_roundtrip_source",
                        stem=stem,
                        params=params,
                        expected={"text": source},
                        source=f"tests/yaml-test-suite/src/{name}",
                        source_kind="yaml-test-suite",
                    )
                )
    return contracts, {
        "yaml_test_suite_sha": sha,
        "yaml_suite_files": parsed_files,
        "yaml_suite_seen": seen_count,
    }


def extract_json_test_suite(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sha = submodule_sha(tag, "tests/json-test-suite")
    if not sha:
        return [], {"json_test_suite_sha": None, "json_suite_files": 0, "json_suite_seen": 0}
    skipped = {
        "y_object_duplicated_key.json",
        "y_object_duplicated_key_and_value.json",
    }
    names = sorted(
        name
        for name in git_ls(JSON_TEST_SUITE, f"{sha}:test_parsing")
        if name.startswith("y_") and name.endswith(".json") and name not in skipped
    )
    contracts: list[dict[str, Any]] = []
    seen_count = 0
    for name in names:
        text = git_show(JSON_TEST_SUITE, f"{sha}:test_parsing/{name}")
        if text is None:
            continue
        try:
            expected = normalize_json(json.loads(text))
        except Exception:
            continue
        stem = Path(name).stem
        seen_count += 1
        contracts.append(
            contract(
                tag=tag,
                version=version,
                published_at=published_at,
                capability="json.parse.value",
                op="json_parse_success",
                stem=stem,
                params={"json": text, "json_test_id": stem},
                expected={"value": expected},
                source=f"tests/json-test-suite/test_parsing/{name}",
                source_kind="json-test-suite",
            )
        )
        seen_count += 1
        contracts.append(
            contract(
                tag=tag,
                version=version,
                published_at=published_at,
                capability="json.stringify.roundtrip",
                op="json_stringify_reparse_success",
                stem=stem,
                params={"json": text, "json_test_id": stem},
                expected={"value": expected},
                source=f"tests/json-test-suite/test_parsing/{name}",
                source_kind="json-test-suite",
            )
        )
    return contracts, {
        "json_test_suite_sha": sha,
        "json_suite_files": len(names),
        "json_suite_seen": seen_count,
    }


def extract_release(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    yts_contracts, yts_audit = extract_yaml_test_suite(version, tag, published_at)
    jts_contracts, jts_audit = extract_json_test_suite(version, tag, published_at)
    contracts = yts_contracts + jts_contracts
    audit = {
        "version": version,
        "tag": tag,
        **yts_audit,
        **jts_audit,
        "contracts_seen": yts_audit["yaml_suite_seen"] + jts_audit["json_suite_seen"],
        "new_contracts": 0,
    }
    return contracts, audit


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
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    npm = load_npm()
    versions = sorted(npm["versions"], key=semver_key)
    tags = git_tags()
    prior_identities = load_pyyaml_identity_set()
    stable_latest = npm.get("dist-tags", {}).get("latest")
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    missing_tags = []
    overlap_skipped = 0
    for version in versions:
        tag = f"v{version}"
        time_info = npm.get("time", {})
        published_at = time_info.get(version)
        if tag not in tags:
            missing_tags.append(version)
            release_counts.append(
                {
                    "version": version,
                    "tag": None,
                    "published_at": published_at,
                    "contracts_seen": 0,
                    "new_contracts": 0,
                    "missing_tag": True,
                }
            )
            continue
        contracts, audit = extract_release(version, tag, published_at)
        new_count = 0
        for row in contracts:
            if generic_identity(row) in prior_identities:
                overlap_skipped += 1
                continue
            key = identity(row)
            if key not in seen:
                seen[key] = row
                new_count += 1
        audit["new_contracts"] = new_count
        release_counts.append(audit)

    contracts = list(seen.values())
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    summary = {
        "domain": "YAML Parser/Emitter",
        "project": "eemeli/yaml",
        "package": "yaml",
        "latest_version": stable_latest,
        "npm_versions": len(versions),
        "versions_with_matching_git_tags": sum(1 for row in release_counts if row.get("tag")),
        "missing_git_tags": missing_tags,
        "prior_project_overlap_basis": "yaml/pyyaml latest survivors",
        "prior_overlap_skipped": overlap_skipped,
        "contracts_seen": sum(row.get("contracts_seen", 0) for row in release_counts),
        "extracted_contracts": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_excluding_pyyaml.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_excluding_pyyaml.rpl")

    lines = [
        "# eemeli/yaml Release Contract Counts",
        "",
        f"NPM versions: {len(versions)}",
        f"Versions with matching git tags: {summary['versions_with_matching_git_tags']}",
        f"Missing git tags: {len(missing_tags)}",
        f"Prior PyYAML overlap skipped: {overlap_skipped}",
        f"Extracted unique contracts: {len(contracts)}",
        "",
        "| Version | Tag | Seen | New | YAML suite files | JSON suite files |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in release_counts:
        lines.append(
            "| {version} | {tag} | {seen} | {new} | {yaml_files} | {json_files} |".format(
                version=row["version"],
                tag=f"`{row['tag']}`" if row.get("tag") else "",
                seen=row.get("contracts_seen", 0),
                new=row.get("new_contracts", 0),
                yaml_files=row.get("yaml_suite_files", 0),
                json_files=row.get("json_suite_files", 0),
            )
        )
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit_lines = [
        "# eemeli/yaml Extraction Audit",
        "",
        "Scope: language-independent, externally observable YAML/JSON parse, stringify, CST, and error behavior.",
        "",
        "Excluded:",
        "",
        "- JavaScript-specific tags or values.",
        "- Contracts with semantic identity already covered by PyYAML latest survivors.",
        "- Internal AST shapes that are not directly replayable through the public package API.",
        "",
        "Artifacts:",
        "",
        "- `all_releases_excluding_pyyaml.summary.json`",
        "- `all_releases_excluding_pyyaml.rpl`",
        "- `release_contract_counts.md`",
    ]
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    printable = {key: summary[key] for key in [
        "latest_version",
        "npm_versions",
        "versions_with_matching_git_tags",
        "missing_git_tags",
        "prior_overlap_skipped",
        "contracts_seen",
        "extracted_contracts",
        "by_capability",
        "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
