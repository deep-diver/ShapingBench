#!/usr/bin/env python3
"""Extract PyYAML release-history contracts from language-independent fixtures."""

from __future__ import annotations

import ast
import base64
import io
import json
import math
import re
import subprocess
import tarfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "yaml" / "pyyaml"
OUT_DIR = ROOT / "contracts" / "yaml" / "pyyaml"
PYPI = "https://pypi.org/pypi/PyYAML/json"

LANGUAGE_SPECIFIC_PATTERNS = [
    "!!python",
    "tag:yaml.org,2002:python",
    "!!binary",
]


def semver_key(version: str) -> tuple[int, int, int, int, str]:
    base = version.replace("rc", ".-1.").replace("b", ".-2.")
    nums = []
    for part in base.split("."):
        match = re.match(r"-?\d+", part)
        if match:
            nums.append(int(match.group(0)))
    while len(nums) < 4:
        nums.append(0)
    return nums[0], nums[1], nums[2], nums[3], version


def load_pypi() -> dict[str, Any]:
    with urllib.request.urlopen(PYPI, timeout=60) as response:
        return json.load(response)


def git_tags() -> set[str]:
    output = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in output.splitlines() if line.strip()}


def git_show(tag: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{tag}:{path}"],
            text=True,
            stderr=subprocess.DEVNULL,
            errors="surrogateescape",
        )
    except subprocess.CalledProcessError:
        return None


def git_show_bytes(tag: str, path: str) -> bytes | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{tag}:{path}"],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None


def git_ls(tag: str, path: str) -> list[str]:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(REPO), "ls-tree", "-r", "--name-only", tag, path],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def read_tree(tag: str, path: str) -> dict[str, bytes]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(REPO), "archive", "--format=tar", tag, path],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return {}
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            files[member.name] = extracted.read()
    return files


def data_dir(tag: str) -> str | None:
    for candidate in ("tests/legacy_tests/data", "tests/data"):
        if git_ls(tag, candidate):
            return candidate
    return None


def has_language_specific_yaml(text: str) -> bool:
    return any(pattern in text for pattern in LANGUAGE_SPECIFIC_PATTERNS)


def jsonable(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(jsonable(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and jsonable(item) for key, item in value.items())
    return False


def structure_literal(text: str) -> Any | None:
    try:
        value = ast.literal_eval(text)
    except Exception:
        return None
    return normalize_json(value)


def code_literal(text: str) -> Any | None:
    try:
        value = ast.literal_eval(text)
    except Exception:
        return None
    value = normalize_json(value)
    return value if jsonable(value) else None


def normalize_json(value: Any) -> Any:
    if isinstance(value, tuple):
        return [normalize_json(item) for item in value]
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_json(item) for key, item in value.items()}
    return value


def scalar_expected(kind: str, data: str) -> dict[str, Any]:
    if kind == "bool":
        return {"kind": "bool", "value": data == "true()"}
    if kind == "null":
        return {"kind": "null", "value": None}
    if kind == "int":
        return {"kind": "int", "value": int(data)}
    if kind in {"float", "inf", "nan"}:
        if data == "inf()":
            return {"kind": "float", "special": "inf"}
        if data == "inf-neg()":
            return {"kind": "float", "special": "-inf"}
        if data == "nan()":
            return {"kind": "float", "special": "nan"}
        return {"kind": "float", "value": float(data)}
    return {"kind": "str", "value": data}


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = json.loads(json.dumps(expected))
    if "html" in mutated:
        mutated["html"] = str(mutated["html"]) + "__mutant__"
    elif "value" in mutated:
        value = mutated["value"]
        if isinstance(value, bool):
            mutated["value"] = not value
        elif isinstance(value, int):
            mutated["value"] = value + 1
        elif isinstance(value, float):
            mutated["value"] = value + 1.0
        elif isinstance(value, str):
            mutated["value"] = value + "__mutant__"
        elif value is None:
            mutated["value"] = "__mutant__"
        else:
            mutated["value"] = "__mutant__"
    elif "tokens" in mutated:
        mutated["tokens"] = list(mutated["tokens"]) + ["__mutant__"]
    elif "structure" in mutated:
        mutated["structure"] = ["__mutant__", mutated["structure"]]
    elif "canonical" in mutated:
        mutated["canonical"] = str(mutated["canonical"]) + "\n__mutant__: true\n"
    elif "error" in mutated:
        mutated["error"] = not bool(mutated["error"])
    elif "dump" in mutated:
        mutated["dump"] = str(mutated["dump"]) + "__mutant__"
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
        "evidence": {
            "tag": tag,
            "source": source,
        },
        "source_kind": source_kind,
    }


def identity(row: dict[str, Any]) -> str:
    return json.dumps(
        [row["op"], row["params"], row["expected"]],
        ensure_ascii=True,
        sort_keys=True,
    )


def schema_skip(tag: str, directory: str) -> tuple[set[str], set[str]]:
    text = git_show(tag, f"{directory}/yaml11.schema-skip")
    if not text:
        return set(), set()
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return set(), set()
    return set(data.get("load") or []), set(data.get("dump") or [])


def extract_release(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    directory = data_dir(tag)
    if not directory:
        return [], {"version": version, "tag": tag, "data_dir": None, "contracts_seen": 0, "new_contracts": 0}
    file_bytes = read_tree(tag, directory)
    files = sorted(file_bytes)
    by_path = {Path(path).name: path for path in files}
    contracts: list[dict[str, Any]] = []
    seen_count = 0

    def get_text(path: str) -> str:
        return file_bytes[path].decode("utf-8", "surrogateescape")

    def get_bytes(path: str) -> bytes:
        return file_bytes[path]

    for name, path in sorted(by_path.items()):
        if not name.endswith(".data"):
            continue
        stem = name[:-5]
        data_text = get_text(path)
        if has_language_specific_yaml(data_text):
            continue
        params = {"yaml": data_text}
        canonical_name = f"{stem}.canonical"
        if canonical_name in by_path:
            canonical = get_text(by_path[canonical_name])
            if canonical and not has_language_specific_yaml(canonical):
                for op, cap in [
                    ("parse_canonical_equivalence", "yaml.parse.events"),
                    ("compose_canonical_equivalence", "yaml.compose.nodes"),
                ]:
                    seen_count += 1
                    contracts.append(
                        contract(
                            tag=tag,
                            version=version,
                            published_at=published_at,
                            capability=cap,
                            op=op,
                            stem=stem,
                            params={**params, "canonical": canonical},
                            expected={"canonical": canonical, "comparison": "semantic_equivalence"},
                            source=f"{path} + {by_path[canonical_name]}",
                            source_kind="canonical-fixture",
                        )
                    )
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.emit.roundtrip",
                        op="emit_parse_roundtrip",
                        stem=stem,
                        params=params,
                        expected={"value": True},
                        source=f"{path} + {by_path[canonical_name]}",
                        source_kind="canonical-fixture",
                    )
                )
        tokens_name = f"{stem}.tokens"
        if tokens_name in by_path:
            token_text = get_text(by_path[tokens_name])
            tokens = token_text.split()
            seen_count += 1
            contracts.append(
                contract(
                    tag=tag,
                    version=version,
                    published_at=published_at,
                    capability="yaml.scan.tokens",
                    op="scan_tokens",
                    stem=stem,
                    params=params,
                    expected={"tokens": tokens},
                    source=f"{path} + {by_path[tokens_name]}",
                    source_kind="token-fixture",
                )
            )
        structure_name = f"{stem}.structure"
        if structure_name in by_path:
            structure_text = get_text(by_path[structure_name])
            structure = structure_literal(structure_text)
            if structure is not None:
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.parse.structure",
                        op="parse_structure",
                        stem=stem,
                        params=params,
                        expected={"structure": structure},
                        source=f"{path} + {by_path[structure_name]}",
                        source_kind="structure-fixture",
                    )
                )
        code_name = f"{stem}.code"
        if code_name in by_path:
            code = get_text(by_path[code_name])
            expected_value = code_literal(code)
            if expected_value is not None:
                seen_count += 1
                contracts.append(
                    contract(
                        tag=tag,
                        version=version,
                        published_at=published_at,
                        capability="yaml.load.json-value",
                        op="safe_load_json_value",
                        stem=stem,
                        params=params,
                        expected={"value": expected_value},
                        source=f"{path} + {by_path[code_name]}",
                        source_kind="constructor-fixture",
                    )
                )

    for name, path in sorted(by_path.items()):
        if name.endswith(".loader-error") or name.endswith(".single-loader-error"):
            error_text = get_text(path)
            if has_language_specific_yaml(error_text):
                continue
            op = "load_all_error" if name.endswith(".loader-error") else "load_single_error"
            seen_count += 1
            contracts.append(
                contract(
                    tag=tag,
                    version=version,
                    published_at=published_at,
                    capability="yaml.load.errors",
                    op=op,
                    stem=name.rsplit(".", 1)[0],
                    params={"yaml": error_text},
                    expected={"error": True},
                    source=path,
                    source_kind="error-fixture",
                )
            )

    for name, path in sorted(by_path.items()):
        if not name.endswith(".unicode"):
            continue
        raw = get_bytes(path)
        text = raw.decode("utf-8")
        expected = " ".join(text.split())
        encoded = base64.b64encode(raw).decode("ascii")
        for op, input_kind in [
            ("load_unicode_text", "text"),
            ("load_unicode_utf8_bytes", "utf8"),
            ("load_unicode_utf8_bom_bytes", "utf8-bom"),
            ("load_unicode_utf16be_bom_bytes", "utf16be-bom"),
            ("load_unicode_utf16le_bom_bytes", "utf16le-bom"),
        ]:
            seen_count += 1
            contracts.append(
                contract(
                    tag=tag,
                    version=version,
                    published_at=published_at,
                    capability="yaml.reader.unicode-input",
                    op=op,
                    stem=Path(path).stem,
                    params={"text": text, "utf8_base64": encoded, "input_kind": input_kind},
                    expected={"value": expected},
                    source=path,
                    source_kind="unicode-fixture",
                )
            )

    schema_name = "yaml11.schema"
    if schema_name in by_path:
        schema_text = get_text(by_path[schema_name])
        if schema_text:
            try:
                schema = yaml.safe_load(schema_text) or {}
            except Exception:
                schema = {}
            skip_load, skip_dump = schema_skip(tag, directory)
            for index, (scalar, spec) in enumerate(sorted(schema.items())):
                if not isinstance(spec, list) or len(spec) < 3:
                    continue
                kind, data, dump = str(spec[0]), str(spec[1]), str(spec[2])
                if scalar not in skip_load:
                    seen_count += 1
                    contracts.append(
                        contract(
                            tag=tag,
                            version=version,
                            published_at=published_at,
                            capability=f"yaml.schema.yaml11.{kind}",
                            op="schema_safe_load_scalar",
                            stem=f"yaml11_{index}",
                            params={"yaml": scalar},
                            expected=scalar_expected(kind, data),
                            source=f"{by_path[schema_name]}:{index}",
                            source_kind="schema-fixture",
                        )
                    )
                if scalar not in skip_load and scalar not in skip_dump:
                    seen_count += 1
                    contracts.append(
                        contract(
                            tag=tag,
                            version=version,
                            published_at=published_at,
                            capability=f"yaml.schema.yaml11.{kind}",
                            op="schema_safe_dump_loaded_scalar",
                            stem=f"yaml11_{index}",
                            params={"yaml": scalar},
                            expected={"dump": dump},
                            source=f"{by_path[schema_name]}:{index}",
                            source_kind="schema-fixture",
                        )
                    )

    audit = {
        "version": version,
        "tag": tag,
        "data_dir": directory,
        "fixture_files": len(files),
        "contracts_seen": seen_count,
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
    pypi = load_pypi()
    tags = git_tags()
    versions = sorted(pypi["releases"], key=semver_key)
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    missing_tags = []
    for version in versions:
        if version not in tags:
            missing_tags.append(version)
            release_counts.append(
                {
                    "version": version,
                    "tag": None,
                    "data_dir": None,
                    "fixture_files": 0,
                    "contracts_seen": 0,
                    "new_contracts": 0,
                }
            )
            continue
        files = pypi["releases"].get(version) or []
        published_at = files[0].get("upload_time_iso_8601") if files else None
        rows, audit = extract_release(version, version, published_at)
        before = len(seen)
        for row in rows:
            seen.setdefault(identity(row), row)
        audit["new_contracts"] = len(seen) - before
        release_counts.append(audit)

    contracts = sorted(seen.values(), key=lambda row: (semver_key(row["version"]), row["name"]))
    by_capability = Counter(row["capability"] for row in contracts)
    by_source_kind = Counter(row["source_kind"] for row in contracts)
    summary = {
        "domain": "YAML Parser/Emitter",
        "project": "yaml/pyyaml",
        "latest_version": pypi["info"]["version"],
        "pypi_releases": len(versions),
        "releases_with_matching_git_tags": len(versions) - len(missing_tags),
        "missing_git_tags": missing_tags,
        "inspected_releases": sum(1 for row in release_counts if row["tag"]),
        "contracts_seen": sum(row["contracts_seen"] for row in release_counts),
        "extracted_contracts": len(contracts),
        "by_capability": dict(sorted(by_capability.items())),
        "by_source_kind": dict(sorted(by_source_kind.items())),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_language_independent.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_language_independent.rpl")

    lines = [
        "# PyYAML Release Contract Counts",
        "",
        "| Version | Tag | Data dir | Fixture files | Contracts seen | New contracts |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in release_counts:
        lines.append(
            f"| `{row['version']}` | `{row['tag']}` | `{row['data_dir']}` | "
            f"{row['fixture_files']} | {row['contracts_seen']} | {row['new_contracts']} |"
        )
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit_lines = [
        "# PyYAML Extraction Audit",
        "",
        f"PyPI releases: {summary['pypi_releases']}",
        f"Releases with matching git tags: {summary['releases_with_matching_git_tags']}",
        f"Missing git tags: {', '.join(missing_tags) if missing_tags else 'none'}",
        f"Contracts seen before semantic dedupe: {summary['contracts_seen']}",
        f"Extracted semantic contracts: {summary['extracted_contracts']}",
        "",
        "## By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_capability.items()):
        audit_lines.append(f"| `{cap}` | {count} |")
    audit_lines.extend(["", "## By Source Kind", "", "| Source kind | Count |", "| --- | ---: |"])
    for kind, count in sorted(by_source_kind.items()):
        audit_lines.append(f"| `{kind}` | {count} |")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    printable = {key: summary[key] for key in [
        "latest_version",
        "pypi_releases",
        "releases_with_matching_git_tags",
        "missing_git_tags",
        "contracts_seen",
        "extracted_contracts",
        "by_capability",
        "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
