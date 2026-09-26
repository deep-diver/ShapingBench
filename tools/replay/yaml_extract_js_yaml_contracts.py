#!/usr/bin/env python3
"""Extract nodeca/js-yaml origin contracts from release-history tests/fixtures."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from yaml_origin_common import (
    ROOT,
    git_ls,
    git_show,
    git_tags,
    has_language_specific_yaml,
    load_common_identity_set,
    make_contract,
    semver_key,
    unique_rows,
    write_extraction_markdown,
    write_rpl,
)


REPO = ROOT / ".cache" / "yaml" / "js-yaml"
OUT_DIR = ROOT / "contracts" / "yaml" / "js-yaml"
NPM = "https://registry.npmjs.org/js-yaml"
RUNNER = ROOT / "tools" / "replay" / "yaml_js_yaml_origin_runner.mjs"


def load_npm() -> dict[str, Any]:
    with urllib.request.urlopen(NPM, timeout=90) as response:
        return json.load(response)


def js_unescape_quoted(text: str) -> str | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def extract_string_literals(source: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for match in re.finditer(r"(?:src|source|yaml|sample)\s*=\s*(`[^`]*`|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")", source, re.S):
        raw = match.group(1)
        if raw.startswith("`"):
            if "${" in raw:
                continue
            value = raw[1:-1]
        else:
            value = js_unescape_quoted(raw)
            if value is None:
                continue
        rows.append(("js-test-literal", value))
    for match in re.finditer(r"\bload(?:All)?\(\s*('(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|`[^`]*`)", source, re.S):
        raw = match.group(1)
        if raw.startswith("`"):
            if "${" in raw:
                continue
            value = raw[1:-1]
        else:
            value = js_unescape_quoted(raw)
            if value is None:
                continue
        rows.append(("js-load-call-literal", value))
    for match in re.finditer(r"name:\s*('(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|`[^`]*`).{0,160}?source:\s*(`[^`]*`|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")", source, re.S):
        raw = match.group(2)
        if raw.startswith("`"):
            if "${" in raw:
                continue
            value = raw[1:-1]
        else:
            value = js_unescape_quoted(raw)
            if value is None:
                continue
        rows.append(("js-error-sample", value))
    return rows


def plausible_yaml(text: str) -> bool:
    if not text or len(text) > 5000:
        return False
    if "\x00" in text or has_language_specific_yaml(text):
        return False
    stripped = text.strip()
    if not stripped:
        return False
    yaml_markers = [":", "\n-", "---", "[", "{", "!!", "&", "*", "|", ">"]
    return any(marker in stripped for marker in yaml_markers) or stripped in {"true", "false", "null", "~"}


def source_paths(tag: str) -> list[str]:
    names = []
    for root in ["test", "benchmark", "examples", "support"]:
        names.extend(git_ls(REPO, f"{tag}:{root}"))
    paths = []
    for name in names:
        if name.endswith((".mjs", ".js", ".yaml", ".yml")):
            if any(part in name for part in ["/ast/", "/parser/", "dist.test"]):
                continue
            paths.append(name)
    return sorted(set(paths))


def source_files_from_archive(tag: str) -> list[tuple[str, str]]:
    roots = []
    for root in ["test", "benchmark", "examples", "support"]:
        if git_ls(REPO, f"{tag}:{root}"):
            roots.append(root)
    if not roots:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        archive = subprocess.Popen(["git", "-C", str(REPO), "archive", tag, *roots], stdout=subprocess.PIPE)
        try:
            subprocess.check_call(["tar", "-x", "-C", tmp], stdin=archive.stdout)
        finally:
            if archive.stdout:
                archive.stdout.close()
            archive.wait()
        rows = []
        base = Path(tmp)
        for candidate in sorted(base.rglob("*")):
            if not candidate.is_file():
                continue
            rel = candidate.relative_to(base).as_posix()
            if not rel.endswith((".mjs", ".js", ".yaml", ".yml")):
                continue
            if any(part in rel for part in ["/ast/", "/parser/", "dist.test"]):
                continue
            rows.append((rel, candidate.read_text(encoding="utf-8", errors="surrogateescape")))
        return rows


def materialize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump({"contracts": rows}, handle)
        path = Path(handle.name)
    try:
        try:
            raw = subprocess.check_output(
                ["node", "--no-warnings", str(RUNNER), "materialize", str(path)],
                cwd=RUNNER.parent,
                text=True,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(exc.output) from exc
    finally:
        path.unlink(missing_ok=True)
    data = json.loads(raw)
    out = []
    for row in data["results"]:
        if not row.get("materialized"):
            continue
        expected = row["expected"]
        out.append({**{key: row[key] for key in rows[0].keys() if key in row}, "expected": expected})
    return out


def add_candidate_contracts(
    *,
    version: str,
    tag: str,
    published_at: str | None,
    path: str,
    source_kind: str,
    stem: str,
    yaml_text: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    schema_names = ["default"]
    if "tags/" in path or "schema" in path:
        schema_names.extend(["json", "core", "yaml11"])
    for schema in schema_names:
        schema_suffix = "" if schema == "default" else f"_{schema}"
        params = {"yaml": yaml_text}
        if schema != "default":
            params["schema"] = schema
        candidates.append(
            make_contract(
                project="nodeca/js-yaml",
                version=version,
                published_at=published_at,
                tag=tag,
                capability="yaml.parse.diagnostic",
                op="parse_error_presence",
                stem=f"{stem}{schema_suffix}_error_presence",
                params=params,
                expected={"errors": None},
                source=path,
                source_kind=source_kind,
            )
        )
        candidates.append(
            make_contract(
                project="nodeca/js-yaml",
                version=version,
                published_at=published_at,
                tag=tag,
                capability="yaml.parse.value",
                op="parse_to_value_with_schema" if schema != "default" else "parse_to_value",
                stem=f"{stem}{schema_suffix}_value",
                params=params,
                expected={},
                source=path,
                source_kind=source_kind,
            )
        )
        candidates.append(
            make_contract(
                project="nodeca/js-yaml",
                version=version,
                published_at=published_at,
                tag=tag,
                capability="yaml.emit.roundtrip",
                op="emit_parse_roundtrip",
                stem=f"{stem}{schema_suffix}_dump_roundtrip",
                params=params,
                expected={},
                source=path,
                source_kind=source_kind,
            )
        )
    return candidates


def extract_release(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_contracts: list[dict[str, Any]] = []
    seen_snippets: set[str] = set()
    files = source_files_from_archive(tag)
    for path, text in files:
        snippets: list[tuple[str, str]] = []
        if path.endswith((".yaml", ".yml")):
            snippets.append(("yaml-file", text))
        else:
            snippets.extend(extract_string_literals(text))
        for source_kind, yaml_text in snippets:
            if not plausible_yaml(yaml_text):
                continue
            key = f"{path}\0{yaml_text}"
            if key in seen_snippets:
                continue
            seen_snippets.add(key)
            stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{Path(path).stem}_{len(seen_snippets)}").strip("_")
            raw_contracts.extend(
                add_candidate_contracts(
                    version=version,
                    tag=tag,
                    published_at=published_at,
                    path=path,
                    source_kind=source_kind,
                    stem=stem,
                    yaml_text=yaml_text,
                )
            )
    materialized: list[dict[str, Any]] = []
    diagnostic = []
    for row in raw_contracts:
        if row["op"] == "parse_error_presence":
            diagnostic.append(row)
        else:
            materialized.append(row)
    value_rows = materialize(materialized)
    by_key = {(row["op"], json.dumps(row["params"], sort_keys=True, ensure_ascii=True)): row for row in value_rows}
    final_rows: list[dict[str, Any]] = []
    for row in diagnostic:
        match_key = ("parse_to_value_with_schema" if row["params"].get("schema") else "parse_to_value", json.dumps(row["params"], sort_keys=True, ensure_ascii=True))
        errored = match_key not in by_key
        row["expected"] = {"errors": errored}
        row["mutant"] = {"errors": not errored}
        final_rows.append(row)
    final_rows.extend(value_rows)
    for row in final_rows:
        if row["op"] == "emit_parse_roundtrip":
            row["expected"] = {"value": True}
            row["mutant"] = {"value": False}
    return final_rows, {
        "version": version,
        "tag": tag,
        "published_at": published_at,
        "source_files": len(files),
        "snippets": len(seen_snippets),
        "seen": len(final_rows),
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    npm = load_npm()
    tags = git_tags(REPO)
    versions = sorted(npm["versions"], key=semver_key)
    common = load_common_identity_set()
    all_rows: list[dict[str, Any]] = []
    release_counts: list[dict[str, Any]] = []
    missing_tags: list[str] = []
    total_overlap = 0
    total_duplicate = 0
    seen_global: dict[str, dict[str, Any]] = {}
    for version in versions:
        tag = version if version in tags else f"v{version}"
        published_at = npm.get("time", {}).get(version)
        if tag not in tags:
            missing_tags.append(version)
            release_counts.append({"version": version, "tag": None, "seen": 0, "new": 0, "overlap": 0, "duplicate": 0})
            continue
        rows, audit = extract_release(version, tag, published_at)
        unique, overlap, duplicate = unique_rows(rows, common)
        new = 0
        for row in unique:
            key = json.dumps([row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)
            if key not in seen_global:
                seen_global[key] = row
                new += 1
        total_overlap += overlap
        total_duplicate += duplicate + (len(unique) - new)
        audit.update({"new": new, "overlap": overlap, "duplicate": duplicate + (len(unique) - new)})
        release_counts.append(audit)
    all_rows = list(seen_global.values())
    summary = {
        "domain": "YAML Parser/Emitter",
        "project": "nodeca/js-yaml",
        "package": "js-yaml",
        "latest_version": npm.get("dist-tags", {}).get("latest"),
        "releases_enumerated": len(versions),
        "releases_with_extractable_source": sum(1 for row in release_counts if row.get("tag")),
        "missing_git_tags": missing_tags,
        "raw_observed_contracts": sum(row.get("seen", 0) for row in release_counts),
        "final_common_overlap_skipped": total_overlap,
        "duplicate_contracts_skipped": total_duplicate,
        "final_common_overlap_basis": "contracts/yaml/common/yaml_cross_common_summary.json final_common_contracts",
        "extracted_contracts": len(all_rows),
        "by_capability": dict(sorted(Counter(row["capability"] for row in all_rows).items())),
        "by_source_kind": dict(sorted(Counter(row["source_kind"] for row in all_rows).items())),
        "release_counts": release_counts,
        "contracts": all_rows,
    }
    (OUT_DIR / "all_releases_excluding_common_1172.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(all_rows, OUT_DIR / "all_releases_excluding_common_1172.rpl")
    write_extraction_markdown(path=OUT_DIR / "release_contract_counts.md", title="nodeca/js-yaml Origin Contract Extraction", summary=summary, release_counts=release_counts)
    (OUT_DIR / "extraction_audit.md").write_text(
        "\n".join(
            [
                "# nodeca/js-yaml Extraction Audit",
                "",
                "Scope: public YAML parse, multi-document decode, dump/reparse roundtrip, and parse diagnostics from release-history tests and fixtures.",
                "",
                "Excluded:",
                "",
                "- Internal AST/parser/presenter tests.",
                "- JavaScript-specific YAML tags or function/object identity contracts.",
                "- Contracts whose semantic identity overlapped the existing YAML final common 1172.",
                "",
                "Artifacts:",
                "",
                "- `all_releases_excluding_common_1172.summary.json`",
                "- `all_releases_excluding_common_1172.rpl`",
                "- `release_contract_counts.md`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({key: summary[key] for key in ["latest_version", "releases_enumerated", "releases_with_extractable_source", "raw_observed_contracts", "final_common_overlap_skipped", "duplicate_contracts_skipped", "extracted_contracts", "by_capability", "by_source_kind"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
