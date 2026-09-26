#!/usr/bin/env python3
"""Extract ruamel.yaml origin contracts from release-history fixtures."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
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
    normalize,
    semver_key,
    unique_rows,
    write_extraction_markdown,
    write_rpl,
)


REPO = ROOT / ".cache" / "yaml" / "ruamel-yaml"
OUT_DIR = ROOT / "contracts" / "yaml" / "ruamel-yaml"
PYPI = "https://pypi.org/pypi/ruamel.yaml/json"
VENDOR = ROOT / "tools" / "replay" / "ruamel_yaml_runner" / "vendor"


SKIP_NAME_PARTS = [
    "construct-python",
    "invalid-python",
    "empty-python",
    "python-module",
    "python-name",
    "object",
    "custom",
    "recursive",
    "emitter-error",
    "tokens",
    "events",
    "structure",
    "resolver",
]


def load_pypi() -> dict[str, Any]:
    with urllib.request.urlopen(PYPI, timeout=90) as response:
        return json.load(response)


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


def yaml_engine() -> Any:
    YAML = ensure_ruamel()
    engine = YAML(typ="safe")
    engine.default_flow_style = False
    return engine


def parse_docs(engine: Any, text: str) -> list[Any]:
    return [normalize(item) for item in engine.load_all(text)]


def dump_docs(engine: Any, docs: list[Any]) -> str:
    chunks = []
    for doc in docs:
        out = io.StringIO()
        engine.dump(doc, out)
        chunks.append(out.getvalue())
    return "".join(chunks)


def should_skip(path: str, text: str | None = None) -> bool:
    lowered = path.lower()
    if any(part in lowered for part in SKIP_NAME_PARTS):
        return True
    return bool(text and has_language_specific_yaml(text))


def fixture_files_from_archive(tag: str) -> list[tuple[str, str]]:
    if not git_ls(REPO, f"{tag}:_test/data"):
        return []
    with tempfile.TemporaryDirectory() as tmp:
        archive = subprocess.Popen(["git", "-C", str(REPO), "archive", tag, "_test/data"], stdout=subprocess.PIPE)
        try:
            subprocess.check_call(["tar", "-x", "-C", tmp], stdin=archive.stdout)
        finally:
            if archive.stdout:
                archive.stdout.close()
            archive.wait()
        rows = []
        base = Path(tmp) / "_test" / "data"
        for candidate in sorted(base.iterdir()) if base.exists() else []:
            if not candidate.is_file():
                continue
            name = candidate.name
            if not name.endswith((".data", ".unicode", ".loader-error", ".single-loader-error", ".stream-error", ".error", ".empty")):
                continue
            if should_skip(name):
                continue
            rows.append((name, candidate.read_text(encoding="utf-8", errors="surrogateescape")))
        return rows


def fixture_paths(tag: str) -> list[str]:
    names = git_ls(REPO, f"{tag}:_test/data")
    wanted = []
    for name in names:
        if not name.endswith((".data", ".unicode", ".loader-error", ".single-loader-error", ".stream-error", ".error", ".empty")):
            continue
        if should_skip(name):
            continue
        wanted.append(name)
    return sorted(set(wanted))


def release_versions_from_tags(tags: set[str]) -> list[str]:
    versions = []
    for tag in tags:
        if re.match(r"^\d+\.\d+(?:\.\d+)?$", tag):
            versions.append(tag)
    return sorted(versions, key=semver_key)


def published_times() -> dict[str, str]:
    try:
        return (load_pypi().get("releases") and {}) or {}
    except Exception:
        return {}


def contract_rows_for_fixture(version: str, tag: str, path: str, published_at: str | None, text: str, engine: Any) -> list[dict[str, Any]]:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(path).name).strip("_")
    source = f"_test/data/{path}"
    if path.endswith((".loader-error", ".single-loader-error", ".stream-error", ".error")):
        return [
            make_contract(
                project="ruamel.yaml",
                version=version,
                tag=tag,
                published_at=published_at,
                capability="yaml.parse.diagnostic",
                op="parse_error_presence",
                stem=stem,
                params={"yaml": text},
                expected={"errors": True},
                source=source,
                source_kind="ruamel-test-error-fixture",
            )
        ]
    if path.endswith(".empty"):
        expected = {"value": [None]}
        return [
            make_contract(
                project="ruamel.yaml",
                version=version,
                tag=tag,
                published_at=published_at,
                capability="yaml.stream.decode",
                op="decode_stream_values",
                stem=stem,
                params={"yaml": text},
                expected=expected,
                source=source,
                source_kind="ruamel-test-empty-fixture",
            )
        ]
    try:
        docs = parse_docs(engine, text)
    except Exception:
        return [
            make_contract(
                project="ruamel.yaml",
                version=version,
                tag=tag,
                published_at=published_at,
                capability="yaml.parse.diagnostic",
                op="parse_error_presence",
                stem=f"{stem}_observed_error",
                params={"yaml": text},
                expected={"errors": True},
                source=source,
                source_kind="ruamel-test-data-fixture",
            )
        ]
    rows = [
        make_contract(
            project="ruamel.yaml",
            version=version,
            tag=tag,
            published_at=published_at,
            capability="yaml.stream.decode",
            op="decode_stream_values",
            stem=f"{stem}_docs",
            params={"yaml": text},
            expected={"value": docs},
            source=source,
            source_kind="ruamel-test-data-fixture",
        ),
        make_contract(
            project="ruamel.yaml",
            version=version,
            tag=tag,
            published_at=published_at,
            capability="yaml.emit.roundtrip",
            op="emit_parse_roundtrip",
            stem=f"{stem}_roundtrip",
            params={"yaml": text},
            expected={"value": True},
            source=source,
            source_kind="ruamel-test-data-fixture",
        ),
        make_contract(
            project="ruamel.yaml",
            version=version,
            tag=tag,
            published_at=published_at,
            capability="yaml.emit.reparse",
            op="stringify_reparse_json_docs",
            stem=f"{stem}_dump_reparse_docs",
            params={"yaml": text},
            expected={"value": docs},
            source=source,
            source_kind="ruamel-test-data-fixture",
        ),
    ]
    if len(docs) == 1:
        rows.append(
            make_contract(
                project="ruamel.yaml",
                version=version,
                tag=tag,
                published_at=published_at,
                capability="yaml.parse.value",
                op="parse_to_value",
                stem=f"{stem}_value",
                params={"yaml": text},
                expected={"value": docs[0]},
                source=source,
                source_kind="ruamel-test-data-fixture",
            )
        )
    return rows


def extract_release(version: str, tag: str, published_at: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    files = fixture_files_from_archive(tag)
    engine = yaml_engine()
    for path, text in files:
        if should_skip(path, text):
            continue
        if len(text) > 12000:
            continue
        rows.extend(contract_rows_for_fixture(version, tag, path, published_at, text, engine))
    return rows, {"version": version, "tag": tag, "published_at": published_at, "fixture_files": len(files), "seen": len(rows)}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pypi = load_pypi()
    tags = git_tags(REPO)
    versions = release_versions_from_tags(tags)
    latest_version = pypi.get("info", {}).get("version", "0.19.1")
    common = load_common_identity_set()
    release_counts: list[dict[str, Any]] = []
    total_overlap = 0
    total_duplicate = 0
    seen_global: dict[str, dict[str, Any]] = {}
    for version in versions:
        tag = version
        rows, audit = extract_release(version, tag, None)
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
    contracts = list(seen_global.values())
    summary = {
        "domain": "YAML Parser/Emitter",
        "project": "ruamel.yaml",
        "package": "ruamel.yaml",
        "latest_version": latest_version,
        "releases_enumerated": len(versions),
        "pypi_releases_observed": len(pypi.get("releases", {})),
        "releases_with_extractable_source": sum(1 for row in release_counts if row.get("tag")),
        "source_history_note": "Git mirror tags through 0.18.5 provide release-history fixtures; latest replay uses PyPI 0.19.1 public API.",
        "raw_observed_contracts": sum(row.get("seen", 0) for row in release_counts),
        "final_common_overlap_skipped": total_overlap,
        "duplicate_contracts_skipped": total_duplicate,
        "final_common_overlap_basis": "contracts/yaml/common/yaml_cross_common_summary.json final_common_contracts",
        "extracted_contracts": len(contracts),
        "by_capability": dict(sorted(Counter(row["capability"] for row in contracts).items())),
        "by_source_kind": dict(sorted(Counter(row["source_kind"] for row in contracts).items())),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_excluding_common_1172.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, OUT_DIR / "all_releases_excluding_common_1172.rpl")
    write_extraction_markdown(path=OUT_DIR / "release_contract_counts.md", title="ruamel.yaml Origin Contract Extraction", summary=summary, release_counts=release_counts)
    (OUT_DIR / "extraction_audit.md").write_text(
        "\n".join(
            [
                "# ruamel.yaml Extraction Audit",
                "",
                "Scope: public YAML load/load_all/dump/reparse and parse diagnostics from release-history `_test/data` fixtures.",
                "",
                "Excluded:",
                "",
                "- Python object construction fixtures and Python-specific tags.",
                "- Token, event, structure, resolver, and emitter-only fixtures that are not public parse/dump observations.",
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
    print(json.dumps({key: summary[key] for key in ["latest_version", "releases_enumerated", "pypi_releases_observed", "releases_with_extractable_source", "raw_observed_contracts", "final_common_overlap_skipped", "duplicate_contracts_skipped", "extracted_contracts", "by_capability", "by_source_kind"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
