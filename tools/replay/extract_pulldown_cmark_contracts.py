#!/usr/bin/env python3
"""Extract pulldown-cmark release-history render contracts from official tests."""

from __future__ import annotations

import json
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "markdown" / "pulldown-cmark"
TARBALL_DIR = ROOT / ".cache" / "markdown" / "crates"
OUT_DIR = ROOT / "contracts" / "markdown" / "pulldown-cmark"
PRIOR = ROOT / "contracts" / "markdown" / "markdown-it" / "all_releases_maximal_language_independent.summary.json"
CRATE = "https://crates.io/api/v1/crates/pulldown-cmark"


def semver_key(version: str) -> tuple[int, int, int, str]:
    nums = []
    for part in version.lstrip("v").split(".")[:3]:
        match = re.match(r"(\d+)", part)
        nums.append(int(match.group(1)) if match else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2], version


def load_crates() -> dict[str, Any]:
    with urllib.request.urlopen(CRATE, timeout=60) as response:
        return json.load(response)


def git_tags() -> set[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for_version(version: str, tags: set[str]) -> str | None:
    for candidate in (f"v{version}", version):
        if candidate in tags:
            return candidate
    return None


def git_show(tag: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{tag}:{path}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None


def git_ls(tag: str) -> list[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "ls-tree", "-r", "--name-only", tag], text=True)
    return [line.strip() for line in out.splitlines() if line.strip()]


def download_crate(version: str) -> Path:
    TARBALL_DIR.mkdir(parents=True, exist_ok=True)
    path = TARBALL_DIR / f"pulldown-cmark-{version}.crate"
    if not path.exists():
        url = f"https://crates.io/api/v1/crates/pulldown-cmark/{version}/download"
        with urllib.request.urlopen(url, timeout=120) as response:
            path.write_bytes(response.read())
    return path


def tarball_files(version: str) -> dict[str, str]:
    path = download_crate(version)
    rows: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(path) as tf:
            tf.extractall(tmpdir, filter="data")
        root = next(Path(tmpdir).iterdir())
        for file in root.rglob("*"):
            if file.is_file():
                rows[str(file.relative_to(root))] = file.read_text(encoding="utf-8", errors="replace")
    return rows


def rust_string_at(text: str, start: int) -> tuple[str, int] | None:
    pos = start
    if text.startswith("r", pos):
        pos += 1
        hashes = 0
        while pos < len(text) and text[pos] == "#":
            hashes += 1
            pos += 1
        if pos >= len(text) or text[pos] != '"':
            return None
        pos += 1
        end_marker = '"' + ("#" * hashes)
        end = text.find(end_marker, pos)
        if end == -1:
            return None
        return text[pos:end], end + len(end_marker)
    if pos < len(text) and text[pos] == '"':
        escaped = False
        out = []
        pos += 1
        while pos < len(text):
            char = text[pos]
            if escaped:
                out.append("\\" + char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                literal = '"' + "".join(out) + '"'
                try:
                    return json.loads(literal), pos + 1
                except Exception:
                    return bytes(literal[1:-1], "utf-8").decode("unicode_escape"), pos + 1
            else:
                out.append(char)
            pos += 1
    return None


def find_assignment(source: str, name: str, start: int) -> tuple[str, int] | None:
    match = re.search(rf"let\s+{name}\s*=\s*", source[start:])
    if not match:
        return None
    value_start = start + match.end()
    return rust_string_at(source, value_start)


def html_standardize(text: str) -> str:
    return (
        text.replace("<br>", "<br />")
        .replace("<br/>", "<br />")
        .replace("<hr>", "<hr />")
        .replace("<hr/>", "<hr />")
        .replace(">\n<", "><")
    )


def prior_keys() -> set[str]:
    if not PRIOR.exists():
        return set()
    data = json.loads(PRIOR.read_text(encoding="utf-8"))
    keys = set()
    for row in data.get("contracts", []):
        params = row.get("params", {})
        expected = row.get("expected", {})
        if "markdown" in params and "html" in expected:
            keys.add(json.dumps([params["markdown"], html_standardize(expected["html"])], ensure_ascii=True))
    return keys


def contract_key(markdown: str, html: str) -> str:
    return json.dumps([markdown, html_standardize(html)], ensure_ascii=True)


def parse_bool_list(text: str) -> list[bool]:
    return [value == "true" for value in re.findall(r"\b(true|false)\b", text)]


def suite_options(flags: list[bool]) -> dict[str, Any]:
    smart_punct, metadata_blocks, old_footnotes, subscript, wikilinks = (flags + [False] * 5)[:5]
    enabled = [
        "math",
        "tables",
        "strikethrough",
        "superscript",
        "tasklists",
        "gfm",
        "heading_attributes",
        "definition_list",
    ]
    enabled.append("old_footnotes" if old_footnotes else "footnotes")
    if metadata_blocks:
        enabled.extend(["yaml_metadata_blocks", "pluses_metadata_blocks"])
    if smart_punct:
        enabled.append("smart_punctuation")
    if subscript:
        enabled.append("subscript")
    if wikilinks:
        enabled.append("wikilinks")
    return {"preset": "pulldown_suite", "enabled": sorted(set(enabled))}


def parse_suite_rs(path: str, source: str) -> list[dict[str, Any]]:
    rows = []
    pos = 0
    while True:
        call = source.find("test_markdown_html", pos)
        if call == -1:
            break
        window_start = max(0, source.rfind("#[test]", 0, call))
        fn_match = re.search(r"fn\s+([A-Za-z0-9_]+)", source[window_start:call])
        test_name = fn_match.group(1) if fn_match else f"line_{source.count(chr(10), 0, call) + 1}"
        original = find_assignment(source, "original", window_start)
        expected = find_assignment(source, "expected", window_start)
        end = source.find(");", call)
        if original and expected and end != -1:
            args = source[source.find("(", call) + 1:end]
            flags = parse_bool_list(args)
            rows.append({
                "source": path,
                "line": source.count("\n", 0, call) + 1,
                "test_name": test_name,
                "markdown": original[0],
                "html": expected[0],
                "options": suite_options(flags),
            })
        pos = call + 1
    return rows


def parse_html_rs(path: str, source: str) -> list[dict[str, Any]]:
    rows = []
    for match in re.finditer(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(\)\s*\{", source):
        start = match.end()
        next_match = re.search(r"\n#\[test\]", source[start:])
        end = start + next_match.start() if next_match else len(source)
        block = source[start:end]
        if "Parser::new_with_broken_link_callback" in block:
            continue
        original = find_assignment(block, "original", 0)
        expected = find_assignment(block, "expected", 0)
        if not original or not expected:
            continue
        enabled = []
        if "ENABLE_TABLES" in block:
            enabled.append("tables")
        if "ENABLE_STRIKETHROUGH" in block:
            enabled.append("strikethrough")
        if "ENABLE_FOOTNOTES" in block:
            enabled.append("footnotes")
        if "ENABLE_TASKLISTS" in block:
            enabled.append("tasklists")
        rows.append({
            "source": path,
            "line": source.count("\n", 0, match.start()) + 1,
            "test_name": match.group(1),
            "markdown": original[0],
            "html": expected[0],
            "options": {"preset": "pulldown_default", "enabled": sorted(set(enabled))},
        })
    return rows


def candidate_sources_from_git(tag: str) -> dict[str, str]:
    rows = {}
    for path in git_ls(tag):
        if not path.endswith(".rs"):
            continue
        if "/tests/suite/" in path or path.startswith("tests/") or "/tests/" in path:
            if "suite/" in path or path.endswith("tests/html.rs") or path in {"tests/html.rs", "tests/table.rs", "tests/footnotes.rs", "tests/spec.rs", "tests/gfm_table.rs", "tests/regression.rs"}:
                text = git_show(tag, path)
                if text:
                    rows[path] = text
    return rows


def extract_rows(version: str, tag: str | None) -> tuple[list[dict[str, Any]], str, int]:
    if tag:
        files = candidate_sources_from_git(tag)
        source_ref = tag
    else:
        files = tarball_files(version)
        source_ref = f"crate:{version}"
    rows = []
    for path, text in files.items():
        if "suite/" in path or path.endswith(("tests/table.rs", "tests/footnotes.rs", "tests/spec.rs", "tests/gfm_table.rs", "tests/regression.rs")):
            rows.extend(parse_suite_rs(path, text))
        if path.endswith("tests/html.rs") or path == "tests/html.rs":
            rows.extend(parse_html_rs(path, text))
    return rows, source_ref, len(files)


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", text.lower()).strip("_")
    return value[:84] or "render"


def capability(item: dict[str, Any]) -> str:
    source = item["source"]
    text = f"{source}\n{item['test_name']}\n{item['markdown']}\n{item['html']}".lower()
    enabled = set(item.get("options", {}).get("enabled", []))
    source_name = source.lower()
    if "metadata" in source_name:
        return "markdown.extension.metadata-blocks"
    if "wikilink" in source_name:
        return "markdown.extension.wikilinks"
    if "definition" in source_name:
        return "markdown.extension.definition-lists"
    if "old_footnotes" in source_name:
        return "markdown.extension.old-footnotes"
    if "footnote" in source_name:
        return "markdown.extension.footnotes"
    if "tasklist" in source_name:
        return "markdown.extension.tasklists"
    if "gfm_table" in source_name or "table" in source_name:
        return "markdown.extension.tables"
    if "smart" in source_name:
        return "markdown.extension.smart-punctuation"
    if "strike" in source_name:
        return "markdown.extension.strikethrough"
    if "heading" in source_name:
        return "markdown.extension.heading-attributes"
    if "super_sub" in source_name:
        return "markdown.extension.super-subscript"
    if "math" in source_name:
        return "markdown.extension.math"
    if "regression" in source_name:
        return "markdown.parser.regression"
    if "html" in source_name:
        return "markdown.html-rendering"
    if "metadata" in enabled:
        return "markdown.extension.metadata-blocks"
    if "wikilinks" in enabled:
        return "markdown.extension.wikilinks"
    if "definition_list" in enabled:
        return "markdown.extension.definition-lists"
    if "footnotes" in enabled or "old_footnotes" in enabled:
        return "markdown.extension.footnotes"
    if "tasklists" in enabled:
        return "markdown.extension.tasklists"
    if "tables" in enabled:
        return "markdown.extension.tables"
    if "smart_punctuation" in enabled:
        return "markdown.extension.smart-punctuation"
    if "strikethrough" in enabled:
        return "markdown.extension.strikethrough"
    if "heading_attributes" in enabled:
        return "markdown.extension.heading-attributes"
    if "subscript" in enabled or "superscript" in enabled:
        return "markdown.extension.super-subscript"
    if "<script" in text or "<table" in text:
        return "markdown.html-rendering"
    if any(token in text for token in ["link", "href", "image", "src"]):
        return "markdown.links-images"
    if any(token in text for token in ["<ul>", "<ol>", "<li>", "list"]):
        return "markdown.lists"
    if any(token in text for token in ["<pre><code>", "```", "`"]):
        return "markdown.code"
    return "markdown.rendering"


def mutate_html(html: str) -> str:
    return html + "__mutant__"


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append("  op render")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    registry = load_crates()
    versions = sorted([v for v in registry["versions"] if not v.get("yanked")], key=lambda row: semver_key(row["num"]))
    tags = git_tags()
    prior = prior_keys()
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    skipped_prior = 0
    inspected = 0
    tarball_fallback = []
    for version_row in versions:
        version = version_row["num"]
        tag = tag_for_version(version, tags)
        rows, source_ref, file_count = extract_rows(version, tag)
        if not tag:
            tarball_fallback.append(version)
        inspected += 1
        new_count = 0
        prior_count = 0
        duplicate_count = 0
        for index, item in enumerate(rows, 1):
            key = contract_key(item["markdown"], item["html"])
            if key in prior:
                skipped_prior += 1
                prior_count += 1
                continue
            rich_key = json.dumps([key, item["options"]], ensure_ascii=True, sort_keys=True)
            if rich_key in seen:
                duplicate_count += 1
                continue
            contract = {
                "name": f"{version}:{slug(Path(item['source']).stem)}:{slug(item['test_name'])}:{index}",
                "version": version,
                "published_at": version_row.get("created_at"),
                "capability": capability(item),
                "op": "render",
                "params": {
                    "markdown": item["markdown"],
                    "options": item["options"],
                },
                "expected": {"html": item["html"], "comparison": "html_standardize"},
                "mutant": {"html": mutate_html(item["html"]), "comparison": "html_standardize"},
                "evidence": {
                    "source_ref": source_ref,
                    "source": f"{item['source']}:line {item['line']}",
                    "test_name": item["test_name"],
                },
                "source_kind": "rust-render-test",
            }
            seen[rich_key] = contract
            new_count += 1
        release_counts.append({
            "version": version,
            "source_ref": source_ref,
            "files_seen": file_count,
            "contracts_seen": len(rows),
            "skipped_as_markdown_it_overlap": prior_count,
            "duplicate_contracts": duplicate_count,
            "new_contracts": new_count,
        })
    contracts = sorted(seen.values(), key=lambda row: (semver_key(row["version"]), row["name"]))
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    by_version = Counter(row["version"] for row in contracts)
    summary = {
        "domain": "Markdown Parser/Renderer",
        "project": "pulldown-cmark/pulldown-cmark",
        "package": "pulldown-cmark",
        "latest_version": registry["crate"]["max_stable_version"],
        "crates_versions": len(versions),
        "git_tags": len(tags),
        "release_points_inspected": inspected,
        "tarball_fallback_versions": tarball_fallback,
        "markdown_it_overlap_skipped": skipped_prior,
        "extraction_basis": "Official Rust render tests from release tags or crates.io tarballs, with exact markdown-it Markdown/HTML pairs removed where detected.",
        "contract_count": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "top_release_counts": by_version.most_common(20),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_excluding_markdown_it.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_excluding_markdown_it.rpl")
    lines = [
        "# pulldown-cmark Release Contract Counts",
        "",
        "| Version | Source | Files | Seen | Skipped markdown-it overlap | Duplicates | New |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in release_counts:
        lines.append(
            f"| `{row['version']}` | `{row['source_ref']}` | {row['files_seen']} | {row['contracts_seen']} | "
            f"{row['skipped_as_markdown_it_overlap']} | {row['duplicate_contracts']} | {row['new_contracts']} |"
        )
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit = [
        "# pulldown-cmark Extraction Audit",
        "",
        f"crates.io versions enumerated: {len(versions)}",
        f"git tags available: {len(tags)}",
        f"release points inspected: {inspected}",
        f"tarball fallback versions: {', '.join(tarball_fallback) if tarball_fallback else 'none'}",
        f"markdown-it exact overlap skipped: {skipped_prior}",
        f"extracted contracts: {len(contracts)}",
        "",
        "## Capability Distribution",
        "",
        "| Capability | Contracts |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_cap.items()):
        audit.append(f"| `{cap}` | {count} |")
    audit.extend(["", "## Source Kind Distribution", "", "| Source kind | Contracts |", "| --- | ---: |"])
    for kind, count in sorted(by_kind.items()):
        audit.append(f"| `{kind}` | {count} |")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    printable = {k: summary[k] for k in [
        "latest_version", "crates_versions", "git_tags", "release_points_inspected",
        "tarball_fallback_versions", "markdown_it_overlap_skipped", "contract_count",
        "by_capability", "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
