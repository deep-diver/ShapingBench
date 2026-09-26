#!/usr/bin/env python3
"""Extract Rank 4/5 Markdown origin contracts and latest-surviving non-common sets."""

from __future__ import annotations

import json
import io
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".cache" / "markdown"
COMMON_FINAL = ROOT / "contracts" / "markdown" / "common" / "final_hidden_filtered_common.json"
RUNNER = ROOT / "tools" / "replay" / "markdown_rank45_origin_node_runner" / "replay_origin.mjs"

PROJECTS = {
    "commonmark-js": {
        "package": "commonmark",
        "repo": "https://github.com/commonmark/commonmark.js.git",
        "repo_dir": CACHE / "commonmark.js",
        "out_dir": ROOT / "contracts" / "markdown" / "commonmark-js",
        "runner_target": "commonmark-js",
    },
    "marked": {
        "package": "marked",
        "repo": "https://github.com/markedjs/marked.git",
        "repo_dir": CACHE / "marked",
        "out_dir": ROOT / "contracts" / "markdown" / "marked",
        "runner_target": "marked",
    },
}


def semver_key(version: str) -> tuple[int, int, int, str]:
    match = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if not match:
        return (0, 0, 0, version)
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
        version,
    )


def npm_registry(package: str) -> dict[str, Any]:
    with urllib.request.urlopen(f"https://registry.npmjs.org/{package}", timeout=60) as response:
        return json.load(response)


def ensure_repo(spec: dict[str, Any]) -> None:
    repo_dir = spec["repo_dir"]
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    if (repo_dir / ".git").exists():
        subprocess.check_call(["git", "-C", str(repo_dir), "fetch", "--tags", "--quiet"])
    else:
        subprocess.check_call(["git", "clone", "--quiet", spec["repo"], str(repo_dir)])


def git_tags(repo: Path) -> set[str]:
    out = subprocess.check_output(["git", "-C", str(repo), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for_version(version: str, tags: set[str]) -> str | None:
    candidates = [version, f"v{version}"]
    if version.count(".") == 2 and version.endswith(".0"):
        candidates.append(version[:-2])
    return next((candidate for candidate in candidates if candidate in tags), None)


def git_show(repo: Path, tag: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "show", f"{tag}:{path}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None


def git_ls(repo: Path, tag: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", tag],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def git_archive_texts(repo: Path, tag: str, prefixes: tuple[str, ...]) -> dict[str, str]:
    out = subprocess.check_output(
        ["git", "-C", str(repo), "archive", "--format=tar", tag],
        stderr=subprocess.DEVNULL,
    )
    rows: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(out), mode="r:") as tf:
        for member in tf:
            if not member.isfile() or not member.name.startswith(prefixes):
                continue
            if not member.name.endswith((".txt", ".md", ".text", ".html", ".json")):
                continue
            fp = tf.extractfile(member)
            if fp is None:
                continue
            rows[member.name] = fp.read().decode("utf-8", "replace")
    return rows


def published_at(registry: dict[str, Any], version: str) -> str | None:
    return registry.get("time", {}).get(version)


def html_standardize(text: str) -> str:
    return (
        str(text)
        .replace("<br>", "<br />")
        .replace("<br/>", "<br />")
        .replace("<hr>", "<hr />")
        .replace("<hr/>", "<hr />")
        .replace(">\n<", "><")
        .strip()
    )


def contract_key(contract: dict[str, Any]) -> str:
    return json.dumps(
        [
            contract.get("op"),
            contract.get("params", {}).get("markdown"),
            html_standardize(contract.get("expected", {}).get("html", "")),
        ],
        ensure_ascii=True,
        sort_keys=True,
    )


def final_common_keys() -> set[str]:
    data = json.loads(COMMON_FINAL.read_text(encoding="utf-8"))
    return {contract_key(row) for row in data["contracts"]}


def capability_from_section(section: str, path: str) -> str:
    text = f"{section} {path}".lower()
    checks = [
        ("markdown.extension.tables", ["table"]),
        ("markdown.extension.strikethrough", ["strikethrough", "del_"]),
        ("markdown.extension.tasklists", ["task"]),
        ("markdown.links-images", ["link", "image", "autolink", "url", "reference"]),
        ("markdown.emphasis", ["emphasis", "em_", "strong", "delimiter"]),
        ("markdown.code", ["code", "fence", "backtick", "indent"]),
        ("markdown.html", ["html", "comment", "tag"]),
        ("markdown.lists", ["list"]),
        ("markdown.blockquotes", ["blockquote"]),
        ("markdown.headings", ["heading", "atx", "setext"]),
        ("markdown.thematic-breaks", ["thematic", "hr", "horizontal"]),
        ("markdown.line-breaks", ["break"]),
        ("markdown.entities-escaping", ["entity", "escape", "angle", "amp"]),
    ]
    for capability, needles in checks:
        if any(needle in text for needle in needles):
            return capability
    return "markdown.rendering"


def mutant_for(html: str) -> dict[str, str]:
    return {
        "html": html + ("\n__mutant__" if not html.endswith("\n") else "__mutant__\n"),
        "comparison": "html_trim_standardize",
    }


def make_contract(
    *,
    project: str,
    version: str,
    published: str | None,
    index: int,
    markdown: str,
    html: str,
    capability: str,
    source_kind: str,
    source: str,
    test_name: str,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {"markdown": markdown}
    if options:
        params["options"] = options
    return {
        "name": f"{version}:{source_kind}:{test_name}:{index}",
        "version": version,
        "published_at": published,
        "capability": capability,
        "op": "render",
        "params": params,
        "expected": {"html": html, "comparison": "html_trim_standardize"},
        "mutant": mutant_for(html),
        "evidence": {
            "source_ref": version,
            "source": source,
            "test_name": test_name,
            "description": f"{project} public markdown-to-HTML fixture",
        },
        "source_kind": source_kind,
    }


def extract_commonmark_examples(text: str) -> list[dict[str, Any]]:
    tests = re.sub(r"\r\n?", "\n", text)
    tests = re.sub(r"^<!-- END TESTS -->(.|\n)*", "", tests, flags=re.M)
    rows = []
    current_section = ""
    example_number = 0
    pattern = re.compile(
        r"^`{32} example\n([\s\S]*?)^\.\n([\s\S]*?)^`{32}$|^#{1,6} *(.*)$",
        re.M,
    )
    for match in pattern.finditer(tests):
        if match.group(3) is not None:
            current_section = match.group(3).strip()
            continue
        example_number += 1
        rows.append({
            "markdown": match.group(1).replace("→", "\t"),
            "html": match.group(2).replace("→", "\t"),
            "section": current_section,
            "example": example_number,
            "line": tests.count("\n", 0, match.start()) + 1,
        })
    return rows


def extract_commonmark_project(version: str, registry: dict[str, Any], tag: str, files: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    published = published_at(registry, version)
    sources = [
        ("spec.txt", "commonmark-spec", {}),
        ("test/spec.txt", "commonmark-spec", {}),
        ("regression.txt", "commonmark-regression", {}),
        ("test/regression.txt", "commonmark-regression", {}),
        ("test/smart_punct.txt", "commonmark-smart-punctuation", {"smart": True}),
    ]
    seen_sources = set()
    for path, source_kind, options in sources:
        text = files.get(path)
        if not text or path in seen_sources:
            continue
        seen_sources.add(path)
        for fixture in extract_commonmark_examples(text):
            rows.append(make_contract(
                project="commonmark-js",
                version=version,
                published=published,
                index=len(rows) + 1,
                markdown=fixture["markdown"],
                html=fixture["html"],
                capability=capability_from_section(fixture["section"], path),
                source_kind=source_kind,
                source=f"{tag}:{path}:line {fixture['line']}",
                test_name=f"example_{fixture['example']}",
                options={"unsafe": True, **options},
            ))
    return rows


def marked_options_from_path(path: str, source_kind: str) -> dict[str, Any]:
    options: dict[str, Any] = {"unsafe": True}
    path_lower = path.lower()
    if "/commonmark/" in path_lower:
        options.update({"gfm": False, "pedantic": False})
    elif "/gfm/" in path_lower or "gfm" in path_lower:
        options.update({"gfm": True, "pedantic": False})
    elif "/original/" in path_lower:
        options.update({"gfm": False, "pedantic": True})
    flags = Path(path).name.split(".")[1:-1]
    for flag in flags:
        if flag == "breaks":
            options["breaks"] = True
        elif flag == "gfm":
            options["gfm"] = True
        elif flag == "nogfm":
            options["gfm"] = False
        elif flag == "pedantic":
            options["pedantic"] = True
        elif flag == "nopedantic":
            options["pedantic"] = False
    return options


def extract_marked_json_tests(version: str, published: str | None, tag: str, path: str, text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    rows = []
    for idx, item in enumerate(payload, start=1):
        if not isinstance(item, dict) or "markdown" not in item or "html" not in item:
            continue
        section = str(item.get("section") or Path(path).stem)
        rows.append(make_contract(
            project="marked",
            version=version,
            published=published,
            index=idx,
            markdown=str(item["markdown"]),
            html=str(item["html"]),
            capability=capability_from_section(section, path),
            source_kind="marked-json-spec",
            source=f"{tag}:{path}:example {item.get('example', idx)}",
            test_name=f"{Path(path).stem}_{item.get('example', idx)}",
            options=marked_options_from_path(path, "marked-json-spec"),
        ))
    return rows


def extract_marked_pair_tests(version: str, published: str | None, tag: str, files: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    html_by_stem = {}
    paths = sorted(files)
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix == ".html":
            html_by_stem[path[:-5]] = path
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix not in {".md", ".text"}:
            continue
        stem = path[: -len(suffix)]
        html_path = html_by_stem.get(stem)
        if not html_path:
            continue
        markdown = files.get(path)
        html = files.get(html_path)
        if markdown is None or html is None:
            continue
        source_kind = "marked-paired-fixture"
        test_name = re.sub(r"[^A-Za-z0-9_]+", "_", Path(stem).name).strip("_") or f"case_{len(rows) + 1}"
        rows.append(make_contract(
            project="marked",
            version=version,
            published=published,
            index=len(rows) + 1,
            markdown=markdown,
            html=html,
            capability=capability_from_section(test_name, path),
            source_kind=source_kind,
            source=f"{tag}:{path} + {html_path}",
            test_name=test_name,
            options=marked_options_from_path(path, source_kind),
        ))
    return rows


def extract_marked_project(version: str, registry: dict[str, Any], tag: str, files: dict[str, str]) -> list[dict[str, Any]]:
    published = published_at(registry, version)
    rows: list[dict[str, Any]] = []
    for path, text in sorted(files.items()):
        if not path.startswith("test/") or not path.endswith(".json"):
            continue
        if text:
            rows.extend(extract_marked_json_tests(version, published, tag, path, text))
    rows.extend(extract_marked_pair_tests(version, published, tag, files))
    for idx, row in enumerate(rows, start=1):
        row["name"] = f"{version}:{row['source_kind']}:{row['evidence']['test_name']}:{idx}"
    return rows


def versions_for_project(name: str, registry: dict[str, Any], tags: set[str]) -> list[tuple[str, str]]:
    rows = []
    for version in registry["versions"]:
        tag = tag_for_version(version, tags)
        if tag:
            rows.append((version, tag))
    return sorted(rows, key=lambda item: semver_key(item[0]))


def dedupe_contracts(contracts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    seen: dict[str, dict[str, Any]] = {}
    duplicates = 0
    for row in contracts:
        key = contract_key(row)
        if key in seen:
            duplicates += 1
            continue
        seen[key] = row
    return list(seen.values()), duplicates


def run_latest(target: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as fp:
        json.dump(payload, fp, ensure_ascii=True)
        path = fp.name
    try:
        out = subprocess.check_output(
            ["node", str(RUNNER), target, path],
            cwd=ROOT,
            text=True,
            stderr=subprocess.STDOUT,
        )
        return json.loads(out)["results"]
    finally:
        Path(path).unlink(missing_ok=True)


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


def write_latest_md(path: Path, summary: dict[str, Any], failed: list[dict[str, Any]], non_common: list[dict[str, Any]]) -> None:
    lines = [
        f"# {summary['project']} Rank 4/5 Origin Latest Replay",
        "",
        f"Latest version: `{summary['latest_version']}`",
        f"Releases with extraction evidence: {summary['releases_with_contracts']}",
        f"Raw extracted contracts: {summary['raw_extracted_contracts']}",
        f"Semantic duplicate identities removed: {summary['semantic_duplicates_removed']}",
        f"Unique extracted contracts: {summary['unique_extracted_contracts']}",
        f"Latest replay passed: {summary['latest_replay_passed']}",
        f"Latest replay failed: {summary['latest_replay_failed']}",
        f"Mutants killed after replay pass: {summary['latest_mutant_killed']}",
        f"Latest survivors: {summary['latest_survivors']}",
        f"Overlaps with final common 877: {summary['overlaps_final_common_877']}",
        f"Non-common latest survivors: {summary['non_common_latest_survivors']}",
        "",
        "## By Capability",
        "",
        "| Capability | Passed | Failed | Non-common survivors |",
        "| --- | ---: | ---: | ---: |",
    ]
    non_common_by_cap = Counter(row["capability"] for row in non_common)
    for cap, counter in summary["by_capability"].items():
        lines.append(f"| `{cap}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} | {non_common_by_cap.get(cap, 0)} |")
    lines.extend([
        "",
        "## By Source Kind",
        "",
        "| Source kind | Passed | Failed |",
        "| --- | ---: | ---: |",
    ])
    for kind, counter in summary["by_source_kind"].items():
        lines.append(f"| `{kind}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Capability | Actual sample |", "| --- | --- | --- |"])
    for row in failed[:80]:
        actual = row["result"].get("actual", {}).get("html")
        if actual is None:
            actual = json.dumps(row["result"].get("actual"), ensure_ascii=False)
        actual = str(actual).replace("\n", "\\n").replace("|", "\\|")
        if len(actual) > 240:
            actual = actual[:237] + "..."
        lines.append(f"| `{row['contract']['name']}` | `{row['contract']['capability']}` | {actual} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_release_counts(path: Path, counts: list[dict[str, Any]]) -> None:
    lines = [
        "# Release Contract Counts",
        "",
        "| Version | Tag | Extracted | Unique retained after global dedupe |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in counts:
        lines.append(f"| `{row['version']}` | `{row['tag']}` | {row['extracted']} | {row['unique_retained']} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def extract_project(name: str) -> dict[str, Any]:
    spec = PROJECTS[name]
    ensure_repo(spec)
    registry = npm_registry(spec["package"])
    tags = git_tags(spec["repo_dir"])
    versions = versions_for_project(name, registry, tags)
    latest_version = registry["dist-tags"]["latest"]
    contracts: list[dict[str, Any]] = []
    seen_identity: set[str] = set()
    release_counts = []
    for version, tag in versions:
        if name == "commonmark-js":
            files = git_archive_texts(spec["repo_dir"], tag, ("spec", "test/", "regression"))
            extracted = extract_commonmark_project(version, registry, tag, files)
        else:
            files = git_archive_texts(spec["repo_dir"], tag, ("test/",))
            extracted = extract_marked_project(version, registry, tag, files)
        new_retained = 0
        for contract in extracted:
            key = contract_key(contract)
            if key in seen_identity:
                continue
            seen_identity.add(key)
            contracts.append(contract)
            new_retained += 1
        release_counts.append({
            "version": version,
            "tag": tag,
            "extracted": len(extracted),
            "unique_retained": new_retained,
        })
    raw_total = sum(row["extracted"] for row in release_counts)
    unique_contracts, duplicate_count = dedupe_contracts(contracts)
    duplicate_count += raw_total - len(contracts)
    payload = {
        "domain": "Markdown Parser/Renderer",
        "project": name,
        "latest_version": latest_version,
        "definition": "Externally observable markdown-to-HTML contracts extracted from the project's own public release-history test/spec fixtures.",
        "contracts": unique_contracts,
    }
    results = run_latest(spec["runner_target"], payload)
    by_name = {row["name"]: row for row in results}
    common_keys = final_common_keys()
    survivors = []
    failed = []
    for contract in unique_contracts:
        result = by_name[contract["name"]]
        if result["status"] == "passed":
            marked_contract = {**contract, "overlaps_final_common_877": contract_key(contract) in common_keys}
            survivors.append(marked_contract)
        else:
            failed.append({"contract": contract, "result": result})
    non_common = [row for row in survivors if not row["overlaps_final_common_877"]]
    by_capability = defaultdict(Counter)
    by_source_kind = defaultdict(Counter)
    for row in results:
        by_capability[row["capability"]][row["status"]] += 1
        by_source_kind[row["source_kind"]][row["status"]] += 1
    summary = {
        "domain": "Markdown Parser/Renderer",
        "project": name,
        "latest_version": latest_version,
        "npm_versions": len(registry["versions"]),
        "matched_release_tags": len(versions),
        "releases_with_contracts": sum(1 for row in release_counts if row["extracted"]),
        "raw_extracted_contracts": raw_total,
        "semantic_duplicates_removed": duplicate_count,
        "unique_extracted_contracts": len(unique_contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_replay_failed": sum(1 for row in results if not row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["replay_passed"] and row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "overlaps_final_common_877": sum(1 for row in survivors if row["overlaps_final_common_877"]),
        "non_common_latest_survivors": len(non_common),
        "by_capability": {cap: dict(counter) for cap, counter in sorted(by_capability.items())},
        "by_source_kind": {kind: dict(counter) for kind, counter in sorted(by_source_kind.items())},
    }
    out_dir = spec["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "all_releases_origin_extracted.summary.json").write_text(
        json.dumps({**summary, "release_counts": release_counts, "contracts": unique_contracts}, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(unique_contracts, out_dir / "all_releases_origin_extracted.rpl")
    write_release_counts(out_dir / "release_contract_counts.md", release_counts)
    latest_out = {
        **summary,
        "survivors": survivors,
        "non_common_survivors": non_common,
        "failed": failed,
        "results": results,
    }
    (out_dir / "latest_replay_mutant_verified.json").write_text(
        json.dumps(latest_out, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(survivors, out_dir / "latest_replay_mutant_verified.rpl")
    write_rpl(non_common, out_dir / "latest_non_common.rpl")
    (out_dir / "latest_non_common.json").write_text(
        json.dumps({**summary, "contracts": non_common}, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_latest_md(out_dir / "latest_replay_mutant_verified.md", summary, failed, non_common)
    return summary


def main() -> int:
    summaries = [extract_project(name) for name in ["commonmark-js", "marked"]]
    print(json.dumps(summaries, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
