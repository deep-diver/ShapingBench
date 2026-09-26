#!/usr/bin/env python3
"""Extract DOMPurify release-history sanitizer contracts from official tests."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "html_sanitizer" / "DOMPurify"
HELPER = ROOT / "tools" / "replay" / "dompurify_extract_tag.mjs"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "dompurify"
NPM_TIME = "https://registry.npmjs.org/dompurify"
GITHUB_RELEASES = "https://api.github.com/repos/cure53/DOMPurify/releases?per_page=100&page={page}"


def semver_key(version: str) -> tuple[int, int, int, str]:
    text = version.lstrip("v")
    parts = text.split(".")
    nums = []
    for part in parts[:3]:
        m = re.match(r"(\d+)", part)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2], text


def load_registry() -> dict[str, Any]:
    with urllib.request.urlopen(NPM_TIME, timeout=30) as response:
        return json.load(response)


def load_github_releases() -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    for page in range(1, 6):
        with urllib.request.urlopen(GITHUB_RELEASES.format(page=page), timeout=30) as response:
            rows = json.load(response)
        if not rows:
            break
        releases.extend(rows)
    return releases


def git_tags() -> set[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for_version(version: str, tags: set[str]) -> str | None:
    candidates = [version, f"v{version}"]
    if version == "0.4.0":
        candidates.extend(["0.4", "v0.4"])
    for candidate in candidates:
        if candidate in tags:
            return candidate
    return None


def run_helper(tag: str) -> dict[str, Any]:
    out = subprocess.check_output(["node", str(HELPER), str(REPO), tag], text=True)
    return json.loads(out)


def normalize_config(config: Any) -> Any:
    if config is None:
        return None
    return config


def key_for(row: dict[str, Any]) -> str:
    return json.dumps(
        {
            "dirty": row["dirty"],
            "config": normalize_config(row.get("config")),
            "expected": row["expected"],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")
    return text[:88] or "sanitize_contract"


def capability(row: dict[str, Any]) -> str:
    text = " ".join([row.get("title", ""), row.get("dirty", ""), json.dumps(row.get("config"), ensure_ascii=False)]).lower()
    if any(token in text for token in ["svg", "xlink", "math", "namespace", "foreignobject"]):
        return "html-sanitize.svg-mathml-namespace"
    if any(token in text for token in ["javascript:", "data:", "uri", "url", "href", "src", "protocol"]):
        return "html-sanitize.uri-attribute-policy"
    if any(token in text for token in ["mxss", "noscript", "template", "style", "textarea", "option", "mutation"]):
        return "html-sanitize.parser-mxss-hardening"
    if any(token in text for token in ["clobber", "name=", "id=", "parentnode", "ownerdocument"]):
        return "html-sanitize.dom-clobbering"
    if any(token in text for token in ["allowed_", "add_", "forbid_", "keep_content", "safe_for", "allow_", "custom_element"]):
        return "html-sanitize.configuration-policy"
    if any(token in text for token in ["aria", "data-", "attribute", "attr", "onerror", "onclick", "onload"]):
        return "html-sanitize.attribute-policy"
    if any(token in text for token in ["trusted", "return_dom", "hook", "in_place", "removed"]):
        return "html-sanitize.api-behavior"
    return "html-sanitize.default-html"


def mutate_expected(expected: Any) -> Any:
    if isinstance(expected, list):
        return [str(item) + "__mutant__" for item in expected]
    return str(expected) + "__mutant__"


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        params = json.dumps(row["params"], ensure_ascii=False, sort_keys=True)
        expected = json.dumps(row["expected"], ensure_ascii=False, sort_keys=True)
        lines.append(f"contract {json.dumps(row['name'])} {{")
        lines.append(f"  version {json.dumps(row['version'])}")
        lines.append(f"  capability {json.dumps(row['capability'])}")
        lines.append("  op sanitize")
        lines.append(f"  params {params}")
        lines.append(f"  expected {expected}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    if not REPO.exists():
        raise SystemExit(f"missing DOMPurify checkout: {REPO}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    registry = load_registry()
    npm_versions = registry.get("versions", {})
    npm_time = registry.get("time", {})
    releases = load_github_releases()
    release_by_tag = {release["tag_name"].lstrip("v"): release for release in releases}
    tags = git_tags()

    versions = sorted(npm_versions.keys(), key=semver_key)
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    inspected = 0
    no_tag = []
    for version in versions:
        tag = tag_for_version(version, tags)
        if not tag:
            no_tag.append(version)
            release_counts.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        inspected += 1
        extracted = run_helper(tag)
        rows = []
        for source_kind in ["fixtures", "statics"]:
            for item in extracted.get(source_kind, []):
                item = dict(item)
                item["source_kind"] = "fixture" if source_kind == "fixtures" else "static-test"
                rows.append(item)
        new_count = 0
        for item in rows:
            key = key_for(item)
            if key in seen:
                continue
            title = item.get("title") or "sanitize"
            contract = {
                "name": f"{version}:{item['source_kind']}:{slug(title)}",
                "version": version,
                "published_at": npm_time.get(version),
                "capability": capability(item),
                "op": "sanitize",
                "params": {
                    "dirty": item["dirty"],
                    "config": normalize_config(item.get("config")),
                },
                "expected": {"clean": item["expected"]},
                "mutant": {"clean": mutate_expected(item["expected"])},
                "evidence": {
                    "tag": tag,
                    "source": item.get("evidence"),
                    "github_release_note": (release_by_tag.get(version, {}).get("body") or "")[:1200],
                },
                "source_kind": item["source_kind"],
            }
            seen[key] = contract
            new_count += 1
        release_counts.append({"version": version, "tag": tag, "contracts_seen": len(rows), "new_contracts": new_count})

    contracts = sorted(seen.values(), key=lambda row: (semver_key(row["version"]), row["name"]))
    name_counts: Counter[str] = Counter()
    for row in contracts:
        base_name = row["name"]
        name_counts[base_name] += 1
        if name_counts[base_name] > 1:
            row["name"] = f"{base_name}_{name_counts[base_name]}"
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    by_version = Counter(row["version"] for row in contracts)
    summary = {
        "domain": "HTML Sanitizer",
        "project": "cure53/DOMPurify",
        "package": "dompurify",
        "latest_version": registry.get("dist-tags", {}).get("latest"),
        "npm_versions": len(versions),
        "github_releases": len(releases),
        "git_tags": len(tags),
        "versions_with_matching_tags_inspected": inspected,
        "versions_without_matching_tags": no_tag,
        "extraction_basis": "Official DOMPurify release tags: data-driven sanitizer fixtures plus static sanitize assertions from test/test-suite.js. GitHub release notes are retained as evidence when available.",
        "contract_count": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "top_release_counts": by_version.most_common(20),
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_maximal_language_independent.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_maximal_language_independent.rpl")

    md = [
        "# DOMPurify Release-History Contract Extraction",
        "",
        f"Latest npm version: `{summary['latest_version']}`",
        f"npm versions: {summary['npm_versions']}",
        f"GitHub releases read: {summary['github_releases']}",
        f"Git tags available: {summary['git_tags']}",
        f"Tagged npm versions inspected: {summary['versions_with_matching_tags_inspected']}",
        f"Extracted contracts: {summary['contract_count']}",
        "",
        "Basis: official DOMPurify release tags; data-driven sanitizer fixtures and static `DOMPurify.sanitize(...)` assertions. GitHub release-note text is stored as evidence where available.",
        "",
        "## By Capability",
        "",
        "| Capability | Contracts |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_cap.items()):
        md.append(f"| `{cap}` | {count} |")
    md.extend(["", "## By Source Kind", "", "| Source | Contracts |", "| --- | ---: |"])
    for kind, count in sorted(by_kind.items()):
        md.append(f"| `{kind}` | {count} |")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    lines = ["# DOMPurify Release Contract Counts", "", "| Version | Tag | Contracts observed in tag | New unique contracts |", "| --- | --- | ---: | ---: |"]
    for row in release_counts:
        lines.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["latest_version", "npm_versions", "github_releases", "versions_with_matching_tags_inspected", "contract_count", "by_capability", "by_source_kind"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
