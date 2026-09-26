#!/usr/bin/env python3
"""Extract and verify apostrophecms/sanitize-html origin contracts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "html_sanitizer" / "sanitize-html"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "sanitize-html"
COMMON_JSON = ROOT / "contracts" / "html_sanitizer" / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
NODE_DIR = ROOT / "tools" / "replay" / "html_sanitizer_node_adapter"
PROBE = ROOT / "tools" / "replay" / "html_sanitizer_sanitize_html_probe.mjs"
NPM = "https://registry.npmjs.org/sanitize-html"


def version_key(version: str) -> tuple[Any, ...]:
    text = version.removeprefix("v").replace("-", ".")
    out: list[Any] = []
    for part in re.findall(r"\d+|[a-zA-Z]+", text):
        out.append(int(part) if part.isdigit() else part)
    return tuple(out)


def run(cmd: list[str], cwd: Path | None = None, input_text: str | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, input=input_text, text=True, stderr=subprocess.STDOUT)


def ensure_repo() -> None:
    if REPO.exists():
        run(["git", "-C", str(REPO), "fetch", "--tags", "--quiet"])
    else:
        REPO.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "https://github.com/apostrophecms/sanitize-html.git", str(REPO)])


def ensure_node_deps() -> None:
    if not (NODE_DIR / "node_modules").exists():
        run(["npm", "install"], cwd=NODE_DIR)


def npm_metadata() -> dict[str, Any]:
    with urllib.request.urlopen(NPM, timeout=30) as response:
        return json.load(response)


def git_tags() -> set[str]:
    return {line.strip() for line in run(["git", "-C", str(REPO), "tag", "--list"]).splitlines() if line.strip()}


def tag_for(version: str, tags: set[str]) -> str | None:
    for candidate in [version, f"v{version}"]:
        if candidate in tags:
            return candidate
    return None


def git_show(tag: str, path: str) -> str | None:
    try:
        return run(["git", "-C", str(REPO), "show", f"{tag}:{path}"])
    except subprocess.CalledProcessError:
        return None


def probe_extract(source: str) -> list[dict[str, Any]]:
    out = run(["node", str(PROBE), "extract"], input_text=json.dumps({"source": source}))
    return json.loads(out)["records"]


def probe_replay(dirty: str, config: Any) -> dict[str, Any]:
    proc = subprocess.run(
        ["node", str(PROBE), "replay"],
        cwd=NODE_DIR,
        input=json.dumps({"dirty": dirty, "config": config}, ensure_ascii=False),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return {"error": "ProcessError", "message": proc.stderr.strip() or proc.stdout.strip()}
    text = proc.stdout.strip()
    if not text:
        return {"error": "NoOutput", "message": proc.stderr.strip()}
    for line in reversed(text.splitlines()):
        candidate = line.strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            return json.loads(candidate)
    start = text.rfind('{"')
    if start >= 0:
        return json.loads(text[start:])
    return {"error": "NonJsonOutput", "message": text[:500]}


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")[:92] or "sanitize"


def mutate_expected(expected: str) -> str:
    return expected + "__mutant__"


def capability(dirty: str, config: Any, expected: str = "") -> str:
    text = " ".join([dirty, expected, json.dumps(config, ensure_ascii=False, sort_keys=True)]).lower()
    if any(token in text for token in ["allowedtags", "allowedattributes", "disallowedtagsmode", "nontexttags", "allowvulnerabletags"]):
        return "html-sanitize.configuration-policy"
    if any(token in text for token in ["javascript:", "vbscript:", "data:", "srcset", "href", "src", "scheme", "allowedschemes", "iframe", "script"]):
        return "html-sanitize.uri-attribute-policy"
    if any(token in text for token in ["style", "css", "allowedstyles", "background", "font-family"]):
        return "html-sanitize.css-style-policy"
    if any(token in text for token in ["transformtags", "textfilter", "exclusivefilter"]):
        return "html-sanitize.transform-filter-policy"
    if any(token in text for token in ["comment", "<!--"]):
        return "html-sanitize.comment-policy"
    if any(token in text for token in ["attribute", "class", "data-", "target", "boolean", "checked", "alt"]):
        return "html-sanitize.attribute-policy"
    if any(token in text for token in ["nestinglimit", "<<", "<hello", "textarea", "option"]):
        return "html-sanitize.parser-mxss-hardening"
    if any(token in text for token in ["&lt;", "&amp;", "entity"]):
        return "html-sanitize.entity-escaping"
    return "html-sanitize.default-html"


def contract_key(row: dict[str, Any]) -> str:
    return json.dumps(
        {"dirty": row["params"]["dirty"], "config": row["params"].get("config"), "expected": row["expected"]},
        ensure_ascii=False,
        sort_keys=True,
    )


def add_contract(
    seen: dict[str, dict[str, Any]],
    version: str,
    published_at: str | None,
    tag: str,
    source_kind: str,
    title: str,
    dirty: str,
    expected: str,
    config: Any,
    evidence: str,
) -> bool:
    row = {
        "name": f"{version}:{source_kind}:{slug(title)}",
        "version": version,
        "published_at": published_at,
        "capability": capability(dirty, config, expected),
        "op": "sanitize",
        "params": {"dirty": dirty, "config": config},
        "expected": {"clean": expected},
        "mutant": {"clean": mutate_expected(expected)},
        "evidence": {"tag": tag, "source": evidence},
        "source_kind": source_kind,
    }
    key = contract_key(row)
    if key in seen:
        return False
    seen[key] = row
    return True


def canon_key(dirty: str, clean: Any) -> str:
    return hashlib.sha256(json.dumps({"dirty": dirty, "clean": clean}, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def common_keys() -> set[str]:
    data = json.loads(COMMON_JSON.read_text(encoding="utf-8"))
    keys = set()
    for row in data["final_common_contracts"]:
        dirty = row.get("params", {}).get("dirty") or row.get("params", {}).get("html") or ""
        clean = row.get("expected", {}).get("clean")
        keys.add(canon_key(str(dirty), clean))
    return keys


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.extend(
            [
                f"contract {json.dumps(row['name'])} {{",
                f"  origin {json.dumps('sanitize-html')}",
                f"  version {json.dumps(row['version'])}",
                f"  capability {json.dumps(row['capability'])}",
                "  op sanitize",
                f"  params {json.dumps(row['params'], ensure_ascii=False, sort_keys=True)}",
                f"  expected {json.dumps(row['expected'], ensure_ascii=False, sort_keys=True)}",
                "}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ensure_repo()
    ensure_node_deps()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    metadata = npm_metadata()
    latest = metadata["dist-tags"]["latest"]
    versions = sorted(metadata["versions"].keys(), key=version_key)
    time_by_version = metadata.get("time", {})
    tags = git_tags()
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    for version in versions:
        tag = tag_for(version, tags)
        if not tag:
            release_counts.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        before = len(seen)
        observed = 0
        for path in ["test/test.js", "tests/test.js"]:
            source = git_show(tag, path)
            if not source:
                continue
            records = probe_extract(source)
            observed += len(records)
            for index, record in enumerate(records):
                add_contract(
                    seen,
                    version,
                    time_by_version.get(version),
                    tag,
                    "test-assertion",
                    f"{record.get('title') or 'sanitize'}:{index}",
                    record["dirty"],
                    record["expected"],
                    record.get("config"),
                    path,
                )
            break
        release_counts.append({"version": version, "tag": tag, "contracts_seen": observed, "new_contracts": len(seen) - before})

    contracts = sorted(seen.values(), key=lambda row: (version_key(row["version"]), row["name"]))
    counts = Counter()
    for row in contracts:
        counts[row["name"]] += 1
        if counts[row["name"]] > 1:
            row["name"] = f"{row['name']}_{counts[row['name']]}"

    keys = common_keys()
    results = []
    survivors = []
    for contract in contracts:
        actual = probe_replay(contract["params"]["dirty"], contract["params"].get("config"))
        replay_passed = actual.get("clean") == contract["expected"]["clean"]
        mutant_passed = actual.get("clean") == contract["mutant"]["clean"] if replay_passed else False
        enriched = dict(contract)
        enriched["origin"] = "sanitize-html"
        enriched["overlap_with_final_common_90"] = canon_key(contract["params"]["dirty"], contract["expected"]["clean"]) in keys
        row = {
            "name": contract["name"],
            "version": contract["version"],
            "capability": contract["capability"],
            "source_kind": contract["source_kind"],
            "replay_passed": replay_passed,
            "mutant_rejected": replay_passed and not mutant_passed,
            "status": "passed" if replay_passed and not mutant_passed else "failed",
            "actual": actual,
            "overlap_with_final_common_90": enriched["overlap_with_final_common_90"],
        }
        results.append(row)
        if row["status"] == "passed":
            survivors.append(enriched)

    non_common = [row for row in survivors if not row["overlap_with_final_common_90"]]
    summary = {
        "domain": "HTML Sanitizer",
        "project": "apostrophecms/sanitize-html",
        "package": "sanitize-html",
        "latest_version": latest,
        "npm_versions": len(versions),
        "git_tags": len(tags),
        "tagged_releases_inspected": sum(1 for row in release_counts if row["tag"]),
        "extraction_basis": "Release-tag public sanitizeHtml(...) assertions from test/test.js. Function/callback-only options are excluded; serializable public options and RegExp options are replayable.",
        "all_unique_contracts": len(contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "overlap_with_final_common_90": sum(1 for row in survivors if row["overlap_with_final_common_90"]),
        "non_common_survivors": len(non_common),
        "by_capability_all": dict(sorted(Counter(row["capability"] for row in contracts).items())),
        "by_capability_survivors": dict(sorted(Counter(row["capability"] for row in survivors).items())),
        "by_capability_non_common": dict(sorted(Counter(row["capability"] for row in non_common).items())),
        "by_source_kind_all": dict(sorted(Counter(row["source_kind"] for row in contracts).items())),
        "by_source_kind_survivors": dict(sorted(Counter(row["source_kind"] for row in survivors).items())),
        "release_counts": release_counts,
        "contracts": contracts,
        "survivors": survivors,
        "non_common": non_common,
        "results": results,
    }
    (OUT_DIR / "all_releases_origin_extraction.summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, OUT_DIR / "all_releases_origin_extraction.rpl")
    (OUT_DIR / "latest_replay_mutant_verified.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_rpl(survivors, OUT_DIR / "latest_replay_mutant_verified.rpl")
    non_common_payload = {
        "domain": summary["domain"],
        "project": summary["project"],
        "latest_version": summary["latest_version"],
        "common_baseline": 90,
        "latest_survivors": len(survivors),
        "overlap_with_final_common_90": summary["overlap_with_final_common_90"],
        "non_common_survivors": len(non_common),
        "by_capability_non_common": summary["by_capability_non_common"],
        "non_common": non_common,
    }
    (OUT_DIR / "non_common_latest_replay_mutant_verified.json").write_text(
        json.dumps(non_common_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(non_common, OUT_DIR / "non_common_latest_replay_mutant_verified.rpl")

    lines = [
        "# sanitize-html Origin Contract Extraction",
        "",
        f"Latest version: `{latest}`",
        f"npm versions: {len(versions)}",
        f"Git tags: {len(tags)}",
        f"Tagged releases inspected: {summary['tagged_releases_inspected']}",
        f"All unique extracted contracts: {len(contracts)}",
        f"Latest replay passed: {summary['latest_replay_passed']}",
        f"Mutants rejected: {summary['latest_mutant_killed']}",
        f"Latest survivors: {len(survivors)}",
        f"Overlap with final common 90: {summary['overlap_with_final_common_90']}",
        f"Non-common survivors: {len(non_common)}",
        "",
        "## Non-Common Survivors By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in summary["by_capability_non_common"].items():
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Release Counts", "", "| Version | Tag | Observed | New unique |", "| --- | --- | ---: | ---: |"])
    for row in release_counts:
        lines.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    non_common_lines = [
        "# sanitize-html Non-Common Latest Survivors",
        "",
        f"Latest version: `{latest}`",
        "Common baseline: final common 90",
        f"Latest survivors: {len(survivors)}",
        f"Overlap with final common 90: {summary['overlap_with_final_common_90']}",
        f"Non-common survivors: {len(non_common)}",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in summary["by_capability_non_common"].items():
        non_common_lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "non_common_latest_replay_mutant_verified.md").write_text(
        "\n".join(non_common_lines) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({k: summary[k] for k in ["latest_version", "all_unique_contracts", "latest_survivors", "overlap_with_final_common_90", "non_common_survivors", "by_capability_non_common"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
