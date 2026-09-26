#!/usr/bin/env python3
"""Extract markdown-it release-history render contracts from official fixtures."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
import ast
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "markdown" / "markdown-it"
OUT_DIR = ROOT / "contracts" / "markdown" / "markdown-it"
NPM_REGISTRY = "https://registry.npmjs.org/markdown-it"


def semver_key(version: str) -> tuple[int, int, int, str]:
    parts = version.lstrip("v").split(".")
    nums = []
    for part in parts[:3]:
        match = re.match(r"(\d+)", part)
        nums.append(int(match.group(1)) if match else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2], version


def load_registry() -> dict[str, Any]:
    with urllib.request.urlopen(NPM_REGISTRY, timeout=60) as response:
        return json.load(response)


def git_tags() -> set[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for_version(version: str, tags: set[str]) -> str | None:
    for candidate in (version, f"v{version}"):
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


def git_ls(tag: str, path: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(REPO), "ls-tree", "-r", "--name-only", tag, path],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def parse_fixture_file(text: str, sep: str = ".") -> list[dict[str, Any]]:
    lines = re.split(r"\r?\n", text)
    fixtures = []
    line = 0
    while line < len(lines):
        if lines[line] != sep:
            line += 1
            continue
        line += 1
        first_start = line
        while line < len(lines) and lines[line] != sep:
            line += 1
        if line >= len(lines):
            break
        markdown = "\n".join(lines[first_start:line])
        markdown = markdown + "\n" if markdown else ""
        line += 1
        second_start = line
        while line < len(lines) and lines[line] != sep:
            line += 1
        if line >= len(lines):
            break
        html = "\n".join(lines[second_start:line])
        html = html + "\n" if html else ""
        header = ""
        for idx in range(first_start - 2, max(-1, first_start - 4), -1):
            if idx < 0 or lines[idx] == sep:
                break
            if lines[idx].strip():
                header = lines[idx].strip()
                break
        fixtures.append(
            {
                "header": header,
                "line": first_start,
                "markdown": markdown,
                "html": html,
            }
        )
        line += 1
    return fixtures


def balanced_slice(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] != "(":
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for pos in range(start, len(text)):
        char = text[pos]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:pos], pos + 1
    return None


def split_top_level_args(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    start = 0
    for pos, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(text[start:pos].strip())
            start = pos + 1
    tail = text[start:].strip()
    if tail:
        args.append(tail)
    return args


def decode_js_string(expr: str) -> str | None:
    expr = expr.strip()
    if not expr or expr[0] not in {"'", '"'} or expr[-1] != expr[0]:
        return None
    try:
        return ast.literal_eval(expr)
    except Exception:
        script = f"process.stdout.write(JSON.stringify({expr}))"
        try:
            return json.loads(subprocess.check_output(["node", "-e", script], text=True))
        except Exception:
            return None


def has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def parse_simple_options(expr: str) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for key, value in re.findall(r"([A-Za-z][A-Za-z0-9_]*)\s*:\s*(true|false|-?\d+)", expr):
        if value == "true":
            options[key] = True
        elif value == "false":
            options[key] = False
        else:
            options[key] = int(value)
    return options


def markdownit_spec_from_args(args_expr: str) -> dict[str, Any] | None:
    if "function" in args_expr or "=>" in args_expr:
        return None
    args = split_top_level_args(args_expr)
    spec: dict[str, Any] = {"preset": "default"}
    if not args:
        return spec
    first_string = decode_js_string(args[0])
    if first_string:
        spec["preset"] = first_string
        if len(args) > 1:
            options = parse_simple_options(args[1])
            if options:
                spec["options"] = options
        return spec
    if args[0].startswith("{"):
        options = parse_simple_options(args[0])
        if options:
            spec["options"] = options
    return spec


def extract_static_misc_contracts(tag: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in ["test/markdown-it/misc.test.mjs", "test/markdown-it/misc.test.js", "test/misc.js"]:
        source = git_show(tag, path)
        if not source:
            continue
        current: dict[str, Any] | None = {"preset": "default"}
        pos = 0
        while pos < len(source):
            next_constructor = source.find("markdownit", pos)
            next_assert = source.find("assert.strictEqual", pos)
            candidates = [value for value in [next_constructor, next_assert] if value != -1]
            if not candidates:
                break
            event = min(candidates)
            line_no = source.count("\n", 0, event) + 1
            if event == next_constructor:
                open_pos = source.find("(", event)
                parsed = balanced_slice(source, open_pos) if open_pos != -1 else None
                if parsed:
                    current = markdownit_spec_from_args(parsed[0])
                    pos = parsed[1]
                    continue
            if event == next_assert:
                open_pos = source.find("(", event)
                parsed = balanced_slice(source, open_pos) if open_pos != -1 else None
                if not parsed:
                    pos = event + 1
                    continue
                args = split_top_level_args(parsed[0])
                if len(args) >= 2 and current is not None:
                    call = args[0].strip()
                    op_match = re.match(r"md\.render(Inline)?\s*\(", call)
                    if op_match:
                        call_open = call.find("(")
                        call_args = balanced_slice(call, call_open)
                        if call_args:
                            call_parts = split_top_level_args(call_args[0])
                            markdown = decode_js_string(call_parts[0]) if call_parts else None
                            expected = decode_js_string(args[1])
                            if markdown is not None and expected is not None:
                                if has_lone_surrogate(markdown) or has_lone_surrogate(expected):
                                    pos = parsed[1]
                                    continue
                                spec = json.loads(json.dumps(current))
                                prefix = source[max(0, event - 900):event]
                                actions = []
                                if re.search(r"md\.set\s*\(\s*\{\s*xhtmlOut\s*:\s*true\s*\}\s*\)", prefix):
                                    spec.setdefault("options", {})["xhtmlOut"] = True
                                if re.search(r"md\.linkify\.set\s*\(\s*\{\s*fuzzyLink\s*:\s*true\s*\}\s*\)", prefix):
                                    actions.append({"kind": "linkify_set", "options": {"fuzzyLink": True}})
                                if re.search(r"md\.disable\s*\(\s*['\"]emphasis['\"]\s*\)", prefix):
                                    actions.append({"kind": "disable", "rules": ["emphasis"]})
                                if re.search(r"md\.enable\s*\(\s*['\"]emphasis['\"]\s*\)", prefix):
                                    actions.append({"kind": "enable", "rules": ["emphasis"]})
                                if "md.renderer.rules" not in prefix and ".use(" not in prefix:
                                    rows.append({
                                        "path": path,
                                        "line": line_no,
                                        "op": "render_inline" if op_match.group(1) else "render",
                                        "markdown": markdown,
                                        "html": expected,
                                        "options": spec,
                                        "actions": actions,
                                    })
                pos = parsed[1]
                continue
            pos = event + 1
    return rows


def changelog_sections(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    lines = text.splitlines()
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        match = re.match(r"^##\s+\[?v?([0-9]+\.[0-9]+\.[0-9]+)\]?", line)
        if match:
            current = match.group(1)
            sections[current] = [line]
        elif current:
            sections[current].append(line)
    return {version: "\n".join(body).strip()[:1600] for version, body in sections.items()}


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", text.lower()).strip("_")
    return value[:84] or "render"


def capability(path: str, fixture: dict[str, Any]) -> str:
    text = f"{path}\n{fixture.get('header', '')}\n{fixture.get('markdown', '')}\n{fixture.get('html', '')}".lower()
    file_name = Path(path).name
    if "commonmark" in path:
        if any(token in text for token in ["link", "image", "autolink", "reference", "destination", "title"]):
            return "markdown.commonmark.links-images"
        if any(token in text for token in ["list", "<ul>", "<ol>", "<li>"]):
            return "markdown.commonmark.lists"
        if any(token in text for token in ["emphasis", "<em>", "<strong>", "***", "___"]):
            return "markdown.commonmark.emphasis"
        if any(token in text for token in ["html", "<script", "<div", "comment"]):
            return "markdown.commonmark.raw-html"
        if any(token in text for token in ["code", "```", "<pre><code>", "`"]):
            return "markdown.commonmark.code"
        if any(token in text for token in ["entity", "&amp;", "&#"]):
            return "markdown.commonmark.entities"
        if any(token in text for token in ["heading", "<h", "setext"]):
            return "markdown.commonmark.headings"
        return "markdown.commonmark.core"
    if file_name == "tables.txt":
        return "markdown.extension.tables"
    if file_name == "strikethrough.txt":
        return "markdown.extension.strikethrough"
    if file_name == "linkify.txt":
        return "markdown.extension.linkify"
    if file_name == "typographer.txt":
        return "markdown.extension.typographer"
    if file_name == "smartquotes.txt":
        return "markdown.extension.smartquotes"
    if file_name == "xss.txt":
        return "markdown.security.link-sanitization"
    if file_name == "normalize.txt":
        return "markdown.inline.normalization"
    if file_name == "proto.txt":
        return "markdown.security.prototype-pollution"
    if file_name == "fatal.txt":
        return "markdown.parser.robustness"
    if file_name == "commonmark_extras.txt":
        return "markdown.commonmark.extras"
    return "markdown.rendering"


def options_for(path: str) -> dict[str, Any]:
    if "test/fixtures/commonmark/" in path:
        return {"preset": "commonmark"}
    return {
        "preset": "default",
        "options": {
            "html": True,
            "langPrefix": "",
            "typographer": True,
            "linkify": True,
        },
    }


def key_for(path: str, fixture: dict[str, Any]) -> str:
    return json.dumps(
        {
            "markdown": fixture["markdown"],
            "html": fixture["html"],
            "options": options_for(path),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def static_key_for(item: dict[str, Any]) -> str:
    return json.dumps(
        {
            "op": item["op"],
            "markdown": item["markdown"],
            "html": item["html"],
            "options": item["options"],
            "actions": item.get("actions", []),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def static_capability(item: dict[str, Any]) -> str:
    text = f"{item['path']}\n{item['markdown']}\n{item['html']}".lower()
    options = item.get("options", {}).get("options", {})
    actions = item.get("actions", [])
    if item["op"] == "render_inline":
        return "markdown.inline.rendering"
    if any(action.get("kind") in {"enable", "disable"} for action in actions) or item.get("options", {}).get("preset") == "zero":
        return "markdown.configuration.rule-selection"
    if options.get("xhtmlOut"):
        return "markdown.rendering.xhtml-output"
    if options.get("breaks"):
        return "markdown.rendering.line-breaks"
    if options.get("maxNesting") is not None:
        return "markdown.parser.nesting-limit"
    if "linkify" in text or any(action.get("kind") == "linkify_set" for action in actions):
        return "markdown.extension.linkify"
    if "\x00" in item["markdown"]:
        return "markdown.inline.normalization"
    if "alt=" in item["html"]:
        return "markdown.inline.image-alt-rendering"
    return "markdown.api.render"


def mutate_html(html: str) -> str:
    return html + "__mutant__"


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


def fixture_paths(tag: str) -> list[str]:
    paths = []
    for path in [
        "test/fixtures/commonmark/good.txt",
        "test/fixtures/commonmark/spec.txt",
    ]:
        if git_show(tag, path):
            paths.append(path)
            break
    paths.extend(
        path
        for path in git_ls(tag, "test/fixtures/markdown-it")
        if path.endswith(".txt")
    )
    return paths


def main() -> int:
    if not REPO.exists():
        raise SystemExit(f"missing markdown-it checkout: {REPO}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    registry = load_registry()
    versions = sorted(registry.get("versions", {}).keys(), key=semver_key)
    tags = git_tags()
    head_changelog = git_show("HEAD", "CHANGELOG.md")
    changelog_by_version = changelog_sections(head_changelog)

    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    missing_tags = []
    inspected = 0
    for version in versions:
        tag = tag_for_version(version, tags)
        if not tag:
            missing_tags.append(version)
            release_counts.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        inspected += 1
        contracts_seen = 0
        new_contracts = 0
        for path in fixture_paths(tag):
            text = git_show(tag, path)
            if not text:
                continue
            fixtures = parse_fixture_file(text)
            contracts_seen += len(fixtures)
            for index, fixture in enumerate(fixtures, 1):
                key = key_for(path, fixture)
                if key in seen:
                    continue
                header = fixture["header"] or f"{Path(path).name}:{fixture['line']}"
                contract = {
                    "name": f"{version}:{slug(Path(path).stem)}:{slug(header)}:{index}",
                    "version": version,
                    "published_at": registry.get("time", {}).get(version),
                    "capability": capability(path, fixture),
                    "op": "render",
                    "params": {
                        "markdown": fixture["markdown"],
                        "options": options_for(path),
                    },
                    "expected": {"html": fixture["html"]},
                    "mutant": {"html": mutate_html(fixture["html"])},
                    "evidence": {
                        "tag": tag,
                        "source": f"{path}:line {fixture['line']}",
                        "fixture_header": fixture["header"],
                        "changelog": changelog_by_version.get(version, ""),
                    },
                    "source_kind": "commonmark-fixture" if "commonmark" in path else "markdown-it-fixture",
                }
                seen[key] = contract
                new_contracts += 1
        static_rows = extract_static_misc_contracts(tag)
        contracts_seen += len(static_rows)
        for index, item in enumerate(static_rows, 1):
            key = static_key_for(item)
            if key in seen:
                continue
            contract = {
                "name": f"{version}:static_misc:{slug(Path(item['path']).stem)}:{item['line']}:{index}",
                "version": version,
                "published_at": registry.get("time", {}).get(version),
                "capability": static_capability(item),
                "op": item["op"],
                "params": {
                    "markdown": item["markdown"],
                    "options": item["options"],
                    "actions": item.get("actions", []),
                },
                "expected": {"html": item["html"]},
                "mutant": {"html": mutate_html(item["html"])},
                "evidence": {
                    "tag": tag,
                    "source": f"{item['path']}:line {item['line']}",
                    "fixture_header": "",
                    "changelog": changelog_by_version.get(version, ""),
                },
                "source_kind": "static-render-test",
            }
            seen[key] = contract
            new_contracts += 1
        release_counts.append(
            {
                "version": version,
                "tag": tag,
                "fixture_files": len(fixture_paths(tag)),
                "contracts_seen": contracts_seen,
                "new_contracts": new_contracts,
            }
        )

    contracts = sorted(seen.values(), key=lambda row: (semver_key(row["version"]), row["name"]))
    name_counts = Counter()
    for row in contracts:
        base = row["name"]
        name_counts[base] += 1
        if name_counts[base] > 1:
            row["name"] = f"{base}_{name_counts[base]}"
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    by_version = Counter(row["version"] for row in contracts)
    summary = {
        "domain": "Markdown Parser/Renderer",
        "project": "markdown-it/markdown-it",
        "package": "markdown-it",
        "latest_version": registry.get("dist-tags", {}).get("latest"),
        "npm_versions": len(versions),
        "git_tags": len(tags),
        "versions_with_matching_tags_inspected": inspected,
        "versions_without_matching_tags": missing_tags,
        "extraction_basis": "Official release tags: CommonMark fixtures, markdown-it rendering/security/extension fixtures, and simple static render/renderInline assertions from misc tests. CHANGELOG sections are retained as release evidence when available.",
        "contract_count": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "top_release_counts": by_version.most_common(20),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_maximal_language_independent.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_maximal_language_independent.rpl")

    lines = [
        "# markdown-it Release Contract Counts",
        "",
        "| Version | Tag | Fixture files | Contracts seen | New contracts |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for row in release_counts:
        lines.append(
            f"| `{row['version']}` | `{row.get('tag') or ''}` | {row.get('fixture_files', 0)} | "
            f"{row['contracts_seen']} | {row['new_contracts']} |"
        )
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit = [
        "# markdown-it Extraction Audit",
        "",
        f"npm versions enumerated: {len(versions)}",
        f"git tags available: {len(tags)}",
        f"versions with matching tags inspected: {inspected}",
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
        "latest_version", "npm_versions", "git_tags",
        "versions_with_matching_tags_inspected", "contract_count",
        "by_capability", "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
