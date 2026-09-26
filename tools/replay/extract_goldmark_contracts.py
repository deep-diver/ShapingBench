#!/usr/bin/env python3
"""Extract goldmark release-history render contracts from official tests."""

from __future__ import annotations

import json
import re
import subprocess
import html as html_lib
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "markdown" / "goldmark"
OUT_DIR = ROOT / "contracts" / "markdown" / "goldmark"
PRIOR_FILES = [
    ROOT / "contracts" / "markdown" / "markdown-it" / "all_releases_maximal_language_independent.summary.json",
    ROOT / "contracts" / "markdown" / "pulldown-cmark" / "all_releases_excluding_markdown_it.summary.json",
]


def tag_key(tag: str) -> tuple[int, int, int, int, int, str]:
    match = re.match(r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$", tag)
    if not match:
        return 999, 999, 999, 9, 999, tag
    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    pre = match.group(4)
    if not pre:
        return major, minor, patch, 9, 999, tag
    rank = 0
    if pre.startswith("beta."):
        rank = 1
    elif pre.startswith("rc."):
        rank = 2
    num_match = re.search(r"(\d+)$", pre)
    num = int(num_match.group(1)) if num_match else 0
    return major, minor, patch, rank, num, tag


def version_from_tag(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def git_tags() -> list[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    tags = [line.strip() for line in out.splitlines() if line.strip()]
    return sorted([tag for tag in tags if re.match(r"^v\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]+)?$", tag)], key=tag_key)


def all_git_tags() -> list[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return sorted([line.strip() for line in out.splitlines() if line.strip()])


def tag_date(tag: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "log", "-1", "--format=%cI", tag],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
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


def html_standardize(text: str) -> str:
    normalized = (
        text.replace("<br>", "<br />")
        .replace("<br/>", "<br />")
        .replace("<hr>", "<hr />")
        .replace("<hr/>", "<hr />")
        .replace(">\n<", "><")
        .strip()
    )
    return html_lib.unescape(normalized)


def prior_keys() -> set[str]:
    keys: set[str] = set()
    for path in PRIOR_FILES:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in data.get("contracts", []):
            params = row.get("params", {})
            expected = row.get("expected", {})
            if "markdown" in params and "html" in expected:
                keys.add(json.dumps([params["markdown"], html_standardize(expected["html"])], ensure_ascii=True))
    return keys


def contract_key(markdown: str, html: str) -> str:
    return json.dumps([markdown, html_standardize(html)], ensure_ascii=True)


def apply_escape_sequence(text: str) -> str:
    data = text.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 92 and i + 1 < len(data):
            c = chr(data[i + 1])
            mapping = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92}
            if c in mapping:
                out.append(mapping[c])
                i += 2
                continue
            if c == "x" and i + 3 < len(data):
                try:
                    out.append(int(data[i + 2:i + 4].decode("ascii"), 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            if c in {"u", "U"}:
                width = 4 if c == "u" else 8
                if i + 1 + width < len(data):
                    try:
                        rune = int(data[i + 2:i + 2 + width].decode("ascii"), 16)
                        out.extend(chr(rune).encode("utf-8"))
                        i += 2 + width
                        continue
                    except ValueError:
                        pass
        out.append(data[i])
        i += 1
    return out.decode("utf-8", errors="replace")


def parse_case_file(path: str, text: str, options: dict[str, Any]) -> list[dict[str, Any]]:
    attr_sep = "//- - - - - - - - -//"
    case_sep = "//= = = = = = = = = = = = = = = = = = = = = = = =//"
    rows = []
    lines = re.split(r"\r?\n", text)
    pos = 0
    while pos < len(lines):
        if not lines[pos].strip():
            pos += 1
            continue
        header = lines[pos].strip()
        if not re.match(r"^\d+(\s*:.*)?$", header):
            pos += 1
            continue
        number = int(header.split(":", 1)[0].strip())
        description = header.split(":", 1)[1].strip() if ":" in header else ""
        pos += 1
        case_options = {}
        if pos < len(lines) and re.match(r"(?i)\s*options:", lines[pos]):
            option_text = re.sub(r"(?i)^\s*options:\s*", "", lines[pos]).strip()
            try:
                case_options = json.loads(option_text)
            except json.JSONDecodeError:
                case_options = {}
            pos += 1
        if pos >= len(lines) or lines[pos] != attr_sep:
            continue
        pos += 1
        start = pos
        while pos < len(lines) and lines[pos] != attr_sep:
            pos += 1
        markdown = "\n".join(lines[start:pos])
        pos += 1
        start = pos
        while pos < len(lines) and lines[pos] != case_sep:
            pos += 1
        html = "\n".join(lines[start:pos])
        if html:
            html += "\n"
        pos += 1
        option_lower = {str(k).lower(): v for k, v in case_options.items()}
        if option_lower.get("trim"):
            markdown = markdown.strip()
            html = html.strip()
        if option_lower.get("enableescape"):
            markdown = apply_escape_sequence(markdown)
            html = apply_escape_sequence(html)
        rows.append({
            "source": path,
            "line": start,
            "test_name": f"case_{number}",
            "description": description,
            "markdown": markdown,
            "html": html,
            "options": dict(options),
        })
    return rows


def go_string_at(text: str, start: int) -> tuple[str, int] | None:
    pos = start
    while pos < len(text) and text[pos].isspace():
        pos += 1
    if pos >= len(text):
        return None
    if text[pos] == "`":
        end = text.find("`", pos + 1)
        if end == -1:
            return None
        return text[pos + 1:end], end + 1
    if text[pos] != '"':
        return None
    escaped = False
    pos += 1
    out = ['"']
    while pos < len(text):
        ch = text[pos]
        out.append(ch)
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            try:
                return json.loads("".join(out)), pos + 1
            except Exception:
                return bytes("".join(out)[1:-1], "utf-8").decode("unicode_escape"), pos + 1
        pos += 1
    return None


def balanced(text: str, open_pos: int, open_ch: str, close_ch: str) -> tuple[str, int] | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for pos in range(open_pos, len(text)):
        ch = text[pos]
        if quote:
            if quote == "`":
                if ch == "`":
                    quote = None
            elif escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:pos], pos + 1
    return None


def field_string(block: str, field: str) -> str | None:
    match = re.search(rf"\b{field}\s*:\s*", block)
    if not match:
        return None
    parsed = go_string_at(block, match.end())
    return parsed[0] if parsed else None


def context_options(path: str, context: str) -> dict[str, Any]:
    enabled = []
    options: dict[str, Any] = {"enabled": enabled}
    if "WithXHTML" in context:
        options["xhtml"] = True
    if "WithUnsafe" in context:
        options["unsafe"] = True
    if "WithHardWraps" in context:
        options["hard_wraps"] = True
    if "WithEscapedSpace" in context:
        options["escaped_space"] = True
    if "SimpleEastAsianLineBreakStrategy" in context:
        options["line_break_strategy"] = "simple_east_asian"
    if "WithEastAsianLineBreaks" in context:
        options["line_break_strategy"] = "simple_east_asian"
    if "CSSText3LineBreakStrategy" in context:
        options["line_break_strategy"] = "css_text3"
    if "WithAttribute" in context:
        options["attribute"] = True
    if "WithAutoHeadingID" in context:
        options["auto_heading_id"] = True
    features = [
        ("NewTable", "tables"),
        ("Table", "tables"),
        ("NewFootnote", "footnotes"),
        ("Footnote", "footnotes"),
        ("NewStrikethrough", "strikethrough"),
        ("Strikethrough", "strikethrough"),
        ("NewTaskList", "tasklists"),
        ("TaskList", "tasklists"),
        ("NewTypographer", "typographer"),
        ("Typographer", "typographer"),
        ("NewLinkify", "linkify"),
        ("Linkify", "linkify"),
        ("NewDefinitionList", "definition_list"),
        ("DefinitionList", "definition_list"),
    ]
    for needle, feature in features:
        if needle in context and feature not in enabled:
            enabled.append(feature)
    if "WithTableCellAlignMethod(TableCellAlignAttribute)" in context:
        options["table_align_method"] = "attribute"
    elif "WithTableCellAlignMethod(TableCellAlignStyle)" in context:
        options["table_align_method"] = "style"
    elif "WithTableCellAlignMethod(TableCellAlignNone)" in context:
        options["table_align_method"] = "none"
    elif "WithTableCellAlignMethod(TableCellAlignDefault)" in context:
        options["table_align_method"] = "default"
    if ("WithAllowedProtocols" in context or "WithLinkifyAllowedProtocols" in context) and "ssh:" in context:
        options["linkify_mode"] = "allowed_ssh_url_regexp"
    elif "WithWWWRegexp" in context or "WithLinkifyWWWRegexp" in context:
        options["linkify_mode"] = "www_example_only"
    elif "WithEmailRegexp" in context or "WithLinkifyEmailRegexp" in context:
        options["linkify_mode"] = "email_user_only"
    if "WithIDPrefix(" in context or "WithIDPrefixFunction" in context:
        options["footnote_mode"] = "article12_custom"
    if "myIDGenerator" in context:
        options["custom_id_generator"] = "my-id"
    elif "testIDGenerator" in context:
        options["custom_id_generator"] = "test-id"
    if path.endswith("_test/options.txt"):
        options["attribute"] = True
        options["auto_heading_id"] = True
    options["enabled"] = sorted(set(enabled))
    return {key: value for key, value in options.items() if value not in (False, None, [], {})}


def infer_file_options(path: str) -> dict[str, Any]:
    if path == "_test/spec.json" or path == "_test/extra.txt":
        return {"xhtml": True, "unsafe": True}
    if path == "_test/options.txt":
        return {"attribute": True, "auto_heading_id": True}
    mapping = {
        "extension/_test/table.txt": "tables",
        "extension/_test/footnote.txt": "footnotes",
        "extension/_test/linkify.txt": "linkify",
        "extension/_test/strikethrough.txt": "strikethrough",
        "extension/_test/tasklist.txt": "tasklists",
        "extension/_test/typographer.txt": "typographer",
        "extension/_test/definition_list.txt": "definition_list",
    }
    if path in mapping:
        opts: dict[str, Any] = {"unsafe": True, "enabled": [mapping[path]]}
        if path == "extension/_test/table.txt":
            opts["xhtml"] = True
        return opts
    return {}


def parse_spec_json(path: str, text: str) -> list[dict[str, Any]]:
    try:
        cases = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = []
    for item in cases:
        rows.append({
            "source": path,
            "line": item.get("start_line", item.get("example", 0)),
            "test_name": f"example_{item.get('example')}",
            "description": item.get("section", ""),
            "markdown": item.get("markdown", ""),
            "html": item.get("html", ""),
            "options": {"xhtml": True, "unsafe": True},
        })
    return rows


def parse_markdown_testcases(path: str, source: str) -> list[dict[str, Any]]:
    rows = []
    pos = 0
    while True:
        match = re.search(r"MarkdownTestCase\s*\{", source[pos:])
        if not match:
            break
        open_pos = pos + match.end() - 1
        block_result = balanced(source, open_pos, "{", "}")
        if not block_result:
            pos = open_pos + 1
            continue
        block, end = block_result
        markdown = field_string(block, "Markdown")
        html = field_string(block, "Expected")
        if markdown is not None and html is not None:
            fn_start = source.rfind("func ", 0, open_pos)
            setup_starts = [
                source.rfind("NewMarkdownToStringFunc", 0, open_pos),
                source.rfind("goldmark.New", 0, open_pos),
            ]
            setup_start = max(setup_starts)
            context = source[fn_start:open_pos] if fn_start != -1 else source[max(0, open_pos - 2000):open_pos]
            if setup_start != -1:
                setup_open = source.find("(", setup_start)
                setup_body = balanced(source, setup_open, "(", ")") if setup_open != -1 else None
                if setup_body:
                    context = setup_body[0]
            no_match = re.search(r"\bNo\s*:\s*(\d+|no)", block)
            number = no_match.group(1) if no_match else str(len(rows) + 1)
            desc = field_string(block, "Description") or ""
            fn_name_match = re.search(r"func\s+([A-Za-z0-9_]+)", source[fn_start:open_pos]) if fn_start != -1 else None
            fn_name = fn_name_match.group(1) if fn_name_match else Path(path).stem
            rows.append({
                "source": path,
                "line": source.count("\n", 0, open_pos) + 1,
                "test_name": f"{fn_name}_{number}_{len(rows) + 1}",
                "description": desc,
                "markdown": markdown,
                "html": html if html.endswith("\n") else html + "\n",
                "options": context_options(path, context),
            })
        pos = end
    return rows


def parse_source_expected_pairs(path: str, source: str) -> list[dict[str, Any]]:
    if "source" not in source or "expected" not in source or "Render" not in source:
        return []
    rows = []
    pos = 0
    current_source: str | None = None
    while True:
        match = re.search(r"\b(source|expected)\s*(?::=|=)\s*\[\]byte\s*\(", source[pos:])
        if not match:
            break
        name = match.group(1)
        value_start = pos + match.end()
        parsed = go_string_at(source, value_start)
        if not parsed:
            pos = value_start
            continue
        value, end = parsed
        if name == "source":
            current_source = value
        elif current_source is not None:
            fn_start = source.rfind("func ", 0, pos + match.start())
            context = source[fn_start:pos + match.start()] if fn_start != -1 else source[max(0, pos + match.start() - 1000):pos + match.start()]
            fn_name_match = re.search(r"func\s+([A-Za-z0-9_]+)", context)
            fn_name = fn_name_match.group(1) if fn_name_match else Path(path).stem
            rows.append({
                "source": path,
                "line": source.count("\n", 0, pos + match.start()) + 1,
                "test_name": f"{fn_name}_source_expected_{len(rows) + 1}",
                "description": "",
                "markdown": current_source,
                "html": value,
                "options": context_options(path, context),
            })
        pos = end
    return rows


def candidate_sources(tag: str) -> dict[str, str]:
    wanted = {}
    for path in git_ls(tag):
        if path == "_test/spec.json" or path.endswith(".txt") and ("_test/" in path):
            text = git_show(tag, path)
            if text:
                wanted[path] = text
        elif path.endswith("_test.go") and (path in {"extra_test.go", "options_test.go", "cjk_test.go"} or path.startswith("extension/")):
            text = git_show(tag, path)
            if text:
                wanted[path] = text
    return wanted


def extract_rows(tag: str) -> tuple[list[dict[str, Any]], int]:
    rows = []
    files = candidate_sources(tag)
    for path, text in files.items():
        if path == "_test/spec.json":
            rows.extend(parse_spec_json(path, text))
        elif path.endswith(".txt"):
            rows.extend(parse_case_file(path, text, infer_file_options(path)))
        elif path.endswith("_test.go"):
            rows.extend(parse_markdown_testcases(path, text))
            rows.extend(parse_source_expected_pairs(path, text))
    return rows, len(files)


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", text.lower()).strip("_")
    return value[:84] or "render"


def capability(item: dict[str, Any]) -> str:
    source = item["source"].lower()
    text = f"{source}\n{item['test_name']}\n{item.get('description','')}\n{item['markdown']}\n{item['html']}".lower()
    options = item.get("options", {})
    enabled = set(options.get("enabled", []))
    if "definition" in source or "definition_list" in enabled:
        return "markdown.extension.definition-lists"
    if "footnote" in source or "footnotes" in enabled:
        return "markdown.extension.footnotes"
    if "linkify" in source or "linkify" in enabled:
        return "markdown.extension.linkify"
    if "strikethrough" in source or "strikethrough" in enabled:
        return "markdown.extension.strikethrough"
    if "table" in source or "tables" in enabled:
        return "markdown.extension.tables"
    if "tasklist" in source or "tasklists" in enabled:
        return "markdown.extension.tasklists"
    if "typographer" in source or "typographer" in enabled:
        return "markdown.extension.typographer"
    if "cjk" in source or options.get("line_break_strategy"):
        return "markdown.i18n.east-asian-line-breaks"
    if "options" in source or options.get("attribute") or options.get("auto_heading_id"):
        return "markdown.parser.attributes-heading-id"
    if "spec.json" in source:
        section = item.get("description", "").lower()
        if "link" in section or "image" in section:
            return "markdown.commonmark.links-images"
        if "list" in section:
            return "markdown.commonmark.lists"
        if "code" in section:
            return "markdown.commonmark.code"
        if "emphasis" in section:
            return "markdown.commonmark.emphasis"
        if "heading" in section:
            return "markdown.commonmark.headings"
        if "html" in section:
            return "markdown.commonmark.html"
        return "markdown.commonmark.core"
    if "dangerous" in text or "javascript:" in text:
        return "markdown.security.link-sanitization"
    if "<table" in text:
        return "markdown.extension.tables"
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
    tags = git_tags()
    all_tags = all_git_tags()
    prior = prior_keys()
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    skipped_prior = 0
    for tag in tags:
        version = version_from_tag(tag)
        rows, file_count = extract_rows(tag)
        new_count = 0
        prior_count = 0
        duplicate_count = 0
        for index, item in enumerate(rows, 1):
            if not item["markdown"] and not item["html"]:
                continue
            key = contract_key(item["markdown"], item["html"])
            if key in prior:
                skipped_prior += 1
                prior_count += 1
                continue
            rich_key = json.dumps([key, item.get("options", {})], ensure_ascii=True, sort_keys=True)
            if rich_key in seen:
                duplicate_count += 1
                continue
            contract = {
                "name": f"{version}:{slug(Path(item['source']).stem)}:{slug(item['test_name'])}:{index}",
                "version": version,
                "published_at": tag_date(tag),
                "capability": capability(item),
                "op": "render",
                "params": {
                    "markdown": item["markdown"],
                    "options": item.get("options", {}),
                },
                "expected": {"html": item["html"], "comparison": "html_trim_standardize"},
                "mutant": {"html": mutate_html(item["html"]), "comparison": "html_trim_standardize"},
                "evidence": {
                    "source_ref": tag,
                    "source": f"{item['source']}:line {item['line']}",
                    "test_name": item["test_name"],
                    "description": item.get("description", ""),
                },
                "source_kind": "go-render-test",
            }
            seen[rich_key] = contract
            new_count += 1
        release_counts.append({
            "version": version,
            "source_ref": tag,
            "files_seen": file_count,
            "contracts_seen": len(rows),
            "skipped_as_prior_markdown_overlap": prior_count,
            "duplicate_contracts": duplicate_count,
            "new_contracts": new_count,
        })
    contracts = sorted(seen.values(), key=lambda row: (tag_key("v" + row["version"]), row["name"]))
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    by_version = Counter(row["version"] for row in contracts)
    invalid_tags = [tag for tag in all_tags if tag not in tags]
    summary = {
        "domain": "Markdown Parser/Renderer",
        "project": "yuin/goldmark",
        "package": "github.com/yuin/goldmark/v2",
        "latest_version": version_from_tag(tags[-1]) if tags else None,
        "git_tags": len(all_tags),
        "semver_release_tags": len(tags),
        "ignored_non_semver_tags": invalid_tags,
        "release_points_inspected": len(tags),
        "prior_overlap_skipped": skipped_prior,
        "prior_overlap_sources": [str(path.relative_to(ROOT)) for path in PRIOR_FILES],
        "extraction_basis": "Official goldmark render tests from release tags, with exact markdown-it and pulldown-cmark Markdown/HTML pairs removed where detected.",
        "contract_count": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "top_release_counts": by_version.most_common(20),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_excluding_prior_markdown.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_excluding_prior_markdown.rpl")
    lines = [
        "# goldmark Release Contract Counts",
        "",
        "| Version | Source | Files | Seen | Skipped prior overlap | Duplicates | New |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in release_counts:
        lines.append(
            f"| `{row['version']}` | `{row['source_ref']}` | {row['files_seen']} | {row['contracts_seen']} | "
            f"{row['skipped_as_prior_markdown_overlap']} | {row['duplicate_contracts']} | {row['new_contracts']} |"
        )
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit = [
        "# goldmark Extraction Audit",
        "",
        f"git tags available: {len(all_tags)}",
        f"semver release tags inspected: {len(tags)}",
        f"ignored non-semver tags: {', '.join(invalid_tags) if invalid_tags else 'none'}",
        f"prior exact overlap skipped: {skipped_prior}",
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
        "latest_version", "git_tags", "semver_release_tags", "ignored_non_semver_tags",
        "release_points_inspected", "prior_overlap_skipped", "contract_count",
        "by_capability", "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
