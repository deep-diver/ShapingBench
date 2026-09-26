#!/usr/bin/env python3
"""Extract jsoup HTML sanitizer release-history contracts."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "html_sanitizer" / "jsoup"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "jsoup"
MAVEN_METADATA = "https://repo1.maven.org/maven2/org/jsoup/jsoup/maven-metadata.xml"
DOMPURIFY_JSON = ROOT / "contracts" / "html_sanitizer" / "dompurify" / "latest_replay_mutant_verified.json"
OWASP_JSON = ROOT / "contracts" / "html_sanitizer" / "java-html-sanitizer" / "latest_replay_mutant_verified.json"


def version_key(version: str) -> tuple[Any, ...]:
    out: list[Any] = []
    for part in re.findall(r"\d+|[a-zA-Z]+", version):
        out.append(int(part) if part.isdigit() else part)
    return tuple(out)


def load_versions() -> tuple[str, list[str]]:
    data = urllib.request.urlopen(MAVEN_METADATA, timeout=30).read().decode("utf-8")
    versions = re.findall(r"<version>([^<]+)</version>", data)
    latest = re.search(r"<latest>([^<]+)</latest>", data)
    return latest.group(1) if latest else versions[-1], versions


def git_tags() -> set[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for(version: str, tags: set[str]) -> str | None:
    for candidate in [version, f"jsoup-{version}"]:
        if candidate in tags:
            return candidate
    return None


def version_from_tag(tag: str) -> str:
    return tag.removeprefix("jsoup-")


def git_show(tag: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{tag}:{path}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None


def git_show_any(tag: str, paths: list[str]) -> str | None:
    for path in paths:
        text = git_show(tag, path)
        if text is not None:
            return text
    return None


def find_method_bodies(source: str) -> list[str]:
    bodies: list[str] = []
    pattern = re.compile(r"(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:void|boolean|String)\s+\w+\s*\([^)]*\)\s*(?:throws[^{]+)?\{")
    for match in pattern.finditer(source):
        start = match.end() - 1
        depth = 0
        quote = None
        for i in range(start, len(source)):
            ch = source[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = None
                continue
            if ch in {"\"", "'"}:
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(source[start + 1 : i])
                    break
    return bodies


def split_top(expr: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(expr[start:i].strip())
            start = i + 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


def find_calls_with_positions(source: str, name: str) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for match in pattern.finditer(source):
        i = match.end()
        depth = 1
        quote = None
        while i < len(source):
            ch = source[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    calls.append((match.start(), source[match.end() : i]))
                    break
            i += 1
    return calls


def find_assignments_with_positions(source: str, pattern: re.Pattern[str]) -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    for match in pattern.finditer(source):
        i = match.end()
        depth = 0
        quote = None
        while i < len(source):
            ch = source[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth == 0:
                rows.append((match.start(), match.group(1), source[match.end() : i]))
                break
            i += 1
    return rows


def unescape_java_string(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            out.append("\\")
            break
        esc = body[i]
        i += 1
        if esc == "n":
            out.append("\n")
        elif esc == "r":
            out.append("\r")
        elif esc == "t":
            out.append("\t")
        elif esc == "b":
            out.append("\b")
        elif esc == "f":
            out.append("\f")
        elif esc in {'"', "'", "\\"}:
            out.append(esc)
        elif esc == "u":
            while i < len(body) and body[i] == "u":
                i += 1
            if i + 4 <= len(body):
                out.append(chr(int(body[i : i + 4], 16)))
                i += 4
        elif esc in "01234567":
            octal = esc
            for _ in range(2):
                if i < len(body) and body[i] in "01234567":
                    octal += body[i]
                    i += 1
                else:
                    break
            out.append(chr(int(octal, 8)))
        else:
            out.append(esc)
    return "".join(out)


def eval_expr(expr: str, vars: dict[str, Any]) -> Any:
    expr = expr.strip()
    if expr == "null":
        return None
    if expr in vars:
        return vars[expr]
    if expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1].strip()
        if inner.count("(") == inner.count(")"):
            return eval_expr(inner, vars)
    if expr.startswith("String.join("):
        inner = expr[len("String.join(") : -1]
        parts = split_top(inner)
        if len(parts) >= 2:
            sep = eval_expr(parts[0], vars)
            values = [eval_expr(part, vars) for part in parts[1:]]
            if isinstance(sep, str) and all(isinstance(value, str) for value in values):
                return sep.join(values)
    pieces = split_top(expr, "+")
    if len(pieces) > 1:
        values = [eval_expr(piece, vars) for piece in pieces]
        if all(isinstance(value, str) for value in values):
            return "".join(values)
        return None
    if len(expr) >= 2 and expr[0] == '"' and expr[-1] == '"':
        return unescape_java_string(expr[1:-1])
    return None


def eval_args(args: str, vars: dict[str, Any]) -> list[str] | None:
    values: list[str] = []
    for arg in split_top(args):
        value = eval_expr(arg, vars)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            values.extend(value)
        else:
            return None
    if all(isinstance(value, str) for value in values):
        return values
    return None


def load_string_vars(source: str) -> dict[str, Any]:
    vars: dict[str, Any] = {}
    for _, name, expr in find_assignments_with_positions(
        source, re.compile(r"(?:String|final String|StringBuilder)\s+(\w+)\s*=\s*", re.S)
    ):
        value = eval_expr(expr, vars)
        if value is not None:
            vars[name] = value
    for m in re.finditer(r"String\[\]\s+(\w+)\s*=\s*\{(.*?)\};", source, re.S):
        values = [eval_expr(part, vars) for part in split_top(m.group(2))]
        if all(isinstance(value, str) for value in values):
            vars[m.group(1)] = values
    return vars


def safelist_base_from_expr(expr: str, safelists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    compact = re.sub(r"\s+", "", expr)
    for name, spec in safelists.items():
        if compact == name or compact.startswith(name + "."):
            return json.loads(json.dumps(spec))
    copy = re.match(r"new(?:Safelist|Whitelist)\((\w+)\)", compact)
    if copy and copy.group(1) in safelists:
        return json.loads(json.dumps(safelists[copy.group(1)]))
    m = re.search(r"(?:Safelist|Whitelist)\.(none|simpleText|basicWithImages|basic|relaxed)\(\)", compact)
    if m:
        return {"base": m.group(1), "steps": []}
    if re.search(r"new(?:Safelist|Whitelist)\(\)", compact):
        return {"base": "empty", "steps": []}
    return None


def apply_safelist_chain(spec: dict[str, Any], expr: str, vars: dict[str, Any]) -> dict[str, Any] | None:
    step_methods = [
        "addTags",
        "removeTags",
        "addAttributes",
        "removeAttributes",
        "addProtocols",
        "removeProtocols",
        "addEnforcedAttribute",
        "removeEnforcedAttribute",
        "preserveRelativeLinks",
    ]
    for method in step_methods:
        for _, args_src in find_calls_with_positions(expr, method):
            if method == "preserveRelativeLinks":
                value = args_src.strip().lower()
                if value not in {"true", "false"}:
                    return None
                spec["steps"].append({"method": method, "value": value == "true"})
                continue
            args = eval_args(args_src, vars)
            if args is None:
                return None
            spec["steps"].append({"method": method, "args": args})
    return spec


def safelist_from_expr(expr: str, vars: dict[str, Any], safelists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    spec = safelist_base_from_expr(expr, safelists)
    if not spec:
        return None
    return apply_safelist_chain(spec, expr, vars)


def parse_clean_call(expr: str, vars: dict[str, Any], safelists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    m = re.search(r"Jsoup\.clean\((.*)\)$", expr.strip(), re.S)
    if not m:
        return None
    args = split_top(m.group(1))
    if len(args) not in {2, 3, 4}:
        return None
    html = eval_expr(args[0], vars)
    if not isinstance(html, str):
        return None
    base_uri = None
    safelist_expr = args[1]
    if len(args) == 3:
        base_uri = eval_expr(args[1], vars)
        safelist_expr = args[2]
        if not isinstance(base_uri, str):
            return None
    output_settings = None
    if len(args) == 4:
        base_uri = eval_expr(args[1], vars)
        safelist_expr = args[2]
        output_settings = vars.get(args[3].strip())
        if not isinstance(base_uri, str) or not isinstance(output_settings, dict):
            return None
    safelist = safelist_from_expr(safelist_expr, vars, safelists)
    if not safelist:
        return None
    return {"op": "jsoup_clean", "params": {"html": html, "base_uri": base_uri, "safelist": safelist, "output_settings": output_settings, "strip_newlines": False}}


def parse_is_valid_call(expr: str, vars: dict[str, Any], safelists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    m = re.search(r"Jsoup\.isValid\((.*)\)$", expr.strip(), re.S)
    if not m:
        return None
    args = split_top(m.group(1))
    if len(args) != 2:
        return None
    html = eval_expr(args[0], vars)
    safelist = safelist_from_expr(args[1], vars, safelists)
    if not isinstance(html, str) or not safelist:
        return None
    return {"op": "jsoup_is_valid", "params": {"html": html, "safelist": safelist}}


def parse_document_expr(expr: str, vars: dict[str, Any]) -> dict[str, Any] | None:
    expr = expr.strip()
    m = re.search(r"Jsoup\.parseBodyFragment\((.*)\)$", expr, re.S)
    mode = "body_fragment"
    if not m:
        m = re.search(r"Jsoup\.parse\((.*)\)$", expr, re.S)
        mode = "parse"
    if not m:
        return None
    args = split_top(m.group(1))
    if not args:
        return None
    html = eval_expr(args[0], vars)
    if not isinstance(html, str):
        return None
    base_uri = None
    if len(args) >= 2:
        base_uri = eval_expr(args[1], vars)
        if base_uri is not None and not isinstance(base_uri, str):
            return None
    return {
        "html": html,
        "base_uri": base_uri,
        "parse_mode": mode,
        "preserve_case": "ParseSettings.preserveCase" in expr,
        "output_settings": None,
    }


def parse_cleaner_expr(expr: str, vars: dict[str, Any], safelists: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    m = re.search(r"new\s+Cleaner\((.*)\)$", expr.strip(), re.S)
    if not m:
        return None
    safelist = safelist_from_expr(m.group(1), vars, safelists)
    return {"safelist": safelist} if safelist else None


def parse_cleaner_document_clean(
    expr: str,
    vars: dict[str, Any],
    safelists: dict[str, dict[str, Any]],
    documents: dict[str, dict[str, Any]],
    cleaners: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    expr = expr.strip()
    if expr.endswith(".body().html()"):
        expr = expr[: -len(".body().html()")]
    m = re.search(r"new\s+Cleaner\((.*?)\)\.clean\((.*?)\)$", expr, re.S)
    cleaner = None
    doc_expr = None
    if m:
        safelist = safelist_from_expr(m.group(1), vars, safelists)
        if safelist:
            cleaner = {"safelist": safelist}
        doc_expr = m.group(2)
    else:
        m = re.search(r"(\w+)\.clean\((.*?)\)$", expr, re.S)
        if m and m.group(1) in cleaners:
            cleaner = cleaners[m.group(1)]
            doc_expr = m.group(2)
    if not cleaner or doc_expr is None:
        return None
    document = documents.get(doc_expr.strip()) or parse_document_expr(doc_expr, vars)
    if not document:
        return None
    return {"op": "jsoup_clean_document", "params": {**document, "safelist": cleaner["safelist"], "strip_newlines": False}}


def parse_cleaner_document_is_valid(
    expr: str,
    documents: dict[str, dict[str, Any]],
    cleaners: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    m = re.search(r"(\w+)\.isValid\((.*?)\)$", expr.strip(), re.S)
    if not m or m.group(1) not in cleaners:
        return None
    document = documents.get(m.group(2).strip())
    if not document:
        return None
    return {"op": "jsoup_is_valid_document", "params": {**document, "safelist": cleaners[m.group(1)]["safelist"]}}


def capability(op: str, params: dict[str, Any], expected: dict[str, Any]) -> str:
    text = json.dumps({"params": params, "expected": expected}, ensure_ascii=True).lower()
    if op in {"jsoup_is_valid", "jsoup_is_valid_document"}:
        return "html-sanitize.validity-check"
    if "javascript:" in text or "script" in text or "onload" in text or "onclick" in text:
        return "html-sanitize.parser-xss-hardening"
    if "base_uri" in params and params.get("base_uri"):
        return "html-sanitize.relative-url-resolution"
    if "href" in text or "src" in text or "protocol" in text or "mailto" in text or "ftp" in text:
        return "html-sanitize.url-attribute-policy"
    if "rel=" in text or "nofollow" in text:
        return "html-sanitize.link-rel-policy"
    if "table" in text or "tbody" in text or "noscript" in text:
        return "html-sanitize.html5-structure-balancing"
    if "class" in text or "data-" in text or "attribute" in text:
        return "html-sanitize.attribute-policy"
    return "html-sanitize.default-html"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for key, value in expected.items():
        out[key] = (not value) if isinstance(value, bool) else str(value) + "__mutant__"
    return out


def prior_exact_keys() -> set[str]:
    keys: set[str] = set()
    for path in [DOMPURIFY_JSON, OWASP_JSON]:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in data.get("survivors", []):
            expected = row.get("expected", {})
            clean = expected.get("clean")
            if clean is None:
                continue
            params = row.get("params", {})
            dirty = params.get("dirty", params.get("html"))
            if dirty is None:
                continue
            keys.add(json.dumps({"dirty": dirty, "clean": clean}, ensure_ascii=True, sort_keys=True))
    return keys


def add_contract(
    out: list[dict[str, Any]],
    seen: set[str],
    version: str,
    tag: str,
    op: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    source: str,
    avoid: set[str],
) -> bool:
    clean = expected.get("clean")
    if clean is not None:
        overlap_key = json.dumps({"dirty": params.get("html"), "clean": clean}, ensure_ascii=True, sort_keys=True)
        if overlap_key in avoid:
            return False
    key = json.dumps({"op": op, "params": params, "expected": expected}, ensure_ascii=True, sort_keys=True)
    if key in seen:
        return False
    seen.add(key)
    out.append({
        "name": f"{version}:{re.sub(r'[^A-Za-z0-9]+', '_', source.lower()).strip('_')}:{len(out) + 1}",
        "version": version,
        "capability": capability(op, params, expected),
        "op": op,
        "params": params,
        "expected": expected,
        "mutant": mutate_expected(expected),
        "evidence": {"tag": tag, "source": source},
    })
    return True


def extract_from_java(version: str, tag: str, source: str, source_name: str, avoid: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for body in find_method_bodies(source):
        vars = load_string_vars(body)
        safelists: dict[str, dict[str, Any]] = {}
        clean_vars: dict[str, dict[str, Any]] = {}
        documents: dict[str, dict[str, Any]] = {}
        cleaners: dict[str, dict[str, Any]] = {}
        clean_doc_vars: dict[str, dict[str, Any]] = {}
        bool_vars: dict[str, dict[str, Any]] = {}
        output_settings: dict[str, dict[str, Any]] = {}
        events: list[tuple[int, str, Any]] = []

        for row in find_assignments_with_positions(body, re.compile(r"(?:String|final String|StringBuilder)\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "string_assignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"(?<![A-Za-z0-9_])(\w+)\s*=\s*", re.S)):
            events.append((row[0], "string_reassignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"(?:Safelist|Whitelist)\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "safelist_assignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"Document\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "document_assignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"Cleaner\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "cleaner_assignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"boolean\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "boolean_assignment", row))
        for row in find_assignments_with_positions(body, re.compile(r"Document\.OutputSettings\s+(\w+)\s*=\s*", re.S)):
            events.append((row[0], "output_settings_assignment", row))
        for method in ["prettyPrint", "escapeMode", "charset", "syntax"]:
            for pos, args in find_calls_with_positions(body, method):
                prefix = body[:pos]
                doc_match = re.search(r"(\w+)\.outputSettings\(\)\s*\.\s*$", prefix)
                if doc_match:
                    events.append((pos, "document_output_settings_mutation", (doc_match.group(1), method, args)))
                    continue
                m = re.search(r"(\w+)\s*\.\s*$", prefix)
                if m:
                    events.append((pos, "output_settings_mutation", (m.group(1), method, args)))
        for method in ["addTags", "removeTags", "addAttributes", "removeAttributes", "addProtocols", "removeProtocols", "addEnforcedAttribute", "removeEnforcedAttribute", "preserveRelativeLinks"]:
            for pos, args in find_calls_with_positions(body, method):
                prefix = body[:pos]
                m = re.search(r"(\w+)\s*\.\s*$", prefix)
                if m:
                    events.append((pos, "safelist_mutation", (m.group(1), method, args)))
        for pos, call in find_calls_with_positions(body, "assertEquals"):
            events.append((pos, "assert_equals", call))
        for pos, call in find_calls_with_positions(body, "assertTrue"):
            events.append((pos, "assert_bool", (call, True)))
        for pos, call in find_calls_with_positions(body, "assertFalse"):
            events.append((pos, "assert_bool", (call, False)))

        for _, kind, payload in sorted(events, key=lambda row: row[0]):
            if kind in {"string_assignment", "string_reassignment"}:
                _, name, expr = payload
                clean_spec = parse_clean_call(expr, vars, safelists)
                if clean_spec:
                    clean_vars[name] = clean_spec
                    continue
                value = eval_expr(expr, vars)
                if isinstance(value, str):
                    vars[name] = value
                continue
            if kind == "safelist_assignment":
                _, name, expr = payload
                spec = safelist_from_expr(expr, vars, safelists)
                if spec:
                    safelists[name] = spec
                continue
            if kind == "document_assignment":
                _, name, expr = payload
                clean_spec = parse_cleaner_document_clean(expr, vars, safelists, documents, cleaners)
                if clean_spec:
                    clean_doc_vars[name] = clean_spec
                    continue
                doc = parse_document_expr(expr, vars)
                if doc:
                    documents[name] = doc
                continue
            if kind == "cleaner_assignment":
                _, name, expr = payload
                cleaner = parse_cleaner_expr(expr, vars, safelists)
                if cleaner:
                    cleaners[name] = cleaner
                continue
            if kind == "boolean_assignment":
                _, name, expr = payload
                spec = parse_is_valid_call(expr, vars, safelists) or parse_cleaner_document_is_valid(expr, documents, cleaners)
                if spec:
                    bool_vars[name] = spec
                continue
            if kind == "output_settings_assignment":
                _, name, _ = payload
                output_settings[name] = {"pretty_print": True, "escape_mode": None, "charset": None, "syntax": None}
                vars[name] = output_settings[name]
                continue
            if kind == "output_settings_mutation":
                name, method, args_src = payload
                if name not in output_settings:
                    continue
                if method == "prettyPrint":
                    value = args_src.strip().lower()
                    if value in {"true", "false"}:
                        output_settings[name]["pretty_print"] = value == "true"
                elif method == "escapeMode":
                    m = re.search(r"EscapeMode\.([A-Za-z]+)", args_src)
                    if m:
                        output_settings[name]["escape_mode"] = m.group(1)
                elif method == "charset":
                    value = eval_expr(args_src, vars)
                    if isinstance(value, str):
                        output_settings[name]["charset"] = value
                elif method == "syntax":
                    m = re.search(r"Syntax\.([A-Za-z]+)", args_src)
                    if m:
                        output_settings[name]["syntax"] = m.group(1)
                vars[name] = output_settings[name]
                continue
            if kind == "document_output_settings_mutation":
                name, method, args_src = payload
                if name not in documents:
                    continue
                settings = documents[name].get("output_settings")
                if not isinstance(settings, dict):
                    settings = {"pretty_print": None, "escape_mode": None, "charset": None, "syntax": None}
                if method == "prettyPrint":
                    value = args_src.strip().lower()
                    if value in {"true", "false"}:
                        settings["pretty_print"] = value == "true"
                elif method == "escapeMode":
                    m = re.search(r"EscapeMode\.([A-Za-z]+)", args_src)
                    if m:
                        settings["escape_mode"] = m.group(1)
                elif method == "charset":
                    value = eval_expr(args_src, vars)
                    if isinstance(value, str):
                        settings["charset"] = value
                elif method == "syntax":
                    m = re.search(r"Syntax\.([A-Za-z]+)", args_src)
                    if m:
                        settings["syntax"] = m.group(1)
                documents[name]["output_settings"] = settings
                continue
            if kind == "safelist_mutation":
                name, method, args_src = payload
                if name not in safelists:
                    continue
                updated = apply_safelist_chain(json.loads(json.dumps(safelists[name])), f".{method}({args_src})", vars)
                if updated:
                    safelists[name] = updated
                continue
            if kind == "assert_equals":
                args = split_top(payload)
                if len(args) == 3 and eval_expr(args[0], vars) is None:
                    args = args[1:]
                if len(args) != 2:
                    continue
                expected_value = eval_expr(args[0], vars)
                if not isinstance(expected_value, str):
                    continue
                rhs = args[1].strip()
                strip_newlines = False
                m = re.match(r"(?:TextUtil\.)?stripNewlines\((.*)\)$", rhs, re.S)
                if m:
                    strip_newlines = True
                    rhs = m.group(1).strip()
                spec = (
                    clean_vars.get(rhs)
                    or clean_doc_vars.get(re.sub(r"\.body\(\)\.html\(\)$", "", rhs))
                    or parse_clean_call(rhs, vars, safelists)
                    or parse_cleaner_document_clean(rhs, vars, safelists, documents, cleaners)
                )
                if spec:
                    params = json.loads(json.dumps(spec["params"]))
                    params["strip_newlines"] = strip_newlines or params.get("strip_newlines", False)
                    add_contract(out, seen, version, tag, spec["op"], params, {"clean": expected_value}, f"{source_name}.clean", avoid)
            if kind == "assert_bool":
                call, expected_bool = payload
                spec = bool_vars.get(call.strip()) or parse_is_valid_call(call, vars, safelists) or parse_cleaner_document_is_valid(call, documents, cleaners)
                if spec:
                    add_contract(out, seen, version, tag, spec["op"], spec["params"], {"valid": expected_bool}, f"{source_name}.isValid", avoid)
    return out


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'])} {{")
        lines.append(f"  version {json.dumps(row['version'])}")
        lines.append(f"  capability {json.dumps(row['capability'])}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    latest, versions = load_versions()
    tags = git_tags()
    avoid = prior_exact_keys()
    global_seen: set[str] = set()
    all_contracts: list[dict[str, Any]] = []
    release_counts: list[dict[str, Any]] = []
    missing_tags: list[str] = []
    release_entries: list[dict[str, str | None]] = []
    matched_tags: set[str] = set()
    maven_version_set = set(versions)

    for version in versions:
        tag = tag_for(version, tags)
        if tag:
            matched_tags.add(tag)
        release_entries.append({"version": version, "tag": tag, "source": "maven"})
    for tag in tags:
        if tag in matched_tags:
            continue
        version = version_from_tag(tag)
        if version in maven_version_set:
            continue
        release_entries.append({"version": version, "tag": tag, "source": "git-tag"})

    paths = {
        "CleanerTest.java": [
            "src/test/java/org/jsoup/safety/CleanerTest.java",
            "src/test/java/org/jsoup/org/jsoup/safety/CleanerTest.java",
        ],
        "SafelistTest.java": [
            "src/test/java/org/jsoup/safety/SafelistTest.java",
            "src/test/java/org/jsoup/safety/WhitelistTest.java",
        ],
        "HtmlParserTest.java": ["src/test/java/org/jsoup/parser/HtmlParserTest.java"],
    }

    for entry in sorted(release_entries, key=lambda row: version_key(str(row["version"]))):
        version = str(entry["version"])
        tag = entry["tag"]
        if not tag:
            missing_tags.append(version)
            release_counts.append({"version": version, "tag": None, "source": entry["source"], "contracts_seen": 0, "new_contracts": 0})
            continue
        contracts: list[dict[str, Any]] = []
        for source_name, source_paths in paths.items():
            source = git_show_any(str(tag), source_paths)
            if source:
                contracts.extend(extract_from_java(version, str(tag), source, source_name, avoid))
        new_count = 0
        for contract in contracts:
            key = json.dumps({"op": contract["op"], "params": contract["params"], "expected": contract["expected"]}, ensure_ascii=True, sort_keys=True)
            if key in global_seen:
                continue
            global_seen.add(key)
            all_contracts.append(contract)
            new_count += 1
        release_counts.append({"version": version, "tag": tag, "source": entry["source"], "contracts_seen": len(contracts), "new_contracts": new_count})

    for idx, contract in enumerate(all_contracts, 1):
        contract["name"] = re.sub(r":\d+$", f":{idx}", contract["name"])

    by_cap = Counter(row["capability"] for row in all_contracts)
    by_op = Counter(row["op"] for row in all_contracts)
    summary = {
        "domain": "HTML Sanitizer",
        "project": "jsoup/jsoup",
        "latest_version": latest,
        "maven_versions": len(versions),
        "git_tags": len(tags),
        "release_points_considered": len(release_entries),
        "release_points_inspected": sum(1 for row in release_counts if row["tag"]),
        "versions_with_matching_tags_inspected": sum(1 for row in release_counts if row["tag"]),
        "versions_without_matching_tags": missing_tags,
        "release_counts": release_counts,
        "prior_exact_survivor_pairs_avoided": len(avoid),
        "extraction_basis": "Official Maven versions and git release tags; Jsoup.clean/Safelist, Cleaner, and Jsoup.isValid observable sanitizer behavior. Exact prior DOMPurify/OWASP survivor clean pairs are skipped.",
        "contract_count": len(all_contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_op": dict(sorted(by_op.items())),
        "contracts": all_contracts,
    }
    (OUT_DIR / "all_releases_excluding_prior.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(all_contracts, OUT_DIR / "all_releases_excluding_prior.rpl")

    lines = ["# jsoup Release Contract Counts", "", "| Version | Source | Tag | Contracts observed | New unique contracts |", "| --- | --- | --- | ---: | ---: |"]
    for row in release_counts:
        lines.append(f"| `{row['version']}` | `{row['source']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit = [
        "# jsoup Extraction Audit",
        "",
        f"Latest Maven version: `{latest}`",
        f"Maven versions: {len(versions)}",
        f"Git tags available: {len(tags)}",
        f"Release points considered: {summary['release_points_considered']}",
        f"Release points inspected: {summary['release_points_inspected']}",
        f"Extracted contracts: {len(all_contracts)}",
        f"Exact prior survivor pairs avoided: {len(avoid)}",
        "",
        "Basis: official release tags; `Jsoup.clean`, `Cleaner.clean(...).body().html()`, and `Jsoup.isValid` observable sanitizer behavior. Callback-heavy, formatter-only, network, and parser-only internals are intentionally excluded.",
        "",
        "## By Capability",
        "",
        "| Capability | Contracts |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_cap.items()):
        audit.append(f"| `{cap}` | {count} |")
    audit.extend(["", "## By Operation", "", "| Operation | Contracts |", "| --- | ---: |"])
    for op, count in sorted(by_op.items()):
        audit.append(f"| `{op}` | {count} |")
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")

    printable = {k: summary[k] for k in ["latest_version", "maven_versions", "git_tags", "release_points_considered", "release_points_inspected", "contract_count", "by_capability", "by_op"]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
