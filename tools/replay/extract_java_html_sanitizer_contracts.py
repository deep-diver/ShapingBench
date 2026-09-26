#!/usr/bin/env python3
"""Extract OWASP java-html-sanitizer release-history contracts."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "html_sanitizer" / "java-html-sanitizer"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "java-html-sanitizer"
DOMPURIFY_JSON = ROOT / "contracts" / "html_sanitizer" / "dompurify" / "latest_replay_mutant_verified.json"
MAVEN_METADATA = "https://repo1.maven.org/maven2/com/googlecode/owasp-java-html-sanitizer/owasp-java-html-sanitizer/maven-metadata.xml"


def semver_key(version: str) -> tuple[int, ...]:
    if version.startswith("r"):
        return (0, int(version[1:]))
    return tuple(int(part) for part in re.findall(r"\d+", version))


def load_versions() -> tuple[str, list[str]]:
    data = urllib.request.urlopen(MAVEN_METADATA, timeout=30).read().decode("utf-8")
    versions = re.findall(r"<version>([^<]+)</version>", data)
    latest = re.search(r"<latest>([^<]+)</latest>", data)
    return latest.group(1) if latest else versions[-1], versions


def git_tags() -> set[str]:
    out = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list"], text=True)
    return {line.strip() for line in out.splitlines() if line.strip()}


def tag_for(version: str, tags: set[str]) -> str | None:
    candidates = [
        version,
        f"release-{version}",
        f"owasp-java-html-sanitizer-{version}",
    ]
    if version.startswith("r"):
        candidates.append(f"release-{version[1:]}")
    for candidate in candidates:
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


def git_show_any(tag: str, paths: list[str]) -> str | None:
    for path in paths:
        text = git_show(tag, path)
        if text is not None:
            return text
    return None


def find_method_bodies(source: str) -> list[str]:
    bodies: list[str] = []
    pattern = re.compile(r"(?:public\s+)?(?:static\s+)?(?:final\s+)?void\s+\w+\s*\([^)]*\)\s*\{")
    for match in pattern.finditer(source):
        start = match.end() - 1
        depth = 0
        quote = None
        escape = False
        for i in range(start, len(source)):
            ch = source[i]
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
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


def unescape_java_string(body: str) -> str:
    out = []
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
        mapping = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "\\": "\\", '"': '"', "'": "'"}
        if esc in mapping:
            out.append(mapping[esc])
        elif esc == "u":
            while i < len(body) and body[i] == "u":
                i += 1
            hexpart = body[i : i + 4]
            if len(hexpart) == 4:
                out.append(chr(int(hexpart, 16)))
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


def split_top(expr: str, sep: str = ",") -> list[str]:
    parts, start, depth, quote = [], 0, 0, None
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


def find_calls(source: str, name: str) -> list[str]:
    return [call for _, call in find_calls_with_positions(source, name)]


def find_calls_with_positions(source: str, name: str) -> list[tuple[int, str]]:
    calls = []
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for match in pattern.finditer(source):
        i = match.end()
        depth, quote = 1, None
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
    assignments: list[tuple[int, str, str]] = []
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
                assignments.append((match.start(), match.group(1), source[match.end() : i]))
                break
            i += 1
    return assignments


def eval_expr(expr: str, vars: dict[str, str]) -> str | None:
    expr = expr.strip()
    if expr == "null":
        return None
    if expr in vars:
        return vars[expr]
    if expr.startswith("String.valueOf(Character.toChars("):
        m = re.search(r"toChars\((0x[0-9a-fA-F]+|\d+)\)", expr)
        return chr(int(m.group(1), 0)) if m else None
    if expr.startswith("String.join("):
        inner = expr[len("String.join(") : -1]
        parts = split_top(inner)
        if len(parts) >= 2:
            sep = eval_expr(parts[0], vars)
            values = [eval_expr(part, vars) for part in parts[1:]]
            if sep is not None and all(value is not None for value in values):
                return sep.join(value or "" for value in values)
    pieces = split_top(expr, "+")
    if len(pieces) > 1:
        values = [eval_expr(piece, vars) for piece in pieces]
        if all(value is not None for value in values):
            return "".join(value or "" for value in values)
        return None
    if len(expr) >= 2 and expr[0] == '"' and expr[-1] == '"':
        return unescape_java_string(expr[1:-1])
    return None


def load_vars(source: str) -> dict[str, str]:
    vars: dict[str, str] = {}
    for m in re.finditer(r"(?:String|final String|StringBuilder)\s+(\w+)\s*=\s*(.*?);", source, re.S):
        name, expr = m.group(1), m.group(2)
        value = eval_expr(expr, vars)
        if value is not None:
            vars[name] = value
    return vars


def load_example_var(source: str) -> dict[str, str]:
    anchor = re.search(r"static final String EXAMPLE\s*=\s*String\.join\(", source)
    if not anchor:
        return {}
    start = anchor.end() - len("String.join(")
    call = find_calls(source[start:], "String.join")
    if not call:
        return {}
    value = eval_expr("String.join(" + call[0] + ")", {})
    return {"EXAMPLE": value} if value is not None else {}


def inside_active_if(source: str, pos: int) -> bool:
    prefix = source[:pos]
    last_if = prefix.rfind("if (")
    if last_if < 0:
        return False
    last_assert = max(prefix.rfind("assertEquals"), prefix.rfind("assertSanitizedDoes"))
    if last_if < last_assert:
        return False
    return prefix[last_if:].count("{") > prefix[last_if:].count("}")


def builder_policy_from_source(source: str) -> dict[str, Any] | None:
    if "new HtmlPolicyBuilder()" not in source:
        return None
    if "->" in source or "ElementPolicy" in source:
        return None
    compact = re.sub(r"\s+", " ", source)
    steps = []
    simple_methods = [
        "allowCommonInlineFormattingElements",
        "allowCommonBlockElements",
        "allowStyling",
        "allowStandardUrlProtocols",
        "requireRelNofollowOnLinks",
    ]
    for method in simple_methods:
        if f".{method}(" in compact:
            steps.append({"method": method, "args": []})
    for method in ["allowElements", "disallowElements", "allowUrlProtocols", "disallowUrlProtocols", "allowWithoutAttributes", "disallowWithoutAttributes", "allowTextIn", "requireRelsOnLinks"]:
        for call in find_calls(compact, method):
            args = [eval_expr(arg, {}) for arg in split_top(call)]
            if all(arg is not None for arg in args):
                steps.append({"method": method, "args": args})
    for m in re.finditer(r"\.(allowAttributes|disallowAttributes)\((.*?)\)(.*?)\.\s*(onElements|globally)\((.*?)\)", compact):
        attrs = [eval_expr(arg, {}) for arg in split_top(m.group(2))]
        middle = m.group(3)
        target_kind = m.group(4)
        targets = [eval_expr(arg, {}) for arg in split_top(m.group(5))] if target_kind == "onElements" else []
        if all(arg is not None for arg in attrs + targets):
            step = {"method": m.group(1), "args": attrs, "target": target_kind, "targets": targets}
            regex_match = re.search(r"\.matching\(Pattern\.compile\((.*?)\)\)", middle)
            allowed_match = re.search(r"\.matching\((true|false)\s*,(.*?)\)", middle)
            if regex_match:
                regex_value = eval_expr(regex_match.group(1), {})
                if regex_value is None:
                    continue
                step["match_regex"] = regex_value
            elif allowed_match:
                allowed = [eval_expr(arg, {}) for arg in split_top(allowed_match.group(2))]
                if any(arg is None for arg in allowed):
                    continue
                step["match_allowed"] = allowed
                step["ignore_case"] = allowed_match.group(1) == "true"
            elif "matching(" in middle:
                continue
            steps.append(step)
    if not steps:
        return None
    return {"type": "builder", "steps": steps}


def policy_from_expr(expr: str, known: dict[str, dict[str, Any]] | None = None) -> dict[str, Any] | None:
    known = known or {}
    compact = re.sub(r"\s+", "", expr)
    if compact in known:
        return known[compact]
    policies: list[dict[str, Any]] = []
    names = re.findall(r"Sanitizers\.([A-Z]+)", compact)
    if names:
        policies.append({"type": "sanitizers", "names": names})
    for name, policy in known.items():
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", compact):
            policies.append(policy)
    if "newHtmlPolicyBuilder()" in compact:
        builder = builder_policy_from_source(expr)
        if builder:
            policies.append(builder)
    if not policies:
        return None

    skeleton = re.sub(r"Sanitizers\.[A-Z]+", "", compact)
    for name in known:
        skeleton = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", "", skeleton)
    skeleton = re.sub(r"newHtmlPolicyBuilder\(\).*?toFactory\(\)", "", skeleton)
    skeleton = skeleton.replace(".and(", "").replace(")", "")
    if re.search(r"[A-Za-z_]", skeleton):
        return None
    if len(policies) == 1:
        return policies[0]
    return {"type": "and", "policies": policies}


def capability(op: str, row: dict[str, Any]) -> str:
    text = json.dumps(row, ensure_ascii=True).lower()
    if op == "antisamy_contains":
        return "html-sanitize.xss-payload-regression"
    if op == "html_sanitizer_test_sanitize":
        if "javascript:" in text or "onload" in text or "onclick" in text or "script" in text:
            return "html-sanitize.parser-xss-hardening"
        if "style" in text or "css" in text:
            return "html-sanitize.css-policy"
        if "href" in text or "src" in text:
            return "html-sanitize.url-attribute-policy"
        if "noscript" in text or "noframes" in text or "table" in text:
            return "html-sanitize.html5-structure-balancing"
        return "html-sanitize.default-html"
    if op == "css_sanitize" or "style" in text or "css" in text:
        return "html-sanitize.css-policy"
    if op.startswith("decode") or op == "strip_banned":
        return "html-sanitize.entity-codeunit-normalization"
    if "srcset" in text:
        return "html-sanitize.srcset-url-policy"
    if "rel=" in text or "nofollow" in text or "noopener" in text or "noreferrer" in text:
        return "html-sanitize.link-rel-policy"
    if "javascript:" in text or "href" in text or "src" in text or "protocol" in text:
        return "html-sanitize.url-attribute-policy"
    if "svg" in text or "mathml" in text:
        return "html-sanitize.foreign-content"
    if "table" in text or "option" in text or "select" in text:
        return "html-sanitize.html5-structure-balancing"
    if "allow" in text or "disallow" in text or "sanitizers" in text:
        return "html-sanitize.policy-composition"
    return "html-sanitize.policy-sanitize"


def slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", text.lower()).strip("_")[:90] or "contract"


def mutate(expected: Any) -> Any:
    if isinstance(expected, bool):
        return not expected
    if expected is None:
        return "__mutant__"
    return str(expected) + "__mutant__"


def dompurify_exact_keys() -> set[str]:
    if not DOMPURIFY_JSON.exists():
        return set()
    data = json.loads(DOMPURIFY_JSON.read_text(encoding="utf-8"))
    keys = set()
    for row in data.get("survivors", []):
        params = row.get("params", {})
        if params.get("config") is None:
            keys.add(json.dumps({"dirty": params.get("dirty"), "clean": row.get("expected", {}).get("clean")}, ensure_ascii=True, sort_keys=True))
    return keys


def add_contract(out: list[dict[str, Any]], seen: set[str], version: str, tag: str, op: str, params: dict[str, Any], expected: dict[str, Any], source: str, avoid: set[str]) -> bool:
    dirty_for_overlap = params.get("dirty", params.get("html"))
    clean_for_overlap = expected.get("clean")
    if clean_for_overlap is not None:
        overlap_key = json.dumps({"dirty": dirty_for_overlap, "clean": clean_for_overlap}, ensure_ascii=True, sort_keys=True)
        if overlap_key in avoid:
            return False
    key = json.dumps({"op": op, "params": params, "expected": expected}, ensure_ascii=True, sort_keys=True)
    if key in seen:
        return False
    seen.add(key)
    raw = f"{op}:{source}:{params}:{expected}"
    out.append({
        "name": f"{version}:{slug(source)}:{len(out) + 1}",
        "version": version,
        "capability": capability(op, {"params": params, "expected": expected, "source": source}),
        "op": op,
        "params": params,
        "expected": expected,
        "mutant": {k: mutate(v) for k, v in expected.items()},
        "evidence": {"tag": tag, "source": source},
    })
    return True


def extract_from_sources(version: str, tag: str, files: dict[str, str | None], avoid: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    styling = files.get("StylingPolicyTest.java") or ""
    vars = load_vars(styling)
    for call in find_calls(styling, "assertSanitizedCss"):
        args = split_top(call)
        if len(args) != 2:
            continue
        expected = eval_expr(args[0], vars)
        css = eval_expr(args[1], vars)
        if css is None:
            continue
        add_contract(out, seen, version, tag, "css_sanitize", {"css": css}, {"clean": expected}, "StylingPolicyTest.assertSanitizedCss", avoid)

    encoding = files.get("EncodingTest.java") or ""
    vars = load_vars(encoding)
    for call in find_calls(encoding, "assertDecodedHtml"):
        args = split_top(call)
        if len(args) == 2:
            want = eval_expr(args[0], vars)
            inp = eval_expr(args[1], vars)
            if inp is not None and want is not None:
                add_contract(out, seen, version, tag, "decode_html", {"html": inp, "in_attribute": False}, {"text": want}, "EncodingTest.assertDecodedHtml.text", avoid)
                add_contract(out, seen, version, tag, "decode_html", {"html": inp, "in_attribute": True}, {"text": want}, "EncodingTest.assertDecodedHtml.attr", avoid)
        elif len(args) == 3:
            want_text = eval_expr(args[0], vars)
            want_attr = eval_expr(args[1], vars)
            inp = eval_expr(args[2], vars)
            if inp is not None and want_text is not None:
                add_contract(out, seen, version, tag, "decode_html", {"html": inp, "in_attribute": False}, {"text": want_text}, "EncodingTest.assertDecodedHtml.text_attr_variant", avoid)
            if inp is not None and want_attr is not None:
                add_contract(out, seen, version, tag, "decode_html", {"html": inp, "in_attribute": True}, {"text": want_attr}, "EncodingTest.assertDecodedHtml.attr_variant", avoid)
    for call in find_calls(encoding, "assertStripped"):
        args = split_top(call)
        if len(args) == 2:
            stripped = eval_expr(args[0], vars)
            orig = eval_expr(args[1], vars)
            if orig is not None and stripped is not None:
                add_contract(out, seen, version, tag, "strip_banned", {"text": orig}, {"text": stripped}, "EncodingTest.assertStripped", avoid)

    sanitizers = files.get("SanitizersTest.java") or ""
    for body in find_method_bodies(sanitizers):
        vars = load_vars(body)
        policy_vars = {}
        events: list[tuple[int, str, Any]] = []
        for m in re.finditer(r"(?:PolicyFactory\s+)?(\w+)\s*=\s*(.*?);", body, re.S):
            events.append((m.start(), "policy_assignment", m))
        for pos, call in find_calls_with_positions(body, "assertEquals"):
            events.append((pos, "assert_equals", call))
        for _, kind, payload in sorted(events, key=lambda row: row[0]):
            if kind == "policy_assignment":
                policy = policy_from_expr(payload.group(2), policy_vars)
                if policy:
                    policy_vars[payload.group(1)] = policy
                continue
            call = payload
            args = split_top(call)
            if len(args) == 3 and eval_expr(args[0], vars) is None:
                args = args[1:]
            if len(args) != 2:
                continue
            expected = eval_expr(args[0], vars)
            sanitize_match = re.search(r"([A-Za-z0-9_.()]+)\.sanitize\((.*)\)$", args[1].strip(), re.S)
            if not sanitize_match:
                continue
            policy_expr, input_expr = sanitize_match.group(1), sanitize_match.group(2)
            if policy_expr in policy_vars:
                policy = policy_vars[policy_expr]
            else:
                policy = policy_from_expr(policy_expr, policy_vars)
            dirty = eval_expr(input_expr, vars)
            if policy and dirty is not None and expected is not None:
                add_contract(out, seen, version, tag, "policy_sanitize", {"policy": policy, "dirty": dirty}, {"clean": expected}, "SanitizersTest.assertEquals.sanitize", avoid)

    builder = files.get("HtmlPolicyBuilderTest.java") or ""
    global_builder_vars = load_example_var(builder)
    for body in find_method_bodies(builder):
        vars = {**global_builder_vars, **load_vars(body)}
        for call in find_calls(body, "assertEquals"):
            args = split_top(call)
            if len(args) == 3 and eval_expr(args[0], vars) is None:
                args = args[1:]
            if len(args) != 2:
                continue
            expected = eval_expr(args[0], vars)
            rhs = args[1].strip()
            if not rhs.startswith("apply("):
                continue
            apply_args = split_top(rhs[len("apply(") : -1])
            if not apply_args:
                continue
            policy = builder_policy_from_source(apply_args[0])
            dirty = eval_expr(apply_args[1], vars) if len(apply_args) > 1 else vars.get("EXAMPLE")
            if policy and dirty is not None and expected is not None:
                add_contract(out, seen, version, tag, "policy_sanitize", {"policy": policy, "dirty": dirty}, {"clean": expected}, "HtmlPolicyBuilderTest.apply", avoid)

    html_sanitizer = files.get("HtmlSanitizerTest.java") or ""
    for body in find_method_bodies(html_sanitizer):
        vars = load_vars(body)
        for call in find_calls(body, "assertEquals"):
            args = split_top(call)
            if len(args) == 3 and eval_expr(args[0], vars) is None:
                args = args[1:]
            if len(args) != 2:
                continue
            expected = eval_expr(args[0], vars)
            rhs = args[1].strip()
            m = re.match(r"sanitize\((.*)\)$", rhs, re.S)
            if not m:
                continue
            input_expr = m.group(1)
            dirty = eval_expr(input_expr, vars)
            if expected is not None and (dirty is not None or input_expr.strip() == "null"):
                add_contract(out, seen, version, tag, "html_sanitizer_test_sanitize", {"html": dirty}, {"clean": expected}, "HtmlSanitizerTest.sanitize", avoid)

    antisamy = files.get("AntiSamyTest.java") or ""
    for body in find_method_bodies(antisamy):
        vars: dict[str, str] = {}
        events: list[tuple[int, str, Any]] = []
        declaration_pattern = re.compile(r"(?:String|final String|StringBuilder)\s+(\w+)\s*=\s*", re.S)
        reassignment_pattern = re.compile(r"(?<![A-Za-z0-9_])(\w+)\s*=\s*", re.S)
        for assignment in find_assignments_with_positions(body, declaration_pattern):
            events.append((assignment[0], "string_assignment", assignment))
        for assignment in find_assignments_with_positions(body, reassignment_pattern):
            events.append((assignment[0], "string_reassignment", assignment))
        for op_name, expected_bool in [("assertSanitizedDoesContain", True), ("assertSanitizedDoesNotContain", False)]:
            for pos, call in find_calls_with_positions(body, op_name):
                events.append((pos, op_name, (call, expected_bool)))
        for pos, kind, payload in sorted(events, key=lambda row: row[0]):
            if kind in {"string_assignment", "string_reassignment"}:
                _, name, expr = payload
                value = eval_expr(expr, vars)
                if value is not None:
                    vars[name] = value
                continue
            if inside_active_if(body, pos):
                continue
            call, expected_bool = payload
            args = split_top(call)
            if len(args) != 2:
                continue
            dirty = eval_expr(args[0], vars)
            needle = eval_expr(args[1], vars)
            if dirty is not None and needle is not None:
                add_contract(out, seen, version, tag, "antisamy_contains", {"html": dirty, "needle": needle}, {"contains": expected_bool}, f"AntiSamyTest.{kind}", avoid)
    return out


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
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
    avoid = dompurify_exact_keys()
    all_contracts: list[dict[str, Any]] = []
    global_seen: set[str] = set()
    release_counts = []
    missing_tags = []
    for version in sorted(versions, key=semver_key):
        tag = tag_for(version, tags)
        if not tag:
            missing_tags.append(version)
            release_counts.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        paths = {
            "StylingPolicyTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/StylingPolicyTest.java",
                "src/test/java/org/owasp/html/StylingPolicyTest.java",
            ],
            "EncodingTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/EncodingTest.java",
                "src/test/java/org/owasp/html/EncodingTest.java",
            ],
            "SanitizersTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/SanitizersTest.java",
                "src/test/java/org/owasp/html/SanitizersTest.java",
            ],
            "HtmlPolicyBuilderTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java",
                "src/test/java/org/owasp/html/HtmlPolicyBuilderTest.java",
            ],
            "HtmlSanitizerTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/HtmlSanitizerTest.java",
                "src/test/java/org/owasp/html/HtmlSanitizerTest.java",
            ],
            "AntiSamyTest.java": [
                "owasp-java-html-sanitizer/src/test/java/org/owasp/html/AntiSamyTest.java",
                "src/test/java/org/owasp/html/AntiSamyTest.java",
            ],
        }
        files = {name: git_show_any(tag, path_options) for name, path_options in paths.items()}
        contracts = extract_from_sources(version, tag, files, avoid)
        new_count = 0
        for contract in contracts:
            key = json.dumps({"op": contract["op"], "params": contract["params"], "expected": contract["expected"]}, ensure_ascii=True, sort_keys=True)
            if key in global_seen:
                continue
            global_seen.add(key)
            all_contracts.append(contract)
            new_count += 1
        release_counts.append({"version": version, "tag": tag, "contracts_seen": len(contracts), "new_contracts": new_count})

    for idx, contract in enumerate(all_contracts, 1):
        contract["name"] = re.sub(r":\\d+$", f":{idx}", contract["name"])
    by_cap = Counter(row["capability"] for row in all_contracts)
    by_op = Counter(row["op"] for row in all_contracts)
    summary = {
        "domain": "HTML Sanitizer",
        "project": "OWASP/java-html-sanitizer",
        "latest_version": latest,
        "maven_versions": len(versions),
        "git_tags": len(tags),
        "versions_with_matching_tags_inspected": sum(1 for row in release_counts if row["tag"]),
        "versions_without_matching_tags": missing_tags,
        "dompurify_exact_survivor_pairs_avoided": len(avoid),
        "extraction_basis": "Official release tags; policy sanitize assertions, CSS sanitizer assertions, HTML entity decoding and banned-codeunit normalization tests. Exact DOMPurify latest survivor default sanitize pairs are skipped.",
        "contract_count": len(all_contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_op": dict(sorted(by_op.items())),
        "contracts": all_contracts,
    }
    (OUT_DIR / "all_releases_excluding_dompurify.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(all_contracts, OUT_DIR / "all_releases_excluding_dompurify.rpl")
    lines = ["# OWASP Java HTML Sanitizer Release Contract Counts", "", "| Version | Tag | Contracts observed | New unique contracts |", "| --- | --- | ---: | ---: |"]
    for row in release_counts:
        lines.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit = [
        "# OWASP Java HTML Sanitizer Extraction Audit",
        "",
        f"Latest Maven version: `{latest}`",
        f"Maven versions: {len(versions)}",
        f"Git tags available: {len(tags)}",
        f"Tagged versions inspected: {summary['versions_with_matching_tags_inspected']}",
        f"Extracted contracts: {len(all_contracts)}",
        f"Exact DOMPurify survivor pairs avoided: {len(avoid)}",
        "",
        "Basis: official release tags; policy sanitize assertions, CSS sanitizer assertions, HTML entity decoding, and banned-codeunit normalization tests. Exact DOMPurify latest-surviving default sanitize input/output pairs were removed.",
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
    print(json.dumps({k: summary[k] for k in ["latest_version", "maven_versions", "versions_with_matching_tags_inspected", "contract_count", "by_capability", "by_op"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
