#!/usr/bin/env python3
"""Cross-replay HTML sanitizer survivor corpora across mature implementations."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from lxml import html as lxml_html


ROOT = Path(__file__).resolve().parents[2]
PYTHON = Path(sys.executable)
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "common"
NODE_DIR = ROOT / "tools" / "replay" / "html_sanitizer_node_adapter"
JSOUP_RUNNER = ROOT / "tools" / "replay" / "jsoup_latest_runner"
OWASP_RUNNER = ROOT / "tools" / "replay" / "java_html_sanitizer_latest_runner"
BLEACH_TARGET = ROOT / ".cache" / "runtime" / "html-sanitizer-python"

CORPORA = {
    "dompurify": ROOT / "contracts" / "html_sanitizer" / "dompurify" / "latest_replay_mutant_verified.json",
    "owasp": ROOT / "contracts" / "html_sanitizer" / "java-html-sanitizer" / "latest_replay_mutant_verified.json",
    "jsoup": ROOT / "contracts" / "html_sanitizer" / "jsoup" / "latest_replay_mutant_verified.json",
}


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, env=env, text=True, stderr=subprocess.STDOUT)


def ensure_node_deps() -> None:
    if not (NODE_DIR / "node_modules").exists():
        run(["npm", "install"], cwd=NODE_DIR)


def ensure_bleach() -> dict[str, str]:
    BLEACH_TARGET.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BLEACH_TARGET) + os.pathsep + env.get("PYTHONPATH", "")
    probe = subprocess.run(
        [str(PYTHON), "-c", "import bleach, tinycss2; print(bleach.__version__)"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if probe.returncode != 0:
        run([str(PYTHON), "-m", "pip", "install", "--upgrade", "--target", str(BLEACH_TARGET), "bleach[css]==6.4.0"])
    return env


def load_survivors(name: str) -> list[dict[str, Any]]:
    data = json.loads(CORPORA[name].read_text(encoding="utf-8"))
    out = []
    for row in data["survivors"]:
        c = json.loads(json.dumps(row))
        c["origin"] = name
        out.append(c)
    return out


def canon_html(text: str | None) -> str | None:
    if text is None:
        return None
    text = str(text)
    if text == "":
        return ""
    try:
        root = lxml_html.fragment_fromstring(text, create_parent="sb-root")
    except Exception:
        return re.sub(r"\s+", " ", text).strip()

    def norm_node(node: Any) -> str:
        pieces: list[str] = []
        if node.text:
            pieces.append(node.text)
        for child in node:
            tag = str(child.tag).lower()
            attrs = "".join(
                f" {str(k).lower()}={json.dumps(str(v), ensure_ascii=True)}"
                for k, v in sorted(child.attrib.items(), key=lambda item: str(item[0]).lower())
            )
            child_body = norm_node(child)
            pieces.append(f"<{tag}{attrs}>{child_body}</{tag}>")
            if child.tail:
                pieces.append(child.tail)
        return "".join(pieces)

    return re.sub(r">\s+<", "><", norm_node(root)).strip()


def html_matches(actual: str | None, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(html_matches(actual, item) for item in expected)
    if actual == expected:
        return True
    return canon_html(actual) == canon_html(expected)


def scalar_matches(actual: Any, expected: Any) -> bool:
    return actual == expected


def expected_field(contract: dict[str, Any]) -> str | None:
    expected = contract.get("expected", {})
    if "clean" in expected:
        return "clean"
    if "valid" in expected:
        return "valid"
    if "contains" in expected:
        return "contains"
    return None


def match_actual(contract: dict[str, Any], actual: dict[str, Any], mutant: bool = False) -> tuple[bool, str | None]:
    if actual.get("unsupported"):
        return False, actual.get("reason", "unsupported")
    if actual.get("error"):
        return False, f"{actual.get('error')}: {actual.get('message', '')}".strip()
    source = contract.get("mutant" if mutant else "expected", {})
    field = expected_field({"expected": source})
    if field is None:
        return False, "no comparable expected field"
    if field == "clean":
        return html_matches(actual.get("clean"), source.get("clean")), None
    return scalar_matches(actual.get(field), source.get(field)), None


def jsoup_tags(base: str) -> list[str]:
    return {
        "none": [],
        "empty": [],
        "simpleText": ["b", "em", "i", "strong", "u"],
        "basic": ["a", "b", "blockquote", "br", "cite", "code", "dd", "dl", "dt", "em", "i", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong", "sub", "sup", "u", "ul"],
        "basicWithImages": ["a", "b", "blockquote", "br", "cite", "code", "dd", "dl", "dt", "em", "i", "img", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong", "sub", "sup", "u", "ul"],
        "relaxed": ["a", "b", "blockquote", "br", "caption", "cite", "code", "col", "colgroup", "dd", "div", "dl", "dt", "em", "h1", "h2", "h3", "h4", "h5", "h6", "i", "img", "li", "ol", "p", "pre", "q", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul"],
    }.get(base, [])


def jsoup_attrs(base: str) -> dict[str, list[str]]:
    attrs: dict[str, list[str]] = {}

    def add(tag: str, values: list[str]) -> None:
        attrs[tag] = sorted(set(attrs.get(tag, []) + values))

    if base in {"basic", "basicWithImages", "relaxed"}:
        add("a", ["href"])
        add("blockquote", ["cite"])
        add("q", ["cite"])
    if base in {"basicWithImages", "relaxed"}:
        add("img", ["src", "alt", "height", "width", "title"])
    if base == "relaxed":
        add("ol", ["start", "type"])
        add("ul", ["type"])
        add("li", ["value"])
        add("td", ["abbr", "axis", "colspan", "rowspan", "width"])
        add("th", ["abbr", "axis", "colspan", "rowspan", "scope", "width"])
        add("col", ["span", "width"])
        add("colgroup", ["span", "width"])
    return attrs


def safelist_to_owasp_policy(safelist: dict[str, Any]) -> dict[str, Any]:
    tags = set(jsoup_tags(safelist.get("base", "empty")))
    attrs = jsoup_attrs(safelist.get("base", "empty"))
    steps: list[dict[str, Any]] = []
    for step in safelist.get("steps", []):
        args = step.get("args", [])
        if step["method"] == "addTags":
            tags.update(args)
        elif step["method"] == "removeTags":
            tags.difference_update(args)
        elif step["method"] == "addAttributes" and len(args) >= 2:
            tag = args[0]
            attrs[tag] = sorted(set(attrs.get(tag, []) + args[1:]))
        elif step["method"] == "removeAttributes" and len(args) >= 2:
            tag = args[0]
            remove = set(args[1:])
            attrs[tag] = [a for a in attrs.get(tag, []) if a not in remove]
    steps.append({"method": "allowElements", "args": sorted(tags)})
    for tag, names in sorted(attrs.items()):
        if names:
            if tag == ":all":
                steps.append({"method": "allowAttributes", "args": names, "target": "globally"})
            else:
                steps.append({"method": "allowAttributes", "args": names, "target": "onElements", "targets": [tag]})
    steps.append({"method": "allowStandardUrlProtocols", "args": []})
    if safelist.get("base") in {"basic", "basicWithImages"}:
        steps.append({"method": "requireRelNofollowOnLinks", "args": []})
    return {"type": "builder", "steps": steps}


def owasp_policy_to_jsoup_safelist(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    if not policy:
        return None
    text = json.dumps(policy)
    if "IMAGES" in text and "TABLES" in text:
        return {"base": "relaxed", "steps": []}
    if "IMAGES" in text:
        return {"base": "basicWithImages", "steps": []}
    if "FORMATTING" in text or "BLOCKS" in text or "LINKS" in text:
        return {"base": "basic", "steps": []}
    if policy.get("type") == "builder":
        steps = []
        tags: list[str] = []
        for step in policy.get("steps", []):
            if step.get("method") == "allowElements":
                tags += step.get("args", [])
            if step.get("method") == "allowAttributes":
                target = ":all" if step.get("target") == "globally" else (step.get("targets") or [""])[0]
                if target:
                    steps.append({"method": "addAttributes", "args": [target] + step.get("args", [])})
        if tags:
            return {"base": "empty", "steps": [{"method": "addTags", "args": sorted(set(tags))}] + steps}
    return None


def dompurify_config_to_jsoup_safelist(config: Any) -> dict[str, Any]:
    if isinstance(config, dict) and isinstance(config.get("ALLOWED_TAGS"), list):
        steps = [{"method": "addTags", "args": [str(x) for x in config["ALLOWED_TAGS"]]}]
        attrs = config.get("ALLOWED_ATTR") or config.get("ADD_ATTR")
        if isinstance(attrs, list):
            steps.append({"method": "addAttributes", "args": [":all"] + [str(x) for x in attrs]})
        return {"base": "empty", "steps": steps}
    return {"base": "relaxed", "steps": []}


def convert_for_jsoup(contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract["op"]
    expected = contract["expected"]
    if op.startswith("jsoup_"):
        return contract
    if op == "sanitize":
        return {
            **contract,
            "op": "jsoup_clean",
            "params": {
                "html": contract["params"].get("dirty"),
                "base_uri": None,
                "safelist": dompurify_config_to_jsoup_safelist(contract["params"].get("config")),
                "output_settings": None,
                "strip_newlines": False,
            },
            "expected": {"clean": expected.get("clean", "")},
        }
    if op == "policy_sanitize":
        safelist = owasp_policy_to_jsoup_safelist(contract["params"].get("policy"))
        if not safelist:
            return None
        return {
            **contract,
            "op": "jsoup_clean",
            "params": {"html": contract["params"].get("dirty"), "base_uri": None, "safelist": safelist, "output_settings": None, "strip_newlines": False},
            "expected": {"clean": expected.get("clean", "")},
        }
    if op == "html_sanitizer_test_sanitize":
        return {
            **contract,
            "op": "jsoup_clean",
            "params": {"html": contract["params"].get("html") or "", "base_uri": None, "safelist": {"base": "relaxed", "steps": [{"method": "addTags", "args": ["iframe", "input", "noframes", "noembed"]}, {"method": "addAttributes", "args": [":all", "id", "class", "title", "dir", "checked", "target", "type"]}]}, "output_settings": None, "strip_newlines": False},
            "expected": {"clean": expected.get("clean", "")},
        }
    if op == "antisamy_contains":
        return {
            **contract,
            "op": "jsoup_clean",
            "params": {"html": contract["params"].get("html"), "base_uri": None, "safelist": {"base": "relaxed", "steps": [{"method": "addTags", "args": ["font", "input"]}, {"method": "addAttributes", "args": [":all", "class", "id", "title"]}, {"method": "addAttributes", "args": ["font", "color"]}, {"method": "addAttributes", "args": ["input", "checked", "type"]}]}, "output_settings": None, "strip_newlines": False},
            "expected": {"clean": ""},
        }
    if op == "css_sanitize":
        return {**contract, "op": "css_sanitize_via_html"}
    if op == "decode_html":
        return {**contract, "op": "decode_html_via_html"}
    if op == "strip_banned":
        return {**contract, "op": "strip_banned_via_html"}
    return None


def convert_for_owasp(contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract["op"]
    if op in {"policy_sanitize", "html_sanitizer_test_sanitize", "antisamy_contains", "css_sanitize", "decode_html", "strip_banned"}:
        return contract
    if op == "sanitize":
        return {
            **contract,
            "op": "html_sanitizer_test_sanitize",
            "params": {"html": contract["params"].get("dirty") or ""},
            "expected": {"clean": contract["expected"].get("clean", "")},
        }
    if op in {"jsoup_clean", "jsoup_clean_document"}:
        return {
            **contract,
            "op": "policy_sanitize",
            "params": {"dirty": contract["params"].get("html") or "", "policy": safelist_to_owasp_policy(contract["params"].get("safelist") or {"base": "empty", "steps": []})},
            "expected": {"clean": contract["expected"].get("clean", "")},
        }
    if op in {"jsoup_is_valid", "jsoup_is_valid_document"}:
        return {
            **contract,
            "op": "policy_sanitize",
            "params": {"dirty": contract["params"].get("html") or "", "policy": safelist_to_owasp_policy(contract["params"].get("safelist") or {"base": "empty", "steps": []})},
            "expected": {"clean": ""},
        }
    return None


def run_node_target(target: str, contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    ensure_node_deps()
    path = OUT_DIR / f"_tmp_{target}.json"
    path.write_text(json.dumps({"contracts": contracts}, ensure_ascii=True), encoding="utf-8")
    out = run(["node", str(NODE_DIR / "replay.mjs"), target, str(path)])
    data = json.loads(out)
    return {row["name"]: row["actual"] for row in data["results"]}


def run_java_target(target: str, contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if target == "jsoup":
        runner = JSOUP_RUNNER
        cls = "shapingbench.JsoupSanitizerRunner"
        converted = [(c, convert_for_jsoup(c)) for c in contracts]
    elif target == "owasp":
        runner = OWASP_RUNNER
        cls = "org.owasp.html.ShapingBenchRunner"
        converted = [(c, convert_for_owasp(c)) for c in contracts]
    else:
        raise ValueError(target)
    native = []
    actuals: dict[str, dict[str, Any]] = {}
    for original, conv in converted:
        if conv is None:
            actuals[original["name"]] = {"unsupported": True, "reason": f"no {target} mapping for {original['op']}"}
        else:
            native.append(conv)
    if native:
        path = OUT_DIR / f"_tmp_{target}.json"
        path.write_text(json.dumps({"contracts": native}, ensure_ascii=True), encoding="utf-8")
        out = run([
            "mvn", "-q", "-DskipTests", "compile", "exec:java",
            f"-Dexec.mainClass={cls}", f"-Dexec.args={path}",
        ], cwd=runner)
        match = re.search(r"(\{\"results\":.*\})\s*$", out, re.S)
        if not match:
            raise RuntimeError(out)
        for row in json.loads(match.group(1))["results"]:
            actuals[row["name"]] = row.get("actual") or {"error": row.get("error", "unknown")}
            if row.get("error"):
                actuals[row["name"]]["error"] = row["error"]
    return actuals


def bleach_policy(contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract["op"]
    tags: list[str] | None = None
    attrs: dict[str, list[str]] = {}
    if op.startswith("jsoup_"):
        safelist = contract["params"].get("safelist") or {"base": "empty", "steps": []}
        tags = jsoup_tags(safelist.get("base", "empty"))
        attrs = jsoup_attrs(safelist.get("base", "empty"))
        for step in safelist.get("steps", []):
            args = step.get("args", [])
            if step["method"] == "addTags":
                tags += args
            if step["method"] == "removeTags":
                tags = [t for t in tags if t not in set(args)]
            if step["method"] == "addAttributes" and len(args) >= 2:
                attrs[args[0] if args[0] != ":all" else "*"] = sorted(set(attrs.get(args[0], []) + args[1:]))
    elif op == "policy_sanitize":
        p = owasp_policy_to_jsoup_safelist(contract["params"].get("policy"))
        if p:
            tags = jsoup_tags(p["base"])
            attrs = jsoup_attrs(p["base"])
    elif op in {"sanitize", "html_sanitizer_test_sanitize", "antisamy_contains"}:
        tags = None
        attrs = {}
    else:
        return None
    return {"tags": sorted(set(tags)) if tags is not None else None, "attributes": attrs}


def run_bleach_target(contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    env = ensure_bleach()
    script = OUT_DIR / "_tmp_bleach_eval.py"
    script.write_text(
        """
import json, sys, bleach
payload=json.load(open(sys.argv[1]))
out=[]
for c in payload['contracts']:
    try:
        pol=c.get('_bleach_policy')
        op=c['op']
        params=c.get('params',{})
        if op=='css_sanitize':
            from bleach.css_sanitizer import CSSSanitizer
            import html.parser
            dirty='<span style="'+str(params.get('css') or '').replace('&','&amp;').replace('"','&quot;').replace('<','&lt;').replace('>','&gt;')+'">x</span>'
            clean=bleach.clean(dirty, tags=['span'], attributes={'span':['style']}, protocols=['http','https','mailto','ftp','cid','data'], strip=True, strip_comments=True, css_sanitizer=CSSSanitizer(allowed_css_properties=frozenset(['background','background-color','background-image','color','display','font','font-family','font-size','font-style','font-weight','height','list-style','margin','padding','text-align','text-decoration','width'])))
            class P(html.parser.HTMLParser):
                value=None
                def handle_starttag(self, tag, attrs):
                    if tag=='span':
                        for k,v in attrs:
                            if k=='style': self.value=v or None
            p=P(); p.feed(clean)
            out.append({'name':c['name'],'actual':{'clean':p.value}})
            continue
        if op=='decode_html':
            import html.parser
            if params.get('in_attribute'):
                dirty='<span title="'+str(params.get('html') or '').replace('&','&amp;').replace('"','&quot;').replace('<','&lt;').replace('>','&gt;')+'">x</span>'
                clean=bleach.clean(dirty, tags=['span'], attributes={'span':['title']}, protocols=['http','https','mailto','ftp','cid','data'], strip=True, strip_comments=True)
                class P(html.parser.HTMLParser):
                    value=''
                    def handle_starttag(self, tag, attrs):
                        if tag=='span':
                            for k,v in attrs:
                                if k=='title': self.value=v or ''
                p=P(); p.feed(clean)
                out.append({'name':c['name'],'actual':{'text':p.value}})
            else:
                clean=bleach.clean(str(params.get('html') or ''), tags=[], attributes={}, protocols=['http','https','mailto','ftp','cid','data'], strip=True, strip_comments=True)
                out.append({'name':c['name'],'actual':{'text':html.unescape(clean)}})
            continue
        if op=='strip_banned':
            clean=bleach.clean(str(params.get('text') or ''), tags=[], attributes={}, protocols=['http','https','mailto','ftp','cid','data'], strip=True, strip_comments=True)
            out.append({'name':c['name'],'actual':{'text':html.unescape(clean)}})
            continue
        if pol is None:
            out.append({'name':c['name'],'actual':{'unsupported':True,'reason':'no bleach mapping for '+op}})
            continue
        tags=pol.get('tags')
        attrs=pol.get('attributes') or {}
        dirty=(params.get('dirty') or params.get('html') or '')
        clean=bleach.clean(dirty, tags=(tags if tags is not None else bleach.sanitizer.ALLOWED_TAGS), attributes=attrs or bleach.sanitizer.ALLOWED_ATTRIBUTES, protocols=['http','https','mailto','ftp','cid','data'], strip=True, strip_comments=True)
        if op=='antisamy_contains':
            out.append({'name':c['name'],'actual':{'contains': c['params']['needle'] in clean, 'clean':clean}})
        elif op.startswith('jsoup_is_valid'):
            out.append({'name':c['name'],'actual':{'valid': clean == dirty, 'clean':clean}})
        else:
            out.append({'name':c['name'],'actual':{'clean':clean}})
    except Exception as e:
        out.append({'name':c['name'],'actual':{'error':e.__class__.__name__,'message':str(e)}})
print(json.dumps({'results':out}))
""",
        encoding="utf-8",
    )
    prepared = []
    actuals: dict[str, dict[str, Any]] = {}
    for c in contracts:
        pol = bleach_policy(c)
        cc = json.loads(json.dumps(c))
        cc["_bleach_policy"] = pol
        prepared.append(cc)
    path = OUT_DIR / "_tmp_bleach.json"
    path.write_text(json.dumps({"contracts": prepared}, ensure_ascii=True), encoding="utf-8")
    out = run([str(PYTHON), str(script), str(path)], env=env)
    match = re.search(r"(\{\"results\":.*\})\s*$", out, re.S)
    if not match:
        raise RuntimeError(out)
    for row in json.loads(match.group(1))["results"]:
        actuals[row["name"]] = row["actual"]
    return actuals


def run_target(target: str, contracts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if target in {"dompurify", "sanitize-html"}:
        return run_node_target(target, contracts)
    if target in {"jsoup", "owasp"}:
        return run_java_target(target, contracts)
    if target == "bleach":
        return run_bleach_target(contracts)
    raise ValueError(target)


def evaluate_on_targets(origin: str, contracts: list[dict[str, Any]], targets: list[str]) -> dict[str, Any]:
    matrix: dict[str, dict[str, Any]] = {}
    target_actuals = {target: run_target(target, contracts) for target in targets}
    passed = []
    failed = []
    for c in contracts:
        row = {"contract": c, "targets": {}}
        ok_all = True
        for target in targets:
            actual = target_actuals[target].get(c["name"], {"error": "missing result"})
            replay, reason = match_actual(c, actual, mutant=False)
            mutant_passed, _ = match_actual(c, actual, mutant=True)
            target_ok = replay and not mutant_passed
            row["targets"][target] = {
                "replay_passed": replay,
                "mutant_rejected": replay and not mutant_passed,
                "actual": actual,
                "reason": reason,
            }
            ok_all = ok_all and target_ok
        matrix[c["name"]] = row
        if ok_all:
            passed.append(c)
        else:
            failed.append(row)
    return {"origin": origin, "targets": targets, "passed": passed, "failed": failed, "matrix": matrix}


def hidden_filter(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    targets = ["bleach", "sanitize-html"]
    target_actuals = {target: run_target(target, candidates) for target in targets}
    survivors = []
    failed = []
    for c in candidates:
        ok_all = True
        row = {"contract": c, "targets": {}}
        for target in targets:
            actual = target_actuals[target].get(c["name"], {"error": "missing result"})
            replay, reason = match_actual(c, actual, mutant=False)
            mutant_passed, _ = match_actual(c, actual, mutant=True)
            ok = replay and not mutant_passed
            row["targets"][target] = {
                "replay_passed": replay,
                "mutant_rejected": replay and not mutant_passed,
                "actual": actual,
                "reason": reason,
            }
            ok_all = ok_all and ok
        if ok_all:
            survivors.append(c)
        else:
            failed.append(row)
    return {"targets": targets, "survivors": survivors, "failed": failed}


def execution_issue_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    unsupported = 0
    errors = 0
    for row in rows:
        for result in row["targets"].values():
            actual = result.get("actual", {})
            unsupported += 1 if actual.get("unsupported") else 0
            errors += 1 if actual.get("error") else 0
    return {"unsupported": unsupported, "errors": errors}


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'])} {{")
        lines.append(f"  origin {json.dumps(row.get('origin'))}")
        lines.append(f"  version {json.dumps(row.get('version'))}")
        lines.append(f"  capability {json.dumps(row.get('capability'))}")
        lines.append(f"  op {row.get('op')}")
        lines.append(f"  params {json.dumps(row.get('params'), ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row.get('expected'), ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    corpora = {name: load_survivors(name) for name in CORPORA}
    rank = {
        "dompurify": ["owasp", "jsoup"],
        "owasp": ["dompurify", "jsoup"],
        "jsoup": ["dompurify", "owasp"],
    }
    cross = {origin: evaluate_on_targets(origin, corpora[origin], targets) for origin, targets in rank.items()}
    candidates = cross["dompurify"]["passed"] + cross["owasp"]["passed"] + cross["jsoup"]["passed"]
    seen = set()
    unique_candidates = []
    for c in candidates:
        key = (c["origin"], c["name"])
        if key not in seen:
            seen.add(key)
            unique_candidates.append(c)
    hidden = hidden_filter(unique_candidates)
    by_origin = Counter(c["origin"] for c in hidden["survivors"])
    by_capability = Counter(c["capability"] for c in hidden["survivors"])
    cross_execution_issues = {
        origin: execution_issue_counts(cross[origin]["failed"])
        for origin in ["dompurify", "owasp", "jsoup"]
    }
    hidden_execution_issues = execution_issue_counts(hidden["failed"])
    summary = {
        "domain": "HTML Sanitizer",
        "rank_1": "cure53/DOMPurify 3.4.14",
        "rank_2": "OWASP/java-html-sanitizer 20260313.1",
        "rank_3": "jsoup/jsoup 1.23.2",
        "rank_4_hidden": "mozilla/bleach 6.4.0",
        "rank_5_hidden": "apostrophecms/sanitize-html 2.17.7",
        "input_survivors": {name: len(rows) for name, rows in corpora.items()},
        "rank1_on_rank2_rank3": len(cross["dompurify"]["passed"]),
        "rank2_on_rank1_rank3": len(cross["owasp"]["passed"]),
        "rank3_on_rank1_rank2": len(cross["jsoup"]["passed"]),
        "unique_common_candidates_before_hidden": len(unique_candidates),
        "failed_on_rank4_bleach": sum(1 for row in hidden["failed"] if not row["targets"]["bleach"]["replay_passed"]),
        "failed_on_rank5_sanitize_html": sum(1 for row in hidden["failed"] if not row["targets"]["sanitize-html"]["replay_passed"]),
        "final_common": len(hidden["survivors"]),
        "final_by_origin": dict(sorted(by_origin.items())),
        "final_by_capability": dict(sorted(by_capability.items())),
        "cross_execution_issues": cross_execution_issues,
        "hidden_execution_issues": hidden_execution_issues,
        "cross": cross,
        "hidden": hidden,
        "final_common_contracts": hidden["survivors"],
    }
    (OUT_DIR / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(hidden["survivors"], OUT_DIR / "final_common.rpl")
    lines = [
        "# HTML Sanitizer Cross-Replay Common",
        "",
        "| Stage | Count |",
        "| --- | ---: |",
        f"| Rank 1 contracts replayed successfully on Rank 2 and Rank 3 | {summary['rank1_on_rank2_rank3']} |",
        f"| Rank 2 contracts replayed successfully on Rank 1 and Rank 3 | {summary['rank2_on_rank1_rank3']} |",
        f"| Rank 3 contracts replayed successfully on Rank 1 and Rank 2 | {summary['rank3_on_rank1_rank2']} |",
        f"| Unique common candidates before hidden filtering | {summary['unique_common_candidates_before_hidden']} |",
        f"| Failed on Rank 4 bleach | {summary['failed_on_rank4_bleach']} |",
        f"| Failed on Rank 5 sanitize-html | {summary['failed_on_rank5_sanitize_html']} |",
        f"| Final common | {summary['final_common']} |",
        f"| Cross replay unsupported/error results | {sum(v['unsupported'] for v in cross_execution_issues.values()) + sum(v['errors'] for v in cross_execution_issues.values())} |",
        f"| Hidden filter unsupported/error results | {hidden_execution_issues['unsupported'] + hidden_execution_issues['errors']} |",
        "",
        "## Final by Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_capability.items()):
        lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "cross_replay_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    printable = {k: summary[k] for k in [
        "input_survivors",
        "rank1_on_rank2_rank3",
        "rank2_on_rank1_rank3",
        "rank3_on_rank1_rank2",
        "unique_common_candidates_before_hidden",
        "failed_on_rank4_bleach",
        "failed_on_rank5_sanitize_html",
        "final_common",
        "final_by_origin",
        "final_by_capability",
        "cross_execution_issues",
        "hidden_execution_issues",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
