#!/usr/bin/env python3
"""Evaluate a generated solsanitize implementation against HTML Sanitizer common contracts."""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from lxml import html as lxml_html


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "html_sanitizer" / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "generated"


def canon_html(text: Any) -> str | None:
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
            pieces.append(f"<{tag}{attrs}>{norm_node(child)}</{tag}>")
            if child.tail:
                pieces.append(child.tail)
        return "".join(pieces)

    return re.sub(r">\s+<", "><", norm_node(root)).strip()


def html_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(html_matches(actual, item) for item in expected)
    if actual == expected:
        return True
    return canon_html(actual) == canon_html(expected)


def attr_escape(value: Any) -> str:
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def first_attr(markup: str, attr: str) -> str | None:
    try:
        root = lxml_html.fragment_fromstring(markup or "", create_parent="sb-root")
    except Exception:
        return None
    el = root.find(".//span")
    if el is None:
        return None
    value = el.attrib.get(attr)
    return value if value else None


def text_content(markup: str) -> str:
    try:
        root = lxml_html.fragment_fromstring(markup or "", create_parent="sb-root")
        return root.text_content()
    except Exception:
        return html.unescape(markup or "")


def call_sanitize(api: Any, dirty: Any, *, config: Any = None, policy: Any = None, base_url: Any = None) -> str:
    fn = getattr(api, "sanitize", None) or getattr(api, "clean", None)
    if fn is None:
        raise AttributeError("module does not expose sanitize or clean")
    attempts = [
        lambda: fn(dirty, config=config, policy=policy, base_url=base_url),
        lambda: fn(dirty, config=config, policy=policy, base_uri=base_url),
        lambda: fn(dirty, config=config, policy=policy),
        lambda: fn(dirty, policy=policy, base_url=base_url),
        lambda: fn(dirty, policy=policy),
        lambda: fn(dirty, config=config),
        lambda: fn(dirty),
    ]
    last: Exception | None = None
    for attempt in attempts:
        try:
            value = attempt()
            return "" if value is None else str(value)
        except TypeError as exc:
            last = exc
    if last:
        raise last
    raise RuntimeError("sanitize call failed")


def call_is_valid(api: Any, dirty: Any, *, config: Any = None, policy: Any = None, base_url: Any = None) -> bool:
    fn = getattr(api, "is_valid", None) or getattr(api, "valid", None)
    if fn is not None:
        attempts = [
            lambda: fn(dirty, config=config, policy=policy, base_url=base_url),
            lambda: fn(dirty, config=config, policy=policy, base_uri=base_url),
            lambda: fn(dirty, config=config, policy=policy),
            lambda: fn(dirty, policy=policy, base_url=base_url),
            lambda: fn(dirty, policy=policy),
            lambda: fn(dirty, config=config),
            lambda: fn(dirty),
        ]
        last: Exception | None = None
        for attempt in attempts:
            try:
                return bool(attempt())
            except TypeError as exc:
                last = exc
        if last:
            raise last
    clean = call_sanitize(api, dirty, config=config, policy=policy, base_url=base_url)
    return clean == ("" if dirty is None else str(dirty))


def policy_for(contract: dict[str, Any]) -> tuple[Any, Any, Any]:
    op = contract["op"]
    params = contract.get("params", {})
    if op == "sanitize":
        return params.get("config"), None, None
    if op in {"jsoup_clean", "jsoup_clean_document", "jsoup_is_valid", "jsoup_is_valid_document"}:
        return None, {
            "kind": "jsoup_safelist",
            "safelist": params.get("safelist"),
            "output_settings": params.get("output_settings"),
            "strip_newlines": params.get("strip_newlines"),
            "parse_mode": params.get("parse_mode"),
        }, params.get("base_uri")
    if op == "policy_sanitize":
        return None, {"kind": "owasp_policy", "policy": params.get("policy")}, None
    if op == "html_sanitizer_test_sanitize":
        return None, {"kind": "owasp_html_sanitizer_test"}, None
    return None, None, None


def evaluate_one(api: Any, contract: dict[str, Any], mutant: bool = False) -> dict[str, Any]:
    op = contract["op"]
    params = contract.get("params", {})
    expected = contract["mutant" if mutant else "expected"]
    config, policy, base_url = policy_for(contract)
    if op == "css_sanitize":
        dirty = f'<span style="{attr_escape(params.get("css"))}">x</span>'
        clean = call_sanitize(api, dirty, config={"ALLOWED_TAGS": ["span"], "ALLOWED_ATTR": ["style"]})
        actual = {"clean": first_attr(clean, "style")}
        return {"passed": actual["clean"] == expected.get("clean"), "actual": actual}
    if op in {"jsoup_is_valid", "jsoup_is_valid_document"}:
        actual = {"valid": call_is_valid(api, params.get("html"), config=config, policy=policy, base_url=base_url)}
        return {"passed": actual["valid"] == expected.get("valid"), "actual": actual}
    if op == "sanitize":
        dirty = params.get("dirty")
    elif op in {"jsoup_clean", "jsoup_clean_document"}:
        dirty = params.get("html")
    elif op == "policy_sanitize":
        dirty = params.get("dirty")
    elif op == "html_sanitizer_test_sanitize":
        dirty = params.get("html") or ""
    else:
        return {"passed": False, "actual": {"error": f"unsupported generated op {op}"}}
    clean = call_sanitize(api, dirty, config=config, policy=policy, base_url=base_url)
    if op in {"jsoup_clean", "jsoup_clean_document"} and params.get("strip_newlines"):
        clean = re.sub(r"\r?\n\s*", "", clean)
    actual = {"clean": clean}
    return {"passed": html_matches(clean, expected.get("clean")), "actual": actual}


def source_hashes(path: Path) -> list[str]:
    rows = []
    for file in sorted(path.rglob("*")):
        ignored_parts = {".eval-venv", "__pycache__", "build", ".pytest_cache"}
        if file.is_file() and not ignored_parts.intersection(file.parts) and ".egg-info" not in str(file):
            digest = hashlib.sha256(file.read_bytes()).hexdigest()
            rows.append(f"{digest}  {file.relative_to(path)}")
    return rows


def install_if_needed(impl: Path) -> None:
    req = impl / "requirements.txt"
    pyproject = impl / "pyproject.toml"
    setup_py = impl / "setup.py"
    if req.exists():
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req)])
    if pyproject.exists() or setup_py.exists():
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", str(impl)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    impl = Path(args.implementation).resolve()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    src_dir = impl / "src"
    if src_dir.exists():
        sys.path.insert(0, str(src_dir))
    sys.path.insert(0, str(impl))
    install_if_needed(impl)
    api = importlib.import_module("solsanitize")
    source = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    contracts = source["final_common_contracts"]
    results = []
    survivors = []
    for contract in contracts:
        row = {"name": contract["name"], "origin": contract.get("origin"), "capability": contract.get("capability"), "op": contract["op"]}
        try:
            replay = evaluate_one(api, contract, mutant=False)
            mutant = evaluate_one(api, contract, mutant=True) if replay["passed"] else {"passed": False, "actual": {}}
            row["replay_passed"] = replay["passed"]
            row["mutant_rejected"] = replay["passed"] and not mutant["passed"]
            row["actual"] = replay["actual"]
            if row["replay_passed"] and row["mutant_rejected"]:
                survivors.append(contract)
        except Exception as exc:
            row["replay_passed"] = False
            row["mutant_rejected"] = False
            row["actual"] = {"error": exc.__class__.__name__, "message": str(exc)}
        results.append(row)

    replay_passed = sum(1 for row in results if row["replay_passed"])
    mutant_killed = sum(1 for row in results if row["replay_passed"] and row["mutant_rejected"])
    by_cap = Counter(row["capability"] for row in results if row["replay_passed"] and row["mutant_rejected"])
    by_op = Counter(row["op"] for row in results if row["replay_passed"] and row["mutant_rejected"])
    failed_by_cap = Counter(row["capability"] for row in results if not row["replay_passed"])
    failed_by_op = Counter(row["op"] for row in results if not row["replay_passed"])
    summary = {
        "domain": "HTML Sanitizer",
        "implementation": str(impl),
        "label": args.label,
        "input_contracts": len(contracts),
        "replay_passed": replay_passed,
        "replay_failed": len(contracts) - replay_passed,
        "mutant_killed": mutant_killed,
        "survivors": len(survivors),
        "by_capability": dict(sorted(by_cap.items())),
        "by_op": dict(sorted(by_op.items())),
        "failed_by_capability": dict(sorted(failed_by_cap.items())),
        "failed_by_op": dict(sorted(failed_by_op.items())),
        "results": results,
    }
    out_json = OUT_DIR / f"{args.label}_survival_from_common_90.json"
    out_md = OUT_DIR / f"{args.label}_survival_from_common_90.md"
    out_hash = OUT_DIR / f"{args.label}_source_hashes.sha256"
    out_json.write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    out_hash.write_text("\n".join(source_hashes(impl)) + "\n", encoding="utf-8")
    lines = [
        f"# {args.label} HTML Sanitizer Common Evaluation",
        "",
        f"Implementation: `{impl}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['replay_passed']}",
        f"Replay failed: {summary['replay_failed']}",
        f"Mutants killed after replay pass: {summary['mutant_killed']}",
        f"Survivors: {summary['survivors']}",
        "",
        "## Survivors by Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Survivors by Operation", "", "| Operation | Survivors |", "| --- | ---: |"])
    for op, count in sorted(by_op.items()):
        lines.append(f"| `{op}` | {count} |")
    lines.extend(["", "## Replay Failures by Capability", "", "| Capability | Failures |", "| --- | ---: |"])
    for cap, count in sorted(failed_by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Replay Failures by Operation", "", "| Operation | Failures |", "| --- | ---: |"])
    for op, count in sorted(failed_by_op.items()):
        lines.append(f"| `{op}` | {count} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    printable = {k: summary[k] for k in ["input_contracts", "replay_passed", "replay_failed", "mutant_killed", "survivors", "by_capability", "by_op"]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
