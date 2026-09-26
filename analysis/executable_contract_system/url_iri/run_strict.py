#!/usr/bin/env python3
"""Execute every URL/IRI non-common contract against the final GPT snapshot."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OLD = ROOT / "tools/replay/replay_generated_url_iri_non_common.py"
SNAPSHOT = Path(os.environ.get(
    "SHAPINGBENCH_TARGET_SNAPSHOT",
    "submission",
))
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))
sys.path.insert(0, str(ROOT))
from analysis.executable_contract_system.capability import absence_established, invoke_candidates, public_surface
from analysis.executable_contract_system.import_target import add_snapshot_import_roots


def load_old():
    spec = importlib.util.spec_from_file_location("strict_url_old", OLD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def candidates(origin: str, contract: dict[str, Any]) -> list[str]:
    op = str(contract.get("op", ""))
    params = contract.get("params") or {}
    method = str(params.get("method", ""))
    part = str(params.get("part", ""))
    names = [op, f"URL.{op}"]
    if method:
        names += [method, f"URL.{method}"]
    if part:
        names += [f"set_{part}", f"URL.set_{part}"]
    semantic = {
        "percent_decode_string": ["percent_decode", "percent_decode_string", "decode_percent"],
        "percent_decode_bytes": ["percent_decode_bytes", "decode_percent_bytes"],
        "low_level_parse": ["parse_url_with_state", "URL.parse_with_state"],
        "object_tag": ["URL.object_tag", "object_tag"],
        "href_setter_searchparams": ["URL.search_params", "URL.searchParams"],
        "idna": ["domain_to_ascii", "domain_to_unicode", "idna"],
        "setpart": [f"URL.set_{part}", "URL.set_part"],
        "dup": ["URL.dup", "URL.copy", "URL.clone"],
    }
    names += semantic.get(op, [])
    return [name for name in names if name and not name.endswith(".")]


def factory(contract: dict[str, Any], solurl: Any):
    params = contract.get("params") or {}
    sample = params.get("input") or params.get("url") or "https://example.test/a?x=1#f"
    args = params.get("args") or []

    def make(name: str, value: Any):
        if name.startswith("URL."):
            instance = solurl.URL(sample)
            bound = getattr(instance, name.split(".", 1)[1])
            # resolve() was performed on the class; invoke the bound operation.
            if callable(bound):
                call_args = tuple(args) if args else ((params.get("value"),) if "value" in params else ())
                return (instance, *call_args), {}
        if "percent" in name:
            return (params.get("input", "%2E"),), {}
        if "idna" in name or "domain" in name:
            return (params.get("input") or params.get("domain") or "buecher.example",), {}
        return (sample, *tuple(args)), {}
    return make


def positive(solurl: Any) -> dict[str, Any]:
    try:
        value = solurl.parse_url("https://example.test/a?x=1")
        return {"passed": bool(getattr(value, "href", "").startswith("https://example.test/")), "href": getattr(value, "href", None)}
    except Exception as exc:
        return {"passed": False, "exception": type(exc).__name__, "message": str(exc)}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old = load_old()
    add_snapshot_import_roots(SNAPSHOT)
    solurl = old.load_solurl(SNAPSHOT)
    buckets = old.load_non_common()
    rows = [(origin, contract) for origin, values in buckets.items() for contract in values]
    assert len(rows) == 1927
    surface = public_surface(solurl)
    control = positive(solurl)
    output = []
    for index, (origin, contract) in enumerate(rows):
        actual = old.run_contract(solurl, origin, contract)
        expected = contract.get("expected") or {}
        if actual.get("surface_error") and contract.get("op") == "idna":
            params = contract.get("params") or {}
            function_name = "domain_to_unicode" if params.get("mode") == "unicode" else "domain_to_ascii"
            function = getattr(solurl, function_name, None)
            if callable(function):
                try:
                    actual = {"ok": True, "result": {"value": function(params.get("input", ""))}}
                except Exception as exc:
                    actual = {"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}}
        if actual.get("surface_error") and contract.get("op") == "dup":
            args = contract.get("args") or []
            copy_method = getattr(solurl.URL, "copy", None) or getattr(solurl.URL, "clone", None)
            if len(args) >= 4 and callable(copy_method):
                try:
                    original = solurl.URL(args[0])
                    duplicate = copy_method(original)
                    if args[2] == "zoneid":
                        hostname = str(getattr(duplicate, "hostname"))
                        prefix = hostname.split("%25", 1)[0]
                        duplicate.hostname = prefix + "%25" + str(args[3]) + "]"
                    actual = {
                        "init_code": 0, "init_error": "No error",
                        "dup_set_code": 0, "dup_set_error": "No error",
                        "original": {"code": 0, "value": str(getattr(original, "href"))},
                        "duplicate": {"code": 0, "value": str(getattr(duplicate, "href"))},
                    }
                except Exception as exc:
                    actual = {"surface_error": f"native duplicate mutation failed: {type(exc).__name__}: {exc}"}
        replay, misses = old.expected_matches(expected, actual)
        mutant_expected = old.mutate_first_scalar(expected)
        mutant_match, _ = old.expected_matches(mutant_expected, actual)
        if not actual.get("surface_error"):
            verdict = "PASS" if replay and not mutant_match else "FAIL_SEMANTIC_MISMATCH"
            evidence = {"kind": "behavior_replay", "actual": actual, "expected": expected, "misses": misses,
                        "mutant_rejected": not mutant_match, "positive_control": control}
        else:
            attempts = invoke_candidates(solurl, candidates(origin, contract), factory(contract, solurl))
            absent = absence_established(attempts, control)
            verdict = "FAIL_CAPABILITY_ABSENCE" if absent else "UNKNOWN_ADAPTER_GAP"
            evidence = {"kind": "contract_specific_native_probe", "required_operation": contract.get("op"),
                        "candidate_interfaces": candidates(origin, contract), "attempts": attempts,
                        "positive_control": control, "public_surface": surface, "legacy_surface_error": actual["surface_error"]}
        identity = f"{origin}\0{contract.get('name')}\0{index}"
        output.append({"scoring_id": "url-noncommon-" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                       "origin": origin, "source_name": contract.get("name"), "source_contract": contract,
                       "target": "solurl", "target_snapshot": str(SNAPSHOT), "verdict": verdict,
                       "evidence": evidence, "adapter_revision": "url-executable-contract-v1"})
    (OUTPUT_DIR / "strict_results.jsonl").write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in output))
    summary = {"total": len(output), "verdicts": dict(Counter(x["verdict"] for x in output)),
               "execution_kinds": dict(Counter(x["evidence"]["kind"] for x in output))}
    (OUTPUT_DIR / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
