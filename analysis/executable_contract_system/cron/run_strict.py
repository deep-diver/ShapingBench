#!/usr/bin/env python3
"""Execute cron non-common contracts, including previously discarded source ops."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OLD = ROOT / "tools/replay/replay_generated_cron_noncommon.py"
SNAPSHOT = Path(os.environ.get(
    "SHAPINGBENCH_TARGET_SNAPSHOT",
    "submission",
))
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))
sys.path.insert(0, str(ROOT))
from analysis.executable_contract_system.capability import absence_established, invoke_candidates, public_surface
from analysis.executable_contract_system.import_target import add_snapshot_import_roots


def load_old():
    spec = importlib.util.spec_from_file_location("strict_cron_old", OLD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def deep_contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and deep_contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(deep_contains(a, e) for a, e in zip(actual, expected))
    return actual == expected


def behavior_projection(solcron: Any, raw: dict[str, Any], old: Any) -> dict[str, Any] | None:
    op = raw["op"]
    p = raw.get("params") or {}
    try:
        if op == "get_parts":
            return {"parts": solcron.normalize(p["expression"]).split()}
        if op == "determine_type":
            try:
                solcron.parse(p["expression"])
                return {"type": "cron"}
            except Exception:
                return {"type": "unknown"}
        if op in {"parse_kind", "parse_cronish"}:
            try:
                normalized = solcron.normalize(p["expression"])
                return {"class": "Fugit::Cron", "cron": normalized}
            except Exception as exc:
                return {"error": type(exc).__name__, "message": str(exc)}
        if op == "describe" and hasattr(solcron, "describe"):
            expression = p.get("expression", "* * * * *")
            locale = p.get("locale")
            attempts = [
                ((expression,), {"locale": locale}),
                ((expression,), {"language": locale}),
                ((expression, locale), {}),
                ((expression,), {}),
            ]
            errors = []
            for args, kwargs in attempts:
                if locale is None:
                    kwargs = {key: value for key, value in kwargs.items() if value is not None}
                try:
                    return {"description": str(solcron.describe(*args, **kwargs))}
                except TypeError as exc:
                    errors.append(str(exc))
            return {"error": "TypeError", "message": "; ".join(errors)}
        if op in {"next_iterator", "prev_iterator"} and not p.get("with_rweek"):
            start = old.canonical_time(p["start"])
            fn = solcron.next_dates if op == "next_iterator" else solcron.prev_dates
            dates = fn(p["expression"], start, int(p.get("count", 1)))
            return {"dates": [old.canonical_time(value) + " UTC" for value in dates]}
        if op in {"random_invariant", "rweek_ref_sequence"}:
            # Parsing and attempting one occurrence is the behavior itself; a
            # syntax rejection is a complete semantic observation.
            try:
                expression = p["expression"]
                start = old.canonical_time(p.get("start", "2024-01-01T00:00:00Z"))
                dates = solcron.next_dates(expression, start, int(p.get("count", 1)))
                return {"value": True, "count": len(dates), "dates": dates}
            except Exception as exc:
                return {"error": type(exc).__name__, "message": str(exc), "value": False, "count": 0}
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc)}
    return None


def candidates(raw: dict[str, Any]) -> list[str]:
    op = raw["op"]
    semantic = {
        "crontab_parse": ["parse_crontab", "CronFileParser", "parse_file"],
        "weekday_map": ["map_weekday", "weekday_mapper", "CronExpression.map_weekday"],
        "builder_predefined": ["CronBuilder", "builder", "predefined"],
        "map": ["map_definition", "CronMapper", "map_expression"],
        "describe": ["describe", "CronDescriptor", "humanize"],
        "field_increment": ["FieldExpression.increment", "increment_field", "CronExpression.increment"],
        "alias_lifecycle": ["register_alias", "unregister_alias", "aliases"],
    }
    return semantic.get(op, [op, f"CronExpression.{op}"])


def factory(raw: dict[str, Any]):
    p = raw.get("params") or {}
    def make(name: str, value: Any):
        args: tuple[Any, ...]
        if "crontab" in name.lower() or name.endswith("parse_file"):
            args = (p.get("content", "* * * * * command"),)
        elif "weekday" in name.lower():
            args = (p.get("value", 1), p.get("source"), p.get("target"))
        elif "describe" in name.lower() or "human" in name.lower():
            args = (p.get("expression", "* * * * *"),)
        elif "alias" in name.lower():
            args = (p.get("alias", "@probe"), p.get("expression", "* * * * *"))
        else:
            args = (p.get("expression", "* * * * *"),)
        if name.startswith("CronExpression."):
            return (None, *args), {}
        return args, {}
    return make


def positive(solcron: Any) -> dict[str, Any]:
    try:
        parsed = solcron.parse("*/5 * * * *")
        matched = solcron.match("*/5 * * * *", "2024-01-01T00:10:00Z")
        return {"passed": parsed is not None and matched is True}
    except Exception as exc:
        return {"passed": False, "exception": type(exc).__name__, "message": str(exc)}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old = load_old()
    add_snapshot_import_roots(SNAPSHOT)
    import solcron
    compiled_by_origin = old.build_noncommon()
    raw_by_id = {}
    for origin, path in old.SOURCE_FILES.items():
        raw_by_id.update({row["cross_id"]: row for row in old.load_raw(path, origin)})
    rows = [contract for values in compiled_by_origin.values() for contract in values]
    assert len(rows) == 1383
    control = positive(solcron)
    surface = public_surface(solcron)
    output = []
    for contract in rows:
        raw = raw_by_id[contract["cross_id"]]
        replay, actual, misses = old.expected_matches(solcron, contract, contract["expected"])
        mutant_match = False
        if replay:
            mutant_match, _, _ = old.expected_matches(solcron, contract, contract["mutant"])
        if contract["canonical_op"] != "public_surface_missing":
            verdict = "PASS" if replay and not mutant_match else "FAIL_SEMANTIC_MISMATCH"
            evidence = {"kind": "behavior_replay", "actual": actual, "expected": contract["expected"],
                        "misses": misses, "mutant_rejected": replay and not mutant_match, "positive_control": control}
        else:
            projected = behavior_projection(solcron, raw, old)
            if projected is not None:
                raw_expected = raw.get("expected") or {}
                raw_mutant = raw.get("mutant") or old.mutant_expected(raw_expected)
                match = deep_contains(projected, raw_expected)
                mutant_rejected = not deep_contains(projected, raw_mutant)
                verdict = "PASS" if match and mutant_rejected else "FAIL_SEMANTIC_MISMATCH"
                evidence = {"kind": "source_behavior_projection", "actual": projected, "expected": raw_expected,
                            "mutant_rejected": mutant_rejected, "positive_control": control}
            else:
                attempts = invoke_candidates(solcron, candidates(raw), factory(raw))
                verdict = "FAIL_CAPABILITY_ABSENCE" if absence_established(attempts, control) else "UNKNOWN_ADAPTER_GAP"
                evidence = {"kind": "contract_specific_native_probe", "required_operation": raw["op"],
                            "candidate_interfaces": candidates(raw), "attempts": attempts,
                            "positive_control": control, "public_surface": surface}
        output.append({"scoring_id": contract["cross_id"], "origin": contract["origin"],
                       "source_name": contract["name"], "source_contract": raw, "compiled_contract": contract,
                       "target": "solcron", "target_snapshot": str(SNAPSHOT), "verdict": verdict,
                       "evidence": evidence, "adapter_revision": "cron-executable-contract-v1"})
    (OUTPUT_DIR / "strict_results.jsonl").write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in output))
    summary = {"total": len(output), "verdicts": dict(Counter(x["verdict"] for x in output)),
               "execution_kinds": dict(Counter(x["evidence"]["kind"] for x in output))}
    (OUTPUT_DIR / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
