#!/usr/bin/env python3
"""Replay confirmed Date/Time/Timezone common contracts against a generated ./dtlib CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "datetime_timezone" / "blind_cross_validation" / "merged_377_rank4_rank5_survivors.summary.json"
OUT_DIR = ROOT / "contracts" / "datetime_timezone" / "generated"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_value(value: Any) -> str:
    text = str(value)
    text = re.sub(r"\.000(?=Z|[+-]\d\d:\d\d|$)", "", text)
    return text


def compare(actual: dict[str, Any], expected: dict[str, Any], errored: bool) -> tuple[bool, str]:
    for key, value in expected.items():
        if key == "throws":
            got = actual.get("throws")
            return (errored or bool(got)) and got == value, f"expected throw {value}, got {got}"
        if key == "not_equals":
            got = actual.get("value")
            if norm_value(got) == norm_value(value):
                return False, f"value unexpectedly equals {value}"
            continue
        if key == "not_offset":
            got = actual.get("offset")
            if norm_value(got) == norm_value(value):
                return False, f"offset unexpectedly equals {value}"
            continue
        if key.endswith("_not"):
            base = key[:-4]
            got = actual.get(base)
            if norm_value(got) == norm_value(value):
                return False, f"{base} unexpectedly equals {value}"
            continue
        if key == "contains":
            hay = actual.get("contains") or actual.get("text") or actual.get("ids") or ""
            if str(value) not in str(hay):
                return False, f"{value} not contained in {hay}"
            continue
        if key == "matches":
            got = actual.get("value", "")
            pattern = str(value).replace("\\\\", "\\")
            if not re.search(pattern, str(got)):
                return False, f"{got} does not match {value}"
            continue
        if key not in actual:
            return False, f"missing {key}"
        got = norm_value(actual[key])
        if isinstance(value, bool):
            if got.lower() != str(value).lower():
                return False, f"{key}: expected {value}, got {got}"
        elif isinstance(value, int):
            if got != str(value):
                return False, f"{key}: expected {value}, got {got}"
        else:
            if got != norm_value(value):
                return False, f"{key}: expected {value}, got {got}"
    return not errored, "ok"


def mutate_expected(expected: dict[str, Any], actual: dict[str, Any] | None = None) -> dict[str, Any]:
    out = json.loads(json.dumps(expected))
    if actual and "not_offset" in out:
        return {"not_offset": actual.get("offset", out["not_offset"])}
    if actual and "not_equals" in out:
        return {"not_equals": actual.get("value", out["not_equals"])}
    if actual:
        for key in list(out):
            if key.endswith("_not"):
                return {key: actual.get(key[:-4], out[key])}
    if "throws" in out:
        out["throws"] = "__no_throw_expected__"
        return out
    for key, value in list(out.items()):
        if isinstance(value, bool):
            out[key] = not value
            return out
        if isinstance(value, int):
            out[key] = value + 1
            return out
        if isinstance(value, str):
            if key == "matches":
                out[key] = r"__never_matches__"
            elif key.endswith("_not"):
                out[key] = "__mutant_not__"
            else:
                out[key] = value + "__mutant__"
            return out
    out["__mutant__"] = "changed"
    return out


def run_contract(dtlib: Path, cwd: Path, contract: dict[str, Any], timeout: int = 8) -> tuple[bool, dict[str, Any]]:
    payload = json.dumps(contract, ensure_ascii=False)
    try:
        proc = subprocess.run(
            [str(dtlib)],
            cwd=str(cwd),
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return True, {"throws": "timeout", "message": "timeout"}
    try:
        actual = json.loads(proc.stdout)
    except Exception as ex:
        if proc.returncode != 0:
            stderr = " ".join(proc.stderr.split())
            return True, {"throws": "process-error", "message": stderr[:500]}
        return True, {"throws": "invalid-output", "message": f"{type(ex).__name__}: {proc.stdout[:500]}"}
    if not isinstance(actual, dict):
        return True, {"throws": "invalid-output", "message": "stdout JSON is not an object"}
    errored = "throws" in actual
    return errored, actual


def write_hashes(impl_dir: Path, path: Path) -> None:
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in {".git", ".tmp", "node_modules", "vendor", "__pycache__"} for part in candidate.parts):
            continue
        if candidate.name.endswith((".pyc", ".lock")):
            continue
        rel = candidate.relative_to(impl_dir)
        rows.append(f"{sha256(candidate)}  {rel}\n")
    path.write_text("".join(rows), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="iter1")
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    dtlib = impl_dir / "dtlib"
    if not dtlib.exists():
        raise SystemExit(f"missing executable {dtlib}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in args.label)
    out_json = OUT_DIR / f"sol_datetime_{safe_label}_survival_from_confirmed_common_250.json"
    out_md = OUT_DIR / f"sol_datetime_{safe_label}_survival_from_confirmed_common_250.md"
    hashes = OUT_DIR / f"sol_datetime_{safe_label}_source_hashes.sha256"

    payload = json.loads(IN_JSON.read_text())
    contracts = payload["contracts"]
    results = []
    survivors = []
    for contract in contracts:
        errored, actual = run_contract(dtlib, impl_dir, contract)
        replay_ok, reason = compare(actual, contract["expected"], errored)
        mutant = mutate_expected(contract["expected"], actual)
        mutant_ok, mutant_reason = compare(actual, mutant, errored)
        verified = replay_ok and not mutant_ok
        row = {
            "name": contract["name"],
            "capability": contract["capability"],
            "replay": contract["replay"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "reason": reason,
            "mutant_reason": mutant_reason,
            "actual": actual,
            "expected": contract["expected"],
        }
        results.append(row)
        if verified:
            survivors.append(contract["name"])

    counts = Counter(r["status"] for r in results)
    summary = {
        "implementation": str(impl_dir),
        "contract_total": len(contracts),
        "passed": counts["passed"],
        "failed": counts["failed"],
        "pass_rate": round(counts["passed"] / len(contracts), 4) if contracts else 0,
    }
    out_json.write_text(json.dumps({"summary": summary, "results": results, "survivors": survivors}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# Generated Date/Time Library Survival",
        "",
        f"Implementation: `{impl_dir}`",
        f"Contracts: {summary['contract_total']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## Failed Contracts",
        "",
        "| Contract | Replay | Capability | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        if row["status"] != "passed":
            reason = str(row["reason"]).replace("|", "\\|")
            lines.append(f"| `{row['name']}` | `{row['replay']}` | `{row['capability']}` | {reason} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_hashes(impl_dir, hashes)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
