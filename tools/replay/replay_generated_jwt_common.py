#!/usr/bin/env python3
"""Replay JWT final common contracts against a generated Python `soljwt` library."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IN_JSON = ROOT / "contracts" / "jwt" / "common" / "final_common.json"
OUT_DIR = ROOT / "contracts" / "jwt" / "generated"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    ignored = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "target",
        "venv",
        ".venv",
        "dist",
        "build",
    }
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in ignored or part.endswith(".egg-info") for part in candidate.parts):
            continue
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        rows.append(f"{sha256(candidate)}  {candidate.relative_to(impl_dir)}\n")
    path.write_text("".join(rows), encoding="utf-8")


def safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def load_soljwt(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    for name in list(sys.modules):
        if name == "soljwt" or name.startswith("soljwt."):
            del sys.modules[name]
    try:
        return importlib.import_module("soljwt")
    except Exception as exc:
        raise SystemExit(f"failed to import generated soljwt from {impl_dir}: {type(exc).__name__}: {exc}") from exc


def normalize_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return b64url(value)
    if isinstance(value, tuple):
        return [normalize_value(item) for item in value]
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_value(item) for key, item in value.items()}
    return value


def normalize_decode_kwargs(params: dict[str, Any], *, verify: bool) -> dict[str, Any]:
    opts = dict(params.get("options") or {})
    kwargs: dict[str, Any] = {"verify": verify}

    algorithms = opts.pop("algorithms", None)
    if algorithms is None and params.get("algorithm"):
        algorithms = [params["algorithm"]]
    if isinstance(algorithms, str):
        algorithms = [algorithms]
    if algorithms is not None:
        kwargs["algorithms"] = algorithms

    options: dict[str, Any] = {}
    if opts.pop("ignoreExpiration", False):
        options["verify_exp"] = False
    if opts.pop("ignoreNotBefore", False):
        options["verify_nbf"] = False
    if "verify_exp" in opts:
        options["verify_exp"] = bool(opts.pop("verify_exp"))
    if "verify_nbf" in opts:
        options["verify_nbf"] = bool(opts.pop("verify_nbf"))
    if "verify_iat" in opts:
        options["verify_iat"] = bool(opts.pop("verify_iat"))
    if "require" in opts:
        options["require"] = opts.pop("require")

    for key in ("audience", "issuer", "subject"):
        if key in opts:
            kwargs[key] = opts.pop(key)
    if "audience" in params:
        kwargs["audience"] = params["audience"]
    if "issuer" in params:
        kwargs["issuer"] = params["issuer"]
    if "subject" in params:
        kwargs["subject"] = params["subject"]
    if "clockTimestamp" in opts:
        kwargs["current_time"] = opts.pop("clockTimestamp")
    if "clockTolerance" in opts:
        kwargs["leeway"] = opts.pop("clockTolerance")
    if "leeway" in params:
        kwargs["leeway"] = params["leeway"]
    if "current_time" in params:
        kwargs["current_time"] = params["current_time"]
    if options:
        kwargs["options"] = options
    return kwargs


def decode_unverified(soljwt: Any, token: str, *, complete: bool = False) -> Any:
    return soljwt.decode(token, verify=False, complete=complete)


def run_contract(soljwt: Any, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract["canonical_op"]
    params = contract.get("params") or {}
    try:
        if op == "decode_complete":
            decoded = decode_unverified(soljwt, params.get("token", ""), complete=True)
            decoded = normalize_value(decoded)
            if isinstance(decoded, dict):
                if "signature" in decoded and "signature_b64" not in decoded:
                    decoded["signature_b64"] = decoded["signature"]
                return decoded
            return {"value": decoded}

        if op == "decode_claim":
            payload = decode_unverified(soljwt, params.get("token", ""), complete=False)
            if not isinstance(payload, dict):
                return {"error": "NonObjectPayload", "value": normalize_value(payload)}
            return {"value": normalize_value(payload.get(params.get("claim")))}

        if op == "decode_error":
            try:
                decode_unverified(soljwt, params.get("token", ""), complete=False)
            except Exception as exc:
                return {"error": True, "throws": type(exc).__name__, "message": str(exc)}
            return {"error": False}

        if op == "verify_hmac_literal":
            kwargs = normalize_decode_kwargs(params, verify=True)
            try:
                payload = soljwt.decode(params.get("token", ""), params.get("secret"), **kwargs)
                return {"ok": True, "payload": normalize_value(payload)}
            except Exception as exc:
                return {"ok": False, "throws": type(exc).__name__, "message": str(exc)}

        if op == "sign_then_verify_hmac":
            token = soljwt.encode(
                params.get("claims") or {},
                params.get("secret"),
                algorithm=params.get("algorithm", "HS256"),
                headers=params.get("headers") or None,
            )
            verify_params = dict(params)
            verify_params["token"] = token
            verify_params["secret"] = params.get("verifySecret", params.get("secret"))
            kwargs = normalize_decode_kwargs(verify_params, verify=True)
            try:
                payload = soljwt.decode(token, verify_params.get("secret"), **kwargs)
                return {"ok": True, "payload": normalize_value(payload), "token": token}
            except Exception as exc:
                return {"ok": False, "throws": type(exc).__name__, "message": str(exc), "token": token}

        return {"unsupported": True, "message": op}
    except Exception as exc:
        return {"exception": type(exc).__name__, "message": str(exc)}


def deep_contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for key, expected_value in expected.items():
            if key not in actual or not deep_contains(actual[key], expected_value):
                return False
        return True
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return False
        return all(deep_contains(left, right) for left, right in zip(actual, expected))
    return actual == expected


def expected_matches(expected: dict[str, Any], actual: dict[str, Any]) -> tuple[bool, list[str]]:
    if actual.get("unsupported"):
        return False, [f"unsupported: {actual.get('message')}"]
    if "exception" in actual and "error" not in expected and "ok" not in expected:
        return False, [f"{actual.get('exception')}: {actual.get('message', '')}"]
    misses: list[str] = []
    for key, expected_value in expected.items():
        if key not in actual:
            misses.append(f"{key}: missing")
        elif not deep_contains(actual[key], expected_value):
            misses.append(f"{key}: expected {expected_value!r}, got {actual.get(key)!r}")
    return not misses, misses


def load_contracts() -> list[dict[str, Any]]:
    data = json.loads(IN_JSON.read_text(encoding="utf-8"))
    return data["contracts"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="soljwt_gpt56sol_high_iter1_20260830")
    parser.add_argument("--iteration", type=int, default=1)
    parser.add_argument("--hinting", default="none")
    parser.add_argument("--prompt", type=Path)
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    label = safe_label(args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    contracts = load_contracts()
    total = len(contracts)
    out_json = OUT_DIR / f"{label}_survival_from_common_{total}.json"
    out_md = OUT_DIR / f"{label}_survival_from_common_{total}.md"
    hashes = OUT_DIR / f"{label}_source_hashes.sha256"
    metadata = OUT_DIR / f"{label}_metadata.json"

    soljwt = load_soljwt(impl_dir)
    results = []
    survivors = []
    for contract in contracts:
        actual = run_contract(soljwt, contract)
        replay_ok, misses = expected_matches(contract["expected"], actual)
        mutant_ok, mutant_misses = expected_matches(contract["mutant"], actual)
        verified = replay_ok and not mutant_ok
        row = {
            "id": contract["id"],
            "origin": contract.get("origin"),
            "source_capability": contract.get("source_capability"),
            "canonical_op": contract["canonical_op"],
            "status": "passed" if verified else "failed",
            "replay_passed": replay_ok,
            "mutant_rejected": not mutant_ok,
            "misses": misses,
            "mutant_misses": mutant_misses,
            "expected": contract["expected"],
            "mutant": contract["mutant"],
            "actual": actual,
        }
        results.append(row)
        if verified:
            survivors.append(contract["id"])

    counts = Counter(row["status"] for row in results)
    by_op = defaultdict(Counter)
    by_origin = defaultdict(Counter)
    by_capability = defaultdict(Counter)
    for row in results:
        status = row["status"]
        by_op[row["canonical_op"]][status] += 1
        by_origin[row.get("origin") or "unknown"][status] += 1
        by_capability[row.get("source_capability") or "unknown"][status] += 1

    summary = {
        "domain": "JWT Signing/Verification",
        "implementation": str(impl_dir),
        "implementation_module": getattr(soljwt, "__file__", "unknown"),
        "label": label,
        "common_contract_total": total,
        "passed": counts["passed"],
        "failed": counts["failed"],
        "pass_rate": round(counts["passed"] / total, 4) if total else 0,
        "by_op": {key: dict(value) for key, value in sorted(by_op.items())},
        "by_origin": {key: dict(value) for key, value in sorted(by_origin.items())},
        "by_capability": {key: dict(value) for key, value in sorted(by_capability.items())},
    }

    out_json.write_text(
        json.dumps({"summary": summary, "survivors": survivors, "results": results}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_hashes(impl_dir, hashes)
    metadata.write_text(
        json.dumps(
            {
                "label": label,
                "prompt": str((args.prompt or ROOT / "experiments" / "jwt" / "prompts" / f"{label}.md").resolve()),
                "implementation_dir": str(impl_dir),
                "common_contracts": str(IN_JSON),
                "result_json": str(out_json),
                "result_md": str(out_md),
                "source_hashes": str(hashes),
                "model": args.model,
                "reasoning": args.reasoning,
                "iteration": args.iteration,
                "hinting": args.hinting,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Generated JWT Library Survival",
        "",
        f"Implementation: `{impl_dir}`",
        f"Module: `{summary['implementation_module']}`",
        f"Contracts: {summary['common_contract_total']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By Operation",
        "",
        "| Operation | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for op, counter in summary["by_op"].items():
        lines.append(f"| `{op}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines += [
        "",
        "## By Origin",
        "",
        "| Origin | Passed | Failed |",
        "| --- | ---: | ---: |",
    ]
    for origin, counter in summary["by_origin"].items():
        lines.append(f"| `{origin}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines += [
        "",
        "## Failed Contracts",
        "",
        "| Contract | Operation | Misses |",
        "| --- | --- | --- |",
    ]
    for row in results:
        if row["status"] == "passed":
            continue
        misses = "; ".join(row["misses"]) or "mutant survived"
        misses = misses.replace("|", "\\|")
        if len(misses) > 260:
            misses = misses[:257] + "..."
        lines.append(f"| `{row['id']}` | `{row['canonical_op']}` | {misses} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
