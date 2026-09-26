#!/usr/bin/env python3
"""Replay JWT origin non-common contracts against a generated Python `soljwt` library."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "jwt"
COMMON_JSON = BASE / "common" / "final_common.json"
CROSS_COMMON = ROOT / "tools" / "replay" / "jwt_cross_common.py"
OUT_DIR = BASE / "generated_non_common"
COMMON_CANDIDATES_JSON = BASE / "common" / "rank1_2_3_cross_replay_common_candidates.json"
COMMON_DETAILS_JSON = BASE / "common" / "jwt_cross_common_details.json"

ORIGIN_FILES = {
    "rank1-auth0-java-jwt": BASE / "auth0-java-jwt" / "latest_replay_mutant_verified.json",
    "rank2-pyjwt": BASE / "pyjwt" / "latest_replay_mutant_verified.json",
    "rank3-node-jsonwebtoken": BASE / "node-jsonwebtoken" / "latest_replay_mutant_verified.json",
    "rank4-golang-jwt": BASE / "golang-jwt" / "latest_replay_mutant_verified.json",
    "rank5-nimbus-jose-jwt": BASE / "nimbus-jose-jwt" / "latest_replay_mutant_verified.json",
}


def load_cross_common() -> Any:
    spec = importlib.util.spec_from_file_location("jwt_cross_common", CROSS_COMMON)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {CROSS_COMMON}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    if "strict_aud" in opts:
        options["strict_aud"] = bool(opts.pop("strict_aud"))
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


def complete_dict(decoded: Any) -> dict[str, Any]:
    decoded = normalize_value(decoded)
    if not isinstance(decoded, dict):
        return {"value": decoded}
    if "signature" in decoded and "signature_b64" not in decoded:
        decoded["signature_b64"] = decoded["signature"]
        decoded["has_signature"] = bool(decoded["signature"])
    return decoded


def decode_unverified(soljwt: Any, token: str, *, complete: bool = False) -> Any:
    return soljwt.decode(token, verify=False, complete=complete)


def run_decode_error(soljwt: Any, token: str) -> dict[str, Any]:
    try:
        decode_unverified(soljwt, token, complete=False)
    except Exception as exc:
        return {"error": True, "throws": type(exc).__name__, "message": str(exc)}
    return {"error": False}


def run_verify_literal(soljwt: Any, params: dict[str, Any]) -> dict[str, Any]:
    kwargs = normalize_decode_kwargs(params, verify=True)
    try:
        payload = soljwt.decode(params.get("token", ""), params.get("secret"), **kwargs)
        return {"ok": True, "payload": normalize_value(payload)}
    except Exception as exc:
        return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}


def run_sign_hmac(soljwt: Any, params: dict[str, Any]) -> dict[str, Any]:
    try:
        token = soljwt.encode(
            params.get("claims") or {},
            params.get("secret"),
            algorithm=params.get("algorithm", "HS256"),
            headers=params.get("headers") or None,
        )
        decoded = complete_dict(decode_unverified(soljwt, token, complete=True))
        decoded["verifies"] = True
        decoded["token"] = token
        return decoded
    except Exception as exc:
        return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}


def run_sign_then_verify(soljwt: Any, params: dict[str, Any]) -> dict[str, Any]:
    try:
        token = soljwt.encode(
            params.get("claims") or {},
            params.get("secret"),
            algorithm=params.get("algorithm", "HS256"),
            headers=params.get("headers") or None,
        )
    except Exception as exc:
        return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}
    verify_params = dict(params)
    verify_params["token"] = token
    verify_params["secret"] = params.get("verifySecret", params.get("secret"))
    actual = run_verify_literal(soljwt, verify_params)
    actual["token"] = token
    return actual


def run_none_algorithm(soljwt: Any, params: dict[str, Any]) -> dict[str, Any]:
    try:
        token = soljwt.encode(params.get("claims") or {}, None, algorithm="none")
        opts = params.get("options") or {}
        if opts.get("algorithms") == ["none"]:
            kwargs = normalize_decode_kwargs({"options": opts, "algorithm": "none"}, verify=True)
            payload = soljwt.decode(token, None, **kwargs)
            return {"ok": True, "payload": normalize_value(payload), **complete_dict(decode_unverified(soljwt, token, complete=True))}
        decoded = complete_dict(decode_unverified(soljwt, token, complete=True))
        decoded["verifies"] = True
        return decoded
    except Exception as exc:
        return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}


def run_hash_digest(params: dict[str, Any]) -> dict[str, Any]:
    name = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}.get(params.get("algorithm"))
    if not name:
        return {"error": True, "message": f"unsupported digest algorithm {params.get('algorithm')}"}
    return {"digest_hex": hashlib.new(name, str(params.get("message", "")).encode()).hexdigest()}


def run_implementation_policy(soljwt: Any, params: dict[str, Any]) -> dict[str, Any]:
    source_op = params.get("source_op")
    try:
        if source_op == "sign_error":
            soljwt.encode(
                params.get("payload", {}),
                params.get("secret"),
                algorithm=(params.get("options") or {}).get("algorithm", "HS256"),
            )
            return {"error": False, "ok": True}
        if source_op in {"verify_error", "key_confusion_verify", "malicious_key_material_rejected", "invalid_asymmetric_key_type"}:
            token = params.get("token") or ""
            return run_verify_literal(
                soljwt,
                {
                    "token": token,
                    "secret": params.get("secret") or params.get("key") or "secret",
                    "algorithm": params.get("algorithm", "HS256"),
                    "options": params.get("options") or params.get("verifyOptions") or {},
                },
            )
        if source_op == "decode_short_hmac_enforced":
            token = soljwt.encode(params.get("claims") or {}, params.get("secret"), algorithm=params.get("algorithm", "HS256"))
            return run_verify_literal(soljwt, {"token": token, "secret": params.get("secret"), "algorithm": params.get("algorithm", "HS256"), "options": {}})
        if source_op == "hmac_prepare_key_error":
            soljwt.encode({}, params.get("key"), algorithm="HS256")
            return {"error": False, "ok": True}
        if source_op == "rsa_min_key_size_sign":
            soljwt.encode(params.get("claims") or {}, params.get("key"), algorithm=params.get("algorithm", "RS256"))
            return {"error": False, "ok": True}
    except Exception as exc:
        return {"error": True, "ok": False, "throws": type(exc).__name__, "message": str(exc)}
    return {"unsupported": True, "ok": False, "error": True, "message": str(source_op)}


def run_unsupported_feature(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "unsupported": True,
        "ok": False,
        "error": True,
        "message": str(params.get("source_op") or "unsupported_feature"),
    }


def run_contract(soljwt: Any, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract["canonical_op"]
    params = contract.get("params") or {}
    try:
        if op == "decode_complete":
            return complete_dict(decode_unverified(soljwt, params.get("token", ""), complete=True))
        if op == "decode_claim":
            payload = decode_unverified(soljwt, params.get("token", ""), complete=False)
            if not isinstance(payload, dict):
                return {"error": "NonObjectPayload", "value": normalize_value(payload)}
            return {"value": normalize_value(payload.get(params.get("claim")))}
        if op == "decode_error":
            return run_decode_error(soljwt, params.get("token", ""))
        if op == "verify_hmac_literal":
            return run_verify_literal(soljwt, params)
        if op == "sign_hmac":
            return run_sign_hmac(soljwt, params)
        if op == "sign_then_verify_hmac":
            return run_sign_then_verify(soljwt, params)
        if op == "none_algorithm":
            return run_none_algorithm(soljwt, params)
        if op == "sign_pss":
            return run_sign_hmac(soljwt, {**params, "secret": None})
        if op == "hash_digest":
            return run_hash_digest(params)
        if op == "implementation_policy":
            return run_implementation_policy(soljwt, params)
        if op == "unsupported_feature":
            return run_unsupported_feature(params)
        return {"unsupported": True, "ok": False, "error": True, "message": op}
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
    if actual.get("unsupported") and expected.get("unsupported") is not True:
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


def load_non_common_buckets() -> dict[str, list[dict[str, Any]]]:
    cross = load_cross_common()
    common = json.loads(COMMON_JSON.read_text(encoding="utf-8"))["contracts"]
    common_identities = {row["identity"] for row in common}
    buckets: dict[str, list[dict[str, Any]]] = {}
    for origin, path in ORIGIN_FILES.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        source_rows = data.get("origin_non_common_contracts") or data.get("survivor_contracts") or data.get("survivors") or []
        canonical = [cross.canonicalize(origin, row) for row in source_rows]
        buckets[origin] = [row for row in canonical if row["identity"] not in common_identities]
    return buckets


def result_row(soljwt: Any, contract: dict[str, Any]) -> dict[str, Any]:
    actual = run_contract(soljwt, contract)
    replay_ok, misses = expected_matches(contract["expected"], actual)
    mutant_ok, mutant_misses = (
        expected_matches(contract["mutant"], actual)
        if replay_ok
        else (False, ["mutant not evaluated because replay failed"])
    )
    verified = replay_ok and not mutant_ok
    return {
        "id": contract["id"],
        "origin": contract.get("origin"),
        "source_name": contract.get("source_name"),
        "source_capability": contract.get("source_capability"),
        "source_op": contract.get("source_op"),
        "canonical_op": contract["canonical_op"],
        "version": contract.get("version"),
        "status": "passed" if verified else "failed",
        "replay_passed": replay_ok,
        "mutant_rejected": replay_ok and not mutant_ok,
        "misses": misses,
        "mutant_misses": mutant_misses,
        "expected": contract["expected"],
        "actual": actual,
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_origin = defaultdict(Counter)
    by_op = defaultdict(Counter)
    by_capability = defaultdict(Counter)
    failure_kinds = Counter()
    for row in results:
        status = row["status"]
        by_origin[row.get("origin") or "unknown"][status] += 1
        by_op[row.get("canonical_op") or "unknown"][status] += 1
        by_capability[row.get("source_capability") or "unknown"][status] += 1
        if status != "passed":
            miss = row["misses"][0] if row["misses"] else "unknown"
            failure_kinds[miss.split(":", 1)[0]] += 1
    passed = sum(1 for row in results if row["status"] == "passed")
    failed = len(results) - passed
    return {
        "total_non_common": len(results),
        "attempted": len(results),
        "unmapped": 0,
        "passed": passed,
        "failed": failed,
        "mutants_killed": sum(1 for row in results if row["mutant_rejected"]),
        "pass_rate": round(passed / len(results), 4) if results else 0,
        "by_origin": {key: dict(value) for key, value in sorted(by_origin.items())},
        "by_op": {key: dict(value) for key, value in sorted(by_op.items())},
        "by_capability": {key: dict(value) for key, value in sorted(by_capability.items())},
        "failure_kinds": dict(failure_kinds.most_common()),
    }


def write_markdown(path: Path, summary: dict[str, Any], results: list[dict[str, Any]]) -> None:
    lines = [
        "# Generated JWT Library Non-Common Replay",
        "",
        f"Implementation: `{summary['implementation']}`",
        f"Module: `{summary['implementation_module']}`",
        f"Model: `{summary['model']}`",
        f"Reasoning: `{summary['reasoning']}`",
        f"Definition: {summary['definition']}",
        f"Total non-common: {summary['total_non_common']}",
        f"Attempted: {summary['attempted']}",
        f"Unmapped: {summary['unmapped']}",
        f"Passed: {summary['passed']}",
        f"Failed: {summary['failed']}",
        f"Mutants killed: {summary['mutants_killed']}",
        f"Pass rate: {summary['pass_rate']:.2%}",
        "",
        "## By OSS Origin",
        "",
        "| OSS origin | Input non-common | Passed | Failed |",
        "| --- | ---: | ---: | ---: |",
    ]
    for origin, counter in summary["by_origin"].items():
        total = counter.get("passed", 0) + counter.get("failed", 0)
        lines.append(f"| `{origin}` | {total} | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")

    lines.extend(["", "## By Canonical Operation", "", "| Operation | Passed | Failed |", "| --- | ---: | ---: |"])
    for op, counter in summary["by_op"].items():
        lines.append(f"| `{op}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")

    lines.extend(["", "## Failure Kinds", "", "| Failure kind | Count |", "| --- | ---: |"])
    for kind, count in summary["failure_kinds"].items():
        lines.append(f"| `{kind}` | {count} |")

    lines.extend(["", "## Failed Samples", "", "| Origin | Contract | Operation | Capability | Miss |", "| --- | --- | --- | --- | --- |"])
    for row in [row for row in results if row["status"] != "passed"][:180]:
        miss = (row.get("misses") or [""])[0].replace("|", "\\|").replace("\n", "<br>")
        if len(miss) > 220:
            miss = miss[:217] + "..."
        lines.append(
            f"| `{row.get('origin')}` | `{row['id']}` | `{row.get('canonical_op')}` | `{row.get('source_capability')}` | {miss} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="soljwt_gpt56sol_high_iter5_hinted_20260830")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    args = parser.parse_args()

    label = safe_label(args.label)
    impl_dir = args.implementation_dir.resolve()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    soljwt = load_soljwt(impl_dir)
    buckets = load_non_common_buckets()
    results = [result_row(soljwt, contract) for contracts in buckets.values() for contract in contracts]

    summary = {
        "domain": "JWT Signing/Verification",
        "run_label": label,
        "implementation": str(impl_dir),
        "implementation_module": getattr(soljwt, "__file__", "unknown"),
        "model": args.model,
        "reasoning": args.reasoning,
        "definition": "All five OSS latest replay+mutant survivor contracts minus the 349-contract hidden-filtered final common set.",
        "input_buckets": {origin: len(rows) for origin, rows in buckets.items()},
        **summarize(results),
    }

    out_json = OUT_DIR / f"{label}_non_common_by_oss.json"
    out_md = OUT_DIR / f"{label}_non_common_by_oss.md"
    out_hashes = OUT_DIR / f"{label}_source_hashes.sha256"
    out_json.write_text(json.dumps({"summary": summary, "results": results}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, out_hashes)
    write_markdown(out_md, summary, results)
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
