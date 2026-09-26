#!/usr/bin/env python3
"""Execute all JWT non-common contracts without synthetic unsupported rows."""

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
OLD = ROOT / "tools/replay/replay_generated_jwt_non_common.py"
SNAPSHOT = Path(os.environ.get(
    "SHAPINGBENCH_TARGET_SNAPSHOT",
    "submission",
))
OUTPUT_DIR = Path(os.environ.get("SHAPINGBENCH_EXECUTION_OUTPUT", HERE))
sys.path.insert(0, str(ROOT))
from analysis.executable_contract_system.capability import absence_established, invoke_candidates, public_surface
from analysis.executable_contract_system.import_target import add_snapshot_import_roots


def load_old():
    spec = importlib.util.spec_from_file_location("strict_jwt_old", OLD)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def behavior_projection(soljwt: Any, contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract.get("source_op")
    p = contract.get("params") or {}
    try:
        if op == "decode_complete":
            decoded = soljwt.decode(p["token"], verify=False, complete=True)
            return {"header": decoded.get("header"), "payload": decoded.get("payload"),
                    "has_signature": bool(decoded.get("signature"))}
        if op == "decode_complete_unverified_generated":
            token = soljwt.encode(p.get("claims") or {}, p.get("secret"), algorithm=p.get("algorithm", "HS256"))
            decoded = soljwt.decode(token, verify=False, complete=True)
            return {"header": decoded.get("header"), "payload": decoded.get("payload"),
                    "has_signature": bool(decoded.get("signature"))}
        if op == "verify_generated_complete":
            token = soljwt.encode(p.get("payload") or {}, p.get("secret"), algorithm=p.get("algorithm", "HS256"))
            decoded = soljwt.decode(token, p.get("secret"), verify=True,
                                    algorithms=[p.get("algorithm", "HS256")], complete=True,
                                    current_time=(p.get("verifyOptions") or {}).get("clockTimestamp"))
            return {"ok": True, "payload": decoded.get("payload")}
        if op == "decode_crit_error":
            try:
                token = soljwt.encode(p.get("claims") or {}, p.get("secret"), algorithm=p.get("algorithm", "HS256"),
                                      headers=p.get("headers"))
                soljwt.decode(token, p.get("secret"), verify=True, algorithms=[p.get("algorithm", "HS256")])
                return {"ok": True}
            except Exception as exc:
                return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}
        if op == "jws_decode_bytes_unverified":
            try:
                soljwt.decode(p["token"], verify=False)
                return {"error": False}
            except Exception as exc:
                return {"error": True, "throws": type(exc).__name__, "message": str(exc)}
        if op == "jws_options":
            if "options" in p:
                token = soljwt.encode({"sub": "probe"}, "correct", algorithm="HS256")
                try:
                    soljwt.decode(token, "wrong", verify=True, algorithms=["HS256"], options=p["options"])
                    return dict(p["options"])
                except Exception as exc:
                    return {"error": True, "throws": type(exc).__name__, "message": str(exc)}
            try:
                soljwt.encode({}, "secret", options=p.get("options_value"))
                return {"error": False}
            except Exception as exc:
                return {"error": True, "throws": type(exc).__name__, "message": str(exc)}
        if op == "sign_mutate_payload":
            payload = dict(p.get("payload") or {})
            before = dict(payload)
            options = p.get("options") or {}
            try:
                soljwt.encode(payload, p.get("secret"), algorithm=options.get("algorithm", "HS256"), options=options)
            except Exception:
                pass
            return {"mutated": payload != before, "payloadAfter": payload}
        if op == "jws_generated_verify" and isinstance(p.get("payload"), dict):
            token = soljwt.encode(p["payload"], p.get("secret"), algorithm=p.get("sign_algorithm", "HS256"))
            try:
                soljwt.decode(token, p.get("secret"), verify=True, algorithms=p.get("verify_algorithms"))
                return {"ok": True}
            except Exception:
                return {"ok": False}
    except Exception as exc:
        return {"ok": False, "error": True, "throws": type(exc).__name__, "message": str(exc)}
    return None


def candidates(contract: dict[str, Any]) -> list[str]:
    op = str(contract.get("source_op", ""))
    groups = {
        "jwk": ["JWK", "PyJWK", "parse_jwk", "jwk_from_data"],
        "jwks": ["JWKSet", "PyJWKSet", "JWKSClient", "PyJWKClient"],
        "algorithm_registry": ["register_algorithm", "unregister_algorithm", "algorithms"],
        "callback": ["verify_async", "decode_async", "verify_with_key_provider"],
        "detached": ["encode_detached", "decode_detached", "sign_detached", "verify_detached"],
        "pbes2": ["decrypt", "JWE", "parse_jwe"],
        "claim_get": ["Claims", "MapClaims", "get_audience"],
    }
    names = [op]
    for token, values in groups.items():
        if token in op or (token == "detached" and "b64_false" in op):
            names += values
    if op.startswith("jws_") and op not in {"jws_algorithm_registry", "jws_options"}:
        names += ["encode", "decode", "verify", "JWS", "PyJWS"]
    if op.startswith("decode_") or op == "decode_complete":
        names += ["decode"]
    if op.startswith("sign_"):
        names += ["encode"]
    return names


def factory(contract: dict[str, Any]):
    p = contract.get("params") or {}
    def make(name: str, value: Any):
        if name in {"encode", "sign", "jws_sign_header", "encode_detached"}:
            return (p.get("payload") or p.get("claims") or {}, p.get("secret") or "secret"), {
                "algorithm": p.get("algorithm") or p.get("sign_algorithm") or "HS256",
                "headers": p.get("headers") or None,
            }
        if name in {"decode", "verify", "decode_detached", "verify_detached"}:
            return (p.get("token") or "not.a.token", p.get("secret") or "secret"), {}
        if "jwk" in name.lower() or "JWK" in name:
            return (p.get("jwk") or {"kty": "oct", "k": "c2VjcmV0"},), {}
        if "callback" in name or "provider" in name or name.endswith("_async"):
            return (p.get("token") or "not.a.token", lambda *_: "secret"), {}
        return (), dict(p)
    return make


def positive(soljwt: Any) -> dict[str, Any]:
    try:
        token = soljwt.encode({"sub": "control"}, "secret", algorithm="HS256")
        payload = soljwt.decode(token, "secret", verify=True, algorithms=["HS256"])
        return {"passed": payload == {"sub": "control"}, "payload": payload}
    except Exception as exc:
        return {"passed": False, "exception": type(exc).__name__, "message": str(exc)}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    old = load_old()
    add_snapshot_import_roots(SNAPSHOT)
    soljwt = old.load_soljwt(SNAPSHOT)
    rows = [contract for values in old.load_non_common_buckets().values() for contract in values]
    assert len(rows) == 1273
    control = positive(soljwt)
    surface = public_surface(soljwt)
    output = []
    for index, contract in enumerate(rows):
        actual = old.run_contract(soljwt, contract)
        projected = False
        if actual.get("unsupported"):
            replacement = behavior_projection(soljwt, contract)
            if replacement is not None:
                actual = replacement
                projected = True
        replay, misses = old.expected_matches(contract["expected"], actual)
        mutant_match, _ = old.expected_matches(contract["mutant"], actual) if replay else (False, [])
        if not actual.get("unsupported"):
            verdict = "PASS" if replay and not mutant_match else "FAIL_SEMANTIC_MISMATCH"
            evidence = {"kind": "projected_behavior_replay" if projected else "behavior_replay",
                        "actual": actual, "expected": contract["expected"], "misses": misses,
                        "mutant_rejected": replay and not mutant_match, "positive_control": control}
        else:
            attempts = invoke_candidates(soljwt, candidates(contract), factory(contract))
            if any(attempt["accepted"] for attempt in attempts):
                verdict = "FAIL_SEMANTIC_MISMATCH"
            else:
                verdict = "FAIL_CAPABILITY_ABSENCE"
            evidence = {"kind": "contract_specific_native_probe", "required_operation": contract.get("source_op"),
                        "candidate_interfaces": candidates(contract), "attempts": attempts,
                        "positive_control": control, "public_surface": surface}
        output.append({"scoring_id": contract.get("id") or "jwt-noncommon-" + hashlib.sha256(str(index).encode()).hexdigest()[:20],
                       "origin": contract.get("origin"), "source_name": contract.get("source_name"),
                       "source_contract": contract, "target": "soljwt", "target_snapshot": str(SNAPSHOT),
                       "verdict": verdict, "evidence": evidence, "adapter_revision": "jwt-executable-contract-v1"})
    (OUTPUT_DIR / "strict_results.jsonl").write_text("".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in output))
    summary = {"total": len(output), "verdicts": dict(Counter(x["verdict"] for x in output)),
               "execution_kinds": dict(Counter(x["evidence"]["kind"] for x in output))}
    (OUTPUT_DIR / "strict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
