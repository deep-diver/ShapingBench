#!/usr/bin/env python3
"""Extract replayable JWT contracts from Nimbus JOSE + JWT release history."""

from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jwt_origin_common import (
    JWT_RE,
    ROOT,
    Contract,
    add_contract,
    b64url_decode_json,
    contract_identity,
    ensure_git_repo,
    git_show,
    git_tags,
    hmac_alg_for_token,
    sh,
    tag_date,
    write_rpl,
)


REPO = ROOT / ".cache" / "jwt" / "nimbus-jose-jwt-bitbucket"
BASE = ROOT / "contracts" / "jwt" / "nimbus-jose-jwt"
URL = "https://bitbucket.org/connect2id/nimbus-jose-jwt.git"
LONG_SECRET = "0123456789012345678901234567890123456789012345678901234567890123"


def source_interesting(path: str) -> bool:
    return path.endswith((".java", ".txt", ".html")) and ("src/test/" in path or "CHANGELOG" in path or "README" in path)


def candidate_files(tag: str) -> list[str]:
    try:
        raw = sh(["git", "grep", "-Il", "eyJ", tag, "--", "*.java", "*.txt", "*.html"], cwd=REPO)
    except Exception:
        return []
    prefix = f"{tag}:"
    files = []
    for line in raw.splitlines():
        path = line[len(prefix) :] if line.startswith(prefix) else line
        if source_interesting(path):
            files.append(path)
    return files


def literal_contracts(version: str, published_at: str | None, tag: str) -> list[Contract]:
    out: list[Contract] = []
    secrets = [
        ("longSecret", LONG_SECRET.encode()),
        ("secret", b"secret"),
        ("12345678901234567890123456789012", b"12345678901234567890123456789012"),
    ]
    for path in candidate_files(tag):
        text = git_show(REPO, tag, path) or ""
        for index, token in enumerate(dict.fromkeys(JWT_RE.findall(text))):
            parts = token.split(".")
            if len(parts) != 3:
                continue
            evidence = {"tag": tag, "source": path, "literal_index": index}
            slug = f"{Path(path).stem}_{index:03d}".replace(".", "_")
            try:
                header = b64url_decode_json(parts[0])
                payload = b64url_decode_json(parts[1])
                if not isinstance(header, dict) or not isinstance(payload, dict):
                    raise ValueError("JWT header/payload must be JSON objects")
            except Exception:
                if "JWT" in text or "JWS" in text:
                    add_contract(out, version, published_at, "jwt.decode.errors", "decode_error", slug, {"token": token}, {"error": True}, evidence, "release-test-token-literal")
                continue
            expected = {"header": header, "payload": payload, "signature_b64": parts[2], "has_signature": parts[2] != ""}
            add_contract(out, version, published_at, "jwt.decode.complete", "decode_complete", slug, {"token": token}, expected, evidence, "release-test-token-literal")
            for claim, value in payload.items():
                cap = "jwt.decode.registered-claim" if claim in {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} else "jwt.decode.custom-claim"
                add_contract(out, version, published_at, cap, "decode_claim_value", f"{slug}_{claim}", {"token": token, "claim": claim}, {"value": value}, evidence, "release-test-token-literal")
            alg = header.get("alg")
            if alg in {"HS256", "HS384", "HS512"}:
                matched = None
                for name, secret in secrets:
                    if hmac_alg_for_token(token, secret):
                        matched = name
                        break
                if matched:
                    add_contract(out, version, published_at, "jwt.verify.hmac-no-time", "verify_hmac", f"{slug}_{matched}", {"token": token, "algorithm": alg, "secret": LONG_SECRET if matched == "longSecret" else matched, "options": {"ignoreExpiration": True, "ignoreNotBefore": True}}, {"ok": True}, evidence, "release-test-token-literal")
    return out


def scenario_specs() -> list[tuple[str, str, str, str, dict[str, Any], dict[str, Any], str]]:
    return [
        ("2.0", "jwt.sign.hmac", "sign_hmac", "hs256_basic", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"iss": "joe", "scope": "read"}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"iss": "joe", "scope": "read"}, "verifies": True}, "JWS HMAC signing / JWT serialisation"),
        ("2.0", "jwt.sign.hmac", "sign_hmac", "hs384_basic", {"algorithm": "HS384", "secret": LONG_SECRET, "claims": {"iss": "joe", "scope": "read"}}, {"header": {"alg": "HS384", "typ": "JWT"}, "payload": {"iss": "joe", "scope": "read"}, "verifies": True}, "JWS HMAC signing / JWT serialisation"),
        ("2.0", "jwt.sign.hmac", "sign_hmac", "hs512_basic", {"algorithm": "HS512", "secret": LONG_SECRET, "claims": {"iss": "joe", "scope": "read"}}, {"header": {"alg": "HS512", "typ": "JWT"}, "payload": {"iss": "joe", "scope": "read"}, "verifies": True}, "JWS HMAC signing / JWT serialisation"),
        ("2.0", "jwt.verify.algorithm-policy", "verify_generated_hmac", "wrong_secret_rejected", {"algorithm": "HS256", "secret": LONG_SECRET, "verifySecret": LONG_SECRET + "x", "claims": {"iss": "joe"}}, {"ok": False}, "MACVerifier rejects wrong key"),
        ("3.1", "jwt.header", "sign_hmac", "custom_kid_header", {"algorithm": "HS256", "secret": LONG_SECRET, "headers": {"kid": "key-1"}, "claims": {"sub": "alice"}}, {"header": {"alg": "HS256", "typ": "JWT", "kid": "key-1"}, "payload": {"sub": "alice"}, "verifies": True}, "JWSHeader registered kid parameter"),
        ("4.0", "jwt.verify.claim-time", "verify_generated_hmac", "expired_rejected", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"exp": 2000000000}, "options": {"clockTimestamp": 2000000001}}, {"ok": False}, "JWT claims verifier expiration check"),
        ("4.0", "jwt.verify.claim-time", "verify_generated_hmac", "nbf_rejected", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"nbf": 2000000010}, "options": {"clockTimestamp": 2000000000}}, {"ok": False}, "JWT claims verifier not-before check"),
        ("4.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_match", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"iss": "https://issuer.example"}, "options": {"issuer": "https://issuer.example"}}, {"ok": True}, "JWT issuer claim verification"),
        ("4.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_mismatch", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"iss": "https://issuer.example"}, "options": {"issuer": "https://other.example"}}, {"ok": False}, "JWT issuer claim verification"),
        ("4.0", "jwt.verify.subject", "verify_generated_hmac", "subject_match", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"sub": "alice"}, "options": {"subject": "alice"}}, {"ok": True}, "JWT subject claim verification"),
        ("4.0", "jwt.verify.audience", "verify_generated_hmac", "audience_match", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"aud": "api"}, "options": {"audience": "api"}}, {"ok": True}, "JWT audience claim verification"),
        ("4.0", "jwt.verify.audience", "verify_generated_hmac", "audience_mismatch", {"algorithm": "HS256", "secret": LONG_SECRET, "claims": {"aud": ["web", "api"]}, "options": {"audience": "mobile"}}, {"ok": False}, "JWT audience claim verification"),
        ("5.0", "jwt.key.jwk", "jwk_oct_parse", "oct_key_round_trip", {"jwk": {"kty": "oct", "kid": "hmac-1", "k": base64.urlsafe_b64encode(LONG_SECRET.encode()).decode().rstrip("=")}}, {"kty": "oct", "kid": "hmac-1", "size_bits": 512}, "JWK octet key representation"),
        ("5.0", "jwt.key.jwkset", "jwk_set_parse", "jwkset_find_by_kid", {"keys": [{"kty": "oct", "kid": "a", "k": base64.urlsafe_b64encode(LONG_SECRET.encode()).decode().rstrip("=")}, {"kty": "oct", "kid": "b", "k": base64.urlsafe_b64encode(b"abcdefghijklmnopqrstuvwxyz012345").decode().rstrip("=")}]}, {"key_count": 2, "contains_a": True, "contains_b": True}, "JWKSet key selection by kid"),
        ("8.2", "jwt.header.critical", "verify_generated_hmac", "unknown_crit_rejected", {"algorithm": "HS256", "secret": LONG_SECRET, "headers": {"crit": ["custom"], "custom": "x"}, "claims": {"iss": "joe"}}, {"ok": False}, "critical header handling"),
        ("9.37.2", "jwt.security.pbes2", "key_pbes2_iteration_policy", "p2c_too_large_rejected", {"p2c": 1000000000}, {"error": True}, "security fix limits excessive PBES2 count"),
    ]


def scenario_contracts(tag_dates: dict[str, str | None]) -> list[Contract]:
    out: list[Contract] = []
    for version, capability, op, slug, params, expected, note in scenario_specs():
        add_contract(out, version, tag_dates.get(version), capability, op, slug, params, expected, {"source": "CHANGELOG.txt/src/test", "note": note}, "release-note-scenario")
    return out


def main() -> int:
    ensure_git_repo(URL, REPO)
    BASE.mkdir(parents=True, exist_ok=True)
    tags = git_tags(REPO)
    tag_dates = {tag: tag_date(REPO, tag) for tag in tags}
    seen: set[str] = set()
    contracts: list[Contract] = []
    release_rows = []
    for tag in tags:
        found = literal_contracts(tag, tag_dates.get(tag), tag)
        new = 0
        for contract in found:
            key = contract_identity(contract)
            if key in seen:
                continue
            seen.add(key)
            contracts.append(contract)
            new += 1
        release_rows.append({"version": tag, "tag": tag, "contracts_seen": len(found), "new_contracts": new})
    for contract in scenario_contracts(tag_dates):
        key = contract_identity(contract)
        if key in seen:
            continue
        seen.add(key)
        contracts.append(contract)
        for row in release_rows:
            if row["version"] == contract.version:
                row["contracts_seen"] += 1
                row["new_contracts"] += 1
                break

    rows = [asdict(contract) for contract in contracts]
    payload = {
        "domain": "JWT Signing/Verification",
        "project": "connect2id/nimbus-jose-jwt",
        "package": "com.nimbusds:nimbus-jose-jwt",
        "latest_version": "10.9.1",
        "source_repository": URL,
        "git_tags": len(tags),
        "release_rows": release_rows,
        "contracts_extracted": len(rows),
        "by_capability": dict(Counter(row["capability"] for row in rows)),
        "by_source_kind": dict(Counter(row["source_kind"] for row in rows)),
        "contracts": rows,
    }
    (BASE / "all_releases_language_independent.summary.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(rows, BASE / "all_releases_language_independent.rpl")

    counts = ["# Nimbus JOSE + JWT Release Contract Counts", "", "| Version | Tag | Contracts seen | New unique contracts |", "| --- | --- | ---: | ---: |"]
    for row in release_rows:
        counts.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (BASE / "release_contract_counts.md").write_text("\n".join(counts) + "\n", encoding="utf-8")

    audit = [
        "# Nimbus JOSE + JWT Contract Extraction Audit",
        "",
        f"- Git tags inspected: {len(tags)}",
        "- Latest replay target: Maven `com.nimbusds:nimbus-jose-jwt:10.9.1`",
        f"- Extracted externally observable contracts: {len(rows)}",
        "",
        "## By Capability",
        "",
        "| Capability | Contracts |",
        "| --- | ---: |",
    ]
    for key, value in sorted(payload["by_capability"].items()):
        audit.append(f"| `{key}` | {value} |")
    audit.extend(["", "## By Source Kind", "", "| Source kind | Contracts |", "| --- | ---: |"])
    for key, value in sorted(payload["by_source_kind"].items()):
        audit.append(f"| `{key}` | {value} |")
    (BASE / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({"latest_version": payload["latest_version"], "git_tags": len(tags), "contracts_extracted": len(rows), "by_capability": payload["by_capability"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
