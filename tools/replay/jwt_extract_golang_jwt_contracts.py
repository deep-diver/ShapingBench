#!/usr/bin/env python3
"""Extract replayable JWT contracts from golang-jwt/jwt release history."""

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
    list_tree,
    tag_date,
    version_key,
    write_rpl,
)


REPO = ROOT / ".cache" / "jwt" / "golang-jwt"
BASE = ROOT / "contracts" / "jwt" / "golang-jwt"
URL = "https://github.com/golang-jwt/jwt"
HMAC_TEST_KEY = REPO / "test" / "hmacTestKey"


def hmac_candidates() -> list[tuple[str, bytes]]:
    out = [
        ("secret", b"secret"),
        ("your-256-bit-secret", b"your-256-bit-secret"),
        ("test", b"test"),
        ("foo", b"foo"),
    ]
    if HMAC_TEST_KEY.exists():
        raw = HMAC_TEST_KEY.read_bytes()
        out.insert(0, ("hmacTestKey", raw))
    return out


def source_interesting(path: str) -> bool:
    return path.endswith(("_test.go", ".md")) or path.startswith("test/")


def literal_contracts(version: str, published_at: str | None, tag: str) -> list[Contract]:
    out: list[Contract] = []
    secrets = hmac_candidates()
    for path in list_tree(REPO, tag):
        if not source_interesting(path):
            continue
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
                if "Parse" in text or "JWT" in text or "jwt" in text:
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
                        matched = (name, secret)
                        break
                options = {"ignoreExpiration": True, "ignoreNotBefore": True}
                if matched:
                    params: dict[str, Any] = {"token": token, "algorithm": alg, "options": options}
                    if matched[0] == "hmacTestKey":
                        params["secret_b64"] = base64.b64encode(matched[1]).decode()
                    else:
                        params["secret"] = matched[0]
                    add_contract(out, version, published_at, "jwt.verify.hmac-no-time", "verify_hmac", f"{slug}_{matched[0]}", params, {"ok": True}, evidence, "release-test-token-literal")
                elif parts[2]:
                    add_contract(out, version, published_at, "jwt.verify.hmac-invalid", "verify_hmac", f"{slug}_invalid_hmac", {"token": token, "algorithm": alg, "secret_b64": base64.b64encode(secrets[0][1]).decode(), "options": options}, {"ok": False}, evidence, "release-test-token-literal")
    return out


def scenario_specs() -> list[tuple[str, str, str, str, dict[str, Any], dict[str, Any], str]]:
    return [
        ("v1.0.0", "jwt.sign.hmac", "sign_hmac", "hs256_basic", {"algorithm": "HS256", "secret": "secret", "claims": {"foo": "bar"}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"foo": "bar"}, "verifies": True}, "public HMAC signing method"),
        ("v1.0.0", "jwt.sign.hmac", "sign_hmac", "hs384_basic", {"algorithm": "HS384", "secret": "secret", "claims": {"foo": "bar"}}, {"header": {"alg": "HS384", "typ": "JWT"}, "payload": {"foo": "bar"}, "verifies": True}, "public HMAC signing method"),
        ("v1.0.0", "jwt.sign.hmac", "sign_hmac", "hs512_basic", {"algorithm": "HS512", "secret": "secret", "claims": {"foo": "bar"}}, {"header": {"alg": "HS512", "typ": "JWT"}, "payload": {"foo": "bar"}, "verifies": True}, "public HMAC signing method"),
        ("v1.0.0", "jwt.sign.none", "sign_none", "unsafe_none_round_trip", {"claims": {"foo": "bar"}}, {"header": {"alg": "none", "typ": "JWT"}, "payload": {"foo": "bar"}, "verifies": True}, "none signing requires unsafe public sentinel"),
        ("v3.2.0", "jwt.verify.algorithm-policy", "verify_generated_hmac", "valid_methods_rejects_wrong_alg", {"algorithm": "HS256", "secret": "secret", "verifySecret": "secret", "claims": {"foo": "bar"}, "options": {"validMethods": ["HS384"]}}, {"ok": False}, "WithValidMethods / parser method allow-list"),
        ("v4.0.0", "jwt.verify.time", "verify_generated_hmac", "expired_rejected", {"algorithm": "HS256", "secret": "secret", "claims": {"foo": "bar", "exp": 2000000000}, "options": {"clockTimestamp": 2000000001}}, {"ok": False}, "MapClaims exp validation"),
        ("v4.0.0", "jwt.verify.time", "verify_generated_hmac", "future_nbf_rejected", {"algorithm": "HS256", "secret": "secret", "claims": {"foo": "bar", "nbf": 2000000010}, "options": {"clockTimestamp": 2000000000}}, {"ok": False}, "MapClaims nbf validation"),
        ("v5.0.0", "jwt.verify.leeway", "verify_generated_hmac", "nbf_leeway_accepts", {"algorithm": "HS256", "secret": "secret", "claims": {"foo": "bar", "nbf": 2000000010}, "options": {"clockTimestamp": 2000000000, "clockTolerance": 15}}, {"ok": True}, "WithLeeway parser option"),
        ("v5.0.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_match", {"algorithm": "HS256", "secret": "secret", "claims": {"iss": "me"}, "options": {"issuer": "me"}}, {"ok": True}, "WithIssuer parser option"),
        ("v5.0.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_mismatch", {"algorithm": "HS256", "secret": "secret", "claims": {"iss": "not-me"}, "options": {"issuer": "me"}}, {"ok": False}, "WithIssuer parser option"),
        ("v5.0.0", "jwt.verify.subject", "verify_generated_hmac", "subject_match", {"algorithm": "HS256", "secret": "secret", "claims": {"sub": "me"}, "options": {"subject": "me"}}, {"ok": True}, "WithSubject parser option"),
        ("v5.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_string_match", {"algorithm": "HS256", "secret": "secret", "claims": {"aud": "example.com"}, "options": {"audience": "example.com"}}, {"ok": True}, "WithAudience parser option"),
        ("v5.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_array_match", {"algorithm": "HS256", "secret": "secret", "claims": {"aud": ["example.org", "example.com"]}, "options": {"audience": "example.com"}}, {"ok": True}, "WithAudience accepts any member"),
        ("v5.0.0", "jwt.verify.required-claim", "verify_generated_hmac", "exp_required_missing", {"algorithm": "HS256", "secret": "secret", "claims": {"foo": "bar"}, "options": {"expirationRequired": True}}, {"ok": False}, "WithExpirationRequired parser option"),
        ("v5.0.0", "jwt.claim.accessor", "claim_get_audience", "aud_string_to_list", {"claims": {"aud": "example.com"}}, {"audience": ["example.com"], "error": False}, "MapClaims.GetAudience public accessor"),
        ("v5.0.0", "jwt.claim.accessor", "claim_get_audience", "aud_array_to_list", {"claims": {"aud": ["a", "b"]}}, {"audience": ["a", "b"], "error": False}, "MapClaims.GetAudience public accessor"),
        ("v5.0.0", "jwt.claim.accessor", "claim_get_audience", "aud_number_rejected", {"claims": {"aud": 123}}, {"error": True}, "MapClaims.GetAudience type error"),
    ]


def scenario_contracts(tag_dates: dict[str, str | None]) -> list[Contract]:
    out: list[Contract] = []
    for version, capability, op, slug, params, expected, note in scenario_specs():
        add_contract(out, version, tag_dates.get(version), capability, op, slug, params, expected, {"source": "VERSION_HISTORY.md/tests", "note": note}, "release-note-scenario")
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
        "project": "golang-jwt/jwt",
        "package": "github.com/golang-jwt/jwt/v5",
        "latest_version": tags[-1],
        "github": URL,
        "git_tags": len(tags),
        "release_rows": release_rows,
        "contracts_extracted": len(rows),
        "by_capability": dict(Counter(row["capability"] for row in rows)),
        "by_source_kind": dict(Counter(row["source_kind"] for row in rows)),
        "contracts": rows,
    }
    (BASE / "all_releases_language_independent.summary.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(rows, BASE / "all_releases_language_independent.rpl")

    counts = ["# golang-jwt/jwt Release Contract Counts", "", "| Version | Tag | Contracts seen | New unique contracts |", "| --- | --- | ---: | ---: |"]
    for row in release_rows:
        counts.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (BASE / "release_contract_counts.md").write_text("\n".join(counts) + "\n", encoding="utf-8")

    audit = [
        "# golang-jwt/jwt Contract Extraction Audit",
        "",
        f"- Git tags inspected: {len(tags)}",
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
    print(json.dumps({"latest_version": tags[-1], "git_tags": len(tags), "contracts_extracted": len(rows), "by_capability": payload["by_capability"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

