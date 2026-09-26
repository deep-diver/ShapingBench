#!/usr/bin/env python3
"""Extract replayable JWT contracts from auth0/java-jwt release history."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "jwt" / "java-jwt"
BASE = ROOT / "contracts" / "jwt" / "auth0-java-jwt"
MAVEN_METADATA = "https://repo1.maven.org/maven2/com/auth0/java-jwt/maven-metadata.xml"


@dataclass(frozen=True)
class Contract:
    name: str
    version: str
    published_at: str | None
    capability: str
    op: str
    params: dict[str, Any]
    expected: dict[str, Any]
    mutant: dict[str, Any]
    evidence: dict[str, Any]
    source_kind: str


def sh(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT)


def fetch_versions() -> list[str]:
    raw = urlopen(MAVEN_METADATA, timeout=30).read().decode("utf-8")
    return re.findall(r"<version>([^<]+)</version>", raw)


def tag_for(version: str, tags: set[str]) -> str | None:
    for candidate in (version, f"java-jwt-{version}", f"v{version}"):
        if candidate in tags:
            return candidate
    return None


def git_show(tag: str, path: str) -> str | None:
    try:
        return sh(["git", "show", f"{tag}:{path}"], cwd=REPO)
    except subprocess.CalledProcessError:
        return None


def list_tree(tag: str) -> list[str]:
    try:
        raw = sh(["git", "ls-tree", "-r", "--name-only", tag], cwd=REPO)
    except subprocess.CalledProcessError:
        return []
    return raw.splitlines()


def b64url_decode_json(part: str) -> Any:
    padded = part + "=" * ((4 - len(part) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))


JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")


def token_signature_valid(token: str, secret: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = b64url_decode_json(parts[0])
    except Exception:
        return None
    alg = header.get("alg")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return None
    signed = f"{parts[0]}.{parts[1]}".encode()
    sig = hmac.new(secret.encode(), signed, digest).digest()
    actual = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return alg if hmac.compare_digest(actual, parts[2]) else None


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if value is None:
        return "__mutant__"
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return value + ["__mutant__"]
    if isinstance(value, dict):
        out = dict(value)
        out["__mutant__"] = True
        return out
    return "__mutant__"


def with_mutant(expected: dict[str, Any]) -> dict[str, Any]:
    if "ok" in expected:
        return {**expected, "ok": not expected["ok"]}
    if "error" in expected:
        return {**expected, "error": not expected["error"]}
    key = next(iter(expected))
    return {**expected, key: mutate_value(expected[key])}


def add(
    out: list[Contract],
    version: str,
    capability: str,
    op: str,
    slug: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    evidence: dict[str, Any],
    source_kind: str,
    published_at: str | None = None,
) -> None:
    out.append(
        Contract(
            name=f"{version}:{op}:{slug}",
            version=version,
            published_at=published_at,
            capability=capability,
            op=op,
            params=params,
            expected=expected,
            mutant=with_mutant(expected),
            evidence=evidence,
            source_kind=source_kind,
        )
    )


def literal_contracts(version: str, tag: str) -> list[Contract]:
    out: list[Contract] = []
    for path in list_tree(tag):
        if not path.endswith(".java") or "/src/test/" not in path:
            continue
        text = git_show(tag, path) or ""
        for index, token in enumerate(dict.fromkeys(JWT_RE.findall(text))):
            parts = token.split(".")
            evidence = {"tag": tag, "source": path, "literal_index": index}
            try:
                header = b64url_decode_json(parts[0])
                payload = b64url_decode_json(parts[1])
            except Exception:
                if "JWT.decode" in text[max(0, text.find(token) - 120) : text.find(token) + len(token) + 120]:
                    add(
                        out,
                        version,
                        "jwt.decode.errors",
                        "decode_error",
                        f"{Path(path).stem}_{index:03d}",
                        {"token": token},
                        {"error": True},
                        evidence,
                        "test-jwt-literal",
                    )
                continue
            slug = f"{Path(path).stem}_{index:03d}"
            add(
                out,
                version,
                "jwt.decode.payload-json",
                "decode_payload_json",
                slug,
                {"token": token},
                {"header": header, "payload": payload},
                evidence,
                "test-jwt-literal",
            )
            alg = token_signature_valid(token, "secret")
            if alg:
                time_claims_valid = all(
                    not isinstance(payload, dict)
                    or claim not in payload
                    or isinstance(payload[claim], (int, float))
                    for claim in ("exp", "nbf", "iat")
                )
                verify_params: dict[str, Any] = {"token": token, "algorithm": alg, "secret": "secret", "checks": {}}
                if isinstance(payload, dict) and time_claims_valid:
                    after_not_before = [int(payload[claim]) + 1 for claim in ("nbf", "iat") if claim in payload]
                    before_expires = [int(payload["exp"]) - 1] if "exp" in payload else []
                    if after_not_before or before_expires:
                        clock = max(after_not_before or [0])
                        if before_expires:
                            clock = min(clock, before_expires[0]) if clock else before_expires[0]
                        verify_params["clock"] = clock
                if not time_claims_valid:
                    alg = None

            if alg:
                add(
                    out,
                    version,
                    "jwt.verify.hmac",
                    "verify_hmac",
                    slug,
                    verify_params,
                    {"ok": True},
                    evidence,
                    "test-jwt-literal",
                )

            if isinstance(payload, dict):
                for claim, value in payload.items():
                    cap = "jwt.decode.registered-claim" if claim in {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} else "jwt.decode.custom-claim"
                    add(
                        out,
                        version,
                        cap,
                        "decode_claim_value",
                        f"{slug}_{claim}",
                        {"token": token, "claim": claim},
                        {"value": value},
                        evidence,
                        "test-jwt-literal",
                    )
    return out


def scenario_specs() -> list[tuple[str, str, str, str, dict[str, Any], dict[str, Any], str]]:
    return [
        ("3.0.0", "jwt.sign.hmac", "sign_hmac", "hs256_basic", {"algorithm": "HS256", "secret": "secret", "claims": {"sub": "1234567890"}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"sub": "1234567890"}, "verifies": True}, "CHANGELOG available algorithm table"),
        ("3.0.0", "jwt.sign.hmac", "sign_hmac", "hs384_basic", {"algorithm": "HS384", "secret": "secret", "claims": {"sub": "1234567890"}}, {"header": {"alg": "HS384", "typ": "JWT"}, "payload": {"sub": "1234567890"}, "verifies": True}, "CHANGELOG available algorithm table"),
        ("3.0.0", "jwt.sign.hmac", "sign_hmac", "hs512_basic", {"algorithm": "HS512", "secret": "secret", "claims": {"sub": "1234567890"}}, {"header": {"alg": "HS512", "typ": "JWT"}, "payload": {"sub": "1234567890"}, "verifies": True}, "CHANGELOG available algorithm table"),
        ("3.0.0", "jwt.verify.algorithm-policy", "verify_hmac", "wrong_algorithm_rejected", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho", "algorithm": "HS512", "secret": "secret", "checks": {}}, {"ok": False, "error_kind": "AlgorithmMismatchException"}, "JWTVerifierTest algorithm mismatch"),
        ("3.0.0", "jwt.verify.issuer", "verify_hmac", "issuer_match", {"token": "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M", "algorithm": "HS256", "secret": "secret", "checks": {"issuer": ["auth0"]}}, {"ok": True}, "JWTVerifierTest shouldValidateIssuer"),
        ("3.0.0", "jwt.verify.issuer", "verify_hmac", "issuer_mismatch", {"token": "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M", "algorithm": "HS256", "secret": "secret", "checks": {"issuer": ["invalid"]}}, {"ok": False, "error_kind": "IncorrectClaimException"}, "JWTVerifierTest shouldThrowOnInvalidIssuer"),
        ("3.0.0", "jwt.verify.subject", "verify_hmac", "subject_match", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I", "algorithm": "HS256", "secret": "secret", "checks": {"subject": "1234567890"}}, {"ok": True}, "JWTVerifierTest shouldValidateSubject"),
        ("3.0.0", "jwt.verify.subject", "verify_hmac", "subject_mismatch", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I", "algorithm": "HS256", "secret": "secret", "checks": {"subject": "invalid"}}, {"ok": False, "error_kind": "IncorrectClaimException"}, "JWTVerifierTest shouldThrowOnInvalidSubject"),
        ("3.1.0", "jwt.sign.claim-array", "sign_hmac", "string_array_claim", {"algorithm": "HS256", "secret": "secret", "claims": {"name": ["text", "123", "true"]}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"name": ["text", "123", "true"]}, "verifies": True}, "CHANGELOG #123 array creation/verification"),
        ("3.2.0", "jwt.sign.header", "sign_hmac", "kid_header", {"algorithm": "HS256", "secret": "secret", "headers": {"kid": "56a8bd44da435300010000015f5ed"}, "claims": {}}, {"header": {"alg": "HS256", "typ": "JWT", "kid": "56a8bd44da435300010000015f5ed"}, "payload": {}, "verifies": True}, "CHANGELOG #138 key id setter"),
        ("3.8.0", "jwt.verify.issuer", "verify_hmac", "multiple_issuer_match", {"token": "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJvdGhlcklzc3VlciJ9.k4BCOJJl-c0_Y-49VD_mtt-u0QABKSV5i3W-RKc74co", "algorithm": "HS256", "secret": "secret", "checks": {"issuer": ["auth0", "otherIssuer"]}}, {"ok": True}, "CHANGELOG #288 multiple issuers"),
        ("3.10.0", "jwt.sign.header", "sign_hmac", "custom_typ_header", {"algorithm": "HS256", "secret": "secret", "headers": {"typ": "passport"}, "claims": {}}, {"header": {"alg": "HS256", "typ": "passport"}, "payload": {}, "verifies": True}, "CHANGELOG #381 customize typ"),
        ("3.11.0", "jwt.verify.claim-presence", "verify_hmac", "claim_presence_present", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbU5hbWUiOiJjbGFpbVZhbHVlIn0.9aChFOlwTT56malAI6s8hOX4_WjZp3ulkp6hPLqm4ek", "algorithm": "HS256", "secret": "secret", "checks": {"claim_presence": ["claimName"]}}, {"ok": True}, "CHANGELOG #442 claim presence"),
        ("3.13.0", "jwt.verify.audience", "verify_hmac", "any_of_audience_match", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiTWFyayIsIkRhdmlkIiwiSm9obiJdfQ.DX5xXiCaYvr54x_iL0LZsJhK7O6HhAdHeDYkgDeb0Rw", "algorithm": "HS256", "secret": "secret", "checks": {"any_of_audience": ["Jim", "John"]}}, {"ok": True}, "CHANGELOG #472 any-of audience"),
        ("4.0.0", "jwt.sign.claim-null", "sign_hmac", "null_claim", {"algorithm": "HS256", "secret": "secret", "claims": {"claimName": None}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"claimName": None}, "verifies": True}, "CHANGELOG v4 consistent null handling"),
        ("4.3.0", "jwt.verify.time", "verify_hmac", "exp_equal_now_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Nzc1OTJ9.isvT0Pqx0yjnZk53mUFSeYFJLDs-Ls9IsNAm86gIdZo", "algorithm": "HS256", "secret": "secret", "clock": 1477592, "checks": {}}, {"ok": False, "error_kind": "TokenExpiredException"}, "CHANGELOG #652 exp equal now invalid"),
        ("4.5.0", "jwt.decode.audience", "decode_claim_value", "empty_string_audience", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIifQ.lSU1tR27rKzgaP22nAu6x-KJF4AwbOYsFbBc3u8FLA4", "claim": "aud"}, {"value": ""}, "CHANGELOG #663 empty string audience"),
        ("4.5.0", "jwt.verify.audience", "verify_hmac", "empty_expected_audience_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ3aWRlIGF1ZGllbmNlIn0.c9anq03XepcuEKWEVsPk9cck0sIIfrT6hHbBsCar49o", "algorithm": "HS256", "secret": "secret", "checks": {"any_of_audience": []}}, {"ok": False, "error_kind": "IncorrectClaimException"}, "CHANGELOG #679 empty expected audience"),
        ("4.6.0", "jwt.sign.rsassa-pss", "sign_rsa_pss", "ps256_round_trip", {"algorithm": "PS256", "claims": {"iss": "auth0", "pss": "supported"}}, {"header": {"alg": "PS256", "typ": "JWT"}, "payload": {"iss": "auth0", "pss": "supported"}, "verifies": True}, "CHANGELOG #788 PS256/PS384/PS512 support"),
        ("4.6.0", "jwt.sign.rsassa-pss", "sign_rsa_pss", "ps384_round_trip", {"algorithm": "PS384", "claims": {"iss": "auth0", "pss": "supported"}}, {"header": {"alg": "PS384", "typ": "JWT"}, "payload": {"iss": "auth0", "pss": "supported"}, "verifies": True}, "CHANGELOG #788 PS256/PS384/PS512 support"),
        ("4.6.0", "jwt.sign.rsassa-pss", "sign_rsa_pss", "ps512_round_trip", {"algorithm": "PS512", "claims": {"iss": "auth0", "pss": "supported"}}, {"header": {"alg": "PS512", "typ": "JWT"}, "payload": {"iss": "auth0", "pss": "supported"}, "verifies": True}, "CHANGELOG #788 PS256/PS384/PS512 support"),
    ]


def scenario_contracts() -> list[Contract]:
    out: list[Contract] = []
    for version, capability, op, slug, params, expected, evidence_text in scenario_specs():
        add(
            out,
            version,
            capability,
            op,
            slug,
            params,
            expected,
            {"source": "CHANGELOG.md", "note": evidence_text},
            "release-note-scenario",
        )
    return out


def identity(contract: Contract) -> str:
    data = asdict(contract)
    return json.dumps([data["capability"], data["op"], data["params"], data["expected"]], sort_keys=True, ensure_ascii=True)


def write_rpl(contracts: list[Contract], path: Path) -> None:
    lines = []
    for contract in contracts:
        row = asdict(contract)
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    BASE.mkdir(parents=True, exist_ok=True)
    versions = fetch_versions()
    tags = set(sh(["git", "tag"], cwd=REPO).splitlines())
    release_rows = []
    contracts: list[Contract] = []
    seen: set[str] = set()
    for version in versions:
        tag = tag_for(version, tags)
        if not tag:
            release_rows.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        found = literal_contracts(version, tag)
        new = 0
        for contract in found:
            key = identity(contract)
            if key in seen:
                continue
            seen.add(key)
            contracts.append(contract)
            new += 1
        release_rows.append({"version": version, "tag": tag, "contracts_seen": len(found), "new_contracts": new})

    for contract in scenario_contracts():
        key = identity(contract)
        if key not in seen:
            seen.add(key)
            contracts.append(contract)
            for row in release_rows:
                if row["version"] == contract.version:
                    row["contracts_seen"] += 1
                    row["new_contracts"] += 1
                    break

    payload = {
        "domain": "JWT Signing/Verification",
        "project": "auth0/java-jwt",
        "package": "com.auth0:java-jwt",
        "latest_version": versions[-1],
        "maven_metadata": MAVEN_METADATA,
        "github": "https://github.com/auth0/java-jwt",
        "maven_versions": len(versions),
        "git_tags": len(tags),
        "release_rows": release_rows,
        "contracts_extracted": len(contracts),
        "by_capability": dict(Counter(c.capability for c in contracts)),
        "by_source_kind": dict(Counter(c.source_kind for c in contracts)),
        "contracts": [asdict(c) for c in contracts],
    }
    (BASE / "all_releases_language_independent.summary.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, BASE / "all_releases_language_independent.rpl")
    counts = ["# auth0/java-jwt Release Contract Counts", "", "| Version | Tag | Contracts seen | New unique contracts |", "| --- | --- | ---: | ---: |"]
    for row in release_rows:
        counts.append(f"| `{row['version']}` | `{row['tag'] or ''}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (BASE / "release_contract_counts.md").write_text("\n".join(counts) + "\n", encoding="utf-8")
    audit = [
        "# auth0/java-jwt Contract Extraction Audit",
        "",
        f"- Maven versions inspected: {len(versions)}",
        f"- Git tags available: {len(tags)}",
        f"- Extracted semantic contracts: {len(contracts)}",
        "",
        "## By Capability",
        "",
        "| Capability | Contracts |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(payload["by_capability"].items()):
        audit.append(f"| `{cap}` | {count} |")
    audit.extend(["", "## By Source Kind", "", "| Source kind | Contracts |", "| --- | ---: |"])
    for kind, count in sorted(payload["by_source_kind"].items()):
        audit.append(f"| `{kind}` | {count} |")
    (BASE / "extraction_audit.md").write_text("\n".join(audit) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ["latest_version", "maven_versions", "contracts_extracted", "by_capability", "by_source_kind"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
