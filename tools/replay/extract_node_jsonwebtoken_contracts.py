#!/usr/bin/env python3
"""Extract replayable JWT contracts from auth0/node-jsonwebtoken release history."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "jwt" / "node-jsonwebtoken"
BASE = ROOT / "contracts" / "jwt" / "node-jsonwebtoken"
NPM_METADATA = "https://registry.npmjs.org/jsonwebtoken"
PRIOR_SURVIVORS = [
    ROOT / "contracts" / "jwt" / "auth0-java-jwt" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "jwt" / "pyjwt" / "latest_replay_mutant_verified.json",
]


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


JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")
JS_STRING_RE = re.compile(r"(?<![A-Za-z0-9_$])(['\"`])((?:\\.|(?!\1).)*?)\1", re.S)
HMAC_SECRETS = ["secret", "key", "shhhhh", "123", "superSecret", "your-256-bit-secret"]
REGISTERED = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}


def sh(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT)


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def fetch_npm_versions() -> tuple[str, dict[str, str | None]]:
    data = json.loads(urlopen(NPM_METADATA, timeout=45).read().decode("utf-8"))
    versions = {version: data.get("time", {}).get(version) for version in data["versions"]}
    return data["dist-tags"]["latest"], versions


def tag_for(version: str, tags: set[str]) -> str | None:
    for candidate in (f"v{version}", version):
        if candidate in tags:
            return candidate
    return None


def list_tree(tag: str) -> list[str]:
    try:
        return sh(["git", "ls-tree", "-r", "--name-only", tag], cwd=REPO).splitlines()
    except subprocess.CalledProcessError:
        return []


def git_show(tag: str, path: str) -> str | None:
    try:
        return sh(["git", "show", f"{tag}:{path}"], cwd=REPO)
    except subprocess.CalledProcessError:
        return None


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4))


def b64url_decode_json(part: str) -> Any:
    return json.loads(b64url_decode(part).decode("utf-8"))


def unescape_js_string(value: str) -> str:
    return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t").replace("\\'", "'").replace('\\"', '"')


def collect_candidate_texts(text: str) -> list[str]:
    literals = [unescape_js_string(match.group(2)) for match in JS_STRING_RE.finditer(text)]
    candidates = [text, *literals]
    for start in range(len(literals)):
        joined = ""
        for end in range(start, min(start + 8, len(literals))):
            joined += literals[end]
            if 20 <= len(joined) <= 4096:
                candidates.append(joined)
    return candidates


def token_signature_valid(token: str, secret: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = b64url_decode_json(parts[0])
    except Exception:
        return None
    alg = header.get("alg") if isinstance(header, dict) else None
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return None
    sig = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), digest).digest()
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
    for key in ("ok", "error", "accepted", "verifies", "mutated"):
        if key in expected and isinstance(expected[key], bool):
            return {**expected, key: not expected[key]}
    key = next(iter(expected))
    return {**expected, key: mutate_value(expected[key])}


def identity_from_row(row: dict[str, Any]) -> str:
    return json.dumps([row["capability"], row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)


def identity(contract: Contract) -> str:
    return identity_from_row(asdict(contract))


def prior_identity_set() -> set[str]:
    identities: set[str] = set()
    for path in PRIOR_SURVIVORS:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in data.get("survivor_contracts", []):
            identities.add(identity_from_row(row))
    return identities


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
    published_at: str | None,
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


def literal_contracts(version: str, published_at: str | None, tag: str) -> list[Contract]:
    out: list[Contract] = []
    for path in list_tree(tag):
        if not path.endswith(".js") or not (path.startswith("test/") or "/test/" in path):
            continue
        text = git_show(tag, path) or ""
        tokens: list[str] = []
        for candidate in collect_candidate_texts(text):
            tokens.extend(JWT_RE.findall(candidate))
        for index, token in enumerate(dict.fromkeys(tokens)):
            parts = token.split(".")
            evidence = {"tag": tag, "source": path, "literal_index": index}
            slug = f"{Path(path).stem}_{index:03d}"
            try:
                header = b64url_decode_json(parts[0])
                payload_bytes = b64url_decode(parts[1])
                if not isinstance(header, dict):
                    raise ValueError("header is not a JSON object")
            except Exception:
                add(out, version, "jwt.decode.errors", "decode_error", slug, {"token": token}, {"error": True}, evidence, "test-token-literal", published_at)
                continue

            try:
                payload = json.loads(payload_bytes.decode("utf-8"))
            except Exception:
                add(
                    out,
                    version,
                    "jwt.decode.string-payload",
                    "decode_unverified",
                    slug,
                    {"token": token},
                    {"payload": payload_bytes.decode("utf-8", errors="replace")},
                    evidence,
                    "test-token-literal",
                    published_at,
                )
                continue

            if not isinstance(payload, dict):
                add(out, version, "jwt.decode.non-object-payload", "decode_unverified", slug, {"token": token}, {"payload": payload}, evidence, "test-token-literal", published_at)
                continue

            add(
                out,
                version,
                "jwt.decode.complete-unverified",
                "decode_complete_unverified",
                slug,
                {"token": token},
                {"header": header, "payload": payload, "signature_b64": parts[2]},
                evidence,
                "test-token-literal",
                published_at,
            )
            for claim, value in payload.items():
                capability = "jwt.decode.registered-claim" if claim in REGISTERED else "jwt.decode.custom-claim"
                add(out, version, capability, "decode_claim_value_unverified", f"{slug}_{claim}", {"token": token, "claim": claim}, {"value": value}, evidence, "test-token-literal", published_at)
            for secret in HMAC_SECRETS:
                alg = token_signature_valid(token, secret)
                if alg and secret:
                    add(
                        out,
                        version,
                        "jwt.verify.hmac-no-time",
                        "verify_hmac",
                        f"{slug}_{secret}",
                        {"token": token, "algorithm": alg, "secret": secret, "options": {"ignoreExpiration": True, "ignoreNotBefore": True}},
                        {"ok": True},
                        evidence,
                        "test-token-literal",
                        published_at,
                    )
                    break
    return out


def scenario_specs() -> list[tuple[str, str, str, str, dict[str, Any], dict[str, Any], str]]:
    return [
        ("0.2.0", "jwt.decode.complete-unverified", "sign_decode_complete", "complete_header_payload_signature", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS256"}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"foo": "bar"}, "has_signature": True}, "complete decode returns header/payload/signature"),
        ("0.2.0", "jwt.verify.hmac", "sign_verify_hmac", "hs256_round_trip", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS256"}, {"ok": True, "payload": {"foo": "bar"}}, "HMAC sign/verify round trip"),
        ("0.2.0", "jwt.verify.hmac", "sign_verify_hmac", "wrong_secret_rejected", {"payload": {"foo": "bar"}, "secret": "secret", "verifySecret": "wrong", "algorithm": "HS256"}, {"ok": False, "error_name": "JsonWebTokenError"}, "wrong HMAC secret rejected"),
        ("1.1.0", "jwt.sign.algorithm", "sign_decode_complete", "hs384_header", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS384"}, {"header": {"alg": "HS384", "typ": "JWT"}, "payload": {"foo": "bar"}, "has_signature": True}, "HS384 support"),
        ("1.1.0", "jwt.sign.algorithm", "sign_decode_complete", "hs512_header", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS512"}, {"header": {"alg": "HS512", "typ": "JWT"}, "payload": {"foo": "bar"}, "has_signature": True}, "HS512 support"),
        ("4.2.1", "jwt.verify.algorithm-policy", "verify_generated_error", "wrong_allowlist_rejected", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"algorithms": ["HS384"]}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "invalid algorithm"}, "algorithm allow-list"),
        ("4.2.1", "jwt.verify.algorithm-policy", "verify_none_generated", "none_rejected_by_default", {"payload": {"iat": 60}, "verifyOptions": {}}, {"ok": False, "error_name": "JsonWebTokenError"}, "unsigned token rejected unless none is allowed"),
        ("4.2.1", "jwt.verify.algorithm-policy", "verify_none_generated", "none_allowed_explicitly", {"payload": {"iat": 60}, "verifyOptions": {"algorithms": ["none"]}}, {"ok": True, "payload": {"iat": 60}}, "unsigned token accepted with algorithms none"),
        ("5.0.0", "jwt.verify.clock-tolerance", "verify_literal_hmac", "expired_with_tolerance_accepts", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU", "secret": "key", "options": {"algorithms": ["HS256"], "clockTimestamp": 1437018594, "clockTolerance": 5}}, {"ok": True, "payload": {"foo": "bar", "iat": 1437018582, "exp": 1437018592}}, "clockTolerance accepts token expired within tolerance"),
        ("5.0.0", "jwt.verify.clock-tolerance", "verify_literal_hmac", "expired_outside_tolerance_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU", "secret": "key", "options": {"algorithms": ["HS256"], "clockTimestamp": 1437018650, "clockTolerance": 5}}, {"ok": False, "error_name": "TokenExpiredError", "expiredAt_ms": 1437018592000}, "clockTolerance still rejects outside window"),
        ("5.0.0", "jwt.verify.clock-timestamp", "verify_generated_error", "clock_timestamp_unexpired", {"payload": {"foo": "bar", "iat": 1000000000, "exp": 1000000001}, "secret": "key", "algorithm": "HS256", "verifyOptions": {"clockTimestamp": 1000000000}}, {"ok": True, "payload": {"foo": "bar", "iat": 1000000000, "exp": 1000000001}}, "clockTimestamp controls current time"),
        ("5.0.0", "jwt.verify.clock-timestamp", "verify_generated_error", "clock_timestamp_expired_at_boundary", {"payload": {"foo": "bar", "iat": 1000000000, "exp": 1000000001}, "secret": "key", "algorithm": "HS256", "verifyOptions": {"clockTimestamp": 1000000001}}, {"ok": False, "error_name": "TokenExpiredError", "expiredAt_ms": 1000000001000}, "expiration boundary"),
        ("5.0.0", "jwt.verify.clock-timestamp", "verify_generated_error", "clock_timestamp_type_rejected", {"payload": {"foo": "bar", "iat": 1000000000, "exp": 1000000001}, "secret": "key", "algorithm": "HS256", "verifyOptions": {"clockTimestamp": "notANumber"}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "clockTimestamp must be a number"}, "clockTimestamp type validation"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "expires_in_string_payload_rejected", {"payload": "a string payload", "secret": "secret", "options": {"algorithm": "HS256", "expiresIn": 100}}, {"error": True, "message_contains": "invalid expiresIn option for string payload"}, "expiresIn requires object payload"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "not_before_string_payload_rejected", {"payload": "a string payload", "secret": "secret", "options": {"algorithm": "HS256", "notBefore": 100}}, {"error": True, "message_contains": "invalid notBefore option for string payload"}, "notBefore requires object payload"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "audience_string_payload_rejected", {"payload": "a string payload", "secret": "secret", "options": {"algorithm": "HS256", "audience": "urn:foo"}}, {"error": True, "message_contains": "invalid audience option for string payload"}, "registered option requires object payload"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "issuer_conflict_rejected", {"payload": {"iss": "urn:payload"}, "secret": "secret", "options": {"algorithm": "HS256", "issuer": "urn:option"}}, {"error": True, "message_contains": "payload already has an \"iss\" property"}, "issuer option conflicts with payload iss"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "subject_conflict_rejected", {"payload": {"sub": "payload-sub"}, "secret": "secret", "options": {"algorithm": "HS256", "subject": "option-sub"}}, {"error": True, "message_contains": "payload already has an \"sub\" property"}, "subject option conflicts with payload sub"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "jwtid_conflict_rejected", {"payload": {"jti": "payload-jti"}, "secret": "secret", "options": {"algorithm": "HS256", "jwtid": "option-jti"}}, {"error": True, "message_contains": "payload already has an \"jti\" property"}, "jwtid option conflicts with payload jti"),
        ("5.0.2", "jwt.sign.options-validation", "sign_error", "deprecated_expiresInSeconds_rejected", {"payload": {"foo": "bar"}, "secret": "secret", "options": {"algorithm": "HS256", "expiresInSeconds": 5}}, {"error": True, "message_contains": "\"expiresInSeconds\" is not allowed"}, "deprecated option rejected"),
        ("5.0.2", "jwt.sign.claims", "sign_decode_complete", "audience_option_sets_aud", {"payload": {}, "secret": "secret", "algorithm": "HS256", "options": {"audience": "urn:foo", "noTimestamp": True}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"aud": "urn:foo"}, "has_signature": True}, "audience option maps to aud claim"),
        ("5.0.2", "jwt.sign.claims", "sign_decode_complete", "issuer_option_sets_iss", {"payload": {}, "secret": "secret", "algorithm": "HS256", "options": {"issuer": "urn:issuer", "noTimestamp": True}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"iss": "urn:issuer"}, "has_signature": True}, "issuer option maps to iss claim"),
        ("5.0.2", "jwt.sign.claims", "sign_decode_complete", "subject_option_sets_sub", {"payload": {}, "secret": "secret", "algorithm": "HS256", "options": {"subject": "user-123", "noTimestamp": True}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"sub": "user-123"}, "has_signature": True}, "subject option maps to sub claim"),
        ("5.0.2", "jwt.sign.claims", "sign_decode_complete", "jwtid_option_sets_jti", {"payload": {}, "secret": "secret", "algorithm": "HS256", "options": {"jwtid": "id-123", "noTimestamp": True}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"jti": "id-123"}, "has_signature": True}, "jwtid option maps to jti claim"),
        ("5.0.2", "jwt.sign.expires", "sign_decode_complete", "expires_in_uses_payload_iat", {"payload": {"iat": 60}, "secret": "secret", "algorithm": "HS256", "options": {"expiresIn": 10}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"iat": 60, "exp": 70}, "has_signature": True}, "expiresIn uses payload iat as base"),
        ("5.0.2", "jwt.sign.not-before", "sign_decode_complete", "not_before_uses_payload_iat", {"payload": {"iat": 60}, "secret": "secret", "algorithm": "HS256", "options": {"notBefore": 10}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"iat": 60, "nbf": 70}, "has_signature": True}, "notBefore uses payload iat as base"),
        ("5.5.0", "jwt.verify.audience", "verify_generated_error", "audience_regex_match", {"payload": {"aud": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"audience": {"regex": "^urn:f[o]{2}$"}}}, {"ok": True, "payload": {"aud": "urn:foo"}}, "RegExp audience option"),
        ("5.5.0", "jwt.verify.audience", "verify_generated_error", "audience_regex_mismatch", {"payload": {"aud": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"audience": {"regex": "^urn:no-match$"}}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "jwt audience invalid"}, "RegExp audience mismatch"),
        ("5.5.0", "jwt.verify.audience", "verify_generated_error", "audience_array_mixed_match", {"payload": {"aud": ["urn:foo", "urn:bar"]}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"audience": ["urn:no-match", {"regex": "^urn:b[a]r$"}]}}, {"ok": True, "payload": {"aud": ["urn:foo", "urn:bar"]}}, "mixed audience array"),
        ("7.2.0", "jwt.sign.header", "sign_decode_complete", "keyid_sets_kid", {"payload": {"foo": "bar"}, "secret": "secret", "algorithm": "HS256", "options": {"keyid": "kid-123", "noTimestamp": True}}, {"header": {"alg": "HS256", "typ": "JWT", "kid": "kid-123"}, "payload": {"foo": "bar"}, "has_signature": True}, "keyid option adds kid"),
        ("7.2.0", "jwt.sign.header", "sign_error", "keyid_type_rejected", {"payload": {"foo": "bar"}, "secret": "secret", "options": {"algorithm": "HS256", "keyid": 123}}, {"error": True, "message_contains": "\"keyid\" must be a string"}, "keyid validation"),
        ("7.3.0", "jwt.verify.complete", "verify_generated_complete", "complete_verify_shape", {"payload": {"foo": "bar", "iat": 60}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"complete": True, "clockTimestamp": 60}}, {"ok": True, "header": {"alg": "HS256", "typ": "JWT"}, "payload": {"foo": "bar", "iat": 60}, "has_signature": True}, "verify complete option"),
        ("7.3.0", "jwt.verify.input-validation", "verify_error", "non_string_token_rejected", {"tokenValue": {"kind": "object"}, "secret": "secret", "options": {}}, {"error": True, "message_contains": "jwt must be a string"}, "verify rejects non-string token"),
        ("7.3.0", "jwt.decode.errors", "decode_error", "jws_decode_error_becomes_null", {"token": "not.a.jwt"}, {"error": True}, "malformed compact token decode error"),
        ("7.4.2", "jwt.sign.secret-policy", "sign_error", "secret_required_for_hs256", {"payload": {"foo": "bar"}, "secret": None, "options": {"algorithm": "HS256"}}, {"error": True, "message_contains": "secretOrPrivateKey must have a value"}, "secret required for HMAC signing"),
        ("7.4.3", "jwt.sign.secret-policy", "sign_decode_complete", "empty_secret_allowed_for_none", {"payload": {"foo": "bar"}, "secret": "", "algorithm": "none", "options": {"noTimestamp": True}}, {"header": {"alg": "none", "typ": "JWT"}, "payload": {"foo": "bar"}, "has_signature": False}, "empty secret with none algorithm"),
        ("8.1.0", "jwt.verify.max-age", "verify_generated_error", "max_age_accepts_before_limit", {"payload": {"foo": "bar", "iat": 70}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"maxAge": "3s", "clockTimestamp": 72}}, {"ok": True, "payload": {"foo": "bar", "iat": 70}}, "maxAge accepts before limit"),
        ("8.1.0", "jwt.verify.max-age", "verify_generated_error", "max_age_rejects_at_limit", {"payload": {"foo": "bar", "iat": 70}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"maxAge": "3s", "clockTimestamp": 73}}, {"ok": False, "error_name": "TokenExpiredError", "message_contains": "maxAge exceeded"}, "maxAge boundary"),
        ("8.1.0", "jwt.verify.max-age", "verify_generated_error", "max_age_option_type_rejected", {"payload": {"foo": "bar", "iat": 70}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"maxAge": True, "clockTimestamp": 72}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "\"maxAge\" should be a number"}, "maxAge option validation"),
        ("8.1.1", "jwt.sign.not-before", "sign_decode_complete", "not_before_uses_payload_iat_after_fix", {"payload": {"iat": 120}, "secret": "secret", "algorithm": "HS256", "options": {"notBefore": "10s"}}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"iat": 120, "nbf": 130}, "has_signature": True}, "notBefore is based on iat"),
        ("8.2.0", "jwt.sign.mutate-payload", "sign_mutate_payload", "mutate_payload_true_adds_exp_to_input", {"payload": {"iat": 60}, "secret": "secret", "options": {"algorithm": "HS256", "expiresIn": 10, "mutatePayload": True}}, {"mutated": True, "payloadAfter": {"iat": 60, "exp": 70}}, "mutatePayload mutates input object"),
        ("8.2.0", "jwt.sign.mutate-payload", "sign_mutate_payload", "mutate_payload_false_preserves_input", {"payload": {"iat": 60}, "secret": "secret", "options": {"algorithm": "HS256", "expiresIn": 10, "mutatePayload": False}}, {"mutated": False, "payloadAfter": {"iat": 60}}, "default/false does not mutate input"),
        ("8.4.0", "jwt.verify.nonce", "verify_generated_error", "nonce_match_accepts", {"payload": {"nonce": "abcde"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"nonce": "abcde"}}, {"ok": True, "payload": {"nonce": "abcde"}}, "nonce option"),
        ("8.4.0", "jwt.verify.nonce", "verify_generated_error", "nonce_mismatch_rejected", {"payload": {"nonce": "abcde"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"nonce": "wrong"}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "jwt nonce invalid"}, "nonce mismatch"),
        ("8.4.0", "jwt.verify.nonce", "verify_generated_error", "nonce_type_rejected", {"payload": {"nonce": "abcde"}, "secret": "secret", "algorithm": "HS256", "verifyOptions": {"nonce": True}}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "nonce must be a non-empty string"}, "nonce option validation"),
        ("8.5.0", "jwt.sign.algorithm", "sign_decode_complete", "ps256_header", {"payload": {"foo": "bar"}, "keyFixture": "rsa-pss-private.pem", "algorithm": "PS256", "options": {"noTimestamp": True}}, {"header": {"alg": "PS256", "typ": "JWT"}, "payload": {"foo": "bar"}, "has_signature": True}, "PS256 support"),
        ("9.0.0", "jwt.security.key-policy", "rsa_min_key_size_sign", "rsa_1024_rejected_by_default", {"allowInsecureKeySizes": False}, {"error": True, "message_contains": "minimum key size of 2048 bits"}, "RSA private key size enforcement"),
        ("9.0.0", "jwt.security.key-policy", "rsa_min_key_size_sign", "rsa_1024_allowed_by_option", {"allowInsecureKeySizes": True}, {"error": False, "header": {"alg": "RS256", "typ": "JWT"}, "payload": {"foo": "bar"}}, "allowInsecureKeySizes override"),
        ("9.0.0", "jwt.security.key-policy", "key_confusion_verify", "rsa_public_key_not_hmac_secret_keyobject", {"keyFormat": "keyobject"}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "must be a symmetric key"}, "RSA key cannot verify HS token"),
        ("9.0.0", "jwt.security.key-policy", "key_confusion_verify", "rsa_public_key_not_hmac_secret_pem", {"keyFormat": "pem"}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "must be a symmetric key"}, "RSA PEM cannot verify HS token"),
        ("9.0.0", "jwt.security.key-policy", "malicious_key_material_rejected", "throwing_to_string_rejected", {}, {"error": True, "message_contains": "not valid key material"}, "malicious Buffer/toString key material rejected"),
        ("9.0.0", "jwt.security.asymmetric-policy", "invalid_asymmetric_key_type", "ec_key_for_rs_rejected", {"algorithm": "RS256", "keyFixture": "secp521r1-private.pem", "allowInvalidAsymmetricKeyTypes": False}, {"error": True, "message_contains": "\"alg\" parameter for \"ec\" key type"}, "key type must match algorithm"),
        ("9.0.0", "jwt.security.asymmetric-policy", "invalid_asymmetric_key_type", "ec_key_for_rs_allowed_by_option", {"algorithm": "RS256", "keyFixture": "secp521r1-private.pem", "allowInvalidAsymmetricKeyTypes": True}, {"error": False}, "legacy invalid asymmetric key option"),
        ("9.0.0", "jwt.verify.callback-secret", "verify_callback_secret", "callback_secret_accepts", {"mode": "ok"}, {"ok": True, "payload": {"foo": "bar", "iat": 1437018582, "exp": 1437018592}}, "secret provider callback"),
        ("9.0.0", "jwt.verify.callback-secret", "verify_callback_secret", "callback_secret_error_wrapped", {"mode": "error"}, {"ok": False, "error_name": "JsonWebTokenError", "message_contains": "error in secret or public key callback"}, "secret provider callback error"),
        ("9.0.0", "jwt.verify.callback-secret", "verify_callback_secret_sync_error", "callback_secret_requires_async_verify", {}, {"error": True, "message_contains": "verify must be called asynchronous"}, "secret callback requires async verify"),
    ]


def scenario_contracts(published_by_version: dict[str, str | None]) -> list[Contract]:
    out: list[Contract] = []
    for version, capability, op, slug, params, expected, note in scenario_specs():
        add(out, version, capability, op, slug, params, expected, {"source": "CHANGELOG.md/test suite", "note": note}, "release-note-scenario", published_by_version.get(version))
    return out


def write_rpl(contracts: list[Contract], path: Path) -> None:
    lines: list[str] = []
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
    latest, published_by_version = fetch_npm_versions()
    tags = set(sh(["git", "tag"], cwd=REPO).splitlines())
    prior_seen = prior_identity_set()
    seen: set[str] = set()
    contracts: list[Contract] = []
    release_rows: list[dict[str, Any]] = []
    prior_overlap_skipped = 0

    for version in sorted(published_by_version, key=version_key):
        tag = tag_for(version, tags)
        if not tag:
            release_rows.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0, "prior_overlap_skipped": 0})
            continue
        found = literal_contracts(version, published_by_version.get(version), tag)
        new = 0
        skipped = 0
        for contract in found:
            key = identity(contract)
            if key in prior_seen:
                prior_overlap_skipped += 1
                skipped += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            contracts.append(contract)
            new += 1
        release_rows.append({"version": version, "tag": tag, "contracts_seen": len(found), "new_contracts": new, "prior_overlap_skipped": skipped})

    for contract in scenario_contracts(published_by_version):
        key = identity(contract)
        if key in prior_seen:
            prior_overlap_skipped += 1
            continue
        if key in seen:
            continue
        seen.add(key)
        contracts.append(contract)
        for row in release_rows:
            if row["version"] == contract.version:
                row["contracts_seen"] += 1
                row["new_contracts"] += 1
                break

    payload = {
        "domain": "JWT Signing/Verification",
        "project": "auth0/node-jsonwebtoken",
        "package": "jsonwebtoken",
        "latest_version": latest,
        "npm_metadata": NPM_METADATA,
        "github": "https://github.com/auth0/node-jsonwebtoken",
        "npm_releases": len(published_by_version),
        "git_tags": len(tags),
        "prior_exact_overlap_skipped": prior_overlap_skipped,
        "release_rows": release_rows,
        "contracts_extracted": len(contracts),
        "by_capability": dict(Counter(c.capability for c in contracts)),
        "by_source_kind": dict(Counter(c.source_kind for c in contracts)),
        "contracts": [asdict(c) for c in contracts],
    }
    (BASE / "all_releases_language_independent.summary.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, BASE / "all_releases_language_independent.rpl")

    rows = ["# auth0/node-jsonwebtoken Release Contract Counts", "", "| Version | Tag | Contracts seen | New unique contracts | Prior exact overlap skipped |", "| --- | --- | ---: | ---: | ---: |"]
    for row in release_rows:
        rows.append(f"| `{row['version']}` | `{row['tag'] or ''}` | {row['contracts_seen']} | {row['new_contracts']} | {row['prior_overlap_skipped']} |")
    (BASE / "release_contract_counts.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    audit = [
        "# auth0/node-jsonwebtoken Contract Extraction Audit",
        "",
        f"- npm releases inspected: {len(published_by_version)}",
        f"- Git tags available: {len(tags)}",
        f"- Extracted semantic contracts: {len(contracts)}",
        f"- Exact prior-survivor overlaps skipped: {prior_overlap_skipped}",
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
    print(json.dumps({k: payload[k] for k in ["latest_version", "npm_releases", "git_tags", "contracts_extracted", "prior_exact_overlap_skipped", "by_capability", "by_source_kind"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
