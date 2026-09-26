#!/usr/bin/env python3
"""Extract replayable JWT contracts from jpadilla/pyjwt release history."""

from __future__ import annotations

import ast
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
REPO = ROOT / ".cache" / "jwt" / "pyjwt"
BASE = ROOT / "contracts" / "jwt" / "pyjwt"
PYPI_METADATA = "https://pypi.org/pypi/PyJWT/json"
AUTH0_SURVIVORS = ROOT / "contracts" / "jwt" / "auth0-java-jwt" / "latest_replay_mutant_verified.json"


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
HMAC_SECRETS = ["secret", "foo", "your-256-bit-secret", ""]


def sh(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT)


def version_key(version: str) -> tuple:
    parts = re.split(r"([0-9]+|[A-Za-z]+)", version)
    out: list[tuple[int, Any]] = []
    for part in parts:
        if not part or part in ".-_":
            continue
        out.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(out)


def fetch_pypi_versions() -> tuple[str, dict[str, str | None]]:
    data = json.loads(urlopen(PYPI_METADATA, timeout=30).read().decode("utf-8"))
    versions: dict[str, str | None] = {}
    for version, files in data["releases"].items():
        published = None
        if files:
            published = files[0].get("upload_time_iso_8601")
        versions[version] = published
    return data["info"]["version"], versions


def tag_for(version: str, tags: set[str]) -> str | None:
    for candidate in (version, f"v{version}", f"pyjwt-{version}"):
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


class LiteralCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.values: list[str] = []

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.values.append(node.value)
        elif isinstance(node.value, bytes):
            try:
                self.values.append(node.value.decode("ascii"))
            except UnicodeDecodeError:
                pass


def collect_literals(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [match.group(2) for match in re.finditer(r"[rubfRUBF]*(['\"])(.*?)\1", text, re.S)]
    collector = LiteralCollector()
    collector.visit(tree)
    return collector.values


def token_signature_valid(token: str, secret: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = b64url_decode_json(parts[0])
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    alg = header.get("alg")
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
    if "ok" in expected:
        return {**expected, "ok": not expected["ok"]}
    if "error" in expected:
        return {**expected, "error": not expected["error"]}
    if "accepted" in expected:
        return {**expected, "accepted": not expected["accepted"]}
    key = next(iter(expected))
    return {**expected, key: mutate_value(expected[key])}


def identity(contract: Contract) -> str:
    row = asdict(contract)
    return json.dumps([row["capability"], row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)


def auth0_identity_set() -> set[str]:
    if not AUTH0_SURVIVORS.exists():
        return set()
    data = json.loads(AUTH0_SURVIVORS.read_text(encoding="utf-8"))
    identities = set()
    for row in data.get("survivor_contracts", []):
        identities.add(json.dumps([row["capability"], row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True))
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
        if not path.endswith(".py") or not (path.startswith("tests/") or "/tests/" in path):
            continue
        text = git_show(tag, path) or ""
        literals = "\n".join(str(value) for value in collect_literals(text))
        for index, token in enumerate(dict.fromkeys(JWT_RE.findall(literals))):
            parts = token.split(".")
            evidence = {"tag": tag, "source": path, "literal_index": index}
            slug = f"{Path(path).stem}_{index:03d}"
            try:
                header = b64url_decode_json(parts[0])
                payload_bytes = b64url_decode(parts[1])
                if not isinstance(header, dict):
                    raise ValueError("header is not a JSON object")
            except Exception:
                add(out, version, published_at=published_at, capability="jwt.decode.errors", op="decode_error", slug=slug, params={"token": token}, expected={"error": True}, evidence=evidence, source_kind="test-token-literal")
                continue

            add(out, version, published_at=published_at, capability="jwt.header.unverified", op="get_unverified_header", slug=slug, params={"token": token}, expected={"header": header}, evidence=evidence, source_kind="test-token-literal")
            signature_b64 = parts[2]
            try:
                payload = json.loads(payload_bytes.decode("utf-8"))
                if isinstance(payload, dict):
                    add(out, version, published_at=published_at, capability="jwt.decode.complete-unverified", op="decode_complete_unverified", slug=slug, params={"token": token}, expected={"header": header, "payload": payload, "signature_b64": signature_b64}, evidence=evidence, source_kind="test-token-literal")
                    for claim, value in payload.items():
                        cap = "jwt.decode.registered-claim" if claim in {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} else "jwt.decode.custom-claim"
                        add(out, version, published_at=published_at, capability=cap, op="decode_claim_value_unverified", slug=f"{slug}_{claim}", params={"token": token, "claim": claim}, expected={"value": value}, evidence=evidence, source_kind="test-token-literal")
                    for secret in HMAC_SECRETS:
                        alg = token_signature_valid(token, secret)
                        if alg and secret:
                            params: dict[str, Any] = {"token": token, "algorithm": alg, "secret": secret, "checks": {}, "options": {"verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_aud": False}}
                            add(out, version, published_at=published_at, capability="jwt.verify.hmac-no-time", op="verify_hmac", slug=f"{slug}_{secret or 'empty'}", params=params, expected={"ok": True}, evidence=evidence, source_kind="test-token-literal")
                            break
                else:
                    add(out, version, published_at=published_at, capability="jwt.decode.errors", op="jwt_payload_must_be_object", slug=slug, params={"token": token, "secret": "secret", "algorithm": header.get("alg", "HS256")}, expected={"error": True, "error_kind": "DecodeError"}, evidence=evidence, source_kind="test-token-literal")
            except Exception:
                add(out, version, published_at=published_at, capability="jws.decode.bytes-unverified", op="jws_decode_bytes_unverified", slug=slug, params={"token": token}, expected={"payload_b64": parts[1]}, evidence=evidence, source_kind="test-token-literal")
                for secret in HMAC_SECRETS:
                    alg = token_signature_valid(token, secret)
                    if alg and secret:
                        add(out, version, published_at=published_at, capability="jws.verify.hmac", op="jws_verify_hmac", slug=f"{slug}_{secret}", params={"token": token, "algorithm": alg, "secret": secret}, expected={"ok": True, "payload_b64": parts[1]}, evidence=evidence, source_kind="test-token-literal")
                        break
    return out


def scenario_specs() -> list[tuple[str, str, str, str, dict[str, Any], dict[str, Any], str]]:
    return [
        ("0.4.0", "jwt.sign.none", "sign_none", "none_unverified_round_trip", {"claims": {"some": "payload"}}, {"header": {"alg": "none", "typ": "JWT"}, "payload": {"some": "payload"}, "verifies": True}, "none algorithm support"),
        ("1.0.0", "jwt.verify.required-claim", "verify_generated_hmac", "require_exp_missing", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "options": {"require": ["exp"]}}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "exp"}, "required exp option"),
        ("1.0.0", "jwt.verify.required-claim", "verify_generated_hmac", "require_iat_missing", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "options": {"require": ["iat"]}}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "iat"}, "required iat option"),
        ("1.0.0", "jwt.verify.required-claim", "verify_generated_hmac", "require_nbf_missing", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "options": {"require": ["nbf"]}}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "nbf"}, "required nbf option"),
        ("1.1.0", "jwt.verify.signature-option", "verify_hmac", "skip_signature_with_wrong_secret", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZA", "secret": "wrong", "algorithm": "HS256", "options": {"verify_signature": False}, "checks": {}}, {"ok": True}, "verify_signature false skips signature"),
        ("1.4.0", "jwt.verify.leeway", "verify_generated_hmac_relative", "expired_with_5s_leeway_accepts", {"claims": {"exp": {"now_offset_seconds": -2}, "some": "payload"}, "secret": "secret", "algorithm": "HS256", "leeway": 5}, {"ok": True}, "expiration leeway"),
        ("1.4.0", "jwt.verify.leeway", "verify_generated_hmac_relative", "expired_with_1s_leeway_rejects", {"claims": {"exp": {"now_offset_seconds": -2}, "some": "payload"}, "secret": "secret", "algorithm": "HS256", "leeway": 1}, {"ok": False, "error_kind": "ExpiredSignatureError"}, "expiration leeway"),
        ("1.4.0", "jwt.verify.leeway", "verify_generated_hmac_relative", "nbf_with_13s_leeway_accepts", {"claims": {"nbf": {"now_offset_seconds": 10}, "some": "payload"}, "secret": "secret", "algorithm": "HS256", "leeway": 13}, {"ok": True}, "not-before leeway"),
        ("1.4.0", "jwt.verify.leeway", "verify_generated_hmac_relative", "nbf_with_1s_leeway_rejects", {"claims": {"nbf": {"now_offset_seconds": 10}, "some": "payload"}, "secret": "secret", "algorithm": "HS256", "leeway": 1}, {"ok": False, "error_kind": "ImmatureSignatureError"}, "not-before leeway"),
        ("1.5.0", "jwt.sign.datetime", "sign_datetime_claims", "datetime_claims_encode_numericdate", {"claims": {"exp": 2000000000, "iat": 2000000000, "nbf": 2000000000}, "secret": "secret", "algorithm": "HS256"}, {"payload": {"exp": 2000000000, "iat": 2000000000, "nbf": 2000000000}}, "datetime claims encoded as NumericDate"),
        ("1.5.0", "jwt.verify.claim-type", "verify_hmac", "exp_string_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiJub3QtYW4taW50In0.P65iYgoHtBqB07PMtBSuKNUEIPPPfmjfJG217cEE66s", "secret": "secret", "algorithm": "HS256", "checks": {}}, {"ok": False, "error_kind": "DecodeError"}, "exp must be numeric"),
        ("1.5.0", "jwt.verify.claim-type", "verify_hmac", "iat_string_non_numeric_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOiJub3QtYW4taW50In0.H1GmcQgSySa5LOKYbzGm--b1OmRbHFkyk8pq811FzZM", "secret": "secret", "algorithm": "HS256", "checks": {}}, {"ok": False, "error_kind": "InvalidIssuedAtError"}, "iat must be numeric"),
        ("1.5.0", "jwt.verify.claim-type", "verify_hmac", "nbf_string_rejected", {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOiJub3QtYW4taW50In0.c25hldC8G2ZamC8uKpax9sYMTgdZo3cxrmzFHaAAluw", "secret": "secret", "algorithm": "HS256", "checks": {}}, {"ok": False, "error_kind": "DecodeError"}, "nbf must be numeric"),
        ("1.6.0", "jwt.sign.header", "sign_hmac", "custom_typ_header", {"claims": {"iss": "https://scim.example.com"}, "secret": "secret", "algorithm": "HS256", "headers": {"typ": "secevent+jwt"}}, {"header": {"alg": "HS256", "typ": "secevent+jwt"}, "payload": {"iss": "https://scim.example.com"}, "verifies": True}, "custom typ header"),
        ("1.6.0", "jwt.sign.json-encoder", "sign_decimal_json_encoder", "decimal_serialized_by_custom_encoder", {"claims": {"some_decimal": "2.2"}, "secret": "secret", "algorithm": "HS256"}, {"payload": {"some_decimal": "it worked"}}, "custom JSON encoder can serialize Decimal"),
        ("1.7.0", "jwt.jwk.hmac", "hmac_to_jwk", "secret_to_oct_jwk", {"secret": "secret"}, {"jwk": {"kty": "oct", "k": "c2VjcmV0"}}, "HMAC to JWK"),
        ("1.7.0", "jwt.jwk.hmac", "hmac_from_jwk_round_trip", "oct_jwk_sign_verify", {"jwk": {"kty": "oct", "k": "c2VjcmV0"}, "message": "Hello World!"}, {"ok": True}, "HMAC from JWK sign/verify"),
        ("1.7.0", "jwt.jwk.reject", "hmac_from_jwk_error", "empty_jwk_rejected", {"jwk": {}}, {"error": True, "error_kind": "InvalidKeyError"}, "empty JWK rejected"),
        ("2.0.0", "jws.algorithm-registry", "jws_algorithm_registry", "register_duplicate_rejected", {"action": "duplicate_register"}, {"error": True, "error_kind": "ValueError"}, "PyJWS algorithm registry"),
        ("2.0.0", "jws.algorithm-registry", "jws_algorithm_registry", "unregister_removes_algorithm", {"action": "unregister", "algorithm": "HS256"}, {"contains_before": True, "contains_after": False}, "PyJWS unregister algorithm"),
        ("2.0.0", "jws.verify.algorithm-policy", "jws_generated_verify", "case_sensitive_alg_rejected", {"payload": "hello world", "secret": "secret", "sign_algorithm": "HS256", "verify_algorithms": ["hs256"]}, {"ok": False, "error_kind": "InvalidAlgorithmError"}, "algorithm names are case-sensitive"),
        ("2.0.0", "jws.decode.bytes", "jws_sign_verify_hmac", "jws_bytes_round_trip", {"payload": "hello world", "secret": "secret", "algorithm": "HS256"}, {"ok": True, "payload_b64": "aGVsbG8gd29ybGQ"}, "JWS bytes payload"),
        ("2.0.0", "jwt.decode.complete-unverified", "decode_complete_unverified_generated", "complete_has_signature_b64", {"claims": {"hello": "world"}, "secret": "secret", "algorithm": "HS256"}, {"header": {"alg": "HS256", "typ": "JWT"}, "payload": {"hello": "world"}, "has_signature": True}, "decode_complete exposes header/payload/signature"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_algorithm_name", "oct_key_algorithm_name", {"jwk": {"kty": "oct", "alg": "HS384", "k": "c2VjcmV0"}}, {"algorithm_name": "HS384", "key_type": "oct"}, "PyJWK algorithm_name"),
        ("2.7.0", "jwt.algorithm.digest", "compute_hash_digest", "hs256_digest", {"algorithm": "HS256", "message": "hello world"}, {"digest_hex": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}, "Algorithm.compute_hash_digest"),
        ("2.7.0", "jwt.jwks.client", "jwks_client_headers_forwarded", "headers_forwarded", {"url": "https://example.test/jwks.json", "headers": {"User-agent": "my-custom-agent"}}, {"request_url": "https://example.test/jwks.json", "headers": {"User-agent": "my-custom-agent"}, "key_count": 1}, "PyJWKClient forwards headers"),
        ("2.7.0", "jwt.jwks.client", "jwks_client_cache_keys", "signing_key_cache_prevents_second_fetch", {"cache_keys": True}, {"second_fetches": 0}, "PyJWKClient signing key cache"),
        ("2.7.0", "jwt.jwks.client", "jwks_client_cache_keys", "jwk_set_cache_disabled_fetches_again", {"cache_jwk_set": False}, {"second_fetches": 1}, "PyJWKClient JWK set cache opt-out"),
        ("2.8.0", "jwt.verify.strict-audience", "verify_generated_hmac", "strict_aud_forbids_list_expected", {"claims": {"aud": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "audience": ["urn:foo", "urn:bar"], "options": {"strict_aud": True}}, {"ok": False, "error_kind": "InvalidAudienceError"}, "strict_aud rejects list expected audience"),
        ("2.8.0", "jwt.verify.strict-audience", "verify_generated_hmac", "strict_aud_forbids_list_claim", {"claims": {"aud": ["urn:foo", "urn:bar"]}, "secret": "secret", "algorithm": "HS256", "audience": "urn:foo", "options": {"strict_aud": True}}, {"ok": False, "error_kind": "InvalidAudienceError"}, "strict_aud rejects list token audience"),
        ("2.8.0", "jwt.verify.strict-audience", "verify_generated_hmac", "strict_aud_accepts_string_to_string", {"claims": {"aud": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "audience": "urn:foo", "options": {"strict_aud": True}}, {"ok": True, "payload": {"aud": "urn:foo"}}, "strict_aud accepts scalar match"),
        ("2.9.0", "jwt.verify.issuer-list", "verify_generated_hmac", "issuer_list_accepts_match", {"claims": {"iss": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "issuer": ["urn:foo", "urn:bar"]}, {"ok": True, "payload": {"iss": "urn:foo"}}, "issuer list accepted"),
        ("2.10.0", "jwt.verify.subject", "verify_generated_hmac", "subject_int_rejected", {"claims": {"sub": 1224344}, "secret": "your-256-bit-secret", "algorithm": "HS256"}, {"ok": False, "error_kind": "InvalidSubjectError"}, "sub must be string"),
        ("2.10.0", "jwt.verify.subject", "verify_generated_hmac", "subject_mismatch_rejected", {"claims": {"sub": "user123"}, "secret": "your-256-bit-secret", "algorithm": "HS256", "subject": "user456"}, {"ok": False, "error_kind": "InvalidSubjectError"}, "subject parameter validation"),
        ("2.10.0", "jwt.verify.jti", "verify_generated_hmac", "jti_int_rejected", {"claims": {"jti": 12223}, "secret": "your-256-bit-secret", "algorithm": "HS256"}, {"ok": False, "error_kind": "InvalidJTIError"}, "jti must be string"),
        ("2.10.0", "jwt.verify.jti", "verify_generated_hmac", "require_jti_missing", {"claims": {"name": "Bob", "admin": False}, "secret": "your-256-bit-secret", "algorithm": "HS256", "options": {"require": ["jti"]}}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "jti"}, "required jti"),
        ("2.10.1", "jwt.verify.issuer", "verify_generated_hmac", "partial_issuer_match_rejected", {"claims": {"iss": "urn:"}, "secret": "secret", "algorithm": "HS256", "issuer": "urn:expected"}, {"ok": False, "error_kind": "InvalidIssuerError"}, "partial issuer matching security fix"),
        ("2.11.0", "jwt.sign.pyjwk", "sign_with_pyjwk", "encode_uses_pyjwk_algorithm", {"jwk": {"kty": "oct", "alg": "HS384", "k": "c2VjcmV0"}, "claims": {"hello": "world"}}, {"header": {"alg": "HS384", "typ": "JWT"}, "payload": {"hello": "world"}, "verifies": True}, "encoding with PyJWK uses key algorithm"),
        ("2.11.0", "jwt.key-policy", "decode_short_hmac_enforced", "short_hmac_key_enforced", {"claims": {"hello": "world"}, "secret": "short", "algorithm": "HS256", "options": {"enforce_minimum_key_length": True}}, {"ok": False, "error_kind": "InvalidKeyError"}, "minimum HMAC key length enforcement"),
        ("2.12.0", "jwt.crit.header", "decode_crit_error", "unknown_crit_rejected", {"claims": {"sub": "attacker", "role": "admin"}, "secret": "secret", "algorithm": "HS256", "headers": {"crit": ["x-custom-policy"], "x-custom-policy": "require-mfa"}}, {"ok": False, "error_kind": "InvalidTokenError"}, "unknown critical header rejected"),
        ("2.13.0", "jwt.jwks.client", "jwks_client_uri_scheme", "file_scheme_rejected", {"uri": "file:///etc/passwd"}, {"accepted": False, "error_kind": "PyJWKClientError"}, "reject non-http JWKS URI"),
        ("2.13.0", "jwt.jwks.client", "jwks_client_uri_scheme", "ftp_scheme_rejected", {"uri": "ftp://example.org/keys.json"}, {"accepted": False, "error_kind": "PyJWKClientError"}, "reject non-http JWKS URI"),
        ("2.13.0", "jwt.jwks.client", "jwks_client_uri_scheme", "https_scheme_accepted", {"uri": "HTTPS://Example.Test/jwks.json"}, {"accepted": True}, "accept http/https JWKS URI"),
        ("2.13.0", "jwt.key-policy", "hmac_prepare_key_error", "empty_hmac_key_rejected", {"key": ""}, {"error": True, "error_kind": "InvalidKeyError"}, "empty HMAC keys rejected"),
        ("2.13.0", "jwt.key-policy", "hmac_prepare_key_error", "jwk_json_as_hmac_secret_rejected", {"key": {"kty": "oct", "alg": "HS256", "k": "c2VjcmV0"}}, {"error": True, "error_kind": "InvalidKeyError"}, "JWK JSON rejected as raw HMAC secret"),
        ("2.13.0", "jwt.jws.detached-payload", "jws_b64_false_round_trip", "detached_payload_round_trip", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"b64": False}}, {"ok": True, "payload": "hello world", "crit_contains_b64": True}, "RFC 7797 b64=false detached payload"),
        ("2.13.0", "jwt.jws.detached-payload", "jws_b64_false_error", "b64_false_non_empty_payload_segment_rejected", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"b64": False}, "tamper": "inline_payload_segment"}, {"ok": False, "error_kind": "DecodeError"}, "b64=false compact payload segment must be empty"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_scalar_match", {"claims": {"aud": "urn:me", "some": "payload"}, "secret": "secret", "algorithm": "HS256", "audience": "urn:me"}, {"ok": True, "payload": {"aud": "urn:me", "some": "payload"}}, "audience scalar match"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_expected_list_match", {"claims": {"aud": "urn:me", "some": "payload"}, "secret": "secret", "algorithm": "HS256", "audience": ["urn:you", "urn:me"]}, {"ok": True, "payload": {"aud": "urn:me", "some": "payload"}}, "audience expected list match"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_missing_expected_rejected", {"claims": {"aud": "urn:me", "some": "payload"}, "secret": "secret", "algorithm": "HS256"}, {"ok": False, "error_kind": "InvalidAudienceError"}, "token audience requires expected audience"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_missing_claim_rejected", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "audience": "urn:me"}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "aud"}, "expected audience requires aud claim"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_array_match", {"claims": {"aud": ["urn:me", "urn:someone-else"], "some": "payload"}, "secret": "secret", "algorithm": "HS256", "audience": "urn:me"}, {"ok": True, "payload": {"aud": ["urn:me", "urn:someone-else"], "some": "payload"}}, "audience array match"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_non_string_claim_rejected", {"claims": {"aud": 1, "hello": "world"}, "secret": "secret", "algorithm": "HS256", "audience": "my_audience"}, {"ok": False, "error_kind": "InvalidAudienceError"}, "aud claim must be string or string list"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_list_member_type_rejected", {"claims": {"aud": [1], "hello": "world"}, "secret": "secret", "algorithm": "HS256", "audience": "my_audience"}, {"ok": False, "error_kind": "InvalidAudienceError"}, "aud list members must be strings"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "audience_param_bytes_rejected", {"claims": {"aud": ["urn:me", "urn:someone-else"]}, "secret": "secret", "algorithm": "HS256", "audience_bytes": "urn:me"}, {"ok": False, "error_kind": "InvalidAudienceError"}, "bytes audience parameter rejected"),
        ("1.0.0", "jwt.verify.audience", "verify_generated_hmac", "verify_aud_false_skips_audience", {"claims": {"aud": "urn:me", "some": "payload"}, "secret": "secret", "algorithm": "HS256", "options": {"verify_aud": False}}, {"ok": True, "payload": {"aud": "urn:me", "some": "payload"}}, "verify_aud false"),
        ("1.0.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_scalar_match", {"claims": {"iss": "urn:foo", "some": "payload"}, "secret": "secret", "algorithm": "HS256", "issuer": "urn:foo"}, {"ok": True, "payload": {"iss": "urn:foo", "some": "payload"}}, "issuer match"),
        ("1.0.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_scalar_mismatch", {"claims": {"iss": "urn:foo", "some": "payload"}, "secret": "secret", "algorithm": "HS256", "issuer": "urn:wrong"}, {"ok": False, "error_kind": "InvalidIssuerError"}, "issuer mismatch"),
        ("1.0.0", "jwt.verify.issuer", "verify_generated_hmac", "issuer_missing_claim_rejected", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "issuer": "urn:wrong"}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "iss"}, "issuer missing claim"),
        ("2.9.0", "jwt.verify.issuer-list", "verify_generated_hmac", "issuer_list_mismatch_rejected", {"claims": {"iss": "urn:foo"}, "secret": "secret", "algorithm": "HS256", "issuer": ["urn:wrong", "urn:bar", "urn:baz"]}, {"ok": False, "error_kind": "InvalidIssuerError"}, "issuer list mismatch"),
        ("2.10.0", "jwt.verify.claim-type", "verify_generated_hmac", "issuer_non_string_claim_rejected", {"claims": {"iss": 123}, "secret": "secret", "algorithm": "HS256", "issuer": "123"}, {"ok": False, "error_kind": "TypeError"}, "iss must be string"),
        ("2.10.0", "jwt.verify.subject", "verify_generated_hmac", "subject_match_accepts", {"claims": {"sub": "user123"}, "secret": "your-256-bit-secret", "algorithm": "HS256", "subject": "user123"}, {"ok": True, "payload": {"sub": "user123"}}, "subject match"),
        ("2.10.0", "jwt.verify.subject", "verify_generated_hmac", "subject_none_does_not_require_match", {"claims": {"sub": "user789"}, "secret": "your-256-bit-secret", "algorithm": "HS256", "subject": None}, {"ok": True, "payload": {"sub": "user789"}}, "subject None"),
        ("2.10.0", "jwt.verify.required-claim", "verify_generated_hmac", "require_sub_missing", {"claims": {}, "secret": "your-256-bit-secret", "algorithm": "HS256", "options": {"require": ["sub"]}}, {"ok": False, "error_kind": "MissingRequiredClaimError", "claim": "sub"}, "required sub"),
        ("2.10.0", "jwt.verify.jti", "verify_generated_hmac", "jti_string_accepts", {"claims": {"jti": "unique-id-456"}, "secret": "your-256-bit-secret", "algorithm": "HS256"}, {"ok": True, "payload": {"jti": "unique-id-456"}}, "jti string"),
        ("2.0.0", "jwt.decode.algorithm-policy", "verify_generated_hmac", "algorithms_required_when_verifying", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "omit_algorithms": True}, {"ok": False, "error_kind": "DecodeError"}, "algorithms required when verifying"),
        ("2.0.0", "jwt.decode.algorithm-policy", "verify_generated_hmac", "algorithms_not_required_when_signature_off", {"claims": {"some": "payload"}, "secret": "secret", "algorithm": "HS256", "options": {"verify_signature": False}, "omit_algorithms": True}, {"ok": True, "payload": {"some": "payload"}}, "algorithms not required if signature verification is disabled"),
        ("2.0.0", "jws.options", "jws_options", "verify_signature_false_sets_option", {"options": {"verify_signature": False}}, {"verify_signature": False}, "PyJWS options"),
        ("2.0.0", "jws.options", "jws_options", "options_type_object_rejected", {"options_value": "object"}, {"error": True, "error_kind": "TypeError"}, "PyJWS options must be dict"),
        ("2.0.0", "jws.algorithm-registry", "jws_algorithm_registry", "register_non_algorithm_rejected", {"action": "register_non_algorithm"}, {"error": True, "error_kind": "TypeError"}, "algorithm registry value type"),
        ("2.0.0", "jws.algorithm-registry", "jws_algorithm_registry", "unregister_missing_algorithm_rejected", {"action": "unregister_missing", "algorithm": "AAA"}, {"error": True, "error_kind": "KeyError"}, "unregister missing algorithm"),
        ("2.0.0", "jws.decode.errors", "jws_decode_error", "missing_segments_rejected", {"token": "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9", "secret": "secret", "algorithm": "HS256"}, {"error": True, "error_kind": "DecodeError"}, "not enough segments"),
        ("2.0.0", "jws.decode.errors", "jws_decode_error", "invalid_token_type_none_rejected", {"token_type": "none", "secret": "secret", "algorithm": "HS256"}, {"error": True, "error_kind": "DecodeError"}, "invalid token type"),
        ("2.0.0", "jws.decode.errors", "jws_decode_error", "invalid_header_padding_rejected", {"token": "a.eyJoZWxsbyI6IndvcmxkIn0.SIr03zM64awWRdPrAM_61QWsZchAtgDV3pphfHPPWkI", "secret": "secret", "algorithm": "HS256"}, {"error": True, "error_kind": "DecodeError"}, "invalid header padding"),
        ("2.0.0", "jws.decode.errors", "jws_decode_error", "invalid_payload_padding_rejected", {"token": "eyJhbGciOiJIUzI1NiJ9.a.SIr03zM64awWRdPrAM_61QWsZchAtgDV3pphfHPPWkI", "secret": "secret", "algorithm": "HS256"}, {"error": True, "error_kind": "DecodeError"}, "invalid payload padding"),
        ("2.0.0", "jws.decode.errors", "jws_decode_error", "invalid_crypto_padding_rejected", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.a", "secret": "secret", "algorithm": "HS256"}, {"error": True, "error_kind": "DecodeError"}, "invalid crypto padding"),
        ("2.0.0", "jws.verify.signature-option", "jws_generated_verify", "skip_signature_wrong_secret_accepts", {"payload": "hello world", "secret": "foo", "verify_secret": "bar", "sign_algorithm": "HS256", "verify_algorithms": ["HS256"], "options": {"verify_signature": False}}, {"ok": True, "payload": "hello world"}, "JWS verify_signature false"),
        ("2.0.0", "jws.verify.algorithm-policy", "jws_generated_verify", "wrong_hmac_secret_rejected", {"payload": "hello world", "secret": "foo", "verify_secret": "bar", "sign_algorithm": "HS256", "verify_algorithms": ["HS256"]}, {"ok": False, "error_kind": "InvalidSignatureError"}, "wrong HMAC secret rejected"),
        ("2.0.0", "jws.verify.algorithm-policy", "jws_generated_verify", "wrong_algorithm_allowlist_rejected", {"payload": "hello world", "secret": "secret", "sign_algorithm": "HS256", "verify_algorithms": ["HS384"]}, {"ok": False, "error_kind": "InvalidAlgorithmError"}, "algorithm allow-list"),
        ("2.0.0", "jws.sign.header", "jws_sign_header", "custom_kid_header", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"kid": "abc123"}}, {"header": {"alg": "HS256", "typ": "JWT", "kid": "abc123"}, "payload": "hello world"}, "custom JWS headers"),
        ("2.0.0", "jws.sign.header", "jws_sign_header", "typ_empty_string_omitted", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"typ": ""}}, {"header": {"alg": "HS256"}, "payload": "hello world"}, "empty typ omitted"),
        ("2.0.0", "jws.sign.header", "jws_sign_header", "typ_none_omitted", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"typ": None}}, {"header": {"alg": "HS256"}, "payload": "hello world"}, "typ None omitted"),
        ("2.0.0", "jws.sign.header", "jws_sign_header_error", "kid_non_string_rejected", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"kid": 123}}, {"error": True, "error_kind": "InvalidTokenError"}, "kid must be string"),
        ("2.12.0", "jwt.crit.header", "decode_crit_error", "empty_crit_rejected", {"claims": {"sub": "attacker"}, "secret": "secret", "algorithm": "HS256", "headers": {"crit": []}}, {"ok": False, "error_kind": "InvalidTokenError"}, "crit must be non-empty list"),
        ("2.12.0", "jwt.crit.header", "decode_crit_error", "crit_non_list_rejected", {"claims": {"sub": "attacker"}, "secret": "secret", "algorithm": "HS256", "headers": {"crit": "b64"}}, {"ok": False, "error_kind": "InvalidTokenError"}, "crit must be list"),
        ("2.12.0", "jwt.crit.header", "decode_crit_error", "crit_non_string_rejected", {"claims": {"sub": "attacker"}, "secret": "secret", "algorithm": "HS256", "headers": {"crit": [123]}}, {"ok": False, "error_kind": "InvalidTokenError"}, "crit values must be strings"),
        ("2.12.0", "jwt.crit.header", "decode_crit_error", "crit_extension_missing_rejected", {"claims": {"sub": "attacker"}, "secret": "secret", "algorithm": "HS256", "headers": {"crit": ["b64"]}}, {"ok": False, "error_kind": "InvalidTokenError"}, "crit extension must be present"),
        ("2.13.0", "jwt.jws.detached-payload", "jws_b64_false_error", "b64_false_without_detached_payload_rejected", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"b64": False}, "tamper": "omit_detached_payload"}, {"ok": False, "error_kind": "DecodeError"}, "detached payload required for b64=false"),
        ("2.13.0", "jwt.jws.detached-payload", "jws_b64_false_error", "b64_false_without_crit_rejected", {"payload": "hello world", "secret": "secret", "algorithm": "HS256", "headers": {"b64": False}, "tamper": "remove_crit"}, {"ok": False, "error_kind": "InvalidTokenError"}, "b64 false must be declared critical"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "rsa_pub_default_alg", {"fixture": "jwk_rsa_pub.json"}, {"key_type": "RSA", "algorithm_name": "RS256"}, "PyJWK RSA default algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "ec_p256_default_alg", {"fixture": "jwk_ec_pub_P-256.json"}, {"key_type": "EC", "algorithm_name": "ES256"}, "PyJWK EC P-256 algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "ec_p384_default_alg", {"fixture": "jwk_ec_pub_P-384.json"}, {"key_type": "EC", "algorithm_name": "ES384"}, "PyJWK EC P-384 algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "ec_p521_default_alg", {"fixture": "jwk_ec_pub_P-521.json"}, {"key_type": "EC", "algorithm_name": "ES512"}, "PyJWK EC P-521 algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "ec_secp256k1_default_alg", {"fixture": "jwk_ec_pub_secp256k1.json"}, {"key_type": "EC", "algorithm_name": "ES256K"}, "PyJWK secp256k1 algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "hmac_default_alg", {"fixture": "jwk_hmac.json"}, {"key_type": "oct", "algorithm_name": "HS256"}, "PyJWK oct algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk", "pyjwk_from_fixture", "okp_default_alg", {"fixture": "jwk_okp_pub_Ed25519.json"}, {"key_type": "OKP", "algorithm_name": "EdDSA"}, "PyJWK OKP algorithm"),
        ("2.4.0", "jwt.jwk.pyjwk-error", "pyjwk_from_data_error", "missing_kty_rejected", {"jwk": {"alg": "RS256"}}, {"error": True, "error_kind": "InvalidKeyError"}, "JWK missing kty rejected"),
        ("2.4.0", "jwt.jwk.pyjwk-error", "pyjwk_from_data_error", "unknown_kty_rejected", {"jwk": {"kty": "unknown"}}, {"error": True, "error_kind": "InvalidKeyError"}, "JWK unknown kty rejected"),
        ("2.4.0", "jwt.jwk.pyjwk-error", "pyjwk_from_data_error", "unknown_algorithm_rejected", {"jwk": {"kty": "oct", "k": "c2VjcmV0"}, "algorithm": "unknown"}, {"error": True, "error_kind": "PyJWKError"}, "JWK unknown algorithm rejected"),
        ("2.4.0", "jwt.jwkset", "pyjwkset_from_data", "keyset_indexes_by_kid", {"keys": [{"kty": "oct", "kid": "key-a", "k": "c2VjcmV0"}, {"kty": "oct", "kid": "key-b", "k": "Zm9v"}]}, {"key_count": 2, "contains_key_a": True, "contains_key_b": True}, "PyJWKSet indexes keys by kid"),
        ("2.4.0", "jwt.jwkset", "pyjwkset_from_data_error", "empty_keyset_rejected", {"keys": []}, {"error": True, "error_kind": "PyJWKSetError"}, "empty JWK set rejected"),
        ("2.13.0", "jwt.security.key-confusion", "verify_key_confusion_vectors", "ed25519_public_key_not_hmac_secret", {"vector": "ed25519"}, {"good_ok": True, "bad_rejected": True, "bad_error_kind": "InvalidKeyError"}, "GHSA ffqj key confusion advisory"),
        ("2.13.0", "jwt.security.key-confusion", "verify_key_confusion_vectors", "ecdsa_ssh_public_key_not_hmac_secret", {"vector": "ecdsa_ssh"}, {"good_ok": True, "bad_rejected": True, "bad_error_kind": "InvalidKeyError"}, "GHSA ffqj key confusion advisory"),
    ]


def scenario_contracts(published_by_version: dict[str, str | None]) -> list[Contract]:
    out: list[Contract] = []
    for version, capability, op, slug, params, expected, note in scenario_specs():
        add(out, version, published_at=published_by_version.get(version), capability=capability, op=op, slug=slug, params=params, expected=expected, evidence={"source": "CHANGELOG.rst/tests", "note": note}, source_kind="release-note-scenario")
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
    latest, published_by_version = fetch_pypi_versions()
    tags = set(sh(["git", "tag"], cwd=REPO).splitlines())
    auth0_seen = auth0_identity_set()
    seen: set[str] = set()
    contracts: list[Contract] = []
    release_rows: list[dict[str, Any]] = []
    exact_auth0_overlap_skipped = 0

    for version in sorted(published_by_version, key=version_key):
        tag = tag_for(version, tags)
        if not tag:
            release_rows.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0, "auth0_overlap_skipped": 0})
            continue
        found = literal_contracts(version, published_by_version.get(version), tag)
        new = 0
        skipped = 0
        for contract in found:
            key = identity(contract)
            if key in auth0_seen:
                exact_auth0_overlap_skipped += 1
                skipped += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            contracts.append(contract)
            new += 1
        release_rows.append({"version": version, "tag": tag, "contracts_seen": len(found), "new_contracts": new, "auth0_overlap_skipped": skipped})

    for contract in scenario_contracts(published_by_version):
        key = identity(contract)
        if key in auth0_seen:
            exact_auth0_overlap_skipped += 1
            continue
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
        "project": "jpadilla/pyjwt",
        "package": "PyJWT",
        "latest_version": latest,
        "pypi_metadata": PYPI_METADATA,
        "github": "https://github.com/jpadilla/pyjwt",
        "pypi_releases": len(published_by_version),
        "git_tags": len(tags),
        "auth0_exact_overlap_skipped": exact_auth0_overlap_skipped,
        "release_rows": release_rows,
        "contracts_extracted": len(contracts),
        "by_capability": dict(Counter(c.capability for c in contracts)),
        "by_source_kind": dict(Counter(c.source_kind for c in contracts)),
        "contracts": [asdict(c) for c in contracts],
    }
    (BASE / "all_releases_language_independent.summary.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, BASE / "all_releases_language_independent.rpl")

    rows = ["# jpadilla/pyjwt Release Contract Counts", "", "| Version | Tag | Contracts seen | New unique contracts | Auth0 exact overlap skipped |", "| --- | --- | ---: | ---: | ---: |"]
    for row in release_rows:
        rows.append(f"| `{row['version']}` | `{row['tag'] or ''}` | {row['contracts_seen']} | {row['new_contracts']} | {row['auth0_overlap_skipped']} |")
    (BASE / "release_contract_counts.md").write_text("\n".join(rows) + "\n", encoding="utf-8")

    audit = [
        "# jpadilla/pyjwt Contract Extraction Audit",
        "",
        f"- PyPI releases inspected: {len(published_by_version)}",
        f"- Git tags available: {len(tags)}",
        f"- Extracted semantic contracts: {len(contracts)}",
        f"- Exact Auth0 survivor overlaps skipped: {exact_auth0_overlap_skipped}",
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
    print(json.dumps({k: payload[k] for k in ["latest_version", "pypi_releases", "contracts_extracted", "auth0_exact_overlap_skipped", "by_capability", "by_source_kind"]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
