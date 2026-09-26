#!/usr/bin/env python3
"""Replay jpadilla/pyjwt contracts against PyJWT 2.13.0."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "jwt" / "pyjwt"
INPUT = BASE / "all_releases_language_independent.summary.json"
OUT_JSON = BASE / "latest_replay_mutant_verified.json"
OUT_MD = BASE / "latest_replay_mutant_verified.md"
OUT_RPL = BASE / "latest_replay_mutant_verified.rpl"
VENV_PYTHON = ROOT / ".cache" / "jwt" / "pyjwt_venv" / "bin" / "python"


RUNNER_CODE = r'''
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from unittest import mock
from urllib.error import URLError

import jwt
from jwt import PyJWK, PyJWKClient
from jwt.api_jwk import PyJWKSet
from jwt.algorithms import HMACAlgorithm, NoneAlgorithm, get_default_algorithms
from jwt.api_jws import PyJWS
from jwt.exceptions import InvalidKeyError, PyJWKClientError


RESPONSE_DATA_WITH_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "0wtlJRY9-ru61LmOgieeI7_rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset_Obh8BwtO-Ww-UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6_GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEw",
            "e": "AQAB",
            "kid": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
        }
    ]
}
RESPONSE_DATA_NO_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "39SJ39VgrQ0qMNK74CaueUBlyYsUyuA7yWlHYZ-jAj6tlFKugEVUTBUVbhGF44uOr99iL_cwmr-srqQDEi-jFHdkS6WFkYyZ03oyyx5dtBMtzrXPieFipSGfQ5EGUGloaKDjL-Ry9tiLnysH2VVWZ5WDDN-DGHxuCOWWjiBNcTmGfnj5_NvRHNUh2iTLuiJpHbGcPzWc5-lc4r-_ehw9EFfp2XsxE9xvtbMZ4SouJCiv9xnrnhe2bdpWuu34hXZCrQwE8DjRY3UR8LjyMxHHPLzX2LWNMHjfN3nAZMteS-Ok11VYDFI-4qCCVGo_WesBCAeqCjPLRyZoV27x1YGsUQ",
            "e": "AQAB",
            "kid": "MLYHNMMhwCNXw9roHIILFsK4nLs=",
        }
    ]
}
KEY_DIR = "''' + str((ROOT / ".cache" / "jwt" / "pyjwt" / "tests" / "keys").as_posix()) + r'''"
PUB_KEY_BYTES = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPL1I9oiq+B8crkmuV4YViiUnhdLjCp3hvy1bNGuGfNL"
SSH_KEY_BYTES = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXMtkUkkoJ9kQP8QhpKO/TfuxcKC2a92dIo/xDY6MNl6VA8MChCpAJN0w1wvVPJ4qTJRnGO7A6V6dl8oRxDPkc="


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def resolve_claims(claims):
    out = {}
    now = int(time.time())
    for key, value in claims.items():
        if isinstance(value, dict) and "now_offset_seconds" in value:
            out[key] = now + int(value["now_offset_seconds"])
        else:
            out[key] = value
    return out


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return "it worked"
        return super().default(obj)


def ok_payload(payload=None):
    actual = {"ok": True}
    if payload is not None:
        actual["payload"] = payload
    return actual


def exception_result(error_key="error"):
    def wrap(fn):
        try:
            return fn()
        except Exception as exc:
            return {error_key: False if error_key == "ok" else True, "error_kind": exc.__class__.__name__, "message": str(exc)}
    return wrap


def decode_complete_unverified(params):
    decoded = jwt.decode_complete(params["token"], options={"verify_signature": False})
    return {"header": decoded["header"], "payload": decoded["payload"], "signature_b64": b64url(decoded["signature"])}


def decode_claim_value_unverified(params):
    payload = jwt.decode(params["token"], options={"verify_signature": False})
    return {"value": payload.get(params["claim"])}


def get_unverified_header(params):
    return {"header": jwt.get_unverified_header(params["token"])}


def decode_error(params):
    try:
        jwt.decode(params["token"], options={"verify_signature": False})
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jwt_payload_must_be_object(params):
    try:
        jwt.decode(params["token"], params.get("secret", "secret"), algorithms=[params.get("algorithm", "HS256")])
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_decode_bytes_unverified(params):
    payload = PyJWS().decode(params["token"], options={"verify_signature": False})
    return {"payload_b64": b64url(payload)}


def jws_verify_hmac(params):
    try:
        payload = PyJWS().decode(params["token"], params["secret"], algorithms=[params["algorithm"]])
        return {"ok": True, "payload_b64": b64url(payload)}
    except Exception as exc:
        return {"ok": False, "error_kind": exc.__class__.__name__, "message": str(exc)}


def verify_hmac(params):
    try:
        kwargs = {}
        if not params.get("omit_algorithms"):
            kwargs["algorithms"] = [params["algorithm"]]
        for key in ("options", "audience", "issuer", "subject", "leeway"):
            if key in params:
                kwargs[key] = params[key]
        if "audience_bytes" in params:
            kwargs["audience"] = params["audience_bytes"].encode()
        payload = jwt.decode(params["token"], params.get("secret", ""), **kwargs)
        return ok_payload(payload)
    except Exception as exc:
        claim = getattr(exc, "claim", None)
        out = {"ok": False, "error_kind": exc.__class__.__name__, "message": str(exc)}
        if claim is not None:
            out["claim"] = claim
        return out


def verify_generated_hmac(params):
    try:
        claims = resolve_claims(params.get("claims", {}))
        token = jwt.encode(claims, params.get("secret", "secret"), algorithm=params.get("algorithm", "HS256"), headers=params.get("headers"))
        merged = dict(params)
        merged["token"] = token
        return verify_hmac(merged)
    except Exception as exc:
        claim = getattr(exc, "claim", None)
        out = {"ok": False, "error_kind": exc.__class__.__name__, "message": str(exc)}
        if claim is not None:
            out["claim"] = claim
        return out


def verify_generated_hmac_relative(params):
    return verify_generated_hmac(params)


def sign_hmac(params):
    token = jwt.encode(params.get("claims", {}), params.get("secret", "secret"), algorithm=params.get("algorithm", "HS256"), headers=params.get("headers"))
    payload = jwt.decode(token, params.get("secret", "secret"), algorithms=[params.get("algorithm", "HS256")], options={"verify_exp": False, "verify_nbf": False, "verify_iat": False})
    return {"header": jwt.get_unverified_header(token), "payload": payload, "verifies": True}


def sign_none(params):
    token = jwt.encode(params.get("claims", {}), key=None, algorithm="none")
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"header": jwt.get_unverified_header(token), "payload": payload, "verifies": True}


def sign_datetime_claims(params):
    claims = {key: datetime.fromtimestamp(value, tz=timezone.utc) for key, value in params.get("claims", {}).items()}
    token = jwt.encode(claims, params.get("secret", "secret"), algorithm=params.get("algorithm", "HS256"))
    payload = jwt.decode(token, options={"verify_signature": False})
    return {"payload": payload}


def sign_decimal_json_encoder(params):
    token = jwt.encode({"some_decimal": Decimal(params["claims"]["some_decimal"])}, params.get("secret", "secret"), algorithm=params.get("algorithm", "HS256"), json_encoder=CustomJSONEncoder)
    payload = jwt.decode(token, params.get("secret", "secret"), algorithms=[params.get("algorithm", "HS256")])
    return {"payload": payload}


def sign_with_pyjwk(params):
    jwk = PyJWK(params["jwk"])
    token = jwt.encode(params["claims"], jwk)
    payload = jwt.decode(token, jwk)
    return {"header": jwt.get_unverified_header(token), "payload": payload, "verifies": True}


def decode_short_hmac_enforced(params):
    token = jwt.encode(params["claims"], params["secret"], algorithm=params["algorithm"])
    return verify_hmac({"token": token, "secret": params["secret"], "algorithm": params["algorithm"], "options": params["options"]})


def hmac_to_jwk(params):
    algo = HMACAlgorithm(HMACAlgorithm.SHA256)
    return {"jwk": json.loads(algo.to_jwk(params["secret"], as_dict=False))}


def hmac_from_jwk_round_trip(params):
    algo = HMACAlgorithm(HMACAlgorithm.SHA256)
    key = algo.from_jwk(json.dumps(params["jwk"]))
    message = params["message"].encode()
    signature = algo.sign(message, key)
    return {"ok": bool(algo.verify(message, key, signature))}


def hmac_from_jwk_error(params):
    try:
        HMACAlgorithm(HMACAlgorithm.SHA256).from_jwk(json.dumps(params["jwk"]))
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_algorithm_registry(params):
    jws = PyJWS()
    action = params["action"]
    try:
        if action == "duplicate_register":
            jws.register_algorithm("AAA", NoneAlgorithm())
            jws.register_algorithm("AAA", NoneAlgorithm())
            return {"error": False}
        if action == "unregister":
            before = params["algorithm"] in jws.get_algorithms()
            jws.unregister_algorithm(params["algorithm"])
            after = params["algorithm"] in jws.get_algorithms()
            return {"contains_before": before, "contains_after": after}
        if action == "register_non_algorithm":
            jws.register_algorithm("AAA123", {})
            return {"error": False}
        if action == "unregister_missing":
            jws.unregister_algorithm(params["algorithm"])
            return {"error": False}
        raise ValueError(action)
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_generated_verify(params):
    jws = PyJWS()
    token = jws.encode(params["payload"].encode(), params["secret"], algorithm=params["sign_algorithm"])
    try:
        payload = jws.decode(token, params.get("verify_secret", params["secret"]), algorithms=params["verify_algorithms"], options=params.get("options"))
        return {"ok": True, "payload": payload.decode()}
    except Exception as exc:
        return {"ok": False, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_sign_verify_hmac(params):
    jws = PyJWS()
    token = jws.encode(params["payload"].encode(), params["secret"], algorithm=params["algorithm"])
    payload = jws.decode(token, params["secret"], algorithms=[params["algorithm"]])
    return {"ok": True, "payload_b64": b64url(payload)}


def jws_options(params):
    try:
        if params.get("options_value") == "object":
            PyJWS(options=object())
            return {"error": False}
        jws = PyJWS(options=params.get("options"))
        return dict(jws.options)
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_decode_error(params):
    try:
        token = None if params.get("token_type") == "none" else params["token"]
        PyJWS().decode(token, params.get("secret", "secret"), algorithms=[params.get("algorithm", "HS256")])
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def jws_sign_header(params):
    jws = PyJWS()
    token = jws.encode(params["payload"].encode(), params["secret"], algorithm=params["algorithm"], headers=params.get("headers"))
    payload = jws.decode(token, params["secret"], algorithms=[params["algorithm"]]).decode()
    return {"header": jws.get_unverified_header(token), "payload": payload}


def jws_sign_header_error(params):
    try:
        PyJWS().encode(params["payload"].encode(), params["secret"], algorithm=params["algorithm"], headers=params.get("headers"))
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def decode_complete_unverified_generated(params):
    token = jwt.encode(params["claims"], params["secret"], algorithm=params["algorithm"])
    decoded = jwt.decode_complete(token, options={"verify_signature": False})
    return {"header": decoded["header"], "payload": decoded["payload"], "has_signature": bool(decoded["signature"])}


def pyjwk_algorithm_name(params):
    key = PyJWK(params["jwk"])
    return {"algorithm_name": key.algorithm_name, "key_type": key.key_type}


def pyjwk_from_fixture(params):
    with open(f"{KEY_DIR}/{params['fixture']}", encoding="utf-8") as fp:
        key = PyJWK.from_dict(json.load(fp))
    return {"algorithm_name": key.algorithm_name, "key_type": key.key_type}


def pyjwk_from_data_error(params):
    try:
        if "algorithm" in params:
            PyJWK.from_dict(params["jwk"], algorithm=params["algorithm"])
        else:
            PyJWK.from_dict(params["jwk"])
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def pyjwkset_from_data(params):
    keyset = PyJWKSet.from_dict({"keys": params["keys"]})
    return {"key_count": len(keyset.keys), "contains_key_a": keyset["key-a"].key_id == "key-a", "contains_key_b": keyset["key-b"].key_id == "key-b"}


def pyjwkset_from_data_error(params):
    try:
        PyJWKSet.from_dict({"keys": params["keys"]})
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def compute_hash_digest(params):
    digest = get_default_algorithms()[params["algorithm"]].compute_hash_digest(params["message"].encode()).hex()
    return {"digest_hex": digest}


class FakeResponse:
    def __init__(self, data):
        self.data = json.dumps(data).encode()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read(self):
        return self.data

    def close(self):
        self.closed = True


def jwks_client_headers_forwarded(params):
    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value = FakeResponse(RESPONSE_DATA_WITH_MATCHING_KID)
        client = PyJWKClient(params["url"], headers=params["headers"])
        jwk_set = client.get_jwk_set()
        req = urlopen.call_args[0][0]
        return {"request_url": req.full_url, "headers": dict(req.headers), "key_count": len(jwk_set.keys)}


def jwks_client_cache_keys(params):
    kid = RESPONSE_DATA_WITH_MATCHING_KID["keys"][0]["kid"]
    if params.get("cache_keys"):
        client = PyJWKClient("https://example.test/jwks.json", cache_keys=True)
        with mock.patch("urllib.request.urlopen") as first:
            first.return_value = FakeResponse(RESPONSE_DATA_WITH_MATCHING_KID)
            client.get_signing_key(kid)
        with mock.patch("urllib.request.urlopen") as second:
            second.return_value = FakeResponse(RESPONSE_DATA_WITH_MATCHING_KID)
            client.get_signing_key(kid)
            return {"second_fetches": second.call_count}
    if params.get("cache_jwk_set") is False:
        client = PyJWKClient("https://example.test/jwks.json", cache_jwk_set=False)
        with mock.patch("urllib.request.urlopen") as first:
            first.return_value = FakeResponse(RESPONSE_DATA_WITH_MATCHING_KID)
            client.get_signing_key(kid)
        with mock.patch("urllib.request.urlopen") as second:
            second.return_value = FakeResponse(RESPONSE_DATA_WITH_MATCHING_KID)
            client.get_signing_key(kid)
            return {"second_fetches": second.call_count}
    raise ValueError("unsupported cache contract")


def jwks_client_uri_scheme(params):
    try:
        PyJWKClient(params["uri"])
        return {"accepted": True}
    except Exception as exc:
        return {"accepted": False, "error_kind": exc.__class__.__name__, "message": str(exc)}


def hmac_prepare_key_error(params):
    try:
        key = params["key"]
        if isinstance(key, dict):
            key = json.dumps(key)
        HMACAlgorithm(HMACAlgorithm.SHA256).prepare_key(key)
        return {"error": False}
    except Exception as exc:
        return {"error": True, "error_kind": exc.__class__.__name__, "message": str(exc)}


def decode_crit_error(params):
    token = jwt.encode(params["claims"], params["secret"], algorithm=params["algorithm"], headers=params["headers"])
    merged = dict(params)
    merged["token"] = token
    return verify_hmac(merged)


def jws_b64_false_round_trip(params):
    jws = PyJWS()
    payload = params["payload"].encode()
    token = jws.encode(payload, params["secret"], algorithm=params["algorithm"], headers=params["headers"], is_payload_detached=True)
    header = jws.get_unverified_header(token)
    decoded = jws.decode(token, params["secret"], algorithms=[params["algorithm"]], detached_payload=payload)
    return {"ok": decoded == payload, "payload": decoded.decode(), "crit_contains_b64": "b64" in header.get("crit", [])}


def jws_b64_false_error(params):
    jws = PyJWS()
    payload = params["payload"].encode()
    token = jws.encode(payload, params["secret"], algorithm=params["algorithm"], headers=params["headers"], is_payload_detached=True)
    if params.get("tamper") == "inline_payload_segment":
        parts = token.split(".")
        parts[1] = b64url(b"attacker")
        token = ".".join(parts)
    elif params.get("tamper") == "remove_crit":
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)))
        header.pop("crit", None)
        parts[0] = b64url(json.dumps(header, separators=(",", ":")).encode())
        token = ".".join(parts)
    detached = None if params.get("tamper") == "omit_detached_payload" else payload
    try:
        jws.decode(token, params["secret"], algorithms=[params["algorithm"]], detached_payload=detached)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error_kind": exc.__class__.__name__, "message": str(exc)}


def verify_key_confusion_vectors(params):
    if params["vector"] == "ed25519":
        good = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoxMjM0fQ.M5y1EEavZkHSlj9i8yi9nXKKyPBSAUhDRTOYZi3zZY11tZItDaR3qwAye8pc74_lZY3Ogt9KPNFbVOSGnUBHDg"
        bad = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxMjM0fQ.6ulDpqSlbHmQ8bZXhZRLFko9SwcHrghCwh8d-exJEE4"
        key = PUB_KEY_BYTES
    else:
        good = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.NX42mS8cNqYoL3FOW9ZcKw8Nfq2mb6GqJVADeMA1-kyHAclilYo_edhdM_5eav9tBRQTlL0XMeu_WFE_mz3OXg"
        bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.5eYfbrbeGYmWfypQ6rMWXNZ8bdHcqKng5GPr9MJZITU"
        key = SSH_KEY_BYTES
    algorithms = list(get_default_algorithms())
    jwt.decode(good, key, algorithms=algorithms)
    try:
        jwt.decode(bad, key, algorithms=algorithms)
        return {"good_ok": True, "bad_rejected": False}
    except Exception as exc:
        return {"good_ok": True, "bad_rejected": True, "bad_error_kind": exc.__class__.__name__}


OPS = {
    "decode_complete_unverified": decode_complete_unverified,
    "decode_claim_value_unverified": decode_claim_value_unverified,
    "get_unverified_header": get_unverified_header,
    "decode_error": decode_error,
    "jwt_payload_must_be_object": jwt_payload_must_be_object,
    "jws_decode_bytes_unverified": jws_decode_bytes_unverified,
    "jws_verify_hmac": jws_verify_hmac,
    "verify_hmac": verify_hmac,
    "verify_generated_hmac": verify_generated_hmac,
    "verify_generated_hmac_relative": verify_generated_hmac_relative,
    "sign_hmac": sign_hmac,
    "sign_none": sign_none,
    "sign_datetime_claims": sign_datetime_claims,
    "sign_decimal_json_encoder": sign_decimal_json_encoder,
    "sign_with_pyjwk": sign_with_pyjwk,
    "decode_short_hmac_enforced": decode_short_hmac_enforced,
    "hmac_to_jwk": hmac_to_jwk,
    "hmac_from_jwk_round_trip": hmac_from_jwk_round_trip,
    "hmac_from_jwk_error": hmac_from_jwk_error,
    "jws_algorithm_registry": jws_algorithm_registry,
    "jws_generated_verify": jws_generated_verify,
    "jws_sign_verify_hmac": jws_sign_verify_hmac,
    "jws_options": jws_options,
    "jws_decode_error": jws_decode_error,
    "jws_sign_header": jws_sign_header,
    "jws_sign_header_error": jws_sign_header_error,
    "decode_complete_unverified_generated": decode_complete_unverified_generated,
    "pyjwk_algorithm_name": pyjwk_algorithm_name,
    "pyjwk_from_fixture": pyjwk_from_fixture,
    "pyjwk_from_data_error": pyjwk_from_data_error,
    "pyjwkset_from_data": pyjwkset_from_data,
    "pyjwkset_from_data_error": pyjwkset_from_data_error,
    "compute_hash_digest": compute_hash_digest,
    "jwks_client_headers_forwarded": jwks_client_headers_forwarded,
    "jwks_client_cache_keys": jwks_client_cache_keys,
    "jwks_client_uri_scheme": jwks_client_uri_scheme,
    "hmac_prepare_key_error": hmac_prepare_key_error,
    "decode_crit_error": decode_crit_error,
    "jws_b64_false_round_trip": jws_b64_false_round_trip,
    "jws_b64_false_error": jws_b64_false_error,
    "verify_key_confusion_vectors": verify_key_confusion_vectors,
}


def matches(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and matches(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return actual == expected
    return actual == expected


def evaluate(contract):
    result = {"name": contract["name"], "capability": contract["capability"], "op": contract["op"]}
    try:
        actual = OPS[contract["op"]](copy.deepcopy(contract["params"]))
        replay_pass = matches(actual, contract["expected"])
        mutant_accepted = matches(actual, contract["mutant"])
        result.update({"replay_pass": replay_pass, "mutant_rejected": not mutant_accepted, "survived": replay_pass and not mutant_accepted, "actual": actual})
        if not replay_pass:
            result["expected"] = contract["expected"]
    except Exception as exc:
        result.update({"replay_pass": False, "mutant_rejected": False, "survived": False, "runner_error": f"{exc.__class__.__name__}: {exc}"})
    return result


def main():
    with open(sys.argv[1], encoding="utf-8") as fp:
        root = json.load(fp)
    contracts = root["contracts"] if isinstance(root, dict) and "contracts" in root else root
    results = [evaluate(contract) for contract in contracts]
    survivors = [contract for contract, result in zip(contracts, results) if result["survived"]]
    output = {
        "implementation": "PyJWT",
        "version": jwt.__version__,
        "contracts_total": len(contracts),
        "replay_pass": sum(1 for row in results if row["replay_pass"]),
        "mutant_rejected": sum(1 for row in results if row["mutant_rejected"]),
        "survivors": len(survivors),
        "survivor_contracts": survivors,
        "results": results,
    }
    print(json.dumps(output, separators=(",", ":")))


if __name__ == "__main__":
    main()
'''


def write_rpl(contracts: list[dict], path: Path) -> None:
    lines: list[str] = []
    for contract in contracts:
        lines.append(f"contract {json.dumps(contract['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(contract['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(contract['capability'], ensure_ascii=True)}")
        lines.append(f"  op {contract['op']}")
        lines.append(f"  params {json.dumps(contract['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(contract['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    env = os.environ.copy()
    completed = subprocess.run(
        [str(VENV_PYTHON), "-c", RUNNER_CODE, str(INPUT)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    OUT_JSON.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    survivors = result["survivor_contracts"]
    write_rpl(survivors, OUT_RPL)

    by_cap = Counter(contract["capability"] for contract in survivors)
    by_source = Counter(contract["source_kind"] for contract in survivors)
    failed = [row for row in result["results"] if not row["survived"]]
    lines = [
        "# jpadilla/pyjwt Latest Replay + Mutant Verification",
        "",
        "- Implementation: `PyJWT`",
        f"- Latest version tested: `{result['version']}`",
        f"- Contracts evaluated: {result['contracts_total']}",
        f"- Replay passed: {result['replay_pass']}",
        f"- Mutant rejected: {result['mutant_rejected']}",
        f"- Latest surviving contracts: {result['survivors']}",
        "",
        "## Survivors By Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for key, value in sorted(by_cap.items()):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Survivors By Source Kind", "", "| Source kind | Survivors |", "| --- | ---: |"])
    for key, value in sorted(by_source.items()):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Reason |", "| --- | --- |"])
    for row in failed[:30]:
        reason = row.get("runner_error") or row.get("actual", {}).get("message") or "replay/mutant mismatch"
        lines.append(f"| `{row['name']}` | {reason} |")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["version", "contracts_total", "replay_pass", "mutant_rejected", "survivors"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
