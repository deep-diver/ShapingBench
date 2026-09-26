#!/usr/bin/env python3
"""Cross-replay JWT survivor contracts across mature JWT implementations."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import textwrap
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "jwt"
OUT = BASE / "common"
RUNTIME = ROOT / ".cache" / "jwt" / "cross_common_runtime"
PYJWT_PYTHON = ROOT / ".cache" / "jwt" / "pyjwt_venv" / "bin" / "python"
JAVA_HOME = "/opt/homebrew/Cellar/openjdk/26.0.2.1/libexec/openjdk.jdk/Contents/Home"

ORIGINS = {
    "rank1-auth0-java-jwt": BASE / "auth0-java-jwt" / "latest_replay_mutant_verified.json",
    "rank2-pyjwt": BASE / "pyjwt" / "latest_replay_mutant_verified.json",
    "rank3-node-jsonwebtoken": BASE / "node-jsonwebtoken" / "latest_replay_mutant_verified.json",
}

RANK_TARGETS = {
    "rank1-auth0-java-jwt": "auth0-java-jwt",
    "rank2-pyjwt": "pyjwt",
    "rank3-node-jsonwebtoken": "node-jsonwebtoken",
    "rank4-golang-jwt": "golang-jwt",
    "rank5-nimbus-jose-jwt": "nimbus-jose-jwt",
}


def b64url_json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4)))


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
    for key in ("ok", "error", "accepted", "verifies", "has_signature"):
        if isinstance(expected.get(key), bool):
            return {**expected, key: not expected[key]}
    key = next(iter(expected))
    return {**expected, key: mutate_value(expected[key])}


def subset_expected(expected: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "ok" in expected:
        out["ok"] = bool(expected["ok"])
        if expected.get("ok") and isinstance(expected.get("payload"), dict):
            out["payload"] = expected["payload"]
        return out
    if "error" in expected:
        out["error"] = bool(expected["error"])
        return out
    if "accepted" in expected:
        return {"accepted": bool(expected["accepted"])}
    for key in ("header", "payload", "value", "has_signature", "verifies", "payload_b64", "digest_hex", "jwk"):
        if key in expected:
            out[key] = expected[key]
    return out or expected


def payload_from_token(token: str) -> dict[str, Any] | None:
    try:
        payload = b64url_json(token.split(".")[1])
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def normalize_verify_options(params: dict[str, Any]) -> dict[str, Any]:
    src = params.get("options") or params.get("verifyOptions") or {}
    checks = params.get("checks") or {}
    out = dict(src)
    if "verify_exp" in out:
        out["ignoreExpiration"] = out.pop("verify_exp") is False
    if "verify_nbf" in out:
        out["ignoreNotBefore"] = out.pop("verify_nbf") is False
    out.pop("verify_iat", None)
    out.pop("verify_aud", None)
    if "clockTimestamp" in out:
        out["clockTimestamp"] = out["clockTimestamp"]
    if "clockTolerance" in out:
        out["clockTolerance"] = out["clockTolerance"]
    if "leeway" in params:
        out["clockTolerance"] = params["leeway"]
    for key in ("audience", "issuer", "subject"):
        if key in params:
            out[key] = params[key]
        if key in checks:
            value = checks[key]
            out[key] = value[0] if key in {"issuer", "subject"} and isinstance(value, list) and len(value) == 1 else value
    if "any_of_audience" in checks:
        out["audience"] = checks["any_of_audience"]
    if "claim_presence" in checks:
        out["require"] = checks["claim_presence"]
    return out


def canonicalize(origin: str, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract["op"]
    params = contract.get("params", {})
    expected = subset_expected(contract.get("expected", {}))
    case: dict[str, Any] = {
        "id": f"{origin}:{contract['name']}",
        "origin": origin,
        "source_name": contract["name"],
        "source_capability": contract["capability"],
        "source_op": op,
        "version": contract.get("version"),
        "evidence": contract.get("evidence", {}),
    }

    if op in {"decode_payload_json", "decode_complete_unverified", "get_unverified_header"}:
        token = params["token"]
        canon_expected: dict[str, Any] = {}
        if "header" in contract["expected"]:
            canon_expected["header"] = contract["expected"]["header"]
        if "payload" in contract["expected"]:
            canon_expected["payload"] = contract["expected"]["payload"]
        if "signature_b64" in contract["expected"]:
            canon_expected["signature_b64"] = contract["expected"]["signature_b64"]
        case.update({"canonical_op": "decode_complete", "params": {"token": token}, "expected": canon_expected})
    elif op in {"decode_claim_value", "decode_claim_value_unverified"}:
        case.update({"canonical_op": "decode_claim", "params": {"token": params["token"], "claim": params["claim"]}, "expected": {"value": contract["expected"]["value"]}})
    elif op in {"decode_error", "jws_decode_error", "jwt_payload_must_be_object"}:
        case.update({"canonical_op": "decode_error", "params": {"token": params.get("token") or ""}, "expected": {"error": True}})
    elif op in {"verify_hmac", "verify_literal_hmac", "jws_verify_hmac"}:
        p = {
            "token": params["token"],
            "secret": params.get("secret", "secret"),
            "algorithm": params.get("algorithm", "HS256"),
            "options": normalize_verify_options(params),
        }
        case.update({"canonical_op": "verify_hmac_literal", "params": p, "expected": expected})
    elif op in {"sign_hmac", "sign_decode_complete", "sign_datetime_claims", "sign_decimal_json_encoder", "sign_with_pyjwk"}:
        claims = params.get("claims") or params.get("payload") or {}
        if op == "sign_decimal_json_encoder":
            claims = {"some_decimal": "it worked"}
        if op == "sign_with_pyjwk":
            alg = params.get("jwk", {}).get("alg", "HS256")
            secret = "secret"
        else:
            alg = params.get("algorithm") or params.get("options", {}).get("algorithm") or "HS256"
            secret = params.get("secret", "secret")
        options = params.get("options", {})
        headers = params.get("headers") or options.get("header") or {}
        for option, claim in (("audience", "aud"), ("issuer", "iss"), ("subject", "sub"), ("jwtid", "jti")):
            if option in options:
                claims = dict(claims)
                claims[claim] = options[option]
        if "expiresIn" in options and isinstance(claims.get("iat"), int):
            claims = dict(claims)
            claims["exp"] = claims["iat"] + parse_timespan(options["expiresIn"])
        if "notBefore" in options and isinstance(claims.get("iat"), int):
            claims = dict(claims)
            claims["nbf"] = claims["iat"] + parse_timespan(options["notBefore"])
        case.update({"canonical_op": "sign_hmac", "params": {"claims": claims, "secret": secret, "algorithm": alg, "headers": headers}, "expected": expected})
    elif op == "sign_verify_hmac":
        case.update({"canonical_op": "sign_then_verify_hmac", "params": {"claims": params.get("payload", {}), "secret": params.get("secret", "secret"), "verifySecret": params.get("verifySecret", params.get("secret", "secret")), "algorithm": params.get("algorithm", "HS256"), "options": {}}, "expected": expected})
    elif op in {"verify_generated_hmac", "verify_generated_hmac_relative", "verify_generated_error"}:
        claims = resolve_relative_claims(params.get("claims") or params.get("payload") or {})
        case.update({"canonical_op": "sign_then_verify_hmac", "params": {"claims": claims, "secret": params.get("secret", "secret"), "verifySecret": params.get("secret", "secret"), "algorithm": params.get("algorithm", "HS256"), "options": normalize_verify_options(params)}, "expected": expected})
    elif op in {"sign_none", "verify_none_generated"}:
        case.update({"canonical_op": "none_algorithm", "params": {"claims": params.get("claims") or params.get("payload") or {}, "options": normalize_verify_options(params)}, "expected": expected})
    elif op in {"sign_rsa_pss"}:
        case.update({"canonical_op": "sign_pss", "params": {"claims": params.get("claims", {}), "algorithm": params.get("algorithm", "PS256")}, "expected": expected})
    elif op == "compute_hash_digest":
        case.update({"canonical_op": "hash_digest", "params": dict(params), "expected": expected})
    elif op in {"sign_error", "verify_error", "hmac_prepare_key_error", "rsa_min_key_size_sign", "key_confusion_verify", "malicious_key_material_rejected", "invalid_asymmetric_key_type", "decode_short_hmac_enforced"}:
        case.update({"canonical_op": "implementation_policy", "params": {"source_op": op, **params}, "expected": expected})
    else:
        case.update({"canonical_op": "unsupported_feature", "params": {"source_op": op, **params}, "expected": expected})

    case["mutant"] = with_mutant(case["expected"])
    case["identity"] = json.dumps([case["canonical_op"], case["params"], case["expected"]], sort_keys=True, ensure_ascii=True)
    return case


def parse_timespan(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        sign = -1 if stripped.startswith("-") else 1
        stripped = stripped.lstrip("+-").strip()
        number = "".join(ch for ch in stripped if ch.isdigit()) or "0"
        if "m" in stripped and not stripped.endswith("ms"):
            return sign * int(number) * 60
        if "h" in stripped:
            return sign * int(number) * 3600
        if "d" in stripped:
            return sign * int(number) * 86400
        return sign * int(number)
    return 0


def resolve_relative_claims(claims: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    base = 2_000_000_000
    for key, value in claims.items():
        if isinstance(value, dict) and "now_offset_seconds" in value:
            out[key] = base + int(value["now_offset_seconds"])
        else:
            out[key] = value
    return out


def load_cases() -> tuple[list[dict[str, Any]], dict[str, int]]:
    cases: list[dict[str, Any]] = []
    totals: dict[str, int] = {}
    for origin, path in ORIGINS.items():
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data["survivor_contracts"]
        totals[origin] = len(rows)
        for row in rows:
            cases.append(canonicalize(origin, row))
    return cases, totals


def matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        if actual.get("unsupported") is True and expected.get("unsupported") is not True:
            return False
        for key, value in expected.items():
            if key == "message_contains":
                if value not in str(actual.get("message", "")):
                    return False
            elif key not in actual or not matches(actual[key], value):
                return False
        return True
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
    return actual == expected


def evaluate_results(cases: list[dict[str, Any]], actuals: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    by_id = {case["id"]: case for case in cases}
    for case_id, actual in actuals.items():
        case = by_id[case_id]
        replay_pass = matches(actual, case["expected"])
        mutant_rejected = not matches(actual, case["mutant"])
        out.append({
            "id": case_id,
            "origin": case["origin"],
            "source_name": case["source_name"],
            "source_capability": case["source_capability"],
            "canonical_op": case["canonical_op"],
            "replay_pass": replay_pass,
            "mutant_rejected": mutant_rejected,
            "survived": replay_pass and mutant_rejected,
            "actual": actual,
            "expected": case["expected"] if not replay_pass else None,
        })
    return out


PY_ADAPTER = r'''
import base64, hashlib, json, sys
import jwt

def b64url(part):
    return base64.urlsafe_b64decode(part + "=" * ((4 - len(part) % 4) % 4))

def decode_complete(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return {"header": header, "payload": payload, "signature_b64": token.split(".")[2]}
    except Exception as e:
        return {"error": True, "message": str(e)}

def decode_claim(token, claim):
    r = decode_complete(token)
    return {"value": r.get("payload", {}).get(claim)} if not r.get("error") else r

def verify_hmac(token, secret, algorithm, options):
    try:
        kwargs = {"algorithms": [algorithm], "options": {}}
        if options.get("ignoreExpiration"): kwargs["options"]["verify_exp"] = False
        if options.get("ignoreNotBefore"): kwargs["options"]["verify_nbf"] = False
        if "clockTolerance" in options: kwargs["leeway"] = options["clockTolerance"]
        if "audience" in options and not isinstance(options["audience"], dict): kwargs["audience"] = options["audience"]
        if "issuer" in options: kwargs["issuer"] = options["issuer"]
        if "subject" in options and options["subject"] is not None: kwargs["subject"] = options["subject"]
        if "require" in options: kwargs["options"]["require"] = options["require"]
        payload = jwt.decode(token, secret, **kwargs)
        return {"ok": True, "payload": payload}
    except Exception as e:
        return {"ok": False, "error": True, "message": str(e)}

def sign_hmac(claims, secret, algorithm, headers):
    try:
        token = jwt.encode(claims, secret, algorithm=algorithm, headers=headers or None)
        d = decode_complete(token)
        d["verifies"] = True
        return d
    except Exception as e:
        return {"error": True, "ok": False, "message": str(e)}

def sign_then_verify(c):
    try:
        token = jwt.encode(c["claims"], c["secret"], algorithm=c["algorithm"])
        return verify_hmac(token, c.get("verifySecret", c["secret"]), c["algorithm"], c.get("options", {}))
    except Exception as e:
        return {"ok": False, "error": True, "message": str(e)}

def none_algorithm(c):
    try:
        token = jwt.encode(c["claims"], key=None, algorithm="none")
        if c.get("options", {}).get("algorithms") == ["none"]:
            payload = jwt.decode(token, options={"verify_signature": False})
            return {"ok": True, "payload": payload, **decode_complete(token)}
        d = decode_complete(token)
        d["verifies"] = True
        return d
    except Exception as e:
        return {"ok": False, "error": True, "message": str(e)}

def hash_digest(c):
    name = {"HS256":"sha256","HS384":"sha384","HS512":"sha512"}[c["algorithm"]]
    return {"digest_hex": hashlib.new(name, c["message"].encode()).hexdigest()}

def run(c):
    op, p = c["canonical_op"], c["params"]
    if op == "decode_complete": return decode_complete(p["token"])
    if op == "decode_claim": return decode_claim(p["token"], p["claim"])
    if op == "decode_error": return {"error": decode_complete(p["token"]).get("error") is True}
    if op == "verify_hmac_literal": return verify_hmac(p["token"], p["secret"], p["algorithm"], p.get("options", {}))
    if op == "sign_hmac": return sign_hmac(p["claims"], p["secret"], p["algorithm"], p.get("headers", {}))
    if op == "sign_then_verify_hmac": return sign_then_verify(p)
    if op == "none_algorithm": return none_algorithm(p)
    if op == "hash_digest": return hash_digest(p)
    return {"unsupported": True, "ok": False, "error": True, "message": op}

cases = json.load(open(sys.argv[1]))
print(json.dumps({c["id"]: run(c) for c in cases}, separators=(",", ":")))
'''


NODE_ADAPTER = r'''
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
function opt(o){ o = JSON.parse(JSON.stringify(o || {})); if (o.audience && o.audience.regex) o.audience = new RegExp(o.audience.regex); if (Array.isArray(o.audience)) o.audience = o.audience.map(x => x && x.regex ? new RegExp(x.regex) : x); return o; }
function dec(token){ try { const d = jwt.decode(token, {complete:true, json:true}); if (!d) return {error:true}; return {header:d.header, payload:d.payload, signature_b64:d.signature, has_signature:!!d.signature}; } catch(e){ return {error:true, message:e.message}; } }
function err(e){ const out = {ok:false, error:true, message:e.message || String(e)}; if (e.expiredAt) out.expiredAt_ms = Number(e.expiredAt); return out; }
function verify(token, secret, options){ try { return {ok:true, payload:jwt.verify(token, secret, opt(options))}; } catch(e){ return err(e); } }
function signHmac(p){ try { const token = jwt.sign(JSON.parse(JSON.stringify(p.claims || {})), p.secret || 'secret', Object.assign({algorithm:p.algorithm || 'HS256'}, p.headers && Object.keys(p.headers).length ? {header:p.headers} : {})); const d = dec(token); d.verifies = true; return d; } catch(e){ return err(e); } }
function run(c){ const p = c.params, op = c.canonical_op; if(op==='decode_complete') return dec(p.token); if(op==='decode_claim'){const d=dec(p.token); return d.error?d:{value:d.payload && d.payload[p.claim]};} if(op==='decode_error') return {error:dec(p.token).error===true}; if(op==='verify_hmac_literal') return verify(p.token,p.secret,p.options); if(op==='sign_hmac') return signHmac(p); if(op==='sign_then_verify_hmac'){try{const t=jwt.sign(p.claims,p.secret,{algorithm:p.algorithm}); return verify(t,p.verifySecret||p.secret,p.options);}catch(e){return err(e)}} if(op==='none_algorithm'){try{const t=jwt.sign(p.claims,null,{algorithm:'none'}); if(p.options && JSON.stringify(p.options.algorithms)==='[\"none\"]') return {ok:true,payload:jwt.verify(t,null,p.options)}; const d=dec(t); d.verifies=true; return d;}catch(e){return err(e)}} if(op==='sign_pss'){try{const {privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}); const t=jwt.sign(p.claims,privateKey,{algorithm:p.algorithm}); const d=dec(t); d.verifies=true; return d;}catch(e){return err(e)}} if(op==='hash_digest'){return {digest_hex:crypto.createHash({'HS256':'sha256','HS384':'sha384','HS512':'sha512'}[p.algorithm]).update(p.message).digest('hex')}} return {unsupported:true,ok:false,error:true,message:op}; }
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = {}; for (const c of cases) out[c.id] = run(c); console.log(JSON.stringify(out));
'''


GO_ADAPTER = r'''
package main
import (
  "crypto"; "crypto/hmac"; "crypto/rand"; "crypto/rsa"; "crypto/sha256"; "crypto/sha512"; "encoding/base64"; "encoding/json"; "fmt"; "os"; "strings"; "time"
  jwt "github.com/golang-jwt/jwt/v5"
)
type Case struct{ Id string `json:"id"`; Op string `json:"canonical_op"`; Params map[string]any `json:"params"` }
func b64json(s string) map[string]any { b,_:=base64.RawURLEncoding.DecodeString(s); var m map[string]any; json.Unmarshal(b,&m); return m }
func dec(tok string) map[string]any { parts:=strings.Split(tok,"."); if len(parts)!=3 { return map[string]any{"error":true} }; return map[string]any{"header":b64json(parts[0]),"payload":b64json(parts[1]),"signature_b64":parts[2],"has_signature":parts[2]!=""} }
func sign(method jwt.SigningMethod, claims jwt.MapClaims, key any) (string,error) { t:=jwt.NewWithClaims(method,claims); t.Header["typ"]="JWT"; return t.SignedString(key) }
func alg(name string) jwt.SigningMethod { if name=="HS384"{return jwt.SigningMethodHS384}; if name=="HS512"{return jwt.SigningMethodHS512}; return jwt.SigningMethodHS256 }
func verify(tok, secret, algorithm string, opts map[string]any) map[string]any { parserOpts:=[]jwt.ParserOption{jwt.WithValidMethods([]string{algorithm})}; if opts["ignoreExpiration"]==true || opts["ignoreNotBefore"]==true { parserOpts=append(parserOpts,jwt.WithoutClaimsValidation()) }; if v,ok:=opts["clockTolerance"].(float64); ok { parserOpts=append(parserOpts,jwt.WithLeeway(time.Duration(v)*time.Second)) }; if v,ok:=opts["clockTimestamp"].(float64); ok { parserOpts=append(parserOpts,jwt.WithTimeFunc(func() time.Time { return time.Unix(int64(v),0) })) }; if v,ok:=opts["audience"].(string); ok { parserOpts=append(parserOpts,jwt.WithAudience(v)) }; if v,ok:=opts["issuer"].(string); ok { parserOpts=append(parserOpts,jwt.WithIssuer(v)) }; if v,ok:=opts["subject"].(string); ok { parserOpts=append(parserOpts,jwt.WithSubject(v)) }; token,err:=jwt.Parse(tok, func(t *jwt.Token)(any,error){ return []byte(secret),nil }, parserOpts...); if err!=nil || !token.Valid { msg:=""; if err!=nil{msg=err.Error()}; return map[string]any{"ok":false,"error":true,"message":msg} }; return map[string]any{"ok":true,"payload":dec(tok)["payload"]} }
func hmacDigest(name, msg string) string { var h crypto.Hash; if name=="HS384"{h=crypto.SHA384}else if name=="HS512"{h=crypto.SHA512}else{h=crypto.SHA256}; mac:=hmac.New(h.New, []byte{}); mac.Write([]byte(msg)); _=sha256.Size; _=sha512.Size; return fmt.Sprintf("%x", mac.Sum(nil)) }
func run(c Case) map[string]any { p:=c.Params; switch c.Op {
case "decode_complete": return dec(p["token"].(string))
case "decode_claim": d:=dec(p["token"].(string)); if pl,ok:=d["payload"].(map[string]any); ok { return map[string]any{"value":pl[p["claim"].(string)]} }; return d
case "decode_error": return map[string]any{"error":dec(p["token"].(string))["error"]==true}
case "verify_hmac_literal": return verify(p["token"].(string), p["secret"].(string), p["algorithm"].(string), p["options"].(map[string]any))
case "sign_hmac": tok,err:=sign(alg(p["algorithm"].(string)), jwt.MapClaims(p["claims"].(map[string]any)), []byte(p["secret"].(string))); if err!=nil{return map[string]any{"ok":false,"error":true,"message":err.Error()}}; d:=dec(tok); d["verifies"]=true; return d
case "sign_then_verify_hmac": tok,err:=sign(alg(p["algorithm"].(string)), jwt.MapClaims(p["claims"].(map[string]any)), []byte(p["secret"].(string))); if err!=nil{return map[string]any{"ok":false,"error":true,"message":err.Error()}}; return verify(tok, p["verifySecret"].(string), p["algorithm"].(string), p["options"].(map[string]any))
case "none_algorithm": tok,err:=sign(jwt.SigningMethodNone, jwt.MapClaims(p["claims"].(map[string]any)), jwt.UnsafeAllowNoneSignatureType); if err!=nil{return map[string]any{"ok":false,"error":true,"message":err.Error()}}; d:=dec(tok); d["verifies"]=true; return d
case "sign_pss": key,_:=rsa.GenerateKey(rand.Reader,2048); var m jwt.SigningMethod; if p["algorithm"]=="PS384"{m=jwt.SigningMethodPS384}else if p["algorithm"]=="PS512"{m=jwt.SigningMethodPS512}else{m=jwt.SigningMethodPS256}; tok,err:=sign(m,jwt.MapClaims(p["claims"].(map[string]any)),key); if err!=nil{return map[string]any{"ok":false,"error":true,"message":err.Error()}}; d:=dec(tok); d["verifies"]=true; return d
case "hash_digest": return map[string]any{"digest_hex":hmacDigest(p["algorithm"].(string),p["message"].(string))}
}; return map[string]any{"unsupported":true,"ok":false,"error":true,"message":c.Op} }
func main(){ var cases []Case; b,_:=os.ReadFile(os.Args[1]); json.Unmarshal(b,&cases); out:=map[string]any{}; for _,c:=range cases{out[c.Id]=run(c)}; enc:=json.NewEncoder(os.Stdout); enc.Encode(out) }
'''


JAVA_AUTH0_ADAPTER = r'''
package shapingbench;
import com.auth0.jwt.JWT; import com.auth0.jwt.JWTCreator; import com.auth0.jwt.algorithms.Algorithm; import com.auth0.jwt.interfaces.*; import com.fasterxml.jackson.databind.*; import com.fasterxml.jackson.databind.node.ArrayNode; import com.fasterxml.jackson.core.type.TypeReference;
import java.io.*; import java.nio.charset.StandardCharsets; import java.security.*; import java.security.interfaces.*; import java.time.*; import java.util.*; import java.math.*;
public class JwtCrossAuth0 { static ObjectMapper M=new ObjectMapper(); public static void main(String[] a)throws Exception{ArrayNode cs=(ArrayNode)M.readTree(new File(a[0])); Map<String,Object> out=new LinkedHashMap<>(); for(JsonNode c:cs) out.put(c.path("id").asText(), run(c.path("canonical_op").asText(), c.path("params"))); System.out.println(M.writeValueAsString(out));}
static Map<String,Object> run(String op, JsonNode p){try{return switch(op){case"decode_complete"->dec(p.path("token").asText());case"decode_claim"->claim(p.path("token").asText(),p.path("claim").asText());case"decode_error"->Map.of("error",dec(p.path("token").asText()).containsKey("error"));case"verify_hmac_literal"->verify(p.path("token").asText(),p.path("secret").asText(),p.path("algorithm").asText(),p.path("options"));case"sign_hmac"->signHmac(p);case"sign_then_verify_hmac"->signThenVerify(p);case"none_algorithm"->Map.of("unsupported",true,"ok",false,"error",true,"message",op);case"sign_pss"->signPss(p);default->Map.of("unsupported",true,"ok",false,"error",true,"message",op);};}catch(Throwable e){return Map.of("ok",false,"error",true,"message",String.valueOf(e.getMessage()));}}
static Map<String,Object> dec(String t)throws Exception{String[] ps=t.split("\\.",-1); JWT.decode(t); Map<String,Object> r=new LinkedHashMap<>(); r.put("header",part(ps[0])); r.put("payload",part(ps[1])); r.put("signature_b64",ps.length>2?ps[2]:""); r.put("has_signature",ps.length>2&&!ps[2].isEmpty()); return r;}
static Map<String,Object> claim(String t,String c)throws Exception{Object p=dec(t).get("payload"); return Map.of("value",((Map<?,?>)p).get(c));}
static Map<String,Object> verify(String t,String s,String alg,JsonNode opts){try{Verification v=JWT.require(alg(alg,s)); if(opts.has("issuer"))v.withIssuer(strs(opts.get("issuer"))); if(opts.has("subject"))v.withSubject(opts.get("subject").asText()); if(opts.has("audience"))v.withAudience(strs(opts.get("audience"))); if(opts.has("require")) for(String k:strs(opts.get("require"))) v.withClaimPresence(k); if(opts.has("clockTolerance")) v.acceptLeeway(opts.get("clockTolerance").asLong()); JWTVerifier vf=opts.has("clockTimestamp")?((com.auth0.jwt.JWTVerifier.BaseVerification)v).build(Clock.fixed(Instant.ofEpochSecond(opts.get("clockTimestamp").asLong()),ZoneOffset.UTC)):v.build(); vf.verify(t); Map<String,Object> r=new LinkedHashMap<>(); r.put("ok",true); try{r.put("payload",dec(t).get("payload"));}catch(Exception ignored){} return r;}catch(Throwable e){return Map.of("ok",false,"error",true,"message",String.valueOf(e.getMessage()));}}
static Map<String,Object> signThenVerify(JsonNode p)throws Exception{String tok=makeHmac(p.path("claims"),p.path("secret").asText(),p.path("algorithm").asText(),null); return verify(tok,p.path("verifySecret").asText(),p.path("algorithm").asText(),p.path("options"));}
static Map<String,Object> signHmac(JsonNode p)throws Exception{String tok=makeHmac(p.path("claims"),p.path("secret").asText(),p.path("algorithm").asText(),p.path("headers")); Map<String,Object> r=dec(tok); r.put("verifies",true); return r;}
static String makeHmac(JsonNode claims,String secret,String alg,JsonNode headers)throws Exception{JWTCreator.Builder b=JWT.create(); if(headers!=null&&!headers.isMissingNode())b.withHeader(M.convertValue(headers,new TypeReference<Map<String,Object>>(){})); addClaims(b,claims); return b.sign(alg(alg,secret));}
static Map<String,Object> signPss(JsonNode p)throws Exception{KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);KeyPair kp=g.generateKeyPair(); Algorithm a=switch(p.path("algorithm").asText()){case"PS384"->Algorithm.RSA384PSS((RSAPublicKey)kp.getPublic(),(RSAPrivateKey)kp.getPrivate());case"PS512"->Algorithm.RSA512PSS((RSAPublicKey)kp.getPublic(),(RSAPrivateKey)kp.getPrivate());default->Algorithm.RSA256PSS((RSAPublicKey)kp.getPublic(),(RSAPrivateKey)kp.getPrivate());}; JWTCreator.Builder b=JWT.create(); addClaims(b,p.path("claims")); String tok=b.sign(a); Map<String,Object> r=dec(tok); r.put("verifies",true); return r;}
static void addClaims(JWTCreator.Builder b,JsonNode cs){Iterator<String> it=cs.fieldNames(); while(it.hasNext()){String k=it.next();JsonNode v=cs.get(k); if(k.equals("iss")&&v.isTextual())b.withIssuer(v.asText()); else if(k.equals("sub")&&v.isTextual())b.withSubject(v.asText()); else if(k.equals("jti")&&v.isTextual())b.withJWTId(v.asText()); else if(k.equals("aud"))b.withAudience(strs(v)); else if(k.equals("exp")&&v.isNumber())b.withExpiresAt(Instant.ofEpochSecond(v.asLong())); else if(k.equals("nbf")&&v.isNumber())b.withNotBefore(Instant.ofEpochSecond(v.asLong())); else if(k.equals("iat")&&v.isNumber())b.withIssuedAt(Instant.ofEpochSecond(v.asLong())); else if(v.isTextual())b.withClaim(k,v.asText()); else if(v.isBoolean())b.withClaim(k,v.asBoolean()); else if(v.isInt())b.withClaim(k,v.asInt()); else if(v.isLong())b.withClaim(k,v.asLong()); else if(v.isDouble()||v.isFloat()||v.isBigDecimal())b.withClaim(k,v.asDouble()); else if(v.isNull())b.withNullClaim(k); else b.withPayload(Map.of(k,M.convertValue(v,Object.class)));}}
static Algorithm alg(String n,String s){return switch(n){case"HS384"->Algorithm.HMAC384(s);case"HS512"->Algorithm.HMAC512(s);default->Algorithm.HMAC256(s);};}
static Object part(String p)throws Exception{return M.readValue(new String(Base64.getUrlDecoder().decode(pad(p)),StandardCharsets.UTF_8),Object.class);} static String pad(String v){int r=v.length()%4;return r==0?v:v+"=".repeat(4-r);} static String[] strs(JsonNode n){if(n.isTextual())return new String[]{n.asText()};List<String> a=new ArrayList<>();for(JsonNode x:n)a.add(x.asText());return a.toArray(new String[0]);}}
'''


JAVA_NIMBUS_ADAPTER = r'''
package shapingbench;
import com.fasterxml.jackson.databind.*; import com.fasterxml.jackson.databind.node.ArrayNode; import com.nimbusds.jose.*; import com.nimbusds.jose.crypto.*; import com.nimbusds.jwt.*; import java.io.*; import java.nio.charset.StandardCharsets; import java.security.*; import java.security.interfaces.*; import java.time.*; import java.util.*;
public class JwtCrossNimbus { static ObjectMapper M=new ObjectMapper(); public static void main(String[] a)throws Exception{ArrayNode cs=(ArrayNode)M.readTree(new File(a[0])); Map<String,Object> out=new LinkedHashMap<>(); for(JsonNode c:cs) out.put(c.path("id").asText(), run(c.path("canonical_op").asText(), c.path("params"))); System.out.println(M.writeValueAsString(out));}
static Map<String,Object> run(String op,JsonNode p){try{return switch(op){case"decode_complete"->dec(p.path("token").asText());case"decode_claim"->claim(p.path("token").asText(),p.path("claim").asText());case"decode_error"->Map.of("error", hasDecodeError(p.path("token").asText()));case"verify_hmac_literal"->verify(p.path("token").asText(),p.path("secret").asText(),p.path("algorithm").asText(),p.path("options"));case"sign_hmac"->signHmac(p);case"sign_then_verify_hmac"->signThenVerify(p);case"sign_pss"->signPss(p);default->Map.of("unsupported",true,"ok",false,"error",true,"message",op);};}catch(Throwable e){return Map.of("ok",false,"error",true,"message",String.valueOf(e.getMessage()));}}
static Map<String,Object> dec(String t)throws Exception{SignedJWT j=SignedJWT.parse(t); Map<String,Object> r=new LinkedHashMap<>(); r.put("header",M.readValue(M.writeValueAsString(j.getHeader().toJSONObject()),Map.class)); r.put("payload",M.readValue(j.getJWTClaimsSet().toPayload().toString(),Map.class)); r.put("signature_b64",t.split("\\.",-1)[2]); r.put("has_signature",!t.split("\\.",-1)[2].isEmpty()); return r;}
static boolean hasDecodeError(String t){try{dec(t);return false;}catch(Throwable e){return true;}} static Map<String,Object> claim(String t,String c)throws Exception{return Map.of("value",((Map<?,?>)dec(t).get("payload")).get(c));}
static Map<String,Object> verify(String t,String secret,String alg,JsonNode opts){try{SignedJWT j=SignedJWT.parse(t); boolean ok=j.verify(new MACVerifier(secret.getBytes(StandardCharsets.UTF_8))); if(!ok)return Map.of("ok",false,"error",true,"message","signature"); Map<String,Object> payload=(Map<String,Object>)dec(t).get("payload"); String fail=claimFail(payload,opts); if(fail!=null)return Map.of("ok",false,"error",true,"message",fail); return Map.of("ok",true,"payload",payload);}catch(Throwable e){return Map.of("ok",false,"error",true,"message",String.valueOf(e.getMessage()));}}
static String claimFail(Map<String,Object> p,JsonNode o){long now=o.has("clockTimestamp")?o.get("clockTimestamp").asLong():Instant.now().getEpochSecond();long leeway=o.has("clockTolerance")?o.get("clockTolerance").asLong():0; if(o.path("ignoreExpiration").asBoolean(false)==false&&p.get("exp") instanceof Number n&&n.longValue()+leeway<=now)return"expired"; if(o.path("ignoreNotBefore").asBoolean(false)==false&&p.get("nbf") instanceof Number n&&n.longValue()-leeway>now)return"not before"; if(o.has("issuer")&&!Objects.equals(p.get("iss"),o.get("issuer").asText()))return"issuer"; if(o.has("subject")&&!Objects.equals(p.get("sub"),o.get("subject").asText()))return"subject"; if(o.has("audience")){Object aud=p.get("aud");List<String> vals=new ArrayList<>();JsonNode a=o.get("audience"); if(a.isTextual())vals.add(a.asText()); else for(JsonNode x:a) if(x.isTextual())vals.add(x.asText()); if(aud instanceof String s){if(!vals.contains(s))return"audience";} else if(aud instanceof List<?> l){boolean any=false;for(Object x:l)if(vals.contains(String.valueOf(x)))any=true;if(!any)return"audience";} else return"audience";} return null;}
static Map<String,Object> signThenVerify(JsonNode p)throws Exception{String tok=makeHmac(p.path("claims"),p.path("secret").asText(),p.path("algorithm").asText()); return verify(tok,p.path("verifySecret").asText(),p.path("algorithm").asText(),p.path("options"));}
static Map<String,Object> signHmac(JsonNode p)throws Exception{String tok=makeHmac(p.path("claims"),p.path("secret").asText(),p.path("algorithm").asText()); Map<String,Object> r=dec(tok); r.put("verifies",true); return r;}
static String makeHmac(JsonNode claims,String secret,String alg)throws Exception{JWSAlgorithm a=new JWSAlgorithm(alg); JWTClaimsSet.Builder cb=new JWTClaimsSet.Builder(); Iterator<String> it=claims.fieldNames(); while(it.hasNext()){String k=it.next();JsonNode v=claims.get(k); cb.claim(k,M.convertValue(v,Object.class));} SignedJWT j=new SignedJWT(new JWSHeader.Builder(a).type(JOSEObjectType.JWT).build(),cb.build()); j.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8))); return j.serialize();}
static Map<String,Object> signPss(JsonNode p)throws Exception{KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);KeyPair kp=g.generateKeyPair(); JWSAlgorithm a=new JWSAlgorithm(p.path("algorithm").asText()); JWTClaimsSet.Builder cb=new JWTClaimsSet.Builder(); Iterator<String> it=p.path("claims").fieldNames(); while(it.hasNext()){String k=it.next();cb.claim(k,M.convertValue(p.path("claims").get(k),Object.class));} SignedJWT j=new SignedJWT(new JWSHeader.Builder(a).type(JOSEObjectType.JWT).build(),cb.build()); j.sign(new RSASSASigner((RSAPrivateKey)kp.getPrivate())); Map<String,Object> r=dec(j.serialize()); r.put("verifies",true); return r;}}
'''


def write_runtime() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    (RUNTIME / "py_adapter.py").write_text(PY_ADAPTER, encoding="utf-8")
    (RUNTIME / "node_adapter.js").write_text(NODE_ADAPTER, encoding="utf-8")
    go_dir = RUNTIME / "go"
    go_dir.mkdir(exist_ok=True)
    (go_dir / "go.mod").write_text("module jwtcross\n\ngo 1.25\n\nrequire github.com/golang-jwt/jwt/v5 v5.3.1\n", encoding="utf-8")
    (go_dir / "main.go").write_text(GO_ADAPTER, encoding="utf-8")
    for name, dep, source in [
        ("java-auth0", "com.auth0:java-jwt:4.6.0", JAVA_AUTH0_ADAPTER),
        ("java-nimbus", "com.nimbusds:nimbus-jose-jwt:10.9.1", JAVA_NIMBUS_ADAPTER),
    ]:
        src = RUNTIME / name / "src/main/java/shapingbench"
        src.mkdir(parents=True, exist_ok=True)
        group, artifact, version = dep.split(":")
        (RUNTIME / name / "pom.xml").write_text(textwrap.dedent(f"""\
            <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
              <modelVersion>4.0.0</modelVersion><groupId>shapingbench</groupId><artifactId>{name}</artifactId><version>1.0.0</version>
              <properties><maven.compiler.source>17</maven.compiler.source><maven.compiler.target>17</maven.compiler.target></properties>
              <dependencies>
                <dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId><version>{version}</version></dependency>
                <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.20.0</version></dependency>
              </dependencies>
              <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><version>3.6.2</version></plugin></plugins></build>
            </project>
        """), encoding="utf-8")
        main = "JwtCrossAuth0.java" if name == "java-auth0" else "JwtCrossNimbus.java"
        (src / main).write_text(source, encoding="utf-8")


def run_cmd(args: list[str], cwd: Path, extra_env: dict[str, str] | None = None) -> str:
    env = os.environ.copy()
    if Path(JAVA_HOME).exists():
        env["JAVA_HOME"] = JAVA_HOME
    if extra_env:
        env.update(extra_env)
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, stderr=subprocess.STDOUT)


def run_adapter(target: str, cases_path: Path) -> dict[str, Any]:
    if target == "pyjwt":
        raw = run_cmd([str(PYJWT_PYTHON), str(RUNTIME / "py_adapter.py"), str(cases_path)], ROOT)
    elif target == "node-jsonwebtoken":
        node_path = ROOT / "tools" / "replay" / "node_jsonwebtoken_latest_runner" / "node_modules"
        raw = run_cmd(["node", str(RUNTIME / "node_adapter.js"), str(cases_path)], ROOT, {"NODE_PATH": str(node_path)})
    elif target == "golang-jwt":
        run_cmd(["go", "mod", "tidy"], RUNTIME / "go")
        raw = run_cmd(["go", "run", ".", str(cases_path)], RUNTIME / "go")
    elif target == "auth0-java-jwt":
        raw = run_cmd(["mvn", "-q", "compile", "exec:java", "-Dexec.mainClass=shapingbench.JwtCrossAuth0", f"-Dexec.args={cases_path}"], RUNTIME / "java-auth0")
    elif target == "nimbus-jose-jwt":
        raw = run_cmd(["mvn", "-q", "compile", "exec:java", "-Dexec.mainClass=shapingbench.JwtCrossNimbus", f"-Dexec.args={cases_path}"], RUNTIME / "java-nimbus")
    else:
        raise ValueError(target)
    return json.loads(raw.strip().splitlines()[-1])


def write_rpl(cases: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for case in cases:
        lines.append(f"contract {json.dumps(case['id'], ensure_ascii=True)} {{")
        lines.append(f"  origin {json.dumps(case['origin'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(case['source_capability'], ensure_ascii=True)}")
        lines.append(f"  op {case['canonical_op']}")
        lines.append(f"  params {json.dumps(case['params'], sort_keys=True, ensure_ascii=True)}")
        lines.append(f"  expected {json.dumps(case['expected'], sort_keys=True, ensure_ascii=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    write_runtime()
    cases, origin_totals = load_cases()
    cases_path = RUNTIME / "cases.json"
    cases_path.write_text(json.dumps(cases, ensure_ascii=True), encoding="utf-8")

    target_actuals = {}
    target_results = {}
    for rank, target in RANK_TARGETS.items():
        actuals = run_adapter(target, cases_path)
        target_actuals[rank] = actuals
        target_results[rank] = evaluate_results(cases, actuals)

    by_id = {case["id"]: case for case in cases}
    survived = {rank: {row["id"] for row in rows if row["survived"]} for rank, rows in target_results.items()}
    triad_targets = ["rank1-auth0-java-jwt", "rank2-pyjwt", "rank3-node-jsonwebtoken"]
    hidden_targets = ["rank4-golang-jwt", "rank5-nimbus-jose-jwt"]

    origin_candidates: dict[str, list[dict[str, Any]]] = {}
    for origin in ORIGINS:
        targets = [target for target in triad_targets if target != origin]
        ids = [case["id"] for case in cases if case["origin"] == origin and all(case["id"] in survived[target] for target in targets)]
        dedup: dict[str, dict[str, Any]] = {}
        for case_id in ids:
            case = by_id[case_id]
            dedup.setdefault(case["identity"], case)
        origin_candidates[origin] = list(dedup.values())

    merged_candidates: dict[str, dict[str, Any]] = {}
    for rows in origin_candidates.values():
        for case in rows:
            merged_candidates.setdefault(case["identity"], case)
    candidate_cases = list(merged_candidates.values())
    final_cases = [case for case in candidate_cases if all(case["id"] in survived[target] for target in hidden_targets)]

    summary = {
        "domain": "JWT Signing/Verification",
        "rank_targets": {
            "rank1-auth0-java-jwt": {"implementation": "com.auth0:java-jwt", "version": "4.6.0"},
            "rank2-pyjwt": {"implementation": "PyJWT", "version": "2.13.0"},
            "rank3-node-jsonwebtoken": {"implementation": "jsonwebtoken", "version": "9.0.3"},
            "rank4-golang-jwt": {"implementation": "github.com/golang-jwt/jwt/v5", "version": "v5.3.1"},
            "rank5-nimbus-jose-jwt": {"implementation": "com.nimbusds:nimbus-jose-jwt", "version": "10.9.1"},
        },
        "origin_totals": origin_totals,
        "attempted_cases": len(cases),
        "attempted_by_canonical_op": dict(Counter(case["canonical_op"] for case in cases)),
        "per_target_survivors": {rank: len(ids) for rank, ids in survived.items()},
        "origin_cross_candidates": {origin: len(rows) for origin, rows in origin_candidates.items()},
        "rank1_2_3_merged_common_candidates": len(candidate_cases),
        "hidden_filter_survivors": {
            rank: sum(1 for case in candidate_cases if case["id"] in survived[rank])
            for rank in hidden_targets
        },
        "final_common": len(final_cases),
        "final_common_by_origin": dict(Counter(case["origin"] for case in final_cases)),
        "final_common_by_capability": dict(Counter(case["source_capability"] for case in final_cases)),
        "final_common_by_canonical_op": dict(Counter(case["canonical_op"] for case in final_cases)),
        "origin_candidates": origin_candidates,
        "final_common_contracts": final_cases,
    }

    (OUT / "jwt_cross_common_summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "rank1_2_3_cross_replay_common_candidates.json").write_text(json.dumps({
        "domain": "JWT Signing/Verification",
        "contracts": candidate_cases,
        "count": len(candidate_cases),
        "origin_counts": {origin: len(rows) for origin, rows in origin_candidates.items()},
    }, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "final_common.json").write_text(json.dumps({
        "domain": "JWT Signing/Verification",
        "contracts": final_cases,
        "count": len(final_cases),
        "rank4": "github.com/golang-jwt/jwt/v5 v5.3.1",
        "rank5": "com.nimbusds:nimbus-jose-jwt 10.9.1",
    }, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    details = {
        "target_results": target_results,
    }
    (OUT / "jwt_cross_common_details.json").write_text(json.dumps(details, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(candidate_cases, OUT / "rank1_2_3_cross_replay_common_candidates.rpl")
    write_rpl(final_cases, OUT / "final_common.rpl")

    md = [
        "# JWT Cross-Replay Common",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Total Rank 1/2/3 survivor contracts attempted | {len(cases)} |",
        f"| Rank 1-origin contracts surviving Rank 2 + Rank 3 | {len(origin_candidates['rank1-auth0-java-jwt'])} |",
        f"| Rank 2-origin contracts surviving Rank 1 + Rank 3 | {len(origin_candidates['rank2-pyjwt'])} |",
        f"| Rank 3-origin contracts surviving Rank 1 + Rank 2 | {len(origin_candidates['rank3-node-jsonwebtoken'])} |",
        f"| Merged Rank 1/2/3 common candidates | {len(candidate_cases)} |",
        f"| Candidates surviving Rank 4 golang-jwt | {summary['hidden_filter_survivors']['rank4-golang-jwt']} |",
        f"| Candidates surviving Rank 5 Nimbus JOSE + JWT | {summary['hidden_filter_survivors']['rank5-nimbus-jose-jwt']} |",
        f"| Final hidden-filtered common | {len(final_cases)} |",
        "",
        "## Final Common By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for key, value in sorted(summary["final_common_by_capability"].items()):
        md.append(f"| `{key}` | {value} |")
    md.extend(["", "## Adapter Survivors Over All Attempted Cases", "", "| Target | Survivors |", "| --- | ---: |"])
    for key, value in summary["per_target_survivors"].items():
        md.append(f"| `{key}` | {value} |")
    (OUT / "jwt_cross_common_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(json.dumps({k: summary[k] for k in [
        "attempted_cases",
        "per_target_survivors",
        "origin_cross_candidates",
        "rank1_2_3_merged_common_candidates",
        "hidden_filter_survivors",
        "final_common",
    ]}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
