#!/usr/bin/env python3
"""Replay golang-jwt/jwt origin contracts against github.com/golang-jwt/jwt/v5 v5.3.1."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

from jwt_origin_common import ROOT, mark_common_overlap, matches, write_rpl


BASE = ROOT / "contracts" / "jwt" / "golang-jwt"
INPUT = BASE / "all_releases_language_independent.summary.json"
OUT_JSON = BASE / "latest_replay_mutant_verified.json"
OUT_MD = BASE / "latest_replay_mutant_verified.md"
OUT_RPL = BASE / "latest_replay_mutant_verified.rpl"
NON_COMMON_JSON = BASE / "origin_non_common.json"
NON_COMMON_MD = BASE / "origin_non_common.md"
RUNNER = ROOT / "tools" / "replay" / "jwt_golang_latest_runner"


GO_MOD = """module jwt_golang_latest_runner

go 1.25

require github.com/golang-jwt/jwt/v5 v5.3.1
"""


GO_CODE = r'''
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Contract struct {
	Name     string         `json:"name"`
	Op       string         `json:"op"`
	Params   map[string]any `json:"params"`
	Expected map[string]any `json:"expected"`
	Mutant   map[string]any `json:"mutant"`
}

func b64(part string) ([]byte, error) {
	part = strings.TrimRight(part, "=")
	return base64.RawURLEncoding.DecodeString(part)
}

func b64JSON(part string) map[string]any {
	raw, err := b64(part)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return normalize(out).(map[string]any)
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			x[k] = normalize(v)
		}
		return x
	case []any:
		for i, v := range x {
			x[i] = normalize(v)
		}
		return x
	case float64:
		if x == float64(int64(x)) {
			return int64(x)
		}
		return x
	default:
		return v
	}
}

func decodeComplete(p map[string]any) map[string]any {
	token := p["token"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return map[string]any{"error": true}
	}
	header := b64JSON(parts[0])
	payload := b64JSON(parts[1])
	if header == nil || payload == nil {
		return map[string]any{"error": true}
	}
	return map[string]any{"header": header, "payload": payload, "signature_b64": parts[2], "has_signature": parts[2] != ""}
}

func secretBytes(p map[string]any) []byte {
	if s, ok := p["secret_b64"].(string); ok {
		raw, _ := base64.StdEncoding.DecodeString(s)
		return raw
	}
	if s, ok := p["secret"].(string); ok {
		return []byte(s)
	}
	return []byte("secret")
}

func alg(name string) jwt.SigningMethod {
	switch name {
	case "HS384":
		return jwt.SigningMethodHS384
	case "HS512":
		return jwt.SigningMethodHS512
	default:
		return jwt.SigningMethodHS256
	}
}

func parserOptions(algorithm string, opts map[string]any) []jwt.ParserOption {
	out := []jwt.ParserOption{jwt.WithValidMethods([]string{algorithm})}
	if methods, ok := opts["validMethods"].([]any); ok {
		valid := []string{}
		for _, m := range methods {
			valid = append(valid, fmt.Sprint(m))
		}
		out = []jwt.ParserOption{jwt.WithValidMethods(valid)}
	}
	if opts["ignoreExpiration"] == true || opts["ignoreNotBefore"] == true {
		out = append(out, jwt.WithoutClaimsValidation())
	}
	if v, ok := opts["clockTimestamp"].(float64); ok {
		out = append(out, jwt.WithTimeFunc(func() time.Time { return time.Unix(int64(v), 0) }))
	}
	if v, ok := opts["clockTolerance"].(float64); ok {
		out = append(out, jwt.WithLeeway(time.Duration(v)*time.Second))
	}
	if v, ok := opts["issuer"].(string); ok {
		out = append(out, jwt.WithIssuer(v))
	}
	if v, ok := opts["subject"].(string); ok {
		out = append(out, jwt.WithSubject(v))
	}
	if v, ok := opts["audience"].(string); ok {
		out = append(out, jwt.WithAudience(v))
	}
	if opts["expirationRequired"] == true {
		out = append(out, jwt.WithExpirationRequired())
	}
	return out
}

func verifyHMAC(p map[string]any) map[string]any {
	token, err := jwt.Parse(p["token"].(string), func(t *jwt.Token) (any, error) { return secretBytes(p), nil }, parserOptions(p["algorithm"].(string), obj(p["options"]))...)
	if err != nil || !token.Valid {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		return map[string]any{"ok": false, "error": true, "message": msg}
	}
	return map[string]any{"ok": true, "payload": decodeComplete(map[string]any{"token": p["token"]})["payload"]}
}

func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func signHMAC(p map[string]any) map[string]any {
	token := jwt.NewWithClaims(alg(p["algorithm"].(string)), jwt.MapClaims(obj(p["claims"])))
	token.Header["typ"] = "JWT"
	for k, v := range obj(p["headers"]) {
		token.Header[k] = v
	}
	s, err := token.SignedString([]byte(p["secret"].(string)))
	if err != nil {
		return map[string]any{"ok": false, "error": true, "message": err.Error()}
	}
	out := decodeComplete(map[string]any{"token": s})
	out["verifies"] = true
	return out
}

func verifyGeneratedHMAC(p map[string]any) map[string]any {
	token := jwt.NewWithClaims(alg(p["algorithm"].(string)), jwt.MapClaims(obj(p["claims"])))
	token.Header["typ"] = "JWT"
	s, err := token.SignedString([]byte(p["secret"].(string)))
	if err != nil {
		return map[string]any{"ok": false, "error": true, "message": err.Error()}
	}
	return verifyHMAC(map[string]any{"token": s, "secret": p["verifySecret"], "algorithm": p["algorithm"], "options": obj(p["options"])})
}

func signNone(p map[string]any) map[string]any {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(obj(p["claims"])))
	token.Header["typ"] = "JWT"
	s, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return map[string]any{"ok": false, "error": true, "message": err.Error()}
	}
	out := decodeComplete(map[string]any{"token": s})
	out["verifies"] = true
	return out
}

func claimGetAudience(p map[string]any) map[string]any {
	aud, err := jwt.MapClaims(obj(p["claims"])).GetAudience()
	if err != nil {
		return map[string]any{"error": true, "message": err.Error()}
	}
	return map[string]any{"audience": []string(aud), "error": false}
}

func hmacDigest(p map[string]any) map[string]any {
	msg := []byte(p["message"].(string))
	key := []byte{}
	var sum []byte
	switch p["algorithm"].(string) {
	case "HS384":
		h := hmac.New(sha512.New384, key)
		h.Write(msg)
		sum = h.Sum(nil)
	case "HS512":
		h := hmac.New(sha512.New, key)
		h.Write(msg)
		sum = h.Sum(nil)
	default:
		h := hmac.New(sha256.New, key)
		h.Write(msg)
		sum = h.Sum(nil)
	}
	return map[string]any{"digest_hex": fmt.Sprintf("%x", sum)}
}

func run(c Contract) map[string]any {
	switch c.Op {
	case "decode_complete":
		return decodeComplete(c.Params)
	case "decode_claim_value":
		d := decodeComplete(c.Params)
		if p, ok := d["payload"].(map[string]any); ok {
			return map[string]any{"value": p[c.Params["claim"].(string)]}
		}
		return d
	case "decode_error":
		return map[string]any{"error": decodeComplete(c.Params)["error"] == true}
	case "verify_hmac":
		return verifyHMAC(c.Params)
	case "sign_hmac":
		return signHMAC(c.Params)
	case "verify_generated_hmac":
		return verifyGeneratedHMAC(c.Params)
	case "sign_none":
		return signNone(c.Params)
	case "claim_get_audience":
		return claimGetAudience(c.Params)
	case "compute_hash_digest":
		return hmacDigest(c.Params)
	default:
		return map[string]any{"unsupported": true, "error": true, "message": c.Op}
	}
}

func main() {
	var root struct{ Contracts []Contract `json:"contracts"` }
	raw, _ := os.ReadFile(os.Args[1])
	json.Unmarshal(raw, &root)
	out := map[string]any{}
	for _, c := range root.Contracts {
		out[c.Name] = run(c)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(out)
}
'''


def ensure_runner() -> None:
    RUNNER.mkdir(parents=True, exist_ok=True)
    (RUNNER / "go.mod").write_text(GO_MOD, encoding="utf-8")
    (RUNNER / "main.go").write_text(GO_CODE, encoding="utf-8")
    subprocess.run(["go", "mod", "tidy"], cwd=RUNNER, check=True)


def main() -> int:
    ensure_runner()
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    completed = subprocess.run(["go", "run", ".", str(INPUT)], cwd=RUNNER, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    actuals = json.loads(completed.stdout.strip().splitlines()[-1])
    results = []
    survivors = []
    for contract in data["contracts"]:
        actual = actuals.get(contract["name"], {"runner_error": "missing actual"})
        replay_pass = matches(actual, contract["expected"])
        mutant_rejected = not matches(actual, contract["mutant"])
        survived = replay_pass and mutant_rejected
        results.append({"name": contract["name"], "capability": contract["capability"], "op": contract["op"], "replay_pass": replay_pass, "mutant_rejected": mutant_rejected, "survived": survived, "actual": actual, "expected": None if replay_pass else contract["expected"]})
        if survived:
            survivors.append(contract)

    marked_survivors, overlap_summary = mark_common_overlap(survivors, "rank4-golang-jwt")
    non_common = [row for row in marked_survivors if not row["overlaps_final_common_349"]]
    result = {
        "implementation": "github.com/golang-jwt/jwt/v5",
        "version": "v5.3.1",
        "contracts_total": len(data["contracts"]),
        "replay_pass": sum(1 for row in results if row["replay_pass"]),
        "mutant_rejected": sum(1 for row in results if row["mutant_rejected"]),
        "survivors": len(survivors),
        **overlap_summary,
        "survivor_contracts": marked_survivors,
        "origin_non_common_contracts": non_common,
        "results": results,
    }
    OUT_JSON.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    NON_COMMON_JSON.write_text(json.dumps({"domain": "JWT Signing/Verification", "origin": "rank4-golang-jwt", "count": len(non_common), "contracts": non_common}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(marked_survivors, OUT_RPL)

    by_cap = Counter(row["capability"] for row in marked_survivors)
    non_common_by_cap = Counter(row["capability"] for row in non_common)
    failed = [row for row in results if not row["survived"]]
    lines = [
        "# golang-jwt/jwt Latest Replay + Mutant Verification",
        "",
        "- Implementation: `github.com/golang-jwt/jwt/v5`",
        "- Latest version tested: `v5.3.1`",
        f"- Contracts evaluated: {result['contracts_total']}",
        f"- Replay passed: {result['replay_pass']}",
        f"- Mutant rejected: {result['mutant_rejected']}",
        f"- Latest surviving contracts: {result['survivors']}",
        f"- Overlap with final common 349: {result['survivor_overlap_with_final_common']}",
        f"- Origin non-common survivors: {result['origin_non_common_survivors']}",
        "",
        "## Survivors By Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for key, value in sorted(by_cap.items()):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(["", "## Failed Samples", "", "| Contract | Reason |", "| --- | --- |"])
    for row in failed[:30]:
        reason = row.get("actual", {}).get("message") or "replay/mutant mismatch"
        lines.append(f"| `{row['name']}` | {reason} |")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    nc_lines = ["# golang-jwt/jwt Origin Non-Common Contracts", "", f"- Origin non-common survivors: {len(non_common)}", f"- Subtracted final common reference: {result['final_common_reference_count']}", "", "| Capability | Count |", "| --- | ---: |"]
    for key, value in sorted(non_common_by_cap.items()):
        nc_lines.append(f"| `{key}` | {value} |")
    NON_COMMON_MD.write_text("\n".join(nc_lines) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["contracts_total", "replay_pass", "mutant_rejected", "survivors", "survivor_overlap_with_final_common", "origin_non_common_survivors"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

