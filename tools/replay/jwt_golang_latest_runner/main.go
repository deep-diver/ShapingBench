
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
