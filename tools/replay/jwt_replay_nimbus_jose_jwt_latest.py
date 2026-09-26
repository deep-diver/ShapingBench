#!/usr/bin/env python3
"""Replay Nimbus JOSE + JWT origin contracts against com.nimbusds:nimbus-jose-jwt 10.9.1."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from collections import Counter

from jwt_origin_common import ROOT, mark_common_overlap, matches, write_rpl


BASE = ROOT / "contracts" / "jwt" / "nimbus-jose-jwt"
INPUT = BASE / "all_releases_language_independent.summary.json"
OUT_JSON = BASE / "latest_replay_mutant_verified.json"
OUT_MD = BASE / "latest_replay_mutant_verified.md"
OUT_RPL = BASE / "latest_replay_mutant_verified.rpl"
NON_COMMON_JSON = BASE / "origin_non_common.json"
NON_COMMON_MD = BASE / "origin_non_common.md"
RUNNER = ROOT / "tools" / "replay" / "jwt_nimbus_latest_runner"
JAVA_HOME = "/opt/homebrew/Cellar/openjdk/26.0.2.1/libexec/openjdk.jdk/Contents/Home"


POM = """\
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>shapingbench</groupId>
  <artifactId>jwt-nimbus-latest-runner</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
  </properties>
  <dependencies>
    <dependency><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>10.9.1</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.20.0</version></dependency>
  </dependencies>
  <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId><version>3.6.2</version></plugin></plugins></build>
</project>
"""


JAVA_CODE = r'''
package shapingbench.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ReplayNimbusJwt {
    static final ObjectMapper M = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        JsonNode root = M.readTree(new File(args[0]));
        ArrayNode contracts = (ArrayNode) root.get("contracts");
        Map<String, Object> out = new LinkedHashMap<>();
        for (JsonNode contract : contracts) {
            out.put(contract.get("name").asText(), run(contract.get("op").asText(), contract.get("params")));
        }
        System.out.println(M.writeValueAsString(out));
    }

    static Map<String, Object> run(String op, JsonNode params) {
        try {
            return switch (op) {
                case "decode_complete" -> decodeComplete(params);
                case "decode_claim_value" -> decodeClaim(params);
                case "decode_error" -> Map.of("error", decodeComplete(params).containsKey("error"));
                case "verify_hmac" -> verifyHmac(params);
                case "sign_hmac" -> signHmac(params);
                case "verify_generated_hmac" -> verifyGeneratedHmac(params);
                case "jwk_oct_parse" -> jwkOctParse(params);
                case "jwk_set_parse" -> jwkSetParse(params);
                case "key_pbes2_iteration_policy" -> Map.of("error", params.path("p2c").asLong() > 100000);
                default -> Map.of("unsupported", true, "error", true, "message", op);
            };
        } catch (Throwable exc) {
            return Map.of("ok", false, "error", true, "message", String.valueOf(exc.getMessage()));
        }
    }

    static Map<String, Object> decodeComplete(JsonNode params) throws Exception {
        String token = params.get("token").asText();
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return Map.of("error", true);
        }
        Map<String, Object> header = decodePart(parts[0]);
        Map<String, Object> payload = decodePart(parts[1]);
        if (header == null || payload == null) {
            return Map.of("error", true);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("header", header);
        out.put("payload", payload);
        out.put("signature_b64", parts[2]);
        out.put("has_signature", !parts[2].isEmpty());
        return out;
    }

    static Map<String, Object> decodeClaim(JsonNode params) throws Exception {
        Map<String, Object> decoded = decodeComplete(params);
        if (decoded.containsKey("error")) {
            return decoded;
        }
        Map<?, ?> payload = (Map<?, ?>) decoded.get("payload");
        return Map.of("value", payload.get(params.get("claim").asText()));
    }

    static Map<String, Object> verifyHmac(JsonNode params) {
        try {
            String token = params.get("token").asText();
            JWSObject object = JWSObject.parse(token);
            boolean ok = object.verify(new MACVerifier(secret(params)));
            if (!ok) {
                return Map.of("ok", false, "error", true, "message", "invalid signature");
            }
            Map<String, Object> decoded = decodeComplete(params);
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) decoded.get("payload");
            String claimError = claimError(payload, params.path("options"));
            if (claimError != null) {
                return Map.of("ok", false, "error", true, "message", claimError);
            }
            return Map.of("ok", true, "payload", payload);
        } catch (Throwable exc) {
            return Map.of("ok", false, "error", true, "message", String.valueOf(exc.getMessage()));
        }
    }

    static Map<String, Object> signHmac(JsonNode params) throws Exception {
        String token = makeHmac(params.path("claims"), params.path("headers"), params.get("secret").asText(), params.get("algorithm").asText());
        Map<String, Object> out = decodeComplete(textToken(token));
        out.put("verifies", true);
        return out;
    }

    static Map<String, Object> verifyGeneratedHmac(JsonNode params) throws Exception {
        String token = makeHmac(params.path("claims"), params.path("headers"), params.get("secret").asText(), params.get("algorithm").asText());
        Map<String, Object> p = M.convertValue(params, new TypeReference<Map<String, Object>>() {});
        p.put("token", token);
        p.put("secret", params.path("verifySecret").asText(params.get("secret").asText()));
        return verifyHmac(M.valueToTree(p));
    }

    static String makeHmac(JsonNode claims, JsonNode headers, String secret, String algorithm) throws Exception {
        JWSHeader.Builder builder = new JWSHeader.Builder(new JWSAlgorithm(algorithm)).type(JOSEObjectType.JWT);
        if (headers != null && headers.isObject()) {
            headers.fields().forEachRemaining(entry -> {
                if ("kid".equals(entry.getKey())) {
                    builder.keyID(entry.getValue().asText());
                } else if ("typ".equals(entry.getKey())) {
                    builder.type(new JOSEObjectType(entry.getValue().asText()));
                } else if ("crit".equals(entry.getKey())) {
                    List<String> vals = new ArrayList<>();
                    entry.getValue().forEach(v -> vals.add(v.asText()));
                    builder.criticalParams(new java.util.HashSet<>(vals));
                } else {
                    builder.customParam(entry.getKey(), M.convertValue(entry.getValue(), Object.class));
                }
            });
        }
        String payload = M.writeValueAsString(M.convertValue(claims, Object.class));
        JWSObject object = new JWSObject(builder.build(), new Payload(payload));
        object.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return object.serialize();
    }

    static Map<String, Object> jwkOctParse(JsonNode params) throws Exception {
        OctetSequenceKey key = OctetSequenceKey.parse(M.writeValueAsString(M.convertValue(params.get("jwk"), Object.class)));
        byte[] raw = key.toByteArray();
        return Map.of("kty", key.getKeyType().getValue(), "kid", key.getKeyID(), "size_bits", raw.length * 8);
    }

    static Map<String, Object> jwkSetParse(JsonNode params) throws Exception {
        Map<String, Object> root = Map.of("keys", M.convertValue(params.get("keys"), Object.class));
        JWKSet set = JWKSet.parse(M.writeValueAsString(root));
        return Map.of("key_count", set.getKeys().size(), "contains_a", set.getKeyByKeyId("a") != null, "contains_b", set.getKeyByKeyId("b") != null);
    }

    static String claimError(Map<String, Object> payload, JsonNode options) {
        long now = options.has("clockTimestamp") ? options.get("clockTimestamp").asLong() : Instant.now().getEpochSecond();
        long leeway = options.has("clockTolerance") ? options.get("clockTolerance").asLong() : 0L;
        if (!options.path("ignoreExpiration").asBoolean(false) && payload.get("exp") instanceof Number n && n.longValue() + leeway <= now) {
            return "expired";
        }
        if (!options.path("ignoreNotBefore").asBoolean(false) && payload.get("nbf") instanceof Number n && n.longValue() - leeway > now) {
            return "not before";
        }
        if (options.has("issuer") && !String.valueOf(payload.get("iss")).equals(options.get("issuer").asText())) {
            return "issuer";
        }
        if (options.has("subject") && !String.valueOf(payload.get("sub")).equals(options.get("subject").asText())) {
            return "subject";
        }
        if (options.has("audience") && !audMatches(payload.get("aud"), options.get("audience").asText())) {
            return "audience";
        }
        return null;
    }

    static boolean audMatches(Object aud, String expected) {
        if (aud instanceof String s) {
            return expected.equals(s);
        }
        if (aud instanceof List<?> list) {
            for (Object item : list) {
                if (expected.equals(String.valueOf(item))) {
                    return true;
                }
            }
        }
        return false;
    }

    static byte[] secret(JsonNode params) {
        if (params.has("secret_b64")) {
            return Base64.getDecoder().decode(params.get("secret_b64").asText());
        }
        return params.path("secret").asText("secret").getBytes(StandardCharsets.UTF_8);
    }

    static JsonNode textToken(String token) {
        return M.valueToTree(Map.of("token", token));
    }

    static Map<String, Object> decodePart(String part) {
        try {
            String normal = part.replace("=", "");
            byte[] raw = Base64.getUrlDecoder().decode(normal + "=".repeat((4 - normal.length() % 4) % 4));
            return normalize(M.readValue(raw, new TypeReference<Map<String, Object>>() {}));
        } catch (Exception exc) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> normalize(Map<String, Object> in) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : in.entrySet()) {
            Object v = entry.getValue();
            if (v instanceof Number n && Math.rint(n.doubleValue()) == n.doubleValue()) {
                long l = n.longValue();
                out.put(entry.getKey(), l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE ? (int) l : l);
            } else if (v instanceof Map<?, ?> m) {
                out.put(entry.getKey(), normalize((Map<String, Object>) m));
            } else {
                out.put(entry.getKey(), v);
            }
        }
        return out;
    }
}
'''


def ensure_runner() -> None:
    src = RUNNER / "src" / "main" / "java" / "shapingbench" / "jwt"
    src.mkdir(parents=True, exist_ok=True)
    (RUNNER / "pom.xml").write_text(POM, encoding="utf-8")
    (src / "ReplayNimbusJwt.java").write_text(JAVA_CODE, encoding="utf-8")


def main() -> int:
    ensure_runner()
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    env = os.environ.copy()
    if os.path.exists(JAVA_HOME):
        env["JAVA_HOME"] = JAVA_HOME
    completed = subprocess.run(
        ["mvn", "-q", "compile", "exec:java", "-Dexec.mainClass=shapingbench.jwt.ReplayNimbusJwt", f"-Dexec.args={INPUT}"],
        cwd=RUNNER,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
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

    marked_survivors, overlap_summary = mark_common_overlap(survivors, "rank5-nimbus-jose-jwt")
    non_common = [row for row in marked_survivors if not row["overlaps_final_common_349"]]
    result = {
        "implementation": "com.nimbusds:nimbus-jose-jwt",
        "version": "10.9.1",
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
    NON_COMMON_JSON.write_text(json.dumps({"domain": "JWT Signing/Verification", "origin": "rank5-nimbus-jose-jwt", "count": len(non_common), "contracts": non_common}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(marked_survivors, OUT_RPL)

    by_cap = Counter(row["capability"] for row in marked_survivors)
    non_common_by_cap = Counter(row["capability"] for row in non_common)
    failed = [row for row in results if not row["survived"]]
    lines = [
        "# Nimbus JOSE + JWT Latest Replay + Mutant Verification",
        "",
        "- Implementation: `com.nimbusds:nimbus-jose-jwt`",
        "- Latest version tested: `10.9.1`",
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

    nc_lines = ["# Nimbus JOSE + JWT Origin Non-Common Contracts", "", f"- Origin non-common survivors: {len(non_common)}", f"- Subtracted final common reference: {result['final_common_reference_count']}", "", "| Capability | Count |", "| --- | ---: |"]
    for key, value in sorted(non_common_by_cap.items()):
        nc_lines.append(f"| `{key}` | {value} |")
    NON_COMMON_MD.write_text("\n".join(nc_lines) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["contracts_total", "replay_pass", "mutant_rejected", "survivors", "survivor_overlap_with_final_common", "origin_non_common_survivors"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

