package shapingbench.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ReplayJavaJwt {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ReplayJavaJwt() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Usage: ReplayJavaJwt <contracts.json>");
        }
        JsonNode root = MAPPER.readTree(new File(args[0]));
        ArrayNode contracts = (ArrayNode) (root.has("contracts") ? root.get("contracts") : root);
        List<Map<String, Object>> results = new ArrayList<>();
        List<JsonNode> survivors = new ArrayList<>();

        int replayPass = 0;
        int mutantRejected = 0;
        for (JsonNode contract : contracts) {
            Map<String, Object> result = evaluateContract(contract);
            results.add(result);
            if (Boolean.TRUE.equals(result.get("replay_pass"))) {
                replayPass++;
            }
            if (Boolean.TRUE.equals(result.get("mutant_rejected"))) {
                mutantRejected++;
            }
            if (Boolean.TRUE.equals(result.get("survived"))) {
                survivors.add(contract);
            }
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("implementation", "com.auth0:java-jwt");
        output.put("version", "4.6.0");
        output.put("contracts_total", contracts.size());
        output.put("replay_pass", replayPass);
        output.put("mutant_rejected", mutantRejected);
        output.put("survivors", survivors.size());
        output.put("survivor_contracts", survivors);
        output.put("results", results);
        System.out.println(MAPPER.writeValueAsString(output));
    }

    private static Map<String, Object> evaluateContract(JsonNode contract) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", contract.path("name").asText());
        result.put("capability", contract.path("capability").asText());
        result.put("op", contract.path("op").asText());
        try {
            Map<String, Object> actual = runOp(contract);
            boolean replayPass = matchesExpected(actual, contract.path("expected"));
            boolean mutantAccepted = matchesExpected(actual, contract.path("mutant"));
            result.put("replay_pass", replayPass);
            result.put("mutant_rejected", !mutantAccepted);
            result.put("survived", replayPass && !mutantAccepted);
            result.put("actual", actual);
            if (!replayPass) {
                result.put("expected", MAPPER.convertValue(contract.path("expected"), Object.class));
            }
        } catch (Throwable error) {
            result.put("replay_pass", false);
            result.put("mutant_rejected", false);
            result.put("survived", false);
            result.put("runner_error", error.getClass().getSimpleName() + ": " + error.getMessage());
        }
        return result;
    }

    private static Map<String, Object> runOp(JsonNode contract) throws Exception {
        String op = contract.path("op").asText();
        JsonNode params = contract.path("params");
        return switch (op) {
            case "decode_payload_json" -> decodePayload(params.path("token").asText());
            case "decode_claim_value" -> decodeClaimValue(params.path("token").asText(), params.path("claim").asText());
            case "decode_error" -> decodeError(params.path("token").asText());
            case "verify_hmac" -> verifyHmac(params);
            case "sign_hmac" -> signJwt(params, algorithmFromName(params.path("algorithm").asText(), params.path("secret").asText()));
            case "sign_rsa_pss" -> signJwt(params, rsaPssAlgorithm(params.path("algorithm").asText()));
            default -> throw new IllegalArgumentException("Unsupported op: " + op);
        };
    }

    private static Map<String, Object> decodePayload(String token) throws Exception {
        JWT.decode(token);
        String[] parts = token.split("\\.", -1);
        Map<String, Object> actual = new LinkedHashMap<>();
        actual.put("header", decodePart(parts[0]));
        actual.put("payload", decodePart(parts[1]));
        return actual;
    }

    private static Map<String, Object> decodeClaimValue(String token, String claim) throws Exception {
        JWT.decode(token);
        String[] parts = token.split("\\.", -1);
        Object value = ((Map<?, ?>) decodePart(parts[1])).get(claim);
        Map<String, Object> actual = new LinkedHashMap<>();
        actual.put("value", value);
        return actual;
    }

    private static Map<String, Object> decodeError(String token) {
        Map<String, Object> actual = new LinkedHashMap<>();
        try {
            JWT.decode(token);
            actual.put("error", false);
        } catch (RuntimeException error) {
            actual.put("error", true);
            actual.put("error_kind", error.getClass().getSimpleName());
        }
        return actual;
    }

    private static Map<String, Object> verifyHmac(JsonNode params) {
        Map<String, Object> actual = new LinkedHashMap<>();
        try {
            Algorithm algorithm = algorithmFromName(params.path("algorithm").asText(), params.path("secret").asText());
            Verification verification = JWT.require(algorithm);
            JsonNode checks = params.path("checks");
            if (checks.has("issuer")) {
                verification.withIssuer(strings(checks.path("issuer")));
            }
            if (checks.has("subject")) {
                verification.withSubject(checks.path("subject").asText());
            }
            if (checks.has("audience")) {
                verification.withAudience(strings(checks.path("audience")));
            }
            if (checks.has("any_of_audience")) {
                verification.withAnyOfAudience(strings(checks.path("any_of_audience")));
            }
            if (checks.has("claim_presence")) {
                for (String claim : strings(checks.path("claim_presence"))) {
                    verification.withClaimPresence(claim);
                }
            }
            JWTVerifier verifier = params.has("clock")
                    ? ((com.auth0.jwt.JWTVerifier.BaseVerification) verification).build(fixedClock(params.path("clock").asLong()))
                    : verification.build();
            verifier.verify(params.path("token").asText());
            actual.put("ok", true);
        } catch (RuntimeException error) {
            actual.put("ok", false);
            actual.put("error_kind", error.getClass().getSimpleName());
        }
        return actual;
    }

    private static Map<String, Object> signJwt(JsonNode params, Algorithm algorithm) throws Exception {
        JWTCreator.Builder builder = JWT.create();
        if (params.has("headers")) {
            builder.withHeader(MAPPER.convertValue(params.path("headers"), new TypeReference<Map<String, Object>>() {
            }));
        }
        if (params.has("claims")) {
            Map<String, Object> claims = MAPPER.convertValue(params.path("claims"), new TypeReference<Map<String, Object>>() {
            });
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                addClaim(builder, entry.getKey(), entry.getValue());
            }
        }
        String token = builder.sign(algorithm);
        DecodedJWT decoded = JWT.decode(token);
        algorithm.verify(decoded);
        Map<String, Object> actual = decodePayload(token);
        actual.put("verifies", true);
        return actual;
    }

    private static void addClaim(JWTCreator.Builder builder, String name, Object value) {
        if ("iss".equals(name) && value instanceof String string) {
            builder.withIssuer(string);
        } else if ("sub".equals(name) && value instanceof String string) {
            builder.withSubject(string);
        } else if ("aud".equals(name) && value instanceof List<?> list) {
            builder.withAudience(list.stream().map(String::valueOf).toArray(String[]::new));
        } else if ("jti".equals(name) && value instanceof String string) {
            builder.withJWTId(string);
        } else if ("exp".equals(name) && value instanceof Number number) {
            builder.withExpiresAt(Instant.ofEpochSecond(number.longValue()));
        } else if ("nbf".equals(name) && value instanceof Number number) {
            builder.withNotBefore(Instant.ofEpochSecond(number.longValue()));
        } else if ("iat".equals(name) && value instanceof Number number) {
            builder.withIssuedAt(Instant.ofEpochSecond(number.longValue()));
        } else if (value == null) {
            builder.withNullClaim(name);
        } else if (value instanceof String string) {
            builder.withClaim(name, string);
        } else if (value instanceof Integer integer) {
            builder.withClaim(name, integer);
        } else if (value instanceof Long longValue) {
            builder.withClaim(name, longValue);
        } else if (value instanceof Number number) {
            builder.withClaim(name, number.doubleValue());
        } else if (value instanceof Boolean bool) {
            builder.withClaim(name, bool);
        } else if (value instanceof List<?> list) {
            addArrayClaim(builder, name, list);
        } else if (value instanceof Map<?, ?> map) {
            builder.withClaim(name, castMap(map));
        } else {
            builder.withClaim(name, String.valueOf(value));
        }
    }

    private static void addArrayClaim(JWTCreator.Builder builder, String name, List<?> list) {
        boolean allString = list.stream().allMatch(item -> item == null || item instanceof String);
        boolean allInteger = list.stream().allMatch(item -> item == null || item instanceof Integer);
        boolean allLong = list.stream().allMatch(item -> item == null || item instanceof Long || item instanceof Integer);
        if (allString) {
            builder.withArrayClaim(name, list.toArray(new String[0]));
        } else if (allInteger) {
            builder.withArrayClaim(name, list.toArray(new Integer[0]));
        } else if (allLong) {
            builder.withArrayClaim(name, list.stream().map(item -> item == null ? null : ((Number) item).longValue()).toArray(Long[]::new));
        } else {
            builder.withPayload(Map.of(name, list));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    private static Algorithm algorithmFromName(String name, String secret) {
        return switch (name) {
            case "HS256" -> Algorithm.HMAC256(secret);
            case "HS384" -> Algorithm.HMAC384(secret);
            case "HS512" -> Algorithm.HMAC512(secret);
            default -> throw new IllegalArgumentException("Unsupported HMAC algorithm: " + name);
        };
    }

    private static Algorithm rsaPssAlgorithm(String name) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        return switch (name) {
            case "PS256" -> Algorithm.RSA256PSS(publicKey, privateKey);
            case "PS384" -> Algorithm.RSA384PSS(publicKey, privateKey);
            case "PS512" -> Algorithm.RSA512PSS(publicKey, privateKey);
            default -> throw new IllegalArgumentException("Unsupported PSS algorithm: " + name);
        };
    }

    private static Object decodePart(String part) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(pad(part));
        return MAPPER.readValue(new String(decoded, StandardCharsets.UTF_8), Object.class);
    }

    private static String pad(String value) {
        int remainder = value.length() % 4;
        return remainder == 0 ? value : value + "=".repeat(4 - remainder);
    }

    private static String[] strings(JsonNode node) {
        if (node.isTextual()) {
            return new String[]{node.asText()};
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : node) {
            out.add(item.asText());
        }
        return out.toArray(new String[0]);
    }

    private static Clock fixedClock(long epochSecond) {
        return Clock.fixed(Instant.ofEpochSecond(epochSecond), ZoneOffset.UTC);
    }

    private static boolean matchesExpected(Map<String, Object> actual, JsonNode expected) {
        JsonNode actualNode = MAPPER.valueToTree(actual);
        if (!expected.isObject()) {
            return jsonEquals(actualNode, expected);
        }
        var fields = expected.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            if (!actualNode.has(field.getKey()) || !jsonEquals(actualNode.get(field.getKey()), field.getValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean jsonEquals(JsonNode left, JsonNode right) {
        if (left == null || right == null) {
            return left == right;
        }
        if (left.isNumber() && right.isNumber()) {
            return decimal(left).compareTo(decimal(right)) == 0;
        }
        return left.equals(right);
    }

    private static BigDecimal decimal(JsonNode node) {
        return node.isBigInteger() ? new BigDecimal(node.bigIntegerValue()) : node.decimalValue();
    }
}
