package org.owasp.html;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class ShapingBenchRunner {
  private static final Gson GSON = new GsonBuilder().serializeNulls().create();

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: ShapingBenchRunner contracts.json");
    }
    JsonObject root = JsonParser.parseString(
        Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
    JsonArray contracts = root.getAsJsonArray("contracts");
    JsonArray results = new JsonArray();
    for (JsonElement el : contracts) {
      JsonObject contract = el.getAsJsonObject();
      JsonObject result = new JsonObject();
      result.addProperty("name", string(contract, "name"));
      result.addProperty("capability", string(contract, "capability"));
      result.addProperty("op", string(contract, "op"));
      try {
        Eval replay = evaluate(contract, false);
        Eval mutant = replay.passed ? evaluate(contract, true) : Eval.skipped();
        result.addProperty("replay_passed", replay.passed);
        result.addProperty("mutant_rejected", replay.passed && !mutant.passed);
        result.add("actual", replay.actual);
        if (replay.error != null) {
          result.addProperty("error", replay.error);
        }
      } catch (Throwable ex) {
        result.addProperty("replay_passed", false);
        result.addProperty("mutant_rejected", false);
        result.addProperty("error", ex.getClass().getName() + ": " + ex.getMessage());
      }
      results.add(result);
    }
    JsonObject out = new JsonObject();
    out.add("results", results);
    System.out.println(GSON.toJson(out));
  }

  private static Eval evaluate(JsonObject contract, boolean mutant) {
    String op = string(contract, "op");
    JsonObject params = contract.getAsJsonObject("params");
    JsonObject expected = contract.getAsJsonObject(mutant ? "mutant" : "expected");
    JsonObject actual = new JsonObject();
    switch (op) {
      case "css_sanitize": {
        StylingPolicy stylingPolicy = new StylingPolicy(
            CssSchema.DEFAULT,
            url -> {
              String safeUrl = StandardUrlAttributePolicy.INSTANCE.apply("img", "src", url);
              return safeUrl != null ? safeUrl + "#sanitized" : null;
            });
        putString(actual, "clean", stylingPolicy.sanitizeCssProperties(string(params, "css")));
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "decode_html": {
        putString(actual, "text", Encoding.decodeHtml(
            string(params, "html"), bool(params, "in_attribute")));
        return Eval.of(jsonEquals(actual.get("text"), expected.get("text")), actual);
      }
      case "strip_banned": {
        putString(actual, "text", Encoding.stripBannedCodeunits(string(params, "text")));
        return Eval.of(jsonEquals(actual.get("text"), expected.get("text")), actual);
      }
      case "policy_sanitize": {
        PolicyFactory policy = policyFrom(params.getAsJsonObject("policy"));
        putString(actual, "clean", policy.sanitize(string(params, "dirty")));
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "html_sanitizer_test_sanitize": {
        putString(actual, "clean", htmlSanitizerTestPolicy().sanitize(string(params, "html")));
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "antisamy_contains": {
        String clean = antiSamyPolicy().sanitize(string(params, "html"));
        actual.addProperty("contains", clean.contains(string(params, "needle")));
        return Eval.of(jsonEquals(actual.get("contains"), expected.get("contains")), actual);
      }
      default:
        return Eval.error("unsupported op: " + op);
    }
  }

  private static PolicyFactory htmlSanitizerTestPolicy() {
    return new HtmlPolicyBuilder()
        .allowElements(
            "a", "b", "br", "div", "i", "iframe", "img", "input", "li",
            "ol", "p", "span", "ul", "noscript", "noframes", "noembed", "noxss")
        .allowAttributes(
            "dir", "checked", "class", "href", "id", "target", "title", "type")
        .globally()
        .allowAttributes("id", "class")
        .matching(new AttributePolicy() {
          public String apply(String elementName, String attributeName, String value) {
            return value.replaceAll("(?:^|\\s)([a-zA-Z])", " p-$1")
                .replaceAll("\\s+", " ")
                .trim();
          }
        })
        .globally()
        .allowStyling()
        .allowWithoutAttributes("img", "input")
        .toFactory();
  }

  private static PolicyFactory antiSamyPolicy() {
    return new HtmlPolicyBuilder()
        .allowElements(
            "a", "b", "br", "div", "font", "i", "img", "input", "li",
            "ol", "p", "span", "td", "ul")
        .allowAttributes("checked", "type").onElements("input")
        .allowAttributes("color").onElements("font")
        .allowAttributes("href").onElements("a")
        .allowAttributes("src").onElements("img")
        .allowAttributes("class", "id", "title").globally()
        .allowAttributes("char").matching(new AttributePolicy() {
          public String apply(String elementName, String attributeName, String value) {
            return value.length() == 1 ? value : null;
          }
        }).onElements("td")
        .allowStandardUrlProtocols()
        .requireRelNofollowOnLinks()
        .allowStyling()
        .toFactory();
  }

  private static PolicyFactory policyFrom(JsonObject policy) {
    String type = string(policy, "type");
    if ("sanitizers".equals(type)) {
      PolicyFactory out = null;
      for (JsonElement nameEl : policy.getAsJsonArray("names")) {
        PolicyFactory next = canned(nameEl.getAsString());
        out = out == null ? next : out.and(next);
      }
      if (out == null) {
        throw new IllegalArgumentException("empty sanitizers policy");
      }
      return out;
    }
    if ("builder".equals(type)) {
      HtmlPolicyBuilder builder = new HtmlPolicyBuilder();
      for (JsonElement stepEl : policy.getAsJsonArray("steps")) {
        applyStep(builder, stepEl.getAsJsonObject());
      }
      return builder.toFactory();
    }
    if ("and".equals(type)) {
      PolicyFactory out = null;
      for (JsonElement childEl : policy.getAsJsonArray("policies")) {
        PolicyFactory next = policyFrom(childEl.getAsJsonObject());
        out = out == null ? next : out.and(next);
      }
      if (out == null) {
        throw new IllegalArgumentException("empty and policy");
      }
      return out;
    }
    throw new IllegalArgumentException("unsupported policy type: " + type);
  }

  private static PolicyFactory canned(String name) {
    switch (name) {
      case "FORMATTING": return Sanitizers.FORMATTING;
      case "BLOCKS": return Sanitizers.BLOCKS;
      case "STYLES": return Sanitizers.STYLES;
      case "LINKS": return Sanitizers.LINKS;
      case "IMAGES": return Sanitizers.IMAGES;
      case "TABLES": return Sanitizers.TABLES;
      default: throw new IllegalArgumentException("unknown Sanitizers member: " + name);
    }
  }

  private static void applyStep(HtmlPolicyBuilder builder, JsonObject step) {
    String method = string(step, "method");
    String[] args = strings(step.getAsJsonArray("args"));
    switch (method) {
      case "allowCommonInlineFormattingElements":
        builder.allowCommonInlineFormattingElements();
        break;
      case "allowCommonBlockElements":
        builder.allowCommonBlockElements();
        break;
      case "allowStyling":
        builder.allowStyling();
        break;
      case "allowStandardUrlProtocols":
        builder.allowStandardUrlProtocols();
        break;
      case "requireRelNofollowOnLinks":
        builder.requireRelNofollowOnLinks();
        break;
      case "requireRelsOnLinks":
        builder.requireRelsOnLinks(args);
        break;
      case "skipRelsOnLinks":
        builder.skipRelsOnLinks(args);
        break;
      case "allowElements":
        builder.allowElements(args);
        break;
      case "disallowElements":
        builder.disallowElements(args);
        break;
      case "allowUrlProtocols":
        builder.allowUrlProtocols(args);
        break;
      case "disallowUrlProtocols":
        builder.disallowUrlProtocols(args);
        break;
      case "allowWithoutAttributes":
        builder.allowWithoutAttributes(args);
        break;
      case "disallowWithoutAttributes":
        builder.disallowWithoutAttributes(args);
        break;
      case "allowTextIn":
        builder.allowTextIn(args);
        break;
      case "allowAttributes": {
        HtmlPolicyBuilder.AttributeBuilder attrs = builder.allowAttributes(args);
        applyAttributeMatcher(attrs, step);
        String target = string(step, "target");
        if ("globally".equals(target)) {
          attrs.globally();
        } else {
          attrs.onElements(strings(step.getAsJsonArray("targets")));
        }
        break;
      }
      case "disallowAttributes": {
        HtmlPolicyBuilder.AttributeBuilder attrs = builder.disallowAttributes(args);
        applyAttributeMatcher(attrs, step);
        String target = string(step, "target");
        if ("globally".equals(target)) {
          attrs.globally();
        } else {
          attrs.onElements(strings(step.getAsJsonArray("targets")));
        }
        break;
      }
      default:
        throw new IllegalArgumentException("unsupported builder method: " + method);
    }
  }

  private static void applyAttributeMatcher(
      HtmlPolicyBuilder.AttributeBuilder attrs, JsonObject step) {
    if (step.has("match_regex")) {
      attrs.matching(Pattern.compile(string(step, "match_regex")));
    }
    if (step.has("match_allowed")) {
      attrs.matching(bool(step, "ignore_case"), strings(step.getAsJsonArray("match_allowed")));
    }
  }

  private static String[] strings(JsonArray arr) {
    List<String> out = new ArrayList<>();
    if (arr != null) {
      for (JsonElement el : arr) {
        out.add(el.getAsString());
      }
    }
    return out.toArray(new String[0]);
  }

  private static String string(JsonObject obj, String key) {
    JsonElement el = obj.get(key);
    return el == null || el.isJsonNull() ? null : el.getAsString();
  }

  private static boolean bool(JsonObject obj, String key) {
    JsonElement el = obj.get(key);
    return el != null && !el.isJsonNull() && el.getAsBoolean();
  }

  private static void putString(JsonObject obj, String key, String value) {
    if (value == null) {
      obj.add(key, null);
    } else {
      obj.addProperty(key, value);
    }
  }

  private static boolean jsonEquals(JsonElement a, JsonElement b) {
    if (a == null || a.isJsonNull()) {
      return b == null || b.isJsonNull();
    }
    return a.equals(b);
  }

  private static final class Eval {
    final boolean passed;
    final JsonObject actual;
    final String error;

    private Eval(boolean passed, JsonObject actual, String error) {
      this.passed = passed;
      this.actual = actual;
      this.error = error;
    }

    static Eval of(boolean passed, JsonObject actual) {
      return new Eval(passed, actual, null);
    }

    static Eval error(String error) {
      return new Eval(false, new JsonObject(), error);
    }

    static Eval skipped() {
      return new Eval(false, new JsonObject(), null);
    }
  }
}
