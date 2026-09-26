package shapingbench;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Entities;
import org.jsoup.nodes.Node;
import org.jsoup.parser.ParseSettings;
import org.jsoup.parser.Parser;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Safelist;

public final class JsoupSanitizerRunner {
  private static final Gson GSON = new GsonBuilder().serializeNulls().create();

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: JsoupSanitizerRunner contracts.json");
    }
    JsonObject root = JsonParser.parseString(
        Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
    JsonArray results = new JsonArray();
    for (JsonElement el : root.getAsJsonArray("contracts")) {
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
      case "jsoup_clean": {
        String clean = cleanString(params);
        if (bool(params, "strip_newlines")) {
          clean = stripNewlines(clean);
        }
        actual.addProperty("clean", clean);
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "jsoup_clean_document": {
        Document dirty = documentFrom(params);
        String clean = new Cleaner(safelistFrom(params.getAsJsonObject("safelist")))
            .clean(dirty).body().html();
        if (bool(params, "strip_newlines")) {
          clean = stripNewlines(clean);
        }
        actual.addProperty("clean", clean);
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "jsoup_is_valid": {
        boolean valid = Jsoup.isValid(string(params, "html"), safelistFrom(params.getAsJsonObject("safelist")));
        actual.addProperty("valid", valid);
        return Eval.of(jsonEquals(actual.get("valid"), expected.get("valid")), actual);
      }
      case "jsoup_is_valid_document": {
        boolean valid = new Cleaner(safelistFrom(params.getAsJsonObject("safelist")))
            .isValid(documentFrom(params));
        actual.addProperty("valid", valid);
        return Eval.of(jsonEquals(actual.get("valid"), expected.get("valid")), actual);
      }
      case "css_sanitize_via_html": {
        String clean = Jsoup.clean(
            "<span style=\"" + attrEscape(string(params, "css")) + "\">x</span>",
            Safelist.none().addTags("span").addAttributes("span", "style"));
        Element span = Jsoup.parseBodyFragment(clean).selectFirst("span");
        String value = span != null && span.hasAttr("style") && !span.attr("style").isEmpty()
            ? span.attr("style") : null;
        putString(actual, "clean", value);
        return Eval.of(jsonEquals(actual.get("clean"), expected.get("clean")), actual);
      }
      case "decode_html_via_html": {
        if (bool(params, "in_attribute")) {
          String clean = Jsoup.clean(
              "<span title=\"" + attrEscape(string(params, "html")) + "\">x</span>",
              Safelist.none().addTags("span").addAttributes("span", "title"));
          Element span = Jsoup.parseBodyFragment(clean).selectFirst("span");
          actual.addProperty("text", span == null ? "" : span.attr("title"));
        } else {
          String clean = Jsoup.clean(string(params, "html"), Safelist.none());
          actual.addProperty("text", Jsoup.parseBodyFragment(clean).text());
        }
        return Eval.of(jsonEquals(actual.get("text"), expected.get("text")), actual);
      }
      case "strip_banned_via_html": {
        String clean = Jsoup.clean(string(params, "text"), Safelist.none());
        actual.addProperty("text", Jsoup.parseBodyFragment(clean).text());
        return Eval.of(jsonEquals(actual.get("text"), expected.get("text")), actual);
      }
      default:
        return Eval.error("unsupported op: " + op);
    }
  }

  private static String cleanString(JsonObject params) {
    Safelist safelist = safelistFrom(params.getAsJsonObject("safelist"));
    String baseUri = string(params, "base_uri");
    Document.OutputSettings outputSettings = outputSettingsFrom(objectOrNull(params, "output_settings"));
    if (outputSettings != null) {
      return Jsoup.clean(string(params, "html"), baseUri == null ? "" : baseUri, safelist, outputSettings);
    }
    if (baseUri == null) {
      return Jsoup.clean(string(params, "html"), safelist);
    }
    return Jsoup.clean(string(params, "html"), baseUri, safelist);
  }

  private static Document documentFrom(JsonObject params) {
    String html = string(params, "html");
    String baseUri = string(params, "base_uri");
    String mode = string(params, "parse_mode");
    Document doc;
    if ("body_fragment".equals(mode)) {
      if (bool(params, "preserve_case")) {
        String resolvedBaseUri = baseUri == null ? "" : baseUri;
        doc = Document.createShell(resolvedBaseUri);
        Parser parser = Parser.htmlParser().settings(ParseSettings.preserveCase);
        for (Node node : parser.parseFragmentInput(html, doc.body(), resolvedBaseUri)) {
          doc.body().appendChild(node);
        }
      } else {
        doc = Jsoup.parseBodyFragment(html, baseUri == null ? "" : baseUri);
      }
    } else if (bool(params, "preserve_case")) {
      doc = Jsoup.parse(html, baseUri == null ? "" : baseUri,
        Parser.htmlParser().settings(ParseSettings.preserveCase));
    } else {
      doc = Jsoup.parse(html, baseUri == null ? "" : baseUri);
    }
    Document.OutputSettings outputSettings = outputSettingsFrom(objectOrNull(params, "output_settings"));
    if (outputSettings != null) {
      doc.outputSettings(outputSettings);
    }
    return doc;
  }

  private static Document.OutputSettings outputSettingsFrom(JsonObject spec) {
    if (spec == null || spec.isJsonNull()) {
      return null;
    }
    Document.OutputSettings out = new Document.OutputSettings();
    if (spec.has("pretty_print") && !spec.get("pretty_print").isJsonNull()) {
      out.prettyPrint(spec.get("pretty_print").getAsBoolean());
    }
    String escapeMode = string(spec, "escape_mode");
    if (escapeMode != null) {
      out.escapeMode(Entities.EscapeMode.valueOf(escapeMode));
    }
    String charset = string(spec, "charset");
    if (charset != null) {
      out.charset(Charset.forName(charset));
    }
    String syntax = string(spec, "syntax");
    if (syntax != null) {
      out.syntax(Document.OutputSettings.Syntax.valueOf(syntax));
    }
    return out;
  }

  private static String stripNewlines(String text) {
    return text.replaceAll("\\r?\\n\\s*", "");
  }

  private static String attrEscape(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  private static Safelist safelistFrom(JsonObject spec) {
    String base = string(spec, "base");
    Safelist safelist;
    switch (base) {
      case "none": safelist = Safelist.none(); break;
      case "simpleText": safelist = Safelist.simpleText(); break;
      case "basic": safelist = Safelist.basic(); break;
      case "basicWithImages": safelist = Safelist.basicWithImages(); break;
      case "relaxed": safelist = Safelist.relaxed(); break;
      case "empty": safelist = new Safelist(); break;
      default: throw new IllegalArgumentException("unknown safelist base: " + base);
    }
    for (JsonElement stepEl : spec.getAsJsonArray("steps")) {
      JsonObject step = stepEl.getAsJsonObject();
      applyStep(safelist, step);
    }
    return safelist;
  }

  private static void applyStep(Safelist safelist, JsonObject step) {
    String method = string(step, "method");
    switch (method) {
      case "addTags":
        safelist.addTags(strings(step.getAsJsonArray("args")));
        break;
      case "removeTags":
        safelist.removeTags(strings(step.getAsJsonArray("args")));
        break;
      case "addAttributes": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.addAttributes(args[0], tail(args, 1));
        break;
      }
      case "removeAttributes": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.removeAttributes(args[0], tail(args, 1));
        break;
      }
      case "addProtocols": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.addProtocols(args[0], args[1], tail(args, 2));
        break;
      }
      case "removeProtocols": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.removeProtocols(args[0], args[1], tail(args, 2));
        break;
      }
      case "addEnforcedAttribute": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.addEnforcedAttribute(args[0], args[1], args[2]);
        break;
      }
      case "removeEnforcedAttribute": {
        String[] args = strings(step.getAsJsonArray("args"));
        safelist.removeEnforcedAttribute(args[0], args[1]);
        break;
      }
      case "preserveRelativeLinks":
        safelist.preserveRelativeLinks(step.get("value").getAsBoolean());
        break;
      default:
        throw new IllegalArgumentException("unsupported safelist method: " + method);
    }
  }

  private static String[] strings(JsonArray arr) {
    String[] out = new String[arr.size()];
    for (int i = 0; i < arr.size(); i++) {
      out[i] = arr.get(i).getAsString();
    }
    return out;
  }

  private static String[] tail(String[] arr, int start) {
    String[] out = new String[Math.max(0, arr.length - start)];
    System.arraycopy(arr, start, out, 0, out.length);
    return out;
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

  private static JsonObject objectOrNull(JsonObject obj, String key) {
    JsonElement el = obj.get(key);
    return el == null || el.isJsonNull() ? null : el.getAsJsonObject();
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
