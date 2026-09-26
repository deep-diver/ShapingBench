package shapingbench.okhttp;

import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.CompressionInterceptor;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.zstd.Zstd;
import okio.Buffer;
import okio.Sink;
import com.squareup.zstd.okio.OkioZstd;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class AxiosOriginCrossRunner {
  private static final Path OUT = Path.of("../../../contracts/axios/axios_origin_okhttp_5.5.0_cross_replay.json");
  private static final MediaType TEXT = MediaType.get("text/plain; charset=utf-8");

  private static final Map<String, String> NONPORTABLE = new LinkedHashMap<>();

  static {
    NONPORTABLE.put("abort_reason_is_preserved", "AbortController reason propagation is a JS cancellation API contract.");
    NONPORTABLE.put("allow_absolute_urls_false_combines_absolute_request_url", "Axios-specific allowAbsoluteUrls/baseURL policy.");
    NONPORTABLE.put("base_url_combination_deduplicates_trailing_slashes", "Axios-specific baseURL URL construction policy.");
    NONPORTABLE.put("cancel_error_includes_config", "Axios cancellation error shape includes Axios config.");
    NONPORTABLE.put("custom_fetch_env_is_used_by_fetch_adapter", "Axios fetch adapter env injection API.");
    NONPORTABLE.put("custom_timeout_error_message_is_used", "Axios timeoutErrorMessage option.");
    NONPORTABLE.put("data_url_max_content_length_is_enforced", "Axios data: URL response adapter limit.");
    NONPORTABLE.put("econnrefused_error_constant_is_exposed", "AxiosError constant surface.");
    NONPORTABLE.put("fetch_adapter_enforces_max_body_length", "Axios fetch adapter maxBodyLength behavior.");
    NONPORTABLE.put("fetch_adapter_uses_current_global_fetch", "Axios fetch adapter/global fetch binding.");
    NONPORTABLE.put("file_object_payload_is_supported_by_http_adapter", "Node File payload support in Axios HTTP adapter.");
    NONPORTABLE.put("form_data_to_json_ignores_polluted_prototype", "Axios formDataToJSON helper hardening.");
    NONPORTABLE.put("form_data_to_json_preserves_literal_punctuation_keys", "Axios formDataToJSON helper key parser.");
    NONPORTABLE.put("https_agent_tls_options_survive_http_connect_proxy", "Axios httpsAgent option propagation through CONNECT.");
    NONPORTABLE.put("interceptor_manager_clear_removes_handlers", "Axios InterceptorManager API.");
    NONPORTABLE.put("json_parse_error_keeps_response", "Axios transform/settle error object shape.");
    NONPORTABLE.put("json_parse_reviver_is_applied", "Axios JSON parse reviver option.");
    NONPORTABLE.put("max_body_length_enforced_when_redirects_disabled", "Axios request body length option.");
    NONPORTABLE.put("max_content_length_destroys_oversized_stream", "Axios response maxContentLength stream handling.");
    NONPORTABLE.put("no_proxy_canonicalizes_ipv4_shorthand", "Axios proxy-from-env/no_proxy canonicalization policy.");
    NONPORTABLE.put("no_proxy_wildcard_bypasses_proxy", "Axios proxy-from-env/no_proxy policy.");
    NONPORTABLE.put("node_data_url_requests_are_supported", "Axios Node adapter data: URL transport.");
    NONPORTABLE.put("object_payload_auto_serializes_to_urlencoded", "Axios object payload transform based on content type.");
    NONPORTABLE.put("params_serializer_callback_is_used", "Axios paramsSerializer option.");
    NONPORTABLE.put("response_encoding_latin1_decodes_bytes", "Axios responseEncoding transform API.");
    NONPORTABLE.put("socket_path_allowlist_rejects_unlisted_path", "Axios socketPath allow-list option.");
    NONPORTABLE.put("streamed_response_max_content_length_is_enforced", "Axios response maxContentLength stream option.");
    NONPORTABLE.put("sync_interceptor_failure_prevents_dispatch", "Axios synchronous interceptor dispatch semantics.");
    NONPORTABLE.put("timeout_string_is_parsed_as_milliseconds", "Axios string timeout parsing compatibility.");
    NONPORTABLE.put("unicode_header_values_survive_interceptors", "Axios interceptor mutation path.");
    NONPORTABLE.put("url_embedded_basic_auth_is_url_decoded", "Axios URL auth extraction into Authorization header.");
    NONPORTABLE.put("utf8_bom_is_removed_before_json_parse", "Axios JSON transform behavior.");
    NONPORTABLE.put("validate_status_null_accepts_every_status", "Axios validateStatus option semantics.");
    NONPORTABLE.put("validate_status_undefined_can_resolve_like_default", "Axios validateStatus option semantics.");
  }

  private interface CheckedRunnable {
    void run() throws Exception;
  }

  private record Contract(String name, String capability) {}

  private record Result(String name, String capability, String status, String detail) {}

  public static void main(String[] args) throws Exception {
    List<Contract> contracts = List.of(
        new Contract("abort_reason_is_preserved", "http.cancel.abort-reason-preservation"),
        new Contract("allow_absolute_urls_false_combines_absolute_request_url", "http.url.allow-absolute-urls-false"),
        new Contract("base_url_combination_deduplicates_trailing_slashes", "http.url.base-url-slash-deduplication"),
        new Contract("blank_header_names_are_skipped", "http.headers.blank-name-skipped"),
        new Contract("cancel_error_includes_config", "http.cancel.error-includes-config"),
        new Contract("custom_fetch_env_is_used_by_fetch_adapter", "http.adapter.fetch-env-config"),
        new Contract("custom_timeout_error_message_is_used", "http.timeout.custom-error-message"),
        new Contract("data_url_max_content_length_is_enforced", "http.response.data-url-max-content-length"),
        new Contract("delete_request_sends_config_data", "http.request.delete-config-data-body"),
        new Contract("econnrefused_error_constant_is_exposed", "http.error.econnrefused-constant"),
        new Contract("fetch_adapter_enforces_max_body_length", "http.request.fetch-max-body-length"),
        new Contract("fetch_adapter_uses_current_global_fetch", "http.adapter.fetch-current-global"),
        new Contract("file_object_payload_is_supported_by_http_adapter", "http.request.file-payload-node-adapter"),
        new Contract("form_data_to_json_ignores_polluted_prototype", "http.formdata.to-json-prototype-hardening"),
        new Contract("form_data_to_json_preserves_literal_punctuation_keys", "http.formdata.to-json-literal-punctuation"),
        new Contract("get_set_cookie_returns_array", "http.headers.get-set-cookie-array"),
        new Contract("https_agent_tls_options_survive_http_connect_proxy", "http.proxy.https-agent-tls-options-preserved"),
        new Contract("interceptor_manager_clear_removes_handlers", "http.interceptor.clear-removes-handlers"),
        new Contract("json_parse_error_keeps_response", "http.response.json-parse-error-retains-response"),
        new Contract("json_parse_reviver_is_applied", "http.response.json-parse-reviver"),
        new Contract("malformed_http_url_without_slashes_is_rejected", "http.url.malformed-protocol-rejection"),
        new Contract("max_body_length_enforced_when_redirects_disabled", "http.request.max-body-length-without-redirects"),
        new Contract("max_content_length_destroys_oversized_stream", "http.response.max-content-length-destroys-stream"),
        new Contract("missing_url_rejects_before_dispatch", "http.url.missing-url-rejection"),
        new Contract("no_proxy_canonicalizes_ipv4_shorthand", "http.proxy.no-proxy-ipv4-canonicalization"),
        new Contract("no_proxy_wildcard_bypasses_proxy", "http.proxy.no-proxy-wildcard"),
        new Contract("node_data_url_requests_are_supported", "http.response.node-data-url-support"),
        new Contract("object_payload_auto_serializes_to_urlencoded", "http.request.auto-urlencoded-object-serialization"),
        new Contract("params_serializer_callback_is_used", "http.url.params-serializer-callback"),
        new Contract("redirect_strips_sensitive_headers_cross_origin", "http.redirect.cross-origin-sensitive-header-stripping"),
        new Contract("response_encoding_latin1_decodes_bytes", "http.response.response-encoding"),
        new Contract("same_origin_redirect_preserves_basic_auth", "http.redirect.same-origin-basic-auth-preservation"),
        new Contract("socket_path_allowlist_rejects_unlisted_path", "http.transport.socket-path-allowlist"),
        new Contract("streamed_response_max_content_length_is_enforced", "http.response.stream-max-content-length"),
        new Contract("sync_interceptor_failure_prevents_dispatch", "http.interceptor.sync-failure-stops-dispatch"),
        new Contract("timeout_string_is_parsed_as_milliseconds", "http.timeout.string-parsed"),
        new Contract("unicode_header_values_survive_interceptors", "http.headers.unicode-values-through-interceptors"),
        new Contract("url_embedded_basic_auth_is_url_decoded", "http.auth.url-basic-credentials-decoding"),
        new Contract("user_agent_header_can_be_omitted", "http.headers.user-agent-omission"),
        new Contract("utf8_bom_is_removed_before_json_parse", "http.response.json-utf8-bom-stripped"),
        new Contract("validate_status_null_accepts_every_status", "http.response.validate-status-null-accepts-all"),
        new Contract("validate_status_undefined_can_resolve_like_default", "http.response.validate-status-undefined-semantics"),
        new Contract("zstd_response_decompression_supported", "http.response.zstd-decompression")
    );

    Map<String, CheckedRunnable> tests = new LinkedHashMap<>();
    tests.put("blank_header_names_are_skipped", AxiosOriginCrossRunner::blankHeaderNamesAreSkipped);
    tests.put("delete_request_sends_config_data", AxiosOriginCrossRunner::deleteRequestSendsConfigData);
    tests.put("get_set_cookie_returns_array", AxiosOriginCrossRunner::getSetCookieReturnsArray);
    tests.put("malformed_http_url_without_slashes_is_rejected", AxiosOriginCrossRunner::malformedHttpUrlWithoutSlashesIsRejected);
    tests.put("missing_url_rejects_before_dispatch", AxiosOriginCrossRunner::missingUrlRejectsBeforeDispatch);
    tests.put("redirect_strips_sensitive_headers_cross_origin", AxiosOriginCrossRunner::redirectStripsSensitiveHeadersCrossOrigin);
    tests.put("same_origin_redirect_preserves_basic_auth", AxiosOriginCrossRunner::sameOriginRedirectPreservesBasicAuth);
    tests.put("user_agent_header_can_be_omitted", AxiosOriginCrossRunner::userAgentHeaderCanBeOmitted);
    tests.put("zstd_response_decompression_supported", AxiosOriginCrossRunner::zstdResponseDecompressionSupported);

    List<Result> results = new ArrayList<>();
    for (Contract contract : contracts) {
      if (NONPORTABLE.containsKey(contract.name())) {
        results.add(new Result(contract.name(), contract.capability(), "nonportable_api_surface", NONPORTABLE.get(contract.name())));
        continue;
      }
      try {
        tests.get(contract.name()).run();
        results.add(new Result(contract.name(), contract.capability(), "passed", "portable replay passed on OkHttp"));
      } catch (Throwable error) {
        results.add(new Result(contract.name(), contract.capability(), "failed", error.getClass().getSimpleName() + ": " + error.getMessage()));
      }
    }

    int passed = 0;
    int failed = 0;
    int nonportable = 0;
    for (Result result : results) {
      if ("passed".equals(result.status())) passed++;
      if ("failed".equals(result.status())) failed++;
      if ("nonportable_api_surface".equals(result.status())) nonportable++;
    }
    String json = "{\n"
        + "  \"summary\": {\n"
        + "    \"target\": \"OkHttp\",\n"
        + "    \"target_version\": \"5.5.0\",\n"
        + "    \"source_contracts\": " + results.size() + ",\n"
        + "    \"passed\": " + passed + ",\n"
        + "    \"failed\": " + failed + ",\n"
        + "    \"nonportable_api_surface\": " + nonportable + "\n"
        + "  },\n"
        + "  \"results\": [\n"
        + joinResults(results)
        + "  ]\n"
        + "}\n";
    Files.createDirectories(OUT.getParent());
    Files.writeString(OUT, json, StandardCharsets.UTF_8);
    System.out.println(json);
  }

  private static OkHttpClient client() {
    return new OkHttpClient.Builder()
        .connectTimeout(Duration.ofSeconds(1))
        .readTimeout(Duration.ofSeconds(1))
        .writeTimeout(Duration.ofSeconds(1))
        .followRedirects(true)
        .build();
  }

  private static void deleteRequestSendsConfigData() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Request request = new Request.Builder()
          .url(server.url("/delete"))
          .method("DELETE", RequestBody.create("alpha=1", TEXT))
          .build();
      try (Response response = client().newCall(request).execute()) {
        require(response.isSuccessful(), "status " + response.code());
      }
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "no request recorded");
      require("DELETE".equals(recorded.getMethod()), "method " + recorded.getMethod());
      require("alpha=1".equals(recorded.getBody().utf8()), "body " + recorded.getBody().utf8());
    }
  }

  private static void malformedHttpUrlWithoutSlashesIsRejected() {
    try {
      new Request.Builder().url("http:example.test/path").build();
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("malformed scheme URL was accepted");
  }

  private static void getSetCookieReturnsArray() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder()
          .addHeader("Set-Cookie", "a=1")
          .addHeader("Set-Cookie", "b=2")
          .body("ok")
          .build());
      server.start();
      try (Response response = client().newCall(new Request.Builder().url(server.url("/cookies")).build()).execute()) {
        List<String> values = response.headers().values("Set-Cookie");
        require(values.equals(List.of("a=1", "b=2")), "set-cookie values " + values);
      }
    }
  }

  private static void missingUrlRejectsBeforeDispatch() {
    try {
      new Request.Builder().url("").build();
    } catch (IllegalArgumentException expected) {
      return;
    }
    throw new AssertionError("missing URL was accepted");
  }

  private static void redirectStripsSensitiveHeadersCrossOrigin() throws Exception {
    try (MockWebServer source = new MockWebServer(); MockWebServer target = new MockWebServer()) {
      target.enqueue(new MockResponse.Builder().body("target").build());
      target.start();
      source.enqueue(new MockResponse.Builder().code(302).addHeader("Location", target.url("/target")).build());
      source.start();
      Request request = new Request.Builder()
          .url(source.url("/start"))
          .addHeader("Authorization", "Basic abc")
          .addHeader("Cookie", "a=b")
          .build();
      try (Response response = client().newCall(request).execute()) {
        require(response.isSuccessful(), "status " + response.code());
      }
      mockwebserver3.RecordedRequest recorded = target.takeRequest(2, TimeUnit.SECONDS);
      require(recorded != null, "no redirected request");
      require(recorded.getHeaders().get("Authorization") == null, "authorization leaked");
      require(recorded.getHeaders().get("Cookie") == null, "cookie leaked");
    }
  }

  private static void sameOriginRedirectPreservesBasicAuth() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().code(302).addHeader("Location", "/target").build());
      server.enqueue(new MockResponse.Builder().body("target").build());
      server.start();
      Request request = new Request.Builder()
          .url(server.url("/start"))
          .addHeader("Authorization", "Basic abc")
          .build();
      try (Response response = client().newCall(request).execute()) {
        require(response.isSuccessful(), "status " + response.code());
      }
      server.takeRequest(2, TimeUnit.SECONDS);
      mockwebserver3.RecordedRequest redirected = server.takeRequest(2, TimeUnit.SECONDS);
      require(redirected != null, "no redirected request");
      require("Basic abc".equals(redirected.getHeaders().get("Authorization")), "authorization not preserved");
    }
  }

  private static void blankHeaderNamesAreSkipped() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      Request request = new Request.Builder()
          .url(server.url("/"))
          .addHeader("", "ignored")
          .addHeader("X-Good", "yes")
          .build();
      try (Response response = client().newCall(request).execute()) {
        require(response.isSuccessful(), "status " + response.code());
      }
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded.getHeaders().get("") == null, "blank header was sent");
      require("yes".equals(recorded.getHeaders().get("X-Good")), "good header missing");
    }
  }

  private static void userAgentHeaderCanBeOmitted() throws Exception {
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder().body("ok").build());
      server.start();
      try (Response response = client().newCall(new Request.Builder().url(server.url("/")).build()).execute()) {
        require(response.isSuccessful(), "status " + response.code());
      }
      mockwebserver3.RecordedRequest recorded = server.takeRequest(2, TimeUnit.SECONDS);
      require(recorded.getHeaders().get("User-Agent") == null, "user-agent was sent: " + recorded.getHeaders().get("User-Agent"));
    }
  }

  private static void zstdResponseDecompressionSupported() throws Exception {
    byte[] compressed = zstd("zstd-ok");
    try (MockWebServer server = new MockWebServer()) {
      server.enqueue(new MockResponse.Builder()
          .addHeader("Content-Encoding", "zstd")
          .body(new Buffer().write(compressed))
          .build());
      server.start();
      OkHttpClient zstdClient = client().newBuilder().addInterceptor(new CompressionInterceptor(Zstd.INSTANCE)).build();
      try (Response response = zstdClient.newCall(new Request.Builder().url(server.url("/zstd")).build()).execute()) {
        require("zstd-ok".equals(response.body().string()), "zstd body mismatch");
      }
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static String joinResults(List<Result> results) {
    List<String> rows = new ArrayList<>();
    for (Result result : results) {
      rows.add("    {\"name\": " + quote(result.name())
          + ", \"capability\": " + quote(result.capability())
          + ", \"status\": " + quote(result.status())
          + ", \"detail\": " + quote(result.detail()) + "}");
    }
    return String.join(",\n", rows) + "\n";
  }

  private static String quote(String value) {
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
  }

  private static byte[] zstd(String text) throws IOException {
    Buffer output = new Buffer();
    try (Sink sink = OkioZstd.zstdCompress(output)) {
      sink.write(new Buffer().writeUtf8(text), text.getBytes(StandardCharsets.UTF_8).length);
    }
    return output.readByteArray();
  }
}
