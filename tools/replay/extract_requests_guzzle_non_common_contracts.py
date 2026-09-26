#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
from collections import Counter


ROOT = pathlib.Path(__file__).resolve().parents[2]


REQUESTS_CONTRACTS = [
    ("2.34.1", "custom_getattr_bodies_are_detected_as_iterables", "http.request.iterable-body-detection", "Bodies with custom attribute lookup are still detected as iterable bodies."),
    ("2.34.0", "response_history_does_not_reference_itself", "http.redirect.history-cycle", "Response history traversal cannot loop because a response appears in its own history."),
    ("2.34.0", "no_proxy_domain_matching_is_not_greedy", "http.proxy.no-proxy-domain-boundary", "NO_PROXY domain matching respects hostname boundaries."),
    ("2.34.0", "duplicate_leading_slashes_in_uri_path_are_preserved", "http.url.path-slash-preservation", "A path beginning with multiple slashes is not collapsed before dispatch."),
    ("2.33.1", "malformed_content_type_header_parsing_is_tolerant", "http.headers.content-type-parse-tolerance", "Malformed Content-Type values do not crash response handling."),
    ("2.33.1", "malformed_header_values_raise_consistent_header_error", "http.headers.malformed-value-taxonomy", "Malformed header values raise a consistent header error."),
    ("2.33.0", "extract_zipped_paths_uses_nondeterministic_destination", "http.util.archive-extraction-hardening", "Zip extraction helper writes to a non-deterministic temporary path."),
    ("2.33.0", "empty_netrc_entry_does_not_apply_malformed_auth", "http.auth.netrc-empty-entry", "Empty netrc entries do not create malformed Authorization headers."),
    ("2.32.5", "ssl_context_is_not_cached_across_session_verify_policy", "tls.context-cache-policy", "Per-request TLS verification state is not leaked through a cached SSLContext."),
    ("2.32.4", "netrc_credentials_are_scoped_to_exact_request_host", "http.auth.netrc-host-scope", "Netrc credentials are selected for the actual target host only."),
    ("2.32.3", "custom_http_adapter_ssl_context_is_preserved", "tls.custom-adapter-ssl-context", "Custom adapter SSLContexts are passed through to transport creation."),
    ("2.32.2", "adapter_exposes_get_connection_with_tls_context", "http.adapter.tls-context-api", "Adapters expose a public get-connection API that receives TLS context."),
    ("2.32.0", "verify_false_does_not_persist_to_later_same_origin_requests", "tls.verification-state-leak", "A verify=False request does not make later same-origin verified requests unverified."),
    ("2.32.0", "response_text_defaults_utf8_without_charset_detector", "http.response.charset-detector-optional", "Text decoding falls back to UTF-8 when no charset detector is available."),
    ("2.32.0", "emoji_body_content_length_counts_bytes_not_characters", "http.request.content-length-unicode", "Request Content-Length for emoji bodies is calculated in bytes."),
    ("2.32.0", "json_decode_error_round_trips_through_pickle", "http.response.json-error-serialization", "JSON decode errors preserve type and data through serialization."),
    ("2.32.0", "extra_leading_path_separator_does_not_trigger_uri_reparse", "http.url.extra-leading-slash", "Extra leading slash path separators remain path data, not URI authority."),
    ("2.31.0", "proxy_authorization_from_proxy_url_is_not_forwarded_after_https_redirect", "http.proxy.authorization-redirect-leak", "Proxy credentials embedded in proxy URL are not forwarded to the redirected HTTPS origin."),
    ("2.29.0", "bytes_and_string_subclass_header_components_are_accepted", "http.headers.component-subclass", "Header names and values accept str/bytes subclasses where safe."),
    ("2.28.2", "missing_schema_error_suggests_https", "http.error.missing-schema-suggestion", "Missing URL scheme errors suggest https."),
    ("2.28.2", "response_json_uses_response_encoding_consistently", "http.response.json-encoding-consistency", "JSON parsing and text decoding use consistent response encoding."),
    ("2.28.0", "empty_curl_ca_bundle_does_not_disable_verification", "tls.env-ca-empty-string", "An empty CURL_CA_BUNDLE does not disable certificate verification."),
    ("2.28.0", "ssl_errors_from_streaming_content_are_wrapped", "tls.streaming-error-taxonomy", "TLS errors raised while consuming response bodies are wrapped in client TLS errors."),
    ("2.28.0", "proxy_url_missing_scheme_is_parsed_with_default_scheme", "http.proxy.missing-scheme-default", "Proxy URLs without a scheme receive an HTTP scheme during parsing."),
    ("2.28.0", "tarfile_extractfile_payload_length_detection_does_not_crash", "http.request.file-length-attribute-error", "File-like bodies whose length attributes raise AttributeError are still sendable."),
    ("2.28.0", "invalid_header_from_transport_is_wrapped", "http.headers.invalid-header-taxonomy", "Transport invalid-header errors are wrapped in client header errors."),
    ("2.28.0", "chunked_requests_do_not_send_duplicate_host_headers", "http.request.chunked-host-duplication", "Chunked requests send exactly one Host header."),
    ("2.27.1", "leading_dot_hostname_error_is_invalid_url", "http.url.leading-dot-hostname", "Leading-dot hostnames fail as invalid URLs."),
    ("2.27.0", "json_decode_error_is_request_exception", "http.response.json-error-taxonomy", "JSON decode errors are part of the client exception hierarchy."),
    ("2.26.0", "application_json_without_charset_decodes_as_utf8", "http.response.json-default-charset", "application/json responses default to UTF-8 decoding."),
    ("2.23.0", "redirect_to_invalid_url_is_wrapped", "http.redirect.invalid-location-taxonomy", "Redirect targets that cannot be parsed raise client URL errors."),
    ("2.22.0", "basic_auth_warning_does_not_include_password", "http.auth.warning-redaction", "Warnings for basic auth usage do not expose the password."),
    ("2.21.0", "same_host_default_port_redirect_preserves_authorization", "http.redirect.default-port-auth-scope", "Redirects between implicit and explicit default ports do not strip Authorization."),
    ("2.20.0", "content_type_header_parsing_is_case_insensitive", "http.headers.content-type-case", "Content-Type parsing is case-insensitive."),
    ("2.20.0", "redirect_fragment_is_preserved_when_location_has_no_fragment", "http.redirect.fragment-preservation", "Existing URL fragments are maintained across redirects when Location omits one."),
    ("2.19.0", "digest_auth_supports_sha256_and_sha512", "http.auth.digest-sha2", "Digest authentication supports SHA-256 and SHA-512 algorithms."),
    ("2.19.0", "empty_link_header_parses_to_empty_list", "http.headers.link-empty", "Parsing an empty Link header returns an empty collection."),
    ("2.19.0", "invalid_certificate_bundle_path_fails_before_dispatch", "tls.ca-path-validation", "Invalid CA bundle paths fail before the request is sent."),
    ("2.18.0", "proxies_mapping_no_proxy_key_is_honored", "http.proxy.no-proxy-mapping-key", "A no_proxy key in the proxies mapping bypasses matching hosts."),
    ("2.18.0", "schemes_starting_with_http_but_not_http_are_rejected", "http.url.scheme-prefix-rejection", "Schemes that merely start with http are not treated as HTTP."),
    ("2.18.0", "non_ascii_location_redirect_is_decoded_without_unicode_error", "http.redirect.non-ascii-location", "Non-ASCII Location headers can be followed without Unicode decode failures."),
    ("2.18.0", "digest_auth_only_answers_4xx_challenges", "http.auth.digest-challenge-scope", "Digest auth responds only to authentication challenges on 4xx responses."),
    ("2.15.1", "header_values_with_leading_whitespace_or_newline_are_rejected", "http.headers.smuggling-guard", "Header values containing leading whitespace or newline are rejected."),
    ("2.15.0", "no_proxy_wildcard_bypasses_all_hosts", "http.proxy.no-proxy-wildcard", "NO_PROXY=* bypasses proxies for every host."),
    ("2.15.0", "iter_content_accepts_integer_and_none_chunk_sizes", "http.response.iter-content-chunk-size", "Streaming content iteration accepts integer chunk sizes and None."),
    ("2.14.0", "case_insensitive_headers_preserve_insertion_order", "http.headers.case-insensitive-order", "Case-insensitive header mappings preserve insertion order."),
    ("2.14.0", "body_tell_exception_falls_back_to_chunked_transfer", "http.request.body-tell-fallback", "Bodies whose tell() raises are sent chunked instead of failing."),
    ("2.14.0", "proxy_connection_failures_raise_proxy_error", "http.proxy.error-taxonomy", "Proxy connection failures raise proxy-specific errors."),
    ("2.13.0", "verify_accepts_ca_certificate_directory", "tls.ca-directory", "The verification option accepts a directory of CA certificates."),
    ("2.12.5", "partial_file_upload_uses_remaining_bytes_only", "http.request.partial-file-upload", "Uploading a file-like object from a non-zero position sends only remaining bytes."),
    ("2.12.5", "empty_unknown_length_file_upload_uses_chunked_transfer", "http.request.empty-file-chunked", "Empty or unknown-length file-like uploads use chunked transfer."),
    ("2.12.5", "session_closes_on_exceptional_and_normal_exit", "http.session.close-lifecycle", "Session contexts close both on success and on exceptions."),
    ("2.12.5", "malformed_digest_qop_is_handled", "http.auth.digest-malformed-qop", "Malformed digest qop challenges do not crash authentication."),
    ("2.11.0", "prepared_request_flow_respects_json_parameter", "http.request.prepared-json", "Prepared request flow serializes json bodies correctly."),
    ("2.11.0", "host_specific_proxy_mapping_is_honored", "http.proxy.host-specific-mapping", "Proxy mappings may be scoped to scheme and hostname."),
    ("2.11.0", "netrc_parse_errors_are_optional", "http.auth.netrc-error-policy", "Netrc parse errors are ignored by default but can be surfaced on request."),
    ("2.11.0", "default_user_agent_avoids_runtime_data_leak", "http.headers.user-agent-privacy", "Default User-Agent avoids leaking implementation runtime details."),
    ("2.11.0", "json_parameter_is_ignored_when_data_or_files_present", "http.request.body-priority", "json= is ignored when data= or files= is also supplied."),
    ("2.11.0", "empty_no_proxy_entries_are_ignored", "http.proxy.no-proxy-empty-field", "Empty entries in NO_PROXY are ignored."),
    ("2.11.0", "chunked_body_connection_is_released_once", "http.connection.chunked-release-once", "Chunked body errors do not return a connection to the pool twice."),
    ("2.7.0", "hooks_argument_is_optional_for_prepared_request", "http.hooks.prepare-default", "PreparedRequest preparation does not require an explicit hooks list."),
    ("2.7.0", "redirect_adapter_kwargs_are_forwarded", "http.redirect.adapter-kwargs-forwarding", "Redirect resolution forwards original adapter options."),
    ("2.7.0", "prepared_request_cookiejar_is_copied_reliably", "http.cookies.prepared-request-copy", "PreparedRequest cookie jars are copied reliably."),
    ("2.6.1", "redirect_cookie_without_domain_is_scoped_to_original_host", "http.cookies.redirect-host-scope", "Hostless cookies on redirect are scoped to the original host."),
    ("2.5.0", "compressed_chunked_response_is_decoded", "http.response.compressed-chunked-decoding", "Compressed responses delivered with chunked framing decode correctly."),
    ("2.4.0", "idna2008_hostnames_are_supported", "http.url.idna2008", "Internationalized hostnames use IDNA2008-compatible handling."),
    ("2.4.0", "content_length_recomputed_for_prepared_request_body_changes", "http.request.prepared-content-length", "PreparedRequest Content-Length is recalculated when body changes."),
    ("2.4.0", "empty_password_in_proxy_credentials_is_allowed", "http.proxy.empty-password", "Proxy credentials may contain an empty password."),
    ("2.4.0", "redirect_307_308_rewinds_file_like_body", "http.redirect.rewind-file-body", "307/308 redirects rewind repeatable file-like bodies before replay."),
    ("2.4.0", "custom_host_header_cookie_matching_is_respected", "http.cookies.custom-host-matching", "Cookies correlate correctly when a custom Host header is used."),
    ("2.3.0", "iter_content_decode_unicode_streams_text", "http.response.iter-content-decode-unicode", "Streaming content can decode unicode incrementally."),
]


GUZZLE_CONTRACTS = [
    ("7.5.3", "set_cookie_invalid_max_age_is_skipped", "http.cookie.set-cookie-max-age-validation", "Invalid Set-Cookie Max-Age values are ignored."),
    ("7.5.2", "set_cookie_constructor_validates_inputs", "http.cookie.constructor-validation", "Set-Cookie construction validates invalid attributes."),
    ("7.5.2", "multipart_file_body_string_zero_is_preserved", "http.multipart.zero-body", "A file upload body equal to the string 0 is not treated as empty."),
    ("7.5.1", "proxy_option_no_overrides_environment_proxy", "http.proxy.option-no-overrides-env", "An explicit proxy=no option overrides proxy environment variables."),
    ("7.4.5", "redirect_port_change_is_origin_change", "http.redirect.port-origin-boundary", "Changing only the port across redirect is considered a different origin."),
    ("7.4.5", "curl_httpauth_option_cleared_on_origin_change", "http.redirect.curl-auth-origin-clear", "Transport auth settings are cleared when redirects change origin."),
    ("7.4.4", "authorization_header_stripped_on_http_downgrade", "http.redirect.downgrade-auth-stripping", "Authorization is stripped when redirect downgrades HTTPS to HTTP."),
    ("7.4.4", "cookie_header_stripped_on_http_downgrade", "http.redirect.downgrade-cookie-stripping", "Cookie is stripped when redirect downgrades HTTPS to HTTP."),
    ("7.4.3", "cross_domain_cookies_are_not_leaked", "http.cookies.cross-domain-leak", "Cookies scoped to one domain are not leaked to another domain."),
    ("7.4.2", "stream_handler_rejects_non_http_schemes", "http.url.non-http-streamhandler-rejection", "The stream handler rejects non-HTTP schemes."),
    ("7.4.2", "stream_handler_sets_default_ssl_peer_name_for_forced_ip", "tls.peer-name-force-ip", "Forced IP resolution still configures an SSL peer name."),
    ("7.4.1", "uri_objects_are_not_implicitly_stringified", "http.url.uri-string-coercion", "URI inputs are not silently coerced through implicit string conversion."),
    ("7.4.0", "invalid_headers_array_raises_invalid_argument", "http.headers.invalid-array-taxonomy", "Invalid headers arrays raise invalid argument errors."),
    ("7.3.0", "der_client_certificates_are_supported", "tls.client-certificate-der", "DER client certificates can be supplied."),
    ("7.3.0", "p12_client_certificates_are_supported", "tls.client-certificate-p12", "P12 client certificates can be supplied."),
    ("7.3.0", "stream_handler_accepts_http_proxy_scheme", "http.proxy.stream-http-scheme", "Stream handler proxies accept the http:// proxy scheme."),
    ("7.2.0", "http_error_middleware_accepts_body_summarizer", "http.error.body-summary-hook", "HTTP error middleware can use a custom response-body summarizer."),
    ("7.2.0", "request_always_has_body_object", "http.request.body-object-invariant", "Every request exposes a body object, including empty-body requests."),
    ("7.2.0", "too_many_redirects_exception_contains_response", "http.redirect.exception-response", "Too-many-redirects errors include the response that triggered them."),
    ("7.1.1", "head_requests_do_not_connect_sink", "http.response.head-sink-policy", "HEAD requests do not connect response sink bodies."),
    ("7.1.0", "cookie_without_value_is_stored", "http.cookie.empty-value", "Cookies with no value are stored instead of dropped."),
    ("7.1.0", "safe_method_redirects_are_allowed", "http.redirect.safe-method-policy", "Safe methods such as OPTIONS are allowed to redirect."),
    ("7.1.0", "logging_empty_response_does_not_fail", "http.logging.empty-response", "Logging an empty response succeeds."),
    ("7.0.0-rc1", "idn_support_is_disabled_by_default", "http.url.idn-default-disabled", "IDN conversion is disabled unless explicitly enabled."),
    ("7.0.0-beta2", "client_exposes_convenience_methods_for_http_verbs", "http.client.verb-methods", "Client exposes convenience methods for common HTTP verbs."),
    ("7.0.0-beta2", "default_user_agent_is_major_version_only", "http.headers.user-agent-major-version", "Default User-Agent identifies Guzzle major version."),
    ("7.0.0-beta2", "connect_exception_extends_transfer_exception", "http.error.connection-taxonomy", "Connection exceptions are transfer exceptions."),
    ("7.0.0-beta1", "psr18_client_interface_is_implemented", "http.client.psr18-interface", "The client implements the PSR-18 client interface."),
    ("7.0.0-beta1", "null_uri_is_rejected", "http.url.null-uri-rejection", "Null URI requests are rejected."),
    ("7.0.0-beta1", "request_exception_response_body_summary_removed", "http.error.response-body-summary-api", "The removed response-body summary API is not available."),
    ("6.5.0", "null_header_option_is_handled_gracefully", "http.headers.null-option", "A null headers option is handled gracefully."),
    ("6.5.0", "retry_middleware_uses_exponential_delay_units_correctly", "http.retry.exponential-delay-units", "Retry middleware exponential delay uses the correct time units."),
    ("6.5.0", "ssl_key_array_options_do_not_emit_undefined_offset", "tls.client-key-array-options", "Array-style SSL key options do not produce undefined offset failures."),
    ("6.4.0", "curl_select_timeout_environment_variable_is_honored", "http.transport.curl-select-timeout-env", "The curl select timeout environment variable controls multi select timeout."),
    ("6.4.0", "transfer_stats_include_appconnect_time", "http.observability.tls-appconnect-time", "Transfer statistics include TLS application connect time."),
    ("6.4.0", "cookie_jar_file_writes_are_serialized", "http.cookie.jar-concurrent-write", "Cookie jar file writes avoid concurrent corruption."),
    ("6.3.3", "decode_content_option_preserves_default_headers", "http.headers.decode-content-defaults", "Default headers are retained when decode_content is configured."),
    ("6.3.1", "cookie_epoch_zero_expiry_is_parsed", "http.cookie.epoch-zero-expiry", "Cookie expiry at epoch 0 is parsed without failure."),
    ("6.3.1", "cookie_domain_containing_slash_is_rejected", "http.cookie.malformed-domain-slash", "Cookie domains containing slash are treated as malformed."),
    ("6.3.1", "empty_headers_are_supported", "http.headers.empty-headers", "Empty header collections are accepted."),
    ("6.3.1", "header_modifications_are_case_insensitive", "http.headers.case-insensitive-mutation", "Header modification operations are case-insensitive."),
    ("6.3.0", "force_ip_resolve_option_is_supported", "http.dns.force-ip-resolve", "Requests can force IPv4 or IPv6 address resolution."),
    ("6.3.0", "read_timeout_option_is_supported", "http.timeout.read-timeout-option", "Read timeout can be configured separately."),
    ("6.3.0", "ntlm_auth_option_is_supported", "http.auth.ntlm", "NTLM authentication is supported."),
    ("6.3.0", "redirect_history_tracks_status_codes", "http.redirect.status-history", "Redirect history exposes the HTTP status codes seen along the chain."),
    ("6.3.0", "handler_type_is_checked_during_client_construction", "http.handler.constructor-validation", "Invalid handler types are rejected at construction."),
    ("6.3.0", "content_length_is_included_when_body_exists", "http.request.content-length-body-invariant", "Content-Length is included whenever a request body exists."),
    ("6.3.0", "cookie_jar_can_access_cookie_by_name", "http.cookie.jar-get-by-name", "Cookie jars can return a cookie value by name."),
    ("6.3.0", "ca_info_and_ca_path_are_filled_correctly", "tls.ca-paths", "CA file and CA path options are populated correctly."),
    ("6.2.2", "on_headers_callback_can_abort_response", "http.response.on-headers-callback", "A response-header callback can inspect or abort before body download."),
    ("6.2.1", "multipart_same_name_files_are_supported", "http.multipart.same-name-files", "Multipart upload supports multiple files with the same field name."),
    ("6.2.0", "expect_header_threshold_is_configurable", "http.request.expect-threshold", "Expect: 100-continue is controlled by a payload threshold."),
    ("6.1.0", "sink_option_writes_response_body_to_target", "http.response.sink", "Response bodies can be streamed directly into a sink target."),
    ("6.1.0", "progress_callback_reports_transfer_progress", "http.observability.progress-callback", "Progress callbacks report transfer progress."),
    ("6.0.0", "base_uri_resolves_relative_request_uris", "http.url.base-uri-resolution", "A base URI resolves relative request URIs."),
    ("6.0.0", "http_errors_option_controls_exception_on_error_status", "http.error.http-errors-option", "The http_errors option controls whether error status responses raise."),
    ("6.0.0", "allow_redirects_option_can_track_redirects", "http.redirect.tracking-option", "Redirect middleware can expose redirect tracking headers."),
    ("6.0.0", "delay_option_defers_request_dispatch", "http.request.delay-option", "Requests can be delayed before dispatch."),
    ("5.3.0", "cookies_option_accepts_boolean_or_cookie_jar", "http.cookie.option-shapes", "Cookies can be disabled, enabled, or supplied as a jar."),
    ("5.3.0", "query_option_merges_with_uri_query", "http.url.query-option-merge", "The query option merges with an existing URI query."),
    ("5.2.0", "body_option_accepts_string_resource_or_stream", "http.request.body-option-shapes", "Request body option accepts strings, resources, or stream objects."),
    ("5.1.0", "future_response_can_be_cancelled", "http.async.future-cancel", "Asynchronous future responses can be cancelled."),
    ("5.0.0", "middleware_can_modify_request_and_response", "http.middleware.modify-request-response", "Middleware can transform requests and responses."),
    ("4.2.0", "post_redirect_behavior_can_be_customized", "http.redirect.post-policy-option", "POST redirect behavior can be customized."),
    ("4.1.0", "content_length_zero_is_set_before_request_event", "http.request.empty-body-content-length-zero", "Empty body requests set Content-Length: 0 before send events."),
    ("4.0.0", "cookie_values_are_not_url_decoded_by_default", "http.cookie.no-url-decode-default", "Cookie values are not URL-decoded by default."),
    ("3.8.0", "debug_curl_options_are_disabled_by_default", "http.observability.debug-disabled-default", "Verbose cURL debugging is disabled by default."),
    ("3.7.0", "response_json_accepts_scalar_values", "http.response.json-scalar", "JSON response parsing accepts scalar JSON values."),
    ("3.6.0", "strict_cookie_jar_rejects_invalid_cookies", "http.cookie.strict-jar", "Strict cookie jars throw when invalid cookies are added."),
    ("3.6.0", "response_json_and_xml_helpers_exist", "http.response.parse-helpers", "Response helper methods parse JSON and XML bodies."),
    ("3.5.0", "redirects_are_implemented_in_client_not_transport", "http.redirect.client-managed", "Redirects are implemented in the client layer rather than delegated to transport."),
    ("3.5.0", "streams_support_custom_rewind", "http.stream.custom-rewind", "Streams expose rewind support for non-repeatable bodies."),
    ("3.4.0", "post_request_custom_body_redirect_policy_differs_from_form_post", "http.redirect.post-custom-body-policy", "POST custom bodies and browser-style form posts can have different redirect behavior."),
    ("3.4.0", "request_factory_uses_post_file_key_as_filename", "http.multipart.default-filename-key", "The request factory uses the POST file key as the filename when needed."),
    ("3.3.0", "stream_response_from_http_request_is_supported", "http.response.streaming-response", "HTTP responses can be represented as streaming responses."),
    ("3.2.0", "string_zero_response_body_is_preserved", "http.response.string-zero-body", "A response body equal to string 0 is preserved."),
    ("3.2.0", "mimetype_guessing_for_post_files_is_supported", "http.multipart.mimetype-guessing", "Multipart uploads guess MIME types from file names."),
    ("3.2.0", "strict_cookie_jar_deduplicates_cookies", "http.cookie.jar-deduplication", "Cookie jars deduplicate cookies."),
    ("3.1.0", "default_accept_headers_are_not_sent_on_every_request", "http.headers.accept-default-policy", "Accept and Accept-Encoding are not sent on every request by default."),
    ("3.1.0", "expect_header_only_for_payloads_over_one_mb", "http.request.expect-default-threshold", "Expect header is sent by default only for payloads larger than 1 MB."),
    ("3.0.0", "phar_uses_bundled_or_system_ca_certificate", "tls.ca-phar-policy", "Packaged archive execution uses bundled or system CA certificates appropriately."),
    ("2.8.0", "oauth_nonce_is_unique_per_request", "http.auth.oauth-nonce-uniqueness", "OAuth signing creates a unique nonce for each request."),
    ("2.8.0", "oauth_parameters_are_sorted_before_signing", "http.auth.oauth-parameter-sorting", "OAuth parameters are sorted before signing."),
    ("2.7.0", "delete_request_can_send_entity_body", "http.request.delete-body", "DELETE requests can send an entity body."),
    ("2.7.0", "stream_read_operations_restore_original_position", "http.stream.read-position-restoration", "Stream helper reads restore the original stream position."),
    ("2.6.0", "post_redirects_can_be_customized", "http.redirect.postredir-option", "POST redirects can be customized."),
    ("2.4.0", "header_glue_is_used_when_transferring_headers", "http.headers.glue-policy", "Header glue rules are applied when transferring headers over the wire."),
    ("2.3.0", "default_cookie_header_casing_is_cookie", "http.headers.cookie-casing", "The default Cookie header casing is Cookie."),
    ("2.2.0", "post_fields_and_files_are_aggregated", "http.multipart.fields-and-files-aggregation", "POST fields and files are aggregated into one multipart request."),
    ("2.1.0", "empty_post_files_and_fields_are_ignored", "http.multipart.empty-fields-ignored", "Empty POST files and fields are ignored."),
    ("2.0.0", "json_response_decode_errors_raise_exception", "http.response.json-error", "Invalid JSON response bodies raise an exception."),
]


def read_changelog(path: pathlib.Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def version_count(text: str) -> int:
    return len(re.findall(r"(?m)^(?:##\s+)?v?\d+\.\d+(?:\.\d+)?(?:[-a-zA-Z0-9.]*)?\s*(?:\(|-)", text))


def write_origin(name: str, contracts: list[tuple[str, str, str, str]], changelog: pathlib.Path) -> None:
    text = read_changelog(changelog)
    rows = [
        {
            "origin": name,
            "source_version": version,
            "key": f"{version}:{contract}",
            "contract": contract,
            "capability": capability,
            "evidence": evidence,
            "source": str(changelog.relative_to(ROOT)) if changelog.exists() else "",
        }
        for version, contract, capability, evidence in contracts
    ]
    out_dir = ROOT / "contracts" / name
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "source_project": name,
        "source_release_notes": str(changelog.relative_to(ROOT)) if changelog.exists() else "",
        "release_note_versions_scanned": version_count(text),
        "rule": "external, observable, latest-lineage non-common HTTP-client contracts extracted from release notes; confirmed HTTP common 114 intentionally excluded by semantic judgment",
        "total_contracts": len(rows),
        "capability_counts": dict(sorted(Counter(row["capability"] for row in rows).items())),
        "results": rows,
    }
    (out_dir / f"{name}_origin_excluding_common_114.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    md = [
        f"# {name} origin non-common contracts excluding HTTP common 114",
        "",
        f"- release_note_versions_scanned: {payload['release_note_versions_scanned']}",
        f"- total_contracts: {payload['total_contracts']}",
        "",
        "| version | contract | capability |",
        "|---|---|---|",
    ]
    for row in rows:
        md.append(f"| `{row['source_version']}` | `{row['contract']}` | `{row['capability']}` |")
    (out_dir / f"{name}_origin_excluding_common_114.md").write_text("\n".join(md) + "\n")


def main() -> int:
    write_origin("requests", REQUESTS_CONTRACTS, ROOT / ".replay" / "requests" / "HISTORY.md")
    write_origin("guzzle", GUZZLE_CONTRACTS, ROOT / ".replay" / "guzzle" / "CHANGELOG.md")
    print(json.dumps({"requests": len(REQUESTS_CONTRACTS), "guzzle": len(GUZZLE_CONTRACTS)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
