#!/usr/bin/env python3
"""Compile HTTP behavior IR rows into SolHTTP measurement projections."""

from __future__ import annotations

import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
IR = HERE / "http_non_common_contract_ir.jsonl"


FEATURES = {
    "origin_form_pool_request": {
        "prefixes": ("http.url.origin-guard", "http.url.request-target"),
        "primitive": "origin-bound pool request accepting an origin-form request target",
        "aliases": ("connection_pool", "urlopen", "origin_form", "same_host"),
    },
    "connection_introspection": {
        "prefixes": ("http.connection.identity", "http.connection.state", "http.proxy.tunnel-metadata", "http.proxy.tunnel-state", "http.proxy.verification-state"),
        "primitive": "public connection and proxy-tunnel state introspection",
        "aliases": ("connection", "is_connected", "is_closed", "is_verified", "is_tunneling", "tunnel_host"),
    },
    "request_blocksize": {
        "prefixes": ("http.request.blocksize",),
        "primitive": "configurable or observable upload block size",
        "aliases": ("blocksize", "block_size", "upload_chunk_size"),
    },
    "skip_automatic_headers": {
        "prefixes": ("http.headers.skip-automatic",),
        "primitive": "explicit suppression of transport-generated headers",
        "aliases": ("skip_header", "skip_headers", "suppress_headers"),
    },
    "configurable_redirect_header_removal": {
        "prefixes": ("http.redirect.header-stripping",),
        "primitive": "configurable sensitive-header removal policy on redirect",
        "aliases": ("remove_headers_on_redirect", "sensitive_headers", "redirect_headers"),
    },
    "url_utility": {
        "prefixes": ("http.url.rfc3986", "http.url.ip-address-classification", "http.url.public-suffix", "http.url.top-private-domain", "http.url.uri-conversion", "http.media-type.parameter-parsing"),
        "primitive": "public URL/domain/media-type parsing and conversion utility",
        "aliases": ("parse_url", "url_parser", "top_private_domain", "public_suffix", "to_uri", "media_type"),
    },
    "response_decode_control": {
        "prefixes": ("http.response.decode-content-option",),
        "primitive": "per-request decoded-content enable/disable control",
        "aliases": ("decode_content", "decompress", "automatic_decompression"),
    },
    "curl_rendering": {
        "prefixes": ("http.request.curl-rendering", "http.headers.sensitive-redaction"),
        "primitive": "request diagnostic/cURL rendering with redaction",
        "aliases": ("to_curl", "curl", "redact_headers", "request_to_string"),
    },
    "fast_fallback": {
        "prefixes": ("http.connection.fast-fallback",),
        "primitive": "Happy Eyeballs/fast-fallback connection racing",
        "aliases": ("fast_fallback", "happy_eyeballs", "connection_race"),
    },
    "cookie_parser": {
        "prefixes": ("http.cookie.samesite", "http.cookie.parser-robustness", "http.cookie.set-cookie", "http.cookie.constructor", "http.cookie.epoch-zero", "http.cookie.malformed-domain"),
        "primitive": "public Set-Cookie parser with attribute and validation observations",
        "aliases": ("parse_cookie", "set_cookie", "cookie_parser", "cookie_attributes"),
    },
    "response_timing": {
        "prefixes": ("http.response.timing-metadata",),
        "primitive": "separate request-sent and response-received timestamps",
        "aliases": ("sent_request_at", "received_response_at", "timing", "elapsed"),
    },
    "proxy_authenticator": {
        "prefixes": ("http.proxy.authenticator",),
        "primitive": "proxy challenge callback/authenticator",
        "aliases": ("proxy_authenticator", "proxy_auth", "on_proxy_auth"),
    },
    "request_builder": {
        "prefixes": ("http.request.builder", "http.request.body-legality-validation"),
        "primitive": "detached request builder with build-time body validation",
        "aliases": ("request_builder", "build_request", "prepare_request"),
    },
    "custom_timeout_error": {
        "prefixes": ("http.timeout.custom-error-message",),
        "primitive": "custom timeout error message configuration",
        "aliases": ("timeout_error_message", "timeout_message"),
    },
    "error_constants": {
        "prefixes": ("http.error.econnrefused-constant",),
        "primitive": "public transport error-code constants",
        "aliases": ("econnrefused", "error_codes", "connection_refused"),
    },
    "json_reviver": {
        "prefixes": ("http.response.json-parse-reviver",),
        "primitive": "custom JSON response reviver/transform callback",
        "aliases": ("json_reviver", "parse_reviver", "transform_response"),
    },
    "data_url": {
        "prefixes": ("http.response.node-data-url-support",),
        "primitive": "data: URL transport support",
        "aliases": ("data_url", "data_uri", "data_adapter"),
    },
    "params_serializer": {
        "prefixes": ("http.url.params-serializer-callback",),
        "primitive": "custom query-parameter serializer callback",
        "aliases": ("params_serializer", "query_serializer", "serialize_params"),
    },
    "response_error_serialization": {
        "prefixes": ("http.response.json-error-serialization",),
        "primitive": "serializable JSON response decode error preserving type and payload",
        "aliases": ("json_decode_error", "pickle", "serialize_error", "to_json"),
    },
    "link_parser": {
        "prefixes": ("http.headers.link-empty",),
        "primitive": "Link response-header parser",
        "aliases": ("links", "parse_link_header", "link_header"),
    },
    "configurable_http_errors": {
        "prefixes": ("http.error.http-errors-option",),
        "primitive": "per-request error-status exception policy",
        "aliases": ("http_errors", "raise_for_status", "validate_status"),
    },
    "redirect_policy_options": {
        "prefixes": ("http.redirect.post-policy-option", "http.redirect.post-custom-body-policy", "http.redirect.postredir-option"),
        "primitive": "configurable POST/custom-body redirect method policy",
        "aliases": ("post_redirect", "postredir", "redirect_policy", "strict_redirects"),
    },
    "expect_threshold": {
        "prefixes": ("http.request.expect-threshold",),
        "primitive": "configurable Expect: 100-continue byte threshold",
        "aliases": ("expect_threshold", "expect_continue", "continue_threshold"),
    },
    "streaming_error_callback": {
        "prefixes": ("http.response.json-parse-error-retains-response",),
        "primitive": "response-bearing JSON parse exception",
        "aliases": ("response", "json_decode_error", "parse_error"),
    },
    "http2": {
        "prefixes": ("http2.",),
        "primitive": "HTTP/2 transport negotiation and frame/stream execution",
        "aliases": ("http2", "http_2", "h2", "alpn_protocols", "http_version", "protocols"),
    },
    "websocket": {
        "prefixes": ("websocket.",),
        "primitive": "WebSocket handshake, frame, close, ping, and compression execution",
        "aliases": ("websocket", "web_socket", "ws_connect", "connect_websocket"),
    },
    "cache": {
        "prefixes": ("http.cache.", "http.cache-control."),
        "primitive": "configurable HTTP response cache with observable cache state",
        "aliases": ("cache", "cache_dir", "cache_path", "cache_storage", "cache_policy"),
    },
    "logging": {
        "prefixes": ("http.logging.",),
        "primitive": "request/response logging with observable redaction and body policy",
        "aliases": ("logger", "logging", "log_request", "log_response", "to_curl", "curl"),
    },
    "lifecycle": {
        "prefixes": ("http.lifecycle.",),
        "primitive": "observable per-call lifecycle event callbacks",
        "aliases": ("event_listener", "event_hooks", "hooks", "on_request", "on_response", "listener"),
    },
    "interceptor": {
        "prefixes": ("http.interceptor.", "http.middleware."),
        "primitive": "ordered request/response interceptor or middleware chain",
        "aliases": ("interceptor", "interceptors", "middleware", "event_hooks", "hooks"),
    },
    "sse": {
        "prefixes": ("http.sse.",),
        "primitive": "server-sent event stream parser and event callback",
        "aliases": ("event_source", "eventsource", "sse", "server_sent_event"),
    },
    "async_call": {
        "prefixes": ("http.call.", "http.async.", "http.dispatcher."),
        "primitive": "native asynchronous request/callback/cancellation lifecycle",
        "aliases": ("async", "async_request", "enqueue", "future", "callback", "cancel_token", "abort"),
    },
    "dns": {
        "prefixes": ("http.dns.",),
        "primitive": "injectable DNS resolver with observable lookup behavior",
        "aliases": ("dns", "resolver", "resolve_host", "name_resolver"),
    },
    "certificate_pinning": {
        "prefixes": ("tls.certificate-pinning",),
        "primitive": "certificate pin configuration and verification",
        "aliases": ("certificate_pinner", "certificate_pinning", "pins", "pin_sha256", "public_key_pin"),
    },
    "upgrade_socket": {
        "prefixes": ("http.upgrade.",),
        "primitive": "HTTP 101 upgraded socket exposed to the caller",
        "aliases": ("upgraded_socket", "upgrade_callback", "detach_socket", "raw_socket"),
    },
    "observability": {
        "prefixes": ("http.observability.",),
        "primitive": "transfer progress/debug/timing observation callbacks",
        "aliases": ("progress", "transfer_stats", "trace", "timing", "debug", "on_progress"),
    },
    "digest_auth": {
        "prefixes": ("http.auth.digest",),
        "primitive": "HTTP Digest challenge processing and response generation",
        "aliases": ("digest_auth", "http_digest", "digest", "auth_handler"),
    },
    "oauth_signing": {
        "prefixes": ("http.auth.oauth",),
        "primitive": "OAuth request signing with nonce and canonical parameter ordering",
        "aliases": ("oauth", "oauth1", "sign_request", "auth_handler"),
    },
    "ntlm_auth": {
        "prefixes": ("http.auth.ntlm",),
        "primitive": "NTLM challenge/response authentication",
        "aliases": ("ntlm", "auth_handler"),
    },
    "cancellation": {
        "prefixes": ("http.cancel.",),
        "primitive": "request cancellation with cancellation reason/error observation",
        "aliases": ("cancel", "abort", "cancel_token", "abort_signal", "cancellation"),
    },
    "fetch_adapter": {
        "prefixes": ("http.adapter.fetch",),
        "primitive": "selectable Fetch-compatible transport adapter and environment",
        "aliases": ("fetch", "fetch_adapter", "adapter", "transport"),
    },
    "formdata_conversion": {
        "prefixes": ("http.formdata.",),
        "primitive": "FormData object conversion with key hardening semantics",
        "aliases": ("form_data", "formdata", "form_to_json", "to_form_data"),
    },
    "body_limits": {
        "prefixes": ("http.request.max-body-length", "http.request.fetch-max-body-length", "http.response.max-content-length", "http.response.stream-max-content-length", "http.response.data-url-max-content-length"),
        "primitive": "configurable request or decoded-response byte limit",
        "aliases": ("max_body_length", "max_content_length", "body_limit", "response_limit"),
    },
    "socket_path": {
        "prefixes": ("http.transport.socket-path",),
        "primitive": "Unix-domain socket request transport with an allowlist",
        "aliases": ("socket_path", "unix_socket", "uds", "unix_adapter"),
    },
    "prepared_request": {
        "prefixes": ("http.request.prepared", "http.cookies.prepared-request", "http.hooks.", "http.redirect.adapter-kwargs", "http.adapter.tls-context", "tls.custom-adapter"),
        "primitive": "public prepared-request and custom transport adapter lifecycle",
        "aliases": ("prepared_request", "prepare_request", "prepare", "http_adapter", "mount", "hooks"),
    },
    "netrc": {
        "prefixes": ("http.auth.netrc",),
        "primitive": "netrc credential discovery and host/error policy",
        "aliases": ("netrc", "trust_env_auth", "credential_file"),
    },
    "response_history": {
        "prefixes": ("http.redirect.history", "http.redirect.status-history", "http.redirect.tracking-option"),
        "primitive": "caller-visible redirect response history",
        "aliases": ("history", "redirect_history", "track_redirects", "previous_response"),
    },
    "response_sink": {
        "prefixes": ("http.response.sink", "http.response.on-headers-callback"),
        "primitive": "response header callback and direct response-body sink",
        "aliases": ("sink", "on_headers", "response_hook", "download_to"),
    },
    "public_cookie_jar": {
        "prefixes": ("http.cookie.jar", "http.cookie.strict-jar", "http.cookies.prepared", "http.cookies.custom-host", "http.cookie.option-shapes"),
        "primitive": "public cookie-jar manipulation, inspection, and policy interface",
        "aliases": ("cookie_jar", "cookiejar", "set_cookie", "get_cookie"),
    },
    "custom_handler": {
        "prefixes": ("http.handler.", "http.client.psr18", "http.error.body-summary", "http.error.response-body-summary", "http.stream.custom", "http.stream.read-position", "http.response.parse-helpers"),
        "primitive": "public handler/stream extension and response helper interface",
        "aliases": ("handler", "adapter", "transport", "rewind", "parse_xml", "body_summarizer"),
    },
    "request_delay": {
        "prefixes": ("http.request.delay-option",),
        "primitive": "request dispatch delay configuration",
        "aliases": ("delay", "dispatch_delay", "schedule_request"),
    },
    "force_ip": {
        "prefixes": ("http.dns.force-ip-resolve",),
        "primitive": "per-request IPv4/IPv6 resolution selection",
        "aliases": ("force_ip_resolve", "ip_version", "address_family"),
    },
    "configurable_retry": {
        "prefixes": ("http.retry.",),
        "primitive": "public retry policy including budget, status, delay, and replayability controls",
        "aliases": ("retry", "retries", "retry_policy", "backoff", "retry_after"),
    },
    "pool_control": {
        "prefixes": ("http.connection.pool", "http.connection.route", "http.pool.", "http.connection.health", "http.connection.worker", "http.connection.pooled"),
        "primitive": "public connection-pool sizing, route, and lifecycle controls",
        "aliases": ("pool", "connection_pool", "max_connections", "maxsize", "pool_timeout", "route"),
    },
    "raw_response_io": {
        "prefixes": ("http.response.read", "http.response.stream-zero", "http.response.content-length", "http.response.shutdown", "http.response.close-policy", "http.response.decode-mode-consistency", "http.response.trailers"),
        "primitive": "raw incremental response read/trailer/lifecycle operations",
        "aliases": ("read", "read1", "read_chunked", "trailers", "shutdown", "length_remaining"),
    },
    "mutable_multi_headers": {
        "prefixes": ("http.headers.key-equivalence", "http.headers.merge-policy", "http.headers.case-insensitive-order"),
        "primitive": "public mutable multi-value header collection operations",
        "aliases": ("add", "discard", "multi_items", "get_list", "headers_union"),
    },
    "keylog": {
        "prefixes": ("tls.keylogfile",),
        "primitive": "TLS key-log file configuration",
        "aliases": ("keylog", "keylog_filename", "sslkeylogfile"),
    },
    "proxy_selector": {
        "prefixes": ("http.proxy.selector", "http.proxy.selection", "http.proxy.connect-failed-callback"),
        "primitive": "lazy system proxy selector with failure callback",
        "aliases": ("proxy_selector", "select_proxy", "connect_failed"),
    },
    "socks_proxy": {
        "prefixes": ("http.proxy.socks",),
        "primitive": "SOCKS proxy transport including remote DNS and authentication",
        "aliases": ("socks", "socks_proxy", "socks5h"),
    },
    "specialized_tls": {
        "prefixes": ("tls.post-handshake", "tls.session-invalid", "tls.connection-spec", "tls.fallback-scsv", "tls.alpn", "tls.handshake-empty", "tls.socket-factory", "tls.private-key", "tls.client-certificate-der", "tls.client-certificate-p12"),
        "primitive": "specialized TLS session, socket-factory, certificate-format, or fallback control",
        "aliases": ("post_handshake_auth", "connection_spec", "fallback_scsv", "alpn", "ssl_socket_factory", "pkcs12", "der_certificate"),
    },
    "archive_utility": {
        "prefixes": ("http.util.archive",),
        "primitive": "archive extraction utility exposed by the HTTP package",
        "aliases": ("extract_zipped_paths", "extract_archive", "unzip"),
    },
    "pyopenssl_error_backend": {
        "prefixes": ("tls.error-taxonomy",),
        "primitive": "selectable PyOpenSSL transport backend with syscall errno error observation",
        "aliases": ("pyopenssl_backend", "openssl_backend", "tls_backend"),
    },
    "socket_options": {
        "prefixes": ("http.connection.socket-options",),
        "primitive": "caller-supplied socket options applied before connect",
        "aliases": ("socket_options", "socket_option", "setsockopt_callback"),
    },
    "brotli_decoder_protocol": {
        "prefixes": ("http.response.brotli-decoding",),
        "primitive": "pluggable Brotli decoder object protocol",
        "aliases": ("brotli_decoder", "decoder_factory", "decompressor"),
    },
    "multipart_part_sink": {
        "prefixes": ("http.multipart.body-lifecycle",),
        "primitive": "multipart part sink whose close is distinct from source-body close",
        "aliases": ("multipart_part_sink", "part_sink", "multipart_writer"),
    },
    "informational_trailers": {
        "prefixes": ("http.response.informational-trailer-boundary",),
        "primitive": "HTTP informational-response and trailer boundary observation",
        "aliases": ("informational_response", "trailers", "early_hints"),
    },
    "per_host_insecure_policy": {
        "prefixes": ("tls.hostname-verification-insecure-host-allowlist",),
        "primitive": "per-host hostname-verification bypass allowlist",
        "aliases": ("insecure_hosts", "hostname_allowlist", "skip_verify_hosts"),
    },
    "multipart_response_reader": {
        "prefixes": ("http.multipart.response-streaming",),
        "primitive": "streaming multipart response reader",
        "aliases": ("multipart_reader", "iter_parts", "response_parts"),
    },
    "shared_proxy_pool": {
        "prefixes": ("http.proxy.connection-pool-sharing",),
        "primitive": "caller-visible shared connection pool across separately configured proxy clients",
        "aliases": ("shared_connection_pool", "connection_pool", "pool_manager"),
    },
    "route_retention": {
        "prefixes": ("http.redirect.route-retention",),
        "primitive": "caller-visible route metadata retained across follow-up requests",
        "aliases": ("route", "route_database", "connection_route"),
    },
    "tls_event_logging": {
        "prefixes": ("tls.logging.handshake",),
        "primitive": "TLS handshake event listener or logger callback",
        "aliases": ("event_listener", "handshake_event", "tls_logger"),
    },
    "authenticator_callback": {
        "prefixes": ("http.auth.null-default-authenticator", "http.auth.exception-connection-release", "http.proxy.tunnel-auth-close-recovery"),
        "primitive": "HTTP challenge authenticator callback lifecycle",
        "aliases": ("authenticator", "authentication_callback", "on_auth_challenge"),
    },
    "http2_cached_headers": {
        "prefixes": ("http.headers.non-ascii-read-robustness",),
        "primitive": "HTTP/2 cached-header decoding",
        "aliases": ("http2", "h2", "header_compression", "hpack"),
    },
    "cleartext_policy": {
        "prefixes": ("http.cleartext-policy",),
        "primitive": "configurable cleartext transport policy",
        "aliases": ("cleartext_policy", "allow_cleartext", "connection_spec"),
    },
    "socket_factory": {
        "prefixes": ("http.connection.socket-factory-direct",),
        "primitive": "caller-supplied socket factory for direct connections",
        "aliases": ("socket_factory", "create_connection", "connection_factory"),
    },
    "abort_timeout": {
        "prefixes": ("http.timeout.abort",),
        "primitive": "separate strict abort timeout",
        "aliases": ("abort_timeout", "cancel_after", "call_timeout"),
    },
    "head_sink": {
        "prefixes": ("http.response.head-sink-policy",),
        "primitive": "direct response sink with HEAD-specific connection policy",
        "aliases": ("sink", "download_to", "response_sink"),
    },
    "client_key_array": {
        "prefixes": ("tls.client-key-array-options",),
        "primitive": "structured client certificate/key/password option",
        "aliases": ("client_key_options", "cert_password", "client_certificate"),
    },
    "curl_select_timeout": {
        "prefixes": ("http.transport.curl-select-timeout-env",),
        "primitive": "cURL multi-select timeout environment control",
        "aliases": ("curl_select_timeout", "curl_multi", "select_timeout"),
    },
    "phar_ca_policy": {
        "prefixes": ("tls.ca-phar-policy",),
        "primitive": "PHAR packaged CA-bundle discovery policy",
        "aliases": ("phar", "bundled_ca", "ca_bundle_path"),
    },
    "long_lived_connect_timeout": {
        "prefixes": ("http.timeout.long-lived-connect",),
        "primitive": "connect-phase timeout for WebSocket, SSE, or duplex streams",
        "aliases": ("websocket", "event_source", "duplex", "connect_timeout"),
    },
    "route_failure_sequence": {
        "prefixes": ("http.connection.exception-priority",),
        "primitive": "injectable multi-route connect attempt with primary and suppressed errors",
        "aliases": ("route_planner", "connection_attempts", "suppressed_errors"),
    },
}


ANALYSIS_BEHAVIOR_TESTS = {
    "application_json_without_charset_decodes_as_utf8",
    "base_uri_resolves_relative_request_uris",
    "body_option_accepts_string_resource_or_stream",
    "case_insensitive_headers_preserve_insertion_order",
    "compressed_chunked_response_is_decoded",
    "cookie_values_are_not_url_decoded_by_default",
    "cookie_without_value_is_stored",
    "content_length_zero_is_set_before_request_event",
    "custom_getattr_bodies_are_detected_as_iterables",
    "default_user_agent_avoids_runtime_data_leak",
    "default_user_agent_is_major_version_only",
    "empty_post_files_and_fields_are_ignored",
    "null_header_option_is_handled_gracefully",
    "http_header_dict_accepts_bytes_keys",
    "http_header_dict_supports_union_operators",
    "http_header_dict_can_repeat_or_combine_values",
    "http_errors_option_controls_exception_on_error_status",
    "invalid_certificate_bundle_path_fails_before_dispatch",
    "invalid_headers_array_raises_invalid_argument",
    "iter_content_accepts_integer_and_none_chunk_sizes",
    "json_decode_error_is_request_exception",
    "leading_dot_hostname_error_is_invalid_url",
    "missing_schema_error_suggests_https",
    "multipart_file_body_string_zero_is_preserved",
    "multipart_same_name_files_are_supported",
    "partial_file_upload_uses_remaining_bytes_only",
    "post_fields_and_files_are_aggregated",
    "query_option_merges_with_uri_query",
    "request_always_has_body_object",
    "request_factory_uses_post_file_key_as_filename",
    "stream_response_from_http_request_is_supported",
    "response_text_defaults_utf8_without_charset_detector",
    "response_json_uses_response_encoding_consistently",
    "safe_method_redirects_are_allowed",
    "schemes_starting_with_http_but_not_http_are_rejected",
    "session_closes_on_exceptional_and_normal_exit",
    "stream_handler_rejects_non_http_schemes",
    "too_many_redirects_exception_contains_response",
    "uri_objects_are_not_implicitly_stringified",
    "authorization_header_stripped_on_http_downgrade",
    "bytes_and_string_subclass_header_components_are_accepted",
    "chunked_requests_do_not_send_duplicate_host_headers",
    "cookie_header_stripped_on_http_downgrade",
    "cross_domain_cookies_are_not_leaked",
    "decode_content_option_preserves_default_headers",
    "default_cookie_header_casing_is_cookie",
    "empty_no_proxy_entries_are_ignored",
    "empty_password_in_proxy_credentials_is_allowed",
    "empty_unknown_length_file_upload_uses_chunked_transfer",
    "extra_leading_path_separator_does_not_trigger_uri_reparse",
    "header_glue_is_used_when_transferring_headers",
    "idna2008_hostnames_are_supported",
    "malformed_header_values_raise_consistent_header_error",
    "non_ascii_location_redirect_is_decoded_without_unicode_error",
    "proxies_mapping_no_proxy_key_is_honored",
    "proxy_connection_failures_raise_proxy_error",
    "proxy_url_missing_scheme_is_parsed_with_default_scheme",
    "redirect_307_308_rewinds_file_like_body",
    "redirect_cookie_without_domain_is_scoped_to_original_host",
    "redirect_port_change_is_origin_change",
    "redirect_to_invalid_url_is_wrapped",
    "redirects_are_implemented_in_client_not_transport",
    "ssl_context_is_not_cached_across_session_verify_policy",
    "ssl_errors_from_streaming_content_are_wrapped",
    "stream_handler_accepts_http_proxy_scheme",
    "verify_false_does_not_persist_to_later_same_origin_requests",
    "allow_absolute_urls_false_combines_absolute_request_url",
    "body_is_not_written_after_server_closes_socket",
    "ca_certificate_directory_is_accepted",
    "call_timeout_is_preserved_across_redirects",
    "connection_is_discarded_after_read_error",
    "cookies_are_accepted_for_ipv6_hosts",
    "empty_query_does_not_include_fragment",
    "failed_connect_does_not_leak_socket",
    "fingerprint_or_hostname_failure_does_not_leak_socket",
    "gzip_streams_are_exhausted_on_close",
    "hostname_verification_does_not_fallback_to_common_name",
    "https_post_streaming_is_not_always_buffered",
    "https_proxy_misconfiguration_reports_http_proxy_hint",
    "incomplete_read_error_reports_excess_content",
    "json_parse_error_keeps_response",
    "multipart_body_omits_aggregate_content_length",
    "no_proxy_canonicalizes_ipv4_shorthand",
    "non_ascii_hostname_fails_before_tls_verification",
    "null_header_values_are_ignored",
    "proxy_certificate_hostname_assertion_is_configurable",
    "proxy_errors_wrap_connection_failures",
    "public_domain_cookies_are_rejected",
    "recorded_request_reports_tls_sni",
    "response_body_can_be_read_after_callback_returns",
    "response_read_error_closes_original_response_and_connection",
    "shoutcast_icy_response_is_supported",
    "socket_ssl_error_is_wrapped_as_ssl_error",
    "timeout_errors_use_socket_timeout_taxonomy",
    "trust_everything_redirect_does_not_fail",
    "url_scheme_may_contain_digits",
    "authentication_credentials_support_charset",
    "ca_info_and_ca_path_are_filled_correctly",
    "cert_reqs_accepts_string_policy_values",
    "client_cipher_suite_precedence_is_honored",
    "curl_httpauth_option_cleared_on_origin_change",
    "custom_trust_manager_is_used_directly",
    "dss_cipher_suite_is_not_offered_by_default",
    "empty_curl_ca_bundle_does_not_disable_verification",
    "https_agent_tls_options_survive_http_connect_proxy",
    "https_hostname_verifier_selection_allows_reuse",
    "https_loads_system_certs_when_no_ca_options_are_set",
    "idn_support_is_disabled_by_default",
    "ipv6_url_host_is_canonicalized",
    "java_net_cookie_jar_handles_multiple_cookies",
    "no_proxy_domain_matching_is_not_greedy",
    "numeric_proxy_address_skips_reverse_dns",
    "proxy_option_no_overrides_environment_proxy",
    "stream_handler_sets_default_ssl_peer_name_for_forced_ip",
    "system_cipher_suites_are_not_overridden_by_default",
    "timeouts_fire_without_scheduler_delay",
    "tls12_is_preferred_where_available",
    "tls13_is_enabled_on_modern_jdk",
    "tls_hostname_verifier_rejects_noncanonical_ip_hosts",
    "verify_accepts_ca_certificate_directory",
    "android_https_sets_sni_server_name",
    "basic_auth_warning_does_not_include_password",
    "chunked_body_connection_is_released_once",
    "custom_timeout_error_message_is_used",
    "invalid_header_from_transport_is_wrapped",
    "ssl_key_array_options_do_not_emit_undefined_offset",
    "tarfile_extractfile_payload_length_detection_does_not_crash",
    "connect_handling_tolerates_misbehaving_proxies",
    "http1_request_body_is_flushed_before_timeout_detach",
    "proxy_authorization_from_proxy_url_is_not_forwarded_after_https_redirect",
    "redirect_does_not_reuse_connection_when_dns_differs",
    "response_is_read_when_request_write_fails",
    "same_host_default_port_redirect_preserves_authorization",
    "tls_tunnel_truncated_response_body_does_not_crash",
}


def required_feature(capability: str) -> tuple[str, dict] | None:
    for name, spec in FEATURES.items():
        if capability.startswith(spec["prefixes"]):
            return name, spec
    return None


def main() -> None:
    rows = [json.loads(line) for line in IR.read_text().splitlines() if line]
    projections = []
    for row in rows:
        feature = required_feature(row["capability"])
        if row["name"] in ANALYSIS_BEHAVIOR_TESTS:
            kind = "analysis_behavior_replay"
            payload = {"test": row["name"]}
        elif row["legacy_execution_available"]:
            kind = "behavior_replay"
            payload = {"legacy_test": row["name"]}
        elif feature:
            name, spec = feature
            kind = "capability_absence_probe"
            payload = {
                "feature": name,
                "required_semantic_primitive": spec["primitive"],
                "equivalent_native_interfaces": list(spec["aliases"]),
            }
        elif not row["definition_complete"]:
            kind = "provenance_recovery_required"
            payload = {"reason": "setup/action/oracle/control are not preserved in frozen artifacts"}
        else:
            kind = "behavior_lowering_required"
            payload = {"setup": row["setup"], "actions": row["actions"], "oracle": row["oracle"]}
        projections.append({
            "scoring_id": row["scoring_id"],
            "contract_hash": row["contract_hash"],
            "origin": row["origin"],
            "name": row["name"],
            "capability": row["capability"],
            "projection_kind": kind,
            "projection": payload,
        })
    (HERE / "solhttp_projection_plan.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in projections)
    )
    from collections import Counter
    print(json.dumps(dict(Counter(row["projection_kind"] for row in projections)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
