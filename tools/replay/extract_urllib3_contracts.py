#!/usr/bin/env python3
"""
Extract language-independent replayable contract candidates from urllib3 release notes.

This extractor is intentionally rule-based. It only emits a contract when a
release-note sentence matches a known protocol, API-contract, or runtime
behavior template that can be checked without depending on a specific
programming language feature.
Language/runtime support, packaging, typing, documentation, and dependency-only
changes are recorded as skipped release notes instead of contracts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHANGES = ROOT / ".replay" / "urllib3-head" / "CHANGES.rst"
OUT_RPL = ROOT / "contracts" / "urllib3" / "all_releases_maximal_language_independent.rpl"
OUT_JSON = ROOT / "contracts" / "urllib3" / "all_releases_maximal_language_independent.summary.json"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    capability: str
    setup: tuple[str, ...]
    actions: tuple[str, ...]
    assertions: tuple[str, ...]
    mutant: str

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text, flags=re.I) is not None


RULES: tuple[Rule, ...] = (
    Rule(
        "response_legacy_header_accessors_are_available",
        r"Restore previously removed ``HTTPResponse.getheaders\(\)`` and\s+``HTTPResponse.getheader\(\)`` methods",
        "http.response.header-access",
        (
            'given response headers {"X-Test":"1"}',
        ),
        ('when response_getheader "X-Test"', 'when response_getheaders'),
        ('then header_value == "1"', 'then headers contains ["X-Test","1"]'),
        "remove_legacy_response_header_accessors",
    ),
    Rule(
        "response_legacy_header_accessors_are_removed",
        r"Removed the ``HTTPResponse.getheaders\(\)`` method.*Removed the ``HTTPResponse.getheader",
        "http.response.header-access-removal",
        (
            'given response headers {"X-Test":"1"}',
        ),
        ('when response_getheader "X-Test"',),
        ('then error 1 kind "unsupported_header_accessor"',),
        "restore_removed_legacy_response_header_accessor",
    ),
    Rule(
        "http_header_dict_accepts_bytes_keys",
        r"HTTPHeaderDict`` using bytes keys",
        "http.headers.key-equivalence",
        (
            'given headers {"X-Test":"1"}',
        ),
        ('when lookup_header bytes "X-Test"', 'when contains_header bytes "X-Test"', 'when delete_header bytes "X-Test"'),
        ('then header_value == "1"', 'then contains_result == true', 'then headers not_contains "X-Test"'),
        "reject_bytes_header_keys",
    ),
    Rule(
        "http_header_dict_supports_union_operators",
        r"union operators to ``HTTPHeaderDict``",
        "http.headers.merge-policy",
        (
            'given headers {"A":"1"}',
            'given headers "other" {"B":"2"}',
        ),
        ('when header_union "$headers" "$other"',),
        ('then headers == {"A":"1","B":"2"}',),
        "missing_header_union_operator",
    ),
    Rule(
        "connection_string_representation_includes_host_and_port",
        r"host and port information to string representations of ``HTTPConnection``",
        "http.connection.identity",
        (
            'given connection origin "http://example.test:8080"',
        ),
        ('when connection_to_string',),
        ('then string contains "example.test"', 'then string contains "8080"'),
        "omit_host_or_port_from_connection_string",
    ),
    Rule(
        "sslkeylogfile_expands_environment_variables",
        r"SSLKEYLOGFILE`` with expandable variables",
        "tls.keylogfile",
        (
            'given env "LOGDIR" "/tmp"',
            'given env "SSLKEYLOGFILE" "$LOGDIR/keys.log"',
        ),
        ('when create_tls_context',),
        ('then keylog_file == "/tmp/keys.log"',),
        "do_not_expand_sslkeylogfile_variables",
    ),
    Rule(
        "empty_sslkeylogfile_does_not_configure_keylog",
        r"SSLKEYLOGFILE`` environment variable was set to the empty string",
        "tls.keylogfile",
        (
            'given env "SSLKEYLOGFILE" ""',
        ),
        ('when create_tls_context',),
        ('then keylog_file absent',),
        "set_empty_sslkeylogfile_on_context",
    ),
    Rule(
        "sslkeylogfile_environment_enables_tls_key_logging",
        r"Added support for ``SSLKEYLOGFILE`` environment variable",
        "tls.keylogfile",
        (
            'given env "SSLKEYLOGFILE" "/tmp/keys.log"',
        ),
        ('when create_tls_context',),
        ('then keylog_file == "/tmp/keys.log"',),
        "ignore_sslkeylogfile_environment",
    ),
    Rule(
        "proxy_connection_exposes_tunneling_state",
        r"proxy_is_tunneling`` property",
        "http.proxy.tunnel-state",
        (
            'given proxy "origin" tunneling true',
        ),
        ('when CONNECT target "example.test:443" via_proxy "$ORIGIN"',),
        ('then connection proxy_is_tunneling == true',),
        "proxy_tunneling_state_unobservable_or_false",
    ),
    Rule(
        "proxy_connection_verification_state_is_boolean",
        r"proxy_is_verified``.*always set to a boolean",
        "http.proxy.verification-state",
        (
            'given proxy "origin" tunneling true tls true',
        ),
        ('when HTTPS_GET "https://example.test/" via_proxy "$ORIGIN"',),
        ('then connection proxy_is_verified type "boolean"',),
        "leave_proxy_is_verified_as_null",
    ),
    Rule(
        "https_proxy_to_http_target_is_not_marked_verified",
        r"HTTPSConnection.is_verified`` to be set to ``False`` when connecting from a HTTPS proxy to an HTTP target",
        "http.proxy.verification-state",
        (
            'given proxy "origin" scheme "https"',
            'given server "target" scheme "http" route "/" status 200 body "ok"',
        ),
        ('when GET "http://target/" via_proxy "$ORIGIN"',),
        ('then connection is_verified == false',),
        "mark_http_target_via_https_proxy_as_verified",
    ),
    Rule(
        "cross_host_redirect_strips_configured_sensitive_header",
        r"sensitive headers specified in ``Retry\.remove_headers_on_redirect``.*redirecting to a different host",
        "http.redirect.header-stripping",
        (
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 303',
            'given server "other" route "/target" echo_header "X-Secret"',
        ),
        ('when GET "/redirect" header "X-Secret" "secret" redirect true remove_headers_on_redirect ["X-Secret"]',),
        ('then server "other" observed_header "X-Secret" absent',),
        "preserve_configured_sensitive_header_on_cross_host_redirect",
    ),
    Rule(
        "cross_host_redirect_strips_authorization_header",
        r"(Authorization header|sensitive headers).*redirecting to a different host|redirecting to a different host.*Authorization header",
        "http.redirect.header-stripping",
        (
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 303',
            'given server "other" route "/target" echo_header "Authorization"',
        ),
        ('when GET "/redirect" header "Authorization" "Bearer secret" redirect true',),
        ('then server "other" observed_header "Authorization" absent',),
        "preserve_authorization_on_cross_host_redirect",
    ),
    Rule(
        "cross_host_redirect_strips_cookie_header",
        r"Cookie`` header.*strip.*redirecting to a different host|strip.*Cookie.*redirecting to a different host",
        "http.redirect.header-stripping",
        (
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 303',
            'given server "other" route "/target" echo_header "Cookie"',
        ),
        ('when GET "/redirect" header "Cookie" "session=secret" redirect true',),
        ('then server "other" observed_header "Cookie" absent',),
        "preserve_cookie_on_cross_host_redirect",
    ),
    Rule(
        "cross_host_redirect_strips_proxy_authorization_header",
        r"Proxy-Authorization`` header.*strip.*redirecting to a different host|strip.*Proxy-Authorization.*redirecting to a different host",
        "http.redirect.header-stripping",
        (
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 303',
            'given server "other" route "/target" echo_header "Proxy-Authorization"',
        ),
        ('when GET "/redirect" header "Proxy-Authorization" "Basic secret" redirect true',),
        ('then server "other" observed_header "Proxy-Authorization" absent',),
        "preserve_proxy_authorization_on_cross_host_redirect",
    ),
    Rule(
        "authorization_header_stripping_is_case_insensitive",
        r"Remove Authorization header regardless of case when redirecting to cross-site",
        "http.redirect.header-stripping",
        (
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 303',
            'given server "other" route "/target" echo_header "authorization"',
        ),
        ('when GET "/redirect" header "authorization" "Bearer secret" redirect true',),
        ('then server "other" observed_header "authorization" absent',),
        "strip_authorization_case_sensitively",
    ),
    Rule(
        "http_303_redirect_switches_method_to_get_and_strips_body",
        r"(body stripped.*303|303 .*body stripped|switch method to '?GET'? if status code is 303)",
        "http.redirect.method-rewrite",
        (
            'given server "origin" route "/redirect" redirect_to "$ORIGIN/target" status 303',
            'given server "origin" route "/target" require_method "GET" require_body_empty true',
        ),
        ('when POST "/redirect" body "payload" redirect true',),
        ('then response 1 status 200',),
        "preserve_post_body_on_303_redirect",
    ),
    Rule(
        "poolmanager_integer_retries_limits_redirects",
        r"(redirect.*integer.*retries|maximum number of followed redirects.*PoolManager.*retries)",
        "http.redirect.retry-budget",
        (
            'given server "origin" route "/loop" redirect_to "$ORIGIN/loop" status 302',
        ),
        ('when GET "/loop" redirect true retries 1',),
        ('then error 1 kind "max_retries_exceeded"',),
        "ignore_integer_redirect_retry_budget",
    ),
    Rule(
        "retry_after_header_is_capped_at_six_hours",
        r"Retry-After`` times greater than 6 hours.*6 hours",
        "http.retry.retry-after-cap",
        (
            'given retry_policy respect_retry_after true',
        ),
        ('when parse_retry_after "25200"',),
        ('then retry_after_seconds <= 21600',),
        "allow_retry_after_above_six_hours",
    ),
    Rule(
        "retry_after_header_is_respected_for_retry_statuses",
        r"Retry-After headers on 413, 429, and 503",
        "http.retry.retry-after",
        (
            'given server "origin" route "/retry-after" sequence status 503 header "Retry-After" "1" body "" then status 200 body "ok"',
        ),
        ('when GET "/retry-after" retries 1 respect_retry_after true',),
        ('then response 1 status 200',),
        "ignore_retry_after_header",
    ),
    Rule(
        "retry_after_http_date_uses_utc",
        r"retry backoff time parsed from ``Retry-After`` header when given in the HTTP date format",
        "http.retry.retry-after-date",
        (
            'given retry_policy respect_retry_after true now "Sun, 06 Nov 1994 08:49:36 GMT"',
        ),
        ('when parse_retry_after "Sun, 06 Nov 1994 08:49:37 GMT"',),
        ('then retry_after_seconds == 1',),
        "parse_retry_after_http_date_as_local_time",
    ),
    Rule(
        "retry_after_setting_propagates_to_subsequent_retries",
        r"Propagate Retry-After header settings to subsequent retries",
        "http.retry.retry-after-propagation",
        (
            'given server "origin" route "/retry-after" sequence status 503 header "Retry-After" "1" body "" then status 200 body "ok"',
        ),
        ('when GET "/retry-after" retries 1 respect_retry_after true',),
        ('then response 1 status 200',),
        "drop_retry_after_setting_after_first_retry",
    ),
    Rule(
        "retry_after_can_be_explicitly_ignored",
        r"Retry-After header was still respected even when explicitly opted out",
        "http.retry.retry-after-opt-out",
        (
            'given server "origin" route "/retry-after" sequence status 503 header "Retry-After" "120" body "" then status 200 body "ok"',
        ),
        ('when GET "/retry-after" retries 1 respect_retry_after false',),
        ('then response 1 status 200', 'then elapsed_seconds < 1'),
        "sleep_despite_retry_after_opt_out",
    ),
    Rule(
        "custom_retry_backoff_max_limits_backoff",
        r"configurable ``backoff_max`` parameter",
        "http.retry.backoff",
        (
            'given retry_policy backoff_factor 10 backoff_max 1',
        ),
        ('when compute_backoff attempt 3',),
        ('then backoff_seconds <= 1',),
        "ignore_custom_backoff_max",
    ),
    Rule(
        "retry_backoff_jitter_is_added_within_bounds",
        r"optional ``backoff_jitter`` parameter",
        "http.retry.backoff",
        (
            'given retry_policy backoff_factor 1 backoff_jitter 0.5',
        ),
        ('when compute_backoff attempt 2',),
        ('then backoff_seconds >= 2', 'then backoff_seconds <= 2.5'),
        "ignore_or_exceed_backoff_jitter",
    ),
    Rule(
        "retry_backoff_constant_is_renamed_without_value_change",
        r"Retry\.BACK0FF_MAX`` to be ``Retry\.DEFAULT_BACKOFF_MAX``",
        "http.retry.backoff",
        (
            'given retry_policy defaults',
        ),
        ('when read_default_backoff_max',),
        ('then default_backoff_max available',),
        "missing_default_backoff_max",
    ),
    Rule(
        "broken_connection_is_retried_until_success",
        r"(Retrying.*connection broken|retry.*connection broken|retry on ``SSLError``|retry on SSLError)",
        "http.retry.broken-connection",
        (
            'given server "origin" route "/flaky" close_first_then status 200 body "recovered"',
        ),
        ('when GET "/flaky" retries 1',),
        ('then response 1 status 200', 'then server "origin" path_requests "/flaky" == 2'),
        "disable_retry_after_broken_connection",
    ),
    Rule(
        "read_timeout_is_wrapped_as_timeout_error",
        r"(socket\.timeout.*ReadTimeoutError|SSL-related timeouts.*detected as timeouts|timeout-related bugs|TimeoutError)",
        "http.timeout.error-kind",
        (
            'given server "origin" route "/sleep" sleep 0.2 status 200 body ""',
        ),
        ('when GET "/sleep" timeout 0.1',),
        ('then error 1 kind "timeout"',),
        "surface_raw_socket_timeout",
    ),
    Rule(
        "read_timeout_retry_respects_method_allowlist",
        r"Prevent retries from occurring on read timeouts.*method whitelist",
        "http.retry.method-allowlist",
        (
            'given server "origin" route "/sleep" sleep 0.2 status 200 body ""',
        ),
        ('when POST "/sleep" timeout 0.1 retries 1 allowed_methods ["GET"]',),
        ('then server "origin" path_requests "/sleep" == 1',),
        "retry_disallowed_method_after_read_timeout",
    ),
    Rule(
        "status_forcelist_retry_increments_retry_counter",
        r"Add retry counter for ``status_forcelist``",
        "http.retry.status-forcelist-budget",
        (
            'given server "origin" route "/status" sequence status 500 body "" then status 500 body ""',
        ),
        ('when GET "/status" retries 1 status_forcelist [500]',),
        ('then error 1 kind "max_retries_exceeded"', 'then server "origin" path_requests "/status" == 2'),
        "do_not_count_status_forcelist_retries",
    ),
    Rule(
        "chunked_parameter_is_preserved_on_retries",
        r"Preserve ``chunked`` parameter on retries",
        "http.retry.chunked-request",
        (
            'given server "origin" route "/flaky-upload" close_first_then_echo_header "Transfer-Encoding"',
        ),
        ('when POST "/flaky-upload" body "abc" chunked true retries 1',),
        ('then response 1 body "chunked"',),
        "drop_chunked_flag_on_retry",
    ),
    Rule(
        "redirect_drain_releases_blocking_pool_connection",
        r"Drain and release connection before recursing on retry/redirect|Drain connection after ``PoolManager`` redirect",
        "http.redirect.connection-lifecycle",
        (
            'given server "origin" route "/redirect" redirect_to "$ORIGIN/target" status 302 body "unread-body"',
            'given server "origin" route "/target" status 200 body "ok"',
        ),
        ('when GET "/redirect" redirect true pool_max 1 block true',),
        ('then response 1 status 200', 'then no_deadlock true'),
        "recurse_redirect_without_releasing_connection",
    ),
    Rule(
        "reused_connection_uses_new_socket_timeout",
        r"socket timeout value when ``HTTPConnection`` is reused|reuse the socket read timeout value",
        "http.connection.timeout-reset",
        (
            'given server "origin" route "/fast" status 200 body "ok"',
            'given server "origin" route "/slow" sleep 0.2 status 200 body "slow"',
        ),
        ('when GET "/fast" timeout 0.5', 'when GET "/slow" timeout 0.1'),
        ('then error 2 kind "timeout"',),
        "reuse_previous_socket_timeout",
    ),
    Rule(
        "same_origin_requests_reuse_one_connection",
        r"Re-use the same socket connection|connection reusing|LifoQueue",
        "http.connection.pooling",
        (
            'given server "origin" route "/first" status 200 body "first"',
            'given server "origin" route "/second" status 200 body "second"',
        ),
        ('when GET "/first"', 'when GET "/second"'),
        ('then server "origin" accepted_connections == 1',),
        "disable_connection_reuse",
    ),
    Rule(
        "default_user_agent_header_is_sent",
        r"Added default ``User-Agent`` header to every request",
        "http.headers.default-user-agent",
        (
            'given server "origin" route "/ua" echo_header "User-Agent"',
        ),
        ('when GET "/ua"',),
        ('then response 1 body matches "urllib3"',),
        "omit_default_user_agent",
    ),
    Rule(
        "skip_header_suppresses_automatic_headers",
        r"SKIP_HEADER.*skipping ``User-Agent``, ``Accept-Encoding``, and ``Host`` headers",
        "http.headers.skip-automatic",
        (
            'given server "origin" route "/headers" capture_headers',
        ),
        ('when GET "/headers" header "User-Agent" SKIP_HEADER header "Accept-Encoding" SKIP_HEADER',),
        ('then server "origin" observed_header "User-Agent" absent', 'then server "origin" observed_header "Accept-Encoding" absent'),
        "ignore_skip_header_sentinel",
    ),
    Rule(
        "bytes_user_agent_header_does_not_duplicate",
        r"two ``User-Agent`` headers would be sent if a ``User-Agent`` header key is passed as ``bytes``",
        "http.headers.duplicate-user-agent",
        (
            'given server "origin" route "/ua" count_header "User-Agent"',
        ),
        ('when GET "/ua" header_bytes "User-Agent" "custom"',),
        ('then server "origin" header_count "User-Agent" == 1',),
        "emit_duplicate_user_agent_for_bytes_key",
    ),
    Rule(
        "bytes_and_string_header_keys_compare_equal",
        r"bytes and string comparison issue with headers",
        "http.headers.key-equivalence",
        (
            'given headers {"Host":"example.test"}',
        ),
        ('when lookup_header bytes "Host"',),
        ('then header_value == "example.test"',),
        "treat_bytes_and_string_header_keys_as_distinct",
    ),
    Rule(
        "explicit_transfer_encoding_chunked_header_is_not_duplicated",
        r"not erroneously emit multiple ``Transfer-Encoding`` headers",
        "http.headers.transfer-encoding",
        (
            'given server "origin" route "/te" count_header "Transfer-Encoding"',
        ),
        ('when POST "/te" header "Transfer-Encoding" "chunked" body "abc" chunked true',),
        ('then server "origin" header_count "Transfer-Encoding" == 1',),
        "duplicate_transfer_encoding_chunked_header",
    ),
    Rule(
        "chunked_head_response_releases_connection",
        r"chunked HEAD response|chunked HEAD response has no body",
        "http.chunked.connection-lifecycle",
        (
            'given server "origin" route "/head" method "HEAD" header "Transfer-Encoding" "chunked" body ""',
            'given server "origin" route "/next" status 200 body "next"',
        ),
        ('when HEAD "/head"', 'when GET "/next"'),
        ('then response 2 status 200',),
        "leave_chunked_head_connection_checked_out",
    ),
    Rule(
        "chunked_keep_alive_preserves_request_boundaries",
        r"chunked requests losing state across keep-alive connections",
        "http.chunked.keep-alive-framing",
        (
            'given server "origin" route "/upload" echo_body',
            'given server "origin" route "/next" status 200 body "next"',
        ),
        ('when POST "/upload" body "abc" chunked true', 'when GET "/next"'),
        ('then response 1 body "abc"', 'then response 2 status 200'),
        "leak_chunked_request_state_across_keep_alive",
    ),
    Rule(
        "chunked_request_sets_transfer_encoding_header",
        r"Chunked transfer encoding when requesting with ``chunked=True``",
        "http.chunked.request-framing",
        (
            'given server "origin" route "/chunked" echo_header "Transfer-Encoding"',
        ),
        ('when POST "/chunked" body "abc" chunked true',),
        ('then response 1 body "chunked"',),
        "omit_transfer_encoding_for_chunked_request",
    ),
    Rule(
        "chunked_request_body_uses_utf8",
        r"default encoding of chunked request bodies to be UTF-8",
        "http.chunked.request-encoding",
        (
            'given server "origin" route "/echo-bytes" echo_body_hex',
        ),
        ('when POST "/echo-bytes" body "caf\u00e9" chunked true',),
        ('then response 1 body_hex "636166c3a9"',),
        "encode_chunked_body_as_latin1",
    ),
    Rule(
        "chunked_boundaries_are_lowercase",
        r"lowercase chunk boundaries",
        "http.chunked.request-framing",
        (
            'given server "origin" route "/raw" capture_raw_request',
        ),
        ('when POST "/raw" body "abc" chunked true',),
        ('then server "origin" raw_request matches "\\\\r\\\\n[0-9a-f]+\\\\r\\\\n"',),
        "uppercase_chunk_boundaries",
    ),
    Rule(
        "http2_request_does_not_send_transfer_encoding_chunked",
        r"Excluded Transfer-Encoding: chunked from HTTP/2 request body",
        "http2.request-framing",
        (
            'given server "origin" protocol "h2" route "/body" echo_header "transfer-encoding"',
        ),
        ('when HTTP2 POST "/body" body "abc"',),
        ('then server "origin" observed_header "transfer-encoding" absent',),
        "send_transfer_encoding_chunked_over_http2",
    ),
    Rule(
        "response_read_zero_returns_empty_without_error",
        r"HTTPResponse\.read\(0\)",
        "http.response.read-zero",
        (
            'given response body "abc"',
        ),
        ('when response_read amt 0',),
        ('then read_result bytes ""',),
        "read_zero_consumes_or_errors",
    ),
    Rule(
        "response_read_negative_amt_behaves_like_read_all",
        r"Allowed passing negative integers as ``amt``",
        "http.response.read-negative",
        (
            'given response body "abc"',
        ),
        ('when response_read amt -1',),
        ('then read_result bytes "abc"',),
        "reject_negative_read_amt",
    ),
    Rule(
        "response_read1_is_available_and_reads_bytes",
        r"Added support for ``HTTPResponse.read1\(\)`` method",
        "http.response.read1",
        (
            'given response body "abc"',
        ),
        ('when response_read1 amt 1',),
        ('then read_result bytes "a"',),
        "missing_read1_method",
    ),
    Rule(
        "response_shutdown_stops_future_reads",
        r"Added ``HTTPResponse.shutdown\(\)`` to stop any ongoing or future reads",
        "http.response.shutdown",
        (
            'given streaming_response body "abcdef"',
        ),
        ('when response_shutdown', 'when response_read amt null'),
        ('then error 2 kind "response_shutdown"',),
        "allow_read_after_response_shutdown",
    ),
    Rule(
        "response_shutdown_after_pool_release_raises",
        r"Raised exception for ``HTTPResponse.shutdown`` on a connection already released to the pool",
        "http.response.shutdown-lifecycle",
        (
            'given response released_to_pool true',
        ),
        ('when response_shutdown',),
        ('then error 1 kind "response_released"',),
        "silently_shutdown_released_response",
    ),
    Rule(
        "response_stream_continues_with_buffered_decompressed_data",
        r"(stream\(\).*buffered decompressed data|read_chunked\(\).*leftover data|read\(amt=None\).*decompressed data buffered|cache only part of the response after a partial read)",
        "http.response.decompression-buffer",
        (
            'given compressed_response encoding "gzip" body "abcdef"',
        ),
        ('when response_read amt 3 decode true', 'when response_read amt null decode true'),
        ('then combined_read_body "abcdef"',),
        "drop_decompressed_buffer_between_reads",
    ),
    Rule(
        "response_read_respects_buffered_io_semantics",
        r"HTTPResponse\.read`` to respect the semantics of ``io\.BufferedIOBase``",
        "http.response.read-buffered-semantics",
        (
            'given response body "abcdef"',
        ),
        ('when response_read amt 3',),
        ('then read_result bytes "abc"', 'then read_result length <= 3'),
        "return_more_than_requested_from_read",
    ),
    Rule(
        "response_read_decode_mode_cannot_change_after_decoding",
        r"raise an error when calling with ``decode_content=False`` after using ``decode_content=True``",
        "http.response.decode-mode-consistency",
        (
            'given compressed_response encoding "gzip" body "hello"',
        ),
        ('when response_read decode true', 'when response_read decode false'),
        ('then error 2 kind "decode_mode_changed"',),
        "allow_decode_mode_change_after_read",
    ),
    Rule(
        "response_stream_amt_zero_yields_empty_without_consuming",
        r"HTTPResponse\.stream\(\).*HTTPResponse\.read_chunked\(\).*amt=0|stream\(\).*read_chunked\(\).*amt=0",
        "http.response.stream-zero",
        (
            'given response body "abc" transfer_encoding "chunked"',
        ),
        ('when response_stream amt 0', 'when response_read_chunked amt 0'),
        ('then chunks == []', 'then remaining_body "abc"'),
        "amt_zero_consumes_stream_data",
    ),
    Rule(
        "closed_chunked_response_yields_no_chunks",
        r"read_chunked\(\) on a closed response returns no chunks",
        "http.response.closed-chunked-stream",
        (
            'given response closed true transfer_encoding "chunked"',
        ),
        ('when response_read_chunked',),
        ('then chunks == []',),
        "raise_on_closed_read_chunked",
    ),
    Rule(
        "read_chunked_handles_gzip_encoded_chunks",
        r"read_chunked.*gzipped|gzip decoding an empty stream|x-gzip",
        "http.response.content-decoding",
        (
            'given compressed_response encoding "gzip" body "hello"',
        ),
        ('when response_stream decode true',),
        ('then combined_read_body "hello"',),
        "break_gzip_content_decoding",
    ),
    Rule(
        "multiple_content_encodings_are_decoded_in_order",
        r"multiple Content-Encodings",
        "http.response.content-decoding",
        (
            'given compressed_response encoding_chain ["gzip","deflate"] body "hello"',
        ),
        ('when response_read decode true',),
        ('then combined_read_body "hello"',),
        "decode_only_first_content_encoding",
    ),
    Rule(
        "x_gzip_content_encoding_decodes_as_gzip",
        r"x-gzip`` content-encoding",
        "http.response.content-decoding",
        (
            'given compressed_response encoding "x-gzip" body "hello"',
        ),
        ('when response_stream decode true',),
        ('then combined_read_body "hello"',),
        "do_not_decode_x_gzip",
    ),
    Rule(
        "zstd_response_with_multiple_frames_decodes_completely",
        r"Zstandard.*several frames|support for Zstandard",
        "http.response.zstd-decoding",
        (
            'given compressed_response encoding "zstd" frames ["hello","world"]',
        ),
        ('when response_stream decode true',),
        ('then combined_read_body "helloworld"',),
        "decode_only_first_zstd_frame",
    ),
    Rule(
        "content_encoding_chain_is_limited_to_five",
        r"Content-Encoding.*unlimited links|number of allowed chained encodings.*limited to 5",
        "http.response.content-encoding-limit",
        (
            'given response header "Content-Encoding" "gzip,gzip,gzip,gzip,gzip,gzip" body "..."',
        ),
        ('when response_read decode true',),
        ('then error 1 kind "content_encoding_chain_too_long"',),
        "allow_unbounded_content_encoding_chain",
    ),
    Rule(
        "body_is_not_written_after_server_closes_socket",
        r"Suppress ``BrokenPipeError`` when writing request body after the server has closed the socket",
        "http.request.broken-pipe",
        (
            'given server "origin" route "/close" close_before_request_body true',
        ),
        ('when POST "/close" body "large-body"',),
        ('then error 1 kind != "broken_pipe"',),
        "surface_broken_pipe_error",
    ),
    Rule(
        "proxy_errors_wrap_connection_failures",
        r"ProxyError`` to wrap any connection error \(timeout, TLS, DNS\)",
        "http.proxy.error-taxonomy",
        (
            'given proxy "origin" fails_with "dns_error"',
        ),
        ('when GET "https://example.test/" via_proxy "$ORIGIN"',),
        ('then error 1 kind "proxy_error"', 'then error 1 reason kind "name_resolution_error"'),
        "surface_proxy_connection_failure_directly",
    ),
    Rule(
        "dns_failure_raises_name_resolution_error",
        r"NameResolutionError`` exception when a DNS error occurs",
        "http.error.name-resolution",
        (
            'given dns host "does-not-resolve.test" fails true',
        ),
        ('when GET "http://does-not-resolve.test/"',),
        ('then error 1 kind "name_resolution_error"',),
        "raise_generic_connection_error_on_dns_failure",
    ),
    Rule(
        "socket_ssl_error_is_wrapped_as_ssl_error",
        r"Wrap ``ssl\.SSLError`` that can be raised from reading a socket",
        "tls.error-taxonomy",
        (
            'given tls_server "origin" corrupts_record_after_headers true',
        ),
        ('when HTTPS_GET "/"',),
        ('then error 1 kind "ssl_error"',),
        "surface_raw_socket_ssl_error",
    ),
    Rule(
        "pyopenssl_syscall_error_preserves_errno",
        r"socket\.error\.errno`` when raised from pyOpenSSL",
        "tls.error-taxonomy",
        (
            'given tls_backend "pyopenssl" syscall_error errno 104',
        ),
        ('when HTTPS_GET "/"',),
        ('then error 1 errno == 104',),
        "drop_errno_from_pyopenssl_syscall_error",
    ),
    Rule(
        "streaming_decompression_bomb_guard_limits_output",
        r"decompression-bomb safeguards|highly compressed HTTP content",
        "http.response.decompression-bomb-guard",
        (
            'given compressed_response encoding "gzip" expansion_ratio "large"',
        ),
        ('when response_stream amt 1 decode true',),
        ('then error 1 kind "decompression_limit_exceeded"',),
        "disable_streaming_decompression_guard",
    ),
    Rule(
        "incomplete_response_body_raises_when_content_length_enforced",
        r"enforce_content_length|incomplete data chunks",
        "http.response.content-length",
        (
            'given server "origin" route "/short" header "Content-Length" "10" body "abc" close_after_body true',
        ),
        ('when GET "/short" preload_content true enforce_content_length true',),
        ('then error 1 kind "incomplete_read"',),
        "silently_accept_truncated_body",
    ),
    Rule(
        "incomplete_response_read_is_wrapped_as_protocol_error",
        r"(IncompleteRead`` not getting converted|Errors during response read.*IncompleteRead)",
        "http.response.incomplete-read-error",
        (
            'given server "origin" route "/short" header "Content-Length" "10" body "abc" close_after_body true',
        ),
        ('when GET "/short" preload_content false then response_stream',),
        ('then error 1 kind "protocol_error"',),
        "surface_raw_incomplete_read",
    ),
    Rule(
        "multiple_set_cookie_headers_are_preserved",
        r"multiple Set-Cookie headers.*not getting merged|duplicate header keys",
        "http.headers.multi-value",
        (
            'given server "origin" route "/cookies" header "Set-Cookie" "a=1" header "Set-Cookie" "b=2" body ""',
        ),
        ('when GET "/cookies"',),
        ('then response 1 header_values "Set-Cookie" == ["a=1","b=2"]',),
        "merge_duplicate_set_cookie_headers",
    ),
    Rule(
        "http_header_dict_can_repeat_or_combine_values",
        r"configuring header merging behavior with HTTPHeaderDict",
        "http.headers.merge-policy",
        (
            'given headers empty',
        ),
        ('when add_header "X-My-Header" "foo"', 'when add_header "X-My-Header" "bar" combine true'),
        ('then header "X-My-Header" == "foo, bar"',),
        "ignore_header_combine_policy",
    ),
    Rule(
        "non_proxy_headers_are_not_cast_to_headerdict",
        r"stop automatically casting non-proxy headers to ``HTTPHeaderDict``",
        "http.headers.input-preservation",
        (
            'given request_headers raw {"X-Binary": bytes "ff"}',
        ),
        ('when GET "/headers" headers_ref "$request_headers"',),
        ('then sent_header "X-Binary" bytes "ff"',),
        "cast_non_proxy_headers_to_headerdict",
    ),
    Rule(
        "request_response_header_order_is_preserved",
        r"Preserve order of request/response headers",
        "http.headers.order",
        (
            'given server "origin" route "/ordered" headers [("X-First","1"),("X-Second","2")] body ""',
        ),
        ('when GET "/ordered" headers [("A","1"),("B","2")]',),
        ('then server "origin" request_header_order contains ["A","B"]', 'then response 1 header_order contains ["X-First","X-Second"]'),
        "sort_or_reorder_headers",
    ),
    Rule(
        "header_values_with_commas_are_preserved",
        r"header values containing commas",
        "http.headers.comma-values",
        (
            'given server "origin" route "/header" header "X-List" "a, b" body ""',
        ),
        ('when GET "/header"',),
        ('then response 1 header "X-List" == "a, b"',),
        "split_comma_header_value",
    ),
    Rule(
        "message_content_type_header_is_accepted",
        r"Content-Type: message/\\*.*HeaderParsingError",
        "http.headers.message-content-type",
        (
            'given server "origin" route "/message" header "Content-Type" "message/http" body "payload"',
        ),
        ('when GET "/message"',),
        ('then response 1 status 200', 'then no_warning kind "HeaderParsingError"'),
        "warn_on_message_content_type",
    ),
    Rule(
        "invalid_chunk_length_raises_protocol_error",
        r"InvalidChunkLength`` to ``ProtocolError``",
        "http.response.chunked-error",
        (
            'given server "origin" route "/bad-chunk" raw_response "HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\nZZ\\r\\n"',
        ),
        ('when GET "/bad-chunk"',),
        ('then error 1 kind "protocol_error"',),
        "raise_invalid_chunk_length_directly",
    ),
    Rule(
        "incomplete_read_error_reports_excess_content",
        r"ProtocolError`` to be more verbose on incomplete reads with excess content",
        "http.response.incomplete-read-error",
        (
            'given server "origin" route "/excess" header "Content-Length" "3" body "abcdef" close_after_body true',
        ),
        ('when GET "/excess"',),
        ('then error 1 kind "protocol_error"', 'then error 1 message contains "excess"'),
        "omit_excess_content_from_incomplete_read_error",
    ),
    Rule(
        "user_supplied_host_header_is_preserved_for_chunked_upload",
        r"user-supplied Host headers on chunked uploads",
        "http.headers.host",
        (
            'given server "origin" route "/host" echo_header "Host"',
        ),
        ('when POST "/host" header "Host" "example.test" body "abc" chunked true',),
        ('then response 1 body "example.test"',),
        "overwrite_host_header_on_chunked_upload",
    ),
    Rule(
        "pool_default_headers_apply_to_get_query_requests",
        r"pool-default headers not applying.*GET",
        "http.headers.default-headers",
        (
            'given server "origin" route "/headers" echo_header "X-Default"',
            'given client default_header "X-Default" "present"',
        ),
        ('when GET "/headers" query {"q":"1"}',),
        ('then response 1 body "present"',),
        "drop_default_headers_for_get_fields",
    ),
    Rule(
        "multipart_file_empty_filename_is_emitted",
        r"Empty filenames in multipart headers",
        "http.multipart.filename",
        (
            'given server "origin" route "/upload" require_upload_filename ""',
        ),
        ('when POST_MULTIPART "/upload" file "file" filename "" body "abc"',),
        ('then response 1 status 200',),
        "suppress_empty_multipart_filename",
    ),
    Rule(
        "multipart_list_of_tuples_preserves_duplicate_field_names",
        r"multipart encoding.*list-of-tuples",
        "http.multipart.duplicate-fields",
        (
            'given server "origin" route "/form" require_field_values "x" ["1","2"]',
        ),
        ('when POST_MULTIPART "/form" fields [["x","1"],["x","2"]]',),
        ('then response 1 status 200',),
        "collapse_duplicate_multipart_field_names",
    ),
    Rule(
        "multipart_file_explicit_content_type_is_sent",
        r"explicit content type.*encoding file fields",
        "http.multipart.content-type",
        (
            'given server "origin" route "/upload" require_part_header "file" "Content-Type" "text/plain"',
        ),
        ('when POST_MULTIPART "/upload" file "file" filename "a.txt" content_type "text/plain" body "abc"',),
        ('then response 1 status 200',),
        "ignore_explicit_multipart_content_type",
    ),
    Rule(
        "multipart_header_control_characters_are_not_percent_encoded",
        r"multipart/form-data`` header parameter formatting matches the WHATWG HTML Standard.*Control characters in filenames are no longer percent encoded",
        "http.multipart.header-formatting",
        (
            'given multipart_encoder',
        ),
        ('when encode_multipart file "file" filename "line\\nfeed.txt" body "abc"',),
        ('then body not_contains "%0A"',),
        "percent_encode_control_characters_in_multipart_filename",
    ),
    Rule(
        "multipart_html5_header_encoder_is_default",
        r"Switched the default multipart header encoder from RFC 2231 to HTML 5",
        "http.multipart.header-formatting",
        (
            'given multipart_encoder',
        ),
        ('when encode_multipart file "file" filename "é.txt" body "abc"',),
        ('then body contains "filename"', 'then body not_contains "filename*"'),
        "use_rfc2231_multipart_filename_by_default",
    ),
    Rule(
        "url_parser_is_rfc3986_compliant",
        r"parse_url\(\).*RFC 3986 compliant",
        "http.url.rfc3986",
        (
            'given url "http://user:pass@example.test:80/path?x=1#frag"',
        ),
        ('when parse_url',),
        ('then parsed_scheme == "http"', 'then parsed_auth == "user:pass"', 'then parsed_host == "example.test"', 'then parsed_port == 80', 'then parsed_path == "/path"', 'then parsed_query == "x=1"', 'then parsed_fragment == "frag"'),
        "parse_url_not_rfc3986_compliant",
    ),
    Rule(
        "url_authority_includes_userinfo_and_host",
        r"authority`` property to the Url class",
        "http.url.authority",
        (
            'given url "http://user:pass@example.test:8080/path"',
        ),
        ('when parse_url',),
        ('then parsed_authority == "user:pass@example.test:8080"',),
        "omit_userinfo_from_url_authority",
    ),
    Rule(
        "explicit_multipart_boundary_is_used",
        r"explicit boundary string",
        "http.multipart.boundary",
        (
            'given multipart_encoder boundary "fixed-boundary"',
        ),
        ('when encode_multipart fields {"a":"b"}',),
        ('then content_type contains "boundary=fixed-boundary"', 'then body contains "--fixed-boundary"'),
        "ignore_explicit_multipart_boundary",
    ),
    Rule(
        "url_port_zero_is_preserved",
        r"port 0 \\(zero\\).*instead of 0|port 0",
        "http.url.port",
        (
            'given url "http://example.test:0/path"',
        ),
        ('when parse_url',),
        ('then parsed_port == 0',),
        "treat_port_zero_as_absent",
    ),
    Rule(
        "url_port_with_leading_zeroes_is_accepted",
        r"leading zeroes in the port.*valid",
        "http.url.port",
        (
            'given url "http://example.test:080/path"',
        ),
        ('when parse_url',),
        ('then parsed_port == 80',),
        "reject_leading_zero_port",
    ),
    Rule(
        "url_port_rejects_integerish_unicode",
        r"superscripts and other integerish things in URL ports",
        "http.url.port",
        (
            'given url "http://example.test:\u00b9/path"',
        ),
        ('when parse_url',),
        ('then error 1 kind "invalid_port"',),
        "accept_unicode_integerish_port",
    ),
    Rule(
        "url_path_query_fragment_invalid_chars_are_percent_encoded",
        r"parse_url`` to percent-encode invalid characters within the path, query, and target components|Percent-encode invalid characters in URL",
        "http.url.percent-encoding",
        (
            'given url "http://example.test/a b?x=<y>"',
        ),
        ('when parse_url',),
        ('then parsed_url contains "/a%20b"', 'then parsed_url contains "x=%3Cy%3E"'),
        "leave_invalid_url_characters_unencoded",
    ),
    Rule(
        "url_auth_invalid_chars_are_percent_encoded",
        r"URLs containing invalid characters within ``Url.auth``.*percent-encoding",
        "http.url.percent-encoding",
        (
            'given url "http://user name:pass word@example.test/"',
        ),
        ('when parse_url',),
        ('then parsed_auth == "user%20name:pass%20word"',),
        "leave_invalid_auth_characters_unencoded",
    ),
    Rule(
        "url_fragment_is_not_sent_in_request_target",
        r"URL fragment was sent within the request target",
        "http.url.request-target",
        (
            'given server "origin" route "/path?x=1" capture_request_target',
        ),
        ('when GET "/path?x=1#fragment"',),
        ('then server "origin" request_target == "/path?x=1"',),
        "send_fragment_in_request_target",
    ),
    Rule(
        "empty_query_section_is_preserved",
        r"empty query section in a URL would fail to parse",
        "http.url.query",
        (
            'given url "http://example.test/path?"',
        ),
        ('when parse_url',),
        ('then parsed_query == ""',),
        "reject_empty_query_section",
    ),
    Rule(
        "url_ipv6_zone_identifier_is_accepted",
        r"IPv6 literals with zone identifiers|IPv6 Zone ID",
        "http.url.ipv6-zone",
        (
            'given url "http://[fe80::1%25eth0]/path"',
        ),
        ('when parse_url',),
        ('then parsed_host == "fe80::1%eth0"',),
        "reject_ipv6_zone_identifier",
    ),
    Rule(
        "url_ipv6_requires_brackets",
        r"IPv6 url parsing enforces brackets",
        "http.url.ipv6",
        (
            'given url "http://fe80::1/path"',
        ),
        ('when parse_url',),
        ('then error 1 kind "invalid_url"',),
        "accept_unbracketed_ipv6_literal",
    ),
    Rule(
        "url_empty_host_is_rejected",
        r"empty host.*raise",
        "http.url.host",
        (
            'given url "http:///path"',
        ),
        ('when connection_from_url',),
        ('then error 1 kind "empty_host"',),
        "allow_empty_host",
    ),
    Rule(
        "method_rejects_control_characters",
        r"Raise ``ValueError`` if method contains control characters",
        "http.request.method-validation",
        (
            'given server "origin" route "/" status 200 body ""',
        ),
        ('when METHOD "GET\\r\\nX: y" "/"',),
        ('then error 1 kind "invalid_method"',),
        "allow_control_characters_in_method",
    ),
    Rule(
        "proxy_url_without_scheme_raises_actionable_error",
        r"ProxySchemeUnknown`` error message.*proxy URL without a scheme",
        "http.proxy.url-validation",
        (
            'given proxy_url "proxy.example.test:8080"',
        ),
        ('when create_proxy_manager',),
        ('then error 1 kind "proxy_scheme_unknown"', 'then error 1 message contains "scheme"'),
        "accept_or_emit_opaque_error_for_proxy_without_scheme",
    ),
    Rule(
        "relative_path_resembling_schemeless_uri_is_accepted",
        r"paths resembling schemeless URIs.*HTTPConnectionPool\.urlopen",
        "http.url.request-target",
        (
            'given server "origin" route "/example.test/path" status 200 body "ok"',
        ),
        ('when GET "//example.test/path" as_origin_form true',),
        ('then response 1 status 200',),
        "parse_origin_form_path_as_schemeless_absolute_uri",
    ),
    Rule(
        "proxy_connect_ipv6_target_uses_brackets",
        r"incorrect `CONNECT` statement when using an IPv6 proxy|missing brackets in ``HTTP CONNECT`` when connecting to IPv6",
        "http.proxy.connect-target",
        (
            'given proxy "origin" capture_connect_target',
        ),
        ('when CONNECT target "[::1]:443" via_proxy "$ORIGIN"',),
        ('then proxy connect_target == "[::1]:443"',),
        "omit_brackets_in_ipv6_connect_target",
    ),
    Rule(
        "http_url_does_not_forward_server_hostname_to_pool",
        r"server_hostname`` being forwarded from ``PoolManager`` to ``HTTPConnectionPool`` when requesting an HTTP URL",
        "http.pool.request-context",
        (
            'given poolmanager server_hostname "example.test"',
        ),
        ('when GET "http://example.test/"',),
        ('then connection_pool has_no_kwarg "server_hostname"',),
        "forward_server_hostname_to_http_pool",
    ),
    Rule(
        "http2_major_version_four_is_required",
        r"only accepting supported h2 major version 4",
        "http2.dependency-contract",
        (
            'given h2_version "3.2.0"',
        ),
        ('when enable_http2',),
        ('then error 1 kind "unsupported_http2_dependency"',),
        "accept_unsupported_h2_major_version",
    ),
    Rule(
        "http2_origin_support_is_probed_with_alpn",
        r"probing mechanism.*supports HTTP/2 via ALPN",
        "http2.alpn-probing",
        (
            'given tls_server "origin" alpn ["h2","http/1.1"] route "/" status 200 body "ok"',
        ),
        ('when GET "/" http_versions ["h2","http/1.1"]',),
        ('then selected_http_version == "h2"',),
        "skip_http2_alpn_probe",
    ),
    Rule(
        "http2_request_body_is_sent",
        r"support for sending a request body with HTTP/2",
        "http2.request-body",
        (
            'given server "origin" protocol "h2" route "/echo" echo_body',
        ),
        ('when HTTP2 POST "/echo" body "abc"',),
        ('then response 1 body "abc"',),
        "drop_http2_request_body",
    ),
    Rule(
        "http2_basic_request_succeeds",
        r"rudimentary support for HTTP/2",
        "http2.basic-request",
        (
            'given server "origin" protocol "h2" route "/" status 200 body "ok"',
        ),
        ('when HTTP2 GET "/"',),
        ('then response 1 status 200', 'then response 1 body "ok"'),
        "disable_http2_request_path",
    ),
    Rule(
        "trailing_dot_hostname_through_proxy_connects",
        r"requests against urls with trailing dots were failing due to SSL errors when using proxy",
        "http.proxy.hostname",
        (
            'given proxy "origin" tunneling true',
            'given tls_server "target" hostname "example.test." route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://example.test./" via_proxy "$ORIGIN"',),
        ('then response 1 status 200',),
        "reject_trailing_dot_hostname_via_proxy",
    ),
    Rule(
        "url_scheme_and_host_are_normalized_lowercase",
        r"Normalize the scheme and host|scheme and host to lowercase|hostnames to be case-insensitive",
        "http.url.normalization",
        (
            'given url "HTTP://EXAMPLE.TEST/path"',
        ),
        ('when parse_url',),
        ('then parsed_scheme == "http"', 'then parsed_host == "example.test"'),
        "preserve_uppercase_scheme_or_host",
    ),
    Rule(
        "same_host_accepts_default_port_equivalence",
        r"default-port comparison.*is_same_host|port 80/443 explicitly",
        "http.url.origin-equivalence",
        (
            'given pool origin "http://example.test"',
        ),
        ('when check_same_host "http://example.test:80/path"',),
        ('then same_host == true',),
        "treat_default_port_as_different_origin",
    ),
    Rule(
        "relative_redirect_location_is_followed",
        r"relative URLs in Location|relative urls in ``Location",
        "http.redirect.relative-location",
        (
            'given server "origin" route "/redirect" header "Location" "/target" status 302 body ""',
            'given server "origin" route "/target" status 200 body "ok"',
        ),
        ('when GET "/redirect" redirect true',),
        ('then response 1 status 200', 'then response 1 body "ok"'),
        "reject_relative_redirect_location",
    ),
    Rule(
        "decode_content_option_controls_response_decoding",
        r"decode_content`` being ignored",
        "http.response.decode-content-option",
        (
            'given compressed_response encoding "gzip" body "hello"',
        ),
        ('when GET "/gzip" decode_content false',),
        ('then response 1 body_is_compressed true',),
        "ignore_decode_content_false",
    ),
    Rule(
        "json_request_sets_content_type_when_missing",
        r"json`` parameter.*Content-Type: application/json",
        "http.request.json",
        (
            'given server "origin" route "/json" echo_header "Content-Type"',
        ),
        ('when REQUEST_JSON "/json" json {"a":1}',),
        ('then response 1 body "application/json"',),
        "omit_json_content_type",
    ),
    Rule(
        "headers_input_is_not_mutated_by_json_request",
        r"headers`` passed in a request with ``json=`` would be mutated",
        "http.request.header-mutation",
        (
            'given headers {"X-Test":"1"}',
        ),
        ('when REQUEST_JSON "/json" json {"a":1} headers_ref "$headers"',),
        ('then headers == {"X-Test":"1"}',),
        "mutate_input_headers_for_json_request",
    ),
    Rule(
        "proxy_request_uri_strips_scheme_and_host",
        r"PoolManager`` strips the scheme and host before sending the request uri",
        "http.proxy.request-target",
        (
            'given server "origin" route "/path" capture_request_target',
        ),
        ('when proxy GET "http://example.test/path?x=1"',),
        ('then server "origin" request_target == "/path?x=1"',),
        "send_absolute_uri_to_origin_server",
    ),
)


MAXIMAL_EXTRA_RULES: tuple[Rule, ...] = (
    Rule(
        "assert_hostname_false_skips_hostname_verification",
        r"assert_hostname=False.*skip hostname|assert_hostname`` set to ``False``.*avoid the ``SubjectAltNameWarning``|``assert_hostname=False``.*skip hostname",
        "tls.hostname-verification",
        (
            'given tls_server "origin" certificate hostname "mismatch.test" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_hostname false',),
        ('then response 1 status 200', 'then no_warning kind "SubjectAltNameWarning"'),
        "ignore_assert_hostname_false",
    ),
    Rule(
        "tls_minimum_and_maximum_versions_configure_context",
        r"``ssl_minimum_version``.*``ssl_maximum_version`` options|``ssl_version``.*minimum_version.*maximum_version",
        "tls.version-bounds",
        (
            'given tls_server "origin" supports_tls_versions ["1.2"] route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" tls_min_version "1.2" tls_max_version "1.2"',),
        ('then negotiated_tls_version == "1.2"',),
        "ignore_tls_version_bounds",
    ),
    Rule(
        "tls_handshake_uses_context_hostname_checking",
        r"Use ``ssl.SSLContext``.*check_hostname.*when possible",
        "tls.hostname-verification",
        (
            'given tls_server "origin" certificate hostname "mismatch.test" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_hostname "example.test"',),
        ('then error 1 kind "certificate_hostname_mismatch"',),
        "disable_context_hostname_checking",
    ),
    Rule(
        "https_validates_certificates_by_default",
        r"HTTPSConnectionPool`.*default certificate verification|cert_reqs = 'CERT_REQUIRED'|validate certificates by default when using HTTPS",
        "tls.default-verification",
        (
            'given tls_server "origin" certificate trusted false route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/"',),
        ('then error 1 kind "certificate_verify_failed"',),
        "disable_default_certificate_verification",
    ),
    Rule(
        "https_loads_system_certs_when_no_ca_options_are_set",
        r"load system CA certificates by default.*unless.*ca_certs.*ca_cert_dir|load system CA certificates when ``ca_certs``.*unspecified",
        "tls.ca-loading",
        (
            'given tls_server "origin" certificate trusted_by_system true route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" ca_options absent',),
        ('then response 1 status 200',),
        "do_not_load_system_ca_certs_by_default",
    ),
    Rule(
        "explicit_ca_options_disable_default_system_cert_loading",
        r"unless any other.*ca_certs.*ca_cert_dir.*ssl_context.*specified|Don't load system certificates by default when any other ``ca_certs``.*specified",
        "tls.ca-loading",
        (
            'given tls_server "origin" certificate trusted_by_system true route "/" status 200 body "ok"',
            'given ca_bundle "custom" trusts []',
        ),
        ('when HTTPS_GET "/" ca_certs "$custom"',),
        ('then error 1 kind "certificate_verify_failed"',),
        "load_system_ca_certs_even_with_explicit_ca_options",
    ),
    Rule(
        "ca_certificate_data_string_is_accepted",
        r"ca_cert_data.*specified as a string",
        "tls.ca-data",
        (
            'given tls_server "origin" certificate trusted_by_ca_data "PEM" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" ca_cert_data "PEM"',),
        ('then response 1 status 200',),
        "reject_string_ca_cert_data",
    ),
    Rule(
        "ca_certificate_directory_is_accepted",
        r"``ca_cert_dir`` for SSL-related PoolManager configuration",
        "tls.ca-directory",
        (
            'given tls_server "origin" certificate trusted_by_ca_dir "/tmp/cadir" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" ca_cert_dir "/tmp/cadir"',),
        ('then response 1 status 200',),
        "ignore_ca_cert_dir",
    ),
    Rule(
        "encrypted_client_key_without_password_raises_ssl_error",
        r"encrypted ``key_file`` without creating a password|encrypted client private key.*no password.*``SSLError``",
        "tls.client-certificate",
        (
            'given tls_server "origin" requires_client_cert true',
            'given client_cert key encrypted true password "secret"',
        ),
        ('when HTTPS_GET "/" client_cert "$client_cert" key_password absent',),
        ('then error 1 kind "ssl_error"',),
        "silently_use_encrypted_key_without_password",
    ),
    Rule(
        "encrypted_client_key_password_is_accepted",
        r"``key_password``.*encrypted ``key_file``|encrypted client private key.*password",
        "tls.client-certificate",
        (
            'given tls_server "origin" requires_client_cert true route "/" status 200 body "ok"',
            'given client_cert key encrypted true password "secret"',
        ),
        ('when HTTPS_GET "/" client_cert "$client_cert" key_password "secret"',),
        ('then response 1 status 200',),
        "ignore_client_key_password",
    ),
    Rule(
        "tls_sni_hostname_can_be_overridden",
        r"override the server hostname used for SNI|overriding the SNI hostname|server_hostname.*overriding the SNI",
        "tls.sni",
        (
            'given tls_server "origin" requires_sni "service.test" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://127.0.0.1/" server_hostname "service.test"',),
        ('then response 1 status 200',),
        "ignore_overridden_sni_hostname",
    ),
    Rule(
        "tls_alpn_http11_identifier_is_sent",
        r"send ``http/1.1`` ALPN identifier|ALPN identifier",
        "tls.alpn",
        (
            'given tls_server "origin" requires_alpn "http/1.1" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/"',),
        ('then negotiated_alpn == "http/1.1"',),
        "omit_http11_alpn_identifier",
    ),
    Rule(
        "tlsv12_session_tickets_are_not_requested",
        r"Do not request TLSv1\.2 session tickets",
        "tls.session-ticket",
        (
            'given tls_server "origin" tls_version "1.2" observes_session_ticket true route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/"',),
        ('then server "origin" observed_session_ticket == false',),
        "request_tls12_session_ticket",
    ),
    Rule(
        "https_proxy_to_https_target_is_supported",
        r"support for HTTPS proxies contacting HTTPS servers|Added HTTPS proxy support|HTTPS proxy support",
        "http.proxy.https-to-https",
        (
            'given proxy "origin" scheme "https" tunneling true',
            'given tls_server "target" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://target/" via_proxy "$ORIGIN"',),
        ('then response 1 status 200',),
        "fail_https_proxy_to_https_target",
    ),
    Rule(
        "https_proxy_misconfiguration_reports_http_proxy_hint",
        r"Detect failed ``HTTPSConnection``.*wrongly-configured proxy|HTTP proxy as HTTPS|proxy as HTTP instead of HTTPS",
        "http.proxy.misconfiguration",
        (
            'given proxy "origin" scheme "http"',
        ),
        ('when HTTPS_GET "https://example.test/" proxy_scheme "https" via_proxy "$ORIGIN"',),
        ('then error 1 message contains "HTTP proxy"',),
        "emit_opaque_proxy_tls_failure",
    ),
    Rule(
        "socks_remote_dns_schemes_are_supported",
        r"SOCKS support.*SOCKS4A.*SOCKS5H|SOCKS4A.*SOCKS5H|socks5h:// and socks4a://.*remote DNS",
        "http.proxy.socks-remote-dns",
        (
            'given socks_proxy "origin" scheme "socks5h" resolves_remote true',
            'given server "target" host "private.test" route "/" status 200 body "ok"',
        ),
        ('when GET "http://private.test/" via_proxy "$ORIGIN"',),
        ('then proxy "origin" performed_dns_lookup_for "private.test"',),
        "resolve_socks5h_locally",
    ),
    Rule(
        "socks_proxy_auth_info_in_url_is_supported",
        r"authentication parameters for SOCKS proxies|auth info in url for SOCKS proxy",
        "http.proxy.socks-auth",
        (
            'given socks_proxy "origin" requires_auth ["user","pass"]',
            'given server "target" route "/" status 200 body "ok"',
        ),
        ('when GET "http://target/" via_proxy "socks5://user:pass@origin"',),
        ('then response 1 status 200',),
        "drop_socks_proxy_credentials",
    ),
    Rule(
        "new_connection_failure_raises_new_connection_error",
        r"``NewConnectionError``.*connection attempts fail|``NewConnectionError``.*fail to establish a new connection",
        "http.error.new-connection",
        (
            'given server "origin" refuses_connections true',
        ),
        ('when GET "/"',),
        ('then error 1 kind "new_connection_error"',),
        "raise_generic_connection_error_on_connect_failure",
    ),
    Rule(
        "all_retry_enabled_errors_are_wrapped_in_max_retry_error",
        r"All raised exceptions should now wrapped in a ``MaxRetryError``",
        "http.retry.error-wrapping",
        (
            'given server "origin" refuses_connections true',
        ),
        ('when GET "/" retries 1',),
        ('then error 1 kind "max_retry_error"', 'then error 1 reason kind "new_connection_error"'),
        "surface_retry_reason_without_max_retry_error",
    ),
    Rule(
        "max_retry_error_reason_is_exception",
        r"MaxRetryError\.reason`` will always be an exception|``MaxRetryError.reason`` will always be an exception",
        "http.retry.error-shape",
        (
            'given server "origin" refuses_connections true',
        ),
        ('when GET "/" retries 1',),
        ('then error 1 kind "max_retry_error"', 'then error 1 reason type "exception"'),
        "store_non_exception_max_retry_reason",
    ),
    Rule(
        "generic_raised_errors_extend_http_exception",
        r"All exceptions .* inherit from HTTPException|All raised exceptions should now wrapped in a ``urllib3.exceptions.HTTPException``",
        "http.error.taxonomy",
        (
            'given server "origin" returns_malformed_response true',
        ),
        ('when GET "/"',),
        ('then error 1 is_http_exception true',),
        "raise_non_http_exception_subclass",
    ),
    Rule(
        "only_fingerprint_verification_is_supported",
        r"assert_fingerprint.*without requiring a CA certificate|\*only\* fingerprint verification",
        "tls.fingerprint-verification",
        (
            'given tls_server "origin" certificate fingerprint "sha256:abc" trusted false route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_fingerprint "sha256:abc" ca_certs absent',),
        ('then response 1 status 200',),
        "require_ca_certificate_even_with_matching_fingerprint",
    ),
    Rule(
        "sha256_fingerprint_verification_is_supported",
        r"SHA-256 support for fingerprint verification",
        "tls.fingerprint-verification",
        (
            'given tls_server "origin" certificate fingerprint "sha256:abc" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_fingerprint "sha256:abc"',),
        ('then response 1 status 200',),
        "reject_sha256_fingerprint",
    ),
    Rule(
        "failed_connect_does_not_leak_socket",
        r"Don.t leak sockets after waiting for 100-continue|Close connections more defensively on exception|socket leak if ``HTTPConnection.connect\(\)`` fails|file descriptor leakage on retries|socket leaking when ``HTTPSConnection.connect\(\)`` raises",
        "http.connection.resource-lifecycle",
        (
            'given server "origin" route "/expect" close_before_continue true',
        ),
        ('when POST "/expect" header "Expect" "100-continue" body "abc"',),
        ('then open_socket_count returns_to_baseline true',),
        "leak_socket_on_failed_expect_continue",
    ),
    Rule(
        "fingerprint_or_hostname_failure_does_not_leak_socket",
        r"Connection\.close\(\) more defensively.*certificate matching|socket leak when fingerprint or hostname verifications fail|open socket leak with SSL-related failures|Close and discard sockets which experienced SSL-related errors",
        "http.connection.resource-lifecycle",
        (
            'given tls_server "origin" certificate hostname "mismatch.test" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_hostname "example.test"',),
        ('then open_socket_count returns_to_baseline true',),
        "leak_socket_on_certificate_failure",
    ),
    Rule(
        "pool_does_not_insert_none_when_empty",
        r"Don't insert ``None`` into ConnectionPool if the pool was empty",
        "http.connection.pool-state",
        (
            'given connection_pool maxsize 1 block false empty true',
        ),
        ('when release_connection null',),
        ('then pool entries not_contains null',),
        "insert_null_connection_into_empty_pool",
    ),
    Rule(
        "pool_full_warning_mentions_pool_size",
        r"Connection pool is full.*not mention the pool size",
        "http.connection.pool-observability",
        (
            'given connection_pool maxsize 1 block false full true',
        ),
        ('when release_connection extra_connection',),
        ('then warning 1 message contains "pool size"',),
        "omit_pool_size_from_full_pool_warning",
    ),
    Rule(
        "poolmanager_many_origins_does_not_close_in_use_pools",
        r"PoolManager.*many distinct origins.*closed before requests are done|PoolManager.*many distinct origins.*closed while requests are in progress",
        "http.connection.poolmanager-lifecycle",
        (
            'given pool_manager max_pools 1',
            'given server "one" route "/slow" hold_response true',
            'given server "two" route "/" status 200 body "ok"',
        ),
        ('when GET "http://one/slow" preload_content false', 'when GET "http://two/"'),
        ('then response 1 stream_open == true',),
        "close_in_use_pool_when_evicted",
    ),
    Rule(
        "chunked_body_and_frame_can_be_sent_together",
        r"Sending a request body when chunked=True.*body wrapped in a frame",
        "http.request.chunked",
        (
            'given server "origin" route "/echo" echo_body',
        ),
        ('when POST "/echo" body "abc" chunked true',),
        ('then response 1 body "abc"',),
        "drop_chunked_body_when_body_is_framed",
    ),
    Rule(
        "response_auto_close_false_keeps_underlying_stream_open",
        r"auto_close.*False.*HTTPResponse|HTTPResponse.auto_close = False",
        "http.response.close-policy",
        (
            'given response body "abc" auto_close false',
        ),
        ('when response_read all',),
        ('then underlying_stream_closed == false',),
        "close_underlying_stream_despite_auto_close_false",
    ),
    Rule(
        "response_iter_yields_body_lines_efficiently",
        r"Response.stream\(\) returns a generator|HTTPResponse.stream.*generator|more efficient ``HTTPResponse.__iter__\(\)``",
        "http.response.streaming",
        (
            'given response body "a\\nb\\n"',
        ),
        ('when response_stream lines true',),
        ('then chunks == ["a\\n","b\\n"]',),
        "buffer_entire_response_before_streaming",
    ),
    Rule(
        "streaming_decoder_regression_is_fixed",
        r"Fixed streaming decoder regression",
        "http.response.content-decoding",
        (
            'given compressed_response encoding "gzip" body "hello"',
        ),
        ('when response_stream amt 1 decode true',),
        ('then combined_read_body "hello"',),
        "break_incremental_content_decoder",
    ),
    Rule(
        "brotli_decoder_handles_objects_without_decompress_attr",
        r"BrotliDecoderDecompressStream.*object.*without a ``decompress`` attribute|Avoid ``hasattr`` call in ``BrotliDecoder.decompress\(\)``",
        "http.response.brotli-decoding",
        (
            'given compressed_response encoding "br" body "hello" decoder_object_without_decompress_attr true',
        ),
        ('when response_stream decode true',),
        ('then combined_read_body "hello"',),
        "require_brotli_decompress_attribute",
    ),
    Rule(
        "gzip_decoder_handles_empty_stream",
        r"gzip decoding an empty stream",
        "http.response.gzip-decoding",
        (
            'given compressed_response encoding "gzip" body ""',
        ),
        ('when response_read decode true',),
        ('then combined_read_body ""',),
        "error_on_empty_gzip_stream",
    ),
    Rule(
        "timeout_value_must_be_positive_and_not_boolean",
        r"Validate that ``timeout`` values are not booleans|timeout.*not booleans|Timeout value.*positive",
        "http.timeout.validation",
        (
            'given timeout value true',
        ),
        ('when configure_timeout "$timeout"',),
        ('then error 1 kind "invalid_timeout"',),
        "accept_boolean_or_nonpositive_timeout",
    ),
    Rule(
        "request_body_file_like_is_rewound_on_retry_or_redirect",
        r"Rewind body position.*redirect|rewind.*body.*retry|request body.*rewound|rewind a file-like body object when a request is retried or redirected",
        "http.request.body-rewind",
        (
            'given body_stream content "abc" position 0',
            'given server "origin" route "/retry" status_sequence [503,200] echo_body true',
        ),
        ('when POST "/retry" body_stream "$body_stream" retries 1',),
        ('then response 2 body "abc"',),
        "do_not_rewind_body_before_retry",
    ),
    Rule(
        "url_composed_property_round_trips_components",
        r"Added ``?Url.url`` property.*composed url string|Added Url.url property.*composed version",
        "http.url.roundtrip",
        (
            'given url_components scheme "http" host "example.test" path "/a" query "b=1"',
        ),
        ('when compose_url',),
        ('then url == "http://example.test/a?b=1"',),
        "drop_component_when_composing_url",
    ),
    Rule(
        "parse_url_handles_at_in_username_and_blank_port",
        r"Parse urls that contain ``@`` within the username.*no port|parse '@' in username.*blank ports",
        "http.url.parsing",
        (
            'given url "http://user@name@example.test:/path"',
        ),
        ('when parse_url',),
        ('then parsed_username == "user@name"', 'then parsed_port absent'),
        "split_username_at_first_at_or_require_port",
    ),
    Rule(
        "unknown_schemes_preserve_case",
        r"Preserve the case of the scheme in ``PoolManager`` connections to custom origins|schemes it does not recognise.*leaves them unchanged",
        "http.url.scheme-case",
        (
            'given url "SCHEME://example.test/path"',
        ),
        ('when parse_url custom_scheme true',),
        ('then parsed_scheme == "SCHEME"',),
        "lowercase_unknown_scheme",
    ),
    Rule(
        "incorrect_scheme_raises_value_error",
        r"``ValueError`` instead of ``AssertionError``.*incorrect scheme|Passing incorrect scheme.*raise ``ValueError``",
        "http.url.scheme-validation",
        (
            'given url "ftp://example.test/"',
        ),
        ('when create_http_pool "$url"',),
        ('then error 1 kind "invalid_scheme"',),
        "raise_internal_assertion_for_invalid_scheme",
    ),
    Rule(
        "idna_invalid_byte_is_rejected_or_normalized",
        r"invalid byte in the hostname",
        "http.url.idna",
        (
            'given url "http://\\xff.example/"',
        ),
        ('when parse_url',),
        ('then error 1 kind "invalid_host"',),
        "accept_invalid_idna_hostname",
    ),
    Rule(
        "ipv6_proxy_host_is_parsed_correctly",
        r"IPv6 proxy|proxy URLs containing IPv6 literals|host parsing for IPv6 proxies",
        "http.proxy.ipv6",
        (
            'given proxy_url "http://[::1]:8080"',
        ),
        ('when parse_proxy_url',),
        ('then parsed_host == "::1"', 'then parsed_port == 8080'),
        "misparse_ipv6_proxy_literal",
    ),
    Rule(
        "proxy_manager_pool_kwargs_override_pool_options",
        r"connection_pool_kw.*ProxyManager.*overridden|PoolManager.connection_from_\\*`` methods.*``pool_kwargs``.*merged",
        "http.proxy.pool-options",
        (
            'given proxy_manager connection_pool_kw {"timeout":1}',
        ),
        ('when request_via_proxy timeout 2',),
        ('then effective_pool_timeout == 2',),
        "ignore_request_level_pool_kw_override",
    ),
    Rule(
        "pool_key_uses_entire_request_context",
        r"PoolKey.*uses the entire request context|pool key.*request context|Connection pools now use the entire request context",
        "http.connection.pool-key",
        (
            'given pool_manager',
        ),
        ('when pool_for "https://example.test/" ca_certs "a.pem"', 'when pool_for "https://example.test/" ca_certs "b.pem"'),
        ('then pools are_distinct true',),
        "pool_key_ignores_request_context",
    ),
    Rule(
        "source_address_is_used_for_new_connections",
        r"source_address.*HTTPConnection|support for specifying ``source_address``",
        "http.connection.source-address",
        (
            'given server "origin" route "/" echo_peer_address',
        ),
        ('when GET "/" source_address "127.0.0.2"',),
        ('then server "origin" observed_peer_address == "127.0.0.2"',),
        "ignore_source_address",
    ),
    Rule(
        "socket_options_are_applied_before_connect",
        r"socket_options.*HTTPConnection|Set socket options|socket_options`` keyword parameter|Apply socket arguments before connecting|Apply socket arguments before binding",
        "http.connection.socket-options",
        (
            'given socket_option name "TCP_NODELAY" value 1',
        ),
        ('when GET "/" socket_options ["$socket_option"]',),
        ('then socket_option "TCP_NODELAY" == 1 before_connect true',),
        "ignore_socket_options",
    ),
    Rule(
        "default_blocksize_is_16k",
        r"default ``blocksize``.*16KiB|default blocksize.*16KB|default ``blocksize`` to 16KB",
        "http.request.blocksize",
        (
            'given connection default_blocksize',
        ),
        ('when inspect_request_blocksize',),
        ('then blocksize == 16384',),
        "use_non_16k_default_blocksize",
    ),
    Rule(
        "http_debug_log_formats_version_as_http11",
        r"HTTP version was rendering as \"HTTP/11\" instead of \"HTTP/1\.1\"",
        "http.observability.debug-log",
        (
            'given server "origin" route "/" status 200 body "ok"',
        ),
        ('when GET "/" debug_log true',),
        ('then log contains "HTTP/1.1"', 'then log not_contains "HTTP/11"'),
        "render_http11_log_as_http11_without_dot",
    ),
    Rule(
        "tls13_post_handshake_auth_works_when_validation_disabled",
        r"TLS 1\.3 post-handshake auth when the server certificate validation is disabled",
        "tls.post-handshake-auth",
        (
            'given tls_server "origin" tls_version "1.3" post_handshake_auth true certificate trusted false route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" cert_reqs "CERT_NONE"',),
        ('then response 1 status 200',),
        "break_tls13_post_handshake_auth_without_cert_validation",
    ),
    Rule(
        "pool_block_true_full_pool_raises_full_pool_error",
        r"``FullPoolError``.*PoolManager\(block=True\).*connection is returned to a full pool",
        "http.connection.pool-full",
        (
            'given connection_pool maxsize 1 block true full true',
        ),
        ('when release_connection extra_connection',),
        ('then error 1 kind "full_pool_error"',),
        "silently_discard_connection_from_blocking_full_pool",
    ),
    Rule(
        "proxy_certificate_hostname_assertion_is_configurable",
        r"``proxy_assert_hostname``.*``ProxyManager``",
        "http.proxy.tls-verification",
        (
            'given proxy "origin" scheme "https" certificate hostname "proxy.test"',
        ),
        ('when GET "http://target/" via_proxy "$ORIGIN" proxy_assert_hostname "proxy.test"',),
        ('then proxy_tls_verified == true',),
        "ignore_proxy_assert_hostname",
    ),
    Rule(
        "proxy_certificate_fingerprint_assertion_is_configurable",
        r"``proxy_assert_fingerprint``.*``ProxyManager``",
        "http.proxy.tls-fingerprint",
        (
            'given proxy "origin" scheme "https" certificate fingerprint "sha256:abc"',
        ),
        ('when GET "http://target/" via_proxy "$ORIGIN" proxy_assert_fingerprint "sha256:abc"',),
        ('then proxy_tls_verified == true',),
        "ignore_proxy_assert_fingerprint",
    ),
    Rule(
        "tunnel_scheme_controls_origin_tunnel_metadata",
        r"``scheme`` parameter to ``HTTPConnection.set_tunnel``",
        "http.proxy.tunnel-metadata",
        (
            'given connection through_proxy true',
        ),
        ('when set_tunnel host "example.test" port 443 scheme "https"',),
        ('then tunnel_scheme == "https"',),
        "ignore_set_tunnel_scheme",
    ),
    Rule(
        "connection_state_properties_track_lifecycle",
        r"``is_closed``.*``is_connected``.*``has_connected_to_proxy`` properties",
        "http.connection.state",
        (
            'given proxy "origin" tunneling true',
            'given tls_server "target" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://target/" via_proxy "$ORIGIN" preload_content false',),
        ('then connection is_connected == true', 'then connection is_closed == false', 'then connection has_connected_to_proxy == true'),
        "leave_connection_state_properties_stale",
    ),
    Rule(
        "system_cipher_suites_are_not_overridden_by_default",
        r"not override the system cipher suites with a default value|new default will be cipher suites configured by the operating system",
        "tls.cipher-defaults",
        (
            'given runtime system_cipher_suites ["TLS_AES_128_GCM_SHA256"]',
        ),
        ('when create_tls_context ciphers absent',),
        ('then context cipher_suites == ["TLS_AES_128_GCM_SHA256"]',),
        "override_system_cipher_suites_with_library_default",
    ),
    Rule(
        "connection_timeout_is_applied_before_reading_response",
        r"getresponse\(\).*set the socket timeout.*before reading data from the socket",
        "http.connection.timeout-lifecycle",
        (
            'given server "origin" route "/slow" delay_body 2 body "ok"',
        ),
        ('when GET "/slow" timeout 1',),
        ('then error 1 kind "read_timeout"',),
        "do_not_apply_connection_timeout_before_getresponse_read",
    ),
    Rule(
        "remove_headers_on_redirect_does_not_mutate_input_headers",
        r"``headers`` would be modified by the ``remove_headers_on_redirect`` feature",
        "http.redirect.header-mutation",
        (
            'given headers {"Authorization":"secret","X-Test":"1"}',
            'given server "origin" route "/redirect" redirect_to "$OTHER/target" status 302',
        ),
        ('when GET "/redirect" headers_ref "$headers" redirect true',),
        ('then headers == {"Authorization":"secret","X-Test":"1"}',),
        "mutate_headers_input_when_stripping_redirect_headers",
    ),
    Rule(
        "ip_address_hostname_verification_without_sni_succeeds",
        r"hostname verification involving IP addresses and lack of SNI",
        "tls.ip-address-verification",
        (
            'given tls_server "origin" certificate ip_san "127.0.0.1" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://127.0.0.1/" sni absent',),
        ('then response 1 status 200',),
        "require_sni_for_ip_address_certificate_verification",
    ),
    Rule(
        "ipv6_braces_are_stripped_for_certificate_matching",
        r"IPv6 braces weren't stripped during certificate hostname matching",
        "tls.ipv6-verification",
        (
            'given tls_server "origin" certificate ip_san "::1" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://[::1]/"',),
        ('then response 1 status 200',),
        "compare_ipv6_certificate_name_with_brackets",
    ),
    Rule(
        "certificate_ipv6_subject_alt_name_is_accepted",
        r"IPv6 addresses in subjectAltName section of certificates|Accept ``iPAddress`` subject alternative name fields",
        "tls.ip-address-verification",
        (
            'given tls_server "origin" certificate ip_san "::1" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "https://[::1]/"',),
        ('then response 1 status 200',),
        "reject_ipaddress_subject_alt_name",
    ),
    Rule(
        "ca_certs_imply_certificate_required",
        r"When ``ca_certs`` is given, ``cert_reqs`` defaults to ``'CERT_REQUIRED'``",
        "tls.ca-loading",
        (
            'given tls_server "origin" certificate trusted false route "/" status 200 body "ok"',
            'given ca_bundle "custom" trusts []',
        ),
        ('when HTTPS_GET "/" ca_certs "$custom" cert_reqs absent',),
        ('then error 1 kind "certificate_verify_failed"',),
        "do_not_require_certificates_when_ca_certs_are_given",
    ),
    Rule(
        "pool_is_replenished_after_release_conn_false_error",
        r"Fix pools not getting replenished when an error occurs during a request using ``release_conn=False``",
        "http.connection.pool-replenishment",
        (
            'given connection_pool maxsize 1',
            'given server "origin" route "/bad" close_before_response true',
        ),
        ('when GET "/bad" release_conn false', 'when GET "/"'),
        ('then pool available_connections == 1',),
        "do_not_replenish_pool_after_release_conn_false_error",
    ),
    Rule(
        "connection_is_discarded_after_read_error",
        r"Close and discard connections if an error occurs during read",
        "http.connection.read-error-lifecycle",
        (
            'given server "origin" route "/bad" header "Content-Length" "10" body "abc" close_after_body true',
        ),
        ('when GET "/bad" preload_content false then response_stream',),
        ('then connection reusable == false',),
        "return_read_error_connection_to_pool",
    ),
    Rule(
        "tilde_in_url_path_is_not_percent_encoded",
        r"tilde \(``~``\) characters were incorrectly percent-encoded in the path",
        "http.url.percent-encoding",
        (
            'given url "http://example.test/~user"',
        ),
        ('when parse_url then compose_url',),
        ('then url == "http://example.test/~user"',),
        "percent_encode_tilde_in_path",
    ),
    Rule(
        "ipvfuture_address_is_not_treated_as_ip_address",
        r"``is_ipaddress`` to not detect IPvFuture addresses",
        "http.url.ip-address-classification",
        (
            'given host "[v1.fe80::]"',
        ),
        ('when classify_host_as_ip_address',),
        ('then is_ip_address == false',),
        "classify_ipvfuture_as_ip_address",
    ),
    Rule(
        "custom_ciphers_parameter_is_applied_to_tls_context",
        r"Restored functionality of ``ciphers`` parameter",
        "tls.cipher-configuration",
        (
            'given cipher_list "ECDHE-RSA-AES128-GCM-SHA256"',
        ),
        ('when create_tls_context ciphers "$cipher_list"',),
        ('then context ciphers contains "ECDHE-RSA-AES128-GCM-SHA256"',),
        "ignore_custom_ciphers_parameter",
    ),
    Rule(
        "http_header_dict_is_usable_as_request_headers",
        r"``HTTPHeaderDict`` usable as a ``headers`` input value",
        "http.headers.input-types",
        (
            'given header_dict {"X-Test":"1"}',
            'given server "origin" route "/" echo_header "X-Test"',
        ),
        ('when GET "/" headers "$header_dict"',),
        ('then response 1 body "1"',),
        "reject_http_header_dict_as_input_headers",
    ),
    Rule(
        "response_stream_amt_none_terminates",
        r"infinite loop in ``stream`` when amt=None",
        "http.response.streaming",
        (
            'given response body "abc"',
        ),
        ('when response_stream amt null',),
        ('then combined_read_body "abc"', 'then stream_terminated == true'),
        "loop_forever_when_stream_amt_none",
    ),
    Rule(
        "response_length_remaining_tracks_unread_body",
        r"Implemented ``length_remaining``",
        "http.response.content-length",
        (
            'given response header "Content-Length" "5" body "abcde"',
        ),
        ('when response_read amt 2',),
        ('then length_remaining == 3',),
        "leave_length_remaining_untracked",
    ),
    Rule(
        "ipv6_dns_is_disabled_when_ipv6_connections_are_unavailable",
        r"Disable IPv6 DNS when IPv6 connections are not possible",
        "http.dns.ipv6",
        (
            'given runtime ipv6_connect_available false',
        ),
        ('when resolve_host "example.test"',),
        ('then dns_query_type not_contains "AAAA"',),
        "query_ipv6_dns_when_ipv6_connect_unavailable",
    ),
    Rule(
        "pool_key_function_can_be_overridden_by_scheme",
        r"``key_fn_by_scheme`` pool keying mechanism that can be overridden",
        "http.connection.pool-key",
        (
            'given pool_manager key_fn_by_scheme {"http":"constant"}',
        ),
        ('when pool_for "http://a.test/"', 'when pool_for "http://b.test/"'),
        ('then pools are_same true',),
        "ignore_custom_pool_key_function",
    ),
    Rule(
        "retry_raise_on_status_false_returns_error_response",
        r"Retry\(raise_on_status=False\)",
        "http.retry.status-policy",
        (
            'given server "origin" route "/unavailable" status 503 body "down"',
        ),
        ('when GET "/unavailable" retries 1 retry_raise_on_status false',),
        ('then response 1 status 503',),
        "raise_on_status_despite_disabled_policy",
    ),
    Rule(
        "socks_proxy_basic_request_succeeds",
        r"SOCKS proxy support!",
        "http.proxy.socks",
        (
            'given socks_proxy "origin"',
            'given server "target" route "/" status 200 body "ok"',
        ),
        ('when GET "http://target/" via_proxy "$ORIGIN"',),
        ('then response 1 status 200',),
        "disable_socks_proxy_path",
    ),
    Rule(
        "proxy_manager_adds_host_header_when_missing",
        r"``ProxyManager`` automatically adds ``Host: ...`` header if not given",
        "http.proxy.host-header",
        (
            'given proxy "origin" capture_header "Host"',
        ),
        ('when GET "http://example.test/path" via_proxy "$ORIGIN" headers {}',),
        ('then proxy "origin" observed_header "Host" == "example.test"',),
        "omit_host_header_for_proxy_request",
    ),
    Rule(
        "cert_reqs_accepts_string_policy_values",
        r"``cert_req`` now optionally takes a string like \"REQUIRED\" or \"NONE\"",
        "tls.verification-policy",
        (
            'given tls_server "origin" certificate trusted false route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" cert_reqs "NONE"',),
        ('then response 1 status 200',),
        "reject_string_cert_reqs_value",
    ),
    Rule(
        "connection_closes_when_no_data_is_received",
        r"Ensure the connection is closed if no data is received",
        "http.connection.resource-lifecycle",
        (
            'given server "origin" accepts_then_closes_without_data true',
        ),
        ('when GET "/"',),
        ('then connection is_closed == true',),
        "leave_connection_open_after_empty_response",
    ),
    Rule(
        "default_headers_are_sent",
        r"Fixed default headers not getting passed",
        "http.request.default-headers",
        (
            'given default_headers {"X-Default":"1"}',
            'given server "origin" route "/" echo_header "X-Default"',
        ),
        ('when GET "/"',),
        ('then response 1 body "1"',),
        "drop_default_headers",
    ),
    Rule(
        "content_encoding_header_is_case_insensitive",
        r"Treat \"content-encoding\" header value as case-insensitive",
        "http.response.content-decoding",
        (
            'given compressed_response encoding "GZip" body "hello"',
        ),
        ('when response_read decode true',),
        ('then combined_read_body "hello"',),
        "treat_content_encoding_case_sensitively",
    ),
    Rule(
        "connection_refused_is_retried",
        r"\"Connection Refused\" SocketErrors will get retried",
        "http.retry.connection-refused",
        (
            'given server "origin" refuses_then_accepts true route "/" status 200 body "ok"',
        ),
        ('when GET "/" retries 1',),
        ('then response 2 status 200',),
        "do_not_retry_connection_refused",
    ),
    Rule(
        "max_retry_error_reason_is_none_for_redirect_exhaustion",
        r"MaxRetryError`` contains a ``reason`` property.*If ``reason is None`` then it was due to a redirect",
        "http.retry.error-shape",
        (
            'given server "origin" route "/loop" redirect_to "/loop" status 302',
        ),
        ('when GET "/loop" redirects 1',),
        ('then error 1 kind "max_retry_error"', 'then error 1 reason == null'),
        "set_non_null_reason_for_redirect_exhaustion",
    ),
    Rule(
        "multipart_plain_fields_do_not_default_to_text_plain",
        r"Don't assume ``Content-Type: text/plain`` for multi-part encoding parameters that are not files",
        "http.multipart.content-type",
        (
            'given multipart_field name "a" value "1" file false',
        ),
        ('when encode_multipart_formdata',),
        ('then part "a" header "Content-Type" absent',),
        "add_text_plain_content_type_to_plain_multipart_field",
    ),
    Rule(
        "md5_sha1_fingerprint_verification_is_supported",
        r"verify SSL certificates by fingerprint \\(md5, sha1\\)",
        "tls.fingerprint-verification",
        (
            'given tls_server "origin" certificate fingerprint "sha1:abc" route "/" status 200 body "ok"',
        ),
        ('when HTTPS_GET "/" assert_fingerprint "sha1:abc"',),
        ('then response 1 status 200',),
        "reject_sha1_fingerprint",
    ),
    Rule(
        "streaming_decompression_is_supported",
        r"Streaming decompression support",
        "http.response.content-decoding",
        (
            'given compressed_response encoding "gzip" body "hello"',
        ),
        ('when response_stream decode true',),
        ('then combined_read_body "hello"',),
        "disable_streaming_decompression",
    ),
    Rule(
        "decode_failure_raises_decode_error",
        r"``DecodeError`` exception for when automatic decoding.*fails",
        "http.response.content-decoding-error",
        (
            'given response header "Content-Encoding" "gzip" body "not-gzip"',
        ),
        ('when response_read decode true',),
        ('then error 1 kind "decode_error"',),
        "raise_generic_protocol_error_on_decode_failure",
    ),
    Rule(
        "pool_eviction_closes_evicted_idle_connections",
        r"pool depletion and leaking connections.*explicit connection closing on pool eviction",
        "http.connection.pool-eviction",
        (
            'given pool_manager max_pools 1',
            'given server "one" route "/" status 200 body "one"',
            'given server "two" route "/" status 200 body "two"',
        ),
        ('when GET "http://one/"', 'when GET "http://two/"'),
        ('then evicted_idle_connections_closed == true',),
        "leak_idle_connection_on_pool_eviction",
    ),
    Rule(
        "poolmanager_clear_closes_all_pools",
        r"Added ``urllib3.PoolManager.clear\(\)``",
        "http.connection.poolmanager-lifecycle",
        (
            'given pool_manager with_open_idle_connections true',
        ),
        ('when poolmanager_clear',),
        ('then all_idle_connections_closed == true',),
        "leave_connections_open_after_poolmanager_clear",
    ),
    Rule(
        "location_parse_error_is_value_error",
        r"Location parsing errors now raise .*LocationParseError.*inherits from ``ValueError``",
        "http.url.parsing-error",
        (
            'given url "http://[invalid"',
        ),
        ('when parse_url',),
        ('then error 1 kind "location_parse_error"', 'then error 1 is_value_error true'),
        "raise_non_value_error_for_location_parse_failure",
    ),
    Rule(
        "cross_scheme_redirect_completes",
        r"PoolManager`` redirects between schemes.*HTTP -> HTTPS.*completing properly",
        "http.redirect.cross-scheme",
        (
            'given server "origin" scheme "http" route "/redirect" redirect_to "https://secure/target" status 302',
            'given tls_server "secure" route "/target" status 200 body "secure"',
        ),
        ('when GET "http://origin/redirect" redirect true',),
        ('then response 1 status 200', 'then response 1 body "secure"'),
        "fail_cross_scheme_redirect",
    ),
)


ALL_RULES: tuple[Rule, ...] = RULES + MAXIMAL_EXTRA_RULES


SKIP_PATTERNS = (
    r"Python \d",
    r"PyPy",
    r"packag|setuptools|Hatch|uv|\bCI\b|tests|documentation|docs|type hint|mypy|typing",
    r"dependency|dependencies|extra|pyOpenSSL version|cryptography|brotli libraries",
    r"AppEngine|Emscripten|Node\\.js|JavaScript|SecureTransport|LibreSSL|OpenSSL versions|free-threading",
    r"warning|DeprecationWarning|FutureWarning|deprecated|Removed support|Drop support|Dropped support",
    r"performance|memory|faster|optimization",
    r"license|attestation|release files",
)


SEED_CONTRACTS_BY_VERSION: dict[str, tuple[dict, ...]] = {
    "0.3": (
        {
            "name": "same_origin_sequential_requests_reuse_one_connection",
            "evidence": "README.txt: Re-use the same socket connection for multiple requests",
            "capability": "http.connection.pooling",
            "mutant": "disable_connection_reuse",
            "setup": (
                'given server "origin" route "/first" status 200 body "first"',
                'given server "origin" route "/second" status 200 body "second"',
            ),
            "actions": ('when GET "/first"', 'when GET "/second"'),
            "assertions": (
                'then response 1 status 200',
                'then response 1 body "first"',
                'then response 2 status 200',
                'then response 2 body "second"',
                'then server "origin" accepted_connections == 1',
            ),
        },
        {
            "name": "get_query_fields_are_sent_as_url_parameters",
            "evidence": "test/test_withdummy.py:test_get_url",
            "capability": "http.request.query-params",
            "mutant": "drop_get_query_fields",
            "setup": ('given server "origin" route "/specific_method" require_method_param',),
            "actions": ('when GET "/specific_method" query {"method":"GET"}',),
            "assertions": ('then response 1 status 200',),
        },
        {
            "name": "post_form_fields_are_sent_as_request_parameters",
            "evidence": "test/test_withdummy.py:test_post_url",
            "capability": "http.request.form-params",
            "mutant": "drop_post_form_fields",
            "setup": ('given server "origin" route "/specific_method" require_method_param',),
            "actions": ('when POST_FORM "/specific_method" form {"method":"POST"}',),
            "assertions": ('then response 1 status 200',),
        },
        {
            "name": "arbitrary_http_method_is_sent_unchanged",
            "evidence": "test/test_withdummy.py:test_urlopen_put",
            "capability": "http.request.method",
            "mutant": "rewrite_put_to_get",
            "setup": ('given server "origin" route "/specific_method" require_method_param',),
            "actions": ('when PUT "/specific_method?method=PUT"',),
            "assertions": ('then response 1 status 200',),
        },
        {
            "name": "multipart_file_post_preserves_file_name_and_size",
            "evidence": "README.txt: File posting; test/test_withdummy.py:test_upload",
            "capability": "http.multipart.file-upload",
            "mutant": "drop_multipart_filename_or_body",
            "setup": ('given server "origin" route "/upload" require_upload',),
            "actions": (
                'when POST_MULTIPART "/upload" form {"upload_param":"filefield","upload_filename":"lolcat.txt","upload_size":"50"} file "filefield" filename "lolcat.txt" body "I\'m in ur multipart form-data, hazing a cheezburgr"',
            ),
            "assertions": ('then response 1 status 200',),
        },
        {
            "name": "redirect_can_be_observed_without_following",
            "evidence": "README.txt: Built-in redirection and retries (optional); test/test_withdummy.py:test_redirect",
            "capability": "http.redirect.optional",
            "mutant": "always_follow_redirects",
            "setup": (
                'given server "origin" route "/" status 200 body "Dummy server!"',
                'given server "origin" route "/redirect" redirect_from_query "target" status 303',
            ),
            "actions": ('when GET "/redirect" query {"target":"/"} redirect false',),
            "assertions": ('then response 1 status 303',),
        },
        {
            "name": "redirect_is_followed_by_default",
            "evidence": "README.txt: Built-in redirection and retries (optional); test/test_withdummy.py:test_redirect",
            "capability": "http.redirect.follow",
            "mutant": "disable_default_redirect_following",
            "setup": (
                'given server "origin" route "/" status 200 body "Dummy server!"',
                'given server "origin" route "/redirect" redirect_from_query "target" status 303',
            ),
            "actions": ('when GET "/redirect" query {"target":"/"} redirect true',),
            "assertions": ('then response 1 status 200', 'then response 1 body "Dummy server!"'),
        },
        {
            "name": "redirect_consumes_retry_budget",
            "evidence": "urllib3/connectionpool.py:urlopen docstring; test/test_withdummy.py:test_maxretry",
            "capability": "http.redirect.retry-budget",
            "mutant": "ignore_redirect_retry_budget",
            "setup": (
                'given server "origin" route "/" status 200 body "Dummy server!"',
                'given server "origin" route "/redirect" redirect_from_query "target" status 303',
            ),
            "actions": ('when GET "/redirect" query {"target":"/"} redirect true retries 0',),
            "assertions": ('then error 1 kind "max_retries_exceeded"',),
        },
        {
            "name": "slow_response_exceeding_socket_timeout_fails",
            "evidence": "urllib3/connectionpool.py:timeout parameter docstring; test/test_withdummy.py:test_timeout",
            "capability": "http.timeout.error-kind",
            "mutant": "ignore_socket_timeout",
            "setup": ('given server "origin" route "/sleep" sleep_from_query "seconds" status 200 body ""',),
            "actions": ('when GET "/sleep" query {"seconds":"0.2"} timeout 0.1',),
            "assertions": ('then error 1 kind "timeout"',),
        },
        {
            "name": "pool_rejects_foreign_origin_requests",
            "evidence": "urllib3/connectionpool.py:HostChangedError; test/test_connectionpool.py:test_same_host",
            "capability": "http.url.origin-guard",
            "mutant": "allow_foreign_origin_on_pool",
            "setup": ('given server "origin" route "/" status 200 body "home"',),
            "actions": ('when GET "http://127.0.0.1:1/"',),
            "assertions": ('then error 1 kind "foreign_origin"', 'then server "origin" accepted_connections == 0'),
        },
        {
            "name": "broken_connection_is_retried_until_success",
            "evidence": "urllib3/connectionpool.py: Retrying after connection broken; urlopen retries parameter",
            "capability": "http.retry.broken-connection",
            "mutant": "disable_retry_after_broken_connection",
            "setup": ('given server "origin" route "/flaky" close_first_then status 200 body "recovered"',),
            "actions": ('when GET "/flaky" retries 1',),
            "assertions": (
                'then response 1 status 200',
                'then response 1 body "recovered"',
                'then server "origin" path_requests "/flaky" == 2',
            ),
        },
        {
            "name": "https_origin_request_succeeds",
            "evidence": "CHANGES.rst:0.3: Added HTTPS support.",
            "capability": "https.basic-request",
            "mutant": "route_https_through_plain_http_connection",
            "setup": ('given tls_server "origin" route "/" status 200 body "secure"',),
            "actions": ('when HTTPS_GET "/" verify false',),
            "assertions": ('then response 1 status 200', 'then response 1 body "secure"'),
        },
    ),
}


def slugify(text: str) -> str:
    text = re.sub(r"``([^`]+)``", r"\1", text)
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text.lower()).strip("_")
    return text[:80] or "contract"


def parse_releases(text: str) -> list[dict]:
    headings = list(re.finditer(r"^(\d+\.\S+) \(([^)]+)\)\n=+", text, re.M))
    releases = []
    for index, heading in enumerate(headings):
        start = heading.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[start:end]
        bullets = []
        current = []
        for line in body.splitlines():
            if re.match(r"^[-*] ", line):
                if current:
                    bullets.append(" ".join(part.strip() for part in current))
                current = [line[2:].strip()]
            elif current and (line.startswith("  ") or not line.strip()):
                if line.strip():
                    current.append(line.strip())
            elif current:
                bullets.append(" ".join(part.strip() for part in current))
                current = []
        if current:
            bullets.append(" ".join(part.strip() for part in current))
        releases.append({"version": heading.group(1), "date": heading.group(2), "bullets": bullets})
    return releases


def classify_bullet(bullet: str) -> tuple[str, Rule | None]:
    for rule in ALL_RULES:
        if rule.matches(bullet):
            return "contract", rule
    for skip in SKIP_PATTERNS:
        if re.search(skip, bullet, flags=re.I):
            return "skipped_language_or_maintenance", None
    return "skipped_no_language_independent_replay_template", None


def render_contract(release: dict, bullet: str, rule: Rule, ordinal: int) -> str:
    name = rule.name
    if ordinal:
        name = f"{name}_{ordinal + 1}"
    lines = [
        f'contract "{name}"',
        f'evidence "CHANGES.rst:{release["version"]}: {bullet.replace(chr(34), chr(39))}"',
        f'capability "{rule.capability}"',
        'replay "template"',
        f'mutant "{rule.mutant}"',
    ]
    lines.extend(rule.setup)
    lines.extend(rule.actions)
    lines.extend(rule.assertions)
    lines.append("end")
    return "\n".join(lines)


def render_seed_contract(seed: dict) -> str:
    lines = [
        f'contract "{seed["name"]}"',
        f'evidence "{seed["evidence"].replace(chr(34), chr(39))}"',
        f'capability "{seed["capability"]}"',
        'replay "template"',
        f'mutant "{seed["mutant"]}"',
    ]
    lines.extend(seed["setup"])
    lines.extend(seed["actions"])
    lines.extend(seed["assertions"])
    lines.append("end")
    return "\n".join(lines)


def main() -> int:
    releases = parse_releases(CHANGES.read_text(encoding="utf-8"))
    OUT_RPL.parent.mkdir(parents=True, exist_ok=True)

    emitted_names: dict[tuple[str, str], int] = {}
    summary = {
        "source": str(CHANGES),
        "release_count": len(releases),
        "contract_count": 0,
        "releases": [],
    }
    blocks = [
        '# Generated by tools/replay/extract_urllib3_contracts.py',
        '# Maximal language-independent extraction: rule-matched HTTP/TLS/proxy/runtime behavior is emitted.',
        "",
    ]

    for release in releases:
        release_contracts = []
        skipped = []
        blocks.append(f'release "urllib3" version "{release["version"]}" date "{release["date"]}"')
        blocks.append(f'source "pypi:urllib3=={release["version"]}"')
        for seed in SEED_CONTRACTS_BY_VERSION.get(release["version"], ()):
            blocks.append("")
            blocks.append(render_seed_contract(seed))
            release_contracts.append(
                {
                    "name": seed["name"],
                    "capability": seed["capability"],
                    "evidence": seed["evidence"],
                    "seed": True,
                }
            )
        for bullet in release["bullets"]:
            kind, rule = classify_bullet(bullet)
            if kind == "contract" and rule is not None:
                key = (release["version"], rule.name)
                ordinal = emitted_names.get(key, 0)
                emitted_names[key] = ordinal + 1
                rendered = render_contract(release, bullet, rule, ordinal)
                blocks.append("")
                blocks.append(rendered)
                release_contracts.append({"name": rule.name if ordinal == 0 else f"{rule.name}_{ordinal + 1}", "capability": rule.capability, "evidence": bullet})
            else:
                skipped.append({"reason": kind, "evidence": bullet})
        if not release_contracts:
            blocks.append('no_contracts "no release-note item matched language-independent HTTP replay templates"')
        blocks.append("")
        summary["contract_count"] += len(release_contracts)
        summary["releases"].append(
            {
                "version": release["version"],
                "date": release["date"],
                "bullet_count": len(release["bullets"]),
                "contract_count": len(release_contracts),
                "contracts": release_contracts,
                "skipped_count": len(skipped),
                "skipped": skipped,
            }
        )

    OUT_RPL.write_text("\n".join(blocks).rstrip() + "\n", encoding="utf-8")
    OUT_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"releases={summary['release_count']} contracts={summary['contract_count']}")
    print(OUT_RPL)
    print(OUT_JSON)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
