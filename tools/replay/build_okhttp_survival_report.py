#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
LOG = pathlib.Path("/tmp/okhttp-survival-run.log")
SOURCE = ROOT / "contracts" / "urllib3" / "final_survival_urllib3_2.7.0.json"
OUT_DIR = ROOT / "contracts" / "okhttp"


MAPPING = {
    "0.3:same_origin_sequential_requests_reuse_one_connection": "connection_reuse",
    "1.2:same_origin_requests_reuse_one_connection": "connection_reuse",
    "0.3:get_query_fields_are_sent_as_url_parameters": "query_params",
    "0.3:post_form_fields_are_sent_as_request_parameters": "post_form",
    "0.3:arbitrary_http_method_is_sent_unchanged": "arbitrary_put_method",
    "0.3:multipart_file_post_preserves_file_name_and_size": "multipart_file_upload",
    "0.3:redirect_can_be_observed_without_following": "redirect_observable_without_following",
    "0.3:redirect_is_followed_by_default": "redirect_followed_by_default",
    "0.3:slow_response_exceeding_socket_timeout_fails": "read_timeout_error",
    "0.3:broken_connection_is_retried_until_success": "broken_connection_retried",
    "1.22:broken_connection_is_retried_until_success": "broken_connection_retried",
    "0.3:https_origin_request_succeeds": "https_basic",
    "2.0.0:tls_minimum_and_maximum_versions_configure_context": "tls_minimum_and_maximum_versions_configure_context",
    "2.0.0:tls_minimum_and_maximum_versions_configure_context_2": "tls_minimum_and_maximum_versions_configure_context",
    "1.18:certificate_ipv6_subject_alt_name_is_accepted": "certificate_ip_subject_alt_name_is_accepted",
    "1.24.2:certificate_ipv6_subject_alt_name_is_accepted": "certificate_ip_subject_alt_name_is_accepted",
    "1.26.7:ipv6_braces_are_stripped_for_certificate_matching": "ipv6_braces_are_stripped_for_certificate_matching",
    "2.0.3:assert_hostname_false_skips_hostname_verification": "hostname_verification_can_be_disabled",
    "1.9.1:only_fingerprint_verification_is_supported": "fingerprint_verification_is_supported",
    "1.24.1:custom_ciphers_parameter_is_applied_to_tls_context": "custom_cipher_suite_is_applied",
    "1.26.0:tls_alpn_http11_identifier_is_sent": "tls_alpn_http11_identifier_is_sent",
    "1.1:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.8.3:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.9:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.10:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "2.0.0:connection_timeout_is_applied_before_reading_response": "read_timeout_error",
    "1.26.15:reused_connection_uses_new_socket_timeout": "reused_connection_uses_new_socket_timeout",
    "2.0.0:reused_connection_uses_new_socket_timeout": "reused_connection_uses_new_socket_timeout",
    "1.7:https_proxy_to_https_target_is_supported": "https_request_through_http_connect_proxy_succeeds",
    "1.11:ipv6_proxy_host_is_parsed_correctly": "ipv6_proxy_host_is_parsed_correctly",
    "1.22:proxy_connect_ipv6_target_uses_brackets": "proxy_connect_ipv6_target_uses_brackets",
    "2.5.0:proxy_connect_ipv6_target_uses_brackets": "proxy_connect_ipv6_target_uses_brackets",
    "2.2.0:trailing_dot_hostname_through_proxy_connects": "trailing_dot_hostname_through_proxy_connects",
    "1.14:socks_proxy_basic_request_succeeds": "socks_proxy_basic_request_succeeds",
    "1.20:socks_remote_dns_schemes_are_supported": "socks_remote_dns_schemes_are_supported",
    "1.6:streaming_decompression_is_supported": "gzip_response_decoded",
    "1.10.1:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "1.13:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "2.1.0:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "1.6:content_encoding_header_is_case_insensitive": "gzip_content_encoding_case_insensitive",
    "1.24:multiple_content_encodings_are_decoded_in_order": "multiple_content_encodings",
    "2.6.0:content_encoding_chain_is_limited_to_five": "content_encoding_chain_limit",
    "2.0.2:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.6.2:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.7.0:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.7.0:response_stream_continues_with_buffered_decompressed_data_2": "decompression_buffer_continues_after_partial_read",
    "1.26.15:url_ipv6_zone_identifier_is_accepted": "url_ipv6_zone_identifier_accepted",
    "1.10.3:multiple_set_cookie_headers_are_preserved": "multiple_set_cookie_headers_preserved",
    "1.10.1:header_values_with_commas_are_preserved": "comma_header_value_preserved",
    "2.0.0:incomplete_response_body_raises_when_content_length_enforced": "incomplete_content_length_raises",
    "1.17:incomplete_response_body_raises_when_content_length_enforced": "incomplete_content_length_raises",
    "1.11:incomplete_response_read_is_wrapped_as_protocol_error": "incomplete_content_length_raises",
    "1.9:incomplete_response_read_is_wrapped_as_protocol_error": "incomplete_content_length_raises",
    "2.2.1:invalid_chunk_length_raises_protocol_error": "invalid_chunk_length_raises",
    "1.25.7:url_fragment_is_not_sent_in_request_target": "fragment_not_sent_in_request_target",
    "1.5:proxy_request_uri_strips_scheme_and_host": "request_target_is_origin_form",
    "1.25.6:tilde_in_url_path_is_not_percent_encoded": "tilde_path_not_percent_encoded",
    "1.25.7:empty_query_section_is_preserved": "empty_query_section_preserved",
    "1.19:user_supplied_host_header_is_preserved_for_chunked_upload": "user_supplied_host_header_preserved",
    "1.15:chunked_request_sets_transfer_encoding_header": "chunked_request_sets_transfer_encoding",
    "1.10.4:chunked_keep_alive_preserves_request_boundaries": "chunked_keep_alive_preserves_request_boundaries",
    "2.2.3:chunked_request_body_uses_utf8": "chunked_request_body_uses_utf8",
    "2.0.0:chunked_boundaries_are_lowercase": "chunked_boundaries_are_lowercase",
    "1.26.6:explicit_transfer_encoding_chunked_header_is_not_duplicated": "explicit_transfer_encoding_chunked_not_duplicated",
    "2.0.7:http_303_redirect_switches_method_to_get_and_strips_body": "http_303_redirect_switches_method_to_get",
    "1.26.18:http_303_redirect_switches_method_to_get_and_strips_body": "http_303_redirect_switches_method_to_get",
    "1.7:relative_redirect_location_is_followed": "relative_redirect_location_followed",
    "1.7:relative_redirect_location_is_followed_2": "relative_redirect_location_followed",
    "1.22:redirect_drain_releases_blocking_pool_connection": "redirect_body_is_released_before_following",
    "1.25.9:redirect_drain_releases_blocking_pool_connection": "redirect_body_is_released_before_following",
    "1.24.2:authorization_header_stripping_is_case_insensitive": "cross_host_redirect_strips_authorization_case_insensitive",
    "2.0.0:remove_headers_on_redirect_does_not_mutate_input_headers": "redirect_header_input_not_mutated",
    "2.0.6:cross_host_redirect_strips_cookie_header": "cross_host_redirect_strips_cookie",
    "1.26.17:cross_host_redirect_strips_cookie_header": "cross_host_redirect_strips_cookie",
    "2.2.2:cross_host_redirect_strips_proxy_authorization_header": "cross_host_redirect_strips_proxy_authorization",
    "1.26.19:cross_host_redirect_strips_proxy_authorization_header": "cross_host_redirect_strips_proxy_authorization",
    "1.25.9:method_rejects_control_characters": "method_rejects_control_characters",
    "1.9:url_empty_host_is_rejected": "url_empty_host_rejected",
    "1.17:url_scheme_and_host_are_normalized_lowercase": "url_scheme_and_host_normalized_lowercase",
    "1.20:url_scheme_and_host_are_normalized_lowercase": "url_scheme_and_host_normalized_lowercase",
    "1.8:same_host_accepts_default_port_equivalence": "url_default_port_equivalence",
    "1.26.13:url_port_with_leading_zeroes_is_accepted": "url_port_with_leading_zeroes_accepted",
    "1.26.14:url_port_zero_is_preserved": "url_port_zero_preserved",
    "1.19:url_port_rejects_integerish_unicode": "url_port_rejects_unicode_digits",
    "1.7:url_ipv6_requires_brackets": "url_ipv6_requires_brackets",
    "1.25.4:url_path_query_fragment_invalid_chars_are_percent_encoded": "url_invalid_chars_percent_encoded",
    "1.25.2:url_path_query_fragment_invalid_chars_are_percent_encoded": "url_invalid_chars_percent_encoded",
    "1.25.4:url_auth_invalid_chars_are_percent_encoded": "url_auth_invalid_chars_percent_encoded",
    "2.0.0:url_authority_includes_userinfo_and_host": "url_authority_includes_userinfo_and_host",
    "2.0.0:json_request_sets_content_type_when_missing": "json_request_sets_content_type",
    "2.2.0:headers_input_is_not_mutated_by_json_request": "request_header_input_not_mutated",
    "2.2.1:non_proxy_headers_are_not_cast_to_headerdict": "request_header_input_not_mutated",
    "1.6:default_headers_are_sent": "default_headers_sent",
    "1.6:proxy_manager_adds_host_header_when_missing": "default_headers_sent",
    "1.12:new_connection_failure_raises_new_connection_error": "connection_refused_error",
    "2.0.0:dns_failure_raises_name_resolution_error": "dns_failure_error",
    "1.11:http_header_dict_is_usable_as_request_headers": "headers_mapping_accepted",
    "1.11:pool_default_headers_apply_to_get_query_requests": "client_default_headers_apply_to_get_query",
    "1.24:message_content_type_header_is_accepted": "message_content_type_header_accepted",
    "1.26.1:bytes_user_agent_header_does_not_duplicate": "duplicate_user_agent_not_added",
    "1.15:request_response_header_order_is_preserved": "request_header_order_preserved",
    "1.3:multipart_list_of_tuples_preserves_duplicate_field_names": "multipart_duplicate_field_names_preserved",
    "1.19:multipart_file_empty_filename_is_emitted": "multipart_empty_filename_emitted",
    "1.25:multipart_html5_header_encoder_is_default": "multipart_html5_filename_formatting",
    "2.0.0:multipart_header_control_characters_are_not_percent_encoded": "multipart_control_chars_not_percent_encoded",
    "1.6:multipart_file_explicit_content_type_is_sent": "multipart_explicit_content_type_sent",
    "1.6:multipart_plain_fields_do_not_default_to_text_plain": "multipart_plain_fields_have_no_default_content_type",
    "1.7:response_iter_yields_body_lines_efficiently": "response_body_lines_streamed",
    "1.25:response_iter_yields_body_lines_efficiently": "response_body_lines_streamed",
    "1.10.4:chunked_head_response_without_body_does_not_hang": "chunked_head_response_without_body_does_not_hang",
    "1.23:chunked_head_response_releases_connection": "chunked_head_response_without_body_does_not_hang",
    "2.2.3:http2_request_does_not_send_transfer_encoding_chunked": "http2_request_body_without_transfer_encoding",
    "2.2.3:http2_request_body_is_sent": "http2_request_body_without_transfer_encoding",
    "2.2.3:http2_origin_support_is_probed_with_alpn": "http2_origin_support_is_probed_with_alpn",
}


def load_runner() -> dict:
    match = re.search(r'\{\"okhttp_version\".*\}\s*$', LOG.read_text(), re.S)
    if not match:
        raise RuntimeError(f"No runner JSON found in {LOG}")
    return json.loads(match.group(0))


def main() -> int:
    runner = load_runner()
    tests = {test["name"]: test for test in runner["tests"]}
    source = json.loads(SOURCE.read_text())
    survivors = [row for row in source["results"] if row["survived_latest"]]
    rows = []
    for src in survivors:
        key = f"{src['source_version']}:{src['contract']}"
        test_name = MAPPING.get(key)
        row = {
            "key": key,
            "source_version": src["source_version"],
            "contract": src["contract"],
            "capability": src.get("capability", ""),
            "urllib3_final_survived": True,
        }
        if test_name:
            test = tests[test_name]
            row.update({"okhttp_status": "passed" if test["passed"] else "failed", "okhttp_test": test_name, "error": test.get("error", "")})
        else:
            row.update({
                "okhttp_status": "failed_absent_or_unmapped",
                "okhttp_test": "",
                "error": "aggressive mode: no executed OkHttp equivalent proved this urllib3 contract survives",
            })
        rows.append(row)

    counts = collections.Counter(row["okhttp_status"] for row in rows)
    raw_counts = collections.Counter("passed" if test["passed"] else "failed" for test in runner["tests"])
    payload = {
        "source_project": "urllib3",
        "source_baseline": "contracts/urllib3/final_survival_urllib3_2.7.0.json",
        "target_project": "okhttp",
        "target_latest_version": runner["okhttp_version"],
        "target_latest_source": "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp-jvm/maven-metadata.xml",
        "mode": "aggressive_no_not_applicable",
        "rule": "Raw target report counts unmapped as failed; canonical evaluator separates adapter blockage and feature absence.",
        "total_urllib3_final_survivors": len(rows),
        "okhttp_survived_aggressive": counts["passed"],
        "okhttp_failed_aggressive": len(rows) - counts["passed"],
        "not_applicable_or_unmapped": 0,
        "breakdown": dict(sorted(counts.items())),
        "adapter_tests": {"total": len(runner["tests"]), **raw_counts},
        "raw_runner": runner,
        "results": rows,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "okhttp_5.5.0_survival_from_urllib3_final_aggressive.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    lines = [
        "# OkHttp 5.5.0 aggressive survival from urllib3 final contracts",
        "",
        "- rule: raw target report counts unmapped as failed; canonical evaluator separates adapter blockage and feature absence",
        f"- total_urllib3_final_survivors: {len(rows)}",
        f"- okhttp_survived_aggressive: {counts['passed']}",
        f"- okhttp_failed_aggressive: {len(rows) - counts['passed']}",
        f"- adapter_tests: {len(runner['tests'])} total, {raw_counts['passed']} passed, {raw_counts['failed']} failed",
        "",
        "## Adapter Test Failures",
        "",
        "| test | error |",
        "|---|---|",
    ]
    for test in runner["tests"]:
        if not test["passed"]:
            error = test["error"].replace("|", "\\|")
            lines.append(f"| `{test['name']}` | {error} |")
    lines += ["", "## Survived", "", "| source | contract | capability | okhttp_test |", "|---:|---|---|---|"]
    for row in rows:
        if row["okhttp_status"] == "passed":
            lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | `{row['okhttp_test']}` |")
    lines += ["", "## Failed", "", "| source | contract | capability | status | okhttp_test | error |", "|---:|---|---|---|---|---|"]
    for row in rows:
        if row["okhttp_status"] != "passed":
            err = row["error"].replace("|", "\\|")
            if len(err) > 160:
                err = err[:157] + "..."
            lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | `{row['okhttp_status']}` | `{row['okhttp_test']}` | {err} |")
    (OUT_DIR / "okhttp_5.5.0_survival_from_urllib3_final_aggressive.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"survived": counts["passed"], "failed": len(rows) - counts["passed"], "adapter_tests": payload["adapter_tests"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
