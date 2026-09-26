#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
URLLIB3 = ROOT / "contracts" / "urllib3" / "final_survival_urllib3_2.7.0.json"
TARGETS = {
    "okhttp": ROOT / "contracts" / "okhttp" / "okhttp_5.5.0_survival_from_urllib3_final_aggressive.json",
    "requests": ROOT / "contracts" / "requests" / "requests_2.34.2_survival_from_urllib3_final_aggressive.json",
    "axios": ROOT / "contracts" / "axios" / "axios_1.19.0_survival_from_urllib3_final_aggressive.json",
}
OUT_DIR = ROOT / "contracts" / "common"

FEATURE_ABSENT_OVERRIDES = {
    ("okhttp", "0.3:redirect_consumes_retry_budget"): "OkHttp exposes redirect on/off but no urllib3-style per-request redirect retry budget of zero.",
    ("okhttp", "2.5.0:poolmanager_integer_retries_limits_redirects"): "OkHttp does not expose urllib3-style integer retry budget as redirect limit.",
    ("okhttp", "2.6.0:poolmanager_integer_retries_limits_redirects"): "OkHttp does not expose urllib3-style integer retry budget as redirect limit.",
    ("okhttp", "2.7.0:cross_host_redirect_strips_configured_sensitive_header"): "OkHttp does not expose urllib3-style configurable remove-headers-on-redirect policy.",
    ("requests", "2.7.0:cross_host_redirect_strips_configured_sensitive_header"): "Requests does not expose urllib3 Retry.remove_headers_on_redirect through its high-level redirect machinery.",
    ("okhttp", "2.2.3:http2_major_version_four_is_required"): "OkHttp does not depend on Python h2, so the urllib3 h2 major-version dependency contract has no target surface.",
    ("okhttp", "1.24:tls_sni_hostname_can_be_overridden"): "OkHttp does not expose a public per-call SNI hostname override separate from the request URL host.",
    ("requests", "1.14:socks_proxy_basic_request_succeeds"): "Requests SOCKS support requires the optional PySocks dependency, which is absent from the tested package environment.",
    ("requests", "1.20:socks_remote_dns_schemes_are_supported"): "Requests SOCKS support requires the optional PySocks dependency, which is absent from the tested package environment.",
    ("requests", "1.23:socks_proxy_auth_info_in_url_is_supported"): "Requests SOCKS support requires the optional PySocks dependency, which is absent from the tested package environment.",
    ("axios", "1.14:socks_proxy_basic_request_succeeds"): "Axios does not include a built-in SOCKS proxy agent in the tested package.",
    ("axios", "1.20:socks_remote_dns_schemes_are_supported"): "Axios does not include a built-in SOCKS proxy agent in the tested package.",
    ("axios", "1.23:socks_proxy_auth_info_in_url_is_supported"): "Axios does not include a built-in SOCKS proxy agent in the tested package.",
    ("okhttp", "1.23:socks_proxy_auth_info_in_url_is_supported"): "OkHttp supports SOCKS proxies through java.net.Proxy, but not urllib3-style SOCKS auth info embedded in a proxy URL.",
    ("axios", "2.6.0:streaming_decompression_bomb_guard_limits_output"): "Axios does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("axios", "2.6.3:streaming_decompression_bomb_guard_limits_output"): "Axios does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("axios", "2.7.0:streaming_decompression_bomb_guard_limits_output"): "Axios does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("okhttp", "2.6.0:streaming_decompression_bomb_guard_limits_output"): "OkHttp does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("okhttp", "2.6.3:streaming_decompression_bomb_guard_limits_output"): "OkHttp does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("okhttp", "2.7.0:streaming_decompression_bomb_guard_limits_output"): "OkHttp does not expose an urllib3-style bounded decoded-buffer streaming decompression guard.",
    ("okhttp", "1.25:encrypted_client_key_without_password_raises_ssl_error"): "OkHttp does not expose a PEM encrypted private-key loading API without going through JVM key-manager setup.",
    ("requests", "2.0.0:proxy_certificate_hostname_assertion_is_configurable"): "Requests does not expose urllib3's proxy_assert_hostname/proxy_assert_fingerprint controls through its high-level proxy API.",
    ("axios", "2.0.0:proxy_certificate_hostname_assertion_is_configurable"): "Axios does not expose urllib3-style HTTPS proxy certificate hostname assertion controls.",
    ("okhttp", "2.0.0:proxy_certificate_hostname_assertion_is_configurable"): "OkHttp does not expose urllib3-style HTTPS proxy certificate hostname assertion controls.",
}

RETRY_POLICY_FEATURE_ABSENT_CAPABILITIES = {
    "http.retry.retry-after",
    "http.retry.retry-after-cap",
    "http.retry.retry-after-date",
    "http.retry.retry-after-opt-out",
    "http.retry.retry-after-propagation",
    "http.retry.status-forcelist-budget",
    "http.retry.status-policy",
}

LOW_LEVEL_POOL_FEATURE_ABSENT_KEYS = {
    "0.3:pool_rejects_foreign_origin_requests",
    "2.7.0:relative_path_resembling_schemeless_uri_is_accepted",
}


def feature_absent_reason(target: str, key: str, capability: str) -> str | None:
    explicit = FEATURE_ABSENT_OVERRIDES.get((target, key))
    if explicit:
        return explicit
    if target in {"axios", "okhttp"} and capability in RETRY_POLICY_FEATURE_ABSENT_CAPABILITIES:
        return f"{target} does not expose urllib3-style configurable status/Retry-After retry policy."
    if target in {"axios", "requests"} and capability.startswith("http2."):
        return f"{target} does not provide native HTTP/2 client support in the tested package."
    if key in LOW_LEVEL_POOL_FEATURE_ABSENT_KEYS:
        return f"{target} does not expose urllib3-style low-level origin-bound pool/request-target API."
    return None


IMPLEMENTATION_SPECIFIC_CAPABILITIES = {
    "http.connection.identity",
    "http.connection.pool-key",
    "http.connection.state",
    "http.error.taxonomy",
    "http.headers.key-equivalence",
    "http.headers.merge-policy",
    "http.observability.debug-log",
    "http.pool.request-context",
    "http.request.blocksize",
    "http.response.close-policy",
    "http.response.decode-content-option",
    "http.response.decode-mode-consistency",
    "http.response.header-access",
    "http.response.read-buffered-semantics",
    "http.response.read-negative",
    "http.response.read-zero",
    "http.response.read1",
    "http.response.shutdown-lifecycle",
    "http.response.stream-zero",
    "http.retry.backoff",
    "http.retry.error-shape",
    "tls.error-taxonomy",
    "tls.keylogfile",
}

IMPLEMENTATION_SPECIFIC_CONTRACTS = {
    "cert_reqs_accepts_string_policy_values",
    "brotli_decoder_handles_objects_without_decompress_attr",
    "ca_certificate_directory_is_accepted",
    "body_is_not_written_after_server_closes_socket",
    "connection_is_discarded_after_read_error",
    "failed_connect_does_not_leak_socket",
    "fingerprint_or_hostname_failure_does_not_leak_socket",
    "https_proxy_to_http_target_is_not_marked_verified",
    "incorrect_proxy_scheme_raises_value_error",
    "incomplete_read_error_reports_excess_content",
    "ipvfuture_address_is_not_treated_as_ip_address",
    "pool_is_replenished_after_release_conn_false_error",
    "pool_block_true_full_pool_raises_full_pool_error",
    "poolmanager_many_origins_does_not_close_in_use_pools",
    "proxy_url_without_scheme_raises_actionable_error",
    "https_proxy_misconfiguration_reports_http_proxy_hint",
    "proxy_errors_wrap_connection_failures",
    "proxy_connection_exposes_tunneling_state",
    "proxy_connection_verification_state_is_boolean",
    "response_length_remaining_tracks_unread_body",
    "response_read_error_closes_original_response_and_connection",
    "skip_header_suppresses_automatic_headers",
    "socket_options_are_applied_before_connect",
    "system_cipher_suites_are_not_overridden_by_default",
    "https_loads_system_certs_when_no_ca_options_are_set",
    "ipv6_dns_is_disabled_when_ipv6_connections_are_unavailable",
    "tls13_post_handshake_auth_works_when_validation_disabled",
    "tunnel_scheme_controls_origin_tunnel_metadata",
    "url_parser_is_rfc3986_compliant",
}

PORTABLE_CONTRACT_NAME_OVERRIDES = {
    "url_scheme_and_host_are_normalized_lowercase": ("portable_core", "URL normalization behavior"),
}

CONNECTION_POLICY_CAPABILITIES = {
    "http.connection.pooling",
    "http.connection.pool-full",
    "http.connection.pool-replenishment",
    "http.connection.poolmanager-lifecycle",
    "http.connection.read-error-lifecycle",
    "http.connection.resource-lifecycle",
    "http.connection.socket-options",
    "http.connection.timeout-lifecycle",
    "http.connection.timeout-reset",
    "http.dns.ipv6",
    "http.request.broken-pipe",
    "http.redirect.connection-lifecycle",
}


def classify_portability(capability: str, contract: str) -> tuple[str, str]:
    if contract in PORTABLE_CONTRACT_NAME_OVERRIDES:
        return PORTABLE_CONTRACT_NAME_OVERRIDES[contract]
    if contract in IMPLEMENTATION_SPECIFIC_CONTRACTS:
        return "implementation_specific", "urllib3-specific API, dependency, diagnostic, or internal connection-state contract"
    if capability in IMPLEMENTATION_SPECIFIC_CAPABILITIES:
        return "implementation_specific", "urllib3/Python API or internal object contract"
    if capability.startswith("tls.") or capability.startswith("https."):
        return "portable_tls", "TLS/HTTPS behavior can be re-expressed for another HTTP client"
    if capability.startswith("http2."):
        return "portable_http2", "HTTP/2 behavior can be re-expressed for another HTTP client"
    if capability.startswith("http.proxy."):
        return "portable_proxy", "Proxy behavior can be re-expressed for another HTTP client"
    if capability.startswith("http.retry.") or capability in CONNECTION_POLICY_CAPABILITIES or capability.startswith("http.error."):
        return "portable_policy", "Client policy/error behavior can be re-expressed for another HTTP client"
    if capability.startswith((
        "http.chunked.",
        "http.headers.",
        "http.multipart.",
        "http.redirect.",
        "http.request.",
        "http.response.",
        "http.timeout.",
        "http.url.",
    )):
        return "portable_core", "HTTP wire/request/response behavior can be re-expressed"
    return "needs_review", "No portability rule matched"


def normalize_target_status(raw_status: str) -> str:
    if raw_status == "passed":
        return "pass"
    if raw_status == "failed":
        return "fail_behavior"
    if raw_status == "failed_absent_or_unmapped":
        return "blocked_adapter"
    return "blocked_adapter"


def aggregate(verdicts: list[str], portability: str) -> str:
    if portability == "implementation_specific":
        return "implementation_specific"
    if all(v == "pass" for v in verdicts):
        return "common_confirmed"
    if any(v == "blocked_adapter" for v in verdicts):
        if any(v in {"fail_behavior", "fail_feature_absent"} for v in verdicts):
            return "blocked_with_nonpass"
        return "blocked_adapter"
    if any(v == "fail_behavior" for v in verdicts):
        return "behavior_divergence"
    if any(v == "fail_feature_absent" for v in verdicts):
        return "feature_absent"
    return "blocked_adapter"


def load_target_results() -> dict[str, dict[str, dict]]:
    out = {}
    for target, path in TARGETS.items():
        data = json.loads(path.read_text())
        out[target] = {row["key"]: row for row in data["results"]}
    return out


def make_markdown(payload: dict) -> str:
    lines = [
        "# Canonical HTTP Common Contract Evaluation",
        "",
        "- verdict taxonomy: pass, fail_behavior, blocked_adapter, implementation_specific",
        "- blocked_adapter is not counted as library behavior failure",
        "",
        f"- total_urllib3_final_survivors: {payload['total_urllib3_final_survivors']}",
        f"- implementation_specific: {payload['implementation_specific']}",
        f"- portable_total: {payload['portable_total']}",
        f"- common_confirmed: {payload['common_confirmed']}",
        f"- behavior_divergence_no_blockers: {payload['behavior_divergence_no_blockers']}",
        f"- feature_absent_no_blockers: {payload['feature_absent_no_blockers']}",
        f"- blocked_adapter_or_mixed: {payload['blocked_adapter_or_mixed']}",
        "",
        "## Aggregate Verdicts",
        "",
        "| aggregate | count |",
        "|---|---:|",
    ]
    for name, count in payload["aggregate_counts"].items():
        lines.append(f"| `{name}` | {count} |")
    lines += [
        "",
        "## Target Verdict Counts",
        "",
        "| target | pass | fail_behavior | fail_feature_absent | blocked_adapter |",
        "|---|---:|---:|---:|---:|",
    ]
    for target, counts in payload["target_verdict_counts"].items():
        lines.append(
            f"| `{target}` | {counts.get('pass', 0)} | "
            f"{counts.get('fail_behavior', 0)} | {counts.get('fail_feature_absent', 0)} | {counts.get('blocked_adapter', 0)} |"
        )
    lines += [
        "",
        "## Confirmed Common",
        "",
        "| source | contract | capability |",
        "|---:|---|---|",
    ]
    for row in payload["results"]:
        if row["aggregate"] == "common_confirmed":
            lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` |")
    lines += [
        "",
        "## Behavior Divergence Without Adapter Blockers",
        "",
        "| source | contract | capability | pass | fail_behavior |",
        "|---:|---|---|---|---|",
    ]
    for row in payload["results"]:
        if row["aggregate"] == "behavior_divergence":
            passed = [t for t, v in row["targets"].items() if v["verdict"] == "pass"]
            failed = [t for t, v in row["targets"].items() if v["verdict"] == "fail_behavior"]
            lines.append(
                f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | "
                f"{','.join(passed) or '-'} | {','.join(failed) or '-'} |"
            )
    lines += [
        "",
        "## Adapter Coverage Backlog By Capability",
        "",
        "| capability | blocked contracts |",
        "|---|---:|",
    ]
    for capability, count in payload["adapter_backlog_by_capability"][:80]:
        lines.append(f"| `{capability}` | {count} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    source = json.loads(URLLIB3.read_text())
    survivors = [row for row in source["results"] if row["survived_latest"]]
    target_results = load_target_results()

    rows = []
    target_counts = {target: collections.Counter() for target in TARGETS}
    backlog_capabilities = collections.Counter()
    behavior_fail_capabilities = collections.Counter()

    for row in survivors:
        key = f"{row['source_version']}:{row['contract']}"
        portability, reason = classify_portability(row.get("capability", ""), row["contract"])
        targets = {}
        verdicts = []
        for target, by_key in target_results.items():
            target_row = by_key[key]
            raw_status = target_row.get(f"{target}_status", "")
            verdict = normalize_target_status(raw_status)
            absent_reason = feature_absent_reason(target, key, row.get("capability", ""))
            if absent_reason:
                verdict = "fail_feature_absent"
            if portability == "implementation_specific":
                verdict = "implementation_specific"
            targets[target] = {
                "raw_status": raw_status,
                "verdict": verdict,
                "test": target_row.get(f"{target}_test", ""),
                "error": absent_reason or target_row.get("error", ""),
            }
            if portability != "implementation_specific":
                target_counts[target][verdict] += 1
                verdicts.append(verdict)
        agg = aggregate(verdicts, portability)
        if portability != "implementation_specific":
            if any(v == "blocked_adapter" for v in verdicts):
                backlog_capabilities[row.get("capability", "")] += 1
            if any(v == "fail_behavior" for v in verdicts):
                behavior_fail_capabilities[row.get("capability", "")] += 1
        rows.append({
            "key": key,
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row.get("capability", ""),
            "portability": portability,
            "portability_reason": reason,
            "aggregate": agg,
            "targets": targets,
        })

    aggregate_counts = collections.Counter(row["aggregate"] for row in rows)
    portable_total = sum(1 for row in rows if row["portability"] != "implementation_specific")
    payload = {
        "source_project": "urllib3",
        "source_baseline": "contracts/urllib3/final_survival_urllib3_2.7.0.json",
        "targets": {target: str(path.relative_to(ROOT)) for target, path in TARGETS.items()},
        "total_urllib3_final_survivors": len(rows),
        "implementation_specific": aggregate_counts["implementation_specific"],
        "portable_total": portable_total,
        "common_confirmed": aggregate_counts["common_confirmed"],
        "behavior_divergence_no_blockers": aggregate_counts["behavior_divergence"],
        "feature_absent_no_blockers": aggregate_counts["feature_absent"],
        "blocked_adapter_or_mixed": aggregate_counts["blocked_adapter"] + aggregate_counts["blocked_with_nonpass"],
        "aggregate_counts": dict(sorted(aggregate_counts.items())),
        "target_verdict_counts": {target: dict(sorted(counts.items())) for target, counts in target_counts.items()},
        "adapter_backlog_by_capability": backlog_capabilities.most_common(),
        "behavior_failure_by_capability": behavior_fail_capabilities.most_common(),
        "results": rows,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "canonical_common_evaluation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    (OUT_DIR / "canonical_common_evaluation.md").write_text(make_markdown(payload))
    print(json.dumps({
        "total": payload["total_urllib3_final_survivors"],
        "implementation_specific": payload["implementation_specific"],
        "portable_total": payload["portable_total"],
        "common_confirmed": payload["common_confirmed"],
        "behavior_divergence_no_blockers": payload["behavior_divergence_no_blockers"],
        "feature_absent_no_blockers": payload["feature_absent_no_blockers"],
        "blocked_adapter_or_mixed": payload["blocked_adapter_or_mixed"],
        "aggregate_counts": payload["aggregate_counts"],
        "target_verdict_counts": payload["target_verdict_counts"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
