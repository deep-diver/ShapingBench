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


IMPLEMENTATION_SPECIFIC_CAPABILITIES = {
    "http.connection.identity",
    "http.connection.pool-key",
    "http.connection.state",
    "http.error.taxonomy",
    "http.headers.key-equivalence",
    "http.headers.merge-policy",
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
    "url_scheme_and_host_are_normalized_lowercase": ("portable_core", "Contract is URL normalization even if source capability mentions pool-key"),
}

TLS_PREFIXES = ("tls.", "https.")
PROXY_PREFIXES = ("http.proxy.",)
HTTP2_PREFIXES = ("http2.",)
RETRY_PREFIXES = ("http.retry.",)
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
CORE_PREFIXES = (
    "http.chunked.",
    "http.headers.",
    "http.multipart.",
    "http.redirect.",
    "http.request.",
    "http.response.",
    "http.timeout.",
    "http.url.",
)


def classify(capability: str, contract: str = "") -> tuple[str, str]:
    if contract in PORTABLE_CONTRACT_NAME_OVERRIDES:
        return PORTABLE_CONTRACT_NAME_OVERRIDES[contract]
    if contract in IMPLEMENTATION_SPECIFIC_CONTRACTS:
        return "implementation_specific", "urllib3-specific API, dependency, diagnostic, or internal connection-state contract"
    if capability in IMPLEMENTATION_SPECIFIC_CAPABILITIES:
        return "implementation_specific", "urllib3/Python API or internal object contract"
    if capability.startswith(TLS_PREFIXES):
        return "portable_tls", "TLS/HTTPS behavior can be re-expressed for other clients"
    if capability.startswith(HTTP2_PREFIXES):
        return "portable_http2", "HTTP/2 behavior can be re-expressed for other clients"
    if capability.startswith(PROXY_PREFIXES):
        return "portable_proxy", "Proxy behavior can be re-expressed for other clients"
    if capability.startswith(RETRY_PREFIXES):
        return "portable_policy", "Retry policy behavior can be re-expressed for other clients"
    if capability in CONNECTION_POLICY_CAPABILITIES:
        return "portable_policy", "Connection/client policy behavior can be re-expressed for other clients"
    if capability.startswith(CORE_PREFIXES):
        return "portable_core", "HTTP wire/request/response behavior can be re-expressed for other clients"
    if capability.startswith("http.error."):
        return "portable_policy", "Network error behavior can be re-expressed as domain error-kind"
    if capability.startswith("http.observability."):
        return "implementation_specific", "Logging/observability formatting is library-specific"
    return "needs_review", "No classification rule matched"


def target_status(row: dict, target: str) -> str:
    return row.get(f"{target}_status", "missing")


def load_target_rows() -> dict[str, dict[str, dict]]:
    loaded: dict[str, dict[str, dict]] = {}
    for target, path in TARGETS.items():
        data = json.loads(path.read_text())
        loaded[target] = {row["key"]: row for row in data["results"]}
    return loaded


def main() -> int:
    urllib3 = json.loads(URLLIB3.read_text())
    survivors = [row for row in urllib3["results"] if row["survived_latest"]]
    target_rows = load_target_rows()

    rows = []
    for source in survivors:
        key = f"{source['source_version']}:{source['contract']}"
        portability, reason = classify(source.get("capability", ""), source["contract"])
        targets = {}
        for target, by_key in target_rows.items():
            target_row = by_key[key]
            targets[target] = {
                "status": target_status(target_row, target),
                "test": target_row.get(f"{target}_test", ""),
                "error": target_row.get("error", ""),
            }
        passed_targets = [target for target, status in targets.items() if status["status"] == "passed"]
        failed_targets = [target for target, status in targets.items() if status["status"] != "passed"]
        rows.append({
            "key": key,
            "source_version": source["source_version"],
            "contract": source["contract"],
            "capability": source.get("capability", ""),
            "portability": portability,
            "portability_reason": reason,
            "target_statuses": targets,
            "passed_target_count": len(passed_targets),
            "passed_targets": passed_targets,
            "failed_targets": failed_targets,
            "common_confirmed_all_targets": len(passed_targets) == len(TARGETS),
        })

    by_portability = collections.Counter(row["portability"] for row in rows)
    portable_rows = [row for row in rows if row["portability"] != "implementation_specific"]
    impl_rows = [row for row in rows if row["portability"] == "implementation_specific"]
    all_pass = [row for row in portable_rows if row["common_confirmed_all_targets"]]
    portable_not_all = [row for row in portable_rows if not row["common_confirmed_all_targets"]]
    by_pass_count = collections.Counter(row["passed_target_count"] for row in portable_rows)
    by_capability_gap = collections.Counter(row["capability"] for row in portable_not_all)

    payload = {
        "source_project": "urllib3",
        "source_baseline": "contracts/urllib3/final_survival_urllib3_2.7.0.json",
        "targets": {target: str(path.relative_to(ROOT)) for target, path in TARGETS.items()},
        "total_urllib3_final_survivors": len(rows),
        "implementation_specific_excluded": len(impl_rows),
        "portable_total": len(portable_rows),
        "portable_common_confirmed_all_targets": len(all_pass),
        "portable_not_common_confirmed": len(portable_not_all),
        "by_portability": dict(sorted(by_portability.items())),
        "portable_by_passed_target_count": {str(k): by_pass_count[k] for k in sorted(by_pass_count)},
        "largest_portable_gaps_by_capability": by_capability_gap.most_common(),
        "results": rows,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "http_client_common_contract_analysis.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    lines = [
        "# HTTP client common contract analysis",
        "",
        f"- total_urllib3_final_survivors: {len(rows)}",
        f"- implementation_specific_excluded: {len(impl_rows)}",
        f"- portable_total: {len(portable_rows)}",
        f"- portable_common_confirmed_all_targets: {len(all_pass)}",
        f"- portable_not_common_confirmed: {len(portable_not_all)}",
        "",
        "## By Portability",
        "",
        "| portability | count |",
        "|---|---:|",
    ]
    for portability, count in sorted(by_portability.items()):
        lines.append(f"| `{portability}` | {count} |")
    lines += [
        "",
        "## Portable By Passed Target Count",
        "",
        "| passed targets | portable contracts |",
        "|---:|---:|",
    ]
    for count in sorted(by_pass_count):
        lines.append(f"| {count} | {by_pass_count[count]} |")
    lines += [
        "",
        "## Confirmed Common Across OkHttp Requests Axios",
        "",
        "| source | contract | capability |",
        "|---:|---|---|",
    ]
    for row in all_pass:
        lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` |")
    lines += [
        "",
        "## Portable But Not Confirmed Common",
        "",
        "| source | contract | capability | passed | failed |",
        "|---:|---|---|---|---|",
    ]
    for row in portable_not_all:
        lines.append(
            f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | "
            f"{','.join(row['passed_targets']) or '-'} | {','.join(row['failed_targets']) or '-'} |"
        )
    lines += [
        "",
        "## Implementation Specific Excluded",
        "",
        "| source | contract | capability | reason |",
        "|---:|---|---|---|",
    ]
    for row in impl_rows:
        lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | {row['portability_reason']} |")
    (OUT_DIR / "http_client_common_contract_analysis.md").write_text("\n".join(lines) + "\n")

    print(json.dumps({
        "total": len(rows),
        "implementation_specific_excluded": len(impl_rows),
        "portable_total": len(portable_rows),
        "portable_common_confirmed_all_targets": len(all_pass),
        "portable_not_common_confirmed": len(portable_not_all),
        "portable_by_passed_target_count": payload["portable_by_passed_target_count"],
        "by_portability": payload["by_portability"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
