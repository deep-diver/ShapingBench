#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
LATEST_EXEC = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_executed_exhaustive.json"
PYTHON_REPLAY = ROOT / "contracts" / "common" / "okhttp_origin_python_cross_replay.json"
AXIOS_REPLAY = ROOT / "contracts" / "common" / "okhttp_origin_axios_cross_replay.json"
URLLIB3_COMMON = ROOT / "contracts" / "common" / "canonical_common_evaluation.json"
OUT = ROOT / "contracts" / "common" / "okhttp_origin_common_exhaustive.json"
OUT_MD = ROOT / "contracts" / "common" / "okhttp_origin_common_exhaustive.md"
MERGED = ROOT / "contracts" / "common" / "merged_common_exhaustive.json"
MERGED_MD = ROOT / "contracts" / "common" / "merged_common_exhaustive.md"


NON_PORTABLE_CAPABILITY_PREFIXES = (
    "http2.",
    "websocket.",
    "http.sse.",
    "http.lifecycle.",
    "http.interceptor.",
    "http.logging.",
    "http.dispatcher.",
)

NON_PORTABLE_CAPABILITIES = {
    "http.cache.key-override",
    "http.cache.corruption-handling",
    "http.cache.write-failure",
    "http.cache.repeated-headers",
    "http.cache.iterator-incomplete-entry",
    "http.cache.immutable-directive",
    "http.cache.304-content-encoding",
    "http.cache.non-ascii-etag",
    "http.cache.journal-rebuild-failure",
    "http.cache.evict-while-update",
    "http.cache.pool-lifecycle-on-hit",
    "http.cache.redirect-lifecycle",
    "http.cache.eager-initialize",
    "http.cache.vary-header-preservation",
    "http.cache.error-taxonomy",
    "http.cache.lazy-initialize",
    "http.cache.private-response",
    "http.cache.default-cacheable-status",
    "http.cache.redirect-status-freshness",
    "http.cache.rewritten-request-headers",
    "http.cache.spdy-premature-close",
    "http.dns.doh-cache-ttl",
    "http.dns.doh-query",
    "http.cookie.samesite",
    "http.cookie.public-suffix-rejection",
    "tls.certificate-pinning-chain",
    "tls.certificate-pinning-double-wildcard",
    "tls.certificate-pinning-sha256",
    "tls.certificate-pinning-no-pins",
    "tls.certificate-pinning-inspection",
    "http.cleartext-policy",
    "http.media-type.parameter-parsing",
    "http.multipart.response-streaming",
    "http.response.brotli-empty-body",
    "http.response.zstd-decoding",
    "http.auth.exception-connection-release",
    "http.auth.null-default-authenticator",
    "http.cache.conditional-header-precedence",
    "http.cache.http-to-https-redirect",
    "http.cache.immutable-directive-freshness",
    "http.cache-control.semicolon-separator",
    "http.call.async-uncaught-exception",
    "http.call.cancel-callback",
    "http.call.cancel-failure-leak",
    "http.connection.exception-priority",
    "http.connection.fast-fallback",
    "http.connection.fast-fallback-race",
    "http.connection.health-check",
    "http.connection.pooled-timeout-isolation",
    "http.connection.route-failure-diagnostics",
    "http.connection.route-recovery",
    "http.connection.socket-factory-direct",
    "http.cookie.ipv6-host",
    "http.cookie.java-net-multiple-cookies",
    "http.cookie.parser-robustness",
    "http.dns.invalid-host-bypass",
    "http.dns.literal-ip-bypass",
    "http.headers.sensitive-redaction",
    "http.multipart.body-lifecycle",
    "http.multipart.content-length-policy",
    "http.proxy.authenticator-selection",
    "http.proxy.connect-failed-callback",
    "http.proxy.connect-robustness",
    "http.proxy.connection-pool-sharing",
    "http.proxy.numeric-address-no-reverse-dns",
    "http.proxy.selection-laziness",
    "http.proxy.selector-connection-pooling",
    "http.proxy.socks-remote-dns",
    "http.proxy.tunnel-truncated-response",
    "http.redirect.route-retention",
    "http.request.builder-url-reset",
    "http.request.write-failure-response",
    "http.response.body-lifetime-after-callback",
    "http.response.gzip-lifecycle",
    "http.response.informational-trailer-boundary",
    "http.response.timing-metadata",
    "http.response.trailers-after-body",
    "http.response.trailers-empty-body",
    "http.response.trailers-peek",
    "http.retry.file-body-failure",
    "http.retry.one-shot-body",
    "http.url.top-private-domain-malformed-host",
    "http.timeout.abort",
    "http.timeout.long-lived-connect",
    "http.timeout.redirect-whole-call",
    "http.timeout.request-body-lifecycle",
    "http.timeout.scheduler",
    "http.upgrade.socket",
    "https.request.streaming-upload",
    "tls.alpn.connection-leak",
    "tls.alpn.resumed-session-protocol",
    "tls.cipher-defaults-no-dss",
    "tls.cipher-precedence",
    "tls.connection-spec-compatibility",
    "tls.connection-spec-default-ciphers",
    "tls.fallback-scsv",
    "tls.handshake-empty-peer-certificates",
    "tls.hostname-verification-insecure-host-allowlist",
    "tls.hostname-verification-no-cn-fallback",
    "tls.hostname-verification-non-ascii",
    "tls.hostname-verifier-connection-reuse",
    "tls.logging.handshake",
    "tls.private-key.validation",
    "tls.redirect.trust-all",
    "tls.sni.recorded-request",
    "tls.sni.server-name",
    "tls.socket-factory-validation",
    "tls.trust-manager.custom",
    "tls.version-defaults",
    "tls.version-preference",
}

SEMANTIC_ALIASES = {
    "same_origin_requests_reuse_one_connection": "connection.pooling.same-origin-reuse",
    "same_origin_sequential_requests_reuse_one_connection": "connection.pooling.same-origin-reuse",
    "slow_response_exceeding_socket_timeout_fails": "timeout.read-timeout-error",
    "read_timeout_is_wrapped_as_timeout_error": "timeout.read-timeout-error",
    "timeout_errors_use_socket_timeout_taxonomy": "timeout.read-timeout-error",
}


def semantic_key(name: str) -> str:
    name = re.sub(r"_\d+$", "", name)
    return SEMANTIC_ALIASES.get(name, name)


def cross_verdict(name: str, target: str, python_replay: dict, axios_replay: dict) -> dict:
    if target in {"urllib3", "requests"}:
        row = python_replay["tests"].get(target, {}).get(name)
    else:
        row = axios_replay["tests"].get(name)
    if row is None:
        return {"verdict": "not_executed", "error": "no cross-target adapter test executed"}
    return {"verdict": "pass_executed" if row["passed"] else "fail_behavior", "error": row.get("error", "")}


def is_non_portable(row: dict) -> bool:
    capability = row["capability"]
    return capability in NON_PORTABLE_CAPABILITIES or capability.startswith(NON_PORTABLE_CAPABILITY_PREFIXES)


def make_markdown(payload: dict) -> str:
    lines = [
        "# OkHttp-Origin Common Exhaustive Evaluation",
        "",
        f"- source_latest_survivor_rows: {payload['source_latest_survivor_rows']}",
        f"- okhttp_latest_executed_pass_rows: {payload['okhttp_latest_executed_pass_rows']}",
        f"- okhttp_latest_executed_fail_rows: {payload['okhttp_latest_executed_fail_rows']}",
        f"- okhttp_latest_not_executed_rows: {payload['okhttp_latest_not_executed_rows']}",
        f"- common_confirmed_rows: {payload['common_confirmed_rows']}",
        f"- behavior_divergence_rows: {payload['behavior_divergence_rows']}",
        f"- non_portable_rows: {payload['non_portable_rows']}",
        f"- cross_adapter_missing_rows: {payload['cross_adapter_missing_rows']}",
        "",
        "## Aggregate Counts",
        "",
        "| aggregate | rows |",
        "|---|---:|",
    ]
    for key, count in payload["aggregate_counts"].items():
        lines.append(f"| `{key}` | {count} |")
    lines += ["", "## Common Confirmed", "", "| release | contract | capability |", "|---:|---|---|"]
    for row in payload["results"]:
        if row["aggregate"] == "common_confirmed":
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` |")
    lines += ["", "## Latest OkHttp Failures", "", "| release | contract | capability | error |", "|---:|---|---|---|"]
    for row in payload["results"]:
        if row["aggregate"] == "okhttp_latest_fail":
            error = row["latest_execution_error"].replace("|", "\\|")
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` | {error} |")
    return "\n".join(lines) + "\n"


def make_merged_markdown(payload: dict) -> str:
    lines = [
        "# Merged Common Exhaustive",
        "",
        f"- fixed_urllib3_common_count: {payload['fixed_urllib3_common_count']}",
        f"- okhttp_origin_net_new_contracts: {payload['okhttp_origin_net_new_contracts']}",
        f"- legacy_row_level_count: {payload['legacy_row_level_count']}",
        f"- urllib3_origin_common_rows: {payload['urllib3_origin_common_rows']}",
        f"- urllib3_origin_unique_contracts: {payload['urllib3_origin_unique_contracts']}",
        f"- okhttp_origin_common_rows: {payload['okhttp_origin_common_rows']}",
        f"- okhttp_origin_unique_contracts: {payload['okhttp_origin_unique_contracts']}",
        f"- cross_origin_semantic_overlap: {payload['cross_origin_semantic_overlap']}",
        f"- fully_deduped_semantic_count_reference_only: {payload['fully_deduped_semantic_count_reference_only']}",
        f"- merged_common_exhaustive: {payload['merged_common_exhaustive']}",
        "",
        "| semantic_key | origins | rows |",
        "|---|---|---:|",
    ]
    for row in payload["results"]:
        lines.append(f"| `{row['semantic_key']}` | {', '.join(row['origins'])} | {row['row_count']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    latest = json.loads(LATEST_EXEC.read_text())
    python_replay = json.loads(PYTHON_REPLAY.read_text())
    axios_replay = json.loads(AXIOS_REPLAY.read_text())
    rows = []
    counts = collections.Counter()
    for row in latest["results"]:
        out = dict(row)
        latest_verdict = row["latest_execution_verdict"]
        if latest_verdict == "executed_fail":
            aggregate = "okhttp_latest_fail"
        elif latest_verdict == "not_executed":
            aggregate = "okhttp_latest_not_executed"
        elif is_non_portable(row):
            aggregate = "not_portable_for_cross_client_common"
        else:
            targets = {
                target: cross_verdict(row["name"], target, python_replay, axios_replay)
                for target in ("urllib3", "requests", "axios")
            }
            out["cross_targets"] = targets
            if all(target["verdict"] == "pass_executed" for target in targets.values()):
                aggregate = "common_confirmed"
            elif any(target["verdict"] == "fail_behavior" for target in targets.values()):
                aggregate = "behavior_divergence"
            else:
                aggregate = "cross_adapter_missing"
        out["aggregate"] = aggregate
        counts[aggregate] += 1
        rows.append(out)

    payload = {
        "rule": "Common is confirmed only from the 292-row latest-survivor ledger when latest OkHttp replay passes and urllib3, Requests, and Axios replay the same contract successfully.",
        "source_latest_survivor_rows": latest["source_latest_survivor_rows"],
        "okhttp_latest_executed_pass_rows": latest["executed_pass_rows"],
        "okhttp_latest_executed_fail_rows": latest["executed_fail_rows"],
        "okhttp_latest_not_executed_rows": latest["not_executed_rows"],
        "common_confirmed_rows": counts["common_confirmed"],
        "behavior_divergence_rows": counts["behavior_divergence"],
        "non_portable_rows": counts["not_portable_for_cross_client_common"],
        "cross_adapter_missing_rows": counts["cross_adapter_missing"],
        "aggregate_counts": dict(sorted(counts.items())),
        "results": rows,
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    OUT_MD.write_text(make_markdown(payload))

    urllib3_common = json.loads(URLLIB3_COMMON.read_text())
    urllib3_rows = [
        {
            "origin": "urllib3",
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
            "semantic_key": semantic_key(row["contract"]),
        }
        for row in urllib3_common["results"]
        if row["aggregate"] == "common_confirmed"
    ]
    okhttp_rows = [
        {
            "origin": "okhttp",
            "source_version": row["source_version"],
            "contract": row["name"],
            "capability": row["capability"],
            "key": row["key"],
            "semantic_key": semantic_key(row["name"]),
        }
        for row in rows
        if row["aggregate"] == "common_confirmed"
    ]
    grouped = collections.defaultdict(list)
    for row in urllib3_rows + okhttp_rows:
        grouped[row["semantic_key"]].append(row)
    merged = [
        {
            "semantic_key": key,
            "origins": sorted({member["origin"] for member in members}),
            "row_count": len(members),
            "members": members,
        }
        for key, members in sorted(grouped.items())
    ]
    urllib3_keys = {row["semantic_key"] for row in urllib3_rows}
    okhttp_keys = {row["semantic_key"] for row in okhttp_rows}
    merged_payload = {
        "rule": "The previously fixed urllib3-origin common set remains fixed at 89. merged_common_exhaustive = fixed urllib3 common count + net-new OkHttp-origin semantic additions.",
        "fixed_urllib3_common_count": len(urllib3_rows),
        "legacy_row_level_count": len(urllib3_rows) + len(okhttp_rows),
        "urllib3_origin_common_rows": len(urllib3_rows),
        "urllib3_origin_unique_contracts": len(urllib3_keys),
        "okhttp_origin_common_rows": len(okhttp_rows),
        "okhttp_origin_unique_contracts": len(okhttp_keys),
        "cross_origin_semantic_overlap": len(urllib3_keys & okhttp_keys),
        "okhttp_origin_net_new_contracts": len(okhttp_keys - urllib3_keys),
        "fully_deduped_semantic_count_reference_only": len(merged),
        "merged_common_exhaustive": len(urllib3_rows) + len(okhttp_keys - urllib3_keys),
        "results": merged,
    }
    MERGED.write_text(json.dumps(merged_payload, indent=2, sort_keys=True) + "\n")
    MERGED_MD.write_text(make_merged_markdown(merged_payload))
    print(json.dumps({
        "common_confirmed_rows": payload["common_confirmed_rows"],
        "behavior_divergence_rows": payload["behavior_divergence_rows"],
        "non_portable_rows": payload["non_portable_rows"],
        "cross_adapter_missing_rows": payload["cross_adapter_missing_rows"],
        "okhttp_latest_not_executed_rows": payload["okhttp_latest_not_executed_rows"],
        "merged_common_exhaustive": merged_payload["merged_common_exhaustive"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
