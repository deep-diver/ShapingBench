#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "contracts" / "okhttp" / "okhttp_origin_excluding_common.summary.json"
URLLIB3_COMMON = ROOT / "contracts" / "common" / "canonical_common_evaluation.json"
OUT_OKHTTP_SURVIVORS = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_survivors.json"
OUT_OKHTTP_SURVIVORS_MD = ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_survivors.md"
OUT_OKHTTP_COMMON = ROOT / "contracts" / "common" / "okhttp_origin_common_candidates.json"
OUT_OKHTTP_COMMON_MD = ROOT / "contracts" / "common" / "okhttp_origin_common_candidates.md"
OUT_MERGED = ROOT / "contracts" / "common" / "merged_common.json"
OUT_MERGED_MD = ROOT / "contracts" / "common" / "merged_common.md"


LATEST_OKHTTP_VERSION = "5.5.0"

LATEST_ABSENT_CAPABILITY_PREFIXES = (
    "http2.spdy",
    "http2.draft",
    "tls.npn",
)

LATEST_ABSENT_CAPABILITIES = {
    "http2.spdy31-support": "SPDY support does not survive in modern OkHttp 5.x.",
    "http2.spdy-client-stream-id": "SPDY support does not survive in modern OkHttp 5.x.",
    "http2.spdy-header-trailing-bytes": "SPDY support does not survive in modern OkHttp 5.x.",
    "http2.flow-control-spdy-window-size": "SPDY support does not survive in modern OkHttp 5.x.",
    "http2.draft09-support": "HTTP/2 draft-09 support does not survive in modern OkHttp 5.x.",
    "tls.npn.headers-fallback": "NPN support was replaced by ALPN and does not survive in modern OkHttp 5.x.",
    "tls.protocol-negotiation-no-npn": "This is a removal/negative NPN policy, not a portable positive client behavior.",
}

LATEST_NEEDS_PLATFORM_CAPABILITY_PREFIXES = (
    "tls.alpn.android",
    "tls.alpn.platform",
    "tls.alpn.closed-socket",
    "tls.socket-shutdown",
    "tls.conscrypt",
)

IMPLEMENTATION_SPECIFIC_PREFIXES = (
    "http.lifecycle.",
    "http.logging.",
    "http.dispatcher.",
    "http.test-server.",
)

IMPLEMENTATION_SPECIFIC_CAPABILITIES = {
    "http.lifecycle.call-tags",
    "http.request.curl-rendering",
    "http.connection.worker-interruption",
    "http.connection.pool-minimum",
    "http.url.public-suffix-failure",
    "http.url.top-private-domain-malformed-host",
    "http.call.interruption",
    "http.call.async-cancel",
    "http.call.cancel-callback",
    "http.call.async-uncaught-exception",
    "http.response.body-presence",
    "http.response.timing-metadata",
    "http.response.body-lifetime-after-callback",
    "http.response.byte-string",
    "http.cache.eager-initialize",
    "http.cache.lazy-initialize",
    "http.cache.journal-rebuild-failure",
    "http.cache.evict-while-update",
    "http.cache.iterator-incomplete-entry",
    "http.cache.pool-lifecycle-on-hit",
    "http.cache.key-override",
    "http.request.builder-url-reset",
    "http.interceptor.connection-access",
    "http.interceptor.response-body-close-contract",
    "http.interceptor.proceed-non-null",
    "http.interceptor.timeout-policy",
    "http.interceptor.retry-route-exhaustion",
    "http.interceptor.preconnect-ioexception",
    "http.interceptor.request-mutation",
    "http.interceptor.method-mutation",
    "http.proxy.selection-laziness",
    "http.proxy.selector-fallback",
    "http.proxy.connect-failed-callback",
    "http.proxy.selector-connection-pooling",
    "tls.private-key.validation",
    "tls.connection-spec-compatibility",
    "tls.connection-spec-default-ciphers",
    "tls.trust-manager.custom",
    "tls.certificate-pinning-inspection",
    "tls.certificate-pinning-chain",
    "tls.certificate-pinning-double-wildcard",
    "tls.certificate-pinning-sha256",
    "tls.certificate-pinning-no-pins",
    "tls.redirect.trust-all",
    "tls.sni.recorded-request",
    "tls.logging.handshake",
}

FEATURE_ABSENT_FOR_OTHER_CLIENTS_PREFIXES = (
    "http2.",
    "websocket.",
    "http.sse.",
)

FEATURE_ABSENT_FOR_OTHER_CLIENTS_CAPABILITIES = {
    "http.cache.key-override",
    "http.cache.corruption-handling",
    "http.cache.write-failure",
    "http.cache.redirect-lifecycle",
    "http.cache.private-response",
    "http.cache.default-cacheable-status",
    "http.cache.repeated-headers",
    "http.cache.iterator-incomplete-entry",
    "http.cache.immutable-directive",
    "http.cache.immutable-directive-freshness",
    "http.cache.304-content-encoding",
    "http.cache.non-ascii-etag",
    "http.cache.redirect-status-freshness",
    "http.dns.doh-cache-ttl",
    "http.dns.doh-query",
    "http.dns.literal-ip-bypass",
    "http.dns.invalid-host-bypass",
    "http.cookie.samesite",
    "http.cookie.public-suffix-rejection",
    "http.cookie.java-net-multiple-cookies",
    "tls.certificate-pinning-chain",
    "tls.certificate-pinning-double-wildcard",
    "tls.certificate-pinning-sha256",
    "tls.certificate-pinning-no-pins",
    "tls.certificate-pinning-inspection",
}

# These are OkHttp-origin contracts whose behavior is ordinary HTTP client
# surface in urllib3, Requests, and Axios. This is intentionally stricter than
# extraction: anything here should be easy to compile into local replay tests.
CROSS_COMMON_CAPABILITIES = {
    "http.request.options-body",
    "http.request.method-body-policy",
    "http.redirect.308-permanent",
    "http.redirect.307-308-nonstandard-method",
    "http.response.informational",
    "http.response.informational-100-continue",
    "http.response.brotli-empty-body",
    "http.url.empty-query-fragment",
    "http.url.encoded-query-plus-preservation",
    "http.url.fragment-non-ascii-preservation",
    "http.url.port-range",
    "http.url.scheme-validation",
    "http.request.form-urlencoded-space",
    "http.request.form-urlencoded-charset",
    "http.headers.null-values-ignored",
    "http.headers.unsafe-non-ascii-values",
    "http.headers.multimap-case-insensitive",
    "http.multipart.filename-encoding",
    "http.multipart.fixed-length-content-length",
    "http.multipart.response-streaming",
    "http.media-type.parameter-parsing",
    "http.proxy.tunnel-header-isolation",
    "http.cleartext-policy",
    "http.timeout.error-taxonomy-socket-timeout",
    "http.retry.retry-after",
    "http.retry.408-policy",
    "http.retry.no-timeout-retry",
}


def all_contracts(raw: dict) -> list[dict]:
    rows = []
    for release in raw["releases"]:
        for contract in release["contracts"]:
            row = dict(contract)
            row["source_project"] = "okhttp"
            row["source_version"] = release["version"]
            row["source_date"] = release["date"]
            row["key"] = f"okhttp:{release['version']}:{contract['name']}"
            rows.append(row)
    return rows


def latest_verdict(row: dict) -> tuple[str, str]:
    capability = row["capability"]
    if capability in LATEST_ABSENT_CAPABILITIES:
        return "fail_feature_absent", LATEST_ABSENT_CAPABILITIES[capability]
    if capability.startswith(LATEST_ABSENT_CAPABILITY_PREFIXES):
        return "fail_feature_absent", "Obsolete protocol surface does not survive in latest OkHttp."
    if capability.startswith(LATEST_NEEDS_PLATFORM_CAPABILITY_PREFIXES):
        return "blocked_platform", "Requires Android/provider-specific runtime not exercised by the local JVM latest replay."
    return "pass_release_lineage", "No later removal found in the OkHttp changelog; retained as latest survivor pending executable adapter coverage."


def portability(row: dict) -> tuple[str, str]:
    capability = row["capability"]
    if capability in IMPLEMENTATION_SPECIFIC_CAPABILITIES or capability.startswith(IMPLEMENTATION_SPECIFIC_PREFIXES):
        return "implementation_specific", "OkHttp API, lifecycle hook, logging, cache internals, or TLS helper surface."
    if capability.startswith(FEATURE_ABSENT_FOR_OTHER_CLIENTS_PREFIXES) or capability in FEATURE_ABSENT_FOR_OTHER_CLIENTS_CAPABILITIES:
        return "feature_absent_in_some_targets", "At least one of urllib3, Requests, or Axios lacks this native target surface."
    if capability in CROSS_COMMON_CAPABILITIES:
        return "portable_common_candidate", "Portable HTTP behavior suitable for cross-client replay."
    if capability.startswith(("http.url.", "http.request.", "http.response.", "http.redirect.", "http.proxy.", "http.timeout.", "http.retry.", "http.headers.", "http.multipart.")):
        return "needs_adapter_execution", "Looks portable, but not promoted to common without explicit cross-target replay mapping."
    if capability.startswith("tls."):
        return "needs_adapter_execution", "TLS behavior may be portable but needs cross-target replay mapping."
    return "needs_review", "No portability rule matched."


def target_verdict(row: dict, target: str, portability_kind: str) -> tuple[str, str]:
    capability = row["capability"]
    if portability_kind == "implementation_specific":
        return "implementation_specific", "Excluded before target evaluation."
    if portability_kind == "feature_absent_in_some_targets":
        return "fail_feature_absent", "Target set lacks the relevant surface in at least one non-OkHttp client."
    if portability_kind == "portable_common_candidate":
        return "pass_pending_adapter", "Portable candidate; not verified common until generated replay tests pass in this target."
    if capability.startswith("http2.") and target in {"requests", "axios"}:
        return "fail_feature_absent", f"{target} lacks native HTTP/2 client surface in the tested baseline."
    if capability.startswith("websocket.") and target in {"urllib3", "requests", "axios"}:
        return "fail_feature_absent", f"{target} is not a WebSocket client package."
    return "blocked_adapter", "No cross-target adapter mapping yet."


def make_latest_markdown(payload: dict) -> str:
    lines = [
        "# OkHttp-Origin Latest Survival",
        "",
        f"- raw_contracts: {payload['raw_contracts']}",
        f"- latest_okhttp_version: {payload['latest_okhttp_version']}",
        f"- latest_survivors: {payload['latest_survivors']}",
        f"- latest_non_survivors_or_blocked: {payload['latest_non_survivors_or_blocked']}",
        "",
        "## Verdict Counts",
        "",
        "| verdict | count |",
        "|---|---:|",
    ]
    for verdict, count in payload["latest_verdict_counts"].items():
        lines.append(f"| `{verdict}` | {count} |")
    lines += ["", "## Latest Survivors", "", "| release | contract | capability | verdict |", "|---:|---|---|---|"]
    for row in payload["results"]:
        if row["latest_survived"]:
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` | `{row['latest_verdict']}` |")
    return "\n".join(lines) + "\n"


def make_okhttp_common_markdown(payload: dict) -> str:
    lines = [
        "# OkHttp-Origin Common Evaluation",
        "",
        f"- latest_survivors: {payload['latest_survivors']}",
        f"- implementation_specific_excluded: {payload['implementation_specific_excluded']}",
        f"- okhttp_origin_common_verified: {payload['okhttp_origin_common_verified']}",
        f"- okhttp_origin_common_candidates_pending_adapter: {payload['okhttp_origin_common_candidates_pending_adapter']}",
        f"- blocked_adapter_or_review: {payload['blocked_adapter_or_review']}",
        "",
        "## Aggregate Counts",
        "",
        "| aggregate | count |",
        "|---|---:|",
    ]
    for aggregate, count in payload["aggregate_counts"].items():
        lines.append(f"| `{aggregate}` | {count} |")
    lines += ["", "## OkHttp-Origin Common Candidates Pending Adapter", "", "| release | contract | capability |", "|---:|---|---|"]
    for row in payload["results"]:
        if row["aggregate"] == "okhttp_origin_common_candidate_pending_adapter":
            lines.append(f"| {row['source_version']} | `{row['name']}` | `{row['capability']}` |")
    lines += ["", "## Adapter Backlog", "", "| capability | count |", "|---|---:|"]
    for capability, count in payload["adapter_backlog_by_capability"]:
        lines.append(f"| `{capability}` | {count} |")
    return "\n".join(lines) + "\n"


def make_merged_markdown(payload: dict) -> str:
    lines = [
        "# Merged Common",
        "",
        f"- urllib3_origin_common: {payload['urllib3_origin_common']}",
        f"- okhttp_origin_common: {payload['okhttp_origin_common']}",
        f"- okhttp_origin_common_candidates_pending_adapter: {payload['okhttp_origin_common_candidates_pending_adapter']}",
        f"- merged_common: {payload['merged_common']}",
        "",
        "## Contracts",
        "",
        "| origin | source | contract | capability |",
        "|---|---:|---|---|",
    ]
    for row in payload["results"]:
        lines.append(f"| `{row['origin']}` | {row['source_version']} | `{row['contract']}` | `{row['capability']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    raw = json.loads(RAW.read_text())
    rows = all_contracts(raw)

    latest_rows = []
    latest_counts = collections.Counter()
    for row in rows:
        verdict, reason = latest_verdict(row)
        latest_counts[verdict] += 1
        latest_row = dict(row)
        latest_row.update({
            "latest_okhttp_version": LATEST_OKHTTP_VERSION,
            "latest_verdict": verdict,
            "latest_reason": reason,
            "latest_survived": verdict.startswith("pass"),
        })
        latest_rows.append(latest_row)

    latest_survivors = [row for row in latest_rows if row["latest_survived"]]
    latest_payload = {
        "source_project": "okhttp",
        "source_baseline": str(RAW.relative_to(ROOT)),
        "latest_okhttp_version": LATEST_OKHTTP_VERSION,
        "latest_latest_source": "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp-jvm/maven-metadata.xml",
        "rule": "Raw OkHttp-origin contracts first pass through latest OkHttp survival before cross-client common evaluation.",
        "raw_contracts": len(rows),
        "latest_survivors": len(latest_survivors),
        "latest_non_survivors_or_blocked": len(rows) - len(latest_survivors),
        "latest_verdict_counts": dict(sorted(latest_counts.items())),
        "results": latest_rows,
    }

    OUT_OKHTTP_SURVIVORS.write_text(json.dumps(latest_payload, indent=2, sort_keys=True) + "\n")
    OUT_OKHTTP_SURVIVORS_MD.write_text(make_latest_markdown(latest_payload))

    common_rows = []
    aggregate_counts = collections.Counter()
    target_counts = {target: collections.Counter() for target in ("urllib3", "requests", "axios")}
    backlog = collections.Counter()
    for row in latest_survivors:
        portability_kind, portability_reason = portability(row)
        targets = {}
        for target in target_counts:
            verdict, reason = target_verdict(row, target, portability_kind)
            targets[target] = {"verdict": verdict, "reason": reason}
            target_counts[target][verdict] += 1
        if portability_kind == "implementation_specific":
            aggregate = "implementation_specific"
        elif all(t["verdict"] == "pass_executed" for t in targets.values()):
            aggregate = "okhttp_origin_common_verified"
        elif all(t["verdict"].startswith("pass") for t in targets.values()):
            aggregate = "okhttp_origin_common_candidate_pending_adapter"
        elif any(t["verdict"] == "blocked_adapter" for t in targets.values()):
            aggregate = "blocked_adapter_or_review"
            backlog[row["capability"]] += 1
        else:
            aggregate = "feature_absent_or_behavior_divergence"
        aggregate_counts[aggregate] += 1
        out = dict(row)
        out.update({
            "portability": portability_kind,
            "portability_reason": portability_reason,
            "targets": targets,
            "aggregate": aggregate,
        })
        common_rows.append(out)

    okhttp_common_verified = [row for row in common_rows if row["aggregate"] == "okhttp_origin_common_verified"]
    okhttp_common_candidates = [row for row in common_rows if row["aggregate"] == "okhttp_origin_common_candidate_pending_adapter"]
    common_payload = {
        "source_project": "okhttp",
        "source_baseline": str(OUT_OKHTTP_SURVIVORS.relative_to(ROOT)),
        "targets": ["urllib3", "requests", "axios"],
        "rule": "OkHttp-origin common requires latest OkHttp survival and executed pass verdict for urllib3, Requests, and Axios. pass_pending_adapter is only a candidate.",
        "latest_survivors": len(latest_survivors),
        "implementation_specific_excluded": aggregate_counts["implementation_specific"],
        "okhttp_origin_common_verified": len(okhttp_common_verified),
        "okhttp_origin_common_candidates_pending_adapter": len(okhttp_common_candidates),
        "blocked_adapter_or_review": aggregate_counts["blocked_adapter_or_review"],
        "aggregate_counts": dict(sorted(aggregate_counts.items())),
        "target_verdict_counts": {target: dict(sorted(counts.items())) for target, counts in target_counts.items()},
        "adapter_backlog_by_capability": backlog.most_common(),
        "results": common_rows,
    }
    OUT_OKHTTP_COMMON.write_text(json.dumps(common_payload, indent=2, sort_keys=True) + "\n")
    OUT_OKHTTP_COMMON_MD.write_text(make_okhttp_common_markdown(common_payload))

    urllib3_common = json.loads(URLLIB3_COMMON.read_text())
    urllib3_common_rows = [
        {
            "origin": "urllib3",
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
        }
        for row in urllib3_common["results"]
        if row["aggregate"] == "common_confirmed"
    ]
    okhttp_common_rows = [
        {
            "origin": "okhttp",
            "source_version": row["source_version"],
            "contract": row["name"],
            "capability": row["capability"],
            "key": row["key"],
        }
        for row in okhttp_common_verified
    ]
    merged = urllib3_common_rows + okhttp_common_rows
    merged_payload = {
        "rule": "merged_common = urllib3_origin_common union verified okhttp_origin_common. OkHttp-origin pending candidates are not included.",
        "urllib3_origin_common": len(urllib3_common_rows),
        "okhttp_origin_common": len(okhttp_common_rows),
        "okhttp_origin_common_candidates_pending_adapter": len(okhttp_common_candidates),
        "merged_common": len(merged),
        "inputs": {
            "urllib3_origin_common": str(URLLIB3_COMMON.relative_to(ROOT)),
            "okhttp_origin_common_candidates": str(OUT_OKHTTP_COMMON.relative_to(ROOT)),
        },
        "results": merged,
    }
    OUT_MERGED.write_text(json.dumps(merged_payload, indent=2, sort_keys=True) + "\n")
    OUT_MERGED_MD.write_text(make_merged_markdown(merged_payload))

    print(json.dumps({
        "raw_okhttp_origin": len(rows),
        "latest_survivors": len(latest_survivors),
        "latest_verdict_counts": latest_payload["latest_verdict_counts"],
        "okhttp_origin_common_verified": len(okhttp_common_rows),
        "okhttp_origin_common_candidates_pending_adapter": len(okhttp_common_candidates),
        "merged_common": len(merged),
        "adapter_backlog_or_review": common_payload["blocked_adapter_or_review"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
