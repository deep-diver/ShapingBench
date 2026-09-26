#!/usr/bin/env python3
from __future__ import annotations

import collections
import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
URLLIB3_COMMON = ROOT / "contracts" / "common" / "canonical_common_evaluation.json"
OKHTTP_COMMON = ROOT / "contracts" / "common" / "okhttp_origin_common_exhaustive.json"
AXIOS_COMMON = ROOT / "contracts" / "axios" / "axios_origin_cross_latest_summary.json"
OUT = ROOT / "contracts" / "common" / "merged_common_semantic.json"
OUT_MD = ROOT / "contracts" / "common" / "merged_common_semantic.md"
FIXED_OUT = ROOT / "contracts" / "common" / "merged_common.json"
FIXED_OUT_MD = ROOT / "contracts" / "common" / "merged_common.md"


ALIASES = {
    "same_origin_requests_reuse_one_connection": "connection.pooling.same-origin-reuse",
    "same_origin_sequential_requests_reuse_one_connection": "connection.pooling.same-origin-reuse",
    "slow_response_exceeding_socket_timeout_fails": "timeout.read-timeout-error",
    "read_timeout_is_wrapped_as_timeout_error": "timeout.read-timeout-error",
    "timeout_errors_use_socket_timeout_taxonomy": "timeout.read-timeout-error",
    "get_set_cookie_returns_array": "multiple_set_cookie_headers_are_preserved",
}


def norm_name(name: str) -> str:
    name = re.sub(r"_\d+$", "", name)
    return ALIASES.get(name, name)


def family_key(capability: str) -> str:
    parts = capability.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:2] + [parts[2].split("-")[0]])
    return capability


def load_rows() -> list[dict]:
    urllib3 = json.loads(URLLIB3_COMMON.read_text())
    okhttp = json.loads(OKHTTP_COMMON.read_text())
    axios = json.loads(AXIOS_COMMON.read_text())
    rows = []
    for row in urllib3["results"]:
        if row["aggregate"] != "common_confirmed":
            continue
        rows.append({
            "origin": "urllib3",
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
        })
    for row in okhttp["results"]:
        if row["aggregate"] != "common_confirmed":
            continue
        rows.append({
            "origin": "okhttp",
            "source_version": row["source_version"],
            "contract": row["name"],
            "capability": row["capability"],
            "key": row["key"],
        })
    for row in axios["results"]:
        if row["verdict"] != "passed_both_latest":
            continue
        rows.append({
            "origin": "axios",
            "source_version": axios["summary"]["axios_latest_version"],
            "contract": row["name"],
            "capability": row["capability"],
            "key": f"axios:{axios['summary']['axios_latest_version']}:{row['name']}",
        })
    return rows


def representative(rows: list[dict], key_name: str) -> list[dict]:
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        grouped[row[key_name]].append(row)
    reps = []
    for key, members in sorted(grouped.items()):
        origins = sorted({member["origin"] for member in members})
        reps.append({
            "canonical_key": key,
            "origins": origins,
            "row_count": len(members),
            "members": members,
        })
    return reps


def markdown(payload: dict) -> str:
    lines = [
        "# Merged Common Semantic",
        "",
        f"- fixed_urllib3_common_count: {payload['fixed_urllib3_common_count']}",
        f"- okhttp_origin_unique_contracts: {payload['okhttp_origin_unique_contracts']}",
        f"- okhttp_origin_already_covered_by_fixed_urllib3: {payload['okhttp_origin_already_covered_by_fixed_urllib3']}",
        f"- okhttp_origin_net_new_contracts: {payload['okhttp_origin_net_new_contracts']}",
        f"- axios_origin_common_rows: {payload['axios_origin_common_rows']}",
        f"- axios_origin_already_covered_by_prior_merged: {payload['axios_origin_already_covered_by_prior_merged']}",
        f"- axios_origin_net_new_contracts: {payload['axios_origin_net_new_contracts']}",
        f"- merged_common_fixed_baseline_count: {payload['merged_common_fixed_baseline_count']}",
        f"- legacy_row_level_count: {payload['legacy_row_level_count']}",
        f"- fully_deduped_semantic_count_reference_only: {payload['fully_deduped_semantic_count_reference_only']}",
        f"- unique_capability_family_count: {payload['unique_capability_family_count']}",
        f"- cross_origin_exact_semantic_overlap: {payload['cross_origin_exact_semantic_overlap']}",
        f"- cross_origin_capability_family_overlap: {payload['cross_origin_capability_family_overlap']}",
        "",
        "## Exact Semantic Representatives",
        "",
        "| canonical_key | origins | rows |",
        "|---|---|---:|",
    ]
    for row in payload["unique_contract_semantic"]:
        lines.append(f"| `{row['canonical_key']}` | {', '.join(row['origins'])} | {row['row_count']} |")
    lines += [
        "",
        "## OkHttp-Origin Unique Additions",
        "",
        "| canonical_key | contract | capability | rows |",
        "|---|---|---|---:|",
    ]
    for row in payload["okhttp_origin_unique_additions"]:
        first = row["members"][0]
        lines.append(f"| `{row['canonical_key']}` | `{first['contract']}` | `{first['capability']}` | {row['row_count']} |")
    lines += [
        "",
        "## Axios-Origin Additions",
        "",
        "| canonical_key | contract | capability | rows | status |",
        "|---|---|---|---:|---|",
    ]
    for row in payload["axios_origin_additions"]:
        first = next(member for member in row["members"] if member["origin"] == "axios")
        status = "net-new" if row["canonical_key"] in payload["axios_origin_net_new_keys"] else "covered"
        lines.append(f"| `{row['canonical_key']}` | `{first['contract']}` | `{first['capability']}` | {row['row_count']} | {status} |")
    return "\n".join(lines) + "\n"


def fixed_markdown(payload: dict) -> str:
    lines = [
        "# Merged Common",
        "",
        f"- urllib3_origin_common: {payload['urllib3_origin_common_rows']}",
        f"- okhttp_origin_net_new: {payload['okhttp_origin_net_new_contracts']}",
        f"- axios_origin_common_rows: {payload['axios_origin_common_rows']}",
        f"- axios_origin_net_new: {payload['axios_origin_net_new_contracts']}",
        f"- merged_common: {payload['merged_common_fixed_baseline_count']}",
        "",
        "## Contracts",
        "",
        "| origin | source | contract | capability |",
        "|---|---:|---|---|",
    ]
    for row in payload["merged_common_fixed_baseline"]:
        lines.append(f"| `{row['origin']}` | {row['source_version']} | `{row['contract']}` | `{row['capability']}` |")
    lines += [
        "",
        "## Axios-Origin Passed Rows",
        "",
        "| status | contract | capability |",
        "|---|---|---|",
    ]
    for row in payload["axios_origin_additions"]:
        first = next(member for member in row["members"] if member["origin"] == "axios")
        status = "net-new" if row["canonical_key"] in payload["axios_origin_net_new_keys"] else "covered"
        lines.append(f"| {status} | `{first['contract']}` | `{first['capability']}` |")
    return "\n".join(lines) + "\n"


def main() -> int:
    rows = load_rows()
    for row in rows:
        row["semantic_key"] = norm_name(row["contract"])
        row["capability_family_key"] = family_key(row["capability"])

    urllib3_rows = [row for row in rows if row["origin"] == "urllib3"]
    okhttp_rows = [row for row in rows if row["origin"] == "okhttp"]
    axios_rows = [row for row in rows if row["origin"] == "axios"]

    semantic = representative(rows, "semantic_key")
    family = representative(rows, "capability_family_key")

    urllib3_semantic = {row["semantic_key"] for row in urllib3_rows}
    okhttp_semantic = {row["semantic_key"] for row in okhttp_rows}
    axios_semantic = {row["semantic_key"] for row in axios_rows}
    urllib3_family = {row["capability_family_key"] for row in urllib3_rows}
    okhttp_family = {row["capability_family_key"] for row in okhttp_rows}
    axios_family = {row["capability_family_key"] for row in axios_rows}
    prior_semantic = urllib3_semantic | okhttp_semantic

    okhttp_unique_additions = [
        row for row in semantic
        if row["canonical_key"] in (okhttp_semantic - urllib3_semantic)
        and any(member["origin"] == "okhttp" for member in row["members"])
    ]
    axios_additions = [
        row for row in semantic
        if row["canonical_key"] in axios_semantic
        and any(member["origin"] == "axios" for member in row["members"])
    ]
    axios_net_new = axios_semantic - prior_semantic

    payload = {
        "rule": "The previously fixed urllib3-origin common set remains fixed at 89. Semantic dedupe is used to decide how many OkHttp-origin and Axios-origin common contracts are net-new additions. Axios-origin additions are the contracts that passed Axios latest, urllib3 latest, and OkHttp latest cross replay.",
        "fixed_urllib3_common_count": len(urllib3_rows),
        "okhttp_origin_common_rows": len(okhttp_rows),
        "okhttp_origin_unique_contracts": len(okhttp_semantic),
        "okhttp_origin_already_covered_by_fixed_urllib3": len(okhttp_semantic & urllib3_semantic),
        "okhttp_origin_net_new_contracts": len(okhttp_semantic - urllib3_semantic),
        "axios_origin_common_rows": len(axios_rows),
        "axios_origin_unique_contracts": len(axios_semantic),
        "axios_origin_already_covered_by_prior_merged": len(axios_semantic & prior_semantic),
        "axios_origin_net_new_contracts": len(axios_net_new),
        "axios_origin_net_new_keys": sorted(axios_net_new),
        "merged_common_fixed_baseline_count": len(urllib3_rows) + len(okhttp_semantic - urllib3_semantic) + len(axios_net_new),
        "legacy_row_level_count": len(rows),
        "fully_deduped_semantic_count_reference_only": len(semantic),
        "unique_capability_family_count": len(family),
        "urllib3_origin_common_rows": len(urllib3_rows),
        "urllib3_origin_unique_contracts": len({row["semantic_key"] for row in urllib3_rows}),
        "cross_origin_exact_semantic_overlap": len((urllib3_semantic & okhttp_semantic) | (urllib3_semantic & axios_semantic) | (okhttp_semantic & axios_semantic)),
        "cross_origin_capability_family_overlap": len((urllib3_family & okhttp_family) | (urllib3_family & axios_family) | (okhttp_family & axios_family)),
        "unique_contract_semantic": semantic,
        "unique_capability_family": family,
        "okhttp_origin_unique_additions": okhttp_unique_additions,
        "axios_origin_additions": axios_additions,
    }

    fixed_rows = list(urllib3_rows)
    fixed_rows += [
        next(member for member in row["members"] if member["origin"] == "okhttp")
        for row in okhttp_unique_additions
    ]
    fixed_rows += [
        next(member for member in row["members"] if member["origin"] == "axios")
        for row in axios_additions
        if row["canonical_key"] in axios_net_new
    ]
    payload["merged_common_fixed_baseline"] = fixed_rows
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    OUT_MD.write_text(markdown(payload))
    fixed_payload = {
        "rule": payload["rule"],
        "urllib3_origin_common": payload["urllib3_origin_common_rows"],
        "okhttp_origin_net_new": payload["okhttp_origin_net_new_contracts"],
        "axios_origin_common_rows": payload["axios_origin_common_rows"],
        "axios_origin_net_new": payload["axios_origin_net_new_contracts"],
        "axios_origin_already_covered_by_prior_merged": payload["axios_origin_already_covered_by_prior_merged"],
        "merged_common": payload["merged_common_fixed_baseline_count"],
        "results": fixed_rows,
        "axios_origin_passed_rows": [
            next(member for member in row["members"] if member["origin"] == "axios")
            for row in axios_additions
        ],
    }
    FIXED_OUT.write_text(json.dumps(fixed_payload, indent=2, sort_keys=True) + "\n")
    FIXED_OUT_MD.write_text(fixed_markdown(payload))
    print(json.dumps({
        key: payload[key]
        for key in (
            "fixed_urllib3_common_count",
            "okhttp_origin_unique_contracts",
            "okhttp_origin_already_covered_by_fixed_urllib3",
            "okhttp_origin_net_new_contracts",
            "axios_origin_common_rows",
            "axios_origin_already_covered_by_prior_merged",
            "axios_origin_net_new_contracts",
            "merged_common_fixed_baseline_count",
            "legacy_row_level_count",
            "fully_deduped_semantic_count_reference_only",
            "unique_capability_family_count",
            "cross_origin_exact_semantic_overlap",
            "cross_origin_capability_family_overlap",
        )
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
