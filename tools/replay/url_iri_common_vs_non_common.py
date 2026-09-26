#!/usr/bin/env python3
"""Classify URL/IRI common vs non-common latest-surviving contracts."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "url_iri"
COMMON_JSON = BASE / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_JSON = BASE / "common" / "common_vs_non_common_classification.json"
OUT_MD = BASE / "common" / "common_vs_non_common_classification.md"

LATEST = {
    "whatwg-url": BASE / "whatwg-url" / "latest_replay_mutant_verified.json",
    "rust-url": BASE / "rust-url" / "latest_replay_mutant_verified.json",
    "yarl": BASE / "yarl" / "latest_replay_mutant_verified.json",
    "ada-url": BASE / "ada-url" / "latest_replay_mutant_verified.json",
    "curl": BASE / "curl" / "latest_replay_mutant_verified.json",
}

CATEGORY_ORDER = [
    "Core parse and serialization",
    "Validation and parse failure behavior",
    "Relative/base resolution and joining",
    "Component mutation and setters",
    "Host, authority, origin, and port semantics",
    "File, opaque, and non-special schemes",
    "Path normalization and path object operations",
    "Query and form parameter semantics",
    "Unicode, IDNA, and human-readable forms",
    "API helpers, diagnostics, and representation",
    "Other externally observable surface",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def slug_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(row.get(key, "")).lower()
        for key in ("capability", "op", "kind", "name")
    )


def category(row: dict[str, Any]) -> str:
    text = slug_text(row)
    cap = str(row.get("capability", "")).lower()
    name = str(row.get("name", "")).lower()
    if any(token in text for token in ["searchparam", "query_pairs", "form_urlencoded", "query.parse", "query.with", "update_query", "incremental-query", "mod_query", "query_view", "appendquery"]):
        return "Query and form parameter semantics"
    if "query" in cap and "parse-components" not in cap:
        return "Query and form parameter semantics"
    if any(token in text for token in ["join", "relative", "base", "path_div"]) and "relative-port" not in text:
        return "Relative/base resolution and joining"
    if any(token in text for token in ["setter", "set_component", "setpart", "modifier", "transform", "with_", "set-parts"]):
        return "Component mutation and setters"
    if any(token in text for token in ["parse-failure", "construct_failure", "validation", "can_parse", "valid-url", "host.validation", "parse_failure"]):
        return "Validation and parse failure behavior"
    if any(token in text for token in ["idna", "i18n", "puny", "unicode", "human", "domain_convert"]):
        return "Unicode, IDNA, and human-readable forms"
    if any(token in text for token in ["file", "opaque", "non-special", "cannot-be-a-base", "cannot_have", "data_url", "mailto"]):
        return "File, opaque, and non-special schemes"
    if any(token in text for token in ["host", "ipv4", "ipv6", "zone", "authority", "origin", "port", "socket-default", "netloc"]):
        return "Host, authority, origin, and port semantics"
    if any(token in text for token in ["path", "segment", "suffix", "name", "dedot", "normalization"]):
        return "Path normalization and path object operations"
    if any(token in text for token in ["error-reporting", "strerror", "lifecycle", "cleanup", "duplication", "compare", "object_tag", "static_presence", "percent_decode", "quote", "unquote", "bytes", "bool", "build", "component-offset", "components-and-types", "traits", "as-str"]):
        return "API helpers, diagnostics, and representation"
    if any(token in text for token in ["parse", "props", "url_constructor", "standard.parse-components", "api.constructor"]):
        return "Core parse and serialization"
    return "Other externally observable surface"


def compact_name(name: str) -> str:
    text = re.sub(r"^\d+(?:\.\d+)*:", "", name)
    return text[:76]


def example(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    first = rows[0]
    return f"`{first['origin']}:{compact_name(first['name'])}`"


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = (row["origin"], row["name"])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def interpretation(cat: str, common_count: int, non_count: int) -> str:
    if common_count and non_count:
        if common_count >= non_count:
            return "Broadly shared surface, with some edge/policy variants outside common."
        return "Shared core exists, but most contracts are edge cases or library-shaped APIs."
    if common_count:
        return "Only observed in the final common set after hidden filtering."
    return "Mostly implementation/API-specific or rejected by at least one hidden filter."


def main() -> None:
    common_data = load_json(COMMON_JSON)
    common_rows = common_data["final_common_contracts"]
    common_ids = {(row["origin"], row["name"]) for row in common_rows}

    all_rows = []
    for origin, path in LATEST.items():
        for contract in load_json(path)["survivors"]:
            all_rows.append({"origin": origin, **contract})
    unique_all_rows = dedupe_rows(all_rows)

    non_common_rows = [row for row in unique_all_rows if (row["origin"], row["name"]) not in common_ids]

    by_category: dict[str, dict[str, Any]] = {
        cat: {"common": [], "non_common": []}
        for cat in CATEGORY_ORDER
    }
    for row in common_rows:
        by_category.setdefault(category(row), {"common": [], "non_common": []})["common"].append(row)
    for row in non_common_rows:
        by_category.setdefault(category(row), {"common": [], "non_common": []})["non_common"].append(row)

    origin_raw_totals = Counter(row["origin"] for row in all_rows)
    origin_totals = Counter(row["origin"] for row in unique_all_rows)
    common_by_origin = Counter(row["origin"] for row in common_rows)
    non_common_by_origin = Counter(row["origin"] for row in non_common_rows)
    common_by_kind = Counter(row.get("kind") or row.get("op") for row in common_rows)
    non_common_by_op = Counter(row.get("op") for row in non_common_rows)

    rows = []
    for cat in CATEGORY_ORDER:
        common_bucket = by_category.get(cat, {}).get("common", [])
        non_bucket = by_category.get(cat, {}).get("non_common", [])
        rows.append(
            {
                "category": cat,
                "common": len(common_bucket),
                "non_common": len(non_bucket),
                "total": len(common_bucket) + len(non_bucket),
                "common_share": round(len(common_bucket) / (len(common_bucket) + len(non_bucket)), 4) if common_bucket or non_bucket else 0,
                "common_example": example(common_bucket),
                "non_common_example": example(non_bucket),
                "interpretation": interpretation(cat, len(common_bucket), len(non_bucket)),
            }
        )

    OUT_JSON.write_text(
        json.dumps(
            {
                "domain": "URL/IRI",
                "basis": "Final common is the de-duplicated Rank 1/2/3 actual cross-replay set that also replays on Rank 4/5. Non-common here means origin-extracted residual contracts: latest-surviving source contracts across Rank 1-5 whose own source contract identity is not in the final common source set.",
                "latest_survivor_raw_rows": len(all_rows),
                "latest_survivor_unique_total": len(unique_all_rows),
                "common_total": len(common_rows),
                "non_common_total": len(non_common_rows),
                "common_candidate_rows_before_dedupe": common_data.get("common_candidate_rows_before_dedupe"),
                "common_candidates_before_hidden_filter": common_data.get("common_candidates_before_hidden_filter"),
                "hidden_filter_failures": common_data.get("hidden_filter_failures"),
                "by_category": rows,
                "by_origin": {
                    origin: {
                        "latest_survivors": origin_totals[origin],
                        "latest_survivor_raw_rows": origin_raw_totals[origin],
                        "common": common_by_origin[origin],
                        "non_common": non_common_by_origin[origin],
                    }
                    for origin in LATEST
                },
                "common_by_kind": dict(common_by_kind),
                "non_common_by_op": dict(non_common_by_op),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    md = [
        "# URL/IRI Common vs Non-Common Classification",
        "",
        "Basis: final common is the de-duplicated Rank 1/2/3 actual cross-replay set that also replays on Rank 4/5. Non-common here means origin-extracted residual contracts: latest-surviving source contracts across Rank 1-5 whose own source contract identity is not in the final common source set.",
        "",
        "Important distinction: the final common suite is supported by every OSS by replay. It is not necessarily a subset of every OSS's own release-note-derived source corpus, so per-OSS origin residuals must not be read as implementation support counts.",
        "",
        "## Totals",
        "",
        "| Bucket | Count |",
        "| --- | ---: |",
        f"| Latest-surviving raw rows across 5 OSS | {len(all_rows)} |",
        f"| Latest-surviving unique source contracts across 5 OSS | {len(unique_all_rows)} |",
        f"| Raw common candidate rows before dedupe | {common_data.get('common_candidate_rows_before_dedupe')} |",
        f"| Unique common candidates before hidden filter | {common_data.get('common_candidates_before_hidden_filter')} |",
        f"| Final common | {len(common_rows)} |",
        f"| Origin-extracted non-common residual | {len(non_common_rows)} |",
        "",
        "## Implementation Support of Final Common",
        "",
        "| OSS | Final common replayed successfully |",
        "| --- | ---: |",
    ]
    for origin in LATEST:
        md.append(f"| `{origin}` | {len(common_rows)} |")
    md.extend([
        "",
        "## By Surface",
        "",
        "| Surface | Common | Non-common | Total | Common share | Common example | Non-common example | Reading |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
    ])
    for row in rows:
        md.append(
            f"| {row['category']} | {row['common']} | {row['non_common']} | {row['total']} | {row['common_share']:.1%} | {row['common_example']} | {row['non_common_example']} | {row['interpretation']} |"
        )
    md.extend(["", "## Origin Contribution and Extracted Residual", "", "| OSS | Raw latest rows | Unique latest contracts | Common source contribution | Origin-extracted non-common residual |", "| --- | ---: | ---: | ---: | ---: |"])
    for origin in LATEST:
        md.append(f"| `{origin}` | {origin_raw_totals[origin]} | {origin_totals[origin]} | {common_by_origin[origin]} | {non_common_by_origin[origin]} |")
    md.extend(["", "## Common by Kind", "", "| Kind | Count |", "| --- | ---: |"])
    for kind, count in common_by_kind.most_common():
        md.append(f"| `{kind}` | {count} |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"latest_survivor_raw_rows": len(all_rows), "latest_survivor_unique_total": len(unique_all_rows), "common_total": len(common_rows), "non_common_total": len(non_common_rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
