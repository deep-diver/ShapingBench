#!/usr/bin/env python3
"""Extract replayable URL/IRI contracts from ada-url/ada releases."""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".replay" / "url_iri" / "ada-meta"
RELEASES = META / "github_releases_ada.json"
TAGS = META / "github_tags_ada_page1.json"
RUNNER = ROOT / ".replay" / "url_iri" / "ada_url_runner_target" / "release" / "ada_url_runner"
OUT_DIR = ROOT / "contracts" / "url_iri" / "ada-url"
OUT_JSON = OUT_DIR / "all_releases_maximal_language_independent.summary.json"
OUT_RPL = OUT_DIR / "all_releases_maximal_language_independent.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


@dataclass(frozen=True)
class Seed:
    version: str
    name: str
    capability: str
    op: str
    params: dict[str, Any]
    evidence: str
    source: str = "release-notes+readme+public-tests"
    mutant: str = "mutate_expected_observation"


def version_key(tag: str) -> list[Any]:
    return [int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", tag.lstrip("v"))]


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def release_rows() -> list[dict[str, Any]]:
    releases = json.loads(RELEASES.read_text(encoding="utf-8"))
    tags = json.loads(TAGS.read_text(encoding="utf-8"))
    by_tag = {row["tag_name"]: row for row in releases}
    names = sorted({row["name"] for row in tags} | set(by_tag), key=version_key)
    return [
        {
            "version": name.lstrip("v"),
            "tag": name,
            "published_at": by_tag.get(name, {}).get("published_at"),
            "body": by_tag.get(name, {}).get("body") or "",
            "has_github_release": bool((by_tag.get(name, {}).get("body") or "").strip()),
        }
        for name in names
    ]


def ev(version: str, phrase: str) -> str:
    return f"ada-url/ada GitHub release v{version}: {phrase}"


def c(
    out: list[Seed],
    version: str,
    name: str,
    capability: str,
    op: str,
    params: dict[str, Any],
    phrase: str,
    *,
    source: str = "release-notes+readme+public-tests",
) -> None:
    out.append(Seed(version, f"{version}:{name}", capability, op, params, ev(version, phrase), source=source))


def seeds() -> list[Seed]:
    out: list[Seed] = []

    # v1 initial parser and mutating URL object public API.
    for raw in [
        "https://www.google.com",
        "HTTP://AMAZON.COM",
        "https://username:password@google.com:9090/search?query#hash",
        "e:@EEEEEEEEEE",
        "http://www.google.com/%X%",
        "http://www.google.com/%37/ /",
        "http://www.google.com/%37+/",
        "http://www.google+com/",
        "file:///tmp/mock/path",
        "something:/.//",
        "http://::@c@d:2",
        "data:space    ?test",
        "data:space    ?test#test",
        "http://0300.168.0xF0",
        "localhost:80",
        "http://foo/bar^baz",
    ]:
        c(out, "1.0.0", f"parse_public_components_{slug(raw)[:42]}", "ada.url.parse-components", "parse", {"input": raw, "base": "http://example.org/foo/bar" if raw == "http://::@c@d:2" else None}, "Initial public URL parser exposes canonical href, components, origin, host/scheme type and boolean has_* flags.", source="readme+basic-tests")

    for raw in ["", "#x", "http://www.google%X%.com/", "http://www.google com/", "http://1.1.1.256", "https://0.0.0.0x100/"]:
        c(out, "1.0.0", f"parse_failure_{slug(raw or 'empty')}", "ada.url.parse-failure", "parse", {"input": raw}, "Invalid URL strings return parse failure instead of a partially usable URL.", source="basic-tests")

    setter_cases = [
        ("set_username_password", "https://www.google.com", "username", "username"),
        ("set_password_after_username", "https://username@www.google.com", "password", "password"),
        ("set_protocol_wss", "https://www.google.com", "protocol", "wss"),
        ("set_host_domain", "https://www.google.com", "host", "github.com"),
        ("set_host_with_port", "https://yagiz.co", "host", "localhost:3000"),
        ("set_hostname_only", "https://localhost:3000/", "hostname", "domain.com"),
        ("set_port_8080", "https://www.google.com", "port", "8080"),
        ("clear_port", "https://example.com:8080", "port", None),
        ("set_pathname_long", "https://www.google.com", "pathname", "/my-super-long-path"),
        ("set_pathname_without_slash", "http://test.com:5/?param=1", "pathname", "path"),
        ("set_search_plain", "https://www.google.com", "search", "target=self"),
        ("set_search_with_question", "https://user:pass@example.com/path?before=yes#fragment", "search", "?same=value"),
        ("clear_search_preserves_opaque_path_space", "data:space    ?test#test", "search", ""),
        ("set_hash_plain", "https://www.google.com", "hash", "is-this-the-real-life"),
        ("clear_hash", "https://example.com/path#old", "hash", None),
        ("remove_username", "http://me@example.net", "username", ""),
        ("remove_password", "http://user:pass@example.net", "password", ""),
        ("remove_password_empty_username", "http://:pass@example.net", "password", ""),
        ("set_href_ipv4_legacy_parts", "file:///var/log/system.log", "href", "http://0300.168.0xF0"),
        ("set_href_bad_percent_path", "http://www.google.com/", "href", "http://www.google.com/%X%"),
    ]
    for name, raw, component, value in setter_cases:
        c(out, "1.0.0", name, "ada.url.setters", "set_component", {"input": raw, "component": component, "value": value}, "Setters mutate one component, report success/failure where applicable, and preserve the rest of the serialized URL.", source="readme+basic-tests")

    for name, raw, component, value in [
        ("set_host_fails_on_mailto", "mailto:a@b.com", "host", "something"),
        ("set_hostname_fails_on_mailto", "mailto:a@b.com", "hostname", "something"),
        ("set_protocol_fails_file_empty_host", "file:", "protocol", "https"),
        ("set_host_rejects_bad_percent", "http://www.google.com/", "host", "www.google%X%.com"),
        ("set_port_rejects_negative", "https://www.google.com", "port", "-1"),
        ("set_port_invalid80_keeps_empty", "fake://dummy.test", "port", "invalid80"),
        ("set_port_accepts_prefix_digits", "fake://dummy.test", "port", "80valid"),
        ("set_host_rejects_ipv6_bare_colons", "http://foo", "host", "::"),
    ]:
        c(out, "1.0.0", name, "ada.url.setter-failures", "set_component", {"input": raw, "component": component, "value": value}, "Failed setters return failure and leave the URL in a valid, predictable state.", source="basic-tests")

    # v2.0 dependency-free IDNA and richer component API.
    for mode, raw in [
        ("ascii", "meßagefactory.ca"),
        ("unicode", "xn--meagefactory-m9a.ca"),
        ("ascii", "εμπορικόσήμα.eu"),
        ("ascii", "faß.de"),
        ("unicode", "xn--fa-hia.de"),
        ("ascii", "ạ́"),
        ("ascii", "Ş́.example"),
    ]:
        c(out, "2.0.0", f"idna_{mode}_{slug(raw)}", "ada.idna.uts46", "idna", {"mode": mode, "input": raw}, "Ada v2 removed ICU dependency and exposes UTS #46-compatible to_ascii/to_unicode behavior.", source="release-notes+idna-tests")

    for raw in [
        "https://user:pass@example.com:1234/foo/bar?baz#quux",
        "http://localhost:3000",
        "http://0.0.0.0",
        "http://[2001:db8:3333:4444:5555:6666:7777:8888]",
        "ftp://example.com/path",
        "wss://example.com/socket",
        "file:///tmp/foo",
        "git://example.com/",
    ]:
        c(out, "2.0.0", f"component_offsets_and_types_{slug(raw)[:38]}", "ada.url.components-and-types", "parse", {"input": raw}, "URL exposes serialization-free component offsets plus host_type and scheme_type classification.", source="rust-binding-tests")

    # can_parse and parse consistency.
    for raw, base in [
        ("https://www.yagiz.co", None),
        ("/hello", "https://yagiz.co"),
        ("/hello", "!!!!!!!1"),
        ("!!!", None),
        ("http://", None),
        ("http://?query", None),
        ("http:///path", None),
        ("http://example.com:65536/", None),
        ("http://1.2.3.999/", None),
        ("http://%65xample.com/", None),
        ("ws:///host", None),
        ("http:////example.com", None),
        ("wss:///host/path", None),
        ("Ws://%2E", None),
        ("http://1%2E2%2E3%2E4/", None),
        ("ws://%2F/", None),
        ("ws://1.2.3.4:+", None),
        ("ws://host:0000001/", None),
        ("ws://host:065535/", None),
        ("ws://host:065536/", None),
        ("ws:.", None),
        ("http:.", None),
        ("", "W:"),
    ]:
        c(out, "2.3.1", f"can_parse_consistency_{slug(raw or 'empty')[:46]}", "ada.url.can-parse", "can_parse", {"input": raw, "base": base}, "can_parse is an exposed validation API and must agree with full parser success/failure.", source="release-notes+basic-tests")

    # v2.5 origin standard change and host getter fixes.
    for raw in [
        "blob:https://example.com/foo",
        "blob:null/foo",
        "http://example.com/path",
        "https://example.com:443/path",
        "file:///tmp/foo",
        "mailto:a@b.com",
        "data:text/plain,hi",
        "http://:pass@example.net",
    ]:
        c(out, "2.5.0", f"origin_getter_{slug(raw)[:44]}", "ada.url.origin-and-host-flags", "parse", {"input": raw}, "Origin getter follows the current URL standard and empty/missing hosts expose stable host flags.", source="release-notes+basic-tests")

    # UrlSearchParams.
    search_param_cases = [
        ("append_duplicate_key", "", "key", [{"type": "append", "key": "key", "value": "value"}, {"type": "append", "key": "key", "value": "value2"}]),
        ("to_string_two_keys", "", "key1", [{"type": "append", "key": "key1", "value": "value1"}, {"type": "append", "key": "key2", "value": "value2"}]),
        ("accent_encoding", "", "key2", [{"type": "append", "key": "key1", "value": "été"}, {"type": "append", "key": "key2", "value": "Céline Dion++"}]),
        ("space_serialization", "", "a", [{"type": "append", "key": "a", "value": "b c"}]),
        ("plus_serialization", "", "a", [{"type": "append", "key": "a", "value": "b+c"}]),
        ("ampersand_serialization", "", "&", [{"type": "append", "key": "&", "value": "a"}, {"type": "append", "key": "b", "value": "&"}]),
        ("set_replaces_duplicates", "", "key1", [{"type": "append", "key": "key1", "value": "value1"}, {"type": "append", "key": "key1", "value": "value2"}, {"type": "set", "key": "key1", "value": "hello"}]),
        ("remove_key", "", "key1", [{"type": "append", "key": "key1", "value": "value1"}, {"type": "append", "key": "key1", "value": "value2"}, {"type": "append", "key": "key2", "value": "value2"}, {"type": "remove_key", "key": "key2"}]),
        ("remove_key_value", "", "key1", [{"type": "append", "key": "key1", "value": "value1"}, {"type": "append", "key": "key1", "value": "value2"}, {"type": "remove", "key": "key1", "value": "value2"}]),
        ("sort_ascii", "", "aaa", [{"type": "append", "key": "bbb", "value": "second"}, {"type": "append", "key": "aaa", "value": "first"}, {"type": "append", "key": "ccc", "value": "third"}, {"type": "sort"}]),
        ("sort_repeated_keys_stable", "z=b&a=b&z=a&a=a", "a", [{"type": "sort"}]),
        ("sort_empty_values", "bbb&bb&aaa&aa=x&aa=y", "aa", [{"type": "sort"}]),
        ("constructor_question_prefix", "?a=b", "a", []),
        ("constructor_without_value", "a=b&c", "c", []),
        ("constructor_edge_cases", "&a&&& &&&&&a+b=& c&m%c3%b8%c3%b8", "møø", []),
        ("contains_name_value", "key1=value1&key2=value2", "key1", []),
    ]
    for name, raw, probe, actions in search_param_cases:
        version = "2.6.1" if "contains" in name else "2.6.0"
        if "sort" in name:
            version = "2.7.0"
        c(out, version, f"url_search_params_{name}", "ada.url-search-params", "search_params", {"input": raw, "probe": probe, "actions": actions}, "UrlSearchParams parses, mutates, sorts, iterates and serializes form-urlencoded entries.", source="release-notes+rust-url-search-params-tests")

    for raw in ["http://example.com/path?k=v", "https://a.test/", "https://zoo.tld/", "https://c.tld/"]:
        c(out, "2.7.0", f"compare_hash_display_{slug(raw)}", "ada.url.traits", "parse", {"input": raw}, "Rust binding exposes Display/AsRef/Borrow-style canonical URL string behavior.", source="rust-binding-tests")
    c(out, "2.7.0", "compare_url_eq_true", "ada.url.traits", "compare", {"left": "http://example.com/", "right": "http://example.com/"}, "URL equality and ordering compare canonical href strings.", source="rust-binding-tests")
    c(out, "2.7.0", "compare_url_ordering", "ada.url.traits", "compare", {"left": "https://c.tld/", "right": "https://a.tld/"}, "URL equality and ordering compare canonical href strings.", source="rust-binding-tests")

    # v2.8-v3.4 regressions and API outcomes from release notes.
    for name, raw, component, value, version in [
        ("path_setter_blob_double_slash_dotdot", "blob:/?", "pathname", "//..", "2.8.0"),
        ("setter_boolean_return_host", "https://www.google.com", "host", "something", "2.9.2"),
        ("repeated_question_marks_two", "https://example.sub.com/??", "search", None, "3.2.8"),
        ("repeated_question_marks_three", "https://example.sub.com/???", "search", None, "3.2.8"),
        ("repeated_question_marks_four", "https://example.sub.com/????", "search", None, "3.2.8"),
        ("set_port_tab_newline_only", "https://example.com:80", "port", "\t\n", "3.2.5"),
        ("set_host_port_value", "https://example.com", "host", "example.org:8080", "3.2.5"),
        ("set_protocol_non_special_keeps_zero_port", "a://h:0", "protocol", "b", "4.0.0"),
        ("set_empty_host_non_special_without_authority", "non-special:/x", "host", "", "4.0.0"),
        ("failed_set_host_rolls_back_authorityless", "non-spec:/x", "host", "@\b[", "4.0.0"),
        ("canonicalize_search_keeps_delimiter", "https://example.com/path#fragment", "search", "?value='x y'", "4.0.0"),
        ("canonicalize_hash_keeps_delimiter", "https://example.com/path?query", "hash", "#frag ment", "4.0.0"),
        ("delete_dash_dot_host_with_port", "non-spec:/.//p", "host", "h:80", "4.0.0"),
    ]:
        params: dict[str, Any]
        if component is None:
            params = {"input": raw}
            op = "parse"
        else:
            params = {"input": raw, "component": component, "value": value}
            op = "set_component"
        c(out, version, name, "ada.release-regression.behavior", op, params, "Release-note regression fixes are observable through parser/setter href and component outcomes.", source="release-notes+basic-tests")

    for raw, version in [
        ("file:///foo/.bar/../baz.js", "3.4.3"),
        ("non-special:opaque  ", "3.2.2"),
        ("non-special:opaque  ?hi", "3.2.2"),
        ("non-special:opaque  #hi", "3.2.2"),
        ("http://%C3%A1%CC%A3/", "4.0.0"),
        ("https://%C5%9A%CC%A7.example/", "4.0.0"),
        ("http://0x0000000ff/", "4.0.0"),
        ("http://0x00000000ff/", "4.0.0"),
        ("http://0x100000000/", "4.0.0"),
        ("http://1234.5.6.7/", "4.0.0"),
        ("http://1..2.34/", "4.0.0"),
        ("http://12.34.56.78/", "4.0.0"),
        ("about:blank", "4.0.0"),
        ("http://\u200b123.123.123.123", "4.0.0"),
        ("https://non-ascii-location-header.sys.workers.dev/redirect", "3.0.0"),
    ]:
        c(out, version, f"release_regression_parse_{slug(raw)[:48]}", "ada.release-regression.parse", "parse", {"input": raw}, "Release-note and downstream regression cases remain externally visible through canonical href/component output.", source="release-notes+basic-tests+wpt")

    for raw, base, version in [
        ("/안녕", "https://non-ascii-location-header.sys.workers.dev/redirect", "3.0.0"),
        ("#f", "a:b", "4.0.0"),
        ("..#", "a:b", "4.0.0"),
        ("//evil.com/p", "about:blank", "4.0.0"),
        ("/etc/passwd#", "about:blank", "4.0.0"),
    ]:
        c(out, version, f"base_resolution_{slug(raw+'_'+base)[:48]}", "ada.url.base-resolution", "parse", {"input": raw, "base": base}, "Base URL resolution handles opaque-path bases and non-ASCII relative locations without crashes or authority confusion.", source="release-notes+basic-tests")

    for raw in [
        "http://foo_bar.example/path with spaces",
        "http://example.com./",
        "http://foo.0xffffffff/",
        "http://foo.0xfffffffff/",
        "http://0xffffffff/",
        "http://@19%2E68.1.10.",
        "http://19%2E68.1.10.",
        "http://19%2E68.1.10./x",
        "http://%31%2e%32%2e%33%2e%34/",
    ]:
        c(out, "4.0.0", f"canonicalize_host_fast_path_{slug(raw)[:48]}", "ada.url.host-canonicalization", "parse", {"input": raw}, "Fast host canonicalization must still apply IPv4 and IDNA semantics and agree with full parse.", source="release-notes+basic-tests")

    return out


def run(seed: Seed) -> dict[str, Any]:
    raw = subprocess.check_output(
        [str(RUNNER)],
        input=json.dumps({"op": seed.op, "params": seed.params}, ensure_ascii=False).encode(),
        cwd=ROOT,
    )
    return json.loads(raw)


def contract_to_rpl(contract: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {contract['name']} {{",
            f"  version = {json.dumps(contract['version'])}",
            f"  capability = {json.dumps(contract['capability'])}",
            f"  op = {json.dumps(contract['op'])}",
            f"  params = {json.dumps(contract['params'], ensure_ascii=False, sort_keys=True)}",
            f"  expect = {json.dumps(contract['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant = {json.dumps(contract['mutant'])}",
            "}",
        ]
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = release_rows()
    all_seeds = seeds()
    seen: set[tuple[str, str, str]] = set()
    contracts: list[dict[str, Any]] = []
    for seed in all_seeds:
        key = (seed.op, json.dumps(seed.params, ensure_ascii=False, sort_keys=True), seed.capability)
        if key in seen:
            continue
        seen.add(key)
        contracts.append(
            {
                "name": seed.name,
                "version": seed.version,
                "capability": seed.capability,
                "op": seed.op,
                "params": seed.params,
                "expected": run(seed),
                "mutant": seed.mutant,
                "evidence": seed.evidence,
                "source": seed.source,
                "pass": "maximal-language-independent-pass2",
            }
        )

    counts = Counter(contract["version"] for contract in contracts)
    by_capability = Counter(contract["capability"] for contract in contracts)
    by_op = Counter(contract["op"] for contract in contracts)
    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "ada-url/ada",
                "package": "ada-url",
                "latest_version_target": "4.0.0",
                "release_source": {
                    "github_releases": sum(1 for row in rows if row["has_github_release"]),
                    "github_tags": len(rows),
                },
                "contract_count": len(contracts),
                "contracts": contracts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(contract) for contract in contracts) + "\n", encoding="utf-8")

    md = [
        "# ada-url Release Contract Counts",
        "",
        f"- GitHub tags inspected: `{len(rows)}`",
        f"- GitHub releases with body text: `{sum(1 for row in rows if row['has_github_release'])}`",
        f"- Extracted replayable contracts: `{len(contracts)}`",
        "",
        "| Version | Published | GitHub body | Contracts |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in rows:
        md.append(f"| `{row['version']}` | {row['published_at'] or ''} | {'yes' if row['has_github_release'] else 'no'} | {counts[row['version']]} |")
    OUT_COUNTS.write_text("\n".join(md) + "\n", encoding="utf-8")

    audit = [
        "# ada-url Extraction Audit",
        "",
        "Two passes were applied to each release artifact:",
        "",
        "1. Release-note pass: public behavior changes and regression fixes were mapped to parser, setter, search-params, can_parse, IDNA and component-offset contracts.",
        "2. Fixture grounding pass: concrete inputs were selected from README examples, Rust binding tests, C++ basic tests and release-linked WPT regression fixtures.",
        "",
        "Excluded: performance-only, SIMD/CPU-specific, packaging, CI, docs-only, private ABI-only and URLPattern contracts not exposed by the Rust binding runner.",
        "",
        f"- Total replayable contracts: `{len(contracts)}`",
        f"- Latest target used to materialize expected observations: `ada-url==4.0.0` via Rust crate",
        "",
        "## By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for capability, count in by_capability.most_common():
        audit.append(f"| `{capability}` | {count} |")
    audit.extend(["", "## By Operation", "", "| Operation | Count |", "| --- | ---: |"])
    for op, count in by_op.most_common():
        audit.append(f"| `{op}` | {count} |")
    OUT_AUDIT.write_text("\n".join(audit) + "\n", encoding="utf-8")

    print(json.dumps({"contracts": len(contracts)}, sort_keys=True))


if __name__ == "__main__":
    main()
