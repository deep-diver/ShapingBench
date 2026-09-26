#!/usr/bin/env python3
"""Extract URL/IRI contracts from servo/rust-url release history.

The rust-url GitHub releases are sparse before v2.4, so this extractor combines:

* crates.io version history and GitHub release bodies;
* public migration examples from UPGRADING.md;
* release-bundled WHATWG URL WPT fixtures from each version tag.

The WPT fixtures are external parser/setter contracts: input URL/reference plus
observable serialized URL component results.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
META_DIR = ROOT / ".replay" / "url_iri"
CRATES_META = META_DIR / "crates_url.json"
GITHUB_RELEASES = META_DIR / "github_releases_rust_url.json"
REPO = META_DIR / "rust-url-repo"
OUT_DIR = ROOT / "contracts" / "url_iri" / "rust-url"
OUT_JSON = OUT_DIR / "all_releases_maximal_language_independent.summary.json"
OUT_RPL = OUT_DIR / "all_releases_maximal_language_independent.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


WPT_URL_PATHS = [
    "url/tests/urltestdata.json",
    "tests/urltestdata.json",
]
WPT_SETTER_PATHS = [
    "url/tests/setters_tests.json",
    "tests/setters_tests.json",
]


@dataclass(frozen=True)
class Contract:
    name: str
    version: str
    capability: str
    op: str
    params: dict[str, Any]
    expected: dict[str, Any]
    mutant: str
    evidence: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "capability": self.capability,
            "op": self.op,
            "params": self.params,
            "expected": self.expected,
            "mutant": self.mutant,
            "evidence": self.evidence,
            "source": self.source,
        }


def semver_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def slug(text: str, limit: int = 70) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return text[:limit].strip("_") or "contract"


def git_show(tag: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(REPO), "show", f"v{tag}:{path}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def load_release_context() -> tuple[list[dict[str, Any]], dict[str, str]]:
    crates = json.loads(CRATES_META.read_text(encoding="utf-8"))
    releases = json.loads(GITHUB_RELEASES.read_text(encoding="utf-8"))
    release_body = {
        rel["tag_name"].lstrip("v"): (rel.get("body") or "")
        for rel in releases
        if re.match(r"^v[0-9]", rel.get("tag_name", ""))
    }
    versions = sorted(
        crates["versions"],
        key=lambda row: semver_key(row["num"]),
    )
    return versions, release_body


def add(
    out: list[Contract],
    *,
    version: str,
    capability: str,
    op: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    mutant: str,
    evidence: str,
    source: str,
    name: str,
) -> None:
    out.append(
        Contract(
            name=f"{version}:{slug(name)}",
            version=version,
            capability=capability,
            op=op,
            params=params,
            expected=expected,
            mutant=mutant,
            evidence=evidence,
            source=source,
        )
    )


def expected_from_wpt_case(case: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "href",
        "origin",
        "protocol",
        "username",
        "password",
        "host",
        "hostname",
        "port",
        "pathname",
        "search",
        "hash",
    ]
    return {key: case[key] for key in keys if key in case}


def extract_wpt_url_cases(versions: list[dict[str, Any]]) -> list[Contract]:
    contracts: list[Contract] = []
    seen: set[str] = set()
    for row in versions:
        version = row["num"]
        body = None
        path = None
        for candidate in WPT_URL_PATHS:
            body = git_show(version, candidate)
            if body is not None:
                path = candidate
                break
        if body is None:
            continue
        try:
            cases = json.loads(body)
        except json.JSONDecodeError:
            continue
        for index, case in enumerate(cases):
            if not isinstance(case, dict) or "input" not in case:
                continue
            params = {"input": case["input"]}
            if case.get("base") is not None:
                params["base"] = case.get("base")
            if case.get("failure") is True or "href" not in case:
                op = "parse_failure"
                expected = {"ok": False}
                capability = "url.standard.parse-failure"
                mutant = "accept_invalid_url_reference"
            else:
                op = "parse_url"
                expected = expected_from_wpt_case(case)
                capability = "url.standard.parse-components"
                mutant = "serialize_or_component_mismatch"
            fingerprint = json.dumps([op, params, expected], ensure_ascii=False, sort_keys=True)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            add(
                contracts,
                version=version,
                capability=capability,
                op=op,
                params=params,
                expected=expected,
                mutant=mutant,
                evidence=f"Release tag v{version}: bundled WHATWG URL WPT fixture {path} case #{index}.",
                source="release-bundled-wpt-urltestdata",
                name=f"wpt_urltestdata_{index}_{case['input']}",
            )
    return contracts


def extract_wpt_setter_cases(versions: list[dict[str, Any]]) -> list[Contract]:
    contracts: list[Contract] = []
    seen: set[str] = set()
    for row in versions:
        version = row["num"]
        body = None
        path = None
        for candidate in WPT_SETTER_PATHS:
            body = git_show(version, candidate)
            if body is not None:
                path = candidate
                break
        if body is None:
            continue
        try:
            groups = json.loads(body)
        except json.JSONDecodeError:
            continue
        for attr, cases in groups.items():
            if attr == "comment" or not isinstance(cases, list):
                continue
            for index, case in enumerate(cases):
                if not isinstance(case, dict) or "href" not in case or "new_value" not in case:
                    continue
                params = {
                    "input": case["href"],
                    "component": attr,
                    "value": case["new_value"],
                    "mode": "quirks",
                }
                expected = dict(case.get("expected") or {})
                if not expected:
                    continue
                fingerprint = json.dumps([attr, params, expected], ensure_ascii=False, sort_keys=True)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                add(
                    contracts,
                    version=version,
                    capability=f"url.standard.setter.{attr}",
                    op="set_component",
                    params=params,
                    expected=expected,
                    mutant=f"setter_{attr}_does_not_follow_url_standard",
                    evidence=f"Release tag v{version}: bundled WHATWG URL setter WPT fixture {path} {attr} case #{index}.",
                    source="release-bundled-wpt-setters",
                    name=f"wpt_setter_{attr}_{index}_{case['href']}_{case['new_value']}",
                )
    return contracts


def extract_release_note_and_upgrade_contracts(release_body: dict[str, str]) -> list[Contract]:
    contracts: list[Contract] = []

    def ev(version: str, text: str) -> str:
        body = re.sub(r"\s+", " ", release_body.get(version, "")).strip()
        if body:
            return f"GitHub release v{version}: {text}"
        return f"UPGRADING.md / README public behavior for v{version}: {text}"

    # Baseline URL behavior exposed by the crate README and initial public API.
    add(contracts, version="0.1.0", capability="url.api.components", op="parse_url",
        params={"input": "https://user:pass@example.com:8443/a/b?x=1#frag"},
        expected={"scheme": "https", "protocol": "https:", "username": "user", "password": "pass", "host": "example.com:8443", "hostname": "example.com", "port": "8443", "pathname": "/a/b", "search": "?x=1", "hash": "#frag"},
        mutant="drop_or_misreport_url_components", evidence=ev("0.1.0", "URL parsing exposes observable components."), source="readme-initial-api", name="url_parse_exposes_all_components")
    add(contracts, version="0.1.0", capability="url.api.relative-requires-base", op="parse_failure",
        params={"input": "../main.css"}, expected={"ok": False, "errorContains": "RelativeUrlWithoutBase"},
        mutant="accept_relative_without_base", evidence=ev("0.1.0", "Relative URL references require a base URL."), source="readme-initial-api", name="relative_url_without_base_fails")
    add(contracts, version="0.1.0", capability="url.api.join", op="join",
        params={"base": "http://servo.github.io/rust-url/url/index.html", "input": "../main.css"},
        expected={"href": "http://servo.github.io/rust-url/main.css"}, mutant="join_ignores_parent_segment",
        evidence=ev("0.1.0", "Base URL join resolves relative references."), source="readme-initial-api", name="join_parent_relative_url")
    add(contracts, version="0.1.0", capability="url.api.cannot-be-a-base", op="parse_url",
        params={"input": "data:text/plain,Hello?World#"},
        expected={"cannot_be_a_base": True, "scheme": "data", "pathname": "text/plain,Hello", "query": "World", "fragment": ""},
        mutant="treat_data_url_as_hierarchical", evidence=ev("0.1.0", "Data URLs are cannot-be-a-base URLs with opaque paths."), source="readme-initial-api", name="data_url_cannot_be_base")
    add(contracts, version="0.1.0", capability="url.api.parse-error", op="parse_failure",
        params={"input": "http://[:::1]"}, expected={"ok": False, "errorContains": "InvalidIpv6Address"},
        mutant="accept_invalid_ipv6_literal", evidence=ev("0.1.0", "Invalid IPv6 host syntax fails parsing."), source="readme-initial-api", name="invalid_ipv6_literal_fails")

    # Upgrading 0.x -> 1.x.
    add(contracts, version="1.0.0", capability="url.api.path-string-and-segments", op="parse_url",
        params={"input": "https://github.com/rust-lang/rust/issues?labels=E-easy&state=open"},
        expected={"pathname": "/rust-lang/rust/issues", "path_segments": ["rust-lang", "rust", "issues"]},
        mutant="path_returns_only_segments_or_only_string", evidence=ev("1.0.0", "path() returns string while path_segments() returns split segments."), source="upgrading-0-to-1", name="path_string_and_segments_both_observable")
    add(contracts, version="1.0.0", capability="url.api.path-segments-mut", op="path_segments_mut",
        params={"input": "https://github.com/rust-lang/rust", "actions": [{"type": "push", "value": "issues"}]},
        expected={"href": "https://github.com/rust-lang/rust/issues", "pathname": "/rust-lang/rust/issues"},
        mutant="path_segments_mut_does_not_append_segment", evidence=ev("1.0.0", "path_mut() was replaced by path_segments_mut()."), source="upgrading-0-to-1", name="path_segments_mut_push_appends_encoded_segment")
    add(contracts, version="1.0.0", capability="url.api.host-string", op="parse_url",
        params={"input": "http://example.com:8080/a"},
        expected={"hostname": "example.com", "host": "example.com:8080", "host_str": "example.com"},
        mutant="host_str_includes_port_or_omits_host", evidence=ev("1.0.0", "serialize_host() was replaced by host_str()."), source="upgrading-0-to-1", name="host_str_and_dom_host_are_distinct")
    add(contracts, version="1.0.0", capability="url.api.as-str", op="parse_url",
        params={"input": "http://servo.github.io/rust-url/url/index.html"},
        expected={"href": "http://servo.github.io/rust-url/url/index.html"},
        mutant="serialize_adds_or_removes_bytes", evidence=ev("1.0.0", "serialize() was replaced by as_str()."), source="upgrading-0-to-1", name="as_str_returns_serialization")
    add(contracts, version="1.0.0", capability="url.api.parse-path-workaround", op="join",
        params={"base": "http://example.com", "input": "/foo/bar/../baz?q=42"},
        expected={"pathname": "/foo/baz", "query": "q=42", "fragment": None},
        mutant="join_does_not_normalize_dot_segments", evidence=ev("1.0.0", "Removed parse_path() can be replaced by joining against a base URL."), source="upgrading-0-to-1", name="join_path_workaround_normalizes_dot_segment")
    add(contracts, version="1.0.0", capability="url.api.query-pairs-mut", op="query_pairs_mut",
        params={"input": "https://duckduckgo.com/", "actions": [{"type": "clear"}, {"type": "extend", "pairs": [["q", "test"], ["ia", "images"]]}]},
        expected={"href": "https://duckduckgo.com/?q=test&ia=images", "query": "q=test&ia=images", "search": "?q=test&ia=images"},
        mutant="query_pairs_mut_fails_to_replace_pairs", evidence=ev("1.0.0", "set_query_from_pairs() was replaced by query_pairs_mut()."), source="upgrading-0-to-1", name="query_pairs_mut_clear_extend_serializes_pairs")
    add(contracts, version="1.0.0", capability="url.api.cannot-be-a-base", op="parse_url",
        params={"input": "mailto:user@example.com"},
        expected={"cannot_be_a_base": True, "path_segments": None, "pathname": "user@example.com"},
        mutant="mailto_exposes_path_segments", evidence=ev("1.0.0", "cannot_be_a_base() replaces removed SchemeData matching."), source="upgrading-0-to-1", name="mailto_cannot_be_base_has_no_path_segments")
    add(contracts, version="1.0.0", capability="url.api.port-default", op="parse_url",
        params={"input": "http://github.com:80/"},
        expected={"port": "", "port_number": None, "port_or_known_default": 80, "href": "http://github.com/"},
        mutant="default_port_remains_explicit", evidence=ev("1.0.0", "port_or_default() replacement observes known default ports."), source="upgrading-0-to-1", name="default_http_port_serializes_empty_but_known_default_is_80")
    add(contracts, version="1.0.0", capability="url.api.form-urlencode", op="form_urlencoded_serialize",
        params={"pairs": [["q", "hello world"], ["ia", "images"]]},
        expected={"value": "q=hello+world&ia=images"},
        mutant="form_serializer_uses_percent20_for_space", evidence=ev("1.0.0", "form_urlencoded::serialize() was replaced with Serializer."), source="upgrading-0-to-1", name="form_urlencoded_serializer_uses_plus_for_space")

    # Upgrading 1.x -> 2.x / 2.1+.
    add(contracts, version="2.1.0", capability="url.api.socket-default-port", op="parse_url",
        params={"input": "socks5://localhost"},
        expected={"scheme": "socks5", "port_or_known_default": None, "host": "localhost"},
        mutant="invent_known_default_for_unknown_scheme", evidence=ev("2.1.0", "socket_addrs accepts caller supplied default ports for schemes like socks5."), source="upgrading-1-to-2", name="unknown_scheme_has_no_known_default_port")

    # Recent release-note behaviors.
    add(contracts, version="2.4.0", capability="url.api.authority", op="parse_url",
        params={"input": "https://user:pass@example.com:9443/a"},
        expected={"authority": "user:pass@example.com:9443"},
        mutant="authority_omits_credentials_or_port", evidence=ev("2.4.0", "url: add the authority method."), source="github-release-note", name="authority_includes_userinfo_host_and_port")
    add(contracts, version="2.4.0", capability="url.opaque-path.spaces", op="parse_url",
        params={"input": "mailto:user@example.com "},
        expected={"href": "mailto:user@example.com", "pathname": "user@example.com"},
        mutant="opaque_path_keeps_trailing_space", evidence=ev("2.4.0", "Implement potentially strip spaces for opaque paths."), source="github-release-note", name="opaque_path_strips_trailing_space")
    add(contracts, version="2.4.0", capability="url.non-special.path-slashes", op="parse_url",
        params={"input": "web+demo:////host/path"},
        expected={"href": "web+demo:////host/path", "pathname": "//host/path", "cannot_be_a_base": False},
        mutant="collapse_non_special_double_slashes", evidence=ev("2.4.0", "Fix anarchist URL where path starts with //."), source="github-release-note", name="non_special_path_starting_double_slash_preserved")
    add(contracts, version="2.4.0", capability="url.credentials.empty-password", op="set_component",
        params={"input": "http://user:pass@example.com/", "component": "password", "value": "", "mode": "quirks"},
        expected={"href": "http://user@example.com/", "password": ""},
        mutant="empty_password_keeps_colon", evidence=ev("2.4.0", "No colon when setting empty password."), source="github-release-note", name="quirks_empty_password_removes_password_colon")
    add(contracts, version="2.4.0", capability="url.api.is-special", op="parse_url",
        params={"input": "gopher://example.com/"},
        expected={"is_special": False, "origin": "null"},
        mutant="treat_gopher_as_special", evidence=ev("2.4.0", "Url is special."), source="github-release-note", name="gopher_is_not_special")
    add(contracts, version="2.4.0", capability="url.file.windows-drive", op="join",
        params={"base": "file:///C:/a/b", "input": "/D:/x"},
        expected={"href": "file:///D:/x", "pathname": "/D:/x"},
        mutant="file_absolute_drive_keeps_base_drive", evidence=ev("2.4.0", "Fix issues with file drives."), source="github-release-note", name="file_absolute_drive_replaces_base_drive")
    add(contracts, version="2.4.1", capability="url.setter.trailing-space", op="set_component",
        params={"input": "http://example.com/a?old=1#f", "component": "search", "value": "q=x ", "mode": "quirks"},
        expected={"href": "http://example.com/a?q=x%20#f", "search": "?q=x%20"},
        mutant="search_setter_trims_trailing_space", evidence=ev("2.4.1", "Fix trailing spaces in scheme / pathname / search setters."), source="github-release-note", name="search_setter_preserves_trailing_space_by_percent_encoding")
    add(contracts, version="2.4.1", capability="url.setter.file-path", op="set_component",
        params={"input": "file:///tmp/a", "component": "path", "value": "/tmp/b"},
        expected={"href": "file:///tmp/b", "pathname": "/tmp/b", "set_ok": True},
        mutant="file_set_path_panics_or_noops", evidence=ev("2.4.1", "Fix panic in set_path for file URLs."), source="github-release-note", name="file_set_path_updates_without_panic")
    add(contracts, version="2.5.0", capability="url.setter.non-special-search", op="set_component",
        params={"input": "foo://example/path?old#frag", "component": "search", "value": "q=x y#z", "mode": "quirks"},
        expected={"href": "foo://example/path?q=x%20y%23z#frag", "search": "?q=x%20y%23z"},
        mutant="non_special_search_setter_misencodes_space_hash", evidence=ev("2.5.0", "Fix search setting for non-special urls with space, query and fragment."), source="github-release-note", name="non_special_search_setter_encodes_space_and_hash")
    add(contracts, version="2.5.2", capability="url.idna.punycode-no-panic", op="parse_failure",
        params={"input": "https://xn--55555577/"}, expected={"ok": False},
        mutant="panic_or_accept_invalid_punycode", evidence=ev("2.5.2", "fix panic on xn--55555577."), source="github-release-note", name="invalid_punycode_does_not_panic_and_fails")
    add(contracts, version="2.5.3", capability="url.path.normalization-then-reverted", op="parse_url",
        params={"input": "http://example.com/.//p"},
        expected={"href": "http://example.com/p", "pathname": "/p"},
        mutant="do_not_normalize_slash_after_dot_segment", evidence=ev("2.5.3", "Normalize URL paths: convert /.//p, /..//p, and //p to p."), source="github-release-note", name="normalized_dot_slash_path_added_in_2_5_3")
    add(contracts, version="2.5.4", capability="url.path.normalization-reverted", op="parse_url",
        params={"input": "http://example.com/.//p"},
        expected={"href": "http://example.com//p", "pathname": "//p"},
        mutant="keep_reverted_2_5_3_normalization", evidence=ev("2.5.4", "Revert Normalize URL paths: convert /.//p, /..//p, and //p to p."), source="github-release-note", name="reverted_dot_slash_path_normalization")
    add(contracts, version="2.5.5", capability="url.setter.hostname-colon", op="set_component",
        params={"input": "http://example.com/a", "component": "hostname", "value": "example.org:81", "mode": "quirks"},
        expected={"set_ok": False, "href": "http://example.com/a", "hostname": "example.com"},
        mutant="hostname_setter_accepts_colon_and_port", evidence=ev("2.5.5", "set_hostname should error when encountering colon ':'."), source="github-release-note", name="hostname_setter_rejects_colon")

    return contracts


def write_rpl(contracts: list[Contract]) -> None:
    blocks = []
    for contract in contracts:
        blocks.append(
            "\n".join(
                [
                    f"contract {contract.name} {{",
                    f"  version = {json.dumps(contract.version)}",
                    f"  capability = {json.dumps(contract.capability)}",
                    f"  op = {json.dumps(contract.op)}",
                    f"  params = {json.dumps(contract.params, ensure_ascii=False, sort_keys=True)}",
                    f"  expect = {json.dumps(contract.expected, ensure_ascii=False, sort_keys=True)}",
                    f"  mutant = {json.dumps(contract.mutant)}",
                    "}",
                ]
            )
        )
    OUT_RPL.write_text("\n\n".join(blocks) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    versions, release_body = load_release_context()
    contracts = []
    contracts.extend(extract_wpt_url_cases(versions))
    contracts.extend(extract_wpt_setter_cases(versions))
    contracts.extend(extract_release_note_and_upgrade_contracts(release_body))

    # The same observable behavior can appear in WPT and in release-note examples.
    deduped: list[Contract] = []
    seen = set()
    for contract in contracts:
        fingerprint = json.dumps(
            [contract.capability, contract.op, contract.params, contract.expected],
            ensure_ascii=False,
            sort_keys=True,
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(contract)
    contracts = deduped

    counts = Counter(contract.version for contract in contracts)
    sources = Counter(contract.source for contract in contracts)
    data = {
        "domain": "URL / IRI parsing, serialization, and manipulation",
        "project": "servo/rust-url",
        "crate": "url",
        "latest_crate_version": "2.5.8",
        "source_versions_crates_io": len(versions),
        "source_github_release_notes_with_body": sum(1 for body in release_body.values() if body.strip()),
        "contracts_total": len(contracts),
        "contracts_by_source": dict(sources),
        "contracts": [contract.as_dict() for contract in contracts],
    }
    OUT_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts)

    rows = [
        "# servo/rust-url Release Contract Counts",
        "",
        "| Version | Published | Yanked | GitHub release note | Contracts |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for row in versions:
        version = row["num"]
        rows.append(
            f"| {version} | {row.get('created_at') or ''} | {'yes' if row.get('yanked') else 'no'} | "
            f"{'yes' if release_body.get(version, '').strip() else 'no'} | {counts.get(version, 0)} |"
        )
    OUT_COUNTS.write_text("\n".join(rows) + "\n", encoding="utf-8")

    audit = [
        "# servo/rust-url Extraction Audit",
        "",
        f"- crates.io versions enumerated: {len(versions)}",
        f"- GitHub `v*` release notes with body text: {sum(1 for body in release_body.values() if body.strip())}",
        f"- extracted language-independent, externally observable contracts: {len(contracts)}",
        "- included sources: release-bundled WHATWG URL parser fixtures, release-bundled WHATWG setter fixtures, public UPGRADING.md examples, and GitHub release-note behavior bullets.",
        "- excluded: Rust MSRV changes, CI/build/docs-only changes, dependency-only updates, perf-only changes without observable output, crate feature plumbing, and internal representation changes without a public behavior.",
        "- verification target: latest crates.io `url@2.5.8`.",
    ]
    OUT_AUDIT.write_text("\n".join(audit) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "source_versions_crates_io": len(versions),
                "source_github_release_notes_with_body": sum(1 for body in release_body.values() if body.strip()),
                "contracts_total": len(contracts),
                "contracts_by_source": dict(sources),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
