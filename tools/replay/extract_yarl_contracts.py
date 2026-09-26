#!/usr/bin/env python3
"""Extract replayable URL/IRI contracts from aio-libs/yarl release history."""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
META_DIR = ROOT / ".replay" / "url_iri" / "yarl-meta"
PYPI_META = META_DIR / "pypi_yarl.json"
GITHUB_RELEASES = META_DIR / "github_releases_yarl.json"
CHANGELOG = ROOT / ".replay" / "url_iri" / "yarl-repo" / "CHANGES.rst"
PYTHON = ROOT / ".replay" / "url_iri" / "yarl-latest-uv" / "bin" / "python"
RUNNER = ROOT / "tools" / "replay" / "yarl_latest_runner.py"
OUT_DIR = ROOT / "contracts" / "url_iri" / "yarl"
OUT_JSON = OUT_DIR / "all_releases_maximal_language_independent.summary.json"
OUT_RPL = OUT_DIR / "all_releases_maximal_language_independent.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


@dataclass(frozen=True)
class ContractSeed:
    version: str
    name: str
    capability: str
    op: str
    params: dict[str, Any]
    mutant: str
    evidence: str
    source: str


def slug(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def version_key(version: str) -> list[Any]:
    return [int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", version)]


def load_releases() -> list[dict[str, Any]]:
    pypi = json.loads(PYPI_META.read_text(encoding="utf-8"))
    github = json.loads(GITHUB_RELEASES.read_text(encoding="utf-8"))
    gh_by_version = {release["tag_name"].lstrip("v"): release for release in github}
    versions = sorted(pypi["releases"], key=version_key)
    rows = []
    for version in versions:
        files = pypi.get("releases", {}).get(version) or []
        rows.append(
            {
                "version": version,
                "published_at": files[-1].get("upload_time_iso_8601") if files else None,
                "body": (gh_by_version.get(version, {}).get("body") or ""),
                "has_github_release": bool((gh_by_version.get(version, {}).get("body") or "").strip()),
            }
        )
    return rows


def changelog_sections() -> dict[str, str]:
    text = CHANGELOG.read_text(encoding="utf-8")
    matches = list(
        re.finditer(
            r"^(?:v)?(\d+\.\d+\.\d+)(?:\s+\([^)]+\))?\n=+\n",
            text,
            re.MULTILINE,
        )
    )
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1)] = text[start:end].strip()
    return sections


def evidence(version: str, phrase: str) -> str:
    return f"yarl CHANGES.rst v{version}: {phrase}"


def c(
    out: list[ContractSeed],
    version: str,
    name: str,
    capability: str,
    op: str,
    params: dict[str, Any],
    phrase: str,
    *,
    mutant: str = "mutate_expected_observation",
    source: str = "changelog+public-tests",
) -> None:
    out.append(
        ContractSeed(
            version=version,
            name=f"{version}:{name}",
            capability=capability,
            op=op,
            params=params,
            mutant=mutant,
            evidence=evidence(version, phrase),
            source=source,
        )
    )


def seeds() -> list[ContractSeed]:
    out: list[ContractSeed] = []

    # Initial public URL object surface: immutable URL construction and decoded/raw properties.
    for raw in [
        "https://www.python.org/~guido?arg=1#frag",
        "http://бажан:пароль@хост.домен:8080/шлях/сюди?арг=вал#фраг",
        "http://example.com/%d0%bf%d1%83%d1%82%d1%8c/%d1%82%d1%83%d0%b4%d0%b0",
        "http://example.com/?%D0%BF=%D0%B7&%D1%8E=%D0%B1",
        "#frag",
        "example.com/a/b",
        "//www.python.org",
        "HTTP://example.com",
        "http://www.python.org/%7Eguido",
        "http://example.com/path%2Fto",
        "http://example.com/?%26=%3D",
        "http://user:@example.com/",
        "http://example.com:0",
        "unknown://example.com:8080",
    ]:
        c(out, "0.0.1", f"parse_props_{slug(raw)[:42]}", "url.object.parse-properties", "props", {"input": raw}, "URL exposes canonical string, raw fields, decoded fields, query, path and fragment properties.")

    for raw in ["", None]:
        params = {} if raw is None else {"input": raw}
        c(out, "0.0.1", "empty_url_truth_and_string" if raw == "" else "default_empty_url_truth_and_string", "url.object.empty", "bool", params, "Empty URL objects have observable false-like behavior and empty serialization.")

    # Query construction and mutation.
    query_cases: list[tuple[str, str, dict[str, Any]]] = [
        ("with_query_mapping", "with_query", {"args": [{"a": "1"}]}),
        ("with_query_pairs", "with_query", {"args": [[["a", "1"], ["b", "2"]]]}),
        ("with_query_kwargs", "with_query", {"kwargs": {"query": "1", "query2": "1"}}),
        ("with_query_none_clears", "with_query", {"args": [None], "input": "http://example.com/path?a=b"}),
        ("with_query_empty_mapping_clears", "with_query", {"args": [{}], "input": "http://example.com/?a=b"}),
        ("with_query_empty_value", "with_query", {"args": [{"a": ""}]}),
        ("with_query_string", "with_query", {"args": ["a=1&b=2"]}),
        ("with_query_non_ascii_string", "with_query", {"args": ["a=1 2&b=знач"]}),
        ("with_query_int_value", "with_query", {"args": [{"a": 1}]}),
        ("with_query_float_value", "with_query", {"args": [{"a": 1.1}]}),
        ("with_query_sequence_values", "with_query", {"args": [{"a": [1, 2]}]}),
        ("with_query_tuple_key_braces", "with_query", {"args": [{"a[]": [1, 2]}]}),
        ("with_query_unsafe_key_and_value", "with_query", {"args": [{"&": ["=", 2]}]}),
        ("with_query_ampersand_value", "with_query", {"args": [{"a": ["1&a=2", 3]}]}),
        ("with_query_reject_bool", "with_query", {"args": [{"a": True}]}),
        ("with_query_reject_none_value", "with_query", {"args": [{"a": None}]}),
        ("with_query_reject_bytes", "with_query", {"args": [{"__special__": "bytes", "value": "a=1"}]}),
        ("with_query_reject_nested", "with_query", {"args": [{"a": [[1]]}]}),
        ("update_query_mapping", "update_query", {"args": [{"baz": "foo"}], "input": "http://example.com/?foo=bar"}),
        ("update_query_string", "update_query", {"args": ["baz=foo"], "input": "http://example.com/?foo=bar"}),
        ("update_query_none_clears", "update_query", {"args": [None], "input": "http://example.com/?foo=bar&baz=foo"}),
        ("update_query_empty_mapping_preserves", "update_query", {"args": [{}], "input": "http://example.com/?foo=bar&baz=foo"}),
        ("update_query_reject_bytes", "update_query", {"args": [{"__special__": "bytes", "value": "foo=bar"}]}),
        ("update_query_reject_two_args", "update_query", {"args": ["a", "b"]}),
    ]
    for name, method, spec in query_cases:
        params = {"input": spec.get("input", "http://example.com/"), "method": method}
        params.update({key: value for key, value in spec.items() if key != "input"})
        if name == "with_query_pairs":
            version = "0.3.1"
        elif name in {"with_query_empty_value", "query_empty_value"}:
            version = "0.4.1"
        elif name in {"with_query_int_value", "with_query_sequence_values", "with_query_tuple_key_braces", "with_query_unsafe_key_and_value", "with_query_ampersand_value"}:
            version = "0.7.0"
        elif name.startswith("with_query_reject") or name == "with_query_kwargs":
            version = "0.8.0"
        elif method == "with_query":
            version = "0.1.3"
        else:
            version = "0.9.0"
        c(out, version, name, f"url.query.{method}", "transform", params, f"{method} accepts supported query shapes, encodes unsafe text, and rejects ambiguous values.")

    for name, raw, query_name in [
        ("query_empty_value", "http://example.com?a=", "a"),
        ("query_plus_is_space", "http://example.com?a+b=c+d", "a b"),
        ("query_duplicate_keys_preserved", "http://example.com?a=1&b=2&a=3", "a"),
        ("query_non_ascii_bmp", "http://example.com?ключ=знач", "ключ"),
        ("query_non_bmp", "http://example.com?bar=𝕦𝕟𝕚𝕔𝕠𝕕𝕖", "bar"),
        ("query_encoded_ampersand_not_separator", "http://127.0.0.1/?a=10%26b=20", "a"),
        ("query_semicolon_not_separator", "http://127.0.0.1/?a=10;b=20", "a"),
        ("query_no_double_unquote", "http://test_url.aha?url=http%3A%2F%2Fbase.place%3Fa%3D%252F%252F%252F%252F%252F", "url"),
    ]:
        c(out, "0.13.0", name, "url.query.parse-view", "query_view", {"input": raw, "name": query_name}, "Parsed query view preserves duplicate keys and treats reserved characters according to URL query rules.")

    for name, args in [
        ("extend_query_adds_duplicate", {"input": "http://example.com/?a=1", "method": "extend_query", "args": [{"a": "2"}]}),
        ("extend_query_with_string", {"input": "http://example.com/?a=1", "method": "extend_query", "args": ["a=2&b=3"]}),
        ("extend_query_with_pairs", {"input": "http://example.com/?a=1", "method": "extend_query", "args": [[["a", "2"], ["b", "3"]]]}),
        ("without_query_params_one", {"input": "http://example.com?a=10&b=M%C3%B9a+xu%C3%A2n&c=30", "method": "without_query_params", "args": ["b"]}),
        ("without_query_params_unicode_key", {"input": "http://example.com?a=10&b=M%C3%B9a+xu%C3%A2n&u%E1%BB%91ng=cafe", "method": "without_query_params", "args": ["uống"]}),
        ("without_query_params_all", {"input": "http://example.com?a=10&b=M%C3%B9a+xu%C3%A2n", "method": "without_query_params", "args": ["a", "b"]}),
    ]:
        version = "1.11.0" if name.startswith("extend") else "1.10.0"
        c(out, version, name, "url.query.incremental-mutation", "transform", args, "Incremental query APIs append duplicate parameters or remove selected names without rebuilding the full URL.")

    # Origin, relative, absolute and port behavior.
    for raw in [
        "http://user:pass@example.com:8080/path?a=b#frag",
        "http://example.com",
        "http://example.com:80",
        "https://example.com:443/a",
        "ws://example.com:80/a",
        "wss://example.com:443/a",
        "unknown://example.com:8080",
        "/path/to",
        "//www.python.org",
    ]:
        c(out, "0.11.0", f"absolute_default_origin_port_{slug(raw)[:38]}", "url.origin-relative-port", "props", {"input": raw}, "origin(), relative(), absolute and is_default_port expose network-location semantics.")

    # Build API, authority, raw authority and explicit port.
    build_cases: list[tuple[str, str, dict[str, Any]]] = [
        ("build_empty", "0.10.0", {}),
        ("build_simple_host", "0.10.0", {"scheme": "http", "host": "127.0.0.1"}),
        ("build_with_ipv6", "0.10.0", {"scheme": "http", "host": "::1"}),
        ("build_ipv4_inside_ipv6", "0.10.0", {"scheme": "http", "host": "2001:db8:122:344::192.0.2.33"}),
        ("build_with_user", "0.10.0", {"scheme": "http", "host": "127.0.0.1", "user": "foo"}),
        ("build_with_user_password", "0.10.0", {"scheme": "http", "host": "127.0.0.1", "user": "foo", "password": "bar"}),
        ("build_with_all_parts", "0.10.0", {"scheme": "http", "host": "127.0.0.1", "user": "foo", "password": "bar", "port": 8000, "path": "/index.html", "query_string": "arg=value1", "fragment": "top"}),
        ("build_with_scheme_and_relative_path", "1.6.0", {"scheme": "blob", "path": "path"}),
        ("build_with_non_ascii_host", "1.6.0", {"scheme": "http", "host": "εμπορικόσήμα.eu"}),
        ("build_lowercases_host", "1.6.0", {"scheme": "http", "host": "EXAMPLE.COM"}),
        ("build_with_authority", "1.6.0", {"scheme": "http", "authority": "user:pass@example.com:8080", "path": "/a"}),
        ("build_with_empty_path_query_fragment", "1.12.0", {"scheme": "http", "host": "example.com", "path": "", "query_string": "", "fragment": ""}),
        ("build_authority_path_requires_slash", "1.14.0", {"scheme": "http", "authority": "example.com", "path": "noslash"}),
        ("build_reject_host_none", "1.8.0", {"scheme": "http", "host": None}),
        ("build_reject_port_without_host", "0.10.0", {"port": 8000}),
        ("build_reject_query_and_query_string", "0.10.0", {"scheme": "http", "host": "127.0.0.1", "query": {"arg": "value1"}, "query_string": "arg=value1"}),
        ("build_reject_authority_and_host", "1.6.0", {"authority": "host.com", "host": "example.com"}),
        ("build_reject_port_str", "1.13.0", {"scheme": "http", "host": "example.com", "port": ""}),
    ]
    for name, version, kwargs in build_cases:
        c(out, version, name, "url.build", "build", {"kwargs": kwargs}, "URL.build constructs or rejects URLs from structured components without requiring string parsing by callers.")

    for raw in [
        "http://%D0%B2%D0%B0%D1%81%D1%8F@host:1234/",
        "http://бажан@host:1234/",
        "http://бажан:пароль@host:1234/",
        "http://xn--einla-pqa.de/",
        "http://einlaß.de/",
        "http://εμπορικόσήμα.eu/",
        "http://[::1]:8080/path",
    ]:
        c(out, "0.17.0", f"canonical_i18n_authority_{slug(raw)[:36]}", "url.i18n-authority", "props", {"input": raw}, "IDNA and percent encoding produce canonical serialized authority and decoded public properties.")

    # Network-location modifiers.
    netloc_cases: list[tuple[str, str, dict[str, Any]]] = [
        ("with_scheme_lowercases", "1.15.0", {"input": "http://example.com", "method": "with_scheme", "args": ["HTTPS"]}),
        ("with_scheme_file_relative_ok", "1.9.0", {"input": "file:///absolute/path", "method": "with_scheme", "args": ["file"]}),
        ("with_scheme_relative_http_rejected", "1.9.0", {"input": "path/to", "method": "with_scheme", "args": ["http"]}),
        ("with_scheme_relative_blob_allowed", "1.9.0", {"input": "path/to", "method": "with_scheme", "args": ["blob"]}),
        ("with_user_ascii", "0.0.1", {"input": "http://example.com", "method": "with_user", "args": ["john"]}),
        ("with_user_non_ascii", "0.0.1", {"input": "http://example.com", "method": "with_user", "args": ["бажан"]}),
        ("with_user_percent_encoded_literal", "0.0.1", {"input": "http://example.com", "method": "with_user", "args": ["%cf%80"]}),
        ("with_user_none_removes_password", "0.0.1", {"input": "http://john:pass@example.com", "method": "with_user", "args": [None]}),
        ("with_password_ascii", "0.0.1", {"input": "http://john@example.com", "method": "with_password", "args": ["pass"]}),
        ("with_password_non_ascii", "0.0.1", {"input": "http://john@example.com", "method": "with_password", "args": ["пароль"]}),
        ("with_password_colon_encoded", "0.0.1", {"input": "http://john@example.com", "method": "with_password", "args": ["п:а"]}),
        ("with_password_none_keeps_user", "0.0.1", {"input": "http://john:pass@example.com", "method": "with_password", "args": [None]}),
        ("with_password_empty_user", "0.0.1", {"input": "http://example.com", "method": "with_password", "args": ["pass"]}),
        ("with_host_ipv4", "0.0.1", {"input": "http://host:80", "method": "with_host", "args": ["192.168.1.1"]}),
        ("with_host_ipv6", "0.0.1", {"input": "http://host:80", "method": "with_host", "args": ["::1"]}),
        ("with_host_non_ascii", "0.0.1", {"input": "http://example.com:123", "method": "with_host", "args": ["оун-упа.укр"]}),
        ("with_host_uppercase_allowed", "1.16.0", {"input": "http://example.com", "method": "with_host", "args": ["EXAMPLE.ORG"]}),
        ("with_host_empty_rejected", "0.0.1", {"input": "http://example.com:123", "method": "with_host", "args": [""]}),
        ("with_host_authority_rejected", "1.16.0", {"input": "http://example.com:123", "method": "with_host", "args": ["user:pass@host.com"]}),
        ("with_host_percent_bad_rejected", "1.16.0", {"input": "http://example.com:123", "method": "with_host", "args": ["not_percent_encoded%Zf"]}),
        ("with_port_custom", "0.0.1", {"input": "http://example.com", "method": "with_port", "args": [8888]}),
        ("with_port_none_removes", "0.0.1", {"input": "http://example.com:81", "method": "with_port", "args": [None]}),
        ("with_port_default_normalized", "1.8.0", {"input": "http://example.com:88", "method": "with_port", "args": [80]}),
        ("with_port_zero_preserved", "1.13.0", {"input": "http://example.com", "method": "with_port", "args": [0]}),
        ("with_port_ipv6_keeps_brackets", "1.6.0", {"input": "http://[::1]:8080/", "method": "with_port", "args": [81]}),
        ("with_port_reject_bool", "1.8.0", {"input": "http://example.com", "method": "with_port", "args": [True]}),
        ("with_port_reject_negative", "1.8.0", {"input": "http://example.com", "method": "with_port", "args": [-1]}),
        ("with_port_reject_relative", "0.0.1", {"input": "path/to", "method": "with_port", "args": [1234]}),
    ]
    for name, version, params in netloc_cases:
        c(out, version, name, "url.netloc.modifiers", "transform", params, "with_scheme/user/password/host/port modifiers preserve or reject authority components predictably.")

    # Path, fragment, name and suffix modifiers.
    path_cases: list[tuple[str, str, dict[str, Any]]] = [
        ("with_path_absolute", "0.12.0", {"input": "http://example.com", "method": "with_path", "args": ["/test"]}),
        ("with_path_non_ascii", "0.12.0", {"input": "http://example.com", "method": "with_path", "args": ["/π"]}),
        ("with_path_percent_literal", "0.12.0", {"input": "http://example.com", "method": "with_path", "args": ["/%cf%80"]}),
        ("with_path_encoded_percent", "1.3.0", {"input": "http://example.com", "method": "with_path", "args": ["/%cf%80"], "kwargs": {"encoded": True}}),
        ("with_path_dot_normalized", "0.11.0", {"input": "http://example.com", "method": "with_path", "args": ["/test/."]}),
        ("with_path_clears_query", "0.11.0", {"input": "http://example.com?a=b", "method": "with_path", "args": ["/test"]}),
        ("with_path_clears_fragment", "0.11.0", {"input": "http://example.com#frag", "method": "with_path", "args": ["/test"]}),
        ("with_path_keep_query", "1.15.0", {"input": "http://example.com?a=b#frag", "method": "with_path", "args": ["/test"], "kwargs": {"keep_query": True}}),
        ("with_path_keep_fragment", "1.15.0", {"input": "http://example.com?a=b#frag", "method": "with_path", "args": ["/test"], "kwargs": {"keep_fragment": True}}),
        ("with_fragment_safe_chars", "0.0.1", {"input": "http://example.com", "method": "with_fragment", "args": ["a:b?c@d/e"]}),
        ("with_fragment_non_ascii", "0.0.1", {"input": "http://example.com", "method": "with_fragment", "args": ["фрагм"]}),
        ("with_fragment_percent_literal", "0.0.1", {"input": "http://example.com", "method": "with_fragment", "args": ["%cf%80"]}),
        ("with_fragment_none_removes", "0.0.1", {"input": "http://example.com/path#frag", "method": "with_fragment", "args": [None]}),
        ("with_name_basic", "0.0.1", {"input": "http://example.com/a/b", "method": "with_name", "args": ["c"]}),
        ("with_name_naked_path", "0.0.1", {"input": "http://example.com", "method": "with_name", "args": ["a"]}),
        ("with_name_relative", "0.0.1", {"input": "a/b", "method": "with_name", "args": ["c"]}),
        ("with_name_non_ascii", "0.0.1", {"input": "http://example.com/path", "method": "with_name", "args": ["шлях"]}),
        ("with_name_percent_literal", "0.0.1", {"input": "http://example.com/path", "method": "with_name", "args": ["%cf%80"]}),
        ("with_name_colon_at_safe", "1.24.3", {"input": "http://example.com/oldpath", "method": "with_name", "args": ["path:abc@123"]}),
        ("with_name_reject_slash", "0.0.1", {"input": "http://example.com", "method": "with_name", "args": ["a/b"]}),
        ("with_name_reject_dot", "0.0.1", {"input": "http://example.com", "method": "with_name", "args": ["."]}),
        ("with_name_keep_query", "1.15.0", {"input": "http://example.com/path/to?a=b#frag", "method": "with_name", "args": ["newname"], "kwargs": {"keep_query": True}}),
        ("with_name_keep_fragment", "1.15.0", {"input": "http://example.com/path/to?a=b#frag", "method": "with_name", "args": ["newname"], "kwargs": {"keep_fragment": True}}),
        ("with_suffix_basic", "1.8.0", {"input": "http://example.com/a/b", "method": "with_suffix", "args": [".c"]}),
        ("with_suffix_space_encoded", "1.8.0", {"input": "http://example.com/a/b", "method": "with_suffix", "args": [". c"]}),
        ("with_suffix_existing_encoded_name", "1.21.0", {"input": "http://example.com/a/b c", "method": "with_suffix", "args": [". d"]}),
        ("with_suffix_non_ascii", "1.8.0", {"input": "http://example.com/path", "method": "with_suffix", "args": [".шлях"]}),
        ("with_suffix_percent_literal", "1.8.0", {"input": "http://example.com/path", "method": "with_suffix", "args": [".%cf%80"]}),
        ("with_suffix_empty_removes", "1.8.0", {"input": "http://example.com/path/to", "method": "with_suffix", "args": [""]}),
        ("with_suffix_reject_naked", "1.8.0", {"input": "http://example.com", "method": "with_suffix", "args": [".a"]}),
        ("with_suffix_reject_no_dot", "1.8.0", {"input": "http://example.com/a", "method": "with_suffix", "args": ["b"]}),
        ("with_suffix_keep_query", "1.15.0", {"input": "http://example.com/path/to.txt?a=b#frag", "method": "with_suffix", "args": [".md"], "kwargs": {"keep_query": True}}),
        ("with_suffix_keep_fragment", "1.15.0", {"input": "http://example.com/path/to.txt?a=b#frag", "method": "with_suffix", "args": [".md"], "kwargs": {"keep_fragment": True}}),
    ]
    for name, version, params in path_cases:
        c(out, version, name, "url.path-fragment.modifiers", "transform", params, "Path, fragment, name and suffix modifiers encode, normalize and preserve selected query/fragment pieces.")

    for raw in [
        "http://example.com/a/b.c.d?x=1#f",
        "http://example.com/a/b%20c.d",
        "/a/b.c",
        "a/b.c",
        "/",
        "",
    ]:
        c(out, "1.8.0", f"path_properties_{slug(raw)[:42]}", "url.path.properties", "props", {"input": raw}, "URL exposes pathlib-like name, suffix, parent and raw/decoded path tuples.")

    # join and joinpath: yarl-specific immutable path append semantics plus RFC joins.
    normal_join = [
        ("g:h", "g:h"),
        ("g", "http://a/b/c/g"),
        ("./g", "http://a/b/c/g"),
        ("g/", "http://a/b/c/g/"),
        ("/g", "http://a/g"),
        ("//g", "http://g"),
        ("?y", "http://a/b/c/d;p?y"),
        ("g?y", "http://a/b/c/g?y"),
        ("#s", "http://a/b/c/d;p?q#s"),
        ("g#s", "http://a/b/c/g#s"),
        ("g?y#s", "http://a/b/c/g?y#s"),
        (";x", "http://a/b/c/;x"),
        ("g;x", "http://a/b/c/g;x"),
        ("", "http://a/b/c/d;p?q"),
        (".", "http://a/b/c/"),
        ("..", "http://a/b/"),
        ("../g", "http://a/b/g"),
        ("../../g", "http://a/g"),
        ("../../../g", "http://a/g"),
        ("/./g", "http://a/g"),
        ("g/./h", "http://a/b/c/g/h"),
        ("g/../h", "http://a/b/c/h"),
        ("g?y/../x", "http://a/b/c/g?y/../x"),
        ("g#s/../x", "http://a/b/c/g#s/../x"),
    ]
    for rel, _expected in normal_join:
        c(out, "0.0.1", f"join_rfc_{slug(rel or 'empty')}", "url.join", "join", {"base": "http://a/b/c/d;p?q", "input": rel}, "URL.join follows RFC relative-reference resolution with yarl canonicalization.")

    for base, rel in [
        ("https://web.archive.org/web/", "./https://github.com/aio-libs/yarl"),
        ("https://web.archive.org/web/https://github.com/", "aio-libs/yarl"),
        ("http://a/b/c/d/", "foo"),
        ("http://a/b/c/d/e/", "../../f/g/"),
        ("a/b", "c"),
        ("a/b/", "c"),
        ("https://x.org/", "/?text=Hello+G%C3%BCnter"),
        ("http://x.org", "https://x.org#fragment"),
    ]:
        c(out, "1.9.5", f"join_empty_segments_{slug(base+'_'+rel)[:46]}", "url.join.empty-segments", "join", {"base": base, "input": rel}, "URL.join honors empty path segments without losing query-string behavior.")

    joinpath_cases: list[tuple[str, dict[str, Any]]] = [
        ("joinpath_multi", {"input": "http://example.com/base", "elements": ["path", "to"]}),
        ("joinpath_dots", {"input": "http://example.com/base", "elements": ["..", "path", ".", "to"]}),
        ("joinpath_non_ascii", {"input": "http://example.com/сюди", "elements": ["туди"]}),
        ("joinpath_percent_literal", {"input": "http://example.com/path", "elements": ["%cf%80"]}),
        ("joinpath_encoded_percent", {"input": "http://example.com/path", "elements": ["%cf%80"], "kwargs": {"encoded": True}}),
        ("joinpath_trailing_slash", {"input": "http://example.com/path", "elements": ["a/"]}),
        ("joinpath_preserves_empty_segments", {"input": "http://example.com/path//", "elements": ["a"]}),
        ("joinpath_forbid_leading_slash", {"input": "http://example.com/path/", "elements": ["/to/others"]}),
        ("joinpath_empty_base_path", {"input": "http://example.com", "elements": ["a"]}),
        ("path_div_two_segments", {"input": "https://www.python.org", "elements": ["foo", "bar"]}),
    ]
    for name, params in joinpath_cases:
        op = "path_div" if name.startswith("path_div") else "joinpath"
        version = "1.8.0" if name.startswith("joinpath") else "0.0.1"
        c(out, version, name, "url.joinpath", op, params, "joinpath and the slash operator append elements immutably while normalizing dot segments.")

    # Human representation, raw serialization and bytes.
    for raw in [
        "http://бажан:пароль@хост.домен:8080/шлях/сюди?арг=вал#фраг",
        "шлях",
        "http://[::1]:8080/path",
        "http://user%5Bname:pass%5Dword@example.com/",
        "ht%74p://example.com/path",
        "javascript%3Aalert(1)",
        "data%3Atext/plain,hello",
    ]:
        c(out, "1.3.0", f"human_repr_{slug(raw)[:44]}", "url.human-representation", "props", {"input": raw}, "human_repr returns a parse-equivalent readable URL without materializing a scheme from relative text.")
    c(out, "0.17.0", "bytes_returns_ascii_serialization", "url.bytes", "bytes", {"input": "http://example.com/шлях/туди"}, "bytes(URL) returns the canonical ASCII byte serialization.")
    c(out, "1.5.0", "encoded_constructor_preserves_fragment_escapes", "url.encoded-input", "props", {"input": "http://example.com/path?qs#frag%2F%2D", "encoded": True}, "encoded=True preserves caller-supplied escapes instead of requoting them.")
    c(out, "1.0.0", "encoded_build_preserves_percent_path", "url.encoded-input", "build", {"kwargs": {"scheme": "http", "host": "example.com", "path": "/%cf%80", "encoded": True}}, "URL.build supports encoded=True for pre-encoded component input.")

    # Recent validation and IPv6 zone contracts.
    invalid_inputs = [
        ("reject_text_before_open_bracket", "http://127.0.0.1[aa::ff]"),
        ("reject_text_after_ip_literal", "http://[::1]allowed.example:1/"),
        ("reject_multiple_bracket_host_confusion", "http://[:localhost[]].google:80"),
        ("reject_backslash_in_authority", "http://example.com\\@evil.test/"),
        ("reject_fullwidth_percent_host", "http://example.com％evil.test/"),
        ("reject_small_percent_host", "http://example.com﹪evil.test/"),
        ("reject_soft_hyphen_host", "http://e\u00advil.com/"),
        ("reject_zero_width_space_host", "http://e\u200bvil.com/"),
        ("reject_word_joiner_host", "http://e\u2060vil.com/"),
        ("reject_bom_host", "http://e\ufeffvil.com/"),
    ]
    for name, raw in invalid_inputs:
        version = "1.24.3" if "percent" in name or "host" in name and "bracket" not in name and "backslash" not in name else "1.24.0"
        c(out, version, name, "url.host.validation", "props", {"input": raw}, "Parser rejects invalid or host-confusing authority syntax instead of exposing a misleading host.")

    for name, params in [
        ("build_ipv6_zone_bare_percent", {"kwargs": {"scheme": "http", "host": "fe80::1%eth0"}}),
        ("build_ipv6_zone_numeric_percent25", {"kwargs": {"scheme": "http", "host": "fe80::1%254"}}),
        ("build_ipv6_zone_unicode", {"kwargs": {"scheme": "http", "host": "fe80::1%日本語", "path": "/"}}),
        ("build_reject_empty_zone", {"kwargs": {"scheme": "http", "host": "::1%", "path": "/"}}),
        ("build_reject_crlf_zone", {"kwargs": {"scheme": "http", "host": "::1%\r\nX-Injected: evil", "path": "/"}}),
        ("authority_bypasses_empty_zone_validation", {"kwargs": {"scheme": "http", "authority": "[fe80::1%25]"}}),
    ]:
        c(out, "1.24.3", name, "url.ipv6.zone-id", "build", params, "IPv6 zone identifiers preserve valid scoped literals and reject invalid control/empty zone forms.")
    for raw in ["http://[fe80::1%251]/", "http://[fe80::1%25eth0]/"]:
        c(out, "1.24.3", f"parse_ipv6_zone_{slug(raw)}", "url.ipv6.zone-id", "props", {"input": raw}, "IPv6 zone identifier parsing decodes the RFC 6874 percent-encoded zone separator in host properties.")
    c(out, "1.24.3", "with_host_ipv6_zone_bare_percent", "url.ipv6.zone-id", "transform", {"input": "http://example.com/x", "method": "with_host", "args": ["fe80::1%1"]}, "with_host accepts RFC 4007 scoped IPv6 literals with a bare percent separator.")

    # Scheme-shaped relative paths must not become absolute/executable URLs.
    for method, params in [
        ("joinpath", {"input": "", "elements": ["javascript:alert(1)"]}),
        ("joinpath", {"input": "rel", "elements": ["http:example.com"]}),
        ("path_div", {"input": "", "elements": ["data:text/plain,hello"]}),
        ("transform", {"input": "old", "method": "with_name", "args": ["javascript:alert(1)"]}),
        ("transform", {"input": "old.txt", "method": "with_suffix", "args": [".javascript:alert(1)"]}),
        ("build", {"kwargs": {"path": "javascript:alert(1)"}}),
    ]:
        c(out, "1.24.3", f"relative_scheme_shape_guard_{method}_{len(out)}", "url.relative.scheme-shape-guard", method, params, "Relative path construction percent-encodes scheme-shaped leading colons rather than creating an absolute or executable-scheme URL.")

    # Public quote/unquote compatibility from older releases.
    for name, op, params in [
        ("quote_percent_non_strict", "quote", {"value": "%", "kwargs": {"safe": "", "protected": "", "qs": False, "strict": False}}),
        ("quote_path_plus_not_query_space", "quote", {"value": "a+b", "kwargs": {"safe": "", "protected": "", "qs": False}}),
        ("quote_query_plus_as_space", "quote", {"value": "a b", "kwargs": {"safe": "", "protected": "", "qs": True}}),
        ("unquote_strict_noop", "unquote", {"value": "a%2Fb", "kwargs": {"unsafe": "", "qs": False, "strict": True}}),
        ("unquote_query_plus", "unquote", {"value": "a+b", "kwargs": {"unsafe": "", "qs": True}}),
    ]:
        c(out, "0.2.0", name, "url.quote-unquote", op, params, "Public quote/unquote helpers expose query-aware plus and percent handling.")

    return out


def run_runner(seed: ContractSeed) -> dict[str, Any]:
    raw = subprocess.check_output(
        [str(PYTHON), str(RUNNER)],
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
    release_rows = load_releases()
    sections = changelog_sections()
    all_seeds = seeds()
    contracts: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for seed in all_seeds:
        key = (seed.op, json.dumps(seed.params, ensure_ascii=False, sort_keys=True), seed.capability)
        if key in seen:
            continue
        seen.add(key)
        expected = run_runner(seed)
        if expected.get("ok") is False and expected.get("throws") == "RuntimeError":
            failures.append({"name": seed.name, "expected": expected})
            continue
        contracts.append(
            {
                "name": seed.name,
                "version": seed.version,
                "capability": seed.capability,
                "op": seed.op,
                "params": seed.params,
                "expected": expected,
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
                "project": "aio-libs/yarl",
                "package": "yarl",
                "latest_version_target": "1.24.5",
                "release_source": {
                    "pypi_versions": len(release_rows),
                    "github_releases_with_body": sum(1 for row in release_rows if row["has_github_release"]),
                    "changelog_version_sections": len(sections),
                },
                "contract_count": len(contracts),
                "generation_failures": failures,
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
        "# yarl Release Contract Counts",
        "",
        f"- PyPI versions inspected: `{len(release_rows)}`",
        f"- GitHub release bodies available: `{sum(1 for row in release_rows if row['has_github_release'])}`",
        f"- CHANGES.rst version sections inspected: `{len(sections)}`",
        f"- Extracted replayable contracts: `{len(contracts)}`",
        "",
        "| Version | Published | GitHub body | Contracts |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in release_rows:
        md.append(
            f"| `{row['version']}` | {row['published_at'] or ''} | {'yes' if row['has_github_release'] else 'no'} | {counts[row['version']]} |"
        )
    OUT_COUNTS.write_text("\n".join(md) + "\n", encoding="utf-8")

    audit = [
        "# yarl Extraction Audit",
        "",
        "Two passes were applied to each release artifact:",
        "",
        "1. Changelog/API pass: release-note behavior changes were mapped to externally observable URL construction, parsing, mutation, query and validation behavior.",
        "2. Fixture grounding pass: concrete inputs were selected from yarl's public README/API examples and upstream public API regression tests, then compiled to replayable DSL operations.",
        "",
        "Excluded: packaging, CI, typing-only, performance-only, internal cache-only and language-runtime compatibility notes without stable user-observable URL behavior.",
        "",
        f"- Total replayable contracts: `{len(contracts)}`",
        f"- Latest target used to materialize expected observations: `yarl==1.24.5`",
        f"- Generation failures skipped: `{len(failures)}`",
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

    print(json.dumps({"contracts": len(contracts), "failures": len(failures)}, sort_keys=True))


if __name__ == "__main__":
    main()
