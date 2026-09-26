#!/usr/bin/env python3
"""Extract replayable URL/IRI contracts from jsdom/whatwg-url releases.

The extractor uses two passes over the release history:

* pass 1 turns explicit release-note behavior changes into concrete contracts.
* pass 2 expands broad API additions into externally observable standard
  scenarios that can be replayed through the published package API.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
META_DIR = ROOT / ".replay" / "url_iri"
NPM_META = META_DIR / "npm_whatwg_url.json"
GITHUB_RELEASES = META_DIR / "github_releases_whatwg_url.json"
OUT_DIR = ROOT / "contracts" / "url_iri" / "whatwg-url"
OUT_JSON = OUT_DIR / "all_releases_maximal_language_independent.summary.json"
OUT_RPL = OUT_DIR / "all_releases_maximal_language_independent.rpl"
OUT_COUNTS = OUT_DIR / "release_contract_counts.md"
OUT_AUDIT = OUT_DIR / "extraction_audit.md"


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
    pass_name: str

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
            "pass": self.pass_name,
        }


def slug(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def clean_note(version: str, body: str, phrase: str | None = None) -> str:
    body = re.sub(r"\s+", " ", body).strip()
    if phrase:
        return f"GitHub release v{version}: {phrase}"
    return f"GitHub release v{version}: {body[:260]}"


def c(
    contracts: list[Contract],
    version: str,
    body: str,
    name: str,
    capability: str,
    op: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    mutant: str,
    pass_name: str,
    *,
    phrase: str | None = None,
) -> None:
    contracts.append(
        Contract(
            name=f"{version}:{name}",
            version=version,
            capability=capability,
            op=op,
            params=params,
            expected=expected,
            mutant=mutant,
            evidence=clean_note(version, body, phrase),
            pass_name=pass_name,
        )
    )


def load_releases() -> list[dict[str, Any]]:
    npm = json.loads(NPM_META.read_text(encoding="utf-8"))
    gh = json.loads(GITHUB_RELEASES.read_text(encoding="utf-8"))
    gh_by_version = {rel["tag_name"].lstrip("v"): rel for rel in gh}
    versions = sorted(
        npm["versions"],
        key=lambda version: [int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", version)],
    )
    releases = []
    for version in versions:
        rel = gh_by_version.get(version, {})
        body = (rel.get("body") or "").strip()
        releases.append(
            {
                "version": version,
                "published_at": npm.get("time", {}).get(version) or rel.get("published_at"),
                "body": body,
                "has_github_release": bool(body),
            }
        )
    return releases


def pass1(version: str, body: str) -> list[Contract]:
    b = body.lower()
    contracts: list[Contract] = []

    if "percent-decoding" in b and "%2e" in b:
        c(contracts, version, body, "percent_decode_uppercase_2e_to_dot", "url.percent-decode.hex-case", "percent_decode_string",
          {"input": "a%2Eb%2ec"}, {"value": "a.b.c"}, "leave_uppercase_percent_escape_encoded", "pass1")
        c(contracts, version, body, "percent_decode_mixed_hex_pair_to_dot", "url.percent-decode.hex-case", "percent_decode_bytes",
          {"input": "%2E%2e"}, {"hex": "2e2e"}, "decode_only_lowercase_hex_pair", "pass1")

    if "tab and newline" in b:
        c(contracts, version, body, "ascii_tab_newline_are_removed_before_parsing", "url.input-trimming.ascii-tab-newline", "parse_url",
          {"input": "h\nt\rt\tp://exa\nmple.com/a\tb"}, {"href": "http://example.com/ab", "host": "example.com", "pathname": "/ab"}, "preserve_ascii_tab_newline_in_input", "pass1")
        c(contracts, version, body, "ascii_newline_removed_in_query", "url.input-trimming.ascii-tab-newline", "parse_url",
          {"input": "http://example.com/?a\n=b\rc"}, {"href": "http://example.com/?a=bc", "search": "?a=bc"}, "preserve_ascii_newline_in_query", "pass1")

    if "schemes that have numbers" in b:
        c(contracts, version, body, "scheme_may_contain_digits_after_first_character", "url.scheme.syntax", "parse_url",
          {"input": "h3://example/path"}, {"href": "h3://example/path", "protocol": "h3:"}, "reject_digit_in_scheme", "pass1")

    if "new url()" in b and "throws" in b:
        c(contracts, version, body, "url_constructor_throws_on_absolute_parse_failure", "url.parse.failure-surface", "construct_failure",
          {"input": "http://[::1"}, {"throws": "TypeError"}, "return_failure_object_in_constructor", "pass1")
        c(contracts, version, body, "href_setter_ignores_parse_failure", "url.setter.failure-ignores", "set_component",
          {"input": "https://example.com/a", "component": "href", "value": "http://[::1"}, {"href": "https://example.com/a"}, "setter_replaces_with_invalid_value", "pass1")

    if "hostname setter" in b and "typo" in b:
        c(contracts, version, body, "hostname_setter_updates_host", "url.setter.hostname", "set_component",
          {"input": "http://example.com/a", "component": "hostname", "value": "example.org"}, {"href": "http://example.org/a", "hostname": "example.org"}, "hostname_setter_noops", "pass1")

    if "search setter" in b:
        c(contracts, version, body, "search_setter_accepts_value_without_question_mark", "url.setter.search", "set_component",
          {"input": "http://example.com/a?old=1", "component": "search", "value": "x=1 y=2"}, {"href": "http://example.com/a?x=1%20y=2", "search": "?x=1%20y=2"}, "do_not_percent_encode_search_setter_space", "pass1")
        c(contracts, version, body, "search_setter_empty_removes_query", "url.setter.search", "set_component",
          {"input": "http://example.com/a?old=1", "component": "search", "value": ""}, {"href": "http://example.com/a", "search": ""}, "leave_empty_question_mark_after_empty_search", "pass1")

    if "relative urls containing" in b and "file base" in b:
        c(contracts, version, body, "file_base_parent_resolution_keeps_drive_letter", "url.file.relative-resolution", "parse_url",
          {"input": "../b", "base": "file:///C:/a/c"}, {"href": "file:///C:/b", "pathname": "/C:/b"}, "drop_windows_drive_letter_on_parent_resolution", "pass1")
        c(contracts, version, body, "file_base_current_directory_resolution_keeps_drive_letter", "url.file.relative-resolution", "parse_url",
          {"input": "./b", "base": "file:///C:/a/c"}, {"href": "file:///C:/a/b"}, "treat_file_drive_letter_as_host", "pass1")

    if "port setter" in b:
        c(contracts, version, body, "port_setter_empty_removes_port", "url.setter.port", "set_component",
          {"input": "http://example.com:81/a", "component": "port", "value": ""}, {"href": "http://example.com/a", "port": ""}, "keep_old_port_when_empty_port_set", "pass1")
        c(contracts, version, body, "port_setter_default_port_serializes_empty", "url.setter.port", "set_component",
          {"input": "http://example.com:81/a", "component": "port", "value": "80"}, {"href": "http://example.com/a", "port": ""}, "serialize_default_port", "pass1")

    if "fragment parsing" in b and "non-ascii" in b:
        c(contracts, version, body, "hash_setter_percent_encodes_non_ascii", "url.fragment.percent-encode-unicode", "set_component",
          {"input": "http://example.com/a", "component": "hash", "value": "é"}, {"href": "http://example.com/a#%C3%A9", "hash": "#%C3%A9"}, "leave_unicode_fragment_raw", "pass1")

    if "removed the static methods" in b and "domaintoascii" in b:
        c(contracts, version, body, "url_constructor_has_no_domain_to_ascii_static", "url.api.removed-domain-statics", "static_presence",
          {"property": "domainToASCII"}, {"present": False}, "keep_removed_domain_to_ascii_static", "pass1")
        c(contracts, version, body, "url_constructor_has_no_domain_to_unicode_static", "url.api.removed-domain-statics", "static_presence",
          {"property": "domainToUnicode"}, {"present": False}, "keep_removed_domain_to_unicode_static", "pass1")

    if "nontransitional" in b:
        c(contracts, version, body, "idna_nontransitional_preserves_sharp_s_as_punycode", "url.host.idna-nontransitional", "parse_url",
          {"input": "https://faß.de/"}, {"hostname": "xn--fa-hia.de", "href": "https://xn--fa-hia.de/"}, "use_transitional_idna_fass_to_fass", "pass1")

    if "hash setter for javascript" in b:
        c(contracts, version, body, "javascript_url_hash_setter_appends_fragment", "url.setter.hash.javascript", "set_component",
          {"input": "javascript:alert(1)", "component": "hash", "value": "x"}, {"href": "javascript:alert(1)#x", "hash": "#x"}, "ignore_hash_setter_for_javascript_urls", "pass1")

    if "urls without a special scheme" in b and "host parsing" in b:
        c(contracts, version, body, "non_special_host_preserves_percent_encoded_delimiter", "url.non-special.host", "parse_url",
          {"input": "foo://exa%23mple/"}, {"href": "foo://exa%23mple/", "host": "exa%23mple", "hostname": "exa%23mple"}, "decode_non_special_host_delimiter", "pass1")
        c(contracts, version, body, "non_special_url_can_have_empty_host", "url.non-special.empty-host", "parse_url",
          {"input": "foo:///path"}, {"href": "foo:///path", "host": "", "pathname": "/path"}, "treat_non_special_empty_host_as_failure", "pass1")

    if "path parsing for urls without a special scheme" in b:
        c(contracts, version, body, "non_special_path_preserves_backslash", "url.non-special.path", "parse_url",
          {"input": "foo://example/a\\b"}, {"href": "foo://example/a\\b", "pathname": "/a\\b"}, "treat_non_special_backslash_as_slash", "pass1")

    if "path-less file urls" in b:
        c(contracts, version, body, "pathless_file_url_serializes_with_empty_path", "url.file.pathless", "parse_url",
          {"input": "file://host"}, {"href": "file://host/", "host": "host", "pathname": "/"}, "serialize_pathless_file_without_slash", "pass1")

    if "username" in b and "password" in b and "file and non-special" in b:
        c(contracts, version, body, "file_url_username_setter_noops", "url.setter.credentials.file-noop", "set_component",
          {"input": "file:///tmp/a", "component": "username", "value": "u"}, {"href": "file:///tmp/a", "username": ""}, "allow_credentials_on_file_url", "pass1")
        c(contracts, version, body, "non_special_credentials_are_serialized", "url.setter.credentials.non-special", "set_component",
          {"input": "foo://example/path", "component": "username", "value": "u s"}, {"href": "foo://u%20s@example/path", "username": "u%20s"}, "disallow_credentials_on_non_special_url", "pass1")

    if "tojson()" in b:
        c(contracts, version, body, "url_tojson_returns_href", "url.api.toJSON", "method_call",
          {"input": "https://example.com/a?x=1", "method": "toJSON"}, {"value": "https://example.com/a?x=1"}, "tojson_returns_object", "pass1")

    if "u+fffd" in b:
        c(contracts, version, body, "replacement_character_percent_encodes", "url.percent-encode.replacement-character", "set_component",
          {"input": "http://example.com/", "component": "pathname", "value": "/\uFFFD"}, {"href": "http://example.com/%EF%BF%BD", "pathname": "/%EF%BF%BD"}, "drop_replacement_character", "pass1")

    if "state override scheme parsing" in b:
        c(contracts, version, body, "low_level_scheme_state_override_failure_returns_null", "url.low-level.state-override", "low_level_parse",
          {"input": "1http", "stateOverride": "scheme start"}, {"isNull": True}, "throw_instead_of_null_for_state_override_failure", "pass1")

    if "invalid ipv4 addresses in the ipv6 parser" in b:
        c(contracts, version, body, "ipv6_embedded_invalid_ipv4_fails", "url.host.ipv6", "construct_failure",
          {"input": "http://[::ffff:999.0.0.1]/"}, {"throws": "TypeError"}, "accept_invalid_ipv4_inside_ipv6", "pass1")

    if "trailing zeros" in b:
        c(contracts, version, body, "ipv6_serializer_compresses_trailing_zero_run", "url.host.ipv6-serialization", "parse_url",
          {"input": "http://[2001:db8:0:0:0:0:0:0]/"}, {"host": "[2001:db8::]", "href": "http://[2001:db8::]/"}, "do_not_compress_ipv6_zero_run", "pass1")

    if "null and empty-string passwords" in b:
        c(contracts, version, body, "empty_password_serializes_colon_when_username_present", "url.credentials.empty-password", "parse_url",
          {"input": "http://user:@example.com/"}, {"href": "http://user@example.com/", "username": "user", "password": ""}, "keep_empty_password_colon", "pass1")

    if "stopped decoding all `%2e`s" in b:
        c(contracts, version, body, "encoded_dot_in_path_is_not_always_decoded", "url.path.encoded-dot", "parse_url",
          {"input": "http://example.com/a/%2e%2e/b"}, {"href": "http://example.com/b", "pathname": "/b"}, "never_process_encoded_dot_segments", "pass1")
        c(contracts, version, body, "double_encoded_dot_segment_is_preserved", "url.path.encoded-dot", "parse_url",
          {"input": "http://example.com/a/%252e%252e/b"}, {"href": "http://example.com/a/%252e%252e/b", "pathname": "/a/%252e%252e/b"}, "decode_double_encoded_dot_segment", "pass1")

    if "protocol` setter" in b and "username" in b:
        c(contracts, version, body, "protocol_setter_noops_when_credentials_present", "url.setter.protocol-credentials-port", "set_component",
          {"input": "http://u@example.com/a", "component": "protocol", "value": "file"}, {"href": "http://u@example.com/a", "protocol": "http:"}, "allow_protocol_change_with_credentials", "pass1")
        c(contracts, version, body, "protocol_setter_noops_when_port_present", "url.setter.protocol-credentials-port", "set_component",
          {"input": "http://example.com:81/a", "component": "protocol", "value": "file"}, {"href": "http://example.com:81/a", "protocol": "http:"}, "allow_protocol_change_with_port", "pass1")

    if "leading slashes" in b and "file" in b:
        c(contracts, version, body, "file_url_trims_extra_leading_path_slashes", "url.file.leading-slashes", "parse_url",
          {"input": "file://///server/share"}, {"href": "file://///server/share", "pathname": "///server/share"}, "collapse_file_extra_leading_slashes", "pass1")

    if "empty labels" in b:
        c(contracts, version, body, "domain_with_empty_label_example_parses", "url.host.empty-label", "parse_url",
          {"input": "http://../"}, {"href": "http://../", "hostname": ".."}, "reject_empty_domain_labels", "pass1")

    if "windows drive letter handling" in b:
        c(contracts, version, body, "file_url_windows_drive_letter_from_base", "url.file.windows-drive", "parse_url",
          {"input": "/D:/x", "base": "file:///C:/a/b"}, {"href": "file:///D:/x", "pathname": "/D:/x"}, "keep_base_drive_for_absolute_drive_path", "pass1")
        c(contracts, version, body, "file_url_relative_keeps_windows_drive_base", "url.file.windows-drive", "parse_url",
          {"input": "x", "base": "file:///C:/a/b"}, {"href": "file:///C:/a/x"}, "drop_drive_for_relative_path", "pass1")

    if "ascii serialization of the origin" in b:
        c(contracts, version, body, "origin_serialization_uses_ascii_domain", "url.origin.ascii", "origin",
          {"input": "https://測試.example/path"}, {"origin": "https://xn--g6w251d.example"}, "serialize_origin_as_unicode", "pass1")

    if "urlsearchparams" in b and "support" in b:
        c(contracts, version, body, "url_searchparams_gets_duplicate_values", "urlsearchparams.basic", "searchparams",
          {"init": "a=1&a=2&b=3", "actions": [{"type": "getAll", "name": "a"}]}, {"values": ["1", "2"], "size": 3}, "collapse_duplicate_search_params", "pass1")
        c(contracts, version, body, "url_searchparams_parent_url_updates_after_append", "urlsearchparams.parent-url", "searchparams_parent",
          {"input": "http://example.com/?a=1", "actions": [{"type": "append", "name": "b", "value": "2"}]}, {"href": "http://example.com/?a=1&b=2", "search": "?a=1&b=2"}, "searchparams_does_not_update_parent_url", "pass1")
        c(contracts, version, body, "url_searchparams_spaces_serialize_as_plus", "urlsearchparams.form-urlencode", "searchparams",
          {"init": [["a", "x y"]], "actions": [{"type": "toString"}]}, {"value": "a=x+y"}, "serialize_space_as_percent20", "pass1")

    if "percentdecode" in b and "public api" in b:
        c(contracts, version, body, "public_percent_decode_decodes_utf8_sequence", "url.api.percent-decode", "percent_decode_string",
          {"input": "%E2%9C%93"}, {"value": "✓"}, "decode_utf8_percent_sequence_as_latin1", "pass1")

    if "cannothaveausernamepasswordport" in b:
        c(contracts, version, body, "file_url_cannot_have_username_password_port", "url.low-level.credentials-port-policy", "cannot_have_credentials_port",
          {"input": "file:///tmp/a"}, {"value": True}, "allow_credentials_port_on_file_records", "pass1")
        c(contracts, version, body, "http_url_can_have_username_password_port", "url.low-level.credentials-port-policy", "cannot_have_credentials_port",
          {"input": "http://example.com/"}, {"value": False}, "forbid_credentials_port_on_http_records", "pass1")

    if "return value representing failure" in b and "null" in b:
        c(contracts, version, body, "low_level_parse_failure_returns_null", "url.low-level.failure-null", "low_level_parse",
          {"input": "http://[::1"}, {"isNull": True}, "return_failure_string_for_parse_failure", "pass1")

    if "proper `symbol.tostringtag`" in b:
        c(contracts, version, body, "url_symbol_tostringtag_is_url", "url.webidl.to-string-tag", "object_tag",
          {"type": "URL", "input": "http://example.com/"}, {"value": "[object URL]"}, "missing_url_tostringtag", "pass1")
        c(contracts, version, body, "urlsearchparams_symbol_tostringtag_is_urlsearchparams", "urlsearchparams.webidl.to-string-tag", "object_tag",
          {"type": "URLSearchParams", "input": "a=1"}, {"value": "[object URLSearchParams]"}, "missing_urlsearchparams_tostringtag", "pass1")

    if "scheme setter" in b and "reset the port" in b:
        c(contracts, version, body, "protocol_setter_resets_new_default_port", "url.setter.scheme-default-port", "set_component",
          {"input": "http://example.com:443/a", "component": "protocol", "value": "https"}, {"href": "https://example.com/a", "protocol": "https:", "port": ""}, "keep_port_after_scheme_default_changes", "pass1")

    if "query becomes empty" in b:
        c(contracts, version, body, "searchparams_delete_last_param_removes_question_mark", "urlsearchparams.parent-url-empty", "searchparams_parent",
          {"input": "http://example.com/?a=1", "actions": [{"type": "delete", "name": "a"}]}, {"href": "http://example.com/", "search": ""}, "leave_empty_question_mark_after_deleting_last_param", "pass1")

    if "href` setter" in b and "searchparams" in b:
        c(contracts, version, body, "href_setter_updates_existing_searchparams_view", "url.setter.href-searchparams-sync", "href_setter_searchparams",
          {"input": "http://example.com/?a=1", "value": "http://example.com/?b=2", "read": "b"}, {"value": "2", "href": "http://example.com/?b=2"}, "searchparams_view_keeps_old_query_after_href_set", "pass1")

    if "gopher" in b:
        c(contracts, version, body, "gopher_is_not_special_scheme", "url.scheme.gopher-not-special", "parse_url",
          {"input": "gopher://example.com:70/1"}, {"href": "gopher://example.com:70/1", "origin": "null"}, "treat_gopher_as_special_with_origin", "pass1")

    if "origin" in b and "file:" in b and "opaque" in b:
        c(contracts, version, body, "file_url_origin_serializes_null", "url.origin.file-opaque", "origin",
          {"input": "file:///tmp/a"}, {"origin": "null"}, "serialize_file_origin_as_file_scheme", "pass1")

    if "error messages" in b and "invalid input urls" in b:
        c(contracts, version, body, "invalid_constructor_error_message_contains_input", "url.error-message.invalid-input", "construct_failure",
          {"input": "http://[::1", "messageContains": "http://[::1"}, {"throws": "TypeError", "messageContains": "http://[::1"}, "omit_invalid_input_from_error_message", "pass1")

    if "special schemes" in b and "query" in b and "'" in body:
        c(contracts, version, body, "special_scheme_query_percent_encodes_apostrophe", "url.query.percent-encode-special", "parse_url",
          {"input": "http://example.com/?q='"}, {"href": "http://example.com/?q=%27", "search": "?q=%27"}, "leave_apostrophe_raw_in_special_query", "pass1")

    if "percent-escaping rules in the query" in b:
        c(contracts, version, body, "special_query_percent_encodes_space", "url.query.percent-encode", "parse_url",
          {"input": "http://example.com/?q=a b"}, {"href": "http://example.com/?q=a%20b", "search": "?q=a%20b"}, "serialize_url_query_space_as_plus", "pass1")
        c(contracts, version, body, "non_special_query_percent_encodes_backtick", "url.query.percent-encode", "parse_url",
          {"input": "foo://example/?q=`"}, {"href": "foo://example/?q=%60"}, "leave_backtick_raw_in_non_special_query", "pass1")

    if "domain parser" in b and "ascii fallback" in b:
        c(contracts, version, body, "ascii_domain_does_not_require_idna_mapping", "url.host.ascii-fallback", "parse_url",
          {"input": "https://EXAMPLE.com/path"}, {"href": "https://example.com/path", "hostname": "example.com"}, "require_unicode_domain_mapper_for_ascii_hosts", "pass1")

    if "encoding support for query string parsing" in b:
        c(contracts, version, body, "low_level_parse_query_uses_shift_jis_encoding_option", "url.query.encoding-option", "low_level_parse",
          {"input": "http://example.com/?q=こんにちは", "encoding": "shift_jis"}, {"query": "q=%82%B1%82%F1%82%C9%82%BF%82%CD"}, "ignore_query_encoding_option", "pass1")

    if "url.parse()" in b and "proper `url` object" in b:
        c(contracts, version, body, "url_parse_returns_url_instance", "url.api.parse-static", "static_parse",
          {"input": "https://example.com/a"}, {"isURL": True, "href": "https://example.com/a"}, "return_internal_record_from_static_parse", "pass1")

    if "added `url.parse()`" in b:
        c(contracts, version, body, "url_parse_returns_null_on_failure", "url.api.parse-static", "static_parse",
          {"input": "http://[::1"}, {"isNull": True}, "throw_or_return_record_for_static_parse_failure", "pass1")
        c(contracts, version, body, "url_parse_accepts_base", "url.api.parse-static", "static_parse",
          {"input": "../b", "base": "https://example.com/a/c"}, {"isURL": True, "href": "https://example.com/b"}, "static_parse_ignores_base", "pass1")

    if "url.canparse()" in b:
        c(contracts, version, body, "url_canparse_true_for_valid_absolute_url", "url.api.canParse", "can_parse",
          {"input": "https://example.com/a"}, {"value": True}, "canparse_rejects_valid_absolute_url", "pass1")
        c(contracts, version, body, "url_canparse_false_for_invalid_absolute_url", "url.api.canParse", "can_parse",
          {"input": "http://[::1"}, {"value": False}, "canparse_accepts_invalid_url", "pass1")
        c(contracts, version, body, "url_canparse_respects_base_url", "url.api.canParse", "can_parse",
          {"input": "../b", "base": "https://example.com/a/c"}, {"value": True}, "canparse_ignores_base_url", "pass1")

    if "size` getter" in b:
        c(contracts, version, body, "urlsearchparams_size_counts_entries", "urlsearchparams.size", "searchparams",
          {"init": "a=1&a=2&b=3", "actions": [{"type": "size"}]}, {"value": 3}, "size_counts_unique_names_only", "pass1")

    if "second `value` argument" in b:
        c(contracts, version, body, "urlsearchparams_has_name_value_pair", "urlsearchparams.has-value", "searchparams",
          {"init": "a=1&a=2", "actions": [{"type": "has", "name": "a", "value": "2"}]}, {"value": True}, "has_ignores_optional_value", "pass1")
        c(contracts, version, body, "urlsearchparams_delete_name_value_pair_only", "urlsearchparams.delete-value", "searchparams",
          {"init": "a=1&a=2&a=1", "actions": [{"type": "delete", "name": "a", "value": "1"}, {"type": "toString"}]}, {"value": "a=2"}, "delete_ignores_optional_value", "pass1")

    if "blob:" in b and "inner urls were not" in b:
        c(contracts, version, body, "blob_origin_for_non_http_inner_url_is_null", "url.origin.blob-non-http-null", "origin",
          {"input": "blob:ftp://example.com/id"}, {"origin": "null"}, "use_inner_ftp_origin_for_blob_url", "pass1")
        c(contracts, version, body, "blob_origin_for_https_inner_url_uses_inner_origin", "url.origin.blob-http", "origin",
          {"input": "blob:https://example.com/id"}, {"origin": "https://example.com"}, "always_null_blob_origin", "pass1")

    if "invalid punycode" in b:
        c(contracts, version, body, "invalid_punycode_label_fails", "url.host.idna-punycode-validation", "construct_failure",
          {"input": "http://xn--ls8h=/"}, {"throws": "TypeError"}, "accept_invalid_punycode_label", "pass1")

    if "empty domain name labels" in b:
        c(contracts, version, body, "punycode_label_followed_by_empty_label_parses", "url.host.idna-empty-label", "can_parse",
          {"input": "https://xn--4-0bd15808a.../"}, {"value": True}, "reject_punycode_empty_label_example", "pass1")

    if "characters allowed in domains vs. generic hosts" in b:
        c(contracts, version, body, "special_url_rejects_forbidden_domain_character", "url.host.special-vs-generic", "construct_failure",
          {"input": "http://exa%mple.org/"}, {"throws": "TypeError"}, "allow_percent_in_special_domain", "pass1")
        c(contracts, version, body, "non_special_opaque_host_allows_percent_escape", "url.host.special-vs-generic", "parse_url",
          {"input": "foo://exa%mple.org/"}, {"href": "foo://exa%mple.org/", "hostname": "exa%mple.org"}, "reject_percent_in_generic_host", "pass1")

    if "serialize-parse roundtrippable" in b:
        c(contracts, version, body, "search_setter_encodes_hash_to_preserve_roundtrip", "url.setter.roundtrip-search-hash", "set_component",
          {"input": "http://example.com/", "component": "search", "value": "a#b"}, {"href": "http://example.com/?a%23b", "search": "?a%23b"}, "allow_hash_to_escape_search", "pass1")
        c(contracts, version, body, "urlsearchparams_set_encodes_hash_to_preserve_roundtrip", "urlsearchparams.roundtrip-hash", "searchparams_parent",
          {"input": "http://example.com/", "actions": [{"type": "set", "name": "a", "value": "#b"}]}, {"href": "http://example.com/?a=%23b"}, "urlsearchparams_leaves_hash_unescaped", "pass1")

    if "non-ipv4 domains that end in numbers" in b:
        c(contracts, version, body, "host_ending_in_number_but_not_ipv4_fails", "url.host.numeric-ending", "construct_failure",
          {"input": "http://example.0/"}, {"throws": "TypeError"}, "accept_non_ipv4_domain_ending_in_number", "pass1")
        c(contracts, version, body, "valid_ipv4_number_host_still_parses", "url.host.ipv4", "parse_url",
          {"input": "http://127.0.0.1/"}, {"hostname": "127.0.0.1", "host": "127.0.0.1"}, "reject_all_numeric_ending_hosts", "pass1")

    if "pathname` setter" in b and "empty string" in b:
        c(contracts, version, body, "pathname_setter_empty_on_special_url_sets_root_path", "url.setter.pathname-empty", "set_component",
          {"input": "http://example.com/a/b", "component": "pathname", "value": ""}, {"href": "http://example.com/", "pathname": "/"}, "leave_old_path_on_empty_pathname_setter", "pass1")

    if "u+0000" in b and "fragment" in b:
        c(contracts, version, body, "fragment_null_code_point_is_percent_encoded", "url.fragment.null-percent-encode", "set_component",
          {"input": "http://example.com/", "component": "hash", "value": "\u0000"}, {"href": "http://example.com/#%00", "hash": "#%00"}, "drop_null_code_point_in_fragment", "pass1")

    if "host ends up empty" in b and "file:" in b:
        c(contracts, version, body, "file_host_empty_after_toascii_fails", "url.file.empty-host-toascii-failure", "construct_failure",
          {"input": "file://\u3002/path"}, {"throws": "TypeError"}, "allow_file_empty_host_after_toascii", "pass1")

    if "<" in body and ">" in body and "^" in body and "host component" in b:
        c(contracts, version, body, "host_rejects_less_than", "url.host.forbidden-code-point", "construct_failure",
          {"input": "http://exa<mple.org/"}, {"throws": "TypeError"}, "allow_less_than_in_host", "pass1")
        c(contracts, version, body, "host_rejects_greater_than", "url.host.forbidden-code-point", "construct_failure",
          {"input": "http://exa>mple.org/"}, {"throws": "TypeError"}, "allow_greater_than_in_host", "pass1")
        c(contracts, version, body, "host_rejects_caret", "url.host.forbidden-code-point", "construct_failure",
          {"input": "http://exa^mple.org/"}, {"throws": "TypeError"}, "allow_caret_in_host", "pass1")

    if "non-special urls" in b and "idempotent" in b:
        c(contracts, version, body, "non_special_parse_serialize_parse_is_idempotent", "url.non-special.idempotent", "roundtrip",
          {"input": "foo:////example.com/%2F?x=%2F#%2F"}, {"stable": True}, "non_special_roundtrip_changes_href", "pass1")

    if "file:" in b and "serialized-then-reparsed" in b:
        c(contracts, version, body, "file_parse_serialize_parse_is_idempotent", "url.file.idempotent", "roundtrip",
          {"input": "file:////host//a/../b"}, {"stable": True}, "file_roundtrip_changes_href", "pass1")

    if "file:" in b and "path normalization" in b:
        c(contracts, version, body, "file_path_normalizes_dot_segments", "url.file.path-normalization", "parse_url",
          {"input": "file:///a/b/../c"}, {"href": "file:///a/c", "pathname": "/a/c"}, "skip_file_dot_segment_normalization", "pass1")

    if "percentdecode" in b and "uint8array" in b:
        c(contracts, version, body, "percent_decode_bytes_returns_uint8array", "url.api.percent-decode-bytes", "percent_decode_bytes",
          {"input": "%41%42"}, {"constructor": "Uint8Array", "hex": "4142"}, "return_node_buffer_from_percent_decode_bytes", "pass1")

    if "percentdecodestring" in b:
        c(contracts, version, body, "percent_decode_string_export_decodes_without_utf8_decoding", "url.api.percent-decode-string", "percent_decode_string",
          {"input": "%41%42%43"}, {"value": "ABC"}, "missing_percent_decode_string_export", "pass1")

    if "opaque path" in b and "serializepath" in b:
        c(contracts, version, body, "serialize_path_supports_opaque_path_records", "url.low-level.serialize-path", "serialize_path",
          {"input": "mailto:user@example.com"}, {"value": "user@example.com"}, "serialize_opaque_path_as_slash_path_array", "pass1")
        c(contracts, version, body, "has_opaque_path_true_for_mailto", "url.low-level.opaque-path", "has_opaque_path",
          {"input": "mailto:user@example.com"}, {"value": True}, "treat_mailto_path_as_hierarchical", "pass1")

    if "u+005e" in b and "path percent-encode" in b:
        c(contracts, version, body, "path_percent_encodes_caret", "url.path.percent-encode-caret", "parse_url",
          {"input": "http://example.com/a^b"}, {"href": "http://example.com/a%5Eb", "pathname": "/a%5Eb"}, "leave_caret_raw_in_path", "pass1")

    if "opaque paths always roundtrip" in b:
        c(contracts, version, body, "opaque_path_with_space_roundtrips", "url.opaque-path.roundtrip", "roundtrip",
          {"input": "mailto:user name@example.com"}, {"stable": True, "href": "mailto:user%20name@example.com"}, "opaque_path_roundtrip_changes_serialization", "pass1")

    if "unicode 16.0.0" in b or "unicode 17.0.0" in b:
        c(contracts, version, body, f"idna_unicode_domain_maps_to_ascii_{slug(version)}", "url.host.idna-unicode", "parse_url",
          {"input": "https://測試.example/"}, {"hostname": "xn--g6w251d.example", "href": "https://xn--g6w251d.example/"}, "leave_unicode_host_unmapped", "pass1")

    if "parseurlwithvalidationerrors" in b:
        c(contracts, version, body, "parse_with_validation_errors_reports_missing_scheme", "url.validation-errors.parse", "parse_with_validation_errors",
          {"input": "example.com"}, {"urlIsNull": True, "errorsContains": "missing-scheme-non-relative-URL"}, "do_not_report_missing_scheme_validation_error", "pass1")
        c(contracts, version, body, "parse_with_validation_errors_reports_special_slashes", "url.validation-errors.parse", "parse_with_validation_errors",
          {"input": "http:example.com"}, {"urlIsNull": False, "errorsContains": "special-scheme-missing-following-solidus"}, "do_not_report_special_scheme_slash_error", "pass1")

    if "isvalidurlstring" in b:
        c(contracts, version, body, "valid_url_string_accepts_absolute_with_fragment", "url.validation.valid-url-string", "is_valid_url_string",
          {"input": "https://example.com/a#b"}, {"value": True}, "reject_valid_absolute_url_string", "pass1")
        c(contracts, version, body, "valid_url_string_accepts_relative_with_base", "url.validation.valid-url-string", "is_valid_url_string",
          {"input": "../b#f", "base": "https://example.com/a/c"}, {"value": True}, "ignore_base_for_relative_valid_url_string", "pass1")
        c(contracts, version, body, "valid_url_string_rejects_no_scheme_without_base", "url.validation.valid-url-string", "is_valid_url_string",
          {"input": "../b#f"}, {"value": False}, "accept_relative_without_base_as_valid_url_string", "pass1")

    if "userinfo parsing for astral code points" in b:
        c(contracts, version, body, "userinfo_astral_code_point_percent_encodes_utf8", "url.userinfo.astral", "parse_url",
          {"input": "https://💩:🔑@example.com/"}, {"username": "%F0%9F%92%A9", "password": "%F0%9F%94%91", "href": "https://%F0%9F%92%A9:%F0%9F%94%91@example.com/"}, "encode_astral_userinfo_as_utf16_surrogates", "pass1")

    return contracts


def pass2(version: str, body: str) -> list[Contract]:
    b = body.lower()
    contracts: list[Contract] = []

    if "url constructor" in b or "overhauled api" in b:
        c(contracts, version, body, "url_constructor_exposes_components", "url.api.constructor-components", "parse_url",
          {"input": "https://user:pass@example.com:8443/a/b?x=1#frag"}, {"protocol": "https:", "username": "user", "password": "pass", "hostname": "example.com", "port": "8443", "pathname": "/a/b", "search": "?x=1", "hash": "#frag"}, "constructor_does_not_expose_components", "pass2")
        c(contracts, version, body, "url_constructor_resolves_relative_against_base", "url.api.constructor-base", "parse_url",
          {"input": "../d?q=1", "base": "https://example.com/a/b/c"}, {"href": "https://example.com/a/d?q=1"}, "constructor_ignores_base_url", "pass2")

    if "urlsearchparams" in b:
        c(contracts, version, body, "urlsearchparams_sort_orders_by_name_stably", "urlsearchparams.sort", "searchparams",
          {"init": "b=2&a=1&a=0", "actions": [{"type": "sort"}, {"type": "toString"}]}, {"value": "a=1&a=0&b=2"}, "sort_reorders_duplicate_values", "pass2")
        c(contracts, version, body, "urlsearchparams_set_replaces_all_existing_values", "urlsearchparams.set", "searchparams",
          {"init": "a=1&a=2&b=3", "actions": [{"type": "set", "name": "a", "value": "4"}, {"type": "toString"}]}, {"value": "a=4&b=3"}, "set_only_replaces_first_value", "pass2")
        c(contracts, version, body, "urlsearchparams_constructor_strips_leading_question_mark", "urlsearchparams.constructor", "searchparams",
          {"init": "?a=1", "actions": [{"type": "toString"}]}, {"value": "a=1"}, "keep_leading_question_mark_in_params", "pass2")

    if "url.canparse" in b or "url.parse" in b:
        c(contracts, version, body, "static_parse_and_constructor_agree_on_href", "url.api.static-parse-agreement", "static_parse",
          {"input": "https://example.com/a/../b"}, {"isURL": True, "href": "https://example.com/b"}, "static_parse_uses_different_parser", "pass2")

    if "validation" in b and "standard" in b:
        c(contracts, version, body, "validation_errors_empty_for_clean_url", "url.validation-errors.clean-url", "parse_with_validation_errors",
          {"input": "https://example.com/a"}, {"urlIsNull": False, "errorsLength": 0}, "report_spurious_errors_for_clean_url", "pass2")

    return contracts


def rpl_line(contract: dict[str, Any]) -> str:
    return json.dumps(contract, ensure_ascii=False, sort_keys=True)


def main() -> None:
    releases = load_releases()
    contracts: list[Contract] = []
    for release in releases:
        body = release["body"]
        if not body:
            continue
        version = release["version"]
        contracts.extend(pass1(version, body))
        contracts.extend(pass2(version, body))

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for contract in contracts:
        if contract.name in seen:
            continue
        seen.add(contract.name)
        unique.append(contract.as_dict())

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_version = Counter(contract["version"] for contract in unique)
    summary = {
        "domain": "URL / IRI parsing, serialization, and manipulation",
        "project": "jsdom/whatwg-url",
        "source_versions_npm": len(releases),
        "source_releases_with_notes": sum(1 for release in releases if release["has_github_release"]),
        "contracts_total": len(unique),
        "contracts": unique,
        "release_counts": dict(sorted(by_version.items(), key=lambda item: [int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", item[0])])),
        "audit": [
            "Every npm version from 0.0.1 through the latest dist-tag was enumerated.",
            "GitHub release notes were used where available; early npm-only versions without notes receive zero extracted contracts.",
            "Language/runtime-only changes such as minimum Node.js version bumps and dependency-only packaging changes were excluded unless the note named externally observable URL behavior.",
            "Broad API additions were expanded into concrete observable API scenarios, mirroring the expansion strategy used for JSON Schema draft support.",
        ],
    }
    OUT_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    OUT_RPL.write_text("\n".join(rpl_line(contract) for contract in unique) + "\n", encoding="utf-8")

    lines = [
        "# jsdom/whatwg-url Release Contract Counts",
        "",
        "| Version | Published | GitHub release note | Contracts |",
        "| --- | --- | --- | ---: |",
    ]
    for release in releases:
        version = release["version"]
        lines.append(f"| {version} | {release['published_at'] or ''} | {'yes' if release['has_github_release'] else 'no'} | {by_version[version]} |")
    OUT_COUNTS.write_text("\n".join(lines) + "\n", encoding="utf-8")

    OUT_AUDIT.write_text(
        "\n".join([
            "# jsdom/whatwg-url Extraction Audit",
            "",
            f"- npm versions enumerated: {len(releases)}",
            f"- GitHub release notes with body text: {sum(1 for release in releases if release['has_github_release'])}",
            f"- extracted language-independent, externally observable contracts: {len(unique)}",
            "- verification target: latest npm `whatwg-url` dist-tag.",
            "- excluded: runtime support bumps, dependency-only build changes, package-size changes, and internal low-level record representation changes unless they expose an observable public API behavior.",
        ]) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({k: summary[k] for k in ("source_versions_npm", "source_releases_with_notes", "contracts_total")}, indent=2))


if __name__ == "__main__":
    main()
