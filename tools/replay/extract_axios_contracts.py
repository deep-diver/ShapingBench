#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPLAY = ROOT / ".replay" / "axios"
OUT_DIR = ROOT / "contracts" / "axios"
OUT_RPL = OUT_DIR / "axios_origin_excluding_merged_common.rpl"
OUT_JSON = OUT_DIR / "axios_origin_excluding_merged_common.summary.json"
OUT_AUDIT = OUT_DIR / "axios_origin_extraction_audit.md"
MERGED = ROOT / "contracts" / "common" / "merged_common_exhaustive.json"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    capability: str
    setup: tuple[str, ...]
    actions: tuple[str, ...]
    assertions: tuple[str, ...]
    mutant: str
    reason: str

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text, flags=re.I | re.S) is not None


def semkey(name: str) -> str:
    return re.sub(r"_\d+$", "", name)


RULES: tuple[Rule, ...] = (
    Rule(
        "redirect_strips_sensitive_headers_cross_origin",
        r"Redirect Header Safety|stripping caller-specified sensitive headers|custom auth headers.*leak|Authorization.*cross-origin",
        "http.redirect.cross-origin-sensitive-header-stripping",
        ('given origin redirects to different origin', 'given request headers {"Authorization":"Bearer secret","Cookie":"a=1","X-Api-Key":"secret"}'),
        ('when GET "/start" redirect true',),
        ('then redirected_request headers exclude ["Authorization","Cookie","X-Api-Key"]',),
        "forward_sensitive_headers_on_cross_origin_redirect",
        "Cross-origin redirect header safety is wire-visible.",
    ),
    Rule(
        "malformed_http_url_without_slashes_is_rejected",
        r"malformed `http:` and `https:` URLs that omit `//`|ERR_INVALID_URL|parseProtocol.*strictly requires a colon",
        "http.url.malformed-protocol-rejection",
        ('given url "http:example.test/path"',),
        ('when GET url',),
        ('then error code "ERR_INVALID_URL"',),
        "accept_http_url_without_double_slash",
        "Malformed URL rejection is deterministic request construction behavior.",
    ),
    Rule(
        "validate_status_undefined_can_resolve_like_default",
        r"validateStatusUndefinedResolves|validateStatus: undefined",
        "http.response.validate-status-undefined-semantics",
        ('given server status 204',),
        ('when GET "/" validateStatus undefined transitional.validateStatusUndefinedResolves true',),
        ('then promise resolved',),
        "treat_validate_status_undefined_as_accept_all",
        "Status validation configuration is observable through promise resolution.",
    ),
    Rule(
        "zstd_response_decompression_supported",
        r"zstd response decompression|Zstandard|advertiseZstdAcceptEncoding",
        "http.response.zstd-decompression",
        ('given server response Content-Encoding "zstd" body compressed("hello")',),
        ('when GET "/"',),
        ('then response body "hello"',),
        "leave_zstd_body_compressed",
        "Compression decoding is observable over HTTP.",
    ),
    Rule(
        "same_origin_redirect_preserves_basic_auth",
        r"Restored Basic auth on same-origin Node redirects|URL-embedded Basic auth",
        "http.redirect.same-origin-basic-auth-preservation",
        ('given same_origin redirect "/start" to "/target"', 'given url credentials "user:p%40ss"'),
        ('when GET "/start" redirect true',),
        ('then redirected_request Authorization decodes "user:p@ss"',),
        "strip_basic_auth_on_same_origin_redirect",
        "Authorization preservation on same-origin redirects is wire-visible.",
    ),
    Rule(
        "url_embedded_basic_auth_is_url_decoded",
        r"Basic auth credentials embedded in URLs are now URL-decoded|URL-decoded basic auth credentials",
        "http.auth.url-basic-credentials-decoding",
        ('given url "http://user:p%40ss@origin/"',),
        ('when GET url',),
        ('then Authorization basic decodes "user:p@ss"',),
        "send_percent_encoded_basic_credentials",
        "URL credential decoding is observable in the request header.",
    ),
    Rule(
        "https_agent_tls_options_survive_http_connect_proxy",
        r"Preserved user `httpsAgent` TLS options when tunneling HTTPS requests through HTTP CONNECT proxies|HTTPS request data could be transmitted in cleartext",
        "http.proxy.https-agent-tls-options-preserved",
        ('given HTTPS origin with self-signed certificate', 'given HTTP CONNECT proxy'),
        ('when GET "https://origin/" via proxy with custom httpsAgent',),
        ('then CONNECT tunnel established', 'then response body "secure"',),
        "drop_https_agent_options_inside_proxy_tunnel",
        "HTTPS proxy tunneling is observable by local proxy and TLS origin.",
    ),
    Rule(
        "blank_header_names_are_skipped",
        r"skipped empty or whitespace-only header names|empty or whitespace-only header names",
        "http.headers.blank-name-skipped",
        ('given request headers {"   ":"ignored","X-Test":"ok"}',),
        ('when GET "/"',),
        ('then request succeeds', 'then blank header absent'),
        "throw_on_blank_header_name",
        "Header filtering is observable on a local server.",
    ),
    Rule(
        "unicode_header_values_survive_interceptors",
        r"Unicode Headers.*Preserved Unicode header values.*interceptors|non-ASCII header content",
        "http.headers.unicode-values-through-interceptors",
        ('given request interceptor touches headers', 'given header "X-Token" "token-é"'),
        ('when GET "/"',),
        ('then server observed header starts_with "token-"'),
        "corrupt_unicode_header_value_in_interceptor",
        "Header value preservation is wire-visible.",
    ),
    Rule(
        "econnrefused_error_constant_is_exposed",
        r"ECONNREFUSED Error Constant|Exposed `ECONNREFUSED`",
        "http.error.econnrefused-constant",
        ('given closed TCP port',),
        ('when GET closed_port',),
        ('then error code equals AxiosError.ECONNREFUSED',),
        "compare_to_missing_econnrefused_constant",
        "Error taxonomy is observable from a failed connection.",
    ),
    Rule(
        "fetch_adapter_enforces_max_body_length",
        r"Fetch adapter now enforces `maxBodyLength`|maxBodyLength.*fetch adapter",
        "http.request.fetch-max-body-length",
        ('given fetch adapter', 'given request body length 8 maxBodyLength 1'),
        ('when POST "/"',),
        ('then error code "ERR_BAD_REQUEST"',),
        "ignore_fetch_max_body_length",
        "Request-size enforcement is observable without network side effects.",
    ),
    Rule(
        "data_url_max_content_length_is_enforced",
        r"data: URL size estimation|enforce maxContentLength for data: URLs|base64 data: URL size",
        "http.response.data-url-max-content-length",
        ('given data_url body length 8 maxContentLength 1',),
        ('when GET data_url',),
        ('then error code "ERR_BAD_RESPONSE"',),
        "underestimate_data_url_size",
        "Data URL response size enforcement is deterministic.",
    ),
    Rule(
        "abort_reason_is_preserved",
        r"preserved the original abort reason|already-aborted input signals immediately|Cancellation",
        "http.cancel.abort-reason-preservation",
        ('given AbortSignal aborted with reason "boom"',),
        ('when GET "/" with signal',),
        ('then error is cancellation', 'then error cause_or_message contains "boom"'),
        "replace_abort_reason_with_generic_error",
        "Cancellation reason propagation is observable.",
    ),
    Rule(
        "json_parse_error_keeps_response",
        r"Attached the parsed response to AxiosError when `JSON.parse` fails|JSON.parse.*dispatchRequest|parse reviver",
        "http.response.json-parse-error-retains-response",
        ('given server response Content-Type "application/json" body "{bad"',),
        ('when GET "/" responseType "json" silentJSONParsing false',),
        ('then error has response status 200',),
        "drop_response_from_json_parse_error",
        "JSON parse error shape is observable.",
    ),
    Rule(
        "socket_path_allowlist_rejects_unlisted_path",
        r"allowedSocketPaths|SSRF via `socketPath`|restrict permitted Unix domain socket paths",
        "http.transport.socket-path-allowlist",
        ('given unix_socket_path "/tmp/a.sock"', 'given allowedSocketPaths excludes path'),
        ('when GET "/" socketPath "/tmp/a.sock"',),
        ('then error code "ERR_BAD_OPTION_VALUE"',),
        "allow_unlisted_socket_path",
        "Unix socket allowlist enforcement is local and deterministic.",
    ),
    Rule(
        "max_body_length_enforced_when_redirects_disabled",
        r"`maxBodyLength` With Zero Redirects|Enforces `maxBodyLength` even when `maxRedirects` is set to `0`",
        "http.request.max-body-length-without-redirects",
        ('given request body length 8 maxBodyLength 1 maxRedirects 0',),
        ('when POST "/"',),
        ('then error code "ERR_BAD_REQUEST"',),
        "skip_max_body_length_when_redirects_disabled",
        "Body-size enforcement is observable before dispatch completes.",
    ),
    Rule(
        "streamed_response_max_content_length_is_enforced",
        r"Streamed Response `maxContentLength` Bypass|Applies `maxContentLength` to streamed responses",
        "http.response.stream-max-content-length",
        ('given server body length 8',),
        ('when GET "/" responseType "stream" maxContentLength 1',),
        ('then stream errors before full body accepted',),
        "ignore_max_content_length_for_stream_response",
        "Streamed response size enforcement is observable.",
    ),
    Rule(
        "form_data_to_json_ignores_polluted_prototype",
        r"formDataToJSON.*prototype|Prototype Pollution Defence-in-Depth|path splitting",
        "http.formdata.to-json-prototype-hardening",
        ('given Object.prototype has polluted key', 'given FormData field "safe" "ok"'),
        ('when axios.formToJSON(form)',),
        ('then json excludes polluted key',),
        "copy_inherited_formdata_keys",
        "FormData JSON conversion is runtime behavior.",
    ),
    Rule(
        "form_data_to_json_preserves_literal_punctuation_keys",
        r"Limited formDataToJSON path splitting to dot and bracket notation|preserving literal punctuation in keys",
        "http.formdata.to-json-literal-punctuation",
        ('given FormData field "a/b:c" "v"',),
        ('when axios.formToJSON(form)',),
        ('then json key "a/b:c" equals "v"',),
        "split_formdata_keys_on_punctuation",
        "FormData key parsing is deterministic.",
    ),
    Rule(
        "data_uri_parser_rejects_invalid_base64",
        r"Data URI Parsing|fromDataURI.*RFC 2397",
        "http.response.data-uri-strict-parsing",
        ('given malformed data URL "data:text/plain;base64,%%%%"',),
        ('when GET data_url',),
        ('then error kind "invalid_data_uri"',),
        "accept_malformed_data_uri",
        "Data URI parsing is deterministic.",
    ),
    Rule(
        "no_proxy_wildcard_bypasses_proxy",
        r"NO_PROXY.*\\*|Proxy Bypass|NO_PROXY matching",
        "http.proxy.no-proxy-wildcard",
        ('given HTTP_PROXY points to failing proxy', 'given NO_PROXY "*"',),
        ('when GET local_origin',),
        ('then origin receives direct request',),
        "ignore_no_proxy_wildcard",
        "Proxy bypass is observable with a local origin.",
    ),
    Rule(
        "no_proxy_canonicalizes_ipv4_shorthand",
        r"Canonicalized IPv4 shorthand, octal, and hexadecimal forms during NO_PROXY matching",
        "http.proxy.no-proxy-ipv4-canonicalization",
        ('given origin "127.0.0.1"', 'given request host "0177.0.0.1"', 'given NO_PROXY "127.0.0.1"'),
        ('when GET request_host with HTTP_PROXY configured',),
        ('then origin receives direct request',),
        "match_no_proxy_before_ipv4_canonicalization",
        "NO_PROXY canonicalization is externally observable.",
    ),
    Rule(
        "get_set_cookie_returns_array",
        r"getSetCookie.*return arrays|getSetCookie method",
        "http.headers.get-set-cookie-array",
        ('given headers Set-Cookie ["a=1","b=2"]',),
        ('when getSetCookie',),
        ('then result ["a=1","b=2"]',),
        "return_joined_set_cookie_string",
        "Header API behavior is deterministic and HTTP-specific.",
    ),
    Rule(
        "base_url_combination_deduplicates_trailing_slashes",
        r"removed repeated trailing slashes when combining base URLs|combineURLs|baseURL",
        "http.url.base-url-slash-deduplication",
        ('given baseURL "http://origin/api///" url "///users"',),
        ('when getUri',),
        ('then URL path "/api/users"',),
        "preserve_duplicate_join_slashes",
        "URL combination is deterministic request construction behavior.",
    ),
    Rule(
        "sync_interceptor_failure_prevents_dispatch",
        r"Synchronous Interceptors.*Prevented requests from being dispatched after synchronous request interceptors fail",
        "http.interceptor.sync-failure-stops-dispatch",
        ('given synchronous request interceptor throws "boom"',),
        ('when GET "/"',),
        ('then origin request_count 0', 'then promise rejected'),
        "dispatch_after_sync_interceptor_failure",
        "Interceptor failure dispatch policy is observable.",
    ),
    Rule(
        "allow_absolute_urls_false_combines_absolute_request_url",
        r"allowAbsoluteUrls|ignoring absolute URLs|allowing absolute URLs",
        "http.url.allow-absolute-urls-false",
        ('given baseURL local_origin', 'given url "http://evil.test/path"', 'given allowAbsoluteUrls false'),
        ('when GET url',),
        ('then local_origin receives request with embedded absolute URL path',),
        "let_absolute_url_override_base_url",
        "Base URL override policy is observable on local origin.",
    ),
    Rule(
        "params_serializer_callback_is_used",
        r"paramsSerializer callback|custom params serializer|URL params serializer",
        "http.url.params-serializer-callback",
        ('given params {"a":"1"} paramsSerializer returns "custom=1"',),
        ('when getUri',),
        ('then query "custom=1"',),
        "ignore_params_serializer_callback",
        "Query serialization is deterministic.",
    ),
    Rule(
        "file_object_payload_is_supported_by_http_adapter",
        r"File objects as payload in http adapter|File object.*payload",
        "http.request.file-payload-node-adapter",
        ('given File payload name "a.txt" body "abc"',),
        ('when POST "/"',),
        ('then server observed body "abc"',),
        "reject_file_payload_in_http_adapter",
        "Request body support is wire-visible.",
    ),
    Rule(
        "fetch_adapter_uses_current_global_fetch",
        r"use current global fetch instead of cached one|MSW support",
        "http.adapter.fetch-current-global",
        ('given global fetch replaced after axios import',),
        ('when GET "/" adapter "fetch"',),
        ('then replacement fetch called',),
        "cache_global_fetch_at_import_time",
        "Adapter global lookup behavior is executable.",
    ),
    Rule(
        "custom_fetch_env_is_used_by_fetch_adapter",
        r"fetch, Request, Response env config variables|fetchOptions",
        "http.adapter.fetch-env-config",
        ('given env.fetch replacement returns Response("ok")',),
        ('when GET "/" adapter "fetch"',),
        ('then replacement fetch called', 'then body "ok"'),
        "ignore_fetch_env_config",
        "Fetch adapter injection is executable.",
    ),
    Rule(
        "json_parse_reviver_is_applied",
        r"support reviver on JSON.parse|parseReviver",
        "http.response.json-parse-reviver",
        ('given server JSON {"n":1}',),
        ('when GET "/" responseType "json" parseReviver increments numbers',),
        ('then response data {"n":2}',),
        "ignore_json_parse_reviver",
        "JSON response transform behavior is observable.",
    ),
    Rule(
        "node_data_url_requests_are_supported",
        r"data URL support for node|data: URL support",
        "http.response.node-data-url-support",
        ('given data_url "data:text/plain,hello"',),
        ('when GET data_url',),
        ('then response body "hello"',),
        "reject_node_data_url",
        "Data URL support is deterministic.",
    ),
    Rule(
        "object_payload_auto_serializes_to_urlencoded",
        r"automatic payload serialization to application/x-www-form-urlencoded|url-encoded-form serializer",
        "http.request.auto-urlencoded-object-serialization",
        ('given request body object {"a":"b"} Content-Type application/x-www-form-urlencoded',),
        ('when POST "/"',),
        ('then server observed_body "a=b"',),
        "send_object_as_json_despite_urlencoded_content_type",
        "Automatic request serialization is wire-visible.",
    ),
    Rule(
        "cancel_error_includes_config",
        r"CancelledError.*include config|Canceler parameters config and request",
        "http.cancel.error-includes-config",
        ('given request config marker "yes"', 'given request cancelled before dispatch'),
        ('when GET "/"',),
        ('then CanceledError.config.marker == "yes"',),
        "omit_config_from_canceled_error",
        "Cancellation error shape is observable.",
    ),
    Rule(
        "interceptor_manager_clear_removes_handlers",
        r"clear\\(\\) function to the request and response interceptors|AxiosInterceptorManager.*clear",
        "http.interceptor.clear-removes-handlers",
        ('given request interceptor adds header "X-Intercepted"', 'given interceptor cleared'),
        ('when GET "/"',),
        ('then server did not observe header "X-Intercepted"',),
        "clear_leaves_interceptor_handler_installed",
        "Interceptor lifecycle behavior is observable.",
    ),
    Rule(
        "user_agent_header_can_be_omitted",
        r"ability to omit User-Agent header|omit User-Agent",
        "http.headers.user-agent-omission",
        ('given request header "User-Agent" false',),
        ('when GET "/"',),
        ('then request header "User-Agent" absent'),
        "send_false_user_agent_literal",
        "Header omission is wire-visible.",
    ),
    Rule(
        "timeout_string_is_parsed_as_milliseconds",
        r"Adding parseInt to config.timeout|timeout.*string",
        "http.timeout.string-parsed",
        ('given timeout "50"', 'given server delays 250ms'),
        ('when GET "/"',),
        ('then timeout error elapsed_ms < 200',),
        "ignore_string_timeout",
        "Timeout parsing is externally observable.",
    ),
    Rule(
        "custom_timeout_error_message_is_used",
        r"custom timeout error copy|timeoutErrorMessage",
        "http.timeout.custom-error-message",
        ('given timeout 50ms timeoutErrorMessage "too slow"', 'given server delays 250ms'),
        ('when GET "/"',),
        ('then error message "too slow"',),
        "ignore_custom_timeout_error_message",
        "Timeout error message is observable.",
    ),
    Rule(
        "validate_status_null_accepts_every_status",
        r"validateStatus.*null|type 'null' is not assignable to validateStatus",
        "http.response.validate-status-null-accepts-all",
        ('given server status 503',),
        ('when GET "/" validateStatus null',),
        ('then promise resolved status 503',),
        "treat_validate_status_null_as_default_validator",
        "Status validation behavior is observable.",
    ),
    Rule(
        "utf8_bom_is_removed_before_json_parse",
        r"utf-8 BOM.*parse to json|remove byte order marker|BOM",
        "http.response.json-utf8-bom-stripped",
        ('given server JSON body UTF8_BOM + {"ok":true}',),
        ('when GET "/" responseType "json"',),
        ('then response data {"ok":true}',),
        "pass_bom_to_json_parse",
        "JSON preprocessing is observable.",
    ),
    Rule(
        "delete_request_sends_config_data",
        r"axios.delete ignores config.data|DELETE.*data as a config option",
        "http.request.delete-config-data-body",
        ('given DELETE config data "payload"',),
        ('when DELETE "/"',),
        ('then server observed body "payload"',),
        "drop_delete_config_data",
        "DELETE body dispatch is wire-visible.",
    ),
    Rule(
        "missing_url_rejects_before_dispatch",
        r"error handling when missing url|missing url",
        "http.url.missing-url-rejection",
        ('given no url',),
        ('when axios.request({})',),
        ('then promise rejected before dispatch'),
        "dispatch_missing_url_to_localhost",
        "Missing URL validation is deterministic.",
    ),
    Rule(
        "response_encoding_latin1_decodes_bytes",
        r"option to specify character set in responses|responseEncoding",
        "http.response.response-encoding",
        ('given server body byte E9',),
        ('when GET "/" responseEncoding "latin1"',),
        ('then response text "é"',),
        "ignore_response_encoding",
        "Response character decoding is observable.",
    ),
    Rule(
        "max_content_length_destroys_oversized_stream",
        r"Destroy stream on exceeding maxContentLength|exceeding maxContentLength",
        "http.response.max-content-length-destroys-stream",
        ('given server streams body length 1024',),
        ('when GET "/" maxContentLength 1',),
        ('then request rejected', 'then server socket closes'),
        "accept_oversized_response_body",
        "Response size enforcement is observable.",
    ),
)

DISABLED_RULES = {
    # The release note says the data: URI regular expression became stricter,
    # but Axios 1.19.0 still accepts the concrete malformed base64 variants we
    # can replay locally by returning an empty Buffer. Do not emit a contract
    # until a surviving, executable boundary can be specified.
    "data_uri_parser_rejects_invalid_base64",
}


def load_release_notes() -> dict[str, dict]:
    npm_time = json.loads((REPLAY / "npm_time.json").read_text())
    releases = {
        version: {
            "version": version,
            "date": date[:10],
            "source": "npm_time",
            "notes": "",
        }
        for version, date in npm_time.items()
        if version and version[0].isdigit()
    }
    for page in sorted(REPLAY.glob("github_releases_page*.json")):
        for rel in json.loads(page.read_text()):
            version = rel.get("tag_name", "").lstrip("v")
            if version not in releases:
                continue
            body = rel.get("body") or ""
            releases[version].update({
                "date": (rel.get("published_at") or releases[version]["date"])[:10],
                "source": "github_release",
                "notes": body,
            })
    return releases


def load_merged_common() -> tuple[set[str], set[str]]:
    merged = json.loads(MERGED.read_text())
    keys = {row["semantic_key"] for row in merged["results"]}
    caps = {member["capability"] for row in merged["results"] for member in row["members"]}
    return keys, caps


def make_rpl(releases: list[dict]) -> str:
    lines = []
    for release in releases:
        lines.append(f'release "axios" "{release["version"]}" date "{release["date"]}"')
        for contract in release["contracts"]:
            lines.append(f'contract "{contract["name"]}"')
            lines.append(f'evidence "{contract["evidence"].replace(chr(34), chr(39))}"')
            lines.append(f'capability "{contract["capability"]}"')
            lines.append(f'reason "{contract["rule_reason"]}"')
            lines.append(f'mutant "{contract["mutant"]}"')
            for stmt in contract["setup"] + contract["actions"] + contract["assertions"]:
                lines.append(stmt)
            lines.append("end")
        lines.append("end")
    return "\n".join(lines) + "\n"


def make_audit(releases: list[dict]) -> str:
    lines = [
        "# Axios-Origin Extraction Audit",
        "",
        "- source: npm time ledger + GitHub release bodies",
        "- exclusion: merged common 115 semantic keys and exact capabilities",
        "- rule: only runtime HTTP/client contracts with local replay adapters are emitted",
        "",
        "| version | date | source | contracts |",
        "|---:|---|---|---:|",
    ]
    for rel in releases:
        lines.append(f"| {rel['version']} | {rel['date']} | {rel['source']} | {len(rel['contracts'])} |")
    lines += ["", "## Non-Empty Releases", ""]
    for rel in releases:
        if not rel["contracts"]:
            continue
        lines.append(f"### {rel['version']} ({rel['date']})")
        for c in rel["contracts"]:
            lines.append(f"- `{c['name']}`: {c['evidence']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    merged_keys, merged_caps = load_merged_common()
    notes = load_release_notes()
    releases = []
    for version in sorted(notes, key=lambda v: [int(x) if x.isdigit() else x for x in re.split(r"[.-]", v)]):
        rel = dict(notes[version])
        text = rel["notes"]
        contracts = []
        if text:
            for rule in RULES:
                if rule.name in DISABLED_RULES:
                    continue
                if semkey(rule.name) in merged_keys or rule.capability in merged_caps:
                    continue
                match = re.search(rule.pattern, text, flags=re.I | re.S)
                if not match:
                    continue
                evidence = re.sub(r"\s+", " ", match.group(0)).strip()
                contracts.append({
                    "name": rule.name,
                    "capability": rule.capability,
                    "evidence": evidence[:360],
                    "setup": list(rule.setup),
                    "actions": list(rule.actions),
                    "assertions": list(rule.assertions),
                    "mutant": rule.mutant,
                    "rule_reason": rule.reason,
                })
        rel["contracts"] = contracts
        releases.append(rel)
    payload = {
        "project": "axios",
        "latest_npm_version": "1.19.0",
        "release_count_from_npm": len(releases),
        "release_count_with_notes": sum(1 for r in releases if r["notes"]),
        "contract_rows": sum(len(r["contracts"]) for r in releases),
        "unique_contracts": len({c["name"] for r in releases for c in r["contracts"]}),
        "excluded_common_count": 115,
        "rules": [r.name for r in RULES],
        "releases": releases,
    }
    OUT_JSON.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    OUT_RPL.write_text(make_rpl(releases))
    OUT_AUDIT.write_text(make_audit(releases))
    print(json.dumps({
        "releases": payload["release_count_from_npm"],
        "with_notes": payload["release_count_with_notes"],
        "contract_rows": payload["contract_rows"],
        "unique_contracts": payload["unique_contracts"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
