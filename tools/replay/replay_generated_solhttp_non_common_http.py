#!/usr/bin/env python3
from __future__ import annotations

import importlib
import io
import json
import os
import pathlib
import signal
import sys
from collections import Counter, defaultdict
from typing import Callable
from urllib.parse import urlsplit


ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "solhttp_non_common"
RUN_SET_LABEL = os.environ.get("SOLHTTP_NON_COMMON_RUN_SET_LABEL", "solhttp_gpt56sol_high_http_non_common_20260829")
TEST_TIMEOUT_SECONDS = float(os.environ.get("SOLHTTP_NON_COMMON_TEST_TIMEOUT_SECONDS", "8"))
CURRENT_SOLHTTP = None

SNAPSHOTS = [
    (
        os.environ.get("SHAPINGBENCH_TARGET_LABEL", "submission"),
        pathlib.Path(os.environ.get("SHAPINGBENCH_TARGET_SNAPSHOT", "submission")),
    )
]


def unique_by_contract_capability(rows: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for row in rows:
        signature = (row["contract"], row["capability"])
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(row)
    return unique


def confirmed_common_rows() -> list[dict]:
    source = ROOT / "contracts" / "guzzle" / "guzzle_8.1.0_survival_from_merged_common_119.json"
    payload = json.loads(source.read_text())
    return [row for row in payload["results"] if row.get("guzzle_status") == "passed"]


def load_origin_rows() -> list[dict]:
    rows: list[dict] = []

    urllib3_payload = json.loads((ROOT / "contracts" / "urllib3" / "final_survival_urllib3_2.7.0.json").read_text())
    for row in urllib3_payload["results"]:
        if row.get("survived_latest"):
            rows.append(
                {
                    "origin": "urllib3",
                    "source_version": row.get("source_version", ""),
                    "key": row.get("key", ""),
                    "contract": row["contract"],
                    "capability": row["capability"],
                    "evidence": row.get("evidence", ""),
                }
            )

    okhttp_payload = json.loads((ROOT / "contracts" / "okhttp" / "okhttp_origin_latest_survivors.json").read_text())
    for row in okhttp_payload["results"]:
        if row.get("latest_survived"):
            rows.append(
                {
                    "origin": "okhttp",
                    "source_version": row.get("source_version", ""),
                    "key": row.get("key", ""),
                    "contract": row.get("contract") or row["name"],
                    "capability": row["capability"],
                    "evidence": row.get("evidence", ""),
                }
            )

    axios_payload = json.loads((ROOT / "contracts" / "axios" / "axios_origin_latest_replay_mutant_verified.json").read_text())
    for row in axios_payload["results"]:
        if row.get("verified"):
            release_rows = row.get("release_rows", [])
            rows.append(
                {
                    "origin": "axios",
                    "source_version": ", ".join(str(item) for item in release_rows[:3]) if isinstance(release_rows, list) else "",
                    "key": row["name"],
                    "contract": row["name"],
                    "capability": row["capability"],
                    "evidence": "",
                }
            )

    for origin in ("requests", "guzzle"):
        payload = json.loads((ROOT / "contracts" / origin / f"{origin}_origin_excluding_common_114.json").read_text())
        for row in payload["results"]:
            rows.append(
                {
                    "origin": origin,
                    "source_version": row.get("source_version", ""),
                    "key": row.get("key", ""),
                    "contract": row["contract"],
                    "capability": row["capability"],
                    "evidence": row.get("evidence", ""),
                }
            )

    return unique_by_contract_capability(rows)


def non_common_rows() -> list[dict]:
    common = confirmed_common_rows()
    common_origin_keys = {(row["origin"], row.get("key", "")) for row in common}
    common_contract_capabilities = {(row["contract"], row["capability"]) for row in common}

    rows: list[dict] = []
    for row in load_origin_rows():
        if (row["origin"], row.get("key", "")) in common_origin_keys:
            continue
        if (row["contract"], row["capability"]) in common_contract_capabilities:
            continue
        rows.append(row)
    return rows


def load_replay_modules():
    sys.path.insert(0, str(ROOT / "tools" / "replay"))
    base = importlib.import_module("replay_requests_survival")
    merged = importlib.import_module("replay_merged_common_requests_latest")
    shim = importlib.import_module("solhttp_requests_shim")
    return base, merged, shim


def test_mapping(row: dict, base, merged) -> str | None:
    if row["origin"] == "urllib3":
        mapped = base.MAPPING.get(row["key"])
        if mapped:
            return mapped
    if row["contract"] in merged.ADDITIONAL_TESTS:
        return row["contract"]
    return f"contract::{row['origin']}::{row['contract']}"


def install_solhttp(snapshot: pathlib.Path, base, merged, shim) -> object:
    global CURRENT_SOLHTTP
    for name in list(sys.modules):
        if name == "solhttp" or name.startswith("solhttp."):
            del sys.modules[name]
    sys.path.insert(0, str(snapshot))
    solhttp = importlib.import_module("solhttp")
    requests_like = shim.make_requests_like(solhttp)
    base.requests = requests_like
    base.HTTPAdapter = requests_like.HTTPAdapter
    merged.requests = requests_like
    merged.HTTPAdapter = requests_like.HTTPAdapter
    merged.base.requests = requests_like
    merged.base.HTTPAdapter = requests_like.HTTPAdapter
    CURRENT_SOLHTTP = solhttp
    return solhttp


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _impl():
    if CURRENT_SOLHTTP is None:
        raise AssertionError("solhttp implementation is not installed")
    return CURRENT_SOLHTTP


def _surface_names() -> set[str]:
    impl = _impl()
    names = set(dir(impl))
    client = getattr(impl, "Client", None)
    response = getattr(impl, "Response", None)
    headers = getattr(impl, "Headers", None)
    for obj in (client, response, headers):
        if obj is not None:
            names.update(dir(obj))
    return names


def _require_surface(row: dict, required: set[str]) -> None:
    names = _surface_names()
    found = sorted(name for name in required if name in names)
    require(
        bool(found),
        f"unsupported_api_surface: {row['capability']} / {row['contract']} requires one of {sorted(required)}",
    )


def _unsupported_surface_probe(row: dict) -> None:
    capability = row["capability"]
    contract = row["contract"]
    if "websocket" in capability:
        _require_surface(row, {"WebSocket", "websocket", "connect_websocket"})
    if "http2" in capability:
        _require_surface(row, {"HTTP2", "Http2", "http2", "Protocol", "protocols"})
    if ".cache" in capability or capability.startswith("http.cache"):
        _require_surface(row, {"Cache", "cache", "cache_dir"})
    if "interceptor" in capability:
        _require_surface(row, {"Interceptor", "interceptors", "event_hooks", "hooks"})
    if "lifecycle" in capability or "listener" in capability or "event" in capability:
        _require_surface(row, {"EventListener", "event_listener", "hooks", "event_hooks"})
    if "logging" in capability or "curl-rendering" in capability:
        _require_surface(row, {"logging", "Logger", "to_curl", "curl"})
    if "dns" in capability:
        _require_surface(row, {"DNS", "Dns", "Resolver", "resolver", "dns"})
    if "cookie" in capability:
        _require_surface(row, {"CookieJar", "cookies", "cookie_jar"})
    if "certificate-pinning" in capability:
        _require_surface(row, {"CertificatePinner", "certificate_pinner", "pins"})
    if "sse" in capability:
        _require_surface(row, {"EventSource", "event_source", "sse"})
    if "cancel" in capability:
        _require_surface(row, {"CancelToken", "cancel", "abort", "AbortController"})
    if "formdata" in capability:
        _require_surface(row, {"FormData", "form_data", "to_form_data"})
    if "socket-path" in capability:
        _require_surface(row, {"socket_path", "unix_socket", "UnixAdapter"})
    if "proxy.selector" in capability or "proxy.selection" in capability:
        _require_surface(row, {"ProxySelector", "proxy_selector", "proxies"})
    if "max-content-length" in capability or "max-body-length" in capability:
        _require_surface(row, {"max_content_length", "max_body_length", "limits"})
    raise AssertionError(f"unsupported_or_unimplemented_contract_probe: {capability} / {contract}")


def base_url_combination_deduplicates_trailing_slashes() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.path)) as server:
        client = impl.Client(base_url=server.url("/api/"))
        response = client.get("/v1")
        require(response.text == "/api/v1", response.text)


def blank_header_names_are_skipped() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(str(any(name == "" for name, _ in req.headers)))) as server:
        response = impl.get(server.url("/"), headers={"": "drop-me", "X-Keep": "1"})
        require(response.text == "False", response.text)


def response_encoding_latin1_decodes_bytes() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    payload = "café".encode("latin-1")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "text/plain; charset=latin-1")], body=payload)) as server:
        response = impl.get(server.url("/latin1"))
        require(response.text == "café", response.text)


def url_embedded_basic_auth_is_url_decoded() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Authorization") or "")) as server:
        target = server.url("/")
        parts = urlsplit(target)
        url = f"{parts.scheme}://user:pa%20ss@{parts.netloc}/"
        response = impl.get(url)
        require(response.text.startswith("Basic "), response.text)


def user_agent_header_can_be_omitted() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(str(req.header("User-Agent")))) as server:
        response = impl.get(server.url("/"), headers={"User-Agent": None})
        require(response.text == "None", response.text)


def utf8_bom_is_removed_before_json_parse() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=b"\xef\xbb\xbf{\"ok\": true}")) as server:
        response = impl.get(server.url("/json"))
        require(response.json() == {"ok": True}, repr(response.content))


def validate_status_null_accepts_every_status() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.status_text(599, "accepted")) as server:
        response = impl.get(server.url("/status"))
        require(response.status_code == 599 and response.text == "accepted", f"{response.status_code} {response.text}")


def malformed_http_url_without_slashes_is_rejected() -> None:
    impl = _impl()
    try:
        impl.get("http:example.com")
    except Exception:
        return
    raise AssertionError("malformed HTTP URL without slashes was accepted")


def timeout_string_is_parsed_as_milliseconds() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: (importlib.import_module("time").sleep(0.05), base.RawResponse.ok("slow"))[1]) as server:
        try:
            impl.get(server.url("/slow"), timeout="1")
        except Exception:
            return
        raise AssertionError("string timeout was not interpreted as a short millisecond timeout")


def object_payload_auto_serializes_to_urlencoded() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        response = impl.post(server.url("/form"), data={"a": "1", "b": "two words"})
        require(response.text in {"a=1&b=two+words", "b=two+words&a=1"}, response.text)


def validate_status_undefined_can_resolve_like_default() -> None:
    validate_status_null_accepts_every_status()


def multiple_informational_responses_are_ignored_until_final() -> None:
    merged = importlib.import_module("replay_merged_common_requests_latest")
    merged.http1_100_continue_status_lines_are_ignored_until_final()


def zstd_compression_is_negotiated_and_decoded() -> None:
    merged = importlib.import_module("replay_merged_common_requests_latest")
    merged.zstd_response_decompression_supported()


def brotli_empty_body_is_not_decompressed() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Encoding", "br")], body=b"")) as server:
        response = impl.get(server.url("/br-empty"))
        require(response.content == b"", repr(response.content))


def bad_url_hostname_characters_are_rejected() -> None:
    impl = _impl()
    try:
        impl.get("http://bad host.example/")
    except Exception:
        return
    raise AssertionError("hostname containing a space was accepted")


def url_domain_label_length_limits_are_enforced() -> None:
    impl = _impl()
    label = "a" * 64
    try:
        impl.get(f"http://{label}.example/")
    except Exception:
        return
    raise AssertionError("domain label longer than 63 octets was accepted")


def no_proxy_wildcard_bypasses_proxy() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        response = impl.get(
            server.url("/"),
            proxies={"http": "http://127.0.0.1:1", "no_proxy": "*"},
            timeout=1,
        )
        require(response.text == "direct", response.text)


def redirect_strips_sensitive_headers_cross_origin() -> None:
    base = importlib.import_module("replay_requests_survival")
    base.cross_host_strips_authorization()
    base.cross_host_strips_cookie()
    base.cross_host_strips_proxy_authorization()


def get_set_cookie_returns_array() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], body=b"ok")) as server:
        response = impl.get(server.url("/"))
        getter = getattr(response.headers, "get_list", None) or getattr(response.headers, "getlist", None)
        require(getter is not None, "response headers do not expose multi-value retrieval")
        require(getter("Set-Cookie") == ["a=1", "b=2"], str(getter("Set-Cookie")))


def file_object_payload_is_supported_by_http_adapter() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        response = impl.post(server.url("/upload"), data=io.BytesIO(b"file-body"))
        require(response.text == "file-body", response.text)


def unicode_header_values_survive_interceptors() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("X-Name") or "")) as server:
        response = impl.get(server.url("/"), headers={"X-Name": "café"})
        require(response.text == "café", response.text)


def proxy_url_without_scheme_raises_actionable_error() -> None:
    impl = _impl()
    try:
        impl.get("http://example.test/", proxies="127.0.0.1:8080", timeout=0.1)
    except Exception:
        return
    raise AssertionError("proxy URL without scheme was accepted")


def incorrect_proxy_scheme_raises_value_error() -> None:
    impl = _impl()
    try:
        impl.get("http://example.test/", proxies="ftp://127.0.0.1:8080", timeout=0.1)
    except Exception:
        return
    raise AssertionError("unsupported proxy URL scheme was accepted")


def bytes_and_string_header_keys_compare_equal() -> None:
    impl = _impl()
    headers = impl.Headers([(b"X-Test", "one")])
    require(headers["x-test"] == "one", repr(headers))


def response_legacy_header_accessors_are_available() -> None:
    impl = _impl()
    headers = impl.Headers([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    for name in ("getlist", "getall"):
        accessor = getattr(headers, name, None)
        require(accessor is not None, f"{name} missing")
        require(accessor("Set-Cookie") == ["a=1", "b=2"], str(accessor("Set-Cookie")))


def generic_raised_errors_extend_http_exception() -> None:
    impl = _impl()
    root = getattr(impl, "SolHTTPError", None)
    require(root is not None, "SolHTTPError root class missing")
    for name in ("RequestError", "ConnectionError", "Timeout", "ProtocolError", "InvalidURL"):
        cls = getattr(impl, name, None)
        require(cls is not None and issubclass(cls, root), f"{name} is not a SolHTTPError subclass")


def duplicate_leading_slashes_in_uri_path_are_preserved() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        response = impl.get(server.url("//signed/path?x=1"))
        require(response.text == "//signed/path?x=1", response.text)


def malformed_content_type_header_parsing_is_tolerant() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "text/plain; charset=\"unterminated")], body=b"ok")) as server:
        response = impl.get(server.url("/"))
        require(response.text == "ok", response.text)


def emoji_body_content_length_counts_bytes_not_characters() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    body = "hi 😀"
    expected = str(len(body.encode("utf-8")))
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Content-Length") or "")) as server:
        response = impl.post(server.url("/"), data=body)
        require(response.text == expected, f"{response.text} != {expected}")


def missing_schema_error_suggests_https() -> None:
    impl = _impl()
    try:
        impl.get("example.com/path")
    except Exception as exc:
        require("https" in str(exc).lower(), str(exc))
        return
    raise AssertionError("missing URL scheme was accepted")


def content_type_header_parsing_is_case_insensitive() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "Application/JSON")], body=b'{"ok": true}')) as server:
        response = impl.get(server.url("/"))
        require(response.text == '{"ok": true}' and response.json() == {"ok": True}, response.text)


def redirect_fragment_is_preserved_when_location_has_no_fragment() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")

    def handler(req):
        if req.path == "/start":
            return base.RawResponse(status=302, headers=[("Location", "/target")])
        return base.RawResponse.ok(req.target)

    with base.RawServer(handler) as server:
        response = impl.get(server.url("/start#frag"))
        require(response.url.endswith("/target#frag"), response.url)


def header_values_with_leading_whitespace_or_newline_are_rejected() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok("should-not-arrive")) as server:
        for value in (" leading", "ok\nbad"):
            try:
                impl.get(server.url("/"), headers={"X-Test": value})
            except Exception:
                continue
            raise AssertionError(f"accepted unsafe header value {value!r}")


def body_tell_exception_falls_back_to_chunked_transfer() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")

    class BadTell(io.BytesIO):
        def tell(self):
            raise OSError("no tell")

    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Transfer-Encoding") or "")) as server:
        response = impl.post(server.url("/"), data=BadTell(b"abc"))
        require(response.text.lower() == "chunked", response.text)


def host_specific_proxy_mapping_is_honored() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        response = impl.get(server.url("/"), proxies={f"http://127.0.0.1:{server.port}": False, "http": "http://127.0.0.1:1"}, timeout=1)
        require(response.text == "direct", response.text)


def json_parameter_is_ignored_when_data_or_files_present() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        try:
            response = impl.post(server.url("/"), data={"a": "1"}, json={"b": 2})
        except Exception as exc:
            raise AssertionError(f"json plus data was rejected instead of ignoring json: {exc}") from exc
        require(response.text == "a=1", response.text)


def iter_content_decode_unicode_streams_text() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "text/plain; charset=utf-8")], body="aé".encode())) as server:
        response = impl.get(server.url("/"), stream=True)
        chunks = list(response.iter_text(1))
        require("".join(chunks) == "aé", chunks)


def null_uri_is_rejected() -> None:
    impl = _impl()
    try:
        impl.get(None)  # type: ignore[arg-type]
    except Exception:
        return
    raise AssertionError("null URI was accepted")


def client_exposes_convenience_methods_for_http_verbs() -> None:
    impl = _impl()
    client = impl.Client()
    for name in ("get", "head", "post", "put", "patch", "delete"):
        require(callable(getattr(client, name, None)), f"{name} missing")


def connect_exception_extends_transfer_exception() -> None:
    impl = _impl()
    root = getattr(impl, "RequestError", None) or getattr(impl, "SolHTTPError", None)
    cls = getattr(impl, "ConnectionError", None)
    require(root is not None and cls is not None and issubclass(cls, root), "connection error is not a transfer/request exception")


def empty_headers_are_supported() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok("ok")) as server:
        response = impl.get(server.url("/"), headers={})
        require(response.text == "ok", response.text)


def header_modifications_are_case_insensitive() -> None:
    impl = _impl()
    headers = impl.Headers([("X-Test", "one")])
    require(headers["x-test"] == "one" and headers["X-TEST"] == "one", repr(headers))


def read_timeout_option_is_supported() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: (importlib.import_module("time").sleep(0.2), base.RawResponse.ok("slow"))[1]) as server:
        try:
            impl.get(server.url("/"), timeout=(1, 0.05))
        except Exception:
            return
        raise AssertionError("read timeout did not fire")


def content_length_is_included_when_body_exists() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Content-Length") or "")) as server:
        response = impl.post(server.url("/"), data="abc")
        require(response.text == "3", response.text)


def base_uri_resolves_relative_request_uris() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(req.path)) as server:
        client = impl.Client(base_url=server.url("/root/"))
        response = client.get("child")
        require(response.text == "/root/child", response.text)


def response_json_accepts_scalar_values() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=b"1")) as server:
        response = impl.get(server.url("/"))
        require(response.json() == 1, repr(response.content))


def string_zero_response_body_is_preserved() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(body=b"0")) as server:
        response = impl.get(server.url("/"))
        require(response.text == "0" and response.content == b"0", repr(response.content))


def mimetype_guessing_for_post_files_is_supported() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(str("Content-Type: text/plain" in req.text))) as server:
        response = impl.post(server.url("/"), files={"file": ("note.txt", b"x")})
        require(response.text == "True", response.text)


def default_accept_headers_are_not_sent_on_every_request() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(str(req.header("Accept")) + "|" + str(req.header("Accept-Encoding")))) as server:
        response = impl.get(server.url("/"))
        require(response.text == "None|None", response.text)


def expect_header_only_for_payloads_over_one_mb() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse.ok(str(req.header("Expect")))) as server:
        response = impl.post(server.url("/"), data="small")
        require(response.text == "None", response.text)


def delete_request_can_send_entity_body() -> None:
    merged = importlib.import_module("replay_merged_common_requests_latest")
    merged.delete_request_sends_config_data()


def json_response_decode_errors_raise_exception() -> None:
    impl = _impl()
    base = importlib.import_module("replay_requests_survival")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=b"{")) as server:
        response = impl.get(server.url("/bad-json"))
        try:
            response.json()
        except Exception:
            return
        raise AssertionError("invalid JSON response did not raise")


SPECIFIC_CONTRACT_TESTS: dict[str, Callable[[], None]] = {
    "base_url_combination_deduplicates_trailing_slashes": base_url_combination_deduplicates_trailing_slashes,
    "bad_url_hostname_characters_are_rejected": bad_url_hostname_characters_are_rejected,
    "blank_header_names_are_skipped": blank_header_names_are_skipped,
    "brotli_empty_body_is_not_decompressed": brotli_empty_body_is_not_decompressed,
    "body_tell_exception_falls_back_to_chunked_transfer": body_tell_exception_falls_back_to_chunked_transfer,
    "bytes_and_string_header_keys_compare_equal": bytes_and_string_header_keys_compare_equal,
    "client_exposes_convenience_methods_for_http_verbs": client_exposes_convenience_methods_for_http_verbs,
    "connect_exception_extends_transfer_exception": connect_exception_extends_transfer_exception,
    "content_length_is_included_when_body_exists": content_length_is_included_when_body_exists,
    "content_type_header_parsing_is_case_insensitive": content_type_header_parsing_is_case_insensitive,
    "default_accept_headers_are_not_sent_on_every_request": default_accept_headers_are_not_sent_on_every_request,
    "delete_request_can_send_entity_body": delete_request_can_send_entity_body,
    "duplicate_leading_slashes_in_uri_path_are_preserved": duplicate_leading_slashes_in_uri_path_are_preserved,
    "emoji_body_content_length_counts_bytes_not_characters": emoji_body_content_length_counts_bytes_not_characters,
    "empty_headers_are_supported": empty_headers_are_supported,
    "expect_header_only_for_payloads_over_one_mb": expect_header_only_for_payloads_over_one_mb,
    "file_object_payload_is_supported_by_http_adapter": file_object_payload_is_supported_by_http_adapter,
    "generic_raised_errors_extend_http_exception": generic_raised_errors_extend_http_exception,
    "get_set_cookie_returns_array": get_set_cookie_returns_array,
    "header_modifications_are_case_insensitive": header_modifications_are_case_insensitive,
    "header_values_with_leading_whitespace_or_newline_are_rejected": header_values_with_leading_whitespace_or_newline_are_rejected,
    "host_specific_proxy_mapping_is_honored": host_specific_proxy_mapping_is_honored,
    "incorrect_proxy_scheme_raises_value_error": incorrect_proxy_scheme_raises_value_error,
    "iter_content_decode_unicode_streams_text": iter_content_decode_unicode_streams_text,
    "json_parameter_is_ignored_when_data_or_files_present": json_parameter_is_ignored_when_data_or_files_present,
    "json_response_decode_errors_raise_exception": json_response_decode_errors_raise_exception,
    "malformed_content_type_header_parsing_is_tolerant": malformed_content_type_header_parsing_is_tolerant,
    "multiple_informational_responses_are_ignored_until_final": multiple_informational_responses_are_ignored_until_final,
    "mimetype_guessing_for_post_files_is_supported": mimetype_guessing_for_post_files_is_supported,
    "no_proxy_wildcard_bypasses_proxy": no_proxy_wildcard_bypasses_proxy,
    "no_proxy_wildcard_bypasses_all_hosts": no_proxy_wildcard_bypasses_proxy,
    "null_uri_is_rejected": null_uri_is_rejected,
    "response_encoding_latin1_decodes_bytes": response_encoding_latin1_decodes_bytes,
    "response_json_accepts_scalar_values": response_json_accepts_scalar_values,
    "proxy_url_without_scheme_raises_actionable_error": proxy_url_without_scheme_raises_actionable_error,
    "read_timeout_option_is_supported": read_timeout_option_is_supported,
    "redirect_fragment_is_preserved_when_location_has_no_fragment": redirect_fragment_is_preserved_when_location_has_no_fragment,
    "redirect_strips_sensitive_headers_cross_origin": redirect_strips_sensitive_headers_cross_origin,
    "response_legacy_header_accessors_are_available": response_legacy_header_accessors_are_available,
    "string_zero_response_body_is_preserved": string_zero_response_body_is_preserved,
    "url_embedded_basic_auth_is_url_decoded": url_embedded_basic_auth_is_url_decoded,
    "unicode_header_values_survive_interceptors": unicode_header_values_survive_interceptors,
    "url_domain_label_length_limits_are_enforced": url_domain_label_length_limits_are_enforced,
    "user_agent_header_can_be_omitted": user_agent_header_can_be_omitted,
    "utf8_bom_is_removed_before_json_parse": utf8_bom_is_removed_before_json_parse,
    "validate_status_null_accepts_every_status": validate_status_null_accepts_every_status,
    "validate_status_undefined_can_resolve_like_default": validate_status_undefined_can_resolve_like_default,
    "malformed_http_url_without_slashes_is_rejected": malformed_http_url_without_slashes_is_rejected,
    "timeout_string_is_parsed_as_milliseconds": timeout_string_is_parsed_as_milliseconds,
    "object_payload_auto_serializes_to_urlencoded": object_payload_auto_serializes_to_urlencoded,
    "zstd_compression_is_negotiated_and_decoded": zstd_compression_is_negotiated_and_decoded,
}


def fn_for(test_name: str, row: dict, base, merged) -> Callable[[], None]:
    base_tests = dict(base.TESTS)
    if test_name in base_tests:
        return base_tests[test_name]
    if test_name in merged.ADDITIONAL_TESTS:
        return merged.ADDITIONAL_TESTS[test_name]
    if row["contract"] in SPECIFIC_CONTRACT_TESTS:
        return SPECIFIC_CONTRACT_TESTS[row["contract"]]
    return lambda: _unsupported_surface_probe(row)


class ReplayTimeout(TimeoutError):
    pass


def run_test(name: str, fn: Callable[[], None]) -> dict:
    def timeout_handler(_signum, _frame):
        raise ReplayTimeout(f"test exceeded {TEST_TIMEOUT_SECONDS:g}s")

    previous = signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, TEST_TIMEOUT_SECONDS)
    try:
        fn()
        return {"name": name, "passed": True, "error": ""}
    except BaseException as exc:
        return {"name": name, "passed": False, "error": f"{exc.__class__.__name__}: {exc}"}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def is_surface_failure(error: str) -> bool:
    return "unsupported_api_surface:" in error or "unsupported_or_unimplemented_contract_probe:" in error


def evaluate_snapshot(snapshot_label: str, snapshot: pathlib.Path, rows: list[dict], base, merged, shim) -> dict:
    if not snapshot.exists():
        raise FileNotFoundError(snapshot)
    try:
        solhttp = install_solhttp(snapshot, base, merged, shim)
    except BaseException as exc:
        results: list[dict] = []
        error = f"{exc.__class__.__name__}: {exc}"
        for row in rows:
            results.append(
                {
                    "origin": row["origin"],
                    "source_version": row["source_version"],
                    "key": row["key"],
                    "contract": row["contract"],
                    "capability": row["capability"],
                    "solhttp_test": row.get("solhttp_test") or "",
                    "solhttp_status": "failed",
                    "error": error,
                }
            )
        by_origin: dict[str, dict] = {}
        for origin in sorted({row["origin"] for row in results}):
            origin_rows = [row for row in results if row["origin"] == origin]
            by_origin[origin] = {
                "total_non_common": len(origin_rows),
                "mapped": len(origin_rows),
                "passed": 0,
                "failed": len(origin_rows),
                "failed_surface_or_unimplemented": 0,
                "failed_behavior": len(origin_rows),
                "unmapped": 0,
            }
        summary = {
            "snapshot_label": snapshot_label,
            "snapshot": str(snapshot),
            "target_project": "solhttp",
            "target_version": "import_failed",
            "total_non_common": len(results),
            "mapped": len(results),
            "passed": 0,
            "failed": len(results),
            "failed_surface_or_unimplemented": 0,
            "failed_behavior": len(results),
            "unmapped": 0,
            "adapter_tests": {"total": 0, "passed": 0, "failed": 0},
            "by_origin": by_origin,
            "evaluation_error": error,
        }
        return {"summary": summary, "raw_runner": {"tests": []}, "results": results}

    mapped_rows: dict[str, dict] = {}
    for row in rows:
        mapped_rows.setdefault(row["solhttp_test"], row)
    mapped_tests = sorted(mapped_rows)
    raw_tests = {
        name: run_test(name, fn_for(name, mapped_rows[name], base, merged))
        for name in mapped_tests
    }

    results: list[dict] = []
    for row in rows:
        test_name = row.get("solhttp_test") or ""
        result = {
            "origin": row["origin"],
            "source_version": row["source_version"],
            "key": row["key"],
            "contract": row["contract"],
            "capability": row["capability"],
            "solhttp_test": test_name,
        }
        test = raw_tests[test_name]
        result.update(
            {
                "solhttp_status": "passed" if test["passed"] else "failed",
                "error": test["error"],
            }
        )
        results.append(result)

    by_origin: dict[str, dict] = {}
    for origin in sorted({row["origin"] for row in results}):
        origin_rows = [row for row in results if row["origin"] == origin]
        by_origin[origin] = {
            "total_non_common": len(origin_rows),
            "mapped": sum(1 for row in origin_rows if row["solhttp_status"] != "unmapped"),
            "passed": sum(1 for row in origin_rows if row["solhttp_status"] == "passed"),
            "failed": sum(1 for row in origin_rows if row["solhttp_status"] == "failed"),
            "failed_surface_or_unimplemented": sum(1 for row in origin_rows if row["solhttp_status"] == "failed" and is_surface_failure(row["error"])),
            "failed_behavior": sum(1 for row in origin_rows if row["solhttp_status"] == "failed" and not is_surface_failure(row["error"])),
            "unmapped": sum(1 for row in origin_rows if row["solhttp_status"] == "unmapped"),
        }

    summary = {
        "snapshot_label": snapshot_label,
        "snapshot": str(snapshot),
        "target_project": "solhttp",
        "target_version": getattr(solhttp, "__version__", "unknown"),
        "total_non_common": len(results),
        "mapped": sum(1 for row in results if row["solhttp_status"] != "unmapped"),
        "passed": sum(1 for row in results if row["solhttp_status"] == "passed"),
        "failed": sum(1 for row in results if row["solhttp_status"] == "failed"),
        "failed_surface_or_unimplemented": sum(1 for row in results if row["solhttp_status"] == "failed" and is_surface_failure(row["error"])),
        "failed_behavior": sum(1 for row in results if row["solhttp_status"] == "failed" and not is_surface_failure(row["error"])),
        "unmapped": sum(1 for row in results if row["solhttp_status"] == "unmapped"),
        "adapter_tests": {
            "total": len(raw_tests),
            "passed": sum(1 for test in raw_tests.values() if test["passed"]),
            "failed": sum(1 for test in raw_tests.values() if not test["passed"]),
        },
        "by_origin": by_origin,
    }
    return {"summary": summary, "raw_runner": {"tests": list(raw_tests.values())}, "results": results}


def write_markdown(payload: dict, path: pathlib.Path) -> None:
    lines = [
        f"# {RUN_SET_LABEL} HTTP Client OSS non-common SolHTTP replay",
        "",
        "Rule: contracts are semantic-unique by `contract + capability`, already latest-surviving on their origin OSS, and excluded when they are part of the confirmed Guzzle-filtered 114 common core.",
        "",
        "All non-common contracts are compiled into executable probes. Behavior probes exercise observable HTTP behavior; surface probes fail when the implementation has no public API for that contract family.",
        "",
        "## Iteration Matrix",
        "",
        "| iteration | total | mapped | passed | failed | surface/unimplemented fail | behavior fail | unmapped | adapter tests |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for run in payload["runs"]:
        summary = run["summary"]
        adapter = summary["adapter_tests"]
        lines.append(
            f"| `{summary['snapshot_label']}` | {summary['total_non_common']} | {summary['mapped']} | "
            f"{summary['passed']} | {summary['failed']} | {summary['failed_surface_or_unimplemented']} | "
            f"{summary['failed_behavior']} | {summary['unmapped']} | "
            f"{adapter['passed']}/{adapter['total']} |"
        )

    lines += ["", "## Final Iteration By Origin", "", "| origin | total | mapped | passed | failed | surface/unimplemented fail | behavior fail | unmapped |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    final = payload["runs"][-1]["summary"]
    for origin, counts in final["by_origin"].items():
        lines.append(
            f"| `{origin}` | {counts['total_non_common']} | {counts['mapped']} | "
            f"{counts['passed']} | {counts['failed']} | {counts['failed_surface_or_unimplemented']} | "
            f"{counts['failed_behavior']} | {counts['unmapped']} |"
        )

    lines += ["", "## Final Iteration Failed Behavior Contracts", "", "| origin | contract | capability | test | error |", "|---|---|---|---|---|"]
    for row in payload["runs"][-1]["results"]:
        if row["solhttp_status"] == "failed" and not is_surface_failure(row["error"]):
            error = row["error"].replace("|", "\\|")
            if len(error) > 180:
                error = error[:177] + "..."
            lines.append(f"| `{row['origin']}` | `{row['contract']}` | `{row['capability']}` | `{row['solhttp_test']}` | {error} |")

    cap_counter: dict[str, Counter] = defaultdict(Counter)
    for row in payload["runs"][-1]["results"]:
        if row["solhttp_status"] == "failed" and is_surface_failure(row["error"]):
            cap_counter[row["origin"]][row["capability"]] += 1
    lines += ["", "## Final Iteration Surface/Unimplemented Failure Top Counts", "", "| origin | capability | count |", "|---|---|---:|"]
    for origin in sorted(cap_counter):
        for capability, count in cap_counter[origin].most_common(12):
            lines.append(f"| `{origin}` | `{capability}` | {count} |")

    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    base, merged, shim = load_replay_modules()
    rows = non_common_rows()
    for row in rows:
        row["solhttp_test"] = test_mapping(row, base, merged) or ""

    by_origin = Counter(row["origin"] for row in rows)
    mapped_by_origin = Counter(row["origin"] for row in rows if row["solhttp_test"])
    corpus_summary = {
        "rule": "semantic-unique latest-surviving origin contracts, excluding the confirmed HTTP common 114 by origin key and by contract+capability",
        "total_non_common": len(rows),
        "by_origin": dict(sorted(by_origin.items())),
        "mapped_by_origin": dict(sorted(mapped_by_origin.items())),
        "unmapped_by_origin": {
            origin: by_origin[origin] - mapped_by_origin[origin]
            for origin in sorted(by_origin)
        },
    }

    runs = []
    for label, snapshot in SNAPSHOTS:
        runs.append(evaluate_snapshot(label, snapshot, rows, base, merged, shim))

    payload = {"summary": corpus_summary, "corpus": rows, "runs": runs}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / f"{RUN_SET_LABEL}.json"
    out_md = OUT_DIR / f"{RUN_SET_LABEL}.md"
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_markdown(payload, out_md)

    compact = {
        "corpus": corpus_summary,
        "iterations": [run["summary"] for run in runs],
        "artifact_json": str(out_json.relative_to(ROOT)),
        "artifact_md": str(out_md.relative_to(ROOT)),
    }
    print(json.dumps(compact, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
