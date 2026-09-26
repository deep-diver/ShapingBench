#!/usr/bin/env python3
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import urllib3


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts/axios/axios_origin_latest_replay_mutant_verified.json"
OUT = ROOT / "contracts/axios/axios_origin_urllib3_2.7.0_cross_replay.json"


NONPORTABLE = {
    "abort_reason_is_preserved": "AbortController reason propagation is a JS cancellation API contract.",
    "allow_absolute_urls_false_combines_absolute_request_url": "Axios-specific allowAbsoluteUrls/baseURL policy.",
    "base_url_combination_deduplicates_trailing_slashes": "Axios-specific baseURL URL construction policy.",
    "cancel_error_includes_config": "Axios cancellation error shape includes Axios config.",
    "custom_fetch_env_is_used_by_fetch_adapter": "Axios fetch adapter env injection API.",
    "custom_timeout_error_message_is_used": "Axios timeoutErrorMessage option.",
    "data_url_max_content_length_is_enforced": "Axios data: URL response adapter limit.",
    "econnrefused_error_constant_is_exposed": "AxiosError constant surface.",
    "fetch_adapter_enforces_max_body_length": "Axios fetch adapter maxBodyLength behavior.",
    "fetch_adapter_uses_current_global_fetch": "Axios fetch adapter/global fetch binding.",
    "file_object_payload_is_supported_by_http_adapter": "Node File payload support in Axios HTTP adapter.",
    "form_data_to_json_ignores_polluted_prototype": "Axios formDataToJSON helper hardening.",
    "form_data_to_json_preserves_literal_punctuation_keys": "Axios formDataToJSON helper key parser.",
    "https_agent_tls_options_survive_http_connect_proxy": "Axios httpsAgent option propagation through CONNECT.",
    "interceptor_manager_clear_removes_handlers": "Axios InterceptorManager API.",
    "json_parse_error_keeps_response": "Axios transform/settle error object shape.",
    "json_parse_reviver_is_applied": "Axios JSON parse reviver option.",
    "max_body_length_enforced_when_redirects_disabled": "Axios request body length option.",
    "max_content_length_destroys_oversized_stream": "Axios response maxContentLength stream handling.",
    "no_proxy_canonicalizes_ipv4_shorthand": "Axios proxy-from-env/no_proxy canonicalization policy.",
    "no_proxy_wildcard_bypasses_proxy": "Axios proxy-from-env/no_proxy policy.",
    "node_data_url_requests_are_supported": "Axios Node adapter data: URL transport.",
    "object_payload_auto_serializes_to_urlencoded": "Axios object payload transform based on content type.",
    "params_serializer_callback_is_used": "Axios paramsSerializer option.",
    "response_encoding_latin1_decodes_bytes": "Axios responseEncoding transform API.",
    "socket_path_allowlist_rejects_unlisted_path": "Axios socketPath allow-list option.",
    "streamed_response_max_content_length_is_enforced": "Axios response maxContentLength stream option.",
    "sync_interceptor_failure_prevents_dispatch": "Axios synchronous interceptor dispatch semantics.",
    "timeout_string_is_parsed_as_milliseconds": "Axios string timeout parsing compatibility.",
    "unicode_header_values_survive_interceptors": "Axios interceptor mutation path.",
    "url_embedded_basic_auth_is_url_decoded": "Axios URL auth extraction into Authorization header.",
    "utf8_bom_is_removed_before_json_parse": "Axios JSON transform behavior.",
    "validate_status_null_accepts_every_status": "Axios validateStatus option semantics.",
    "validate_status_undefined_can_resolve_like_default": "Axios validateStatus option semantics.",
}


class Recorder:
    def __init__(self):
        self.requests = []

    def append(self, item):
        self.requests.append(item)


class LocalServer:
    def __init__(self, routes):
        self.routes = routes
        self.recorder = Recorder()
        recorder = self.recorder
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                return

            def do_GET(self):
                self.handle_any()

            def do_DELETE(self):
                self.handle_any()

            def handle_any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                request = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body.decode("utf-8", "replace"),
                }
                recorder.append(request)
                status, headers, response_body = routes.get(self.path, routes.get("*"))(request)
                payload = response_body if isinstance(response_body, bytes) else response_body.encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.thread.join(timeout=2)

    def url(self, path):
        return f"http://127.0.0.1:{self.httpd.server_port}{path}"


def ok(status="passed", detail=""):
    return {"status": status, "detail": detail}


def delete_request_sends_config_data():
    with LocalServer({"*": lambda _r: (200, {}, "ok")}) as server:
        http = urllib3.PoolManager()
        http.request("DELETE", server.url("/delete"), body=b"alpha=1", headers={"Content-Type": "text/plain"})
        seen = server.recorder.requests[-1]
        assert seen["method"] == "DELETE"
        assert seen["body"] == "alpha=1"


def malformed_http_url_without_slashes_is_rejected():
    try:
        urllib3.PoolManager().request("GET", "http:example.test/path", timeout=urllib3.Timeout(0.1), retries=False)
    except Exception:
        return
    raise AssertionError("malformed scheme URL was accepted")


def missing_url_rejects_before_dispatch():
    try:
        urllib3.PoolManager().request("GET", "", timeout=urllib3.Timeout(0.1), retries=False)
    except Exception:
        return
    raise AssertionError("missing URL was accepted")


def redirect_strips_sensitive_headers_cross_origin():
    with LocalServer({"*": lambda _r: (200, {}, "target")}) as target:
        with LocalServer({"/start": lambda _r: (302, {"Location": target.url("/target")}, "")}) as source:
            http = urllib3.PoolManager()
            http.request(
                "GET",
                source.url("/start"),
                headers={"Authorization": "Basic abc", "Cookie": "a=b"},
                redirect=True,
            )
            seen = target.recorder.requests[-1]["headers"]
            assert "authorization" not in seen
            assert "cookie" not in seen


def same_origin_redirect_preserves_basic_auth():
    def route(request):
        if request["path"] == "/start":
            return 302, {"Location": "/target"}, ""
        return 200, {}, "target"

    with LocalServer({"*": route}) as server:
        http = urllib3.PoolManager()
        http.request("GET", server.url("/start"), headers={"Authorization": "Basic abc"}, redirect=True)
        seen = server.recorder.requests[-1]["headers"]
        assert seen.get("authorization") == "Basic abc"


def blank_header_names_are_skipped():
    with LocalServer({"*": lambda _r: (200, {}, "ok")}) as server:
        http = urllib3.PoolManager()
        http.request("GET", server.url("/"), headers={"": "ignored", "X-Good": "yes"})
        seen = server.recorder.requests[-1]["headers"]
        assert "" not in seen
        assert seen.get("x-good") == "yes"


def user_agent_header_can_be_omitted():
    with LocalServer({"*": lambda _r: (200, {}, "ok")}) as server:
        http = urllib3.PoolManager(headers={})
        http.request("GET", server.url("/"))
        seen = server.recorder.requests[-1]["headers"]
        assert "user-agent" not in seen, f"user-agent was sent: {seen.get('user-agent')}"


class RawDuplicateCookieServer:
    def __init__(self):
        import socket

        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        try:
            self.socket.close()
        finally:
            self.thread.join(timeout=2)

    def url(self):
        return f"http://127.0.0.1:{self.port}/cookies"

    def serve(self):
        try:
            conn, _addr = self.socket.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Set-Cookie: a=1\r\n"
                    b"Set-Cookie: b=2\r\n"
                    b"Content-Length: 2\r\n"
                    b"\r\nok"
                )
        except OSError:
            return


def get_set_cookie_returns_array():
    with RawDuplicateCookieServer() as server:
        response = urllib3.PoolManager().request("GET", server.url())
        values = response.headers.getlist("Set-Cookie")
        assert values == ["a=1", "b=2"], values


def zstd_response_decompression_supported():
    try:
        import backports.zstd as zstd
    except Exception as exc:
        raise AssertionError(f"backports.zstd unavailable: {exc}") from exc

    payload = zstd.compress(b"zstd-ok")
    with LocalServer({"*": lambda _r: (200, {"Content-Encoding": "zstd"}, payload)}) as server:
        response = urllib3.PoolManager().request("GET", server.url("/zstd"))
        assert response.data == b"zstd-ok", response.data


TESTS = {
    "blank_header_names_are_skipped": blank_header_names_are_skipped,
    "delete_request_sends_config_data": delete_request_sends_config_data,
    "get_set_cookie_returns_array": get_set_cookie_returns_array,
    "malformed_http_url_without_slashes_is_rejected": malformed_http_url_without_slashes_is_rejected,
    "missing_url_rejects_before_dispatch": missing_url_rejects_before_dispatch,
    "redirect_strips_sensitive_headers_cross_origin": redirect_strips_sensitive_headers_cross_origin,
    "same_origin_redirect_preserves_basic_auth": same_origin_redirect_preserves_basic_auth,
    "user_agent_header_can_be_omitted": user_agent_header_can_be_omitted,
    "zstd_response_decompression_supported": zstd_response_decompression_supported,
}


def main():
    data = json.loads(SOURCE.read_text())
    results = []
    for row in data["results"]:
        name = row["name"]
        if name in NONPORTABLE:
            result = ok("nonportable_api_surface", NONPORTABLE[name])
        else:
            try:
                TESTS[name]()
                result = ok("passed", "portable replay passed on urllib3")
            except Exception as exc:
                result = ok("failed", f"{type(exc).__name__}: {exc}")
        results.append(
            {
                "name": name,
                "capability": row["capability"],
                "status": result["status"],
                "detail": result["detail"],
            }
        )

    summary = {
        "target": "urllib3",
        "target_version": urllib3.__version__,
        "source_contracts": len(results),
        "passed": sum(r["status"] == "passed" for r in results),
        "failed": sum(r["status"] == "failed" for r in results),
        "nonportable_api_surface": sum(r["status"] == "nonportable_api_surface" for r in results),
    }
    OUT.write_text(json.dumps({"summary": summary, "results": results}, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
