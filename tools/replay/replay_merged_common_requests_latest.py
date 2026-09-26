#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import gzip
import json
import pathlib
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
from http import HTTPStatus
from typing import Callable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import replay_requests_survival as base  # noqa: E402

import requests  # noqa: E402
from requests.adapters import HTTPAdapter  # noqa: E402
from urllib3.util import Retry  # noqa: E402


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "contracts" / "common" / "merged_common.json"
OUT = ROOT / "contracts" / "requests" / "requests_2.32.5_survival_from_merged_common_119.json"
OUT_MD = ROOT / "contracts" / "requests" / "requests_2.32.5_survival_from_merged_common_119.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def request_with_raw_target(path: str) -> str:
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        return requests.get(server.url(path), timeout=2).text


def encoded_query_plus_is_preserved() -> None:
    require(request_with_raw_target("/search?q=a+b") == "/search?q=a+b", "encoded query plus was rewritten")


def form_body_builder_accepts_explicit_charset() -> None:
    def handler(req: base.RawRequest) -> base.RawResponse:
        ok = req.header("Content-Type") == "application/x-www-form-urlencoded; charset=iso-8859-1"
        ok = ok and req.body == "café=1".encode("iso-8859-1")
        return base.RawResponse.ok("ok") if ok else base.RawResponse.status_text(400, f"{req.header('Content-Type')} {req.body!r}")

    with base.RawServer(handler) as server:
        response = requests.post(
            server.url("/form"),
            data="café=1".encode("iso-8859-1"),
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-1"},
            timeout=2,
        )
        require(response.status_code == 200, response.text)


def form_body_encodes_space_as_plus() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        require(requests.post(server.url("/form"), data={"q": "a b"}, timeout=2).text == "q=a+b", "space not encoded as plus")


def headers_to_multimap_is_case_insensitive() -> None:
    with base.RawServer(lambda req: base.RawResponse(headers=[("X-Test", "one")], body=b"ok")) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.headers["x-test"] == "one" and response.headers["X-TEST"] == "one", str(response.headers))


def http10_requests_are_not_sent() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.protocol)) as server:
        require(requests.get(server.url("/"), timeout=2).text == "HTTP/1.1", "did not send HTTP/1.1")


class RawBytesServer:
    def __init__(self, response: bytes, request_limit: int = 1):
        self.response = response
        self.request_limit = request_limit
        self.requests: list[bytes] = []
        self._running = True
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        self._running = False
        with contextlib.suppress(Exception):
            self._sock.close()

    def __enter__(self) -> "RawBytesServer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _accept(self) -> None:
        count = 0
        while self._running and count < self.request_limit:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            count += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data.extend(chunk)
            self.requests.append(bytes(data))
            conn.sendall(self.response)


def http1_100_continue_status_lines_are_ignored_until_final() -> None:
    response = (
        b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal"
    )
    with RawBytesServer(response) as server:
        r = requests.get(server.url("/info"), timeout=2)
        require(r.status_code == 200 and r.text == "final", f"{r.status_code} {r.text}")


def redirect_307_308_preserve_method_body() -> None:
    seen: list[str] = []

    def handler(req: base.RawRequest) -> base.RawResponse:
        seen.append(f"{req.method}:{req.path}:{req.text}")
        if req.path == "/start":
            return base.RawResponse(status=307, headers=[("Location", "/target")])
        return base.RawResponse.ok(f"{req.method}:{req.text}")

    with base.RawServer(handler) as server:
        response = requests.request("PATCH", server.url("/start"), data="body", timeout=2)
        require(response.text == "PATCH:body", f"{response.status_code} {response.text} {seen}")


def http_308_permanent_redirect_is_handled() -> None:
    with base.RawServer(lambda req: base.RawResponse(status=308, headers=[("Location", "/target")]) if req.path == "/start" else base.RawResponse.ok("target")) as server:
        require(requests.get(server.url("/start"), timeout=2).text == "target", "308 not followed")


def http_408_retry_respects_retry_on_connection_failure() -> None:
    attempts = {"n": 0}

    def handler(req: base.RawRequest) -> base.RawResponse:
        attempts["n"] += 1
        return base.RawResponse.status_text(408, "retry") if attempts["n"] == 1 else base.RawResponse.ok("ok")

    retry = Retry(total=1, status=1, status_forcelist=[408], allowed_methods=None, raise_on_status=False)
    with base.RawServer(handler) as server:
        session = base.session_with_retry_policy(retry)
        response = session.get(server.url("/408"), timeout=2)
        require(response.text == "ok" and attempts["n"] == 2, f"{response.status_code} attempts={attempts['n']}")


class HeaderRecordingProxy:
    def __init__(self):
        self.headers: list[tuple[str, str]] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}"

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._sock.close()

    def __enter__(self) -> "HeaderRecordingProxy":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _accept(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data.extend(chunk)
            header = bytes(data).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
            for line in header.split("\r\n")[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    self.headers.append((key, value.strip()))
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")


def https_tunnel_does_not_leak_origin_headers_to_proxy() -> None:
    with HeaderRecordingProxy() as proxy:
        try:
            requests.get(
                "https://example.test/",
                headers={"Authorization": "Bearer origin", "Cookie": "a=1"},
                proxies={"https": proxy.url},
                timeout=1,
            )
        except requests.exceptions.ProxyError:
            pass
        names = {key.lower() for key, _ in proxy.headers}
        require("authorization" not in names and "cookie" not in names, str(proxy.headers))


def idn_uses_uts46_nontransitional_processing() -> None:
    prepared = requests.Request("GET", "http://straße.de/").prepare()
    require("xn--strae-oqa.de" in prepared.url, prepared.url)


def ipv4_mapped_ipv6_url_does_not_crash() -> None:
    prepared = requests.Request("GET", "http://[::ffff:192.0.2.128]/").prepare()
    require(prepared.url.startswith("http://[::ffff:192.0.2.128]"), prepared.url)


def multipart_filename_allows_non_ascii() -> None:
    base.multipart_html5_filename_formatting()


def multipart_fixed_length_body_emits_content_length() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Content-Length") or "")) as server:
        response = requests.post(server.url("/"), files={"file": ("a.txt", b"x")}, timeout=2)
        require(response.text.isdigit() and int(response.text) > 0, response.text)


def mutual_tls_client_certificate_is_sent_when_required() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        ca_key, ca_cert = d / "ca-key.pem", d / "ca-cert.pem"
        server_key, server_csr, server_cert = d / "server-key.pem", d / "server.csr", d / "server-cert.pem"
        client_key, client_csr, client_cert = d / "client-key.pem", d / "client.csr", d / "client-cert.pem"
        import subprocess

        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-noenc", "-subj", "/CN=ca", "-keyout", ca_key, "-out", ca_cert, "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-noenc", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost", "-keyout", server_key, "-out", server_csr], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-req", "-in", server_csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-out", server_cert, "-days", "1", "-copy_extensions", "copy"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-noenc", "-subj", "/CN=client", "-keyout", client_key, "-out", client_csr], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-req", "-in", client_csr, "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial", "-out", client_cert, "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def handler(req: base.RawRequest) -> base.RawResponse:
            return base.RawResponse.ok("mtls")

        server = base.RawServer(handler, tls=False)
        server.close()
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(server_cert), str(server_key))
        ctx.load_verify_locations(str(ca_cert))
        ctx.verify_mode = ssl.CERT_REQUIRED
        port = sock.getsockname()[1]
        seen = {"ok": False}

        def serve() -> None:
            try:
                conn, _ = sock.accept()
                with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    seen["ok"] = tls_conn.getpeercert() is not None
                    while b"\r\n\r\n" not in tls_conn.recv(4096):
                        pass
                    tls_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmtls")
            except Exception:
                return

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            response = requests.get(f"https://127.0.0.1:{port}/", verify=str(ca_cert), cert=(str(client_cert), str(client_key)), timeout=3)
            require(response.text == "mtls" and seen["ok"], "client cert not observed")
        finally:
            sock.close()


def options_request_body_is_allowed() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(f"{req.method}:{req.text}")) as server:
        response = requests.request("OPTIONS", server.url("/"), data="body", timeout=2)
        require(response.text == "OPTIONS:body", response.text)


def port_out_of_range_fails_early() -> None:
    try:
        requests.Request("GET", "http://example.com:65536/").prepare()
    except Exception:
        return
    raise AssertionError("accepted out-of-range port")


def query_method_redirects_follow_rfc10008() -> None:
    seen: list[str] = []

    def handler(req: base.RawRequest) -> base.RawResponse:
        seen.append(req.method)
        if req.path == "/start":
            return base.RawResponse(status=302, headers=[("Location", "/target")])
        return base.RawResponse.ok(req.method)

    with base.RawServer(handler) as server:
        response = requests.request("QUERY", server.url("/start"), data="body", timeout=2)
        require(response.text == "GET", f"{response.text} seen={seen}")


def query_parameter_builder_escapes_ascii_punctuation() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        response = requests.get(server.url("/search"), params={"q": " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~"}, timeout=2)
        target = response.text
        require(" " not in target, target)
        for escaped in ("%21", "%22", "%23", "%24", "%25", "%26", "%27", "%28", "%29", "%2A", "%2B", "%2C", "%2F", "%3A", "%3B", "%3C", "%3D", "%3E", "%3F", "%40", "%5B", "%5C", "%5D", "%5E", "%60", "%7B", "%7C", "%7D"):
            require(escaped in target, target)


def request_bodies_allowed_for_methods_except_get_and_head() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(f"{req.method}:{req.text}")) as server:
        require(requests.request("POST", server.url("/"), data="body", timeout=2).text == "POST:body", "POST body rejected")
        require(requests.request("PUT", server.url("/"), data="body", timeout=2).text == "PUT:body", "PUT body rejected")
        try:
            response = requests.request("GET", server.url("/"), data="body", timeout=2)
        except Exception:
            return
        raise AssertionError(f"GET body was accepted: {response.text}")


def response_body_is_non_null_for_all_responses() -> None:
    with base.RawServer(lambda req: base.RawResponse.status_text(204, "")) as server:
        response = requests.get(server.url("/empty"), timeout=2)
        require(response.content == b"", repr(response.content))


def timeout_failures_are_not_retried() -> None:
    attempts = {"n": 0}

    def handler(req: base.RawRequest) -> base.RawResponse:
        attempts["n"] += 1
        time.sleep(0.25)
        return base.RawResponse.ok("slow")

    with base.RawServer(handler) as server:
        try:
            requests.get(server.url("/slow"), timeout=(1, 0.05))
        except requests.exceptions.RequestException:
            require(attempts["n"] == 1, f"retried timeout attempts={attempts['n']}")
            return
        raise AssertionError("timeout did not fail")


def unsafe_non_ascii_header_values_can_be_added() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("X-Name") or "")) as server:
        response = requests.get(server.url("/"), headers={"X-Name": "é"}, timeout=2)
        require(response.text == "é", response.text)


def url_fragment_preserves_non_ascii_characters() -> None:
    prepared = requests.Request("GET", "http://example.com/path#café").prepare()
    require("caf%C3%A9" in prepared.url or "café" in prepared.url, prepared.url)


def webdav_methods_are_supported() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(req.method)) as server:
        require(requests.request("PROPFIND", server.url("/"), timeout=2).text == "PROPFIND", "PROPFIND not sent")


def delete_request_sends_config_data() -> None:
    with base.RawServer(lambda req: base.RawResponse.ok(f"{req.method}:{req.text}")) as server:
        require(requests.delete(server.url("/delete"), data="alpha=1", timeout=2).text == "DELETE:alpha=1", "DELETE body not sent")


def missing_url_rejects_before_dispatch() -> None:
    try:
        requests.get("", timeout=1)
    except requests.exceptions.MissingSchema:
        return
    raise AssertionError("missing URL was accepted")


def same_origin_redirect_preserves_basic_auth() -> None:
    seen: list[str | None] = []

    def handler(req: base.RawRequest) -> base.RawResponse:
        seen.append(req.header("Authorization"))
        if req.path == "/start":
            return base.RawResponse(status=302, headers=[("Location", "/target")])
        return base.RawResponse.ok(str(req.header("Authorization")))

    with base.RawServer(handler) as server:
        response = requests.get(server.url("/start"), headers={"Authorization": "Basic abc"}, timeout=2)
        require(response.text == "Basic abc" and seen[-1] == "Basic abc", f"{response.text} seen={seen}")


def zstd_response_decompression_supported() -> None:
    try:
        import backports.zstd as zstd
    except Exception as exc:
        raise AssertionError(f"backports.zstd unavailable: {exc}") from exc
    payload = zstd.compress(b"zstd-ok")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Encoding", "zstd")], body=payload)) as server:
        response = requests.get(server.url("/zstd"), timeout=2)
        require(response.content == b"zstd-ok", response.content)


ADDITIONAL_TESTS: dict[str, Callable[[], None]] = {
    "disabled_redirect_policy_is_honored": base.redirect_observable_without_following,
    "encoded_query_plus_is_preserved": encoded_query_plus_is_preserved,
    "form_body_builder_accepts_explicit_charset": form_body_builder_accepts_explicit_charset,
    "form_body_encodes_space_as_plus": form_body_encodes_space_as_plus,
    "headers_to_multimap_is_case_insensitive": headers_to_multimap_is_case_insensitive,
    "http10_requests_are_not_sent": http10_requests_are_not_sent,
    "http1_100_continue_status_lines_are_ignored_until_final": http1_100_continue_status_lines_are_ignored_until_final,
    "http_307_308_redirects_preserve_non_get_post_method_and_body": redirect_307_308_preserve_method_body,
    "http_308_permanent_redirect_is_handled": http_308_permanent_redirect_is_handled,
    "http_408_retry_respects_retry_on_connection_failure": http_408_retry_respects_retry_on_connection_failure,
    "https_tunnel_does_not_leak_origin_headers_to_proxy": https_tunnel_does_not_leak_origin_headers_to_proxy,
    "idn_uses_uts46_nontransitional_processing": idn_uses_uts46_nontransitional_processing,
    "ipv4_mapped_ipv6_url_does_not_crash": ipv4_mapped_ipv6_url_does_not_crash,
    "multipart_filename_allows_non_ascii": multipart_filename_allows_non_ascii,
    "multipart_fixed_length_body_emits_content_length": multipart_fixed_length_body_emits_content_length,
    "mutual_tls_client_certificate_is_sent_when_required": mutual_tls_client_certificate_is_sent_when_required,
    "options_request_body_is_allowed": options_request_body_is_allowed,
    "port_out_of_range_fails_early": port_out_of_range_fails_early,
    "query_method_redirects_follow_rfc10008": query_method_redirects_follow_rfc10008,
    "query_parameter_builder_escapes_ascii_punctuation": query_parameter_builder_escapes_ascii_punctuation,
    "request_bodies_allowed_for_methods_except_get_and_head": request_bodies_allowed_for_methods_except_get_and_head,
    "response_body_is_non_null_for_all_responses": response_body_is_non_null_for_all_responses,
    "timeout_failures_are_not_retried": timeout_failures_are_not_retried,
    "unsafe_non_ascii_header_values_can_be_added": unsafe_non_ascii_header_values_can_be_added,
    "url_fragment_preserves_non_ascii_characters": url_fragment_preserves_non_ascii_characters,
    "webdav_methods_are_supported": webdav_methods_are_supported,
    "delete_request_sends_config_data": delete_request_sends_config_data,
    "missing_url_rejects_before_dispatch": missing_url_rejects_before_dispatch,
    "same_origin_redirect_preserves_basic_auth": same_origin_redirect_preserves_basic_auth,
    "zstd_response_decompression_supported": zstd_response_decompression_supported,
}


def test_name_for(row: dict) -> str | None:
    if row["origin"] == "urllib3":
        return base.MAPPING.get(row["key"])
    return row["contract"] if row["contract"] in ADDITIONAL_TESTS else None


def fn_for(test_name: str) -> Callable[[], None]:
    base_tests = dict(base.TESTS)
    if test_name in base_tests:
        return base_tests[test_name]
    return ADDITIONAL_TESTS[test_name]


def main() -> int:
    source = json.loads(SOURCE.read_text())
    rows = source["results"]
    requested_tests = sorted({test_name_for(row) for row in rows if test_name_for(row)})
    raw_tests = {name: base.run_test(name, fn_for(name)) for name in requested_tests}

    results = []
    for row in rows:
        test_name = test_name_for(row)
        result = {
            "origin": row["origin"],
            "source_version": row["source_version"],
            "contract": row["contract"],
            "capability": row["capability"],
            "key": row["key"],
            "requests_test": test_name or "",
        }
        if not test_name:
            result.update({
                "requests_status": "failed_absent_or_unmapped",
                "error": "no executed Requests equivalent mapped for this merged common contract",
            })
        else:
            test = raw_tests[test_name]
            result.update({
                "requests_status": "passed" if test["passed"] else "failed",
                "error": test["error"],
            })
        results.append(result)

    survived = sum(1 for row in results if row["requests_status"] == "passed")
    summary = {
        "source_project": "merged_common",
        "source_baseline": str(SOURCE.relative_to(ROOT)),
        "target_project": "requests",
        "target_latest_version": requests.__version__,
        "target_latest_source": "pip index versions requests",
        "mode": "aggressive_no_not_applicable",
        "rule": "A merged common contract counts as surviving Requests only when an executed Requests adapter test passed. Unmapped or absent equivalents count as failed.",
        "total_merged_common": len(results),
        "requests_survived": survived,
        "requests_failed": len(results) - survived,
        "adapter_tests": {
            "total": len(raw_tests),
            "passed": sum(1 for test in raw_tests.values() if test["passed"]),
            "failed": sum(1 for test in raw_tests.values() if not test["passed"]),
        },
        "by_origin": {},
    }
    for origin in sorted({row["origin"] for row in results}):
        origin_rows = [row for row in results if row["origin"] == origin]
        summary["by_origin"][origin] = {
            "total": len(origin_rows),
            "survived": sum(1 for row in origin_rows if row["requests_status"] == "passed"),
            "failed": sum(1 for row in origin_rows if row["requests_status"] != "passed"),
        }

    payload = {"summary": summary, "raw_runner": {"requests_version": requests.__version__, "tests": list(raw_tests.values())}, "results": results}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    lines = [
        f"# Requests {requests.__version__} survival from merged common 119",
        "",
        f"- total_merged_common: {summary['total_merged_common']}",
        f"- requests_survived: {summary['requests_survived']}",
        f"- requests_failed: {summary['requests_failed']}",
        f"- adapter_tests: {summary['adapter_tests']['total']} total, {summary['adapter_tests']['passed']} passed, {summary['adapter_tests']['failed']} failed",
        "",
        "## By Origin",
        "",
        "| origin | total | survived | failed |",
        "|---|---:|---:|---:|",
    ]
    for origin, counts in summary["by_origin"].items():
        lines.append(f"| `{origin}` | {counts['total']} | {counts['survived']} | {counts['failed']} |")
    lines += ["", "## Adapter Test Failures", "", "| test | error |", "|---|---|"]
    for test in raw_tests.values():
        if not test["passed"]:
            err = test["error"].replace("|", "\\|")
            lines.append(f"| `{test['name']}` | {err} |")
    lines += ["", "## Failed Contracts", "", "| origin | contract | status | requests_test | error |", "|---|---|---|---|---|"]
    for row in results:
        if row["requests_status"] != "passed":
            err = row["error"].replace("|", "\\|")
            if len(err) > 180:
                err = err[:177] + "..."
            lines.append(f"| `{row['origin']}` | `{row['contract']}` | {row['requests_status']} | `{row['requests_test']}` | {err} |")
    OUT_MD.write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
