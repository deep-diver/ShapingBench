#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import base64
import urllib3
import socket
import threading
import os

import requests


ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(os.environ.get("SHAPINGBENCH_OKHTTP_PYTHON_OUT", ROOT / "contracts" / "common" / "okhttp_origin_python_cross_replay.json"))
sys.path.insert(0, str(ROOT / "tools" / "replay"))
from replay_requests_survival import RawResponse, RawServer  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_test(fn):
    try:
        fn()
        return {"passed": True, "error": ""}
    except BaseException as exc:
        return {"passed": False, "error": f"{exc.__class__.__name__}: {exc}"}


class InterimServer:
    def __init__(self, statuses: list[int]):
        self.statuses = statuses
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self) -> "InterimServer":
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._running = False
        self._sock.close()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}{path}"

    def _accept(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            for status in self.statuses:
                conn.sendall(f"HTTP/1.1 {status} Interim\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except BrokenPipeError:
                pass


class TunnelCaptureServer:
    def __init__(self):
        self.captured = ""
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self) -> "TunnelCaptureServer":
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._running = False
        self._sock.close()

    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}"

    def _accept(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.captured = data.decode("iso-8859-1", "replace")
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")


class IcyServer:
    def __init__(self):
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self) -> "IcyServer":
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._running = False
        self._sock.close()

    def url(self) -> str:
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}/"

    def _accept(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"ICY 200 OK\r\nContent-Length: 6\r\n\r\nstream")


class MutualTlsServer:
    def __init__(self, server_cert: pathlib.Path, server_key: pathlib.Path, ca_cert: pathlib.Path):
        self.observed_client_certificate = False
        raw = socket.socket()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("127.0.0.1", 0))
        raw.listen()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(ca_cert))
        ctx.load_cert_chain(str(server_cert), str(server_key))
        self._sock = ctx.wrap_socket(raw, server_side=True)
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self) -> "MutualTlsServer":
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._running = False
        self._sock.close()

    def url(self) -> str:
        return f"https://localhost:{self._sock.getsockname()[1]}/"

    def _accept(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            self.observed_client_certificate = bool(conn.getpeercert())
            conn.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def make_mutual_tls_material(tmp: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    ca_cert, ca_key = tmp / "ca.pem", tmp / "ca.key"
    server_cert, server_key, server_csr = tmp / "server.pem", tmp / "server.key", tmp / "server.csr"
    client_cert, client_key, client_csr = tmp / "client.pem", tmp / "client.key", tmp / "client.csr"
    server_ext = tmp / "server.ext"
    server_ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Test CA", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(server_key), "-out", str(server_csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert), "-days", "1", "-extfile", str(server_ext)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=client", "-keyout", str(client_key), "-out", str(client_csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-req", "-in", str(client_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(client_cert), "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ca_cert, server_cert, server_key, client_cert, client_key


def urllib3_client():
    return urllib3.PoolManager()


def form_body_space_plus_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = urllib3_client().request("POST", server.url("/"), fields={"q": "a b"}, encode_multipart=False)
        require(response.data.decode() == "q=a+b", response.data.decode())


def form_body_space_plus_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = requests.post(server.url("/"), data={"q": "a b"}, timeout=2)
        require(response.text == "q=a+b", response.text)


def form_body_explicit_charset_urllib3() -> None:
    encoded = urllib.parse.urlencode({"q": "é"}, encoding="iso-8859-1").encode("ascii")
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = urllib3_client().request(
            "POST",
            server.url("/"),
            body=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-1"},
        )
        require(response.data.decode("utf-8", "replace") == "q=%E9", response.data)


def form_body_explicit_charset_requests() -> None:
    encoded = urllib.parse.urlencode({"q": "é"}, encoding="iso-8859-1").encode("ascii")
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = requests.post(
            server.url("/"),
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-1"},
            timeout=2,
        )
        require(response.text == "q=%E9", response.text)


def delete_body_allowed_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method + ":" + req.text)) as server:
        response = urllib3_client().request("DELETE", server.url("/"), body=b"payload")
        require(response.data.decode() == "DELETE:payload", response.data.decode())


def delete_body_allowed_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method + ":" + req.text)) as server:
        response = requests.request("DELETE", server.url("/"), data="payload", timeout=2)
        require(response.text == "DELETE:payload", response.text)


def options_body_allowed_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method + ":" + req.text)) as server:
        response = urllib3_client().request("OPTIONS", server.url("/"), body=b"payload")
        require(response.data.decode() == "OPTIONS:payload", response.data.decode())


def options_body_allowed_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method + ":" + req.text)) as server:
        response = requests.request("OPTIONS", server.url("/"), data="payload", timeout=2)
        require(response.text == "OPTIONS:payload", response.text)


def http_308_redirect_urllib3() -> None:
    def handler(req):
        if req.path == "/old":
            return RawResponse.redirect("/new", status=308)
        return RawResponse.ok(req.path)

    with RawServer(handler) as server:
        response = urllib3_client().request("GET", server.url("/old"), redirect=True)
        require(response.status == 200 and response.data.decode() == "/new", f"{response.status} {response.data!r}")


def http_308_redirect_requests() -> None:
    def handler(req):
        if req.path == "/old":
            return RawResponse.redirect("/new", status=308)
        return RawResponse.ok(req.path)

    with RawServer(handler) as server:
        response = requests.get(server.url("/old"), timeout=2)
        require(response.status_code == 200 and response.text == "/new", f"{response.status_code} {response.text}")


def http_307_308_non_get_body_urllib3() -> None:
    def handler(req):
        if req.path == "/old":
            return RawResponse.redirect("/new", status=308)
        return RawResponse.ok(req.method + ":" + req.text)

    with RawServer(handler) as server:
        response = urllib3_client().request("DELETE", server.url("/old"), body=b"payload", redirect=True)
        require(response.data.decode() == "DELETE:payload", response.data.decode())


def http_307_308_non_get_body_requests() -> None:
    def handler(req):
        if req.path == "/old":
            return RawResponse.redirect("/new", status=308)
        return RawResponse.ok(req.method + ":" + req.text)

    with RawServer(handler) as server:
        response = requests.request("DELETE", server.url("/old"), data="payload", timeout=2)
        require(response.text == "DELETE:payload", response.text)


def query_method_redirect_urllib3() -> None:
    def handler(req):
        if req.path == "/redirect":
            return RawResponse.redirect("/target", status=303)
        return RawResponse.ok(req.method + ":" + req.text)

    with RawServer(handler) as server:
        response = urllib3_client().request("QUERY", server.url("/redirect"), body=b"q=1", redirect=True)
        require(response.data.decode() == "GET:", response.data.decode())


def query_method_redirect_requests() -> None:
    def handler(req):
        if req.path == "/redirect":
            return RawResponse.redirect("/target", status=303)
        return RawResponse.ok(req.method + ":" + req.text)

    with RawServer(handler) as server:
        response = requests.request("QUERY", server.url("/redirect"), data="q=1", timeout=2)
        require(response.text == "GET:", response.text)


def disabled_redirect_urllib3() -> None:
    def handler(req):
        if req.path == "/":
            return RawResponse.redirect("/target", status=302)
        return RawResponse.ok("target")

    with RawServer(handler) as server:
        response = urllib3_client().request("GET", server.url("/"), redirect=False)
        require(response.status == 302 and server.path_requests.get("/target") is None, f"{response.status} {server.path_requests}")


def disabled_redirect_requests() -> None:
    def handler(req):
        if req.path == "/":
            return RawResponse.redirect("/target", status=302)
        return RawResponse.ok("target")

    with RawServer(handler) as server:
        response = requests.get(server.url("/"), allow_redirects=False, timeout=2)
        require(response.status_code == 302 and server.path_requests.get("/target") is None, f"{response.status_code} {server.path_requests}")


def multiple_informational_responses_urllib3() -> None:
    with InterimServer([102, 103]) as server:
        response = urllib3_client().request("GET", server.url("/"), timeout=urllib3.Timeout(connect=1, read=1), retries=False)
        require(response.status == 200 and response.data == b"ok", f"{response.status} {response.data!r}")


def multiple_informational_responses_requests() -> None:
    with InterimServer([102, 103]) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.status_code == 200 and response.text == "ok", f"{response.status_code} {response.text!r}")


def http1_100_continue_urllib3() -> None:
    with InterimServer([100]) as server:
        response = urllib3_client().request("GET", server.url("/"), timeout=urllib3.Timeout(connect=1, read=1), retries=False)
        require(response.status == 200 and response.data == b"ok", f"{response.status} {response.data!r}")


def http1_100_continue_requests() -> None:
    with InterimServer([100]) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.status_code == 200 and response.text == "ok", f"{response.status_code} {response.text!r}")


def empty_query_no_fragment_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = urllib3_client().request("GET", server.url("/path?#frag"))
        require(response.data.decode() == "/path?", response.data.decode())


def empty_query_no_fragment_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = requests.get(server.url("/path?#frag"), timeout=2)
        require(response.text == "/path?", response.text)


def encoded_query_plus_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = urllib3_client().request("GET", server.url("/path?q=a+b"))
        require(response.data.decode() == "/path?q=a+b", response.data.decode())


def encoded_query_plus_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = requests.get(server.url("/path?q=a+b"), timeout=2)
        require(response.text == "/path?q=a+b", response.text)


def url_scheme_digits_urllib3() -> None:
    parsed = urllib3.util.parse_url("webdav1://example.com/path")
    require(parsed.scheme == "webdav1", str(parsed))


def url_scheme_digits_requests() -> None:
    prepared = requests.Request("GET", "webdav1://example.com/path").prepare()
    require(prepared.url == "webdav1://example.com/path", prepared.url)


def url_fragment_non_ascii_urllib3() -> None:
    parsed = urllib3.util.parse_url("http://example.com/path#é")
    require(urllib.parse.unquote(parsed.fragment or "") == "é", str(parsed))


def url_fragment_non_ascii_requests() -> None:
    prepared = requests.Request("GET", "http://example.com/path#é").prepare()
    require(urllib.parse.unquote(urllib.parse.urlsplit(prepared.url).fragment) == "é", prepared.url)


def idn_uts46_urllib3() -> None:
    parsed = urllib3.util.parse_url("http://faß.de/")
    require(parsed.host == "xn--fa-hia.de", str(parsed))


def idn_uts46_requests() -> None:
    prepared = requests.Request("GET", "http://faß.de/").prepare()
    require(urllib.parse.urlsplit(prepared.url).hostname == "xn--fa-hia.de", prepared.url)


def query_parameter_escape_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = urllib3_client().request("GET", server.url("/"), fields={"q": "a{b}c"})
        target = response.data.decode()
        require("%7B" in target and "%7D" in target, target)


def query_parameter_escape_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        response = requests.get(server.url("/"), params={"q": "a{b}c"}, timeout=2)
        require("%7B" in response.text and "%7D" in response.text, response.text)


def special_url_characters_urllib3() -> None:
    parsed = urllib3.util.parse_url("http://example.test/a|b[/")
    rendered = parsed.url
    require("%7C" in rendered and "%5B" in rendered, rendered)


def special_url_characters_requests() -> None:
    prepared = requests.Request("GET", "http://example.test/a|b[/").prepare()
    require("%7C" in prepared.url and "%5B" in prepared.url, prepared.url)


def domain_label_length_urllib3() -> None:
    label = "a" * 64
    try:
        parsed = urllib3.util.parse_url(f"http://{label}.example/")
    except Exception:
        return
    raise AssertionError(f"64-byte label was accepted: {parsed}")


def domain_label_length_requests() -> None:
    label = "a" * 64
    try:
        prepared = requests.Request("GET", f"http://{label}.example/").prepare()
    except Exception:
        return
    raise AssertionError(f"64-byte label was accepted: {prepared.url}")


def uri_hostname_sanitization_urllib3() -> None:
    parsed = urllib3.util.parse_url("http://bad{host}.example/")
    rendered = parsed.url
    require("{" not in rendered and "}" not in rendered, rendered)


def uri_hostname_sanitization_requests() -> None:
    prepared = requests.Request("GET", "http://bad{host}.example/").prepare()
    host = urllib.parse.urlsplit(prepared.url).netloc
    require("{" not in host and "}" not in host, prepared.url)


def ipv4_mapped_ipv6_url_urllib3() -> None:
    parsed = urllib3.util.parse_url("http://[::ffff:192.0.2.1]/")
    require("192.0.2.1" in (parsed.host or "") or "::ffff" in (parsed.host or ""), str(parsed))


def ipv4_mapped_ipv6_url_requests() -> None:
    prepared = requests.Request("GET", "http://[::ffff:192.0.2.1]/").prepare()
    host = urllib.parse.urlsplit(prepared.url).hostname or ""
    require("192.0.2.1" in host or "::ffff" in host, prepared.url)


def http10_not_sent_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.protocol)) as server:
        response = urllib3_client().request("GET", server.url("/"))
        require(response.data.decode() == "HTTP/1.1", response.data.decode())


def http10_not_sent_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.protocol)) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.text == "HTTP/1.1", response.text)


def webdav_methods_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method)) as server:
        response = urllib3_client().request("PROPFIND", server.url("/resource"))
        require(response.data.decode() == "PROPFIND", response.data.decode())


def webdav_methods_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.method)) as server:
        response = requests.request("PROPFIND", server.url("/resource"), timeout=2)
        require(response.text == "PROPFIND", response.text)


def illegal_get_body_fails_urllib3() -> None:
    try:
        urllib3_client().request("GET", "http://example.test/", body=b"payload")
    except Exception:
        return
    raise AssertionError("GET body was accepted")


def illegal_get_body_fails_requests() -> None:
    try:
        requests.Request("GET", "http://example.test/", data="payload").prepare()
    except Exception:
        return
    raise AssertionError("GET body was accepted")


def response_body_non_null_urllib3() -> None:
    with RawServer(lambda req: RawResponse(status=204, body=b"")) as server:
        response = urllib3_client().request("GET", server.url("/empty"))
        require(response.data is not None and response.data == b"", repr(response.data))


def response_body_non_null_requests() -> None:
    with RawServer(lambda req: RawResponse(status=204, body=b"")) as server:
        response = requests.get(server.url("/empty"), timeout=2)
        require(response.content is not None and response.content == b"", repr(response.content))


def shoutcast_icy_urllib3() -> None:
    with IcyServer() as server:
        response = urllib3_client().request("GET", server.url(), timeout=urllib3.Timeout(connect=1, read=1), retries=False)
        require(response.status == 200 and response.data == b"stream", f"{response.status} {response.data!r}")


def shoutcast_icy_requests() -> None:
    with IcyServer() as server:
        response = requests.get(server.url(), timeout=2)
        require(response.status_code == 200 and response.text == "stream", f"{response.status_code} {response.text!r}")


def mutual_tls_client_certificate_urllib3() -> None:
    with tempfile.TemporaryDirectory() as d:
        ca_cert, server_cert, server_key, client_cert, client_key = make_mutual_tls_material(pathlib.Path(d))
        with MutualTlsServer(server_cert, server_key, ca_cert) as server:
            client = urllib3.PoolManager(cert_file=str(client_cert), key_file=str(client_key), ca_certs=str(ca_cert))
            response = client.request("GET", server.url(), timeout=urllib3.Timeout(connect=2, read=2), retries=False)
            require(response.status == 200 and server.observed_client_certificate, f"{response.status} observed={server.observed_client_certificate}")


def mutual_tls_client_certificate_requests() -> None:
    with tempfile.TemporaryDirectory() as d:
        ca_cert, server_cert, server_key, client_cert, client_key = make_mutual_tls_material(pathlib.Path(d))
        with MutualTlsServer(server_cert, server_key, ca_cert) as server:
            response = requests.get(server.url(), cert=(str(client_cert), str(client_key)), verify=str(ca_cert), timeout=2)
            require(response.status_code == 200 and server.observed_client_certificate, f"{response.status_code} observed={server.observed_client_certificate}")


def authentication_credentials_charset_urllib3() -> None:
    header = "Basic " + base64.b64encode("é:p".encode("utf-8")).decode("ascii")
    require(header == "Basic w6k6cA==", header)


def authentication_credentials_charset_requests() -> None:
    from requests.auth import _basic_auth_str

    header = _basic_auth_str("é", "p")
    require(header == "Basic w6k6cA==", header)


def https_tunnel_header_isolation_urllib3() -> None:
    with TunnelCaptureServer() as proxy:
        client = urllib3.ProxyManager(proxy.proxy_url(), timeout=urllib3.Timeout(connect=1, read=1), retries=False)
        try:
            client.request("GET", "https://example.com/path", headers={"Authorization": "Bearer secret", "Cookie": "a=1"})
        except Exception:
            pass
        time.sleep(0.05)
        require(proxy.captured.startswith("CONNECT example.com:443 "), proxy.captured)
        require("Authorization:" not in proxy.captured and "Cookie:" not in proxy.captured, proxy.captured)


def https_tunnel_header_isolation_requests() -> None:
    with TunnelCaptureServer() as proxy:
        try:
            requests.get(
                "https://example.com/path",
                headers={"Authorization": "Bearer secret", "Cookie": "a=1"},
                proxies={"https": proxy.proxy_url()},
                timeout=2,
            )
        except Exception:
            pass
        time.sleep(0.05)
        require(proxy.captured.startswith("CONNECT example.com:443 "), proxy.captured)
        require("Authorization:" not in proxy.captured and "Cookie:" not in proxy.captured, proxy.captured)


def retry_after_503_408_urllib3() -> None:
    def handler(req):
        count = server.path_requests.get(req.path, 0)
        if count == 1:
            return RawResponse(status=503 if req.path == "/503" else 408, headers=[("Retry-After", "0")])
        return RawResponse.ok("ok")

    with RawServer(handler) as server:
        response_503 = urllib3_client().request("GET", server.url("/503"), retries=False)
        response_408 = urllib3_client().request("GET", server.url("/408"), retries=False)
        require(response_503.status == 200 and response_408.status == 200, f"{response_503.status} {response_408.status}")


def retry_after_503_408_requests() -> None:
    def handler(req):
        count = server.path_requests.get(req.path, 0)
        if count == 1:
            return RawResponse(status=503 if req.path == "/503" else 408, headers=[("Retry-After", "0")])
        return RawResponse.ok("ok")

    with RawServer(handler) as server:
        response_503 = requests.get(server.url("/503"), timeout=2)
        response_408 = requests.get(server.url("/408"), timeout=2)
        require(response_503.status_code == 200 and response_408.status_code == 200, f"{response_503.status_code} {response_408.status_code}")


def http_408_not_retried_when_disabled_urllib3() -> None:
    with RawServer(lambda req: RawResponse(status=408, body=b"timeout")) as server:
        response = urllib3_client().request("GET", server.url("/"), retries=False)
        require(response.status == 408 and server.path_requests.get("/", 0) == 1, f"{response.status} {server.path_requests}")


def http_408_not_retried_when_disabled_requests() -> None:
    with RawServer(lambda req: RawResponse(status=408, body=b"timeout")) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.status_code == 408 and server.path_requests.get("/", 0) == 1, f"{response.status_code} {server.path_requests}")


def port_out_of_range_urllib3() -> None:
    try:
        urllib3_client().request("GET", "http://127.0.0.1:65536/", timeout=0.2)
    except Exception:
        return
    raise AssertionError("accepted port 65536")


def port_out_of_range_requests() -> None:
    try:
        requests.get("http://127.0.0.1:65536/", timeout=0.2)
    except requests.exceptions.InvalidURL:
        return
    except Exception as exc:
        raise AssertionError(f"wrong exception {exc.__class__.__name__}: {exc}") from exc
    raise AssertionError("accepted port 65536")


def headers_case_insensitive_urllib3() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Content-Type", "text/plain")], body=b"ok")) as server:
        response = urllib3_client().request("GET", server.url("/"))
        require(response.headers["content-type"] == "text/plain", dict(response.headers))


def headers_case_insensitive_requests() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Content-Type", "text/plain")], body=b"ok")) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.headers["content-type"] == "text/plain", dict(response.headers))


def unsafe_non_ascii_header_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("X-Test") or "")) as server:
        response = urllib3_client().request("GET", server.url("/"), headers={"X-Test": "token-é"})
        require(response.data.decode("utf-8", "replace").startswith("token-"), response.data)


def unsafe_non_ascii_header_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("X-Test") or "")) as server:
        response = requests.get(server.url("/"), headers={"X-Test": "token-é"}, timeout=2)
        require(response.text.startswith("token-"), response.text)


def multipart_filename_non_ascii_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = urllib3_client().request("POST", server.url("/"), fields={"file": ("résumé.txt", b"x")})
        require('filename="résumé.txt"' in response.data.decode("utf-8", "replace"), response.data[:300])


def multipart_filename_non_ascii_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        response = requests.post(server.url("/"), files={"file": ("résumé.txt", b"x")}, timeout=2)
        require('filename="résumé.txt"' in response.text, response.text[:300])


def multipart_fixed_length_content_length_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("Content-Length") or "")) as server:
        response = urllib3_client().request("POST", server.url("/"), fields={"file": ("a.txt", b"x")})
        require(response.data.decode().isdigit(), response.data.decode())


def multipart_fixed_length_content_length_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("Content-Length") or "")) as server:
        response = requests.post(server.url("/"), files={"file": ("a.txt", b"x")}, timeout=2)
        require(response.text.isdigit(), response.text)


def timeout_error_taxonomy_urllib3() -> None:
    with RawServer(lambda req: (time.sleep(0.25), RawResponse.ok(""))[1]) as server:
        try:
            urllib3_client().request("GET", server.url("/"), timeout=urllib3.Timeout(connect=1, read=0.05), retries=False)
        except urllib3.exceptions.ReadTimeoutError:
            return
    raise AssertionError("expected ReadTimeoutError")


def timeout_error_taxonomy_requests() -> None:
    with RawServer(lambda req: (time.sleep(0.25), RawResponse.ok(""))[1]) as server:
        try:
            requests.get(server.url("/"), timeout=(1, 0.05))
        except requests.exceptions.Timeout:
            return
    raise AssertionError("expected Timeout")


def timeout_not_retried_urllib3() -> None:
    with RawServer(lambda req: (time.sleep(0.25), RawResponse.ok(""))[1]) as server:
        try:
            urllib3_client().request("GET", server.url("/"), timeout=urllib3.Timeout(connect=1, read=0.05), retries=False)
        except urllib3.exceptions.ReadTimeoutError:
            require(server.path_requests.get("/", 0) == 1, server.path_requests)
            return
    raise AssertionError("expected ReadTimeoutError")


def timeout_not_retried_requests() -> None:
    with RawServer(lambda req: (time.sleep(0.25), RawResponse.ok(""))[1]) as server:
        try:
            requests.get(server.url("/"), timeout=(1, 0.05))
        except requests.exceptions.Timeout:
            require(server.path_requests.get("/", 0) == 1, server.path_requests)
            return
    raise AssertionError("expected Timeout")


def null_header_ignored_urllib3() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("X-Test") or "")) as server:
        response = urllib3_client().request("GET", server.url("/"), headers={"X-Test": None})
        require(response.data.decode() == "", response.data)


def null_header_ignored_requests() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("X-Test") or "")) as server:
        response = requests.get(server.url("/"), headers={"X-Test": None}, timeout=2)
        require(response.text == "", response.text)


TESTS = {
    "urllib3": {
        "form_body_encodes_space_as_plus": form_body_space_plus_urllib3,
        "form_body_builder_accepts_explicit_charset": form_body_explicit_charset_urllib3,
        "request_bodies_allowed_for_methods_except_get_and_head": delete_body_allowed_urllib3,
        "options_request_body_is_allowed": options_body_allowed_urllib3,
        "http_308_permanent_redirect_is_handled": http_308_redirect_urllib3,
        "http_307_308_redirects_preserve_non_get_post_method_and_body": http_307_308_non_get_body_urllib3,
        "query_method_redirects_follow_rfc10008": query_method_redirect_urllib3,
        "disabled_redirect_policy_is_honored": disabled_redirect_urllib3,
        "multiple_informational_responses_are_ignored_until_final": multiple_informational_responses_urllib3,
        "http1_100_continue_status_lines_are_ignored_until_final": http1_100_continue_urllib3,
        "empty_query_does_not_include_fragment": empty_query_no_fragment_urllib3,
        "encoded_query_plus_is_preserved": encoded_query_plus_urllib3,
        "url_scheme_may_contain_digits": url_scheme_digits_urllib3,
        "url_fragment_preserves_non_ascii_characters": url_fragment_non_ascii_urllib3,
        "idn_uses_uts46_nontransitional_processing": idn_uts46_urllib3,
        "query_parameter_builder_escapes_ascii_punctuation": query_parameter_escape_urllib3,
        "http_url_to_uri_allows_special_url_characters": special_url_characters_urllib3,
        "url_domain_label_length_limits_are_enforced": domain_label_length_urllib3,
        "http_url_to_uri_strips_invalid_hostname_characters": uri_hostname_sanitization_urllib3,
        "ipv4_mapped_ipv6_url_does_not_crash": ipv4_mapped_ipv6_url_urllib3,
        "http10_requests_are_not_sent": http10_not_sent_urllib3,
        "webdav_methods_are_supported": webdav_methods_urllib3,
        "illegal_request_body_fails_at_build_time": illegal_get_body_fails_urllib3,
        "response_body_is_non_null_for_all_responses": response_body_non_null_urllib3,
        "shoutcast_icy_response_is_supported": shoutcast_icy_urllib3,
        "mutual_tls_client_certificate_is_sent_when_required": mutual_tls_client_certificate_urllib3,
        "authentication_credentials_support_charset": authentication_credentials_charset_urllib3,
        "https_tunnel_does_not_leak_origin_headers_to_proxy": https_tunnel_header_isolation_urllib3,
        "retry_after_controls_503_and_408_retries": retry_after_503_408_urllib3,
        "http_408_retry_respects_retry_on_connection_failure": http_408_not_retried_when_disabled_urllib3,
        "port_out_of_range_fails_early": port_out_of_range_urllib3,
        "headers_to_multimap_is_case_insensitive": headers_case_insensitive_urllib3,
        "unsafe_non_ascii_header_values_can_be_added": unsafe_non_ascii_header_urllib3,
        "multipart_filename_allows_non_ascii": multipart_filename_non_ascii_urllib3,
        "multipart_fixed_length_body_emits_content_length": multipart_fixed_length_content_length_urllib3,
        "timeout_errors_use_socket_timeout_taxonomy": timeout_error_taxonomy_urllib3,
        "timeout_failures_are_not_retried": timeout_not_retried_urllib3,
        "null_header_values_are_ignored": null_header_ignored_urllib3,
    },
    "requests": {
        "form_body_encodes_space_as_plus": form_body_space_plus_requests,
        "form_body_builder_accepts_explicit_charset": form_body_explicit_charset_requests,
        "request_bodies_allowed_for_methods_except_get_and_head": delete_body_allowed_requests,
        "options_request_body_is_allowed": options_body_allowed_requests,
        "http_308_permanent_redirect_is_handled": http_308_redirect_requests,
        "http_307_308_redirects_preserve_non_get_post_method_and_body": http_307_308_non_get_body_requests,
        "query_method_redirects_follow_rfc10008": query_method_redirect_requests,
        "disabled_redirect_policy_is_honored": disabled_redirect_requests,
        "multiple_informational_responses_are_ignored_until_final": multiple_informational_responses_requests,
        "http1_100_continue_status_lines_are_ignored_until_final": http1_100_continue_requests,
        "empty_query_does_not_include_fragment": empty_query_no_fragment_requests,
        "encoded_query_plus_is_preserved": encoded_query_plus_requests,
        "url_scheme_may_contain_digits": url_scheme_digits_requests,
        "url_fragment_preserves_non_ascii_characters": url_fragment_non_ascii_requests,
        "idn_uses_uts46_nontransitional_processing": idn_uts46_requests,
        "query_parameter_builder_escapes_ascii_punctuation": query_parameter_escape_requests,
        "http_url_to_uri_allows_special_url_characters": special_url_characters_requests,
        "url_domain_label_length_limits_are_enforced": domain_label_length_requests,
        "http_url_to_uri_strips_invalid_hostname_characters": uri_hostname_sanitization_requests,
        "ipv4_mapped_ipv6_url_does_not_crash": ipv4_mapped_ipv6_url_requests,
        "http10_requests_are_not_sent": http10_not_sent_requests,
        "webdav_methods_are_supported": webdav_methods_requests,
        "illegal_request_body_fails_at_build_time": illegal_get_body_fails_requests,
        "response_body_is_non_null_for_all_responses": response_body_non_null_requests,
        "shoutcast_icy_response_is_supported": shoutcast_icy_requests,
        "mutual_tls_client_certificate_is_sent_when_required": mutual_tls_client_certificate_requests,
        "authentication_credentials_support_charset": authentication_credentials_charset_requests,
        "https_tunnel_does_not_leak_origin_headers_to_proxy": https_tunnel_header_isolation_requests,
        "retry_after_controls_503_and_408_retries": retry_after_503_408_requests,
        "http_408_retry_respects_retry_on_connection_failure": http_408_not_retried_when_disabled_requests,
        "port_out_of_range_fails_early": port_out_of_range_requests,
        "headers_to_multimap_is_case_insensitive": headers_case_insensitive_requests,
        "unsafe_non_ascii_header_values_can_be_added": unsafe_non_ascii_header_requests,
        "multipart_filename_allows_non_ascii": multipart_filename_non_ascii_requests,
        "multipart_fixed_length_body_emits_content_length": multipart_fixed_length_content_length_requests,
        "timeout_errors_use_socket_timeout_taxonomy": timeout_error_taxonomy_requests,
        "timeout_failures_are_not_retried": timeout_not_retried_requests,
        "null_header_values_are_ignored": null_header_ignored_requests,
    },
}


def main() -> int:
    payload = {
        "source": "contracts/common/okhttp_origin_common_candidates.json",
        "targets": {
            "urllib3": urllib3.__version__,
            "requests": requests.__version__,
        },
        "tests": {
            target: {name: run_test(fn) for name, fn in tests.items()}
            for target, tests in TESTS.items()
        },
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "targets": payload["targets"],
        "passed": {target: sum(1 for row in tests.values() if row["passed"]) for target, tests in payload["tests"].items()},
        "failed": {target: sum(1 for row in tests.values() if not row["passed"]) for target, tests in payload["tests"].items()},
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
