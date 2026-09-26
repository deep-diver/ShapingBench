#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import email.utils
import gzip
import hashlib
import json
import pathlib
import re
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "requests"
SOURCE = ROOT / "contracts" / "urllib3" / "final_survival_urllib3_2.7.0.json"


@dataclass
class RawRequest:
    method: str
    target: str
    protocol: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes
    chunk_size_lines: list[str] | None = None

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass
class RawResponse:
    status: int = 200
    headers: list[tuple[str, str]] | None = None
    body: bytes = b""
    close_after: bool = False
    close_without_response: bool = False
    explicit_length: int | None = None

    @classmethod
    def ok(cls, body: str = "ok") -> "RawResponse":
        return cls(body=body.encode())

    @classmethod
    def status_text(cls, status: int, body: str = "") -> "RawResponse":
        return cls(status=status, body=body.encode())

    @classmethod
    def redirect(cls, location: str, status: int = 303) -> "RawResponse":
        return cls(status=status, headers=[("Location", location)])

    @classmethod
    def close(cls) -> "RawResponse":
        return cls(close_without_response=True)

    def write(self, sock: socket.socket) -> None:
        phrase = HTTPStatus(self.status).phrase if self.status in HTTPStatus._value2member_map_ else "OK"
        head = [f"HTTP/1.1 {self.status} {phrase}\r\n"]
        headers = list(self.headers or [])
        if not any(k.lower() == "content-length" for k, _ in headers) and not any(k.lower() == "transfer-encoding" for k, _ in headers):
            headers.append(("Content-Length", str(self.explicit_length if self.explicit_length is not None else len(self.body))))
        for key, value in headers:
            head.append(f"{key}: {value}\r\n")
        head.append("\r\n")
        sock.sendall("".join(head).encode("iso-8859-1") + self.body)


class RawServer:
    def __init__(
        self,
        handler: Callable[[RawRequest], RawResponse],
        tls: bool = False,
        tls_minimum: ssl.TLSVersion | None = None,
        tls_maximum: ssl.TLSVersion | None = None,
        tls_ciphers: str | None = None,
        cert_alt_names: str = "DNS:localhost,IP:127.0.0.1",
        alpn_protocols: list[str] | None = None,
        bind_host: str = "127.0.0.1",
    ):
        self.handler = handler
        self.accepted_connections = 0
        self.path_requests: dict[str, int] = {}
        self.cert_path: pathlib.Path | None = None
        self.selected_alpn_protocols: list[str | None] = []
        self.selected_ciphers: list[str | None] = []
        self.received_sni: list[str | None] = []
        self.alpn_protocols = alpn_protocols
        self._running = True
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self.bind_host = bind_host
        family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
        self._sock = socket.socket(family)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, 0))
        self._sock.listen()
        self.scheme = "https" if tls else "http"
        if tls:
            self._tmp = tempfile.TemporaryDirectory()
            d = pathlib.Path(self._tmp.name)
            cert, key = d / "cert.pem", d / "key.pem"
            self.cert_path = cert
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-noenc",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    f"subjectAltName={cert_alt_names}",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if tls_minimum is not None:
                ctx.minimum_version = tls_minimum
            if tls_maximum is not None:
                ctx.maximum_version = tls_maximum
            if tls_ciphers is not None:
                ctx.set_ciphers(tls_ciphers)
            if alpn_protocols is not None:
                ctx.set_alpn_protocols(alpn_protocols)
            ctx.set_servername_callback(lambda _sock, name, _ctx: self.received_sni.append(name))
            ctx.load_cert_chain(str(cert), str(key))
            self._sock = ctx.wrap_socket(self._sock, server_side=True)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    def url(self, path: str) -> str:
        host = f"[{self.bind_host}]" if ":" in self.bind_host else self.bind_host
        return f"{self.scheme}://{host}:{self.port}{path}"

    def close(self) -> None:
        self._running = False
        with contextlib.suppress(Exception):
            self._sock.close()
        if self._tmp:
            self._tmp.cleanup()

    def __enter__(self) -> "RawServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _accept(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.accepted_connections += 1
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            if isinstance(conn, ssl.SSLSocket):
                self.selected_alpn_protocols.append(conn.selected_alpn_protocol())
                cipher = conn.cipher()
                self.selected_ciphers.append(cipher[0] if cipher else None)
            conn.settimeout(5)
            while self._running:
                try:
                    request = self._read_request(conn)
                except Exception:
                    return
                if request is None:
                    return
                self.path_requests[request.path] = self.path_requests.get(request.path, 0) + 1
                response = self.handler(request)
                if response.close_without_response:
                    return
                response.write(conn)
                if response.close_after or (request.header("Connection") or "").lower() == "close":
                    return

    def _readline(self, conn: socket.socket) -> bytes | None:
        data = bytearray()
        while True:
            b = conn.recv(1)
            if not b:
                return bytes(data) if data else None
            data.extend(b)
            if data.endswith(b"\r\n"):
                return bytes(data[:-2])

    def _read_request(self, conn: socket.socket) -> RawRequest | None:
        line = self._readline(conn)
        if not line:
            return None
        method, target, protocol = line.decode("iso-8859-1").split(" ", 2)
        headers: list[tuple[str, str]] = []
        while True:
            line = self._readline(conn)
            if line is None:
                return None
            if line == b"":
                break
            key, value = line.decode("iso-8859-1").split(":", 1)
            headers.append((key, value.strip()))
        header_map = {k.lower(): v for k, v in headers}
        body = b""
        chunk_size_lines: list[str] = []
        if header_map.get("transfer-encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size_line = self._readline(conn)
                if size_line is None:
                    break
                chunk_size_lines.append(size_line.decode("iso-8859-1"))
                size = int(size_line.split(b";", 1)[0], 16)
                if size == 0:
                    self._readline(conn)
                    break
                chunk = b""
                while len(chunk) < size:
                    chunk += conn.recv(size - len(chunk))
                chunks.append(chunk)
                conn.recv(2)
            body = b"".join(chunks)
        elif "content-length" in header_map:
            remaining = int(header_map["content-length"])
            chunks = []
            while remaining:
                chunk = conn.recv(remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
        parsed = urllib.parse.urlsplit(target)
        return RawRequest(method, target, protocol, parsed.path or target.split("?", 1)[0], parsed.query, headers, body, chunk_size_lines)


class TunnelProxy:
    def __init__(self, bind_host: str = "127.0.0.1"):
        self.requests: list[str] = []
        self.bind_host = bind_host
        self._running = True
        family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
        self._sock = socket.socket(family)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, 0))
        self._sock.listen()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    @property
    def url(self) -> str:
        host = f"[{self.bind_host}]" if ":" in self.bind_host else self.bind_host
        return f"http://{host}:{self.port}"

    def close(self) -> None:
        self._running = False
        with contextlib.suppress(Exception):
            self._sock.close()

    def __enter__(self) -> "TunnelProxy":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _accept(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5)
            data = bytearray()
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data.extend(chunk)
            header = bytes(data).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
            request_line = header.split("\r\n", 1)[0]
            self.requests.append(request_line)
            method, authority, _version = request_line.split(" ", 2)
            if method.upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                return
            host, port_text = authority.rsplit(":", 1)
            host = host.strip("[]")
            try:
                upstream = socket.create_connection((host, int(port_text)), timeout=5)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            with upstream:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                sockets = [client, upstream]
                while True:
                    readable, _, _ = select.select(sockets, [], [], 5)
                    if not readable:
                        return
                    for src in readable:
                        dst = upstream if src is client else client
                        chunk = src.recv(8192)
                        if not chunk:
                            return
                        dst.sendall(chunk)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def session_with_retries(total: int = 1) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=total, connect=total, read=total, redirect=total, status=total, allowed_methods=None)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def session_with_retry_policy(retry: Retry) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def run_test(name: str, fn: Callable[[], None]) -> dict:
    try:
        fn()
        return {"name": name, "passed": True, "error": ""}
    except BaseException as exc:
        return {"name": name, "passed": False, "error": f"{exc.__class__.__name__}: {exc}"}


def connection_reuse() -> None:
    with RawServer(lambda req: RawResponse.ok(req.path.strip("/"))) as server:
        session = requests.Session()
        r1 = session.get(server.url("/first"), timeout=2)
        r2 = session.get(server.url("/second"), timeout=2)
        require(r1.text == "first" and r2.text == "second", "bad bodies")
        require(server.accepted_connections == 1, f"accepted {server.accepted_connections}")


def query_params() -> None:
    with RawServer(lambda req: RawResponse.ok("ok") if req.query == "method=GET" else RawResponse.status_text(400, req.query)) as server:
        require(requests.get(server.url("/specific_method"), params={"method": "GET"}, timeout=2).status_code == 200, "query not sent")


def post_form() -> None:
    with RawServer(lambda req: RawResponse.ok("ok") if req.text == "method=POST" else RawResponse.status_text(400, req.text)) as server:
        require(requests.post(server.url("/specific_method"), data={"method": "POST"}, timeout=2).status_code == 200, "form not sent")


def arbitrary_put_method() -> None:
    with RawServer(lambda req: RawResponse.ok("ok") if req.method == "PUT" and req.query == "method=PUT" else RawResponse.status_text(400, req.method)) as server:
        require(requests.request("PUT", server.url("/specific_method?method=PUT"), timeout=2).status_code == 200, "PUT not preserved")


def multipart_file_upload() -> None:
    def handler(req: RawRequest) -> RawResponse:
        ok = 'filename="lolcat.txt"' in req.text and "I'm in ur multipart form-data, hazing a cheezburgr" in req.text
        return RawResponse.ok("ok") if ok else RawResponse.status_text(400, req.text)
    with RawServer(handler) as server:
        files = {"filefield": ("lolcat.txt", b"I'm in ur multipart form-data, hazing a cheezburgr")}
        require(requests.post(server.url("/upload"), files=files, timeout=2).status_code == 200, "multipart failed")


def redirect_observable_without_following() -> None:
    with RawServer(lambda req: RawResponse.redirect("/")) as server:
        require(requests.get(server.url("/redirect"), allow_redirects=False, timeout=2).status_code == 303, "redirect not observable")


def redirect_followed_by_default() -> None:
    with RawServer(lambda req: RawResponse.redirect("/") if req.path == "/redirect" else RawResponse.ok("Dummy server!")) as server:
        require(requests.get(server.url("/redirect"), timeout=2).text == "Dummy server!", "redirect not followed")


def redirect_consumes_retry_budget() -> None:
    with RawServer(lambda req: RawResponse.redirect("/")) as server:
        session = requests.Session()
        session.max_redirects = 0
        try:
            session.get(server.url("/redirect"), timeout=2)
        except requests.TooManyRedirects:
            return
        raise AssertionError("expected TooManyRedirects")


def read_timeout_error() -> None:
    with RawServer(lambda req: (time.sleep(0.25), RawResponse.ok(""))[1]) as server:
        try:
            requests.get(server.url("/sleep"), timeout=(1, 0.1))
        except requests.exceptions.Timeout:
            return
        raise AssertionError("expected timeout")


def reused_connection_uses_new_socket_timeout() -> None:
    def handler(req: RawRequest) -> RawResponse:
        if req.path == "/slow":
            time.sleep(0.25)
        return RawResponse.ok(req.path)
    session = requests.Session()
    with RawServer(handler) as server:
        require(session.get(server.url("/fast"), timeout=(1, 1)).text == "/fast", "first request failed")
        try:
            session.get(server.url("/slow"), timeout=(1, 0.05))
        except requests.exceptions.Timeout:
            return
        raise AssertionError("expected reused connection to use new read timeout")


def broken_connection_retried() -> None:
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        return RawResponse.close() if attempts["n"] == 1 else RawResponse.ok("recovered")
    with RawServer(handler) as server:
        response = session_with_retries(1).get(server.url("/flaky"), timeout=2)
        require(response.text == "recovered" and attempts["n"] == 2, f"attempts {attempts['n']} body {response.text}")


def status_forcelist_retry_increments_retry_counter() -> None:
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        return RawResponse.status_text(503, "retry") if attempts["n"] == 1 else RawResponse.ok("ok")
    retry = Retry(total=1, status=1, status_forcelist=[503], allowed_methods=None, raise_on_status=False)
    with RawServer(handler) as server:
        response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        require(response.text == "ok" and attempts["n"] == 2, f"{response.status_code} attempts={attempts['n']}")


def retry_raise_on_status_false_returns_error_response() -> None:
    retry = Retry(total=0, status=0, status_forcelist=[503], allowed_methods=None, raise_on_status=False)
    with RawServer(lambda req: RawResponse.status_text(503, "unavailable")) as server:
        response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        require(response.status_code == 503 and response.text == "unavailable", f"{response.status_code} {response.text}")


def retry_after_header_is_respected_for_retry_statuses() -> None:
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return RawResponse(status=503, headers=[("Retry-After", "0")], body=b"retry")
        return RawResponse.ok("ok")
    retry = Retry(total=1, status=1, status_forcelist=[503], allowed_methods=None, raise_on_status=False, respect_retry_after_header=True)
    with RawServer(handler) as server:
        response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        require(response.text == "ok" and attempts["n"] == 2, f"{response.status_code} attempts={attempts['n']}")


def retry_after_can_be_explicitly_ignored() -> None:
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return RawResponse(status=503, headers=[("Retry-After", "3600")], body=b"retry")
        return RawResponse.ok("ok")
    retry = Retry(total=1, status=1, status_forcelist=[503], allowed_methods=None, raise_on_status=False, respect_retry_after_header=False)
    with RawServer(handler) as server:
        started = time.monotonic()
        response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        elapsed = time.monotonic() - started
        require(response.text == "ok" and attempts["n"] == 2 and elapsed < 1, f"{response.status_code} attempts={attempts['n']} elapsed={elapsed}")


def retry_after_setting_propagates_to_subsequent_retries() -> None:
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        if attempts["n"] < 3:
            return RawResponse(status=503, headers=[("Retry-After", "3600")], body=b"retry")
        return RawResponse.ok("ok")
    retry = Retry(total=2, status=2, status_forcelist=[503], allowed_methods=None, raise_on_status=False, respect_retry_after_header=False)
    with RawServer(handler) as server:
        started = time.monotonic()
        response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        elapsed = time.monotonic() - started
        require(response.text == "ok" and attempts["n"] == 3 and elapsed < 1, f"{response.status_code} attempts={attempts['n']} elapsed={elapsed}")


def retry_after_header_is_capped_at_six_hours() -> None:
    sleeps: list[float] = []
    attempts = {"n": 0}
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return RawResponse(status=503, headers=[("Retry-After", "999999")], body=b"retry")
        return RawResponse.ok("ok")
    retry = Retry(total=1, status=1, status_forcelist=[503], allowed_methods=None, raise_on_status=False, respect_retry_after_header=True)
    original_sleep = time.sleep
    try:
        time.sleep = lambda seconds: sleeps.append(seconds)  # type: ignore[assignment]
        with RawServer(handler) as server:
            response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        require(response.text == "ok" and attempts["n"] == 2, f"{response.status_code} attempts={attempts['n']}")
        require(sleeps and max(sleeps) <= 21600, f"sleeps={sleeps}")
    finally:
        time.sleep = original_sleep  # type: ignore[assignment]


def retry_after_http_date_uses_utc() -> None:
    sleeps: list[float] = []
    attempts = {"n": 0}
    retry_at = email.utils.format_datetime(datetime.now(timezone.utc) + timedelta(seconds=2), usegmt=True)
    def handler(req: RawRequest) -> RawResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return RawResponse(status=503, headers=[("Retry-After", retry_at)], body=b"retry")
        return RawResponse.ok("ok")
    retry = Retry(total=1, status=1, status_forcelist=[503], allowed_methods=None, raise_on_status=False, respect_retry_after_header=True)
    original_sleep = time.sleep
    try:
        time.sleep = lambda seconds: sleeps.append(seconds)  # type: ignore[assignment]
        with RawServer(handler) as server:
            response = session_with_retry_policy(retry).get(server.url("/status"), timeout=2)
        require(response.text == "ok" and attempts["n"] == 2, f"{response.status_code} attempts={attempts['n']}")
        require(sleeps and 0 <= sleeps[0] <= 5, f"retry_at={retry_at} sleeps={sleeps}")
    finally:
        time.sleep = original_sleep  # type: ignore[assignment]


def https_basic() -> None:
    with RawServer(lambda req: RawResponse.ok("secure"), tls=True) as server:
        response = requests.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "secure", "https failed")


def tls_minimum_and_maximum_versions_configure_context() -> None:
    class TLSAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    session = requests.Session()
    session.mount("https://", TLSAdapter())
    with RawServer(
        lambda req: RawResponse.ok("tls12"),
        tls=True,
        tls_minimum=ssl.TLSVersion.TLSv1_2,
        tls_maximum=ssl.TLSVersion.TLSv1_2,
    ) as server:
        response = session.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "tls12", response.text)


def certificate_ip_subject_alt_name_is_accepted() -> None:
    with RawServer(lambda req: RawResponse.ok("ip-san"), tls=True) as server:
        require(server.cert_path is not None, "missing generated cert")
        response = requests.get(server.url("/"), verify=str(server.cert_path), timeout=2)
        require(response.text == "ip-san", response.text)


def ipv6_braces_are_stripped_for_certificate_matching() -> None:
    with RawServer(
        lambda req: RawResponse.ok("ipv6 cert"),
        tls=True,
        cert_alt_names="IP:::1",
        bind_host="::1",
    ) as server:
        require(server.cert_path is not None, "missing generated cert")
        response = requests.get(server.url("/ipv6-cert"), verify=str(server.cert_path), timeout=2)
        require(response.text == "ipv6 cert", response.text)


def hostname_verification_can_be_disabled() -> None:
    with RawServer(lambda req: RawResponse.ok("hostname-disabled"), tls=True, cert_alt_names="DNS:wrong.test") as server:
        response = requests.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "hostname-disabled", response.text)


def fingerprint_verification_is_supported() -> None:
    class FingerprintAdapter(HTTPAdapter):
        def __init__(self, fingerprint: str):
            self.fingerprint = fingerprint
            super().__init__()

        def init_poolmanager(self, *args, **kwargs):
            kwargs["assert_fingerprint"] = self.fingerprint
            return super().init_poolmanager(*args, **kwargs)

    with RawServer(lambda req: RawResponse.ok("fingerprint"), tls=True, cert_alt_names="DNS:wrong.test") as server:
        require(server.cert_path is not None, "missing generated cert")
        pem = server.cert_path.read_bytes()
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
        fingerprint = hashlib.sha256(der).hexdigest()
        session = requests.Session()
        session.mount("https://", FingerprintAdapter(fingerprint))
        response = session.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "fingerprint", response.text)


def custom_cipher_suite_is_applied() -> None:
    cipher = "ECDHE-RSA-AES128-GCM-SHA256"

    class CipherAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(cipher)
            kwargs["ssl_context"] = ctx
            return super().init_poolmanager(*args, **kwargs)

    session = requests.Session()
    session.mount("https://", CipherAdapter())
    with RawServer(
        lambda req: RawResponse.ok("cipher"),
        tls=True,
        tls_minimum=ssl.TLSVersion.TLSv1_2,
        tls_maximum=ssl.TLSVersion.TLSv1_2,
        tls_ciphers=cipher,
    ) as server:
        response = session.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "cipher", response.text)
        require(server.selected_ciphers == [cipher], f"cipher {server.selected_ciphers}")


def tls_sni_hostname_can_be_overridden() -> None:
    class SNIAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["server_hostname"] = "override.test"
            return super().init_poolmanager(*args, **kwargs)

    session = requests.Session()
    session.mount("https://", SNIAdapter())
    with RawServer(lambda req: RawResponse.ok("sni"), tls=True, cert_alt_names="DNS:override.test") as server:
        response = session.get(server.url("/sni"), verify=False, timeout=2)
        require(response.text == "sni", response.text)
        require(server.received_sni == ["override.test"], str(server.received_sni))


def encrypted_client_key_without_password_raises_ssl_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        cert, key = d / "client-cert.pem", d / "client-key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-subj",
                "/CN=client",
                "-passout",
                "pass:secret",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with RawServer(lambda req: RawResponse.ok("should not load key"), tls=True) as server:
            code = """
import requests, sys
try:
    requests.get(sys.argv[1], verify=False, cert=(sys.argv[2], sys.argv[3]), timeout=2)
except requests.exceptions.SSLError:
    raise SystemExit(0)
except OSError:
    raise SystemExit(0)
raise SystemExit(1)
"""
            proc = subprocess.run(
                [sys.executable, "-c", code, server.url("/client-cert"), str(cert), str(key)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if proc.returncode == 0:
                return
            raise AssertionError("encrypted key without password was accepted")


def tls_alpn_http11_identifier_is_sent() -> None:
    with RawServer(lambda req: RawResponse.ok("alpn"), tls=True, alpn_protocols=["http/1.1"]) as server:
        response = requests.get(server.url("/"), verify=False, timeout=2)
        require(response.text == "alpn", response.text)
        require("http/1.1" in server.selected_alpn_protocols, str(server.selected_alpn_protocols))


def gzip_response_decoded() -> None:
    body = gzip.compress(b"hello gzip")
    with RawServer(lambda req: RawResponse(headers=[("Content-Encoding", "gzip")], body=body)) as server:
        require(requests.get(server.url("/gzip"), timeout=2).text == "hello gzip", "gzip not decoded")


def gzip_case_insensitive() -> None:
    body = gzip.compress(b"hello gzip")
    with RawServer(lambda req: RawResponse(headers=[("Content-Encoding", "GZip")], body=body)) as server:
        require(requests.get(server.url("/gzip"), timeout=2).text == "hello gzip", "gzip not decoded")


def multiple_content_encodings() -> None:
    body = gzip.compress(gzip.compress(b"double"))
    with RawServer(lambda req: RawResponse(headers=[("Content-Encoding", "gzip, gzip")], body=body)) as server:
        require(requests.get(server.url("/gzip"), timeout=2).text == "double", "multiple gzip not decoded")


def gzip_nested(body: bytes, count: int) -> bytes:
    for _ in range(count):
        body = gzip.compress(body)
    return body


def content_encoding_chain_limit() -> None:
    body = gzip_nested(b"too deep", 6)
    headers = [("Content-Encoding", "gzip, gzip, gzip, gzip, gzip, gzip")]
    with RawServer(lambda req: RawResponse(headers=headers, body=body)) as server:
        try:
            requests.get(server.url("/gzip"), timeout=2).content
        except requests.exceptions.RequestException:
            return
        raise AssertionError("expected chained content-encoding limit failure")


def decompression_buffer_continues_after_partial_read() -> None:
    body = gzip.compress(b"abcdef")
    with RawServer(lambda req: RawResponse(headers=[("Content-Encoding", "gzip")], body=body)) as server:
        response = requests.get(server.url("/gzip"), stream=True, timeout=2)
        try:
            response.raw.decode_content = True
            first = response.raw.read(2)
            rest = response.raw.read()
            require(first + rest == b"abcdef", f"decoded stream was {first + rest!r}")
        finally:
            response.close()


def streaming_decompression_bomb_guard_limits_output() -> None:
    body = gzip.compress(b"x" * 1_000_000)
    with RawServer(lambda req: RawResponse(headers=[("Content-Encoding", "gzip")], body=body)) as server:
        response = requests.get(server.url("/bomb"), stream=True, timeout=2)
        try:
            for _ in range(3):
                data = response.raw.read(1, decode_content=True)
                require(len(data) == 1, f"read {len(data)}")
                require(len(response.raw._decoded_buffer) == 0, f"buffer {len(response.raw._decoded_buffer)}")
        finally:
            response.close()


def url_ipv6_zone_identifier_accepted() -> None:
    prepared = requests.Request("GET", "http://[fe80::1%en0]/").prepare()
    require("[fe80::1%25en0]" in prepared.url, prepared.url)


def multiple_set_cookie_headers_preserved() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")], body=b"ok")) as server:
        response = requests.get(server.url("/"), timeout=2)
        require(response.raw.headers.getlist("Set-Cookie") == ["a=1", "b=2"], str(response.raw.headers))


def comma_header_value_preserved() -> None:
    with RawServer(lambda req: RawResponse(headers=[("X-Items", "a, b")], body=b"ok")) as server:
        require(requests.get(server.url("/"), timeout=2).headers["X-Items"] == "a, b", "comma lost")


def incomplete_content_length_raises() -> None:
    with RawServer(lambda req: RawResponse(body=b"short", explicit_length=10, close_after=True)) as server:
        try:
            requests.get(server.url("/"), timeout=2).content
        except requests.exceptions.ChunkedEncodingError:
            return
        raise AssertionError("expected incomplete read error")


def invalid_chunk_length_raises() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Transfer-Encoding", "chunked")], body=b"ZZZ\r\nbad\r\n0\r\n\r\n", close_after=True)) as server:
        try:
            requests.get(server.url("/"), timeout=2).content
        except requests.exceptions.ChunkedEncodingError:
            return
        raise AssertionError("expected invalid chunk error")


def fragment_not_sent() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        require(requests.get(server.url("/path?x=1#fragment"), timeout=2).text == "/path?x=1", "fragment sent")


def request_target_is_origin_form() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        require(requests.get(server.url("/path?x=1"), timeout=2).text == "/path?x=1", "absolute-form target sent")


def tilde_not_percent_encoded() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        require(requests.get(server.url("/~user"), timeout=2).text == "/~user", "tilde encoded")


def empty_query_preserved() -> None:
    with RawServer(lambda req: RawResponse.ok(req.target)) as server:
        require(requests.get(server.url("/path?"), timeout=2).text == "/path?", "empty query not preserved")


def host_header_preserved() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("Host") or "")) as server:
        require(requests.get(server.url("/"), headers={"Host": "example.test"}, timeout=2).text == "example.test", "host changed")


def chunked_request_sets_transfer_encoding() -> None:
    def gen():
        yield b"chunk me"
    with RawServer(lambda req: RawResponse.ok(req.header("Transfer-Encoding") or "")) as server:
        require(requests.post(server.url("/"), data=gen(), timeout=2).text.lower() == "chunked", "not chunked")


def chunked_keep_alive_preserves_request_boundaries() -> None:
    session = requests.Session()
    def gen():
        yield b"chunked"
    def handler(req: RawRequest) -> RawResponse:
        if req.method == "POST":
            return RawResponse.ok(req.body.decode("utf-8"))
        return RawResponse.ok(req.path)
    with RawServer(handler) as server:
        post = session.post(server.url("/upload"), data=gen(), timeout=2)
        get = session.get(server.url("/next"), timeout=2)
        require(post.text == "chunked", post.text)
        require(get.text == "/next", get.text)
        require(server.accepted_connections == 1, f"accepted {server.accepted_connections}")


def chunked_request_body_uses_utf8() -> None:
    def gen():
        yield "cafe \u00e9"
    with RawServer(lambda req: RawResponse.ok(req.body.hex())) as server:
        response = requests.post(server.url("/"), data=gen(), timeout=2)
        require(response.text == "cafe \u00e9".encode("utf-8").hex(), response.text)


def chunked_boundaries_are_lowercase() -> None:
    def gen():
        yield b"x" * 26
    with RawServer(lambda req: RawResponse.ok(",".join(req.chunk_size_lines or []))) as server:
        response = requests.post(server.url("/"), data=gen(), timeout=2)
        sizes = response.text.split(",")
        require("1a" in sizes and "1A" not in sizes, response.text)


def explicit_transfer_encoding_not_duplicated() -> None:
    def gen():
        yield b"chunk me"
    with RawServer(lambda req: RawResponse.ok(str(len(req.header_values("Transfer-Encoding"))))) as server:
        require(requests.post(server.url("/"), data=gen(), headers={"Transfer-Encoding": "chunked"}, timeout=2).text == "1", "duplicated")


def http_303_redirect_switches_method_to_get() -> None:
    seen: list[str] = []
    def handler(req: RawRequest) -> RawResponse:
        seen.append(f"{req.method} {req.path} {req.text}")
        return RawResponse.redirect("/target") if req.path == "/redirect" else RawResponse.ok(f"{req.method}:{req.text}")
    with RawServer(handler) as server:
        response = requests.post(server.url("/redirect"), data="body", timeout=2)
        require(response.text == "GET:", f"body {response.text}")
        require(seen[-1] == "GET /target ", str(seen))


def relative_redirect_followed() -> None:
    with RawServer(lambda req: RawResponse.redirect("../target") if req.path == "/a/start" else RawResponse.ok(req.path)) as server:
        require(requests.get(server.url("/a/start"), timeout=2).text == "/target", "relative redirect failed")


def redirect_body_is_released_before_following() -> None:
    def handler(req: RawRequest) -> RawResponse:
        if req.path == "/start":
            return RawResponse(status=302, headers=[("Location", "/target")], body=b"x" * 1024)
        return RawResponse.ok("target")
    session = requests.Session()
    session.mount("http://", HTTPAdapter(pool_connections=1, pool_maxsize=1, pool_block=True))
    with RawServer(handler) as server:
        response = session.get(server.url("/start"), timeout=2)
        require(response.text == "target", response.text)


def cross_host_strips_authorization() -> None:
    with RawServer(lambda req: RawResponse.ok(str(req.header("Authorization")))) as target:
        with RawServer(lambda req: RawResponse.redirect(target.url("/target"))) as source:
            response = requests.get(source.url("/start"), headers={"Authorization": "Bearer secret"}, timeout=2)
            require(response.text == "None", response.text)


def cross_host_strips_cookie() -> None:
    with RawServer(lambda req: RawResponse.ok(str(req.header("Cookie")))) as target:
        with RawServer(lambda req: RawResponse.redirect(target.url("/target"))) as source:
            response = requests.get(source.url("/start"), headers={"Cookie": "a=1"}, timeout=2)
            require(response.text == "None", response.text)


def cross_host_strips_proxy_authorization() -> None:
    with RawServer(lambda req: RawResponse.ok(str(req.header("Proxy-Authorization")))) as target:
        with RawServer(lambda req: RawResponse.redirect(target.url("/target"))) as source:
            response = requests.get(source.url("/start"), headers={"Proxy-Authorization": "Basic secret"}, timeout=2)
            require(response.text == "None", response.text)


def redirect_header_input_not_mutated() -> None:
    headers = {"Authorization": "Bearer secret"}
    with RawServer(lambda req: RawResponse.ok("ok")) as target:
        with RawServer(lambda req: RawResponse.redirect(target.url("/target"))) as source:
            requests.get(source.url("/start"), headers=headers, timeout=2)
    require(headers == {"Authorization": "Bearer secret"}, str(headers))


def method_rejects_control_characters() -> None:
    with RawServer(lambda req: RawResponse.status_text(599, f"invalid method reached server: {req.method!r}")) as server:
        try:
            requests.request("GE\nT", server.url("/"), timeout=2)
        except Exception:
            return
        raise AssertionError("accepted invalid method")


def url_empty_host_rejected() -> None:
    try:
        requests.Request("GET", "http:///path").prepare()
    except Exception:
        return
    raise AssertionError("accepted empty host")


def url_scheme_and_host_lowercase() -> None:
    prepared = requests.Request("GET", "HTTP://EXAMPLE.COM/Path").prepare()
    parsed = urllib.parse.urlsplit(prepared.url)
    require(parsed.scheme == "http" and parsed.hostname == "example.com", prepared.url)


def url_default_port_equivalence() -> None:
    a = requests.Request("GET", "http://example.com/").prepare().url
    b = requests.Request("GET", "http://example.com:80/").prepare().url
    require(urllib.parse.urlsplit(a).port in (None, 80) and urllib.parse.urlsplit(b).port == 80, f"{a} {b}")


def url_port_with_leading_zeroes() -> None:
    prepared = requests.Request("GET", "http://example.com:00080/").prepare()
    require(urllib.parse.urlsplit(prepared.url).port == 80, prepared.url)


def url_port_zero_preserved() -> None:
    prepared = requests.Request("GET", "http://example.com:0/").prepare()
    require(urllib.parse.urlsplit(prepared.url).port == 0, prepared.url)


def url_port_rejects_unicode_digits() -> None:
    try:
        requests.Request("GET", "http://example.com:\u0661/").prepare()
    except Exception:
        return
    raise AssertionError("accepted unicode port")


def url_ipv6_requires_brackets() -> None:
    try:
        requests.Request("GET", "http://::1/").prepare()
    except Exception:
        pass
    else:
        raise AssertionError("accepted bare ipv6")
    require(requests.Request("GET", "http://[::1]/").prepare().url.startswith("http://[::1]"), "bracketed rejected")


def url_invalid_chars_percent_encoded() -> None:
    url = requests.Request("GET", "http://example.com/a b?x=a b#frag ment").prepare().url
    require("/a%20b" in url and "x=a%20b" in url and "frag%20ment" in url, url)


def url_auth_invalid_chars_percent_encoded() -> None:
    url = requests.Request("GET", "http://u s:p s@example.com/").prepare().url
    require("u%20s:p%20s@" in url, url)


def url_authority_includes_userinfo_and_host() -> None:
    parsed = urllib.parse.urlsplit(requests.Request("GET", "http://user:pass@example.com:8080/path").prepare().url)
    require(parsed.username == "user" and parsed.password == "pass" and parsed.hostname == "example.com" and parsed.port == 8080, str(parsed))


def json_request_sets_content_type() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("Content-Type") or "")) as server:
        require(requests.post(server.url("/json"), json={"ok": True}, timeout=2).text.startswith("application/json"), "json content-type missing")


def request_header_input_not_mutated() -> None:
    headers = {"X-Test": "before"}
    with RawServer(lambda req: RawResponse.ok("ok")) as server:
        requests.post(server.url("/"), headers=headers, json={"ok": True}, timeout=2)
    require(headers == {"X-Test": "before"}, str(headers))


def default_headers_sent() -> None:
    def handler(req: RawRequest) -> RawResponse:
        ok = req.header("Host") and req.header("Accept-Encoding") and req.header("User-Agent")
        return RawResponse.ok("ok") if ok else RawResponse.status_text(400, str(req.headers))
    with RawServer(handler) as server:
        require(requests.get(server.url("/"), timeout=2).status_code == 200, "default headers missing")


def connection_refused_error() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    try:
        requests.get(f"http://127.0.0.1:{port}/", timeout=0.5)
    except requests.exceptions.ConnectionError:
        return
    raise AssertionError("expected connection error")


def https_request_through_http_connect_proxy_succeeds() -> None:
    with RawServer(lambda req: RawResponse.ok("proxied secure"), tls=True) as origin:
        with TunnelProxy() as proxy:
            response = requests.get(
                origin.url("/proxied"),
                proxies={"https": proxy.url},
                verify=False,
                timeout=3,
            )
            require(response.text == "proxied secure", response.text)
            require(proxy.requests and proxy.requests[0].startswith("CONNECT 127.0.0.1:"), str(proxy.requests))


def proxy_connect_ipv6_target_uses_brackets() -> None:
    with RawServer(lambda req: RawResponse.ok("ipv6 proxied"), tls=True, bind_host="::1") as origin:
        with TunnelProxy() as proxy:
            response = requests.get(
                origin.url("/ipv6"),
                proxies={"https": proxy.url},
                verify=False,
                timeout=3,
            )
            require(response.text == "ipv6 proxied", response.text)
            require(proxy.requests and proxy.requests[0].startswith("CONNECT [::1]:"), str(proxy.requests))


def ipv6_proxy_host_is_parsed_correctly() -> None:
    with RawServer(lambda req: RawResponse.ok("ipv6 proxy host"), tls=True) as origin:
        with TunnelProxy(bind_host="::1") as proxy:
            response = requests.get(
                origin.url("/ipv6-proxy"),
                proxies={"https": proxy.url},
                verify=False,
                timeout=3,
            )
            require(response.text == "ipv6 proxy host", response.text)
            require(proxy.requests and proxy.requests[0].startswith("CONNECT 127.0.0.1:"), str(proxy.requests))


def trailing_dot_hostname_through_proxy_connects() -> None:
    with RawServer(lambda req: RawResponse.ok("trailing dot"), tls=True) as origin:
        with TunnelProxy() as proxy:
            response = requests.get(
                f"https://localhost.:{origin.port}/trailing",
                proxies={"https": proxy.url},
                verify=False,
                timeout=3,
            )
            require(response.text == "trailing dot", response.text)
            require(proxy.requests and proxy.requests[0].startswith("CONNECT localhost.:"), str(proxy.requests))


def dns_failure_error() -> None:
    session = requests.Session()
    session.trust_env = False
    try:
        session.get("http://nonexistent.shapingbench.invalid/", timeout=1)
    except requests.exceptions.ConnectionError:
        return
    raise AssertionError("expected DNS connection error")


def headers_mapping_accepted() -> None:
    with RawServer(lambda req: RawResponse.ok(req.header("X-Test") or "")) as server:
        require(requests.get(server.url("/"), headers={"X-Test": "ok"}, timeout=2).text == "ok", "header mapping rejected")


def session_default_headers_apply_to_get_query() -> None:
    def handler(req: RawRequest) -> RawResponse:
        ok = req.query == "q=1" and req.header("X-Default") == "yes"
        return RawResponse.ok("ok") if ok else RawResponse.status_text(400, f"{req.query} {req.headers}")
    session = requests.Session()
    session.headers.update({"X-Default": "yes"})
    with RawServer(handler) as server:
        require(session.get(server.url("/search"), params={"q": "1"}, timeout=2).status_code == 200, "default header missing")


def message_content_type_header_accepted() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Content-Type", "message/http")], body=b"ok")) as server:
        require(requests.get(server.url("/"), timeout=2).text == "ok", "message content type rejected")


def duplicate_user_agent_not_added() -> None:
    with RawServer(lambda req: RawResponse.ok(str(len(req.header_values("User-Agent"))))) as server:
        require(requests.get(server.url("/"), headers={"User-Agent": "custom"}, timeout=2).text == "1", "duplicate UA")


def header_order_preserved() -> None:
    def handler(req: RawRequest) -> RawResponse:
        names = [k for k, _ in req.headers if k in {"X-One", "X-Two"}]
        return RawResponse.ok(",".join(names))
    with RawServer(handler) as server:
        require(requests.get(server.url("/"), headers={"X-One": "1", "X-Two": "2"}, timeout=2).text == "X-One,X-Two", "order changed")


def multipart_duplicate_fields() -> None:
    with RawServer(lambda req: RawResponse.ok(str(req.text.count('name="field"')))) as server:
        files = [("field", (None, "one")), ("field", (None, "two"))]
        require(requests.post(server.url("/"), files=files, timeout=2).text == "2", "duplicate fields lost")


def multipart_empty_filename() -> None:
    with RawServer(lambda req: RawResponse.ok(str('filename=""' in req.text))) as server:
        require(requests.post(server.url("/"), files={"file": ("", b"x")}, timeout=2).text == "True", "empty filename missing")


def multipart_html5_filename_formatting() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        body = requests.post(server.url("/"), files={"file": ("cafe-\u00e9.txt", b"x")}, timeout=2).text
        require('filename="cafe-\u00e9.txt"' in body and "filename*=" not in body, body)


def multipart_control_chars_not_percent_encoded() -> None:
    with RawServer(lambda req: RawResponse.ok(req.text)) as server:
        body = requests.post(server.url("/"), files={"file": ("control-\x1f.txt", b"x")}, timeout=2).text
        require("%1F" not in body.upper() and 'filename="control-\x1f.txt"' in body, body)


def multipart_explicit_content_type() -> None:
    with RawServer(lambda req: RawResponse.ok(str("Content-Type: text/plain" in req.text))) as server:
        require(requests.post(server.url("/"), files={"file": ("a.txt", b"x", "text/plain")}, timeout=2).text == "True", "content type missing")


def multipart_plain_field_no_default_content_type() -> None:
    def handler(req: RawRequest) -> RawResponse:
        part = req.text.split('name="field"', 1)[1].split("--", 1)[0]
        return RawResponse.ok(str("Content-Type:" not in part))
    with RawServer(handler) as server:
        require(requests.post(server.url("/"), files={"field": (None, "value")}, timeout=2).text == "True", "plain field content-type added")


def response_lines_streamed() -> None:
    with RawServer(lambda req: RawResponse.ok("a\nb\n")) as server:
        response = requests.get(server.url("/"), stream=True, timeout=2)
        require(list(response.iter_lines()) == [b"a", b"b"], "bad lines")


def chunked_head_no_hang() -> None:
    with RawServer(lambda req: RawResponse(headers=[("Transfer-Encoding", "chunked")])) as server:
        require(requests.head(server.url("/"), timeout=2).status_code == 200, "HEAD failed")


TESTS: list[tuple[str, Callable[[], None]]] = [
    ("connection_reuse", connection_reuse),
    ("query_params", query_params),
    ("post_form", post_form),
    ("arbitrary_put_method", arbitrary_put_method),
    ("multipart_file_upload", multipart_file_upload),
    ("redirect_observable_without_following", redirect_observable_without_following),
    ("redirect_followed_by_default", redirect_followed_by_default),
    ("redirect_consumes_retry_budget", redirect_consumes_retry_budget),
    ("read_timeout_error", read_timeout_error),
    ("reused_connection_uses_new_socket_timeout", reused_connection_uses_new_socket_timeout),
    ("broken_connection_retried", broken_connection_retried),
    ("status_forcelist_retry_increments_retry_counter", status_forcelist_retry_increments_retry_counter),
    ("retry_raise_on_status_false_returns_error_response", retry_raise_on_status_false_returns_error_response),
    ("retry_after_header_is_respected_for_retry_statuses", retry_after_header_is_respected_for_retry_statuses),
    ("retry_after_can_be_explicitly_ignored", retry_after_can_be_explicitly_ignored),
    ("retry_after_setting_propagates_to_subsequent_retries", retry_after_setting_propagates_to_subsequent_retries),
    ("retry_after_header_is_capped_at_six_hours", retry_after_header_is_capped_at_six_hours),
    ("retry_after_http_date_uses_utc", retry_after_http_date_uses_utc),
    ("https_basic", https_basic),
    ("tls_minimum_and_maximum_versions_configure_context", tls_minimum_and_maximum_versions_configure_context),
    ("certificate_ip_subject_alt_name_is_accepted", certificate_ip_subject_alt_name_is_accepted),
    ("ipv6_braces_are_stripped_for_certificate_matching", ipv6_braces_are_stripped_for_certificate_matching),
    ("hostname_verification_can_be_disabled", hostname_verification_can_be_disabled),
    ("fingerprint_verification_is_supported", fingerprint_verification_is_supported),
    ("custom_cipher_suite_is_applied", custom_cipher_suite_is_applied),
    ("tls_sni_hostname_can_be_overridden", tls_sni_hostname_can_be_overridden),
    ("encrypted_client_key_without_password_raises_ssl_error", encrypted_client_key_without_password_raises_ssl_error),
    ("tls_alpn_http11_identifier_is_sent", tls_alpn_http11_identifier_is_sent),
    ("gzip_response_decoded", gzip_response_decoded),
    ("gzip_content_encoding_case_insensitive", gzip_case_insensitive),
    ("multiple_content_encodings", multiple_content_encodings),
    ("content_encoding_chain_limit", content_encoding_chain_limit),
    ("decompression_buffer_continues_after_partial_read", decompression_buffer_continues_after_partial_read),
    ("streaming_decompression_bomb_guard_limits_output", streaming_decompression_bomb_guard_limits_output),
    ("url_ipv6_zone_identifier_accepted", url_ipv6_zone_identifier_accepted),
    ("multiple_set_cookie_headers_preserved", multiple_set_cookie_headers_preserved),
    ("comma_header_value_preserved", comma_header_value_preserved),
    ("incomplete_content_length_raises", incomplete_content_length_raises),
    ("invalid_chunk_length_raises", invalid_chunk_length_raises),
    ("fragment_not_sent_in_request_target", fragment_not_sent),
    ("request_target_is_origin_form", request_target_is_origin_form),
    ("tilde_path_not_percent_encoded", tilde_not_percent_encoded),
    ("empty_query_section_preserved", empty_query_preserved),
    ("user_supplied_host_header_preserved", host_header_preserved),
    ("chunked_request_sets_transfer_encoding", chunked_request_sets_transfer_encoding),
    ("chunked_keep_alive_preserves_request_boundaries", chunked_keep_alive_preserves_request_boundaries),
    ("chunked_request_body_uses_utf8", chunked_request_body_uses_utf8),
    ("chunked_boundaries_are_lowercase", chunked_boundaries_are_lowercase),
    ("explicit_transfer_encoding_chunked_not_duplicated", explicit_transfer_encoding_not_duplicated),
    ("http_303_redirect_switches_method_to_get", http_303_redirect_switches_method_to_get),
    ("relative_redirect_location_followed", relative_redirect_followed),
    ("redirect_body_is_released_before_following", redirect_body_is_released_before_following),
    ("cross_host_redirect_strips_authorization", cross_host_strips_authorization),
    ("cross_host_redirect_strips_cookie", cross_host_strips_cookie),
    ("cross_host_redirect_strips_proxy_authorization", cross_host_strips_proxy_authorization),
    ("redirect_header_input_not_mutated", redirect_header_input_not_mutated),
    ("method_rejects_control_characters", method_rejects_control_characters),
    ("url_empty_host_rejected", url_empty_host_rejected),
    ("url_scheme_and_host_normalized_lowercase", url_scheme_and_host_lowercase),
    ("url_default_port_equivalence", url_default_port_equivalence),
    ("url_port_with_leading_zeroes_accepted", url_port_with_leading_zeroes),
    ("url_port_zero_preserved", url_port_zero_preserved),
    ("url_port_rejects_unicode_digits", url_port_rejects_unicode_digits),
    ("url_ipv6_requires_brackets", url_ipv6_requires_brackets),
    ("url_invalid_chars_percent_encoded", url_invalid_chars_percent_encoded),
    ("url_auth_invalid_chars_percent_encoded", url_auth_invalid_chars_percent_encoded),
    ("url_authority_includes_userinfo_and_host", url_authority_includes_userinfo_and_host),
    ("json_request_sets_content_type", json_request_sets_content_type),
    ("request_header_input_not_mutated", request_header_input_not_mutated),
    ("default_headers_sent", default_headers_sent),
    ("connection_refused_error", connection_refused_error),
    ("https_request_through_http_connect_proxy_succeeds", https_request_through_http_connect_proxy_succeeds),
    ("proxy_connect_ipv6_target_uses_brackets", proxy_connect_ipv6_target_uses_brackets),
    ("ipv6_proxy_host_is_parsed_correctly", ipv6_proxy_host_is_parsed_correctly),
    ("trailing_dot_hostname_through_proxy_connects", trailing_dot_hostname_through_proxy_connects),
    ("dns_failure_error", dns_failure_error),
    ("headers_mapping_accepted", headers_mapping_accepted),
    ("session_default_headers_apply_to_get_query", session_default_headers_apply_to_get_query),
    ("message_content_type_header_accepted", message_content_type_header_accepted),
    ("duplicate_user_agent_not_added", duplicate_user_agent_not_added),
    ("request_header_order_preserved", header_order_preserved),
    ("multipart_duplicate_field_names_preserved", multipart_duplicate_fields),
    ("multipart_empty_filename_emitted", multipart_empty_filename),
    ("multipart_html5_filename_formatting", multipart_html5_filename_formatting),
    ("multipart_control_chars_not_percent_encoded", multipart_control_chars_not_percent_encoded),
    ("multipart_explicit_content_type_sent", multipart_explicit_content_type),
    ("multipart_plain_fields_have_no_default_content_type", multipart_plain_field_no_default_content_type),
    ("response_body_lines_streamed", response_lines_streamed),
    ("chunked_head_response_without_body_does_not_hang", chunked_head_no_hang),
]


MAPPING = {
    "0.3:same_origin_sequential_requests_reuse_one_connection": "connection_reuse",
    "1.2:same_origin_requests_reuse_one_connection": "connection_reuse",
    "0.3:get_query_fields_are_sent_as_url_parameters": "query_params",
    "0.3:post_form_fields_are_sent_as_request_parameters": "post_form",
    "0.3:arbitrary_http_method_is_sent_unchanged": "arbitrary_put_method",
    "0.3:multipart_file_post_preserves_file_name_and_size": "multipart_file_upload",
    "0.3:redirect_can_be_observed_without_following": "redirect_observable_without_following",
    "0.3:redirect_is_followed_by_default": "redirect_followed_by_default",
    "0.3:redirect_consumes_retry_budget": "redirect_consumes_retry_budget",
    "2.5.0:poolmanager_integer_retries_limits_redirects": "redirect_consumes_retry_budget",
    "2.6.0:poolmanager_integer_retries_limits_redirects": "redirect_consumes_retry_budget",
    "0.3:slow_response_exceeding_socket_timeout_fails": "read_timeout_error",
    "1.1:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.8.3:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.9:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "1.10:read_timeout_is_wrapped_as_timeout_error": "read_timeout_error",
    "2.0.0:connection_timeout_is_applied_before_reading_response": "read_timeout_error",
    "1.26.15:reused_connection_uses_new_socket_timeout": "reused_connection_uses_new_socket_timeout",
    "2.0.0:reused_connection_uses_new_socket_timeout": "reused_connection_uses_new_socket_timeout",
    "0.3:broken_connection_is_retried_until_success": "broken_connection_retried",
    "1.22:broken_connection_is_retried_until_success": "broken_connection_retried",
    "1.15:retry_raise_on_status_false_returns_error_response": "retry_raise_on_status_false_returns_error_response",
    "1.19:retry_after_header_is_respected_for_retry_statuses": "retry_after_header_is_respected_for_retry_statuses",
    "1.21:status_forcelist_retry_increments_retry_counter": "status_forcelist_retry_increments_retry_counter",
    "1.25.4:retry_after_can_be_explicitly_ignored": "retry_after_can_be_explicitly_ignored",
    "1.25.4:retry_after_setting_propagates_to_subsequent_retries": "retry_after_setting_propagates_to_subsequent_retries",
    "1.25.11:retry_after_http_date_uses_utc": "retry_after_http_date_uses_utc",
    "2.6.3:retry_after_header_is_capped_at_six_hours": "retry_after_header_is_capped_at_six_hours",
    "0.3:https_origin_request_succeeds": "https_basic",
    "2.0.0:tls_minimum_and_maximum_versions_configure_context": "tls_minimum_and_maximum_versions_configure_context",
    "2.0.0:tls_minimum_and_maximum_versions_configure_context_2": "tls_minimum_and_maximum_versions_configure_context",
    "1.18:certificate_ipv6_subject_alt_name_is_accepted": "certificate_ip_subject_alt_name_is_accepted",
    "1.24.2:certificate_ipv6_subject_alt_name_is_accepted": "certificate_ip_subject_alt_name_is_accepted",
    "1.26.7:ipv6_braces_are_stripped_for_certificate_matching": "ipv6_braces_are_stripped_for_certificate_matching",
    "2.0.3:assert_hostname_false_skips_hostname_verification": "hostname_verification_can_be_disabled",
    "1.9.1:only_fingerprint_verification_is_supported": "fingerprint_verification_is_supported",
    "1.24.1:custom_ciphers_parameter_is_applied_to_tls_context": "custom_cipher_suite_is_applied",
    "1.24:tls_sni_hostname_can_be_overridden": "tls_sni_hostname_can_be_overridden",
    "1.25:encrypted_client_key_without_password_raises_ssl_error": "encrypted_client_key_without_password_raises_ssl_error",
    "1.26.0:tls_alpn_http11_identifier_is_sent": "tls_alpn_http11_identifier_is_sent",
    "1.6:streaming_decompression_is_supported": "gzip_response_decoded",
    "1.10.1:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "1.13:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "2.1.0:read_chunked_handles_gzip_encoded_chunks": "gzip_response_decoded",
    "1.6:content_encoding_header_is_case_insensitive": "gzip_content_encoding_case_insensitive",
    "1.24:multiple_content_encodings_are_decoded_in_order": "multiple_content_encodings",
    "2.6.0:content_encoding_chain_is_limited_to_five": "content_encoding_chain_limit",
    "2.0.2:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.6.2:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.7.0:response_stream_continues_with_buffered_decompressed_data": "decompression_buffer_continues_after_partial_read",
    "2.7.0:response_stream_continues_with_buffered_decompressed_data_2": "decompression_buffer_continues_after_partial_read",
    "2.6.0:streaming_decompression_bomb_guard_limits_output": "streaming_decompression_bomb_guard_limits_output",
    "2.6.3:streaming_decompression_bomb_guard_limits_output": "streaming_decompression_bomb_guard_limits_output",
    "2.7.0:streaming_decompression_bomb_guard_limits_output": "streaming_decompression_bomb_guard_limits_output",
    "1.26.15:url_ipv6_zone_identifier_is_accepted": "url_ipv6_zone_identifier_accepted",
    "1.10.3:multiple_set_cookie_headers_are_preserved": "multiple_set_cookie_headers_preserved",
    "1.10.1:header_values_with_commas_are_preserved": "comma_header_value_preserved",
    "2.0.0:incomplete_response_body_raises_when_content_length_enforced": "incomplete_content_length_raises",
    "1.17:incomplete_response_body_raises_when_content_length_enforced": "incomplete_content_length_raises",
    "1.11:incomplete_response_read_is_wrapped_as_protocol_error": "incomplete_content_length_raises",
    "1.9:incomplete_response_read_is_wrapped_as_protocol_error": "incomplete_content_length_raises",
    "2.2.1:invalid_chunk_length_raises_protocol_error": "invalid_chunk_length_raises",
    "1.25.7:url_fragment_is_not_sent_in_request_target": "fragment_not_sent_in_request_target",
    "1.5:proxy_request_uri_strips_scheme_and_host": "request_target_is_origin_form",
    "1.25.6:tilde_in_url_path_is_not_percent_encoded": "tilde_path_not_percent_encoded",
    "1.25.7:empty_query_section_is_preserved": "empty_query_section_preserved",
    "1.19:user_supplied_host_header_is_preserved_for_chunked_upload": "user_supplied_host_header_preserved",
    "1.15:chunked_request_sets_transfer_encoding_header": "chunked_request_sets_transfer_encoding",
    "1.10.4:chunked_keep_alive_preserves_request_boundaries": "chunked_keep_alive_preserves_request_boundaries",
    "2.2.3:chunked_request_body_uses_utf8": "chunked_request_body_uses_utf8",
    "2.0.0:chunked_boundaries_are_lowercase": "chunked_boundaries_are_lowercase",
    "1.26.6:explicit_transfer_encoding_chunked_header_is_not_duplicated": "explicit_transfer_encoding_chunked_not_duplicated",
    "2.0.7:http_303_redirect_switches_method_to_get_and_strips_body": "http_303_redirect_switches_method_to_get",
    "1.26.18:http_303_redirect_switches_method_to_get_and_strips_body": "http_303_redirect_switches_method_to_get",
    "1.7:relative_redirect_location_is_followed": "relative_redirect_location_followed",
    "1.7:relative_redirect_location_is_followed_2": "relative_redirect_location_followed",
    "1.22:redirect_drain_releases_blocking_pool_connection": "redirect_body_is_released_before_following",
    "1.25.9:redirect_drain_releases_blocking_pool_connection": "redirect_body_is_released_before_following",
    "1.24.2:authorization_header_stripping_is_case_insensitive": "cross_host_redirect_strips_authorization",
    "2.0.6:cross_host_redirect_strips_cookie_header": "cross_host_redirect_strips_cookie",
    "1.26.17:cross_host_redirect_strips_cookie_header": "cross_host_redirect_strips_cookie",
    "2.2.2:cross_host_redirect_strips_proxy_authorization_header": "cross_host_redirect_strips_proxy_authorization",
    "1.26.19:cross_host_redirect_strips_proxy_authorization_header": "cross_host_redirect_strips_proxy_authorization",
    "2.0.0:remove_headers_on_redirect_does_not_mutate_input_headers": "redirect_header_input_not_mutated",
    "1.25.9:method_rejects_control_characters": "method_rejects_control_characters",
    "1.9:url_empty_host_is_rejected": "url_empty_host_rejected",
    "1.17:url_scheme_and_host_are_normalized_lowercase": "url_scheme_and_host_normalized_lowercase",
    "1.20:url_scheme_and_host_are_normalized_lowercase": "url_scheme_and_host_normalized_lowercase",
    "1.8:same_host_accepts_default_port_equivalence": "url_default_port_equivalence",
    "1.26.13:url_port_with_leading_zeroes_is_accepted": "url_port_with_leading_zeroes_accepted",
    "1.26.14:url_port_zero_is_preserved": "url_port_zero_preserved",
    "1.19:url_port_rejects_integerish_unicode": "url_port_rejects_unicode_digits",
    "1.7:url_ipv6_requires_brackets": "url_ipv6_requires_brackets",
    "1.25.4:url_path_query_fragment_invalid_chars_are_percent_encoded": "url_invalid_chars_percent_encoded",
    "1.25.2:url_path_query_fragment_invalid_chars_are_percent_encoded": "url_invalid_chars_percent_encoded",
    "1.25.4:url_auth_invalid_chars_are_percent_encoded": "url_auth_invalid_chars_percent_encoded",
    "2.0.0:url_authority_includes_userinfo_and_host": "url_authority_includes_userinfo_and_host",
    "2.0.0:json_request_sets_content_type_when_missing": "json_request_sets_content_type",
    "2.2.0:headers_input_is_not_mutated_by_json_request": "request_header_input_not_mutated",
    "2.2.1:non_proxy_headers_are_not_cast_to_headerdict": "request_header_input_not_mutated",
    "1.6:default_headers_are_sent": "default_headers_sent",
    "1.6:proxy_manager_adds_host_header_when_missing": "default_headers_sent",
    "1.12:new_connection_failure_raises_new_connection_error": "connection_refused_error",
    "1.7:https_proxy_to_https_target_is_supported": "https_request_through_http_connect_proxy_succeeds",
    "1.11:ipv6_proxy_host_is_parsed_correctly": "ipv6_proxy_host_is_parsed_correctly",
    "1.22:proxy_connect_ipv6_target_uses_brackets": "proxy_connect_ipv6_target_uses_brackets",
    "2.5.0:proxy_connect_ipv6_target_uses_brackets": "proxy_connect_ipv6_target_uses_brackets",
    "2.2.0:trailing_dot_hostname_through_proxy_connects": "trailing_dot_hostname_through_proxy_connects",
    "2.0.0:dns_failure_raises_name_resolution_error": "dns_failure_error",
    "1.11:http_header_dict_is_usable_as_request_headers": "headers_mapping_accepted",
    "1.11:pool_default_headers_apply_to_get_query_requests": "session_default_headers_apply_to_get_query",
    "1.24:message_content_type_header_is_accepted": "message_content_type_header_accepted",
    "1.26.1:bytes_user_agent_header_does_not_duplicate": "duplicate_user_agent_not_added",
    "1.15:request_response_header_order_is_preserved": "request_header_order_preserved",
    "1.3:multipart_list_of_tuples_preserves_duplicate_field_names": "multipart_duplicate_field_names_preserved",
    "1.19:multipart_file_empty_filename_is_emitted": "multipart_empty_filename_emitted",
    "1.25:multipart_html5_header_encoder_is_default": "multipart_html5_filename_formatting",
    "2.0.0:multipart_header_control_characters_are_not_percent_encoded": "multipart_control_chars_not_percent_encoded",
    "1.6:multipart_file_explicit_content_type_is_sent": "multipart_explicit_content_type_sent",
    "1.6:multipart_plain_fields_do_not_default_to_text_plain": "multipart_plain_fields_have_no_default_content_type",
    "1.7:response_iter_yields_body_lines_efficiently": "response_body_lines_streamed",
    "1.25:response_iter_yields_body_lines_efficiently": "response_body_lines_streamed",
    "1.10.4:chunked_head_response_without_body_does_not_hang": "chunked_head_response_without_body_does_not_hang",
    "1.23:chunked_head_response_releases_connection": "chunked_head_response_without_body_does_not_hang",
}


def main() -> int:
    raw_tests = [run_test(name, fn) for name, fn in TESTS]
    tests = {row["name"]: row for row in raw_tests}
    source = json.loads(SOURCE.read_text())
    survivors = [r for r in source["results"] if r["survived_latest"]]
    rows = []
    for src in survivors:
        key = f"{src['source_version']}:{src['contract']}"
        row = {
            "key": key,
            "source_version": src["source_version"],
            "contract": src["contract"],
            "capability": src.get("capability", ""),
            "urllib3_final_survived": True,
        }
        test_name = MAPPING.get(key)
        if test_name:
            test = tests[test_name]
            row.update({"requests_status": "passed" if test["passed"] else "failed", "requests_test": test_name, "error": test["error"]})
        else:
            row.update({
                "requests_status": "failed_absent_or_unmapped",
                "requests_test": "",
                "error": "aggressive mode: no executed Requests equivalent proved this urllib3 contract survives",
            })
        rows.append(row)
    passed = sum(1 for r in rows if r["requests_status"] == "passed")
    failed = len(rows) - passed
    payload = {
        "source_project": "urllib3",
        "source_baseline": "contracts/urllib3/final_survival_urllib3_2.7.0.json",
        "target_project": "requests",
        "target_latest_version": requests.__version__,
        "target_latest_source": "https://pypi.org/pypi/requests/json",
        "mode": "aggressive_no_not_applicable",
        "rule": "A urllib3 final survivor counts as surviving Requests only when a Requests adapter test passed. Unmapped or absent equivalents count as not surviving.",
        "total_urllib3_final_survivors": len(rows),
        "requests_survived_aggressive": passed,
        "requests_failed_aggressive": failed,
        "adapter_tests": {
            "total": len(raw_tests),
            "passed": sum(1 for t in raw_tests if t["passed"]),
            "failed": sum(1 for t in raw_tests if not t["passed"]),
        },
        "raw_runner": {"requests_version": requests.__version__, "tests": raw_tests},
        "results": rows,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"requests_{requests.__version__}_survival_from_urllib3_final_aggressive.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    lines = [
        f"# Requests {requests.__version__} aggressive survival from urllib3 final contracts",
        "",
        "- rule: unmapped/absent Requests equivalents count as failed, not not_applicable",
        f"- total_urllib3_final_survivors: {len(rows)}",
        f"- requests_survived_aggressive: {passed}",
        f"- requests_failed_aggressive: {failed}",
        f"- adapter_tests: {payload['adapter_tests']['total']} total, {payload['adapter_tests']['passed']} passed, {payload['adapter_tests']['failed']} failed",
        "",
        "## Adapter Test Failures",
        "",
        "| test | error |",
        "|---|---|",
    ]
    for test in raw_tests:
        if not test["passed"]:
            escaped_error = test["error"].replace("|", "\\|")
            lines.append(f"| `{test['name']}` | {escaped_error} |")
    lines += ["", "## Survived", "", "| source | contract | capability | requests_test |", "|---:|---|---|---|"]
    for row in rows:
        if row["requests_status"] == "passed":
            lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | `{row['requests_test']}` |")
    lines += ["", "## Failed", "", "| source | contract | capability | status | requests_test | error |", "|---:|---|---|---|---|---|"]
    for row in rows:
        if row["requests_status"] != "passed":
            err = row["error"].replace("|", "\\|")
            if len(err) > 160:
                err = err[:157] + "..."
            lines.append(f"| {row['source_version']} | `{row['contract']}` | `{row['capability']}` | `{row['requests_status']}` | `{row['requests_test']}` | {err} |")
    (OUT_DIR / f"requests_{requests.__version__}_survival_from_urllib3_final_aggressive.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({
        "target_latest_version": requests.__version__,
        "total": len(rows),
        "survived": passed,
        "failed": failed,
        "adapter_tests": payload["adapter_tests"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
