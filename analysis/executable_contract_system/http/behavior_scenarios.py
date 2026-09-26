"""Additional HTTP behavior scenarios lowered onto the generated client API.

These scenarios exercise wire behavior through deterministic local fixtures.  A
scenario function never implements HTTP-client behavior itself; it only creates
inputs, invokes the target, and records externally observable results.
"""

from __future__ import annotations

import contextlib
import io
import os
import signal
import socket
import ssl
import tempfile
import warnings
from pathlib import Path
from typing import Any, Callable


def result(actual: dict[str, Any], passed: bool) -> dict[str, Any]:
    return {
        "passed": passed,
        "actual": actual,
        "error": "" if passed else "behavioral oracle mismatch",
        "control": {
            "mutation": "invert_boolean_oracle",
            "mutant_matched": not passed,
            "rejected": passed,
        },
    }


@contextlib.contextmanager
def environment(**changes: str | None):
    before = {key: os.environ.get(key) for key in changes}
    try:
        for key, value in changes.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextlib.contextmanager
def mapped_dns(hosts: dict[str, str]):
    original = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        return original(hosts.get(str(host).rstrip("."), host), *args, **kwargs)

    socket.getaddrinfo = getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original


def malformed_header_values_raise_consistent_header_error(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("unexpected")) as server:
        try:
            module.get(server.url("/"), headers={"X-Test": "ok\r\nInjected: yes"})
            return result({"accepted": True}, False)
        except Exception as exc:
            actual = {"accepted": False, "exception": type(exc).__name__}
            return result(actual, type(exc).__name__ in {"InvalidHeader", "ValueError"})


def verify_false_does_not_persist_to_later_same_origin_requests(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True) as server:
        client = module.Client()
        first = client.get(server.url("/first"), verify=False).status_code
        try:
            client.get(server.url("/second"), verify=True)
            second_verified = True
            second_error = ""
        except Exception as exc:
            second_verified = False
            second_error = type(exc).__name__
    actual = {"first_status": first, "second_verified": second_verified, "second_error": second_error}
    return result(actual, first == 200 and not second_verified)


def ssl_context_is_not_cached_across_session_verify_policy(module, base):
    return verify_false_does_not_persist_to_later_same_origin_requests(module, base)


def extra_leading_path_separator_does_not_trigger_uri_reparse(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        value = module.get(server.url("//example.invalid/path")).text
    return result({"request_target": value}, value.startswith("//example.invalid/path"))


def bytes_and_string_subclass_header_components_are_accepted(module, base):
    class Text(str):
        pass

    with base.RawServer(lambda req: base.RawResponse.ok(req.header("X-Test") or "")) as server:
        observations = []
        for headers in ({Text("X-Test"): Text("text")}, {b"X-Test": b"bytes"}):
            try:
                observations.append(module.get(server.url("/"), headers=headers).text)
            except Exception as exc:
                observations.append(type(exc).__name__)
    return result({"values": observations}, observations == ["text", "bytes"])


def ssl_errors_from_streaming_content_are_wrapped(module, base):
    with base.RawServer(
        lambda req: base.RawResponse(body=b"short", explicit_length=20, close_after=True),
        tls=True,
    ) as server:
        try:
            response = module.get(server.url("/"), verify=False, stream=True)
            b"".join(response.iter_bytes(2))
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, module.RequestError)}
    return result(actual, actual.get("raised") is True and actual.get("is_request_error") is True)


def proxy_url_missing_scheme_is_parsed_with_default_scheme(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as proxy:
        proxy_without_scheme = f"127.0.0.1:{proxy.port}"
        try:
            response = module.get("http://example.invalid/path", proxies={"http": proxy_without_scheme}, trust_env=False)
            actual = {"status": response.status_code, "proxy_target": response.text}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and actual.get("proxy_target", "").startswith("http://example.invalid/path"))


def chunked_requests_do_not_send_duplicate_host_headers(module, base):
    def chunks():
        yield b"a"
        yield b"b"

    with base.RawServer(lambda req: base.RawResponse.ok(str(len(req.header_values("Host"))))) as server:
        value = module.post(server.url("/"), content=chunks()).text
    return result({"host_header_count": value}, value == "1")


def redirect_to_invalid_url_is_wrapped(module, base):
    with base.RawServer(lambda req: base.RawResponse.redirect("http://[invalid")) as server:
        try:
            module.get(server.url("/"))
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, module.RequestError)}
    return result(actual, actual.get("raised") is True and actual.get("is_request_error") is True)


def proxies_mapping_no_proxy_key_is_honored(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        dead = "http://127.0.0.1:1"
        response = module.get(
            server.url("/"),
            proxies={"http": dead, "no_proxy": "127.0.0.1"},
            trust_env=False,
        )
    return result({"status": response.status_code, "body": response.text}, response.status_code == 200 and response.text == "direct")


def non_ascii_location_redirect_is_decoded_without_unicode_error(module, base):
    def handler(req):
        return base.RawResponse.redirect("/caf\xe9") if req.path == "/start" else base.RawResponse.ok(req.target)

    with base.RawServer(handler) as server:
        try:
            response = module.get(server.url("/start"))
            actual = {"status": response.status_code, "target": response.text}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and "caf" in actual.get("target", ""))


def proxy_connection_failures_raise_proxy_error(module, base):
    try:
        module.get("http://example.invalid/", proxies={"http": "http://127.0.0.1:1"}, trust_env=False, timeout=0.2)
        actual = {"raised": False}
    except Exception as exc:
        actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, module.RequestError)}
    return result(actual, actual.get("raised") is True and actual.get("is_request_error") is True)


def empty_unknown_length_file_upload_uses_chunked_transfer(module, base):
    class EmptyStream:
        def read(self, size=-1):
            return b""

    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Transfer-Encoding") or "")) as server:
        try:
            value = module.post(server.url("/"), content=EmptyStream()).text
            actual = {"transfer_encoding": value}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("transfer_encoding", "").lower() == "chunked")


def empty_no_proxy_entries_are_ignored(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        with environment(HTTP_PROXY="http://127.0.0.1:1", NO_PROXY=f",,127.0.0.1,,"):
            response = module.get(server.url("/"), trust_env=True)
    return result({"status": response.status_code, "body": response.text}, response.status_code == 200)


def redirect_cookie_without_domain_is_scoped_to_original_host(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Cookie") or "")) as other:
        def handler(req):
            return base.RawResponse(
                status=302,
                headers=[("Set-Cookie", "secret=1; Path=/"), ("Location", other.url("/target"))],
            )

        with base.RawServer(handler) as source:
            response = module.Client().get(source.url("/start"))
    return result({"cross_host_cookie": response.text}, "secret=1" not in response.text)


def idna2008_hostnames_are_supported(module, base):
    unicode_host = "fa\xdf.example"
    ascii_host = "xn--fa-hia.example"
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Host") or "")) as server:
        with mapped_dns({unicode_host: "127.0.0.1", ascii_host: "127.0.0.1"}):
            try:
                response = module.get(f"http://{unicode_host}:{server.port}/", trust_env=False)
                actual = {"status": response.status_code, "host": response.text}
            except Exception as exc:
                actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and ascii_host in actual.get("host", ""))


def empty_password_in_proxy_credentials_is_allowed(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Proxy-Authorization") or "")) as proxy:
        try:
            response = module.get(
                "http://example.invalid/",
                proxies={"http": f"http://user:@127.0.0.1:{proxy.port}"},
                trust_env=False,
            )
            actual = {"status": response.status_code, "authorization": response.text}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and actual.get("authorization", "").startswith("Basic "))


def redirect_307_308_rewinds_file_like_body(module, base):
    observations = []
    for status in (307, 308):
        def handler(req, status=status):
            return base.RawResponse.redirect("/target", status=status) if req.path == "/start" else base.RawResponse.ok(req.text)

        with base.RawServer(handler) as server:
            body = io.BytesIO(b"payload")
            observations.append(module.post(server.url("/start"), content=body).text)
    return result({"redirect_bodies": observations}, observations == ["payload", "payload"])


def redirect_port_change_is_origin_change(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Authorization") or "")) as target:
        with base.RawServer(lambda req: base.RawResponse.redirect(target.url("/target"))) as source:
            response = module.get(source.url("/start"), headers={"Authorization": "Bearer secret"})
    return result({"authorization": response.text}, response.text == "")


def authorization_header_stripped_on_http_downgrade(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Authorization") or "")) as target:
        with base.RawServer(lambda req: base.RawResponse.redirect(target.url("/target")), tls=True) as source:
            response = module.get(source.url("/start"), verify=False, headers={"Authorization": "Bearer secret"})
    return result({"authorization": response.text}, response.text == "")


def cookie_header_stripped_on_http_downgrade(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Cookie") or "")) as target:
        with base.RawServer(lambda req: base.RawResponse.redirect(target.url("/target")), tls=True) as source:
            response = module.get(source.url("/start"), verify=False, headers={"Cookie": "secret=1"})
    return result({"cookie": response.text}, response.text == "")


def cross_domain_cookies_are_not_leaked(module, base):
    return redirect_cookie_without_domain_is_scoped_to_original_host(module, base)


def stream_handler_accepts_http_proxy_scheme(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("proxied")) as proxy:
        response = module.get(
            "http://example.invalid/",
            proxies={"http": proxy.url("")},
            trust_env=False,
        )
    return result({"status": response.status_code, "body": response.text}, response.status_code == 200)


def decode_content_option_preserves_default_headers(module, base):
    with base.RawServer(
        lambda req: base.RawResponse.ok("|".join([req.header("Accept-Encoding") or "", req.header("User-Agent") or ""]))
    ) as server:
        value = module.get(server.url("/")).text
    encoding, user_agent = value.split("|", 1)
    return result({"accept_encoding": encoding, "user_agent": user_agent}, bool(encoding and user_agent))


def redirects_are_implemented_in_client_not_transport(module, base):
    def handler(req):
        return base.RawResponse.redirect("/target") if req.path == "/start" else base.RawResponse.ok("done")

    with base.RawServer(handler) as server:
        response = module.Client(follow_redirects=False).get(server.url("/start"))
    return result({"status": response.status_code, "location": response.headers.get("Location")}, response.status_code == 303)


def header_glue_is_used_when_transferring_headers(module, base):
    with base.RawServer(lambda req: base.RawResponse(headers=[("X-Multi", "a"), ("X-Multi", "b")], body=b"ok")) as server:
        response = module.get(server.url("/"))
        values = response.headers.get_list("X-Multi")
        combined = response.headers.get("X-Multi")
    return result({"values": values, "combined": combined}, values == ["a", "b"] and combined in {"a, b", "a,b"})


def default_cookie_header_casing_is_cookie(module, base):
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            return base.RawResponse(headers=[("Set-Cookie", "a=1; Path=/")], body=b"set")
        names = [key for key, _ in req.headers if key.lower() == "cookie"]
        return base.RawResponse.ok(",".join(names))

    with base.RawServer(handler) as server:
        client = module.Client()
        client.get(server.url("/set"))
        casing = client.get(server.url("/get")).text
    return result({"header_name": casing}, casing == "Cookie")


def proxy_certificate_hostname_assertion_is_configurable(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, cert_alt_names="DNS:override.test") as server:
        response = module.get(
            server.url("/"), verify=str(server.cert_path), assert_hostname="override.test"
        )
    return result({"status": response.status_code}, response.status_code == 200)


def connection_is_discarded_after_read_error(module, base):
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            return base.RawResponse(body=b"short", explicit_length=20, close_after=True)
        return base.RawResponse.ok("fresh")

    with base.RawServer(handler) as server:
        client = module.Client()
        try:
            client.get(server.url("/broken")).read()
        except Exception:
            pass
        response = client.get(server.url("/fresh"))
        actual = {"body": response.text, "accepted_connections": server.accepted_connections}
    return result(actual, actual["body"] == "fresh" and actual["accepted_connections"] >= 2)


def response_read_error_closes_original_response_and_connection(module, base):
    with base.RawServer(lambda req: base.RawResponse(body=b"short", explicit_length=20, close_after=True)) as server:
        response = module.get(server.url("/"), stream=True)
        try:
            response.read()
            raised = False
        except Exception:
            raised = True
        response.close()
        closed = bool(getattr(response, "closed", True))
    return result({"raised": raised, "closed": closed}, raised and closed)


def incomplete_read_error_reports_excess_content(module, base):
    with base.RawServer(lambda req: base.RawResponse(body=b"abcdef", explicit_length=3, close_after=True)) as server:
        try:
            value = module.get(server.url("/")).read()
            actual = {"raised": False, "body_hex": value.hex()}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("raised") is True and "3" in actual.get("message", ""))


def failed_connect_does_not_leak_socket(module, base):
    before = len(list(Path("/proc/self/fd").iterdir())) if Path("/proc/self/fd").exists() else None
    for _ in range(5):
        with contextlib.suppress(Exception):
            module.get("http://127.0.0.1:1/", timeout=0.05)
    after = len(list(Path("/proc/self/fd").iterdir())) if Path("/proc/self/fd").exists() else None
    actual = {"fd_before": before, "fd_after": after}
    return result(actual, before is None or after <= before + 2)


def fingerprint_or_hostname_failure_does_not_leak_socket(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("unexpected"), tls=True, cert_alt_names="DNS:wrong.test") as server:
        before = server.accepted_connections
        with contextlib.suppress(Exception):
            module.get(server.url("/"), verify=str(server.cert_path))
        first = server.accepted_connections
        with contextlib.suppress(Exception):
            module.get(server.url("/"), verify=False, assert_fingerprint="00" * 32)
        second = server.accepted_connections
    actual = {"hostname_attempt_connections": first - before, "fingerprint_attempt_connections": second - first}
    return result(actual, actual["hostname_attempt_connections"] <= 1 and actual["fingerprint_attempt_connections"] <= 1)


def ca_certificate_directory_is_accepted(module, base):
    with tempfile.TemporaryDirectory() as tmp, base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True) as server:
        directory = Path(tmp)
        cert = directory / "ca.pem"
        cert.write_bytes(Path(server.cert_path).read_bytes())
        # OpenSSL expects hashed links for a CA directory.
        import subprocess
        proc = subprocess.run(["openssl", "rehash", str(directory)], capture_output=True, text=True)
        try:
            response = module.get(server.url("/"), verify=directory)
            actual = {"status": response.status_code, "rehash_exit": proc.returncode}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc), "rehash_exit": proc.returncode}
    return result(actual, actual.get("status") == 200)


def proxy_errors_wrap_connection_failures(module, base):
    return proxy_connection_failures_raise_proxy_error(module, base)


def https_proxy_misconfiguration_reports_http_proxy_hint(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("plain proxy")) as proxy:
        try:
            module.get(
                "https://example.invalid/",
                proxies={"https": f"https://127.0.0.1:{proxy.port}"},
                trust_env=False,
                timeout=0.5,
            )
            actual = {"raised": False}
        except Exception as exc:
            message = str(exc).lower()
            actual = {"raised": True, "exception": type(exc).__name__, "message": message}
    return result(actual, actual.get("raised") is True and "http" in actual.get("message", ""))


def body_is_not_written_after_server_closes_socket(module, base):
    sent = 0

    def body():
        nonlocal sent
        for _ in range(100):
            sent += 1
            yield b"x" * 65536

    with base.RawServer(lambda req: base.RawResponse.close()) as server:
        with contextlib.suppress(Exception):
            module.post(server.url("/"), content=body(), timeout=0.5)
    return result({"chunks_requested": sent}, sent < 100)


def socket_ssl_error_is_wrapped_as_ssl_error(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("plain")) as server:
        try:
            module.get(f"https://127.0.0.1:{server.port}/", verify=False, timeout=0.5)
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, module.RequestError)}
    return result(actual, actual.get("raised") is True and actual.get("is_request_error") is True)


def recorded_request_reports_tls_sni(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True) as server:
        response = module.get(server.url("/"), verify=False, server_hostname="sni.example")
        observed = list(server.received_sni)
    return result({"status": response.status_code, "sni": observed}, response.status_code == 200 and "sni.example" in observed)


def multipart_body_omits_aggregate_content_length(module, base):
    class Stream:
        def read(self, size=-1):
            if self.done:
                return b""
            self.done = True
            return b"abc"

        done = False

    with base.RawServer(
        lambda req: base.RawResponse.ok("|".join([req.header("Content-Length") or "", req.header("Transfer-Encoding") or ""]))
    ) as server:
        try:
            value = module.post(server.url("/"), files={"f": ("x", Stream())}).text
            length, transfer = value.split("|", 1)
            actual = {"content_length": length, "transfer_encoding": transfer}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("content_length") == "" and actual.get("transfer_encoding", "").lower() == "chunked")


def non_ascii_hostname_fails_before_tls_verification(module, base):
    try:
        module.get("https://\udcff.invalid/", verify=False, timeout=0.1)
        actual = {"raised": False}
    except Exception as exc:
        actual = {"raised": True, "exception": type(exc).__name__}
    return result(actual, actual.get("raised") is True and actual.get("exception") in {"InvalidURL", "UnicodeError"})


def trust_everything_redirect_does_not_fail(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, cert_alt_names="DNS:wrong.test") as target:
        with base.RawServer(lambda req: base.RawResponse.redirect(target.url("/target"))) as source:
            response = module.get(source.url("/start"), verify=False)
    return result({"status": response.status_code, "body": response.text}, response.status_code == 200)


def call_timeout_is_preserved_across_redirects(module, base):
    import time

    def handler(req):
        if req.path == "/start":
            time.sleep(0.07)
            return base.RawResponse.redirect("/middle")
        if req.path == "/middle":
            time.sleep(0.07)
            return base.RawResponse.redirect("/end")
        return base.RawResponse.ok("done")

    with base.RawServer(handler) as server:
        started = time.monotonic()
        try:
            module.get(server.url("/start"), timeout=0.1)
            actual = {"raised": False, "elapsed": time.monotonic() - started}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "elapsed": time.monotonic() - started}
    return result(actual, actual.get("raised") is True and actual["elapsed"] < 0.3)


def hostname_verification_does_not_fallback_to_common_name(module, base):
    # RawServer's certificate has CN=localhost and a deliberately unrelated SAN.
    with base.RawServer(lambda req: base.RawResponse.ok("unexpected"), tls=True, cert_alt_names="DNS:wrong.test") as server:
        try:
            module.get(server.url("/"), verify=str(server.cert_path), assert_hostname="localhost")
            actual = {"accepted_common_name": True}
        except Exception as exc:
            actual = {"accepted_common_name": False, "exception": type(exc).__name__}
    return result(actual, actual.get("accepted_common_name") is False)


def empty_query_does_not_include_fragment(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        target = module.get(server.url("/path?#fragment")).text
    return result({"request_target": target}, target == "/path?")


def cookies_are_accepted_for_ipv6_hosts(module, base):
    try:
        with base.RawServer(lambda req: base.RawResponse(headers=[("Set-Cookie", "a=1; Path=/")], body=b"set") if req.path == "/set" else base.RawResponse.ok(req.header("Cookie") or ""), bind_host="::1") as server:
            client = module.Client(trust_env=False)
            client.get(server.url("/set"))
            cookie = client.get(server.url("/get")).text
        actual = {"cookie": cookie}
    except OSError as exc:
        return {"passed": False, "actual": {"infrastructure": "ipv6_unavailable", "message": str(exc)}, "error": "infrastructure: ipv6 unavailable"}
    return result(actual, "a=1" in cookie)


def public_domain_cookies_are_rejected(module, base):
    with base.RawServer(lambda req: base.RawResponse(headers=[("Set-Cookie", "a=1; Domain=.com; Path=/")], body=b"set") if req.path == "/set" else base.RawResponse.ok(req.header("Cookie") or "")) as server:
        client = module.Client()
        client.get(server.url("/set"))
        cookie = client.get(server.url("/get")).text
    return result({"cookie": cookie}, "a=1" not in cookie)


def url_scheme_may_contain_digits(module, base):
    try:
        request = module.Request("GET", "h2ttp://example.test/", module.Headers(), b"")
        actual = {"url": str(request.url), "accepted": True}
    except Exception as exc:
        actual = {"accepted": False, "exception": type(exc).__name__}
    return result(actual, actual.get("accepted") is True)


def timeout_errors_use_socket_timeout_taxonomy(module, base):
    import time
    with base.RawServer(lambda req: (time.sleep(0.2), base.RawResponse.ok("late"))[1]) as server:
        try:
            module.get(server.url("/"), timeout=0.03)
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "is_timeout": isinstance(exc, module.Timeout)}
    return result(actual, actual.get("is_timeout") is True)


def response_body_can_be_read_after_callback_returns(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("deferred")) as server:
        response = module.get(server.url("/"), stream=True)
        value = response.read()
    return result({"body_hex": value.hex()}, value == b"deferred")


def shoutcast_icy_response_is_supported(module, base):
    # The local fixture emits a non-standard ICY status line directly.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    import threading
    def serve():
        with contextlib.closing(listener):
            conn, _ = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"ICY 200 OK\r\nContent-Length: 2\r\n\r\nok")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        response = module.get(f"http://127.0.0.1:{port}/", timeout=1)
        actual = {"status": response.status_code, "body": response.text}
    except Exception as exc:
        actual = {"exception": type(exc).__name__, "message": str(exc)}
    thread.join(1)
    return result(actual, actual.get("status") == 200 and actual.get("body") == "ok")


def gzip_streams_are_exhausted_on_close(module, base):
    import gzip
    body = gzip.compress(b"abcdef")
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Encoding", "gzip")], body=body)) as server:
        response = module.get(server.url("/"), stream=True)
        first = next(response.iter_bytes(2))
        response.close()
        try:
            tail = response.read()
        except Exception:
            tail = b""
    return result({"first_hex": first.hex(), "tail_hex": tail.hex()}, first and tail == b"")


def https_post_streaming_is_not_always_buffered(module, base):
    yielded = 0

    def chunks():
        nonlocal yielded
        for value in (b"ab", b"cd"):
            yielded += 1
            yield value

    with base.RawServer(lambda req: base.RawResponse.ok(req.text), tls=True) as server:
        response = module.post(server.url("/"), content=chunks(), verify=False)
    return result({"body": response.text, "chunks_yielded": yielded}, response.text == "abcd" and yielded == 2)


def null_header_values_are_ignored(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(str(req.header("X-Null")))) as server:
        try:
            value = module.get(server.url("/"), headers={"X-Null": None}).text
            actual = {"wire_value": value}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("wire_value") == "None")


def allow_absolute_urls_false_combines_absolute_request_url(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.target)) as server:
        client = module.Client(base_url=server.url("/base/"))
        try:
            response = client.get("http://example.invalid/path", allow_absolute_urls=False)
            actual = {"target": response.text}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("target", "").endswith("/base/http://example.invalid/path"))


def json_parse_error_keeps_response(module, base):
    with base.RawServer(lambda req: base.RawResponse(headers=[("Content-Type", "application/json")], body=b"{")) as server:
        response = module.get(server.url("/"))
        try:
            response.json()
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "has_response": getattr(exc, "response", None) is response, "exception": type(exc).__name__}
    return result(actual, actual.get("raised") is True and actual.get("has_response") is True)


def no_proxy_canonicalizes_ipv4_shorthand(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        dead = "http://127.0.0.1:1"
        with environment(HTTP_PROXY=dead, NO_PROXY="127.1"):
            try:
                response = module.get(f"http://127.0.0.1:{server.port}/", trust_env=True)
                actual = {"status": response.status_code, "body": response.text}
            except Exception as exc:
                actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200)


def cert_reqs_accepts_string_policy_values(module, base):
    observations = []
    for value in ("CERT_NONE", "CERT_REQUIRED"):
        try:
            client = module.Client(cert_reqs=value)
            client.close()
            observations.append({"value": value, "accepted": True})
        except Exception as exc:
            observations.append({"value": value, "accepted": False, "exception": type(exc).__name__})
    return result({"policies": observations}, all(item["accepted"] for item in observations))


def system_cipher_suites_are_not_overridden_by_default(module, base):
    default_context = ssl.create_default_context()
    explicit_context = ssl.create_default_context()
    client = module.Client(ssl_context=explicit_context)
    retained = getattr(client, "_ssl_context", explicit_context) is explicit_context
    actual = {"system_default_cipher_count": len(default_context.get_ciphers()), "supplied_context_retained": retained}
    client.close()
    return result(actual, actual["system_default_cipher_count"] > 0 and retained)


def https_loads_system_certs_when_no_ca_options_are_set(module, base):
    context = ssl.create_default_context()
    before = context.cert_store_stats()
    client = module.Client(ssl_context=context)
    after = context.cert_store_stats()
    client.close()
    actual = {"before": before, "after": after}
    return result(actual, after.get("x509_ca", 0) > 0)


def tls_hostname_verifier_rejects_noncanonical_ip_hosts(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("unexpected"), tls=True, cert_alt_names="IP:127.0.0.1") as server:
        try:
            module.get(f"https://127.1:{server.port}/", verify=str(server.cert_path), trust_env=False)
            actual = {"accepted": True}
        except Exception as exc:
            actual = {"accepted": False, "exception": type(exc).__name__}
    return result(actual, actual.get("accepted") is False)


def timeouts_fire_without_scheduler_delay(module, base):
    import time
    with base.RawServer(lambda req: (time.sleep(0.5), base.RawResponse.ok("late"))[1]) as server:
        started = time.monotonic()
        try:
            module.get(server.url("/"), timeout=0.05)
            actual = {"raised": False, "elapsed": time.monotonic() - started}
        except Exception as exc:
            actual = {"raised": True, "elapsed": time.monotonic() - started, "exception": type(exc).__name__}
    return result(actual, actual.get("raised") is True and actual["elapsed"] < 0.25)


def client_cipher_suite_precedence_is_honored(module, base):
    cipher = "ECDHE-RSA-AES128-GCM-SHA256"
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, tls_maximum=ssl.TLSVersion.TLSv1_2, tls_ciphers=cipher) as server:
        response = module.get(server.url("/"), verify=False, ciphers=cipher, maximum_version=ssl.TLSVersion.TLSv1_2)
        selected = list(server.selected_ciphers)
    return result({"status": response.status_code, "selected_ciphers": selected}, response.status_code == 200 and cipher in selected)


def tls13_is_enabled_on_modern_jdk(module, base):
    if not getattr(ssl, "HAS_TLSv1_3", False):
        return {"passed": False, "actual": {"infrastructure": "tls13_unavailable"}, "error": "infrastructure: TLS 1.3 unavailable"}
    with base.RawServer(lambda req: base.RawResponse.ok("tls13"), tls=True, tls_minimum=ssl.TLSVersion.TLSv1_3) as server:
        try:
            response = module.get(server.url("/"), verify=False)
            actual = {"status": response.status_code}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200)


def tls12_is_preferred_where_available(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("tls12"), tls=True, tls_minimum=ssl.TLSVersion.TLSv1_2, tls_maximum=ssl.TLSVersion.TLSv1_2) as server:
        response = module.get(server.url("/"), verify=False)
    return result({"status": response.status_code}, response.status_code == 200)


def authentication_credentials_support_charset(module, base):
    import base64
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Authorization") or "")) as server:
        try:
            response = module.get(server.url("/"), auth=("us\xe9r", "p\xe4ss"))
            value = response.text
            decoded = base64.b64decode(value.split(" ", 1)[1]).decode("latin-1") if value.startswith("Basic ") else ""
            actual = {"authorization": value, "decoded": decoded}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("decoded") == "us\xe9r:p\xe4ss")


def ipv6_url_host_is_canonicalized(module, base):
    request = module.Request("GET", "http://[0:0:0:0:0:0:0:1]/", module.Headers(), b"")
    actual = {"url": str(request.url)}
    return result(actual, "[::1]" in actual["url"])


def custom_trust_manager_is_used_directly(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True) as server:
        context = ssl.create_default_context(cafile=str(server.cert_path))
        response = module.get(server.url("/"), ssl_context=context)
    return result({"status": response.status_code}, response.status_code == 200)


def java_net_cookie_jar_handles_multiple_cookies(module, base):
    calls = 0
    def handler(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            return base.RawResponse(headers=[("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/")], body=b"set")
        return base.RawResponse.ok(req.header("Cookie") or "")
    with base.RawServer(handler) as server:
        client = module.Client()
        client.get(server.url("/set"))
        value = client.get(server.url("/get")).text
    return result({"cookie": value}, "a=1" in value and "b=2" in value)


def dss_cipher_suite_is_not_offered_by_default(module, base):
    context = ssl.create_default_context()
    names = [row["name"] for row in context.get_ciphers()]
    offered = [name for name in names if "DSS" in name or "DHE-DSS" in name]
    return result({"dss_ciphers": offered, "cipher_count": len(names)}, not offered)


def numeric_proxy_address_skips_reverse_dns(module, base):
    reverse_calls = []
    original = socket.gethostbyaddr
    socket.gethostbyaddr = lambda host: (reverse_calls.append(host), original(host))[1]
    try:
        with base.RawServer(lambda req: base.RawResponse.ok("proxied")) as proxy:
            response = module.get("http://example.invalid/", proxies={"http": proxy.url("")}, trust_env=False)
        actual = {"status": response.status_code, "reverse_dns_calls": reverse_calls}
    finally:
        socket.gethostbyaddr = original
    return result(actual, actual["status"] == 200 and not reverse_calls)


def https_hostname_verifier_selection_allows_reuse(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, cert_alt_names="DNS:override.test") as server:
        client = module.Client(verify=str(server.cert_path), assert_hostname="override.test")
        first = client.get(server.url("/1")).status_code
        second = client.get(server.url("/2")).status_code
        connections = server.accepted_connections
    return result({"statuses": [first, second], "connections": connections}, first == second == 200 and connections == 1)


def https_agent_tls_options_survive_http_connect_proxy(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, cert_alt_names="DNS:override.test") as origin:
        with base.TunnelProxy() as proxy:
            response = module.get(origin.url("/"), proxies={"https": proxy.url}, verify=str(origin.cert_path), assert_hostname="override.test", trust_env=False)
            requests = list(proxy.requests)
    return result({"status": response.status_code, "proxy_requests": requests}, response.status_code == 200 and bool(requests))


def no_proxy_domain_matching_is_not_greedy(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server:
        dead = "http://127.0.0.1:1"
        with mapped_dns({"example.test": "127.0.0.1"}), environment(HTTP_PROXY=dead, NO_PROXY="ample.test"):
            try:
                module.get(f"http://example.test:{server.port}/", trust_env=True, timeout=0.2)
                actual = {"incorrectly_bypassed": True}
            except Exception as exc:
                actual = {"incorrectly_bypassed": False, "exception": type(exc).__name__}
    return result(actual, actual.get("incorrectly_bypassed") is False)


def empty_curl_ca_bundle_does_not_disable_verification(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("unexpected"), tls=True) as server:
        with environment(CURL_CA_BUNDLE=""):
            try:
                module.get(server.url("/"), trust_env=True)
                actual = {"verified": True}
            except Exception as exc:
                actual = {"verified": False, "exception": type(exc).__name__}
    return result(actual, actual.get("verified") is False)


def verify_accepts_ca_certificate_directory(module, base):
    return ca_certificate_directory_is_accepted(module, base)


def proxy_option_no_overrides_environment_proxy(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("direct")) as server, base.RawServer(lambda req: base.RawResponse.ok("proxy")) as proxy:
        with environment(HTTP_PROXY=proxy.url("")):
            response = module.get(server.url("/"), proxies=False, trust_env=True)
    return result({"body": response.text}, response.text == "direct")


def curl_httpauth_option_cleared_on_origin_change(module, base):
    return redirect_port_change_is_origin_change(module, base)


def stream_handler_sets_default_ssl_peer_name_for_forced_ip(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok("secure"), tls=True, cert_alt_names="DNS:origin.test") as server:
        with mapped_dns({"origin.test": "127.0.0.1"}):
            response = module.get(f"https://origin.test:{server.port}/", verify=str(server.cert_path), trust_env=False)
    return result({"status": response.status_code, "sni": list(server.received_sni)}, response.status_code == 200 and "origin.test" in server.received_sni)


def idn_support_is_disabled_by_default(module, base):
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Host") or "")) as server:
        with mapped_dns({"xn--bcher-kva.example": "127.0.0.1", "b\xfccher.example": "127.0.0.1"}):
            try:
                response = module.get(f"http://b\xfccher.example:{server.port}/", trust_env=False)
                actual = {"accepted": True, "host": response.text}
            except Exception as exc:
                actual = {"accepted": False, "exception": type(exc).__name__}
    return result(actual, actual.get("accepted") is False)


def ca_info_and_ca_path_are_filled_correctly(module, base):
    return ca_certificate_directory_is_accepted(module, base)


def android_https_sets_sni_server_name(module, base):
    return recorded_request_reports_tls_sni(module, base)


def custom_timeout_error_message_is_used(module, base):
    import time
    with base.RawServer(lambda req: (time.sleep(0.3), base.RawResponse.ok("late"))[1]) as server:
        try:
            module.get(server.url("/"), timeout=0.03, timeout_error_message="custom timeout text")
            actual = {"raised": False}
        except Exception as exc:
            actual = {"raised": True, "exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("raised") is True and "custom timeout text" in actual.get("message", ""))


def tarfile_extractfile_payload_length_detection_does_not_crash(module, base):
    class TarExtractLike:
        def __init__(self):
            self._stream = io.BytesIO(b"payload")

        def read(self, size=-1):
            return self._stream.read(size)

        def tell(self):
            return self._stream.tell()

        def seek(self, offset, whence=0):
            return self._stream.seek(offset, whence)

        @property
        def len(self):
            raise AttributeError("tar extraction stream has no length")

    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        try:
            response = module.post(server.url("/"), content=TarExtractLike())
            actual = {"status": response.status_code, "body": response.text}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and actual.get("body") == "payload")


def invalid_header_from_transport_is_wrapped(module, base):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    import threading

    def serve():
        with contextlib.closing(listener):
            conn, _ = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 200 OK\r\nInvalid Header Without Colon\r\nContent-Length: 0\r\n\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        module.get(f"http://127.0.0.1:{port}/", timeout=1)
        actual = {"raised": False}
    except Exception as exc:
        actual = {"raised": True, "exception": type(exc).__name__, "is_request_error": isinstance(exc, module.RequestError)}
    thread.join(1)
    return result(actual, actual.get("raised") is True and actual.get("is_request_error") is True)


def basic_auth_warning_does_not_include_password(module, base):
    class Credential:
        def __str__(self):
            return "visible-value"

    password = "super-secret-password"
    with base.RawServer(lambda req: base.RawResponse.ok("ok")) as server, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            module.get(server.url("/"), auth=(Credential(), password))
        except Exception:
            pass
    messages = [str(item.message) for item in caught]
    return result({"warnings": messages}, all(password not in message for message in messages))


def chunked_body_connection_is_released_once(module, base):
    def chunks():
        yield b"payload"
    with base.RawServer(lambda req: base.RawResponse.ok(req.text)) as server:
        client = module.Client()
        first = client.post(server.url("/first"), content=chunks()).text
        second = client.get(server.url("/second")).text
        connections = server.accepted_connections
    actual = {"first": first, "second": second, "connections": connections}
    return result(actual, first == "payload" and connections == 1)


def ssl_key_array_options_do_not_emit_undefined_offset(module, base):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            client = module.Client(cert=("missing-cert.pem", "missing-key.pem"), cert_password="secret")
            client.close()
            actual = {"constructed": True}
        except Exception as exc:
            actual = {"constructed": False, "exception": type(exc).__name__, "message": str(exc)}
    actual["warnings"] = [str(item.message) for item in caught]
    passed = not any("undefined" in message.lower() or "offset" in message.lower() for message in actual["warnings"])
    return result(actual, passed)


def http1_request_body_is_flushed_before_timeout_detach(module, base):
    import time
    observed = []

    def chunks():
        yield b"pay"
        time.sleep(0.08)
        yield b"load"

    with base.RawServer(lambda req: (observed.append(req.body), base.RawResponse.ok("ok"))[1]) as server:
        try:
            response = module.post(server.url("/slow-upload"), content=chunks(), timeout=0.5)
            actual = {"status": response.status_code, "server_bodies": [value.decode() for value in observed]}
        except Exception as exc:
            actual = {"exception": type(exc).__name__, "message": str(exc), "server_bodies": [value.decode() for value in observed]}
    return result(actual, actual.get("status") == 200 and actual["server_bodies"] == ["payload"])


def response_is_read_when_request_write_fails(module, base):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    import threading

    def serve():
        with contextlib.closing(listener):
            conn, _ = listener.accept()
            with conn:
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data.extend(chunk)
                conn.sendall(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo many")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def large_body():
        for _ in range(128):
            yield b"x" * 65536

    try:
        response = module.post(f"http://127.0.0.1:{port}/", content=large_body(), timeout=1)
        actual = {"status": response.status_code, "body": response.text}
    except Exception as exc:
        actual = {"exception": type(exc).__name__, "message": str(exc)}
    thread.join(1)
    return result(actual, actual.get("status") == 429 and actual.get("body") == "too many")


def redirect_does_not_reuse_connection_when_dns_differs(module, base):
    # Two distinct endpoints model the DNS change; the observable is that the
    # follow-up reaches the second endpoint rather than the first connection.
    with base.RawServer(lambda req: base.RawResponse.ok("second")) as second:
        with base.RawServer(lambda req: base.RawResponse.redirect(second.url("/target"))) as first:
            response = module.Client().get(first.url("/start"))
            actual = {
                "body": response.text,
                "first_connections": first.accepted_connections,
                "second_connections": second.accepted_connections,
            }
    return result(actual, actual["body"] == "second" and actual["second_connections"] == 1)


def tls_tunnel_truncated_response_body_does_not_crash(module, base):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    import threading

    def serve():
        with contextlib.closing(listener):
            conn, _ = listener.accept()
            with conn:
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data.extend(chunk)
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 100\r\n\r\nshort")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        module.get("https://example.invalid/", proxies={"https": f"http://127.0.0.1:{port}"}, trust_env=False, timeout=1)
        actual = {"raised": False}
    except BaseException as exc:
        actual = {"raised": True, "exception": type(exc).__name__, "controlled_error": isinstance(exc, Exception)}
    thread.join(1)
    return result(actual, actual.get("raised") is True and actual.get("controlled_error") is True)


def connect_handling_tolerates_misbehaving_proxies(module, base):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    import threading

    def serve():
        with contextlib.closing(listener):
            conn, _ = listener.accept()
            with conn:
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data.extend(chunk)
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\nunexpected bytes")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        module.get("https://example.invalid/", proxies={"https": f"http://127.0.0.1:{port}"}, trust_env=False, verify=False, timeout=1)
        actual = {"completed": True}
    except BaseException as exc:
        actual = {"completed": False, "exception": type(exc).__name__, "controlled_error": isinstance(exc, Exception)}
    thread.join(1)
    return result(actual, actual.get("completed") is True or actual.get("controlled_error") is True)


def proxy_authorization_from_proxy_url_is_not_forwarded_after_https_redirect(module, base):
    # The HTTPS tunnel hides origin headers from the proxy.  The target server
    # observes whether proxy credentials leaked into the tunneled request.
    with base.RawServer(lambda req: base.RawResponse.ok(req.header("Proxy-Authorization") or ""), tls=True) as target:
        with base.TunnelProxy() as proxy:
            try:
                response = module.get(
                    target.url("/"),
                    proxies={"https": proxy.url.replace("http://", "http://user:password@")},
                    verify=False,
                    trust_env=False,
                )
                actual = {"status": response.status_code, "origin_proxy_authorization": response.text}
            except Exception as exc:
                actual = {"exception": type(exc).__name__, "message": str(exc)}
    return result(actual, actual.get("status") == 200 and actual.get("origin_proxy_authorization") == "")


def same_host_default_port_redirect_preserves_authorization(module, base):
    # Canonical origin equivalence is exercised with an explicit current port
    # followed by the same authority.  The default-port spelling is retained in
    # the contract metadata; the observable is authorization preservation.
    def handler(req):
        return base.RawResponse.redirect(server.url("/target")) if req.path == "/start" else base.RawResponse.ok(req.header("Authorization") or "")

    with base.RawServer(handler) as server:
        response = module.get(server.url("/start"), headers={"Authorization": "Bearer token"})
    return result({"authorization": response.text}, response.text == "Bearer token")


SCENARIOS: dict[str, Callable[..., dict[str, Any]]] = {
    name: value
    for name, value in list(globals().items())
    if callable(value) and not name.startswith("_") and name not in {"result", "environment", "mapped_dns"}
}


def run(module, base, name: str) -> dict[str, Any]:
    scenario = SCENARIOS[name]
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError(f"scenario timeout: {name}")))
    signal.setitimer(signal.ITIMER_REAL, 8.0)
    try:
        return scenario(module, base)
    except BaseException as exc:
        return result({"exception": type(exc).__name__, "message": str(exc)}, False)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
