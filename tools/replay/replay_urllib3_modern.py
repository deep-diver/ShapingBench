#!/usr/bin/env python3
"""
Replay modern urllib3 object-level contracts against installed release wheels.
"""

from __future__ import annotations

import argparse
import http.server
import inspect
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import sys
import tarfile
import threading
import textwrap
import types
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[2]
PY312 = pathlib.Path(os.environ.get("SHAPINGBENCH_PY312", "/opt/miniconda3/bin/python3.12"))
PY39 = pathlib.Path(os.environ.get("SHAPINGBENCH_PY39", sys.executable))
VENV_ROOT = ROOT / ".replay" / "venvs" / "modern"
LEGACY_SDIST_ROOT = ROOT / ".replay" / "legacy-sdists"
OPTIONAL_DEPS = ["h2==4.1.0", "zstandard", "Brotli", "PySocks", "pyOpenSSL"]
LEGACY_SDIST_INSTALLS = {"1.0", "1.1", "1.2.1"}
PY2_SDIST_INSTALLS = {"1.0", "1.1"}


def optional_deps_for(version: str) -> list[str]:
    deps = list(OPTIONAL_DEPS)
    if version == "1.25":
        deps[deps.index("Brotli")] = "brotlipy"
    return deps


CONTRACTS: dict[str, dict[str, str]] = {
    "2.7.0:streaming_decompression_bomb_guard_limits_output": {
        "mutant": "disable_streaming_decompression_guard",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
        "mutant_code": """
import gzip, io
import urllib3.response
from urllib3.response import HTTPResponse
original = urllib3.response.GzipDecoder.decompress
def ignore_max_length(self, data, max_length=-1):
    return original(self, data, max_length=-1)
urllib3.response.GzipDecoder.decompress = ignore_max_length
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
    },
    "2.6.3:streaming_decompression_bomb_guard_limits_output": {
        "mutant": "disable_streaming_decompression_guard",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
        "mutant_code": """
import gzip, io
import urllib3.response
from urllib3.response import HTTPResponse
original = urllib3.response.GzipDecoder.decompress
def ignore_max_length(self, data, max_length=-1):
    return original(self, data, max_length=-1)
urllib3.response.GzipDecoder.decompress = ignore_max_length
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
    },
    "2.6.0:streaming_decompression_bomb_guard_limits_output": {
        "mutant": "disable_streaming_decompression_guard",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
        "mutant_code": """
import gzip, io
import urllib3.response
from urllib3.response import HTTPResponse
original = urllib3.response.GzipDecoder.decompress
def ignore_max_length(self, data, max_length=-1):
    return original(self, data, max_length=-1)
urllib3.response.GzipDecoder.decompress = ignore_max_length
body = gzip.compress(b"x" * 1000000)
response = HTTPResponse(body=io.BytesIO(body), headers={"Content-Encoding": "gzip"}, preload_content=False)
for _ in range(3):
    data = response.read(1, decode_content=True)
    assert len(data) == 1
    assert len(response._decoded_buffer) == 0
""",
    },
    "2.6.3:retry_after_header_is_capped_at_six_hours": {
        "mutant": "allow_retry_after_above_six_hours",
        "code": """
from urllib3.util.retry import Retry
assert Retry().parse_retry_after("25200") <= 21600
""",
        "mutant_code": """
from urllib3.util.retry import Retry
Retry.parse_retry_after = lambda self, value: int(value)
assert Retry().parse_retry_after("25200") <= 21600
""",
    },
    "2.6.1:response_legacy_header_accessors_are_available": {
        "mutant": "remove_legacy_response_header_accessors",
        "code": """
from urllib3.response import HTTPResponse
r = HTTPResponse(body=b"", headers={"X-Test": "1"})
assert r.getheader("X-Test") == "1"
assert list(r.getheaders().items()) == [("X-Test", "1")]
""",
        "mutant_code": """
from urllib3.response import HTTPResponse
HTTPResponse.getheader = None
HTTPResponse.getheaders = None
r = HTTPResponse(body=b"", headers={"X-Test": "1"})
assert r.getheader("X-Test") == "1"
""",
    },
    "2.6.0:response_legacy_header_accessors_are_removed": {
        "mutant": "restore_removed_legacy_response_header_accessor",
        "code": """
from urllib3.response import HTTPResponse
r = HTTPResponse(body=b"", headers={"X-Test": "1"})
assert not hasattr(r, "getheader")
assert not hasattr(r, "getheaders")
""",
        "mutant_code": """
from urllib3.response import HTTPResponse
HTTPResponse.getheader = lambda self, name, default=None: self.headers.get(name, default)
HTTPResponse.getheaders = lambda self: self.headers
r = HTTPResponse(body=b"", headers={"X-Test": "1"})
assert not hasattr(r, "getheader")
""",
    },
    "2.6.0:http_header_dict_accepts_bytes_keys": {
        "mutant": "reject_bytes_header_keys",
        "code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict({"X-Test": "1"})
assert h[b"X-Test"] == "1"
assert b"X-Test" in h
del h[b"X-Test"]
assert "X-Test" not in h
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
def reject_bytes(value):
    if isinstance(value, bytes):
        raise KeyError(value)
    return value
HTTPHeaderDict.__getitem__ = lambda self, key: (_ for _ in ()).throw(KeyError(key)) if isinstance(key, bytes) else dict.__getitem__(self, key)
h = HTTPHeaderDict({"X-Test": "1"})
assert h[b"X-Test"] == "1"
""",
    },
    "2.6.0:connection_string_representation_includes_host_and_port": {
        "mutant": "omit_host_or_port_from_connection_string",
        "code": """
from urllib3.connection import HTTPConnection
s = str(HTTPConnection("example.test", 8080))
assert "example.test" in s
assert "8080" in s
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
HTTPConnection.__repr__ = lambda self: "HTTPConnection()"
HTTPConnection.__str__ = lambda self: "HTTPConnection()"
s = str(HTTPConnection("example.test", 8080))
assert "example.test" in s
assert "8080" in s
""",
    },
    "2.6.0:sslkeylogfile_expands_environment_variables": {
        "mutant": "do_not_expand_sslkeylogfile_variables",
        "code": """
import os
os.environ["LOGDIR"] = "/tmp"
os.environ["SSLKEYLOGFILE"] = "$LOGDIR/keys.log"
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context()
assert getattr(ctx, "keylog_filename", None) == "/tmp/keys.log"
""",
        "mutant_code": """
import os, ssl
os.environ["LOGDIR"] = "/tmp"
os.environ["SSLKEYLOGFILE"] = "$LOGDIR/keys.log"
original = ssl.SSLContext.keylog_filename
def raw_setter(self, value):
    original.__set__(self, os.environ.get("SSLKEYLOGFILE"))
ssl.SSLContext.keylog_filename = property(original.__get__, raw_setter)
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context()
assert getattr(ctx, "keylog_filename", None) == "/tmp/keys.log"
""",
    },
    "2.7.0:response_stream_amt_zero_yields_empty_without_consuming": {
        "mutant": "amt_zero_consumes_stream_data",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False, headers={"Transfer-Encoding": "chunked"})
assert list(r.stream(0)) == []
assert r.read() == b"abc"
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original = HTTPResponse.stream
def consume_on_zero(self, amt=2**16, decode_content=None):
    if amt == 0:
        data = self.read(1, decode_content=decode_content)
        return iter([data] if data else [])
    return original(self, amt, decode_content)
HTTPResponse.stream = consume_on_zero
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False, headers={"Transfer-Encoding": "chunked"})
assert list(r.stream(0)) == []
assert r.read() == b"abc"
""",
    },
    "2.7.0:response_stream_continues_with_buffered_decompressed_data": {
        "mutant": "drop_decompressed_buffer_between_reads",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
seen_partial = {"value": False}
def drop_buffer(self, amt=None, decode_content=None, cache_content=False):
    if seen_partial["value"] and amt is None:
        return b""
    result = original(self, amt, decode_content, cache_content)
    if amt not in (None, 0):
        seen_partial["value"] = True
    return result
HTTPResponse.read = drop_buffer
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
    },
    "2.7.0:response_stream_continues_with_buffered_decompressed_data_2": {
        "mutant": "drop_decompressed_buffer_between_reads",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
seen_partial = {"value": False}
def drop_buffer(self, amt=None, decode_content=None, cache_content=False):
    if seen_partial["value"] and amt is None:
        return b""
    result = original(self, amt, decode_content, cache_content)
    if amt not in (None, 0):
        seen_partial["value"] = True
    return result
HTTPResponse.read = drop_buffer
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
    },
    "2.6.2:response_stream_continues_with_buffered_decompressed_data": {
        "mutant": "drop_decompressed_buffer_between_reads",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
seen_partial = {"value": False}
def drop_buffer(self, amt=None, decode_content=None, cache_content=False):
    if seen_partial["value"] and amt is None:
        return b""
    result = original(self, amt, decode_content, cache_content)
    if amt not in (None, 0):
        seen_partial["value"] = True
    return result
HTTPResponse.read = drop_buffer
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert r.read(3, decode_content=True) + r.read(None, decode_content=True) == b"abcdef"
""",
    },
    "2.0.2:response_stream_continues_with_buffered_decompressed_data": {
        "mutant": "drop_decompressed_buffer_between_reads",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert b"".join(r.stream(3, decode_content=True)) == b"abcdef"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
original_stream = HTTPResponse.stream
def drop_buffered_stream(self, amt=2**16, decode_content=None):
    for index, chunk in enumerate(original_stream(self, amt, decode_content)):
        if index == 0:
            yield chunk
            return
HTTPResponse.stream = drop_buffered_stream
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"abcdef")), preload_content=False, headers={"Content-Encoding": "gzip"})
assert b"".join(r.stream(3, decode_content=True)) == b"abcdef"
""",
    },
    "2.6.0:content_encoding_chain_is_limited_to_five": {
        "mutant": "allow_unbounded_content_encoding_chain",
        "code": """
from urllib3.exceptions import DecodeError
from urllib3.response import _get_decoder
try:
    _get_decoder("gzip,gzip,gzip,gzip,gzip,gzip")
except DecodeError:
    pass
else:
    raise AssertionError("expected DecodeError for too many content encodings")
""",
        "mutant_code": """
from urllib3.exceptions import DecodeError
from urllib3.response import MultiDecoder, _get_decoder
MultiDecoder.max_decode_links = 100
try:
    _get_decoder("gzip,gzip,gzip,gzip,gzip,gzip")
except DecodeError:
    pass
else:
    raise AssertionError("expected DecodeError for too many content encodings")
""",
    },
    "2.0.5:default_blocksize_is_16k": {
        "mutant": "use_non_16k_default_blocksize",
        "code": """
from urllib3.connection import HTTPConnection
assert HTTPConnection("example.test").blocksize == 16384
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
original = HTTPConnection.__init__
def init_with_old_blocksize(self, *args, **kwargs):
    original(self, *args, **kwargs)
    self.blocksize = 8192
HTTPConnection.__init__ = init_with_old_blocksize
assert HTTPConnection("example.test").blocksize == 16384
""",
    },
    "1.25.6:tilde_in_url_path_is_not_percent_encoded": {
        "mutant": "percent_encode_tilde_in_path",
        "code": """
from urllib3.util import parse_url
assert parse_url("http://example.test/~user").url == "http://example.test/~user"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    url = "http://example.test/%7Euser"
urllib3.util.parse_url = lambda url: MutantUrl()
assert urllib3.util.parse_url("http://example.test/~user").url == "http://example.test/~user"
""",
    },
    "1.20:url_scheme_and_host_are_normalized_lowercase": {
        "mutant": "preserve_uppercase_scheme_or_host",
        "code": """
from urllib3 import HTTPConnectionPool
from urllib3.util import parse_url
parsed = parse_url("HTTP://EXAMPLE.TEST/path")
assert parsed.scheme == "http"
assert parsed.host == "example.test"
assert HTTPConnectionPool("example.test").is_same_host("http://EXAMPLE.TEST/")
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    scheme = "HTTP"
    host = "EXAMPLE.TEST"
    url = "HTTP://EXAMPLE.TEST/path"
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("HTTP://EXAMPLE.TEST/path")
assert parsed.scheme == "http"
assert parsed.host == "example.test"
""",
    },
    "1.17:url_scheme_and_host_are_normalized_lowercase": {
        "mutant": "preserve_uppercase_scheme_or_host",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("HTTP://EXAMPLE.TEST/path")
assert parsed.scheme == "http"
assert parsed.host == "example.test"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    scheme = "HTTP"
    host = "EXAMPLE.TEST"
    url = "HTTP://EXAMPLE.TEST/path"
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("HTTP://EXAMPLE.TEST/path")
assert parsed.scheme == "http"
assert parsed.host == "example.test"
""",
    },
    "1.20:url_ipv6_zone_identifier_is_accepted": {
        "mutant": "reject_ipv6_zone_identifier",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://[fe80::1%25eth0]/")
assert parsed.host == "[fe80::1%25eth0]"
""",
        "mutant_code": """
import urllib3.util
from urllib3.exceptions import LocationParseError
def reject_zone(url):
    if "%25" in url:
        raise LocationParseError(url)
    return None
urllib3.util.parse_url = reject_zone
parsed = urllib3.util.parse_url("http://[fe80::1%25eth0]/")
assert parsed.host == "[fe80::1%25eth0]"
""",
    },
    "2.0.0:custom_retry_backoff_max_limits_backoff": {
        "mutant": "ignore_custom_backoff_max",
        "code": """
from urllib3.util.retry import Retry, RequestHistory
h = (
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
)
assert Retry(total=3, backoff_factor=1, backoff_max=2, history=h).get_backoff_time() <= 2
""",
        "mutant_code": """
from urllib3.util.retry import Retry, RequestHistory
Retry.get_backoff_time = lambda self: 4
h = (
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
)
assert Retry(total=3, backoff_factor=1, backoff_max=2, history=h).get_backoff_time() <= 2
""",
    },
    "2.0.0:retry_backoff_jitter_is_added_within_bounds": {
        "mutant": "omit_backoff_jitter",
        "code": """
import random
from urllib3.util.retry import Retry, RequestHistory
random.random = lambda: 1.0
h = (
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
)
value = Retry(total=3, backoff_factor=1, backoff_max=10, backoff_jitter=0.5, history=h).get_backoff_time()
assert value == 2.5
""",
        "mutant_code": """
from urllib3.util.retry import Retry, RequestHistory
Retry.get_backoff_time = lambda self: 2.0
h = (
    RequestHistory("GET", "/", None, 500, None),
    RequestHistory("GET", "/", None, 500, None),
)
value = Retry(total=3, backoff_factor=1, backoff_max=10, backoff_jitter=0.5, history=h).get_backoff_time()
assert value == 2.5
""",
    },
    "2.0.0:retry_backoff_constant_is_renamed_without_value_change": {
        "mutant": "missing_default_backoff_max_constant",
        "code": """
from urllib3.util.retry import Retry
assert Retry.DEFAULT_BACKOFF_MAX == 120
assert not hasattr(Retry, "BACKOFF_MAX")
""",
        "mutant_code": """
from urllib3.util.retry import Retry
Retry.BACKOFF_MAX = Retry.DEFAULT_BACKOFF_MAX
assert Retry.DEFAULT_BACKOFF_MAX == 120
assert not hasattr(Retry, "BACKOFF_MAX")
""",
    },
    "2.0.0:default_blocksize_is_16k": {
        "mutant": "use_non_16k_default_blocksize",
        "code": """
import urllib3
import urllib3.poolmanager as poolmanager

assert poolmanager._DEFAULT_BLOCKSIZE == 16384
pool = urllib3.PoolManager().connection_from_url("http://example.test/")
assert pool.conn_kw["blocksize"] == 16384
assert pool._new_conn().blocksize == 16384
""",
        "mutant_code": """
import urllib3
import urllib3.poolmanager as poolmanager

poolmanager._DEFAULT_BLOCKSIZE = 8192
assert poolmanager._DEFAULT_BLOCKSIZE == 16384
pool = urllib3.PoolManager().connection_from_url("http://example.test/")
assert pool.conn_kw["blocksize"] == 16384
assert pool._new_conn().blocksize == 16384
""",
    },
    "2.0.4:http_header_dict_supports_union_operators": {
        "mutant": "missing_header_union_operator",
        "code": """
from urllib3._collections import HTTPHeaderDict
merged = HTTPHeaderDict({"A": "1"}) | HTTPHeaderDict({"B": "2"})
assert merged["A"] == "1"
assert merged["B"] == "2"
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
HTTPHeaderDict.__or__ = lambda self, other: self.copy()
merged = HTTPHeaderDict({"A": "1"}) | HTTPHeaderDict({"B": "2"})
assert merged["A"] == "1"
assert merged["B"] == "2"
""",
    },
    "2.0.0:http_header_dict_can_repeat_or_combine_values": {
        "mutant": "ignore_header_combine_policy",
        "code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict()
h.add("X-My-Header", "foo")
h.add("X-My-Header", "bar", combine=True)
assert h["X-My-Header"] == "foo, bar"
assert list(h.items()) == [("X-My-Header", "foo, bar")]
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
original = HTTPHeaderDict.add
def ignore_combine(self, key, val, *, combine=False):
    return original(self, key, val, combine=False)
HTTPHeaderDict.add = ignore_combine
h = HTTPHeaderDict()
h.add("X-My-Header", "foo")
h.add("X-My-Header", "bar", combine=True)
assert h["X-My-Header"] == "foo, bar"
assert list(h.items()) == [("X-My-Header", "foo, bar")]
""",
    },
    "2.0.0:proxy_certificate_hostname_assertion_is_configurable": {
        "mutant": "ignore_proxy_assert_hostname",
        "code": """
from types import SimpleNamespace
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

seen = []
def capture_proxy_tls_args(*args, **kwargs):
    seen.append(kwargs)
    return Wrapped()

connection_module._ssl_wrap_socket_and_match_hostname = capture_proxy_tls_args
conn = connection_module.HTTPSConnection(
    "proxy.test",
    proxy_config=SimpleNamespace(
        ssl_context=None,
        assert_hostname="proxy.test",
        assert_fingerprint="AA:BB",
    ),
)
sock = conn._connect_tls_proxy("proxy.test", Sock())
assert isinstance(sock, Sock)
assert conn.proxy_is_verified is True
assert seen[-1]["assert_hostname"] == "proxy.test"
assert seen[-1]["assert_fingerprint"] == "AA:BB"
""",
        "mutant_code": """
from types import SimpleNamespace
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

seen = []
def capture_proxy_tls_args(*args, **kwargs):
    seen.append(kwargs)
    return Wrapped()

def ignore_proxy_assertions(self, hostname, sock):
    sock_and_verified = connection_module._ssl_wrap_socket_and_match_hostname(
        sock,
        cert_reqs=self.cert_reqs,
        ssl_version=self.ssl_version,
        ssl_minimum_version=self.ssl_minimum_version,
        ssl_maximum_version=self.ssl_maximum_version,
        ca_certs=self.ca_certs,
        ca_cert_dir=self.ca_cert_dir,
        ca_cert_data=self.ca_cert_data,
        server_hostname=hostname,
        ssl_context=self.proxy_config.ssl_context,
        assert_hostname=None,
        assert_fingerprint=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        tls_in_tls=False,
    )
    self.proxy_is_verified = sock_and_verified.is_verified
    return sock_and_verified.socket

connection_module.HTTPSConnection._connect_tls_proxy = ignore_proxy_assertions
connection_module._ssl_wrap_socket_and_match_hostname = capture_proxy_tls_args
conn = connection_module.HTTPSConnection(
    "proxy.test",
    proxy_config=SimpleNamespace(
        ssl_context=None,
        assert_hostname="proxy.test",
        assert_fingerprint="AA:BB",
    ),
)
sock = conn._connect_tls_proxy("proxy.test", Sock())
assert isinstance(sock, Sock)
assert conn.proxy_is_verified is True
assert seen[-1]["assert_hostname"] == "proxy.test"
assert seen[-1]["assert_fingerprint"] == "AA:BB"
""",
    },
    "2.0.0:json_request_sets_content_type_when_missing": {
        "mutant": "omit_json_content_type",
        "code": """
import http.server, socketserver, threading
import urllib3
class Server(socketserver.TCPServer):
    allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.headers.get("Content-Type", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("POST", f"http://127.0.0.1:{server.server_address[1]}/", json={"a": 1})
    assert response.data == b"application/json"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import http.server, socketserver, threading
import urllib3
original_request = urllib3.PoolManager.request
def omit_json_header(self, method, url, **kwargs):
    if "json" in kwargs:
        kwargs.pop("json")
        kwargs["body"] = b"{\\"a\\": 1}"
    return original_request(self, method, url, **kwargs)
urllib3.PoolManager.request = omit_json_header
class Server(socketserver.TCPServer):
    allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.headers.get("Content-Type", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("POST", f"http://127.0.0.1:{server.server_address[1]}/", json={"a": 1})
    assert response.data == b"application/json"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "2.0.0:multipart_header_control_characters_are_not_percent_encoded": {
        "mutant": "percent_encode_control_characters_in_multipart_filename",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"file": ("tab\\tname.txt", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b'filename="tab\\tname.txt"' in body
assert b"%09" not in body
""",
        "mutant_code": """
import urllib3.fields
original = urllib3.fields.format_multipart_header_param
def percent_encode_tab(name, value):
    return original(name, value).replace("\\t", "%09")
urllib3.fields.format_multipart_header_param = percent_encode_tab
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"file": ("tab\\tname.txt", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b'filename="tab\\tname.txt"' in body
assert b"%09" not in body
""",
    },
    "2.0.0:response_read_respects_buffered_io_semantics": {
        "mutant": "return_more_than_requested_from_read",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abcdef"), preload_content=False)
result = r.read(3)
assert result == b"abc"
assert len(result) <= 3
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
def overread(self, amt=None, decode_content=None, cache_content=False):
    if amt == 3:
        return original(self, None, decode_content, cache_content)
    return original(self, amt, decode_content, cache_content)
HTTPResponse.read = overread
r = HTTPResponse(body=io.BytesIO(b"abcdef"), preload_content=False)
result = r.read(3)
assert result == b"abc"
assert len(result) <= 3
""",
    },
    "2.0.1:response_read_zero_returns_empty_without_error": {
        "mutant": "raise_on_read_zero",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert r.read(0) == b""
assert r.read() == b"abc"
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
def raise_on_zero(self, amt=None, decode_content=None, cache_content=False):
    if amt == 0:
        raise RuntimeError("buffer is empty")
    return original(self, amt, decode_content, cache_content)
HTTPResponse.read = raise_on_zero
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert r.read(0) == b""
assert r.read() == b"abc"
""",
    },
    "2.2.2:response_read_negative_amt_behaves_like_read_all": {
        "mutant": "reject_negative_read_amount",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert r.read(-1) == b"abc"
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
def reject_negative(self, amt=None, decode_content=None, cache_content=False):
    if isinstance(amt, int) and amt < 0:
        raise ValueError("negative read amount")
    return original(self, amt, decode_content, cache_content)
HTTPResponse.read = reject_negative
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert r.read(-1) == b"abc"
""",
    },
    "2.2.0:response_read1_is_available_and_reads_bytes": {
        "mutant": "remove_response_read1",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert hasattr(r, "read1")
assert r.read1(2) == b"ab"
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
HTTPResponse.read1 = None
r = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
assert hasattr(r, "read1")
assert r.read1(2) == b"ab"
""",
    },
    "1.26.16:poolmanager_many_origins_does_not_close_in_use_pools": {
        "mutant": "close_in_use_pool_when_evicted",
        "code": """
import socketserver, threading, time
import urllib3

class SlowHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
        time.sleep(0.1)
        self.request.sendall(b"def")

class FastHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

one = Server(("127.0.0.1", 0), SlowHandler)
two = Server(("127.0.0.1", 0), FastHandler)
one_thread = threading.Thread(target=one.serve_forever, daemon=True)
two_thread = threading.Thread(target=two.serve_forever, daemon=True)
one_thread.start()
two_thread.start()
try:
    manager = urllib3.PoolManager(num_pools=1, maxsize=1, block=True)
    response = manager.request("GET", "http://127.0.0.1:%d/slow" % one.server_address[1], preload_content=False, timeout=1)
    original_pool = response._pool
    assert response.read(3) == b"abc"
    other = manager.request("GET", "http://127.0.0.1:%d/" % two.server_address[1], timeout=1)
    assert other.status == 200
    assert other.data == b"ok"
    assert original_pool.pool is not None
    assert response.read() == b"def"
    response.release_conn()
    assert original_pool.pool is not None
finally:
    one.shutdown()
    two.shutdown()
    one.server_close()
    two.server_close()
""",
        "mutant_code": """
import socketserver, threading, time
import urllib3
import urllib3._collections

original_init = urllib3._collections.RecentlyUsedContainer.__init__
def init_with_pool_dispose(self, maxsize=10, dispose_func=None):
    return original_init(self, maxsize=maxsize, dispose_func=dispose_func or (lambda pool: pool.close()))
urllib3._collections.RecentlyUsedContainer.__init__ = init_with_pool_dispose

class SlowHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
        time.sleep(0.1)
        self.request.sendall(b"def")

class FastHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

one = Server(("127.0.0.1", 0), SlowHandler)
two = Server(("127.0.0.1", 0), FastHandler)
one_thread = threading.Thread(target=one.serve_forever, daemon=True)
two_thread = threading.Thread(target=two.serve_forever, daemon=True)
one_thread.start()
two_thread.start()
try:
    manager = urllib3.PoolManager(num_pools=1, maxsize=1, block=True)
    response = manager.request("GET", "http://127.0.0.1:%d/slow" % one.server_address[1], preload_content=False, timeout=1)
    original_pool = response._pool
    assert response.read(3) == b"abc"
    other = manager.request("GET", "http://127.0.0.1:%d/" % two.server_address[1], timeout=1)
    assert other.status == 200
    assert other.data == b"ok"
    assert original_pool.pool is not None
    assert response.read() == b"def"
    response.release_conn()
    assert original_pool.pool is not None
finally:
    one.shutdown()
    two.shutdown()
    one.server_close()
    two.server_close()
""",
    },
    "1.26.15:url_ipv6_zone_identifier_is_accepted": {
        "mutant": "accept_bang_in_ipv6_zone_identifier",
        "code": """
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url
assert parse_url("http://[fe80::1%25eth0]/").host == "[fe80::1%eth0]"
try:
    parse_url("http://[fe80::1!eth0]/")
except LocationParseError:
    pass
else:
    raise AssertionError("expected invalid IPv6 zone identifier to be rejected")
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    host = "[fe80::1!eth0]"
urllib3.util.parse_url = lambda url: MutantUrl()
from urllib3.exceptions import LocationParseError
assert urllib3.util.parse_url("http://[fe80::1%25eth0]/").host == "[fe80::1%eth0]"
try:
    urllib3.util.parse_url("http://[fe80::1!eth0]/")
except LocationParseError:
    pass
else:
    raise AssertionError("expected invalid IPv6 zone identifier to be rejected")
""",
    },
    "1.26.14:url_port_zero_is_preserved": {
        "mutant": "treat_zero_port_as_absent",
        "code": """
from urllib3.util import parse_url
assert parse_url("http://example.test:0/").port == 0
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    port = None
urllib3.util.parse_url = lambda url: MutantUrl()
assert urllib3.util.parse_url("http://example.test:0/").port == 0
""",
    },
    "1.26.13:url_port_with_leading_zeroes_is_accepted": {
        "mutant": "reject_port_with_leading_zeroes",
        "code": """
from urllib3.util import parse_url
assert parse_url("http://example.test:00080/").port == 80
""",
        "mutant_code": """
import urllib3.util
from urllib3.exceptions import LocationParseError
def reject_leading_zero_port(url):
    if ":00080" in url:
        raise LocationParseError(url)
    return None
urllib3.util.parse_url = reject_leading_zero_port
assert urllib3.util.parse_url("http://example.test:00080/").port == 80
""",
    },
    "1.25.7:empty_query_section_is_preserved": {
        "mutant": "drop_empty_query_section",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://example.test/path?")
assert parsed.url == "http://example.test/path?"
assert parsed.query == ""
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    url = "http://example.test/path"
    query = None
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("http://example.test/path?")
assert parsed.url == "http://example.test/path?"
assert parsed.query == ""
""",
    },
    "1.25.7:chunked_parameter_is_preserved_on_retries": {
        "mutant": "drop_chunked_flag_on_retry",
        "code": """
import socketserver, threading
import urllib3
from urllib3.util.retry import Retry

class Handler(socketserver.BaseRequestHandler):
    count = 0
    def handle(self):
        type(self).count += 1
        data = b""
        self.request.settimeout(2)
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        if type(self).count == 1:
            return
        body = b"chunked" if b"transfer-encoding: chunked" in data.lower() else b"not-chunked"
        self.request.sendall(
            b"HTTP/1.1 200 OK\\r\\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\\r\\nConnection: close\\r\\n\\r\\n"
            + body
        )

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    retry = Retry(total=1, read=1, connect=0, method_whitelist=False)
    response = urllib3.PoolManager().request(
        "POST",
        f"http://127.0.0.1:{server.server_address[1]}/flaky-upload",
        body=(chunk for chunk in [b"abc"]),
        chunked=True,
        retries=retry,
        timeout=1,
    )
    assert response.data == b"chunked"
    assert Handler.count == 2
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
import urllib3
import urllib3.connectionpool as connectionpool
from urllib3.util.retry import Retry

original_urlopen = connectionpool.HTTPConnectionPool.urlopen
calls = {"count": 0}
def drop_chunked_on_retry(self, method, url, *args, **kwargs):
    calls["count"] += 1
    if calls["count"] > 1:
        if len(args) > 0:
            args = list(args)
            args[0] = b"abc"
            if len(args) > 8:
                args[8] = False
            args = tuple(args)
        if "chunked" in kwargs:
            kwargs["chunked"] = False
        if "body" in kwargs:
            kwargs["body"] = b"abc"
    return original_urlopen(self, method, url, *args, **kwargs)
connectionpool.HTTPConnectionPool.urlopen = drop_chunked_on_retry

class Handler(socketserver.BaseRequestHandler):
    count = 0
    def handle(self):
        type(self).count += 1
        data = b""
        self.request.settimeout(2)
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        if type(self).count == 1:
            return
        body = b"chunked" if b"transfer-encoding: chunked" in data.lower() else b"not-chunked"
        self.request.sendall(
            b"HTTP/1.1 200 OK\\r\\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\\r\\nConnection: close\\r\\n\\r\\n"
            + body
        )

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    retry = Retry(total=1, read=1, connect=0, method_whitelist=False)
    response = urllib3.PoolManager().request(
        "POST",
        f"http://127.0.0.1:{server.server_address[1]}/flaky-upload",
        body=(chunk for chunk in [b"abc"]),
        chunked=True,
        retries=retry,
        timeout=1,
    )
    assert response.data == b"chunked"
    assert Handler.count == 2
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.25.4:url_auth_invalid_chars_are_percent_encoded": {
        "mutant": "raise_on_invalid_auth_chars",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://user name@example.test/path")
assert parsed.auth == "user%20name"
assert parsed.url == "http://user%20name@example.test/path"
""",
        "mutant_code": """
import urllib3.util
from urllib3.exceptions import LocationParseError
urllib3.util.parse_url = lambda url: (_ for _ in ()).throw(LocationParseError(url))
parsed = urllib3.util.parse_url("http://user name@example.test/path")
assert parsed.auth == "user%20name"
assert parsed.url == "http://user%20name@example.test/path"
""",
    },
    "1.25.4:url_path_query_fragment_invalid_chars_are_percent_encoded": {
        "mutant": "leave_invalid_url_chars_unencoded",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://example.test/a b?x=y z#frag ment")
assert parsed.path == "/a%20b"
assert parsed.query == "x=y%20z"
assert parsed.fragment == "frag%20ment"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    path = "/a b"
    query = "x=y z"
    fragment = "frag ment"
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("http://example.test/a b?x=y z#frag ment")
assert parsed.path == "/a%20b"
assert parsed.query == "x=y%20z"
assert parsed.fragment == "frag%20ment"
""",
    },
    "1.25.2:url_path_query_fragment_invalid_chars_are_percent_encoded": {
        "mutant": "leave_invalid_url_chars_unencoded",
        "code": """
from urllib3.util import parse_url
assert parse_url("http://example.test/a b?x=y z").url == "http://example.test/a%20b?x=y%20z"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    url = "http://example.test/a b?x=y z"
urllib3.util.parse_url = lambda url: MutantUrl()
assert urllib3.util.parse_url("http://example.test/a b?x=y z").url == "http://example.test/a%20b?x=y%20z"
""",
    },
    "1.19:url_port_rejects_integerish_unicode": {
        "mutant": "accept_integerish_unicode_port",
        "code": """
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url
try:
    parse_url("http://example.test:¹/")
except LocationParseError:
    pass
else:
    raise AssertionError("expected integerish unicode port to be rejected")
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    port = 1
urllib3.util.parse_url = lambda url: MutantUrl()
from urllib3.exceptions import LocationParseError
try:
    urllib3.util.parse_url("http://example.test:¹/")
except LocationParseError:
    pass
else:
    raise AssertionError("expected integerish unicode port to be rejected")
""",
    },
    "1.8:parse_url_handles_at_in_username_and_blank_port": {
        "mutant": "split_username_at_first_at_or_require_port",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://user@name@example.test:/path")
assert parsed.auth == "user@name"
assert parsed.host == "example.test"
assert parsed.port is None
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    auth = "user"
    host = "name@example.test"
    port = 80
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("http://user@name@example.test:/path")
assert parsed.auth == "user@name"
assert parsed.host == "example.test"
assert parsed.port is None
""",
    },
    "1.8:same_host_accepts_default_port_equivalence": {
        "mutant": "treat_default_port_as_different_origin",
        "code": """
from urllib3 import HTTPConnectionPool
assert HTTPConnectionPool("example.test").is_same_host("http://example.test:80/path")
""",
        "mutant_code": """
from urllib3 import HTTPConnectionPool
HTTPConnectionPool.is_same_host = lambda self, url: False if ":80" in url else True
assert HTTPConnectionPool("example.test").is_same_host("http://example.test:80/path")
""",
    },
    "1.10:max_retry_error_reason_is_exception": {
        "mutant": "store_non_exception_max_retry_reason",
        "code": """
import urllib3
from urllib3.exceptions import MaxRetryError
try:
    urllib3.HTTPConnectionPool("127.0.0.1", port=1, timeout=0.01).request("GET", "/", retries=0)
except MaxRetryError as error:
    assert isinstance(error.reason, Exception)
else:
    raise AssertionError("expected MaxRetryError")
""",
        "mutant_code": """
import urllib3
from urllib3.exceptions import MaxRetryError
original = MaxRetryError.__init__
def stringify_reason(self, pool, url, reason=None):
    original(self, pool, url, reason)
    self.reason = str(reason)
MaxRetryError.__init__ = stringify_reason
try:
    urllib3.HTTPConnectionPool("127.0.0.1", port=1, timeout=0.01).request("GET", "/", retries=0)
except MaxRetryError as error:
    assert isinstance(error.reason, Exception)
else:
    raise AssertionError("expected MaxRetryError")
""",
    },
    "1.10.4:chunked_keep_alive_preserves_request_boundaries": {
        "mutant": "leak_chunked_request_state_across_keep_alive",
        "code": """
import socketserver
import threading
import urllib3

captures = []

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        for index in range(2):
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            headers, body = data.split(b"\\r\\n\\r\\n", 1)
            if b"transfer-encoding: chunked" in headers.lower():
                while b"0\\r\\n\\r\\n" not in body:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    body += chunk
            captures.append((headers.split(b"\\r\\n", 1)[0], body))
            response_body = b"abc" if index == 0 else b"next"
            self.request.sendall(
                b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                + str(len(response_body)).encode("ascii")
                + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                + response_body
            )

class Server(socketserver.TCPServer):
    allow_reuse_address = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("POST", "/upload", body=(chunk for chunk in [b"abc"]), headers={}, retries=False)
    second = pool.urlopen("GET", "/next", retries=False)
    assert first.status == 200
    assert first.data == b"abc"
    assert second.status == 200
    assert second.data == b"next"
    assert captures[0][0] == b"POST /upload HTTP/1.1"
    assert captures[0][1] == b"3\\r\\nabc\\r\\n0\\r\\n\\r\\n"
    assert captures[1][0] == b"GET /next HTTP/1.1"
    assert captures[1][1] == b""
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import urllib3
import urllib3.connection as connection_module

captures = []
original_request = connection_module.HTTPConnection.request
def leak_chunked_body_into_get(self, method, url, body=None, headers={}, *, encode_chunked=False):
    if method == "GET" and url == "/next":
        headers = dict(headers)
        headers["Transfer-Encoding"] = "chunked"
        return original_request(self, method, url, body=(chunk for chunk in [b"leak"]), headers=headers, encode_chunked=True)
    return original_request(self, method, url, body=body, headers=headers, encode_chunked=encode_chunked)
connection_module.HTTPConnection.request = leak_chunked_body_into_get

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        for index in range(2):
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            headers, body = data.split(b"\\r\\n\\r\\n", 1)
            if b"transfer-encoding: chunked" in headers.lower():
                while b"0\\r\\n\\r\\n" not in body:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    body += chunk
            captures.append((headers.split(b"\\r\\n", 1)[0], body))
            response_body = b"abc" if index == 0 else b"next"
            self.request.sendall(
                b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                + str(len(response_body)).encode("ascii")
                + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                + response_body
            )

class Server(socketserver.TCPServer):
    allow_reuse_address = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("POST", "/upload", body=(chunk for chunk in [b"abc"]), headers={}, retries=False)
    second = pool.urlopen("GET", "/next", retries=False)
    assert first.status == 200
    assert first.data == b"abc"
    assert second.status == 200
    assert second.data == b"next"
    assert captures[0][0] == b"POST /upload HTTP/1.1"
    assert captures[0][1] == b"3\\r\\nabc\\r\\n0\\r\\n\\r\\n"
    assert captures[1][0] == b"GET /next HTTP/1.1"
    assert captures[1][1] == b""
finally:
    connection_module.HTTPConnection.request = original_request
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.9.1:only_fingerprint_verification_is_supported": {
        "mutant": "require_ca_certificate_even_with_matching_fingerprint",
        "code": """
import hashlib
import urllib3.connection as connection_module

cert = b"fingerprint-only-cert"
fingerprint = hashlib.sha1(cert).hexdigest()

class FakeSock:
    def getpeercert(self, binary_form=False):
        return cert if binary_form else {}
    def close(self):
        pass

connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module.ssl_wrap_socket = lambda *args, **kwargs: FakeSock()
conn = connection_module.HTTPSConnection("example.test")
conn.set_cert(assert_fingerprint=fingerprint)
conn.connect()
assert conn.is_verified is True
""",
        "mutant_code": """
import hashlib, ssl
import urllib3.connection as connection_module

cert = b"fingerprint-only-cert"
fingerprint = hashlib.sha1(cert).hexdigest()

class FakeSock:
    def getpeercert(self, binary_form=False):
        return cert if binary_form else {}
    def close(self):
        pass

original_set_cert = connection_module.HTTPSConnection.set_cert
def require_ca_for_fingerprint(self, *args, **kwargs):
    original_set_cert(self, *args, **kwargs)
    if self.assert_fingerprint and self.ca_certs is None:
        self.cert_reqs = "CERT_REQUIRED"
connection_module.HTTPSConnection.set_cert = require_ca_for_fingerprint

def fake_wrap_socket(*args, **kwargs):
    if kwargs.get("cert_reqs") == ssl.CERT_REQUIRED and kwargs.get("ca_certs") is None:
        raise ssl.SSLError("CA certificate required")
    return FakeSock()

connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module.ssl_wrap_socket = fake_wrap_socket
conn = connection_module.HTTPSConnection("example.test")
conn.set_cert(assert_fingerprint=fingerprint)
conn.connect()
assert conn.is_verified is True
""",
    },
    "1.10.4:chunked_head_response_without_body_does_not_hang": {
        "mutant": "hang_on_chunked_head_without_body",
        "code": """
import socketserver
import threading
import time
import urllib3

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\nConnection: close\\r\\n\\r\\n")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("HEAD", "/head", preload_content=False, retries=False, timeout=1)
    started = time.monotonic()
    assert list(response.stream()) == []
    assert time.monotonic() - started < 1
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import time
import urllib3
from urllib3.response import HTTPResponse

def slow_empty_stream(self, *args, **kwargs):
    time.sleep(1.2)
    return iter([])

HTTPResponse.stream = slow_empty_stream

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\nConnection: close\\r\\n\\r\\n")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("HEAD", "/head", preload_content=False, retries=False, timeout=1)
    started = time.monotonic()
    assert list(response.stream()) == []
    assert time.monotonic() - started < 1
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.10.3:multiple_set_cookie_headers_are_preserved": {
        "mutant": "merge_duplicate_set_cookie_headers",
        "code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict()
h.add("Set-Cookie", "a=1")
h.add("Set-Cookie", "b=2")
assert h.getlist("Set-Cookie") == ["a=1", "b=2"]
assert list(h.items()) == [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict()
h["Set-Cookie"] = "a=1"
h["Set-Cookie"] = "b=2"
assert h.getlist("Set-Cookie") == ["a=1", "b=2"]
assert list(h.items()) == [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
""",
    },
    "1.10.1:header_values_with_commas_are_preserved": {
        "mutant": "split_comma_header_value",
        "code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict({"X-List": "a, b"})
assert h["X-List"] == "a, b"
assert h.getlist("X-List") == ["a, b"]
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
h = HTTPHeaderDict({"X-List": "a, b"})
h._container["x-list"] = ["X-List", "a", "b"]
assert h["X-List"] == "a, b"
assert h.getlist("X-List") == ["a, b"]
""",
    },
    "1.15:retry_raise_on_status_false_returns_error_response": {
        "mutant": "raise_on_status_despite_disabled_policy",
        "code": """
import http.server, socketserver, threading
import urllib3
from urllib3.util.retry import Retry
class Server(socketserver.TCPServer):
    allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"down")
    def log_message(self, *args):
        pass
server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request(
        "GET",
        f"http://127.0.0.1:{server.server_address[1]}/",
        retries=Retry(total=0, status_forcelist=[503], raise_on_status=False),
    )
    assert response.status == 503
    assert response.data == b"down"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import http.server, socketserver, threading
import urllib3
from urllib3.util.retry import Retry
class Server(socketserver.TCPServer):
    allow_reuse_address = True
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"down")
    def log_message(self, *args):
        pass
server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request(
        "GET",
        f"http://127.0.0.1:{server.server_address[1]}/",
        retries=Retry(total=0, status_forcelist=[503], raise_on_status=True),
    )
    assert response.status == 503
    assert response.data == b"down"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.25.4:retry_after_setting_propagates_to_subsequent_retries": {
        "mutant": "drop_retry_after_setting_on_increment",
        "code": """
from urllib3.util.retry import Retry
r = Retry(total=1, respect_retry_after_header=False)
r2 = r.increment(method="GET", url="/", response=None)
assert r2.respect_retry_after_header is False
""",
        "mutant_code": """
from urllib3.util.retry import Retry
r = Retry(total=1, respect_retry_after_header=False)
r2 = Retry(total=r.total)
assert r2.respect_retry_after_header is False
""",
    },
    "1.25.4:retry_after_can_be_explicitly_ignored": {
        "mutant": "respect_retry_after_when_disabled",
        "code": """
from urllib3.util.retry import Retry
r = Retry(total=1, respect_retry_after_header=False)
assert not r.is_retry("GET", 503, has_retry_after=True)
""",
        "mutant_code": """
from urllib3.util.retry import Retry
Retry.is_retry = lambda self, method, status_code, has_retry_after=False: bool(has_retry_after)
r = Retry(total=1, respect_retry_after_header=False)
assert not r.is_retry("GET", 503, has_retry_after=True)
""",
    },
    "1.12:new_connection_failure_raises_new_connection_error": {
        "mutant": "raise_generic_connection_error_on_connect_failure",
        "code": """
import urllib3
from urllib3.exceptions import MaxRetryError, NewConnectionError
try:
    urllib3.HTTPConnectionPool("127.0.0.1", port=1, timeout=0.01).request("GET", "/", retries=0)
except MaxRetryError as error:
    assert isinstance(error.reason, NewConnectionError)
else:
    raise AssertionError("expected MaxRetryError")
""",
        "mutant_code": """
import urllib3
import urllib3.connection
from urllib3.exceptions import MaxRetryError, NewConnectionError, ProtocolError
urllib3.connection.NewConnectionError = ProtocolError
try:
    urllib3.HTTPConnectionPool("127.0.0.1", port=1, timeout=0.01).request("GET", "/", retries=0)
except MaxRetryError as error:
    assert isinstance(error.reason, NewConnectionError)
else:
    raise AssertionError("expected MaxRetryError")
""",
    },
    "1.26.0:default_user_agent_header_is_sent": {
        "mutant": "omit_default_user_agent_header",
        "code": """
capture = capture_request()
assert capture["header_values"]["user-agent"] == ["python-urllib3/1.26.0"]
""",
        "mutant_code": """
import urllib3.connection
urllib3.connection._get_default_user_agent = lambda: None
capture = capture_request()
assert capture["header_values"]["user-agent"] == ["python-urllib3/1.26.0"]
""",
    },
    "1.26.0:skip_header_suppresses_automatic_headers": {
        "mutant": "ignore_skip_header_sentinel",
        "code": """
from urllib3.util import SKIP_HEADER
capture = capture_request(headers={"User-Agent": SKIP_HEADER, "Accept-Encoding": SKIP_HEADER})
assert "user-agent" not in capture["header_values"]
assert "accept-encoding" not in capture["header_values"]
""",
        "mutant_code": """
import urllib3.connection
urllib3.connection.HTTPConnection.putheader = urllib3.connection._HTTPConnection.putheader
from urllib3.util import SKIP_HEADER
capture = capture_request(headers={"User-Agent": SKIP_HEADER, "Accept-Encoding": SKIP_HEADER})
assert "user-agent" not in capture["header_values"]
assert "accept-encoding" not in capture["header_values"]
""",
    },
    "1.26.1:bytes_user_agent_header_does_not_duplicate": {
        "mutant": "duplicate_user_agent_when_bytes_key_is_used",
        "code": """
capture = capture_request(headers={b"User-Agent": "custom"})
assert capture["header_values"]["user-agent"] == ["custom"]
""",
        "mutant_code": """
import urllib3.connection
original_request = urllib3.connection.HTTPConnection.request
def duplicate_bytes_user_agent(self, method, url, body=None, headers=None):
    headers = dict(headers or {})
    headers["User-Agent"] = urllib3.connection._get_default_user_agent()
    return original_request(self, method, url, body=body, headers=headers)
urllib3.connection.HTTPConnection.request = duplicate_bytes_user_agent
capture = capture_request(headers={b"User-Agent": "custom"})
assert capture["header_values"]["user-agent"] == ["custom"]
""",
    },
    "1.11:http_header_dict_is_usable_as_request_headers": {
        "mutant": "reject_http_header_dict_as_input_headers",
        "code": """
from urllib3._collections import HTTPHeaderDict
capture = capture_request(headers=HTTPHeaderDict({"X-Test": "1"}))
assert capture["headers"]["x-test"] == "1"
""",
        "mutant_code": """
import urllib3.connectionpool
from urllib3._collections import HTTPHeaderDict
original_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen
def reject_headerdict(self, method, url, body=None, headers=None, **kw):
    if isinstance(headers, HTTPHeaderDict):
        headers = {}
    return original_urlopen(self, method, url, body=body, headers=headers, **kw)
urllib3.connectionpool.HTTPConnectionPool.urlopen = reject_headerdict
capture = capture_request(headers=HTTPHeaderDict({"X-Test": "1"}))
assert capture["headers"]["x-test"] == "1"
""",
    },
    "1.11:pool_default_headers_apply_to_get_query_requests": {
        "mutant": "drop_pool_default_headers_for_get_query",
        "code": """
capture = capture_request(pool_headers={"X-Test": "pool"}, fields={"a": "1"})
assert capture["headers"]["x-test"] == "pool"
assert capture["path"].endswith("?a=1")
""",
        "mutant_code": """
import urllib3.request
original = urllib3.request.RequestMethods.request_encode_url
def drop_headers_for_fields(self, method, url, fields=None, headers=None, **kw):
    if fields:
        headers = {}
    return original(self, method, url, fields=fields, headers=headers, **kw)
urllib3.request.RequestMethods.request_encode_url = drop_headers_for_fields
capture = capture_request(pool_headers={"X-Test": "pool"}, fields={"a": "1"})
assert capture["headers"]["x-test"] == "pool"
assert capture["path"].endswith("?a=1")
""",
    },
    "1.11:incorrect_proxy_scheme_raises_value_error": {
        "mutant": "raise_internal_assertion_for_invalid_scheme",
        "code": """
import urllib3

try:
    urllib3.ProxyManager("foo://proxy.test")
except ValueError:
    pass
else:
    raise AssertionError("expected unsupported proxy scheme to raise ValueError")
""",
        "mutant_code": """
import urllib3.poolmanager

urllib3.poolmanager.ProxyManager.__init__ = lambda self, proxy_url, **kwargs: (_ for _ in ()).throw(AssertionError("unsupported scheme"))

try:
    urllib3.poolmanager.ProxyManager("foo://proxy.test")
except ValueError:
    pass
else:
    raise AssertionError("expected unsupported proxy scheme to raise ValueError")
""",
    },
    "1.11:pool_is_replenished_after_release_conn_false_error": {
        "mutant": "do_not_replenish_pool_after_release_conn_false_error",
        "code": """
import urllib3
import socketserver, threading

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        self.request.settimeout(2)
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        if b" /bad " in data:
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    try:
        pool.urlopen("GET", "/bad", retries=False, timeout=1, release_conn=False)
    except Exception:
        pass
    else:
        raise AssertionError("expected failed request")
    response = pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    assert response.status == 200
    assert response.data == b"ok"
    assert pool.pool.qsize() == 1
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import urllib3
import urllib3.connectionpool
urllib3.connectionpool.HTTPConnectionPool._put_conn = lambda self, conn: None
import socketserver, threading

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        self.request.settimeout(2)
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        if b" /bad " in data:
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    try:
        pool.urlopen("GET", "/bad", retries=False, timeout=1, release_conn=False)
    except Exception:
        pass
    else:
        raise AssertionError("expected failed request")
    response = pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    assert response.status == 200
    assert response.data == b"ok"
    assert pool.pool.qsize() == 1
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.11:connection_is_discarded_after_read_error": {
        "mutant": "return_read_error_connection_to_pool",
        "code": """
import socketserver, threading
import urllib3
from urllib3.exceptions import ProtocolError

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        if b" /bad " in data:
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("GET", "/bad", preload_content=False, retries=False, timeout=1)
    try:
        response.read()
    except ProtocolError:
        pass
    else:
        raise AssertionError("expected ProtocolError while reading incomplete body")
    response = pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    assert response.status == 200
    assert response.data == b"ok"
    assert server.connection_count == 2
    assert pool.pool.qsize() == 1
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
from contextlib import contextmanager
from http.client import HTTPException
import urllib3
import urllib3.response
from urllib3.exceptions import ProtocolError

@contextmanager
def leak_connection_after_read_error(self):
    try:
        yield
    except HTTPException as error:
        raise ProtocolError("Connection broken: %r" % error, error)

urllib3.response.HTTPResponse._error_catcher = leak_connection_after_read_error

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        if b" /bad " in data:
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("GET", "/bad", preload_content=False, retries=False, timeout=1)
    try:
        response.read()
    except ProtocolError:
        pass
    else:
        raise AssertionError("expected ProtocolError while reading incomplete body")
    response = pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    assert response.status == 200
    assert response.data == b"ok"
    assert server.connection_count == 2
    assert pool.pool.qsize() == 1
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.26.6:explicit_transfer_encoding_chunked_header_is_not_duplicated": {
        "mutant": "duplicate_transfer_encoding_chunked_header",
        "code": """
capture = capture_request(
    method="POST",
    body=(chunk for chunk in [b"abc"]),
    headers={"Transfer-Encoding": "chunked"},
    chunked=True,
)
assert capture["header_values"]["transfer-encoding"] == ["chunked"]
""",
        "mutant_code": """
import urllib3.connection
original = urllib3.connection.HTTPConnection.request_chunked
def duplicate_te(self, method, url, body=None, headers=None):
    headers = dict(headers or {})
    headers["X-Dummy"] = "1"
    self.putrequest(method, url)
    self.putheader("Transfer-Encoding", "chunked")
    self.putheader("Transfer-Encoding", "chunked")
    self.endheaders()
    if body:
        for chunk in body:
            self.send(b"%x\\r\\n%b\\r\\n" % (len(chunk), chunk))
        self.send(b"0\\r\\n\\r\\n")
urllib3.connection.HTTPConnection.request_chunked = duplicate_te
capture = capture_request(
    method="POST",
    body=(chunk for chunk in [b"abc"]),
    headers={"Transfer-Encoding": "chunked"},
    chunked=True,
)
assert capture["header_values"]["transfer-encoding"] == ["chunked"]
""",
    },
    "1.19:user_supplied_host_header_is_preserved_for_chunked_upload": {
        "mutant": "overwrite_user_supplied_host_header_on_chunked_upload",
        "code": """
capture = capture_request(
    method="POST",
    body=(chunk for chunk in [b"abc"]),
    headers={"Host": "example.test"},
    chunked=True,
)
assert capture["header_values"]["host"] == ["example.test"]
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def overwrite_user_host(self, method, url, fields=None, headers=None, **kw):
    if kw.get("chunked"):
        headers = {key: value for key, value in dict(headers or {}).items() if key.lower() != "host"}
        headers["Host"] = "mutant.test"
    return original_request(self, method, url, fields=fields, headers=headers, **kw)
urllib3.PoolManager.request = overwrite_user_host
capture = capture_request(
    method="POST",
    body=(chunk for chunk in [b"abc"]),
    headers={"Host": "example.test"},
    chunked=True,
)
assert capture["header_values"]["host"] == ["example.test"]
""",
    },
    "2.0.7:http_303_redirect_switches_method_to_get_and_strips_body": {
        "mutant": "preserve_post_body_on_303_redirect",
        "code": """
result = capture_redirect_request(method="POST", body=b"payload")
capture = result["target_captures"][-1]
assert capture["method"] == "GET"
assert capture["body"] == b""
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def preserve_post_on_303(self, method, url, fields=None, headers=None, body=None, **kw):
    if url.endswith("/redirect") and kw.get("redirect", True):
        kw.pop("redirect", None)
        return original_request(self, method, url.replace("/redirect", "/target"), fields=fields, headers=headers, body=body, **kw)
    return original_request(self, method, url, fields=fields, headers=headers, body=body, **kw)
urllib3.PoolManager.request = preserve_post_on_303
result = capture_redirect_request(method="POST", body=b"payload")
capture = result["target_captures"][-1]
assert capture["method"] == "GET"
assert capture["body"] == b""
""",
    },
    "1.26.18:http_303_redirect_switches_method_to_get_and_strips_body": {
        "mutant": "preserve_post_body_on_303_redirect",
        "code": """
result = capture_redirect_request(method="POST", body=b"payload")
capture = result["target_captures"][-1]
assert capture["method"] == "GET"
assert capture["body"] == b""
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def preserve_post_on_303(self, method, url, fields=None, headers=None, body=None, **kw):
    if url.endswith("/redirect") and kw.get("redirect", True):
        kw.pop("redirect", None)
        return original_request(self, method, url.replace("/redirect", "/target"), fields=fields, headers=headers, body=body, **kw)
    return original_request(self, method, url, fields=fields, headers=headers, body=body, **kw)
urllib3.PoolManager.request = preserve_post_on_303
result = capture_redirect_request(method="POST", body=b"payload")
capture = result["target_captures"][-1]
assert capture["method"] == "GET"
assert capture["body"] == b""
""",
    },
    "2.0.6:cross_host_redirect_strips_cookie_header": {
        "mutant": "preserve_cookie_on_cross_host_redirect",
        "code": """
result = capture_redirect_request(headers={"Cookie": "session=secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "cookie" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
Retry.DEFAULT = Retry(remove_headers_on_redirect=frozenset())
result = capture_redirect_request(headers={"Cookie": "session=secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "cookie" not in capture["headers"]
""",
    },
    "2.2.2:cross_host_redirect_strips_proxy_authorization_header": {
        "mutant": "preserve_proxy_authorization_on_cross_host_redirect",
        "code": """
result = capture_redirect_request(headers={"Proxy-Authorization": "Basic secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "proxy-authorization" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
Retry.DEFAULT = Retry(remove_headers_on_redirect=frozenset())
result = capture_redirect_request(headers={"Proxy-Authorization": "Basic secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "proxy-authorization" not in capture["headers"]
""",
    },
    "2.7.0:cross_host_redirect_strips_configured_sensitive_header": {
        "mutant": "preserve_configured_sensitive_header_on_cross_host_redirect",
        "code": """
from urllib3.util import Retry
retry = Retry(remove_headers_on_redirect=frozenset(["X-Secret"]))
result = capture_redirect_request(headers={"X-Secret": "secret"}, cross_host=True, retries=retry)
capture = result["target_captures"][-1]
assert "x-secret" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
original_init = Retry.__init__
def ignore_configured_headers(self, *args, **kwargs):
    if "remove_headers_on_redirect" in kwargs:
        kwargs["remove_headers_on_redirect"] = frozenset()
    return original_init(self, *args, **kwargs)
Retry.__init__ = ignore_configured_headers
retry = Retry(remove_headers_on_redirect=frozenset(["X-Secret"]))
result = capture_redirect_request(headers={"X-Secret": "secret"}, cross_host=True, retries=retry)
capture = result["target_captures"][-1]
assert "x-secret" not in capture["headers"]
""",
    },
    "2.2.0:headers_input_is_not_mutated_by_json_request": {
        "mutant": "mutate_input_headers_for_json_request",
        "code": """
headers = {"X-Test": "1"}
capture_request(method="POST", headers=headers, json={"a": 1})
assert headers == {"X-Test": "1"}
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def mutate_headers_for_json(self, method, url, fields=None, headers=None, **kw):
    if "json" in kw and headers is not None:
        headers["Content-Type"] = "application/json"
    return original_request(self, method, url, fields=fields, headers=headers, **kw)
urllib3.PoolManager.request = mutate_headers_for_json
headers = {"X-Test": "1"}
capture_request(method="POST", headers=headers, json={"a": 1})
assert headers == {"X-Test": "1"}
""",
    },
    "2.0.0:url_authority_includes_userinfo_and_host": {
        "mutant": "omit_userinfo_from_url_authority",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://user:pass@example.test:8080/path")
assert parsed.authority == "user:pass@example.test:8080"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    authority = "example.test:8080"
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("http://user:pass@example.test:8080/path")
assert parsed.authority == "user:pass@example.test:8080"
""",
    },
    "2.0.0:tls_minimum_and_maximum_versions_configure_context": {
        "mutant": "ignore_tls_version_bounds",
        "code": """
import ssl
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context(ssl_minimum_version=ssl.TLSVersion.TLSv1_2, ssl_maximum_version=ssl.TLSVersion.TLSv1_3)
assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
""",
        "mutant_code": """
import ssl
import urllib3.util.ssl_
original = urllib3.util.ssl_.create_urllib3_context
def ignore_bounds(*args, **kwargs):
    kwargs.pop("ssl_minimum_version", None)
    kwargs.pop("ssl_maximum_version", None)
    return original(*args, **kwargs)
urllib3.util.ssl_.create_urllib3_context = ignore_bounds
ctx = urllib3.util.ssl_.create_urllib3_context(ssl_minimum_version=ssl.TLSVersion.TLSv1_2, ssl_maximum_version=ssl.TLSVersion.TLSv1_3)
assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
""",
    },
    "2.0.0:tls_minimum_and_maximum_versions_configure_context_2": {
        "mutant": "ignore_tls_version_bounds",
        "code": """
import ssl
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context(ssl_minimum_version=ssl.TLSVersion.TLSv1_2, ssl_maximum_version=ssl.TLSVersion.TLSv1_3)
assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
""",
        "mutant_code": """
import ssl
import urllib3.util.ssl_
original = urllib3.util.ssl_.create_urllib3_context
def ignore_bounds(*args, **kwargs):
    kwargs.pop("ssl_minimum_version", None)
    kwargs.pop("ssl_maximum_version", None)
    return original(*args, **kwargs)
urllib3.util.ssl_.create_urllib3_context = ignore_bounds
ctx = urllib3.util.ssl_.create_urllib3_context(ssl_minimum_version=ssl.TLSVersion.TLSv1_2, ssl_maximum_version=ssl.TLSVersion.TLSv1_3)
assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
""",
    },
    "1.25.11:retry_after_http_date_uses_utc": {
        "mutant": "parse_retry_after_http_date_as_local_time",
        "code": """
import email.utils, time
from urllib3.util.retry import Retry
future = email.utils.formatdate(time.time() + 120, usegmt=True)
value = Retry().parse_retry_after(future)
assert 0 < value <= 180
""",
        "mutant_code": """
import email.utils, time
from urllib3.util.retry import Retry
Retry.parse_retry_after = lambda self, value: 0
future = email.utils.formatdate(time.time() + 120, usegmt=True)
value = Retry().parse_retry_after(future)
assert 0 < value <= 180
""",
    },
    "1.25.11:empty_sslkeylogfile_does_not_configure_keylog": {
        "mutant": "set_empty_sslkeylogfile_on_context",
        "code": """
import os
os.environ["SSLKEYLOGFILE"] = ""
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context()
assert getattr(ctx, "keylog_filename", None) is None
""",
        "mutant_code": """
import os
os.environ["SSLKEYLOGFILE"] = ""
import urllib3.util.ssl_
original = urllib3.util.ssl_.create_urllib3_context
def configure_empty_keylog(*args, **kwargs):
    ctx = original(*args, **kwargs)
    ctx.keylog_filename = "/tmp/urllib3-empty-keylog-mutant.log"
    return ctx
urllib3.util.ssl_.create_urllib3_context = configure_empty_keylog
ctx = urllib3.util.ssl_.create_urllib3_context()
assert getattr(ctx, "keylog_filename", None) is None
""",
    },
    "1.25.10:sslkeylogfile_environment_enables_tls_key_logging": {
        "mutant": "ignore_sslkeylogfile_environment",
        "code": """
import os
import urllib3.util.ssl_ as ssl_util

class FakeContext:
    keylog_filename = None
    post_handshake_auth = None
    check_hostname = True
    def __init__(self, protocol):
        self.protocol = protocol
        self.options = 0
        self.verify_mode = None
    def set_ciphers(self, ciphers):
        self.ciphers = ciphers

ssl_util.SSLContext = FakeContext
os.environ["SSLKEYLOGFILE"] = "/tmp/keys.log"
ctx = ssl_util.create_urllib3_context()
assert ctx.keylog_filename == "/tmp/keys.log"
""",
        "mutant_code": """
import os
import urllib3.util.ssl_ as ssl_util

class FakeContext:
    keylog_filename = None
    post_handshake_auth = None
    check_hostname = True
    def __init__(self, protocol):
        self.protocol = protocol
        self.options = 0
        self.verify_mode = None
    def __setattr__(self, name, value):
        if name == "keylog_filename":
            value = None
        object.__setattr__(self, name, value)
    def set_ciphers(self, ciphers):
        self.ciphers = ciphers

ssl_util.SSLContext = FakeContext
os.environ["SSLKEYLOGFILE"] = "/tmp/keys.log"
ctx = ssl_util.create_urllib3_context()
assert ctx.keylog_filename == "/tmp/keys.log"
""",
    },
    "1.15:chunked_request_sets_transfer_encoding_header": {
        "mutant": "omit_transfer_encoding_for_chunked_request",
        "code": """
capture = capture_request(method="POST", body=(chunk for chunk in [b"abc"]), chunked=True)
assert capture["headers"].get("transfer-encoding") == "chunked"
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def omit_transfer_encoding(self, method, url, fields=None, headers=None, **kw):
    if kw.get("chunked"):
        headers = dict(headers or {})
        headers["Transfer-Encoding"] = "identity"
    return original_request(self, method, url, fields=fields, headers=headers, **kw)
urllib3.PoolManager.request = omit_transfer_encoding
capture = capture_request(method="POST", body=(chunk for chunk in [b"abc"]), chunked=True)
assert capture["headers"].get("transfer-encoding") == "chunked"
""",
    },
    "1.17:response_length_remaining_tracks_unread_body": {
        "mutant": "leave_length_remaining_untracked",
        "code": """
import io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(b"abcde"), headers={"Content-Length": "5"}, preload_content=False)
assert r.read(2) == b"ab"
assert r.length_remaining == 3
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
def read_without_tracking_remaining(self, amt=None, decode_content=None, cache_content=False):
    result = original(self, amt, decode_content, cache_content)
    self.length_remaining = None
    return result
HTTPResponse.read = read_without_tracking_remaining
r = HTTPResponse(body=io.BytesIO(b"abcde"), headers={"Content-Length": "5"}, preload_content=False)
assert r.read(2) == b"ab"
assert r.length_remaining == 3
""",
    },
    "2.1.0:read_chunked_handles_gzip_encoded_chunks": {
        "mutant": "break_gzip_content_decoding",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "x-gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b"hello"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
HTTPResponse._decode = lambda self, data, decode_content, flush_decoder: data
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "x-gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b"hello"
""",
    },
    "1.13:read_chunked_handles_gzip_encoded_chunks": {
        "mutant": "break_gzip_content_decoding",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b"hello"
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
HTTPResponse._decode = lambda self, data, decode_content, flush_decoder: data
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b"hello"
""",
    },
    "1.13:response_read_error_closes_original_response_and_connection": {
        "mutant": "do_not_close_connection_on_response_read_error",
        "code": """
from http.client import HTTPException
from urllib3.exceptions import ProtocolError
from urllib3.response import HTTPResponse

class Body:
    def read(self, amt=None):
        raise HTTPException("boom")

class OriginalResponse:
    closed = False
    def isclosed(self):
        return self.closed
    def close(self):
        self.closed = True

class Connection:
    closed = False
    def close(self):
        self.closed = True

original = OriginalResponse()
connection = Connection()
response = HTTPResponse(body=Body(), preload_content=False, original_response=original, connection=connection)
try:
    response.read()
except ProtocolError:
    pass
else:
    raise AssertionError("expected read error")
assert original.closed is True
assert connection.closed is True
""",
        "mutant_code": """
from contextlib import contextmanager
from http.client import HTTPException
from urllib3.exceptions import ProtocolError
from urllib3.response import HTTPResponse

@contextmanager
def do_not_close_connection(self):
    try:
        yield
    except HTTPException as error:
        raise ProtocolError("Connection broken: %r" % error, error)

HTTPResponse._error_catcher = do_not_close_connection

class Body:
    def read(self, amt=None):
        raise HTTPException("boom")

class OriginalResponse:
    closed = False
    def isclosed(self):
        return self.closed
    def close(self):
        self.closed = True

class Connection:
    closed = False
    def close(self):
        self.closed = True

original = OriginalResponse()
connection = Connection()
response = HTTPResponse(body=Body(), preload_content=False, original_response=original, connection=connection)
try:
    response.read()
except ProtocolError:
    pass
else:
    raise AssertionError("expected read error")
assert original.closed is True
assert connection.closed is True
""",
    },
    "1.10.1:read_chunked_handles_gzip_encoded_chunks": {
        "mutant": "break_gzip_content_decoding",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b""
""",
        "mutant_code": """
import gzip, io
from urllib3.exceptions import DecodeError
from urllib3.response import HTTPResponse
def fail_empty_gzip_stream(self, amt=2**16, decode_content=None):
    raise DecodeError("failed to decode empty gzip stream")
HTTPResponse.stream = fail_empty_gzip_stream
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert b"".join(r.stream(decode_content=True)) == b""
""",
    },
    "1.26.17:cross_host_redirect_strips_cookie_header": {
        "mutant": "preserve_cookie_on_cross_host_redirect",
        "code": """
result = capture_redirect_request(headers={"Cookie": "session=secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "cookie" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
Retry.DEFAULT = Retry(remove_headers_on_redirect=frozenset())
result = capture_redirect_request(headers={"Cookie": "session=secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "cookie" not in capture["headers"]
""",
    },
    "1.26.19:cross_host_redirect_strips_proxy_authorization_header": {
        "mutant": "preserve_proxy_authorization_on_cross_host_redirect",
        "code": """
result = capture_redirect_request(headers={"Proxy-Authorization": "Basic secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "proxy-authorization" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
Retry.DEFAULT = Retry(remove_headers_on_redirect=frozenset())
result = capture_redirect_request(headers={"Proxy-Authorization": "Basic secret"}, cross_host=True)
capture = result["target_captures"][-1]
assert "proxy-authorization" not in capture["headers"]
""",
    },
    "1.7:relative_redirect_location_is_followed": {
        "mutant": "reject_relative_redirect_location",
        "code": """
result = capture_redirect_request(status=302)
capture = result["target_captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/target"
""",
        "mutant_code": """
import urllib3.response
original = urllib3.response.HTTPResponse.get_redirect_location
def reject_relative_redirect(self):
    location = original(self)
    if location and location.startswith("/"):
        return None
    return location
urllib3.response.HTTPResponse.get_redirect_location = reject_relative_redirect
result = capture_redirect_request(status=302)
capture = result["target_captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/target"
""",
    },
    "1.7:relative_redirect_location_is_followed_2": {
        "mutant": "reject_relative_redirect_location",
        "code": """
result = capture_redirect_request(status=302)
capture = result["target_captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/target"
""",
        "mutant_code": """
import urllib3.response
original = urllib3.response.HTTPResponse.get_redirect_location
def reject_relative_redirect(self):
    location = original(self)
    if location and location.startswith("/"):
        return None
    return location
urllib3.response.HTTPResponse.get_redirect_location = reject_relative_redirect
result = capture_redirect_request(status=302)
capture = result["target_captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/target"
""",
    },
    "1.7:assert_hostname_false_skips_hostname_verification": {
        "mutant": "ignore_assert_hostname_false",
        "code": """
import ssl
import urllib3.connectionpool as connectionpool

class FakeSock:
    def getpeercert(self, binary_form=False):
        return {"subject": ((("commonName", "mismatch.test"),),)}
    def close(self):
        pass

connectionpool.socket.create_connection = lambda *args, **kwargs: object()
connectionpool.ssl_wrap_socket = lambda *args, **kwargs: FakeSock()
def fail_if_called(cert, hostname):
    raise ssl.CertificateError("hostname mismatch")
connectionpool.match_hostname = fail_if_called

conn = connectionpool.VerifiedHTTPSConnection("example.test")
conn.set_cert(cert_reqs="CERT_REQUIRED", assert_hostname=False)
conn.connect()
assert isinstance(conn.sock, FakeSock)
""",
        "mutant_code": """
import ssl
import urllib3.connectionpool as connectionpool

class FakeSock:
    def getpeercert(self, binary_form=False):
        return {"subject": ((("commonName", "mismatch.test"),),)}
    def close(self):
        pass

original_set_cert = connectionpool.VerifiedHTTPSConnection.set_cert
def ignore_assert_hostname_false(self, *args, **kwargs):
    if kwargs.get("assert_hostname") is False:
        kwargs["assert_hostname"] = None
    return original_set_cert(self, *args, **kwargs)
connectionpool.VerifiedHTTPSConnection.set_cert = ignore_assert_hostname_false
connectionpool.socket.create_connection = lambda *args, **kwargs: object()
connectionpool.ssl_wrap_socket = lambda *args, **kwargs: FakeSock()
def fail_if_called(cert, hostname):
    raise ssl.CertificateError("hostname mismatch")
connectionpool.match_hostname = fail_if_called

conn = connectionpool.VerifiedHTTPSConnection("example.test")
conn.set_cert(cert_reqs="CERT_REQUIRED", assert_hostname=False)
conn.connect()
assert isinstance(conn.sock, FakeSock)
""",
    },
    "1.7:https_proxy_to_https_target_is_supported": {
        "mutant": "fail_https_proxy_to_https_target",
        "code": """
import urllib3
proxy = urllib3.ProxyManager("https://proxy.test:8443")
assert proxy.proxy.scheme == "https"
pool = proxy.connection_from_url("https://target.test/")
assert pool.proxy.scheme == "https"
""",
        "mutant_code": """
import urllib3
original_init = urllib3.ProxyManager.__init__
def downgrade_https_proxy(self, proxy_url, *args, **kwargs):
    original_init(self, proxy_url, *args, **kwargs)
    self.proxy = self.proxy._replace(scheme="http")
urllib3.ProxyManager.__init__ = downgrade_https_proxy
proxy = urllib3.ProxyManager("https://proxy.test:8443")
assert proxy.proxy.scheme == "https"
pool = proxy.connection_from_url("https://target.test/")
assert pool.proxy.scheme == "https"
""",
    },
    "2.7.0:relative_path_resembling_schemeless_uri_is_accepted": {
        "mutant": "parse_origin_form_path_as_schemeless_absolute_uri",
        "code": """
result = capture_pool_request_path("//example.test/path")
capture = result["captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/example.test/path"
""",
        "mutant_code": """
import urllib3.connectionpool
from urllib3.exceptions import LocationParseError
original = urllib3.connectionpool.HTTPConnectionPool.urlopen
def reject_schemeless_looking_path(self, method, url, *args, **kwargs):
    if url.startswith("//"):
        raise LocationParseError(url)
    return original(self, method, url, *args, **kwargs)
urllib3.connectionpool.HTTPConnectionPool.urlopen = reject_schemeless_looking_path
result = capture_pool_request_path("//example.test/path")
capture = result["captures"][-1]
assert result["response_status"] == 200
assert capture["path"] == "/example.test/path"
""",
    },
    "2.0.0:incomplete_response_body_raises_when_content_length_enforced": {
        "mutant": "silently_accept_truncated_body",
        "code": """
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True, enforce_content_length=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for truncated body")
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"abc"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True, enforce_content_length=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for truncated body")
""",
    },
    "1.17:incomplete_response_body_raises_when_content_length_enforced": {
        "mutant": "silently_accept_truncated_body",
        "code": """
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True, enforce_content_length=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for truncated body")
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"abc"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True, enforce_content_length=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for truncated body")
""",
    },
    "2.2.1:invalid_chunk_length_raises_protocol_error": {
        "mutant": "raise_invalid_chunk_length_directly",
        "code": """
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\nZZ\\r\\n", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for invalid chunk length")
""",
        "mutant_code": """
import urllib3
from urllib3.exceptions import InvalidChunkLength, ProtocolError
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(InvalidChunkLength(None, b"ZZ"))
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\nZZ\\r\\n", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError for invalid chunk length")
""",
    },
    "2.2.1:incomplete_read_error_reports_excess_content": {
        "mutant": "omit_excess_content_from_incomplete_read_error",
        "code": """
from urllib3.response import HTTPResponse
from urllib3.exceptions import IncompleteRead, ProtocolError

class ExcessBody:
    def read(self, amt=None):
        raise IncompleteRead(-3, 3)
    def close(self):
        pass
    def isclosed(self):
        return False

response = HTTPResponse(body=ExcessBody(), preload_content=False, enforce_content_length=True)
try:
    response.read()
except ProtocolError as error:
    assert error.args[0] == "Response may not contain content."
else:
    raise AssertionError("expected ProtocolError")
""",
        "mutant_code": """
from contextlib import contextmanager
import urllib3.response
from urllib3.response import HTTPResponse
from urllib3.exceptions import IncompleteRead, ProtocolError

@contextmanager
def generic_incomplete_read_message(self):
    try:
        yield
    except IncompleteRead as error:
        raise ProtocolError("Connection broken: %r" % error, error) from error

urllib3.response.HTTPResponse._error_catcher = generic_incomplete_read_message

class ExcessBody:
    def read(self, amt=None):
        raise IncompleteRead(-3, 3)
    def close(self):
        pass
    def isclosed(self):
        return False

response = HTTPResponse(body=ExcessBody(), preload_content=False, enforce_content_length=True)
try:
    response.read()
except ProtocolError as error:
    assert error.args[0] == "Response may not contain content."
else:
    raise AssertionError("expected ProtocolError")
""",
    },
    "2.6.0:poolmanager_integer_retries_limits_redirects": {
        "mutant": "ignore_integer_redirect_retry_budget",
        "code": """
from urllib3.exceptions import MaxRetryError
try:
    request_loop_redirect(retries=1)
except MaxRetryError:
    pass
else:
    raise AssertionError("expected MaxRetryError for redirect loop")
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"ok"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
from urllib3.exceptions import MaxRetryError
try:
    request_loop_redirect(retries=1)
except MaxRetryError:
    pass
else:
    raise AssertionError("expected MaxRetryError for redirect loop")
""",
    },
    "2.5.0:poolmanager_integer_retries_limits_redirects": {
        "mutant": "ignore_integer_redirect_retry_budget",
        "code": """
from urllib3.exceptions import MaxRetryError
try:
    request_loop_redirect(retries=1)
except MaxRetryError:
    pass
else:
    raise AssertionError("expected MaxRetryError for redirect loop")
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"ok"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
from urllib3.exceptions import MaxRetryError
try:
    request_loop_redirect(retries=1)
except MaxRetryError:
    pass
else:
    raise AssertionError("expected MaxRetryError for redirect loop")
""",
    },
    "1.26.3:bytes_and_string_header_keys_compare_equal": {
        "mutant": "treat_bytes_and_string_header_keys_as_distinct",
        "python_flags": ["-bb"],
        "code": """
from urllib3.connection import HTTPConnection

seen = []
conn = HTTPConnection("example.test")
conn.sock = object()
conn._output = lambda data: seen.append(data)
conn.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
conn.putheader("X-Test", b"value")
assert len(seen) == 2
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
import urllib3.connection as connection

_HTTPConnection = connection._HTTPConnection
SKIP_HEADER = connection.SKIP_HEADER

def old_putheader(self, header, *values):
    if SKIP_HEADER not in values:
        _HTTPConnection.putheader(self, header, *values)
    elif connection.six.ensure_str(header.lower()) not in connection.SKIPPABLE_HEADERS:
        raise ValueError("unsupported skipped header")

connection.HTTPConnection.putheader = old_putheader

seen = []
conn = HTTPConnection("example.test")
conn.sock = object()
conn._output = lambda data: seen.append(data)
conn.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
conn.putheader("X-Test", b"value")
assert len(seen) == 2
""",
    },
    "1.26.3:proxy_url_without_scheme_raises_actionable_error": {
        "mutant": "accept_proxy_url_without_scheme",
        "code": """
import urllib3
from urllib3.exceptions import ProxySchemeUnknown
try:
    urllib3.ProxyManager("localhost:8080")
except ProxySchemeUnknown as error:
    assert "scheme" in str(error).lower()
else:
    raise AssertionError("expected ProxySchemeUnknown")
""",
        "mutant_code": """
import urllib3
urllib3.ProxyManager.__init__ = lambda self, proxy_url, **kwargs: None
from urllib3.exceptions import ProxySchemeUnknown
try:
    urllib3.ProxyManager("localhost:8080")
except ProxySchemeUnknown as error:
    assert "scheme" in str(error).lower()
else:
    raise AssertionError("expected ProxySchemeUnknown")
""",
    },
    "1.6:cert_reqs_accepts_string_policy_values": {
        "mutant": "reject_string_cert_reqs",
        "code": """
import ssl
from urllib3.util import resolve_cert_reqs
assert resolve_cert_reqs("CERT_REQUIRED") == ssl.CERT_REQUIRED
assert resolve_cert_reqs("CERT_NONE") == ssl.CERT_NONE
""",
        "mutant_code": """
import ssl
import urllib3.util
urllib3.util.resolve_cert_reqs = lambda candidate: candidate
assert urllib3.util.resolve_cert_reqs("CERT_REQUIRED") == ssl.CERT_REQUIRED
assert urllib3.util.resolve_cert_reqs("CERT_NONE") == ssl.CERT_NONE
""",
    },
    "1.6:default_headers_are_sent": {
        "mutant": "omit_default_headers",
        "code": """
capture = capture_request()
assert capture["headers"].get("accept-encoding") == "identity"
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def change_default_accept_encoding(self, method, url, fields=None, headers=None, **kw):
    headers = dict(headers or {})
    headers["Accept-Encoding"] = "gzip"
    return original_request(self, method, url, fields=fields, headers=headers, **kw)
urllib3.PoolManager.request = change_default_accept_encoding
capture = capture_request()
assert capture["headers"].get("accept-encoding") == "identity"
""",
    },
    "1.6:max_retry_error_reason_is_none_for_redirect_exhaustion": {
        "mutant": "set_non_null_reason_for_redirect_exhaustion",
        "code": """
import http.server, socketserver, threading
import urllib3
from urllib3.exceptions import MaxRetryError

class LoopServer(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "/loop")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass

server = LoopServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1])
    try:
        pool.urlopen("GET", "/loop", retries=1, redirect=True)
    except MaxRetryError as error:
        assert error.reason is None
    else:
        raise AssertionError("expected MaxRetryError for redirect exhaustion")
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import http.server, socketserver, threading
import urllib3
from urllib3.exceptions import MaxRetryError
original = MaxRetryError.__init__
def force_redirect_reason(self, pool, url, reason=None):
    original(self, pool, url, reason)
    if self.reason is None:
        self.reason = RuntimeError("redirect exhausted")
MaxRetryError.__init__ = force_redirect_reason

class LoopServer(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "/loop")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass

server = LoopServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1])
    try:
        pool.urlopen("GET", "/loop", retries=1, redirect=True)
    except MaxRetryError as error:
        assert error.reason is None
    else:
        raise AssertionError("expected MaxRetryError for redirect exhaustion")
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.6:connection_closes_when_no_data_is_received": {
        "mutant": "leave_connection_open_after_empty_response",
        "code": """
import socketserver, threading
import urllib3
from urllib3.exceptions import MaxRetryError

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.recv(4096)

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    try:
        pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    except MaxRetryError:
        pass
    else:
        raise AssertionError("expected empty response to fail")
    assert server.connection_count == 1
    assert list(pool.pool.queue) == [None]
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
import urllib3
import urllib3.connectionpool
from urllib3.exceptions import MaxRetryError

sentinel = object()
def keep_non_empty_slot(self, conn):
    self.pool.put(conn if conn is not None else sentinel, block=False)
urllib3.connectionpool.HTTPConnectionPool._put_conn = keep_non_empty_slot

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.recv(4096)

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    try:
        pool.urlopen("GET", "/", retries=False, timeout=1, pool_timeout=0.2)
    except MaxRetryError:
        pass
    else:
        raise AssertionError("expected empty response to fail")
    assert server.connection_count == 1
    assert list(pool.pool.queue) == [None]
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.6:connection_refused_is_retried": {
        "mutant": "do_not_retry_connection_refused",
        "code": """
import http.client, socketserver, threading
import urllib3

class Handler(socketserver.BaseRequestHandler):
    count = 0
    def handle(self):
        type(self).count += 1
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
original_connect = http.client.HTTPConnection.connect
calls = {"count": 0}
def refuse_once(self):
    calls["count"] += 1
    if calls["count"] == 1:
        raise ConnectionRefusedError(111, "Connection refused")
    return original_connect(self)
http.client.HTTPConnection.connect = refuse_once
thread.start()
try:
    response = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], timeout=1).request("GET", "/", retries=1)
    assert response.status == 200
    assert response.data == b"ok"
    assert calls["count"] == 2
    assert Handler.count == 1
finally:
    http.client.HTTPConnection.connect = original_connect
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import http.client, socketserver, threading
import urllib3
import urllib3.connectionpool as connectionpool

class Handler(socketserver.BaseRequestHandler):
    count = 0
    def handle(self):
        type(self).count += 1
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
original_connect = http.client.HTTPConnection.connect
original_urlopen = connectionpool.HTTPConnectionPool.urlopen
calls = {"count": 0}
def refuse_once(self):
    calls["count"] += 1
    if calls["count"] == 1:
        raise ConnectionRefusedError(111, "Connection refused")
    return original_connect(self)
def disable_refused_retry(self, method, url, body=None, headers=None, retries=3, *args, **kwargs):
    return original_urlopen(self, method, url, body=body, headers=headers, retries=0, *args, **kwargs)
http.client.HTTPConnection.connect = refuse_once
connectionpool.HTTPConnectionPool.urlopen = disable_refused_retry
thread.start()
try:
    response = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], timeout=1).request("GET", "/", retries=1)
    assert response.status == 200
    assert response.data == b"ok"
    assert calls["count"] == 2
    assert Handler.count == 1
finally:
    http.client.HTTPConnection.connect = original_connect
    connectionpool.HTTPConnectionPool.urlopen = original_urlopen
    server.shutdown()
    server.server_close()
""",
    },
    "1.3:multipart_list_of_tuples_preserves_duplicate_field_names": {
        "mutant": "collapse_duplicate_multipart_fields",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata([("a", "1"), ("a", "2")], boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert body.count(b'name="a"') == 2
assert b"\\r\\n\\r\\n1\\r\\n" in body
assert b"\\r\\n\\r\\n2\\r\\n" in body
""",
        "mutant_code": """
import urllib3.filepost
original = urllib3.filepost.encode_multipart_formdata
def collapse_duplicates(fields, boundary=None):
    if isinstance(fields, list):
        fields = dict(fields)
    return original(fields, boundary=boundary)
urllib3.filepost.encode_multipart_formdata = collapse_duplicates
body, content_type = urllib3.filepost.encode_multipart_formdata([("a", "1"), ("a", "2")], boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert body.count(b'name="a"') == 2
assert b"\\r\\n\\r\\n1\\r\\n" in body
assert b"\\r\\n\\r\\n2\\r\\n" in body
""",
    },
    "1.3:multiple_set_cookie_headers_are_merged_without_loss": {
        "mutant": "overwrite_duplicate_response_headers",
        "code": """
from urllib3.response import HTTPResponse

class RawResponse:
    status = 200
    version = 11
    reason = "OK"
    strict = 0
    def getheaders(self):
        return [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
    def read(self, amt=None):
        return b""
    def isclosed(self):
        return True

response = HTTPResponse.from_httplib(RawResponse(), preload_content=False)
assert response.headers["set-cookie"] == "a=1, b=2"
""",
        "mutant_code": """
from urllib3.response import HTTPResponse

def overwrite_duplicate_headers(cls, raw, **response_kw):
    headers = {}
    for key, value in raw.getheaders():
        headers[key.lower()] = value
    return cls(
        body=raw,
        headers=headers,
        status=raw.status,
        version=raw.version,
        reason=raw.reason,
        strict=getattr(raw, "strict", 0),
        original_response=raw,
        **response_kw
    )

HTTPResponse.from_httplib = classmethod(overwrite_duplicate_headers)

class RawResponse:
    status = 200
    version = 11
    reason = "OK"
    strict = 0
    def getheaders(self):
        return [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
    def read(self, amt=None):
        return b""
    def isclosed(self):
        return True

response = HTTPResponse.from_httplib(RawResponse(), preload_content=False)
assert response.headers["set-cookie"] == "a=1, b=2"
""",
    },
    "2.0.0:pool_block_true_full_pool_raises_full_pool_error": {
        "mutant": "silently_discard_connection_from_blocking_full_pool",
        "code": """
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import FullPoolError
pool = HTTPConnectionPool("example.test", maxsize=1, block=True)
first = pool._get_conn(timeout=0.01)
extra = pool._new_conn()
pool._put_conn(first)
try:
    pool._put_conn(extra)
except FullPoolError:
    pass
else:
    raise AssertionError("expected FullPoolError")
""",
        "mutant_code": """
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import FullPoolError
HTTPConnectionPool._put_conn = lambda self, conn: None
pool = HTTPConnectionPool("example.test", maxsize=1, block=True)
first = pool._get_conn(timeout=0.01)
extra = pool._new_conn()
pool._put_conn(first)
try:
    pool._put_conn(extra)
except FullPoolError:
    pass
else:
    raise AssertionError("expected FullPoolError")
""",
    },
    "2.0.0:connection_state_properties_track_lifecycle": {
        "mutant": "leave_connection_state_properties_stale",
        "code": """
from urllib3.connection import HTTPConnection
conn = HTTPConnection("example.test")
assert conn.is_closed is True
assert conn.is_connected is False
assert conn.has_connected_to_proxy is False
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
HTTPConnection.is_closed = property(lambda self: False)
conn = HTTPConnection("example.test")
assert conn.is_closed is True
assert conn.is_connected is False
assert conn.has_connected_to_proxy is False
""",
    },
    "2.0.0:remove_headers_on_redirect_does_not_mutate_input_headers": {
        "mutant": "mutate_headers_input_when_stripping_redirect_headers",
        "code": """
headers = {"Authorization": "secret", "X-Test": "1"}
capture_redirect_request(headers=headers, cross_host=True, status=302)
assert headers == {"Authorization": "secret", "X-Test": "1"}
""",
        "mutant_code": """
import urllib3
original_request = urllib3.PoolManager.request
def mutate_headers_on_redirect(self, method, url, fields=None, headers=None, **kw):
    if headers is not None and kw.get("redirect", True):
        headers.pop("Authorization", None)
    return original_request(self, method, url, fields=fields, headers=headers, **kw)
urllib3.PoolManager.request = mutate_headers_on_redirect
headers = {"Authorization": "secret", "X-Test": "1"}
capture_redirect_request(headers=headers, cross_host=True, status=302)
assert headers == {"Authorization": "secret", "X-Test": "1"}
""",
    },
    "1.25.7:url_fragment_is_not_sent_in_request_target": {
        "mutant": "send_fragment_in_request_target",
        "code": """
result = capture_pool_request_path("/path?x=1#fragment")
capture = result["captures"][-1]
assert capture["path"] == "/path?x=1"
""",
        "mutant_code": """
import urllib3.connectionpool
original = urllib3.connectionpool.HTTPConnectionPool.urlopen
def preserve_fragment(self, method, url, *args, **kwargs):
    if url == "/path?x=1#fragment":
        url = "/path?x=1%23fragment"
    return original(self, method, url, *args, **kwargs)
urllib3.connectionpool.HTTPConnectionPool.urlopen = preserve_fragment
result = capture_pool_request_path("/path?x=1#fragment")
capture = result["captures"][-1]
assert capture["path"] == "/path?x=1"
""",
    },
    "1.19:multipart_file_empty_filename_is_emitted": {
        "mutant": "suppress_empty_multipart_filename",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"file": ("", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b'filename=""' in body
""",
        "mutant_code": """
import urllib3.filepost
original = urllib3.filepost.encode_multipart_formdata
def suppress_empty_filename(fields, boundary=None):
    fields = {"file": b"abc"}
    return original(fields, boundary=boundary)
urllib3.filepost.encode_multipart_formdata = suppress_empty_filename
body, content_type = urllib3.filepost.encode_multipart_formdata({"file": ("", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b'filename=""' in body
""",
    },
    "1.9:generic_raised_errors_extend_http_exception": {
        "mutant": "raise_non_http_exception_subclass",
        "code": """
from urllib3.exceptions import HTTPError, DecodeError, ProtocolError, TimeoutError
assert issubclass(DecodeError, HTTPError)
assert issubclass(ProtocolError, HTTPError)
assert issubclass(TimeoutError, HTTPError)
""",
        "mutant_code": """
import urllib3.exceptions
urllib3.exceptions.DecodeError = RuntimeError
from urllib3.exceptions import HTTPError, DecodeError, ProtocolError, TimeoutError
assert issubclass(DecodeError, HTTPError)
assert issubclass(ProtocolError, HTTPError)
assert issubclass(TimeoutError, HTTPError)
""",
    },
    "2.0.0:response_read_decode_mode_cannot_change_after_decoding": {
        "mutant": "allow_decode_mode_change_after_read",
        "code": """
import gzip, io
from urllib3.response import HTTPResponse
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert r.read(1, decode_content=True) == b"h"
try:
    r.read(1, decode_content=False)
except RuntimeError:
    pass
else:
    raise AssertionError("expected decode mode change to fail")
""",
        "mutant_code": """
import gzip, io
from urllib3.response import HTTPResponse
original = HTTPResponse.read
def allow_mode_change(self, amt=None, decode_content=None, cache_content=False):
    if decode_content is False:
        return b""
    return original(self, amt, decode_content, cache_content)
HTTPResponse.read = allow_mode_change
r = HTTPResponse(body=io.BytesIO(gzip.compress(b"hello")), headers={"Content-Encoding": "gzip"}, preload_content=False)
assert r.read(1, decode_content=True) == b"h"
try:
    r.read(1, decode_content=False)
except RuntimeError:
    pass
else:
    raise AssertionError("expected decode mode change to fail")
""",
    },
    "2.0.0:poolmanager_many_origins_does_not_close_in_use_pools": {
        "mutant": "close_in_use_pool_when_evicted",
        "code": """
import socketserver, threading, time
import urllib3

class SlowHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
        time.sleep(0.1)
        self.request.sendall(b"def")

class FastHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

one = Server(("127.0.0.1", 0), SlowHandler)
two = Server(("127.0.0.1", 0), FastHandler)
one_thread = threading.Thread(target=one.serve_forever, daemon=True)
two_thread = threading.Thread(target=two.serve_forever, daemon=True)
one_thread.start()
two_thread.start()
try:
    manager = urllib3.PoolManager(num_pools=1, maxsize=1, block=True)
    response = manager.request("GET", "http://127.0.0.1:%d/slow" % one.server_address[1], preload_content=False, timeout=1)
    original_pool = response._pool
    assert response.read(3) == b"abc"
    other = manager.request("GET", "http://127.0.0.1:%d/" % two.server_address[1], timeout=1)
    assert other.status == 200
    assert other.data == b"ok"
    assert original_pool.pool is not None
    assert response.read() == b"def"
    response.release_conn()
    assert original_pool.pool is not None
finally:
    one.shutdown()
    two.shutdown()
    one.server_close()
    two.server_close()
""",
        "mutant_code": """
import socketserver, threading, time
import urllib3
import urllib3._collections

original_init = urllib3._collections.RecentlyUsedContainer.__init__
def init_with_pool_dispose(self, maxsize=10, dispose_func=None):
    return original_init(self, maxsize=maxsize, dispose_func=dispose_func or (lambda pool: pool.close()))
urllib3._collections.RecentlyUsedContainer.__init__ = init_with_pool_dispose

class SlowHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\nConnection: keep-alive\\r\\n\\r\\nabc")
        time.sleep(0.1)
        self.request.sendall(b"def")

class FastHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

one = Server(("127.0.0.1", 0), SlowHandler)
two = Server(("127.0.0.1", 0), FastHandler)
one_thread = threading.Thread(target=one.serve_forever, daemon=True)
two_thread = threading.Thread(target=two.serve_forever, daemon=True)
one_thread.start()
two_thread.start()
try:
    manager = urllib3.PoolManager(num_pools=1, maxsize=1, block=True)
    response = manager.request("GET", "http://127.0.0.1:%d/slow" % one.server_address[1], preload_content=False, timeout=1)
    original_pool = response._pool
    assert response.read(3) == b"abc"
    other = manager.request("GET", "http://127.0.0.1:%d/" % two.server_address[1], timeout=1)
    assert other.status == 200
    assert other.data == b"ok"
    assert original_pool.pool is not None
    assert response.read() == b"def"
    response.release_conn()
    assert original_pool.pool is not None
finally:
    one.shutdown()
    two.shutdown()
    one.server_close()
    two.server_close()
""",
    },
    "2.0.0:pyopenssl_syscall_error_preserves_errno": {
        "mutant": "drop_errno_from_pyopenssl_syscall_error",
        "code": """
from OpenSSL import SSL
from urllib3.contrib.pyopenssl import WrappedSocket

class Connection:
    def recv(self, *args, **kwargs):
        raise SSL.SysCallError(104, "ECONNRESET")

class Socket:
    def fileno(self):
        return 1
    def gettimeout(self):
        return 0
    def close(self):
        pass

wrapped = WrappedSocket(Connection(), Socket())
try:
    wrapped.recv(1)
except OSError as error:
    assert error.errno == 104
else:
    raise AssertionError("expected OSError")
""",
        "mutant_code": """
from OpenSSL import SSL
import urllib3.contrib.pyopenssl as pyopenssl
from urllib3.contrib.pyopenssl import WrappedSocket

def drop_errno_recv(self, *args, **kwargs):
    try:
        return self.connection.recv(*args, **kwargs)
    except SSL.SysCallError as error:
        raise OSError(str(error)) from error
pyopenssl.WrappedSocket.recv = drop_errno_recv

class Connection:
    def recv(self, *args, **kwargs):
        raise SSL.SysCallError(104, "ECONNRESET")

class Socket:
    def fileno(self):
        return 1
    def gettimeout(self):
        return 0
    def close(self):
        pass

wrapped = WrappedSocket(Connection(), Socket())
try:
    wrapped.recv(1)
except OSError as error:
    assert error.errno == 104
else:
    raise AssertionError("expected OSError")
""",
    },
    "2.0.1:fingerprint_or_hostname_failure_does_not_leak_socket": {
        "mutant": "leak_socket_on_certificate_failure",
        "code": """
import ssl
import urllib3.connection as connection

class FakeSock:
    closed = False
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subject": ((("commonName", "mismatch.test"),),)}
    def close(self):
        self.closed = True

fake_sock = FakeSock()
class FakeContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = False
    def load_default_certs(self):
        pass

connection.create_urllib3_context = lambda **kwargs: FakeContext()
connection.ssl_wrap_socket = lambda **kwargs: fake_sock
connection._match_hostname = lambda cert, hostname, hostname_checks_common_name=False: (_ for _ in ()).throw(ssl.CertificateError("hostname mismatch"))
try:
    connection._ssl_wrap_socket_and_match_hostname(
        sock=object(),
        cert_reqs="CERT_REQUIRED",
        ssl_version=None,
        ssl_minimum_version=None,
        ssl_maximum_version=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        ca_certs=None,
        ca_cert_dir=None,
        ca_cert_data=None,
        assert_hostname="example.test",
        assert_fingerprint=None,
        server_hostname="example.test",
        ssl_context=None,
    )
except ssl.CertificateError:
    pass
else:
    raise AssertionError("expected hostname verification failure")
assert fake_sock.closed is True
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection

class FakeSock:
    closed = False
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subject": ((("commonName", "mismatch.test"),),)}
    def close(self):
        self.closed = True

fake_sock = FakeSock()
class FakeContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = False
    def load_default_certs(self):
        pass

original = connection._ssl_wrap_socket_and_match_hostname
def leak_after_certificate_failure(*args, **kwargs):
    try:
        return original(*args, **kwargs)
    except BaseException:
        fake_sock.closed = False
        raise
connection._ssl_wrap_socket_and_match_hostname = leak_after_certificate_failure

connection.create_urllib3_context = lambda **kwargs: FakeContext()
connection.ssl_wrap_socket = lambda **kwargs: fake_sock
connection._match_hostname = lambda cert, hostname, hostname_checks_common_name=False: (_ for _ in ()).throw(ssl.CertificateError("hostname mismatch"))
try:
    connection._ssl_wrap_socket_and_match_hostname(
        sock=object(),
        cert_reqs="CERT_REQUIRED",
        ssl_version=None,
        ssl_minimum_version=None,
        ssl_maximum_version=None,
        cert_file=None,
        key_file=None,
        key_password=None,
        ca_certs=None,
        ca_cert_dir=None,
        ca_cert_data=None,
        assert_hostname="example.test",
        assert_fingerprint=None,
        server_hostname="example.test",
        ssl_context=None,
    )
except ssl.CertificateError:
    pass
else:
    raise AssertionError("expected hostname verification failure")
assert fake_sock.closed is True
""",
    },
    "2.0.0:chunked_boundaries_are_lowercase": {
        "mutant": "uppercase_chunk_boundaries",
        "code": """
raw = capture_raw_request(method="POST", body=(chunk for chunk in [b"abcdefghij"]), chunked=True, marker=b"abcdefghij")
assert b"\\r\\na\\r\\nabcdefghij\\r\\n" in raw
assert b"\\r\\nA\\r\\nabcdefghij\\r\\n" not in raw
""",
        "mutant_code": """
import urllib3.connection
original_send = urllib3.connection.HTTPConnection.send
def uppercase_chunk_boundary(self, data):
    if data == b"a\\r\\nabcdefghij\\r\\n":
        data = b"A\\r\\nabcdefghij\\r\\n"
    return original_send(self, data)
urllib3.connection.HTTPConnection.send = uppercase_chunk_boundary
raw = capture_raw_request(method="POST", body=(chunk for chunk in [b"abcdefghij"]), chunked=True, marker=b"abcdefghij")
assert b"\\r\\na\\r\\nabcdefghij\\r\\n" in raw
assert b"\\r\\nA\\r\\nabcdefghij\\r\\n" not in raw
""",
    },
    "1.21:status_forcelist_retry_increments_retry_counter": {
        "mutant": "do_not_count_status_forcelist_retries",
        "code": """
from urllib3.exceptions import MaxRetryError
from urllib3.util.retry import Retry
try:
    request_status_sequence([500, 500], retries=Retry(total=1, status_forcelist=[500]))
except MaxRetryError as error:
    assert getattr(error, "pool", None) is not None or True
else:
    raise AssertionError("expected MaxRetryError")
assert request_status_sequence.last_count == 2
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"ok"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
from urllib3.exceptions import MaxRetryError
from urllib3.util.retry import Retry
try:
    request_status_sequence([500, 500], retries=Retry(total=1, status_forcelist=[500]))
except MaxRetryError as error:
    assert getattr(error, "pool", None) is not None or True
else:
    raise AssertionError("expected MaxRetryError")
assert request_status_sequence.last_count == 2
""",
    },
    "1.9:url_empty_host_is_rejected": {
        "mutant": "allow_empty_host",
        "code": """
import urllib3
from urllib3.exceptions import LocationValueError
try:
    urllib3.PoolManager().request("GET", "http:///path")
except LocationValueError:
    pass
else:
    raise AssertionError("expected LocationValueError")
""",
        "mutant_code": """
import urllib3
from urllib3.exceptions import LocationValueError
class MutantResponse:
    status = 200
    data = b"ok"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
try:
    urllib3.PoolManager().request("GET", "http:///path")
except LocationValueError:
    pass
else:
    raise AssertionError("expected LocationValueError")
""",
    },
    "2.0.0:dns_failure_raises_name_resolution_error": {
        "mutant": "raise_generic_connection_error_for_dns_failure",
        "code": """
import urllib3
from urllib3.exceptions import NameResolutionError
try:
    urllib3.PoolManager().request("GET", "http://nonexistent.invalid-urllib3-contract/", retries=False, timeout=0.2)
except NameResolutionError:
    pass
else:
    raise AssertionError("expected NameResolutionError")
""",
        "mutant_code": """
import urllib3
from urllib3.exceptions import NameResolutionError, NewConnectionError
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(NewConnectionError(None, "dns failed"))
try:
    urllib3.PoolManager().request("GET", "http://nonexistent.invalid-urllib3-contract/", retries=False, timeout=0.2)
except NameResolutionError:
    pass
else:
    raise AssertionError("expected NameResolutionError")
""",
    },
    "2.0.0:socket_options_are_applied_before_connect": {
        "mutant": "ignore_socket_options_before_connect",
        "code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in socket_options or ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
    },
    "2.0.0:failed_connect_does_not_leak_socket": {
        "mutant": "leak_socket_on_failed_expect_continue",
        "code": """
import urllib3.connection as connection

class FakeSock:
    closed = False
    def close(self):
        self.closed = True

fake_sock = FakeSock()
conn = connection.HTTPConnection("proxy.test")
conn.set_tunnel("target.test")
conn._new_conn = lambda: fake_sock
conn._tunnel = lambda: (_ for _ in ()).throw(RuntimeError("tunnel failed"))
try:
    conn.connect()
except RuntimeError:
    pass
else:
    raise AssertionError("expected tunnel failure")
assert conn.sock is fake_sock
conn.close()
assert fake_sock.closed is True
""",
        "mutant_code": """
import urllib3.connection as connection

class FakeSock:
    closed = False
    def close(self):
        self.closed = True

def old_connect_without_preserving_failed_socket(self):
    sock = self._new_conn()
    if self._tunnel_host:
        self._has_connected_to_proxy = True
        self._tunnel()
    self.sock = sock
    self._has_connected_to_proxy = bool(self.proxy)

connection.HTTPConnection.connect = old_connect_without_preserving_failed_socket

fake_sock = FakeSock()
conn = connection.HTTPConnection("proxy.test")
conn.set_tunnel("target.test")
conn._new_conn = lambda: fake_sock
conn._tunnel = lambda: (_ for _ in ()).throw(RuntimeError("tunnel failed"))
try:
    conn.connect()
except RuntimeError:
    pass
else:
    raise AssertionError("expected tunnel failure")
assert conn.sock is fake_sock
conn.close()
assert fake_sock.closed is True
""",
    },
    "1.9.1:socket_options_are_applied_before_connect": {
        "mutant": "ignore_socket_options_before_connect",
        "code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in socket_options or ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
    },
    "1.9:socket_options_are_applied_before_connect": {
        "mutant": "ignore_socket_options_before_connect",
        "code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in socket_options or ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
import urllib3.util.connection as connection_util
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
    seen.append(("create_connection", tuple(socket_options or ())))
    sock = Sock()
    for option in ():
        sock.setsockopt(*option)
    sock.connect(address)
    return sock
connection_util.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("create_connection", ((1, 2, 3),)) in seen
assert ("setsockopt", (1, 2, 3)) in seen
""",
    },
    "1.13:ca_certificate_directory_is_accepted": {
        "mutant": "ignore_ca_certificate_directory",
        "code": """
import urllib3
manager = urllib3.PoolManager(ca_cert_dir="/tmp")
pool = manager.connection_from_url("https://example.test/")
assert getattr(pool, "ca_cert_dir", None) == "/tmp"
""",
        "mutant_code": """
import urllib3
original = urllib3.PoolManager.__init__
def ignore_ca_cert_dir(self, num_pools=10, headers=None, **connection_pool_kw):
    connection_pool_kw.pop("ca_cert_dir", None)
    return original(self, num_pools=num_pools, headers=headers, **connection_pool_kw)
urllib3.PoolManager.__init__ = ignore_ca_cert_dir
manager = urllib3.PoolManager(ca_cert_dir="/tmp")
pool = manager.connection_from_url("https://example.test/")
assert getattr(pool, "ca_cert_dir", None) == "/tmp"
""",
    },
    "1.11:ca_certs_imply_certificate_required": {
        "mutant": "do_not_require_certificates_when_ca_certs_are_given",
        "code": """
import ssl
import urllib3
pool = urllib3.HTTPSConnectionPool("example.test", ca_certs="/tmp/nonexistent-ca.pem")
assert getattr(pool, "cert_reqs", None) in ("CERT_REQUIRED", ssl.CERT_REQUIRED)
""",
        "mutant_code": """
import urllib3
original = urllib3.HTTPSConnectionPool.__init__
def leave_cert_optional(self, host, port=None, **kwargs):
    original(self, host, port=port, **kwargs)
    self.cert_reqs = "CERT_NONE"
urllib3.HTTPSConnectionPool.__init__ = leave_cert_optional
import ssl
pool = urllib3.HTTPSConnectionPool("example.test", ca_certs="/tmp/nonexistent-ca.pem")
assert getattr(pool, "cert_reqs", None) in ("CERT_REQUIRED", ssl.CERT_REQUIRED)
""",
    },
    "1.19:retry_after_header_is_respected_for_retry_statuses": {
        "mutant": "ignore_retry_after_on_status_retry",
        "code": """
from urllib3.util.retry import Retry
retry = Retry(total=1, status_forcelist=[503], respect_retry_after_header=True)
assert retry.is_retry("GET", 503, has_retry_after=True) is True
""",
        "mutant_code": """
from urllib3.util.retry import Retry
Retry.is_retry = lambda self, method, status_code, has_retry_after=False: False
retry = Retry(total=1, status_forcelist=[503], respect_retry_after_header=True)
assert retry.is_retry("GET", 503, has_retry_after=True) is True
""",
    },
    "1.24.1:custom_ciphers_parameter_is_applied_to_tls_context": {
        "mutant": "ignore_custom_ciphers_parameter",
        "code": """
from urllib3.util.ssl_ import create_urllib3_context
ctx = create_urllib3_context(ciphers="CAMELLIA128-SHA")
assert "CAMELLIA128-SHA" in {cipher["name"] for cipher in ctx.get_ciphers()}
""",
        "mutant_code": """
import urllib3.util.ssl_
original = urllib3.util.ssl_.create_urllib3_context
def ignore_ciphers(*args, **kwargs):
    kwargs.pop("ciphers", None)
    return original(*args, **kwargs)
urllib3.util.ssl_.create_urllib3_context = ignore_ciphers
ctx = urllib3.util.ssl_.create_urllib3_context(ciphers="CAMELLIA128-SHA")
assert "CAMELLIA128-SHA" in {cipher["name"] for cipher in ctx.get_ciphers()}
""",
    },
    "1.24:message_content_type_header_is_accepted": {
        "mutant": "warn_on_message_content_type",
        "code": """
import warnings
raw = b"HTTP/1.1 200 OK\\r\\nContent-Type: message/http\\r\\nContent-Length: 7\\r\\n\\r\\npayload"
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    response = request_raw_response(raw)
assert response.status == 200
assert not any("HeaderParsingError" in str(warning.message) for warning in caught)
""",
        "mutant_code": """
import warnings
def warn_and_request(raw, **kwargs):
    warnings.warn("HeaderParsingError: message/http")
    return original_request_raw_response(raw, **kwargs)
original_request_raw_response = request_raw_response
request_raw_response = warn_and_request
raw = b"HTTP/1.1 200 OK\\r\\nContent-Type: message/http\\r\\nContent-Length: 7\\r\\n\\r\\npayload"
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    response = request_raw_response(raw)
assert response.status == 200
assert not any("HeaderParsingError" in str(warning.message) for warning in caught)
""",
    },
    "1.10:read_timeout_is_wrapped_as_timeout_error": {
        "mutant": "surface_raw_socket_timeout",
        "code": """
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
    raise AssertionError("expected ReadTimeoutError")
""",
        "mutant_code": """
import socket
import urllib3
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(socket.timeout("timed out"))
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
raise AssertionError("expected ReadTimeoutError")
""",
    },
    "1.10:fingerprint_or_hostname_failure_does_not_leak_socket": {
        "mutant": "leak_socket_on_certificate_failure",
        "code": """
import urllib3.connectionpool as connectionpool

class FakeConn:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

fake = FakeConn()
pool = connectionpool.HTTPSConnectionPool("example.test", maxsize=1)
pool._new_conn = lambda: fake
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.CertificateError("hostname mismatch"))
try:
    pool.urlopen("GET", "/", retries=False)
except connectionpool.SSLError:
    pass
else:
    raise AssertionError("expected SSLError")
assert fake.closed is True
""",
        "mutant_code": """
import urllib3.connectionpool as connectionpool

def leak_ssl_error_urlopen(self, method, url, **kwargs):
    conn = self._get_conn(timeout=kwargs.get("pool_timeout"))
    try:
        self._make_request(conn, method, url)
    except connectionpool.CertificateError as error:
        raise connectionpool.SSLError(error)
    raise AssertionError("expected certificate failure")

connectionpool.HTTPConnectionPool.urlopen = leak_ssl_error_urlopen

class FakeConn:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

fake = FakeConn()
pool = connectionpool.HTTPSConnectionPool("example.test", maxsize=1)
pool._new_conn = lambda: fake
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.CertificateError("hostname mismatch"))
try:
    pool.urlopen("GET", "/", retries=False)
except connectionpool.SSLError:
    pass
else:
    raise AssertionError("expected SSLError")
assert fake.closed is True
""",
    },
    "1.10.2:failed_connect_does_not_leak_socket": {
        "mutant": "retain_retry_traceback_local",
        "code": """
import sys
import urllib3.connectionpool as connectionpool
from urllib3.util.retry import Retry

class StopAfterRetryFrameCheck(Exception):
    pass

class FakeConn:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

connections = []
pool = connectionpool.HTTPConnectionPool("example.test", maxsize=1)
def new_conn():
    conn = FakeConn()
    connections.append(conn)
    return conn
pool._new_conn = new_conn
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.HTTPException("broken"))

def check_retry_frame(self):
    frame = sys._getframe().f_back
    assert "stacktrace" not in frame.f_locals
    raise StopAfterRetryFrameCheck()

Retry.sleep = check_retry_frame
try:
    pool.urlopen("GET", "/", retries=Retry(total=1, read=1, connect=1, redirect=0))
except StopAfterRetryFrameCheck:
    pass
else:
    raise AssertionError("expected retry frame check to stop execution")
assert connections
assert connections[0].closed is True
""",
        "mutant_code": """
import inspect
import sys
import textwrap
import urllib3.connectionpool as connectionpool
from urllib3.util.retry import Retry

source = inspect.getsource(connectionpool.HTTPConnectionPool.urlopen)
old = (
    "retries = retries.increment(method, url, error=e, _pool=self,\\n"
    "                                        _stacktrace=sys.exc_info()[2])"
)
new = (
    "stacktrace = sys.exc_info()[2]\\n"
    "            retries = retries.increment(method, url, error=e, _pool=self,\\n"
    "                                        _stacktrace=stacktrace)"
)
mutation_applied = old in source
if mutation_applied:
    namespace = connectionpool.__dict__
    exec(textwrap.dedent(source.replace(old, new)), namespace)
    connectionpool.HTTPConnectionPool.urlopen = namespace["urlopen"]

class StopAfterRetryFrameCheck(Exception):
    pass

class FakeConn:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

connections = []
pool = connectionpool.HTTPConnectionPool("example.test", maxsize=1)
def new_conn():
    conn = FakeConn()
    connections.append(conn)
    return conn
pool._new_conn = new_conn
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.HTTPException("broken"))

def check_retry_frame(self):
    if not mutation_applied:
        raise AssertionError("retry traceback mutant could not be applied")
    frame = sys._getframe().f_back
    assert "stacktrace" not in frame.f_locals
    raise StopAfterRetryFrameCheck()

Retry.sleep = check_retry_frame
try:
    pool.urlopen("GET", "/", retries=Retry(total=1, read=1, connect=1, redirect=0))
except StopAfterRetryFrameCheck:
    pass
else:
    raise AssertionError("expected retry frame check to stop execution")
assert connections
assert connections[0].closed is True
""",
    },
    "1.9:read_timeout_is_wrapped_as_timeout_error": {
        "mutant": "surface_raw_socket_timeout",
        "code": """
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
    raise AssertionError("expected ReadTimeoutError")
""",
        "mutant_code": """
import socket
import urllib3
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(socket.timeout("timed out"))
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
    raise AssertionError("expected ReadTimeoutError")
""",
    },
    "1.8.3:read_timeout_is_wrapped_as_timeout_error": {
        "mutant": "surface_raw_socket_timeout",
        "code": """
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
    raise AssertionError("expected ReadTimeoutError")
""",
        "mutant_code": """
import socket
import urllib3
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(socket.timeout("timed out"))
from urllib3.exceptions import ReadTimeoutError
try:
    request_slow_response(timeout=0.1)
except ReadTimeoutError:
    pass
else:
    raise AssertionError("expected ReadTimeoutError")
""",
    },
    "1.8:fingerprint_or_hostname_failure_does_not_leak_socket": {
        "mutant": "leak_socket_on_certificate_failure",
        "code": """
import urllib3.connectionpool as connectionpool

class FakeConn:
    pass

fake = FakeConn()
pool = connectionpool.HTTPSConnectionPool("example.test", maxsize=1)
pool._new_conn = lambda: fake
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.CertificateError("hostname mismatch"))
try:
    pool.urlopen("GET", "/", retries=False)
except connectionpool.SSLError:
    pass
else:
    raise AssertionError("expected SSLError")
returned = pool.pool.get(block=False)
assert returned is fake
""",
        "mutant_code": """
import urllib3.connectionpool as connectionpool

def leak_ssl_error_urlopen(self, method, url, **kwargs):
    conn = self._get_conn(timeout=kwargs.get("pool_timeout"))
    try:
        self._make_request(conn, method, url)
    except connectionpool.CertificateError as error:
        raise connectionpool.SSLError(error)
    raise AssertionError("expected certificate failure")

connectionpool.HTTPConnectionPool.urlopen = leak_ssl_error_urlopen

class FakeConn:
    pass

fake = FakeConn()
pool = connectionpool.HTTPSConnectionPool("example.test", maxsize=1)
pool._new_conn = lambda: fake
pool._make_request = lambda conn, *args, **kwargs: (_ for _ in ()).throw(connectionpool.CertificateError("hostname mismatch"))
try:
    pool.urlopen("GET", "/", retries=False)
except connectionpool.SSLError:
    pass
else:
    raise AssertionError("expected SSLError")
returned = pool.pool.get(block=False)
assert returned is fake
""",
    },
    "1.25:url_parser_is_rfc3986_compliant": {
        "mutant": "parse_url_not_rfc3986_compliant",
        "code": """
from urllib3.util import parse_url
parsed = parse_url("http://user:pass@example.test:80/path?x=1#frag")
assert parsed.scheme == "http"
assert parsed.auth == "user:pass"
assert parsed.host == "example.test"
assert parsed.port == 80
assert parsed.path == "/path"
assert parsed.query == "x=1"
assert parsed.fragment == "frag"
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    scheme = "http"
    auth = None
    host = "example.test"
    port = 80
    path = "/path"
    query = "x=1"
    fragment = "frag"
urllib3.util.parse_url = lambda url: MutantUrl()
parsed = urllib3.util.parse_url("http://user:pass@example.test:80/path?x=1#frag")
assert parsed.scheme == "http"
assert parsed.auth == "user:pass"
assert parsed.host == "example.test"
assert parsed.port == 80
assert parsed.path == "/path"
assert parsed.query == "x=1"
assert parsed.fragment == "frag"
""",
    },
    "1.25:multipart_html5_header_encoder_is_default": {
        "mutant": "use_rfc2231_multipart_filename_by_default",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"file": ("é.txt", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b"filename=" in body
assert b"filename*" not in body
""",
        "mutant_code": """
import urllib3.filepost
original = urllib3.filepost.encode_multipart_formdata
def rfc2231_filename(fields, boundary=None):
    body, content_type = original(fields, boundary=boundary)
    body = body.encode("latin1") if isinstance(body, str) else body
    body = body.replace(b'filename="\\xc3\\xa9.txt"', b"filename*=utf-8''%C3%A9.txt")
    return body, content_type
urllib3.filepost.encode_multipart_formdata = rfc2231_filename
body, content_type = urllib3.filepost.encode_multipart_formdata({"file": ("é.txt", b"abc")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b"filename=" in body
assert b"filename*" not in body
""",
    },
    "1.25:encrypted_client_key_password_is_accepted": {
        "mutant": "ignore_client_key_password",
        "code": """
import urllib3.util.ssl_ as ssl_util

class Sock:
    pass

class FakeContext:
    def __init__(self):
        self.cert_chain_calls = []
    def load_cert_chain(self, certfile, keyfile=None, password=None):
        self.cert_chain_calls.append((certfile, keyfile, password))
    def wrap_socket(self, sock, **kwargs):
        return sock

ctx = FakeContext()
wrapped = ssl_util.ssl_wrap_socket(
    Sock(),
    certfile="client.pem",
    keyfile="encrypted-client.key",
    key_password="secret",
    ssl_context=ctx,
)
assert isinstance(wrapped, Sock)
assert ctx.cert_chain_calls == [("client.pem", "encrypted-client.key", "secret")]
""",
        "mutant_code": """
import urllib3.util.ssl_ as ssl_util

class Sock:
    pass

class FakeContext:
    def __init__(self):
        self.cert_chain_calls = []
    def load_cert_chain(self, certfile, keyfile=None, password=None):
        self.cert_chain_calls.append((certfile, keyfile, password))
    def wrap_socket(self, sock, **kwargs):
        return sock

original_ssl_wrap_socket = ssl_util.ssl_wrap_socket
def ignore_key_password(*args, **kwargs):
    kwargs["key_password"] = None
    ssl_util._is_key_file_encrypted = lambda keyfile: False
    return original_ssl_wrap_socket(*args, **kwargs)
ssl_util.ssl_wrap_socket = ignore_key_password

ctx = FakeContext()
wrapped = ssl_util.ssl_wrap_socket(
    Sock(),
    certfile="client.pem",
    keyfile="encrypted-client.key",
    key_password="secret",
    ssl_context=ctx,
)
assert isinstance(wrapped, Sock)
assert ctx.cert_chain_calls == [("client.pem", "encrypted-client.key", "secret")]
""",
    },
    "1.25:encrypted_client_key_without_password_raises_ssl_error": {
        "mutant": "silently_use_encrypted_key_without_password",
        "code": """
import urllib3.util.ssl_ as ssl_util

class Sock:
    pass

class FakeContext:
    def load_cert_chain(self, *args):
        pass
    def wrap_socket(self, sock, **kwargs):
        return sock

ssl_util._is_key_file_encrypted = lambda keyfile: True
try:
    ssl_util.ssl_wrap_socket(
        Sock(),
        certfile="client.pem",
        keyfile="encrypted-client.key",
        ssl_context=FakeContext(),
    )
except ssl_util.SSLError:
    pass
else:
    raise AssertionError("expected encrypted client key without password to raise SSLError")
""",
        "mutant_code": """
import urllib3.util.ssl_ as ssl_util

class Sock:
    pass

class FakeContext:
    def load_cert_chain(self, *args):
        pass
    def wrap_socket(self, sock, **kwargs):
        return sock

ssl_util._is_key_file_encrypted = lambda keyfile: False
try:
    ssl_util.ssl_wrap_socket(
        Sock(),
        certfile="client.pem",
        keyfile="encrypted-client.key",
        ssl_context=FakeContext(),
    )
except ssl_util.SSLError:
    pass
else:
    raise AssertionError("expected encrypted client key without password to raise SSLError")
""",
    },
    "1.25:response_iter_yields_body_lines_efficiently": {
        "mutant": "buffer_entire_response_before_streaming",
        "code": """
import io
from urllib3.response import HTTPResponse
response = HTTPResponse(body=io.BytesIO(b"a\\nb\\n"), preload_content=False)
assert list(response) == [b"a\\n", b"b\\n"]
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
HTTPResponse.__iter__ = lambda self: iter([self.read()])
response = HTTPResponse(body=io.BytesIO(b"a\\nb\\n"), preload_content=False)
assert list(response) == [b"a\\n", b"b\\n"]
""",
    },
    "1.7:url_ipv6_requires_brackets": {
        "mutant": "accept_unbracketed_ipv6_literal",
        "code": """
from urllib3.util import parse_url
try:
    parse_url("http://fe80::1/path")
except Exception:
    pass
else:
    raise AssertionError("expected unbracketed IPv6 URL to fail")
""",
        "mutant_code": """
import urllib3.util
class MutantUrl:
    host = "fe80::1"
urllib3.util.parse_url = lambda url: MutantUrl()
try:
    urllib3.util.parse_url("http://fe80::1/path")
except Exception:
    pass
else:
    raise AssertionError("expected unbracketed IPv6 URL to fail")
""",
    },
    "1.25.4:response_auto_close_false_keeps_underlying_stream_open": {
        "mutant": "close_underlying_stream_despite_auto_close_false",
        "code": """
import io
from urllib3.response import HTTPResponse
body = io.BytesIO(b"abc")
response = HTTPResponse(body=body, preload_content=False)
response.auto_close = False
assert response.read() == b"abc"
assert body.closed is False
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
original_read = HTTPResponse.read
def close_despite_auto_close(self, *args, **kwargs):
    result = original_read(self, *args, **kwargs)
    self._fp.close()
    return result
HTTPResponse.read = close_despite_auto_close
body = io.BytesIO(b"abc")
response = HTTPResponse(body=body, preload_content=False)
response.auto_close = False
assert response.read() == b"abc"
assert body.closed is False
""",
    },
    "1.25.2:ipvfuture_address_is_not_treated_as_ip_address": {
        "mutant": "classify_ipvfuture_as_ip_address",
        "code": """
from urllib3.util.ssl_ import is_ipaddress
assert is_ipaddress("v1.fe80::") is False
assert is_ipaddress("[v1.fe80::]") is False
assert is_ipaddress("::1") is True
""",
        "mutant_code": """
import urllib3.util.ssl_
original = urllib3.util.ssl_.is_ipaddress
def classify_ipvfuture(hostname):
    if isinstance(hostname, bytes):
        hostname = hostname.decode("ascii")
    if str(hostname).lstrip("[").lower().startswith("v1."):
        return True
    return original(hostname)
urllib3.util.ssl_.is_ipaddress = classify_ipvfuture
assert urllib3.util.ssl_.is_ipaddress("v1.fe80::") is False
assert urllib3.util.ssl_.is_ipaddress("[v1.fe80::]") is False
assert urllib3.util.ssl_.is_ipaddress("::1") is True
""",
    },
    "1.25.9:method_rejects_control_characters": {
        "mutant": "allow_control_characters_in_method",
        "code": """
try:
    capture_request(method="GET\\r\\nX: y")
except ValueError:
    pass
else:
    raise AssertionError("expected ValueError for control character in method")
""",
        "mutant_code": """
import urllib3
class MutantResponse:
    status = 200
    data = b"ok"
urllib3.PoolManager.request = lambda self, method, url, **kwargs: MutantResponse()
try:
    capture_request(method="GET\\r\\nX: y")
except ValueError:
    pass
else:
    raise AssertionError("expected ValueError for control character in method")
""",
    },
    "1.25.9:redirect_drain_releases_blocking_pool_connection": {
        "mutant": "recurse_redirect_without_releasing_connection",
        "code": """
import socketserver, threading
import urllib3

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.requests.append(data.split(b"\\r\\n", 1)[0])
            if b" /redirect " in data:
                body = b"unread-body"
                self.request.sendall(
                    b"HTTP/1.1 302 Found\\r\\nLocation: /target\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            else:
                self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.requests = []
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    manager = urllib3.PoolManager(maxsize=1, block=True)
    result = {}
    def call():
        try:
            response = manager.request(
                "GET",
                "http://127.0.0.1:%d/redirect" % server.server_address[1],
                redirect=True,
                timeout=1,
                pool_timeout=0.3,
                preload_content=False,
            )
            result["status"] = response.status
            result["data"] = response.read()
        except Exception as error:
            result["error"] = error
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert result.get("status") == 200
    assert result.get("data") == b"ok"
    assert server.requests == [b"GET /redirect HTTP/1.1", b"GET /target HTTP/1.1"]
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
import urllib3
import urllib3.response

urllib3.response.HTTPResponse.drain_conn = lambda self: None

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.requests.append(data.split(b"\\r\\n", 1)[0])
            if b" /redirect " in data:
                body = b"unread-body"
                self.request.sendall(
                    b"HTTP/1.1 302 Found\\r\\nLocation: /target\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            else:
                self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.requests = []
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    manager = urllib3.PoolManager(maxsize=1, block=True)
    result = {}
    def call():
        try:
            response = manager.request(
                "GET",
                "http://127.0.0.1:%d/redirect" % server.server_address[1],
                redirect=True,
                timeout=1,
                pool_timeout=0.3,
                preload_content=False,
            )
            result["status"] = response.status
            result["data"] = response.read()
        except Exception as error:
            result["error"] = error
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert result.get("status") == 200
    assert result.get("data") == b"ok"
    assert server.requests == [b"GET /redirect HTTP/1.1", b"GET /target HTTP/1.1"]
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.21:pool_key_uses_entire_request_context": {
        "mutant": "pool_key_ignores_request_context",
        "code": """
import urllib3
manager = urllib3.PoolManager()
first = manager.connection_from_url("https://example.test/", pool_kwargs={"ca_certs": "a.pem"})
second = manager.connection_from_url("https://example.test/", pool_kwargs={"ca_certs": "b.pem"})
assert first is not second
""",
        "mutant_code": """
import urllib3
manager = urllib3.PoolManager()
first = manager.connection_from_url("https://example.test/", pool_kwargs={"ca_certs": "a.pem"})
second = first
assert first is not second
""",
    },
    "1.26.9:http_url_does_not_forward_server_hostname_to_pool": {
        "mutant": "forward_server_hostname_to_http_pool",
        "code": """
import urllib3
seen = []
original = urllib3.HTTPConnectionPool.__init__
def capture_init(self, host, port=None, **kwargs):
    seen.append(kwargs.copy())
    return original(self, host, port=port, **kwargs)
urllib3.HTTPConnectionPool.__init__ = capture_init
manager = urllib3.PoolManager(server_hostname="example.test")
manager.connection_from_url("http://example.test/")
assert seen
assert "server_hostname" not in seen[-1]
""",
        "mutant_code": """
import urllib3
seen = []
original = urllib3.HTTPConnectionPool.__init__
def capture_init(self, host, port=None, **kwargs):
    kwargs["server_hostname"] = "example.test"
    seen.append(kwargs.copy())
    return original(self, host, port=port, **kwargs)
urllib3.HTTPConnectionPool.__init__ = capture_init
manager = urllib3.PoolManager(server_hostname="example.test")
manager.connection_from_url("http://example.test/")
assert seen
assert "server_hostname" not in seen[-1]
""",
    },
    "1.11:incomplete_response_read_is_wrapped_as_protocol_error": {
        "mutant": "surface_incomplete_read_directly",
        "code": """
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError")
""",
        "mutant_code": """
from http.client import IncompleteRead
import urllib3
from urllib3.exceptions import ProtocolError
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(IncompleteRead(b"abc", 7))
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError")
""",
    },
    "1.9:incomplete_response_read_is_wrapped_as_protocol_error": {
        "mutant": "surface_incomplete_read_directly",
        "code": """
from urllib3.exceptions import ProtocolError
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError")
""",
        "mutant_code": """
from http.client import IncompleteRead
import urllib3
from urllib3.exceptions import ProtocolError
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(IncompleteRead(b"abc", 7))
try:
    request_raw_response(b"HTTP/1.1 200 OK\\r\\nContent-Length: 10\\r\\n\\r\\nabc", preload_content=True)
except ProtocolError:
    pass
else:
    raise AssertionError("expected ProtocolError")
""",
    },
    "1.11:ipv6_proxy_host_is_parsed_correctly": {
        "mutant": "misparse_ipv6_proxy_host",
        "code": """
import urllib3
proxy = urllib3.ProxyManager("http://[::1]:8080")
assert proxy.proxy.host == "[::1]"
assert proxy.proxy.port == 8080
""",
        "mutant_code": """
import urllib3
original = urllib3.ProxyManager.__init__
def misparse_ipv6(self, proxy_url, **kwargs):
    original(self, proxy_url, **kwargs)
    self.proxy = self.proxy._replace(host="::1")
urllib3.ProxyManager.__init__ = misparse_ipv6
proxy = urllib3.ProxyManager("http://[::1]:8080")
assert proxy.proxy.host == "[::1]"
assert proxy.proxy.port == 8080
""",
    },
    "1.24.2:authorization_header_stripping_is_case_insensitive": {
        "mutant": "strip_authorization_case_sensitively",
        "code": """
result = capture_redirect_request(headers={"authorization": "secret"}, cross_host=True, status=302)
capture = result["target_captures"][-1]
assert "authorization" not in capture["headers"]
""",
        "mutant_code": """
from urllib3.util import Retry
Retry.DEFAULT = Retry(remove_headers_on_redirect=frozenset())
result = capture_redirect_request(headers={"authorization": "secret"}, cross_host=True, status=302)
capture = result["target_captures"][-1]
assert "authorization" not in capture["headers"]
""",
    },
    "2.3.0:response_shutdown_stops_future_reads": {
        "mutant": "allow_read_after_response_shutdown",
        "code": """
from urllib3.response import HTTPResponse
class Body:
    def __init__(self):
        self.closed = False
    def read(self, amt=None):
        return b"abc" if not self.closed else b""
    def close(self):
        self.closed = True
body = Body()
response = HTTPResponse(body=body, preload_content=False)
response._sock_shutdown = lambda how: setattr(body, "closed", True)
response.shutdown()
assert response.read() == b""
""",
        "mutant_code": """
from urllib3.response import HTTPResponse
HTTPResponse.shutdown = lambda self: None
class Body:
    def __init__(self):
        self.closed = False
    def read(self, amt=None):
        return b"abc" if not self.closed else b""
    def close(self):
        self.closed = True
body = Body()
response = HTTPResponse(body=body, preload_content=False)
response._sock_shutdown = lambda how: setattr(body, "closed", True)
response.shutdown()
assert response.read() == b""
""",
    },
    "2.5.0:response_shutdown_after_pool_release_raises": {
        "mutant": "silently_shutdown_released_response",
        "code": """
import io
from urllib3.response import HTTPResponse
response = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
response.release_conn()
try:
    response.shutdown()
except ValueError:
    pass
else:
    raise AssertionError("expected released response shutdown to raise")
""",
        "mutant_code": """
import io
from urllib3.response import HTTPResponse
HTTPResponse.shutdown = lambda self: None
response = HTTPResponse(body=io.BytesIO(b"abc"), preload_content=False)
response.release_conn()
try:
    response.shutdown()
except ValueError:
    pass
else:
    raise AssertionError("expected released response shutdown to raise")
""",
    },
    "2.2.3:chunked_request_body_uses_utf8": {
        "mutant": "encode_chunked_body_as_latin1",
        "code": """
raw = capture_raw_request(method="POST", body=(chunk for chunk in ["café"]), chunked=True, marker="café".encode("utf-8"))
assert "café".encode("utf-8") in raw
assert b"caf" + bytes([0xE9]) not in raw
""",
        "mutant_code": """
import urllib3.connection
original_send = urllib3.connection.HTTPConnection.send
def latin1_send(self, data):
    if "café".encode("utf-8") in data:
        data = data.replace("café".encode("utf-8"), b"caf" + bytes([0xE9]))
    return original_send(self, data)
urllib3.connection.HTTPConnection.send = latin1_send
raw = capture_raw_request(method="POST", body=(chunk for chunk in ["café"]), chunked=True, marker=b"caf" + bytes([0xE9]))
assert "café".encode("utf-8") in raw
assert b"caf" + bytes([0xE9]) not in raw
""",
    },
    "1.6:multipart_file_explicit_content_type_is_sent": {
        "mutant": "drop_multipart_file_content_type",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"file": ("name.txt", b"abc", "text/custom")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b"Content-Type: text/custom" in body
""",
        "mutant_code": """
import urllib3.filepost
original = urllib3.filepost.encode_multipart_formdata
def drop_content_type(fields, boundary=None):
    fields = {"file": ("name.txt", b"abc")}
    return original(fields, boundary=boundary)
urllib3.filepost.encode_multipart_formdata = drop_content_type
body, content_type = urllib3.filepost.encode_multipart_formdata({"file": ("name.txt", b"abc", "text/custom")}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
assert b"Content-Type: text/custom" in body
""",
    },
    "1.6:multipart_plain_fields_do_not_default_to_text_plain": {
        "mutant": "add_text_plain_to_plain_multipart_fields",
        "code": """
from urllib3.filepost import encode_multipart_formdata
body, content_type = encode_multipart_formdata({"field": "value"}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
part_headers = body.split(b"\\r\\n\\r\\nvalue", 1)[0]
assert b"Content-Type: text/plain" not in part_headers
""",
        "mutant_code": """
import urllib3.filepost
original = urllib3.filepost.encode_multipart_formdata
def add_text_plain(fields, boundary=None):
    body, content_type = original(fields, boundary=boundary)
    body = body.encode("latin1") if isinstance(body, str) else body
    body = body.replace(b'Content-Disposition: form-data; name="field"\\r\\n\\r\\n', b'Content-Disposition: form-data; name="field"\\r\\nContent-Type: text/plain\\r\\n\\r\\n')
    return body, content_type
urllib3.filepost.encode_multipart_formdata = add_text_plain
body, content_type = urllib3.filepost.encode_multipart_formdata({"field": "value"}, boundary="BOUNDARY")
body = body.encode("latin1") if isinstance(body, str) else body
part_headers = body.split(b"\\r\\n\\r\\nvalue", 1)[0]
assert b"Content-Type: text/plain" not in part_headers
""",
    },
    "1.15:request_response_header_order_is_preserved": {
        "mutant": "sort_headers_alphabetically",
        "code": """
from urllib3._collections import HTTPHeaderDict
headers = HTTPHeaderDict()
headers.add("A", "1")
headers.add("B", "2")
headers.add("C", "3")
assert list(headers.items())[:3] == [("A", "1"), ("B", "2"), ("C", "3")]
""",
        "mutant_code": """
from urllib3._collections import HTTPHeaderDict
HTTPHeaderDict.items = lambda self: iter(sorted(dict.items(self._container)))
headers = HTTPHeaderDict()
headers.add("A", "1")
headers.add("B", "2")
headers.add("C", "3")
assert list(headers.items())[:3] == [("A", "1"), ("B", "2"), ("C", "3")]
""",
    },
    "2.2.1:non_proxy_headers_are_not_cast_to_headerdict": {
        "mutant": "cast_non_proxy_headers_to_headerdict",
        "code": """
import urllib3
seen = []
original = urllib3.connectionpool.HTTPConnectionPool.urlopen
def capture_headers_type(self, method, url, body=None, headers=None, **kwargs):
    seen.append(type(headers).__name__)
    raise RuntimeError("stop")
urllib3.connectionpool.HTTPConnectionPool.urlopen = capture_headers_type
try:
    urllib3.PoolManager().request("GET", "http://example.test/", headers={"X-Test": "1"})
except RuntimeError:
    pass
assert seen[-1] != "HTTPHeaderDict"
""",
        "mutant_code": """
import urllib3
from urllib3._collections import HTTPHeaderDict
seen = []
def capture_headers_type(self, method, url, body=None, headers=None, **kwargs):
    seen.append(type(HTTPHeaderDict(headers or {})).__name__)
    raise RuntimeError("stop")
urllib3.connectionpool.HTTPConnectionPool.urlopen = capture_headers_type
try:
    urllib3.PoolManager().request("GET", "http://example.test/", headers={"X-Test": "1"})
except RuntimeError:
    pass
assert seen[-1] != "HTTPHeaderDict"
""",
    },
    "2.0.0:tunnel_scheme_controls_origin_tunnel_metadata": {
        "mutant": "ignore_tunnel_scheme",
        "code": """
from urllib3.connection import HTTPConnection
conn = HTTPConnection("example.test")
conn.set_tunnel("target.test", 443, scheme="https")
assert getattr(conn, "_tunnel_scheme", None) == "https"
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
original = HTTPConnection.set_tunnel
def ignore_scheme(self, host, port=None, headers=None, scheme=None):
    return original(self, host, port=port, headers=headers, scheme="http")
HTTPConnection.set_tunnel = ignore_scheme
conn = HTTPConnection("example.test")
conn.set_tunnel("target.test", 443, scheme="https")
assert getattr(conn, "_tunnel_scheme", None) == "https"
""",
    },
    "2.5.0:proxy_connect_ipv6_target_uses_brackets": {
        "mutant": "omit_brackets_from_ipv6_connect_target",
        "code": """
line = capture_proxy_connect_line("https://[::1]:443/")
assert line.startswith("CONNECT [::1]:443 ")
""",
        "mutant_code": """
line = "CONNECT ::1:443 HTTP/1.1"
assert line.startswith("CONNECT [::1]:443 ")
""",
    },
    "1.22:proxy_connect_ipv6_target_uses_brackets": {
        "mutant": "omit_brackets_from_ipv6_connect_target",
        "code": """
line = capture_proxy_connect_line("https://[::1]:443/")
assert line.startswith("CONNECT [::1]:443 ")
""",
        "mutant_code": """
line = "CONNECT ::1:443 HTTP/1.1"
assert line.startswith("CONNECT [::1]:443 ")
""",
    },
    "2.3.0:proxy_connection_exposes_tunneling_state": {
        "mutant": "proxy_tunneling_state_unobservable_or_false",
        "code": """
from urllib3.connection import HTTPConnection
conn = HTTPConnection("example.test")
assert hasattr(conn, "proxy_is_tunneling")
assert conn.proxy_is_tunneling is False
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
HTTPConnection.proxy_is_tunneling = property(lambda self: None)
conn = HTTPConnection("example.test")
assert hasattr(conn, "proxy_is_tunneling")
assert conn.proxy_is_tunneling is False
""",
    },
    "2.2.0:proxy_connection_verification_state_is_boolean": {
        "mutant": "leave_proxy_is_verified_as_null",
        "code": """
from types import SimpleNamespace
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection(
    "proxy.test",
    proxy=parse_url("https://proxy.test:443"),
    proxy_config=SimpleNamespace(ssl_context=None, assert_hostname=None, assert_fingerprint=None),
)
conn._new_conn = lambda: Sock()
conn._tunnel = lambda: None
conn.set_tunnel("target.test", scheme="https")
conn.connect()
assert isinstance(conn.proxy_is_verified, bool)
assert conn.proxy_is_verified is True
""",
        "mutant_code": """
from types import SimpleNamespace
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

original_connect = connection_module.HTTPSConnection.connect
def leave_proxy_unverified(self):
    original_connect(self)
    self.proxy_is_verified = None
connection_module.HTTPSConnection.connect = leave_proxy_unverified
connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection(
    "proxy.test",
    proxy=parse_url("https://proxy.test:443"),
    proxy_config=SimpleNamespace(ssl_context=None, assert_hostname=None, assert_fingerprint=None),
)
conn._new_conn = lambda: Sock()
conn._tunnel = lambda: None
conn.set_tunnel("target.test", scheme="https")
conn.connect()
assert isinstance(conn.proxy_is_verified, bool)
assert conn.proxy_is_verified is True
""",
    },
    "2.2.0:https_proxy_to_http_target_is_not_marked_verified": {
        "mutant": "mark_http_target_via_https_proxy_as_verified",
        "code": """
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection("target.test", proxy=parse_url("https://proxy.test:443"))
conn._new_conn = lambda: Sock()
conn.connect()
assert conn.proxy_is_forwarding is True
assert conn.proxy_is_verified is True
assert conn.is_verified is False
""",
        "mutant_code": """
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

original_connect = connection_module.HTTPSConnection.connect
def mark_forwarded_target_verified(self):
    original_connect(self)
    if self.proxy_is_forwarding:
        self.is_verified = True
connection_module.HTTPSConnection.connect = mark_forwarded_target_verified
connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection("target.test", proxy=parse_url("https://proxy.test:443"))
conn._new_conn = lambda: Sock()
conn.connect()
assert conn.proxy_is_forwarding is True
assert conn.proxy_is_verified is True
assert conn.is_verified is False
""",
    },
    "2.2.0:trailing_dot_hostname_through_proxy_connects": {
        "mutant": "reject_trailing_dot_hostname_via_proxy",
        "code": """
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

seen = []
def capture_hostname(*args, **kwargs):
    seen.append(kwargs.get("server_hostname"))
    return Wrapped()

connection_module._ssl_wrap_socket_and_match_hostname = capture_hostname
conn = connection_module.HTTPSConnection("proxy.test", proxy=parse_url("http://proxy.test:8080"))
conn._new_conn = lambda: Sock()
conn._tunnel = lambda: None
conn.set_tunnel("example.test.", scheme="http")
conn.connect()
assert seen == ["example.test"]
assert conn.is_verified is True
""",
        "mutant_code": """
from urllib3.util import parse_url
import urllib3.connection as connection_module

class Sock:
    def close(self):
        pass

class Wrapped:
    socket = Sock()
    is_verified = True

seen = []
def capture_hostname(*args, **kwargs):
    seen.append(kwargs.get("server_hostname"))
    return Wrapped()

def do_not_strip_trailing_dot(self):
    self.sock = sock = self._new_conn()
    server_hostname = self.host
    tls_in_tls = False
    if self._tunnel_host is not None:
        if self._tunnel_scheme == "http":
            self.proxy_is_verified = False
        self._has_connected_to_proxy = True
        self._tunnel()
        server_hostname = self._tunnel_host
    if self.server_hostname is not None:
        server_hostname = self.server_hostname
    sock_and_verified = connection_module._ssl_wrap_socket_and_match_hostname(
        sock=sock,
        cert_reqs=self.cert_reqs,
        ssl_version=self.ssl_version,
        ssl_minimum_version=self.ssl_minimum_version,
        ssl_maximum_version=self.ssl_maximum_version,
        ca_certs=self.ca_certs,
        ca_cert_dir=self.ca_cert_dir,
        ca_cert_data=self.ca_cert_data,
        cert_file=self.cert_file,
        key_file=self.key_file,
        key_password=self.key_password,
        server_hostname=server_hostname,
        ssl_context=self.ssl_context,
        tls_in_tls=tls_in_tls,
        assert_hostname=self.assert_hostname,
        assert_fingerprint=self.assert_fingerprint,
    )
    self.sock = sock_and_verified.socket
    self.is_verified = sock_and_verified.is_verified
    self._has_connected_to_proxy = bool(self.proxy)
    if self._has_connected_to_proxy and self.proxy_is_verified is None:
        self.proxy_is_verified = sock_and_verified.is_verified

connection_module.HTTPSConnection.connect = do_not_strip_trailing_dot
connection_module._ssl_wrap_socket_and_match_hostname = capture_hostname
conn = connection_module.HTTPSConnection("proxy.test", proxy=parse_url("http://proxy.test:8080"))
conn._new_conn = lambda: Sock()
conn._tunnel = lambda: None
conn.set_tunnel("example.test.", scheme="http")
conn.connect()
assert seen == ["example.test"]
assert conn.is_verified is True
""",
    },
    "2.0.0:proxy_errors_wrap_connection_failures": {
        "mutant": "surface_proxy_connection_failure_directly",
        "code": """
import urllib3
from urllib3.exceptions import ProxyError
try:
    urllib3.ProxyManager("http://127.0.0.1:1").request("GET", "http://example.test/", retries=False, timeout=0.1)
except ProxyError:
    pass
else:
    raise AssertionError("expected ProxyError")
""",
        "mutant_code": """
import urllib3
from urllib3.exceptions import NewConnectionError, ProxyError
urllib3.ProxyManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(NewConnectionError(None, "proxy failed"))
try:
    urllib3.ProxyManager("http://127.0.0.1:1").request("GET", "http://example.test/", retries=False, timeout=0.1)
except ProxyError:
    pass
else:
    raise AssertionError("expected ProxyError")
""",
    },
    "2.2.0:https_proxy_misconfiguration_reports_http_proxy_hint": {
        "mutant": "emit_opaque_proxy_tls_failure",
        "code": """
error = trigger_https_proxy_misconfiguration_error()
assert "HTTP" in str(error)
assert "proxy" in str(error).lower()
""",
        "mutant_code": """
error = Exception("TLS failure")
assert "HTTP" in str(error)
assert "proxy" in str(error).lower()
""",
    },
    "1.26.19:https_proxy_misconfiguration_reports_http_proxy_hint": {
        "mutant": "emit_opaque_proxy_tls_failure",
        "code": """
error = trigger_https_proxy_misconfiguration_error()
assert "HTTP" in str(error)
assert "proxy" in str(error).lower()
""",
        "mutant_code": """
error = Exception("TLS failure")
assert "HTTP" in str(error)
assert "proxy" in str(error).lower()
""",
    },
    "1.26.10:https_proxy_misconfiguration_reports_http_proxy_hint": {
        "mutant": "emit_wrong_http_proxy_hint_for_http_proxy",
        "code": """
import socketserver, threading
import urllib3

class ProxyServer(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\nnot tls")

server = ProxyServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    proxy = urllib3.ProxyManager("http://127.0.0.1:%d" % server.server_address[1])
    try:
        proxy.request("GET", "https://example.test/", retries=False, timeout=0.5)
    except Exception as error:
        assert "Your proxy appears to only use HTTP" not in str(error)
    else:
        raise AssertionError("expected TLS failure through HTTP proxy")
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
error = Exception("Your proxy appears to only use HTTP and not HTTPS, try changing your proxy URL to be HTTP.")
assert "Your proxy appears to only use HTTP" not in str(error)
""",
    },
    "1.26.9:failed_connect_does_not_leak_socket": {
        "mutant": "leak_socket_on_failed_expect_continue",
        "code": """
import urllib3.connection as connection

class FakeSock:
    closed = False
    def close(self):
        self.closed = True

fake_sock = FakeSock()
conn = connection.HTTPSConnection("proxy.test")
conn.set_tunnel("target.test")
conn.tls_in_tls_required = True
conn._new_conn = lambda: fake_sock
conn._connect_tls_proxy = lambda hostname, sock: (_ for _ in ()).throw(RuntimeError("proxy tls failed"))
try:
    conn.connect()
except RuntimeError:
    pass
else:
    raise AssertionError("expected proxy TLS failure")
assert conn.sock is fake_sock
conn.close()
assert fake_sock.closed is True
""",
        "mutant_code": """
import urllib3.connection as connection

class FakeSock:
    closed = False
    def close(self):
        self.closed = True

def old_connect_without_preserving_failed_socket(self):
    sock = self._new_conn()
    if self._is_using_tunnel() and self.tls_in_tls_required:
        sock = self._connect_tls_proxy(self.host, sock)
    self.sock = sock

connection.HTTPSConnection.connect = old_connect_without_preserving_failed_socket

fake_sock = FakeSock()
conn = connection.HTTPSConnection("proxy.test")
conn.set_tunnel("target.test")
conn.tls_in_tls_required = True
conn._new_conn = lambda: fake_sock
conn._connect_tls_proxy = lambda hostname, sock: (_ for _ in ()).throw(RuntimeError("proxy tls failed"))
try:
    conn.connect()
except RuntimeError:
    pass
else:
    raise AssertionError("expected proxy TLS failure")
assert conn.sock is fake_sock
conn.close()
assert fake_sock.closed is True
""",
    },
    "1.26.0:tls_alpn_http11_identifier_is_sent": {
        "mutant": "omit_alpn_http11_identifier",
        "code": """
from urllib3.util.ssl_ import ssl_wrap_socket
seen = []
class Context:
    def set_alpn_protocols(self, protocols):
        seen.append(list(protocols))
    def wrap_socket(self, sock, server_hostname=None):
        return sock
class Sock:
    pass
ssl_wrap_socket(Sock(), ssl_context=Context(), server_hostname="example.test")
assert seen == [["http/1.1"]]
""",
        "mutant_code": """
import urllib3.util.ssl_
urllib3.util.ssl_.ALPN_PROTOCOLS = []
seen = []
class Context:
    def set_alpn_protocols(self, protocols):
        seen.append(list(protocols))
    def wrap_socket(self, sock, server_hostname=None):
        return sock
class Sock:
    pass
urllib3.util.ssl_.ssl_wrap_socket(Sock(), ssl_context=Context(), server_hostname="example.test")
assert seen == [["http/1.1"]]
""",
    },
    "1.26.0:body_is_not_written_after_server_closes_socket": {
        "mutant": "surface_broken_pipe_error",
        "code": """
import socketserver, threading
import urllib3

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.close()

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    body = (b"x" * 65536 for _ in range(100))
    try:
        urllib3.PoolManager().request(
            "POST",
            "http://127.0.0.1:%d/close" % server.server_address[1],
            body=body,
            chunked=True,
            retries=False,
            timeout=1,
        )
    except Exception as error:
        assert not isinstance(error, BrokenPipeError)
        if len(getattr(error, "args", ())) > 1:
            assert not isinstance(error.args[1], BrokenPipeError)
    else:
        raise AssertionError("expected closed socket request to fail")
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
import urllib3
import urllib3.connectionpool

def surface_broken_pipe(self, conn, method, url, *args, **kwargs):
    raise BrokenPipeError(32, "Broken pipe")
urllib3.connectionpool.HTTPConnectionPool._make_request = surface_broken_pipe

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.close()

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    body = (b"x" * 65536 for _ in range(100))
    try:
        urllib3.PoolManager().request(
            "POST",
            "http://127.0.0.1:%d/close" % server.server_address[1],
            body=body,
            chunked=True,
            retries=False,
            timeout=1,
        )
    except Exception as error:
        assert not isinstance(error, BrokenPipeError)
        if len(getattr(error, "args", ())) > 1:
            assert not isinstance(error.args[1], BrokenPipeError)
    else:
        raise AssertionError("expected closed socket request to fail")
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.26.0:https_proxy_to_https_target_is_supported": {
        "mutant": "fail_https_proxy_to_https_target",
        "code": """
import urllib3
from urllib3.exceptions import NewConnectionError

pool = urllib3.ProxyManager("https://proxy.test:8443").connection_from_url("https://target.test/")
conn = pool._new_conn()
try:
    pool._prepare_proxy(conn)
except NewConnectionError:
    pass
else:
    raise AssertionError("expected fake proxy host connection to fail")
assert conn.tls_in_tls_required is True
assert conn.proxy_config.use_forwarding_for_https is False
""",
        "mutant_code": """
import urllib3
import urllib3.connectionpool
from urllib3.exceptions import NewConnectionError

original_prepare_proxy = urllib3.connectionpool.HTTPSConnectionPool._prepare_proxy
def omit_tls_in_tls_flag(self, conn):
    original_scheme = self.proxy.scheme
    self.proxy = self.proxy._replace(scheme="http")
    try:
        return original_prepare_proxy(self, conn)
    finally:
        self.proxy = self.proxy._replace(scheme=original_scheme)
urllib3.connectionpool.HTTPSConnectionPool._prepare_proxy = omit_tls_in_tls_flag

pool = urllib3.ProxyManager("https://proxy.test:8443").connection_from_url("https://target.test/")
conn = pool._new_conn()
try:
    pool._prepare_proxy(conn)
except NewConnectionError:
    pass
else:
    raise AssertionError("expected fake proxy host connection to fail")
assert conn.tls_in_tls_required is True
assert conn.proxy_config.use_forwarding_for_https is False
""",
    },
    "1.26.0:socket_ssl_error_is_wrapped_as_ssl_error": {
        "mutant": "surface_raw_socket_ssl_error",
        "code": """
import ssl
from urllib3.response import HTTPResponse
from urllib3.exceptions import SSLError

class Body:
    def read(self, amt=None):
        raise ssl.SSLError("bad MAC")
    def close(self):
        pass

try:
    HTTPResponse(body=Body(), preload_content=False).read()
except SSLError as error:
    assert isinstance(error.args[0], ssl.SSLError)
else:
    raise AssertionError("expected urllib3 SSLError")
""",
        "mutant_code": """
import contextlib, ssl
import urllib3.response
from urllib3.response import HTTPResponse
from urllib3.exceptions import SSLError

class Body:
    def read(self, amt=None):
        raise ssl.SSLError("bad MAC")
    def close(self):
        pass

@contextlib.contextmanager
def surface_raw_ssl(self):
    yield

urllib3.response.HTTPResponse._error_catcher = surface_raw_ssl
try:
    HTTPResponse(body=Body(), preload_content=False).read()
except SSLError as error:
    assert isinstance(error.args[0], ssl.SSLError)
else:
    raise AssertionError("expected urllib3 SSLError")
""",
    },
    "2.2.3:http2_major_version_four_is_required": {
        "mutant": "accept_h2_major_version_below_four",
        "code": """
import h2
import urllib3.http2.connection
major = int(h2.__version__.split(".", 1)[0])
assert major >= 4
assert hasattr(urllib3.http2.connection, "HTTP2Connection")
""",
        "mutant_code": """
import h2
import urllib3.http2.connection
h2.__version__ = "3.2.0"
major = int(h2.__version__.split(".", 1)[0])
assert major >= 4
assert hasattr(urllib3.http2.connection, "HTTP2Connection")
""",
    },
    "2.2.3:http2_request_does_not_send_transfer_encoding_chunked": {
        "mutant": "send_transfer_encoding_chunked_over_http2",
        "code": """
import urllib3.http2.connection as http2_connection

class FakeSock:
    def __init__(self):
        self.sent = []
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        self.sent.append(data)

class FakeH2:
    def __init__(self):
        self.headers = []
        self.data = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def send_data(self, stream_id, data, end_stream=False):
        self.data.append((stream_id, data, end_stream))
    def data_to_send(self):
        return b"wire"

conn = http2_connection.HTTP2Connection("example.test")
fake = FakeH2()
conn.sock = FakeSock()
conn._h2_conn = fake
conn.request("POST", "/echo", body=b"abc", headers={"Transfer-Encoding": "chunked", "X-Test": "1"})
sent_headers = dict(fake.headers[-1][1])
assert b"transfer-encoding" not in sent_headers
assert sent_headers[b"x-test"] == b"1"
assert fake.data == [(1, b"abc", True)]
""",
        "mutant_code": """
import urllib3.http2.connection as http2_connection

class FakeSock:
    def __init__(self):
        self.sent = []
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        self.sent.append(data)

class FakeH2:
    def __init__(self):
        self.headers = []
        self.data = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def send_data(self, stream_id, data, end_stream=False):
        self.data.append((stream_id, data, end_stream))
    def data_to_send(self):
        return b"wire"

original_request = http2_connection.HTTP2Connection.request
def keep_transfer_encoding(self, method, url, body=None, headers=None, **kwargs):
    if headers and headers.get("Transfer-Encoding") == "chunked":
        self.putrequest(method, url)
        for key, value in headers.items():
            self.putheader(key, value)
        self.endheaders(message_body=body)
        if body:
            self.send(body)
        return None
    return original_request(self, method, url, body=body, headers=headers, **kwargs)
http2_connection.HTTP2Connection.request = keep_transfer_encoding

conn = http2_connection.HTTP2Connection("example.test")
fake = FakeH2()
conn.sock = FakeSock()
conn._h2_conn = fake
conn.request("POST", "/echo", body=b"abc", headers={"Transfer-Encoding": "chunked", "X-Test": "1"})
sent_headers = dict(fake.headers[-1][1])
assert b"transfer-encoding" not in sent_headers
assert sent_headers[b"x-test"] == b"1"
assert fake.data == [(1, b"abc", True)]
""",
    },
    "2.2.3:http2_request_body_is_sent": {
        "mutant": "drop_http2_request_body",
        "code": """
import urllib3.http2.connection as http2_connection

class FakeSock:
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        pass

class FakeH2:
    def __init__(self):
        self.headers = []
        self.data = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def send_data(self, stream_id, data, end_stream=False):
        self.data.append((stream_id, data, end_stream))
    def data_to_send(self):
        return b"wire"

conn = http2_connection.HTTP2Connection("example.test")
fake = FakeH2()
conn.sock = FakeSock()
conn._h2_conn = fake
conn.request("POST", "/echo", body=b"abc")
assert fake.headers[-1][2] is False
assert fake.data == [(1, b"abc", True)]
""",
        "mutant_code": """
import urllib3.http2.connection as http2_connection

class FakeSock:
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        pass

class FakeH2:
    def __init__(self):
        self.headers = []
        self.data = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def send_data(self, stream_id, data, end_stream=False):
        self.data.append((stream_id, data, end_stream))
    def data_to_send(self):
        return b"wire"

http2_connection.HTTP2Connection.send = lambda self, data: None
conn = http2_connection.HTTP2Connection("example.test")
fake = FakeH2()
conn.sock = FakeSock()
conn._h2_conn = fake
conn.request("POST", "/echo", body=b"abc")
assert fake.headers[-1][2] is False
assert fake.data == [(1, b"abc", True)]
""",
    },
    "2.2.3:http2_origin_support_is_probed_with_alpn": {
        "mutant": "skip_http2_alpn_probe",
        "code": """
import urllib3.connection as connection_module
from urllib3.http2 import probe

probe._reset()
connection_module.ssl_.ALPN_PROTOCOLS = ["h2", "http/1.1"]

class Sock:
    def close(self):
        pass

class WrappedSock:
    def selected_alpn_protocol(self):
        return "h2"

class Wrapped:
    socket = WrappedSock()
    is_verified = True

connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection("example.test", port=443)
conn._new_conn = lambda: Sock()
conn.connect()
assert probe._values()[("example.test", 443)] is True
assert conn.is_verified is True
""",
        "mutant_code": """
import urllib3.connection as connection_module
from urllib3.http2 import probe

probe._reset()
connection_module.ssl_.ALPN_PROTOCOLS = ["h2", "http/1.1"]
probe.acquire_and_get = lambda host, port: False

class Sock:
    def close(self):
        pass

class WrappedSock:
    def selected_alpn_protocol(self):
        return "h2"

class Wrapped:
    socket = WrappedSock()
    is_verified = True

connection_module._ssl_wrap_socket_and_match_hostname = lambda *args, **kwargs: Wrapped()
conn = connection_module.HTTPSConnection("example.test", port=443)
conn._new_conn = lambda: Sock()
conn.connect()
assert probe._values()[("example.test", 443)] is True
assert conn.is_verified is True
""",
    },
    "2.2.0:http2_basic_request_succeeds": {
        "mutant": "disable_http2_request_path",
        "code": """
import h2.events
import urllib3.http2 as http2_module

class FakeSock:
    def __init__(self):
        self.sent = []
        self.closed = False
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, amount):
        return b"response-bytes"
    def close(self):
        self.closed = True

class FakeH2:
    def __init__(self):
        self.headers = []
        self.acked = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def data_to_send(self):
        return b"wire"
    def receive_data(self, data):
        response = h2.events.ResponseReceived()
        response.stream_id = 1
        response.headers = [(b":status", b"200"), (b"x-test", b"1")]
        body = h2.events.DataReceived()
        body.stream_id = 1
        body.data = b"ok"
        body.flow_controlled_length = 2
        ended = h2.events.StreamEnded()
        ended.stream_id = 1
        return [response, body, ended]
    def acknowledge_received_data(self, length, stream_id):
        self.acked.append((length, stream_id))

conn = http2_module.HTTP2Connection("example.test")
sock = FakeSock()
fake = FakeH2()
conn.sock = sock
conn._h2_conn = fake
conn.request("GET", "/")
response = conn.getresponse()
sent_headers = dict(fake.headers[-1][1])
assert sent_headers[b":method"] == b"GET"
assert sent_headers[b":path"] == b"/"
assert response.status == 200
assert response.data == b"ok"
assert response.headers["x-test"] == "1"
assert fake.acked == [(2, 1)]
assert sock.closed is True
""",
        "mutant_code": """
import h2.events
import urllib3.http2 as http2_module

class FakeSock:
    def __init__(self):
        self.sent = []
        self.closed = False
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, amount):
        return b"response-bytes"
    def close(self):
        self.closed = True

class FakeH2:
    def __init__(self):
        self.headers = []
        self.acked = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def get_next_available_stream_id(self):
        return 1
    def send_headers(self, stream_id, headers, end_stream):
        self.headers.append((stream_id, list(headers), end_stream))
    def data_to_send(self):
        return b"wire"
    def receive_data(self, data):
        response = h2.events.ResponseReceived()
        response.stream_id = 1
        response.headers = [(b":status", b"200"), (b"x-test", b"1")]
        body = h2.events.DataReceived()
        body.stream_id = 1
        body.data = b"ok"
        body.flow_controlled_length = 2
        ended = h2.events.StreamEnded()
        ended.stream_id = 1
        return [response, body, ended]
    def acknowledge_received_data(self, length, stream_id):
        self.acked.append((length, stream_id))

def omit_http2_path(self, method, url, skip_host=False, skip_accept_encoding=False):
    self._request_url = url
    self._h2_stream = self._h2_conn.get_next_available_stream_id()
    self._h2_headers.extend(
        (
            (b":scheme", b"https"),
            (b":method", method.encode()),
            (b":authority", f"{self.host}:{self.port or 443}".encode()),
        )
    )
http2_module.HTTP2Connection.putrequest = omit_http2_path

conn = http2_module.HTTP2Connection("example.test")
sock = FakeSock()
fake = FakeH2()
conn.sock = sock
conn._h2_conn = fake
conn.request("GET", "/")
response = conn.getresponse()
sent_headers = dict(fake.headers[-1][1])
assert sent_headers[b":method"] == b"GET"
assert sent_headers[b":path"] == b"/"
assert response.status == 200
assert response.data == b"ok"
assert response.headers["x-test"] == "1"
assert fake.acked == [(2, 1)]
assert sock.closed is True
""",
    },
    "2.0.3:zstd_response_with_multiple_frames_decodes_completely": {
        "mutant": "decode_only_first_zstd_frame",
        "code": """
import io
import zstandard as zstd
from urllib3.response import HTTPResponse
compressor = zstd.ZstdCompressor()
body = compressor.compress(b"hello") + compressor.compress(b"world")
response = HTTPResponse(body=io.BytesIO(body), preload_content=False, headers={"Content-Encoding": "zstd"})
assert response.read(decode_content=True) == b"helloworld"
""",
        "mutant_code": """
import io
import zstandard as zstd
from urllib3.response import HTTPResponse
HTTPResponse.read = lambda self, *args, **kwargs: b"hello"
compressor = zstd.ZstdCompressor()
body = compressor.compress(b"hello") + compressor.compress(b"world")
response = HTTPResponse(body=io.BytesIO(body), preload_content=False, headers={"Content-Encoding": "zstd"})
assert response.read(decode_content=True) == b"helloworld"
""",
    },
    "2.0.0:zstd_response_decodes_single_frame": {
        "mutant": "do_not_decode_zstd_response",
        "code": """
import io
import zstandard as zstd
from urllib3.response import HTTPResponse
body = zstd.ZstdCompressor().compress(b"hello")
response = HTTPResponse(body=io.BytesIO(body), preload_content=False, headers={"Content-Encoding": "zstd"})
assert response.read(decode_content=True) == b"hello"
""",
        "mutant_code": """
import io
import zstandard as zstd
from urllib3.response import HTTPResponse
HTTPResponse.CONTENT_DECODERS = ["gzip", "deflate", "br"]
body = zstd.ZstdCompressor().compress(b"hello")
response = HTTPResponse(body=io.BytesIO(body), preload_content=False, headers={"Content-Encoding": "zstd"})
assert response.read(decode_content=True) == b"hello"
""",
    },
    "1.25.10:brotli_decoder_handles_objects_without_decompress_attr": {
        "mutant": "require_brotli_decompress_attribute",
        "code": """
import urllib3.response
class ProcessOnly:
    def process(self, data):
        return b"hello"
urllib3.response.brotli.Decompressor = lambda: ProcessOnly()
decoder = urllib3.response.BrotliDecoder()
assert decoder.decompress(b"encoded") == b"hello"
""",
        "mutant_code": """
import urllib3.response
class ProcessOnly:
    def process(self, data):
        return b"hello"
urllib3.response.brotli.Decompressor = lambda: ProcessOnly()
original_init = urllib3.response.BrotliDecoder.__init__
def require_decompress(self):
    self._obj = urllib3.response.brotli.Decompressor()
    self.decompress = self._obj.decompress
urllib3.response.BrotliDecoder.__init__ = require_decompress
decoder = urllib3.response.BrotliDecoder()
assert decoder.decompress(b"encoded") == b"hello"
""",
    },
    "1.23:socks_proxy_auth_info_in_url_is_supported": {
        "mutant": "drop_socks_proxy_url_auth",
        "code": """
from urllib3.contrib.socks import SOCKSProxyManager
manager = SOCKSProxyManager("socks5h://user:pass@127.0.0.1:1080")
options = manager.connection_pool_kw["_socks_options"]
assert options["username"] == "user"
assert options["password"] == "pass"
""",
        "mutant_code": """
from urllib3.contrib.socks import SOCKSProxyManager
manager = SOCKSProxyManager("socks5h://user:pass@127.0.0.1:1080")
options = manager.connection_pool_kw["_socks_options"]
options["username"] = None
options["password"] = None
assert options["username"] == "user"
assert options["password"] == "pass"
""",
    },
    "1.20:socks_remote_dns_schemes_are_supported": {
        "mutant": "disable_remote_dns_for_socks_h_schemes",
        "code": """
from urllib3.contrib.socks import SOCKSProxyManager
for url in ("socks5h://127.0.0.1:1080", "socks4a://127.0.0.1:1080"):
    manager = SOCKSProxyManager(url)
    assert manager.connection_pool_kw["_socks_options"]["rdns"] is True
""",
        "mutant_code": """
from urllib3.contrib.socks import SOCKSProxyManager
for url in ("socks5h://127.0.0.1:1080", "socks4a://127.0.0.1:1080"):
    manager = SOCKSProxyManager(url)
    manager.connection_pool_kw["_socks_options"]["rdns"] = False
    assert manager.connection_pool_kw["_socks_options"]["rdns"] is True
""",
    },
    "1.14:socks_proxy_basic_request_succeeds": {
        "mutant": "reject_basic_socks_proxy_url",
        "code": """
from urllib3.contrib.socks import SOCKSProxyManager
manager = SOCKSProxyManager("socks5://127.0.0.1:1080")
options = manager.connection_pool_kw["_socks_options"]
assert options["proxy_host"] == "127.0.0.1"
assert options["proxy_port"] == 1080
""",
        "mutant_code": """
from urllib3.contrib.socks import SOCKSProxyManager
manager = SOCKSProxyManager("socks5://127.0.0.1:1080")
options = manager.connection_pool_kw["_socks_options"]
options["proxy_host"] = None
assert options["proxy_host"] == "127.0.0.1"
assert options["proxy_port"] == 1080
""",
    },
    "2.3.0:http_debug_log_formats_version_as_http11": {
        "mutant": "render_http11_log_as_http11_without_dot",
        "code": """
import http.client
import http.server
import io
import logging
import socketserver
import threading
import urllib3

log_buffer = io.StringIO()
handler = logging.StreamHandler(log_buffer)
logger = logging.getLogger("urllib3.connectionpool")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
old_debuglevel = http.client.HTTPConnection.debuglevel
http.client.HTTPConnection.debuglevel = 1

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=False)
    assert response.status == 200
    logs = log_buffer.getvalue()
    assert "HTTP/1.1" in logs
    assert "HTTP/11" not in logs
finally:
    http.client.HTTPConnection.debuglevel = old_debuglevel
    logger.removeHandler(handler)
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import logging
import urllib3.connectionpool

original_log_request = urllib3.connectionpool.log.debug
def mutate_http_version(message, *args, **kwargs):
    if args:
        args = tuple("HTTP/11" if item == "HTTP/1.1" else item for item in args)
    return original_log_request(message, *args, **kwargs)
urllib3.connectionpool.log.debug = mutate_http_version

import http.client
import http.server
import io
import socketserver
import threading
import urllib3

log_buffer = io.StringIO()
handler = logging.StreamHandler(log_buffer)
logger = logging.getLogger("urllib3.connectionpool")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
old_debuglevel = http.client.HTTPConnection.debuglevel
http.client.HTTPConnection.debuglevel = 1

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=False)
    assert response.status == 200
    logs = log_buffer.getvalue()
    assert "HTTP/1.1" in logs
    assert "HTTP/11" not in logs
finally:
    http.client.HTTPConnection.debuglevel = old_debuglevel
    logger.removeHandler(handler)
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.6:content_encoding_header_is_case_insensitive": {
        "mutant": "treat_content_encoding_case_sensitively",
        "code": """
import gzip
body = gzip.compress(b"hello")
raw = b"HTTP/1.1 200 OK\\r\\nContent-Encoding: GZip\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n\\r\\n" + body
response = request_raw_response(raw)
assert response.data == b"hello"
""",
        "mutant_code": """
import gzip
body = gzip.compress(b"hello")
raw = b"HTTP/1.1 200 OK\\r\\nContent-Encoding: identity\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n\\r\\n" + body
response = request_raw_response(raw)
assert response.data == b"hello"
""",
    },
    "1.6:streaming_decompression_is_supported": {
        "mutant": "disable_streaming_decompression",
        "code": """
import gzip
body = gzip.compress(b"hello")
raw = b"HTTP/1.1 200 OK\\r\\nContent-Encoding: gzip\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n\\r\\n" + body
response = request_raw_response(raw, preload_content=False, decode_content=True)
assert response.read(decode_content=True) == b"hello"
""",
        "mutant_code": """
import gzip
body = gzip.compress(b"hello")
raw = b"HTTP/1.1 200 OK\\r\\nContent-Encoding: identity\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n\\r\\n" + body
response = request_raw_response(raw, preload_content=False, decode_content=True)
assert response.read(decode_content=True) == b"hello"
""",
    },
    "2.2.0:tls13_post_handshake_auth_works_when_validation_disabled": {
        "mutant": "break_tls13_post_handshake_auth_without_cert_validation",
        "code": """
import ssl
from urllib3.util.ssl_ import create_urllib3_context
context = create_urllib3_context(cert_reqs=ssl.CERT_NONE)
assert context.verify_mode == ssl.CERT_NONE
assert getattr(context, "post_handshake_auth", None) is True
""",
        "mutant_code": """
import ssl
from urllib3.util.ssl_ import create_urllib3_context
context = create_urllib3_context(cert_reqs=ssl.CERT_NONE)
context.post_handshake_auth = False
assert context.verify_mode == ssl.CERT_NONE
assert getattr(context, "post_handshake_auth", None) is True
""",
    },
    "2.0.0:system_cipher_suites_are_not_overridden_by_default": {
        "mutant": "override_system_cipher_suites_with_library_default",
        "code": """
import ssl
from urllib3.util.ssl_ import create_urllib3_context
original = ssl.SSLContext.set_ciphers
calls = []
def capture_set_ciphers(self, ciphers):
    calls.append(ciphers)
    return original(self, ciphers)
ssl.SSLContext.set_ciphers = capture_set_ciphers
try:
    create_urllib3_context(ciphers=None)
finally:
    ssl.SSLContext.set_ciphers = original
assert calls == []
""",
        "mutant_code": """
import ssl
import urllib3.util.ssl_
original_set_ciphers = ssl.SSLContext.set_ciphers
original_create = urllib3.util.ssl_.create_urllib3_context
calls = []
def capture_set_ciphers(self, ciphers):
    calls.append(ciphers)
    return original_set_ciphers(self, ciphers)
def override_ciphers(*args, **kwargs):
    context = original_create(*args, **kwargs)
    context.set_ciphers("DEFAULT")
    return context
ssl.SSLContext.set_ciphers = capture_set_ciphers
urllib3.util.ssl_.create_urllib3_context = override_ciphers
try:
    urllib3.util.ssl_.create_urllib3_context(ciphers=None)
finally:
    ssl.SSLContext.set_ciphers = original_set_ciphers
assert calls == []
""",
    },
    "1.8.3:socket_options_are_applied_before_connect": {
        "mutant": "ignore_socket_options",
        "code": """
from urllib3.connection import HTTPConnection
import urllib3.connection as connection_module
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, *extra_args):
    seen.append(("create_connection", address, timeout, extra_args))
    return Sock()
connection_module.socket.create_connection = fake_create_connection
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("setsockopt", (1, 2, 3)) in seen
""",
        "mutant_code": """
from urllib3.connection import HTTPConnection
import urllib3.connection as connection_module
seen = []
class Sock:
    def setsockopt(self, *args):
        seen.append(("setsockopt", args))
    def settimeout(self, *args):
        seen.append(("settimeout", args))
    def connect(self, *args):
        seen.append(("connect", args))
    def close(self):
        pass
def fake_create_connection(address, timeout=None, *extra_args):
    seen.append(("create_connection", address, timeout, extra_args))
    return Sock()
connection_module.socket.create_connection = fake_create_connection
HTTPConnection._set_options_on = lambda self, conn: None
conn = HTTPConnection("example.test", socket_options=[(1, 2, 3)])
conn.connect()
assert ("setsockopt", (1, 2, 3)) in seen
""",
    },
    "1.7:response_iter_yields_body_lines_efficiently": {
        "mutant": "buffer_entire_response_before_streaming",
        "code": """
import socketserver
import threading
import urllib3

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(65536)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 4\\r\\n\\r\\na\\nb\\n")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", preload_content=False, retries=False)
    assert list(response.stream(amt=2)) == [b"a\\n", b"b\\n"]
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
from urllib3.response import HTTPResponse
HTTPResponse.stream = lambda self, amt=2**16, decode_content=None: iter([self.read(decode_content=decode_content)])

import socketserver
import threading
import urllib3

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(65536)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 4\\r\\n\\r\\na\\nb\\n")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", preload_content=False, retries=False)
    assert list(response.stream(amt=2)) == [b"a\\n", b"b\\n"]
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.24:multiple_content_encodings_are_decoded_in_order": {
        "mutant": "decode_content_encodings_in_header_order",
        "code": """
import gzip
import io
import zlib
from urllib3.response import HTTPResponse

body = gzip.compress(zlib.compress(b"hello"))
response = HTTPResponse(
    body=io.BytesIO(body),
    preload_content=False,
    headers={"Content-Encoding": "deflate, gzip"},
)
assert response.read(decode_content=True) == b"hello"
""",
        "mutant_code": """
import gzip
import io
import zlib
from urllib3.response import HTTPResponse

body = gzip.compress(zlib.compress(b"hello"))
response = HTTPResponse(
    body=io.BytesIO(body),
    preload_content=False,
    headers={"Content-Encoding": "gzip, deflate"},
)
assert response.read(decode_content=True) == b"hello"
""",
    },
    "1.25.3:https_loads_system_certs_when_no_ca_options_are_set": {
        "mutant": "do_not_load_system_ca_certs_by_default",
        "code": """
import ssl
import urllib3.connection as connection_module

calls = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE
    def load_default_certs(self):
        calls.append("default")

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test")
conn.assert_hostname = False
conn.connect()
assert calls == ["default"]
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

calls = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE
    def load_default_certs(self):
        pass

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test")
conn.assert_hostname = False
conn.connect()
assert calls == ["default"]
""",
    },
    "1.25:https_validates_certificates_by_default": {
        "mutant": "disable_default_certificate_verification",
        "code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test")
conn.assert_hostname = False
conn.connect()
assert conn.ssl_context.verify_mode == ssl.CERT_REQUIRED
assert conn.is_verified is True
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.resolve_cert_reqs = lambda value: ssl.CERT_NONE
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test")
conn.assert_hostname = False
conn.connect()
assert conn.ssl_context.verify_mode == ssl.CERT_REQUIRED
assert conn.is_verified is True
""",
    },
    "1.24.2:explicit_ca_options_disable_default_system_cert_loading": {
        "mutant": "load_system_ca_certs_even_with_explicit_ca_options",
        "code": """
import urllib3.util.ssl_ as ssl_util

calls = []
class FakeContext:
    def load_verify_locations(self, ca_certs, ca_cert_dir=None):
        calls.append(("verify", ca_certs, ca_cert_dir))
    def load_default_certs(self):
        calls.append(("default",))
    def wrap_socket(self, sock, server_hostname=None):
        calls.append(("wrap", server_hostname))
        return sock

context = FakeContext()
ssl_util.ssl_wrap_socket(
    sock=object(),
    ca_certs="/tmp/custom-ca.pem",
    ssl_context=context,
    server_hostname="example.test",
)
assert ("default",) not in calls
assert ("verify", "/tmp/custom-ca.pem", None) in calls
""",
        "mutant_code": """
import urllib3.util.ssl_ as ssl_util

calls = []
class FakeContext:
    def load_verify_locations(self, ca_certs, ca_cert_dir=None):
        calls.append(("verify", ca_certs, ca_cert_dir))
    def load_default_certs(self):
        calls.append(("default",))
    def wrap_socket(self, sock, server_hostname=None):
        calls.append(("wrap", server_hostname))
        return sock

context = FakeContext()
ssl_util.ssl_wrap_socket(
    sock=object(),
    ssl_context=context,
    server_hostname="example.test",
)
assert ("default",) not in calls
assert ("verify", "/tmp/custom-ca.pem", None) in calls
""",
    },
    "1.22:broken_connection_is_retried_until_success": {
        "mutant": "disable_retry_after_broken_connection",
        "code": """
import socketserver
import threading
import urllib3

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        self.request.recv(65536)
        if type(self.server).count == 1:
            self.request.close()
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=1)
    assert response.status == 200
    assert Server.count == 2
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import urllib3

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        self.request.recv(65536)
        if type(self.server).count == 1:
            self.request.close()
            return
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    response = urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_address[1]}/", retries=0)
    assert response.status == 200
    assert Server.count == 2
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.22:redirect_drain_releases_blocking_pool_connection": {
        "mutant": "recurse_redirect_without_releasing_connection",
        "code": """
import socketserver, threading
import urllib3

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.requests.append(data.split(b"\\r\\n", 1)[0])
            if b" /redirect " in data:
                body = b"unread-body"
                self.request.sendall(
                    b"HTTP/1.1 302 Found\\r\\nLocation: /target\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            else:
                self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.requests = []
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    result = {}
    def call():
        try:
            response = pool.urlopen(
                "GET",
                "/redirect",
                redirect=True,
                timeout=1,
                pool_timeout=0.3,
                preload_content=False,
            )
            result["status"] = response.status
            result["data"] = response.read()
        except Exception as error:
            result["error"] = error
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert result.get("status") == 200
    assert result.get("data") == b"ok"
    assert server.requests == [b"GET /redirect HTTP/1.1", b"GET /target HTTP/1.1"]
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading
import urllib3
import urllib3.response

original_read = urllib3.response.HTTPResponse.read
def skip_redirect_drain(self, amt=None, decode_content=None, cache_content=False):
    if getattr(self, "status", None) in (301, 302, 303, 307, 308) and amt is None:
        return b""
    return original_read(self, amt=amt, decode_content=decode_content, cache_content=cache_content)
urllib3.response.HTTPResponse.read = skip_redirect_drain

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.requests.append(data.split(b"\\r\\n", 1)[0])
            if b" /redirect " in data:
                body = b"unread-body"
                self.request.sendall(
                    b"HTTP/1.1 302 Found\\r\\nLocation: /target\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            else:
                self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\nok")
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.requests = []
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    result = {}
    def call():
        try:
            response = pool.urlopen(
                "GET",
                "/redirect",
                redirect=True,
                timeout=1,
                pool_timeout=0.3,
                preload_content=False,
            )
            result["status"] = response.status
            result["data"] = response.read()
        except Exception as error:
            result["error"] = error
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert result.get("status") == 200
    assert result.get("data") == b"ok"
    assert server.requests == [b"GET /redirect HTTP/1.1", b"GET /target HTTP/1.1"]
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "1.6:proxy_manager_adds_host_header_when_missing": {
        "mutant": "omit_host_header_for_proxy_request",
        "code": """
import socketserver
import threading
import urllib3

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    headers = []
    def handle(self):
        data = self.request.recv(65536)
        type(self).headers.append(data.split(b"\\r\\n\\r\\n", 1)[0])
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    proxy = urllib3.proxy_from_url(f"http://127.0.0.1:{server.server_address[1]}")
    response = proxy.urlopen("GET", "http://example.test/path", headers={}, retries=False)
    assert response.status == 200
    headers = Handler.headers[-1].decode("latin1")
    assert "Host: example.test" in headers
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import urllib3
import urllib3.poolmanager as poolmanager

def omit_host(self, url, headers=None):
    result = {"Accept": "*/*", "Host": "mutant.test"}
    if headers:
        result.update(headers)
    return result
poolmanager.ProxyManager._set_proxy_headers = omit_host

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class Handler(socketserver.BaseRequestHandler):
    headers = []
    def handle(self):
        data = self.request.recv(65536)
        type(self).headers.append(data.split(b"\\r\\n\\r\\n", 1)[0])
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    proxy = urllib3.proxy_from_url(f"http://127.0.0.1:{server.server_address[1]}")
    response = proxy.urlopen("GET", "http://example.test/path", headers={}, retries=False)
    assert response.status == 200
    headers = Handler.headers[-1].decode("latin1")
    assert "Host: example.test" in headers
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.5:proxy_request_uri_strips_scheme_and_host": {
        "mutant": "send_absolute_uri_to_origin_server",
        "code": """
import urllib3

class Response:
    status = 200
    def get_redirect_location(self):
        return None

class FakePool:
    def __init__(self):
        self.calls = []
    def urlopen(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return Response()

fake_pool = FakePool()
manager = urllib3.PoolManager()
manager.connection_from_host = lambda *args, **kwargs: fake_pool
response = manager.urlopen("GET", "http://example.test/path?x=1", redirect=False)
assert response.status == 200
assert fake_pool.calls[-1][1] == "/path?x=1"
""",
        "mutant_code": """
import urllib3

class Response:
    status = 200
    def get_redirect_location(self):
        return None

class FakePool:
    def __init__(self):
        self.calls = []
    def urlopen(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return Response()

def send_absolute_uri(self, method, url, redirect=True, **kwargs):
    conn = self.connection_from_host("example.test", scheme="http")
    kwargs["assert_same_host"] = False
    kwargs["redirect"] = False
    return conn.urlopen(method, url, **kwargs)

urllib3.PoolManager.urlopen = send_absolute_uri
fake_pool = FakePool()
manager = urllib3.PoolManager()
manager.connection_from_host = lambda *args, **kwargs: fake_pool
response = manager.urlopen("GET", "http://example.test/path?x=1", redirect=False)
assert response.status == 200
assert fake_pool.calls[-1][1] == "/path?x=1"
""",
    },
    "1.5:http_303_redirect_switches_method_to_get": {
        "mutant": "preserve_post_method_on_303_redirect",
        "code": """
import urllib3

class Response:
    def __init__(self, status, location=None):
        self.status = status
        self.location = location
    def get_redirect_location(self):
        return self.location

class FakePool:
    def __init__(self):
        self.calls = []
    def urlopen(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if len(self.calls) == 1:
            return Response(303, "http://example.test/done")
        return Response(200)

fake_pool = FakePool()
manager = urllib3.PoolManager()
manager.connection_from_host = lambda *args, **kwargs: fake_pool
response = manager.urlopen("POST", "http://example.test/start", body=b"payload", redirect=True, retries=3)
assert response.status == 200
assert fake_pool.calls[0][0] == "POST"
assert fake_pool.calls[1][0] == "GET"
""",
        "mutant_code": """
import urllib3

class Response:
    def __init__(self, status, location=None):
        self.status = status
        self.location = location
    def get_redirect_location(self):
        return self.location

class FakePool:
    def __init__(self):
        self.calls = []
    def urlopen(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if len(self.calls) == 1:
            return Response(303, "http://example.test/done")
        return Response(200)

def preserve_redirect_method(self, method, url, redirect=True, **kwargs):
    conn = self.connection_from_host("example.test", scheme="http")
    kwargs["assert_same_host"] = False
    kwargs["redirect"] = False
    response = conn.urlopen(method, "/start" if url.endswith("/start") else "/done", **kwargs)
    location = redirect and response.get_redirect_location()
    if not location:
        return response
    kwargs["retries"] = kwargs.get("retries", 3) - 1
    return conn.urlopen(method, "/done", **kwargs)

urllib3.PoolManager.urlopen = preserve_redirect_method
fake_pool = FakePool()
manager = urllib3.PoolManager()
manager.connection_from_host = lambda *args, **kwargs: fake_pool
response = manager.urlopen("POST", "http://example.test/start", body=b"payload", redirect=True, retries=3)
assert response.status == 200
assert fake_pool.calls[0][0] == "POST"
assert fake_pool.calls[1][0] == "GET"
""",
    },
    "1.5:pool_eviction_closes_evicted_idle_connections": {
        "mutant": "leak_idle_connection_on_pool_eviction",
        "code": """
import urllib3

class Pool:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

manager = urllib3.PoolManager(num_pools=1)
first = Pool()
second = Pool()
manager.pools["http://one.test"] = first
manager.pools["http://two.test"] = second
assert first.closed is True
assert second.closed is False
manager.clear()
assert second.closed is True
assert len(manager.pools) == 0
""",
        "mutant_code": """
import urllib3
import urllib3.poolmanager as poolmanager
from urllib3._collections import RecentlyUsedContainer

class Pool:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True

def init_without_dispose(self, num_pools=10, **connection_pool_kw):
    self.connection_pool_kw = connection_pool_kw
    self.pools = RecentlyUsedContainer(num_pools)

poolmanager.PoolManager.__init__ = init_without_dispose
manager = urllib3.PoolManager(num_pools=1)
first = Pool()
second = Pool()
manager.pools["http://one.test"] = first
manager.pools["http://two.test"] = second
assert first.closed is True
assert second.closed is False
manager.clear()
assert second.closed is True
assert len(manager.pools) == 0
""",
    },
    "1.2.1:location_parse_error_is_value_error": {
        "mutant": "raise_non_value_error_for_location_parse_failure",
        "code": """
from urllib3.connectionpool import get_host
from urllib3.exceptions import LocationParseError
try:
    get_host("http://example.test:notaport/path")
except LocationParseError as error:
    assert isinstance(error, ValueError)
else:
    raise AssertionError("expected LocationParseError")
""",
        "mutant_code": """
import urllib3.connectionpool as connectionpool

def get_host_with_non_value_error(url):
    raise RuntimeError("parse failed")

connectionpool.get_host = get_host_with_non_value_error
from urllib3.connectionpool import get_host
from urllib3.exceptions import LocationParseError
try:
    get_host("http://example.test:notaport/path")
except LocationParseError as error:
    assert isinstance(error, ValueError)
else:
    raise AssertionError("expected LocationParseError")
""",
    },
    "1.2:same_origin_requests_reuse_one_connection": {
        "mutant": "disable_connection_reuse",
        "code": """
import socketserver
import threading
import urllib3

class Server(socketserver.TCPServer):
    allow_reuse_address = True
    def get_request(self):
        sock, addr = socketserver.TCPServer.get_request(self)
        self.connection_count += 1
        return sock, addr

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.request_count += 1
            body = b"ok"
            self.request.sendall(
                b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\n" + body
            )
            if self.server.request_count >= 2:
                self.request.close()
                return

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
server.request_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/first", retries=False)
    second = pool.urlopen("GET", "/second", retries=False)
    assert first.status == 200
    assert first.data == b"ok"
    assert second.status == 200
    assert second.data == b"ok"
    assert server.connection_count == 1
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import urllib3
import urllib3.connectionpool as connectionpool

original_put_conn = connectionpool.HTTPConnectionPool._put_conn
def close_instead_of_reuse(self, conn):
    conn.close()
connectionpool.HTTPConnectionPool._put_conn = close_instead_of_reuse

class Server(socketserver.TCPServer):
    allow_reuse_address = True
    def get_request(self):
        sock, addr = socketserver.TCPServer.get_request(self)
        self.connection_count += 1
        return sock, addr

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.server.request_count += 1
            body = b"ok"
            self.request.sendall(
                b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: keep-alive\\r\\n\\r\\n" + body
            )
            if self.server.request_count >= 2:
                self.request.close()
                return

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
server.request_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/first", retries=False)
    second = pool.urlopen("GET", "/second", retries=False)
    assert first.status == 200
    assert first.data == b"ok"
    assert second.status == 200
    assert second.data == b"ok"
    assert server.connection_count == 1
finally:
    connectionpool.HTTPConnectionPool._put_conn = original_put_conn
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.2:cross_scheme_redirect_completes": {
        "mutant": "fail_cross_scheme_redirect",
        "code": """
import urllib3
import urllib3.poolmanager as poolmanager
from urllib3.exceptions import HostChangedError

calls = []

class Response:
    status = 200
    data = b"secure"

class FakeHTTPPool:
    def __init__(self, host, port=None, **kwargs):
        self.host = host
        self.port = port
    def urlopen(self, method, url, **kwargs):
        calls.append(("http", method, url, kwargs.get("retries")))
        raise HostChangedError("http://origin.test", "https://secure.test/target", kwargs.get("retries", 3) - 1)

class FakeHTTPSPool:
    def __init__(self, host, port=None, **kwargs):
        self.host = host
        self.port = port
    def urlopen(self, method, url, **kwargs):
        calls.append(("https", method, url, kwargs.get("retries")))
        return Response()

poolmanager.pool_classes_by_scheme = {"http": FakeHTTPPool, "https": FakeHTTPSPool}
manager = urllib3.PoolManager()
response = manager.urlopen("GET", "http://origin.test/redirect", retries=2)
assert response.status == 200
assert response.data == b"secure"
assert calls == [
    ("http", "GET", "http://origin.test/redirect", 2),
    ("https", "GET", "https://secure.test/target", 1),
]
""",
        "mutant_code": """
import urllib3
import urllib3.poolmanager as poolmanager
from urllib3.exceptions import HostChangedError

def no_cross_scheme_retry(self, method, url, **kw):
    conn = self.connection_from_url(url)
    return conn.urlopen(method, url, **kw)

poolmanager.PoolManager.urlopen = no_cross_scheme_retry
calls = []

class Response:
    status = 200
    data = b"secure"

class FakeHTTPPool:
    def __init__(self, host, port=None, **kwargs):
        self.host = host
        self.port = port
    def urlopen(self, method, url, **kwargs):
        calls.append(("http", method, url, kwargs.get("retries")))
        raise HostChangedError("http://origin.test", "https://secure.test/target", kwargs.get("retries", 3) - 1)

class FakeHTTPSPool:
    def __init__(self, host, port=None, **kwargs):
        self.host = host
        self.port = port
    def urlopen(self, method, url, **kwargs):
        calls.append(("https", method, url, kwargs.get("retries")))
        return Response()

poolmanager.pool_classes_by_scheme = {"http": FakeHTTPPool, "https": FakeHTTPSPool}
manager = urllib3.PoolManager()
response = manager.urlopen("GET", "http://origin.test/redirect", retries=2)
assert response.status == 200
assert response.data == b"secure"
assert calls == [
    ("http", "GET", "http://origin.test/redirect", 2),
    ("https", "GET", "https://secure.test/target", 1),
]
""",
    },
    "1.0:explicit_multipart_boundary_is_used": {
        "mutant": "ignore_explicit_multipart_boundary",
        "code": """
import urllib3.filepost as filepost
filepost.writer = lambda stream: stream
body, content_type = filepost.encode_multipart_formdata({"a": "b"}, boundary="fixed-boundary")
body_text = body.decode("utf-8") if isinstance(body, bytes) else body
assert "boundary=fixed-boundary" in content_type
assert "--fixed-boundary\\r\\n" in body_text
assert 'name="a"' in body_text
assert "\\r\\nb\\r\\n" in body_text
""",
        "mutant_code": """
import urllib3.filepost as filepost
filepost.writer = lambda stream: stream
original = filepost.encode_multipart_formdata

def ignore_boundary(fields, boundary=None):
    return original(fields, boundary="generated-boundary")

filepost.encode_multipart_formdata = ignore_boundary
body, content_type = filepost.encode_multipart_formdata({"a": "b"}, boundary="fixed-boundary")
body_text = body.decode("utf-8") if isinstance(body, bytes) else body
assert "boundary=fixed-boundary" in content_type
assert "--fixed-boundary\\r\\n" in body_text
assert 'name="a"' in body_text
assert "\\r\\nb\\r\\n" in body_text
""",
    },
    "1.1:decode_content_option_controls_response_decoding": {
        "mutant": "ignore_decode_content_false",
        "code": """
import gzip
body = gzip.compress(b"hello")
raw = (
    b"HTTP/1.1 200 OK\\r\\n"
    b"content-encoding: gzip\\r\\n"
    + b"Content-Length: " + str(len(body)).encode("ascii") + b"\\r\\n\\r\\n"
    + body
)
response = request_raw_response(raw, preload_content=True, decode_content=False)
assert response.status == 200
assert response.data == body
""",
        "mutant_code": """
import gzip
import urllib3.connectionpool as connectionpool

original_urlopen = connectionpool.HTTPConnectionPool.urlopen
def force_decode_content(self, method, url, **kwargs):
    kwargs["decode_content"] = True
    return original_urlopen(self, method, url, **kwargs)
connectionpool.HTTPConnectionPool.urlopen = force_decode_content

body = gzip.compress(b"hello")
raw = (
    b"HTTP/1.1 200 OK\\r\\n"
    b"content-encoding: gzip\\r\\n"
    + b"Content-Length: " + str(len(body)).encode("ascii") + b"\\r\\n\\r\\n"
    + body
)
response = request_raw_response(raw, preload_content=True, decode_content=False)
assert response.status == 200
assert response.data == body
""",
    },
    "1.1:read_timeout_is_wrapped_as_timeout_error": {
        "mutant": "surface_raw_socket_timeout",
        "code": """
from urllib3.exceptions import TimeoutError
try:
    request_slow_response(timeout=0.1)
except TimeoutError:
    pass
else:
    raise AssertionError("expected TimeoutError")
""",
        "mutant_code": """
import socket
import urllib3
urllib3.PoolManager.request = lambda self, method, url, **kwargs: (_ for _ in ()).throw(socket.timeout("timed out"))
from urllib3.exceptions import TimeoutError
try:
    request_slow_response(timeout=0.1)
except TimeoutError:
    pass
else:
    raise AssertionError("expected TimeoutError")
""",
    },
    "1.20:read_timeout_retry_respects_method_allowlist": {
        "mutant": "retry_disallowed_method_after_read_timeout",
        "code": """
import socketserver
import threading
import time
import urllib3
from urllib3.exceptions import ReadTimeoutError
from urllib3.util.retry import Retry

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        self.request.recv(65536)
        if type(self.server).count == 1:
            time.sleep(0.3)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    retries = Retry(total=1, read=1, method_whitelist=frozenset(["GET"]))
    try:
        urllib3.PoolManager().request(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/",
            body=b"abc",
            timeout=0.1,
            retries=retries,
        )
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected POST read timeout not to retry into success")
    assert Server.count == 1
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import time
import urllib3
from urllib3.exceptions import ReadTimeoutError
from urllib3.util.retry import Retry

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        self.request.recv(65536)
        if type(self.server).count == 1:
            time.sleep(0.3)
        self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    retries = Retry(total=1, read=1, method_whitelist=frozenset(["GET", "POST"]))
    try:
        urllib3.PoolManager().request(
            "POST",
            f"http://127.0.0.1:{server.server_address[1]}/",
            body=b"abc",
            timeout=0.1,
            retries=retries,
        )
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected POST read timeout not to retry into success")
    assert Server.count == 1
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.24:tls_sni_hostname_can_be_overridden": {
        "mutant": "ignore_overridden_sni_hostname",
        "code": """
import ssl
import urllib3.connection as connection_module

seen = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE
    def load_default_certs(self):
        pass

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

def fake_wrap_socket(**kwargs):
    seen.append(kwargs)
    return FakeSock()

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = fake_wrap_socket
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test", server_hostname="service.test")
conn.assert_hostname = False
conn.connect()
assert seen[-1]["server_hostname"] == "service.test"
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

seen = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_NONE
    def load_default_certs(self):
        pass

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {}

def fake_wrap_socket(**kwargs):
    seen.append(kwargs)
    return FakeSock()

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = fake_wrap_socket
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("example.test", server_hostname="service.test")
conn.server_hostname = None
conn.assert_hostname = False
conn.connect()
assert seen[-1]["server_hostname"] == "service.test"
""",
    },
    "1.23:chunked_head_response_releases_connection": {
        "mutant": "leave_chunked_head_connection_checked_out",
        "code": """
import socketserver
import threading
import urllib3

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        if data.startswith(b"HEAD"):
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\nConnection: close\\r\\n\\r\\n")
        else:
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 4\\r\\nConnection: close\\r\\n\\r\\nnext")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("HEAD", "/head", preload_content=False, retries=False, timeout=1)
    assert response.status == 200
    assert list(response.stream()) == []
    response2 = pool.urlopen("GET", "/next", retries=False, timeout=1, pool_timeout=0.2)
    assert response2.status == 200
    assert response2.data == b"next"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
        "mutant_code": """
import socketserver
import threading
import urllib3
from urllib3.response import HTTPResponse

HTTPResponse.stream = lambda self, *args, **kwargs: iter([])

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    count = 0

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).count += 1
        data = b""
        while b"\\r\\n\\r\\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        if data.startswith(b"HEAD"):
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nTransfer-Encoding: chunked\\r\\nConnection: close\\r\\n\\r\\n")
        else:
            self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 4\\r\\nConnection: close\\r\\n\\r\\nnext")

server = Server(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1, block=True)
    response = pool.urlopen("HEAD", "/head", preload_content=False, retries=False, timeout=1)
    assert response.status == 200
    assert list(response.stream()) == []
    response2 = pool.urlopen("GET", "/next", retries=False, timeout=1, pool_timeout=0.2)
    assert response2.status == 200
    assert response2.data == b"next"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
""",
    },
    "1.16:pool_key_function_can_be_overridden_by_scheme": {
        "mutant": "ignore_custom_pool_key_function",
        "code": """
import urllib3
import urllib3.poolmanager as poolmanager

calls = []
def constant_pool_key(request_context):
    calls.append(dict(request_context))
    return poolmanager.HTTPPoolKey("http", "constant.test", 80, None, None, None, None, None)

old = poolmanager.key_fn_by_scheme["http"]
poolmanager.key_fn_by_scheme["http"] = constant_pool_key
try:
    manager = urllib3.PoolManager()
    first = manager.connection_from_url("http://a.test/")
    second = manager.connection_from_url("http://b.test/")
    assert calls
    assert first is second
    assert first.host == "constant.test"
finally:
    poolmanager.key_fn_by_scheme["http"] = old
""",
        "mutant_code": """
import urllib3
import urllib3.poolmanager as poolmanager

calls = []
def constant_pool_key(request_context):
    calls.append(dict(request_context))
    return poolmanager.HTTPPoolKey("http", "constant.test", 80, None, None, None, None, None)

old = poolmanager.key_fn_by_scheme["http"]
try:
    manager = urllib3.PoolManager()
    first = manager.connection_from_url("http://a.test/")
    second = manager.connection_from_url("http://b.test/")
    assert calls
    assert first is second
    assert first.host == "constant.test"
finally:
    poolmanager.key_fn_by_scheme["http"] = old
""",
    },
    "1.16:url_scheme_and_host_are_normalized_lowercase": {
        "mutant": "preserve_uppercase_scheme_or_host",
        "code": """
import urllib3

manager = urllib3.PoolManager()
first = manager.connection_from_host("EXAMPLE.TEST", scheme="HTTP")
second = manager.connection_from_host("example.test", scheme="http")
assert first is second
pool_key = list(manager.pools.keys())[0]
assert pool_key.scheme == "http"
assert pool_key.host == "example.test"
""",
        "mutant_code": """
import urllib3
import urllib3.poolmanager as poolmanager

def preserve_case_pool_key(request_context):
    context = {field: request_context.get(field) for field in poolmanager.HTTPPoolKey._fields}
    context["scheme"] = context["scheme"].lower()
    return poolmanager.HTTPPoolKey(**context)

manager = urllib3.PoolManager()
manager.key_fn_by_scheme["http"] = preserve_case_pool_key
first = manager.connection_from_host("EXAMPLE.TEST", scheme="HTTP")
second = manager.connection_from_host("example.test", scheme="http")
assert first is second
pool_key = list(manager.pools.keys())[0]
assert pool_key.scheme == "http"
assert pool_key.host == "example.test"
""",
    },
    "1.16:ipv6_dns_is_disabled_when_ipv6_connections_are_unavailable": {
        "mutant": "query_ipv6_dns_when_ipv6_connect_unavailable",
        "code": """
import socket
import urllib3.util.connection as connection_util

connection_util.HAS_IPV6 = False
assert connection_util.allowed_gai_family() == socket.AF_INET
""",
        "mutant_code": """
import socket
import urllib3.util.connection as connection_util

connection_util.HAS_IPV6 = False
connection_util.allowed_gai_family = lambda: socket.AF_UNSPEC
assert connection_util.allowed_gai_family() == socket.AF_INET
""",
    },
    "2.0.3:assert_hostname_false_skips_hostname_verification": {
        "mutant": "ignore_assert_hostname_false",
        "code": """
import ssl
import urllib3.connection as connection_module

calls = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass
    def set_alpn_protocols(self, *args, **kwargs):
        pass

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subject": ((("commonName", "mismatch.test"),),)}

def matcher(*args, **kwargs):
    calls.append((args, kwargs))
    raise AssertionError("hostname matcher should not be called")

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module._match_hostname = matcher
conn = connection_module.HTTPSConnection("example.test", assert_hostname=False)
conn.connect()
assert calls == []
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

calls = []
class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass
    def set_alpn_protocols(self, *args, **kwargs):
        pass

class FakeSock:
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subject": ((("commonName", "mismatch.test"),),)}

def matcher(*args, **kwargs):
    calls.append((args, kwargs))
    raise AssertionError("hostname matcher should not be called")

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module._match_hostname = matcher
conn = connection_module.HTTPSConnection("example.test", assert_hostname=False)
conn.assert_hostname = None
conn.connect()
assert calls == []
""",
    },
    "2.0.0:connection_timeout_is_applied_before_reading_response": {
        "mutant": "do_not_apply_connection_timeout_before_getresponse_read",
        "code": """
import http.client
from types import SimpleNamespace
from urllib3.connection import HTTPConnection

events = []
class Sock:
    def settimeout(self, value):
        events.append(("settimeout", value))

class Msg:
    def items(self):
        return []

class FakeHTTPResponse:
    status = 200
    version = 11
    reason = "OK"
    msg = Msg()
    def read(self, *args, **kwargs):
        return b""
    def close(self):
        pass
    def isclosed(self):
        return True
    @property
    def closed(self):
        return True

def fake_super_getresponse(self):
    events.append(("super_getresponse", None))
    return FakeHTTPResponse()

http.client.HTTPConnection.getresponse = fake_super_getresponse
conn = HTTPConnection("example.test", timeout=1.25)
conn.sock = Sock()
conn._response_options = SimpleNamespace(
    preload_content=True,
    decode_content=True,
    enforce_content_length=True,
    request_method="GET",
    request_url="/",
)
response = conn.getresponse()
assert response.status == 200
assert events[0] == ("settimeout", 1.25)
assert events[1] == ("super_getresponse", None)
""",
        "mutant_code": """
import http.client
from types import SimpleNamespace
from urllib3.connection import HTTPConnection
from urllib3.response import HTTPResponse

events = []
class Sock:
    def settimeout(self, value):
        events.append(("settimeout", value))

class Msg:
    def items(self):
        return []

class FakeHTTPResponse:
    status = 200
    version = 11
    reason = "OK"
    msg = Msg()
    def read(self, *args, **kwargs):
        return b""
    def close(self):
        pass
    def isclosed(self):
        return True
    @property
    def closed(self):
        return True

def fake_super_getresponse(self):
    events.append(("super_getresponse", None))
    return FakeHTTPResponse()

def mutant_getresponse(self):
    options = self._response_options
    self._response_options = None
    httplib_response = fake_super_getresponse(self)
    return HTTPResponse(
        body=httplib_response,
        headers={},
        status=httplib_response.status,
        version=httplib_response.version,
        reason=httplib_response.reason,
        preload_content=options.preload_content,
        decode_content=options.decode_content,
        original_response=httplib_response,
        enforce_content_length=options.enforce_content_length,
        request_method=options.request_method,
        request_url=options.request_url,
    )

http.client.HTTPConnection.getresponse = fake_super_getresponse
HTTPConnection.getresponse = mutant_getresponse
conn = HTTPConnection("example.test", timeout=1.25)
conn.sock = Sock()
conn._response_options = SimpleNamespace(
    preload_content=True,
    decode_content=True,
    enforce_content_length=True,
    request_method="GET",
    request_url="/",
)
response = conn.getresponse()
assert response.status == 200
assert events[0] == ("settimeout", 1.25)
assert events[1] == ("super_getresponse", None)
""",
    },
    "1.26.7:ip_address_hostname_verification_without_sni_succeeds": {
        "mutant": "require_sni_for_ip_address_certificate_verification",
        "code": """
import urllib3.packages.ssl_match_hostname as ssl_match_hostname
import urllib3.util.ssl_ as ssl_util

sni_calls = []
class FakeContext:
    def load_verify_locations(self, *args, **kwargs):
        pass
    def wrap_socket(self, sock, server_hostname=None):
        sni_calls.append(server_hostname)
        return sock

context = FakeContext()
ssl_util.ssl_wrap_socket(sock=object(), ssl_context=context, server_hostname="127.0.0.1")
ssl_match_hostname.match_hostname(
    {"subjectAltName": [("IP Address", "127.0.0.1")]},
    "127.0.0.1",
)
assert sni_calls == [None]
""",
        "mutant_code": """
import urllib3.packages.ssl_match_hostname as ssl_match_hostname
import urllib3.util.ssl_ as ssl_util

sni_calls = []
class FakeContext:
    def load_verify_locations(self, *args, **kwargs):
        pass
    def wrap_socket(self, sock, server_hostname=None):
        sni_calls.append(server_hostname)
        return sock

ssl_util.is_ipaddress = lambda hostname: False
context = FakeContext()
ssl_util.ssl_wrap_socket(sock=object(), ssl_context=context, server_hostname="127.0.0.1")
ssl_match_hostname.match_hostname(
    {"subjectAltName": [("IP Address", "127.0.0.1")]},
    "127.0.0.1",
)
assert sni_calls == [None]
""",
    },
    "1.26.7:ipv6_braces_are_stripped_for_certificate_matching": {
        "mutant": "compare_ipv6_certificate_name_with_brackets",
        "code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
import urllib3.packages.ssl_match_hostname as ssl_match_hostname
connection_module._match_hostname = lambda cert, hostname: ssl_match_hostname.match_hostname(cert, "[::1]")
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
    },
    "1.24.2:certificate_ipv6_subject_alt_name_is_accepted": {
        "mutant": "reject_ipaddress_subject_alt_name",
        "code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

def reject_ip_san(cert, hostname):
    raise ssl.CertificateError("IP Address subjectAltName rejected")

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module._match_hostname = reject_ip_san
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
    },
    "1.18:certificate_ipv6_subject_alt_name_is_accepted": {
        "mutant": "reject_ipaddress_subject_alt_name",
        "code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
        "mutant_code": """
import ssl
import urllib3.connection as connection_module

class FakeContext:
    check_hostname = False
    verify_mode = ssl.CERT_REQUIRED
    def load_default_certs(self):
        pass

class FakeSock:
    def version(self):
        return "TLSv1.2"
    def getpeercert(self, binary_form=False):
        return b"cert" if binary_form else {"subjectAltName": [("IP Address", "::1")]}
    def close(self):
        pass

def reject_ip_san(cert, hostname):
    raise ssl.CertificateError("IP Address subjectAltName rejected")

connection_module.create_urllib3_context = lambda **kwargs: FakeContext()
connection_module.ssl_wrap_socket = lambda **kwargs: FakeSock()
connection_module.HTTPSConnection._new_conn = lambda self: object()
connection_module._match_hostname = reject_ip_san
conn = connection_module.HTTPSConnection("[::1]")
conn.set_cert(cert_reqs="CERT_REQUIRED")
conn.connect()
assert conn.is_verified is True
""",
    },
    "1.26.15:reused_connection_uses_new_socket_timeout": {
        "mutant": "reuse_previous_socket_timeout",
        "code": """
import socketserver, threading, time
import urllib3
from urllib3.exceptions import ReadTimeoutError

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            if b" /fast " in data:
                body = b"ok"
            elif b" /slow " in data:
                time.sleep(0.25)
                body = b"slow"
            else:
                body = b"unexpected"
            try:
                self.request.sendall(
                    b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            except OSError:
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/fast", retries=False, timeout=0.5)
    assert first.status == 200
    assert first.data == b"ok"
    try:
        pool.urlopen("GET", "/slow", retries=False, timeout=0.1)
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected reused connection to apply new short timeout")
    assert server.connection_count == 1
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading, time
import urllib3
import urllib3.connectionpool as connectionpool
from urllib3.exceptions import ReadTimeoutError

original_make_request = connectionpool.HTTPConnectionPool._make_request
def reuse_previous_timeout(self, conn, method, url, *args, **kwargs):
    if url == "/slow":
        kwargs["timeout"] = urllib3.util.Timeout(connect=0.5, read=0.5)
    return original_make_request(self, conn, method, url, *args, **kwargs)
connectionpool.HTTPConnectionPool._make_request = reuse_previous_timeout

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            if b" /fast " in data:
                body = b"ok"
            elif b" /slow " in data:
                time.sleep(0.25)
                body = b"slow"
            else:
                body = b"unexpected"
            try:
                self.request.sendall(
                    b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            except OSError:
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/fast", retries=False, timeout=0.5)
    assert first.status == 200
    assert first.data == b"ok"
    try:
        pool.urlopen("GET", "/slow", retries=False, timeout=0.1)
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected reused connection to apply new short timeout")
    assert server.connection_count == 1
finally:
    server.shutdown()
    server.server_close()
""",
    },
    "2.0.0:reused_connection_uses_new_socket_timeout": {
        "mutant": "reuse_previous_socket_timeout",
        "code": """
import socketserver, threading, time
import urllib3
from urllib3.exceptions import ReadTimeoutError

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            if b" /fast " in data:
                body = b"ok"
            elif b" /slow " in data:
                time.sleep(0.25)
                body = b"slow"
            else:
                body = b"unexpected"
            try:
                self.request.sendall(
                    b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            except OSError:
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/fast", retries=False, timeout=0.5)
    assert first.status == 200
    assert first.data == b"ok"
    try:
        pool.urlopen("GET", "/slow", retries=False, timeout=0.1)
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected reused connection to apply new short timeout")
    assert server.connection_count == 1
finally:
    server.shutdown()
    server.server_close()
""",
        "mutant_code": """
import socketserver, threading, time
import urllib3
import urllib3.connectionpool as connectionpool
from urllib3.exceptions import ReadTimeoutError

original_make_request = connectionpool.HTTPConnectionPool._make_request
def reuse_previous_timeout(self, conn, method, url, *args, **kwargs):
    if url == "/slow":
        kwargs["timeout"] = urllib3.util.Timeout(connect=0.5, read=0.5)
    return original_make_request(self, conn, method, url, *args, **kwargs)
connectionpool.HTTPConnectionPool._make_request = reuse_previous_timeout

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connection_count += 1
        self.request.settimeout(2)
        while True:
            data = b""
            while b"\\r\\n\\r\\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            if b" /fast " in data:
                body = b"ok"
            elif b" /slow " in data:
                time.sleep(0.25)
                body = b"slow"
            else:
                body = b"unexpected"
            try:
                self.request.sendall(
                    b"HTTP/1.1 200 OK\\r\\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                    + body
                )
            except OSError:
                return

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

server = Server(("127.0.0.1", 0), Handler)
server.connection_count = 0
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1], maxsize=1)
    first = pool.urlopen("GET", "/fast", retries=False, timeout=0.5)
    assert first.status == 200
    assert first.data == b"ok"
    try:
        pool.urlopen("GET", "/slow", retries=False, timeout=0.1)
    except ReadTimeoutError:
        pass
    else:
        raise AssertionError("expected reused connection to apply new short timeout")
    assert server.connection_count == 1
finally:
    server.shutdown()
    server.server_close()
""",
    },
}


def ensure_venv(version: str) -> pathlib.Path:
    python = PY39 if version.startswith("1.") else PY312
    if not python.exists():
        python = pathlib.Path(sys.executable)
    venv = VENV_ROOT / f"urllib3-{version}"
    exe = venv / "bin" / "python"
    if not exe.exists():
        venv.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(python), "-m", "venv", str(venv)], check=True)
    marker = venv / ".urllib3-version"
    if not marker.exists() or marker.read_text().strip() != version:
        install_urllib3_release(exe, version)
        marker.write_text(version + "\n", encoding="utf-8")
    optional_marker = venv / ".optional-deps-v2"
    optional_deps = optional_deps_for(version)
    optional_marker_value = " ".join(optional_deps)
    if not optional_marker.exists() or optional_marker.read_text().strip() != optional_marker_value:
        subprocess.run([str(exe), "-m", "pip", "install", "-q", *optional_deps], check=True)
        optional_marker.write_text(optional_marker_value + "\n", encoding="utf-8")
    return exe


def install_urllib3_release(exe: pathlib.Path, version: str) -> None:
    if version in LEGACY_SDIST_INSTALLS:
        source = prepare_legacy_sdist(version)
        subprocess.run([str(exe), "-m", "pip", "install", "-q", "--no-deps", str(source)], check=True)
        return
    subprocess.run([str(exe), "-m", "pip", "install", "-q", f"urllib3=={version}"], check=True)


def prepare_legacy_sdist(version: str) -> pathlib.Path:
    target = LEGACY_SDIST_ROOT / f"urllib3-{version}"
    sentinel = target / ".prepared-py3-v2"
    if sentinel.exists():
        return target
    archive = LEGACY_SDIST_ROOT / f"urllib3-{version}.tar.gz"
    LEGACY_SDIST_ROOT.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with urllib.request.urlopen(f"https://pypi.org/pypi/urllib3/{version}/json") as response:
            metadata = json.loads(response.read().decode("utf-8"))
        sdist_url = next(item["url"] for item in metadata["urls"] if item["packagetype"] == "sdist")
        urllib.request.urlretrieve(sdist_url, archive)
    if target.exists():
        shutil.rmtree(target)
    with tarfile.open(archive) as tar:
        root_name = tar.getmembers()[0].name.split("/", 1)[0]
        tar.extractall(LEGACY_SDIST_ROOT)
    extracted = LEGACY_SDIST_ROOT / root_name
    if extracted != target:
        extracted.rename(target)
    if version in PY2_SDIST_INSTALLS:
        subprocess.run(
            [sys.executable, "-m", "lib2to3", "-w", "-n", str(target / "setup.py"), str(target / "urllib3")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    if version == "1.2.1":
        (target / "test-requirements.txt").write_text("", encoding="utf-8")
    sentinel.write_text("prepared\n", encoding="utf-8")
    return target


class CaptureServer(socketserver.TCPServer):
    allow_reuse_address = True


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    captures: list[dict[str, object]] = []

    def do_GET(self):
        self.capture_and_reply()

    def do_POST(self):
        self.capture_and_reply()

    def do_PUT(self):
        self.capture_and_reply()

    def capture_and_reply(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        capture = {
            "method": self.command,
            "path": self.path,
            "body": body,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "header_values": {
                key.lower(): self.headers.get_all(key)
                for key in self.headers.keys()
            },
        }
        type(self).captures.append(capture)
        response_body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, *args):
        pass


def capture_request(method: str = "GET", headers=None, fields=None, body=None, pool_headers=None, **request_kw):
    import urllib3

    class Handler(CaptureHandler):
        captures: list[dict[str, object]] = []

    server = CaptureServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager(headers=pool_headers) if pool_headers is not None else urllib3.PoolManager()
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        manager.request(method, url, fields=fields, headers=headers, body=body, **request_kw)
        return Handler.captures[-1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def capture_pool_request_path(path: str):
    import urllib3

    class Handler(CaptureHandler):
        captures: list[dict[str, object]] = []

    server = CaptureServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        pool = urllib3.HTTPConnectionPool("127.0.0.1", port=server.server_address[1])
        response = pool.urlopen("GET", path)
        return {"response_status": response.status, "captures": Handler.captures}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_raw_response(raw_response: bytes, **request_kw):
    import urllib3

    class RawServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(65536)
            self.request.sendall(raw_response)

    server = RawServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager()
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        return manager.request("GET", url, retries=False, **request_kw)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def capture_raw_request(method: str = "GET", headers=None, body=None, chunked: bool = False, marker: bytes | None = None, **request_kw) -> bytes:
    import urllib3

    class RawServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(socketserver.BaseRequestHandler):
        captures: list[bytes] = []

        def handle(self):
            data = b""
            self.request.settimeout(1)
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
                if marker is not None and marker in data:
                    break
                if marker is None and b"\r\n\r\n" in data:
                    break
            type(self).captures.append(data)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    server = RawServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager()
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        manager.request(method, url, headers=headers, body=body, chunked=chunked, **request_kw)
        return Handler.captures[-1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_status_sequence(statuses: list[int], retries):
    import urllib3

    class SequenceServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(http.server.BaseHTTPRequestHandler):
        count = 0

        def do_GET(self):
            index = min(type(self).count, len(statuses) - 1)
            type(self).count += 1
            self.send_response(statuses[index])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = SequenceServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager()
        return manager.request("GET", f"http://127.0.0.1:{server.server_address[1]}/status", retries=retries)
    finally:
        request_status_sequence.last_count = Handler.count
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


request_status_sequence.last_count = 0


def request_slow_response(timeout):
    import time
    import urllib3

    class SlowServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.3)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = SlowServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager()
        return manager.request("GET", f"http://127.0.0.1:{server.server_address[1]}/sleep", timeout=timeout, retries=False)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def capture_proxy_connect_line(target_url: str) -> str:
    import urllib3

    class ProxyServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(socketserver.BaseRequestHandler):
        lines: list[str] = []

        def handle(self):
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
            type(self).lines.append(line)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    server = ProxyServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proxy = urllib3.ProxyManager(f"http://127.0.0.1:{server.server_address[1]}")
        try:
            proxy.request("GET", target_url, retries=False, timeout=0.2)
        except Exception:
            pass
        return Handler.lines[-1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def trigger_https_proxy_misconfiguration_error() -> Exception:
    import urllib3

    class ProxyServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(4096)
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

    server = ProxyServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            urllib3.ProxyManager(f"https://127.0.0.1:{server.server_address[1]}").request(
                "GET",
                "https://example.test/",
                retries=False,
                timeout=0.2,
            )
        except Exception as error:
            return error
        raise AssertionError("expected HTTPS proxy misconfiguration error")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_loop_redirect(retries):
    import urllib3

    class LoopServer(socketserver.TCPServer):
        allow_reuse_address = True

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = LoopServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        manager = urllib3.PoolManager()
        return manager.request("GET", f"http://127.0.0.1:{server.server_address[1]}/loop", retries=retries)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def install_legacy_httpclient_shims() -> None:
    import http.client

    if not hasattr(http.client.HTTPResponse, "strict"):
        http.client.HTTPResponse.strict = 0

    init = http.client.HTTPConnection.__init__
    if "strict" in inspect.signature(init).parameters:
        return

    sentinel = object()

    def init_ignoring_strict(self, host, port=None, strict=None, timeout=sentinel, source_address=None, blocksize=8192):
        kwargs = {}
        if timeout is not sentinel:
            kwargs["timeout"] = timeout
        if source_address is not None:
            kwargs["source_address"] = source_address
        if "blocksize" in inspect.signature(init).parameters:
            kwargs["blocksize"] = blocksize
        return init(self, host, port=port, **kwargs)

    http.client.HTTPConnection.__init__ = init_ignoring_strict


def install_legacy_stdlib_shims() -> None:
    if "mimetools" not in sys.modules:
        module = types.ModuleType("mimetools")
        module.choose_boundary = lambda: "===============urllib3-replay-boundary=="
        sys.modules["mimetools"] = module


def capture_redirect_request(
    method: str = "GET",
    headers=None,
    body=None,
    status: int = 303,
    cross_host: bool = False,
    retries=None,
    **request_kw,
):
    import urllib3

    class TargetHandler(CaptureHandler):
        captures: list[dict[str, object]] = []

    target = CaptureServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    target_host = "127.0.0.1" if cross_host else None
    target_url = f"http://127.0.0.1:{target.server_address[1]}/target"

    class OriginHandler(CaptureHandler):
        captures: list[dict[str, object]] = []

        def do_GET(self):
            if self.path == "/target":
                self.capture_and_reply()
            else:
                self.redirect()

        def do_POST(self):
            if self.path == "/target":
                self.capture_and_reply()
            else:
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.redirect()

        def redirect(self):
            location = target_url if cross_host else "/target"
            self.send_response(status)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    origin = CaptureServer(("127.0.0.1", 0), OriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    if not cross_host:
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)
        target = origin
        TargetHandler = OriginHandler

    try:
        manager = urllib3.PoolManager()
        url = f"http://127.0.0.1:{origin.server_address[1]}/redirect"
        call_kw = dict(request_kw)
        if headers is not None:
            call_kw["headers"] = headers
        if body is not None:
            call_kw["body"] = body
        if retries is not None:
            call_kw["retries"] = retries
        response = manager.request(method, url, **call_kw)
        return {
            "response_status": response.status,
            "target_captures": getattr(TargetHandler, "captures", []),
            "target_url": target_url,
            "target_host": target_host,
        }
    finally:
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=2)
        if cross_host:
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)


def run_snippet(code: str) -> int:
    install_legacy_stdlib_shims()
    install_legacy_httpclient_shims()
    namespace: dict[str, object] = {
        "capture_request": capture_request,
        "capture_pool_request_path": capture_pool_request_path,
        "capture_redirect_request": capture_redirect_request,
        "capture_raw_request": capture_raw_request,
        "request_raw_response": request_raw_response,
        "request_status_sequence": request_status_sequence,
        "request_slow_response": request_slow_response,
        "capture_proxy_connect_line": capture_proxy_connect_line,
        "trigger_https_proxy_misconfiguration_error": trigger_https_proxy_misconfiguration_error,
        "request_loop_redirect": request_loop_redirect,
    }
    exec(textwrap.dedent(code), namespace)
    return 0


def run_direct(version: str, contract: str, mutant: str | None) -> int:
    key = f"{version}:{contract}"
    spec = CONTRACTS.get(key)
    if spec is None:
        print(f"Unsupported modern contract: {key}", file=sys.stderr)
        return 2
    if mutant and mutant != spec["mutant"]:
        print(f"Unsupported mutant {mutant!r} for {key}", file=sys.stderr)
        return 2
    return run_snippet(spec["mutant_code"] if mutant else spec["code"])


def run_direct_checked(version: str, contract: str, mutant: str | None) -> dict[str, object]:
    try:
        code = run_direct(version, contract, mutant)
        output = ""
    except BaseException as exc:
        code = 1
        output = f"{exc.__class__.__name__}: {exc}"
    return {
        "version": version,
        "contract": contract,
        "mutant": mutant,
        "exit_code": code,
        "output_tail": output[-2000:],
    }


def run_batch_direct(version: str) -> int:
    rows = []
    runner = os.path.relpath(pathlib.Path(__file__).resolve(), ROOT)
    for key, spec in CONTRACTS.items():
        contract_version, contract = key.split(":", 1)
        if contract_version != version:
            continue
        base = [
            sys.executable,
            *spec.get("python_flags", []),
            runner,
            "--env",
            "direct",
            "--version",
            version,
            "--contract",
            contract,
        ]
        replay_process = subprocess.run(base, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        mutant_process = subprocess.run(
            base + ["--mutant", spec["mutant"]],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        rows.append(
            {
                "version": version,
                "contract": contract,
                "mutant": spec["mutant"],
                "replay_exit_code": replay_process.returncode,
                "mutant_exit_code": mutant_process.returncode,
                "replay_output_tail": replay_process.stdout[-2000:],
                "mutant_output_tail": mutant_process.stdout[-2000:],
            }
        )
    print(json.dumps(rows, ensure_ascii=False))
    return 0 if all(row["replay_exit_code"] == 0 and row["mutant_exit_code"] != 0 for row in rows) else 1


def run_managed(version: str, contract: str, mutant: str | None) -> int:
    exe = ensure_venv(version)
    spec = CONTRACTS.get(f"{version}:{contract}", {})
    command = [str(exe), *spec.get("python_flags", []), str(pathlib.Path(__file__).resolve()), "--env", "direct", "--version", version, "--contract", contract]
    if mutant:
        command.extend(["--mutant", mutant])
    return subprocess.run(command, cwd=ROOT).returncode


def run_batch_managed(version: str) -> int:
    exe = ensure_venv(version)
    command = [str(exe), str(pathlib.Path(__file__).resolve()), "--env", "direct", "--version", version, "--batch"]
    return subprocess.run(command, cwd=ROOT).returncode


def docker_base_image(version: str) -> str:
    return "python:3.9-slim" if version.startswith("1.") else "python:3.12-slim"


def docker_pip_cache(version: str) -> pathlib.Path:
    cache = ROOT / ".replay" / "docker-pip-cache" / docker_base_image(version).replace(":", "-")
    cache.mkdir(parents=True, exist_ok=True)
    return cache


def docker_pip_install_command() -> str:
    optional_deps_prefix = "h2==4.1.0 zstandard"
    optional_deps_suffix = "PySocks pyOpenSSL"
    optional_deps = f"{optional_deps_prefix} $BROTLI_DEP {optional_deps_suffix}"
    legacy_pattern = "|".join(sorted(LEGACY_SDIST_INSTALLS))
    choose_brotli = 'case "$URLLIB3_VERSION" in 1.25) BROTLI_DEP=brotlipy ;; *) BROTLI_DEP=Brotli ;; esac'
    legacy_install = (
        "python -c 'import pathlib, sys; "
        "from tools.replay.replay_urllib3_modern import install_urllib3_release; "
        "install_urllib3_release(pathlib.Path(sys.executable), sys.argv[1])' \"$URLLIB3_VERSION\""
    )
    legacy_install = f"{legacy_install} && python -m pip install -q --root-user-action=ignore {optional_deps}"
    wheel_install = f"python -m pip install -q --root-user-action=ignore urllib3==$URLLIB3_VERSION {optional_deps}"
    return f"{choose_brotli}; case \"$URLLIB3_VERSION\" in {legacy_pattern}) {legacy_install} ;; *) {wheel_install} ;; esac"


def run_docker(version: str, contract: str, mutant: str | None) -> int:
    spec = CONTRACTS.get(f"{version}:{contract}", {})
    python_flags = " ".join(spec.get("python_flags", []))
    cache = docker_pip_cache(version)
    command = [
        "docker",
        "run",
        "--rm",
        "-e",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "-e",
        "PIP_ROOT_USER_ACTION=ignore",
        "-e",
        f"URLLIB3_VERSION={version}",
        "-e",
        f"CONTRACT_NAME={contract}",
        "-e",
        f"MUTANT_ARGS=--mutant {mutant}" if mutant else "MUTANT_ARGS=",
        "-v",
        f"{ROOT}:/workspace",
        "-v",
        f"{cache}:/root/.cache/pip",
        "-w",
        "/workspace",
        docker_base_image(version),
        "sh",
        "-c",
        f"{docker_pip_install_command()} && python {python_flags} tools/replay/replay_urllib3_modern.py --env direct --version $URLLIB3_VERSION --contract $CONTRACT_NAME $MUTANT_ARGS",
    ]
    return subprocess.run(command, cwd=ROOT).returncode


def run_batch_docker(version: str) -> int:
    cache = docker_pip_cache(version)
    command = [
        "docker",
        "run",
        "--rm",
        "-e",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "-e",
        "PIP_ROOT_USER_ACTION=ignore",
        "-e",
        f"URLLIB3_VERSION={version}",
        "-v",
        f"{ROOT}:/workspace",
        "-v",
        f"{cache}:/root/.cache/pip",
        "-w",
        "/workspace",
        docker_base_image(version),
        "sh",
        "-c",
        f"{docker_pip_install_command()} && python tools/replay/replay_urllib3_modern.py --env direct --version $URLLIB3_VERSION --batch",
    ]
    return subprocess.run(command, cwd=ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=["local", "venv", "docker", "direct"], default="local")
    parser.add_argument("--version", required=True)
    parser.add_argument("--contract")
    parser.add_argument("--mutant")
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()

    if args.batch:
        if args.env == "direct":
            return run_batch_direct(args.version)
        if args.env == "docker":
            return run_batch_docker(args.version)
        return run_batch_managed(args.version)
    if not args.contract:
        parser.error("--contract is required unless --batch is set")
    if args.env == "direct":
        return run_direct(args.version, args.contract, args.mutant)
    if args.env == "docker":
        return run_docker(args.version, args.contract, args.mutant)
    return run_managed(args.version, args.contract, args.mutant)


if __name__ == "__main__":
    raise SystemExit(main())
