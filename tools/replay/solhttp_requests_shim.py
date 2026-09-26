from __future__ import annotations

import types
import urllib.parse
from dataclasses import dataclass


class _HeaderList:
    def __init__(self, headers):
        self._headers = headers

    def getlist(self, name: str) -> list[str]:
        if hasattr(self._headers, "get_all"):
            return self._headers.get_all(name)
        value = self._headers.get(name)
        return [] if value is None else [value]


class _RawShim:
    def __init__(self, response):
        self._response = response
        self.decode_content = False
        self.headers = _HeaderList(response.headers)
        self._decoded_buffer = b""
        self._decoded_iter = None

    def read(self, size: int | None = -1, decode_content: bool | None = None):
        decoded = self.decode_content if decode_content is None else decode_content
        if decoded:
            if self._decoded_iter is None:
                self._decoded_iter = self._response.iter_bytes(65536)
            if size is None or size < 0:
                buffered = self._decoded_buffer
                self._decoded_buffer = b""
                return buffered + b"".join(self._decoded_iter)
            chunks = bytearray()
            while len(chunks) < size:
                if self._decoded_buffer:
                    take = min(size - len(chunks), len(self._decoded_buffer))
                    chunks.extend(self._decoded_buffer[:take])
                    self._decoded_buffer = self._decoded_buffer[take:]
                    continue
                try:
                    self._decoded_buffer = next(self._decoded_iter)
                except StopIteration:
                    break
            return bytes(chunks)
        return self._response._raw.read(65536 if size is None or size < 0 else size)


class _ResponseShim:
    def __init__(self, response):
        self._response = response
        self.raw = _RawShim(response)
        self.history = [_ResponseShim(item) for item in getattr(response, "history", [])]

    @property
    def status_code(self):
        return self._response.status_code

    @status_code.setter
    def status_code(self, value):
        self._response.status_code = value

    @property
    def headers(self):
        return self._response.headers

    @property
    def text(self):
        return self._response.text

    @property
    def content(self):
        return self._response.content

    @property
    def url(self):
        return self._response.url

    @property
    def ok(self):
        return self._response.ok

    def json(self, **kwargs):
        return self._response.json(**kwargs)

    def close(self):
        return self._response.close()

    def iter_content(self, chunk_size=1, decode_unicode=False):
        for chunk in self._response.iter_bytes(chunk_size):
            yield chunk.decode(self._response.encoding, "replace") if decode_unicode else chunk

    def iter_lines(self):
        pending = b""
        for chunk in self.iter_content(65536):
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                yield line.rstrip(b"\r")
        if pending:
            yield pending.rstrip(b"\r")

    def raise_for_status(self):
        return self._response.raise_for_status()


class _HTTPAdapter:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def init_poolmanager(self, *args, **kwargs):
        self.poolmanager_kwargs = kwargs


class _MissingSchema(ValueError):
    pass


@dataclass
class _PreparedRequest:
    method: str
    url: str


class _Request:
    def __init__(self, method, url, **kwargs):
        self.method = method
        self.url = url

    def prepare(self):
        return _PreparedRequest(self.method, _prepare_url(self.url))


class _Session:
    def __init__(self, impl):
        self._impl = impl
        self._client = impl.Client()
        self.headers = self._client.headers
        self.trust_env = True
        self._adapters = {}

    def mount(self, prefix, adapter):
        self._adapters[prefix] = adapter

    def request(self, method, url, **kwargs):
        return _request(self._impl, self._client, method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def close(self):
        self._client.close()


def make_requests_like(impl):
    request_error = getattr(impl, "RequestError", getattr(impl, "SolHTTPError", Exception))
    connection_error = getattr(impl, "ConnectionError", request_error)
    timeout_error = getattr(impl, "Timeout", request_error)
    protocol_error = getattr(impl, "ProtocolError", request_error)
    shim = types.SimpleNamespace()
    shim.__version__ = getattr(impl, "__version__", "unknown")
    shim.HTTPAdapter = _HTTPAdapter
    shim.adapters = types.SimpleNamespace(HTTPAdapter=_HTTPAdapter)
    shim.Request = _Request
    shim.Session = lambda: _Session(impl)
    shim.exceptions = types.SimpleNamespace(
        RequestException=getattr(impl, "SolHTTPError", request_error),
        Timeout=timeout_error,
        ConnectionError=connection_error,
        ProxyError=connection_error,
        SSLError=connection_error,
        ChunkedEncodingError=protocol_error,
        MissingSchema=_MissingSchema,
    )
    for method in ("get", "post", "put", "patch", "delete", "head", "options"):
        setattr(shim, method, lambda url, _method=method.upper(), **kwargs: _request(impl, impl.Client(), _method, url, **kwargs))
    shim.request = lambda method, url, **kwargs: _request(impl, impl.Client(), method, url, **kwargs)
    return shim


def _request(impl, client, method, url, **kwargs):
    mapped = {
        "params": kwargs.get("params"),
        "headers": kwargs.get("headers"),
        "data": kwargs.get("data"),
        "files": kwargs.get("files"),
        "json": kwargs.get("json"),
        "timeout": _timeout(impl, kwargs.get("timeout")),
        "follow_redirects": kwargs.get("allow_redirects", True),
        "stream": kwargs.get("stream", False),
        "proxy": kwargs.get("proxy") if "proxy" in kwargs else kwargs.get("proxies"),
    }
    if "verify" in kwargs:
        mapped["verify"] = kwargs["verify"]
    if "cert" in kwargs:
        mapped["cert"] = kwargs["cert"]
    mapped = {key: value for key, value in mapped.items() if value is not None}
    if "verify" in mapped or "cert" in mapped:
        scoped = impl.Client(
            headers=getattr(client, "headers", None),
            timeout=getattr(client, "timeout", 30.0),
            verify=mapped.pop("verify", True),
            cert=mapped.pop("cert", None),
            proxy=getattr(client, "proxy", None),
            follow_redirects=getattr(client, "follow_redirects", True),
            max_redirects=getattr(client, "max_redirects", 10),
        )
        client = scoped
    try:
        return _ResponseShim(client.request(method, url, **mapped))
    except impl.InvalidURL as exc:
        if not url:
            raise _MissingSchema(str(exc)) from exc
        raise
    except impl.Timeout:
        raise
    except impl.ConnectionError:
        raise
    except impl.SolHTTPError:
        raise


def _timeout(impl, value):
    if value is None:
        return None
    if isinstance(value, tuple):
        return impl.TimeoutConfig(value[0], value[1])
    return value


def _prepare_url(url):
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("URL must be absolute")
    if parsed.port is not None and not parsed.netloc.rsplit(":", 1)[-1].isascii():
        raise ValueError("unicode ports are not accepted")
    scheme = parsed.scheme.lower()
    hostname = _idna_encode((parsed.hostname or "").lower())
    if ":" in hostname and not parsed.netloc.startswith("["):
        raise ValueError("bare IPv6 literals require brackets")
    if "%" in hostname and ":" in hostname:
        hostname = hostname.replace("%", "%25")
    userinfo = ""
    if parsed.username is not None:
        userinfo = urllib.parse.quote(parsed.username, safe="") 
        if parsed.password is not None:
            userinfo += ":" + urllib.parse.quote(parsed.password, safe="")
        userinfo += "@"
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    port = "" if parsed.port is None else f":{parsed.port}"
    path = urllib.parse.quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(parsed.query, safe="%=&?/:;+,$@[]!~*'()-._")
    fragment = urllib.parse.quote(parsed.fragment, safe="%=&?/:;+,$@[]!~*'()-._")
    return urllib.parse.urlunsplit((scheme, userinfo + host + port, path, query, fragment))


def _idna_encode(hostname: str) -> str:
    if ":" in hostname:
        return hostname
    trailing_dot = hostname.endswith(".")
    value = hostname[:-1] if trailing_dot else hostname
    try:
        import idna

        encoded = idna.encode(value, uts46=True).decode("ascii")
    except ImportError:
        encoded = value.encode("idna").decode("ascii")
    return encoded + ("." if trailing_dot else "")
