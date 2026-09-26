You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python HTTP client library named `solhttp`.

Create whatever files are appropriate, but expose this public API:

- `from solhttp import Client, request, get, post, put, patch, delete, head, options`
- `Client()` creates a reusable client with connection pooling where possible.
- `Client.request(method, url, **kwargs)` performs an HTTP request.
- Top-level `request`, `get`, `post`, `put`, `patch`, `delete`, `head`, and `options` functions should work without explicitly constructing a client.
- Responses expose:
  - `status_code`
  - `headers`
  - `content`
  - `text`
  - `url`
  - `ok`
  - `history`
  - `json(**kwargs)`
  - `iter_bytes(chunk_size=1)`
  - `close()`
  - `raise_for_status()`
- Support common request options:
  - `params`
  - `headers`
  - `data`
  - `files`
  - `json`
  - `timeout`
  - `follow_redirects`
  - `stream`
  - `verify`
  - `cert`
  - `proxy`
- Define a useful exception hierarchy including:
  - `SolHTTPError`
  - `RequestError`
  - `InvalidURL`
  - `ConnectionError`
  - `Timeout`
  - `ProtocolError`
  - `HTTPStatusError`
  - `TooManyRedirects`
  - `TimeoutConfig`

Aim for mature behavior across common HTTP client expectations: request construction, URL normalization, query parameters, form bodies, multipart file uploads, JSON bodies, redirects, cookies, response streaming, decompression, connection reuse, retries where appropriate, timeout handling, TLS verification, proxies, error classification, and stable response metadata.

Add tests and documentation if useful. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
