You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python JWT signing and verification library named `soljwt`.

Create whatever files are appropriate, but expose this public API:

- `from soljwt import encode, decode, verify`
- `encode(payload: dict, key: str | bytes | None = None, *, algorithm: str = "HS256", headers: dict | None = None, options: dict | None = None) -> str`
- `decode(token: str, key: str | bytes | None = None, *, algorithms: list[str] | None = None, verify: bool = True, options: dict | None = None, audience: str | list[str] | None = None, issuer: str | list[str] | None = None, subject: str | None = None, leeway: int | float = 0, current_time: int | float | None = None, complete: bool = False) -> dict`
- `verify(token: str, key: str | bytes | None = None, **kwargs) -> dict`

Expected behavior:

- Encode and decode compact JWT/JWS strings deterministically.
- Support practical HMAC algorithms HS256, HS384, and HS512.
- Support unsigned `none` tokens only when explicitly requested and never as a permissive verification default.
- Preserve and expose protected headers and JSON payload claims when `complete=True`.
- Verify signatures, algorithm allow-lists, and common registered claims: `exp`, `nbf`, `iat`, `iss`, `sub`, `aud`, and `jti`.
- Support ordinary custom JSON claims including strings, numbers, booleans, nulls, arrays, and nested objects.
- Support useful verification options such as disabling expiration or not-before checks, explicit current time, clock tolerance/leeway, required claims, and complete-result verification.
- Detect malformed compact tokens, invalid base64url, invalid JSON, unsupported algorithms, bad signatures, and invalid claim types with clear exceptions.
- Keep serialization stable and conventional enough for mature JWT libraries.

You may add tests, documentation, and small dependencies if useful, but keep the package practical and easy to run locally.

Do not assume access to any external hidden contract corpus. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
