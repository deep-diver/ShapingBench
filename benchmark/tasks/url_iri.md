You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python URL/IRI parsing and manipulation library named `solurl`.

Create whatever files are appropriate, but expose this public API:

- `from solurl import URL, parse_url, can_parse`
- `URL(input: str, base: str | URL | None = None)` parses an absolute URL, or resolves a relative reference against `base`.
- Invalid inputs should raise `ValueError`.
- URL instances expose string properties:
  - `href`
  - `origin`
  - `protocol`
  - `username`
  - `password`
  - `host`
  - `hostname`
  - `port`
  - `pathname`
  - `search`
  - `hash`
- The same components are settable where meaningful:
  - `href`
  - `protocol`
  - `username`
  - `password`
  - `host`
  - `hostname`
  - `port`
  - `pathname`
  - `search`
  - `hash`
- `str(url)` should return `url.href`.
- `parse_url(input, base=None)` should return a `URL`.
- `can_parse(input, base=None)` should return a boolean.
- `URL.can_parse(input, base=None)` should also work.

Aim for mature behavior across common modern URL/IRI expectations: relative resolution, component extraction, percent encoding, IDNA host handling, IPv4/IPv6 hosts, file URLs, non-special schemes, query and fragment handling, path normalization, setter semantics, and stable serialization. Add tests and documentation if useful.

Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
