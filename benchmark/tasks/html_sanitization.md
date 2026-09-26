Implement a production-quality, dependency-light Python HTML sanitizer library named `solsanitize`.

Public API:

- `from solsanitize import sanitize, is_valid`
- `sanitize(html: str | None, *, config: dict | None = None, policy: dict | str | None = None, base_url: str | None = None) -> str`
- `is_valid(html: str | None, *, config: dict | None = None, policy: dict | str | None = None, base_url: str | None = None) -> bool`

Expected behavior:

- Accept an HTML fragment or document-ish string and return a sanitized HTML fragment string.
- Remove dangerous scripting, event handlers, unsafe URLs, unsafe attributes, and unsafe namespaced markup.
- Preserve common safe formatting, links, images, tables, SVG/MathML-safe fragments, and text where appropriate.
- Support configurable policies for allowed/forbidden tags, allowed/forbidden attributes, URL protocols, relative URL handling, CSS/style handling, and simple canned policies such as formatting, blocks, links, images, tables, and relaxed/basic/simple-text styles.
- Decode and serialize HTML entities consistently enough for mature sanitizer behavior.
- `is_valid` should report whether sanitization would leave the observable fragment unchanged under the selected policy.

You may add tests, documentation, and dependencies if useful, but keep the package practical and easy to run locally. Do not assume access to any external hidden contract corpus.

Fairness constraint: do not inspect benchmark files, evaluator outputs, hidden corpora, previous generated implementations, previous experiment summaries, or any contract corpus in this repository. Work only from this prompt and your general knowledge.
