You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python Markdown parser/renderer library named `solmarkdown`.

Create whatever files are appropriate, but expose this public API:

- `from solmarkdown import render, render_inline`
- `render(markdown: str | None, *, options: dict | None = None) -> str`
- `render_inline(markdown: str | None, *, options: dict | None = None) -> str`

Expected behavior:

- Convert Markdown text to deterministic HTML.
- Support mature CommonMark-style behavior across paragraphs, emphasis, strong emphasis, code spans, fenced and indented code blocks, block quotes, ATX and Setext headings, thematic breaks, ordered and unordered lists, nested lists, links, images, autolinks, raw HTML handling, entities, escaping, hard and soft line breaks, and edge-case parser regressions.
- Support practical extension behavior where enabled through `options`, including tables, strikethrough, task lists, typographer/smart punctuation, linkify/autolink-style URL handling, heading attributes and generated heading IDs, definition lists, footnotes, metadata/front-matter style blocks, math-ish spans/blocks, wiki links, XHTML-style empty tags, unsafe/raw HTML toggles, and line-break options.
- `render_inline` should render inline Markdown without wrapping it in a paragraph.
- `options` may contain booleans, nested option dictionaries, an `enabled` list, or preset-style values. Treat unknown options safely.
- HTML serialization should be stable and conventional enough for mature Markdown parser/renderers.

You may add tests, documentation, and dependencies if useful, but keep the package practical and easy to run locally.

Do not inspect parent directories or any benchmark/evaluator/contract corpus outside this workspace. Do not assume access to any external hidden contract corpus. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
