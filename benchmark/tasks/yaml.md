You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python YAML parser/emitter library named `solyaml`.

Create whatever files are appropriate, but expose this public API:

- `from solyaml import parse, parse_all, dump, dump_all`
- `parse(yaml_text: str | bytes | None, *, options: dict | None = None) -> object`
- `parse_all(yaml_text: str | bytes | None, *, options: dict | None = None) -> list[object]`
- `dump(value: object, *, options: dict | None = None) -> str`
- `dump_all(values: list[object], *, options: dict | None = None) -> str`

Expected behavior:

- Parse YAML streams into deterministic Python values using ordinary data types: `dict`, `list`, `str`, `int`, `float`, `bool`, and `None`.
- Support mature YAML behavior across block and flow mappings/sequences, plain/single/double quoted scalars, literal and folded block scalars, anchors and aliases, merge keys, explicit tags for common YAML scalar types, multiple documents, directives, comments, Unicode input, UTF BOMs, and practical JSON-subset parsing.
- Detect malformed YAML with clear exceptions.
- Emit deterministic YAML for ordinary Python values and preserve semantic round trips through `parse` and `parse_all`.
- Handle common YAML 1.1 and YAML 1.2 scalar resolution behavior pragmatically, especially booleans, nulls, integers, floats, infinities, NaN values, and quoted strings.
- `options` may contain booleans or nested dictionaries for loader/emitter preferences. Treat unknown options safely.
- Serialization should be stable and conventional enough for mature YAML parser/emitters.

You may add tests, documentation, and dependencies if useful, but keep the package practical and easy to run locally.

Do not assume access to any external hidden contract corpus. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
