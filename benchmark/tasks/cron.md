You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python cron / schedule expression engine named `solcron`.

Create whatever files are appropriate, but expose this public API:

- `from solcron import parse, is_valid, normalize, next_dates, prev_dates, match`
- `parse(expression: str, *, options: dict | None = None) -> object`
- `is_valid(expression: str, *, options: dict | None = None) -> bool`
- `normalize(expression: str, *, include_seconds: bool = False, options: dict | None = None) -> str`
- `next_dates(expression: str, start: str | object, count: int = 1, *, options: dict | None = None) -> list[str]`
- `prev_dates(expression: str, start: str | object, count: int = 1, *, options: dict | None = None) -> list[str]`
- `match(expression: str, date: str | object, *, options: dict | None = None) -> bool`

Expected behavior:

- Parse ordinary 5-field crontab expressions and practical 6-field expressions with seconds.
- Support wildcards, lists, ranges, steps, month/day names, whitespace normalization, and common validation errors.
- Compute deterministic next and previous run dates from ISO-8601 start times.
- Return date strings in stable ISO-8601 UTC form when possible.
- Support matching a date against an expression.
- Handle practical timezone-aware ISO inputs and naive ISO inputs consistently.
- Treat unknown options safely; useful options may include timezone, day-of-month/day-of-week matching policy, and second-field position.
- Detect malformed expressions with clear exceptions.
- Keep the library simple to install and easy to run locally.

You may add tests, documentation, and small dependencies if useful, but keep the package practical.

Do not assume access to any external hidden contract corpus. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
