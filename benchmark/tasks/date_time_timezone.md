Implement a compact standalone date/time/timezone library.

Create an executable `./dtlib`. It must read one JSON object from stdin and
write one JSON object to stdout. The input has a `replay` operation name and
optional `params`. Semantic errors should be JSON such as `{"throws":"parse"}`.

Do not inspect benchmark files, evaluator outputs, hidden corpora, or previous
answers. Do not hard-code tests. This is the first no-hint implementation.

Implement broad, practical behavior for dates, times, datetimes, instants,
durations, periods, intervals, fixed offsets, IANA zones, DST gaps/overlaps,
epoch conversion, local/zoned conversion, and common parsing/formatting. Be
generous with operation-name aliases and return specific JSON fields like
`value`, `date`, `time`, `datetime`, `instant`, `offset`, `millis`, `seconds`,
`start`, `end`, `id`, `ids`, `canonical_id`, `exists`, and `ambiguous`.

Keep the implementation compact and create a meaningful local self-test. Avoid
large preliminary exploration and avoid enormous single shell commands.
