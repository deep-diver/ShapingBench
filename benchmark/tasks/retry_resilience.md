You are working in an empty independent workspace.

Implement a production-quality, dependency-light Python retry / backoff / resilience policy library named `solretry`.

Create whatever files are appropriate, but expose this public API:

- `from solretry import retry, RetryPolicy, retryable`
- `retry(fn, *, max_attempts: int = 3, wait: float = 0, retry_exceptions: tuple[type[BaseException], ...] | type[BaseException] = Exception, retry_on_result=None, on_retry=None, raise_on_giveup: bool = True, **kwargs) -> object`
- `RetryPolicy(max_attempts: int = 3, wait: float = 0, retry_exceptions=Exception, retry_on_result=None, on_retry=None, raise_on_giveup: bool = True, **kwargs)`
- `RetryPolicy.call(fn, *args, **kwargs) -> object`
- `retryable(...)` as a decorator factory using the same options as `retry`.

Expected behavior:

- Retry callables that raise configured exceptions until they succeed or the attempt limit is reached.
- Treat `max_attempts` as total attempts, including the first attempt.
- Validate attempt limits sensibly; values below one should behave as one attempt.
- Do not retry exceptions outside the configured retry exception set.
- Preserve and re-raise the final exception on give-up by default.
- Support zero wait and small fixed waits without requiring real long sleeps.
- Call `on_retry` after failed attempts that will be retried, passing useful information such as the exception and attempt number.
- Return successful values unchanged, including falsey values.
- Provide a small, practical API surface rather than a large framework.
- Keep behavior deterministic and easy to test locally.
- Add tests or examples if helpful.

Do not assume access to any external hidden contract corpus. Do not ask questions. Implement, test locally, and leave the final implementation in this workspace.
