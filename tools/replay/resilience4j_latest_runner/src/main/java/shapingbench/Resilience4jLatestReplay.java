package shapingbench;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.resilience4j.bulkhead.Bulkhead;
import io.github.resilience4j.bulkhead.BulkheadConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.core.functions.CheckedSupplier;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.timelimiter.TimeLimiter;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

public class Resilience4jLatestReplay {
    static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    static class TransientFailure extends RuntimeException {
        TransientFailure(String message) { super(message); }
    }

    static class IgnoredFailure extends RuntimeException {
        IgnoredFailure(String message) { super(message); }
    }

    static class CheckedFailure extends Exception {
        CheckedFailure(String message) { super(message); }
    }

    static class MutableClock extends Clock {
        Instant instant = Instant.EPOCH;

        void advanceMillis(long millis) {
            instant = instant.plusMillis(millis);
        }

        @Override public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override public Instant instant() {
            return instant;
        }
    }

    static class NeverFuture<T> implements Future<T> {
        boolean cancelled;

        @Override public boolean cancel(boolean mayInterruptIfRunning) {
            cancelled = true;
            return true;
        }

        @Override public boolean isCancelled() {
            return cancelled;
        }

        @Override public boolean isDone() {
            return false;
        }

        @Override public T get() throws InterruptedException {
            Thread.sleep(10_000);
            return null;
        }

        @Override public T get(long timeout, TimeUnit unit) throws TimeoutException {
            throw new TimeoutException("synthetic timeout");
        }
    }

    static int integer(JsonObject object, String key, int fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsInt() : fallback;
    }

    static long lng(JsonObject object, String key, long fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsLong() : fallback;
    }

    static double dbl(JsonObject object, String key, double fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsDouble() : fallback;
    }

    static boolean bool(JsonObject object, String key, boolean fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsBoolean() : fallback;
    }

    static String string(JsonObject object, String key, String fallback) {
        return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsString() : fallback;
    }

    static JsonObject object(JsonObject parent, String key) {
        return parent.getAsJsonObject(key);
    }

    static JsonArray array(JsonObject parent, String key) {
        return parent.has(key) && parent.get(key).isJsonArray() ? parent.getAsJsonArray(key) : new JsonArray();
    }

    static Map<String, Object> result() {
        return new LinkedHashMap<>();
    }

    static Map<String, Object> error(Throwable throwable) {
        Throwable t = unwrap(throwable);
        Map<String, Object> out = result();
        out.put("status", "raised");
        out.put("errorType", t.getClass().getSimpleName());
        out.put("errorMessagePrefix", t.getMessage() == null ? "" : t.getMessage().substring(0, Math.min(60, t.getMessage().length())));
        return out;
    }

    static Throwable unwrap(Throwable throwable) {
        if (throwable instanceof ExecutionException && throwable.getCause() != null) return unwrap(throwable.getCause());
        if (throwable.getCause() != null && throwable.getClass().getSimpleName().contains("CompletionException")) return unwrap(throwable.getCause());
        return throwable;
    }

    static RuntimeException runtimeFor(String kind, int attempt) {
        if ("ignored".equals(kind)) return new IgnoredFailure("ignored-" + attempt);
        if ("runtime".equals(kind)) return new IllegalStateException("runtime-" + attempt);
        return new TransientFailure("transient-" + attempt);
    }

    static Exception checkedFor(String kind, int attempt) {
        if ("checked".equals(kind)) return new CheckedFailure("checked-" + attempt);
        return runtimeFor(kind, attempt);
    }

    @SuppressWarnings("unchecked")
    static Class<? extends Throwable>[] classes(JsonArray names) {
        List<Class<? extends Throwable>> out = new ArrayList<>();
        for (JsonElement name : names) {
            switch (name.getAsString()) {
                case "ignored" -> out.add(IgnoredFailure.class);
                case "runtime" -> out.add(IllegalStateException.class);
                case "checked" -> out.add(CheckedFailure.class);
                default -> out.add(TransientFailure.class);
            }
        }
        return out.toArray(new Class[0]);
    }

    static Map<String, Object> retryMetrics(Retry retry) {
        Map<String, Object> out = result();
        Retry.Metrics m = retry.getMetrics();
        out.put("successNoRetry", m.getNumberOfSuccessfulCallsWithoutRetryAttempt());
        out.put("failureNoRetry", m.getNumberOfFailedCallsWithoutRetryAttempt());
        out.put("successWithRetry", m.getNumberOfSuccessfulCallsWithRetryAttempt());
        out.put("failureWithRetry", m.getNumberOfFailedCallsWithRetryAttempt());
        out.put("total", m.getNumberOfTotalCalls());
        return out;
    }

    static RetryConfig retryConfig(JsonObject params, AtomicInteger consumedBeforeRetry) {
        RetryConfig.Builder<String> builder = RetryConfig.<String>custom()
            .maxAttempts(integer(params, "maxAttempts", 3))
            .waitDuration(Duration.ofMillis(lng(params, "waitMillis", 0)))
            .failAfterMaxAttempts(bool(params, "failAfterMaxAttempts", false))
            .writableStackTraceEnabled(bool(params, "writableStackTrace", true));
        if (params.has("retryExceptions")) {
            builder.retryExceptions(classes(array(params, "retryExceptions")));
        }
        if (params.has("ignoreExceptions")) {
            builder.ignoreExceptions(classes(array(params, "ignoreExceptions")));
        }
        String retryOnResult = string(params, "retryOnResult", "");
        if (!retryOnResult.isEmpty()) {
            builder.retryOnResult(value -> Objects.equals(value, retryOnResult));
            builder.consumeResultBeforeRetryAttempt((attempt, value) -> consumedBeforeRetry.incrementAndGet());
        }
        String interval = string(params, "interval", "");
        if ("exponential".equals(interval)) {
            builder.intervalFunction(IntervalFunction.ofExponentialBackoff(
                lng(params, "initialIntervalMillis", 1),
                dbl(params, "multiplier", 2.0),
                lng(params, "maxIntervalMillis", 10_000)
            ));
        } else if ("fixed".equals(interval)) {
            builder.intervalFunction(IntervalFunction.of(lng(params, "initialIntervalMillis", lng(params, "waitMillis", 0))));
        }
        return builder.build();
    }

    static Map<String, Object> runRetryCall(JsonObject params) {
        AtomicInteger consumedBeforeRetry = new AtomicInteger();
        Retry retry = Retry.of("shape-retry", retryConfig(params, consumedBeforeRetry));
        AtomicInteger onRetry = new AtomicInteger();
        AtomicInteger onSuccess = new AtomicInteger();
        AtomicInteger onError = new AtomicInteger();
        AtomicInteger onIgnored = new AtomicInteger();
        retry.getEventPublisher()
            .onRetry(event -> onRetry.incrementAndGet())
            .onSuccess(event -> onSuccess.incrementAndGet())
            .onError(event -> onError.incrementAndGet())
            .onIgnoredError(event -> onIgnored.incrementAndGet());

        JsonArray outcomes = array(params, "outcomes");
        AtomicInteger attempts = new AtomicInteger();
        CheckedSupplier<String> supplier = () -> {
            int attempt = attempts.incrementAndGet();
            String outcome = outcomes.size() == 0
                ? "ok"
                : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
            if (outcome.startsWith("throw:")) {
                throw checkedFor(outcome.substring("throw:".length()), attempt);
            }
            return outcome;
        };

        Map<String, Object> out = result();
        try {
            String value = Retry.decorateCheckedSupplier(retry, supplier).get();
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("events", Map.of(
            "retry", onRetry.get(),
            "success", onSuccess.get(),
            "error", onError.get(),
            "ignoredError", onIgnored.get(),
            "consumeResultBeforeRetry", consumedBeforeRetry.get()
        ));
        out.put("metrics", retryMetrics(retry));
        return out;
    }

    static Map<String, Object> runRetrySequence(JsonObject params) {
        AtomicInteger consumedBeforeRetry = new AtomicInteger();
        Retry retry = Retry.of("shape-retry-sequence", retryConfig(params, consumedBeforeRetry));
        AtomicInteger onRetry = new AtomicInteger();
        AtomicInteger onSuccess = new AtomicInteger();
        AtomicInteger onError = new AtomicInteger();
        AtomicInteger onIgnored = new AtomicInteger();
        retry.getEventPublisher()
            .onRetry(event -> onRetry.incrementAndGet())
            .onSuccess(event -> onSuccess.incrementAndGet())
            .onError(event -> onError.incrementAndGet())
            .onIgnoredError(event -> onIgnored.incrementAndGet());

        List<Object> calls = new ArrayList<>();
        for (JsonElement callElement : array(params, "calls")) {
            JsonArray outcomes = callElement.getAsJsonArray();
            AtomicInteger attempts = new AtomicInteger();
            CheckedSupplier<String> supplier = () -> {
                int attempt = attempts.incrementAndGet();
                String outcome = outcomes.size() == 0
                    ? "ok"
                    : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
                if (outcome.startsWith("throw:")) {
                    throw checkedFor(outcome.substring("throw:".length()), attempt);
                }
                return outcome;
            };
            Map<String, Object> call = result();
            try {
                String value = Retry.decorateCheckedSupplier(retry, supplier).get();
                call.put("status", "returned");
                call.put("value", value);
            } catch (Throwable t) {
                call.putAll(error(t));
            }
            call.put("attempts", attempts.get());
            call.put("metrics", retryMetrics(retry));
            calls.add(call);
        }
        Map<String, Object> out = result();
        out.put("calls", calls);
        out.put("events", Map.of(
            "retry", onRetry.get(),
            "success", onSuccess.get(),
            "error", onError.get(),
            "ignoredError", onIgnored.get(),
            "consumeResultBeforeRetry", consumedBeforeRetry.get()
        ));
        out.put("finalMetrics", retryMetrics(retry));
        return out;
    }

    static Map<String, Object> runRetryConfig(JsonObject params) {
        AtomicInteger consumedBeforeRetry = new AtomicInteger();
        RetryConfig config = retryConfig(params, consumedBeforeRetry);
        Map<String, Object> out = result();
        out.put("maxAttempts", config.getMaxAttempts());
        out.put("failAfterMaxAttempts", config.isFailAfterMaxAttempts());
        out.put("writableStackTrace", config.isWritableStackTraceEnabled());
        JsonArray attempts = array(params, "intervalAttempts");
        List<Long> intervals = new ArrayList<>();
        for (JsonElement value : attempts) {
            intervals.add(config.getIntervalFunction().apply(value.getAsInt()));
        }
        out.put("intervalsMillis", intervals);
        return out;
    }

    static CircuitBreakerConfig circuitConfig(JsonObject params, MutableClock clock) {
        CircuitBreakerConfig.Builder builder = CircuitBreakerConfig.custom()
            .failureRateThreshold((float) dbl(params, "failureRateThreshold", 50.0))
            .slowCallRateThreshold((float) dbl(params, "slowCallRateThreshold", 100.0))
            .slowCallDurationThreshold(Duration.ofMillis(lng(params, "slowCallMillis", 60_000)))
            .waitDurationInOpenState(Duration.ofMillis(lng(params, "waitOpenMillis", 60_000)))
            .permittedNumberOfCallsInHalfOpenState(integer(params, "halfOpenPermits", 2))
            .slidingWindowSize(integer(params, "slidingWindowSize", 4))
            .minimumNumberOfCalls(integer(params, "minimumNumberOfCalls", 2))
            .slidingWindowType("time".equals(string(params, "windowType", "count"))
                ? CircuitBreakerConfig.SlidingWindowType.TIME_BASED
                : CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .writableStackTraceEnabled(bool(params, "writableStackTrace", true))
            .clock(clock);
        if (bool(params, "automaticTransition", false)) {
            builder.automaticTransitionFromOpenToHalfOpenEnabled(true);
        }
        if (params.has("initialState")) {
            builder.initialState(CircuitBreaker.State.valueOf(string(params, "initialState", "CLOSED")));
        }
        if (params.has("recordExceptions")) {
            builder.recordExceptions(classes(array(params, "recordExceptions")));
        }
        if (params.has("ignoreExceptions")) {
            builder.ignoreExceptions(classes(array(params, "ignoreExceptions")));
        }
        if (params.has("ignoreExceptionsPrecedence")) {
            builder.ignoreExceptionsPrecedenceEnabled(bool(params, "ignoreExceptionsPrecedence", true));
        }
        String badResult = string(params, "recordResultValue", "");
        if (!badResult.isEmpty()) {
            builder.recordResult(value -> Objects.equals(value, badResult));
        }
        return builder.build();
    }

    static Map<String, Object> cbMetrics(CircuitBreaker cb) {
        CircuitBreaker.Metrics m = cb.getMetrics();
        Map<String, Object> out = result();
        out.put("failureRate", Math.round(m.getFailureRate() * 1000.0) / 1000.0);
        out.put("slowCallRate", Math.round(m.getSlowCallRate() * 1000.0) / 1000.0);
        out.put("buffered", m.getNumberOfBufferedCalls());
        out.put("failed", m.getNumberOfFailedCalls());
        out.put("successful", m.getNumberOfSuccessfulCalls());
        out.put("slow", m.getNumberOfSlowCalls());
        out.put("notPermitted", m.getNumberOfNotPermittedCalls());
        return out;
    }

    static Map<String, Object> cbSnapshot(CircuitBreaker cb) {
        Map<String, Object> out = result();
        out.put("state", cb.getState().name());
        out.put("metrics", cbMetrics(cb));
        return out;
    }

    static Map<String, Object> runCircuitBreakerSequence(JsonObject params) {
        MutableClock clock = new MutableClock();
        CircuitBreaker cb = CircuitBreaker.of("shape-cb", circuitConfig(params, clock));
        AtomicInteger transitions = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger ignoredErrors = new AtomicInteger();
        AtomicInteger notPermitted = new AtomicInteger();
        cb.getEventPublisher()
            .onStateTransition(event -> transitions.incrementAndGet())
            .onError(event -> errors.incrementAndGet())
            .onSuccess(event -> successes.incrementAndGet())
            .onIgnoredError(event -> ignoredErrors.incrementAndGet())
            .onCallNotPermitted(event -> notPermitted.incrementAndGet());

        List<Object> events = new ArrayList<>();
        for (JsonElement element : array(params, "actions")) {
            JsonObject action = element.getAsJsonObject();
            String op = string(action, "op", "");
            Map<String, Object> event = result();
            event.put("op", op);
            try {
                switch (op) {
                    case "success" -> cb.onSuccess(lng(action, "durationMillis", 0), TimeUnit.MILLISECONDS);
                    case "error" -> cb.onError(lng(action, "durationMillis", 0), TimeUnit.MILLISECONDS, runtimeFor(string(action, "kind", "transient"), events.size() + 1));
                    case "checked_error" -> cb.onError(lng(action, "durationMillis", 0), TimeUnit.MILLISECONDS, checkedFor("checked", events.size() + 1));
                    case "result" -> cb.onResult(lng(action, "durationMillis", 0), TimeUnit.MILLISECONDS, string(action, "value", "ok"));
                    case "try_acquire" -> event.put("value", cb.tryAcquirePermission());
                    case "release" -> cb.releasePermission();
                    case "transition_open" -> cb.transitionToOpenState();
                    case "transition_open_for" -> cb.transitionToOpenStateFor(Duration.ofMillis(lng(action, "millis", 1)));
                    case "transition_half_open" -> cb.transitionToHalfOpenState();
                    case "transition_closed" -> cb.transitionToClosedState();
                    case "transition_disabled" -> cb.transitionToDisabledState();
                    case "transition_metrics_only" -> cb.transitionToMetricsOnlyState();
                    case "transition_forced_open" -> cb.transitionToForcedOpenState();
                    case "reset" -> cb.reset();
                    case "advance" -> {
                        clock.advanceMillis(lng(action, "millis", 0));
                        event.put("nowMillis", clock.instant.toEpochMilli());
                    }
                    case "execute_success" -> event.put("value", cb.executeSupplier(() -> string(action, "value", "ok")));
                    case "execute_error" -> cb.executeSupplier(() -> {
                        throw runtimeFor(string(action, "kind", "transient"), events.size() + 1);
                    });
                    default -> throw new IllegalArgumentException("unknown circuitbreaker op " + op);
                }
                event.put("status", "ok");
            } catch (Throwable t) {
                event.putAll(error(t));
            }
            event.putAll(cbSnapshot(cb));
            events.add(event);
        }

        Map<String, Object> out = result();
        out.put("events", events);
        out.put("final", cbSnapshot(cb));
        out.put("publishedEvents", Map.of(
            "stateTransitions", transitions.get(),
            "errors", errors.get(),
            "successes", successes.get(),
            "ignoredErrors", ignoredErrors.get(),
            "notPermitted", notPermitted.get()
        ));
        return out;
    }

    static Map<String, Object> runCircuitBreakerConfig(JsonObject params) {
        MutableClock clock = new MutableClock();
        CircuitBreakerConfig config = circuitConfig(params, clock);
        CircuitBreaker cb = CircuitBreaker.of("shape-cb-config", config);
        Map<String, Object> out = result();
        out.put("initialState", cb.getState().name());
        out.put("failureRateThreshold", Math.round(config.getFailureRateThreshold() * 1000.0) / 1000.0);
        out.put("minimumNumberOfCalls", config.getMinimumNumberOfCalls());
        out.put("slidingWindowSize", config.getSlidingWindowSize());
        out.put("permittedHalfOpen", config.getPermittedNumberOfCallsInHalfOpenState());
        out.put("waitOpenMillis", config.getWaitIntervalFunctionInOpenState().apply(1));
        out.put("writableStackTrace", config.isWritableStackTraceEnabled());
        return out;
    }

    static BulkheadConfig bulkheadConfig(JsonObject params) {
        return BulkheadConfig.custom()
            .maxConcurrentCalls(integer(params, "maxConcurrentCalls", 1))
            .maxWaitDuration(Duration.ofMillis(lng(params, "maxWaitMillis", 0)))
            .writableStackTraceEnabled(bool(params, "writableStackTrace", true))
            .fairCallHandlingStrategyEnabled(bool(params, "fair", false))
            .build();
    }

    static Map<String, Object> bhMetrics(Bulkhead bulkhead) {
        Bulkhead.Metrics m = bulkhead.getMetrics();
        Map<String, Object> out = result();
        out.put("available", m.getAvailableConcurrentCalls());
        out.put("maxAllowed", m.getMaxAllowedConcurrentCalls());
        return out;
    }

    static Map<String, Object> runBulkheadSequence(JsonObject params) {
        Bulkhead bulkhead = Bulkhead.of("shape-bh", bulkheadConfig(params));
        AtomicInteger permitted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        AtomicInteger finished = new AtomicInteger();
        bulkhead.getEventPublisher()
            .onCallPermitted(event -> permitted.incrementAndGet())
            .onCallRejected(event -> rejected.incrementAndGet())
            .onCallFinished(event -> finished.incrementAndGet());

        List<Object> events = new ArrayList<>();
        for (JsonElement element : array(params, "actions")) {
            JsonObject action = element.getAsJsonObject();
            String op = string(action, "op", "");
            Map<String, Object> event = result();
            event.put("op", op);
            try {
                switch (op) {
                    case "try_acquire" -> event.put("value", bulkhead.tryAcquirePermission());
                    case "release" -> bulkhead.releasePermission();
                    case "on_complete" -> bulkhead.onComplete();
                    case "execute_success" -> event.put("value", bulkhead.executeSupplier(() -> string(action, "value", "ok")));
                    case "execute_error" -> bulkhead.executeSupplier(() -> {
                        throw runtimeFor(string(action, "kind", "transient"), events.size() + 1);
                    });
                    case "change_config" -> bulkhead.changeConfig(bulkheadConfig(object(action, "config")));
                    default -> throw new IllegalArgumentException("unknown bulkhead op " + op);
                }
                event.put("status", "ok");
            } catch (Throwable t) {
                event.putAll(error(t));
            }
            event.put("metrics", bhMetrics(bulkhead));
            events.add(event);
        }
        Map<String, Object> out = result();
        out.put("events", events);
        out.put("finalMetrics", bhMetrics(bulkhead));
        out.put("publishedEvents", Map.of(
            "permitted", permitted.get(),
            "rejected", rejected.get(),
            "finished", finished.get()
        ));
        return out;
    }

    static Map<String, Object> runTimeLimiter(JsonObject params) {
        TimeLimiterConfig config = TimeLimiterConfig.custom()
            .timeoutDuration(Duration.ofMillis(lng(params, "timeoutMillis", 100)))
            .cancelRunningFuture(bool(params, "cancelRunningFuture", true))
            .build();
        TimeLimiter limiter = TimeLimiter.of("shape-tl", config);
        AtomicInteger onSuccess = new AtomicInteger();
        AtomicInteger onError = new AtomicInteger();
        AtomicInteger onTimeout = new AtomicInteger();
        limiter.getEventPublisher()
            .onSuccess(event -> onSuccess.incrementAndGet())
            .onError(event -> onError.incrementAndGet())
            .onTimeout(event -> onTimeout.incrementAndGet());
        String scenario = string(params, "scenario", "completed");
        Map<String, Object> out = result();
        NeverFuture<String> never = null;
        try {
            if ("failed".equals(scenario)) {
                String value = limiter.executeFutureSupplier(() -> {
                    CompletableFuture<String> future = new CompletableFuture<>();
                    future.completeExceptionally(new TransientFailure("future-failed"));
                    return future;
                });
                out.put("status", "returned");
                out.put("value", value);
            } else if ("timeout".equals(scenario)) {
                NeverFuture<String> local = new NeverFuture<>();
                never = local;
                String value = limiter.executeFutureSupplier(() -> local);
                out.put("status", "returned");
                out.put("value", value);
            } else {
                String value = limiter.executeFutureSupplier(() -> CompletableFuture.completedFuture(string(params, "value", "ok")));
                out.put("status", "returned");
                out.put("value", value);
            }
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("timeoutMillis", config.getTimeoutDuration().toMillis());
        out.put("cancelRunningFuture", config.shouldCancelRunningFuture());
        if (never != null) {
            out.put("futureCancelled", never.isCancelled());
        }
        out.put("events", Map.of("success", onSuccess.get(), "error", onError.get(), "timeout", onTimeout.get()));
        return out;
    }

    static Map<String, Object> runPolicyComposition(JsonObject params) {
        JsonObject retryParams = object(params, "retry");
        JsonObject cbParams = object(params, "circuitbreaker");
        AtomicInteger consumedBeforeRetry = new AtomicInteger();
        Retry retry = Retry.of("shape-composed-retry", retryConfig(retryParams, consumedBeforeRetry));
        MutableClock clock = new MutableClock();
        CircuitBreaker cb = CircuitBreaker.of("shape-composed-cb", circuitConfig(cbParams, clock));
        JsonArray outcomes = array(params, "outcomes");
        AtomicInteger attempts = new AtomicInteger();
        CheckedSupplier<String> supplier = () -> {
            int attempt = attempts.incrementAndGet();
            String outcome = outcomes.size() == 0
                ? "ok"
                : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
            if (outcome.startsWith("throw:")) {
                throw checkedFor(outcome.substring("throw:".length()), attempt);
            }
            return outcome;
        };
        String order = string(params, "order", "retry_outside_circuitbreaker");
        CheckedSupplier<String> decorated = "circuitbreaker_outside_retry".equals(order)
            ? CircuitBreaker.decorateCheckedSupplier(cb, Retry.decorateCheckedSupplier(retry, supplier))
            : Retry.decorateCheckedSupplier(retry, CircuitBreaker.decorateCheckedSupplier(cb, supplier));
        Map<String, Object> out = result();
        try {
            String value = decorated.get();
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("retryMetrics", retryMetrics(retry));
        out.put("circuitBreaker", cbSnapshot(cb));
        return out;
    }

    static Map<String, Object> runRegistry(JsonObject params) {
        Map<String, Object> out = result();
        String type = string(params, "type", "retry");
        if ("retry".equals(type)) {
            RetryConfig config = retryConfig(params, new AtomicInteger());
            var registry = io.github.resilience4j.retry.RetryRegistry.of(config);
            Retry a = registry.retry("a");
            Retry b = registry.retry("b");
            Retry again = registry.retry("a");
            out.put("all", registry.getAllRetries().size());
            out.put("sameNameReused", a == again);
            out.put("names", Arrays.asList(a.getName(), b.getName()));
            if (bool(params, "removeA", false)) {
                out.put("removed", registry.remove("a").isPresent());
                out.put("allAfterRemove", registry.getAllRetries().size());
            }
        } else if ("circuitbreaker".equals(type)) {
            MutableClock clock = new MutableClock();
            CircuitBreakerConfig config = circuitConfig(params, clock);
            var registry = io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry.of(config);
            CircuitBreaker a = registry.circuitBreaker("a");
            CircuitBreaker b = registry.circuitBreaker("b");
            out.put("all", registry.getAllCircuitBreakers().size());
            out.put("sameNameReused", a == registry.circuitBreaker("a"));
            out.put("names", Arrays.asList(a.getName(), b.getName()));
            if (bool(params, "removeA", false)) {
                out.put("removed", registry.remove("a").isPresent());
                out.put("allAfterRemove", registry.getAllCircuitBreakers().size());
            }
        }
        return out;
    }

    static Map<String, Object> runContract(JsonObject contract) {
        String op = string(contract, "op", "");
        JsonObject params = object(contract, "params");
        return switch (op) {
            case "retry_call" -> runRetryCall(params);
            case "retry_sequence" -> runRetrySequence(params);
            case "retry_config" -> runRetryConfig(params);
            case "circuitbreaker_sequence" -> runCircuitBreakerSequence(params);
            case "circuitbreaker_config" -> runCircuitBreakerConfig(params);
            case "bulkhead_sequence" -> runBulkheadSequence(params);
            case "timelimiter_future" -> runTimeLimiter(params);
            case "registry_probe" -> runRegistry(params);
            case "policy_composition" -> runPolicyComposition(params);
            default -> {
                Map<String, Object> out = result();
                out.put("status", "unsupported");
                out.put("error", "unknown op " + op);
                yield out;
            }
        };
    }

    public static void main(String[] args) throws Exception {
        boolean fill = false;
        String path = null;
        for (String arg : args) {
            if ("--fill".equals(arg)) fill = true;
            else path = arg;
        }
        if (path == null) throw new IllegalArgumentException("missing contracts path");

        JsonObject input;
        try (Reader reader = Files.newBufferedReader(Path.of(path))) {
            JsonElement parsed = JsonParser.parseReader(reader);
            if (parsed.isJsonArray()) {
                input = new JsonObject();
                input.add("contracts", parsed.getAsJsonArray());
            } else {
                input = parsed.getAsJsonObject();
            }
        }

        JsonArray rows = input.getAsJsonArray("contracts");
        JsonArray outRows = new JsonArray();
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject().deepCopy();
            try {
                Map<String, Object> actual = runContract(row);
                row.add("actual", GSON.toJsonTree(actual));
                if (fill) row.add("expected", GSON.toJsonTree(actual));
            } catch (Throwable t) {
                Map<String, Object> actual = error(t);
                row.add("actual", GSON.toJsonTree(actual));
                if (fill) row.add("expected", GSON.toJsonTree(actual));
            }
            outRows.add(row);
        }
        JsonObject output = new JsonObject();
        output.add("contracts", outRows);
        System.out.println(GSON.toJson(output));
    }
}
