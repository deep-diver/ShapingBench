package shapingbench;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.failsafe.Bulkhead;
import dev.failsafe.BulkheadConfig;
import dev.failsafe.CircuitBreaker;
import dev.failsafe.CircuitBreakerConfig;
import dev.failsafe.CircuitBreakerOpenException;
import dev.failsafe.Failsafe;
import dev.failsafe.Fallback;
import dev.failsafe.Policy;
import dev.failsafe.RetryPolicy;
import dev.failsafe.RetryPolicyBuilder;
import dev.failsafe.RetryPolicyConfig;
import dev.failsafe.Timeout;
import dev.failsafe.TimeoutConfig;
import dev.failsafe.TimeoutExceededException;
import dev.failsafe.event.ExecutionAttemptedEvent;
import dev.failsafe.event.ExecutionCompletedEvent;
import dev.failsafe.event.ExecutionScheduledEvent;
import dev.failsafe.function.CheckedSupplier;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class FailsafeLatestReplay {
    static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    static class TransientFailure extends RuntimeException {
        TransientFailure(String message) { super(message); }
    }

    static class IgnoredFailure extends RuntimeException {
        IgnoredFailure(String message) { super(message); }
    }

    static class FatalFailure extends RuntimeException {
        FatalFailure(String message) { super(message); }
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

    static JsonArray array(JsonObject object, String key) {
        return object.has(key) && object.get(key).isJsonArray() ? object.getAsJsonArray(key) : new JsonArray();
    }

    static JsonObject object(JsonObject object, String key) {
        return object.getAsJsonObject(key);
    }

    static Map<String, Object> result() {
        return new LinkedHashMap<>();
    }

    static Throwable unwrap(Throwable throwable) {
        if (throwable.getCause() != null && throwable.getClass().getSimpleName().contains("Failsafe")) {
            return unwrap(throwable.getCause());
        }
        return throwable;
    }

    static Map<String, Object> error(Throwable throwable) {
        Throwable t = unwrap(throwable);
        Map<String, Object> out = result();
        out.put("status", "raised");
        out.put("errorType", t.getClass().getSimpleName());
        out.put("errorMessagePrefix", t.getMessage() == null ? "" : t.getMessage().substring(0, Math.min(60, t.getMessage().length())));
        return out;
    }

    static RuntimeException failureFor(String kind, int attempt) {
        return switch (kind) {
            case "fatal" -> new FatalFailure("fatal-" + attempt);
            case "ignored" -> new IgnoredFailure("ignored-" + attempt);
            case "timeout" -> new IllegalStateException("timeout-" + attempt);
            case "circuitOpen" -> new IllegalStateException("circuit-open-" + attempt);
            default -> new TransientFailure("transient-" + attempt);
        };
    }

    static void applyHandle(RetryPolicyBuilder<String> builder, JsonObject params) {
        JsonArray handle = array(params, "handle");
        if (handle.size() == 0) {
            builder.handle(TransientFailure.class);
            return;
        }
        for (JsonElement element : handle) {
            switch (element.getAsString()) {
                case "fatal" -> builder.handle(FatalFailure.class);
                case "ignored" -> builder.handle(IgnoredFailure.class);
                case "timeout" -> builder.handle(TimeoutExceededException.class);
                default -> builder.handle(TransientFailure.class);
            }
        }
    }

    static RetryPolicy<String> retryPolicy(JsonObject params, Map<String, Object> listenerCounts) {
        AtomicInteger failedAttempt = new AtomicInteger();
        AtomicInteger retry = new AtomicInteger();
        AtomicInteger retryScheduled = new AtomicInteger();
        AtomicInteger retriesExceeded = new AtomicInteger();
        AtomicInteger abort = new AtomicInteger();
        RetryPolicyBuilder<String> builder = RetryPolicy.<String>builder();
        applyHandle(builder, params);
        if (params.has("handleResult")) {
            builder.handleResult(string(params, "handleResult", "bad"));
        }
        if (params.has("handleResultPrefix")) {
            String prefix = string(params, "handleResultPrefix", "");
            builder.handleResultIf(value -> value != null && value.startsWith(prefix));
        }
        if (params.has("abortWhen")) {
            builder.abortWhen(string(params, "abortWhen", ""));
        }
        if (params.has("abortOn")) {
            String kind = string(params, "abortOn", "fatal");
            if ("fatal".equals(kind)) builder.abortOn(FatalFailure.class);
            else if ("ignored".equals(kind)) builder.abortOn(IgnoredFailure.class);
            else builder.abortOn(TransientFailure.class);
        }
        if (params.has("abortResultPrefix")) {
            String prefix = string(params, "abortResultPrefix", "");
            builder.abortIf(value -> value != null && value.startsWith(prefix));
        }
        if (params.has("maxAttempts")) builder.withMaxAttempts(integer(params, "maxAttempts", 3));
        if (params.has("maxRetries")) builder.withMaxRetries(integer(params, "maxRetries", 2));
        if (params.has("delayMillis")) builder.withDelay(Duration.ofMillis(lng(params, "delayMillis", 0)));
        if (params.has("delayMinMillis") && params.has("delayMaxMillis")) {
            if (params.has("delayFactor")) {
                builder.withBackoff(lng(params, "delayMinMillis", 1), lng(params, "delayMaxMillis", 10), ChronoUnit.MILLIS, dbl(params, "delayFactor", 2.0));
            } else {
                builder.withDelay(Duration.ofMillis(lng(params, "delayMinMillis", 1)), Duration.ofMillis(lng(params, "delayMaxMillis", 10)));
            }
        }
        if (params.has("jitterFactor")) builder.withJitter(dbl(params, "jitterFactor", 0.0));
        if (params.has("jitterMillis")) builder.withJitter(Duration.ofMillis(lng(params, "jitterMillis", 0)));
        if (params.has("maxDurationMillis")) builder.withMaxDuration(Duration.ofMillis(lng(params, "maxDurationMillis", 100)));
        if (params.has("delayFnMillis")) {
            long delay = lng(params, "delayFnMillis", 0);
            builder.withDelayFn(context -> Duration.ofMillis(delay + context.getAttemptCount()));
        }
        if (params.has("delayFnOnKind")) {
            long delay = lng(params, "delayFnMillis", 0);
            builder.withDelayFnOn(context -> Duration.ofMillis(delay + context.getAttemptCount()), TransientFailure.class);
        }
        if (params.has("delayFnWhenResult")) {
            long delay = lng(params, "delayFnMillis", 0);
            builder.withDelayFnWhen(context -> Duration.ofMillis(delay + context.getAttemptCount()), string(params, "delayFnWhenResult", "bad"));
        }
        builder.onFailedAttempt(event -> failedAttempt.incrementAndGet());
        builder.onRetry(event -> retry.incrementAndGet());
        builder.onRetryScheduled(event -> retryScheduled.incrementAndGet());
        builder.onRetriesExceeded(event -> retriesExceeded.incrementAndGet());
        builder.onAbort(event -> abort.incrementAndGet());
        RetryPolicy<String> policy = builder.build();
        listenerCounts.put("failedAttempt", failedAttempt);
        listenerCounts.put("retry", retry);
        listenerCounts.put("retryScheduled", retryScheduled);
        listenerCounts.put("retriesExceeded", retriesExceeded);
        listenerCounts.put("abort", abort);
        return policy;
    }

    static Map<String, Object> retryConfigSnapshot(RetryPolicyConfig<String> config) {
        Map<String, Object> out = result();
        out.put("maxAttempts", config.getMaxAttempts());
        out.put("maxRetries", config.getMaxRetries());
        out.put("allowsRetries", config.allowsRetries());
        out.put("delayMillis", config.getDelay() == null ? null : config.getDelay().toMillis());
        out.put("delayMinMillis", config.getDelayMin() == null ? null : config.getDelayMin().toMillis());
        out.put("delayMaxMillis", config.getDelayMax() == null ? null : config.getDelayMax().toMillis());
        out.put("delayFactor", config.getDelayFactor());
        out.put("maxDelayMillis", config.getMaxDelay() == null ? null : config.getMaxDelay().toMillis());
        out.put("jitterMillis", config.getJitter() == null ? null : config.getJitter().toMillis());
        out.put("jitterFactor", config.getJitterFactor());
        out.put("maxDurationMillis", config.getMaxDuration() == null ? null : config.getMaxDuration().toMillis());
        out.put("failureConditions", config.getFailureConditions().size());
        out.put("abortConditions", config.getAbortConditions().size());
        return out;
    }

    static Map<String, Object> listenerSnapshot(Map<String, Object> listenerCounts) {
        Map<String, Object> out = result();
        for (Map.Entry<String, Object> entry : listenerCounts.entrySet()) {
            out.put(entry.getKey(), ((AtomicInteger) entry.getValue()).get());
        }
        return out;
    }

    static CheckedSupplier<String> supplierFor(JsonArray outcomes, AtomicInteger attempts) {
        return () -> {
            int attempt = attempts.incrementAndGet();
            String outcome = outcomes.size() == 0 ? "ok" : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
            if (outcome.startsWith("throw:")) {
                throw failureFor(outcome.substring("throw:".length()), attempt);
            }
            if (outcome.startsWith("sleep:")) {
                long millis = Long.parseLong(outcome.substring("sleep:".length()));
                Thread.sleep(millis);
                return "slept";
            }
            return outcome;
        };
    }

    static Map<String, Object> runRetryCall(JsonObject params) {
        Map<String, Object> listenerCounts = result();
        RetryPolicy<String> policy = retryPolicy(params, listenerCounts);
        AtomicInteger attempts = new AtomicInteger();
        Map<String, Object> out = result();
        try {
            String value = Failsafe.with(policy).get(supplierFor(array(params, "outcomes"), attempts));
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("listeners", listenerSnapshot(listenerCounts));
        out.put("config", retryConfigSnapshot(policy.getConfig()));
        return out;
    }

    static Map<String, Object> runRetrySequence(JsonObject params) {
        Map<String, Object> listenerCounts = result();
        RetryPolicy<String> policy = retryPolicy(params, listenerCounts);
        List<Object> calls = new ArrayList<>();
        for (JsonElement callElement : array(params, "calls")) {
            AtomicInteger attempts = new AtomicInteger();
            Map<String, Object> call = result();
            try {
                String value = Failsafe.with(policy).get(supplierFor(callElement.getAsJsonArray(), attempts));
                call.put("status", "returned");
                call.put("value", value);
            } catch (Throwable t) {
                call.putAll(error(t));
            }
            call.put("attempts", attempts.get());
            calls.add(call);
        }
        Map<String, Object> out = result();
        out.put("calls", calls);
        out.put("listeners", listenerSnapshot(listenerCounts));
        out.put("config", retryConfigSnapshot(policy.getConfig()));
        return out;
    }

    static Map<String, Object> runRetryConfig(JsonObject params) {
        Map<String, Object> listenerCounts = result();
        RetryPolicy<String> policy = retryPolicy(params, listenerCounts);
        return retryConfigSnapshot(policy.getConfig());
    }

    static CircuitBreaker<String> circuitBreaker(JsonObject params, Map<String, Object> listeners) {
        AtomicInteger opened = new AtomicInteger();
        AtomicInteger halfOpened = new AtomicInteger();
        AtomicInteger closed = new AtomicInteger();
        var builder = CircuitBreaker.<String>builder();
        if (params.has("handleResult")) builder.handleResult(string(params, "handleResult", "bad"));
        if (params.has("handleResultPrefix")) {
            String prefix = string(params, "handleResultPrefix", "");
            builder.handleResultIf(value -> value != null && value.startsWith(prefix));
        }
        if (params.has("handle")) {
            for (JsonElement element : array(params, "handle")) {
                if ("fatal".equals(element.getAsString())) builder.handle(FatalFailure.class);
                else builder.handle(TransientFailure.class);
            }
        } else {
            builder.handle(TransientFailure.class);
        }
        if (params.has("failureThreshold")) builder.withFailureThreshold(integer(params, "failureThreshold", 1));
        if (params.has("failureThresholdingCapacity")) {
            int failures = integer(params, "failureThreshold", 1);
            int capacity = integer(params, "failureThresholdingCapacity", 2);
            if (params.has("failureThresholdingPeriodMillis")) {
                builder.withFailureThreshold(failures, capacity, Duration.ofMillis(lng(params, "failureThresholdingPeriodMillis", 100)));
            } else {
                builder.withFailureThreshold(failures, capacity);
            }
        }
        if (params.has("failureRateThreshold")) {
            builder.withFailureRateThreshold(integer(params, "failureRateThreshold", 50), integer(params, "failureExecutionThreshold", 2), Duration.ofMillis(lng(params, "failureThresholdingPeriodMillis", 1000)));
        }
        if (params.has("successThresholdingCapacity")) {
            builder.withSuccessThreshold(integer(params, "successThreshold", 1), integer(params, "successThresholdingCapacity", 1));
        } else if (params.has("successThreshold")) {
            builder.withSuccessThreshold(integer(params, "successThreshold", 1));
        }
        if (params.has("delayMillis")) builder.withDelay(Duration.ofMillis(lng(params, "delayMillis", 0)));
        builder.onOpen(event -> opened.incrementAndGet());
        builder.onHalfOpen(event -> halfOpened.incrementAndGet());
        builder.onClose(event -> closed.incrementAndGet());
        CircuitBreaker<String> cb = builder.build();
        listeners.put("open", opened);
        listeners.put("halfOpen", halfOpened);
        listeners.put("close", closed);
        return cb;
    }

    static Map<String, Object> cbSnapshot(CircuitBreaker<String> cb) {
        Map<String, Object> out = result();
        CircuitBreakerConfig<String> config = cb.getConfig();
        out.put("state", cb.getState().name());
        out.put("executionCount", cb.getExecutionCount());
        out.put("failureCount", cb.getFailureCount());
        out.put("failureRate", cb.getFailureRate());
        out.put("successCount", cb.getSuccessCount());
        out.put("successRate", cb.getSuccessRate());
        out.put("remainingDelayMillis", cb.getRemainingDelay().toMillis());
        out.put("configFailureThreshold", config.getFailureThreshold());
        out.put("configSuccessThreshold", config.getSuccessThreshold());
        out.put("configFailureRateThreshold", config.getFailureRateThreshold());
        return out;
    }

    static Map<String, Object> runCircuitBreakerSequence(JsonObject params) {
        Map<String, Object> listeners = result();
        CircuitBreaker<String> cb = circuitBreaker(params, listeners);
        List<Object> events = new ArrayList<>();
        for (JsonElement element : array(params, "actions")) {
            JsonObject action = element.getAsJsonObject();
            String op = string(action, "op", "");
            Map<String, Object> event = result();
            event.put("op", op);
            try {
                switch (op) {
                    case "record_success" -> cb.recordSuccess();
                    case "record_failure" -> cb.recordFailure();
                    case "record_exception" -> cb.recordException(failureFor(string(action, "kind", "transient"), events.size() + 1));
                    case "record_result" -> cb.recordResult(string(action, "value", "ok"));
                    case "open" -> cb.open();
                    case "close" -> cb.close();
                    case "half_open" -> cb.halfOpen();
                    case "try_acquire" -> event.put("value", cb.tryAcquirePermit());
                    case "execute" -> event.put("value", Failsafe.with(cb).get(supplierFor(array(action, "outcomes"), new AtomicInteger())));
                    case "sleep" -> Thread.sleep(lng(action, "millis", 0));
                    default -> throw new IllegalArgumentException("unknown circuit op " + op);
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
        out.put("listeners", listenerSnapshot(listeners));
        return out;
    }

    static Map<String, Object> runCircuitBreakerConfig(JsonObject params) {
        Map<String, Object> listeners = result();
        return cbSnapshot(circuitBreaker(params, listeners));
    }

    static Map<String, Object> runBulkheadSequence(JsonObject params) {
        Bulkhead<String> bulkhead = Bulkhead.<String>builder(integer(params, "maxConcurrency", 1))
            .withMaxWaitTime(Duration.ofMillis(lng(params, "maxWaitMillis", 0)))
            .build();
        List<Object> events = new ArrayList<>();
        for (JsonElement element : array(params, "actions")) {
            JsonObject action = element.getAsJsonObject();
            String op = string(action, "op", "");
            Map<String, Object> event = result();
            event.put("op", op);
            try {
                switch (op) {
                    case "try_acquire" -> event.put("value", bulkhead.tryAcquirePermit());
                    case "release" -> bulkhead.releasePermit();
                    case "execute" -> event.put("value", Failsafe.with(bulkhead).get(() -> string(action, "value", "ok")));
                    default -> throw new IllegalArgumentException("unknown bulkhead op " + op);
                }
                event.put("status", "ok");
            } catch (Throwable t) {
                event.putAll(error(t));
            }
            BulkheadConfig<String> config = bulkhead.getConfig();
            event.put("maxConcurrency", config.getMaxConcurrency());
            event.put("maxWaitMillis", config.getMaxWaitTime().toMillis());
            events.add(event);
        }
        Map<String, Object> out = result();
        out.put("events", events);
        return out;
    }

    static Map<String, Object> runTimeoutCall(JsonObject params) {
        Timeout<String> timeout = Timeout.<String>builder(Duration.ofMillis(lng(params, "timeoutMillis", 10)))
            .withInterrupt()
            .build();
        TimeoutConfig<String> config = timeout.getConfig();
        AtomicInteger attempts = new AtomicInteger();
        AtomicBoolean interrupted = new AtomicBoolean(false);
        JsonArray outcomes = array(params, "outcomes");
        Map<String, Object> out = result();
        try {
            String value = Failsafe.with(timeout).get(() -> {
                int attempt = attempts.incrementAndGet();
                String outcome = outcomes.size() == 0 ? "ok" : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
                if (outcome.startsWith("sleep:")) {
                    try {
                        Thread.sleep(Long.parseLong(outcome.substring("sleep:".length())));
                    } catch (InterruptedException e) {
                        interrupted.set(true);
                        throw e;
                    }
                    return "slept";
                }
                if (outcome.startsWith("throw:")) throw failureFor(outcome.substring("throw:".length()), attempt);
                return outcome;
            });
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("timeoutMillis", config.getTimeout().toMillis());
        out.put("canInterrupt", config.canInterrupt());
        out.put("interrupted", interrupted.get());
        return out;
    }

    static Fallback<String> fallback(JsonObject params, Map<String, Object> listeners) {
        AtomicInteger failedAttempt = new AtomicInteger();
        String mode = string(params, "fallbackMode", "value");
        Fallback<String> fallback;
        if ("event_value".equals(mode)) {
            fallback = Fallback.<String>builder(event -> "fallback:" + event.getAttemptCount() + ":" + event.getLastException().getClass().getSimpleName()).onFailedAttempt(event -> failedAttempt.incrementAndGet()).build();
        } else if ("exception".equals(mode)) {
            fallback = Fallback.<String>builderOfException(event -> new IllegalArgumentException("fallback-exception")).onFailedAttempt(event -> failedAttempt.incrementAndGet()).build();
        } else {
            fallback = Fallback.<String>builder(string(params, "fallbackValue", "fallback")).onFailedAttempt(event -> failedAttempt.incrementAndGet()).build();
        }
        listeners.put("fallbackFailedAttempt", failedAttempt);
        return fallback;
    }

    static Map<String, Object> runFallbackCall(JsonObject params) {
        Map<String, Object> listeners = result();
        Fallback<String> fallback = fallback(params, listeners);
        AtomicInteger attempts = new AtomicInteger();
        Map<String, Object> out = result();
        try {
            String value = Failsafe.with(fallback).get(supplierFor(array(params, "outcomes"), attempts));
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("listeners", listenerSnapshot(listeners));
        return out;
    }

    static Map<String, Object> runComposition(JsonObject params) {
        List<Policy<String>> policies = new ArrayList<>();
        Map<String, Object> retryListeners = result();
        Map<String, Object> cbListeners = result();
        Map<String, Object> fallbackListeners = result();
        for (JsonElement element : array(params, "policies")) {
            String policy = element.getAsString();
            if ("fallback".equals(policy)) policies.add(fallback(object(params, "fallback"), fallbackListeners));
            if ("retry".equals(policy)) policies.add(retryPolicy(object(params, "retry"), retryListeners));
            if ("circuitbreaker".equals(policy)) policies.add(circuitBreaker(object(params, "circuitbreaker"), cbListeners));
            if ("bulkhead".equals(policy)) {
                JsonObject bh = object(params, "bulkhead");
                policies.add(Bulkhead.<String>builder(integer(bh, "maxConcurrency", 1)).withMaxWaitTime(Duration.ofMillis(lng(bh, "maxWaitMillis", 0))).build());
            }
            if ("timeout".equals(policy)) policies.add(Timeout.<String>builder(Duration.ofMillis(lng(object(params, "timeout"), "timeoutMillis", 10))).withInterrupt().build());
        }
        AtomicInteger attempts = new AtomicInteger();
        Map<String, Object> out = result();
        try {
            String value = Failsafe.with(policies).get(supplierFor(array(params, "outcomes"), attempts));
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("retryListeners", listenerSnapshot(retryListeners));
        out.put("circuitBreakerListeners", listenerSnapshot(cbListeners));
        out.put("fallbackListeners", listenerSnapshot(fallbackListeners));
        return out;
    }

    static Map<String, Object> runExecutorListeners(JsonObject params) {
        Map<String, Object> retryListeners = result();
        RetryPolicy<String> retry = retryPolicy(object(params, "retry"), retryListeners);
        AtomicInteger onComplete = new AtomicInteger();
        AtomicInteger onSuccess = new AtomicInteger();
        AtomicInteger onFailure = new AtomicInteger();
        AtomicInteger attempts = new AtomicInteger();
        Map<String, Object> completeEvent = result();
        var executor = Failsafe.with(retry)
            .onComplete(event -> {
                onComplete.incrementAndGet();
                completeEvent.put("attemptCount", event.getAttemptCount());
                completeEvent.put("executionCount", event.getExecutionCount());
                completeEvent.put("isFirstAttempt", event.isFirstAttempt());
                completeEvent.put("isRetry", event.isRetry());
                completeEvent.put("hasResult", event.getResult() != null);
                completeEvent.put("hasException", event.getException() != null);
            })
            .onSuccess(event -> onSuccess.incrementAndGet())
            .onFailure(event -> onFailure.incrementAndGet());
        Map<String, Object> out = result();
        try {
            String value = executor.get(supplierFor(array(params, "outcomes"), attempts));
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("executorListeners", Map.of("complete", onComplete.get(), "success", onSuccess.get(), "failure", onFailure.get()));
        out.put("completeEvent", completeEvent);
        out.put("retryListeners", listenerSnapshot(retryListeners));
        return out;
    }

    static Map<String, Object> runContextualRetry(JsonObject params) {
        Map<String, Object> retryListeners = result();
        RetryPolicy<String> retry = retryPolicy(params, retryListeners);
        JsonArray outcomes = array(params, "outcomes");
        AtomicInteger attempts = new AtomicInteger();
        List<Object> contexts = new ArrayList<>();
        Map<String, Object> out = result();
        try {
            String value = Failsafe.with(retry).get(ctx -> {
                int attempt = attempts.incrementAndGet();
                Map<String, Object> context = result();
                context.put("attemptCount", ctx.getAttemptCount());
                context.put("executionCount", ctx.getExecutionCount());
                context.put("isFirstAttempt", ctx.isFirstAttempt());
                context.put("isRetry", ctx.isRetry());
                context.put("lastResult", ctx.getLastResult(null));
                Throwable last = ctx.getLastException();
                context.put("lastExceptionType", last == null ? null : last.getClass().getSimpleName());
                contexts.add(context);
                String outcome = outcomes.size() == 0 ? "ok" : outcomes.get(Math.min(attempt - 1, outcomes.size() - 1)).getAsString();
                if (outcome.startsWith("throw:")) {
                    throw failureFor(outcome.substring("throw:".length()), attempt);
                }
                return outcome;
            });
            out.put("status", "returned");
            out.put("value", value);
        } catch (Throwable t) {
            out.putAll(error(t));
        }
        out.put("attempts", attempts.get());
        out.put("contexts", contexts);
        out.put("retryListeners", listenerSnapshot(retryListeners));
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
            case "timeout_call" -> runTimeoutCall(params);
            case "fallback_call" -> runFallbackCall(params);
            case "composition_call" -> runComposition(params);
            case "executor_listeners" -> runExecutorListeners(params);
            case "contextual_retry" -> runContextualRetry(params);
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
