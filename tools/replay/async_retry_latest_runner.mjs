#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const PACKAGE_ROOT = path.join(ROOT, ".replay", "async_retry_latest", "node_modules", "async-retry");
const retry = require(PACKAGE_ROOT);

class TransientError extends Error {
  constructor(message = "transient") {
    super(message);
    this.name = "TransientError";
    this.kind = "transient";
  }
}

class FatalError extends Error {
  constructor(message = "fatal") {
    super(message);
    this.name = "FatalError";
    this.kind = "fatal";
  }
}

class OtherError extends Error {
  constructor(message = "other") {
    super(message);
    this.name = "OtherError";
    this.kind = "other";
  }
}

function normalize(value) {
  if (value === undefined) return "__undefined__";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return String(value);
    return Math.round(value * 1_000_000) / 1_000_000;
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = normalize(value[key]);
    return out;
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(normalize(value));
}

function errorFor(kind, message = null) {
  if (kind === "fatal") return new FatalError(message || "fatal");
  if (kind === "other") return new OtherError(message || "other");
  if (kind === "string") return message || "string-failure";
  if (kind === "object") return { name: "ObjectFailure", kind: "object", message: message || "object" };
  return new TransientError(message || "transient");
}

function describeError(error) {
  if (error instanceof Error) {
    return {
      errorType: error.name,
      errorMessage: error.message,
      errorKind: error.kind || null,
      bail: Boolean(error.bail),
    };
  }
  return {
    errorType: typeof error,
    errorMessage: typeof error === "string" ? error : stableStringify(error),
    errorKind: error && typeof error === "object" ? error.kind || null : null,
    bail: Boolean(error && typeof error === "object" && error.bail),
  };
}

function applyOutcome(outcome, bail) {
  if (typeof outcome === "string" && outcome.startsWith("return:")) {
    return outcome.slice("return:".length);
  }
  if (typeof outcome === "string" && outcome.startsWith("throw:")) {
    throw errorFor(outcome.slice("throw:".length));
  }
  if (typeof outcome === "string" && outcome.startsWith("reject:")) {
    return Promise.reject(errorFor(outcome.slice("reject:".length)));
  }
  if (typeof outcome === "string" && outcome.startsWith("bail:")) {
    bail(errorFor(outcome.slice("bail:".length)));
    return "__bailed_return__";
  }
  if (outcome === "bail") {
    bail();
    return "__bailed_return__";
  }
  if (typeof outcome === "string" && outcome.startsWith("throw_bail_flag:")) {
    const err = errorFor(outcome.slice("throw_bail_flag:".length));
    err.bail = true;
    throw err;
  }
  if (outcome === "__undefined__") return undefined;
  return outcome;
}

function buildOptions(params, onRetryCalls) {
  if (params.optsMode === "undefined") return undefined;
  if (params.optsMode === "numberArray") return params.timeouts || [];
  const options = {};
  for (const key of ["retries", "factor", "minTimeout", "maxTimeout", "randomize", "forever", "maxRetryTime"]) {
    if (Object.prototype.hasOwnProperty.call(params, key)) options[key] = params[key];
  }
  if (params.onRetryMode) {
    options.onRetry = (error, attemptNumber) => {
      const desc = describeError(error);
      onRetryCalls.push({
        attemptNumber: normalize(attemptNumber),
        errorType: desc.errorType,
        errorMessage: desc.errorMessage,
        errorKind: desc.errorKind,
        bail: desc.bail,
      });
      if (params.onRetryMode === "throws") {
        throw new OtherError("onRetry threw");
      }
      if (params.onRetryMode === "returnsPromise") {
        return Promise.resolve("ignored");
      }
      return params.onRetryReturn ?? "__undefined__";
    };
  }
  return options;
}

async function runRetryCall(params) {
  const oldSetTimeout = globalThis.setTimeout;
  const oldClearTimeout = globalThis.clearTimeout;
  const oldRandom = Math.random;
  const waits = [];
  const cleared = [];
  let timerId = 0;
  Math.random = () => params.random ?? 0.25;
  globalThis.setTimeout = (callback, delay, ...args) => {
    const id = { id: ++timerId, unref() {} };
    waits.push(normalize(Number(delay)));
    oldSetTimeout(() => callback(...args), 0);
    return id;
  };
  globalThis.clearTimeout = timer => {
    if (timer && typeof timer === "object" && "id" in timer) cleared.push(timer.id);
    return undefined;
  };

  const attempts = [];
  const onRetryCalls = [];
  const outcomes = params.outcomes || ["ok"];
  try {
    const options = buildOptions(params, onRetryCalls);
    const value = await retry((bail, attemptNumber) => {
      attempts.push(attemptNumber);
      const outcome = outcomes[Math.min(attempts.length - 1, outcomes.length - 1)];
      if (params.fnMode === "syncValue") return applyOutcome(outcome, bail);
      if (params.fnMode === "syncThrow") return applyOutcome(outcome, bail);
      return Promise.resolve().then(() => applyOutcome(outcome, bail));
    }, options);
    return normalize({ status: "returned", value, attempts, waits, onRetryCalls, clearedCount: cleared.length });
  } catch (error) {
    return normalize({ status: "thrown", ...describeError(error), attempts, waits, onRetryCalls, clearedCount: cleared.length });
  } finally {
    globalThis.setTimeout = oldSetTimeout;
    globalThis.clearTimeout = oldClearTimeout;
    Math.random = oldRandom;
  }
}

async function run(contract) {
  if (contract.op !== "retry_call") {
    return { status: "unsupported", reason: `unsupported op ${contract.op}` };
  }
  return await runRetryCall(contract.params || {});
}

function mutateExpected(actual) {
  const mutant = JSON.parse(JSON.stringify(actual));
  if (Array.isArray(mutant.waits) && mutant.waits.length) {
    mutant.waits[0] += 1;
    return mutant;
  }
  if (Array.isArray(mutant.attempts) && mutant.attempts.length) {
    mutant.attempts[0] += 1;
    return mutant;
  }
  if (typeof mutant.clearedCount === "number") {
    mutant.clearedCount += 1;
    return mutant;
  }
  mutant.status = mutant.status === "returned" ? "thrown" : "returned";
  return mutant;
}

async function main() {
  const args = process.argv.slice(2);
  const fill = args.includes("--fill");
  const inputPath = args.find(arg => !arg.startsWith("--"));
  if (!inputPath) throw new Error("usage: async_retry_latest_runner.mjs [--fill] contracts.json");
  const payload = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const contracts = [];
  for (const contract of payload.contracts || []) {
    const actual = await run(contract);
    const expected = fill ? actual : contract.expected;
    const replayPass = stableStringify(actual) === stableStringify(expected);
    const mutantExpected = contract.mutantExpected || mutateExpected(expected);
    const mutantRejected = stableStringify(actual) !== stableStringify(mutantExpected);
    contracts.push({
      ...contract,
      expected,
      mutantExpected,
      actual,
      replayPass,
      mutantRejected,
      pass: replayPass && mutantRejected,
    });
  }
  process.stdout.write(JSON.stringify({ contracts }, null, 2) + "\n");
}

main().catch(error => {
  console.error(error.stack || String(error));
  process.exit(1);
});
