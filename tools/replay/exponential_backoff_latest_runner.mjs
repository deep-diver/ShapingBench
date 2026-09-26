#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const PACKAGE_ROOT = path.join(ROOT, ".replay", "exponential_backoff_latest", "node_modules", "exponential-backoff");
const { backOff } = require(PACKAGE_ROOT);

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

function errorFor(kind) {
  if (kind === "fatal") return new FatalError();
  if (kind === "other") return new OtherError();
  if (kind === "string") return "string-failure";
  if (kind === "object") return { name: "ObjectFailure", kind: "object" };
  return new TransientError();
}

function describeError(error) {
  if (error instanceof Error) {
    return {
      errorType: error.name,
      errorMessage: error.message,
      errorKind: error.kind || null,
    };
  }
  return {
    errorType: typeof error,
    errorMessage: typeof error === "string" ? error : stableStringify(error),
    errorKind: error && typeof error === "object" ? error.kind || null : null,
  };
}

function applyOutcome(outcome) {
  if (typeof outcome === "string" && outcome.startsWith("throw:")) {
    throw errorFor(outcome.slice("throw:".length));
  }
  if (typeof outcome === "string" && outcome.startsWith("reject:")) {
    return Promise.reject(errorFor(outcome.slice("reject:".length)));
  }
  if (outcome === "__undefined__") return undefined;
  return outcome;
}

function buildOptions(params, retryCalls) {
  const options = {};
  for (const key of [
    "delayFirstAttempt",
    "jitter",
    "maxDelay",
    "numOfAttempts",
    "startingDelay",
    "timeMultiple",
  ]) {
    if (Object.prototype.hasOwnProperty.call(params, key)) options[key] = params[key];
  }

  const mode = params.retryMode || "default";
  if (mode !== "default") {
    options.retry = async (error, attemptNumber) => {
      const desc = describeError(error);
      retryCalls.push({
        attemptNumber,
        errorType: desc.errorType,
        errorMessage: desc.errorMessage,
        errorKind: desc.errorKind,
      });
      if (mode === "never") return false;
      if (mode === "untilAttemptLessThan") return attemptNumber < params.retryUntil;
      if (mode === "onlyTransient") return desc.errorKind === "transient" || desc.errorType === "TransientError";
      if (mode === "excludeFatal") return desc.errorKind !== "fatal" && desc.errorType !== "FatalError";
      if (mode === "promiseTrue") {
        await new Promise(resolve => setTimeout(resolve, params.retryDelayMs ?? 0));
        return true;
      }
      if (mode === "promiseFalse") {
        await new Promise(resolve => setTimeout(resolve, params.retryDelayMs ?? 0));
        return false;
      }
      return true;
    };
  }
  return options;
}

async function runBackoffCall(params) {
  const oldSetTimeout = globalThis.setTimeout;
  const oldRandom = Math.random;
  const waits = [];
  Math.random = () => params.random ?? 0.5;
  globalThis.setTimeout = (callback, delay, ...args) => {
    waits.push(normalize(Number(delay)));
    return oldSetTimeout(callback, 0, ...args);
  };

  const retryCalls = [];
  let attempts = 0;
  const outcomes = params.outcomes || ["ok"];
  try {
    const options = buildOptions(params, retryCalls);
    const value = await backOff(async () => {
      attempts += 1;
      const outcome = outcomes[Math.min(attempts - 1, outcomes.length - 1)];
      return await applyOutcome(outcome);
    }, options);
    return normalize({ status: "returned", value, attempts, waits, retryCalls });
  } catch (error) {
    return normalize({ status: "thrown", ...describeError(error), attempts, waits, retryCalls });
  } finally {
    globalThis.setTimeout = oldSetTimeout;
    Math.random = oldRandom;
  }
}

async function run(contract) {
  if (contract.op !== "backoff_call") {
    return { status: "unsupported", reason: `unsupported op ${contract.op}` };
  }
  return await runBackoffCall(contract.params || {});
}

function mutateExpected(actual) {
  const mutant = JSON.parse(JSON.stringify(actual));
  if (Array.isArray(mutant.waits) && mutant.waits.length) {
    mutant.waits[0] = mutant.waits[0] + 1;
    return mutant;
  }
  if (typeof mutant.attempts === "number") {
    mutant.attempts += 1;
    return mutant;
  }
  if (mutant.status === "returned") {
    mutant.status = "thrown";
    return mutant;
  }
  mutant.status = "returned";
  return mutant;
}

async function main() {
  const args = process.argv.slice(2);
  const fill = args.includes("--fill");
  const inputPath = args.find(arg => !arg.startsWith("--"));
  if (!inputPath) throw new Error("usage: exponential_backoff_latest_runner.mjs [--fill] contracts.json");
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
