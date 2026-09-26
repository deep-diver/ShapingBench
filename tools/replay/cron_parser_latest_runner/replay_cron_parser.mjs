#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  CronExpressionParser,
  CronFileParser,
} from "cron-parser";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function deepEqual(left, right) {
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

function mutateValue(value) {
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value + 1;
  if (typeof value === "string") return value + "__mutant__";
  if (Array.isArray(value)) return value.concat(["__mutant__"]);
  if (value && typeof value === "object") return { ...value, __mutant__: true };
  return "__mutant__";
}

function mutateExpected(expected) {
  const out = JSON.parse(JSON.stringify(expected));
  for (const key of ["error", "hasNext", "hasPrev", "value"]) {
    if (typeof out[key] === "boolean") {
      out[key] = !out[key];
      return out;
    }
  }
  for (const key of ["dates", "fields", "string", "variables", "expressions", "errors", "messageContains"]) {
    if (key in out) {
      out[key] = mutateValue(out[key]);
      return out;
    }
  }
  const key = Object.keys(out)[0];
  if (key) out[key] = mutateValue(out[key]);
  else out.__mutant__ = true;
  return out;
}

function convertOptions(options = {}) {
  return { ...options };
}

function parse(contract) {
  return CronExpressionParser.parse(contract.params.expression, convertOptions(contract.params.options || {}));
}

function dateIso(value) {
  if (value && typeof value.toDate === "function") return value.toDate().toISOString();
  if (value && typeof value.toISOString === "function") return value.toISOString();
  return String(value);
}

function fieldValues(interval, field) {
  const target = interval.fields[field];
  if (!target) return null;
  const values = target.values ?? target;
  return Array.from(values);
}

function run(contract) {
  const params = contract.params || {};
  try {
    if (contract.op === "next_dates") {
      const interval = parse(contract);
      const dates = [];
      for (let i = 0; i < (params.count || 1); i += 1) dates.push(dateIso(interval.next()));
      return { dates };
    }
    if (contract.op === "prev_dates") {
      const interval = parse(contract);
      const dates = [];
      for (let i = 0; i < (params.count || 1); i += 1) dates.push(dateIso(interval.prev()));
      return { dates };
    }
    if (contract.op === "take_dates") {
      const interval = parse(contract);
      return { dates: interval.take(params.count || 1).map(dateIso) };
    }
    if (contract.op === "stringify") {
      const interval = parse(contract);
      return { string: interval.stringify(Boolean(params.includeSeconds)) };
    }
    if (contract.op === "fields_values") {
      const interval = parse(contract);
      return { fields: Object.fromEntries((params.fields || []).map((field) => [field, fieldValues(interval, field)])) };
    }
    if (contract.op === "parse_error") {
      try {
        parse(contract);
      } catch (error) {
        return { error: true, messageContains: String(error.message || error) };
      }
      return { error: false };
    }
    if (contract.op === "next_error") {
      try {
        parse(contract).next();
      } catch (error) {
        return { error: true, messageContains: String(error.message || error) };
      }
      return { error: false };
    }
    if (contract.op === "includes_date") {
      const interval = parse(contract);
      return { value: Boolean(interval.includesDate(new Date(params.date))) };
    }
    if (contract.op === "has_next_prev") {
      const interval = parse(contract);
      return { hasNext: interval.hasNext(), hasPrev: interval.hasPrev() };
    }
    if (contract.op === "reset_next") {
      const interval = parse(contract);
      for (let i = 0; i < (params.skipNext || 0); i += 1) interval.next();
      interval.reset(new Date(params.resetDate));
      return { dates: [dateIso(interval.next())] };
    }
    if (contract.op === "crontab_parse") {
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cron-parser-file-")), "crontab");
      fs.writeFileSync(file, params.content || "", "utf8");
      const result = CronFileParser.parseFileSync(file);
      return {
        variables: result.variables,
        expressions: result.expressions.length,
        errors: Object.keys(result.errors).length,
      };
    }
    return { error: true, messageContains: `unsupported op ${contract.op}` };
  } catch (error) {
    return { error: true, messageContains: String(error.message || error) };
  }
}

function matches(expected, actual) {
  if (!expected || typeof expected !== "object") return false;
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (!(key in actual)) return false;
    if (key === "messageContains") {
      if (!String(actual[key] || "").includes(String(expectedValue))) return false;
    } else if (!deepEqual(actual[key], expectedValue)) {
      return false;
    }
  }
  return true;
}

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const mode = process.argv.includes("--fill") ? "fill" : "replay";
const rows = Array.isArray(input) ? input : input.contracts;

if (mode === "fill") {
  const contracts = rows.map((contract) => {
    const actual = run(contract);
    return { ...contract, expected: actual, mutant: mutateExpected(actual) };
  });
  process.stdout.write(JSON.stringify({ contracts }, null, 2));
} else {
  const results = rows.map((contract) => {
    const actual = run(contract);
    const replayPassed = matches(contract.expected, actual);
    const mutantPassed = replayPassed ? matches(contract.mutant, actual) : false;
    return {
      name: contract.name,
      version: contract.version,
      capability: contract.capability,
      op: contract.op,
      status: replayPassed && !mutantPassed ? "passed" : "failed",
      replay_passed: replayPassed,
      mutant_rejected: replayPassed && !mutantPassed,
      expected: contract.expected,
      mutant: contract.mutant,
      actual,
    };
  });
  process.stdout.write(JSON.stringify({ results }, null, 2));
}
