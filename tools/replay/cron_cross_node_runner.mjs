#!/usr/bin/env node
import fs from "node:fs";
import { CronExpressionParser } from "./cron_parser_latest_runner/node_modules/cron-parser/dist/index.js";

function readPayload() {
  const path = process.argv[2];
  const text = path ? fs.readFileSync(path, "utf8") : fs.readFileSync(0, "utf8");
  return JSON.parse(text);
}

function cleanExpression(expression, type) {
  let parts = String(expression).trim().split(/\s+/).map((part) => part === "?" ? "*" : part);
  if ((type === "QUARTZ" || type === "SPRING" || type === "SPRING53") && parts.length === 7 && parts[6] === "*") {
    parts = parts.slice(0, 6);
  }
  return parts.join(" ");
}

function parse(contract) {
  const params = contract.params || {};
  const expression = cleanExpression(params.expression, params.type);
  const options = { ...(params.options || {}) };
  const start = dateInput(params.start ?? params.at ?? params.date);
  if (start && !options.currentDate) options.currentDate = start;
  if (params.timezone && !options.tz) options.tz = params.timezone;
  return CronExpressionParser.parse(expression, options);
}

function dateInput(value) {
  if (!value || typeof value !== "string") return value;
  if (/[zZ]$/.test(value) || /[+-]\d\d:?\d\d(?:\[[^\]]+\])?$/.test(value)) return value;
  if (/^\d{4}-\d{2}-\d{2}T/.test(value)) return `${value}Z`;
  return value;
}

function iso(value) {
  if (value && typeof value.toDate === "function") return value.toDate().toISOString();
  if (value && typeof value.toISOString === "function") return value.toISOString();
  return String(value);
}

function run(contract) {
  const params = contract.params || {};
  const op = contract.canonical_op || contract.op;
  try {
    if (op === "next_dates") {
      const interval = parse(contract);
      const dates = [];
      for (let i = 0; i < Number(params.count || 1); i += 1) dates.push(iso(interval.next()));
      return { dates };
    }
    if (op === "prev_dates") {
      const interval = parse(contract);
      const dates = [];
      for (let i = 0; i < Number(params.count || 1); i += 1) dates.push(iso(interval.prev()));
      return { dates };
    }
    if (op === "parse_valid") {
      parse(contract);
      return { value: true };
    }
    if (op === "parse_error") {
      try {
        const interval = parse(contract);
        if (params.use_next) interval.next();
        return { error: false };
      } catch (error) {
        return { error: true, messageContains: String(error.message || error) };
      }
    }
    if (op === "match") {
      const interval = parse(contract);
      return { value: Boolean(interval.includesDate(new Date(dateInput(params.date || params.at)))) };
    }
    if (op === "match_range") {
      const interval = parse(contract);
      const stop = new Date(params.stop || params.end);
      const first = interval.next().toDate();
      return { value: first <= stop };
    }
    if (op === "parse_normalize") {
      const interval = parse(contract);
      return { string: interval.stringify(Boolean(params.includeSeconds)) };
    }
    if (op === "unsupported") {
      return { error: true, unsupported: true, messageContains: params.reason || "unsupported canonical op" };
    }
    return { error: true, unsupported: true, messageContains: `unsupported canonical op ${op}` };
  } catch (error) {
    return { error: true, messageContains: String(error.message || error) };
  }
}

const payload = readPayload();
const contracts = Array.isArray(payload) ? payload : payload.contracts;
process.stdout.write(JSON.stringify({
  results: contracts.map((contract) => ({
    name: contract.name,
    cross_id: contract.cross_id,
    actual: run(contract),
  })),
}, null, 2));
