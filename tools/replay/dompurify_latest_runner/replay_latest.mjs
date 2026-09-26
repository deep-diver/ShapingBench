#!/usr/bin/env node
import fs from 'node:fs';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const [contractsPath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(contractsPath, 'utf8'));
const contracts = payload.contracts || [];

function revive(value) {
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(revive);
  }
  if (value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, '__function')) {
    const source = value.__function;
    try {
      return Function(`"use strict"; return (${source});`)();
    } catch {
      return undefined;
    }
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      if (child && typeof child === 'object' && (child.__undefined || child.__cycle || child.__unserializable)) continue;
      out[key] = revive(child);
    }
    return out;
  }
  return undefined;
}

function makePurify() {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'https://example.test/',
    runScripts: 'dangerously',
  });
  return createDOMPurify(window);
}

function cleanValue(value) {
  if (value === null || value === undefined) return String(value);
  return String(value);
}

function matches(clean, expected) {
  if (Array.isArray(expected)) {
    return expected.includes(clean);
  }
  return clean === expected;
}

function firstMiss(clean, expected) {
  const sample = Array.isArray(expected) ? expected.slice(0, 3) : expected;
  return `clean: expected ${JSON.stringify(sample)}, got ${JSON.stringify(clean)}`;
}

const results = [];
for (const contract of contracts) {
  const params = contract.params || {};
  let actual = {};
  try {
    const DOMPurify = makePurify();
    const config = revive(params.config);
    const clean = cleanValue(DOMPurify.sanitize(params.dirty, config || undefined));
    actual = { clean };
  } catch (error) {
    actual = { throws: error?.constructor?.name || 'Error', message: String(error?.message || error) };
  }
  const expectedClean = contract.expected?.clean;
  const replayPassed = Object.prototype.hasOwnProperty.call(actual, 'clean') && matches(actual.clean, expectedClean);
  const mutantClean = contract.mutant?.clean;
  const mutantWouldPass = Object.prototype.hasOwnProperty.call(actual, 'clean') && matches(actual.clean, mutantClean);
  results.push({
    name: contract.name,
    version: contract.version,
    capability: contract.capability,
    op: contract.op,
    source_kind: contract.source_kind,
    status: replayPassed && !mutantWouldPass ? 'passed' : 'failed',
    replay_passed: replayPassed,
    mutant_rejected: !mutantWouldPass,
    misses: replayPassed ? [] : [firstMiss(actual.clean, expectedClean)],
    expected: contract.expected,
    actual,
  });
}

console.log(JSON.stringify({ results }));
