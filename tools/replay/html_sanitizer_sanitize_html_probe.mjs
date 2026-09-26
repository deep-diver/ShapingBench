#!/usr/bin/env node
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const adapterRequire = createRequire(new URL('./html_sanitizer_node_adapter/package.json', import.meta.url));

function encode(value, seen = new Set()) {
  if (value === undefined) return { __undefined: true };
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof RegExp) return { __regex: value.source, flags: value.flags };
  if (typeof value === 'function') return { __function: true };
  if (typeof value !== 'object') return { __unsupported: String(typeof value) };
  if (seen.has(value)) return { __cycle: true };
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => encode(item, seen));
  const out = {};
  for (const [key, child] of Object.entries(value)) out[key] = encode(child, seen);
  seen.delete(value);
  return out;
}

function hasUnsupported(value) {
  if (!value || typeof value !== 'object') return false;
  if (value.__function || value.__cycle || value.__unsupported) return true;
  if (Array.isArray(value)) return value.some(hasUnsupported);
  return Object.values(value).some(hasUnsupported);
}

function revive(value) {
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(revive);
  if (value && typeof value === 'object' && value.__undefined) return undefined;
  if (value && typeof value === 'object' && value.__regex !== undefined) return new RegExp(value.__regex, value.flags || '');
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) out[key] = revive(child);
    return out;
  }
  return undefined;
}

function fakeSanitizeHtmlFactory(calls) {
  function sanitizeHtml(...args) {
    const marker = { __sanitizeHtmlCall: calls.length };
    calls.push({ args: encode(args) });
    return marker;
  }
  sanitizeHtml.defaults = {
    allowedTags: [
      'address', 'article', 'aside', 'footer', 'header', 'h1', 'h2', 'h3', 'h4',
      'h5', 'h6', 'hgroup', 'main', 'nav', 'section', 'blockquote', 'dd', 'div',
      'dl', 'dt', 'figcaption', 'figure', 'hr', 'li', 'menu', 'ol', 'p', 'pre',
      'ul', 'a', 'abbr', 'b', 'bdi', 'bdo', 'br', 'cite', 'code', 'data', 'dfn',
      'em', 'i', 'kbd', 'mark', 'q', 'rb', 'rp', 'rt', 'rtc', 'ruby', 's', 'samp',
      'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr', 'caption',
      'col', 'colgroup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'
    ],
    allowedAttributes: {
      a: ['href', 'name', 'target'],
      img: ['src', 'srcset', 'alt', 'title', 'width', 'height', 'loading']
    }
  };
  sanitizeHtml.simpleTransform = function simpleTransform(tagName, attribs = {}, merge = true) {
    return function transform() {
      return { tagName, attribs, merge };
    };
  };
  return sanitizeHtml;
}

function extract(source) {
  const calls = [];
  const records = [];
  const sanitizeHtml = fakeSanitizeHtmlFactory(calls);
  let currentTitle = 'module';
  const assert = {};
  function maybeRecord(actual, expected) {
    if (!actual || actual.__sanitizeHtmlCall === undefined) return;
    const call = calls[actual.__sanitizeHtmlCall];
    const args = call.args;
    if (!Array.isArray(args) || args.length === 0) return;
    if (hasUnsupported(args) || hasUnsupported(expected)) return;
    const dirty = args[0];
    if (typeof dirty !== 'string') return;
    records.push({
      title: currentTitle,
      dirty,
      config: args.length > 1 ? args[1] : null,
      expected: encode(expected)
    });
  }
  assert.equal = maybeRecord;
  assert.strictEqual = maybeRecord;
  assert.deepEqual = () => {};
  assert.deepStrictEqual = () => {};
  assert.ok = () => {};
  assert.fail = () => {};
  assert.throws = (fn) => {
    try { fn(); } catch {}
  };
  const sinon = {
    spy() {
      return { calledWith: () => true, notCalled: true, called: false };
    },
    stub() {
      return { callsFake() { return this; }, restore() {} };
    }
  };
  const sandbox = {
    console: { log() {}, warn() {}, error() {} },
    Buffer,
    process: { env: {} },
    require(name) {
      if (name === 'assert') return assert;
      if (name === 'sinon') return sinon;
      if (name === '../index.js' || name === '..' || name === '../') return sanitizeHtml;
      return {};
    },
    describe(title, fn) {
      try { fn.call({ timeout() {} }); } catch {}
    },
    it(title, fn) {
      currentTitle = title;
      try { fn.call({ timeout() {} }); } catch {}
      currentTitle = 'module';
    },
    before(fn) { try { fn(); } catch {} },
    after(fn) { try { fn(); } catch {} },
    beforeEach(fn) { try { fn(); } catch {} },
    afterEach(fn) { try { fn(); } catch {} },
    sanitizeHtml
  };
  vm.createContext(sandbox);
  try {
    vm.runInContext(source, sandbox, { timeout: 3000, filename: 'test.js' });
  } catch {}
  return records.filter((row) => typeof row.expected === 'string');
}

function replay(payload) {
  const sanitizeHtml = adapterRequire('sanitize-html');
  const config = revive(payload.config);
  try {
    const clean = sanitizeHtml(String(payload.dirty ?? ''), config ?? undefined);
    return { clean };
  } catch (error) {
    return { error: error.constructor.name, message: error.message };
  }
}

const mode = process.argv[2];
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
if (mode === 'extract') {
  process.stdout.write(JSON.stringify({ records: extract(input.source) }));
} else if (mode === 'replay') {
  process.stdout.write(JSON.stringify(replay(input)));
} else {
  throw new Error(`unknown mode: ${mode}`);
}
