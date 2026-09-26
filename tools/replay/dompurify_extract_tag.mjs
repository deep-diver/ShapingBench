#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import vm from 'node:vm';

const [repo, tag] = process.argv.slice(2);

function show(path) {
  try {
    return execFileSync('git', ['-C', repo, 'show', `${tag}:${path}`], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

function serialize(value, seen = new Set()) {
  if (value === undefined) return { __undefined: true };
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'function') {
    return { __function: value.toString() };
  }
  if (seen.has(value)) {
    return { __cycle: true };
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => serialize(item, seen));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      try {
        out[key] = serialize(value[key], seen);
      } catch {
        out[key] = { __unserializable: true };
      }
    }
    return out;
  }
  return { __unserializable: typeof value };
}

function evalFixture(source) {
  const code = source.replace(/^\s*export\s+default\s+/, 'module.exports = ');
  const context = {
    module: { exports: {} },
    exports: {},
  };
  vm.runInNewContext(code, context, { timeout: 5000 });
  return Array.isArray(context.module.exports) ? context.module.exports : [];
}

function marker(id) {
  return {
    __sanitizeCall: id,
    toString() {
      return `__SANITIZE_CALL_${id}__`;
    },
    valueOf() {
      return `__SANITIZE_CALL_${id}__`;
    },
  };
}

function extractSuite(source) {
  const context = {
    module: { exports: {} },
    exports: {},
    globalThis: {},
    self: {},
    console,
  };
  try {
    vm.runInNewContext(source, context, { timeout: 5000 });
  } catch {
    return [];
  }
  const testSuite = context.module.exports;
  if (typeof testSuite !== 'function') return [];

  let next = 1;
  let currentTest = '';
  const calls = new Map();
  const captures = [];
  const DOMPurify = function () {
    return DOMPurify;
  };
  DOMPurify.sanitize = (...args) => {
    const id = next++;
    calls.set(id, { id, args, test: currentTest });
    return marker(id);
  };
  for (const name of ['addHook', 'removeHook', 'removeHooks', 'removeAllHooks', 'setConfig', 'clearConfig']) {
    DOMPurify[name] = () => {};
  }
  DOMPurify.isSupported = true;
  DOMPurify.isValidAttribute = () => true;
  DOMPurify.removed = [];

  const assert = {
    equal(actual, expected, message) {
      if (actual && actual.__sanitizeCall) captures.push({ id: actual.__sanitizeCall, expected, assert: 'equal', message });
    },
    strictEqual(actual, expected, message) {
      this.equal(actual, expected, message);
    },
    deepEqual(actual, expected, message) {
      this.equal(actual, expected, message);
    },
    contains(actual, expected, message) {
      if (actual && actual.__sanitizeCall) captures.push({ id: actual.__sanitizeCall, expected, assert: 'contains', message });
    },
    ok() {},
    notOk() {},
    notEqual() {},
    async() {
      return () => {};
    },
    throws(fn) {
      try {
        fn();
      } catch {}
    },
  };
  const fakeQUnit = {
    module() {},
    test(name, fn) {
      currentTest = name;
      try {
        fn(assert);
      } catch {}
    },
  };
  context.QUnit = fakeQUnit;
  context.globalThis.QUnit = fakeQUnit;
  global.QUnit = fakeQUnit;

  const fakeElement = {
    innerHTML: '',
    textContent: '',
    appendChild() {},
    removeChild() {},
    setAttribute() {},
    getAttribute() {
      return null;
    },
    parentNode: { removeChild() {} },
    content: {},
  };
  const document = {
    getElementById() {
      return fakeElement;
    },
    createElement() {
      return fakeElement;
    },
    createTextNode() {
      return fakeElement;
    },
    body: fakeElement,
    implementation: {
      createHTMLDocument() {
        return document;
      },
    },
    createTreeWalker() {
      return { nextNode() { return null; } };
    },
  };
  const window = {
    document,
    jQuery: () => ({ html() {}, empty() {} }),
    NodeFilter: { SHOW_ELEMENT: 1 },
    DOMParser: function DOMParser() {
      this.parseFromString = () => document;
    },
    trustedTypes: null,
    alert() {},
  };

  try {
    testSuite(DOMPurify, window, [], []);
  } catch {}

  const out = [];
  for (const capture of captures) {
    const call = calls.get(capture.id);
    if (!call) continue;
    const [dirty, config] = call.args;
    if (typeof dirty !== 'string') continue;
    const expected = capture.expected;
    const expectedOk = typeof expected === 'string' || (Array.isArray(expected) && expected.every((item) => typeof item === 'string'));
    if (!expectedOk) continue;
    out.push({
      title: call.test || capture.message || `static sanitize ${capture.id}`,
      dirty,
      config: serialize(config),
      expected,
      evidence: `test/test-suite.js::${call.test || capture.message || capture.id}`,
    });
  }
  return out;
}

const fixtures = [];
for (const path of ['test/fixtures/expect.mjs', 'test/fixtures/expect.js']) {
  const source = show(path);
  if (!source) continue;
  for (const item of evalFixture(source)) {
    if (typeof item?.payload !== 'string') continue;
    const expected = item.expected;
    const expectedOk = typeof expected === 'string' || (Array.isArray(expected) && expected.every((value) => typeof value === 'string'));
    if (!expectedOk) continue;
    fixtures.push({
      title: item.title || `fixture ${fixtures.length + 1}`,
      dirty: item.payload,
      config: null,
      expected,
      evidence: `${path}::${item.title || fixtures.length + 1}`,
    });
  }
}

const suiteSource = show('test/test-suite.js');
const statics = suiteSource ? extractSuite(suiteSource) : [];

console.log(JSON.stringify({ tag, fixtures, statics }));
