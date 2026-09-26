#!/usr/bin/env node
import fs from 'node:fs';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import sanitizeHtml from 'sanitize-html';

const [target, contractsPath] = process.argv.slice(2);
const payload = JSON.parse(fs.readFileSync(contractsPath, 'utf8'));

function revive(value) {
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(revive);
  if (value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, '__function')) {
    try {
      return Function(`"use strict"; return (${value.__function});`)();
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

function domPurify() {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'https://example.test/',
    runScripts: 'dangerously',
  });
  return createDOMPurify(window);
}

const jsoupTagSets = {
  none: [],
  empty: [],
  simpleText: ['b', 'em', 'i', 'strong', 'u'],
  basic: ['a', 'b', 'blockquote', 'br', 'cite', 'code', 'dd', 'dl', 'dt', 'em', 'i', 'li', 'ol', 'p', 'pre', 'q', 'small', 'span', 'strike', 'strong', 'sub', 'sup', 'u', 'ul'],
  basicWithImages: ['a', 'b', 'blockquote', 'br', 'cite', 'code', 'dd', 'dl', 'dt', 'em', 'i', 'img', 'li', 'ol', 'p', 'pre', 'q', 'small', 'span', 'strike', 'strong', 'sub', 'sup', 'u', 'ul'],
  relaxed: ['a', 'b', 'blockquote', 'br', 'caption', 'cite', 'code', 'col', 'colgroup', 'dd', 'div', 'dl', 'dt', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'i', 'img', 'li', 'ol', 'p', 'pre', 'q', 'small', 'span', 'strike', 'strong', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'u', 'ul'],
};

function jsoupAttrs(base) {
  const attrs = {};
  function add(tag, values) {
    attrs[tag] = Array.from(new Set([...(attrs[tag] || []), ...values]));
  }
  if (['basic', 'basicWithImages', 'relaxed'].includes(base)) {
    add('a', ['href']);
    add('blockquote', ['cite']);
    add('q', ['cite']);
  }
  if (['basicWithImages', 'relaxed'].includes(base)) {
    add('img', ['src', 'alt', 'height', 'width', 'title']);
  }
  if (base === 'relaxed') {
    add('ol', ['start', 'type']);
    add('ul', ['type']);
    add('li', ['value']);
    add('td', ['abbr', 'axis', 'colspan', 'rowspan', 'width']);
    add('th', ['abbr', 'axis', 'colspan', 'rowspan', 'scope', 'width']);
    add('col', ['span', 'width']);
    add('colgroup', ['span', 'width']);
  }
  return attrs;
}

function policyFromJsoupSafelist(spec) {
  if (!spec) return null;
  const tags = new Set(jsoupTagSets[spec.base] || []);
  const attrs = jsoupAttrs(spec.base);
  let allowAllAttrs = attrs['*'] || attrs[':all'] || [];
  let preserveRelative = false;
  for (const step of spec.steps || []) {
    const args = step.args || [];
    if (step.method === 'addTags') args.forEach((tag) => tags.add(tag));
    if (step.method === 'removeTags') args.forEach((tag) => tags.delete(tag));
    if (step.method === 'addAttributes' && args.length >= 2) {
      const tag = args[0] === ':all' ? '*' : args[0];
      attrs[tag] = Array.from(new Set([...(attrs[tag] || []), ...args.slice(1)]));
      if (tag === '*') allowAllAttrs = attrs[tag];
    }
    if (step.method === 'removeAttributes' && args.length >= 2) {
      const tag = args[0] === ':all' ? '*' : args[0];
      const remove = new Set(args.slice(1));
      attrs[tag] = (attrs[tag] || []).filter((attr) => !remove.has(attr));
      if (tag === '*') allowAllAttrs = attrs[tag];
    }
    if (step.method === 'preserveRelativeLinks') preserveRelative = !!step.value;
  }
  return { tags: Array.from(tags), attrs, allowAllAttrs, preserveRelative };
}

function policyFromOwasp(policy) {
  const tags = new Set();
  const attrs = {};
  let allowStyle = false;
  let relNofollow = false;
  function addAttrs(tag, list) {
    attrs[tag] = Array.from(new Set([...(attrs[tag] || []), ...list]));
  }
  function addCanned(name) {
    if (name === 'FORMATTING') ['b', 'i', 'font', 's', 'u', 'o', 'sup', 'sub', 'ins', 'del', 'strong', 'strike', 'tt', 'code', 'big', 'small', 'br', 'span', 'em'].forEach((t) => tags.add(t));
    if (name === 'BLOCKS') ['p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'ul', 'ol', 'li'].forEach((t) => tags.add(t));
    if (name === 'LINKS') { tags.add('a'); addAttrs('a', ['href']); relNofollow = true; }
    if (name === 'IMAGES') { tags.add('img'); addAttrs('img', ['src', 'alt', 'height', 'width', 'title']); }
    if (name === 'TABLES') ['table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'caption', 'col', 'colgroup'].forEach((t) => tags.add(t));
    if (name === 'STYLES') { allowStyle = true; addAttrs('*', ['style']); }
  }
  function visit(p) {
    if (!p) return;
    if (p.type === 'sanitizers') for (const name of p.names || []) addCanned(name);
    if (p.type === 'and') for (const child of p.policies || []) visit(child);
    if (p.type === 'builder') {
      for (const step of p.steps || []) {
        const args = step.args || [];
        if (step.method === 'allowCommonInlineFormattingElements') addCanned('FORMATTING');
        if (step.method === 'allowCommonBlockElements') addCanned('BLOCKS');
        if (step.method === 'allowStyling') { allowStyle = true; addAttrs('*', ['style']); }
        if (step.method === 'requireRelNofollowOnLinks' || step.method === 'requireRelsOnLinks') relNofollow = true;
        if (step.method === 'allowElements') args.forEach((t) => tags.add(t));
        if (step.method === 'disallowElements') args.forEach((t) => tags.delete(t));
        if (step.method === 'allowAttributes') {
          const target = step.target === 'globally' ? '*' : null;
          if (target) addAttrs(target, args);
          for (const t of step.targets || []) addAttrs(t, args);
        }
        if (step.method === 'disallowAttributes') {
          const targetTags = step.target === 'globally' ? ['*'] : (step.targets || []);
          for (const t of targetTags) {
            const remove = new Set(args);
            attrs[t] = (attrs[t] || []).filter((a) => !remove.has(a));
          }
        }
      }
    }
  }
  visit(policy);
  return { tags: Array.from(tags), attrs, allowStyle, relNofollow };
}

function domPurifyConfigFromPolicy(policy) {
  if (!policy) return undefined;
  const cfg = { ALLOWED_TAGS: policy.tags || [], ALLOWED_ATTR: [] };
  const attrs = new Set(policy.allowAllAttrs || []);
  for (const list of Object.values(policy.attrs || {})) list.forEach((a) => attrs.add(a));
  cfg.ALLOWED_ATTR = Array.from(attrs);
  return cfg;
}

function sanitizeHtmlOptionsFromPolicy(policy) {
  if (!policy) return undefined;
  const allowedAttributes = {};
  for (const [tag, list] of Object.entries(policy.attrs || {})) {
    allowedAttributes[tag === ':all' ? '*' : tag] = list;
  }
  return {
    allowedTags: policy.tags || [],
    allowedAttributes,
    allowedSchemes: ['http', 'https', 'mailto', 'ftp', 'cid', 'data'],
    allowProtocolRelative: true,
  };
}

function attrEscape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function fragmentText(markup) {
  const { window } = new JSDOM(`<body>${markup}</body>`);
  return window.document.body.textContent;
}

function firstAttr(markup, selector, attr) {
  const { window } = new JSDOM(`<body>${markup}</body>`);
  const el = window.document.body.querySelector(selector);
  if (!el || !el.hasAttribute(attr)) return null;
  const value = el.getAttribute(attr);
  return value === '' ? null : value;
}

function portable(contract) {
  const op = contract.op;
  if (op === 'sanitize') {
    return { kind: 'clean', dirty: contract.params.dirty, policy: { type: 'dompurify', config: revive(contract.params.config) } };
  }
  if (op === 'jsoup_clean' || op === 'jsoup_clean_document') {
    return { kind: 'clean', dirty: contract.params.html, policy: { type: 'jsoup', safelist: contract.params.safelist } };
  }
  if (op === 'jsoup_is_valid' || op === 'jsoup_is_valid_document') {
    return { kind: 'valid', dirty: contract.params.html, policy: { type: 'jsoup', safelist: contract.params.safelist } };
  }
  if (op === 'policy_sanitize') {
    return { kind: 'clean', dirty: contract.params.dirty, policy: { type: 'owasp', policy: contract.params.policy } };
  }
  if (op === 'html_sanitizer_test_sanitize') {
    return { kind: 'clean', dirty: contract.params.html ?? '', policy: { type: 'owasp-html-test' } };
  }
  if (op === 'antisamy_contains') {
    return { kind: 'contains', dirty: contract.params.html, needle: contract.params.needle, policy: { type: 'owasp-antisamy' } };
  }
  if (op === 'css_sanitize') {
    return { kind: 'css', dirty: `<span style="${attrEscape(contract.params.css)}">x</span>`, policy: { type: 'css-style-attribute' } };
  }
  if (op === 'decode_html') {
    if (contract.params.in_attribute) {
      return { kind: 'attr_text', dirty: `<span title="${attrEscape(contract.params.html)}">x</span>`, policy: { type: 'entity-observation' } };
    }
    return { kind: 'text', dirty: String(contract.params.html ?? ''), policy: { type: 'entity-observation' } };
  }
  if (op === 'strip_banned') {
    return { kind: 'text', dirty: String(contract.params.text ?? ''), policy: { type: 'entity-observation' } };
  }
  return null;
}

function optionsFor(contract) {
  const p = portable(contract);
  if (!p) return null;
  if (target === 'dompurify') {
    if (p.policy.type === 'dompurify') return p.policy.config || undefined;
    if (p.policy.type === 'jsoup') return domPurifyConfigFromPolicy(policyFromJsoupSafelist(p.policy.safelist));
    if (p.policy.type === 'owasp') return domPurifyConfigFromPolicy(policyFromOwasp(p.policy.policy));
    if (p.policy.type === 'owasp-html-test' || p.policy.type === 'owasp-antisamy') return undefined;
    if (p.policy.type === 'css-style-attribute') return { ALLOWED_TAGS: ['span'], ALLOWED_ATTR: ['style'] };
    if (p.policy.type === 'entity-observation') return { ALLOWED_TAGS: ['span'], ALLOWED_ATTR: ['title'] };
  }
  if (target === 'sanitize-html') {
    if (p.policy.type === 'jsoup') return sanitizeHtmlOptionsFromPolicy(policyFromJsoupSafelist(p.policy.safelist));
    if (p.policy.type === 'owasp') return sanitizeHtmlOptionsFromPolicy(policyFromOwasp(p.policy.policy));
    if (p.policy.type === 'dompurify') return undefined;
    if (p.policy.type === 'owasp-html-test' || p.policy.type === 'owasp-antisamy') return undefined;
    if (p.policy.type === 'css-style-attribute') {
      return { allowedTags: ['span'], allowedAttributes: { span: ['style'] }, allowedStyles: { '*': { '*': [/^[\\s\\S]*$/] } } };
    }
    if (p.policy.type === 'entity-observation') {
      return { allowedTags: ['span'], allowedAttributes: { span: ['title'] } };
    }
  }
  return undefined;
}

function runClean(contract) {
  const p = portable(contract);
  if (!p) return { unsupported: true, reason: `unsupported op ${contract.op}` };
  const opts = optionsFor(contract);
  const dirty = p.dirty == null ? '' : String(p.dirty);
  let clean;
  if (target === 'dompurify') clean = String(domPurify().sanitize(dirty, opts));
  else if (target === 'sanitize-html') clean = sanitizeHtml(dirty, opts);
  else throw new Error(`unknown target ${target}`);
  if (p.kind === 'contains') return { contains: clean.includes(p.needle), clean };
  if (p.kind === 'valid') return { valid: clean === dirty, clean };
  if (p.kind === 'css') return { clean: firstAttr(clean, 'span', 'style') };
  if (p.kind === 'attr_text') return { text: firstAttr(clean, 'span', 'title') ?? '' };
  if (p.kind === 'text') return { text: fragmentText(clean) };
  return { clean };
}

const results = [];
for (const contract of payload.contracts || []) {
  try {
    const actual = runClean(contract);
    results.push({ name: contract.name, actual });
  } catch (error) {
    results.push({ name: contract.name, actual: { error: error?.constructor?.name || 'Error', message: String(error?.message || error) } });
  }
}
console.log(JSON.stringify({ target, results }));
