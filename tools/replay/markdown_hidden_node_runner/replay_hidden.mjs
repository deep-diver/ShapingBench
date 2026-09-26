#!/usr/bin/env node
import fs from 'node:fs'
import * as commonmark from 'commonmark'
import { marked } from 'marked'
import { decodeHTML } from 'entities'

function htmlStandardize (text) {
  return decodeHTML(String(text ?? '')
    .replaceAll('<br>', '<br />')
    .replaceAll('<br/>', '<br />')
    .replaceAll('<hr>', '<hr />')
    .replaceAll('<hr/>', '<hr />')
    .replaceAll('>\n<', '><')
    .trim())
}

function stripInlineEnvelope (html) {
  if (html.startsWith('<p>') && html.endsWith('</p>\n')) {
    return html.slice(3, -5)
  }
  if (html.startsWith('<p>') && html.endsWith('</p>')) {
    return html.slice(3, -4)
  }
  return html
}

function renderCommonmark (contract) {
  const parser = new commonmark.Parser()
  const renderer = new commonmark.HtmlRenderer({
    safe: !Boolean(contract.params?.options?.unsafe)
  })
  let html = renderer.render(parser.parse(contract.params?.markdown || ''))
  if (contract.op === 'render_inline') html = stripInlineEnvelope(html)
  return html
}

function renderMarked (contract) {
  const options = contract.params?.options || {}
  const enabled = Array.isArray(options.enabled) ? options.enabled : []
  marked.setOptions({
    async: false,
    gfm: true,
    breaks: Boolean(options.hard_wraps || options.options?.breaks),
    pedantic: false,
    silent: true
  })
  let html = marked.parse(contract.params?.markdown || '')
  if (contract.op === 'render_inline' && typeof marked.parseInline === 'function') {
    html = marked.parseInline(contract.params?.markdown || '')
  } else if (contract.op === 'render_inline') {
    html = stripInlineEnvelope(html)
  }
  if (!enabled.includes('tables') && contract.capability?.includes('tables')) {
    html = marked.parse(contract.params?.markdown || '')
  }
  return html
}

function render (target, contract) {
  if (contract.op !== 'render' && contract.op !== 'render_inline') {
    return { ok: false, actual: { error: `unsupported op: ${contract.op}` } }
  }
  if (target === 'commonmark') return { ok: true, html: renderCommonmark(contract) }
  if (target === 'marked') return { ok: true, html: renderMarked(contract) }
  return { ok: false, actual: { error: `unknown target: ${target}` } }
}

function evaluate (target, contract, mutant = false) {
  const actual = render(target, contract)
  if (!actual.ok) return { replay_passed: false, actual: actual.actual }
  const expected = mutant ? contract.mutant : contract.expected
  return {
    replay_passed: htmlStandardize(actual.html) === htmlStandardize(expected.html),
    actual: { html: actual.html }
  }
}

const target = process.argv[2]
const inputPath = process.argv[3]
const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'))
const results = input.contracts.map(contract => {
  try {
    const replay = evaluate(target, contract, false)
    const mutant = replay.replay_passed ? evaluate(target, contract, true) : { replay_passed: false }
    return {
      name: contract.name,
      version: contract.version,
      capability: contract.capability,
      source_kind: contract.source_kind,
      op: contract.op,
      replay_passed: replay.replay_passed,
      mutant_rejected: replay.replay_passed && !mutant.replay_passed,
      status: replay.replay_passed && !mutant.replay_passed ? 'passed' : 'failed',
      actual: replay.actual
    }
  } catch (error) {
    return {
      name: contract.name,
      version: contract.version,
      capability: contract.capability,
      source_kind: contract.source_kind,
      op: contract.op,
      replay_passed: false,
      mutant_rejected: false,
      status: 'failed',
      actual: { error: error.name, message: error.message }
    }
  }
})
process.stdout.write(JSON.stringify({ results }))
