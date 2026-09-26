#!/usr/bin/env node
import fs from 'node:fs'
import { createRequire } from 'node:module'

const requireFromHidden = createRequire(import.meta.resolve('../markdown_hidden_node_runner/package.json'))
const commonmark = requireFromHidden('commonmark')
const { decodeHTML } = requireFromHidden('entities')
const markedModule = await import('../markdown_hidden_node_runner/node_modules/marked/lib/marked.esm.js')
const { Marked } = markedModule

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
  if (html.startsWith('<p>') && html.endsWith('</p>\n')) return html.slice(3, -5)
  if (html.startsWith('<p>') && html.endsWith('</p>')) return html.slice(3, -4)
  return html
}

function renderCommonmark (contract) {
  const options = contract.params?.options || {}
  const parser = new commonmark.Parser({
    smart: Boolean(options.smart || options.smart_punctuation)
  })
  const renderer = new commonmark.HtmlRenderer({
    safe: !Boolean(options.unsafe)
  })
  let html = renderer.render(parser.parse(contract.params?.markdown || ''))
  if (contract.op === 'render_inline') html = stripInlineEnvelope(html)
  return html
}

function markedOptions (contract) {
  const options = contract.params?.options || {}
  const enabled = Array.isArray(options.enabled) ? options.enabled : []
  return {
    async: false,
    breaks: Boolean(options.breaks || options.hard_wraps),
    gfm: options.gfm !== undefined ? Boolean(options.gfm) : !enabled.includes('no_gfm'),
    pedantic: Boolean(options.pedantic),
    silent: options.silent !== undefined ? Boolean(options.silent) : true
  }
}

function renderMarked (contract) {
  const parser = new Marked(markedOptions(contract))
  if (contract.op === 'render_inline') {
    return parser.parseInline(contract.params?.markdown || '')
  }
  return parser.parse(contract.params?.markdown || '')
}

function render (target, contract) {
  if (contract.op !== 'render' && contract.op !== 'render_inline') {
    return { ok: false, actual: { error: `unsupported op: ${contract.op}` } }
  }
  if (target === 'commonmark-js') return { ok: true, html: renderCommonmark(contract) }
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
