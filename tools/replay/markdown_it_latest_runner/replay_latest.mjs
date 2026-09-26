#!/usr/bin/env node
import fs from 'node:fs'
import MarkdownIt from 'markdown-it'
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

function makeParser (optionsSpec) {
  if (!optionsSpec || typeof optionsSpec !== 'object') return new MarkdownIt()
  const preset = optionsSpec.preset || 'default'
  const enabled = Array.isArray(optionsSpec.enabled) ? optionsSpec.enabled : []
  const options = {
    ...(optionsSpec.options || {}),
    html: Boolean(optionsSpec.unsafe || optionsSpec.options?.html),
    xhtmlOut: Boolean(optionsSpec.xhtml || optionsSpec.options?.xhtmlOut),
    breaks: Boolean(optionsSpec.hard_wraps || optionsSpec.options?.breaks),
    linkify: Boolean(enabled.includes('linkify') || optionsSpec.options?.linkify),
    typographer: Boolean(enabled.includes('typographer') || enabled.includes('smart_punctuation') || optionsSpec.options?.typographer)
  }
  if (preset === 'commonmark') return new MarkdownIt('commonmark', options)
  if (preset === 'zero') return new MarkdownIt('zero', options)
  return new MarkdownIt(options)
}

function applyActions (md, actions) {
  for (const action of actions || []) {
    if (action.kind === 'linkify_set') md.linkify.set(action.options || {})
    if (action.kind === 'disable') md.disable(action.rules || [])
    if (action.kind === 'enable') md.enable(action.rules || [])
  }
}

function evaluate (contract, mutant = false) {
  const expected = mutant ? contract.mutant : contract.expected
  if (contract.op !== 'render' && contract.op !== 'render_inline') {
    return {
      replay_passed: false,
      actual: { error: `unsupported op: ${contract.op}` }
    }
  }
  const md = makeParser(contract.params.options)
  applyActions(md, contract.params.actions)
  const actual = {
    html: contract.op === 'render_inline'
      ? md.renderInline(contract.params.markdown || '')
      : md.render(contract.params.markdown || '')
  }
  return {
    replay_passed: htmlStandardize(actual.html) === htmlStandardize(expected.html),
    actual
  }
}

const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
const results = input.contracts.map(contract => {
  try {
    const replay = evaluate(contract, false)
    const mutant = replay.replay_passed ? evaluate(contract, true) : { replay_passed: false }
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
