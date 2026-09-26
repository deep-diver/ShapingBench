#!/usr/bin/env node
import fs from 'node:fs'
import * as YAML from 'yaml'

const inputPath = process.argv[2]
if (!inputPath) {
  console.error('usage: replay_latest.mjs <contracts.json>')
  process.exit(2)
}

const source = JSON.parse(fs.readFileSync(inputPath, 'utf8'))
const contracts = source.contracts ?? []

function normalize(value) {
  if (value === undefined) return null
  if (value === null) return null
  if (typeof value === 'number') {
    if (Number.isNaN(value)) return { special: 'nan' }
    if (!Number.isFinite(value)) return { special: value > 0 ? 'inf' : '-inf' }
    return value
  }
  if (typeof value === 'bigint') return Number(value)
  if (typeof value === 'string' || typeof value === 'boolean') return value
  if (value instanceof Map) {
    const out = {}
    for (const [key, item] of value.entries()) out[String(key)] = normalize(item)
    return out
  }
  if (Array.isArray(value)) return value.map(normalize)
  if (typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) out[key] = normalize(item)
    return out
  }
  return String(value)
}

function docsToJSONDocs(text) {
  const docs = YAML.parseAllDocuments(text, { resolveKnownTags: false })
  const errors = docs.flatMap(doc => doc.errors ?? [])
  if (errors.length) {
    const err = new Error(errors.map(error => error.message).join('; '))
    err.yamlErrors = errors
    throw err
  }
  return docs.map(doc => normalize(doc.toJS({ mapAsMap: false })))
}

function parseSingleJSON(text) {
  const doc = YAML.parseDocument(text)
  if (doc.errors.length) {
    const err = new Error(doc.errors.map(error => error.message).join('; '))
    err.yamlErrors = doc.errors
    throw err
  }
  return normalize(doc.toJS({ mapAsMap: false }))
}

function stringifyCST(text) {
  let out = ''
  for (const token of new YAML.Parser().parse(text)) out += YAML.CST.stringify(token)
  return out
}

function runContract(contract, expected) {
  const params = contract.params ?? {}
  const op = contract.op
  if (op === 'parse_error_presence') {
    const docs = YAML.parseAllDocuments(params.yaml ?? '', { resolveKnownTags: false })
    return { errors: docs.some(doc => (doc.errors ?? []).length > 0) }
  }
  if (op === 'parse_to_json_docs') {
    return { value: docsToJSONDocs(params.yaml ?? '') }
  }
  if (op === 'stringify_reparse_json_docs') {
    const docs = YAML.parseAllDocuments(params.yaml ?? '', { resolveKnownTags: false })
    const errors = docs.flatMap(doc => doc.errors ?? [])
    if (errors.length) throw new Error(errors.map(error => error.message).join('; '))
    const rendered = docs.map(doc => String(doc)).join('')
    return { value: docsToJSONDocs(rendered) }
  }
  if (op === 'emitted_yaml_matches_json') {
    return { value: docsToJSONDocs(params.emitted_yaml ?? '') }
  }
  if (op === 'cst_roundtrip_source') {
    return { text: stringifyCST(params.yaml ?? '') }
  }
  if (op === 'json_parse_success') {
    return { value: parseSingleJSON(params.json ?? '') }
  }
  if (op === 'json_stringify_reparse_success') {
    const value = parseSingleJSON(params.json ?? '')
    return { value: parseSingleJSON(JSON.stringify(value)) }
  }
  return { error: 'UnsupportedOperation', message: op }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key])
    return out
  }
  return value
}

function deepEqual(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right))
}

function evaluate(contract, expected) {
  try {
    const actual = runContract(contract, expected)
    if (actual.error && !Object.hasOwn(expected, 'error')) {
      return { ok: false, actual, misses: [`${actual.error}: ${actual.message ?? ''}`] }
    }
    for (const [key, value] of Object.entries(expected)) {
      if (!deepEqual(actual[key], value)) {
        return {
          ok: false,
          actual,
          misses: [`${key} mismatch: expected ${JSON.stringify(value)}, got ${JSON.stringify(actual[key])}`],
        }
      }
    }
    return { ok: true, actual, misses: [] }
  } catch (error) {
    return {
      ok: false,
      actual: { error: error?.name ?? 'Error', message: error?.message ?? String(error) },
      misses: [`${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`],
    }
  }
}

const results = []
const survivors = []
for (const contract of contracts) {
  const replay = evaluate(contract, contract.expected ?? {})
  const mutant = replay.ok ? evaluate(contract, contract.mutant ?? {}) : { ok: false, actual: {}, misses: ['mutant not evaluated because replay failed'] }
  const verified = replay.ok && !mutant.ok
  const row = {
    name: contract.name,
    version: contract.version,
    capability: contract.capability,
    source_kind: contract.source_kind,
    op: contract.op,
    status: verified ? 'passed' : 'failed',
    replay_passed: replay.ok,
    mutant_rejected: replay.ok && !mutant.ok,
    misses: replay.misses,
    mutant_misses: mutant.misses,
    actual: replay.actual,
    mutant_actual: mutant.actual,
  }
  results.push(row)
  if (verified) survivors.push(contract)
}

console.log(JSON.stringify({
  runtime_package: 'yaml',
  runtime_version: YAML.defaultOptions?.version ?? '2.9.0',
  input_contracts: contracts.length,
  latest_replay_passed: results.filter(row => row.replay_passed).length,
  latest_replay_failed: results.filter(row => !row.replay_passed).length,
  latest_mutant_killed: results.filter(row => row.mutant_rejected).length,
  latest_survivors: survivors.length,
  survivors,
  results,
}, null, 2))
