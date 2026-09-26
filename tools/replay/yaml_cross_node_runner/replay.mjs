#!/usr/bin/env node
import fs from 'node:fs'
import YAML from 'yaml'
import * as jsYaml from 'js-yaml'

const [target, inputPath] = process.argv.slice(2)
if (!target || !inputPath) {
  console.error('usage: replay.mjs <eemeli|js-yaml> <contracts.json>')
  process.exit(2)
}

const source = JSON.parse(fs.readFileSync(inputPath, 'utf8'))
const contracts = source.contracts ?? source.survivors ?? []

function normalize(value) {
  if (value === undefined) return null
  if (value === null) return null
  if (typeof value === 'number') {
    if (Number.isNaN(value)) return { special: 'nan' }
    if (!Number.isFinite(value)) return { special: value > 0 ? 'inf' : '-inf' }
    return value
  }
  if (value instanceof Date) {
    const iso = value.toISOString()
    return iso.endsWith('T00:00:00.000Z') ? iso.slice(0, 10) : iso.replace('.000Z', 'Z')
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

function parseDocs(text) {
  if (target === 'eemeli') {
    const docs = YAML.parseAllDocuments(text, { resolveKnownTags: false })
    const errors = docs.flatMap(doc => doc.errors ?? [])
    if (errors.length) throw new Error(errors.map(error => error.message).join('; '))
    return docs.map(doc => normalize(doc.toJS({ mapAsMap: false })))
  }
  const docs = []
  jsYaml.loadAll(text, doc => docs.push(normalize(doc)), { schema: jsYaml.DEFAULT_SCHEMA })
  return docs
}

function parseOne(text) {
  const docs = parseDocs(text)
  return docs.length === 1 ? docs[0] : docs
}

function parseError(text) {
  try {
    parseDocs(text)
    return false
  } catch {
    return true
  }
}

function dump(value) {
  if (target === 'eemeli') return YAML.stringify(value)
  return jsYaml.dump(value, { lineWidth: -1, noRefs: true })
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') {
    if (Object.keys(value).length === 1 && Object.hasOwn(value, 'special')) return value
    const out = {}
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key])
    return out
  }
  return value
}

function deepEqual(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right))
}

function stripDump(text) {
  return text.replace(/\n\.\.\.\n$/, '\n').replace(/\n$/, '')
}

function scalarKind(value) {
  if (typeof value === 'boolean') return { kind: 'bool', value }
  if (value === null) return { kind: 'null', value: null }
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return { kind: 'int', value }
    if (Number.isNaN(value)) return { kind: 'float', special: 'nan' }
    if (!Number.isFinite(value)) return { kind: 'float', special: value > 0 ? 'inf' : '-inf' }
    return { kind: 'float', value }
  }
  return { kind: 'str', value: String(value) }
}

function lookupPath(value, path) {
  let cur = value
  for (const step of path ?? []) {
    if (cur == null) return null
    cur = cur[String(step)]
  }
  return cur
}

function run(contract, expected) {
  const params = contract.params ?? {}
  const op = contract.op
  if (op === 'safe_load_json_value' || op === 'parse_to_value') return { value: parseOne(params.yaml ?? '') }
  if (op === 'parse_to_value_at_path') return { value: lookupPath(parseOne(params.yaml ?? ''), params.path ?? []) }
  if (op === 'decode_stream_values') return { value: parseDocs(params.yaml ?? '') }
  if (op === 'parse_to_json_docs') return { value: parseDocs(params.yaml ?? '') }
  if (op === 'json_parse_success') return { value: parseOne(params.json ?? '') }
  if (op === 'json_stringify_reparse_success') return { value: parseOne(JSON.stringify(parseOne(params.json ?? ''))) }
  if (op === 'stringify_reparse_json_docs') {
    const rendered = parseDocs(params.yaml ?? '').map(doc => dump(doc)).join('')
    return { value: parseDocs(rendered) }
  }
  if (op === 'emitted_yaml_matches_json') return { value: parseDocs(params.emitted_yaml ?? '') }
  if (op === 'load_all_error' || op === 'load_single_error' || op === 'parse_error_presence') return { errors: parseError(params.yaml ?? ''), error: parseError(params.yaml ?? '') }
  if (op === 'schema_safe_load_scalar') return scalarKind(parseOne(params.yaml ?? ''))
  if (op === 'schema_safe_dump_loaded_scalar') return { dump: stripDump(dump(parseOne(params.yaml ?? ''))) }
  if (op === 'parse_canonical_equivalence' || op === 'compose_canonical_equivalence') return { value: deepEqual(parseDocs(params.yaml ?? ''), parseDocs(expected.canonical ?? params.canonical ?? '')) }
  if (op === 'emit_parse_roundtrip') {
    const value = parseDocs(params.yaml ?? '')
    const rendered = value.map(doc => dump(doc)).join('')
    return { value: deepEqual(value, parseDocs(rendered)) }
  }
  if (op === 'load_unicode_text' || op === 'load_unicode_utf8_bytes' || op === 'load_unicode_utf8_bom_bytes' || op === 'load_unicode_utf16be_bom_bytes' || op === 'load_unicode_utf16le_bom_bytes') {
    return { value: normalize(parseOne(params.text ?? '')) }
  }
  if (op === 'cst_roundtrip_source' || op === 'scan_tokens' || op === 'parse_structure' || op === 'parse_node_signature') {
    return { error: 'nonportable-surface' }
  }
  if (op === 'marshal_to_yaml') return { yaml: dump(params.value) }
  return { error: `unsupported op: ${op}` }
}

function evaluate(contract, expected) {
  try {
    const actual = run(contract, expected)
    if (actual.error && !Object.hasOwn(expected, 'error') && !Object.hasOwn(expected, 'errors')) return { ok: false, actual, misses: [String(actual.error)] }
    for (const [key, value] of Object.entries(expected)) {
      if (key === 'comparison' || key === 'error_regex') continue
      if (!deepEqual(actual[key], value)) return { ok: false, actual, misses: [`${key} mismatch`] }
    }
    return { ok: true, actual, misses: [] }
  } catch (error) {
    return { ok: false, actual: { error: error?.name ?? 'Error', message: error?.message ?? String(error) }, misses: [`${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`] }
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
    cross_id: contract.cross_id,
    origin: contract.origin,
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

console.log(JSON.stringify({ target, input_contracts: contracts.length, survivors, results }, null, 2))
