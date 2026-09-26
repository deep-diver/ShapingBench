#!/usr/bin/env node
import fs from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const jsYaml = require('./yaml_cross_node_runner/node_modules/js-yaml')

const args = process.argv.slice(2)
const mode = args.length === 2 ? args[0] : 'replay'
const inputPath = args.length === 2 ? args[1] : args[0]
if (!inputPath || !['replay', 'materialize'].includes(mode)) {
  console.error('usage: yaml_js_yaml_origin_runner.mjs [replay|materialize] <contracts.json>')
  process.exit(2)
}

const payload = JSON.parse(fs.readFileSync(inputPath, 'utf8'))
const contracts = payload.contracts ?? payload.survivors ?? []

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

function schema(name) {
  if (name === 'json') return jsYaml.JSON_SCHEMA
  if (name === 'core') return jsYaml.CORE_SCHEMA
  if (name === 'yaml11') return jsYaml.YAML11_SCHEMA
  if (name === 'failsafe') return jsYaml.FAILSAFE_SCHEMA
  return jsYaml.DEFAULT_SCHEMA
}

function loadDocs(text, opts = {}) {
  const docs = []
  jsYaml.loadAll(text, doc => docs.push(normalize(doc)), { schema: schema(opts.schema) })
  return docs
}

function loadOne(text, opts = {}) {
  const docs = loadDocs(text, opts)
  return docs.length === 1 ? docs[0] : docs
}

function parseError(text, opts = {}) {
  try {
    loadDocs(text, opts)
    return false
  } catch {
    return true
  }
}

function dumpOptions(params) {
  const opts = { ...(params.options ?? {}) }
  if (params.schema) opts.schema = schema(params.schema)
  return opts
}

function dump(value, params = {}) {
  return jsYaml.dump(value, dumpOptions(params))
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

function run(contract) {
  const params = contract.params ?? {}
  const op = contract.op
  if (op === 'parse_to_value' || op === 'parse_to_value_with_schema') return { value: loadOne(params.yaml ?? '', params) }
  if (op === 'parse_to_json_docs') return { value: loadDocs(params.yaml ?? '', params) }
  if (op === 'decode_stream_values') return { value: loadDocs(params.yaml ?? '', params) }
  if (op === 'parse_error_presence') return { errors: parseError(params.yaml ?? '', params), error: parseError(params.yaml ?? '', params) }
  if (op === 'stringify_reparse_json_docs') {
    const rendered = loadDocs(params.yaml ?? '', params).map(doc => dump(doc, params)).join('')
    return { value: loadDocs(rendered, params) }
  }
  if (op === 'emit_parse_roundtrip') {
    const docs = loadDocs(params.yaml ?? '', params)
    const rendered = docs.map(doc => dump(doc, params)).join('')
    return { value: deepEqual(docs, loadDocs(rendered, params)) }
  }
  if (op === 'dump_value_to_yaml' || op === 'dump_option_yaml') return { yaml: dump(params.value, params) }
  if (op === 'dump_value_roundtrip') return { value: loadOne(dump(params.value, params), params) }
  if (op === 'emitted_yaml_matches_json') return { value: loadDocs(params.emitted_yaml ?? '', params) }
  if (op === 'schema_safe_dump_loaded_scalar') return { dump: stripDump(dump(loadOne(params.yaml ?? '', params), params)) }
  return { error: `unsupported op: ${op}` }
}

function evaluate(contract, expected) {
  try {
    const actual = run(contract)
    if (actual.error && !Object.hasOwn(expected, 'error') && !Object.hasOwn(expected, 'errors')) {
      return { ok: false, actual, misses: [String(actual.error)] }
    }
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
  if (mode === 'materialize') {
    try {
      const actual = run(contract)
      if (actual.error) {
        results.push({ ...contract, materialized: false, actual, misses: [String(actual.error)] })
      } else {
        results.push({ ...contract, materialized: true, expected: actual })
      }
    } catch (error) {
      results.push({
        ...contract,
        materialized: false,
        actual: { error: error?.name ?? 'Error', message: error?.message ?? String(error) },
        misses: [`${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`]
      })
    }
    continue
  }
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
    mutant_actual: mutant.actual
  }
  results.push(row)
  if (verified) survivors.push(contract)
}

console.log(JSON.stringify({
  target: 'js-yaml',
  mode,
  runtime_package: 'js-yaml',
  runtime_version: jsYaml.VERSION ?? '5.4.1',
  input_contracts: contracts.length,
  materialized: mode === 'materialize' ? results.filter(row => row.materialized).length : undefined,
  latest_replay_passed: results.filter(row => row.replay_passed).length,
  latest_replay_failed: results.filter(row => !row.replay_passed).length,
  latest_mutant_killed: results.filter(row => row.mutant_rejected).length,
  latest_survivors: survivors.length,
  survivors,
  results
}, null, 2))
