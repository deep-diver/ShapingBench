#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const ROOT = path.resolve(__dirname, '../../..');
const KEY_DIR = path.join(ROOT, '.cache/jwt/node-jsonwebtoken/test');

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function loadKey(name) {
  return fs.readFileSync(path.join(KEY_DIR, name));
}

function coerceOptions(options) {
  if (!options) return {};
  const out = deepClone(options);
  if (out.audience && typeof out.audience === 'object' && out.audience.regex) {
    out.audience = new RegExp(out.audience.regex);
  } else if (Array.isArray(out.audience)) {
    out.audience = out.audience.map((item) => (item && typeof item === 'object' && item.regex ? new RegExp(item.regex) : item));
  }
  return out;
}

function serializeError(error) {
  const out = {
    ok: false,
    error: true,
    error_name: error && error.name ? error.name : error.constructor.name,
    message: String(error && error.message ? error.message : error)
  };
  if (error && error.expiredAt instanceof Date) out.expiredAt_ms = Number(error.expiredAt);
  if (error && error.date instanceof Date) out.date_ms = Number(error.date);
  return out;
}

function normalizePayload(payload) {
  if (Buffer.isBuffer(payload)) return payload.toString('utf8');
  return payload;
}

function decodeComplete(token) {
  const decoded = jwt.decode(token, { complete: true, json: true });
  if (!decoded) return { error: true };
  return {
    header: decoded.header,
    payload: normalizePayload(decoded.payload),
    signature_b64: decoded.signature,
    has_signature: Boolean(decoded.signature)
  };
}

function verifyResult(fn) {
  try {
    const payload = fn();
    return { ok: true, payload: normalizePayload(payload) };
  } catch (error) {
    return serializeError(error);
  }
}

function decode_complete_unverified(params) {
  return decodeComplete(params.token);
}

function decode_claim_value_unverified(params) {
  const payload = jwt.decode(params.token, { json: true });
  return { value: payload ? payload[params.claim] : undefined };
}

function decode_unverified(params) {
  return { payload: normalizePayload(jwt.decode(params.token)) };
}

function decode_error(params) {
  const decoded = jwt.decode(params.token, { complete: true, json: true });
  return { error: decoded === null };
}

function verify_hmac(params) {
  return verifyResult(() => jwt.verify(params.token, params.secret, coerceOptions(params.options)));
}

function verify_literal_hmac(params) {
  return verify_hmac(params);
}

function sign_decode_complete(params) {
  const secret = Object.prototype.hasOwnProperty.call(params, 'secret') ? params.secret : 'secret';
  const key = params.keyFixture ? loadKey(params.keyFixture) : secret;
  const options = Object.assign({}, params.options || {}, { algorithm: params.algorithm || (params.options && params.options.algorithm) || 'HS256' });
  const token = jwt.sign(deepClone(params.payload || {}), key, options);
  return decodeComplete(token);
}

function sign_verify_hmac(params) {
  const token = jwt.sign(deepClone(params.payload || {}), params.secret || 'secret', { algorithm: params.algorithm || 'HS256' });
  const verifySecret = Object.prototype.hasOwnProperty.call(params, 'verifySecret') ? params.verifySecret : params.secret;
  return verifyResult(() => jwt.verify(token, verifySecret || 'secret', { algorithms: [params.algorithm || 'HS256'] }));
}

function verify_generated_error(params) {
  const token = jwt.sign(deepClone(params.payload || {}), params.secret || 'secret', { algorithm: params.algorithm || 'HS256' });
  return verifyResult(() => jwt.verify(token, params.secret || 'secret', coerceOptions(params.verifyOptions)));
}

function verify_generated_complete(params) {
  const token = jwt.sign(deepClone(params.payload || {}), params.secret || 'secret', { algorithm: params.algorithm || 'HS256' });
  try {
    const decoded = jwt.verify(token, params.secret || 'secret', coerceOptions(params.verifyOptions));
    return {
      ok: true,
      header: decoded.header,
      payload: decoded.payload,
      signature_b64: decoded.signature,
      has_signature: Boolean(decoded.signature)
    };
  } catch (error) {
    return serializeError(error);
  }
}

function verify_none_generated(params) {
  const token = jwt.sign(deepClone(params.payload || {}), null, { algorithm: 'none' });
  return verifyResult(() => jwt.verify(token, null, coerceOptions(params.verifyOptions)));
}

function sign_error(params) {
  try {
    jwt.sign(params.payload, params.secret, params.options || {});
    return { error: false };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

function verify_error(params) {
  try {
    const token = params.tokenValue && params.tokenValue.kind === 'object' ? {} : params.tokenValue;
    jwt.verify(token, params.secret, params.options || {});
    return { error: false };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

function sign_mutate_payload(params) {
  const payload = deepClone(params.payload || {});
  const before = deepClone(payload);
  jwt.sign(payload, params.secret || 'secret', params.options || {});
  return { mutated: JSON.stringify(payload) !== JSON.stringify(before), payloadAfter: payload };
}

function rsa_min_key_size_sign(params) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  try {
    const token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256', allowInsecureKeySizes: Boolean(params.allowInsecureKeySizes) });
    const decoded = decodeComplete(token);
    return { error: false, header: decoded.header, payload: decoded.payload };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

function key_confusion_verify(params) {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYUtleUlkIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE2NTk1MTA2MDh9.cOcHI1TXPbxTMlyVTfjArSWskrmezbrG8iR7uJHwtrQ';
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = params.keyFormat === 'pem' ? publicKey.export({ type: 'spki', format: 'pem' }) : publicKey;
  return verifyResult(() => jwt.verify(token, key, { algorithms: ['RS256', 'HS256'] }));
}

function malicious_key_material_rejected() {
  const token = jwt.sign({ foo: 'bar' }, 'secret');
  const maliciousBuffer = { toString: () => { throw new Error('Arbitrary Code Execution'); } };
  try {
    jwt.verify(token, maliciousBuffer);
    return { error: false };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

function invalid_asymmetric_key_type(params) {
  try {
    jwt.sign({ foo: 'bar' }, loadKey(params.keyFixture), {
      algorithm: params.algorithm,
      allowInvalidAsymmetricKeyTypes: Boolean(params.allowInvalidAsymmetricKeyTypes)
    });
    return { error: false };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

function verify_callback_secret(params) {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
  const options = { algorithms: ['HS256'], ignoreExpiration: true };
  return new Promise((resolve) => {
    const provider = (_header, callback) => {
      if (params.mode === 'error') callback(new Error('key not found'));
      else callback(undefined, 'key');
    };
    jwt.verify(token, provider, options, (error, payload) => {
      if (error) resolve(serializeError(error));
      else resolve({ ok: true, payload });
    });
  });
}

function verify_callback_secret_sync_error() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
  try {
    jwt.verify(token, (_header, callback) => callback(undefined, 'key'), { algorithms: ['HS256'], ignoreExpiration: true });
    return { error: false };
  } catch (error) {
    return Object.assign({ error: true }, serializeError(error));
  }
}

const OPS = {
  decode_complete_unverified,
  decode_claim_value_unverified,
  decode_unverified,
  decode_error,
  verify_hmac,
  verify_literal_hmac,
  sign_decode_complete,
  sign_verify_hmac,
  verify_generated_error,
  verify_generated_complete,
  verify_none_generated,
  sign_error,
  verify_error,
  sign_mutate_payload,
  rsa_min_key_size_sign,
  key_confusion_verify,
  malicious_key_material_rejected,
  invalid_asymmetric_key_type,
  verify_callback_secret,
  verify_callback_secret_sync_error
};

function matches(actual, expected) {
  if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    for (const [key, value] of Object.entries(expected)) {
      if (key === 'message_contains') {
        if (typeof actual.message !== 'string' || !actual.message.includes(value)) return false;
      } else if (!Object.prototype.hasOwnProperty.call(actual, key) || !matches(actual[key], value)) {
        return false;
      }
    }
    return true;
  }
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && actual.length === expected.length && expected.every((value, index) => matches(actual[index], value));
  }
  return actual === expected;
}

async function evaluate(contract) {
  const result = { name: contract.name, capability: contract.capability, op: contract.op };
  try {
    if (!OPS[contract.op]) throw new Error(`unsupported op ${contract.op}`);
    const actual = await OPS[contract.op](deepClone(contract.params || {}));
    const replayPass = matches(actual, contract.expected);
    const mutantAccepted = matches(actual, contract.mutant);
    Object.assign(result, {
      replay_pass: replayPass,
      mutant_rejected: !mutantAccepted,
      survived: replayPass && !mutantAccepted,
      actual
    });
    if (!replayPass) result.expected = contract.expected;
  } catch (error) {
    Object.assign(result, {
      replay_pass: false,
      mutant_rejected: false,
      survived: false,
      runner_error: `${error.constructor.name}: ${error.message}`
    });
  }
  return result;
}

async function main() {
  const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const contracts = input.contracts || input;
  const results = [];
  const survivors = [];
  for (const contract of contracts) {
    const result = await evaluate(contract);
    results.push(result);
    if (result.survived) survivors.push(contract);
  }
  process.stdout.write(JSON.stringify({
    implementation: 'auth0/node-jsonwebtoken',
    version: require('jsonwebtoken/package.json').version,
    contracts_total: contracts.length,
    replay_pass: results.filter((row) => row.replay_pass).length,
    mutant_rejected: results.filter((row) => row.mutant_rejected).length,
    survivors: survivors.length,
    survivor_contracts: survivors,
    results
  }));
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
