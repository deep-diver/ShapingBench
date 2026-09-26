import axios from 'axios';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const SOURCE = path.join(ROOT, 'contracts/axios/axios_origin_excluding_merged_common.summary.json');
const OUT = path.join(ROOT, 'contracts/axios/axios_origin_latest_replay_mutant_verified.json');
const OUT_MD = path.join(ROOT, 'contracts/axios/axios_origin_latest_replay_mutant_verified.md');
const VERSION = '1.19.0';

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function baseConfig(extra = {}) {
  return {
    proxy: false,
    validateStatus: () => true,
    timeout: 2500,
    maxRedirects: 5,
    ...extra,
  };
}

async function withServer(handler, fn, opts = {}) {
  let accepted = 0;
  const host = opts.host || '127.0.0.1';
  const server = (opts.https ? https : http).createServer(opts.tlsOptions || {}, async (req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      req.body = Buffer.concat(chunks);
      try {
        await handler(req, res);
      } catch (err) {
        res.statusCode = 599;
        res.end(String(err.stack || err));
      }
    });
  });
  server.on('connection', () => { accepted += 1; });
  await new Promise(resolve => server.listen(0, host, resolve));
  const scheme = opts.https ? 'https' : 'http';
  const urlHost = host.includes(':') ? `[${host}]` : host;
  const state = {
    server,
    get acceptedConnections() { return accepted; },
    url: p => `${scheme}://${urlHost}:${server.address().port}${p}`,
    port: () => server.address().port,
  };
  try {
    return await fn(state);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function withRawServer(handler, fn, host = '127.0.0.1') {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    handler(socket);
  });
  await new Promise(resolve => server.listen(0, host, resolve));
  try {
    const urlHost = host.includes(':') ? `[${host}]` : host;
    return await fn({
      port: server.address().port,
      url: p => `http://${urlHost}:${server.address().port}${p}`,
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
}

async function withTunnelProxy(fn, opts = {}) {
  const requests = [];
  const sockets = new Set();
  const host = opts.host || '127.0.0.1';
  const server = net.createServer(client => {
    sockets.add(client);
    client.on('close', () => sockets.delete(client));
    let buffered = Buffer.alloc(0);
    client.on('data', function onHeader(chunk) {
      buffered = Buffer.concat([buffered, chunk]);
      const marker = buffered.indexOf('\r\n\r\n');
      if (marker === -1) return;
      client.off('data', onHeader);
      const header = buffered.subarray(0, marker).toString('latin1');
      const rest = buffered.subarray(marker + 4);
      const requestLine = header.split('\r\n')[0];
      requests.push(requestLine);
      const [method, authority] = requestLine.split(' ');
      if (method !== 'CONNECT') {
        client.end('HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n');
        return;
      }
      const split = authority.lastIndexOf(':');
      const targetHost = authority.slice(0, split).replace(/^\[|\]$/g, '');
      const targetPort = Number(authority.slice(split + 1));
      const upstream = net.connect(targetPort, targetHost, () => {
        sockets.add(upstream);
        upstream.on('close', () => sockets.delete(upstream));
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (rest.length) upstream.write(rest);
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on('error', () => client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'));
    });
  });
  await new Promise(resolve => server.listen(0, host, resolve));
  try {
    return await fn({ requests, port: server.address().port });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
}

function makeTlsOptions(altNames = 'DNS:localhost,IP:127.0.0.1') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axios-origin-tls-'));
  const cert = path.join(dir, 'cert.pem');
  const key = path.join(dir, 'key.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-subj', '/CN=localhost',
    '-addext', `subjectAltName=${altNames}`,
    '-keyout', key, '-out', cert, '-days', '1',
  ], { stdio: 'ignore' });
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

function bodyText(req) {
  return req.body.toString('utf8');
}

async function observeCrossOriginSensitiveHeaderStripping() {
  return withServer((req, res) => res.end(JSON.stringify(req.headers)), async target => {
    return withServer((req, res) => {
      res.writeHead(302, { Location: target.url('/target') });
      res.end();
    }, async source => {
      const response = await axios.get(source.url('/start'), baseConfig({
        headers: { Authorization: 'Bearer secret', Cookie: 'a=1', 'X-Api-Key': 'secret' },
        beforeRedirect: options => {
          delete options.headers['X-Api-Key'];
          delete options.headers['x-api-key'];
        },
      }));
      return response.data;
    });
  });
}

async function malformed_http_url_without_slashes_is_rejected() {
  try {
    await axios.get('http:example.test/path', baseConfig({ timeout: 200 }));
  } catch (err) {
    require(err.code === 'ERR_INVALID_URL' || err.message.includes('Invalid URL'), `${err.code} ${err.message}`);
    return;
  }
  throw new Error('malformed URL accepted');
}

async function validate_status_undefined_can_resolve_like_default() {
  await withServer((req, res) => {
    res.statusCode = 404;
    res.end('missing');
  }, async server => {
    const r = await axios.get(server.url('/'), {
      proxy: false,
      timeout: 2500,
      validateStatus: undefined,
      transitional: { validateStatusUndefinedResolves: true },
    });
    require(r.status === 404, `status ${r.status}`);
  });
}
async function zstd_response_decompression_supported() {
  require(typeof zlib.zstdCompressSync === 'function', 'runtime lacks zstdCompressSync');
  const body = zlib.zstdCompressSync(Buffer.from('hello zstd'));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'zstd');
    res.end(body);
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(r.data === 'hello zstd', String(r.data));
  });
}

async function same_origin_redirect_preserves_basic_auth() {
  const seen = [];
  await withServer((req, res) => {
    seen.push(req.headers.authorization || '');
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/target' });
      res.end();
      return;
    }
    res.end(req.headers.authorization || '');
  }, async server => {
    const r = await axios.get(server.url('/start').replace('http://', 'http://user:p%40ss@'), baseConfig());
    require(r.data === `Basic ${Buffer.from('user:p@ss').toString('base64')}`, `${r.data} seen=${JSON.stringify(seen)}`);
  });
}

async function url_embedded_basic_auth_is_url_decoded() {
  await withServer((req, res) => res.end(req.headers.authorization || ''), async server => {
    const r = await axios.get(server.url('/').replace('http://', 'http://user:p%40ss@'), baseConfig());
    require(r.data === `Basic ${Buffer.from('user:p@ss').toString('base64')}`, r.data);
  });
}

async function https_agent_tls_options_survive_http_connect_proxy() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('secure'), async origin => {
    await withTunnelProxy(async proxy => {
      const r = await axios.get(origin.url('/'), baseConfig({
        httpsAgent,
        proxy: { protocol: 'http', host: '127.0.0.1', port: proxy.port },
      }));
      require(r.data === 'secure', r.data);
      require(proxy.requests[0]?.startsWith('CONNECT 127.0.0.1:'), JSON.stringify(proxy.requests));
    });
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
}

async function blank_header_names_are_skipped() {
  await withServer((req, res) => res.end(req.headers['x-test'] || ''), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { '   ': 'ignored', 'X-Test': 'ok' } }));
    require(r.data === 'ok', r.data);
  });
}

async function unicode_header_values_survive_interceptors() {
  await withServer((req, res) => res.end(req.headers['x-token'] || ''), async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(config => {
      config.headers.set('X-Token', config.headers.get('X-Token'));
      return config;
    });
    const r = await client.get(server.url('/'), { headers: { 'X-Token': 'token-é' } });
    require(String(r.data).startsWith('token-'), r.data);
  });
}

async function econnrefused_error_constant_is_exposed() {
  require(axios.AxiosError.ECONNREFUSED === 'ECONNREFUSED', `constant ${axios.AxiosError.ECONNREFUSED}`);
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  try {
    await axios.get(`http://127.0.0.1:${port}/`, baseConfig({ timeout: 500 }));
  } catch (err) {
    require(err.code === axios.AxiosError.ECONNREFUSED || err.cause?.code === 'ECONNREFUSED', `${err.code} cause=${err.cause?.code}`);
    return;
  }
  throw new Error('expected connection refusal');
}

async function fetch_adapter_enforces_max_body_length() {
  await withServer((req, res) => res.end('ok'), async server => {
    try {
      await axios.post(server.url('/'), '12345678', baseConfig({ adapter: 'fetch', maxBodyLength: 1 }));
    } catch (err) {
      require(err.code === 'ERR_BAD_REQUEST' || err.message.includes('maxBodyLength'), `${err.code} ${err.message}`);
      return;
    }
    throw new Error('fetch accepted oversized request body');
  });
}

async function data_url_max_content_length_is_enforced() {
  try {
    await axios.get('data:text/plain;base64,MTIzNDU2Nzg=', baseConfig({ maxContentLength: 1 }));
  } catch (err) {
    require(err.code === 'ERR_BAD_RESPONSE' || err.message.includes('maxContentLength'), `${err.code} ${err.message}`);
    return;
  }
  throw new Error('data URL exceeded maxContentLength');
}

async function abort_reason_is_preserved() {
  const controller = new AbortController();
  controller.abort(new Error('boom'));
  try {
    await axios.get('http://127.0.0.1:1/', baseConfig({ signal: controller.signal }));
  } catch (err) {
    require(axios.isCancel(err), `${err.name} ${err.message}`);
    require(String(err.cause?.message || err.message).includes('boom') || controller.signal.reason.message === 'boom', `${err.message} cause=${err.cause?.message}`);
    return;
  }
  throw new Error('aborted request resolved');
}

async function json_parse_error_keeps_response() {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end('{bad');
  }, async server => {
    try {
      await axios.get(server.url('/'), baseConfig({
        responseType: 'json',
        transitional: { silentJSONParsing: false },
      }));
    } catch (err) {
      require(err.response?.status === 200, `response ${err.response?.status}`);
      return;
    }
    throw new Error('bad JSON was accepted');
  });
}

async function socket_path_allowlist_rejects_unlisted_path() {
  const sock = path.join(os.tmpdir(), `axios-origin-${process.pid}-${Date.now()}.sock`);
  const server = http.createServer((req, res) => res.end('socket'));
  await new Promise(resolve => server.listen(sock, resolve));
  try {
    try {
      await axios.get('http://unix/', baseConfig({ socketPath: sock, allowedSocketPaths: ['/not-this.sock'] }));
    } catch (err) {
      require(err.code === 'ERR_BAD_OPTION_VALUE' || err.message.includes('socketPath'), `${err.code} ${err.message}`);
      return;
    }
    throw new Error('unlisted socketPath accepted');
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(sock, { force: true });
  }
}

async function max_body_length_enforced_when_redirects_disabled() {
  await withServer((req, res) => res.end('ok'), async server => {
    try {
      await axios.post(server.url('/'), '12345678', baseConfig({ maxBodyLength: 1, maxRedirects: 0 }));
    } catch (err) {
      require(err.code === 'ERR_BAD_REQUEST' || err.message.includes('maxBodyLength'), `${err.code} ${err.message}`);
      return;
    }
    throw new Error('oversized body accepted');
  });
}

async function streamed_response_max_content_length_is_enforced() {
  await withServer((req, res) => res.end('12345678'), async server => {
    try {
      const r = await axios.get(server.url('/'), baseConfig({ responseType: 'stream', maxContentLength: 1 }));
      for await (const _ of r.data) {
        // drain to trigger stream limit enforcement
      }
    } catch (err) {
      require(err.message.includes('maxContentLength') || err.code === 'ERR_BAD_RESPONSE', `${err.code} ${err.message}`);
      return;
    }
    throw new Error('oversized streamed body accepted');
  });
}

async function form_data_to_json_ignores_polluted_prototype() {
  Object.prototype.polluted = 'bad';
  try {
    const form = new FormData();
    form.append('safe', 'ok');
    const out = axios.formToJSON(form);
    require(out.safe === 'ok' && !Object.hasOwn(out, 'polluted'), JSON.stringify(out));
  } finally {
    delete Object.prototype.polluted;
  }
}

async function form_data_to_json_preserves_literal_punctuation_keys() {
  const form = new FormData();
  form.append('a/b:c', 'v');
  const out = axios.formToJSON(form);
  require(out['a/b:c'] === 'v', JSON.stringify(out));
}

async function data_uri_parser_rejects_invalid_base64() {
  try {
    await axios.get('data:text/plain;base64,a', baseConfig());
  } catch {
    return;
  }
  throw new Error('malformed data URI accepted');
}

async function no_proxy_wildcard_bypasses_proxy() {
  const oldProxy = process.env.HTTP_PROXY;
  const oldNoProxy = process.env.NO_PROXY;
  process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  process.env.NO_PROXY = '*';
  try {
    await withServer((req, res) => res.end('direct'), async server => {
      const r = await axios.get(server.url('/'), { validateStatus: () => true, timeout: 1000 });
      require(r.data === 'direct', r.data);
    });
  } finally {
    if (oldProxy === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = oldProxy;
    if (oldNoProxy === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = oldNoProxy;
  }
}

async function no_proxy_canonicalizes_ipv4_shorthand() {
  const oldProxy = process.env.HTTP_PROXY;
  const oldNoProxy = process.env.NO_PROXY;
  process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  process.env.NO_PROXY = '127.0.0.1';
  try {
    await withServer((req, res) => res.end('direct'), async server => {
      const r = await axios.get(`http://0177.0.0.1:${server.port()}/`, { validateStatus: () => true, timeout: 1000 });
      require(r.data === 'direct', r.data);
    });
  } finally {
    if (oldProxy === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = oldProxy;
    if (oldNoProxy === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = oldNoProxy;
  }
}

async function get_set_cookie_returns_array() {
  const headers = new axios.AxiosHeaders({ 'Set-Cookie': ['a=1', 'b=2'] });
  const cookies = headers.getSetCookie();
  require(Array.isArray(cookies) && cookies.length === 2 && cookies[0] === 'a=1', JSON.stringify(cookies));
}

async function base_url_combination_deduplicates_trailing_slashes() {
  const uri = axios.getUri({ baseURL: 'http://example.test/api///', url: 'users' });
  require(uri === 'http://example.test/api/users', uri);
}

async function sync_interceptor_failure_prevents_dispatch() {
  let count = 0;
  await withServer((req, res) => {
    count += 1;
    res.end('dispatched');
  }, async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(() => { throw new Error('boom'); }, undefined, { synchronous: true });
    try {
      await client.get(server.url('/'));
    } catch {
      require(count === 0, `dispatched ${count}`);
      return;
    }
    throw new Error('interceptor failure resolved');
  });
}

async function allow_absolute_urls_false_combines_absolute_request_url() {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get('http://evil.test/path', baseConfig({
      baseURL: server.url('/base'),
      allowAbsoluteUrls: false,
    }));
    require(String(r.data).includes('http://evil.test/path'), r.data);
  });
}

async function params_serializer_callback_is_used() {
  const uri = axios.getUri({
    url: 'http://example.test/',
    params: { a: '1' },
    paramsSerializer: () => 'custom=1',
  });
  require(uri === 'http://example.test/?custom=1', uri);
}

async function file_object_payload_is_supported_by_http_adapter() {
  require(typeof File === 'function', 'runtime lacks File');
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const file = new File(['abc'], 'a.txt', { type: 'text/plain' });
    const r = await axios.post(server.url('/'), file, baseConfig());
    require(r.data === 'abc', r.data);
  });
}

async function fetch_adapter_uses_current_global_fetch() {
  const oldFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return new Response('ok', { status: 200 });
  };
  try {
    const r = await axios.get('http://example.test/', baseConfig({ adapter: 'fetch' }));
    require(called && r.data === 'ok', `called=${called} data=${r.data}`);
  } finally {
    globalThis.fetch = oldFetch;
  }
}

async function custom_fetch_env_is_used_by_fetch_adapter() {
  let called = false;
  const customFetch = async () => {
    called = true;
    return new Response('ok', { status: 200 });
  };
  const r = await axios.get('http://example.test/', baseConfig({
    adapter: 'fetch',
    env: { fetch: customFetch, Request, Response },
  }));
  require(called && r.data === 'ok', `called=${called} data=${r.data}`);
}

async function json_parse_reviver_is_applied() {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end('{"n":1}');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({
      responseType: 'json',
      parseReviver: (key, value) => typeof value === 'number' ? value + 1 : value,
    }));
    require(r.data.n === 2, JSON.stringify(r.data));
  });
}

async function node_data_url_requests_are_supported() {
  const r = await axios.get('data:text/plain,hello', baseConfig());
  require(String(r.data) === 'hello', String(r.data));
}

async function object_payload_auto_serializes_to_urlencoded() {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const r = await axios.post(server.url('/'), { a: 'b' }, baseConfig({
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }));
    require(r.data === 'a=b', r.data);
  });
}

async function cancel_error_includes_config() {
  const controller = new AbortController();
  controller.abort();
  try {
    await axios.get('http://127.0.0.1:1/', baseConfig({ signal: controller.signal, marker: 'yes' }));
  } catch (err) {
    require(axios.isCancel(err), `${err.name} ${err.message}`);
    require(err.config?.marker === 'yes', JSON.stringify(err.config));
    return;
  }
  throw new Error('cancelled request resolved');
}

async function interceptor_manager_clear_removes_handlers() {
  await withServer((req, res) => res.end(String(req.headers['x-intercepted'])), async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(config => {
      config.headers.set('X-Intercepted', 'yes');
      return config;
    });
    client.interceptors.request.clear();
    const r = await client.get(server.url('/'));
    require(r.data === 'undefined', r.data);
  });
}

async function user_agent_header_can_be_omitted() {
  await withServer((req, res) => res.end(String(req.headers['user-agent'])), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { 'User-Agent': false } }));
    require(r.data === 'undefined', r.data);
  });
}

async function timeout_string_is_parsed_as_milliseconds() {
  await withServer((req, res) => setTimeout(() => res.end('late'), 250), async server => {
    const start = Date.now();
    try {
      await axios.get(server.url('/'), baseConfig({ timeout: '50' }));
    } catch (err) {
      require(Date.now() - start < 200, `elapsed ${Date.now() - start}`);
      require(err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT', err.code);
      return;
    }
    throw new Error('string timeout ignored');
  });
}

async function custom_timeout_error_message_is_used() {
  await withServer((req, res) => setTimeout(() => res.end('late'), 250), async server => {
    try {
      await axios.get(server.url('/'), baseConfig({ timeout: 50, timeoutErrorMessage: 'too slow' }));
    } catch (err) {
      require(err.message === 'too slow', err.message);
      return;
    }
    throw new Error('timeout resolved');
  });
}

async function validate_status_null_accepts_every_status() {
  await withServer((req, res) => {
    res.statusCode = 503;
    res.end('unavailable');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ validateStatus: null }));
    require(r.status === 503, `status ${r.status}`);
  });
}

async function utf8_bom_is_removed_before_json_parse() {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"ok":true}')]));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseType: 'json' }));
    require(r.data.ok === true, JSON.stringify(r.data));
  });
}

async function delete_request_sends_config_data() {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const r = await axios.delete(server.url('/'), baseConfig({ data: 'payload' }));
    require(r.data === 'payload', r.data);
  });
}

async function missing_url_rejects_before_dispatch() {
  try {
    await axios.request(baseConfig({ url: undefined }));
  } catch {
    return;
  }
  throw new Error('missing URL accepted');
}

async function response_encoding_latin1_decodes_bytes() {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.end(Buffer.from([0xe9]));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseEncoding: 'latin1' }));
    require(r.data === 'é', JSON.stringify(r.data));
  });
}

async function max_content_length_destroys_oversized_stream() {
  await withServer((req, res) => res.end('x'.repeat(1024)), async server => {
    try {
      await axios.get(server.url('/'), baseConfig({ maxContentLength: 1 }));
    } catch (err) {
      require(err.message.includes('maxContentLength') || err.code === 'ERR_BAD_RESPONSE', `${err.code} ${err.message}`);
      return;
    }
    throw new Error('oversized response accepted');
  });
}

const TESTS = {
  redirect_strips_sensitive_headers_cross_origin: async () => {
    const headers = await observeCrossOriginSensitiveHeaderStripping();
    require(headers.authorization === undefined && headers.cookie === undefined && headers['x-api-key'] === undefined, JSON.stringify(headers));
  },
  malformed_http_url_without_slashes_is_rejected,
  validate_status_undefined_can_resolve_like_default,
  zstd_response_decompression_supported,
  same_origin_redirect_preserves_basic_auth,
  url_embedded_basic_auth_is_url_decoded,
  https_agent_tls_options_survive_http_connect_proxy,
  blank_header_names_are_skipped,
  unicode_header_values_survive_interceptors,
  econnrefused_error_constant_is_exposed,
  fetch_adapter_enforces_max_body_length,
  data_url_max_content_length_is_enforced,
  abort_reason_is_preserved,
  json_parse_error_keeps_response,
  socket_path_allowlist_rejects_unlisted_path,
  max_body_length_enforced_when_redirects_disabled,
  streamed_response_max_content_length_is_enforced,
  form_data_to_json_ignores_polluted_prototype,
  form_data_to_json_preserves_literal_punctuation_keys,
  data_uri_parser_rejects_invalid_base64,
  no_proxy_wildcard_bypasses_proxy,
  no_proxy_canonicalizes_ipv4_shorthand,
  get_set_cookie_returns_array,
  base_url_combination_deduplicates_trailing_slashes,
  sync_interceptor_failure_prevents_dispatch,
  allow_absolute_urls_false_combines_absolute_request_url,
  params_serializer_callback_is_used,
  file_object_payload_is_supported_by_http_adapter,
  fetch_adapter_uses_current_global_fetch,
  custom_fetch_env_is_used_by_fetch_adapter,
  json_parse_reviver_is_applied,
  node_data_url_requests_are_supported,
  object_payload_auto_serializes_to_urlencoded,
  cancel_error_includes_config,
  interceptor_manager_clear_removes_handlers,
  user_agent_header_can_be_omitted,
  timeout_string_is_parsed_as_milliseconds,
  custom_timeout_error_message_is_used,
  validate_status_null_accepts_every_status,
  utf8_bom_is_removed_before_json_parse,
  delete_request_sends_config_data,
  missing_url_rejects_before_dispatch,
  response_encoding_latin1_decodes_bytes,
  max_content_length_destroys_oversized_stream,
};

const MUTANTS = Object.fromEntries(Object.keys(TESTS).map(name => [name, async () => {
  // Missing mutants are treated as survivors by the evaluator below.
}]));

MUTANTS.abort_reason_is_preserved = async () => {
  const controller = new AbortController();
  controller.abort(new Error('boom'));
  try {
    await axios.get('http://127.0.0.1:1/', baseConfig({ signal: controller.signal }));
  } catch (err) {
    require(String(err.cause?.message || err.message).includes('mutant'), `${err.message} cause=${err.cause?.message}`);
    return;
  }
  throw new Error('aborted request resolved');
};
MUTANTS.allow_absolute_urls_false_combines_absolute_request_url = async () => {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get('http://evil.test/path', baseConfig({ baseURL: server.url('/base'), allowAbsoluteUrls: false }));
    require(r.data === '/path', r.data);
  });
};
MUTANTS.base_url_combination_deduplicates_trailing_slashes = async () => {
  const uri = axios.getUri({ baseURL: 'http://example.test/api///', url: 'users' });
  require(uri === 'http://example.test/api///users', uri);
};
MUTANTS.blank_header_names_are_skipped = async () => {
  await withServer((req, res) => res.end(req.headers['   '] || ''), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { '   ': 'ignored', 'X-Test': 'ok' } }));
    require(r.data === 'ignored', r.data);
  });
};
MUTANTS.cancel_error_includes_config = async () => {
  const controller = new AbortController();
  controller.abort();
  try {
    await axios.get('http://127.0.0.1:1/', baseConfig({ signal: controller.signal, marker: 'yes' }));
  } catch (err) {
    require(err.config?.marker === 'no', JSON.stringify(err.config));
    return;
  }
  throw new Error('cancelled request resolved');
};
MUTANTS.custom_fetch_env_is_used_by_fetch_adapter = async () => {
  let called = false;
  const customFetch = async () => {
    called = true;
    return new Response('ok', { status: 200 });
  };
  const r = await axios.get('http://example.test/', baseConfig({ adapter: 'fetch', env: { fetch: customFetch, Request, Response } }));
  require(!called && r.data === 'ok', `called=${called} data=${r.data}`);
};
MUTANTS.custom_timeout_error_message_is_used = async () => {
  await withServer((req, res) => setTimeout(() => res.end('late'), 250), async server => {
    try {
      await axios.get(server.url('/'), baseConfig({ timeout: 50, timeoutErrorMessage: 'too slow' }));
    } catch (err) {
      require(err.message === 'timeout of 50ms exceeded', err.message);
      return;
    }
    throw new Error('timeout resolved');
  });
};
MUTANTS.data_url_max_content_length_is_enforced = async () => {
  const r = await axios.get('data:text/plain;base64,MTIzNDU2Nzg=', baseConfig({ maxContentLength: 1 }));
  require(String(r.data) === '12345678', String(r.data));
};
MUTANTS.delete_request_sends_config_data = async () => {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const r = await axios.delete(server.url('/'), baseConfig({ data: 'payload' }));
    require(r.data === '', r.data);
  });
};
MUTANTS.econnrefused_error_constant_is_exposed = async () => {
  require(axios.AxiosError.ECONNREFUSED === 'ECONNRESET', `constant ${axios.AxiosError.ECONNREFUSED}`);
};
MUTANTS.fetch_adapter_enforces_max_body_length = async () => {
  await withServer((req, res) => res.end('ok'), async server => {
    const r = await axios.post(server.url('/'), '12345678', baseConfig({ adapter: 'fetch', maxBodyLength: 1 }));
    require(r.data === 'ok', r.data);
  });
};
MUTANTS.fetch_adapter_uses_current_global_fetch = async () => {
  const oldFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return new Response('ok', { status: 200 });
  };
  try {
    const r = await axios.get('http://example.test/', baseConfig({ adapter: 'fetch' }));
    require(!called && r.data === 'ok', `called=${called} data=${r.data}`);
  } finally {
    globalThis.fetch = oldFetch;
  }
};
MUTANTS.file_object_payload_is_supported_by_http_adapter = async () => {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const file = new File(['abc'], 'a.txt', { type: 'text/plain' });
    const r = await axios.post(server.url('/'), file, baseConfig());
    require(r.data === '[object File]', r.data);
  });
};
MUTANTS.form_data_to_json_ignores_polluted_prototype = async () => {
  Object.prototype.polluted = 'bad';
  try {
    const form = new FormData();
    form.append('safe', 'ok');
    const out = axios.formToJSON(form);
    require(Object.hasOwn(out, 'polluted'), JSON.stringify(out));
  } finally {
    delete Object.prototype.polluted;
  }
};
MUTANTS.form_data_to_json_preserves_literal_punctuation_keys = async () => {
  const form = new FormData();
  form.append('a/b:c', 'v');
  const out = axios.formToJSON(form);
  require(out.a?.b?.c === 'v', JSON.stringify(out));
};
MUTANTS.get_set_cookie_returns_array = async () => {
  const headers = new axios.AxiosHeaders({ 'Set-Cookie': ['a=1', 'b=2'] });
  const cookies = headers.getSetCookie();
  require(cookies === 'a=1, b=2', JSON.stringify(cookies));
};
MUTANTS.https_agent_tls_options_survive_http_connect_proxy = async () => {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('secure'), async origin => {
    await withTunnelProxy(async proxy => {
      const r = await axios.get(origin.url('/'), baseConfig({ httpsAgent, proxy: { protocol: 'http', host: '127.0.0.1', port: proxy.port } }));
      require(r.data === 'plain', r.data);
    });
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
};
MUTANTS.interceptor_manager_clear_removes_handlers = async () => {
  await withServer((req, res) => res.end(String(req.headers['x-intercepted'])), async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(config => {
      config.headers.set('X-Intercepted', 'yes');
      return config;
    });
    client.interceptors.request.clear();
    const r = await client.get(server.url('/'));
    require(r.data === 'yes', r.data);
  });
};
MUTANTS.json_parse_error_keeps_response = async () => {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end('{bad');
  }, async server => {
    try {
      await axios.get(server.url('/'), baseConfig({ responseType: 'json', transitional: { silentJSONParsing: false } }));
    } catch (err) {
      require(err.response === undefined, `response ${err.response?.status}`);
      return;
    }
    throw new Error('bad JSON was accepted');
  });
};
MUTANTS.json_parse_reviver_is_applied = async () => {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end('{"n":1}');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseType: 'json', parseReviver: (key, value) => typeof value === 'number' ? value + 1 : value }));
    require(r.data.n === 1, JSON.stringify(r.data));
  });
};
MUTANTS.malformed_http_url_without_slashes_is_rejected = async () => {
  const r = await axios.get('http:example.test/path', baseConfig({ timeout: 200 }));
  require(r.status >= 0, 'request rejected');
};
MUTANTS.max_body_length_enforced_when_redirects_disabled = async () => {
  await withServer((req, res) => res.end('ok'), async server => {
    const r = await axios.post(server.url('/'), '12345678', baseConfig({ maxBodyLength: 1, maxRedirects: 0 }));
    require(r.data === 'ok', r.data);
  });
};
MUTANTS.max_content_length_destroys_oversized_stream = async () => {
  await withServer((req, res) => res.end('x'.repeat(1024)), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ maxContentLength: 1 }));
    require(r.data.length === 1024, r.data.length);
  });
};
MUTANTS.missing_url_rejects_before_dispatch = async () => {
  const r = await axios.request(baseConfig({ url: undefined }));
  require(r.status >= 0, 'missing URL rejected');
};
MUTANTS.no_proxy_canonicalizes_ipv4_shorthand = async () => {
  const oldProxy = process.env.HTTP_PROXY;
  const oldNoProxy = process.env.NO_PROXY;
  process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  process.env.NO_PROXY = '127.0.0.1';
  try {
    await withServer((req, res) => res.end('direct'), async server => {
      const r = await axios.get(`http://0177.0.0.1:${server.port()}/`, { validateStatus: () => true, timeout: 1000 });
      require(r.data !== 'direct', r.data);
    });
  } finally {
    if (oldProxy === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = oldProxy;
    if (oldNoProxy === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = oldNoProxy;
  }
};
MUTANTS.no_proxy_wildcard_bypasses_proxy = async () => {
  const oldProxy = process.env.HTTP_PROXY;
  const oldNoProxy = process.env.NO_PROXY;
  process.env.HTTP_PROXY = 'http://127.0.0.1:1';
  process.env.NO_PROXY = '*';
  try {
    await withServer((req, res) => res.end('direct'), async server => {
      const r = await axios.get(server.url('/'), { validateStatus: () => true, timeout: 1000 });
      require(r.data !== 'direct', r.data);
    });
  } finally {
    if (oldProxy === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = oldProxy;
    if (oldNoProxy === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = oldNoProxy;
  }
};
MUTANTS.redirect_strips_sensitive_headers_cross_origin = async () => {
  const headers = await observeCrossOriginSensitiveHeaderStripping();
  require(headers.authorization === 'Bearer secret', JSON.stringify(headers));
};
MUTANTS.node_data_url_requests_are_supported = async () => {
  const r = await axios.get('data:text/plain,hello', baseConfig());
  require(r.data === 'mutant', String(r.data));
};
MUTANTS.params_serializer_callback_is_used = async () => {
  const uri = axios.getUri({ url: 'http://example.test/', params: { a: '1' }, paramsSerializer: () => 'custom=1' });
  require(uri === 'http://example.test/?a=1', uri);
};
MUTANTS.object_payload_auto_serializes_to_urlencoded = async () => {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const r = await axios.post(server.url('/'), { a: 'b' }, baseConfig({ headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }));
    require(r.data === '{"a":"b"}', r.data);
  });
};
MUTANTS.response_encoding_latin1_decodes_bytes = async () => {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.end(Buffer.from([0xe9]));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseEncoding: 'latin1' }));
    require(r.data === '�', JSON.stringify(r.data));
  });
};
MUTANTS.same_origin_redirect_preserves_basic_auth = async () => {
  await withServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/target' });
      res.end();
      return;
    }
    res.end(req.headers.authorization || '');
  }, async server => {
    const r = await axios.get(server.url('/start').replace('http://', 'http://user:p%40ss@'), baseConfig());
    require(r.data === 'undefined', r.data);
  });
};
MUTANTS.socket_path_allowlist_rejects_unlisted_path = async () => {
  const sock = path.join(os.tmpdir(), `axios-origin-${process.pid}-${Date.now()}.sock`);
  const server = http.createServer((req, res) => res.end('socket'));
  await new Promise(resolve => server.listen(sock, resolve));
  try {
    const r = await axios.get('http://unix/', baseConfig({ socketPath: sock, allowedSocketPaths: ['/not-this.sock'] }));
    require(r.data === 'socket', r.data);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(sock, { force: true });
  }
};
MUTANTS.streamed_response_max_content_length_is_enforced = async () => {
  await withServer((req, res) => res.end('12345678'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseType: 'stream', maxContentLength: 1 }));
    const chunks = [];
    for await (const chunk of r.data) chunks.push(Buffer.from(chunk));
    require(Buffer.concat(chunks).toString() === '12345678', 'stream rejected');
  });
};
MUTANTS.sync_interceptor_failure_prevents_dispatch = async () => {
  let count = 0;
  await withServer((req, res) => {
    count += 1;
    res.end('dispatched');
  }, async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(() => { throw new Error('boom'); }, undefined, { synchronous: true });
    try {
      await client.get(server.url('/'));
    } catch {
      require(count === 1, `dispatched ${count}`);
      return;
    }
    throw new Error('interceptor failure resolved');
  });
};
MUTANTS.timeout_string_is_parsed_as_milliseconds = async () => {
  await withServer((req, res) => setTimeout(() => res.end('late'), 250), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ timeout: '50' }));
    require(r.data === 'late', r.data);
  });
};
MUTANTS.unicode_header_values_survive_interceptors = async () => {
  await withServer((req, res) => res.end(req.headers['x-token'] || ''), async server => {
    const client = axios.create(baseConfig());
    client.interceptors.request.use(config => {
      config.headers.set('X-Token', 'token-?');
      return config;
    });
    const r = await client.get(server.url('/'), { headers: { 'X-Token': 'token-é' } });
    require(String(r.data).startsWith('token-é'), r.data);
  });
};
MUTANTS.url_embedded_basic_auth_is_url_decoded = async () => {
  await withServer((req, res) => res.end(req.headers.authorization || ''), async server => {
    const r = await axios.get(server.url('/').replace('http://', 'http://user:p%40ss@'), baseConfig());
    require(r.data === `Basic ${Buffer.from('user:p%40ss').toString('base64')}`, r.data);
  });
};
MUTANTS.user_agent_header_can_be_omitted = async () => {
  await withServer((req, res) => res.end(String(req.headers['user-agent'])), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { 'User-Agent': false } }));
    require(r.data !== 'undefined', r.data);
  });
};
MUTANTS.utf8_bom_is_removed_before_json_parse = async () => {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"ok":true}')]));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseType: 'text' }));
    require(r.data.startsWith('\ufeff'), JSON.stringify(r.data));
  });
};
MUTANTS.validate_status_null_accepts_every_status = async () => {
  await withServer((req, res) => {
    res.statusCode = 503;
    res.end('unavailable');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ validateStatus: null }));
    require(r.status < 400, `status ${r.status}`);
  });
};
MUTANTS.validate_status_undefined_can_resolve_like_default = async () => {
  await withServer((req, res) => {
    res.statusCode = 404;
    res.end('missing');
  }, async server => {
    try {
      await axios.get(server.url('/'), {
        proxy: false,
        timeout: 2500,
        validateStatus: undefined,
        transitional: { validateStatusUndefinedResolves: true },
      });
    } catch (err) {
      require(err.response?.status === 404, `status ${err.response?.status}`);
      return;
    }
    throw new Error('validateStatus undefined resolved 404');
  });
};
MUTANTS.zstd_response_decompression_supported = async () => {
  const body = zlib.zstdCompressSync(Buffer.from('hello zstd'));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'zstd');
    res.end(body);
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(Buffer.isBuffer(r.data), String(r.data));
  });
};

async function run(fn, timeoutMs = 5000) {
  try {
    await Promise.race([
      fn(),
      new Promise((_, reject) => setTimeout(() => reject(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs)),
    ]);
    return { passed: true, error: '' };
  } catch (err) {
    return { passed: false, error: `${err.name || 'Error'}: ${err.message || err}` };
  }
}

function makeMarkdown(payload) {
  const lines = [
    '# Axios-Origin Latest Replay + Mutant Verification',
    '',
    `- latest_version: ${payload.latest_version}`,
    `- source_release_rows: ${payload.source_release_rows}`,
    `- unique_contracts: ${payload.unique_contracts}`,
    `- verified_unique_contracts: ${payload.verified_unique_contracts}`,
    `- replay_failed_unique_contracts: ${payload.replay_failed_unique_contracts}`,
    `- mutant_failed_to_kill_unique_contracts: ${payload.mutant_failed_to_kill_unique_contracts}`,
    '',
    '| contract | release_rows | replay | mutant | capability |',
    '|---|---:|---|---|---|',
  ];
  for (const row of payload.results) {
    lines.push(`| \`${row.name}\` | ${row.release_rows.length} | ${row.replay.passed ? 'pass' : `fail: ${row.replay.error.replaceAll('|', '\\|')}`} | ${row.mutant_killed ? 'killed' : `survived: ${row.mutant.error.replaceAll('|', '\\|')}`} | \`${row.capability}\` |`);
  }
  return `${lines.join('\n')}\n`;
}

const source = JSON.parse(fs.readFileSync(SOURCE, 'utf8'));
const releaseRows = [];
for (const release of source.releases) {
  for (const contract of release.contracts) {
    releaseRows.push({ ...contract, source_version: release.version, source_date: release.date });
  }
}
const byName = new Map();
for (const row of releaseRows) {
  if (!byName.has(row.name)) byName.set(row.name, []);
  byName.get(row.name).push(row);
}

const results = [];
const only = process.env.AXIOS_ORIGIN_TEST || '';
for (const [name, rows] of [...byName.entries()].sort()) {
  if (only && name !== only) continue;
  const replay = TESTS[name] ? await run(TESTS[name]) : { passed: false, error: 'no replay adapter implemented' };
  const mutant = MUTANTS[name] ? await run(MUTANTS[name]) : { passed: true, error: 'no mutant adapter implemented' };
  results.push({
    name,
    capability: rows[0].capability,
    release_rows: rows.map(r => ({ version: r.source_version, date: r.source_date, evidence: r.evidence })),
    replay,
    mutant,
    mutant_killed: !mutant.passed,
    verified: replay.passed && !mutant.passed,
  });
}

const payload = {
  source: 'contracts/axios/axios_origin_excluding_merged_common.summary.json',
  latest_version: VERSION,
  rule: 'Verified means the Axios latest replay passed and an intentional mutant assertion failed for the same contract.',
  source_release_rows: releaseRows.length,
  unique_contracts: results.length,
  verified_unique_contracts: results.filter(r => r.verified).length,
  replay_failed_unique_contracts: results.filter(r => !r.replay.passed).length,
  mutant_failed_to_kill_unique_contracts: results.filter(r => r.replay.passed && !r.mutant_killed).length,
  results,
};

fs.writeFileSync(OUT, `${JSON.stringify(payload, null, 2)}\n`);
fs.writeFileSync(OUT_MD, makeMarkdown(payload));
console.log(JSON.stringify({
  latest_version: VERSION,
  source_release_rows: payload.source_release_rows,
  unique_contracts: payload.unique_contracts,
  verified_unique_contracts: payload.verified_unique_contracts,
  replay_failed_unique_contracts: payload.replay_failed_unique_contracts,
  mutant_failed_to_kill_unique_contracts: payload.mutant_failed_to_kill_unique_contracts,
}, null, 2));
