import axios from 'axios';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Readable } from 'node:stream';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const SOURCE = path.join(ROOT, 'contracts/urllib3/final_survival_urllib3_2.7.0.json');
const OUT_DIR = path.join(ROOT, 'contracts/axios');
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
  };
  try {
    await fn(state);
  } finally {
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
    client.setTimeout(3000, () => client.destroy());
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
      const host = authority.slice(0, split).replace(/^\[|\]$/g, '');
      const port = Number(authority.slice(split + 1));
      const upstream = net.connect(port, host, () => {
        sockets.add(upstream);
        upstream.on('close', () => sockets.delete(upstream));
        upstream.setTimeout(3000, () => upstream.destroy());
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (rest.length) upstream.write(rest);
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on('error', () => client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'));
    });
  });
  await new Promise(resolve => server.listen(0, host, resolve));
  const urlHost = host.includes(':') ? `[${host}]` : host;
  try {
    await fn({
      requests,
      port: server.address().port,
      url: `http://${urlHost}:${server.address().port}`,
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
}

function makeTlsOptions(altNames = 'DNS:localhost,IP:127.0.0.1') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axios-survival-'));
  const cert = path.join(dir, 'cert.pem');
  const key = path.join(dir, 'key.pem');
  execFileSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-subj',
    '/CN=localhost',
    '-addext',
    `subjectAltName=${altNames}`,
    '-keyout',
    key,
    '-out',
    cert,
    '-days',
    '1',
  ], { stdio: 'ignore' });
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

function makeEncryptedClientCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'axios-survival-client-'));
  const cert = path.join(dir, 'client-cert.pem');
  const key = path.join(dir, 'client-key.pem');
  execFileSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-subj',
    '/CN=client',
    '-passout',
    'pass:secret',
    '-keyout',
    key,
    '-out',
    cert,
    '-days',
    '1',
  ], { stdio: 'ignore' });
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

function bodyText(req) {
  return req.body.toString('utf8');
}

async function connection_reuse() {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  await withServer((req, res) => {
    res.end(req.url.slice(1));
  }, async server => {
    const cfg = baseConfig({ httpAgent: agent });
    const r1 = await axios.get(server.url('/first'), cfg);
    const r2 = await axios.get(server.url('/second'), cfg);
    require(r1.data === 'first' && r2.data === 'second', 'bad bodies');
    require(server.acceptedConnections === 1, `accepted ${server.acceptedConnections}`);
  });
  agent.destroy();
}

async function query_params() {
  await withServer((req, res) => {
    res.statusCode = req.url === '/specific_method?method=GET' ? 200 : 400;
    res.end(req.url);
  }, async server => {
    const r = await axios.get(server.url('/specific_method'), baseConfig({ params: { method: 'GET' } }));
    require(r.status === 200, r.data);
  });
}

async function post_form() {
  await withServer((req, res) => {
    res.statusCode = bodyText(req) === 'method=POST' ? 200 : 400;
    res.end(bodyText(req));
  }, async server => {
    const body = new URLSearchParams({ method: 'POST' });
    const r = await axios.post(server.url('/specific_method'), body, baseConfig());
    require(r.status === 200, r.data);
  });
}

async function arbitrary_put_method() {
  await withServer((req, res) => {
    res.statusCode = req.method === 'PUT' && req.url === '/specific_method?method=PUT' ? 200 : 400;
    res.end(req.method);
  }, async server => {
    const r = await axios.put(server.url('/specific_method?method=PUT'), '', baseConfig());
    require(r.status === 200, r.data);
  });
}

async function multipart_file_upload() {
  await withServer((req, res) => {
    const text = bodyText(req);
    const ok = text.includes('filename="lolcat.txt"') && text.includes("I'm in ur multipart form-data, hazing a cheezburgr");
    res.statusCode = ok ? 200 : 400;
    res.end(text);
  }, async server => {
    const form = new FormData();
    form.append('filefield', new Blob(["I'm in ur multipart form-data, hazing a cheezburgr"]), 'lolcat.txt');
    const r = await axios.post(server.url('/upload'), form, baseConfig());
    require(r.status === 200, r.data);
  });
}

async function redirect_observable_without_following() {
  await withServer((req, res) => {
    res.writeHead(303, { Location: '/' });
    res.end();
  }, async server => {
    const r = await axios.get(server.url('/redirect'), baseConfig({ maxRedirects: 0 }));
    require(r.status === 303, `status ${r.status}`);
  });
}

async function redirect_followed_by_default() {
  await withServer((req, res) => {
    if (req.url.startsWith('/redirect')) {
      res.writeHead(303, { Location: '/' });
      res.end();
    } else {
      res.end('Dummy server!');
    }
  }, async server => {
    const r = await axios.get(server.url('/redirect'), baseConfig());
    require(r.data === 'Dummy server!', r.data);
  });
}

async function redirect_consumes_retry_budget() {
  await withServer((req, res) => {
    res.writeHead(303, { Location: '/' });
    res.end();
  }, async server => {
    try {
      await axios.get(server.url('/redirect'), baseConfig({ maxRedirects: 0, validateStatus: status => status < 300 }));
    } catch (err) {
      require(err.response?.status === 303, 'expected redirect status failure');
      return;
    }
    throw new Error('expected redirect budget failure');
  });
}

async function read_timeout_error() {
  await withServer((req, res) => {
    setTimeout(() => res.end(''), 250);
  }, async server => {
    try {
      await axios.get(server.url('/sleep'), baseConfig({ timeout: 100 }));
    } catch (err) {
      require(err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT', `code ${err.code}`);
      return;
    }
    throw new Error('expected timeout');
  });
}

async function reused_connection_uses_new_socket_timeout() {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  await withServer((req, res) => {
    if (req.url === '/slow') setTimeout(() => res.end('/slow'), 250);
    else res.end(req.url);
  }, async server => {
    const fast = await axios.get(server.url('/fast'), baseConfig({ httpAgent: agent, timeout: 1000 }));
    require(fast.data === '/fast', fast.data);
    try {
      await axios.get(server.url('/slow'), baseConfig({ httpAgent: agent, timeout: 50 }));
    } catch (err) {
      require(err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT', `code ${err.code}`);
      return;
    }
    throw new Error('expected reused connection to use new timeout');
  });
  agent.destroy();
}

async function broken_connection_retried() {
  let attempts = 0;
  await withServer((req, res) => {
    attempts += 1;
    if (attempts === 1) {
      req.socket.destroy();
    } else {
      res.end('recovered');
    }
  }, async server => {
    try {
      await axios.get(server.url('/flaky'), baseConfig());
    } catch {
      // Axios does not retry this by default.
    }
    require(attempts === 1, `unexpected retry attempts ${attempts}`);
    throw new Error('no retry after broken connection');
  });
}

async function https_basic() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('secure'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'secure', r.data);
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
}

async function tls_minimum_and_maximum_versions_configure_context() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
  await withServer((req, res) => res.end('tls12'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'tls12', r.data);
  }, { https: true, tlsOptions: { ...makeTlsOptions(), minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' } });
  httpsAgent.destroy();
}

async function certificate_ip_subject_alt_name_is_accepted() {
  const tlsOptions = makeTlsOptions();
  const httpsAgent = new https.Agent({ ca: tlsOptions.cert, rejectUnauthorized: true });
  await withServer((req, res) => res.end('ip-san'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'ip-san', r.data);
  }, { https: true, tlsOptions });
  httpsAgent.destroy();
}

async function ipv6_braces_are_stripped_for_certificate_matching() {
  const tlsOptions = makeTlsOptions('IP:::1');
  const httpsAgent = new https.Agent({ ca: tlsOptions.cert, rejectUnauthorized: true });
  await withServer((req, res) => res.end('ipv6 cert'), async server => {
    const r = await axios.get(server.url('/ipv6-cert'), baseConfig({ httpsAgent }));
    require(r.data === 'ipv6 cert', r.data);
  }, { https: true, tlsOptions, host: '::1' });
  httpsAgent.destroy();
}

async function hostname_verification_can_be_disabled() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('hostname-disabled'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'hostname-disabled', r.data);
  }, { https: true, tlsOptions: makeTlsOptions('DNS:wrong.test') });
  httpsAgent.destroy();
}

async function fingerprint_verification_is_supported() {
  const tlsOptions = makeTlsOptions('DNS:wrong.test');
  const expected = new crypto.X509Certificate(tlsOptions.cert).fingerprint256;
  const httpsAgent = new https.Agent({
    ca: tlsOptions.cert,
    rejectUnauthorized: true,
    checkServerIdentity: (host, cert) => {
      if (cert.fingerprint256 !== expected) return new Error(`fingerprint ${cert.fingerprint256}`);
      return undefined;
    },
  });
  await withServer((req, res) => res.end('fingerprint'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'fingerprint', r.data);
  }, { https: true, tlsOptions });
  httpsAgent.destroy();
}

async function custom_cipher_suite_is_applied() {
  const openSslCipher = 'ECDHE-RSA-AES128-GCM-SHA256';
  const tlsOptions = {
    ...makeTlsOptions(),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: openSslCipher,
    honorCipherOrder: true,
  };
  const httpsAgent = new https.Agent({
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: openSslCipher,
  });
  await withServer((req, res) => {
    const selected = req.socket.getCipher();
    res.end(selected.standardName || selected.name || '');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(
      r.data === 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' || r.data === openSslCipher,
      `cipher ${r.data}`,
    );
  }, { https: true, tlsOptions });
  httpsAgent.destroy();
}

async function tls_sni_hostname_can_be_overridden() {
  const baseTlsOptions = makeTlsOptions('DNS:override.test');
  const seen = [];
  const tlsOptions = {
    ...baseTlsOptions,
    SNICallback: (servername, cb) => {
      seen.push(servername);
      cb(null, tls.createSecureContext(baseTlsOptions));
    },
  };
  const httpsAgent = new https.Agent({ rejectUnauthorized: false, servername: 'override.test' });
  await withServer((req, res) => res.end('sni'), async server => {
    const r = await axios.get(server.url('/sni'), baseConfig({ httpsAgent }));
    require(r.data === 'sni', r.data);
    require(JSON.stringify(seen) === JSON.stringify(['override.test']), JSON.stringify(seen));
  }, { https: true, tlsOptions });
  httpsAgent.destroy();
}

async function encrypted_client_key_without_password_raises_ssl_error() {
  const clientCert = makeEncryptedClientCert();
  const tlsOptions = makeTlsOptions();
  await withServer((req, res) => res.end('should not load key'), async server => {
    try {
      const httpsAgent = new https.Agent({
        rejectUnauthorized: false,
        cert: clientCert.cert,
        key: clientCert.key,
      });
      await axios.get(server.url('/client-cert'), baseConfig({ httpsAgent }));
    } catch {
      return;
    }
    throw new Error('encrypted key without password was accepted');
  }, { https: true, tlsOptions });
}

async function tls_alpn_http11_identifier_is_sent() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end(String(req.socket.alpnProtocol || '')), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ httpsAgent }));
    require(r.data === 'http/1.1', String(r.data));
  }, { https: true, tlsOptions: { ...makeTlsOptions(), ALPNProtocols: ['http/1.1'] } });
  httpsAgent.destroy();
}

async function gzip_response_decoded() {
  const gz = zlib.gzipSync(Buffer.from('hello gzip'));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'gzip');
    res.end(gz);
  }, async server => {
    const r = await axios.get(server.url('/gzip'), baseConfig());
    require(r.data === 'hello gzip', String(r.data));
  });
}

async function gzip_case_insensitive() {
  const gz = zlib.gzipSync(Buffer.from('hello gzip'));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'GZip');
    res.end(gz);
  }, async server => {
    const r = await axios.get(server.url('/gzip'), baseConfig());
    require(r.data === 'hello gzip', String(r.data));
  });
}

async function multiple_content_encodings() {
  const gz = zlib.gzipSync(zlib.gzipSync(Buffer.from('double')));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'gzip, gzip');
    res.end(gz);
  }, async server => {
    const r = await axios.get(server.url('/gzip'), baseConfig());
    require(r.data === 'double', String(r.data));
  });
}

function gzipNested(body, count) {
  let out = Buffer.from(body);
  for (let i = 0; i < count; i += 1) out = zlib.gzipSync(out);
  return out;
}

async function content_encoding_chain_limit() {
  const gz = gzipNested(Buffer.from('too deep'), 6);
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'gzip, gzip, gzip, gzip, gzip, gzip');
    res.end(gz);
  }, async server => {
    try {
      await axios.get(server.url('/gzip'), baseConfig());
    } catch {
      return;
    }
    throw new Error('expected chained content-encoding limit failure');
  });
}

async function decompression_buffer_continues_after_partial_read() {
  const gz = zlib.gzipSync(Buffer.from('abcdef'));
  await withServer((req, res) => {
    res.setHeader('Content-Encoding', 'gzip');
    res.end(gz);
  }, async server => {
    const r = await axios.get(server.url('/gzip'), baseConfig({ responseType: 'stream' }));
    const decoded = await new Promise((resolve, reject) => {
      const stream = r.data;
      const chunks = [];
      stream.once('error', reject);
      stream.once('readable', () => {
        const first = stream.read(2);
        if (first === null) {
          reject(new Error('decoded stream did not expose partial read'));
          return;
        }
        chunks.push(Buffer.from(first));
        stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
        stream.once('end', () => resolve(Buffer.concat(chunks)));
        stream.resume();
      });
    });
    require(decoded.toString('utf8') === 'abcdef', decoded.toString('utf8'));
  });
}

async function url_ipv6_zone_identifier_accepted() {
  try {
    new URL('http://[fe80::1%25en0]/');
  } catch (err) {
    throw new Error(`zone identifier rejected: ${err.message}`);
  }
}

async function multiple_set_cookie_headers_preserved() {
  await withServer((req, res) => {
    res.setHeader('Set-Cookie', ['a=1', 'b=2']);
    res.end('ok');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(JSON.stringify(r.headers['set-cookie']) === JSON.stringify(['a=1', 'b=2']), JSON.stringify(r.headers));
  });
}

async function comma_header_value_preserved() {
  await withServer((req, res) => {
    res.setHeader('X-Items', 'a, b');
    res.end('ok');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(r.headers['x-items'] === 'a, b', r.headers['x-items']);
  });
}

async function incomplete_content_length_raises() {
  const server = net.createServer(socket => {
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort');
      socket.destroy();
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    try {
      await axios.get(`http://127.0.0.1:${server.address().port}/`, baseConfig());
    } catch {
      return;
    }
    throw new Error('expected incomplete body error');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function invalid_chunk_length_raises() {
  const server = net.createServer(socket => {
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nbad\r\n0\r\n\r\n');
      socket.end();
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    try {
      await axios.get(`http://127.0.0.1:${server.address().port}/`, baseConfig());
    } catch {
      return;
    }
    throw new Error('expected invalid chunk error');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function fragment_not_sent() {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get(server.url('/path?x=1#fragment'), baseConfig());
    require(r.data === '/path?x=1', r.data);
  });
}

async function request_target_is_origin_form() {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get(server.url('/path?x=1'), baseConfig());
    require(r.data === '/path?x=1', r.data);
  });
}

async function tilde_not_percent_encoded() {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get(server.url('/~user'), baseConfig());
    require(r.data === '/~user', r.data);
  });
}

async function empty_query_preserved() {
  await withServer((req, res) => res.end(req.url), async server => {
    const r = await axios.get(server.url('/path?'), baseConfig());
    require(r.data === '/path?', r.data);
  });
}

async function host_header_preserved() {
  await withServer((req, res) => res.end(req.headers.host || ''), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { Host: 'example.test' } }));
    require(r.data === 'example.test', r.data);
  });
}

async function chunked_request_sets_transfer_encoding() {
  await withServer((req, res) => res.end(req.headers['transfer-encoding'] || ''), async server => {
    const stream = Readable.from(['chunk me']);
    const r = await axios.post(server.url('/'), stream, baseConfig());
    require(String(r.data).toLowerCase() === 'chunked', r.data);
  });
}

async function chunked_keep_alive_preserves_request_boundaries() {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  await withServer((req, res) => {
    if (req.method === 'POST') res.end(bodyText(req));
    else res.end(new URL(req.url, 'http://x').pathname);
  }, async server => {
    const cfg = baseConfig({ httpAgent: agent });
    const post = await axios.post(server.url('/upload'), Readable.from([Buffer.from('chunked')]), cfg);
    const get = await axios.get(server.url('/next'), cfg);
    require(post.data === 'chunked', post.data);
    require(get.data === '/next', get.data);
    require(server.acceptedConnections === 1, `accepted ${server.acceptedConnections}`);
  });
  agent.destroy();
}

async function chunked_request_body_uses_utf8() {
  await withServer((req, res) => res.end(req.body.toString('hex')), async server => {
    const r = await axios.post(server.url('/'), Readable.from(['cafe \u00e9']), baseConfig());
    require(r.data === Buffer.from('cafe \u00e9', 'utf8').toString('hex'), r.data);
  });
}

async function chunked_boundaries_are_lowercase() {
  const server = net.createServer(socket => {
    let raw = Buffer.alloc(0);
    socket.on('data', chunk => {
      raw = Buffer.concat([raw, chunk]);
      if (raw.includes(Buffer.from('\r\n0\r\n\r\n'))) {
        const text = raw.toString('latin1');
        const ok = text.includes('\r\n1a\r\n') && !text.includes('\r\n1A\r\n');
        socket.write(`HTTP/1.1 ${ok ? 200 : 400} OK\r\nContent-Length: ${ok ? 2 : text.length}\r\nConnection: close\r\n\r\n${ok ? 'ok' : text}`);
        socket.end();
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const body = Readable.from([Buffer.alloc(26, 'x')]);
    const r = await axios.post(`http://127.0.0.1:${server.address().port}/`, body, baseConfig());
    require(r.status === 200, String(r.data));
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function explicit_transfer_encoding_not_duplicated() {
  await withServer((req, res) => {
    const raw = req.rawHeaders.filter((_, i) => i % 2 === 0).filter(h => h.toLowerCase() === 'transfer-encoding');
    res.end(String(raw.length));
  }, async server => {
    const stream = Readable.from(['chunk me']);
    const r = await axios.post(server.url('/'), stream, baseConfig({ headers: { 'Transfer-Encoding': 'chunked' } }));
    require(String(r.data) === '1', r.data);
  });
}

async function http_303_redirect_switches_method_to_get() {
  const seen = [];
  await withServer((req, res) => {
    seen.push(`${req.method} ${new URL(req.url, 'http://x').pathname} ${bodyText(req)}`);
    if (req.url === '/redirect') {
      res.writeHead(303, { Location: '/target' });
      res.end();
    } else {
      res.end(`${req.method}:${bodyText(req)}`);
    }
  }, async server => {
    const r = await axios.post(server.url('/redirect'), 'body', baseConfig());
    require(r.data === 'GET:', r.data);
    require(seen.at(-1) === 'GET /target ', JSON.stringify(seen));
  });
}

async function relative_redirect_followed() {
  await withServer((req, res) => {
    if (req.url === '/a/start') {
      res.writeHead(303, { Location: '../target' });
      res.end();
    } else {
      res.end(new URL(req.url, 'http://x').pathname);
    }
  }, async server => {
    const r = await axios.get(server.url('/a/start'), baseConfig());
    require(r.data === '/target', r.data);
  });
}

async function redirect_body_is_released_before_following() {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  await withServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/target', 'Content-Length': '1024' });
      res.end('x'.repeat(1024));
    } else {
      res.end('target');
    }
  }, async server => {
    const r = await axios.get(server.url('/start'), baseConfig({ httpAgent: agent }));
    require(r.data === 'target', r.data);
  });
  agent.destroy();
}

async function cross_host_strips_authorization() {
  await withServer((req, res) => res.end(String(req.headers.authorization)), async target => {
    await withServer((req, res) => {
      res.writeHead(303, { Location: target.url('/target') });
      res.end();
    }, async source => {
      const r = await axios.get(source.url('/start'), baseConfig({ headers: { Authorization: 'Bearer secret' } }));
      require(r.data === 'undefined', r.data);
    });
  });
}

async function cross_host_strips_cookie() {
  await withServer((req, res) => res.end(String(req.headers.cookie)), async target => {
    await withServer((req, res) => {
      res.writeHead(303, { Location: target.url('/target') });
      res.end();
    }, async source => {
      const r = await axios.get(source.url('/start'), baseConfig({ headers: { Cookie: 'a=1' } }));
      require(r.data === 'undefined', r.data);
    });
  });
}

async function cross_host_strips_proxy_authorization() {
  await withServer((req, res) => res.end(String(req.headers['proxy-authorization'])), async target => {
    await withServer((req, res) => {
      res.writeHead(303, { Location: target.url('/target') });
      res.end();
    }, async source => {
      const r = await axios.get(source.url('/start'), baseConfig({ headers: { 'Proxy-Authorization': 'Basic secret' } }));
      require(r.data === 'undefined', r.data);
    });
  });
}

async function cross_host_strips_configured_sensitive_header() {
  await withServer((req, res) => res.end(String(req.headers['x-secret'])), async target => {
    await withServer((req, res) => {
      res.writeHead(303, { Location: target.url('/target') });
      res.end();
    }, async source => {
      const r = await axios.get(source.url('/start'), baseConfig({
        headers: { 'X-Secret': 'secret' },
        beforeRedirect: options => {
          delete options.headers['X-Secret'];
          delete options.headers['x-secret'];
        },
      }));
      require(r.data === 'undefined', r.data);
    });
  });
}

async function redirect_header_input_not_mutated() {
  const headers = { Authorization: 'Bearer secret' };
  await withServer((req, res) => res.end('ok'), async target => {
    await withServer((req, res) => {
      res.writeHead(303, { Location: target.url('/target') });
      res.end();
    }, async source => {
      await axios.get(source.url('/start'), baseConfig({ headers }));
    });
  });
  require(headers.Authorization === 'Bearer secret', JSON.stringify(headers));
}

async function method_rejects_control_characters() {
  await withServer((req, res) => res.end('reached'), async server => {
    try {
      await axios({ method: 'GE\nT', url: server.url('/'), ...baseConfig() });
    } catch {
      return;
    }
    throw new Error('accepted invalid method');
  });
}

async function url_empty_host_rejected() {
  try {
    await axios.get('http:///path', baseConfig());
  } catch {
    return;
  }
  throw new Error('accepted empty host');
}

function preparedUrl(url) {
  return new URL(url);
}

async function url_scheme_and_host_lowercase() {
  const u = preparedUrl('HTTP://EXAMPLE.COM/Path');
  require(u.protocol === 'http:' && u.hostname === 'example.com', String(u));
}

async function url_default_port_equivalence() {
  const a = preparedUrl('http://example.com/');
  const b = preparedUrl('http://example.com:80/');
  require(a.hostname === b.hostname && (a.port === '' || a.port === '80') && (b.port === '' || b.port === '80'), `${a} ${b}`);
}

async function url_port_with_leading_zeroes() {
  const u = preparedUrl('http://example.com:00080/');
  require(u.port === '' || u.port === '80', String(u));
}

async function url_port_zero_preserved() {
  const u = preparedUrl('http://example.com:0/');
  require(u.port === '0', String(u));
}

async function url_port_rejects_unicode_digits() {
  try {
    preparedUrl('http://example.com:\u0661/');
  } catch {
    return;
  }
  throw new Error('accepted unicode port');
}

async function url_ipv6_requires_brackets() {
  try {
    preparedUrl('http://::1/');
  } catch {
    require(preparedUrl('http://[::1]/').hostname === '[::1]', 'bracketed rejected');
    return;
  }
  throw new Error('accepted bare ipv6');
}

async function url_invalid_chars_percent_encoded() {
  const u = preparedUrl('http://example.com/a b?x=a b#frag ment');
  require(String(u).includes('/a%20b') && String(u).includes('x=a%20b') && String(u).includes('frag%20ment'), String(u));
}

async function url_auth_invalid_chars_percent_encoded() {
  const u = preparedUrl('http://u s:p s@example.com/');
  require(String(u).includes('u%20s:p%20s@'), String(u));
}

async function url_authority_includes_userinfo_and_host() {
  const u = preparedUrl('http://user:pass@example.com:8080/path');
  require(u.username === 'user' && u.password === 'pass' && u.hostname === 'example.com' && u.port === '8080', String(u));
}

async function json_request_sets_content_type() {
  await withServer((req, res) => res.end(req.headers['content-type'] || ''), async server => {
    const r = await axios.post(server.url('/json'), { ok: true }, baseConfig());
    require(String(r.data).startsWith('application/json'), r.data);
  });
}

async function request_header_input_not_mutated() {
  const headers = { 'X-Test': 'before' };
  await withServer((req, res) => res.end('ok'), async server => {
    await axios.post(server.url('/'), { ok: true }, baseConfig({ headers }));
  });
  require(Object.keys(headers).length === 1 && headers['X-Test'] === 'before', JSON.stringify(headers));
}

async function default_headers_sent() {
  await withServer((req, res) => {
    const ok = req.headers.host && req.headers['accept-encoding'] && req.headers['user-agent'];
    res.statusCode = ok ? 200 : 400;
    res.end(JSON.stringify(req.headers));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(r.status === 200, r.data);
  });
}

async function connection_refused_error() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  try {
    await axios.get(`http://127.0.0.1:${port}/`, baseConfig({ timeout: 500 }));
  } catch {
    return;
  }
  throw new Error('expected connection error');
}

async function https_request_through_http_connect_proxy_succeeds() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('proxied secure'), async origin => {
    await withTunnelProxy(async proxy => {
      const r = await axios.get(origin.url('/proxied'), baseConfig({
        httpsAgent,
        proxy: {
          protocol: 'http',
          host: '127.0.0.1',
          port: proxy.port,
        },
      }));
      require(r.data === 'proxied secure', r.data);
      require(proxy.requests[0]?.startsWith('CONNECT 127.0.0.1:'), JSON.stringify(proxy.requests));
    });
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
}

async function proxy_connect_ipv6_target_uses_brackets() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('ipv6 proxied'), async origin => {
    await withTunnelProxy(async proxy => {
      const r = await axios.get(origin.url('/ipv6'), baseConfig({
        httpsAgent,
        proxy: {
          protocol: 'http',
          host: '127.0.0.1',
          port: proxy.port,
        },
      }));
      require(r.data === 'ipv6 proxied', r.data);
      require(proxy.requests[0]?.startsWith('CONNECT [::1]:'), JSON.stringify(proxy.requests));
    });
  }, { https: true, tlsOptions: makeTlsOptions(), host: '::1' });
  httpsAgent.destroy();
}

async function ipv6_proxy_host_is_parsed_correctly() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('ipv6 proxy host'), async origin => {
    await withTunnelProxy(async proxy => {
      const r = await axios.get(origin.url('/ipv6-proxy'), baseConfig({
        httpsAgent,
        proxy: {
          protocol: 'http',
          host: '::1',
          port: proxy.port,
        },
      }));
      require(r.data === 'ipv6 proxy host', r.data);
      require(proxy.requests[0]?.startsWith('CONNECT 127.0.0.1:'), JSON.stringify(proxy.requests));
    }, { host: '::1' });
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
}

async function trailing_dot_hostname_through_proxy_connects() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: false });
  await withServer((req, res) => res.end('trailing dot'), async origin => {
    const port = new URL(origin.url('/')).port;
    await withTunnelProxy(async proxy => {
      const r = await axios.get(`https://localhost.:${port}/trailing`, baseConfig({
        httpsAgent,
        proxy: {
          protocol: 'http',
          host: '127.0.0.1',
          port: proxy.port,
        },
      }));
      require(r.data === 'trailing dot', r.data);
      require(proxy.requests[0]?.startsWith('CONNECT localhost.:'), JSON.stringify(proxy.requests));
    });
  }, { https: true, tlsOptions: makeTlsOptions() });
  httpsAgent.destroy();
}

async function dns_failure_error() {
  try {
    await axios.get('http://nonexistent.shapingbench.invalid/', baseConfig({ timeout: 1000 }));
  } catch {
    return;
  }
  throw new Error('expected DNS error');
}

async function headers_mapping_accepted() {
  await withServer((req, res) => res.end(req.headers['x-test'] || ''), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { 'X-Test': 'ok' } }));
    require(r.data === 'ok', r.data);
  });
}

async function instance_default_headers_apply_to_get_query() {
  await withServer((req, res) => {
    const ok = req.url === '/search?q=1' && req.headers['x-default'] === 'yes';
    res.statusCode = ok ? 200 : 400;
    res.end(JSON.stringify({ url: req.url, headers: req.headers }));
  }, async server => {
    const client = axios.create(baseConfig({ headers: { 'X-Default': 'yes' } }));
    const r = await client.get(server.url('/search'), { params: { q: '1' } });
    require(r.status === 200, r.data);
  });
}

async function message_content_type_header_accepted() {
  await withServer((req, res) => {
    res.setHeader('Content-Type', 'message/http');
    res.end('ok');
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig());
    require(r.data === 'ok', r.data);
  });
}

async function duplicate_user_agent_not_added() {
  await withServer((req, res) => {
    const count = req.rawHeaders.filter((_, i) => i % 2 === 0).filter(h => h.toLowerCase() === 'user-agent').length;
    res.end(String(count));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { 'User-Agent': 'custom' } }));
    require(String(r.data) === '1', r.data);
  });
}

async function header_order_preserved() {
  await withServer((req, res) => {
    const names = req.rawHeaders.filter((_, i) => i % 2 === 0).filter(h => h === 'X-One' || h === 'X-Two');
    res.end(names.join(','));
  }, async server => {
    const r = await axios.get(server.url('/'), baseConfig({ headers: { 'X-One': '1', 'X-Two': '2' } }));
    require(r.data === 'X-One,X-Two', r.data);
  });
}

async function multipart_duplicate_fields() {
  await withServer((req, res) => res.end(String(bodyText(req).match(/name="field"/g)?.length || 0)), async server => {
    const form = new FormData();
    form.append('field', 'one');
    form.append('field', 'two');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(String(r.data) === '2', r.data);
  });
}

async function multipart_empty_filename() {
  await withServer((req, res) => res.end(String(bodyText(req).includes('filename=""'))), async server => {
    const form = new FormData();
    form.append('file', new Blob(['x']), '');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(String(r.data) === 'true', r.data);
  });
}

async function multipart_html5_filename_formatting() {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const form = new FormData();
    form.append('file', new Blob(['x']), 'cafe-\u00e9.txt');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(r.data.includes('filename="cafe-\u00e9.txt"') && !r.data.includes('filename*='), r.data);
  });
}

async function multipart_control_chars_not_percent_encoded() {
  await withServer((req, res) => res.end(bodyText(req)), async server => {
    const form = new FormData();
    form.append('file', new Blob(['x']), 'control-\x1f.txt');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(!r.data.toUpperCase().includes('%1F') && r.data.includes('filename="control-\x1f.txt"'), r.data);
  });
}

async function multipart_explicit_content_type() {
  await withServer((req, res) => res.end(String(bodyText(req).includes('Content-Type: text/plain'))), async server => {
    const form = new FormData();
    form.append('file', new Blob(['x'], { type: 'text/plain' }), 'a.txt');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(String(r.data) === 'true', r.data);
  });
}

async function multipart_plain_field_no_default_content_type() {
  await withServer((req, res) => {
    const text = bodyText(req);
    const part = text.split('name="field"', 2)[1]?.split('--', 1)[0] || '';
    res.end(String(!part.includes('Content-Type:')));
  }, async server => {
    const form = new FormData();
    form.append('field', 'value');
    const r = await axios.post(server.url('/'), form, baseConfig());
    require(String(r.data) === 'true', r.data);
  });
}

async function response_lines_streamed() {
  await withServer((req, res) => res.end('a\nb\n'), async server => {
    const r = await axios.get(server.url('/'), baseConfig({ responseType: 'stream' }));
    const chunks = [];
    for await (const chunk of r.data) chunks.push(chunk);
    require(Buffer.concat(chunks).toString('utf8').split(/\n/).filter(Boolean).join(',') === 'a,b', 'bad lines');
  });
}

async function chunked_head_no_hang() {
  await withServer((req, res) => {
    res.setHeader('Transfer-Encoding', 'chunked');
    res.end();
  }, async server => {
    const r = await axios.head(server.url('/'), baseConfig());
    require(r.status === 200, `status ${r.status}`);
  });
}

const tests = [
  ['connection_reuse', connection_reuse],
  ['query_params', query_params],
  ['post_form', post_form],
  ['arbitrary_put_method', arbitrary_put_method],
  ['multipart_file_upload', multipart_file_upload],
  ['redirect_observable_without_following', redirect_observable_without_following],
  ['redirect_followed_by_default', redirect_followed_by_default],
  ['redirect_consumes_retry_budget', redirect_consumes_retry_budget],
  ['read_timeout_error', read_timeout_error],
  ['reused_connection_uses_new_socket_timeout', reused_connection_uses_new_socket_timeout],
  ['broken_connection_retried', broken_connection_retried],
  ['https_basic', https_basic],
  ['tls_minimum_and_maximum_versions_configure_context', tls_minimum_and_maximum_versions_configure_context],
  ['certificate_ip_subject_alt_name_is_accepted', certificate_ip_subject_alt_name_is_accepted],
  ['ipv6_braces_are_stripped_for_certificate_matching', ipv6_braces_are_stripped_for_certificate_matching],
  ['hostname_verification_can_be_disabled', hostname_verification_can_be_disabled],
  ['fingerprint_verification_is_supported', fingerprint_verification_is_supported],
  ['custom_cipher_suite_is_applied', custom_cipher_suite_is_applied],
  ['tls_sni_hostname_can_be_overridden', tls_sni_hostname_can_be_overridden],
  ['encrypted_client_key_without_password_raises_ssl_error', encrypted_client_key_without_password_raises_ssl_error],
  ['tls_alpn_http11_identifier_is_sent', tls_alpn_http11_identifier_is_sent],
  ['gzip_response_decoded', gzip_response_decoded],
  ['gzip_content_encoding_case_insensitive', gzip_case_insensitive],
  ['multiple_content_encodings', multiple_content_encodings],
  ['content_encoding_chain_limit', content_encoding_chain_limit],
  ['decompression_buffer_continues_after_partial_read', decompression_buffer_continues_after_partial_read],
  ['url_ipv6_zone_identifier_accepted', url_ipv6_zone_identifier_accepted],
  ['multiple_set_cookie_headers_preserved', multiple_set_cookie_headers_preserved],
  ['comma_header_value_preserved', comma_header_value_preserved],
  ['incomplete_content_length_raises', incomplete_content_length_raises],
  ['invalid_chunk_length_raises', invalid_chunk_length_raises],
  ['fragment_not_sent_in_request_target', fragment_not_sent],
  ['request_target_is_origin_form', request_target_is_origin_form],
  ['tilde_path_not_percent_encoded', tilde_not_percent_encoded],
  ['empty_query_section_preserved', empty_query_preserved],
  ['user_supplied_host_header_preserved', host_header_preserved],
  ['chunked_request_sets_transfer_encoding', chunked_request_sets_transfer_encoding],
  ['chunked_keep_alive_preserves_request_boundaries', chunked_keep_alive_preserves_request_boundaries],
  ['chunked_request_body_uses_utf8', chunked_request_body_uses_utf8],
  ['chunked_boundaries_are_lowercase', chunked_boundaries_are_lowercase],
  ['explicit_transfer_encoding_chunked_not_duplicated', explicit_transfer_encoding_not_duplicated],
  ['http_303_redirect_switches_method_to_get', http_303_redirect_switches_method_to_get],
  ['relative_redirect_location_followed', relative_redirect_followed],
  ['redirect_body_is_released_before_following', redirect_body_is_released_before_following],
  ['cross_host_redirect_strips_authorization', cross_host_strips_authorization],
  ['cross_host_redirect_strips_cookie', cross_host_strips_cookie],
  ['cross_host_redirect_strips_proxy_authorization', cross_host_strips_proxy_authorization],
  ['cross_host_redirect_strips_configured_sensitive_header', cross_host_strips_configured_sensitive_header],
  ['redirect_header_input_not_mutated', redirect_header_input_not_mutated],
  ['method_rejects_control_characters', method_rejects_control_characters],
  ['url_empty_host_rejected', url_empty_host_rejected],
  ['url_scheme_and_host_normalized_lowercase', url_scheme_and_host_lowercase],
  ['url_default_port_equivalence', url_default_port_equivalence],
  ['url_port_with_leading_zeroes_accepted', url_port_with_leading_zeroes],
  ['url_port_zero_preserved', url_port_zero_preserved],
  ['url_port_rejects_unicode_digits', url_port_rejects_unicode_digits],
  ['url_ipv6_requires_brackets', url_ipv6_requires_brackets],
  ['url_invalid_chars_percent_encoded', url_invalid_chars_percent_encoded],
  ['url_auth_invalid_chars_percent_encoded', url_auth_invalid_chars_percent_encoded],
  ['url_authority_includes_userinfo_and_host', url_authority_includes_userinfo_and_host],
  ['json_request_sets_content_type', json_request_sets_content_type],
  ['request_header_input_not_mutated', request_header_input_not_mutated],
  ['default_headers_sent', default_headers_sent],
  ['connection_refused_error', connection_refused_error],
  ['https_request_through_http_connect_proxy_succeeds', https_request_through_http_connect_proxy_succeeds],
  ['proxy_connect_ipv6_target_uses_brackets', proxy_connect_ipv6_target_uses_brackets],
  ['ipv6_proxy_host_is_parsed_correctly', ipv6_proxy_host_is_parsed_correctly],
  ['trailing_dot_hostname_through_proxy_connects', trailing_dot_hostname_through_proxy_connects],
  ['dns_failure_error', dns_failure_error],
  ['headers_mapping_accepted', headers_mapping_accepted],
  ['instance_default_headers_apply_to_get_query', instance_default_headers_apply_to_get_query],
  ['message_content_type_header_accepted', message_content_type_header_accepted],
  ['duplicate_user_agent_not_added', duplicate_user_agent_not_added],
  ['request_header_order_preserved', header_order_preserved],
  ['multipart_duplicate_field_names_preserved', multipart_duplicate_fields],
  ['multipart_empty_filename_emitted', multipart_empty_filename],
  ['multipart_html5_filename_formatting', multipart_html5_filename_formatting],
  ['multipart_control_chars_not_percent_encoded', multipart_control_chars_not_percent_encoded],
  ['multipart_explicit_content_type_sent', multipart_explicit_content_type],
  ['multipart_plain_fields_have_no_default_content_type', multipart_plain_field_no_default_content_type],
  ['response_body_lines_streamed', response_lines_streamed],
  ['chunked_head_response_without_body_does_not_hang', chunked_head_no_hang],
];

const mapping = {
  '0.3:same_origin_sequential_requests_reuse_one_connection': 'connection_reuse',
  '1.2:same_origin_requests_reuse_one_connection': 'connection_reuse',
  '0.3:get_query_fields_are_sent_as_url_parameters': 'query_params',
  '0.3:post_form_fields_are_sent_as_request_parameters': 'post_form',
  '0.3:arbitrary_http_method_is_sent_unchanged': 'arbitrary_put_method',
  '0.3:multipart_file_post_preserves_file_name_and_size': 'multipart_file_upload',
  '0.3:redirect_can_be_observed_without_following': 'redirect_observable_without_following',
  '0.3:redirect_is_followed_by_default': 'redirect_followed_by_default',
  '0.3:redirect_consumes_retry_budget': 'redirect_consumes_retry_budget',
  '2.5.0:poolmanager_integer_retries_limits_redirects': 'redirect_consumes_retry_budget',
  '2.6.0:poolmanager_integer_retries_limits_redirects': 'redirect_consumes_retry_budget',
  '0.3:slow_response_exceeding_socket_timeout_fails': 'read_timeout_error',
  '1.1:read_timeout_is_wrapped_as_timeout_error': 'read_timeout_error',
  '1.8.3:read_timeout_is_wrapped_as_timeout_error': 'read_timeout_error',
  '1.9:read_timeout_is_wrapped_as_timeout_error': 'read_timeout_error',
  '1.10:read_timeout_is_wrapped_as_timeout_error': 'read_timeout_error',
  '2.0.0:connection_timeout_is_applied_before_reading_response': 'read_timeout_error',
  '1.26.15:reused_connection_uses_new_socket_timeout': 'reused_connection_uses_new_socket_timeout',
  '2.0.0:reused_connection_uses_new_socket_timeout': 'reused_connection_uses_new_socket_timeout',
  '0.3:broken_connection_is_retried_until_success': 'broken_connection_retried',
  '1.22:broken_connection_is_retried_until_success': 'broken_connection_retried',
  '0.3:https_origin_request_succeeds': 'https_basic',
  '2.0.0:tls_minimum_and_maximum_versions_configure_context': 'tls_minimum_and_maximum_versions_configure_context',
  '2.0.0:tls_minimum_and_maximum_versions_configure_context_2': 'tls_minimum_and_maximum_versions_configure_context',
  '1.18:certificate_ipv6_subject_alt_name_is_accepted': 'certificate_ip_subject_alt_name_is_accepted',
  '1.24.2:certificate_ipv6_subject_alt_name_is_accepted': 'certificate_ip_subject_alt_name_is_accepted',
  '1.26.7:ipv6_braces_are_stripped_for_certificate_matching': 'ipv6_braces_are_stripped_for_certificate_matching',
  '2.0.3:assert_hostname_false_skips_hostname_verification': 'hostname_verification_can_be_disabled',
  '1.9.1:only_fingerprint_verification_is_supported': 'fingerprint_verification_is_supported',
  '1.24.1:custom_ciphers_parameter_is_applied_to_tls_context': 'custom_cipher_suite_is_applied',
  '1.24:tls_sni_hostname_can_be_overridden': 'tls_sni_hostname_can_be_overridden',
  '1.25:encrypted_client_key_without_password_raises_ssl_error': 'encrypted_client_key_without_password_raises_ssl_error',
  '1.26.0:tls_alpn_http11_identifier_is_sent': 'tls_alpn_http11_identifier_is_sent',
  '1.6:streaming_decompression_is_supported': 'gzip_response_decoded',
  '1.10.1:read_chunked_handles_gzip_encoded_chunks': 'gzip_response_decoded',
  '1.13:read_chunked_handles_gzip_encoded_chunks': 'gzip_response_decoded',
  '2.1.0:read_chunked_handles_gzip_encoded_chunks': 'gzip_response_decoded',
  '1.6:content_encoding_header_is_case_insensitive': 'gzip_content_encoding_case_insensitive',
  '1.24:multiple_content_encodings_are_decoded_in_order': 'multiple_content_encodings',
  '2.6.0:content_encoding_chain_is_limited_to_five': 'content_encoding_chain_limit',
  '2.0.2:response_stream_continues_with_buffered_decompressed_data': 'decompression_buffer_continues_after_partial_read',
  '2.6.2:response_stream_continues_with_buffered_decompressed_data': 'decompression_buffer_continues_after_partial_read',
  '2.7.0:response_stream_continues_with_buffered_decompressed_data': 'decompression_buffer_continues_after_partial_read',
  '2.7.0:response_stream_continues_with_buffered_decompressed_data_2': 'decompression_buffer_continues_after_partial_read',
  '1.26.15:url_ipv6_zone_identifier_is_accepted': 'url_ipv6_zone_identifier_accepted',
  '1.10.3:multiple_set_cookie_headers_are_preserved': 'multiple_set_cookie_headers_preserved',
  '1.10.1:header_values_with_commas_are_preserved': 'comma_header_value_preserved',
  '2.0.0:incomplete_response_body_raises_when_content_length_enforced': 'incomplete_content_length_raises',
  '1.17:incomplete_response_body_raises_when_content_length_enforced': 'incomplete_content_length_raises',
  '1.11:incomplete_response_read_is_wrapped_as_protocol_error': 'incomplete_content_length_raises',
  '1.9:incomplete_response_read_is_wrapped_as_protocol_error': 'incomplete_content_length_raises',
  '2.2.1:invalid_chunk_length_raises_protocol_error': 'invalid_chunk_length_raises',
  '1.25.7:url_fragment_is_not_sent_in_request_target': 'fragment_not_sent_in_request_target',
  '1.5:proxy_request_uri_strips_scheme_and_host': 'request_target_is_origin_form',
  '1.25.6:tilde_in_url_path_is_not_percent_encoded': 'tilde_path_not_percent_encoded',
  '1.25.7:empty_query_section_is_preserved': 'empty_query_section_preserved',
  '1.19:user_supplied_host_header_is_preserved_for_chunked_upload': 'user_supplied_host_header_preserved',
  '1.15:chunked_request_sets_transfer_encoding_header': 'chunked_request_sets_transfer_encoding',
  '1.10.4:chunked_keep_alive_preserves_request_boundaries': 'chunked_keep_alive_preserves_request_boundaries',
  '2.2.3:chunked_request_body_uses_utf8': 'chunked_request_body_uses_utf8',
  '2.0.0:chunked_boundaries_are_lowercase': 'chunked_boundaries_are_lowercase',
  '1.26.6:explicit_transfer_encoding_chunked_header_is_not_duplicated': 'explicit_transfer_encoding_chunked_not_duplicated',
  '2.0.7:http_303_redirect_switches_method_to_get_and_strips_body': 'http_303_redirect_switches_method_to_get',
  '1.26.18:http_303_redirect_switches_method_to_get_and_strips_body': 'http_303_redirect_switches_method_to_get',
  '1.7:relative_redirect_location_is_followed': 'relative_redirect_location_followed',
  '1.7:relative_redirect_location_is_followed_2': 'relative_redirect_location_followed',
  '1.22:redirect_drain_releases_blocking_pool_connection': 'redirect_body_is_released_before_following',
  '1.25.9:redirect_drain_releases_blocking_pool_connection': 'redirect_body_is_released_before_following',
  '1.24.2:authorization_header_stripping_is_case_insensitive': 'cross_host_redirect_strips_authorization',
  '2.0.6:cross_host_redirect_strips_cookie_header': 'cross_host_redirect_strips_cookie',
  '1.26.17:cross_host_redirect_strips_cookie_header': 'cross_host_redirect_strips_cookie',
  '2.2.2:cross_host_redirect_strips_proxy_authorization_header': 'cross_host_redirect_strips_proxy_authorization',
  '1.26.19:cross_host_redirect_strips_proxy_authorization_header': 'cross_host_redirect_strips_proxy_authorization',
  '2.7.0:cross_host_redirect_strips_configured_sensitive_header': 'cross_host_redirect_strips_configured_sensitive_header',
  '2.0.0:remove_headers_on_redirect_does_not_mutate_input_headers': 'redirect_header_input_not_mutated',
  '1.25.9:method_rejects_control_characters': 'method_rejects_control_characters',
  '1.9:url_empty_host_is_rejected': 'url_empty_host_rejected',
  '1.17:url_scheme_and_host_are_normalized_lowercase': 'url_scheme_and_host_normalized_lowercase',
  '1.20:url_scheme_and_host_are_normalized_lowercase': 'url_scheme_and_host_normalized_lowercase',
  '1.8:same_host_accepts_default_port_equivalence': 'url_default_port_equivalence',
  '1.26.13:url_port_with_leading_zeroes_is_accepted': 'url_port_with_leading_zeroes_accepted',
  '1.26.14:url_port_zero_is_preserved': 'url_port_zero_preserved',
  '1.19:url_port_rejects_integerish_unicode': 'url_port_rejects_unicode_digits',
  '1.7:url_ipv6_requires_brackets': 'url_ipv6_requires_brackets',
  '1.25.4:url_path_query_fragment_invalid_chars_are_percent_encoded': 'url_invalid_chars_percent_encoded',
  '1.25.2:url_path_query_fragment_invalid_chars_are_percent_encoded': 'url_invalid_chars_percent_encoded',
  '1.25.4:url_auth_invalid_chars_are_percent_encoded': 'url_auth_invalid_chars_percent_encoded',
  '2.0.0:url_authority_includes_userinfo_and_host': 'url_authority_includes_userinfo_and_host',
  '2.0.0:json_request_sets_content_type_when_missing': 'json_request_sets_content_type',
  '2.2.0:headers_input_is_not_mutated_by_json_request': 'request_header_input_not_mutated',
  '2.2.1:non_proxy_headers_are_not_cast_to_headerdict': 'request_header_input_not_mutated',
  '1.6:default_headers_are_sent': 'default_headers_sent',
  '1.6:proxy_manager_adds_host_header_when_missing': 'default_headers_sent',
  '1.12:new_connection_failure_raises_new_connection_error': 'connection_refused_error',
  '1.7:https_proxy_to_https_target_is_supported': 'https_request_through_http_connect_proxy_succeeds',
  '1.11:ipv6_proxy_host_is_parsed_correctly': 'ipv6_proxy_host_is_parsed_correctly',
  '1.22:proxy_connect_ipv6_target_uses_brackets': 'proxy_connect_ipv6_target_uses_brackets',
  '2.5.0:proxy_connect_ipv6_target_uses_brackets': 'proxy_connect_ipv6_target_uses_brackets',
  '2.2.0:trailing_dot_hostname_through_proxy_connects': 'trailing_dot_hostname_through_proxy_connects',
  '2.0.0:dns_failure_raises_name_resolution_error': 'dns_failure_error',
  '1.11:http_header_dict_is_usable_as_request_headers': 'headers_mapping_accepted',
  '1.11:pool_default_headers_apply_to_get_query_requests': 'instance_default_headers_apply_to_get_query',
  '1.24:message_content_type_header_is_accepted': 'message_content_type_header_accepted',
  '1.26.1:bytes_user_agent_header_does_not_duplicate': 'duplicate_user_agent_not_added',
  '1.15:request_response_header_order_is_preserved': 'request_header_order_preserved',
  '1.3:multipart_list_of_tuples_preserves_duplicate_field_names': 'multipart_duplicate_field_names_preserved',
  '1.19:multipart_file_empty_filename_is_emitted': 'multipart_empty_filename_emitted',
  '1.25:multipart_html5_header_encoder_is_default': 'multipart_html5_filename_formatting',
  '2.0.0:multipart_header_control_characters_are_not_percent_encoded': 'multipart_control_chars_not_percent_encoded',
  '1.6:multipart_file_explicit_content_type_is_sent': 'multipart_explicit_content_type_sent',
  '1.6:multipart_plain_fields_do_not_default_to_text_plain': 'multipart_plain_fields_have_no_default_content_type',
  '1.7:response_iter_yields_body_lines_efficiently': 'response_body_lines_streamed',
  '1.25:response_iter_yields_body_lines_efficiently': 'response_body_lines_streamed',
  '1.10.4:chunked_head_response_without_body_does_not_hang': 'chunked_head_response_without_body_does_not_hang',
  '1.23:chunked_head_response_releases_connection': 'chunked_head_response_without_body_does_not_hang',
};

async function runTest(name, fn) {
  try {
    await fn();
    return { name, passed: true, error: '' };
  } catch (err) {
    return { name, passed: false, error: `${err.name}: ${err.message}` };
  }
}

function writeReports(payload) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const jsonPath = path.join(OUT_DIR, `axios_${VERSION}_survival_from_urllib3_final_aggressive.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2) + '\n');
  const lines = [
    `# Axios ${VERSION} aggressive survival from urllib3 final contracts`,
    '',
    '- rule: unmapped/absent Axios equivalents count as failed, not not_applicable',
    `- total_urllib3_final_survivors: ${payload.total_urllib3_final_survivors}`,
    `- axios_survived_aggressive: ${payload.axios_survived_aggressive}`,
    `- axios_failed_aggressive: ${payload.axios_failed_aggressive}`,
    `- adapter_tests: ${payload.adapter_tests.total} total, ${payload.adapter_tests.passed} passed, ${payload.adapter_tests.failed} failed`,
    '',
    '## Adapter Test Failures',
    '',
    '| test | error |',
    '|---|---|',
  ];
  for (const test of payload.raw_runner.tests.filter(t => !t.passed)) {
    lines.push(`| \`${test.name}\` | ${test.error.replaceAll('|', '\\|')} |`);
  }
  lines.push('', '## Survived', '', '| source | contract | capability | axios_test |', '|---:|---|---|---|');
  for (const row of payload.results.filter(r => r.axios_status === 'passed')) {
    lines.push(`| ${row.source_version} | \`${row.contract}\` | \`${row.capability}\` | \`${row.axios_test}\` |`);
  }
  lines.push('', '## Failed', '', '| source | contract | capability | status | axios_test | error |', '|---:|---|---|---|---|---|');
  for (const row of payload.results.filter(r => r.axios_status !== 'passed')) {
    let err = (row.error || '').replaceAll('|', '\\|');
    if (err.length > 160) err = `${err.slice(0, 157)}...`;
    lines.push(`| ${row.source_version} | \`${row.contract}\` | \`${row.capability}\` | \`${row.axios_status}\` | \`${row.axios_test || ''}\` | ${err} |`);
  }
  fs.writeFileSync(path.join(OUT_DIR, `axios_${VERSION}_survival_from_urllib3_final_aggressive.md`), lines.join('\n') + '\n');
}

const rawTests = [];
for (const [name, fn] of tests) rawTests.push(await runTest(name, fn));
const testByName = Object.fromEntries(rawTests.map(t => [t.name, t]));
const source = JSON.parse(fs.readFileSync(SOURCE, 'utf8'));
const survivors = source.results.filter(r => r.survived_latest);
const results = survivors.map(src => {
  const key = `${src.source_version}:${src.contract}`;
  const testName = mapping[key];
  const base = {
    key,
    source_version: src.source_version,
    contract: src.contract,
    capability: src.capability || '',
    urllib3_final_survived: true,
  };
  if (!testName) {
    return {
      ...base,
      axios_status: 'failed_absent_or_unmapped',
      axios_test: '',
      error: 'aggressive mode: no executed Axios equivalent proved this urllib3 contract survives',
    };
  }
  const test = testByName[testName];
  return {
    ...base,
    axios_status: test.passed ? 'passed' : 'failed',
    axios_test: testName,
    error: test.error,
  };
});
const passed = results.filter(r => r.axios_status === 'passed').length;
const payload = {
  source_project: 'urllib3',
  source_baseline: 'contracts/urllib3/final_survival_urllib3_2.7.0.json',
  target_project: 'axios',
  target_latest_version: VERSION,
  target_latest_source: 'https://registry.npmjs.org/axios/latest',
  mode: 'aggressive_no_not_applicable',
  rule: 'A urllib3 final survivor counts as surviving Axios only when an Axios adapter test passed. Unmapped or absent equivalents count as not surviving.',
  total_urllib3_final_survivors: results.length,
  axios_survived_aggressive: passed,
  axios_failed_aggressive: results.length - passed,
  adapter_tests: {
    total: rawTests.length,
    passed: rawTests.filter(t => t.passed).length,
    failed: rawTests.filter(t => !t.passed).length,
  },
  raw_runner: { axios_version: VERSION, tests: rawTests },
  results,
};
writeReports(payload);
console.log(JSON.stringify({
  target_latest_version: VERSION,
  total: results.length,
  survived: payload.axios_survived_aggressive,
  failed: payload.axios_failed_aggressive,
  adapter_tests: payload.adapter_tests,
}, null, 2));
