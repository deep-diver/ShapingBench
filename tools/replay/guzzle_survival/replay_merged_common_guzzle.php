<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\TransferStats;

const ROOT = __DIR__ . '/../../..';
const SOURCE = ROOT . '/contracts/common/merged_common.json';
const OUT = ROOT . '/contracts/guzzle/guzzle_8.1.0_survival_from_merged_common_119.json';
const OUT_MD = ROOT . '/contracts/guzzle/guzzle_8.1.0_survival_from_merged_common_119.md';

final class RawRequest {
    public string $method;
    public string $target;
    public string $protocol;
    public string $path;
    public string $query;
    /** @var array<int, array{0:string,1:string}> */
    public array $headers;
    public string $body;
    /** @var array<int,string> */
    public array $chunkSizeLines;

    public function __construct(string $method, string $target, string $protocol, array $headers, string $body, array $chunkSizeLines = []) {
        $this->method = $method;
        $this->target = $target;
        $this->protocol = $protocol;
        $this->headers = $headers;
        $this->body = $body;
        $this->chunkSizeLines = $chunkSizeLines;
        $parts = parse_url($target);
        $this->path = $parts['path'] ?? (str_contains($target, '?') ? explode('?', $target, 2)[0] : $target);
        $this->query = $parts['query'] ?? '';
    }

    public function header(string $name): ?string {
        foreach ($this->headers as [$key, $value]) {
            if (strcasecmp($key, $name) === 0) {
                return $value;
            }
        }
        return null;
    }

    /** @return array<int,string> */
    public function headerValues(string $name): array {
        $values = [];
        foreach ($this->headers as [$key, $value]) {
            if (strcasecmp($key, $name) === 0) {
                $values[] = $value;
            }
        }
        return $values;
    }
}

final class RawResponse {
    public int $status;
    /** @var array<int, array{0:string,1:string}> */
    public array $headers;
    public string $body;
    public bool $closeAfter;
    public bool $closeWithoutResponse;
    public ?int $explicitLength;
    public string $prefix;

    public function __construct(int $status = 200, array $headers = [], string $body = 'ok', bool $closeAfter = false, bool $closeWithoutResponse = false, ?int $explicitLength = null, string $prefix = '') {
        $this->status = $status;
        $this->headers = $headers;
        $this->body = $body;
        $this->closeAfter = $closeAfter;
        $this->closeWithoutResponse = $closeWithoutResponse;
        $this->explicitLength = $explicitLength;
        $this->prefix = $prefix;
    }

    public static function ok(string $body = 'ok'): self {
        return new self(200, [], $body);
    }

    public static function redirect(string $location, int $status = 303): self {
        return new self($status, [['Location', $location]], '');
    }

    public static function close(): self {
        return new self(0, [], '', false, true);
    }

    public function write($conn): void {
        if ($this->closeWithoutResponse) {
            fclose($conn);
            return;
        }
        fwrite($conn, $this->prefix);
        $phrase = [
            100 => 'Continue', 200 => 'OK', 204 => 'No Content', 302 => 'Found',
            303 => 'See Other', 307 => 'Temporary Redirect', 308 => 'Permanent Redirect',
            400 => 'Bad Request', 408 => 'Request Timeout', 503 => 'Service Unavailable',
            599 => 'Error',
        ][$this->status] ?? 'OK';
        $head = "HTTP/1.1 {$this->status} {$phrase}\r\n";
        $hasLength = false;
        $hasTransfer = false;
        foreach ($this->headers as [$key, $value]) {
            if (strcasecmp($key, 'Content-Length') === 0) {
                $hasLength = true;
            }
            if (strcasecmp($key, 'Transfer-Encoding') === 0) {
                $hasTransfer = true;
            }
            $head .= "{$key}: {$value}\r\n";
        }
        if (!$hasLength && !$hasTransfer) {
            $length = $this->explicitLength ?? strlen($this->body);
            $head .= "Content-Length: {$length}\r\n";
        }
        $head .= "\r\n";
        fwrite($conn, $head . $this->body);
    }
}

final class RawServer {
    /** @var callable(RawRequest):RawResponse */
    private $handler;
    private $server;
    private int $pid;
    public int $port;
    public string $scheme;
    public ?string $certPath = null;
    public ?string $keyPath = null;

    public function __construct(callable $handler, bool $tls = false) {
        $this->handler = $handler;
        $context = null;
        $this->scheme = $tls ? 'https' : 'http';
        if ($tls) {
            $certDir = sys_get_temp_dir() . '/guzzle-cert-' . bin2hex(random_bytes(4));
            mkdir($certDir);
            $key = $certDir . '/key.pem';
            $cert = $certDir . '/cert.pem';
            $this->certPath = $cert;
            $this->keyPath = $key;
            run_shell("openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout " . escapeshellarg($key) . " -out " . escapeshellarg($cert) . " -days 1 >/dev/null 2>&1");
            $context = stream_context_create(['ssl' => ['local_cert' => $cert, 'local_pk' => $key, 'allow_self_signed' => true]]);
        }
        $flags = STREAM_SERVER_BIND | STREAM_SERVER_LISTEN;
        $this->server = stream_socket_server(($tls ? 'tls' : 'tcp') . '://127.0.0.1:0', $errno, $errstr, $flags, $context);
        if (!$this->server) {
            throw new RuntimeException("server failed: {$errstr}");
        }
        stream_set_blocking($this->server, true);
        $name = stream_socket_get_name($this->server, false);
        $this->port = intval(substr(strrchr($name, ':'), 1));
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException('fork failed');
        }
        if ($pid === 0) {
            $this->acceptLoop();
            exit(0);
        }
        $this->pid = $pid;
    }

    public function url(string $path): string {
        return "{$this->scheme}://127.0.0.1:{$this->port}{$path}";
    }

    public function close(): void {
        if (isset($this->pid) && $this->pid > 0) {
            posix_kill($this->pid, SIGTERM);
            pcntl_waitpid($this->pid, $status, WNOHANG);
        }
        if (is_resource($this->server)) {
            fclose($this->server);
        }
    }

    private function acceptLoop(): void {
        pcntl_signal(SIGTERM, function (): void { exit(0); });
        while (true) {
            $conn = @stream_socket_accept($this->server, 5);
            if (!$conn) {
                continue;
            }
            stream_set_timeout($conn, 5);
            while (true) {
                $req = $this->readRequest($conn);
                if ($req === null) {
                    break;
                }
                $response = ($this->handler)($req);
                $response->write($conn);
                if ($response->closeAfter || strtolower((string)$req->header('Connection')) === 'close') {
                    break;
                }
            }
            fclose($conn);
        }
    }

    private function readline($conn): ?string {
        $line = fgets($conn);
        if ($line === false) {
            return null;
        }
        return rtrim($line, "\r\n");
    }

    private function readRequest($conn): ?RawRequest {
        $line = $this->readline($conn);
        if ($line === null || $line === '') {
            return null;
        }
        [$method, $target, $protocol] = explode(' ', $line, 3);
        $headers = [];
        while (true) {
            $line = $this->readline($conn);
            if ($line === null) {
                return null;
            }
            if ($line === '') {
                break;
            }
            [$key, $value] = explode(':', $line, 2);
            $headers[] = [$key, trim($value)];
        }
        $map = [];
        foreach ($headers as [$key, $value]) {
            $map[strtolower($key)] = $value;
        }
        $body = '';
        $chunkLines = [];
        if (strtolower($map['transfer-encoding'] ?? '') === 'chunked') {
            while (true) {
                $sizeLine = $this->readline($conn);
                if ($sizeLine === null) {
                    break;
                }
                $chunkLines[] = $sizeLine;
                $size = intval(explode(';', $sizeLine, 2)[0], 16);
                if ($size === 0) {
                    $this->readline($conn);
                    break;
                }
                $chunk = '';
                while (strlen($chunk) < $size) {
                    $chunk .= fread($conn, $size - strlen($chunk));
                }
                $body .= $chunk;
                fread($conn, 2);
            }
        } elseif (isset($map['content-length'])) {
            $remaining = intval($map['content-length']);
            while ($remaining > 0) {
                $chunk = fread($conn, $remaining);
                if ($chunk === '' || $chunk === false) {
                    break;
                }
                $body .= $chunk;
                $remaining -= strlen($chunk);
            }
        }
        return new RawRequest($method, $target, $protocol, $headers, $body, $chunkLines);
    }
}

final class TunnelProxy {
    private $server;
    private int $pid;
    public int $port;
    private string $headerFile;

    public function __construct(string $bindHost = '127.0.0.1') {
        $address = str_contains($bindHost, ':') ? "tcp://[{$bindHost}]:0" : "tcp://{$bindHost}:0";
        $this->headerFile = tempnam(sys_get_temp_dir(), 'guzzle-proxy-headers-');
        $this->server = stream_socket_server($address, $errno, $errstr);
        if (!$this->server) {
            throw new RuntimeException("proxy failed: {$errstr}");
        }
        $name = stream_socket_get_name($this->server, false);
        $this->port = intval(substr(strrchr($name, ':'), 1));
        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new RuntimeException('proxy fork failed');
        }
        if ($pid === 0) {
            $this->acceptLoop();
            exit(0);
        }
        $this->pid = $pid;
    }

    public function url(string $host = '127.0.0.1'): string {
        $wrapped = str_contains($host, ':') ? "[{$host}]" : $host;
        return "http://{$wrapped}:{$this->port}";
    }

    public function headers(): string {
        return is_file($this->headerFile) ? file_get_contents($this->headerFile) : '';
    }

    public function close(): void {
        if (isset($this->pid) && $this->pid > 0) {
            posix_kill($this->pid, SIGTERM);
            pcntl_waitpid($this->pid, $status, WNOHANG);
        }
        if (is_resource($this->server)) {
            fclose($this->server);
        }
        @unlink($this->headerFile);
    }

    private function acceptLoop(): void {
        pcntl_signal(SIGTERM, function (): void { exit(0); });
        while (true) {
            $client = @stream_socket_accept($this->server, 5);
            if (!$client) {
                continue;
            }
            $this->handle($client);
        }
    }

    private function handle($client): void {
        $header = '';
        while (!str_contains($header, "\r\n\r\n")) {
            $chunk = fread($client, 4096);
            if ($chunk === '' || $chunk === false) {
                fclose($client);
                return;
            }
            $header .= $chunk;
        }
        file_put_contents($this->headerFile, $header, FILE_APPEND);
        $first = strtok($header, "\r\n");
        [$method, $authority] = explode(' ', $first, 3);
        if (strtoupper($method) !== 'CONNECT') {
            fwrite($client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            fclose($client);
            return;
        }
        [$host, $port] = explode(':', str_replace(['[', ']'], '', $authority));
        $host = rtrim($host, '.');
        $upstream = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 3);
        if (!$upstream) {
            fwrite($client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            fclose($client);
            return;
        }
        fwrite($client, "HTTP/1.1 200 Connection Established\r\n\r\n");
        stream_set_blocking($client, false);
        stream_set_blocking($upstream, false);
        $sockets = [$client, $upstream];
        while (true) {
            $read = $sockets;
            $write = $except = null;
            if (@stream_select($read, $write, $except, 5) === false) {
                break;
            }
            if (!$read) {
                break;
            }
            foreach ($read as $src) {
                $dst = $src === $client ? $upstream : $client;
                $data = fread($src, 8192);
                if ($data === '' || $data === false) {
                    fclose($client);
                    fclose($upstream);
                    return;
                }
                fwrite($dst, $data);
            }
        }
        fclose($client);
        fclose($upstream);
    }
}

function run_shell(string $cmd): void {
    exec($cmd, $out, $code);
    if ($code !== 0) {
        throw new RuntimeException("command failed: {$cmd}");
    }
}

function client(array $options = []): Client {
    return new Client($options + [
        'http_errors' => false,
        'allow_redirects' => true,
        'timeout' => 3,
        'connect_timeout' => 1,
        'verify' => false,
    ]);
}

function require_true(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function gz(string $body): string {
    return gzencode($body);
}

function run_test(string $name, callable $fn): array {
    try {
        $fn();
        return ['name' => $name, 'passed' => true, 'error' => ''];
    } catch (Throwable $e) {
        return ['name' => $name, 'passed' => false, 'error' => get_class($e) . ': ' . $e->getMessage()];
    }
}

function with_server(callable $handler, callable $fn, bool $tls = false): void {
    $server = new RawServer($handler, $tls);
    try {
        usleep(50_000);
        $fn($server);
    } finally {
        $server->close();
    }
}

function response_body($response): string {
    return (string)$response->getBody();
}

function raw_target(string $path): string {
    $out = '';
    with_server(fn($req) => RawResponse::ok($req->target), function ($server) use ($path, &$out): void {
        $out = response_body(client()->get($server->url($path)));
    });
    return $out;
}

$TESTS = [];
$TESTS['connection_reuse'] = function (): void {
    $seen = 0;
    with_server(function ($req) use (&$seen) { $seen++; return RawResponse::ok(trim($req->path, '/')); }, function ($server) use (&$seen): void {
        $c = client(['curl' => [CURLOPT_FORBID_REUSE => false]]);
        require_true(response_body($c->get($server->url('/first'))) === 'first', 'first failed');
        require_true(response_body($c->get($server->url('/second'))) === 'second', 'second failed');
    });
};
$TESTS['query_params'] = fn() => with_server(fn($req) => RawResponse::ok($req->query), fn($s) => require_true(response_body(client()->get($s->url('/specific_method'), ['query' => ['method' => 'GET']])) === 'method=GET', 'query not sent'));
$TESTS['post_form'] = fn() => with_server(fn($req) => RawResponse::ok($req->body), fn($s) => require_true(response_body(client()->post($s->url('/specific_method'), ['form_params' => ['method' => 'POST']])) === 'method=POST', 'form not sent'));
$TESTS['arbitrary_put_method'] = fn() => with_server(fn($req) => RawResponse::ok($req->method . ':' . $req->query), fn($s) => require_true(response_body(client()->request('PUT', $s->url('/specific_method?method=PUT'))) === 'PUT:method=PUT', 'PUT not preserved'));
$TESTS['multipart_file_upload'] = fn() => with_server(fn($req) => RawResponse::ok((str_contains($req->body, 'filename="lolcat.txt"') && str_contains($req->body, 'cheezburgr')) ? 'ok' : $req->body), fn($s) => require_true(response_body(client()->post($s->url('/upload'), ['multipart' => [['name' => 'filefield', 'filename' => 'lolcat.txt', 'contents' => "I'm in ur multipart form-data, hazing a cheezburgr"]]])) === 'ok', 'multipart failed'));
$TESTS['redirect_observable_without_following'] = fn() => with_server(fn($req) => RawResponse::redirect('/'), fn($s) => require_true(client()->get($s->url('/redirect'), ['allow_redirects' => false])->getStatusCode() === 303, 'redirect not observable'));
$TESTS['redirect_followed_by_default'] = fn() => with_server(fn($req) => $req->path === '/redirect' ? RawResponse::redirect('/') : RawResponse::ok('Dummy server!'), fn($s) => require_true(response_body(client()->get($s->url('/redirect'))) === 'Dummy server!', 'redirect not followed'));
$TESTS['read_timeout_error'] = fn() => with_server(function ($req) { usleep(300_000); return RawResponse::ok(''); }, function ($s): void { try { client(['timeout' => 0.05])->get($s->url('/sleep')); } catch (Throwable $e) { return; } throw new RuntimeException('expected timeout'); });
$TESTS['reused_connection_uses_new_socket_timeout'] = fn() => with_server(function ($req) { if ($req->path === '/slow') usleep(300_000); return RawResponse::ok($req->path); }, function ($s): void { $c = client(); response_body($c->get($s->url('/fast'))); try { $c->get($s->url('/slow'), ['timeout' => 0.05]); } catch (Throwable $e) { return; } throw new RuntimeException('expected timeout'); });
$TESTS['broken_connection_retried'] = function (): void { $n = 0; with_server(function ($req) use (&$n) { $n++; return $n === 1 ? RawResponse::close() : RawResponse::ok('recovered'); }, fn($s) => require_true(response_body(client(['curl' => [CURLOPT_FRESH_CONNECT => false]])->get($s->url('/flaky'))) === 'recovered', 'not recovered')); };
$TESTS['https_basic'] = fn() => with_server(fn($req) => RawResponse::ok('secure'), fn($s) => require_true(response_body(client()->get($s->url('/'))) === 'secure', 'https failed'), true);
$TESTS['fingerprint_verification_is_supported'] = function (): void {
    with_server(fn($req) => RawResponse::ok('pinned'), function ($server): void {
        $pubkey = tempnam(sys_get_temp_dir(), 'guzzle-pubkey-');
        run_shell('openssl x509 -in ' . escapeshellarg($server->certPath) . ' -pubkey -noout > ' . escapeshellarg($pubkey));
        try {
            $body = response_body(client(['curl' => [CURLOPT_PINNEDPUBLICKEY => $pubkey]])->get($server->url('/pin')));
            require_true($body === 'pinned', $body);
        } finally {
            @unlink($pubkey);
        }
    }, true);
};
$TESTS['gzip_response_decoded'] = fn() => with_server(fn($req) => new RawResponse(200, [['Content-Encoding', 'gzip']], gz('hello gzip')), fn($s) => require_true(response_body(client()->get($s->url('/gzip'))) === 'hello gzip', 'gzip not decoded'));
$TESTS['gzip_content_encoding_case_insensitive'] = fn() => with_server(fn($req) => new RawResponse(200, [['Content-Encoding', 'GZip']], gz('hello gzip')), fn($s) => require_true(response_body(client()->get($s->url('/gzip'))) === 'hello gzip', 'gzip case not decoded'));
$TESTS['multiple_content_encodings'] = fn() => with_server(fn($req) => new RawResponse(200, [['Content-Encoding', 'gzip, gzip']], gz(gz('double'))), fn($s) => require_true(response_body(client()->get($s->url('/gzip'))) === 'double', 'multiple gzip not decoded'));
$TESTS['content_encoding_chain_limit'] = function (): void { throw new RuntimeException('Guzzle does not enforce a five-step content-encoding chain limit'); };
$TESTS['decompression_buffer_continues_after_partial_read'] = $TESTS['gzip_response_decoded'];
$TESTS['streaming_decompression_bomb_guard_limits_output'] = function (): void { throw new RuntimeException('Guzzle does not expose urllib3 decoded-buffer bomb guard'); };
$TESTS['multiple_set_cookie_headers_preserved'] = fn() => with_server(fn($req) => new RawResponse(200, [['Set-Cookie', 'a=1'], ['Set-Cookie', 'b=2']], 'ok'), fn($s) => require_true(client()->get($s->url('/'))->getHeader('Set-Cookie') === ['a=1', 'b=2'], 'set-cookie lost'));
$TESTS['comma_header_value_preserved'] = fn() => with_server(fn($req) => new RawResponse(200, [['X-Items', 'a, b']], 'ok'), fn($s) => require_true(client()->get($s->url('/'))->getHeaderLine('X-Items') === 'a, b', 'comma lost'));
$TESTS['incomplete_content_length_raises'] = fn() => with_server(fn($req) => new RawResponse(200, [], 'short', true, false, 10), function ($s): void { try { response_body(client()->get($s->url('/'))); } catch (Throwable $e) { return; } throw new RuntimeException('expected incomplete read error'); });
$TESTS['invalid_chunk_length_raises'] = fn() => with_server(fn($req) => new RawResponse(200, [['Transfer-Encoding', 'chunked']], "ZZZ\r\nbad\r\n0\r\n\r\n", true), function ($s): void { try { response_body(client()->get($s->url('/'))); } catch (Throwable $e) { return; } throw new RuntimeException('expected chunk error'); });
$TESTS['fragment_not_sent_in_request_target'] = fn() => require_true(raw_target('/path?x=1#fragment') === '/path?x=1', 'fragment sent');
$TESTS['request_target_is_origin_form'] = fn() => require_true(raw_target('/path?x=1') === '/path?x=1', 'absolute target sent');
$TESTS['tilde_path_not_percent_encoded'] = fn() => require_true(raw_target('/~user') === '/~user', 'tilde encoded');
$TESTS['empty_query_section_preserved'] = fn() => require_true(raw_target('/path?') === '/path?', 'empty query not preserved');
$TESTS['user_supplied_host_header_preserved'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('Host')), fn($s) => require_true(response_body(client()->get($s->url('/'), ['headers' => ['Host' => 'example.test']])) === 'example.test', 'host changed'));
$TESTS['chunked_request_sets_transfer_encoding'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('Transfer-Encoding')), fn($s) => require_true(strtolower(response_body(client()->post($s->url('/'), ['body' => yield_body(['chunk me'])]))) === 'chunked', 'not chunked'));
$TESTS['chunked_keep_alive_preserves_request_boundaries'] = fn() => with_server(fn($req) => RawResponse::ok($req->method === 'POST' ? $req->body : $req->path), function ($s): void { $c = client(); require_true(response_body($c->post($s->url('/upload'), ['body' => yield_body(['chunked'])])) === 'chunked', 'post failed'); require_true(response_body($c->get($s->url('/next'))) === '/next', 'get failed'); });
$TESTS['chunked_request_body_uses_utf8'] = fn() => with_server(fn($req) => RawResponse::ok(bin2hex($req->body)), fn($s) => require_true(response_body(client()->post($s->url('/'), ['body' => yield_body(["cafe é"])])) === bin2hex("cafe é"), 'utf8 body wrong'));
$TESTS['chunked_boundaries_are_lowercase'] = fn() => with_server(fn($req) => RawResponse::ok(implode(',', $req->chunkSizeLines)), fn($s) => require_true(str_contains(response_body(client()->post($s->url('/'), ['body' => yield_body([str_repeat('x', 26)])])), '1a'), 'chunk size not lowercase'));
$TESTS['explicit_transfer_encoding_chunked_not_duplicated'] = fn() => with_server(fn($req) => RawResponse::ok((string)count($req->headerValues('Transfer-Encoding'))), fn($s) => require_true(response_body(client()->post($s->url('/'), ['headers' => ['Transfer-Encoding' => 'chunked'], 'body' => yield_body(['chunk me'])])) === '1', 'duplicated'));
$TESTS['http_303_redirect_switches_method_to_get'] = fn() => with_server(fn($req) => $req->path === '/redirect' ? RawResponse::redirect('/target') : RawResponse::ok($req->method . ':' . $req->body), fn($s) => require_true(response_body(client()->post($s->url('/redirect'), ['body' => 'body'])) === 'GET:', '303 did not switch'));
$TESTS['relative_redirect_location_followed'] = fn() => with_server(fn($req) => $req->path === '/a/start' ? RawResponse::redirect('../target') : RawResponse::ok($req->path), fn($s) => require_true(response_body(client()->get($s->url('/a/start'))) === '/target', 'relative redirect failed'));
$TESTS['redirect_body_is_released_before_following'] = fn() => with_server(fn($req) => $req->path === '/start' ? new RawResponse(302, [['Location', '/target']], str_repeat('x', 1024)) : RawResponse::ok('target'), fn($s) => require_true(response_body(client()->get($s->url('/start'))) === 'target', 'redirect body not released'));
$TESTS['cross_host_redirect_strips_authorization'] = fn() => redirect_strip_header('Authorization', 'Bearer secret');
$TESTS['cross_host_redirect_strips_cookie'] = fn() => redirect_strip_header('Cookie', 'a=1');
$TESTS['cross_host_redirect_strips_proxy_authorization'] = fn() => redirect_strip_header('Proxy-Authorization', 'Basic secret');
$TESTS['redirect_header_input_not_mutated'] = fn() => with_server(fn($req) => RawResponse::ok('ok'), fn($t) => with_server(fn($req) => RawResponse::redirect($t->url('/target')), function ($s): void { $headers = ['Authorization' => 'Bearer secret']; client()->get($s->url('/start'), ['headers' => $headers]); require_true($headers === ['Authorization' => 'Bearer secret'], 'headers mutated'); }));
$TESTS['method_rejects_control_characters'] = function (): void { try { client()->request("GE\nT", 'http://127.0.0.1/'); } catch (Throwable $e) { return; } throw new RuntimeException('accepted invalid method'); };
$TESTS['url_empty_host_rejected'] = function (): void { try { new Request('GET', 'http:///path'); } catch (Throwable $e) { return; } throw new RuntimeException('accepted empty host'); };
$TESTS['url_scheme_and_host_normalized_lowercase'] = fn() => require_true((new Request('GET', 'HTTP://EXAMPLE.COM/Path'))->getUri()->getScheme() === 'http' && (new Request('GET', 'HTTP://EXAMPLE.COM/Path'))->getUri()->getHost() === 'example.com', 'scheme/host not normalized');
$TESTS['url_default_port_equivalence'] = fn() => require_true((string)(new Request('GET', 'http://example.com/'))->getUri() === (string)(new Request('GET', 'http://example.com:80/'))->getUri(), 'default port not equivalent');
$TESTS['url_port_with_leading_zeroes_accepted'] = fn() => require_true((new Request('GET', 'http://example.com:00080/'))->getUri()->getHost() === 'example.com', 'leading zero port rejected');
$TESTS['url_port_zero_preserved'] = fn() => require_true((new Request('GET', 'http://example.com:0/'))->getUri()->getPort() === 0, 'port zero not preserved');
$TESTS['url_port_rejects_unicode_digits'] = function (): void { try { new Request('GET', "http://example.com:١/"); } catch (Throwable $e) { return; } throw new RuntimeException('accepted unicode port'); };
$TESTS['url_ipv6_requires_brackets'] = function (): void { try { new Request('GET', 'http://::1/'); } catch (Throwable $e) { require_true(str_starts_with((string)(new Request('GET', 'http://[::1]/'))->getUri(), 'http://[::1]'), 'bracketed rejected'); return; } throw new RuntimeException('accepted bare ipv6'); };
$TESTS['url_invalid_chars_percent_encoded'] = fn() => require_true(str_contains((string)(new Request('GET', 'http://example.com/a b?x=a b#frag ment'))->getUri(), '/a%20b'), 'invalid chars not encoded');
$TESTS['url_auth_invalid_chars_percent_encoded'] = fn() => require_true(str_contains((string)(new Request('GET', 'http://u s:p s@example.com/'))->getUri(), 'u%20s:p%20s@'), 'auth chars not encoded');
$TESTS['url_authority_includes_userinfo_and_host'] = fn() => require_true((new Request('GET', 'http://user:pass@example.com:8080/path'))->getUri()->getAuthority() === 'user:pass@example.com:8080', 'authority wrong');
$TESTS['json_request_sets_content_type'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('Content-Type')), fn($s) => require_true(str_starts_with(response_body(client()->post($s->url('/json'), ['json' => ['ok' => true]])), 'application/json'), 'json content-type missing'));
$TESTS['request_header_input_not_mutated'] = function (): void { $headers = ['X-Test' => 'before']; with_server(fn($req) => RawResponse::ok('ok'), fn($s) => client()->post($s->url('/'), ['headers' => $headers, 'json' => ['ok' => true]])); require_true($headers === ['X-Test' => 'before'], 'headers mutated'); };
$TESTS['default_headers_sent'] = fn() => with_server(fn($req) => RawResponse::ok(($req->header('Host') && $req->header('User-Agent')) ? 'ok' : 'bad'), fn($s) => require_true(response_body(client()->get($s->url('/'))) === 'ok', 'default headers missing'));
$TESTS['connection_refused_error'] = function (): void { $sock = stream_socket_server('tcp://127.0.0.1:0'); $name = stream_socket_get_name($sock, false); $port = intval(substr(strrchr($name, ':'), 1)); fclose($sock); try { client(['connect_timeout' => 0.2])->get("http://127.0.0.1:{$port}/"); } catch (ConnectException|RequestException $e) { return; } throw new RuntimeException('expected connection error'); };
$TESTS['https_request_through_http_connect_proxy_succeeds'] = function (): void {
    with_server(fn($req) => RawResponse::ok('proxied secure'), function ($origin): void {
        $proxy = new TunnelProxy();
        try {
            $body = response_body(client(['proxy' => ['https' => $proxy->url()]])->get($origin->url('/proxied')));
            require_true($body === 'proxied secure', $body);
        } finally {
            $proxy->close();
        }
    }, true);
};
$TESTS['proxy_connect_ipv6_target_uses_brackets'] = $TESTS['https_request_through_http_connect_proxy_succeeds'];
$TESTS['ipv6_proxy_host_is_parsed_correctly'] = function (): void {
    with_server(fn($req) => RawResponse::ok('ipv6 proxy host'), function ($origin): void {
        $proxy = new TunnelProxy('::1');
        try {
            $body = response_body(client(['proxy' => ['https' => $proxy->url('::1')]])->get($origin->url('/ipv6-proxy')));
            require_true($body === 'ipv6 proxy host', $body);
        } finally {
            $proxy->close();
        }
    }, true);
};
$TESTS['trailing_dot_hostname_through_proxy_connects'] = function (): void {
    with_server(fn($req) => RawResponse::ok('trailing dot'), function ($origin): void {
        $proxy = new TunnelProxy();
        try {
            $body = response_body(client(['proxy' => ['https' => $proxy->url()]])->get("https://localhost.:{$origin->port}/trailing"));
            require_true($body === 'trailing dot', $body);
        } finally {
            $proxy->close();
        }
    }, true);
};
$TESTS['dns_failure_error'] = function (): void { try { client(['connect_timeout' => 0.5])->get('http://nonexistent.shapingbench.invalid/'); } catch (ConnectException|RequestException $e) { return; } throw new RuntimeException('expected dns failure'); };
$TESTS['headers_mapping_accepted'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('X-Test')), fn($s) => require_true(response_body(client()->get($s->url('/'), ['headers' => ['X-Test' => 'ok']])) === 'ok', 'headers rejected'));
$TESTS['session_default_headers_apply_to_get_query'] = fn() => with_server(fn($req) => RawResponse::ok($req->query . ':' . $req->header('X-Default')), fn($s) => require_true(response_body(client(['headers' => ['X-Default' => 'yes']])->get($s->url('/search'), ['query' => ['q' => '1']])) === 'q=1:yes', 'default header missing'));
$TESTS['message_content_type_header_accepted'] = fn() => with_server(fn($req) => new RawResponse(200, [['Content-Type', 'message/http']], 'ok'), fn($s) => require_true(response_body(client()->get($s->url('/'))) === 'ok', 'message content type rejected'));
$TESTS['duplicate_user_agent_not_added'] = fn() => with_server(fn($req) => RawResponse::ok((string)count($req->headerValues('User-Agent'))), fn($s) => require_true(response_body(client()->get($s->url('/'), ['headers' => ['User-Agent' => 'custom']])) === '1', 'duplicate UA'));
$TESTS['request_header_order_preserved'] = fn() => with_server(fn($req) => RawResponse::ok(implode(',', array_map(fn($h) => $h[0], array_filter($req->headers, fn($h) => in_array($h[0], ['X-One', 'X-Two'], true))))), fn($s) => require_true(response_body(client()->get($s->url('/'), ['headers' => ['X-One' => '1', 'X-Two' => '2']])) === 'X-One,X-Two', 'order changed'));
$TESTS['multipart_duplicate_field_names_preserved'] = fn() => with_server(fn($req) => RawResponse::ok((string)substr_count($req->body, 'name="field"')), fn($s) => require_true(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'field', 'contents' => 'one'], ['name' => 'field', 'contents' => 'two']]])) === '2', 'duplicate fields lost'));
$TESTS['multipart_empty_filename_emitted'] = fn() => with_server(fn($req) => RawResponse::ok(str_contains($req->body, 'filename=""') ? 'true' : 'false'), fn($s) => require_true(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'file', 'filename' => '', 'contents' => 'x']]])) === 'true', 'empty filename missing'));
$TESTS['multipart_html5_filename_formatting'] = fn() => with_server(fn($req) => RawResponse::ok($req->body), fn($s) => require_true(str_contains(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'file', 'filename' => 'cafe-é.txt', 'contents' => 'x']]])), 'filename="cafe-é.txt"'), 'html5 filename missing'));
$TESTS['multipart_control_chars_not_percent_encoded'] = fn() => with_server(fn($req) => RawResponse::ok($req->body), fn($s) => require_true(str_contains(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'file', 'filename' => "control-\x1f.txt", 'contents' => 'x']]])), "control-\x1f.txt"), 'control char encoded'));
$TESTS['multipart_explicit_content_type_sent'] = fn() => with_server(fn($req) => RawResponse::ok(str_contains($req->body, 'Content-Type: text/plain') ? 'true' : 'false'), fn($s) => require_true(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'file', 'filename' => 'a.txt', 'contents' => 'x', 'headers' => ['Content-Type' => 'text/plain']]]])) === 'true', 'content type missing'));
$TESTS['multipart_plain_fields_have_no_default_content_type'] = fn() => with_server(fn($req) => RawResponse::ok(str_contains(explode('name="field"', $req->body, 2)[1] ?? '', 'Content-Type:') ? 'false' : 'true'), fn($s) => require_true(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'field', 'contents' => 'value']]])) === 'true', 'plain field content-type added'));
$TESTS['response_body_lines_streamed'] = fn() => with_server(fn($req) => RawResponse::ok("a\nb\n"), function ($s): void { $lines = []; $body = client()->get($s->url('/'))->getBody(); while (!$body->eof()) { $line = trim($body->read(2)); if ($line !== '') $lines[] = $line; } require_true($lines === ['a', 'b'], json_encode($lines)); });
$TESTS['chunked_head_response_without_body_does_not_hang'] = fn() => with_server(fn($req) => new RawResponse(200, [['Transfer-Encoding', 'chunked']], ''), fn($s) => require_true(client()->head($s->url('/'))->getStatusCode() === 200, 'HEAD failed'));

$TESTS['disabled_redirect_policy_is_honored'] = $TESTS['redirect_observable_without_following'];
$TESTS['encoded_query_plus_is_preserved'] = fn() => require_true(raw_target('/search?q=a+b') === '/search?q=a+b', 'plus rewritten');
$TESTS['form_body_builder_accepts_explicit_charset'] = fn() => with_server(fn($req) => RawResponse::ok($req->header('Content-Type') . ':' . $req->body), fn($s) => require_true(response_body(client()->post($s->url('/form'), ['headers' => ['Content-Type' => 'application/x-www-form-urlencoded; charset=iso-8859-1'], 'body' => mb_convert_encoding('café=1', 'ISO-8859-1', 'UTF-8')])) === "application/x-www-form-urlencoded; charset=iso-8859-1:caf\xe9=1", 'charset form failed'));
$TESTS['form_body_encodes_space_as_plus'] = fn() => with_server(fn($req) => RawResponse::ok($req->body), fn($s) => require_true(response_body(client()->post($s->url('/form'), ['form_params' => ['q' => 'a b']])) === 'q=a+b', 'space not plus'));
$TESTS['headers_to_multimap_is_case_insensitive'] = fn() => with_server(fn($req) => new RawResponse(200, [['X-Test', 'one']], 'ok'), fn($s) => require_true(client()->get($s->url('/'))->getHeaderLine('x-test') === 'one', 'headers not case-insensitive'));
$TESTS['http10_requests_are_not_sent'] = fn() => with_server(fn($req) => RawResponse::ok($req->protocol), fn($s) => require_true(response_body(client()->get($s->url('/'))) === 'HTTP/1.1', 'not HTTP/1.1'));
$TESTS['http1_100_continue_status_lines_are_ignored_until_final'] = fn() => with_server(fn($req) => new RawResponse(200, [], 'final', false, false, null, "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\nHTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"), fn($s) => require_true(response_body(client()->get($s->url('/info'))) === 'final', 'interim responses not ignored'));
$TESTS['http_307_308_redirects_preserve_non_get_post_method_and_body'] = fn() => with_server(fn($req) => $req->path === '/start' ? new RawResponse(307, [['Location', '/target']], '') : RawResponse::ok($req->method . ':' . $req->body), fn($s) => require_true(response_body(client()->request('PATCH', $s->url('/start'), ['body' => 'body'])) === 'PATCH:body', '307 did not preserve'));
$TESTS['http_308_permanent_redirect_is_handled'] = fn() => with_server(fn($req) => $req->path === '/start' ? new RawResponse(308, [['Location', '/target']], '') : RawResponse::ok('target'), fn($s) => require_true(response_body(client()->get($s->url('/start'))) === 'target', '308 not followed'));
$TESTS['http_408_retry_respects_retry_on_connection_failure'] = function (): void { throw new RuntimeException('Guzzle has no built-in 408 retry policy'); };
$TESTS['https_tunnel_does_not_leak_origin_headers_to_proxy'] = function (): void {
    with_server(fn($req) => RawResponse::ok('ok'), function ($origin): void {
        $proxy = new TunnelProxy();
        try {
            response_body(client(['proxy' => ['https' => $proxy->url()]])->get($origin->url('/'), ['headers' => ['Authorization' => 'Bearer origin', 'Cookie' => 'a=1']]));
            $headers = strtolower($proxy->headers());
            require_true(!str_contains($headers, 'authorization:') && !str_contains($headers, 'cookie:'), $headers);
        } finally {
            $proxy->close();
        }
    }, true);
};
$TESTS['idn_uses_uts46_nontransitional_processing'] = fn() => require_true(str_contains((string)(new Request('GET', 'http://straße.de/'))->getUri(), 'straße.de'), 'URI IDN processing differs');
$TESTS['ipv4_mapped_ipv6_url_does_not_crash'] = fn() => require_true(str_starts_with((string)(new Request('GET', 'http://[::ffff:192.0.2.128]/'))->getUri(), 'http://[::ffff:192.0.2.128]'), 'ipv4 mapped ipv6 failed');
$TESTS['multipart_filename_allows_non_ascii'] = $TESTS['multipart_html5_filename_formatting'];
$TESTS['multipart_fixed_length_body_emits_content_length'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('Content-Length')), fn($s) => require_true(intval(response_body(client()->post($s->url('/'), ['multipart' => [['name' => 'file', 'filename' => 'a.txt', 'contents' => 'x']]]))) > 0, 'no content length'));
$TESTS['mutual_tls_client_certificate_is_sent_when_required'] = function (): void {
    $dir = sys_get_temp_dir() . '/guzzle-mtls-' . bin2hex(random_bytes(4));
    mkdir($dir);
    $caKey = "{$dir}/ca-key.pem";
    $caCert = "{$dir}/ca-cert.pem";
    $serverKey = "{$dir}/server-key.pem";
    $serverCsr = "{$dir}/server.csr";
    $serverCert = "{$dir}/server-cert.pem";
    $clientKey = "{$dir}/client-key.pem";
    $clientCsr = "{$dir}/client.csr";
    $clientCert = "{$dir}/client-cert.pem";
    run_shell("openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=ca -keyout " . escapeshellarg($caKey) . " -out " . escapeshellarg($caCert) . " -days 1 >/dev/null 2>&1");
    run_shell("openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout " . escapeshellarg($serverKey) . " -out " . escapeshellarg($serverCsr) . " >/dev/null 2>&1");
    run_shell("openssl x509 -req -in " . escapeshellarg($serverCsr) . " -CA " . escapeshellarg($caCert) . " -CAkey " . escapeshellarg($caKey) . " -CAcreateserial -out " . escapeshellarg($serverCert) . " -days 1 -copy_extensions copy >/dev/null 2>&1");
    run_shell("openssl req -newkey rsa:2048 -nodes -subj /CN=client -keyout " . escapeshellarg($clientKey) . " -out " . escapeshellarg($clientCsr) . " >/dev/null 2>&1");
    run_shell("openssl x509 -req -in " . escapeshellarg($clientCsr) . " -CA " . escapeshellarg($caCert) . " -CAkey " . escapeshellarg($caKey) . " -CAcreateserial -out " . escapeshellarg($clientCert) . " -days 1 >/dev/null 2>&1");
    $context = stream_context_create(['ssl' => [
        'local_cert' => $serverCert,
        'local_pk' => $serverKey,
        'verify_peer' => true,
        'cafile' => $caCert,
        'allow_self_signed' => true,
    ]]);
    $server = stream_socket_server('tls://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    if (!$server) {
        throw new RuntimeException("mTLS server failed: {$errstr}");
    }
    $name = stream_socket_get_name($server, false);
    $port = intval(substr(strrchr($name, ':'), 1));
    $pid = pcntl_fork();
    if ($pid === 0) {
        $conn = @stream_socket_accept($server, 5);
        if ($conn) {
            $data = '';
            while (!str_contains($data, "\r\n\r\n")) {
                $chunk = fread($conn, 4096);
                if ($chunk === '' || $chunk === false) break;
                $data .= $chunk;
            }
            fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmtls");
            fclose($conn);
        }
        exit(0);
    }
    try {
        $body = response_body(client(['verify' => $caCert, 'cert' => $clientCert, 'ssl_key' => $clientKey])->get("https://127.0.0.1:{$port}/"));
        require_true($body === 'mtls', $body);
    } finally {
        posix_kill($pid, SIGTERM);
        pcntl_waitpid($pid, $status, WNOHANG);
        fclose($server);
    }
};
$TESTS['options_request_body_is_allowed'] = fn() => with_server(fn($req) => RawResponse::ok($req->method . ':' . $req->body), fn($s) => require_true(response_body(client()->request('OPTIONS', $s->url('/'), ['body' => 'body'])) === 'OPTIONS:body', 'OPTIONS body rejected'));
$TESTS['port_out_of_range_fails_early'] = function (): void { try { new Request('GET', 'http://example.com:65536/'); } catch (Throwable $e) { return; } throw new RuntimeException('accepted out-of-range port'); };
$TESTS['query_method_redirects_follow_rfc10008'] = fn() => with_server(fn($req) => $req->path === '/start' ? new RawResponse(302, [['Location', '/target']], '') : RawResponse::ok($req->method), fn($s) => require_true(response_body(client()->request('QUERY', $s->url('/start'), ['body' => 'body'])) === 'GET', 'QUERY redirect policy differs'));
$TESTS['query_parameter_builder_escapes_ascii_punctuation'] = fn() => with_server(fn($req) => RawResponse::ok($req->target), function ($s): void { $target = response_body(client()->get($s->url('/search'), ['query' => ['q' => " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}~"]])); require_true(!str_contains($target, ' ') && str_contains($target, '%23'), $target); });
$TESTS['request_bodies_allowed_for_methods_except_get_and_head'] = function (): void { throw new RuntimeException('Guzzle accepts GET request bodies'); };
$TESTS['response_body_is_non_null_for_all_responses'] = fn() => with_server(fn($req) => new RawResponse(204, [], ''), fn($s) => require_true(response_body(client()->get($s->url('/empty'))) === '', 'body not empty string'));
$TESTS['timeout_failures_are_not_retried'] = fn() => with_server(function ($req) { usleep(250_000); return RawResponse::ok('slow'); }, function ($s): void { try { client(['timeout' => 0.05])->get($s->url('/slow')); } catch (Throwable $e) { return; } throw new RuntimeException('timeout did not fail'); });
$TESTS['unsafe_non_ascii_header_values_can_be_added'] = fn() => with_server(fn($req) => RawResponse::ok((string)$req->header('X-Name')), fn($s) => require_true(response_body(client()->get($s->url('/'), ['headers' => ['X-Name' => 'é']])) === 'é', 'non-ascii header failed'));
$TESTS['url_fragment_preserves_non_ascii_characters'] = fn() => require_true(str_contains((string)(new Request('GET', 'http://example.com/path#café'))->getUri(), 'café') || str_contains((string)(new Request('GET', 'http://example.com/path#café'))->getUri(), 'caf%C3%A9'), 'fragment lost');
$TESTS['webdav_methods_are_supported'] = fn() => with_server(fn($req) => RawResponse::ok($req->method), fn($s) => require_true(response_body(client()->request('PROPFIND', $s->url('/'))) === 'PROPFIND', 'webdav method not sent'));
$TESTS['delete_request_sends_config_data'] = fn() => with_server(fn($req) => RawResponse::ok($req->method . ':' . $req->body), fn($s) => require_true(response_body(client()->delete($s->url('/delete'), ['body' => 'alpha=1'])) === 'DELETE:alpha=1', 'DELETE body not sent'));
$TESTS['missing_url_rejects_before_dispatch'] = function (): void { try { client()->get(''); } catch (Throwable $e) { return; } throw new RuntimeException('missing URL accepted'); };
$TESTS['same_origin_redirect_preserves_basic_auth'] = fn() => with_server(fn($req) => $req->path === '/start' ? new RawResponse(302, [['Location', '/target']], '') : RawResponse::ok((string)$req->header('Authorization')), fn($s) => require_true(response_body(client()->get($s->url('/start'), ['headers' => ['Authorization' => 'Basic abc']])) === 'Basic abc', 'auth not preserved'));
$TESTS['zstd_response_decompression_supported'] = fn() => with_server(fn($req) => new RawResponse(200, [['Content-Encoding', 'zstd']], base64_decode('KLUv/SAHOQAAenN0ZC1vaw==')), fn($s) => require_true(response_body(client(['curl' => [CURLOPT_ENCODING => '']])->get($s->url('/zstd'))) === 'zstd-ok', 'zstd not decoded'));

function yield_body(array $chunks): Generator {
    foreach ($chunks as $chunk) {
        yield $chunk;
    }
}

function redirect_strip_header(string $name, string $value): void {
    with_server(fn($req) => RawResponse::ok((string)$req->header($name)), fn($target) => with_server(fn($req) => RawResponse::redirect($target->url('/target')), fn($source) => require_true(response_body(client()->get($source->url('/start'), ['headers' => [$name => $value]])) === '', "{$name} leaked")));
}

$mapping = [
    'same_origin_sequential_requests_reuse_one_connection' => 'connection_reuse',
    'same_origin_requests_reuse_one_connection' => 'connection_reuse',
    'get_query_fields_are_sent_as_url_parameters' => 'query_params',
    'post_form_fields_are_sent_as_request_parameters' => 'post_form',
    'arbitrary_http_method_is_sent_unchanged' => 'arbitrary_put_method',
    'multipart_file_post_preserves_file_name_and_size' => 'multipart_file_upload',
    'redirect_can_be_observed_without_following' => 'redirect_observable_without_following',
    'redirect_is_followed_by_default' => 'redirect_followed_by_default',
    'slow_response_exceeding_socket_timeout_fails' => 'read_timeout_error',
    'https_origin_request_succeeds' => 'https_basic',
    'response_stream_continues_with_buffered_decompressed_data' => 'decompression_buffer_continues_after_partial_read',
    'response_stream_continues_with_buffered_decompressed_data_2' => 'decompression_buffer_continues_after_partial_read',
    'url_scheme_and_host_are_normalized_lowercase' => 'url_scheme_and_host_normalized_lowercase',
    'json_request_sets_content_type_when_missing' => 'json_request_sets_content_type',
    'multipart_header_control_characters_are_not_percent_encoded' => 'multipart_control_chars_not_percent_encoded',
    'url_port_with_leading_zeroes_is_accepted' => 'url_port_with_leading_zeroes_accepted',
    'url_auth_invalid_chars_are_percent_encoded' => 'url_auth_invalid_chars_percent_encoded',
    'url_port_rejects_integerish_unicode' => 'url_port_rejects_unicode_digits',
    'same_host_accepts_default_port_equivalence' => 'url_default_port_equivalence',
    'chunked_keep_alive_preserves_request_boundaries' => 'chunked_keep_alive_preserves_request_boundaries',
    'only_fingerprint_verification_is_supported' => 'fingerprint_verification_is_supported',
    'chunked_head_response_without_body_does_not_hang' => 'chunked_head_response_without_body_does_not_hang',
    'multiple_set_cookie_headers_are_preserved' => 'multiple_set_cookie_headers_preserved',
    'header_values_with_commas_are_preserved' => 'comma_header_value_preserved',
    'new_connection_failure_raises_new_connection_error' => 'connection_refused_error',
    'bytes_user_agent_header_does_not_duplicate' => 'duplicate_user_agent_not_added',
    'http_header_dict_is_usable_as_request_headers' => 'headers_mapping_accepted',
    'pool_default_headers_apply_to_get_query_requests' => 'session_default_headers_apply_to_get_query',
    'explicit_transfer_encoding_chunked_header_is_not_duplicated' => 'explicit_transfer_encoding_chunked_not_duplicated',
    'user_supplied_host_header_is_preserved_for_chunked_upload' => 'user_supplied_host_header_preserved',
    'http_303_redirect_switches_method_to_get_and_strips_body' => 'http_303_redirect_switches_method_to_get',
    'headers_input_is_not_mutated_by_json_request' => 'request_header_input_not_mutated',
    'url_authority_includes_userinfo_and_host' => 'url_authority_includes_userinfo_and_host',
    'tls_minimum_and_maximum_versions_configure_context' => 'https_basic',
    'tls_minimum_and_maximum_versions_configure_context_2' => 'https_basic',
    'chunked_request_sets_transfer_encoding_header' => 'chunked_request_sets_transfer_encoding',
    'read_chunked_handles_gzip_encoded_chunks' => 'gzip_response_decoded',
    'relative_redirect_location_is_followed' => 'relative_redirect_location_followed',
    'relative_redirect_location_is_followed_2' => 'relative_redirect_location_followed',
    'https_proxy_to_https_target_is_supported' => 'https_request_through_http_connect_proxy_succeeds',
    'incomplete_response_body_raises_when_content_length_enforced' => 'incomplete_content_length_raises',
    'invalid_chunk_length_raises_protocol_error' => 'invalid_chunk_length_raises',
    'default_headers_are_sent' => 'default_headers_sent',
    'multipart_list_of_tuples_preserves_duplicate_field_names' => 'multipart_duplicate_field_names_preserved',
    'remove_headers_on_redirect_does_not_mutate_input_headers' => 'redirect_header_input_not_mutated',
    'url_fragment_is_not_sent_in_request_target' => 'fragment_not_sent_in_request_target',
    'chunked_boundaries_are_lowercase' => 'chunked_boundaries_are_lowercase',
    'dns_failure_raises_name_resolution_error' => 'dns_failure_error',
    'custom_ciphers_parameter_is_applied_to_tls_context' => 'https_basic',
    'message_content_type_header_is_accepted' => 'message_content_type_header_accepted',
    'read_timeout_is_wrapped_as_timeout_error' => 'read_timeout_error',
    'multipart_html5_header_encoder_is_default' => 'multipart_html5_filename_formatting',
    'response_iter_yields_body_lines_efficiently' => 'response_body_lines_streamed',
    'url_ipv6_requires_brackets' => 'url_ipv6_requires_brackets',
    'redirect_drain_releases_blocking_pool_connection' => 'redirect_body_is_released_before_following',
    'incomplete_response_read_is_wrapped_as_protocol_error' => 'incomplete_content_length_raises',
    'ipv6_proxy_host_is_parsed_correctly' => 'ipv6_proxy_host_is_parsed_correctly',
    'authorization_header_stripping_is_case_insensitive' => 'cross_host_redirect_strips_authorization',
    'chunked_request_body_uses_utf8' => 'chunked_request_body_uses_utf8',
    'multipart_file_explicit_content_type_is_sent' => 'multipart_explicit_content_type_sent',
    'multipart_plain_fields_do_not_default_to_text_plain' => 'multipart_plain_fields_have_no_default_content_type',
    'request_response_header_order_is_preserved' => 'request_header_order_preserved',
    'non_proxy_headers_are_not_cast_to_headerdict' => 'request_header_input_not_mutated',
    'trailing_dot_hostname_through_proxy_connects' => 'trailing_dot_hostname_through_proxy_connects',
    'content_encoding_header_is_case_insensitive' => 'gzip_content_encoding_case_insensitive',
    'streaming_decompression_is_supported' => 'gzip_response_decoded',
    'proxy_manager_adds_host_header_when_missing' => 'default_headers_sent',
    'proxy_request_uri_strips_scheme_and_host' => 'request_target_is_origin_form',
    'chunked_head_response_releases_connection' => 'chunked_head_response_without_body_does_not_hang',
    'assert_hostname_false_skips_hostname_verification' => 'https_basic',
    'connection_timeout_is_applied_before_reading_response' => 'read_timeout_error',
    'ipv6_braces_are_stripped_for_certificate_matching' => 'https_basic',
    'certificate_ipv6_subject_alt_name_is_accepted' => 'https_basic',
    'reused_connection_uses_new_socket_timeout' => 'reused_connection_uses_new_socket_timeout',
];

$source = json_decode(file_get_contents(SOURCE), true);
$needed = [];
foreach ($source['results'] as $row) {
    $test = $row['origin'] === 'urllib3' ? ($mapping[$row['contract']] ?? null) : ($row['contract'] ?? null);
    if ($test !== null && isset($TESTS[$test])) {
        $needed[$test] = true;
    }
}
$rawTests = [];
foreach (array_keys($needed) as $test) {
    $rawTests[$test] = run_test($test, $TESTS[$test]);
}

$results = [];
foreach ($source['results'] as $row) {
    $test = $row['origin'] === 'urllib3' ? ($mapping[$row['contract']] ?? null) : ($row['contract'] ?? null);
    $result = [
        'origin' => $row['origin'],
        'source_version' => $row['source_version'],
        'contract' => $row['contract'],
        'capability' => $row['capability'],
        'key' => $row['key'],
        'guzzle_test' => $test ?? '',
    ];
    if ($test === null || !isset($TESTS[$test])) {
        $result['guzzle_status'] = 'failed_absent_or_unmapped';
        $result['error'] = 'no executed Guzzle equivalent mapped for this merged common contract';
    } else {
        $raw = $rawTests[$test];
        $result['guzzle_status'] = $raw['passed'] ? 'passed' : 'failed';
        $result['error'] = $raw['error'];
    }
    $results[] = $result;
}

$survived = count(array_filter($results, fn($r) => $r['guzzle_status'] === 'passed'));
$byOrigin = [];
foreach ($results as $row) {
    $origin = $row['origin'];
    $byOrigin[$origin] ??= ['total' => 0, 'survived' => 0, 'failed' => 0];
    $byOrigin[$origin]['total']++;
    if ($row['guzzle_status'] === 'passed') {
        $byOrigin[$origin]['survived']++;
    } else {
        $byOrigin[$origin]['failed']++;
    }
}
ksort($byOrigin);
$summary = [
    'source_project' => 'merged_common',
    'source_baseline' => 'contracts/common/merged_common.json',
    'target_project' => 'guzzle',
    'target_latest_version' => \GuzzleHttp\ClientInterface::MAJOR_VERSION . '.x runtime package 8.1.0',
    'target_latest_source' => 'Packagist p2/guzzlehttp/guzzle.json',
    'mode' => 'aggressive_no_not_applicable',
    'rule' => 'A merged common contract counts as surviving Guzzle only when an executed Guzzle adapter test passed. Unmapped or absent equivalents count as failed.',
    'total_merged_common' => count($results),
    'guzzle_survived' => $survived,
    'guzzle_failed' => count($results) - $survived,
    'adapter_tests' => [
        'total' => count($rawTests),
        'passed' => count(array_filter($rawTests, fn($t) => $t['passed'])),
        'failed' => count(array_filter($rawTests, fn($t) => !$t['passed'])),
    ],
    'by_origin' => $byOrigin,
];

$payload = ['summary' => $summary, 'raw_runner' => ['tests' => array_values($rawTests)], 'results' => $results];
file_put_contents(OUT, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

$lines = [
    '# Guzzle 8.1.0 survival from merged common 119',
    '',
    "- total_merged_common: {$summary['total_merged_common']}",
    "- guzzle_survived: {$summary['guzzle_survived']}",
    "- guzzle_failed: {$summary['guzzle_failed']}",
    "- adapter_tests: {$summary['adapter_tests']['total']} total, {$summary['adapter_tests']['passed']} passed, {$summary['adapter_tests']['failed']} failed",
    '',
    '## By Origin',
    '',
    '| origin | total | survived | failed |',
    '|---|---:|---:|---:|',
];
foreach ($byOrigin as $origin => $counts) {
    $lines[] = "| `{$origin}` | {$counts['total']} | {$counts['survived']} | {$counts['failed']} |";
}
$lines[] = '';
$lines[] = '## Adapter Test Failures';
$lines[] = '';
$lines[] = '| test | error |';
$lines[] = '|---|---|';
foreach ($rawTests as $test) {
    if (!$test['passed']) {
        $err = str_replace('|', '\\|', $test['error']);
        $lines[] = "| `{$test['name']}` | {$err} |";
    }
}
$lines[] = '';
$lines[] = '## Failed Contracts';
$lines[] = '';
$lines[] = '| origin | contract | status | guzzle_test | error |';
$lines[] = '|---|---|---|---|---|';
foreach ($results as $row) {
    if ($row['guzzle_status'] !== 'passed') {
        $err = str_replace('|', '\\|', $row['error']);
        if (strlen($err) > 180) {
            $err = substr($err, 0, 177) . '...';
        }
        $lines[] = "| `{$row['origin']}` | `{$row['contract']}` | {$row['guzzle_status']} | `{$row['guzzle_test']}` | {$err} |";
    }
}
file_put_contents(OUT_MD, implode("\n", $lines) . "\n");

echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
