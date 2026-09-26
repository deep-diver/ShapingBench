#!/usr/bin/env python3
"""
Compile and replay the first executable urllib3 release contract.

The DSL intentionally describes protocol-level behavior, not urllib3's Python
API. This script is the rule-based compiler for that DSL: it maps those rules
onto a runnable test against the urllib3 0.3 source artifact.
"""

from __future__ import annotations

import argparse
import cgi
import http.server
import http.client
import importlib.util
import io
import json
import pathlib
import re
import shutil
import socketserver
import ssl
import subprocess
import sys
import tarfile
import time
import types
import unittest
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from lib2to3.refactor import RefactoringTool, get_fixers_from_package


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "contracts" / "urllib3" / "0.3.rpl"
WORK_DIR = ROOT / ".replay"
ARTIFACT_DIR = WORK_DIR / "urllib3-first"
BUILD_DIR = WORK_DIR / "build" / "urllib3-0.3-py3"
GENERATED_DIR = WORK_DIR / "generated"
VENV_DIR = WORK_DIR / "venvs" / "urllib3-0.3"


@dataclass
class Route:
    path: str
    behavior: str = "static"
    status: int = 200
    body: str = ""
    param: str | None = None


@dataclass
class Action:
    method: str
    path: str
    query: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)
    file_field: str | None = None
    file_filename: str | None = None
    file_body: str | None = None
    redirect: bool = True
    retries: int = 3


@dataclass
class Expectation:
    subject: str
    index: int | None
    field: str
    op: str
    value: str | int


@dataclass
class Contract:
    name: str
    evidence: str = ""
    capability: str = ""
    mutant: str = ""
    use_tls: bool = False
    routes: list[Route] = field(default_factory=list)
    client_origin: str = "$SERVER"
    pool_max: int = 1
    timeout: float = 2
    actions: list[Action] = field(default_factory=list)
    expectations: list[Expectation] = field(default_factory=list)


@dataclass
class ReleaseSpec:
    project: str
    version: str
    source: str
    contracts: list[Contract]


def parse_value(raw: str) -> str | int:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        return raw


def parse_json_map(raw: str) -> dict[str, str]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"Expected object map, got: {raw}")
    return {str(key): str(item) for key, item in value.items()}


def parse_action(stripped: str) -> Action:
    match = re.match(r'when ([A-Z_]+) "([^"]+)"(.*)$', stripped)
    if not match:
        raise ValueError(f"Invalid action rule: {stripped}")
    action = Action(method=match.group(1), path=match.group(2))
    rest = match.group(3).strip()

    while rest:
        if match := re.match(r'query (\{.*?\})(?:\s+|$)', rest):
            action.query = parse_json_map(match.group(1))
        elif match := re.match(r'form (\{.*?\})(?:\s+|$)', rest):
            action.form = parse_json_map(match.group(1))
        elif match := re.match(r'file "([^"]+)" filename "([^"]+)" body "([^"]*)"(?:\s+|$)', rest):
            action.file_field = match.group(1)
            action.file_filename = match.group(2)
            action.file_body = match.group(3)
        elif match := re.match(r'redirect (true|false)(?:\s+|$)', rest):
            action.redirect = match.group(1) == "true"
        elif match := re.match(r'retries (\d+)(?:\s+|$)', rest):
            action.retries = int(match.group(1))
        else:
            raise ValueError(f"Invalid action option near: {rest}")
        rest = rest[match.end() :].strip()

    return action


def parse_contract(path: pathlib.Path) -> ReleaseSpec:
    lines = [
        line.rstrip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    release_match = re.fullmatch(r'release "([^"]+)" version "([^"]+)"', lines[0])
    source_match = re.fullmatch(r'source "([^"]+)"', lines[1])
    if not release_match or not source_match:
        raise ValueError("Invalid release header")

    contracts: list[Contract] = []
    current: Contract | None = None
    section: str | None = None

    for line in lines[2:]:
        stripped = line.strip()
        if match := re.fullmatch(r'contract "([^"]+)"', stripped):
            current = Contract(name=match.group(1))
            contracts.append(current)
            section = None
            continue
        if current is None:
            raise ValueError(f"Rule outside contract: {line}")
        if stripped == "end":
            current = None
            section = None
            continue
        if match := re.fullmatch(r'evidence "([^"]+)"', stripped):
            current.evidence = match.group(1)
            continue
        if match := re.fullmatch(r'capability "([^"]+)"', stripped):
            current.capability = match.group(1)
            continue
        if stripped == 'replay "template"':
            continue
        if match := re.fullmatch(r'mutant "([^"]+)"', stripped):
            current.mutant = match.group(1)
            continue
        if stripped == "given server":
            section = "server"
            continue
        if stripped == "given tls_server":
            section = "server"
            current.use_tls = True
            continue
        if stripped.startswith("given client "):
            section = "client"
            match = re.fullmatch(
                r'given client origin "([^"]+)" pool_max (\d+) timeout ([0-9.]+)',
                stripped,
            )
            if not match:
                raise ValueError(f"Invalid client rule: {line}")
            current.client_origin = match.group(1)
            current.pool_max = int(match.group(2))
            current.timeout = float(match.group(3))
            continue
        if stripped.startswith("when "):
            current.actions.append(parse_action(stripped))
            continue
        if stripped.startswith("then "):
            match = re.fullmatch(
                r'then (response) (\d+) (status|body) (== )?(.+)|then (server) (accepted_connections) == (.+)|then (error) (\d+) kind "([^"]+)"|then (server) (path_requests) "([^"]+)" == (.+)',
                stripped,
            )
            if not match:
                raise ValueError(f"Invalid expectation rule: {line}")
            if match.group(1):
                current.expectations.append(
                    Expectation(
                        subject="response",
                        index=int(match.group(2)),
                        field=match.group(3),
                        op="==",
                        value=parse_value(match.group(5)),
                    )
                )
            elif match.group(6):
                current.expectations.append(
                    Expectation(
                        subject="server",
                        index=None,
                        field=match.group(7),
                        op="==",
                        value=parse_value(match.group(8)),
                    )
                )
            else:
                if match.group(9):
                    current.expectations.append(
                        Expectation(
                            subject="error",
                            index=int(match.group(10)),
                            field="kind",
                            op="==",
                            value=match.group(11),
                        )
                    )
                else:
                    current.expectations.append(
                        Expectation(
                            subject="server",
                            index=None,
                            field=f"{match.group(13)}:{match.group(14)}",
                            op="==",
                            value=parse_value(match.group(15)),
                        )
                    )
            continue
        if section == "server":
            if match := re.fullmatch(r'route "([^"]+)" status (\d+) body "([^"]*)"', stripped):
                current.routes.append(Route(match.group(1), status=int(match.group(2)), body=match.group(3)))
            elif match := re.fullmatch(r'route "([^"]+)" require_method_param', stripped):
                current.routes.append(Route(match.group(1), behavior="require_method_param"))
            elif match := re.fullmatch(r'route "([^"]+)" require_upload', stripped):
                current.routes.append(Route(match.group(1), behavior="require_upload"))
            elif match := re.fullmatch(r'route "([^"]+)" redirect_from_query "([^"]+)" status (\d+)', stripped):
                current.routes.append(
                    Route(match.group(1), behavior="redirect_from_query", status=int(match.group(3)), param=match.group(2))
                )
            elif match := re.fullmatch(r'route "([^"]+)" sleep_from_query "([^"]+)" status (\d+) body "([^"]*)"', stripped):
                current.routes.append(
                    Route(
                        match.group(1),
                        behavior="sleep_from_query",
                        status=int(match.group(3)),
                        body=match.group(4),
                        param=match.group(2),
                    )
                )
            elif match := re.fullmatch(r'route "([^"]+)" close_first_then status (\d+) body "([^"]*)"', stripped):
                current.routes.append(
                    Route(match.group(1), behavior="close_first_then", status=int(match.group(2)), body=match.group(3))
                )
            else:
                raise ValueError(f"Invalid route rule: {line}")
            continue
        raise ValueError(f"Unknown rule: {line}")

    return ReleaseSpec(
        project=release_match.group(1),
        version=release_match.group(2),
        source=source_match.group(1),
        contracts=contracts,
    )


def ensure_artifact(source_url: str) -> None:
    if (ARTIFACT_DIR / "urllib3" / "connectionpool.py").exists():
        return
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(source_url, timeout=30) as response:
        data = response.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        root = archive.getmembers()[0].name.split("/", 1)[0]
        for member in archive.getmembers():
            if not member.name.startswith(root + "/"):
                continue
            member.name = member.name[len(root) + 1 :]
            if member.name:
                archive.extract(member, ARTIFACT_DIR)


def convert_module_to_py3() -> None:
    package_dir = BUILD_DIR / "urllib3"
    package_dir.mkdir(parents=True, exist_ok=True)
    tool = RefactoringTool(get_fixers_from_package("lib2to3.fixes"))
    for source_file in (ARTIFACT_DIR / "urllib3").glob("*.py"):
        converted = str(tool.refactor_string(source_file.read_text(encoding="utf-8"), str(source_file)))
        if source_file.name == "filepost.py":
            converted = converted.replace("import mimetools, mimetypes", "import mimetypes\nimport mimetools")
        if source_file.name == "connectionpool.py":
            converted = converted.replace("strict=r.strict)", "strict=getattr(r, 'strict', 0))")
            converted = converted.replace(
                "headers=dict(r.getheaders()),",
                "headers={k.lower(): v for k, v in r.getheaders()},",
            )
        (package_dir / source_file.name).write_text(converted, encoding="utf-8")


def install_legacy_shims() -> None:
    mimetools = types.ModuleType("mimetools")
    counter = {"value": 0}

    def choose_boundary() -> str:
        counter["value"] += 1
        return f"replay-boundary-{counter['value']}"

    mimetools.choose_boundary = choose_boundary
    sys.modules["mimetools"] = mimetools


def import_urllib3_03(mutant: str | None):
    install_legacy_shims()
    sys.path.insert(0, str(BUILD_DIR))
    for name in list(sys.modules):
        if name == "urllib3" or name.startswith("urllib3."):
            del sys.modules[name]
    spec = importlib.util.spec_from_file_location("urllib3", BUILD_DIR / "urllib3" / "__init__.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to import converted urllib3 0.3")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urllib3"] = module
    spec.loader.exec_module(module)
    connectionpool = sys.modules.get("urllib3.connectionpool")
    if connectionpool is not None:
        class UnverifiedHTTPSConnection(http.client.HTTPSConnection):
            def __init__(self, *args, **kwargs):
                kwargs.setdefault("context", ssl._create_unverified_context())
                super().__init__(*args, **kwargs)

        connectionpool.HTTPSConnection = UnverifiedHTTPSConnection
    if mutant in {"no_connection_reuse", "disable_connection_reuse"}:
        original_put_conn = module.HTTPConnectionPool._put_conn

        def close_instead_of_pool(self, conn):
            conn.close()
            return original_put_conn(self, None)

        module.HTTPConnectionPool._put_conn = close_instead_of_pool
    return module


class CountingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, request_handler_class, routes):
        self.routes = routes
        self.accepted_connections = 0
        self.path_requests: dict[str, int] = {}
        super().__init__(server_address, request_handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        self.accepted_connections += 1
        return sock, addr


CERT_DIR = WORK_DIR / "certs"
CERT_FILE = CERT_DIR / "localhost.crt"
KEY_FILE = CERT_DIR / "localhost.key"


def ensure_localhost_cert() -> tuple[pathlib.Path, pathlib.Path]:
    if CERT_FILE.exists() and KEY_FILE.exists():
        return CERT_FILE, KEY_FILE
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(KEY_FILE),
            "-out",
            str(CERT_FILE),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return CERT_FILE, KEY_FILE


class CountingHTTPSServer(CountingHTTPServer):
    def __init__(self, server_address, request_handler_class, routes):
        cert_file, key_file = ensure_localhost_cert()
        super().__init__(server_address, request_handler_class, routes)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        self.socket = context.wrap_socket(self.socket, server_side=True)


class ReplayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.handle_replay_request()

    def do_POST(self):
        self.handle_replay_request()

    def do_PUT(self):
        self.handle_replay_request()

    def parse_params(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = {
            key: values[-1]
            for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
        }
        body_params = {}
        files = {}
        content_length = int(self.headers.get("Content-Length", "0"))
        content_type = self.headers.get("Content-Type", "")
        if content_length and self.command in {"POST", "PUT"}:
            if content_type.startswith("multipart/form-data"):
                environ = {
                    "REQUEST_METHOD": self.command,
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": str(content_length),
                }
                form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=environ)
                for key in form:
                    item = form[key]
                    if isinstance(item, list):
                        item = item[-1]
                    if item.filename:
                        data = item.file.read()
                        files[key] = {"filename": item.filename, "size": len(data), "body": data.decode("utf-8")}
                    else:
                        body_params[key] = item.value
            else:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body_params.update(
                    {
                        key: values[-1]
                        for key, values in urllib.parse.parse_qs(raw_body, keep_blank_values=True).items()
                    }
                )
        params.update(body_params)
        return parsed.path, params, files

    def handle_replay_request(self):
        path, params, files = self.parse_params()
        self.server.path_requests[path] = self.server.path_requests.get(path, 0) + 1
        route = self.server.routes.get(path)
        if route is None:
            self.send_text(404, f"missing route: {path}")
        elif route.behavior == "static":
            self.send_text(route.status, route.body)
        elif route.behavior == "require_method_param":
            expected = params.get("method")
            if self.command == expected:
                self.send_text(200, "")
            else:
                self.send_text(400, f"Wrong method: {expected} != {self.command}")
        elif route.behavior == "require_upload":
            param = params.get("upload_param", "myfile")
            filename = params.get("upload_filename", "")
            expected_size = int(params.get("upload_size", "0"))
            file_info = files.get(param)
            if file_info is None:
                self.send_text(400, f"Not a file: {param}")
            elif expected_size != file_info["size"]:
                self.send_text(400, f"Wrong size: {expected_size} != {file_info['size']}")
            elif filename != file_info["filename"]:
                self.send_text(400, f"Wrong filename: {filename} != {file_info['filename']}")
            else:
                self.send_text(200, "")
        elif route.behavior == "redirect_from_query":
            target = params.get(route.param or "target", "/")
            self.send_response(route.status)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.close_connection = False
        elif route.behavior == "sleep_from_query":
            seconds = float(params.get(route.param or "seconds", "1"))
            time.sleep(seconds)
            self.send_text(route.status, route.body)
        elif route.behavior == "close_first_then":
            if self.server.path_requests[path] == 1:
                self.close_connection = True
                self.connection.close()
                return
            self.send_text(route.status, route.body)
        else:
            self.send_text(500, f"unknown route behavior: {route.behavior}")

    def send_text(self, status: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
            self.close_connection = False
        except BrokenPipeError:
            self.close_connection = True

    def log_message(self, format, *args):
        return


def append_query(path: str, query: dict[str, str]) -> str:
    if not query:
        return path
    separator = "&" if "?" in path else "?"
    return path + separator + urllib.parse.urlencode(query)


def classify_error(urllib3_module, error: BaseException) -> str:
    if isinstance(error, urllib3_module.TimeoutError):
        return "timeout"
    if isinstance(error, urllib3_module.MaxRetryError):
        return "max_retries_exceeded"
    if isinstance(error, urllib3_module.connectionpool.HostChangedError):
        return "foreign_origin"
    return error.__class__.__name__


def execute_action(client, action: dict, mutant: str | None):
    method = action["method"]
    path = action["path"]
    query = action.get("query", {})
    form = dict(action.get("form", {}))
    redirect = action.get("redirect", True)
    retries = action.get("retries", 3)

    if mutant == "drop_get_query_fields" and method == "GET":
        query = {}
    elif mutant == "drop_post_form_fields" and method == "POST_FORM":
        form = {}
    elif mutant == "rewrite_put_to_get" and method == "PUT":
        method = "GET"
    elif mutant == "drop_multipart_filename_or_body" and method == "POST_MULTIPART":
        action = dict(action)
        action["file_filename"] = "mutant.txt"
        action["file_body"] = ""
    elif mutant == "always_follow_redirects":
        redirect = True
    elif mutant == "disable_default_redirect_following":
        redirect = False
    elif mutant == "ignore_redirect_retry_budget":
        retries = max(retries, 1)
    elif mutant == "allow_foreign_origin_on_pool":
        path = "/"
    elif mutant == "disable_retry_after_broken_connection":
        retries = 0

    if method == "GET":
        return client.get_url(path, fields=query, redirect=redirect, retries=retries)
    if method in {"POST_FORM", "POST_MULTIPART"}:
        if action.get("file_field"):
            form[action["file_field"]] = (action["file_filename"], action["file_body"])
        return client.post_url(path, fields=form, redirect=redirect, retries=retries)
    return client.urlopen(method, append_query(path, query), redirect=redirect, retries=retries)


def run_contract_data(contract_data: dict, mutant: str | None):
    routes = {
        route["path"]: Route(
            path=route["path"],
            behavior=route["behavior"],
            status=route["status"],
            body=route["body"],
            param=route["param"],
        )
        for route in contract_data["routes"]
    }
    server_cls = CountingHTTPSServer if contract_data.get("use_tls") else CountingHTTPServer
    server = server_cls(("127.0.0.1", 0), ReplayHandler, routes)
    thread = __import__("threading").Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        urllib3 = import_urllib3_03(mutant)
        scheme = "https" if contract_data.get("use_tls") else "http"
        origin = "%s://127.0.0.1:%d" % (scheme, server.server_port)
        timeout = contract_data["client"]["timeout"]
        if mutant == "ignore_socket_timeout":
            timeout = 2
        if mutant == "route_https_through_plain_http_connection" and contract_data.get("use_tls"):
            origin = "http://127.0.0.1:%d" % server.server_port
        client = urllib3.connection_from_url(
            origin,
            maxsize=contract_data["client"]["pool_max"],
            timeout=timeout,
        )
        outcomes = []
        for action in contract_data["actions"]:
            try:
                outcomes.append({"response": execute_action(client, action, mutant), "error": None})
            except Exception as exc:
                outcomes.append({"response": None, "error": classify_error(urllib3, exc)})

        for expectation in contract_data["expectations"]:
            subject = expectation["subject"]
            if subject == "response":
                response = outcomes[expectation["index"] - 1]["response"]
                if response is None:
                    raise AssertionError("expected response, got error")
                field = expectation["field"]
                runtime_field = "data" if field == "body" else field
                actual = getattr(response, runtime_field)
                if field == "body" and isinstance(actual, bytes):
                    actual = actual.decode("utf-8")
            elif subject == "error":
                actual = outcomes[expectation["index"] - 1]["error"]
            elif subject == "server":
                if expectation["field"].startswith("path_requests:"):
                    _, path = expectation["field"].split(":", 1)
                    actual = server.path_requests.get(path, 0)
                else:
                    actual = getattr(server, expectation["field"])
            else:
                raise AssertionError("unknown subject: " + subject)
            if actual != expectation["value"]:
                raise AssertionError(f"{subject}.{expectation['field']} {actual!r} != {expectation['value']!r}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def contract_to_data(contract: Contract) -> dict:
    return {
        "name": contract.name,
        "evidence": contract.evidence,
        "capability": contract.capability,
        "mutant": contract.mutant,
        "use_tls": contract.use_tls,
        "routes": [
            {
                "path": route.path,
                "behavior": route.behavior,
                "status": route.status,
                "body": route.body,
                "param": route.param,
            }
            for route in contract.routes
        ],
        "client": {
            "origin": contract.client_origin,
            "pool_max": contract.pool_max,
            "timeout": contract.timeout,
        },
        "actions": [
            {
                "method": action.method,
                "path": action.path,
                "query": action.query,
                "form": action.form,
                "file_field": action.file_field,
                "file_filename": action.file_filename,
                "file_body": action.file_body,
                "redirect": action.redirect,
                "retries": action.retries,
            }
            for action in contract.actions
        ],
        "expectations": [
            {
                "subject": expectation.subject,
                "index": expectation.index,
                "field": expectation.field,
                "value": expectation.value,
            }
            for expectation in contract.expectations
        ],
    }


def compile_contract(spec: ReleaseSpec, contract: Contract) -> pathlib.Path:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    output = GENERATED_DIR / f"test_{spec.project}_{spec.version.replace('.', '_')}_{contract.name}.py"
    contract_data = contract_to_data(contract)
    output.write_text(
        f"""# Generated from {CONTRACT_PATH.relative_to(ROOT)}
# Evidence: {contract.evidence}

import unittest
from tools.replay.replay_urllib3_03 import run_contract_data


CONTRACT = {contract_data!r}


class ContractTest(unittest.TestCase):
    def test_{contract.name}(self):
        run_contract_data(CONTRACT, getattr(self, "mutant", None))

""",
        encoding="utf-8",
    )
    return output


def run_test(compiled_path: pathlib.Path, mutant: str | None) -> unittest.result.TestResult:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location("compiled_contract", compiled_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load generated test: {compiled_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ContractTest.mutant = mutant
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.ContractTest)
    return unittest.TextTestRunner(verbosity=2).run(suite)


def replay_in_process(mutant: str | None, compile_only: bool, only: str | None) -> int:
    spec = parse_contract(CONTRACT_PATH)
    ensure_artifact(spec.source)
    convert_module_to_py3()

    contracts = [contract for contract in spec.contracts if only in (None, contract.name)]
    if only and not contracts:
        print(f"Contract not found: {only}", file=sys.stderr)
        return 2
    compiled = [compile_contract(spec, contract) for contract in contracts]
    print("compiled:")
    for path in compiled:
        print(f"  {path}")
    if compile_only:
        return 0

    failed = False
    for path in compiled:
        result = run_test(path, mutant)
        failed = failed or not result.wasSuccessful()
    return 1 if failed else 0


def replay_batch_in_process() -> int:
    spec = parse_contract(CONTRACT_PATH)
    ensure_artifact(spec.source)
    convert_module_to_py3()

    rows = []
    for contract in spec.contracts:
        compiled = compile_contract(spec, contract)
        replay_result = run_test(compiled, None)
        mutant_result = run_test(compiled, contract.mutant)
        rows.append(
            {
                "version": spec.version,
                "contract": contract.name,
                "capability": contract.capability,
                "mutant": contract.mutant,
                "replay_exit_code": 0 if replay_result.wasSuccessful() else 1,
                "mutant_exit_code": 0 if mutant_result.wasSuccessful() else 1,
                "replay_output_tail": "",
                "mutant_output_tail": "",
            }
        )
    print(json.dumps(rows, ensure_ascii=False))
    return 0 if all(row["replay_exit_code"] == 0 and row["mutant_exit_code"] != 0 for row in rows) else 1


def replay_in_venv(mutant: str | None, compile_only: bool, only: str | None, batch: bool) -> int:
    if not (VENV_DIR / "bin" / "python").exists():
        VENV_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)

    command = [
        str(VENV_DIR / "bin" / "python"),
        str(pathlib.Path(__file__).resolve()),
        "--env",
        "local",
    ]
    if batch:
        command.append("--batch")
    if mutant:
        command.extend(["--mutant", mutant])
    if compile_only:
        command.append("--compile-only")
    if only:
        command.extend(["--only", only])
    return subprocess.run(command, cwd=ROOT).returncode


def replay_in_docker(mutant: str | None, compile_only: bool, only: str | None, batch: bool) -> int:
    docker = shutil.which("docker")
    if docker is None:
        print("Docker executable not found on PATH", file=sys.stderr)
        return 127

    command = [
        docker,
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/workspace",
        "-w",
        "/workspace",
        "python:3.12-slim",
        "python",
        "tools/replay/replay_urllib3_03.py",
        "--env",
        "local",
    ]
    if batch:
        command.append("--batch")
    if mutant:
        command.extend(["--mutant", mutant])
    if compile_only:
        command.append("--compile-only")
    if only:
        command.extend(["--only", only])
    return subprocess.run(command).returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--env",
        choices=["local", "venv", "docker"],
        default="local",
        help="Execution environment for replaying compiled contracts.",
    )
    parser.add_argument("--mutant")
    parser.add_argument("--only", help="Run only one contract by name.")
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()

    if args.env == "venv":
        return replay_in_venv(args.mutant, args.compile_only, args.only, args.batch)
    if args.env == "docker":
        return replay_in_docker(args.mutant, args.compile_only, args.only, args.batch)
    if args.batch:
        return replay_batch_in_process()
    return replay_in_process(args.mutant, args.compile_only, args.only)


if __name__ == "__main__":
    raise SystemExit(main())
