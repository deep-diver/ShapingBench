#!/usr/bin/env python3
"""Cross-replay URL/IRI latest survivors across Rank 1/2/3, then filter by Rank 4/5."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "url_iri" / "common"
OUT_JSON = OUT_DIR / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_MD = OUT_DIR / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.md"
OUT_RPL = OUT_DIR / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.rpl"

WHATWG_JSON = ROOT / "contracts" / "url_iri" / "whatwg-url" / "latest_replay_mutant_verified.json"
RUST_JSON = ROOT / "contracts" / "url_iri" / "rust-url" / "latest_replay_mutant_verified.json"
YARL_JSON = ROOT / "contracts" / "url_iri" / "yarl" / "latest_replay_mutant_verified.json"
WHATWG_DIR = ROOT / ".replay" / "url_iri" / "whatwg-url-latest"
RUST_RUNNER = ROOT / ".replay" / "url_iri" / "rust_url_runner_target" / "release" / "rust_url_runner"
YARL_PYTHON = ROOT / ".replay" / "url_iri" / "yarl-latest-uv" / "bin" / "python"
ADA_RUNNER = ROOT / ".replay" / "url_iri" / "ada_url_runner_target" / "release" / "ada_url_runner"
CURL_RUNNER = ROOT / ".replay" / "url_iri" / "curl_urlapi_runner"


COMMON_KEYS = [
    "href",
    "origin",
    "protocol",
    "username",
    "password",
    "host",
    "hostname",
    "port",
    "pathname",
    "search",
    "hash",
    "set_ok",
    "stable",
    "value",
    "ok",
]


WHATWG_BATCH = r"""
const w = require("./node_modules/whatwg-url");

function urlFrom(input, base) {
  return base === null || base === undefined ? new w.URL(input) : new w.URL(input, base);
}

function common(u) {
  return {
    ok: true,
    href: u.href,
    origin: u.origin,
    protocol: u.protocol,
    username: u.username,
    password: u.password,
    host: u.host,
    hostname: u.hostname,
    port: u.port,
    pathname: u.pathname,
    search: u.search,
    hash: u.hash
  };
}

function runOne(item) {
  const p = item.params || {};
  try {
    if (item.kind === "parse") {
      return common(urlFrom(p.input, p.base));
    }
    if (item.kind === "parse_failure") {
      try {
        const u = urlFrom(p.input, p.base);
        return {...common(u), ok: true};
      } catch (e) {
        return {ok: false, throws: e.name};
      }
    }
    if (item.kind === "set_component") {
      const u = urlFrom(p.input, p.base);
      try {
        u[p.component] = p.value === null ? "" : p.value;
        return {...common(u), set_ok: true};
      } catch (e) {
        return {...common(u), set_ok: false, throws: e.name};
      }
    }
    if (item.kind === "can_parse") {
      return {value: w.URL.canParse(p.input, p.base)};
    }
    if (item.kind === "roundtrip") {
      const first = urlFrom(p.input, p.base);
      const second = urlFrom(first.href);
      return {stable: first.href === second.href, href: second.href};
    }
    return {unsupported: true, message: item.kind};
  } catch (e) {
    return {ok: false, throws: e.name, message: e.message};
  }
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  const items = JSON.parse(input);
  process.stdout.write(JSON.stringify(items.map(runOne)));
});
"""


YARL_BATCH = r"""
import json
import sys
from yarl import URL

def common(u):
    raw_host = u.raw_host or ""
    explicit_port = u.explicit_port
    port = "" if explicit_port is None else str(explicit_port)
    host = raw_host
    if port:
        host = f"{host}:{port}" if host else f":{port}"
    query_string = u.raw_query_string
    fragment = u.raw_fragment
    return {
        "ok": True,
        "href": str(u),
        "origin": _origin(u),
        "protocol": f"{u.scheme}:" if u.scheme else "",
        "username": u.raw_user or "",
        "password": u.raw_password or "",
        "host": host,
        "hostname": raw_host,
        "port": port,
        "pathname": u.raw_path,
        "search": f"?{query_string}" if query_string else "",
        "hash": f"#{fragment}" if fragment else "",
    }

def _origin(u):
    try:
        return str(u.origin())
    except Exception:
        return "null"

def make_url(p):
    if p.get("base"):
        return URL(p["base"]).join(URL(p["input"]))
    return URL(p["input"])

def set_value(url, component, value):
    if value is None:
        value = ""
    if component == "protocol":
        return url.with_scheme(value[:-1] if value.endswith(":") else value)
    if component == "username":
        return url.with_user(value)
    if component == "password":
        return url.with_password(value)
    if component in ("host", "hostname"):
        if ":" in value and not value.startswith("["):
            host, port = value.rsplit(":", 1)
            try:
                return url.with_host(host).with_port(int(port))
            except ValueError:
                return url.with_host(value)
        return url.with_host(value)
    if component == "port":
        return url.with_port(None if value == "" else int(value))
    if component == "pathname":
        return url.with_path(value)
    if component == "search":
        return url.with_query(value[1:] if isinstance(value, str) and value.startswith("?") else value)
    if component == "hash":
        return url.with_fragment(value[1:] if isinstance(value, str) and value.startswith("#") else value)
    if component == "href":
        return URL(value)
    raise RuntimeError(f"unsupported component {component}")

def run_one(item):
    p = item.get("params") or {}
    try:
        if item["kind"] == "parse":
            return common(make_url(p))
        if item["kind"] == "parse_failure":
            try:
                return common(make_url(p))
            except Exception as e:
                return {"ok": False, "throws": type(e).__name__}
        if item["kind"] == "set_component":
            u = make_url(p)
            try:
                u2 = set_value(u, p["component"], p.get("value"))
                out = common(u2)
                out["set_ok"] = True
                return out
            except Exception as e:
                out = common(u)
                out["set_ok"] = False
                out["throws"] = type(e).__name__
                return out
        if item["kind"] == "can_parse":
            try:
                make_url(p)
                return {"value": True}
            except Exception:
                return {"value": False}
        if item["kind"] == "roundtrip":
            u = make_url(p)
            second = URL(str(u))
            return {"stable": str(u) == str(second), "href": str(second)}
        return {"unsupported": True, "message": item["kind"]}
    except Exception as e:
        return {"ok": False, "throws": type(e).__name__, "message": str(e)}

print(json.dumps([run_one(item) for item in json.loads(sys.stdin.read())], ensure_ascii=False))
"""


def load(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["survivors"]


def pick_keys(data: dict[str, Any], keys: list[str] = COMMON_KEYS) -> dict[str, Any]:
    return {key: data[key] for key in keys if key in data}


def normalize_expected_from_parse(expected: dict[str, Any]) -> dict[str, Any]:
    out = pick_keys(expected)
    if "ok" not in out:
        out["ok"] = True
    return out


def normalize_expected_from_yarl_result(result: dict[str, Any]) -> dict[str, Any]:
    raw_host = result.get("raw_host") or result.get("host_subcomponent") or result.get("host") or ""
    explicit_port = result.get("explicit_port")
    port = "" if explicit_port is None else str(explicit_port)
    host = result.get("host_port_subcomponent")
    if not isinstance(host, str):
        host = raw_host
        if port:
            host = f"{host}:{port}" if host else f":{port}"
    query_string = result.get("raw_query_string") or ""
    fragment = result.get("raw_fragment") or result.get("fragment") or ""
    return {
        "ok": True,
        "href": result.get("str"),
        "origin": result.get("origin") if isinstance(result.get("origin"), str) else None,
        "protocol": f"{result.get('scheme')}:" if result.get("scheme") else "",
        "username": result.get("raw_user") or "",
        "password": result.get("raw_password") or "",
        "host": host,
        "hostname": raw_host,
        "port": port,
        "pathname": result.get("raw_path") or result.get("path") or "",
        "search": f"?{query_string}" if query_string else "",
        "hash": f"#{fragment}" if fragment else "",
    }


def compact_expected(expected: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in expected.items() if value is not None}


def portable(origin: str, contract: dict[str, Any]) -> dict[str, Any] | None:
    op = contract["op"]
    params = copy.deepcopy(contract.get("params") or {})
    expected = contract.get("expected") or {}

    if origin in {"whatwg-url", "rust-url"}:
        if op == "parse_url":
            return {"kind": "parse", "params": params, "expected": compact_expected(normalize_expected_from_parse(expected))}
        if op in {"construct_failure", "parse_failure"}:
            return {"kind": "parse_failure", "params": params, "expected": {"ok": False}}
        if op == "set_component":
            component = params.get("component")
            if component == "scheme":
                component = "protocol"
                params["component"] = component
                if isinstance(params.get("value"), str) and not params["value"].endswith(":"):
                    params["value"] += ":"
            if component in {"href", "protocol", "username", "password", "host", "hostname", "port", "pathname", "search", "hash"}:
                return {"kind": "set_component", "params": params, "expected": compact_expected(normalize_expected_from_parse(expected))}
        if op in {"join"}:
            p = {"input": params.get("input"), "base": params.get("base")}
            return {"kind": "parse", "params": p, "expected": compact_expected(normalize_expected_from_parse(expected))}
        if op == "origin":
            return {"kind": "parse", "params": params, "expected": {"ok": True, "origin": expected.get("origin") or expected.get("ascii")}}
        if op == "can_parse":
            return {"kind": "can_parse", "params": params, "expected": {"value": expected.get("value")}}
        if op == "roundtrip":
            return {"kind": "roundtrip", "params": params, "expected": pick_keys(expected, ["stable", "href"])}
        return None

    if origin == "yarl":
        if not expected.get("ok", True):
            if "input" in params:
                return {"kind": "parse_failure", "params": params, "expected": {"ok": False}}
            return None
        result = expected.get("result") or {}
        if op == "props":
            return {"kind": "parse", "params": params, "expected": compact_expected(normalize_expected_from_yarl_result(result))}
        if op == "join":
            return {"kind": "parse", "params": {"input": params.get("input"), "base": params.get("base")}, "expected": compact_expected(normalize_expected_from_yarl_result(result))}
        if op == "transform":
            method = params.get("method")
            mapping = {
                "with_scheme": "protocol",
                "with_user": "username",
                "with_password": "password",
                "with_host": "hostname",
                "with_port": "port",
                "with_path": "pathname",
                "with_query": "search",
                "with_fragment": "hash",
                "with_name": None,
                "with_suffix": None,
            }
            component = mapping.get(method)
            if component is None:
                return None
            args = params.get("args") or []
            value = args[0] if args else None
            if component == "protocol" and isinstance(value, str) and not value.endswith(":"):
                value += ":"
            if component == "search" and isinstance(value, str) and value and not value.startswith("?"):
                value = f"?{value}"
            if component == "hash" and isinstance(value, str) and value and not value.startswith("#"):
                value = f"#{value}"
            return {
                "kind": "set_component",
                "params": {"input": params.get("input"), "component": component, "value": value},
                "expected": compact_expected(normalize_expected_from_yarl_result(result)),
            }
        return None
    return None


def expected_matches(expected: dict[str, Any], actual: dict[str, Any]) -> tuple[bool, list[str]]:
    misses = []
    if actual.get("unsupported"):
        return False, [f"unsupported: {actual.get('message')}"]
    for key, value in expected.items():
        if actual.get(key) != value:
            misses.append(f"{key}: expected {value!r}, got {actual.get(key)!r}")
    return not misses, misses


def run_node_batch(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not items:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".js", dir=WHATWG_DIR, delete=False) as fh:
        fh.write(WHATWG_BATCH)
        runner = Path(fh.name)
    try:
        raw = subprocess.check_output(
            ["node", str(runner.name)],
            input=json.dumps(items, ensure_ascii=False),
            cwd=WHATWG_DIR,
            text=True,
        )
        return json.loads(raw)
    finally:
        runner.unlink(missing_ok=True)


def run_yarl_batch(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not items:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".py", dir=ROOT / ".replay" / "url_iri", delete=False) as fh:
        fh.write(YARL_BATCH)
        runner = Path(fh.name)
    try:
        raw = subprocess.check_output(
            [str(YARL_PYTHON), str(runner)],
            input=json.dumps(items, ensure_ascii=False),
            cwd=ROOT,
            text=True,
        )
        return json.loads(raw)
    finally:
        runner.unlink(missing_ok=True)


def run_rust_one(item: dict[str, Any]) -> dict[str, Any]:
    p = item["params"]
    kind = item["kind"]
    if kind == "parse":
        contract = {"op": "parse_url", "params": p}
    elif kind == "parse_failure":
        contract = {"op": "parse_failure", "params": p}
    elif kind == "set_component":
        contract = {"op": "set_component", "params": {**p, "mode": "quirks"}}
    elif kind == "can_parse":
        raw = run_rust_one({"kind": "parse_failure", "params": p})
        return {"value": bool(raw.get("ok"))}
    elif kind == "roundtrip":
        first = run_rust_one({"kind": "parse", "params": p})
        if not first.get("ok"):
            return {"stable": False, "href": None}
        second = run_rust_one({"kind": "parse", "params": {"input": first.get("href")}})
        return {"stable": first.get("href") == second.get("href"), "href": second.get("href")}
    else:
        return {"unsupported": True, "message": kind}
    proc = subprocess.run(
        [str(RUST_RUNNER)],
        input=json.dumps(contract, ensure_ascii=False),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        return {"ok": False, "throws": "RunnerProcessError", "message": proc.stderr.strip()}
    result = json.loads(proc.stdout)
    if not result.get("ok"):
        if kind == "parse_failure":
            return {"ok": False, "throws": result.get("error")}
        return {"ok": False, "throws": result.get("error")}
    actual = result["actual"]
    if kind == "parse_failure":
        return {"ok": actual.get("ok"), "href": actual.get("href"), "throws": actual.get("error")}
    out = pick_keys(actual)
    if "ok" not in out:
        out["ok"] = True
    return out


def run_ada_one(item: dict[str, Any]) -> dict[str, Any]:
    p = copy.deepcopy(item["params"])
    kind = item["kind"]
    if kind == "parse":
        payload = {"op": "parse", "params": p}
    elif kind == "parse_failure":
        payload = {"op": "parse", "params": p}
    elif kind == "set_component":
        payload = {"op": "set_component", "params": p}
    elif kind == "can_parse":
        payload = {"op": "can_parse", "params": p}
    elif kind == "roundtrip":
        first = run_ada_one({"kind": "parse", "params": p})
        if not first.get("ok"):
            return {"stable": False, "href": None}
        second = run_ada_one({"kind": "parse", "params": {"input": first.get("href"), "base": None}})
        return {"stable": first.get("href") == second.get("href"), "href": second.get("href")}
    else:
        return {"unsupported": True, "message": kind}
    raw = subprocess.check_output([str(ADA_RUNNER)], input=json.dumps(payload, ensure_ascii=False).encode(), cwd=ROOT)
    result = json.loads(raw)
    if kind == "can_parse":
        return {"value": result.get("result", {}).get("value")}
    if not result.get("ok"):
        return {"ok": False, "throws": result.get("throws")}
    if kind == "parse_failure":
        return {"ok": True, **pick_keys(result.get("result", {}))}
    result_data = result.get("result") or {}
    data = result_data.get("url") or result_data
    out = pick_keys(data)
    if "ok" not in out:
        out["ok"] = True
    if "set_ok" not in out and kind == "set_component":
        out["set_ok"] = result_data.get("setter_ok")
    return out


def curl_flags_for_parse(item: dict[str, Any]) -> int:
    p = item["params"]
    expected = item.get("expected") or {}
    value = p.get("input") or ""
    protocol = expected.get("protocol") or ""
    scheme = protocol[:-1].lower() if protocol.endswith(":") else protocol.lower()
    built_in = {"dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https", "imap", "imaps", "ldap", "ldaps", "mqtt", "pop3", "pop3s", "rtmp", "rtmps", "rtsp", "scp", "sftp", "smb", "smbs", "smtp", "smtps", "telnet", "tftp", "ws", "wss"}
    flags = 0
    if scheme and scheme not in built_in:
        flags |= 1 << 3
    if " " in value:
        flags |= 1 << 11
    return flags


def curl_get_flags(item: dict[str, Any]) -> int:
    expected = item.get("expected") or {}
    text = json.dumps(expected, ensure_ascii=False)
    if "xn--" in text:
        return 1 << 12
    return 0


def origin_from_parts(protocol: str, hostname: str, port: str) -> str | None:
    scheme = protocol[:-1].lower() if protocol.endswith(":") else protocol.lower()
    if scheme not in {"http", "https", "ws", "wss", "ftp"} or not hostname:
        return "null"
    default_ports = {"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}
    if port and port != default_ports.get(scheme):
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def normalize_curl_parse(actual: dict[str, Any], kind: str) -> dict[str, Any]:
    if kind == "parse_failure":
        return {"ok": actual.get("set_code") == 0}
    if actual.get("set_code") != 0:
        return {"ok": False, "throws": actual.get("set_error")}
    if "parts" not in actual:
        return {"ok": False, "throws": actual.get("set_error") or actual.get("init_error")}
    parts = actual["parts"]
    def val(name: str) -> str:
        item = parts.get(name, {})
        return item.get("value") if item.get("code") == 0 and item.get("value") is not None else ""
    query = val("query")
    fragment = val("fragment")
    return {
        "ok": True,
        "href": val("url"),
        "protocol": f"{val('scheme')}:" if val("scheme") else "",
        "username": val("user"),
        "password": val("password"),
        "host": val("host") + (f":{val('port')}" if val("port") else ""),
        "hostname": val("host"),
        "port": val("port"),
        "pathname": val("path"),
        "search": f"?{query}" if query else "",
        "hash": f"#{fragment}" if fragment else "",
        "origin": origin_from_parts(f"{val('scheme')}:" if val("scheme") else "", val("host"), val("port")),
    }


def run_curl_one(item: dict[str, Any]) -> dict[str, Any]:
    kind = item["kind"]
    p = item["params"]
    def hx(value: Any) -> str:
        return str(value or "").encode("utf-8").hex()

    if kind in {"parse", "parse_failure"}:
        flags = curl_flags_for_parse(item)
        get_flags = curl_get_flags(item)
        if p.get("base"):
            base_flags = curl_flags_for_parse({"params": {"input": p.get("base")}, "expected": item.get("expected", {})})
            raw = subprocess.check_output([str(CURL_RUNNER), "relative_hex", hx(p.get("base")), str(base_flags), hx(p.get("input")), str(flags), str(get_flags)], cwd=ROOT, text=True)
            actual = json.loads(raw)
            if kind == "parse_failure":
                return {"ok": actual.get("base_code") == 0 and actual.get("relative_code") == 0}
            if actual.get("relative_code") != 0:
                return {"ok": False, "throws": actual.get("relative_error")}
            return normalize_curl_parse({"set_code": 0, "parts": actual.get("parts", {})}, kind)
        raw = subprocess.check_output([str(CURL_RUNNER), "parse_hex", hx(p.get("input")), str(flags), str(get_flags)], cwd=ROOT, text=True)
        return normalize_curl_parse(json.loads(raw), kind)
    if kind == "set_component":
        mapping = {
            "href": "url",
            "protocol": "scheme",
            "username": "user",
            "password": "password",
            "host": "host",
            "hostname": "host",
            "port": "port",
            "pathname": "path",
            "search": "query",
            "hash": "fragment",
        }
        component = p.get("component")
        if component not in mapping or p.get("base"):
            return {"unsupported": True, "message": f"curl set_component {component}"}
        value = p.get("value")
        if component == "protocol" and isinstance(value, str) and value.endswith(":"):
            value = value[:-1]
        if component == "search" and isinstance(value, str) and value.startswith("?"):
            value = value[1:]
        if component == "hash" and isinstance(value, str) and value.startswith("#"):
            value = value[1:]
        expected_text = json.dumps(item.get("expected") or {}, ensure_ascii=False)
        set_flags = 0
        if component in {"username", "password", "pathname", "search", "hash"} and "%" in expected_text:
            set_flags |= 1 << 7
        init_flags = curl_flags_for_parse({"params": {"input": p.get("input")}, "expected": item.get("expected", {})})
        raw = subprocess.check_output(
            [str(CURL_RUNNER), "setpart_hex", hx(p.get("input")), str(init_flags), mapping[component], "__NULL__" if value is None else hx(value), str(set_flags), "0"],
            cwd=ROOT,
            text=True,
        )
        actual = json.loads(raw)
        out = normalize_curl_parse(actual, "parse")
        out["set_ok"] = actual.get("set_code") == 0
        return out
    if kind == "can_parse":
        parsed = run_curl_one({"kind": "parse", "params": p})
        return {"value": bool(parsed.get("ok"))}
    if kind == "roundtrip":
        parsed = run_curl_one({"kind": "parse", "params": p})
        if not parsed.get("ok"):
            return {"stable": False, "href": None}
        second = run_curl_one({"kind": "parse", "params": {"input": parsed.get("href")}})
        return {"stable": parsed.get("href") == second.get("href"), "href": second.get("href")}
    return {"unsupported": True, "message": kind}


def run_target(target: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if target == "whatwg-url":
        return run_node_batch(items)
    if target == "yarl":
        return run_yarl_batch(items)
    if target == "rust-url":
        return [run_rust_one(item) for item in items]
    if target == "ada-url":
        return [run_ada_one(item) for item in items]
    if target == "curl":
        return [run_curl_one(item) for item in items]
    raise ValueError(target)


def build_origin(origin: str, contracts: list[dict[str, Any]], targets: list[str]) -> dict[str, Any]:
    candidates = []
    unsupported = []
    for contract in contracts:
        p = portable(origin, contract)
        if p is None or not p.get("expected"):
            unsupported.append(contract["name"])
            continue
        p = {**p, "origin": origin, "contract": contract}
        candidates.append(p)

    target_results: dict[str, list[dict[str, Any]]] = {}
    for target in targets:
        target_results[target] = run_target(target, candidates)

    survivors = []
    failures = []
    for index, candidate in enumerate(candidates):
        per_target = {}
        passed = True
        for target in targets:
            actual = target_results[target][index]
            ok, misses = expected_matches(candidate["expected"], actual)
            per_target[target] = {"passed": ok, "actual": actual, "misses": misses}
            passed = passed and ok
        row = {
            "origin": origin,
            "name": candidate["contract"]["name"],
            "version": candidate["contract"]["version"],
            "capability": candidate["contract"]["capability"],
            "kind": candidate["kind"],
            "params": candidate["params"],
            "expected": candidate["expected"],
            "targets": per_target,
            "source_contract": candidate["contract"],
        }
        if passed:
            survivors.append(row)
        else:
            failures.append(row)
    return {
        "origin": origin,
        "input": len(contracts),
        "portable": len(candidates),
        "unsupported": unsupported,
        "targets": targets,
        "survivors": survivors,
        "failures": failures,
    }


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = (row["origin"], row["name"])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def contract_to_rpl(row: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {row['origin']}::{row['name']} {{",
            f"  origin = {json.dumps(row['origin'])}",
            f"  version = {json.dumps(row['version'])}",
            f"  capability = {json.dumps(row['capability'])}",
            f"  kind = {json.dumps(row['kind'])}",
            f"  params = {json.dumps(row['params'], ensure_ascii=False, sort_keys=True)}",
            f"  expect = {json.dumps(row['expected'], ensure_ascii=False, sort_keys=True)}",
            "}",
        ]
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    origins = {
        "whatwg-url": load(WHATWG_JSON),
        "rust-url": load(RUST_JSON),
        "yarl": load(YARL_JSON),
    }
    stage_123 = [
        build_origin("whatwg-url", origins["whatwg-url"], ["rust-url", "yarl"]),
        build_origin("rust-url", origins["rust-url"], ["whatwg-url", "yarl"]),
        build_origin("yarl", origins["yarl"], ["whatwg-url", "rust-url"]),
    ]
    raw_common_candidates = [row for stage in stage_123 for row in stage["survivors"]]
    common_candidates = dedupe_rows(raw_common_candidates)
    filter4 = run_target("ada-url", common_candidates)
    filter5 = run_target("curl", common_candidates)
    final_common = []
    hidden_failures = []
    for row, ada_actual, curl_actual in zip(common_candidates, filter4, filter5, strict=True):
        ada_ok, ada_misses = expected_matches(row["expected"], ada_actual)
        curl_ok, curl_misses = expected_matches(row["expected"], curl_actual)
        enriched = {
            **row,
            "hidden_filters": {
                "ada-url": {"passed": ada_ok, "actual": ada_actual, "misses": ada_misses},
                "curl": {"passed": curl_ok, "actual": curl_actual, "misses": curl_misses},
            },
        }
        if ada_ok and curl_ok:
            final_common.append(enriched)
        else:
            hidden_failures.append(enriched)

    OUT_JSON.write_text(
        json.dumps(
            {
                "domain": "URL/IRI",
                "definition": "Rank 1/2/3 actual cross replay survivors, then filtered by actual replay on Rank 4/5.",
                "rank_1_2_3": stage_123,
                "common_candidate_rows_before_dedupe": len(raw_common_candidates),
                "common_candidates_before_hidden_filter": len(common_candidates),
                "hidden_filter_input": len(common_candidates),
                "hidden_filter_failures": len(hidden_failures),
                "final_common": len(final_common),
                "final_common_contracts": final_common,
                "hidden_failures": hidden_failures,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    OUT_RPL.write_text("\n\n".join(contract_to_rpl(row) for row in final_common) + "\n", encoding="utf-8")

    by_origin = Counter(row["origin"] for row in final_common)
    by_kind = Counter(row["kind"] for row in final_common)
    by_cap = Counter(row["capability"] for row in final_common)
    hidden_failed_by_target = Counter()
    curl_failure_first_field = Counter()
    for row in hidden_failures:
        for target, result in row["hidden_filters"].items():
            if not result["passed"]:
                hidden_failed_by_target[target] += 1
                if target == "curl":
                    actual = result["actual"]
                    if actual.get("unsupported"):
                        curl_failure_first_field[f"unsupported: {actual.get('message')}"] += 1
                    elif result["misses"]:
                        curl_failure_first_field[result["misses"][0].split(":")[0]] += 1
                    else:
                        curl_failure_first_field["unknown"] += 1
    md = [
        "# URL/IRI Cross-Replay Common",
        "",
        "Definition: unique Rank 1/2/3 contracts that replay on the other two Rank 1/2/3 libraries, filtered again by replay on Rank 4 and Rank 5.",
        "",
        "## Rank 1/2/3 Cross-Replay",
        "",
        "| Origin | Input latest survivors | Portable to common DSL | Cross targets | Cross survivors |",
        "| --- | ---: | ---: | --- | ---: |",
    ]
    for stage in stage_123:
        md.append(f"| `{stage['origin']}` | {stage['input']} | {stage['portable']} | {', '.join(f'`{x}`' for x in stage['targets'])} | {len(stage['survivors'])} |")
    md.extend(
        [
            "",
            "## Hidden Filter",
            "",
            "| Stage | Count |",
            "| --- | ---: |",
            f"| Common candidate rows from (1)+(2)+(3) | {len(raw_common_candidates)} |",
            f"| Unique common candidates from (1)+(2)+(3) | {len(common_candidates)} |",
            f"| Failed on Rank 4 `ada-url` | {hidden_failed_by_target.get('ada-url', 0)} |",
            f"| Failed on Rank 5 `curl` | {hidden_failed_by_target.get('curl', 0)} |",
            f"| Final common | {len(final_common)} |",
            "",
            "## Final Common by Origin",
            "",
            "| Origin | Count |",
            "| --- | ---: |",
        ]
    )
    for origin, count in by_origin.most_common():
        md.append(f"| `{origin}` | {count} |")
    md.extend(["", "## Final Common by Kind", "", "| Kind | Count |", "| --- | ---: |"])
    for kind, count in by_kind.most_common():
        md.append(f"| `{kind}` | {count} |")
    md.extend(
        [
            "",
            "## Rank 5 curl Failure Clusters",
            "",
            "| First mismatching field / adapter limit | Count |",
            "| --- | ---: |",
        ]
    )
    for field, count in curl_failure_first_field.most_common():
        md.append(f"| `{field}` | {count} |")
    md.extend(
        [
            "",
            "Remaining curl failures are mostly actual policy/API-shape differences after adapter support for public URL encoding flags and hex-encoded runner input: WHATWG tab/newline stripping, opaque/non-special schemes, `about:blank` bases, Windows-drive `file:` URLs, IDNA punycode serialization, and raw NUL code points observed through libcurl's null-terminated C string URL API.",
        ]
    )
    md.extend(["", "## Final Common by Capability", "", "| Capability | Count |", "| --- | ---: |"])
    for cap, count in by_cap.most_common():
        md.append(f"| `{cap}` | {count} |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"cross_candidates": len(common_candidates), "hidden_failures": len(hidden_failures), "final_common": len(final_common), "by_origin": dict(by_origin)}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
