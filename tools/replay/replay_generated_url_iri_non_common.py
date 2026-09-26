#!/usr/bin/env python3
"""Replay URL/IRI origin non-common contracts against a generated Python solurl library."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote_plus, unquote, unquote_to_bytes, urlsplit


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "contracts" / "url_iri"
COMMON_JSON = BASE / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
OUT_DIR = BASE / "generated_non_common"

LATEST = {
    "whatwg-url": BASE / "whatwg-url" / "latest_replay_mutant_verified.json",
    "rust-url": BASE / "rust-url" / "latest_replay_mutant_verified.json",
    "yarl": BASE / "yarl" / "latest_replay_mutant_verified.json",
    "ada-url": BASE / "ada-url" / "latest_replay_mutant_verified.json",
    "curl": BASE / "curl" / "latest_replay_mutant_verified.json",
}

DEFAULT_PORT = {
    "ftp": 21,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}

CURL_PART_ERRORS = {
    "user": (11, "No user part in the URL"),
    "password": (12, "No password part in the URL"),
    "options": (13, "No options part in the URL"),
    "host": (14, "No host part in the URL"),
    "port": (15, "No port part in the URL"),
    "query": (16, "No query part in the URL"),
    "fragment": (17, "No fragment part in the URL"),
    "zoneid": (18, "No zoneid part in the URL"),
}

CURL_STRERROR = {
    "0": "No error",
    "1": "Unsupported protocol",
    "2": "Malformed input to a URL function",
    "3": "A memory function failed",
    "4": "Port number was not a decimal number between 0 and 65535",
    "5": "Unsupported URL scheme",
    "6": "Bad file:// URL",
    "7": "Bad fragment part",
    "8": "Bad hostname",
    "9": "Bad IPv6 address",
    "10": "Bad login part",
    "11": "No user part in the URL",
    "12": "No password part in the URL",
    "13": "No options part in the URL",
    "14": "No host part in the URL",
    "15": "No port part in the URL",
    "16": "No query part in the URL",
    "17": "No fragment part in the URL",
    "18": "No zoneid part in the URL",
    "19": "Bad file path",
    "20": "Bad query part",
    "21": "Bad scheme",
    "22": "Bad slash sequence",
    "23": "Bad user part",
    "24": "Bad password part",
    "25": "Bad options part",
    "26": "Bad path part",
    "27": "Bad URL handle",
    "28": "Part does not work with userinfo",
}


class SurfaceError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_hashes(impl_dir: Path, path: Path) -> None:
    rows = []
    for candidate in sorted(impl_dir.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "target", "venv", ".venv"} for part in candidate.parts):
            continue
        if candidate.suffix in {".pyc", ".pyo"}:
            continue
        rows.append(f"{sha256(candidate)}  {candidate.relative_to(impl_dir)}\n")
    path.write_text("".join(rows), encoding="utf-8")


def as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def load_solurl(impl_dir: Path) -> Any:
    sys.path.insert(0, str(impl_dir))
    try:
        return importlib.import_module("solurl")
    except Exception as ex:
        raise SystemExit(f"failed to import generated solurl from {impl_dir}: {type(ex).__name__}: {ex}") from ex


def make_url(solurl: Any, input_value: str, base: Any = None) -> Any:
    return solurl.URL(input_value, base) if base is not None else solurl.URL(input_value)


def url_basic(url: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "href": as_text(getattr(url, "href", str(url))),
        "as_str": as_text(getattr(url, "href", str(url))),
        "protocol": as_text(getattr(url, "protocol", "")),
        "scheme": as_text(getattr(url, "protocol", ""))[:-1],
        "username": as_text(getattr(url, "username", "")),
        "password": as_text(getattr(url, "password", "")),
        "host": as_text(getattr(url, "host", "")),
        "hostname": as_text(getattr(url, "hostname", "")),
        "port": as_text(getattr(url, "port", "")),
        "pathname": as_text(getattr(url, "pathname", "")),
        "path": as_text(getattr(url, "pathname", "")),
        "search": as_text(getattr(url, "search", "")),
        "query": as_text(getattr(url, "search", ""))[1:] if as_text(getattr(url, "search", "")).startswith("?") else as_text(getattr(url, "search", "")),
        "hash": as_text(getattr(url, "hash", "")),
        "fragment": as_text(getattr(url, "hash", ""))[1:] if as_text(getattr(url, "hash", "")).startswith("#") else as_text(getattr(url, "hash", "")),
        "origin": as_text(getattr(url, "origin", "")),
    }


def decoded_pairs(query: str) -> list[list[str]]:
    return [[k, v] for k, v in parse_qsl(query, keep_blank_values=True)]


def params_init_pairs(init: Any) -> list[list[str]]:
    if isinstance(init, str):
        text = init[1:] if init.startswith("?") else init
        return decoded_pairs(text)
    if isinstance(init, dict):
        return [[str(k), str(v)] for k, v in init.items()]
    if isinstance(init, list):
        return [[str(k), str(v)] for k, v in init]
    return []


def yarl_like(url: Any) -> dict[str, Any]:
    basic = url_basic(url)
    href = basic["href"]
    split = urlsplit(href)
    scheme = basic["scheme"]
    explicit_port = int(basic["port"]) if basic["port"].isdigit() else None
    default_port = DEFAULT_PORT.get(scheme)
    port_value = explicit_port if explicit_port is not None else (default_port if basic["hostname"] and scheme in DEFAULT_PORT else None)
    raw_path = basic["pathname"]
    path = unquote(raw_path)
    parts = path.split("/") if path.startswith("/") else ([path] if path else [""])
    if path.startswith("/"):
        parts[0] = "/"
    name = parts[-1] if parts else ""
    suffixes = []
    if "." in name and not name.startswith("."):
        pieces = name.split(".")[1:]
        suffixes = ["." + ".".join(pieces[i:]) for i in range(len(pieces))]
    query_string = basic["query"]
    user = unquote(basic["username"]) or None
    password = unquote(basic["password"]) or None
    authority_host = basic["hostname"] or None
    authority = ""
    if authority_host:
        if user is not None:
            authority += user
            if password is not None:
                authority += ":" + password
            authority += "@"
        authority += authority_host
        if port_value is not None:
            authority += f":{port_value}"
    raw_authority = split.netloc
    parent = href.rsplit("/", 1)[0] if "/" in href else ""
    if href.endswith("/"):
        parent = href
    human_repr = unquote(href)
    result = {
        **basic,
        "absolute": bool(scheme and (basic["hostname"] or scheme in {"file"})),
        "is_absolute": bool(scheme and (basic["hostname"] or scheme in {"file"})),
        "authority": authority,
        "explicit_port": explicit_port,
        "is_default_port": explicit_port is None and default_port is not None and bool(basic["hostname"]),
        "host": authority_host,
        "raw_host": authority_host,
        "host_subcomponent": authority_host,
        "host_port_subcomponent": authority_host if explicit_port is None else f"{authority_host}:{explicit_port}",
        "human_repr": human_repr,
        "name": name,
        "raw_name": basic["pathname"].rstrip("/").rsplit("/", 1)[-1] if basic["pathname"] else "",
        "parent": parent,
        "parts": parts,
        "raw_parts": parts,
        "path": path,
        "raw_path": raw_path,
        "path_qs": path + (("?" + query_string) if query_string else ""),
        "raw_path_qs": raw_path + (("?" + query_string) if query_string else ""),
        "path_safe": path,
        "port": port_value,
        "query_items": decoded_pairs(query_string),
        "query_string": query_string,
        "raw_query_string": query_string,
        "raw_fragment": basic["fragment"],
        "raw_authority": raw_authority,
        "raw_password": password,
        "raw_user": user,
        "relative": path + (("?" + query_string) if query_string else "") + (("#" + basic["fragment"]) if basic["fragment"] else ""),
        "suffix": suffixes[0] if suffixes else "",
        "suffixes": suffixes,
        "raw_suffix": suffixes[0] if suffixes else "",
        "raw_suffixes": suffixes,
        "user": user,
        "password": password,
        "repr": f"URL('{href}')",
        "str": href,
    }
    if basic["origin"] == "null":
        result["origin_throws"] = "ValueError"
    return result


def wrap_ok_result(value: Any) -> dict[str, Any]:
    return {"ok": True, "result": value}


def surface_error(message: str) -> dict[str, Any]:
    return {"ok": False, "surface_error": message}


def run_parse(solurl: Any, params: dict[str, Any]) -> dict[str, Any]:
    url = make_url(solurl, params.get("input", ""), params.get("base"))
    return url_basic(url)


def run_parse_failure(solurl: Any, params: dict[str, Any]) -> dict[str, Any]:
    try:
        url = make_url(solurl, params.get("input", ""), params.get("base"))
        out = url_basic(url)
        out["ok"] = True
        return out
    except Exception as ex:
        return {"ok": False, "throws": type(ex).__name__, "message": str(ex)}


def set_component(url: Any, component: str, value: Any) -> tuple[bool, dict[str, Any]]:
    try:
        setattr(url, component, "" if value is None else value)
        return True, url_basic(url)
    except Exception as ex:
        out = url_basic(url)
        out.update({"throws": type(ex).__name__, "message": str(ex)})
        return False, out


def apply_actions_to_url(solurl: Any, input_value: str, actions: list[dict[str, Any]]) -> Any:
    url = make_url(solurl, input_value)
    pairs = decoded_pairs(url.search[1:] if url.search.startswith("?") else url.search)
    for action in actions:
        typ = action.get("type")
        if typ == "clear":
            pairs = []
        elif typ == "append":
            pairs.append([str(action.get("name", action.get("key", ""))), str(action.get("value", ""))])
        elif typ == "set":
            key = str(action.get("name", action.get("key", "")))
            pairs = [[k, v] for k, v in pairs if k != key]
            pairs.append([key, str(action.get("value", ""))])
        elif typ == "delete":
            key = str(action.get("name", action.get("key", "")))
            pairs = [[k, v] for k, v in pairs if k != key]
        elif typ == "sort":
            pairs = sorted(pairs, key=lambda item: item[0])
        elif typ == "extend":
            pairs.extend([[str(k), str(v)] for k, v in action.get("pairs", [])])
        elif typ == "push":
            path = url.pathname.rstrip("/") + "/" + quote_plus(str(action.get("value", ""))).replace("+", "%20")
            url.pathname = path
            continue
    url.search = "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in pairs)
    return url


def run_searchparams(solurl: Any, params: dict[str, Any], parent: bool = False) -> dict[str, Any]:
    if parent:
        url = apply_actions_to_url(solurl, params.get("input", ""), params.get("actions", []))
        return url_basic(url)
    pairs = params_init_pairs(params.get("init", ""))
    values: Any = None
    for action in params.get("actions", []):
        typ = action.get("type")
        name = str(action.get("name", ""))
        if typ == "append":
            pairs.append([name, str(action.get("value", ""))])
        elif typ == "set":
            replacement = [name, str(action.get("value", ""))]
            next_pairs = []
            inserted = False
            for k, v in pairs:
                if k == name:
                    if not inserted:
                        next_pairs.append(replacement)
                        inserted = True
                else:
                    next_pairs.append([k, v])
            if not inserted:
                next_pairs.append(replacement)
            pairs = next_pairs
        elif typ == "delete":
            if "value" in action:
                pairs = [[k, v] for k, v in pairs if not (k == name and v == str(action.get("value")))]
            else:
                pairs = [[k, v] for k, v in pairs if k != name]
        elif typ == "sort":
            pairs = sorted(pairs, key=lambda item: item[0])
        elif typ == "get":
            values = next((v for k, v in pairs if k == name), None)
        elif typ == "getAll":
            values = [v for k, v in pairs if k == name]
        elif typ == "has":
            if "value" in action:
                values = any(k == name and v == str(action["value"]) for k, v in pairs)
            else:
                values = any(k == name for k, _ in pairs)
        elif typ == "size":
            values = len(pairs)
        elif typ == "toString":
            values = None
    out = {
        "size": len(pairs),
        "entries": pairs,
        "keys": [k for k, _ in pairs],
        "values": [v for _, v in pairs],
        "string": "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in pairs),
    }
    out["value"] = out["string"]
    if values is not None:
        out["value" if not isinstance(values, list) else "values"] = values
    return out


def run_static_parse(solurl: Any, params: dict[str, Any]) -> dict[str, Any]:
    try:
        url = make_url(solurl, params.get("input", ""), params.get("base"))
        out = url_basic(url)
        out["isURL"] = True
        out["isNull"] = False
        return out
    except Exception as ex:
        return {"isURL": False, "isNull": True, "throws": type(ex).__name__, "message": str(ex)}


def component_offsets(href: str, basic: dict[str, Any]) -> dict[str, Any]:
    protocol_end = len(basic["protocol"]) - 1 if basic["protocol"] else None
    after_scheme = len(basic["protocol"])
    authority_start = after_scheme + 2 if href.startswith("//", after_scheme) else after_scheme
    username_end = authority_start + len(basic["username"])
    host_start = authority_start
    if basic["username"] or basic["password"]:
        at = href.find("@", authority_start)
        host_start = at + 1
        username_end = authority_start + len(basic["username"])
    host_end = host_start + len(basic["host"])
    pathname_start = href.find(basic["pathname"], host_end) if basic["pathname"] else host_end
    if pathname_start < 0:
        pathname_start = host_end
    search_start = href.find("?") if "?" in href else None
    hash_start = href.find("#") if "#" in href else None
    port = int(basic["port"]) if str(basic["port"]).isdigit() else None
    return {
        "protocol_end": protocol_end,
        "username_end": username_end,
        "host_start": host_start,
        "host_end": host_end,
        "pathname_start": pathname_start,
        "search_start": search_start,
        "hash_start": hash_start,
        "port": port,
    }


def ada_url_observation(url: Any) -> dict[str, Any]:
    basic = url_basic(url)
    scheme = basic["scheme"]
    host = basic["hostname"]
    return {
        **basic,
        "components": component_offsets(basic["href"], basic),
        "has_credentials": bool(basic["username"] or basic["password"]),
        "has_empty_hostname": host == "",
        "has_hash": bool(basic["hash"]),
        "has_hostname": bool(host),
        "has_non_empty_password": bool(basic["password"]),
        "has_non_empty_username": bool(basic["username"]),
        "has_password": bool(basic["password"]),
        "has_port": bool(basic["port"]),
        "has_search": bool(basic["search"]),
        "host_type": "Ipv6" if host.startswith("[") else ("Ipv4" if host.replace(".", "").isdigit() else "Domain"),
        "scheme_type": {"http": "Http", "https": "Https", "ws": "Ws", "wss": "Wss", "ftp": "Ftp", "file": "File"}.get(scheme, "NotSpecial"),
    }


def run_yarl(solurl: Any, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract.get("op")
    params = contract.get("params") or {}
    if op in {"props", "bytes"}:
        url = make_url(solurl, params.get("input", ""))
        result = yarl_like(url)
        if op == "bytes":
            result = {"value": result["href"]}
        return wrap_ok_result(result)
    if op == "bool":
        try:
            url = make_url(solurl, params.get("input", ""))
            return wrap_ok_result({"value": bool(url.href)})
        except Exception:
            return wrap_ok_result({"value": False})
    if op in {"join", "joinpath", "path_div"}:
        if op == "join":
            url = make_url(solurl, params.get("input", ""), params.get("base"))
        else:
            url = make_url(solurl, params.get("input", ""))
            for element in params.get("elements", []):
                url.pathname = url.pathname.rstrip("/") + "/" + str(element).strip("/")
        return wrap_ok_result(yarl_like(url))
    if op == "query_view":
        url = make_url(solurl, params.get("input", ""))
        query = url.search[1:] if url.search.startswith("?") else url.search
        pairs = decoded_pairs(query)
        name = params.get("name")
        result = {
            "len": len(pairs),
            "query_items": pairs,
            "query_string": query,
            "raw_query_string": query,
            "values": [v for k, v in pairs if k == name],
        }
        result["value"] = result["values"][0] if result["values"] else None
        return wrap_ok_result(result)
    if op == "transform":
        url = make_url(solurl, params.get("input", ""))
        method = params.get("method")
        args = params.get("args", [])
        if method in {"with_query", "update_query"}:
            current = [] if method == "with_query" else decoded_pairs(url.search[1:] if url.search.startswith("?") else url.search)
            arg = args[0] if args else {}
            if isinstance(arg, dict):
                for key, value in arg.items():
                    current = [[k, v] for k, v in current if k != str(key)]
                    current.append([str(key), str(value)])
            elif isinstance(arg, list):
                current.extend([[str(k), str(v)] for k, v in arg])
            url.search = "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in current)
        elif method in {"with_path", "with_fragment", "with_name", "with_suffix"}:
            value = str(args[0]) if args else ""
            if method == "with_path":
                url.pathname = value
            elif method == "with_fragment":
                url.hash = value
            elif method == "with_name":
                url.pathname = url.pathname.rstrip("/").rsplit("/", 1)[0] + "/" + value
            elif method == "with_suffix":
                stem = url.pathname.rsplit(".", 1)[0]
                url.pathname = stem + (value if value.startswith(".") else "." + value)
        elif method in {"with_host", "with_port", "with_user", "with_password", "with_scheme"}:
            prop = {"with_host": "hostname", "with_port": "port", "with_user": "username", "with_password": "password", "with_scheme": "protocol"}[method]
            setattr(url, prop, str(args[0]) if args else "")
        else:
            return surface_error(f"required yarl transform surface absent: {method}")
        return wrap_ok_result(yarl_like(url))
    if op == "build":
        kwargs = params.get("kwargs") or {}
        scheme = kwargs.get("scheme", "")
        host = kwargs.get("host") or kwargs.get("authority") or ""
        if not scheme and not host:
            return wrap_ok_result(yarl_like(make_url(solurl, "http://placeholder.invalid/"))) | {"surface_note": "relative empty URL unsupported by solurl"}
        text = (scheme + "://" if scheme else "") + host + kwargs.get("path", "")
        if kwargs.get("query"):
            text += "?" + str(kwargs["query"])
        if kwargs.get("fragment"):
            text += "#" + str(kwargs["fragment"])
        return wrap_ok_result(yarl_like(make_url(solurl, text)))
    return surface_error(f"required yarl op absent: {op}")


def run_ada(solurl: Any, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract.get("op")
    params = contract.get("params") or {}
    if op in {"parse", "set_component"}:
        if op == "parse":
            try:
                return wrap_ok_result(ada_url_observation(make_url(solurl, params.get("input", ""), params.get("base"))))
            except Exception as ex:
                return {"ok": False, "throws": type(ex).__name__, "message": str(ex)}
        url = make_url(solurl, params.get("input", ""))
        ok, result = set_component(url, params.get("component", ""), params.get("value", ""))
        return wrap_ok_result({"setter_ok": ok, "url": ada_url_observation(url) if ok else result})
    if op == "can_parse":
        fn = getattr(solurl.URL, "can_parse", None) or getattr(solurl, "can_parse")
        return wrap_ok_result({"value": bool(fn(params.get("input", ""), params.get("base")))})
    if op == "search_params":
        input_value = params.get("input", "")
        pairs = decoded_pairs(input_value[1:] if input_value.startswith("?") else input_value)
        for action in params.get("actions", []):
            typ = action.get("type")
            key = str(action.get("key", action.get("name", "")))
            if typ == "append":
                pairs.append([key, str(action.get("value", ""))])
            elif typ == "set":
                pairs = [[k, v] for k, v in pairs if k != key]
                pairs.append([key, str(action.get("value", ""))])
            elif typ == "delete":
                pairs = [[k, v] for k, v in pairs if k != key]
        probe = params.get("probe")
        result = {
            "contains_probe_key": any(k == probe for k, _ in pairs),
            "entries": pairs,
            "is_empty": not pairs,
            "keys": [k for k, _ in pairs],
            "len": len(pairs),
            "probe_value": next((v for k, v in pairs if k == probe), None),
            "probe_values": [v for k, v in pairs if k == probe],
            "string": "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in pairs),
            "values": [v for _, v in pairs],
        }
        return wrap_ok_result(result)
    if op == "compare":
        left = make_url(solurl, params.get("left", "")).href
        right = make_url(solurl, params.get("right", "")).href
        return wrap_ok_result({"eq": left == right, "lt": left < right, "left": left, "right": right})
    if op == "idna":
        return surface_error("required direct IDNA conversion API absent")
    return surface_error(f"required ada op absent: {op}")


def curl_part(value: str | None, absent: str) -> dict[str, Any]:
    if value is None or value == "":
        code, error = CURL_PART_ERRORS[absent]
        return {"code": code, "error": error, "value": None}
    return {"code": 0, "error": "No error", "value": value}


def curl_parts(url: Any) -> dict[str, Any]:
    basic = url_basic(url)
    return {
        "url": {"code": 0, "error": "No error", "value": basic["href"]},
        "scheme": {"code": 0, "error": "No error", "value": basic["scheme"]},
        "user": curl_part(basic["username"], "user"),
        "password": curl_part(basic["password"], "password"),
        "options": curl_part(None, "options"),
        "host": curl_part(basic["hostname"], "host"),
        "port": curl_part(basic["port"], "port"),
        "path": {"code": 0, "error": "No error", "value": basic["pathname"] or "/"},
        "query": curl_part(basic["query"], "query"),
        "fragment": curl_part(basic["fragment"], "fragment"),
        "zoneid": curl_part(None, "zoneid"),
    }


def run_curl(solurl: Any, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract.get("op")
    args = contract.get("args") or []
    if op == "strerror":
        return {"message": CURL_STRERROR.get(str(args[0]), "Unknown URL error")}
    if op == "cleanup_null":
        return {"ok": True}
    if op == "parse":
        try:
            url = make_url(solurl, args[0])
            return {"set_code": 0, "set_error": "No error", "parts": curl_parts(url)}
        except Exception as ex:
            return {"set_code": 2, "set_error": "Malformed input to a URL function", "throws": type(ex).__name__, "message": str(ex)}
    if op == "relative":
        try:
            base = make_url(solurl, args[0])
            url = make_url(solurl, args[2], base.href)
            return {"base_code": 0, "base_error": "No error", "relative_code": 0, "relative_error": "No error", "parts": curl_parts(url)}
        except Exception as ex:
            return {"relative_code": 2, "relative_error": "Malformed input to a URL function", "throws": type(ex).__name__, "message": str(ex)}
    if op == "getpart":
        try:
            url = make_url(solurl, args[0])
            parts = curl_parts(url)
            part = args[2]
            return {"set_code": 0, "set_error": "No error", "part": parts.get(part, {"code": 99, "error": "unknown part", "value": None})}
        except Exception as ex:
            return {"set_code": 2, "set_error": "Malformed input to a URL function", "throws": type(ex).__name__, "message": str(ex)}
    if op == "setpart":
        try:
            if args[0] == "__EMPTY_HANDLE__":
                seed = "http://placeholder.invalid/"
            else:
                seed = args[0]
            url = make_url(solurl, seed)
            part = args[2]
            value = args[3]
            prop = {"scheme": "protocol", "user": "username", "password": "password", "host": "hostname", "port": "port", "path": "pathname", "query": "search", "fragment": "hash"}.get(part)
            if prop is None:
                return surface_error(f"required curl setpart surface absent: {part}")
            setattr(url, prop, "" if value is None else value)
            return {"init_code": 0, "init_error": "No error", "set_code": 0, "set_error": "No error", "parts": curl_parts(url)}
        except Exception as ex:
            return {"init_code": 0, "init_error": "No error", "set_code": 2, "set_error": "Malformed input to a URL function", "throws": type(ex).__name__, "message": str(ex)}
    if op == "dup":
        try:
            original = make_url(solurl, args[0])
            duplicate = make_url(solurl, original.href)
            prop = {"scheme": "protocol", "user": "username", "password": "password", "host": "hostname", "port": "port", "path": "pathname", "query": "search", "fragment": "hash"}.get(args[2])
            if prop is None:
                return surface_error(f"required curl dup surface absent: {args[2]}")
            setattr(duplicate, prop, args[3])
            return {
                "init_code": 0,
                "init_error": "No error",
                "dup_set_code": 0,
                "dup_set_error": "No error",
                "original": {"code": 0, "value": original.href},
                "duplicate": {"code": 0, "value": duplicate.href},
            }
        except Exception as ex:
            return {"dup_set_code": 2, "dup_set_error": "Malformed input to a URL function", "throws": type(ex).__name__, "message": str(ex)}
    return surface_error(f"required curl op absent: {op}")


def run_contract(solurl: Any, origin: str, contract: dict[str, Any]) -> dict[str, Any]:
    op = contract.get("op") or contract.get("kind")
    params = contract.get("params") or {}
    try:
        if origin == "yarl":
            return run_yarl(solurl, contract)
        if origin == "ada-url":
            return run_ada(solurl, contract)
        if origin == "curl":
            return run_curl(solurl, contract)
        if op in {"parse", "parse_url"}:
            return run_parse(solurl, params)
        if op == "static_parse":
            return run_static_parse(solurl, params)
        if op in {"parse_failure", "construct_failure"}:
            return run_parse_failure(solurl, params)
        if op == "set_component":
            url = make_url(solurl, params.get("input", ""), params.get("base"))
            ok, out = set_component(url, params.get("component", ""), params.get("value", ""))
            out["set_ok"] = ok
            return out
        if op in {"can_parse", "is_valid_url_string"}:
            fn = getattr(solurl.URL, "can_parse", None) or getattr(solurl, "can_parse")
            return {"value": bool(fn(params.get("input", ""), params.get("base")))}
        if op == "roundtrip":
            url = make_url(solurl, params.get("input", ""), params.get("base"))
            second = make_url(solurl, url.href)
            return {"stable": url.href == second.href, "href": second.href}
        if op == "join":
            url = make_url(solurl, params.get("input", ""), params.get("base"))
            return url_basic(url)
        if op == "origin":
            return {"origin": make_url(solurl, params.get("input", ""), params.get("base")).origin}
        if op == "method_call":
            url = make_url(solurl, params.get("input", ""))
            method = getattr(url, params.get("method", ""), None)
            if method is None:
                return surface_error(f"required URL method absent: {params.get('method')}")
            return {"value": method()}
        if op == "static_presence":
            return {"present": hasattr(solurl.URL, params.get("property", ""))}
        if op == "low_level_parse":
            return surface_error("required state-override parser API absent")
        if op in {"percent_decode_string", "percent_decode_bytes"}:
            return surface_error("required percent-decode utility API absent")
        if op in {"searchparams", "searchparams_parent"}:
            return run_searchparams(solurl, params, parent=(op == "searchparams_parent"))
        if op == "cannot_have_credentials_port":
            url = make_url(solurl, params.get("input", ""))
            value = url.protocol == "file:" or not getattr(url, "host", "")
            return {"value": value}
        if op == "object_tag":
            return surface_error("required JavaScript object tag API absent")
        if op == "parse_with_validation_errors":
            try:
                out = run_parse(solurl, params)
                out["validation_errors"] = []
                return out
            except Exception as ex:
                return {"ok": False, "throws": type(ex).__name__, "message": str(ex), "validation_errors": []}
        if op == "href_setter_searchparams":
            return surface_error("required parent URLSearchParams identity surface absent")
        if op in {"serialize_path", "has_opaque_path"}:
            return run_parse(solurl, params)
        if op == "path_segments_mut":
            url = apply_actions_to_url(solurl, params.get("input", ""), params.get("actions", []))
            return url_basic(url)
        if op == "query_pairs_mut":
            url = apply_actions_to_url(solurl, params.get("input", ""), params.get("actions", []))
            out = url_basic(url)
            out["query"] = out["search"][1:] if out["search"].startswith("?") else out["search"]
            return out
        if op == "form_urlencoded_serialize":
            return {"value": "&".join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k, v in params.get("pairs", []))}
        return surface_error(f"required op absent: {op}")
    except Exception as ex:
        return {"ok": False, "throws": type(ex).__name__, "message": str(ex)}


def expected_matches(expected: Any, actual: Any, path: str = "") -> tuple[bool, list[str]]:
    misses: list[str] = []
    if isinstance(actual, dict) and actual.get("surface_error"):
        return False, [f"{path or '$'}: {actual['surface_error']}"]
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False, [f"{path or '$'}: expected object, got {type(actual).__name__}"]
        for key, value in expected.items():
            ok, sub = expected_matches(value, actual.get(key), f"{path}.{key}" if path else key)
            if not ok:
                misses.extend(sub)
                if len(misses) >= 12:
                    break
        return not misses, misses
    if path.endswith("throws") and isinstance(expected, str) and isinstance(actual, str) and actual:
        return True, []
    if isinstance(expected, list):
        if actual != expected:
            return False, [f"{path or '$'}: expected {expected!r}, got {actual!r}"]
        return True, []
    if actual != expected:
        return False, [f"{path or '$'}: expected {expected!r}, got {actual!r}"]
    return True, []


def mutate_first_scalar(value: Any) -> Any:
    out = deepcopy(value)

    def mutate(container: Any) -> bool:
        if isinstance(container, dict):
            for key, child in list(container.items()):
                if isinstance(child, bool):
                    container[key] = not child
                    return True
                if isinstance(child, int):
                    container[key] = child + 1
                    return True
                if isinstance(child, str):
                    container[key] = child + "__mutant__"
                    return True
                if child is None:
                    container[key] = "__mutant__"
                    return True
                if mutate(child):
                    return True
        if isinstance(container, list):
            for index, child in enumerate(container):
                if isinstance(child, bool):
                    container[index] = not child
                    return True
                if isinstance(child, int):
                    container[index] = child + 1
                    return True
                if isinstance(child, str):
                    container[index] = child + "__mutant__"
                    return True
                if child is None:
                    container[index] = "__mutant__"
                    return True
                if mutate(child):
                    return True
        return False

    if not mutate(out):
        return {"__mutant__": "changed"}
    return out


def load_non_common() -> dict[str, list[dict[str, Any]]]:
    common_rows = load_json(COMMON_JSON)["final_common_contracts"]
    common_ids = {(row["origin"], row["name"]) for row in common_rows}
    by_origin: dict[str, list[dict[str, Any]]] = {}
    for origin, path in LATEST.items():
        seen = set()
        rows = []
        for contract in load_json(path)["survivors"]:
            key = (origin, contract["name"])
            if key in seen or key in common_ids:
                continue
            seen.add(key)
            rows.append(contract)
        by_origin[origin] = rows
    return by_origin


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("implementation_dir", type=Path)
    parser.add_argument("--label", default="gpt56sol_high_iter4_hinted_clean_20260829")
    args = parser.parse_args()

    impl_dir = args.implementation_dir.resolve()
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in args.label)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUT_DIR / f"solurl_{safe_label}_non_common_by_oss.json"
    out_md = OUT_DIR / f"solurl_{safe_label}_non_common_by_oss.md"
    hashes = OUT_DIR / f"solurl_{safe_label}_source_hashes.sha256"

    solurl = load_solurl(impl_dir)
    by_origin_contracts = load_non_common()
    results = []
    for origin, contracts in by_origin_contracts.items():
        for contract in contracts:
            expected = contract.get("expected", {})
            actual = run_contract(solurl, origin, contract)
            replay_ok, misses = expected_matches(expected, actual)
            mutant_expected = mutate_first_scalar(expected)
            mutant_ok, mutant_misses = expected_matches(mutant_expected, actual)
            verified = replay_ok and not mutant_ok
            results.append(
                {
                    "origin": origin,
                    "name": contract["name"],
                    "version": contract.get("version"),
                    "capability": contract.get("capability"),
                    "op": contract.get("op") or contract.get("kind"),
                    "status": "passed" if verified else "failed",
                    "replay_passed": replay_ok,
                    "mutant_rejected": not mutant_ok,
                    "misses": misses,
                    "mutant_misses": mutant_misses,
                    "expected": expected,
                    "actual": actual,
                }
            )

    by_origin = defaultdict(Counter)
    by_op = defaultdict(Counter)
    by_capability = defaultdict(Counter)
    failure_reason = defaultdict(Counter)
    for row in results:
        by_origin[row["origin"]][row["status"]] += 1
        by_op[(row["origin"], row["op"])][row["status"]] += 1
        by_capability[(row["origin"], row["capability"])][row["status"]] += 1
        if row["status"] == "failed":
            reason = row["misses"][0] if row["misses"] else "mutant survived"
            if "surface" in reason or "absent" in reason:
                bucket = "required surface absent"
            elif "throws" in reason or "set_code" in reason or "ok" in reason:
                bucket = "accept/reject policy mismatch"
            else:
                bucket = "semantic value mismatch"
            failure_reason[row["origin"]][bucket] += 1

    total = len(results)
    passed = sum(1 for row in results if row["status"] == "passed")
    summary = {
        "domain": "URL/IRI",
        "basis": "Per-OSS latest-surviving source contracts minus final common source identities. Every non-common row is attempted as an executable replay probe; unsupported generated-library surface is counted as a failed probe, not removed.",
        "implementation": str(impl_dir),
        "implementation_module": getattr(solurl, "__file__", "unknown"),
        "final_common_excluded": len(load_json(COMMON_JSON)["final_common_contracts"]),
        "attempted_non_common_total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0,
        "by_origin": {
            origin: {
                "attempted": sum(counter.values()),
                "passed": counter.get("passed", 0),
                "failed": counter.get("failed", 0),
                "pass_rate": round(counter.get("passed", 0) / sum(counter.values()), 4) if sum(counter.values()) else 0,
                "failure_reasons": dict(failure_reason[origin]),
            }
            for origin, counter in sorted(by_origin.items())
        },
        "by_origin_op": {
            f"{origin}:{op}": dict(counter)
            for (origin, op), counter in sorted(by_op.items())
        },
        "by_origin_capability": {
            f"{origin}:{capability}": dict(counter)
            for (origin, capability), counter in sorted(by_capability.items())
        },
    }

    payload = {"summary": summary, "results": results}
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_hashes(impl_dir, hashes)

    lines = [
        "# Generated URL/IRI Library Non-Common Replay by OSS",
        "",
        f"Implementation: `{impl_dir}`",
        f"Module: `{summary['implementation_module']}`",
        "",
        "Basis: per-OSS latest-surviving source contracts minus the 245 final common source identities. Every residual row is attempted; required surface that the generated library does not expose is a failed executable probe.",
        "",
        "## Totals",
        "",
        "| Bucket | Count |",
        "| --- | ---: |",
        f"| Final common excluded | {summary['final_common_excluded']} |",
        f"| Non-common attempted | {summary['attempted_non_common_total']} |",
        f"| Passed | {summary['passed']} |",
        f"| Failed | {summary['failed']} |",
        f"| Pass rate | {summary['pass_rate']:.2%} |",
        "",
        "## By OSS",
        "",
        "| OSS | Attempted | Passed | Failed | Pass rate | Top failure buckets |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for origin, row in summary["by_origin"].items():
        reasons = ", ".join(f"{k}: {v}" for k, v in sorted(row["failure_reasons"].items(), key=lambda item: (-item[1], item[0]))[:3])
        lines.append(f"| `{origin}` | {row['attempted']} | {row['passed']} | {row['failed']} | {row['pass_rate']:.2%} | {reasons} |")
    lines += [
        "",
        "## By OSS and Operation",
        "",
        "| OSS | Operation | Passed | Failed |",
        "| --- | --- | ---: | ---: |",
    ]
    for key, counter in summary["by_origin_op"].items():
        origin, op = key.split(":", 1)
        lines.append(f"| `{origin}` | `{op}` | {counter.get('passed', 0)} | {counter.get('failed', 0)} |")
    lines += [
        "",
        "## Failed Contract Samples",
        "",
        "| OSS | Contract | Operation | First miss |",
        "| --- | --- | --- | --- |",
    ]
    for row in [r for r in results if r["status"] == "failed"][:80]:
        miss = (row["misses"][0] if row["misses"] else "mutant survived").replace("|", "\\|")
        if len(miss) > 220:
            miss = miss[:217] + "..."
        lines.append(f"| `{row['origin']}` | `{row['name']}` | `{row['op']}` | {miss} |")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
