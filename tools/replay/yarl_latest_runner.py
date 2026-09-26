#!/usr/bin/env python3
"""Execute replayable yarl URL/IRI contracts against an installed yarl."""

from __future__ import annotations

import json
import math
import sys
from typing import Any

from yarl import URL

try:
    from yarl import quote, unquote
except ImportError:  # pragma: no cover - old yarl compatibility
    quote = None
    unquote = None


def special(value: Any) -> Any:
    if isinstance(value, dict) and "__special__" in value:
        name = value["__special__"]
        if name == "nan":
            return float("nan")
        if name == "inf":
            return float("inf")
        if name == "ninf":
            return float("-inf")
        if name == "bytes":
            return value.get("value", "").encode(value.get("encoding", "utf-8"))
        if name == "bytearray":
            return bytearray(value.get("value", "").encode(value.get("encoding", "utf-8")))
        if name == "memoryview":
            return memoryview(value.get("value", "").encode(value.get("encoding", "utf-8")))
        if name == "intlike":
            class IntLike:
                def __int__(self) -> int:
                    return int(value["value"])

            return IntLike()
    if isinstance(value, list):
        return [special(item) for item in value]
    if isinstance(value, dict):
        return {key: special(item) for key, item in value.items()}
    return value


def make_url(params: dict[str, Any]) -> URL:
    if "input" not in params:
        return URL()
    kwargs: dict[str, Any] = {}
    if "encoded" in params:
        kwargs["encoded"] = params["encoded"]
    return URL(special(params["input"]), **kwargs)


def props(url: URL) -> dict[str, Any]:
    out: dict[str, Any] = {
        "str": str(url),
        "repr": repr(url),
        "scheme": url.scheme,
        "raw_user": url.raw_user,
        "user": url.user,
        "raw_password": url.raw_password,
        "password": url.password,
        "raw_host": url.raw_host,
        "host": url.host,
        "port": url.port,
        "explicit_port": url.explicit_port,
        "raw_path": url.raw_path,
        "path": url.path,
        "path_safe": url.path_safe,
        "raw_query_string": url.raw_query_string,
        "query_string": url.query_string,
        "fragment": url.fragment,
        "raw_fragment": url.raw_fragment,
        "parts": list(url.parts),
        "raw_parts": list(url.raw_parts),
        "parent": str(url.parent),
        "name": url.name,
        "raw_name": url.raw_name,
        "suffix": url.suffix,
        "raw_suffix": url.raw_suffix,
        "suffixes": list(url.suffixes),
        "raw_suffixes": list(url.raw_suffixes),
        "path_qs": url.path_qs,
        "raw_path_qs": url.raw_path_qs,
        "authority": url.authority,
        "raw_authority": url.raw_authority,
        "host_subcomponent": url.host_subcomponent,
        "host_port_subcomponent": url.host_port_subcomponent,
        "absolute": url.absolute,
        "is_absolute": url.is_absolute(),
        "is_default_port": url.is_default_port(),
        "human_repr": url.human_repr(),
        "query_items": list(url.query.items()),
    }
    for method in ("origin", "relative"):
        try:
            out[method] = str(getattr(url, method)())
        except Exception as exc:  # noqa: BLE001 - replay surface includes failures
            out[f"{method}_throws"] = type(exc).__name__
    return out


def execute(contract: dict[str, Any]) -> dict[str, Any]:
    op = contract["op"]
    p = contract.get("params") or {}

    if op == "props":
        return props(make_url(p))
    if op == "build":
        kwargs = special(p.get("kwargs", {}))
        return props(URL.build(**kwargs))
    if op == "transform":
        url = make_url(p)
        method = getattr(url, p["method"])
        args = special(p.get("args", []))
        kwargs = special(p.get("kwargs", {}))
        result = method(*args, **kwargs)
        if isinstance(result, URL):
            return props(result)
        return {"value": result}
    if op == "join":
        base = URL(p["base"])
        other_kwargs = {"encoded": p["other_encoded"]} if "other_encoded" in p else {}
        return props(base.join(URL(p["input"], **other_kwargs)))
    if op == "joinpath":
        url = make_url(p)
        return props(url.joinpath(*special(p.get("elements", [])), **special(p.get("kwargs", {}))))
    if op == "path_div":
        url = make_url(p)
        for element in special(p.get("elements", [])):
            url = url / element
        return props(url)
    if op == "mod_query":
        return props(make_url(p) % special(p.get("query")))
    if op == "query_view":
        url = make_url(p)
        name = p.get("name")
        result: dict[str, Any] = {
            "query_items": list(url.query.items()),
            "query_string": url.query_string,
            "raw_query_string": url.raw_query_string,
            "len": len(url.query),
        }
        if name is not None:
            result["value"] = url.query.get(name)
            result["values"] = url.query.getall(name, [])
        return result
    if op == "bytes":
        return {"value": bytes(make_url(p)).decode("ascii")}
    if op == "bool":
        return {"value": bool(make_url(p))}
    if op == "quote":
        if quote is None:
            raise RuntimeError("yarl.quote is unavailable")
        return {"value": quote(special(p.get("value", "")), **special(p.get("kwargs", {})))}
    if op == "unquote":
        if unquote is None:
            raise RuntimeError("yarl.unquote is unavailable")
        return {"value": unquote(special(p.get("value", "")), **special(p.get("kwargs", {})))}
    raise RuntimeError(f"unsupported op {op}")


def normalize(value: Any) -> Any:
    if isinstance(value, float) and math.isnan(value):
        return "__NaN__"
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    return value


def run(contract: dict[str, Any]) -> dict[str, Any]:
    try:
        return {"ok": True, "result": normalize(execute(contract))}
    except Exception as exc:  # noqa: BLE001 - replay needs exception shape
        return {
            "ok": False,
            "throws": type(exc).__name__,
            "message": str(exc),
        }


def main() -> None:
    contract = json.loads(sys.stdin.read())
    print(json.dumps(run(contract), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
