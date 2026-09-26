#!/usr/bin/env python3
"""Executable target-native probe for semantic HTTP extension primitives."""

from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
import re
import sys
from pathlib import Path
from typing import Any


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def public_surface(module: Any) -> dict[str, list[str]]:
    names: set[str] = set()
    signatures: set[str] = set()
    parameters: set[str] = set()
    paths: set[str] = set()
    sources: set[str] = set()
    queue = [(module.__name__, module)]
    seen: set[int] = set()
    while queue:
        owner, value = queue.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        for name in dir(value):
            if name.startswith("_"):
                continue
            names.add(normalize(name))
            paths.add(normalize(f"{owner}.{name}"))
            child = getattr(value, name, None)
            if child is None:
                continue
            if inspect.isclass(child) and getattr(child, "__module__", "").startswith(module.__name__):
                queue.append((f"{owner}.{name}", child))
            if callable(child):
                try:
                    signature = inspect.signature(child)
                    signatures.add(normalize(f"{owner}.{name} {signature}"))
                    parameters.update(normalize(parameter) for parameter in signature.parameters)
                except (TypeError, ValueError):
                    pass
    root = Path(inspect.getfile(module)).parent
    for path in root.glob("*.py"):
        sources.add(normalize(path.read_text(errors="ignore")))
    return {
        "public_names": sorted(names),
        "public_signatures": sorted(signatures),
        "public_parameters": sorted(parameters),
        "public_paths": sorted(paths),
        "package_source_tokens": sorted(set("_".join(sources).split("_"))),
        "package_files": sorted(str(path) for path in root.glob("*.py")),
        "dependencies": sorted(item.name for item in pkgutil.iter_modules() if item.name in {"h2", "httpx", "websockets", "wsproto", "requests_cache"}),
    }


def detect(surface: dict[str, list[str]], aliases: list[str]) -> dict[str, Any]:
    haystacks = {
        "public_name": set(surface["public_names"]),
        "public_parameter": set(surface.get("public_parameters", [])),
        "public_path": set(surface.get("public_paths", [])),
    }
    matches = []
    for alias in aliases:
        token = normalize(alias)
        for location, values in haystacks.items():
            path_suffix = re.compile(rf"(?:^|_){re.escape(token)}$")
            if token in values or any(path_suffix.search(value) for value in values if location == "public_path"):
                matches.append({"alias": alias, "location": location})
    return {"present": bool(matches), "matches": matches}


def native_resolution_attempts(module: Any, aliases: list[str]) -> list[dict[str, Any]]:
    """Resolve and, where possible, invoke exact public candidate interfaces."""
    attempts = []
    public = {normalize(name): (name, getattr(module, name)) for name in dir(module) if not name.startswith("_")}
    for alias in dict.fromkeys(aliases):
        token = normalize(alias)
        item = {"interface": alias, "resolved": False, "invoked": False, "accepted": False}
        candidate = public.get(token)
        if candidate is None:
            attempts.append(item)
            continue
        real_name, value = candidate
        item.update({"resolved": True, "resolved_name": real_name, "kind": type(value).__name__})
        if not callable(value):
            attempts.append(item)
            continue
        try:
            signature = inspect.signature(value)
            required = [parameter for parameter in signature.parameters.values()
                        if parameter.default is inspect.Parameter.empty
                        and parameter.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}]
            args = []
            for parameter in required:
                name = normalize(parameter.name)
                if name in {"url", "uri", "request_url"}:
                    args.append("http://127.0.0.1:1/")
                elif name in {"method", "http_method"}:
                    args.append("GET")
                elif name in {"headers"}:
                    args.append({})
                else:
                    args.append(None)
            result = value(*args)
            item.update({"invoked": True, "accepted": True, "result_type": type(result).__name__})
            close = getattr(result, "close", None)
            if callable(close):
                close()
        except Exception as exc:
            item.update({"invoked": True, "exception": type(exc).__name__, "message": str(exc)[:500]})
        attempts.append(item)
    return attempts


def target_positive_control(module: Any) -> dict[str, Any]:
    try:
        client = module.Client()
        close = getattr(client, "close", None)
        if callable(close):
            close()
        return {"passed": True, "operation": "Client construction and close", "client_type": type(client).__name__}
    except Exception as exc:
        return {"passed": False, "operation": "Client construction and close",
                "exception": type(exc).__name__, "message": str(exc)[:500]}


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: probe_solhttp_surface.py SNAPSHOT PROJECTION_JSON")
    snapshot = Path(sys.argv[1]).resolve()
    projection = json.loads(sys.argv[2])
    sys.path.insert(0, str(snapshot))
    module = importlib.import_module("solhttp")
    surface = public_surface(module)
    actual = detect(surface, projection["equivalent_native_interfaces"])

    print(json.dumps({
        "target": "solhttp",
        "target_version": getattr(module, "__version__", "unknown"),
        "required_semantic_primitive": projection["required_semantic_primitive"],
        "equivalent_native_interfaces_checked": projection["equivalent_native_interfaces"],
        "probe_observation": actual,
        "target_native_attempts": native_resolution_attempts(module, projection["equivalent_native_interfaces"]),
        "positive_control": target_positive_control(module),
        "surface": surface,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
