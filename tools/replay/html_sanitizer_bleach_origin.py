#!/usr/bin/env python3
"""Extract and verify mozilla/bleach origin HTML sanitizer contracts."""

from __future__ import annotations

import ast
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "html_sanitizer" / "bleach"
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "bleach"
COMMON_JSON = ROOT / "contracts" / "html_sanitizer" / "common" / "rank1_2_3_cross_replay_common_filtered_by_rank4_5.json"
PYTHON = Path(sys.executable)
TARGET = ROOT / ".cache" / "runtime" / "html-sanitizer-bleach-latest"
PYPI = "https://pypi.org/pypi/bleach/json"


def version_key(version: str) -> tuple[Any, ...]:
    text = version.removeprefix("v").replace("rc", ".rc.")
    out: list[Any] = []
    for part in re.findall(r"\d+|[a-zA-Z]+", text):
        out.append(int(part) if part.isdigit() else part)
    return tuple(out)


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, env=env, text=True, stderr=subprocess.STDOUT)


def ensure_repo() -> None:
    if REPO.exists():
        run(["git", "-C", str(REPO), "fetch", "--tags", "--quiet"])
    else:
        REPO.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "https://github.com/mozilla/bleach.git", str(REPO)])


def pypi_metadata() -> dict[str, Any]:
    with urllib.request.urlopen(PYPI, timeout=30) as response:
        return json.load(response)


def git_tags() -> set[str]:
    return {line.strip() for line in run(["git", "-C", str(REPO), "tag", "--list"]).splitlines() if line.strip()}


def tag_for(version: str, tags: set[str]) -> str | None:
    candidates = [version, f"v{version}"]
    for candidate in candidates:
        if candidate in tags:
            return candidate
    return None


def git_show(tag: str, path: str) -> str | None:
    try:
        return run(["git", "-C", str(REPO), "show", f"{tag}:{path}"])
    except subprocess.CalledProcessError:
        return None


def list_tree(tag: str, path: str) -> list[str]:
    try:
        out = run(["git", "-C", str(REPO), "ls-tree", "-r", "--name-only", tag, path])
    except subprocess.CalledProcessError:
        return []
    return [line for line in out.splitlines() if line.strip()]


def clean_config(kwargs: dict[str, Any]) -> dict[str, Any] | _Unsupported:
    out: dict[str, Any] = {}
    for key, value in kwargs.items():
        if key in {"filters", "css_sanitizer"}:
            return _UNSUPPORTED
        encoded = encode_jsonable(value)
        if encoded is not _UNSUPPORTED:
            out[key] = encoded
        else:
            return _UNSUPPORTED
    return out


class _Unsupported:
    pass


_UNSUPPORTED = _Unsupported()


def encode_jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (set, frozenset, tuple, list)):
        values = [encode_jsonable(item) for item in value]
        if any(item is _UNSUPPORTED for item in values):
            return _UNSUPPORTED
        return sorted(values) if isinstance(value, (set, frozenset)) else values
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if not isinstance(key, str):
                return _UNSUPPORTED
            encoded = encode_jsonable(child)
            if encoded is _UNSUPPORTED:
                return _UNSUPPORTED
            out[key] = encoded
        return out
    return _UNSUPPORTED


def mutate_expected(expected: str) -> str:
    return expected + "__mutant__"


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", value.lower()).strip("_")[:92] or "sanitize"


def capability(dirty: str, config: Any, expected: str = "") -> str:
    text = " ".join([dirty, expected, json.dumps(config, ensure_ascii=False, sort_keys=True)]).lower()
    if any(token in text for token in ["javascript:", "vbscript:", "data:", "href", "src", "protocol", "scheme"]):
        return "html-sanitize.uri-attribute-policy"
    if any(token in text for token in ["style", "css", "background", "font-family", "svg", "math"]):
        return "html-sanitize.css-svg-policy"
    if any(token in text for token in ["comment", "<!--", "strip_comments"]):
        return "html-sanitize.comment-policy"
    if any(token in text for token in ["script", "textarea", "noscript", "option", "rcdata"]):
        return "html-sanitize.parser-mxss-hardening"
    if any(token in text for token in ["attribute", "onclick", "onload", "class", "title", "data-"]):
        return "html-sanitize.attribute-policy"
    if any(token in text for token in ["strip", "allowed", "tags", "attributes"]):
        return "html-sanitize.configuration-policy"
    if any(token in text for token in ["&lt;", "&amp;", "entity", "entities"]):
        return "html-sanitize.entity-escaping"
    return "html-sanitize.default-html"


def contract_key(row: dict[str, Any]) -> str:
    return json.dumps(
        {"dirty": row["params"]["dirty"], "config": row["params"].get("config"), "expected": row["expected"]},
        ensure_ascii=False,
        sort_keys=True,
    )


def add_contract(
    seen: dict[str, dict[str, Any]],
    version: str,
    published_at: str | None,
    tag: str,
    source_kind: str,
    title: str,
    dirty: Any,
    expected: Any,
    config: dict[str, Any] | None = None,
    evidence: str | None = None,
) -> bool:
    if not isinstance(dirty, str) or not isinstance(expected, str):
        return False
    params = {"dirty": dirty, "config": config or None}
    row = {
        "name": f"{version}:{source_kind}:{slug(title)}",
        "version": version,
        "published_at": published_at,
        "capability": capability(dirty, config, expected),
        "op": "sanitize",
        "params": params,
        "expected": {"clean": expected},
        "mutant": {"clean": mutate_expected(expected)},
        "evidence": {"tag": tag, "source": evidence},
        "source_kind": source_kind,
    }
    key = contract_key(row)
    if key in seen:
        return False
    seen[key] = row
    return True


def parse_data_fixtures(tag: str, version: str, published_at: str | None, seen: dict[str, dict[str, Any]]) -> int:
    count = 0
    for path in list_tree(tag, "tests/data"):
        if not path.endswith(".test"):
            continue
        text = git_show(tag, path)
        if not text or "\n--\n" not in text:
            continue
        dirty, expected = text.split("\n--\n", 1)
        dirty = dirty.rstrip("\n")
        expected = expected.rstrip("\n")
        title = Path(path).stem
        if add_contract(seen, version, published_at, tag, "fixture", title, dirty, expected, None, path):
            count += 1
    return count


class Recorder:
    def __init__(self, version: str, published_at: str | None, tag: str, source: str, seen: dict[str, dict[str, Any]]) -> None:
        self.version = version
        self.published_at = published_at
        self.tag = tag
        self.source = source
        self.seen = seen
        self.current = "module"
        self.count = 0

    def record(self, dirty: Any, expected: Any, kwargs: dict[str, Any], prefix: str = "clean") -> None:
        config = clean_config(kwargs)
        if config is _UNSUPPORTED:
            return
        if add_contract(
            self.seen,
            self.version,
            self.published_at,
            self.tag,
            "test-assertion",
            f"{self.current}:{prefix}:{self.count}",
            dirty,
            expected,
            config,
            self.source,
        ):
            self.count += 1


class CleanMarker:
    def __init__(self, recorder: Recorder, dirty: Any, kwargs: dict[str, Any]) -> None:
        self.recorder = recorder
        self.dirty = dirty
        self.kwargs = kwargs

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            self.recorder.record(self.dirty, other, self.kwargs)
        return True

    def __ne__(self, other: Any) -> bool:
        return False

    def __str__(self) -> str:
        return ""

    def __repr__(self) -> str:
        return "CleanMarker()"


class FakeCleaner:
    def __init__(self, recorder: Recorder, **kwargs: Any) -> None:
        self.recorder = recorder
        self.kwargs = kwargs

    def clean(self, dirty: Any) -> CleanMarker:
        return CleanMarker(self.recorder, dirty, self.kwargs)


class FakeRaises:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.value = Exception("")

    def __enter__(self) -> "FakeRaises":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return True


def parametrize(argnames: str | list[str], argvalues: list[Any], **kwargs: Any) -> Any:
    if isinstance(argnames, str):
        names = [name.strip() for name in argnames.split(",")]
    else:
        names = list(argnames)

    def decorator(func: Any) -> Any:
        params = getattr(func, "_sb_params", [])
        params.append((names, argvalues))
        func._sb_params = params
        return func

    return decorator


class FakeMark:
    parametrize = staticmethod(parametrize)

    def __getattr__(self, name: str) -> Any:
        def marker(*args: Any, **kwargs: Any) -> Any:
            if args and callable(args[0]) and len(args) == 1 and not kwargs:
                return args[0]

            def decorator(func: Any) -> Any:
                return func

            return decorator

        return marker


def make_pytest_module() -> Any:
    return types.SimpleNamespace(mark=FakeMark(), raises=FakeRaises, param=lambda *a, **k: a[0] if a else None)


def install_fake_modules(recorder: Recorder) -> dict[str, Any]:
    original: dict[str, Any] = {}

    def stash(name: str, module: Any) -> None:
        original[name] = sys.modules.get(name)
        sys.modules[name] = module

    bleach_mod = types.ModuleType("bleach")

    def fake_clean(dirty: Any = "", **kwargs: Any) -> CleanMarker:
        return CleanMarker(recorder, dirty, kwargs)

    bleach_mod.clean = fake_clean
    sanitizer_mod = types.ModuleType("bleach.sanitizer")
    sanitizer_mod.ALLOWED_PROTOCOLS = {"http", "https", "mailto"}
    sanitizer_mod.NoCssSanitizerWarning = Warning
    sanitizer_mod.Cleaner = lambda **kwargs: FakeCleaner(recorder, **kwargs)
    shim_mod = types.ModuleType("bleach.html5lib_shim")
    shim_mod.Filter = object
    vendor_mod = types.ModuleType("bleach._vendor")
    html5lib_mod = types.ModuleType("bleach._vendor.html5lib")
    constants_mod = types.ModuleType("bleach._vendor.html5lib.constants")
    constants_mod.rcdataElements = {"title", "textarea"}
    stash("pytest", make_pytest_module())
    stash("bleach", bleach_mod)
    stash("bleach.sanitizer", sanitizer_mod)
    stash("bleach.html5lib_shim", shim_mod)
    stash("bleach._vendor", vendor_mod)
    stash("bleach._vendor.html5lib", html5lib_mod)
    stash("bleach._vendor.html5lib.constants", constants_mod)
    return original


def restore_modules(original: dict[str, Any]) -> None:
    for name, module in original.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def case_product(param_sets: list[tuple[list[str], list[Any]]]) -> list[dict[str, Any]]:
    cases = [{}]
    for names, values in param_sets:
        next_cases: list[dict[str, Any]] = []
        for value in values:
            if len(names) == 1:
                mapping = {names[0]: value}
            elif isinstance(value, (tuple, list)):
                mapping = {name: value[i] for i, name in enumerate(names) if i < len(value)}
            else:
                continue
            for base in cases:
                merged = dict(base)
                merged.update(mapping)
                next_cases.append(merged)
        cases = next_cases
    return cases


def parse_test_clean(tag: str, version: str, published_at: str | None, seen: dict[str, dict[str, Any]]) -> int:
    source = None
    source_path = None
    for candidate in ["tests/test_clean.py", "bleach/tests/test_clean.py"]:
        source = git_show(tag, candidate)
        if source:
            source_path = candidate
            break
    if not source or not source_path:
        return 0
    recorder = Recorder(version, published_at, tag, source_path, seen)
    original = install_fake_modules(recorder)
    temp = tempfile.TemporaryDirectory()
    temp_root = Path(temp.name)
    temp_tests = temp_root / "tests"
    temp_data = temp_tests / "data"
    temp_data.mkdir(parents=True, exist_ok=True)
    for path in list_tree(tag, "tests/data"):
        if not path.endswith(".test"):
            continue
        text = git_show(tag, path)
        if text is not None:
            (temp_data / Path(path).name).write_text(text, encoding="utf-8")
    namespace: dict[str, Any] = {"__name__": f"bleach_extract_{slug(tag)}", "__file__": str(temp_tests / "test_clean.py")}
    try:
        exec(compile(source, source_path, "exec"), namespace)
        for name, obj in sorted(namespace.items()):
            if not name.startswith("test_") or not callable(obj):
                continue
            recorder.current = name
            params = getattr(obj, "_sb_params", [])
            cases = case_product(params) if params else [{}]
            for case in cases[:800]:
                try:
                    obj(**case)
                except Exception:
                    continue
    except Exception:
        pass
    finally:
        restore_modules(original)
        temp.cleanup()
    return recorder.count


def ensure_latest_bleach(latest: str) -> dict[str, str]:
    TARGET.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(TARGET) + os.pathsep + env.get("PYTHONPATH", "")
    probe = subprocess.run(
        [str(PYTHON), "-c", "import bleach; print(bleach.__version__)"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if probe.returncode != 0 or probe.stdout.strip() != latest:
        run([str(PYTHON), "-m", "pip", "install", "--upgrade", "--target", str(TARGET), f"bleach[css]=={latest}"])
    return env


def replay_contract(contract: dict[str, Any], env: dict[str, str], mutant: bool = False) -> dict[str, Any]:
    expected = contract["mutant" if mutant else "expected"]["clean"]
    params = contract["params"]
    program = """
import json, sys
import bleach
payload=json.loads(sys.stdin.read())
dirty=payload["dirty"]
config=payload.get("config") or {}
try:
    clean=bleach.clean(dirty, **config)
    print(json.dumps({"clean": clean}, ensure_ascii=False))
except Exception as exc:
    print(json.dumps({"error": exc.__class__.__name__, "message": str(exc)}, ensure_ascii=False))
"""
    proc = subprocess.run(
        [str(PYTHON), "-c", program],
        input=json.dumps(params, ensure_ascii=False),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return {"passed": False, "actual": {"error": "ProcessError", "message": proc.stderr.strip()}}
    actual = json.loads(proc.stdout)
    return {"passed": actual.get("clean") == expected, "actual": actual}


def canon_key(dirty: str, clean: Any) -> str:
    return hashlib.sha256(json.dumps({"dirty": dirty, "clean": clean}, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def common_keys() -> set[str]:
    data = json.loads(COMMON_JSON.read_text(encoding="utf-8"))
    keys = set()
    for row in data["final_common_contracts"]:
        dirty = row.get("params", {}).get("dirty") or row.get("params", {}).get("html") or ""
        clean = row.get("expected", {}).get("clean")
        keys.add(canon_key(str(dirty), clean))
    return keys


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.extend(
            [
                f"contract {json.dumps(row['name'])} {{",
                f"  origin {json.dumps('bleach')}",
                f"  version {json.dumps(row['version'])}",
                f"  capability {json.dumps(row['capability'])}",
                "  op sanitize",
                f"  params {json.dumps(row['params'], ensure_ascii=False, sort_keys=True)}",
                f"  expected {json.dumps(row['expected'], ensure_ascii=False, sort_keys=True)}",
                "}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ensure_repo()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    metadata = pypi_metadata()
    latest = metadata["info"]["version"]
    releases = metadata["releases"]
    tags = git_tags()
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    for version in sorted(releases, key=version_key):
        tag = tag_for(version, tags)
        if not tag:
            release_counts.append({"version": version, "tag": None, "contracts_seen": 0, "new_contracts": 0})
            continue
        before = len(seen)
        fixture_count = parse_data_fixtures(tag, version, (metadata.get("releases", {}).get(version) or [{}])[0].get("upload_time_iso_8601"), seen)
        assertion_count = parse_test_clean(tag, version, (metadata.get("releases", {}).get(version) or [{}])[0].get("upload_time_iso_8601"), seen)
        release_counts.append(
            {
                "version": version,
                "tag": tag,
                "contracts_seen": fixture_count + assertion_count,
                "new_contracts": len(seen) - before,
            }
        )

    contracts = sorted(seen.values(), key=lambda row: (version_key(row["version"]), row["name"]))
    counts = Counter()
    for row in contracts:
        counts[row["name"]] += 1
        if counts[row["name"]] > 1:
            row["name"] = f"{row['name']}_{counts[row['name']]}"

    env = ensure_latest_bleach(latest)
    results = []
    survivors = []
    keys = common_keys()
    for contract in contracts:
        replay = replay_contract(contract, env, mutant=False)
        mutant = replay_contract(contract, env, mutant=True) if replay["passed"] else {"passed": False, "actual": {}}
        status = "passed" if replay["passed"] and not mutant["passed"] else "failed"
        enriched = dict(contract)
        enriched["origin"] = "bleach"
        enriched["overlap_with_final_common_90"] = canon_key(contract["params"]["dirty"], contract["expected"]["clean"]) in keys
        row = {
            "name": contract["name"],
            "version": contract["version"],
            "capability": contract["capability"],
            "source_kind": contract["source_kind"],
            "replay_passed": replay["passed"],
            "mutant_rejected": replay["passed"] and not mutant["passed"],
            "status": status,
            "actual": replay["actual"],
            "overlap_with_final_common_90": enriched["overlap_with_final_common_90"],
        }
        results.append(row)
        if status == "passed":
            survivors.append(enriched)

    non_common = [row for row in survivors if not row["overlap_with_final_common_90"]]
    summary = {
        "domain": "HTML Sanitizer",
        "project": "mozilla/bleach",
        "package": "bleach",
        "latest_version": latest,
        "pypi_releases": len(releases),
        "git_tags": len(tags),
        "tagged_releases_inspected": sum(1 for row in release_counts if row["tag"]),
        "extraction_basis": "Release-tag tests/data fixtures and public bleach.clean/Cleaner.clean assertions. Only externally observable sanitizer behavior is retained.",
        "all_unique_contracts": len(contracts),
        "latest_replay_passed": sum(1 for row in results if row["replay_passed"]),
        "latest_mutant_killed": sum(1 for row in results if row["mutant_rejected"]),
        "latest_survivors": len(survivors),
        "overlap_with_final_common_90": sum(1 for row in survivors if row["overlap_with_final_common_90"]),
        "non_common_survivors": len(non_common),
        "by_capability_all": dict(sorted(Counter(row["capability"] for row in contracts).items())),
        "by_capability_survivors": dict(sorted(Counter(row["capability"] for row in survivors).items())),
        "by_capability_non_common": dict(sorted(Counter(row["capability"] for row in non_common).items())),
        "by_source_kind_all": dict(sorted(Counter(row["source_kind"] for row in contracts).items())),
        "by_source_kind_survivors": dict(sorted(Counter(row["source_kind"] for row in survivors).items())),
        "release_counts": release_counts,
        "contracts": contracts,
        "survivors": survivors,
        "non_common": non_common,
        "results": results,
    }
    (OUT_DIR / "all_releases_origin_extraction.summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_rpl(contracts, OUT_DIR / "all_releases_origin_extraction.rpl")
    (OUT_DIR / "latest_replay_mutant_verified.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_rpl(survivors, OUT_DIR / "latest_replay_mutant_verified.rpl")
    non_common_payload = {
        "domain": summary["domain"],
        "project": summary["project"],
        "latest_version": summary["latest_version"],
        "common_baseline": 90,
        "latest_survivors": len(survivors),
        "overlap_with_final_common_90": summary["overlap_with_final_common_90"],
        "non_common_survivors": len(non_common),
        "by_capability_non_common": summary["by_capability_non_common"],
        "non_common": non_common,
    }
    (OUT_DIR / "non_common_latest_replay_mutant_verified.json").write_text(
        json.dumps(non_common_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(non_common, OUT_DIR / "non_common_latest_replay_mutant_verified.rpl")

    lines = [
        "# Bleach Origin Contract Extraction",
        "",
        f"Latest version: `{latest}`",
        f"PyPI releases: {len(releases)}",
        f"Git tags: {len(tags)}",
        f"Tagged releases inspected: {summary['tagged_releases_inspected']}",
        f"All unique extracted contracts: {len(contracts)}",
        f"Latest replay passed: {summary['latest_replay_passed']}",
        f"Mutants rejected: {summary['latest_mutant_killed']}",
        f"Latest survivors: {len(survivors)}",
        f"Overlap with final common 90: {summary['overlap_with_final_common_90']}",
        f"Non-common survivors: {len(non_common)}",
        "",
        "## Non-Common Survivors By Capability",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in summary["by_capability_non_common"].items():
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Release Counts", "", "| Version | Tag | Observed | New unique |", "| --- | --- | ---: | ---: |"])
    for row in release_counts:
        lines.append(f"| `{row['version']}` | `{row['tag']}` | {row['contracts_seen']} | {row['new_contracts']} |")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    non_common_lines = [
        "# Bleach Non-Common Latest Survivors",
        "",
        f"Latest version: `{latest}`",
        "Common baseline: final common 90",
        f"Latest survivors: {len(survivors)}",
        f"Overlap with final common 90: {summary['overlap_with_final_common_90']}",
        f"Non-common survivors: {len(non_common)}",
        "",
        "| Capability | Count |",
        "| --- | ---: |",
    ]
    for cap, count in summary["by_capability_non_common"].items():
        non_common_lines.append(f"| `{cap}` | {count} |")
    (OUT_DIR / "non_common_latest_replay_mutant_verified.md").write_text(
        "\n".join(non_common_lines) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({k: summary[k] for k in ["latest_version", "all_unique_contracts", "latest_survivors", "overlap_with_final_common_90", "non_common_survivors", "by_capability_non_common"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
