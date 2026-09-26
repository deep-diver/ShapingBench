#!/usr/bin/env python3
"""Replay jsdom/whatwg-url contracts against the latest published package."""

from __future__ import annotations

import copy
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts" / "url_iri" / "whatwg-url" / "all_releases_maximal_language_independent.summary.json"
OUT_DIR = ROOT / "contracts" / "url_iri" / "whatwg-url"
OUT_JSON = OUT_DIR / "latest_replay_mutant_verified.json"
OUT_MD = OUT_DIR / "latest_replay_mutant_verified.md"
OUT_RPL = OUT_DIR / "latest_replay_mutant_verified.rpl"
PACKAGE_DIR = ROOT / ".replay" / "url_iri" / "whatwg-url-latest"
LATEST_VERSION = "17.1.0"


NODE_RUNNER = r"""
const w = require("./node_modules/whatwg-url");

function urlFrom(input, base) {
  return base === undefined ? new w.URL(input) : new w.URL(input, base);
}

function publicURL(u) {
  return {
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

function baseRecord(base) {
  if (base === undefined) {
    return undefined;
  }
  return w.parseURL(base);
}

function recordSummary(record) {
  if (record === null) {
    return { isNull: true };
  }
  const out = {
    isNull: false,
    scheme: record.scheme,
    username: record.username,
    password: record.password,
    host: typeof record.host === "string" ? record.host : (record.host === null ? null : w.serializeHost(record.host)),
    port: record.port,
    path: w.serializePath(record),
    query: record.query,
    fragment: record.fragment
  };
  try {
    out.href = w.serializeURL(record);
  } catch {
    // Some state-override records are intentionally partial.
  }
  return out;
}

function runSearchParams(params) {
  const sp = new w.URLSearchParams(params.init);
  let last;
  for (const action of params.actions || []) {
    if (action.type === "getAll") {
      last = { values: sp.getAll(action.name), size: sp.size };
    } else if (action.type === "toString") {
      last = { value: sp.toString() };
    } else if (action.type === "sort") {
      sp.sort();
      last = { value: sp.toString() };
    } else if (action.type === "set") {
      sp.set(action.name, action.value);
      last = { value: sp.toString(), size: sp.size };
    } else if (action.type === "append") {
      sp.append(action.name, action.value);
      last = { value: sp.toString(), size: sp.size };
    } else if (action.type === "delete") {
      if (Object.prototype.hasOwnProperty.call(action, "value")) {
        sp.delete(action.name, action.value);
      } else {
        sp.delete(action.name);
      }
      last = { value: sp.toString(), size: sp.size };
    } else if (action.type === "has") {
      const value = Object.prototype.hasOwnProperty.call(action, "value") ? sp.has(action.name, action.value) : sp.has(action.name);
      last = { value };
    } else if (action.type === "size") {
      last = { value: sp.size };
    } else {
      throw new Error(`unsupported searchparams action ${action.type}`);
    }
  }
  return last || { value: sp.toString(), size: sp.size };
}

function runSearchParamsParent(params) {
  const u = urlFrom(params.input, params.base);
  let last;
  for (const action of params.actions || []) {
    if (action.type === "append") {
      u.searchParams.append(action.name, action.value);
    } else if (action.type === "delete") {
      if (Object.prototype.hasOwnProperty.call(action, "value")) {
        u.searchParams.delete(action.name, action.value);
      } else {
        u.searchParams.delete(action.name);
      }
    } else if (action.type === "set") {
      u.searchParams.set(action.name, action.value);
    } else if (action.type === "sort") {
      u.searchParams.sort();
    } else {
      throw new Error(`unsupported parent searchparams action ${action.type}`);
    }
    last = { href: u.href, search: u.search, value: u.searchParams.toString(), size: u.searchParams.size };
  }
  return last || { href: u.href, search: u.search, value: u.searchParams.toString(), size: u.searchParams.size };
}

function execute(contract) {
  const p = contract.params || {};
  switch (contract.op) {
    case "parse_url":
      return publicURL(urlFrom(p.input, p.base));
    case "construct_failure":
      try {
        urlFrom(p.input, p.base);
        return { throws: null };
      } catch (e) {
        return { throws: e.name, message: e.message };
      }
    case "set_component": {
      const u = urlFrom(p.input, p.base);
      try {
        u[p.component] = p.value;
      } catch (e) {
        return { throws: e.name, message: e.message, ...publicURL(u) };
      }
      return publicURL(u);
    }
    case "static_presence":
      return { present: p.property in w.URL };
    case "method_call": {
      const u = urlFrom(p.input, p.base);
      return { value: u[p.method]() };
    }
    case "origin":
      return { origin: urlFrom(p.input, p.base).origin };
    case "percent_decode_string":
      return { hex: Buffer.from(w.percentDecodeString(p.input)).toString("hex"), value: Buffer.from(w.percentDecodeString(p.input)).toString("utf8") };
    case "percent_decode_bytes":
      const decodedBytes = w.percentDecodeBytes(Buffer.from(p.input, "utf8"));
      return { constructor: decodedBytes.constructor.name, hex: Buffer.from(decodedBytes).toString("hex") };
    case "cannot_have_credentials_port":
      return { value: w.cannotHaveAUsernamePasswordPort(w.parseURL(p.input)) };
    case "has_opaque_path":
      return { value: w.hasAnOpaquePath(w.parseURL(p.input)) };
    case "low_level_parse": {
      const options = {};
      if (p.base) {
        options.baseURL = baseRecord(p.base);
      }
      if (p.encoding) {
        options.encoding = p.encoding;
      }
      if (p.stateOverride) {
        options.stateOverride = p.stateOverride;
      }
      return recordSummary(w.basicURLParse(p.input, options));
    }
    case "serialize_path":
      return { value: w.serializePath(w.parseURL(p.input)) };
    case "searchparams":
      return runSearchParams(p);
    case "searchparams_parent":
      return runSearchParamsParent(p);
    case "href_setter_searchparams": {
      const u = urlFrom(p.input, p.base);
      const sp = u.searchParams;
      u.href = p.value;
      return { href: u.href, search: u.search, value: sp.get(p.read), serialized: sp.toString() };
    }
    case "object_tag": {
      const obj = (p.target === "URLSearchParams" || p.type === "URLSearchParams") ?
        new w.URLSearchParams(p.init || p.input || "") :
        urlFrom(p.input, p.base);
      return { value: Object.prototype.toString.call(obj) };
    }
    case "roundtrip": {
      const first = urlFrom(p.input, p.base);
      const second = urlFrom(first.href);
      return { stable: first.href === second.href, href: second.href };
    }
    case "can_parse":
      return { value: w.URL.canParse(p.input, p.base) };
    case "static_parse": {
      const r = w.URL.parse(p.input, p.base);
      if (r === null) {
        return { isNull: true };
      }
      return { isNull: false, isURL: r instanceof w.URL, ...publicURL(r) };
    }
    case "parse_with_validation_errors": {
      const options = {};
      if (p.base) {
        options.baseURL = baseRecord(p.base);
      }
      if (p.encoding) {
        options.encoding = p.encoding;
      }
      const result = w.parseURLWithValidationErrors(p.input, options);
      return {
        urlIsNull: result.url === null,
        errors: result.validationErrors,
        errorsLength: result.validationErrors.length
      };
    }
    case "is_valid_url_string": {
      const options = {};
      if (p.base) {
        options.baseURL = baseRecord(p.base);
      }
      return { value: w.isValidURLString(p.input, options) };
    }
    default:
      throw new Error(`unsupported op ${contract.op}`);
  }
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => { input += chunk; });
process.stdin.on("end", () => {
  try {
    const contract = JSON.parse(input);
    const actual = execute(contract);
    process.stdout.write(JSON.stringify({ ok: true, actual }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: { name: e.name, message: e.message, stack: e.stack } }));
  }
});
"""


def run_node(contract: dict[str, Any]) -> dict[str, Any]:
    proc = subprocess.run(
        ["node", "-e", NODE_RUNNER],
        cwd=PACKAGE_DIR,
        input=json.dumps(contract),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": {"name": "NodeProcessError", "message": proc.stderr.strip()}}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": {"name": "JSONDecodeError", "message": str(exc), "stdout": proc.stdout, "stderr": proc.stderr}}


def expected_matches(actual: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, list[str]]:
    misses: list[str] = []
    for key, value in expected.items():
        if key.endswith("Contains"):
            actual_key = key[: -len("Contains")]
            actual_value = actual.get(actual_key)
            if isinstance(actual_value, list):
                if value not in actual_value:
                    misses.append(f"{key}: {value!r} not in {actual_value!r}")
            elif isinstance(actual_value, str):
                if value not in actual_value:
                    misses.append(f"{key}: {value!r} not in {actual_value!r}")
            else:
                misses.append(f"{key}: actual {actual_key!r} is not searchable ({actual_value!r})")
        elif actual.get(key) != value:
            misses.append(f"{key}: expected {value!r}, got {actual.get(key)!r}")
    return not misses, misses


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return list(reversed(value)) if len(value) > 1 else value + ["__mutant__"]
    if value is None:
        return "__mutant__"
    if isinstance(value, dict):
        mutated = copy.deepcopy(value)
        if mutated:
            first = next(iter(mutated))
            mutated[first] = mutate_value(mutated[first])
        else:
            mutated["__mutant__"] = True
        return mutated
    return "__mutant__"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = copy.deepcopy(expected)
    key = next(iter(mutated))
    mutated[key] = mutate_value(mutated[key])
    return mutated


def contract_to_rpl(contract: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"contract {contract['name']} {{",
            f"  version = {json.dumps(contract['version'])}",
            f"  capability = {json.dumps(contract['capability'])}",
            f"  op = {json.dumps(contract['op'])}",
            f"  params = {json.dumps(contract['params'], ensure_ascii=False, sort_keys=True)}",
            f"  expect = {json.dumps(contract['expected'], ensure_ascii=False, sort_keys=True)}",
            f"  mutant = {json.dumps(contract['mutant'])}",
            "}",
        ]
    )


def main() -> None:
    data = json.loads(CONTRACTS.read_text(encoding="utf-8"))
    contracts = data["contracts"]
    results = []
    survivors = []

    for contract in contracts:
        node_result = run_node(contract)
        if not node_result.get("ok"):
            replay_ok = False
            actual = {}
            failures = [node_result.get("error", {}).get("message", "unknown node failure")]
        else:
            actual = node_result["actual"]
            replay_ok, failures = expected_matches(actual, contract["expected"])

        mutant_expected = mutate_expected(contract["expected"])
        mutant_ok, mutant_failures = expected_matches(actual, mutant_expected)
        mutant_killed = not mutant_ok
        survived = replay_ok and mutant_killed

        row = {
            "name": contract["name"],
            "version": contract["version"],
            "capability": contract["capability"],
            "op": contract["op"],
            "replay_ok": replay_ok,
            "mutant_killed": mutant_killed,
            "survived_latest": survived,
            "expected": contract["expected"],
            "actual": actual,
            "failures": failures,
            "mutant_expected": mutant_expected,
            "mutant_failures": mutant_failures,
        }
        results.append(row)
        if survived:
            survivors.append(contract)

    counts_by_op = Counter(c["op"] for c in survivors)
    counts_by_capability = Counter(c["capability"] for c in survivors)
    failing = [r for r in results if not r["survived_latest"]]

    OUT_JSON.write_text(
        json.dumps(
            {
                "project": "jsdom/whatwg-url",
                "latest_version": LATEST_VERSION,
                "input_contracts": len(contracts),
                "latest_replay_passed": sum(1 for r in results if r["replay_ok"]),
                "latest_mutant_killed": sum(1 for r in results if r["mutant_killed"]),
                "latest_survivors": len(survivors),
                "survivors": survivors,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    md = [
        "# whatwg-url latest replay + mutant verification",
        "",
        f"- Latest target: `whatwg-url@{LATEST_VERSION}`",
        f"- Input contracts: `{len(contracts)}`",
        f"- Replay passed: `{sum(1 for r in results if r['replay_ok'])}`",
        f"- Mutant killed: `{sum(1 for r in results if r['mutant_killed'])}`",
        f"- Latest survivors: `{len(survivors)}`",
        "",
        "## Survivors by operation",
        "",
        "| Operation | Count |",
        "| --- | ---: |",
    ]
    for op, count in counts_by_op.most_common():
        md.append(f"| `{op}` | {count} |")
    md.extend(["", "## Survivors by capability", "", "| Capability | Count |", "| --- | ---: |"])
    for cap, count in counts_by_capability.most_common():
        md.append(f"| `{cap}` | {count} |")
    md.extend(["", "## Non-survivors", "", "| Contract | Reason |", "| --- | --- |"])
    for row in failing:
        reason = "; ".join(row["failures"]) if row["failures"] else "mutant was not killed"
        md.append(f"| `{row['name']}` | {reason.replace('|', '\\|')} |")
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    OUT_RPL.write_text("\n\n".join(contract_to_rpl(c) for c in survivors) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "input_contracts": len(contracts),
                "latest_replay_passed": sum(1 for r in results if r["replay_ok"]),
                "latest_mutant_killed": sum(1 for r in results if r["mutant_killed"]),
                "latest_survivors": len(survivors),
                "non_survivors": len(failing),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
