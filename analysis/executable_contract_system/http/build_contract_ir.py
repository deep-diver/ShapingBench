#!/usr/bin/env python3
"""Build a lossless HTTP non-common contract IR from frozen benchmark artifacts.

This is analysis-side infrastructure.  It never rewrites the frozen corpus.  A
contract is marked executable only when its setup, action, oracle, and negative
control are all recoverable; a release-note sentence alone is not promoted to
an executable contract.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CORPUS = ROOT / "contracts/solhttp_non_common/solhttp_gpt56sol_high_http_non_common_20260829.json"
OLD_RUNNER = ROOT / "tools/replay/replay_generated_solhttp_non_common_http.py"


@dataclass
class RplContract:
    origin: str
    version: str
    name: str
    source_file: str
    source_line: int
    evidence: str = ""
    capability: str = ""
    mutant: str = ""
    setup: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return bool(self.setup and self.actions and self.assertions and self.mutant)


def quoted(line: str) -> list[str]:
    # The checked-in RPL uses JSON-like quoted scalars.  Keep the original line
    # too, because the IR is intentionally lossless even for unfamiliar verbs.
    return re.findall(r'"((?:[^"\\]|\\.)*)"', line)


def parse_rpl(path: Path, origin: str) -> list[RplContract]:
    version = ""
    current: RplContract | None = None
    contracts: list[RplContract] = []
    for number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        line = raw.strip()
        if line.startswith("release "):
            values = quoted(line)
            version = values[1] if len(values) > 1 else ""
            continue
        if line.startswith("contract "):
            if current is not None:
                contracts.append(current)
            values = quoted(line)
            current = RplContract(
                origin=origin,
                version=version,
                name=values[0] if values else "",
                source_file=str(path.relative_to(ROOT)),
                source_line=number,
            )
            continue
        if current is None:
            continue
        if line == "end":
            contracts.append(current)
            current = None
            continue
        current.raw_lines.append(raw)
        values = quoted(line)
        if line.startswith("evidence ") and values:
            current.evidence = values[0]
        elif line.startswith("capability ") and values:
            current.capability = values[0]
        elif line.startswith("mutant ") and values:
            current.mutant = values[0]
        elif line.startswith("given "):
            current.setup.append(line[6:])
        elif line.startswith("when "):
            current.actions.append(line[5:])
        elif line.startswith("then "):
            current.assertions.append(line[5:])
    if current is not None:
        contracts.append(current)
    return contracts


def parse_okhttp_json(path: Path) -> list[RplContract]:
    rows = json.loads(path.read_text())["results"]

    def normalized_steps(value: object, prefix: str) -> list[str]:
        if not isinstance(value, list):
            return []
        # Some historical extraction rows accidentally serialized one DSL line
        # as a list of characters.  Rejoining is lossless and independently
        # checkable against the concatenated frozen value.
        if len(value) > 5 and all(isinstance(item, str) and len(item) == 1 for item in value):
            value = ["".join(value)]
        return [str(item).removeprefix(prefix) for item in value]

    return [
        RplContract(
            origin="okhttp",
            version=str(row.get("source_version", "")),
            name=row.get("contract") or row["name"],
            source_file=str(path.relative_to(ROOT)),
            source_line=index + 1,
            evidence=row.get("evidence", ""),
            capability=row.get("capability", ""),
            mutant=row.get("mutant", ""),
            setup=normalized_steps(row.get("setup", []), "given "),
            actions=normalized_steps(row.get("actions", []), "when "),
            assertions=normalized_steps(row.get("assertions", []), "then "),
            raw_lines=[*row.get("setup", []), *row.get("actions", []), *row.get("assertions", [])],
        )
        for index, row in enumerate(rows)
    ]


def old_executable_names() -> tuple[set[str], set[str]]:
    tree = ast.parse(OLD_RUNNER.read_text())
    specific: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) else node.target
        if isinstance(target, ast.Name) and target.id == "SPECIFIC_CONTRACT_TESTS":
            assert isinstance(node.value, ast.Dict)
            specific = {ast.literal_eval(key) for key in node.value.keys}
    # These are the 32 legacy mappings recorded by the frozen evaluator output.
    payload = json.loads(CORPUS.read_text())
    statuses: dict[str, set[str]] = defaultdict(set)
    for run in payload["runs"]:
        for row in run.get("results", []):
            error = row.get("error", "")
            if "unsupported_api_surface:" not in error and "unsupported_or_unimplemented_contract_probe:" not in error:
                statuses[row["key"]].add("executed")
    legacy = {key for key, values in statuses.items() if "executed" in values}
    return specific, legacy


def sha256_json(value: object) -> str:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def choose_definition(row: dict, definitions: dict[tuple[str, str], list[RplContract]]) -> tuple[RplContract | None, str]:
    candidates = definitions.get((row["origin"], row["contract"]), [])
    if not candidates:
        return None, "release_note_only"
    exact = [item for item in candidates if item.version == row.get("source_version")]
    if exact:
        return exact[0], "exact_version_and_name"
    # Axios' frozen source_version field is a formatted release-row list.  Its
    # repeated RPL definitions are semantically identical for a given name.
    fingerprints: dict[str, RplContract] = {}
    for item in candidates:
        semantic = {
            "capability": item.capability,
            "mutant": item.mutant,
            "setup": item.setup,
            "actions": item.actions,
            "assertions": item.assertions,
        }
        fingerprints.setdefault(sha256_json(semantic), item)
    if len(fingerprints) == 1:
        item = next(iter(fingerprints.values()))
        axios_oracle_repairs = {
            "unicode_header_values_survive_interceptors": 'server observed_header "X-Token" starts_with "token-é"',
            "user_agent_header_can_be_omitted": 'server observed_header "User-Agent" absent',
        }
        if item.origin == "axios" and item.name in axios_oracle_repairs and not item.assertions:
            item.assertions = [axios_oracle_repairs[item.name]]
            return item, "name_with_identical_release_definitions_and_replay_oracle_repair"
        return item, "name_with_identical_release_definitions"
    return None, "ambiguous_release_definitions"


def write_csv(path: Path, rows: Iterable[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    HERE.mkdir(parents=True, exist_ok=True)
    corpus = json.loads(CORPUS.read_text())["corpus"]
    all_defs = [
        *parse_rpl(ROOT / "contracts/urllib3/all_releases_maximal_language_independent.rpl", "urllib3"),
        *parse_rpl(ROOT / "contracts/axios/axios_origin_excluding_merged_common.rpl", "axios"),
        *parse_okhttp_json(ROOT / "contracts/okhttp/okhttp_origin_latest_survivors.json"),
    ]
    definitions: dict[tuple[str, str], list[RplContract]] = defaultdict(list)
    for item in all_defs:
        definitions[(item.origin, item.name)].append(item)
    specific, previously_executed = old_executable_names()

    output: list[dict] = []
    inventory: list[dict] = []
    for ordinal, row in enumerate(corpus, 1):
        definition, match = choose_definition(row, definitions)
        scoring_id = f"http-noncommon-{ordinal:04d}"
        ir = {
            "schema": "shapingbench.behavior-contract/v1",
            "scoring_id": scoring_id,
            "origin": row["origin"],
            "source_version": row.get("source_version", ""),
            "source_key": row["key"],
            "name": row["contract"],
            "capability": row["capability"],
            "evidence": row.get("evidence", ""),
            "definition_match": match,
            "source_definition": None,
            "setup": definition.setup if definition else [],
            "actions": definition.actions if definition else [],
            "oracle": definition.assertions if definition else [],
            "negative_control": {"mutant": definition.mutant} if definition and definition.mutant else None,
            "definition_complete": bool(definition and definition.complete),
            "legacy_execution_available": row["key"] in previously_executed or row["contract"] in specific,
        }
        if definition:
            ir["source_definition"] = {
                "path": definition.source_file,
                "line": definition.source_line,
                "version": definition.version,
                "semantic_hash": sha256_json({
                    "setup": definition.setup,
                    "actions": definition.actions,
                    "oracle": definition.assertions,
                    "mutant": definition.mutant,
                }),
            }
        ir["contract_hash"] = sha256_json({k: ir[k] for k in ("origin", "source_key", "name", "capability", "setup", "actions", "oracle", "negative_control")})
        output.append(ir)
        inventory.append({
            "scoring_id": scoring_id,
            "origin": row["origin"],
            "source_key": row["key"],
            "name": row["contract"],
            "capability": row["capability"],
            "definition_match": match,
            "definition_complete": str(ir["definition_complete"]).lower(),
            "setup_count": len(ir["setup"]),
            "action_count": len(ir["actions"]),
            "oracle_count": len(ir["oracle"]),
            "negative_control": (ir["negative_control"] or {}).get("mutant", ""),
            "legacy_execution_available": str(ir["legacy_execution_available"]).lower(),
            "source_definition": "" if not definition else f"{definition.source_file}:{definition.source_line}",
            "contract_hash": ir["contract_hash"],
        })

    (HERE / "http_non_common_contract_ir.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in output)
    )
    write_csv(HERE / "source_definition_inventory.csv", inventory, list(inventory[0]))
    by_origin = {}
    for origin in sorted({row["origin"] for row in output}):
        rows = [row for row in output if row["origin"] == origin]
        by_origin[origin] = {
            "total": len(rows),
            "definition_complete": sum(row["definition_complete"] for row in rows),
            "legacy_execution_available": sum(row["legacy_execution_available"] for row in rows),
            "definition_match": dict(Counter(row["definition_match"] for row in rows)),
        }
    summary = {
        "total": len(output),
        "definition_complete": sum(row["definition_complete"] for row in output),
        "definition_incomplete": sum(not row["definition_complete"] for row in output),
        "legacy_execution_available": sum(row["legacy_execution_available"] for row in output),
        "by_origin": by_origin,
    }
    (HERE / "source_definition_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
