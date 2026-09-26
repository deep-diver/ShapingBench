#!/usr/bin/env python3
"""Shared helpers for JWT origin contract extraction/replay."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
JWT_RE = re.compile(r"(?<![A-Za-z0-9_=-])([A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]*\.[A-Za-z0-9_=-]*)(?![A-Za-z0-9_=-])")


@dataclass(frozen=True)
class Contract:
    name: str
    version: str
    published_at: str | None
    capability: str
    op: str
    params: dict[str, Any]
    expected: dict[str, Any]
    mutant: dict[str, Any]
    evidence: dict[str, Any]
    source_kind: str


def sh(args: list[str], cwd: Path = ROOT) -> str:
    raw = subprocess.check_output(args, cwd=cwd, stderr=subprocess.STDOUT)
    return raw.decode("utf-8", errors="replace")


def ensure_git_repo(url: str, repo: Path) -> None:
    if (repo / ".git").exists():
        sh(["git", "fetch", "--tags", "--quiet"], cwd=repo)
        return
    repo.parent.mkdir(parents=True, exist_ok=True)
    sh(["git", "clone", "--quiet", url, str(repo)], cwd=ROOT)


def version_key(version: str) -> tuple:
    value = version.removeprefix("v")
    parts = re.split(r"([0-9]+|[A-Za-z]+)", value)
    out: list[tuple[int, Any]] = []
    for part in parts:
        if not part or part in ".-_+":
            continue
        out.append((0, int(part)) if part.isdigit() else (1, part.lower()))
    return tuple(out)


def git_tags(repo: Path) -> list[str]:
    tags = sh(["git", "tag"], cwd=repo).splitlines()
    return sorted(tags, key=version_key)


def git_show(repo: Path, tag: str, path: str) -> str | None:
    try:
        return sh(["git", "show", f"{tag}:{path}"], cwd=repo)
    except subprocess.CalledProcessError:
        return None


def list_tree(repo: Path, tag: str) -> list[str]:
    try:
        return sh(["git", "ls-tree", "-r", "--name-only", tag], cwd=repo).splitlines()
    except subprocess.CalledProcessError:
        return []


def tag_date(repo: Path, tag: str) -> str | None:
    try:
        return sh(["git", "log", "-1", "--format=%cI", tag], cwd=repo).strip()
    except subprocess.CalledProcessError:
        return None


def b64url_decode(part: str) -> bytes:
    value = part.replace("\n", "").replace("\r", "")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode())


def b64url_decode_json(part: str) -> Any:
    return normalize_json(json.loads(b64url_decode(part).decode("utf-8")))


def normalize_json(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_json(item) for key, item in value.items()}
    return value


def hmac_alg_for_token(token: str, secret: bytes) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = b64url_decode_json(parts[0])
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    alg = header.get("alg")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return None
    signature = hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), digest).digest()
    actual = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return alg if hmac.compare_digest(actual, parts[2].rstrip("=")) else None


def mutate_value(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if value is None:
        return "__mutant__"
    if isinstance(value, int):
        return value + 1
    if isinstance(value, float):
        return value + 1.0
    if isinstance(value, str):
        return value + "__mutant__"
    if isinstance(value, list):
        return value + ["__mutant__"]
    if isinstance(value, dict):
        out = dict(value)
        out["__mutant__"] = True
        return out
    return "__mutant__"


def with_mutant(expected: dict[str, Any]) -> dict[str, Any]:
    for key in ("ok", "error", "accepted", "verifies", "has_signature"):
        if isinstance(expected.get(key), bool):
            return {**expected, key: not expected[key]}
    key = next(iter(expected))
    return {**expected, key: mutate_value(expected[key])}


def add_contract(
    out: list[Contract],
    version: str,
    published_at: str | None,
    capability: str,
    op: str,
    slug: str,
    params: dict[str, Any],
    expected: dict[str, Any],
    evidence: dict[str, Any],
    source_kind: str,
) -> None:
    out.append(
        Contract(
            name=f"{version}:{op}:{slug}",
            version=version,
            published_at=published_at,
            capability=capability,
            op=op,
            params=params,
            expected=expected,
            mutant=with_mutant(expected),
            evidence=evidence,
            source_kind=source_kind,
        )
    )


def contract_identity(contract: Contract | dict[str, Any]) -> str:
    row = asdict(contract) if isinstance(contract, Contract) else contract
    return json.dumps([row["capability"], row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)


def load_final_common_identities() -> tuple[set[str], dict[str, str], list[dict[str, Any]]]:
    path = ROOT / "contracts" / "jwt" / "common" / "final_common.json"
    if not path.exists():
        return set(), {}, []
    data = json.loads(path.read_text(encoding="utf-8"))
    identities: set[str] = set()
    by_identity: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for row in data.get("contracts", []):
        identity = row.get("identity") or json.dumps([row.get("canonical_op"), row.get("params"), row.get("expected")], sort_keys=True, ensure_ascii=True)
        identities.add(identity)
        by_identity[identity] = row.get("id", identity)
        rows.append({**row, "identity": identity})
    return identities, by_identity, rows


def canonical_contract(contract: dict[str, Any], origin: str) -> dict[str, Any]:
    op = contract["op"]
    params = contract.get("params", {})
    expected = contract.get("expected", {})
    case: dict[str, Any] = {
        "id": f"{origin}:{contract['name']}",
        "origin": origin,
        "source_name": contract["name"],
        "source_capability": contract["capability"],
        "source_op": op,
        "version": contract.get("version"),
        "evidence": contract.get("evidence", {}),
    }
    if op in {"decode_complete", "decode_payload_json", "get_unverified_header"}:
        canon_expected = {key: expected[key] for key in ("header", "payload", "signature_b64", "has_signature") if key in expected}
        case.update({"canonical_op": "decode_complete", "params": {"token": params["token"]}, "expected": canon_expected})
    elif op in {"decode_claim_value", "decode_claim_value_unverified"}:
        case.update({"canonical_op": "decode_claim", "params": {"token": params["token"], "claim": params["claim"]}, "expected": {"value": expected["value"]}})
    elif op in {"decode_error", "parse_error"}:
        case.update({"canonical_op": "decode_error", "params": {"token": params.get("token", "")}, "expected": {"error": True}})
    elif op == "verify_hmac":
        p = {"token": params["token"], "algorithm": params.get("algorithm", "HS256"), "options": params.get("options", {})}
        if "secret" in params:
            p["secret"] = params["secret"]
        if "secret_b64" in params:
            p["secret_b64"] = params["secret_b64"]
        case.update({"canonical_op": "verify_hmac_literal", "params": p, "expected": {"ok": bool(expected.get("ok"))}})
    elif op == "sign_hmac":
        case.update({"canonical_op": "sign_hmac", "params": {"claims": params.get("claims", {}), "secret": params.get("secret", "secret"), "algorithm": params.get("algorithm", "HS256"), "headers": params.get("headers", {})}, "expected": expected})
    elif op == "verify_generated_hmac":
        case.update({"canonical_op": "sign_then_verify_hmac", "params": {"claims": params.get("claims", {}), "secret": params.get("secret", "secret"), "verifySecret": params.get("verifySecret", params.get("secret", "secret")), "algorithm": params.get("algorithm", "HS256"), "options": params.get("options", {})}, "expected": {"ok": bool(expected.get("ok"))}})
    elif op == "sign_none":
        case.update({"canonical_op": "none_algorithm", "params": {"claims": params.get("claims", {})}, "expected": expected})
    elif op.startswith("claim_"):
        case.update({"canonical_op": op, "params": params, "expected": expected})
    elif op.startswith("key_") or op.startswith("jwk_"):
        case.update({"canonical_op": op, "params": params, "expected": expected})
    else:
        case.update({"canonical_op": op, "params": params, "expected": expected})
    case["mutant"] = with_mutant(case["expected"])
    case["identity"] = json.dumps([case["canonical_op"], case["params"], case["expected"]], sort_keys=True, ensure_ascii=True)
    return case


def mark_common_overlap(contracts: list[dict[str, Any]], origin: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    common_ids, common_by_identity, common_rows = load_final_common_identities()
    marked: list[dict[str, Any]] = []
    overlap = 0
    for contract in contracts:
        row = dict(contract)
        canonical = canonical_contract(row, origin)
        overlap_id = common_by_identity.get(canonical["identity"])
        is_overlap = overlap_id is not None
        if not is_overlap:
            for common in common_rows:
                if common.get("canonical_op") != canonical["canonical_op"]:
                    continue
                if common.get("params") != canonical["params"]:
                    continue
                if matches(canonical["expected"], common.get("expected", {})) or matches(common.get("expected", {}), canonical["expected"]):
                    is_overlap = True
                    overlap_id = common.get("id")
                    break
        overlap += int(is_overlap)
        row["canonical"] = canonical
        row["overlaps_final_common_349"] = is_overlap
        row["final_common_id"] = overlap_id
        marked.append(row)
    summary = {
        "final_common_reference_count": len(common_ids),
        "survivor_overlap_with_final_common": overlap,
        "origin_non_common_survivors": len(contracts) - overlap,
    }
    return marked, summary


def matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        for key, value in expected.items():
            if key not in actual or not matches(actual[key], value):
                return False
        return True
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
    if isinstance(expected, int) and isinstance(actual, float):
        return expected == int(actual) and actual.is_integer()
    return actual == expected


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for contract in contracts:
        lines.append(f"contract {json.dumps(contract['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(contract['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(contract['capability'], ensure_ascii=True)}")
        lines.append(f"  op {contract['op']}")
        lines.append(f"  params {json.dumps(contract['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(contract['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
