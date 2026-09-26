#!/usr/bin/env python3
"""
Verify executable urllib3 replay contracts.

This script is deliberately strict about the word "verified": a contract is
verified only when the real release artifact replay passes and its declared
mutant fails.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

BOOTSTRAP_ROOT = Path(__file__).resolve().parents[2]
if str(BOOTSTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(BOOTSTRAP_ROOT))

from tools.replay.replay_urllib3_03 import CONTRACT_PATH as URLIB3_03_CONTRACT_PATH
from tools.replay.replay_urllib3_03 import ROOT, parse_contract
from tools.replay.replay_urllib3_modern import CONTRACTS as MODERN_CONTRACTS


REPORT_JSON = ROOT / "contracts" / "urllib3" / "verification_report.json"
REPORT_MD = ROOT / "contracts" / "urllib3" / "verification_report.md"
MAXIMAL_SUMMARY = ROOT / "contracts" / "urllib3" / "all_releases_maximal_language_independent.summary.json"
MAXIMAL_RPL = ROOT / "contracts" / "urllib3" / "all_releases_maximal_language_independent.rpl"
VERIFIED_RPL = ROOT / "contracts" / "urllib3" / "verified.rpl"
VERIFIED_JSON = ROOT / "contracts" / "urllib3" / "verified.summary.json"


def run_command(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.returncode, completed.stdout


def verify_urllib3_03(env: str) -> list[dict]:
    code, output = run_command(
        [
            sys.executable,
            "tools/replay/replay_urllib3_03.py",
            "--env",
            env,
            "--batch",
        ]
    )
    try:
        rows = parse_last_json_line(output)
    except ValueError:
        spec = parse_contract(URLIB3_03_CONTRACT_PATH)
        rows = [
            {
                "version": spec.version,
                "contract": contract.name,
                "capability": contract.capability,
                "mutant": contract.mutant,
                "replay_exit_code": code,
                "mutant_exit_code": None,
                "replay_output_tail": output[-2000:],
                "mutant_output_tail": "",
            }
            for contract in spec.contracts
        ]
    results = []
    for row in rows:
        replay_code = row["replay_exit_code"]
        mutant_code = row["mutant_exit_code"]
        verified = replay_code == 0 and mutant_code not in (None, 0)
        results.append(
            {
                "project": "urllib3",
                "version": row["version"],
                "contract": row["contract"],
                "capability": row["capability"],
                "mutant": row["mutant"],
                "env": env,
                "replay_passed": replay_code == 0,
                "mutant_failed": mutant_code not in (None, 0),
                "verified": verified,
                "replay_exit_code": replay_code,
                "mutant_exit_code": mutant_code,
                "replay_output_tail": row.get("replay_output_tail", ""),
                "mutant_output_tail": row.get("mutant_output_tail", ""),
            }
        )
    return results


def verify_modern(env: str) -> list[dict]:
    if env == "docker":
        return verify_modern_docker_batched()
    results = []
    for key, spec in MODERN_CONTRACTS.items():
        version, contract_name = key.split(":", 1)
        base = [
            sys.executable,
            "tools/replay/replay_urllib3_modern.py",
            "--env",
            env,
            "--version",
            version,
            "--contract",
            contract_name,
        ]
        replay_code, replay_output = run_command(base)
        mutant_code, mutant_output = run_command(base + ["--mutant", spec["mutant"]])
        results.append(
            {
                "project": "urllib3",
                "version": version,
                "contract": contract_name,
                "capability": capability_for(version, contract_name),
                "mutant": spec["mutant"],
                "env": env,
                "replay_passed": replay_code == 0,
                "mutant_failed": mutant_code != 0,
                "verified": replay_code == 0 and mutant_code != 0,
                "replay_exit_code": replay_code,
                "mutant_exit_code": mutant_code,
                "replay_output_tail": replay_output[-2000:],
                "mutant_output_tail": mutant_output[-2000:],
            }
        )
    return results


def parse_last_json_line(output: str) -> list[dict]:
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            return json.loads(stripped)
    raise ValueError("No JSON result line found in output")


def verify_modern_docker_batched() -> list[dict]:
    results = []
    versions = sorted({key.split(":", 1)[0] for key in MODERN_CONTRACTS}, key=lambda item: tuple(int(part) for part in item.split(".")))
    for version in versions:
        code, output = run_command(
            [
                sys.executable,
                "tools/replay/replay_urllib3_modern.py",
                "--env",
                "docker",
                "--version",
                version,
                "--batch",
            ]
        )
        try:
            rows = parse_last_json_line(output)
        except ValueError:
            rows = [
                {
                    "version": version,
                    "contract": key.split(":", 1)[1],
                    "mutant": spec["mutant"],
                    "replay_exit_code": code,
                    "mutant_exit_code": None,
                    "replay_output_tail": output[-2000:],
                    "mutant_output_tail": "",
                }
                for key, spec in MODERN_CONTRACTS.items()
                if key.startswith(version + ":")
            ]
        for row in rows:
            replay_code = row["replay_exit_code"]
            mutant_code = row["mutant_exit_code"]
            results.append(
                {
                    "project": "urllib3",
                    "version": row["version"],
                    "contract": row["contract"],
                    "capability": capability_for(row["version"], row["contract"]),
                    "mutant": row["mutant"],
                    "env": "docker",
                    "replay_passed": replay_code == 0,
                    "mutant_failed": mutant_code not in (None, 0),
                    "verified": replay_code == 0 and mutant_code not in (None, 0),
                    "replay_exit_code": replay_code,
                    "mutant_exit_code": mutant_code,
                    "replay_output_tail": row.get("replay_output_tail", ""),
                    "mutant_output_tail": row.get("mutant_output_tail", ""),
                }
            )
    return results


def capability_for(version: str, contract_name: str) -> str:
    if not MAXIMAL_SUMMARY.exists():
        return ""
    summary = json.loads(MAXIMAL_SUMMARY.read_text(encoding="utf-8"))
    for release in summary["releases"]:
        if release["version"] != version:
            continue
        for contract in release["contracts"]:
            if contract["name"] == contract_name:
                return contract["capability"]
    return ""


def load_maximal_totals() -> dict:
    if not MAXIMAL_SUMMARY.exists():
        return {"release_count": None, "contract_count": None}
    summary = json.loads(MAXIMAL_SUMMARY.read_text(encoding="utf-8"))
    return {
        "release_count": summary["release_count"],
        "contract_count": summary["contract_count"],
        "maximal_summary": str(MAXIMAL_SUMMARY),
    }


def write_reports(report: dict) -> None:
    REPORT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = report["results"]
    verified_count = sum(1 for row in rows if row["verified"])
    envs = ", ".join(f"`{env}`" for env in report["envs"])
    lines = [
        "# urllib3 Contract Verification Report",
        "",
        f"- Environments: {envs}",
        f"- Maximal extracted contracts: {report['maximal'].get('contract_count')}",
        f"- Executable contracts attempted: {len(rows)}",
        f"- Verified contracts: {verified_count}",
        f"- Unique verified contracts: {report['unique_verified_count']}",
        f"- Not verified in this runner family: {report['maximal'].get('contract_count', 0) - report['unique_verified_count']}",
        "",
        "| Env | Version | Contract | Capability | Replay | Mutant killed | Verified |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| `{env}` | {version} | `{contract}` | `{capability}` | {replay} | {mutant} | {verified} |".format(
                env=row["env"],
                version=row["version"],
                contract=row["contract"],
                capability=row["capability"],
                replay="yes" if row["replay_passed"] else "no",
                mutant="yes" if row["mutant_failed"] else "no",
                verified="yes" if row["verified"] else "no",
            )
        )
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_verified_ledger(report: dict) -> None:
    verified_keys = {
        (row["version"], row["contract"])
        for row in report["results"]
        if row["verified"]
    }

    lines = [
        "# Verified urllib3 contracts.",
        "# A contract appears here only after replay passes and its declared mutant fails.",
        "",
    ]

    if ("0.3", "same_origin_sequential_requests_reuse_one_connection") in verified_keys:
        lines.extend(URLIB3_03_CONTRACT_PATH.read_text(encoding="utf-8").rstrip().splitlines())
        lines.append("")

    if MAXIMAL_RPL.exists():
        current_release: list[str] = []
        current_version = ""
        release_emitted = False
        block: list[str] | None = None
        block_name = ""
        for line in MAXIMAL_RPL.read_text(encoding="utf-8").splitlines():
            if line.startswith("release "):
                current_release = [line]
                current_version = line.split('version "', 1)[1].split('"', 1)[0]
                release_emitted = False
                block = None
                continue
            if line.startswith("source ") and current_release:
                current_release.append(line)
                continue
            if line.startswith('contract "'):
                block = [line]
                block_name = line.split('"', 2)[1]
                continue
            if block is not None:
                block.append(line)
                if line == "end":
                    if current_version != "0.3" and (current_version, block_name) in verified_keys:
                        if not release_emitted:
                            lines.extend(current_release)
                            lines.append("")
                            release_emitted = True
                        lines.extend(block)
                        lines.append("")
                    block = None

    unique = []
    seen = set()
    for row in report["results"]:
        key = (row["project"], row["version"], row["contract"])
        if row["verified"] and key not in seen:
            seen.add(key)
            unique.append({k: row[k] for k in ("project", "version", "contract", "capability", "mutant")})

    VERIFIED_RPL.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    VERIFIED_JSON.write_text(
        json.dumps(
            {
                "source_candidate_summary": str(MAXIMAL_SUMMARY),
                "verified_rpl": str(VERIFIED_RPL),
                "verified_contract_count": len(unique),
                "environments": report["envs"],
                "contracts": unique,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", choices=["local", "venv", "docker", "all"], default="local")
    args = parser.parse_args()

    envs = ["local", "venv", "docker"] if args.env == "all" else [args.env]
    results = []
    for env in envs:
        results.extend(verify_urllib3_03(env))
        results.extend(verify_modern(env))
    unique_verified = {
        (row["project"], row["version"], row["contract"])
        for row in results
        if row["verified"]
    }
    report = {
        "envs": envs,
        "maximal": load_maximal_totals(),
        "unique_verified_count": len(unique_verified),
        "results": results,
    }
    write_reports(report)
    write_verified_ledger(report)
    verified = sum(1 for row in results if row["verified"])
    print(f"verified={verified}/{len(results)} unique={len(unique_verified)} env={args.env}")
    print(REPORT_JSON)
    print(REPORT_MD)
    return 0 if verified == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
