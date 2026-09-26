#!/usr/bin/env python3
"""Run the public ShapingBench evaluator for one submission and domain."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from score import DOMAIN_NAMES, parse_common_counts


ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "tools/replay"
EXECUTABLE = ROOT / "analysis/executable_contract_system/run_domain.py"

COMMON = {
    "http": ("replay_generated_solhttp_survival.py", "contracts/solhttp/{label}_survival_from_guzzle_common_114.json"),
    "datetime": ("replay_generated_datetime.py", "contracts/datetime_timezone/generated/sol_datetime_{label}_survival_from_confirmed_common_250.json"),
    "url_iri": ("replay_generated_url_iri_common.py", "contracts/url_iri/generated/solurl_{label}_survival_from_common_245.json"),
    "html_sanitizer": ("replay_generated_html_sanitizer_common.py", "contracts/html_sanitizer/generated/{label}_survival_from_common_90.json"),
    "markdown": ("replay_generated_markdown_common.py", "contracts/markdown/generated/solmarkdown_{label}_survival_from_common_877.json"),
    "yaml": ("replay_generated_yaml_common.py", "contracts/yaml/generated/solyaml_{label}_survival_from_common_1172.json"),
    "jwt": ("replay_generated_jwt_common.py", "contracts/jwt/generated/{label}_survival_from_common_349.json"),
    "cron": ("replay_generated_cron_common.py", "contracts/cron/generated/{label}_survival_from_common_113.json"),
    "resilience": ("replay_generated_resilience_policy_common.py", "contracts/resilience_policy/generated/{label}_survival_from_resilience_common_78.json"),
}


def common_command(domain: str, snapshot: Path, label: str, python: str) -> tuple[list[str], dict[str, str]]:
    script = str(REPLAY / COMMON[domain][0])
    env: dict[str, str] = {}
    if domain == "http":
        env = {"SOLHTTP_ROOT": str(snapshot), "SOLHTTP_RUN_LABEL": label}
        return [python, script], env
    if domain in {"datetime", "url_iri", "markdown", "yaml", "jwt", "cron"}:
        return [python, script, str(snapshot), "--label", label], env
    if domain in {"html_sanitizer", "resilience"}:
        return [python, script, "--implementation", str(snapshot), "--label", label], env
    raise AssertionError(domain)


def variable_result(output: Path, domain: str) -> Path:
    if domain == "http":
        return output / "solhttp_measurement_results.jsonl"
    if domain in {"html_sanitizer", "markdown", "yaml"}:
        return output / domain / "strict_results.jsonl"
    return output / "strict_results.jsonl"


def run_checked(command: list[str], env: dict[str, str], log_prefix: Path) -> None:
    process = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    log_prefix.with_suffix(".stdout.log").write_text(process.stdout, encoding="utf-8")
    log_prefix.with_suffix(".stderr.log").write_text(process.stderr, encoding="utf-8")
    if process.returncode:
        raise SystemExit(f"command failed ({process.returncode}); see {log_prefix}.stderr.log")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, choices=sorted(DOMAIN_NAMES))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--label", default="submission")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    if not snapshot.is_dir():
        raise SystemExit(f"submission directory does not exist: {snapshot}")
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", args.label).strip("_") or "submission"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    command, additions = common_command(args.domain, snapshot, label, args.python)
    common_env = os.environ.copy()
    common_env.update(additions)
    run_checked(command, common_env, output / "common")
    generated_common = ROOT / COMMON[args.domain][1].format(label=label)
    if not generated_common.is_file():
        raise SystemExit(f"common evaluator did not create {generated_common}")
    common_copy = output / "common_results.json"
    shutil.copy2(generated_common, common_copy)
    common_total, common_passed = parse_common_counts(args.domain, common_copy)

    variable_output = output / "variable"
    variable_command = [
        args.python, str(EXECUTABLE), "--domain", args.domain,
        "--snapshot", str(snapshot), "--output", str(variable_output),
        "--python", args.python, "--label", label,
    ]
    run_checked(variable_command, os.environ.copy(), output / "variable")
    variable_path = variable_result(variable_output, args.domain)
    if not variable_path.is_file():
        raise SystemExit(f"variable evaluator did not create {variable_path}")

    score_command = [
        args.python, str(Path(__file__).with_name("score.py")),
        "--domain", args.domain, "--common-json", str(common_copy),
        "--variable-jsonl", str(variable_path), "--output", str(output / "scores"),
    ]
    run_checked(score_command, os.environ.copy(), output / "score")
    summary = json.loads((output / "scores/summary.json").read_text(encoding="utf-8"))
    execution = {
        "domain": args.domain,
        "domain_name": DOMAIN_NAMES[args.domain],
        "snapshot": str(snapshot),
        "label": label,
        "python": args.python,
        "common_command": command,
        "variable_command": variable_command,
        "common_component": {"passed": common_passed, "total": common_total},
        "summary": summary,
    }
    (output / "execution.json").write_text(json.dumps(execution, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
