#!/usr/bin/env python3
"""Execute and select one immutable non-common scoring contract."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
HTTP = "http"
DIRECT = {"html_sanitizer", "markdown", "yaml"}


def result_path(output: Path, domain: str) -> Path:
    if domain == HTTP:
        return output / "solhttp_measurement_results.jsonl"
    if domain in DIRECT:
        return output / domain / "strict_results.jsonl"
    return output / "strict_results.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--evidence-output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="shapingbench-contract-") as raw:
        output = Path(raw)
        command = [
            args.python, str(HERE / "run_domain.py"),
            "--domain", args.domain,
            "--snapshot", str(args.snapshot),
            "--output", str(output),
            "--python", args.python,
            "--label", "single-contract-selection",
        ]
        process = subprocess.run(command, text=True, capture_output=True)
        if process.returncode:
            sys.stderr.write(process.stderr)
            return process.returncode
        path = result_path(output, args.domain)
        matches = [
            row for row in map(json.loads, path.read_text().splitlines())
            if (row.get("scoring_id") or row.get("contract_id")) == args.contract_id
        ]
        if len(matches) != 1:
            raise SystemExit(f"expected one scoring row, found {len(matches)}")
        row = matches[0]
        encoded = json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.evidence_output:
            args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
            args.evidence_output.write_text(encoded)
        sys.stdout.write(encoded)
        verdict = str(row.get("verdict", ""))
        if verdict == "PASS":
            return 0
        if verdict.startswith("FAIL_"):
            return 1
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
