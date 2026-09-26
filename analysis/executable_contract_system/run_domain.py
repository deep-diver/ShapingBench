#!/usr/bin/env python3
"""Run one executable non-common contract suite against one target snapshot."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent

RUNNERS = {
    "http": HERE / "http/run_solhttp_measurement.py",
    "datetime": HERE / "datetime/run_strict.py",
    "url_iri": HERE / "url_iri/run_strict.py",
    "jwt": HERE / "jwt/run_strict.py",
    "cron": HERE / "cron/run_strict.py",
    "resilience": HERE / "resilience/run_strict.py",
    "html_sanitizer": HERE / "direct_domains/run_all.py",
    "markdown": HERE / "direct_domains/run_all.py",
    "yaml": HERE / "direct_domains/run_all.py",
}

DIRECT_ENV = {
    "html_sanitizer": "SHAPINGBENCH_HTML_SANITIZER_SNAPSHOT",
    "markdown": "SHAPINGBENCH_MARKDOWN_SNAPSHOT",
    "yaml": "SHAPINGBENCH_YAML_SNAPSHOT",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, choices=sorted(RUNNERS))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--label", default="target")
    args = parser.parse_args()
    if not args.snapshot.exists():
        raise SystemExit(f"snapshot does not exist: {args.snapshot}")
    args.output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SHAPINGBENCH_EXECUTION_OUTPUT"] = str(args.output)
    env["SHAPINGBENCH_TARGET_SNAPSHOT"] = str(args.snapshot)
    env["SHAPINGBENCH_TARGET_LABEL"] = args.label
    if args.domain in DIRECT_ENV:
        env[DIRECT_ENV[args.domain]] = str(args.snapshot)
        env["SHAPINGBENCH_DIRECT_DOMAIN"] = args.domain
    command = [args.python, str(RUNNERS[args.domain])]
    process = subprocess.run(command, env=env, text=True, capture_output=True)
    record = {
        "domain": args.domain,
        "snapshot": str(args.snapshot.resolve()),
        "output": str(args.output.resolve()),
        "command": command,
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    (args.output / "execution.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(process.stdout)
    sys.stderr.write(process.stderr)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
