#!/usr/bin/env python3
"""Replay OWASP java-html-sanitizer contracts against the latest Maven release."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "contracts" / "html_sanitizer" / "java-html-sanitizer"
CONTRACTS_JSON = OUT_DIR / "all_releases_excluding_dompurify.summary.json"
RUNNER_DIR = ROOT / "tools" / "replay" / "java_html_sanitizer_latest_runner"
RUNTIME_DIR = ROOT / ".cache" / "runtime" / "java-html-sanitizer"
JDK_DIR = RUNTIME_DIR / "jdk"
MAVEN_DIR = RUNTIME_DIR / "apache-maven-3.9.11"
MAVEN_URL = "https://dlcdn.apache.org/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz"
JDK_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/mac/aarch64/jdk/hotspot/normal/eclipse"


def find_exe(name: str) -> str | None:
    return shutil.which(name)


def download(url: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    with urllib.request.urlopen(url, timeout=120) as response:
        path.write_bytes(response.read())


def extract_single_root_tarball(tar_path: Path, target: Path) -> None:
    if target.exists():
        return
    tmp = target.with_name(target.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    with tarfile.open(tar_path) as tf:
        tf.extractall(tmp)
    roots = [p for p in tmp.iterdir() if p.is_dir()]
    if len(roots) != 1:
        raise RuntimeError(f"expected one root in {tar_path}, got {roots}")
    roots[0].rename(target)
    shutil.rmtree(tmp)


def ensure_java() -> tuple[str, dict[str, str]]:
    java = find_exe("java")
    if java:
        return java, os.environ.copy()
    if platform.system() != "Darwin" or platform.machine() not in {"arm64", "aarch64"}:
        raise RuntimeError("No local Java runtime and no bundled downloader for this platform")
    tar_path = RUNTIME_DIR / "temurin-21-mac-aarch64.tar.gz"
    download(JDK_URL, tar_path)
    extract_single_root_tarball(tar_path, JDK_DIR)
    contents = next((JDK_DIR / "Contents" / "Home").glob("*"), None)
    java_home = JDK_DIR / "Contents" / "Home" if (JDK_DIR / "Contents" / "Home" / "bin" / "java").exists() else None
    if java_home is None:
        candidates = list(JDK_DIR.glob("**/bin/java"))
        if not candidates:
            raise RuntimeError("downloaded JDK did not contain bin/java")
        java_home = candidates[0].parents[1]
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    return str(java_home / "bin" / "java"), env


def ensure_maven(env: dict[str, str]) -> str:
    mvn = shutil.which("mvn", path=env.get("PATH"))
    if mvn:
        return mvn
    tar_path = RUNTIME_DIR / "apache-maven-3.9.11-bin.tar.gz"
    download(MAVEN_URL, tar_path)
    extract_single_root_tarball(tar_path, MAVEN_DIR)
    return str(MAVEN_DIR / "bin" / "mvn")


def run_latest() -> dict[str, Any]:
    _, env = ensure_java()
    mvn = ensure_maven(env)
    cmd = [
        mvn,
        "-q",
        "-DskipTests",
        "compile",
        "exec:java",
        "-Dexec.mainClass=org.owasp.html.ShapingBenchRunner",
        f"-Dexec.args={CONTRACTS_JSON}",
    ]
    out = subprocess.check_output(cmd, cwd=RUNNER_DIR, env=env, text=True, stderr=subprocess.STDOUT)
    match = re.search(r"(\{\"results\":.*\})\s*$", out, re.S)
    if not match:
        raise RuntimeError(out)
    return json.loads(match.group(1))


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines: list[str] = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'])} {{")
        lines.append(f"  version {json.dumps(row['version'])}")
        lines.append(f"  capability {json.dumps(row['capability'])}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    source = json.loads(CONTRACTS_JSON.read_text(encoding="utf-8"))
    contracts = source["contracts"]
    result = run_latest()
    result_by_name = {row["name"]: row for row in result["results"]}
    survivors = []
    failed = []
    for contract in contracts:
        row = result_by_name[contract["name"]]
        if row["replay_passed"] and row["mutant_rejected"]:
            survivors.append(contract)
        else:
            failed.append({"contract": contract, "result": row})

    by_cap = Counter(row["capability"] for row in survivors)
    by_op = Counter(row["op"] for row in survivors)
    replay_passed = sum(1 for row in result["results"] if row["replay_passed"])
    mutant_killed = sum(1 for row in result["results"] if row["replay_passed"] and row["mutant_rejected"])
    summary = {
        "domain": source["domain"],
        "project": source["project"],
        "latest_version": source["latest_version"],
        "input_contracts": len(contracts),
        "latest_replay_passed": replay_passed,
        "latest_replay_failed": len(contracts) - replay_passed,
        "latest_mutant_killed": mutant_killed,
        "latest_survivors": len(survivors),
        "by_capability": dict(sorted(by_cap.items())),
        "by_op": dict(sorted(by_op.items())),
        "survivors": survivors,
        "failed": failed,
    }
    (OUT_DIR / "latest_replay_mutant_verified.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    write_rpl(survivors, OUT_DIR / "latest_replay_mutant_verified.rpl")

    lines = [
        "# OWASP Java HTML Sanitizer Latest Replay + Mutant Verification",
        "",
        f"Project: `{summary['project']}`",
        f"Latest version tested: `{summary['latest_version']}`",
        f"Input contracts: {summary['input_contracts']}",
        f"Replay passed: {summary['latest_replay_passed']}",
        f"Replay failed: {summary['latest_replay_failed']}",
        f"Mutants killed after replay pass: {summary['latest_mutant_killed']}",
        f"Latest survivors: {summary['latest_survivors']}",
        "",
        "## Survivors by Capability",
        "",
        "| Capability | Survivors |",
        "| --- | ---: |",
    ]
    for cap, count in sorted(by_cap.items()):
        lines.append(f"| `{cap}` | {count} |")
    lines.extend(["", "## Survivors by Operation", "", "| Operation | Survivors |", "| --- | ---: |"])
    for op, count in sorted(by_op.items()):
        lines.append(f"| `{op}` | {count} |")
    (OUT_DIR / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    printable = {k: summary[k] for k in [
        "latest_version", "input_contracts", "latest_replay_passed",
        "latest_replay_failed", "latest_mutant_killed", "latest_survivors",
        "by_capability", "by_op",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
