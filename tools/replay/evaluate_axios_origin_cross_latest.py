#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "contracts/axios/axios_origin_latest_replay_mutant_verified.json"
PY = ROOT / "contracts/axios/axios_origin_urllib3_2.7.0_cross_replay.json"
JAVA = ROOT / "contracts/axios/axios_origin_okhttp_5.5.0_cross_replay.json"
OUT = ROOT / "contracts/axios/axios_origin_cross_latest_summary.json"
MD = ROOT / "contracts/axios/axios_origin_cross_latest_summary.md"


def load_by_name(path):
    return {row["name"]: row for row in json.loads(path.read_text())["results"]}


def main():
    source = json.loads(SRC.read_text())["results"]
    urllib3 = load_by_name(PY)
    okhttp = load_by_name(JAVA)
    rows = []
    for item in source:
        name = item["name"]
        py = urllib3[name]
        ok = okhttp[name]
        if py["status"] == "passed" and ok["status"] == "passed":
            verdict = "passed_both_latest"
        elif "nonportable_api_surface" in {py["status"], ok["status"]}:
            verdict = "nonportable_api_surface"
        else:
            verdict = "failed_portable_replay"
        rows.append(
            {
                "name": name,
                "capability": item["capability"],
                "urllib3": py["status"],
                "okhttp": ok["status"],
                "verdict": verdict,
                "urllib3_detail": py["detail"],
                "okhttp_detail": ok["detail"],
            }
        )

    summary = {
        "source": "axios-origin contracts verified on Axios latest",
        "axios_latest_version": json.loads(SRC.read_text())["latest_version"],
        "urllib3_target": json.loads(PY.read_text())["summary"]["target_version"],
        "okhttp_target": json.loads(JAVA.read_text())["summary"]["target_version"],
        "source_contracts": len(rows),
        "passed_both_latest": sum(r["verdict"] == "passed_both_latest" for r in rows),
        "failed_portable_replay": sum(r["verdict"] == "failed_portable_replay" for r in rows),
        "nonportable_api_surface": sum(r["verdict"] == "nonportable_api_surface" for r in rows),
    }
    OUT.write_text(json.dumps({"summary": summary, "results": rows}, indent=2) + "\n")

    lines = [
        "# Axios-Origin Cross Latest Summary",
        "",
        f"- source_contracts: {summary['source_contracts']}",
        f"- axios_latest_version: {summary['axios_latest_version']}",
        f"- urllib3_target: {summary['urllib3_target']}",
        f"- okhttp_target: {summary['okhttp_target']}",
        f"- passed_both_latest: {summary['passed_both_latest']}",
        f"- failed_portable_replay: {summary['failed_portable_replay']}",
        f"- nonportable_api_surface: {summary['nonportable_api_surface']}",
        "",
        "| contract | urllib3 | OkHttp | verdict |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(f"| `{row['name']}` | {row['urllib3']} | {row['okhttp']} | {row['verdict']} |")
    MD.write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
