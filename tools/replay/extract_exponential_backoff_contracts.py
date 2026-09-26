#!/usr/bin/env python3
"""Extract coveooss/exponential-backoff contracts and verify them on latest."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "resilience_policy" / "exponential-backoff"
RUNNER = ROOT / "tools" / "replay" / "exponential_backoff_latest_runner.mjs"
PRIOR = [
    ROOT / "contracts" / "resilience_policy" / "resilience4j" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "failsafe" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "backoff" / "latest_replay_mutant_verified.json",
]


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value.lower()).strip("_")
    return re.sub(r"_+", "_", value)[:82]


def version_sort(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)) or (0,)


def fetch_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=45) as res:
        return json.loads(res.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ShapingBench"})
    with urllib.request.urlopen(req, timeout=45) as res:
        return res.read().decode("utf-8", errors="replace")


def fetch_release_history() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    OUT.mkdir(parents=True, exist_ok=True)
    npm_cache = OUT / "npm_versions.json"
    gh_cache = OUT / "release_notes.github.json"
    readme_cache = OUT / "readme.latest.md"
    audit_cache = OUT / "npm_tarball_surface_audit.json"

    if not npm_cache.exists():
        registry = fetch_json("https://registry.npmjs.org/exponential-backoff")
        rows = []
        for version, meta in sorted(registry.get("versions", {}).items(), key=lambda kv: version_sort(kv[0])):
            rows.append(
                {
                    "version": version,
                    "date": registry.get("time", {}).get(version, ""),
                    "description": meta.get("description", ""),
                    "dist": {"tarball": meta.get("dist", {}).get("tarball", "")},
                    "main": meta.get("main"),
                    "types": meta.get("types") or meta.get("typings"),
                }
            )
        npm_cache.write_text(
            json.dumps(
                {
                    "name": registry.get("name"),
                    "latest": registry.get("dist-tags", {}).get("latest"),
                    "versions": rows,
                },
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if not gh_cache.exists():
        releases = fetch_json("https://api.github.com/repos/coveooss/exponential-backoff/releases?per_page=100")
        gh_cache.write_text(
            json.dumps(
                [
                    {
                        "tag_name": r.get("tag_name") or "",
                        "version": (r.get("tag_name") or "").lstrip("v"),
                        "published_at": r.get("published_at") or "",
                        "name": r.get("name") or "",
                        "body": r.get("body") or "",
                    }
                    for r in releases
                ],
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if not readme_cache.exists():
        readme_cache.write_text(
            fetch_text("https://raw.githubusercontent.com/coveooss/exponential-backoff/master/README.md"),
            encoding="utf-8",
        )

    npm = json.loads(npm_cache.read_text(encoding="utf-8"))
    gh = json.loads(gh_cache.read_text(encoding="utf-8"))
    if not audit_cache.exists():
        audit_cache.write_text(json.dumps(audit_tarballs(npm["versions"]), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return npm["versions"], gh


def audit_tarballs(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    terms = [
        "backOff",
        "delayFirstAttempt",
        "jitter",
        "full",
        "none",
        "maxDelay",
        "numOfAttempts",
        "retry",
        "startingDelay",
        "timeMultiple",
        "Minimum value is `1`",
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="shapingbench-expbackoff-audit-") as td:
        base = Path(td)
        for row in versions:
            version = row["version"]
            pack = subprocess.run(
                ["npm", "pack", f"exponential-backoff@{version}", "--json", "--pack-destination", str(base)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            pack_info = json.loads(pack.stdout)[0]
            tar_path = base / pack_info["filename"]
            extract_dir = base / f"pkg-{version}"
            extract_dir.mkdir()
            with tarfile.open(tar_path, "r:gz") as tf:
                tf.extractall(extract_dir)
            package_dir = extract_dir / "package"
            text_parts = []
            for pattern in ["README.md", "src/**/*.ts", "dist/**/*.js", "dist/**/*.d.ts"]:
                for file in package_dir.glob(pattern):
                    if file.is_file():
                        text_parts.append(file.read_text(encoding="utf-8", errors="replace"))
            blob = "\n".join(text_parts)
            rows.append(
                {
                    "version": version,
                    "date": row.get("date", ""),
                    "tarball": row.get("dist", {}).get("tarball", ""),
                    "terms_present": {term: (term in blob) for term in terms},
                    "public_file_count": sum(1 for _ in package_dir.rglob("*") if _.is_file()),
                    "surface_digest": hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest(),
                }
            )
            try:
                tar_path.unlink()
                shutil.rmtree(extract_dir)
            except OSError:
                pass
    return rows


def earliest_with(term: str, fallback: str = "1.0.2") -> dict[str, Any]:
    versions, _ = fetch_release_history()
    audit = json.loads((OUT / "npm_tarball_surface_audit.json").read_text(encoding="utf-8"))
    by_version = {r["version"]: r for r in versions}
    for row in sorted(audit, key=lambda r: version_sort(r["version"])):
        if row.get("terms_present", {}).get(term):
            return by_version[row["version"]]
    return by_version[fallback]


def evidence(release: dict[str, Any], human: str) -> str:
    return (
        f"exponential-backoff npm release {release['version']} ({release.get('date', '')}): "
        f"public package exposes backOff/BackOffOptions behavior; {human}"
    )


def load_prior_signatures() -> set[str]:
    sigs: set[str] = set()
    for path in PRIOR:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for contract in data.get("contracts", data if isinstance(data, list) else []):
            text = " ".join(str(contract.get(k, "")) for k in ["capability", "human", "op"])
            sigs.add(slug(text))
    return sigs


def add(rows: list[dict[str, Any]], release: dict[str, Any], capability: str, params: dict[str, Any], human: str, pass_name: str = "pass1") -> None:
    key = hashlib.sha256(stable_json([capability, params]).encode()).hexdigest()[:12]
    rows.append(
        {
            "name": f"exponential_backoff_{release['version'].replace('.', '_')}_{slug(capability)}_{key}",
            "version": release["version"],
            "project": "coveooss/exponential-backoff",
            "domain": "retry_backoff_resilience_policy_engine",
            "capability": capability,
            "op": "backoff_call",
            "params": params,
            "evidence": evidence(release, human),
            "human": human,
            "pass": pass_name,
        }
    )


def build_candidates() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    releases, gh = fetch_release_history()
    by_term = {term: earliest_with(term) for term in ["backOff", "delayFirstAttempt", "jitter", "maxDelay", "numOfAttempts", "retry", "startingDelay", "timeMultiple"]}
    rows: list[dict[str, Any]] = []

    base = by_term["backOff"]
    for value in ["ok", 0, False, "", {"payload": "done"}, "__undefined__"]:
        add(rows, base, "backOff.returns-first-successful-result", {"outcomes": [value]}, f"backOff resolves with the first successful request value {value!r}")

    num = by_term["numOfAttempts"]
    for attempts in [0, -3, 1, 2, 3, 5]:
        add(
            rows,
            num,
            "numOfAttempts.bounds-total-invocations",
            {"numOfAttempts": attempts, "startingDelay": 1, "outcomes": ["throw:transient"] * 8},
            f"numOfAttempts={attempts} bounds total calls, with values below one sanitized to one",
        )
    for failures in [1, 2, 3, 4]:
        add(
            rows,
            num,
            "numOfAttempts.success-before-limit",
            {"numOfAttempts": failures + 1, "startingDelay": 1, "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"request succeeds when a later attempt before numOfAttempts={failures + 1} succeeds",
        )

    start = by_term["startingDelay"]
    for delay in [0, 1, 7, 25, 100]:
        add(
            rows,
            start,
            "startingDelay.first-retry-delay-without-first-delay",
            {"startingDelay": delay, "numOfAttempts": 3, "outcomes": ["throw:transient", "ok"]},
            f"startingDelay={delay} is the first retry wait when delayFirstAttempt is false",
        )
    for delay in [1, 7, 25]:
        add(
            rows,
            start,
            "startingDelay.repeated-constant-when-multiple-one",
            {"startingDelay": delay, "timeMultiple": 1, "numOfAttempts": 5, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"timeMultiple=1 keeps every retry wait equal to startingDelay={delay}",
            "pass2",
        )

    mult = by_term["timeMultiple"]
    for multiple in [0, 0.5, 1, 1.5, 2, 3, 4]:
        add(
            rows,
            mult,
            "timeMultiple.exponential-retry-delay-sequence",
            {"startingDelay": 8, "timeMultiple": multiple, "numOfAttempts": 5, "outcomes": ["throw:transient"] * 4 + ["ok"]},
            f"timeMultiple={multiple} shapes the retry delay sequence from startingDelay",
        )
    for start_delay, multiple in [(3, 3), (4, 2.5), (9, 1.25)]:
        add(
            rows,
            mult,
            "timeMultiple.fractional-and-nondefault-base",
            {"startingDelay": start_delay, "timeMultiple": multiple, "numOfAttempts": 4, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"non-default startingDelay={start_delay} and timeMultiple={multiple} compose multiplicatively",
            "pass2",
        )

    first = by_term["delayFirstAttempt"]
    for delay, failures in [(5, 0), (5, 1), (9, 2), (11, 3)]:
        add(
            rows,
            first,
            "delayFirstAttempt.true-delays-before-initial-call",
            {"delayFirstAttempt": True, "startingDelay": delay, "timeMultiple": 2, "numOfAttempts": failures + 2, "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"delayFirstAttempt=true applies startingDelay={delay} before the first request",
        )
    for delay, failures in [(5, 0), (5, 1), (9, 2), (11, 3)]:
        add(
            rows,
            first,
            "delayFirstAttempt.false-skips-initial-delay",
            {"delayFirstAttempt": False, "startingDelay": delay, "timeMultiple": 2, "numOfAttempts": failures + 2, "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"delayFirstAttempt=false invokes the first request immediately before retry waits",
            "pass2",
        )

    maxd = by_term["maxDelay"]
    for cap in [0, 1, 9, 10, 15, 17, 40]:
        add(
            rows,
            maxd,
            "maxDelay.caps-each-computed-delay",
            {"startingDelay": 10, "timeMultiple": 2, "maxDelay": cap, "numOfAttempts": 6, "outcomes": ["throw:transient"] * 5 + ["ok"]},
            f"maxDelay={cap} caps every computed exponential retry delay",
        )
    for cap in [6, 12, 24]:
        add(
            rows,
            maxd,
            "maxDelay.composes-with-delayFirstAttempt",
            {"delayFirstAttempt": True, "startingDelay": 10, "timeMultiple": 3, "maxDelay": cap, "numOfAttempts": 4, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"maxDelay={cap} also caps the initial delay when delayFirstAttempt=true",
            "pass2",
        )

    jitter = by_term["jitter"]
    for random_value in [0, 0.24, 0.5, 0.75, 1]:
        add(
            rows,
            jitter,
            "jitter.full-randomizes-rounded-delay",
            {"jitter": "full", "random": random_value, "startingDelay": 20, "timeMultiple": 2, "numOfAttempts": 4, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"full jitter uses Math.random={random_value} and rounds within each computed delay",
        )
    for supplied in ["none", "unknown", "FULL"]:
        add(
            rows,
            jitter,
            "jitter.none-and-unknown-fall-back-to-computed-delay",
            {"jitter": supplied, "random": 0.12, "startingDelay": 12, "timeMultiple": 2, "numOfAttempts": 4, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"jitter={supplied!r} leaves the computed delay sequence unchanged unless it is exactly full",
            "pass2",
        )

    retry = by_term["retry"]
    for failures in [1, 2, 3]:
        add(
            rows,
            retry,
            "retry.callback-never-stops-after-first-failure",
            {"retryMode": "never", "startingDelay": 1, "numOfAttempts": failures + 2, "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"retry callback returning false stops after the first failed attempt",
        )
    for limit in [1, 2, 3, 4]:
        add(
            rows,
            retry,
            "retry.callback-attempt-number-controls-continuation",
            {"retryMode": "untilAttemptLessThan", "retryUntil": limit, "startingDelay": 1, "numOfAttempts": 6, "outcomes": ["throw:transient"] * 5 + ["ok"]},
            f"retry callback receives 1-based failed-attempt numbers and can stop before retryUntil={limit}",
        )
    for mode, outcomes in [
        ("onlyTransient", ["throw:transient", "ok"]),
        ("onlyTransient", ["throw:fatal", "ok"]),
        ("excludeFatal", ["throw:other", "ok"]),
        ("excludeFatal", ["throw:fatal", "ok"]),
    ]:
        add(
            rows,
            retry,
            "retry.callback-classifies-last-error",
            {"retryMode": mode, "startingDelay": 1, "numOfAttempts": 3, "outcomes": outcomes},
            f"retry callback mode {mode} makes continuation depend on the last error",
            "pass2",
        )
    for mode in ["promiseTrue", "promiseFalse"]:
        for retry_delay in [0, 3, 8]:
            add(
                rows,
                retry,
                "retry.callback-may-return-a-promise",
                {"retryMode": mode, "retryDelayMs": retry_delay, "startingDelay": 2, "numOfAttempts": 3, "outcomes": ["throw:transient", "ok"]},
                f"retry callback may asynchronously resolve {mode} after {retry_delay}ms before backOff continues",
                "pass2",
            )

    for outcome in ["throw:transient", "reject:transient", "throw:string", "throw:object"]:
        add(
            rows,
            base,
            "request-failure-style-is-propagated",
            {"startingDelay": 1, "numOfAttempts": 1, "outcomes": [outcome]},
            f"single-attempt failure {outcome} is propagated without retry conversion",
            "pass2",
        )
    for first_outcome, second_outcome in [("reject:transient", "ok"), ("throw:string", "ok"), ("throw:object", "ok")]:
        add(
            rows,
            retry,
            "retry.handles-rejected-and-non-error-failures",
            {"retryMode": "default", "startingDelay": 1, "numOfAttempts": 2, "outcomes": [first_outcome, second_outcome]},
            f"default retry handles {first_outcome} before later success",
            "pass2",
        )

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        sig = stable_json([row["capability"], row["params"]])
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(row)
    metadata = {
        "npm_versions_seen": len(releases),
        "github_releases_seen": len(gh),
        "prior_signature_families_seen": len(load_prior_signatures()),
        "candidate_contracts": len(unique),
        "exclusion_note": "Exact deterministic de-duplication across resilience-policy APIs is not meaningful; generation avoided generic circuit-breaker/rate-limiter/broad decorator surfaces and focused on exponential-backoff-specific public option semantics.",
    }
    return unique, metadata


def run_runner(contracts: list[dict[str, Any]], fill: bool) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
        json.dump({"contracts": contracts}, handle)
        path = Path(handle.name)
    try:
        cmd = ["node", str(RUNNER)]
        if fill:
            cmd.append("--fill")
        cmd.append(str(path))
        proc = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return json.loads(proc.stdout)["contracts"]
    finally:
        path.unlink(missing_ok=True)


def write_outputs(survivors: list[dict[str, Any]], all_contracts: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    by_version = Counter(c["version"] for c in survivors)
    by_cap = Counter(c["capability"] for c in survivors)
    summary = {
        **metadata,
        "latest_target": "exponential-backoff@3.1.3",
        "replay_passed": sum(1 for c in all_contracts if c.get("replayPass")),
        "mutant_rejected": sum(1 for c in all_contracts if c.get("mutantRejected")),
        "latest_survivors": len(survivors),
        "survivors_by_origin_version": dict(sorted(by_version.items(), key=lambda kv: version_sort(kv[0]))),
        "survivors_by_capability": dict(sorted(by_cap.items())),
    }
    (OUT / "all_releases_excluding_prior.json").write_text(json.dumps({"contracts": all_contracts, "summary": summary}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "all_releases_excluding_prior.summary.json").write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "all_releases_excluding_prior.rpl").write_text(
        "\n".join(
            f"contract {c['name']} {{ op: {c['op']}; params: {stable_json(c['params'])}; expect: {stable_json(c['expected'])}; }}"
            for c in all_contracts
        )
        + "\n",
        encoding="utf-8",
    )
    (OUT / "latest_replay_mutant_verified.json").write_text(json.dumps({"contracts": survivors, "summary": summary}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (OUT / "latest_replay_mutant_verified.rpl").write_text(
        "\n".join(
            f"contract {c['name']} {{ op: {c['op']}; params: {stable_json(c['params'])}; expect: {stable_json(c['expected'])}; }}"
            for c in survivors
        )
        + "\n",
        encoding="utf-8",
    )
    lines = [
        "# coveooss/exponential-backoff latest survivor contracts",
        "",
        f"- Latest target: `exponential-backoff@3.1.3`",
        f"- npm versions inspected: `{metadata['npm_versions_seen']}`",
        f"- GitHub releases inspected: `{metadata['github_releases_seen']}`",
        f"- Candidate contracts after prior-overlap avoidance: `{metadata['candidate_contracts']}`",
        f"- Replay passed on latest: `{summary['replay_passed']}`",
        f"- Mutant rejected on latest: `{summary['mutant_rejected']}`",
        f"- Latest replay/mutant survivors: `{len(survivors)}`",
        "",
        "## Survivors by capability",
        "",
    ]
    for cap, count in sorted(by_cap.items()):
        lines.append(f"- `{cap}`: {count}")
    lines.extend(["", "## Survivors by origin version", ""])
    for version, count in sorted(by_version.items(), key=lambda kv: version_sort(kv[0])):
        lines.append(f"- `{version}`: {count}")
    lines.extend(["", "## Contracts", ""])
    for c in survivors:
        lines.append(f"- `{c['name']}`: {c['human']}")
    (OUT / "latest_replay_mutant_verified.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "extraction_audit.md").write_text(
        "\n".join(
            [
                "# coveooss/exponential-backoff extraction audit",
                "",
                "Extraction inspected all npm-published versions and cached the single GitHub release note currently exposed by the repository.",
                "Because the release-note trail is sparse, public package README/source/type surfaces from each npm tarball were used to anchor first-observed option semantics.",
                "",
                f"- npm versions inspected: `{metadata['npm_versions_seen']}`",
                f"- GitHub releases inspected: `{metadata['github_releases_seen']}`",
                f"- Prior resilience-policy signature families loaded: `{metadata['prior_signature_families_seen']}`",
                f"- Candidate contracts after prior-overlap avoidance: `{metadata['candidate_contracts']}`",
                f"- Latest replay/mutant survivors: `{len(survivors)}`",
                "",
                "Overlap policy: avoided broad retry/circuit-breaker/bulkhead/fallback surfaces already represented by resilience4j, Failsafe, and litl/backoff, and focused this corpus on public `exponential-backoff` option semantics: attempt count bounding, first-delay policy, computed delay sequence, max-delay capping, jitter, retry callback behavior, async retry callback behavior, and JavaScript failure propagation.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    contracts, metadata = build_candidates()
    filled = run_runner(contracts, fill=True)
    checked = run_runner(filled, fill=False)
    survivors = [c for c in checked if c.get("replayPass") and c.get("mutantRejected")]
    write_outputs(survivors, checked, metadata)
    print(json.dumps({"summary": {**metadata, "latest_survivors": len(survivors)}}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
