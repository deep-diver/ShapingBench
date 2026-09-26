#!/usr/bin/env python3
"""Extract vercel/async-retry contracts and verify them on latest."""

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
OUT = ROOT / "contracts" / "resilience_policy" / "async-retry"
RUNNER = ROOT / "tools" / "replay" / "async_retry_latest_runner.mjs"
PRIOR = [
    ROOT / "contracts" / "resilience_policy" / "resilience4j" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "failsafe" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "backoff" / "latest_replay_mutant_verified.json",
    ROOT / "contracts" / "resilience_policy" / "exponential-backoff" / "latest_replay_mutant_verified.json",
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
        registry = fetch_json("https://registry.npmjs.org/async-retry")
        rows = []
        for version, meta in sorted(registry.get("versions", {}).items(), key=lambda kv: version_sort(kv[0])):
            rows.append(
                {
                    "version": version,
                    "date": registry.get("time", {}).get(version, ""),
                    "description": meta.get("description", ""),
                    "dist": {"tarball": meta.get("dist", {}).get("tarball", "")},
                    "main": meta.get("main"),
                    "dependencies": meta.get("dependencies", {}),
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
        releases = fetch_json("https://api.github.com/repos/vercel/async-retry/releases?per_page=100")
        gh_cache.write_text(
            json.dumps(
                sorted(
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
                    key=lambda r: version_sort(r["version"]),
                ),
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if not readme_cache.exists():
        readme_cache.write_text(
            fetch_text("https://raw.githubusercontent.com/vercel/async-retry/main/README.md"),
            encoding="utf-8",
        )

    npm = json.loads(npm_cache.read_text(encoding="utf-8"))
    gh = json.loads(gh_cache.read_text(encoding="utf-8"))
    if not audit_cache.exists():
        audit_cache.write_text(json.dumps(audit_tarballs(npm["versions"]), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return npm["versions"], gh


def audit_tarballs(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    terms = [
        "bail",
        "onRetry",
        "Promise.resolve",
        "randomize",
        "retries",
        "factor",
        "minTimeout",
        "maxTimeout",
        "attempt",
        "module.exports",
        "default",
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="shapingbench-async-retry-audit-") as td:
        base = Path(td)
        for row in versions:
            version = row["version"]
            pack = subprocess.run(
                ["npm", "pack", f"async-retry@{version}", "--json", "--pack-destination", str(base)],
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
            for pattern in ["README.md", "lib/**/*.js", "test/**/*.js", "index.js", "dist/**/*.js"]:
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
                    "public_file_count": sum(1 for f in package_dir.rglob("*") if f.is_file()),
                    "surface_digest": hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest(),
                }
            )
            try:
                tar_path.unlink()
                shutil.rmtree(extract_dir)
            except OSError:
                pass
    return rows


def release_by_version(version: str) -> dict[str, Any]:
    versions, _ = fetch_release_history()
    by_version = {r["version"]: r for r in versions}
    return by_version[version]


def earliest_with(term: str, fallback: str = "0.1.0") -> dict[str, Any]:
    versions, _ = fetch_release_history()
    audit = json.loads((OUT / "npm_tarball_surface_audit.json").read_text(encoding="utf-8"))
    by_version = {r["version"]: r for r in versions}
    for row in sorted(audit, key=lambda r: version_sort(r["version"])):
        if row.get("terms_present", {}).get(term):
            return by_version[row["version"]]
    return by_version[fallback]


def gh_body(version: str) -> str:
    _, gh = fetch_release_history()
    for row in gh:
        if row["version"] == version:
            body = re.sub(r"\s+", " ", row.get("body", "")).strip()
            return body[:260]
    return ""


def evidence(release: dict[str, Any], human: str) -> str:
    note = gh_body(release["version"])
    if note:
        return f"async-retry release {release['version']}: {note}"
    return f"async-retry npm release {release['version']} ({release.get('date', '')}): {human}"


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
            "name": f"async_retry_{release['version'].replace('.', '_')}_{slug(capability)}_{key}",
            "version": release["version"],
            "project": "vercel/async-retry",
            "domain": "retry_backoff_resilience_policy_engine",
            "capability": capability,
            "op": "retry_call",
            "params": params,
            "evidence": evidence(release, human),
            "human": human,
            "pass": pass_name,
        }
    )


def build_candidates() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    releases, gh = fetch_release_history()
    rows: list[dict[str, Any]] = []
    base = release_by_version("0.1.0")
    onretry = release_by_version("0.2.0")
    optional = release_by_version("0.2.1")
    promise = release_by_version("1.1.2")
    onretry_attempt = release_by_version("1.2.0")
    random_default = release_by_version("1.3.0")
    optional_again = release_by_version("1.3.1")

    for fn_mode, value in [
        ("syncValue", "ok"),
        ("syncValue", 0),
        ("syncValue", False),
        ("syncValue", ""),
        ("syncValue", {"payload": "done"}),
        ("asyncPromise", "ok"),
        ("asyncPromise", "__undefined__"),
    ]:
        add(rows, promise if fn_mode == "syncValue" else base, "retrier.returned-value-resolution", {"fnMode": fn_mode, "randomize": False, "outcomes": [value]}, f"retrier {fn_mode} resolves successful value {value!r}")

    for failures in [1, 2, 3, 4]:
        add(
            rows,
            base,
            "retry.retries-until-later-success",
            {"retries": failures, "minTimeout": 1, "factor": 1, "randomize": False, "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"retry makes {failures} retries and resolves when the later attempt succeeds",
        )
    for retries in [0, 1, 2, 3, 5]:
        add(
            rows,
            base,
            "retry.retries-option-is-retry-count-not-total-attempts",
            {"retries": retries, "minTimeout": 1, "factor": 1, "randomize": False, "outcomes": ["throw:transient"] * 10},
            f"retries={retries} allows initial attempt plus retry-count attempts before rejecting",
        )

    for outcome in ["bail:fatal", "bail:transient", "bail:other"]:
        add(
            rows,
            base,
            "bail.abort-without-scheduling-retry",
            {"retries": 5, "minTimeout": 1, "randomize": False, "outcomes": [outcome, "ok"]},
            f"{outcome} aborts retrying immediately without scheduling a retry",
        )
    for outcome in ["throw_bail_flag:fatal", "throw_bail_flag:transient"]:
        add(
            rows,
            base,
            "error.bail-flag-aborts-retry",
            {"retries": 5, "minTimeout": 1, "randomize": False, "outcomes": [outcome, "ok"]},
            f"throwing an error object with bail=true aborts retrying immediately",
            "pass2",
        )
    add(
        rows,
        base,
        "bail.without-error-uses-aborted-error",
        {"retries": 5, "minTimeout": 1, "randomize": False, "outcomes": ["bail"]},
        "calling bail without a supplied error rejects with the library's default abort error",
        "pass2",
    )

    for retries, failures in [(3, 1), (3, 2), (3, 3), (5, 4)]:
        add(
            rows,
            onretry,
            "onRetry.called-only-for-scheduled-retries",
            {"retries": retries, "minTimeout": 1, "factor": 1, "randomize": False, "onRetryMode": "capture", "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"onRetry is called for each failed attempt that schedules a retry, failures={failures}",
        )
    for retries in [0, 1, 2]:
        add(
            rows,
            onretry,
            "onRetry.not-called-on-final-giveup",
            {"retries": retries, "minTimeout": 1, "factor": 1, "randomize": False, "onRetryMode": "capture", "outcomes": ["throw:transient"] * 10},
            f"onRetry is not called for the final failure after retries={retries} is exhausted",
            "pass2",
        )
    for outcome in ["bail:fatal", "throw_bail_flag:fatal"]:
        add(
            rows,
            onretry,
            "onRetry.not-called-for-bail",
            {"retries": 4, "minTimeout": 1, "randomize": False, "onRetryMode": "capture", "outcomes": [outcome, "ok"]},
            f"onRetry is not called when retrying is aborted by {outcome}",
            "pass2",
        )

    for failures in [1, 2, 3, 4]:
        add(
            rows,
            onretry_attempt,
            "onRetry.receives-failed-attempt-number",
            {"retries": failures, "minTimeout": 1, "factor": 1, "randomize": False, "onRetryMode": "capture", "outcomes": ["throw:transient"] * failures + ["ok"]},
            f"onRetry receives the failed attempt number for failures={failures}",
        )

    for factor in [1, 1.5, 2, 3, 4]:
        add(
            rows,
            base,
            "factor.shapes-timeout-sequence",
            {"retries": 4, "minTimeout": 8, "factor": factor, "randomize": False, "outcomes": ["throw:transient"] * 4 + ["ok"]},
            f"factor={factor} shapes the timeout sequence passed through node-retry",
        )
    for min_timeout in [0, 1, 5, 10, 25]:
        add(
            rows,
            base,
            "minTimeout.first-retry-delay-and-minimum-floor",
            {"retries": 3, "minTimeout": min_timeout, "factor": 2, "randomize": False, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"minTimeout={min_timeout} controls first retry delay, with node-retry's lower floor applied",
        )
    for max_timeout in [10, 12, 16, 40]:
        add(
            rows,
            base,
            "maxTimeout.caps-computed-timeouts",
            {"retries": 5, "minTimeout": 10, "factor": 2, "maxTimeout": max_timeout, "randomize": False, "outcomes": ["throw:transient"] * 5 + ["ok"]},
            f"maxTimeout={max_timeout} caps each computed retry timeout",
        )
    for max_timeout in [0, 1, 9]:
        add(
            rows,
            base,
            "invalid-timeout-bounds-reject-before-first-attempt",
            {"retries": 3, "minTimeout": 10, "maxTimeout": max_timeout, "randomize": False, "outcomes": ["ok"]},
            f"maxTimeout={max_timeout} below minTimeout rejects before the retrier is first invoked",
            "pass2",
        )

    for random_value in [0, 0.25, 0.5, 0.9, 1]:
        add(
            rows,
            base,
            "randomize.true-multiplies-timeout-by-one-to-two-factor",
            {"retries": 3, "minTimeout": 10, "factor": 2, "randomize": True, "random": random_value, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"randomize=true multiplies each timeout by Math.random()+1 with Math.random={random_value}",
            "pass2",
        )
    for random_value in [0, 0.25, 0.5]:
        add(
            rows,
            random_default,
            "randomize.defaults-to-true-when-option-omitted",
            {"retries": 3, "minTimeout": 10, "factor": 2, "random": random_value, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"async-retry defaults randomize to true when the option is omitted, Math.random={random_value}",
        )
    for random_value in [0, 0.9]:
        add(
            rows,
            base,
            "randomize.false-keeps-deterministic-computed-timeouts",
            {"retries": 3, "minTimeout": 10, "factor": 2, "randomize": False, "random": random_value, "outcomes": ["throw:transient"] * 3 + ["ok"]},
            f"randomize=false ignores Math.random={random_value} and keeps computed timeouts",
            "pass2",
        )

    for timeouts in [[1], [1, 3], [2, 5, 9], [5, 1, 4]]:
        add(
            rows,
            base,
            "timeouts-array.defines-explicit-retry-schedule",
            {"optsMode": "numberArray", "timeouts": timeouts, "outcomes": ["throw:transient"] * (len(timeouts) + 1) + ["ok"]},
            f"array opts {timeouts} define the explicit retry schedule",
            "pass2",
        )

    for release, mode in [(optional, "undefined"), (optional_again, "undefined")]:
        add(
            rows,
            release,
            "opts.optional-defaults-to-object",
            {"optsMode": mode, "random": 0, "outcomes": ["ok"]},
            f"opts may be omitted and retry still resolves on first success ({release['version']})",
        )
    add(
        rows,
        optional_again,
        "opts.optional-still-uses-default-retry-policy",
        {"optsMode": "undefined", "random": 0, "outcomes": ["throw:transient", "ok"]},
        "when opts is omitted, the default retry policy still retries a transient failure",
        "pass2",
    )

    for outcome in ["throw:transient", "reject:transient", "throw:string", "throw:object"]:
        add(
            rows,
            base,
            "failure-style.propagated-after-retry-exhaustion",
            {"retries": 0, "minTimeout": 1, "randomize": False, "outcomes": [outcome]},
            f"failure style {outcome} is propagated after retry exhaustion",
            "pass2",
        )
    for first_outcome in ["throw:transient", "reject:transient", "throw:string", "throw:object"]:
        add(
            rows,
            promise,
            "failure-style.can-retry-sync-throw-and-promise-rejection",
            {"retries": 1, "minTimeout": 1, "randomize": False, "outcomes": [first_outcome, "ok"]},
            f"{first_outcome} can be retried before a later success",
            "pass2",
        )

    for pair in [
        ["throw:fatal", "throw:transient", "throw:transient"],
        ["throw:transient", "throw:fatal", "throw:fatal"],
        ["throw:other", "throw:other", "throw:fatal"],
    ]:
        add(
            rows,
            base,
            "mainError.selects-most-frequent-final-error",
            {"retries": len(pair) - 1, "minTimeout": 1, "factor": 1, "randomize": False, "outcomes": pair},
            f"final rejection uses node-retry mainError selection from failure sequence {pair}",
            "pass2",
        )

    add(
        rows,
        base,
        "invalid-timeout-bounds-reject-before-first-attempt",
        {"retries": 3, "minTimeout": 20, "maxTimeout": 10, "randomize": False, "outcomes": ["ok"]},
        "minTimeout greater than maxTimeout rejects before the retrier is first invoked",
        "pass2",
    )

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        params = dict(row["params"])
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
        "exclusion_note": "Exact deterministic de-duplication across resilience-policy APIs is not meaningful; generation avoided broad circuit-breaker/fallback/decorator wait-generator overlap and focused on async-retry-specific public call semantics, bail, onRetry, node-retry option pass-through, timeout arrays, and default randomization.",
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
        "latest_target": "async-retry@1.3.3",
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
        "# vercel/async-retry latest survivor contracts",
        "",
        f"- Latest target: `async-retry@1.3.3`",
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
                "# vercel/async-retry extraction audit",
                "",
                "Extraction inspected all npm-published versions, all GitHub release notes, and public package tarball surfaces.",
                "Contracts are externally observable through the exported `retry(fn, opts)` call and its effects on returned values, thrown/rejected errors, attempt numbers, scheduled retry delays, `bail`, and `onRetry`.",
                "",
                f"- npm versions inspected: `{metadata['npm_versions_seen']}`",
                f"- GitHub releases inspected: `{metadata['github_releases_seen']}`",
                f"- Prior resilience-policy signature families loaded: `{metadata['prior_signature_families_seen']}`",
                f"- Candidate contracts after prior-overlap avoidance: `{metadata['candidate_contracts']}`",
                f"- Latest replay/mutant survivors: `{len(survivors)}`",
                "",
                "Overlap policy: avoided broad retry-policy and backoff-generator contracts already represented by earlier OSS where possible, and emphasized async-retry-specific behavior: `bail`, `err.bail`, optional opts, `onRetry`, attempt-number propagation, node-retry option pass-through, timeout arrays, default randomization, and sync/async retrier normalization.",
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
