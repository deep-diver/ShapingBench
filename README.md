# ShapingBench

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/d125ded3-83f1-4d42-988d-9543162bf0b1" />

ShapingBench is an executable behavioral benchmark for evaluating coding-agent
implementations against behaviors recovered from mature open-source software.
The public release contains the frozen scoring inventory, the contract payloads,
the hidden-evaluation harness, exact public task descriptions, reference-support
metadata, and compact result tables needed to reproduce the reported analyses.

## Benchmark at a glance

- 9 software domains
- 45 reference implementations (5 per domain)
- 14,537 frozen scoring contracts
- 4,754 **Shared Core** contracts observed in all 5 references
- 9,783 **Variable Surface** contracts observed in 1--4 references
- Complete 1/5--5/5 reference-support evidence; no UNKNOWN support cells

| Domain | Public implementation | 1/5 | 2/5 | 3/5 | 4/5 | 5/5 | Total |
|---|---|---:|---:|---:|---:|---:|---:|
| HTTP Client | `solhttp` | 284 | 65 | 37 | 36 | 211 | 633 |
| Date, Time, and Time Zones | `./dtlib` | 209 | 104 | 77 | 14 | 250 | 654 |
| URL and IRI Processing | `solurl` | 324 | 37 | 582 | 899 | 330 | 2,172 |
| HTML Sanitization | `solsanitize` | 831 | 277 | 123 | 190 | 141 | 1,562 |
| Markdown Parsing and Rendering | `solmarkdown` | 371 | 163 | 223 | 288 | 1,114 | 2,159 |
| YAML Parsing and Emission | `solyaml` | 838 | 370 | 258 | 373 | 1,881 | 3,720 |
| JWT Signing and Verification | `soljwt` | 137 | 30 | 106 | 832 | 517 | 1,622 |
| Cron and Schedule Expressions | `solcron` | 831 | 140 | 183 | 165 | 177 | 1,496 |
| Retry, Backoff, and Resilience | `solretry` | 313 | 37 | 29 | 7 | 133 | 519 |

The 1/5--5/5 labels are empirical recurrence across reference implementations,
not importance levels. A 1/5 behavior may still be correctness- or
security-critical.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/verify_release.py
python -m unittest discover -s tests
```

Evaluate one independent implementation snapshot:

```bash
python evaluation/run.py \
  --domain url_iri \
  --snapshot /absolute/path/to/agent/workspace \
  --output runs/url_iri
```

The command writes raw evaluator logs, mapped contract evidence,
`support_scores.csv`, and `summary.json`. Supported domain keys are `http`,
`datetime`, `url_iri`, `html_sanitizer`, `markdown`, `yaml`, `jwt`, `cron`, and
`resilience`.

Read [Evaluating other agents](docs/EVALUATING_AGENTS.md) before running a new
agent. The benchmark contracts and evaluator must remain hidden while the agent
develops its implementation.

## Repository layout

| Path | Contents |
|---|---|
| `benchmark/tasks/` | Exact public task supplied to an agent for each domain |
| `benchmark/scoring_contracts.csv` | Canonical 14,537-row scoring inventory and five-reference support matrix |
| `benchmark/reference_implementations.csv` | Selected OSS identities, roles, versions, and provenance metadata |
| `contracts/` | Frozen executable contract payloads used by the evaluators |
| `tools/replay/` | Reference replay and agent-facing evaluation logic |
| `analysis/executable_contract_system/` | Strict Variable Surface execution and projection layer |
| `evaluation/` | Public one-domain runner and recurrence-aware scorer |
| `results/agent_evaluation/` | Compact machine-readable reported agent outcomes |
| `results/benchmark_validation/` | Full-corpus behavioral-mutant audit summaries |

See [Benchmark format](docs/BENCHMARK_FORMAT.md) and
[Reproduction notes](docs/REPRODUCING.md) for definitions and provenance.

## Release scope

This repository intentionally omits dependency caches, cloned upstream source
trees, generated agent workspaces, repeated intermediate reports, model API
credentials, and raw provider transcripts. The exact public tasks, frozen
contracts, evaluator code, reference-support matrix, compact final results, and
validation summaries are retained. The private development tree used to build
the release is not modified by this export.

## License

ShapingBench is released under the Apache License 2.0. See [LICENSE](LICENSE).
