# Reproduction Notes

## Included reproduction layers

1. **Inventory integrity**: `python scripts/verify_release.py` verifies all
   14,537 unique IDs, the exact recurrence distribution, 45 references, nine
   task prompts, known five-reference outcomes, and all referenced payloads.
2. **Submission evaluation**: `evaluation/run.py` executes the frozen contract
   suites against a compatible independent implementation and scores the result
   by recurrence.
3. **Reported analyses**: compact row-level and derived data are under
   `results/agent_evaluation/`.
4. **Oracle diagnostics**: the completed full-corpus behavioral-mutant audit is
   under `results/benchmark_validation/`.

## Environment

The public runner was verified with Python 3.12 and uses the pinned packages in
`requirements.txt`. Some reference-construction utilities also require native
or ecosystem runtimes such as Node.js, Java, Go, Rust, Ruby, PHP, or a C
compiler. Those upstream repositories, package caches, and compiled binaries
are intentionally not vendored.

The ordinary agent evaluator expects the public Python surfaces listed in
`docs/EVALUATING_AGENTS.md`; the Date/Time task instead provides `./dtlib`.

## Verify the export

```bash
python scripts/verify_release.py
python -m unittest discover -s tests -v
```

The expected support totals are:

| Support | Contracts |
|---|---:|
| 1/5 | 4,138 |
| 2/5 | 1,223 |
| 3/5 | 1,618 |
| 4/5 | 2,804 |
| 5/5 | 4,754 |
| Total | 14,537 |

## Reproduce one evaluation

```bash
python evaluation/run.py \
  --domain markdown \
  --snapshot /absolute/path/to/solmarkdown-workspace \
  --output runs/example-markdown \
  --label example-markdown
```

The command does not mutate the submitted workspace. Domain replay scripts may
write generated result files under `contracts/*/generated`; these paths are
ignored by Git and copied into the selected run output before scoring.

## Data lineage

- Contract inventory: `benchmark/scoring_contracts.csv`
- Reference selection metadata: `benchmark/reference_implementations.csv`
- Domain totals: `benchmark/support_summary.csv`
- Prompt provenance and hashes: `benchmark/prompt_sources.csv`
- Frozen payloads: paths in each inventory row's `source_artifact` field
- Agent analysis bundle metadata: `results/agent_evaluation/bundle_metadata.json`
- Mutant audit conclusions and limitations:
  `results/benchmark_validation/final_completion_report.md`

The release omits large upstream checkouts and raw agent workspaces. Therefore
it reproduces scoring of new compatible submissions and the included
machine-readable analyses, while exhaustive reconstruction of every historical
upstream release requires fetching the corresponding project/version listed in
the reference inventory.
