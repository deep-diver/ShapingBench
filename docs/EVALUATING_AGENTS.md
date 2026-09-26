# Evaluating Other Coding Agents

This guide describes the protocol needed to obtain scores comparable to the
preserved ShapingBench runs.

## 1. Keep development and evaluation separate

1. Create a new empty workspace for one domain and one model-agent
   configuration.
2. Give the agent only the corresponding file in `benchmark/tasks/`.
3. Do not expose `benchmark/scoring_contracts.csv`, `contracts/`, `tools/replay/`,
   evaluator output, reference implementations, or previous agent solutions.
4. Preserve the workspace after each development session if a trajectory is
   being measured. Continue from that workspace; do not silently replace an
   intermediate checkpoint with a later or best-performing snapshot.
5. Run ShapingBench only after the checkpoint is frozen. Evaluation output must
   not be fed back to the agent unless the experimental condition explicitly
   permits broad hints.

The exact initial tasks and their source hashes are listed in
`benchmark/prompt_sources.csv`.

## 2. Required public surfaces

| Domain key | Task | Expected entry point |
|---|---|---|
| `http` | `benchmark/tasks/http_client.md` | Python package `solhttp` |
| `datetime` | `benchmark/tasks/date_time_timezone.md` | Executable `./dtlib` using JSONL stdin/stdout |
| `url_iri` | `benchmark/tasks/url_iri.md` | Python package `solurl` |
| `html_sanitizer` | `benchmark/tasks/html_sanitization.md` | Python package `solsanitize` |
| `markdown` | `benchmark/tasks/markdown.md` | Python package `solmarkdown` |
| `yaml` | `benchmark/tasks/yaml.md` | Python package `solyaml` |
| `jwt` | `benchmark/tasks/jwt.md` | Python package `soljwt` |
| `cron` | `benchmark/tasks/cron.md` | Python package `solcron` |
| `resilience` | `benchmark/tasks/retry_resilience.md` | Python package `solretry` |

If a new experiment intentionally uses another language or API, write a thin,
auditable adapter. It may translate inputs and observations to an equivalent
native interface; it must not implement missing algorithms, policies, expected
outputs, or behavior on behalf of the submission.

## 3. Run the evaluator

Install the analysis dependencies once:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Then evaluate a frozen snapshot:

```bash
python evaluation/run.py \
  --domain DOMAIN_KEY \
  --snapshot /absolute/path/to/frozen/workspace \
  --output runs/RUN_ID \
  --label RUN_ID
```

Use a new output directory for every checkpoint. The evaluator runs the frozen
construction-core suite and the strict residual suite, joins residual records to
canonical IDs, and then reports the current empirical partition:

- **Shared Core**: exact support 5/5.
- **Variable Surface**: exact support 1/5 through 4/5.
- **Full Surface**: both partitions combined.

Important outputs:

| File | Meaning |
|---|---|
| `common_results.json` | Raw result from the original construction-core replay |
| `variable/` | Strict executable residual results and observations |
| `scores/mapped_variable_results.jsonl.gz` | Canonical ID and recurrence for every residual scoring row |
| `scores/support_scores.csv` | PASS/FAIL totals for each 1/5--5/5 stratum |
| `scores/summary.json` | Shared Core, Variable Surface, and Full Surface coverage |
| `execution.json` | Commands, snapshot path, label, and aggregate result |
| `*.stdout.log`, `*.stderr.log` | Raw process output for diagnosis |

An evaluator crash, import failure, timeout in the harness, or missing result is
a measurement problem, not automatically a behavioral failure. Repair the
execution path and rerun the affected checkpoint. Do not weaken the contract or
oracle.

## 4. Report comparable results

Report, at minimum:

- agent framework and exact version;
- provider and model identifier;
- reasoning setting and permission/sandbox mode;
- exact public task hash;
- number and wording of development sessions or broad hints;
- frozen snapshot identifier;
- Python and relevant native runtime versions;
- PASS/total and coverage for 1/5, 2/5, 3/5, 4/5, and 5/5;
- Shared Core, Variable Surface, and Full Surface coverage;
- any adapter change, infrastructure failure, or unresolved result.

For multi-domain results, compute the headline macro average by first computing
coverage within each domain and then giving every domain equal weight. Do not
replace it with a contract-micro average without labeling the change.

## 5. Fairness checklist

- [ ] Independent clean workspace
- [ ] Exact public task only
- [ ] Contracts and evaluator hidden during development
- [ ] No previous solution or reference implementation exposed
- [ ] Checkpoint frozen before evaluation
- [ ] Same runtime and evaluator revision recorded
- [ ] Every missing execution investigated rather than counted as FAIL
- [ ] No adapter-side behavior emulation
- [ ] Recurrence strata and domain-macro aggregation reported
