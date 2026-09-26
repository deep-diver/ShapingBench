# Final Behavioral-Mutant Validity Audit

## Scope and Completion

This is an additive validity audit, not a benchmark revision or an agent reevaluation. All nine active domains, 14,537 exact scoring-row identities and 122,639 existing mutation slots are retained. No new operator volume is credited. Original contracts, expected observations, oracles and scores are unchanged. Adjudicating an invalid control is not the same as executing a valid mutation trial; the blocked population below remains explicit.

**Primary conditional detection rate: 21,861 / 22,587 = 96.786%.** The denominator contains only valid mutants that change a contract-required observation. It includes 726 genuine escapes on 284 distinct scoring rows. This rate is conditional on the measured subset, not a claim of full-corpus validation coverage.

| Quantity | Count |
| --- | --- |
| Scoring rows with at least one valid mutant | 13,330 / 14,537 |
| Scoring rows with a valid required-behavior change | 10922 |
| Valid required-behavior-changing mutants | 22587 |
| Killed required-behavior-changing mutants | 21861 |
| Genuinely surviving required-behavior mutants | 726 |
| Valid masked / score-preserving mutants, excluded from denominator | 23631 |
| Unresolved pair verdicts | 0 |
| Error / invalid-control / invalid-operator pair slots | 3315 |
| Total operationally unvalidated slots (ERROR + unresolved) | 3315 |
| Rows with no valid mutant: blocked | 535 |
| Rows with no valid mutant: unresolved | 0 |
| Rows with no applicable operator in the preserved finite catalog | 672 |

Source: `results/final_pair_results.jsonl.gz`, `results/final_scoring_rows.csv`, `results/final_domain_recurrence_summary.csv`. Pair counts are not unique implementations or independent mutation draws.

## Domain Results

| Domain | Rows covered / total | Required changes | Killed | Escapes | Valid masked | Unresolved pairs | Blocked rows |
| --- | --- | --- | --- | --- | --- | --- | --- |
| http_client | 293/633 | 219 | 215 | 4 | 565 | 0 | 315 |
| datetime_timezone | 646/654 | 776 | 776 | 0 | 769 | 0 | 4 |
| url_iri | 2,169/2,172 | 1826 | 1776 | 50 | 5066 | 0 | 2 |
| html_sanitizer | 1,515/1,562 | 2812 | 2747 | 65 | 3682 | 0 | 0 |
| markdown | 2,157/2,159 | 4702 | 4702 | 0 | 3132 | 0 | 0 |
| yaml | 3,580/3,720 | 5938 | 5938 | 0 | 4504 | 0 | 88 |
| jwt | 1,034/1,622 | 3538 | 3189 | 349 | 3556 | 0 | 48 |
| cron | 1,418/1,496 | 2222 | 2176 | 46 | 683 | 0 | 78 |
| resilience_policy | 518/519 | 554 | 342 | 212 | 1674 | 0 | 0 |

The complete domain-by-recurrence 1/5 through 5/5 breakdown is in `results/final_domain_recurrence_summary.csv`; recurrence membership was not changed.

## The Targeted Queues

| Original queue | Final outcomes |
| --- | --- |
| 64 required-observation survivors | {"ERROR": 5, "MASKED": 8, "SURVIVED_REQUIRED_BEHAVIOR": 51} |
| 139 ambiguous pairs | {"ERROR": 123, "KILLED": 3, "MASKED": 5, "NOT_APPLICABLE": 8} |
| 152 blocked scoring rows | {"BLOCKED": 148, "COVERED": 4} |

Exact IDs, reasons and evidence references are in `results/reviewed_64_survivors.csv`, `results/reviewed_139_ambiguous_pairs.csv`, and `results/prior_blocked_row_review.csv`. Invalid or non-applicable outcomes are never credited as kills. Previously valid masked pairs are also invalidated when their shared positive control is invalid. A repaired baseline alone does not make a row mutation-covered: at least one same-binding applicable mutant is still required.

## Required Observations Versus Oracle Tolerance

- URL/IRI: 50 repeated Yarl mutations replace an explicitly expected exception class. The frozen RPL and strict source matcher require that class, while the unchanged scoring matcher accepts any nonempty `throws` string. These are counted as explicit-contract escapes, not hidden as masking. The tolerance is deliberate; an accidental checker bug is not established. The earlier narrower equivalence-based judgment is retained in `url_iri/pair_resolutions.jsonl`; `literal_requirement_resolutions.jsonl` records the explicit, evidence-backed adjudication. Of these, 27 change primary-operation errors and 23 change auxiliary getter errors that are nevertheless expressly included in the frozen expected observation.
- HTML: 65 existing mutants on 60 scoring rows replace escaped literal text with real DOM structure. The unchanged HTML canonicalizer collapses the distinct observations and accepts them. All were reproduced twice; the diagnostic structural comparison checks all permitted expected alternatives. No diagnostic comparison replaces the scoring oracle. See `supplemental/html_sanitizer_resolutions.jsonl`.
- HTTP timeout: the preserved broad exception handler accepts an unrelated native exception within the time bound even though the recovered requirement specifies timeout behavior. Original and mutated native controls were repeated; see `http_baselines/pair_resolutions.jsonl`.
- JWT and Cron: explicit source-contract exception, claim, diagnostic-substring or normalized-expression fields dropped by a coarse canonical projection are counted as contract-to-scoring escapes when strict unmodified controls pass and native mutants violate those same fields. See `denominator_review/literal_requirement_resolutions.jsonl` and `literal_authority.py`.
- Resilience: 212 mutants change explicitly expected policy fields while the canonical scoring projection retains only `surface=implemented`. All 212 native controls equal the preserved origin expected object, repeated mutants violate it, and the origin JSON pointer has been checked. These are projection escapes, not unasserted auxiliary observations. See `literal_requirement_resolutions.jsonl`.
- Literal differences that still satisfy an actual relational, substring, allowed-alternative or representation requirement remain masked. JWT has 401 separately reviewed native accessor changes (290 payload, 111 claim-value cases): the frozen extractor reconstructs values from the input token instead of using native accessors, so its output stays unchanged. These are **input-derived measurement masking**, not established benign or unimportant native changes. Required API-path equivalence is unproven; they are not automatically promoted into genuine escapes. Per-pair origin/RPL evidence is in `denominator_review/jwt_accessor_path_review.jsonl`.

**Exception-class-equivalence sensitivity:** if the 50 intentional exception-class relaxations are excluded, the conditional rate is 97.000%. Both scopes are exposed rather than choosing the more favorable one silently. All genuine escapes, including any additional HTTP discoveries, are listed in `results/required_behavior_survivors.csv`.

Excluding all explicitly recorded coarse-projection relaxations (660 pairs), the scoring-equivalence sensitivity rate is 99.699%. The primary rate retains them because the contract explicitly requires those observations; this narrower secondary rate is not evidence that the omitted behavior was preserved.

## HTTP Baseline Reconciliation

The original 115/633 selected nonpasses comprise **11 FAIL, 41 ERROR, and 63 NOT_RUN**, not 115 demonstrated native semantic violations. Their origins are OkHttp 32, Requests 32, Guzzle 50 and Axios 1. An alternate reference positive control does not retroactively turn a failed selected source baseline into PASS.

| Original selected cause | Rows |
| --- | --- |
| NO_SELECTED_EXECUTABLE_CONTROL | 63 |
| MISSING_DISPATCH_MAPPING | 36 |
| NATIVE_API_ADAPTER_SHAPE_ERROR | 3 |
| CONFIRMED_INVALID_MEASUREMENT | 2 |
| ALTERNATE_TARGET_AND_INCOMPLETE_URL_ERROR_BINDING | 1 |
| CONSTRUCTOR_ONLY_NOT_BEFORE_DISPATCH | 1 |
| DIFFERENT_FAULT_INJECTION_NOT_TRANSPORT_EXCEPTION | 1 |
| ENVIRONMENT_AND_NATIVE_POLICY_PROBE_CONFLICT | 1 |
| FIXTURE_DISCARDS_QUERY_BEFORE_COMPARISON | 1 |
| SAME_HOST_DIFFERENT_PORT_FIXTURE | 1 |
| SUPPLEMENTAL_NATIVE_CONFIGURATION_CONFLICT | 1 |
| TARGET_BRAND_SPECIFIC_ORACLE | 1 |
| UNSUPPORTED_COOKIE_API_MEASUREMENT | 1 |
| WRONG_EXCEPTION_NAMESPACE | 1 |
| WRONG_EXCEPTION_NAMESPACE_AND_WRONG_FAULT_FIXTURE | 1 |

Final current-control status (distinct from the unchanged selected historical record):

| Status | Rows |
| --- | --- |
| ERROR | 100 |
| FAIL | 1 |
| NOT_RUN | 6 |
| PASS | 8 |

Row-specific current results, both historical and current evidence, original inputs, complete required observations and remaining requirements are in `http_baselines/baseline_reconciliation.jsonl` and `results/http_baseline_reconciliation.csv`. Three distinctions matter:
- Measurement defects include missing dispatch, mismatched exception namespaces, wrong fault injection, lost request options, skipped preconditions and fixture timing races. The IPv6 CONNECT race was repaired only by waiting for the existing fixture to finish; unchanged prefix assertions then kill the same three mutants.
- Some current capability-only scoring branches have no accepting path even for an unmodified native implementation. They cannot certify a positive-control mutant test without changing the frozen scorer. These exclusions are not evidence that a native library lacks the behavior.
- Other exact native controls conflict with the recorded expectation or remain timing-sensitive. Version labels alone do not establish a version-caused defect; no silent version substitution was used.

## Remaining Validation Limits

`results/validation_limitations.csv` groups invalid and unresolved pair slots with example IDs and evidence. `results/final_scoring_rows.csv` retains every uncovered row. Known invalidity is resolved as a diagnosis but is not successful validation. The following limits cannot be hidden in the detection denominator:
- Frozen scorer/projection conflicts: HTTP/JWT/Cron no-accepting capability branches; four Date/Time exact-string versus native substring bindings; two WHATWG list-versus-scalar error projections. Repairing expected-dependent extraction or replacing these assertions would change the frozen audit target.
- Invalid native mutation operators, syntax/internal runtime failures, unstable controls and bounded timeouts remain excluded. Catalog exhaustion does not prove that another sound operator is impossible.
- The YAML historical error ledger retains 452 slots: 358 internal runtime errors, 14 timeouts, 65 alternate-backend baseline conflicts, and 15 malformed rule deletions. No unexecuted repair is credited. These include 86 error-only rows; they are not silently counted as covered.
- JVM conditional mutations are executable bytecode edits, documented with instruction-level diffs and source mappings; they are not mislabeled textual source patches. Rust reuses hash-verified preserved mutant binaries rather than claiming an independent rebuild.
- Noda Time queue metadata says 3.3.0 while preserved executable/native source is 3.3.3. The actual executed version remains recorded; neither metadata nor frozen results were rewritten.

## Evidence and Reproduction

Each final pair links its original exact identity, contract/expectation hashes, original diff and command/log references, plus a per-pair resolution record. Resolution records retain repeated actual observations, unchanged oracle decisions and control status. `results/scope_reconciliation.csv` preserves conflicting historical decisions and explicit supersession reasons; no majority vote or PASS preference is used.

```sh
python3 -B analysis/full_corpus_behavioral_mutants/final_completion/prepare.py
python3 -B analysis/full_corpus_behavioral_mutants/final_completion/review_literal_requirements.py
python3 -B analysis/full_corpus_behavioral_mutants/final_completion/assemble.py
python3 -B analysis/full_corpus_behavioral_mutants/final_completion/test_completion.py
python3 -B analysis/full_corpus_behavioral_mutants/final_completion/write_report.py
```

These commands reconcile preserved evidence and check invariants; they do not rerun development sessions or expand mutation volume. Native reproduction scripts, isolated runtimes and checkpointed logs are in the domain subdirectories. `prior_snapshot.json` and `results/manifest.json` verify preservation of 1,731 original input files; owner-specific manifests additionally verify isolated runtime/source files.
