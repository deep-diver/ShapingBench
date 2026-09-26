# Benchmark Format

## Scoring inventory

`benchmark/scoring_contracts.csv` and its compressed JSONL equivalent contain
one row per frozen scoring contract. `canonical_contract_family_id` is the
stable row identity and must not be replaced by a description, list position,
or similar-looking native test name.

Key fields:

| Field | Meaning |
|---|---|
| `benchmark_partition` | Current empirical partition: Shared Core or Variable Surface |
| `construction_classification` | Historical construction-time core/extended label |
| `domain`, `domain_key` | Publication name and stable domain key |
| `canonical_contract_family_id` | Unique scoring-row identity |
| `repository_native_id` | Identity in the source project corpus |
| `short_behavioral_description` | Compact description, not an identity key |
| `behavioral_category` | Repository/domain-native category |
| `source_oss`, `source_version` | Origin project and preserved source version |
| `oss_1_result` ... `oss_5_result` | Executed cross-reference verdicts |
| `exact_support_count` | Number of PASS verdicts; defined because all five cells are known |
| `source_artifact` | Frozen payload supplying the contract evidence |

The current public partition is based on completed cross-implementation replay:
5/5 is Shared Core; 1/5--4/5 is Variable Surface. The historical
`construction_classification` is retained because the original core was frozen
earlier by a three-discovery plus two-confirmation construction procedure. A row
may therefore have construction label `extended` and current support 5/5. The
release never rewrites this history.

## Reference inventory

`benchmark/reference_implementations.csv` contains five rows per domain. It
records project identity, construction role, language/ecosystem where
recoverable, selected version, provenance sources, and maturity indicators
available from the preserved construction artifacts. Construction order is not
a quality ranking.

## Support semantics

- `PASS`: the reference or submission satisfied the unchanged observable
  contract through a faithful execution path.
- `FAIL`: valid execution produced a semantic mismatch or established that the
  required capability is absent.
- `UNKNOWN`: no trustworthy verdict was obtained. The released reference matrix
  has zero UNKNOWN cells.

Recurrence is independent of normative importance and of construction history.
A 5/5 Variable-Surface-at-construction row remains historically extended; a
1/5 behavior is not automatically dispensable.

## Evaluator result semantics

The strict runners retain source identity, actual observation, expected
observation, verdict, and adapter revision where the domain runner exposes them.
`evaluation/score.py` performs an identity-preserving join and rejects missing,
ambiguous, or duplicate rows instead of guessing.
