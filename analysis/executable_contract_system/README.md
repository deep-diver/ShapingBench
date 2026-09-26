# Executable Contract System

This analysis-side system makes every non-common scoring contract enter an executable path without changing its frozen identity, inputs, expected observations, or core/extended membership.

## Coverage

- Domains: **12**
- Immutable scoring rows: **28,745**
- Full behavior replays: **27,548**
- Executable capability-absence tests: **1,197**
- UNKNOWN or unmapped rows: **0**
- Identity/evidence validation errors: **0**

A semantic mismatch is a valid executed failure. A missing execution path is not. When the target does not expose the semantic primitive, the compiler emits a capability-absence program that checks equivalent native interfaces with contract-shaped calls and a target-native positive control.

## Domain Results

| Domain | Contracts | Behavior replay | Capability test | PASS | Semantic FAIL | Capability absence | UNKNOWN |
|---|---:|---:|---:|---:|---:|---:|---:|
| HTTP Client | 519 | 217 | 302 | 156 | 61 | 302 | 0 |
| JSON Schema | 15,533 | 15,470 | 63 | 14,800 | 670 | 63 | 0 |
| Date/time & timezone | 404 | 404 | 0 | 18 | 386 | 0 | 0 |
| URL/IRI | 1,927 | 1,897 | 30 | 1,366 | 531 | 30 | 0 |
| HTML Sanitization | 1,472 | 1,472 | 0 | 615 | 857 | 0 | 0 |
| Markdown | 1,282 | 1,282 | 0 | 798 | 484 | 0 | 0 |
| YAML | 2,548 | 2,548 | 0 | 1,460 | 1,088 | 0 | 0 |
| JWT | 1,273 | 1,224 | 49 | 1,143 | 81 | 49 | 0 |
| Template Engine | 1,187 | 1,187 | 0 | 170 | 1,017 | 0 | 0 |
| Cron | 1,383 | 1,269 | 114 | 723 | 546 | 114 | 0 |
| Rate Limiting | 776 | 304 | 472 | 165 | 139 | 472 | 0 |
| Resilience Policy | 441 | 274 | 167 | 102 | 172 | 167 | 0 |

## Reproduction

```bash
python analysis/executable_contract_system/run_domain.py --domain url_iri --snapshot /path/to/snapshot --output /tmp/url-results
python analysis/executable_contract_system/run_contract.py --domain url_iri --contract-id <scoring-id> --snapshot /path/to/snapshot
python analysis/executable_contract_system/validate_all.py
python analysis/executable_contract_system/build_inventory.py
```

The inventory provides the exact command for every row. Exit code `0` means PASS and `1` means an executed FAIL. Result JSON contains the verdict class and traceable evidence.

## Files

- `executable_contract_inventory.csv`: one row per immutable scoring contract
- `executable_contract_inventory.jsonl`: the same inventory in lossless JSON Lines form
- `execution_coverage_summary.csv`: per-domain coverage and verdict counts
- `execution_validation_errors.csv`: must contain only its header for a valid build
- `manifest.json`: hashes, snapshots, commands, assumptions, and limitations
- `requirements-analysis.txt`: analysis runtime dependencies

Frozen contracts and previous benchmark results are read-only inputs. All compiler, adapter, replay, and derived evidence changes live in this directory.
