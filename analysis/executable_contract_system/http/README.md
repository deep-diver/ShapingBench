# Executable HTTP Contract System

Analysis-side compiler and replay infrastructure for the frozen 519-contract
HTTP non-common scoring corpus.

The frozen corpus and historical results remain unchanged. Generated files in
this directory preserve the original scoring row identity and distinguish:

- a complete behavioral definition (`setup + action + oracle + control`);
- a compiled target projection;
- an executed behavioral verdict;
- a verified native capability absence;
- a measurement gap.

`PASS` can only come from a complete behavioral execution. A capability probe
may establish `FAIL_CAPABILITY_ABSENCE`; it can never produce `PASS`. Zero or
partial projections remain `UNKNOWN` and are not counted as behavioral tests.

Run the source-definition compiler:

```bash
python3 analysis/executable_contract_system/http/build_contract_ir.py
```
