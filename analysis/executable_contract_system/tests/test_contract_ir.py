from analysis.executable_contract_system.contract_ir import (
    BehaviorContract,
    ExecutionEvidence,
    Observation,
    Projection,
    Verdict,
)


def contract() -> BehaviorContract:
    return BehaviorContract(
        scoring_id="c1",
        domain="HTTP Client",
        origin="x",
        source_version="1",
        name="example",
        capability="http.example",
        setup=("origin",),
        actions=("GET /",),
        observations=(Observation("o1", "status", 200),),
        negative_control="status=500",
        source_reference="source:1",
        contract_hash="hash",
    )


def projection() -> Projection:
    return Projection("v1", "target", "1", (), (), ({"id": "o1"},), ({"source": "o1", "target": "o1"},))


def test_complete_pass_is_accepted() -> None:
    evidence = ExecutionEvidence(
        scoring_id="c1",
        contract_hash="hash",
        target="target",
        target_version="1",
        adapter_revision="v1",
        verdict=Verdict.PASS,
        execution_command=["runner"],
        actual_observations=[{"id": "o1", "value": 200}],
        oracle_comparisons=[{"id": "o1", "matched": True}],
        control_validation="PASS",
    )
    evidence.validate(contract(), projection())


def test_adapter_gap_cannot_be_semantic_fail() -> None:
    evidence = ExecutionEvidence(
        scoring_id="c1",
        contract_hash="hash",
        target="target",
        target_version="1",
        adapter_revision="v1",
        verdict=Verdict.FAIL_SEMANTIC_MISMATCH,
        execution_command=["runner"],
        reason="unsupported adapter op",
    )
    try:
        evidence.validate(contract(), None)
    except AssertionError as exc:
        assert "behavioral execution" in str(exc)
    else:
        raise AssertionError("adapter failure was accepted as semantic FAIL")


def test_capability_absence_requires_executable_probe() -> None:
    evidence = ExecutionEvidence(
        scoring_id="c1",
        contract_hash="hash",
        target="target",
        target_version="1",
        adapter_revision="v1",
        verdict=Verdict.FAIL_CAPABILITY_ABSENCE,
        execution_command=["runner"],
        capability_probe={"required_semantic_primitive": "x"},
    )
    try:
        evidence.validate(contract(), None)
    except AssertionError as exc:
        assert "absence evidence" in str(exc)
    else:
        raise AssertionError("incomplete capability probe was accepted")
