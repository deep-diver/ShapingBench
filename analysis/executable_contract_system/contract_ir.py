"""Shared behavioral-contract IR and strict verdict validation.

The benchmark's scoring IDs and semantics are immutable.  This module only
defines the evolvable measurement representation used to lower those semantics
onto heterogeneous implementations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL_SEMANTIC_MISMATCH = "FAIL_SEMANTIC_MISMATCH"
    FAIL_CAPABILITY_ABSENCE = "FAIL_CAPABILITY_ABSENCE"
    UNKNOWN_ADAPTER_GAP = "UNKNOWN_ADAPTER_GAP"
    UNKNOWN_INFRASTRUCTURE = "UNKNOWN_INFRASTRUCTURE"
    UNKNOWN_PROVENANCE = "UNKNOWN_PROVENANCE"
    UNKNOWN_UNSTABLE = "UNKNOWN_UNSTABLE"


@dataclass(frozen=True)
class Observation:
    observation_id: str
    expression: str
    expected: Any


@dataclass(frozen=True)
class BehaviorContract:
    scoring_id: str
    domain: str
    origin: str
    source_version: str
    name: str
    capability: str
    setup: tuple[str, ...]
    actions: tuple[str, ...]
    observations: tuple[Observation, ...]
    negative_control: str
    source_reference: str
    contract_hash: str


@dataclass(frozen=True)
class Projection:
    adapter_revision: str
    target: str
    target_version: str
    setup: tuple[dict[str, Any], ...]
    actions: tuple[dict[str, Any], ...]
    observations: tuple[dict[str, Any], ...]
    source_to_projection: tuple[dict[str, Any], ...]
    required_primitives: tuple[str, ...] = ()


@dataclass
class ExecutionEvidence:
    scoring_id: str
    contract_hash: str
    target: str
    target_version: str
    adapter_revision: str
    verdict: Verdict
    execution_command: list[str]
    actual_observations: list[dict[str, Any]] = field(default_factory=list)
    oracle_comparisons: list[dict[str, Any]] = field(default_factory=list)
    control_validation: str = ""
    log_reference: str = ""
    reason: str = ""
    capability_probe: dict[str, Any] | None = None

    def validate(self, contract: BehaviorContract, projection: Projection | None) -> None:
        if self.scoring_id != contract.scoring_id or self.contract_hash != contract.contract_hash:
            raise AssertionError("evidence identity does not match contract")
        if self.verdict == Verdict.PASS:
            if projection is None:
                raise AssertionError("PASS requires a projection")
            required = len(contract.observations)
            if required == 0:
                raise AssertionError("zero-observation contract cannot PASS")
            if len(self.actual_observations) != required or len(self.oracle_comparisons) != required:
                raise AssertionError("PASS requires every observation to be executed and compared")
            if not all(item.get("matched") is True for item in self.oracle_comparisons):
                raise AssertionError("PASS contains a non-matching oracle comparison")
            if self.control_validation != "PASS":
                raise AssertionError("PASS requires a working negative control")
        elif self.verdict == Verdict.FAIL_SEMANTIC_MISMATCH:
            if projection is None or not self.actual_observations:
                raise AssertionError("semantic FAIL requires behavioral execution")
            if len(self.actual_observations) != len(contract.observations):
                raise AssertionError("semantic FAIL requires complete observations")
            if not any(item.get("matched") is False for item in self.oracle_comparisons):
                raise AssertionError("semantic FAIL requires a demonstrated mismatch")
        elif self.verdict == Verdict.FAIL_CAPABILITY_ABSENCE:
            probe = self.capability_probe or {}
            required = {
                "required_semantic_primitive",
                "equivalent_native_interfaces_checked",
                "executable_probe",
                "probe_observation",
                "positive_control",
            }
            if not required.issubset(probe):
                raise AssertionError("capability FAIL lacks executable absence evidence")
            if not probe["equivalent_native_interfaces_checked"]:
                raise AssertionError("capability FAIL checked no equivalent interface")
            if probe["positive_control"].get("recognized") is not True:
                raise AssertionError("capability probe positive control is broken")
        elif not self.reason:
            raise AssertionError("UNKNOWN evidence requires a specific reason")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["verdict"] = self.verdict.value
        return value
