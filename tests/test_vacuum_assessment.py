from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.absence import PhysicalStateKind, PhysicalStateReference
from mosaic.core.physical_transitions import PhysicalTransition
from mosaic.core.vacuum_assessment import (
    EvidenceKind,
    VacuumStability,
    VacuumStabilityAssessment,
    VacuumTransitionAssessment,
)


def vacuum(state_id: str) -> PhysicalStateReference:
    return PhysicalStateReference(
        state_id=state_id,
        model_id="field-model-v1",
        kind=PhysicalStateKind.VACUUM,
        description="Model-defined vacuum configuration",
    )


def transition() -> PhysicalTransition:
    return PhysicalTransition(
        transition_id="decay-candidate-1",
        model_id="field-model-v1",
        source_state=vacuum("false-vacuum"),
        target_state=vacuum("lower-energy-vacuum"),
        mechanism="Candidate tunnelling process",
        system_boundary="declared field system",
    )


def test_stability_is_scoped_to_model_state_and_regime():
    assessment = VacuumStabilityAssessment(
        assessment_id="stability-1",
        state=vacuum("false-vacuum"),
        stability=VacuumStability.METASTABLE_WITHIN_MODEL,
        regime="specified parameter range",
        method="Analysis of the model potential",
        evidence_kind=EvidenceKind.THEORETICAL,
    )
    assert assessment.state.model_id == "field-model-v1"
    assert assessment.stability == VacuumStability.METASTABLE_WITHIN_MODEL


def test_unassessed_is_explicit_not_assumed_stable():
    assessment = VacuumStabilityAssessment(
        assessment_id="stability-2",
        state=vacuum("unknown-vacuum"),
        stability=VacuumStability.UNASSESSED,
        regime="unspecified energy range",
        method="No stability calculation performed",
        evidence_kind=EvidenceKind.THEORETICAL,
    )
    assert assessment.stability == VacuumStability.UNASSESSED


def test_stability_assessment_rejects_non_vacuum_state():
    excited = PhysicalStateReference(
        state_id="particle-state",
        model_id="field-model-v1",
        kind=PhysicalStateKind.EXCITED,
    )
    with pytest.raises(ValidationError):
        VacuumStabilityAssessment(
            assessment_id="bad",
            state=excited,
            stability=VacuumStability.STABLE_WITHIN_MODEL,
            regime="test regime",
            method="test",
            evidence_kind=EvidenceKind.SIMULATED,
        )


def test_vacuum_transition_evidence_keeps_kind_explicit():
    assessment = VacuumTransitionAssessment(
        assessment_id="transition-evidence-1",
        transition=transition(),
        evidence_kind=EvidenceKind.SIMULATED,
        method="Numerical evolution under declared initial conditions",
        regime="finite simulation domain",
    )
    assert assessment.evidence_kind == EvidenceKind.SIMULATED
    assert assessment.transition.target_state.state_id == "lower-energy-vacuum"


def test_transition_assessment_rejects_non_vacuum_endpoint():
    mixed = PhysicalTransition(
        transition_id="mixed",
        model_id="field-model-v1",
        source_state=vacuum("vac"),
        target_state=PhysicalStateReference(
            state_id="excited",
            model_id="field-model-v1",
            kind=PhysicalStateKind.EXCITED,
        ),
        mechanism="test",
        system_boundary="declared field system",
    )
    with pytest.raises(ValidationError):
        VacuumTransitionAssessment(
            assessment_id="bad-transition",
            transition=mixed,
            evidence_kind=EvidenceKind.OBSERVATIONAL,
            method="test observation",
            regime="test regime",
        )


def test_evidence_hash_is_integrity_metadata_not_truth_claim():
    assessment = VacuumStabilityAssessment(
        assessment_id="hashed",
        state=vacuum("vac"),
        stability=VacuumStability.STABLE_WITHIN_MODEL,
        regime="bounded regime",
        method="Analytic calculation",
        evidence_kind=EvidenceKind.THEORETICAL,
        evidence_sha256="a" * 64,
    )
    assert assessment.evidence_sha256 == "a" * 64
