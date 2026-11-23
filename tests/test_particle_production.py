import pytest
from pydantic import ValidationError

from mosaic.core.absence import (
    ParticleExcitation,
    PhysicalStateKind,
    PhysicalStateReference,
)
from mosaic.core.physical_transitions import PhysicalTransition
from mosaic.core.vacuum_assessment import EvidenceKind
from mosaic.core.particle_production import ParticleProductionRecord


def state(state_id: str, kind: PhysicalStateKind) -> PhysicalStateReference:
    return PhysicalStateReference(
        state_id=state_id,
        model_id="qft-model-v1",
        kind=kind,
    )


def excitation(
    excitation_id: str = "e-1",
    reference_state_id: str = "vacuum-0",
    model_id: str = "qft-model-v1",
) -> ParticleExcitation:
    return ParticleExcitation(
        excitation_id=excitation_id,
        model_id=model_id,
        reference_state_id=reference_state_id,
        particle_label="particle-like mode",
        energy_above_reference="1.25",
        energy_unit="model energy units",
    )


def make_transition(
    source_kind: PhysicalStateKind = PhysicalStateKind.VACUUM,
    target_kind: PhysicalStateKind = PhysicalStateKind.EXCITED,
) -> PhysicalTransition:
    return PhysicalTransition(
        transition_id="production-transition",
        model_id="qft-model-v1",
        source_state=state("vacuum-0", source_kind),
        target_state=state("excited-1", target_kind),
        mechanism="Modelled excitation process",
        system_boundary="declared field system",
    )


def test_records_particle_production_from_modelled_vacuum():
    record = ParticleProductionRecord(
        production_id="production-1",
        transition=make_transition(),
        excitations=(excitation(), excitation("e-2")),
        evidence_kind=EvidenceKind.SIMULATED,
        method="Numerical field evolution",
        regime="finite volume and finite time",
    )
    assert len(record.excitations) == 2
    assert record.excitations[0].reference_state_id == "vacuum-0"


def test_rejects_non_vacuum_source():
    with pytest.raises(ValidationError):
        ParticleProductionRecord(
            production_id="bad-source",
            transition=make_transition(source_kind=PhysicalStateKind.OTHER),
            excitations=(excitation(),),
            evidence_kind=EvidenceKind.THEORETICAL,
            method="formal calculation",
            regime="declared regime",
        )


def test_rejects_non_excited_target():
    with pytest.raises(ValidationError):
        ParticleProductionRecord(
            production_id="bad-target",
            transition=make_transition(target_kind=PhysicalStateKind.OTHER),
            excitations=(excitation(),),
            evidence_kind=EvidenceKind.THEORETICAL,
            method="formal calculation",
            regime="declared regime",
        )


def test_rejects_excitation_from_another_model():
    with pytest.raises(ValidationError):
        ParticleProductionRecord(
            production_id="wrong-model",
            transition=make_transition(),
            excitations=(excitation(model_id="different-model"),),
            evidence_kind=EvidenceKind.OBSERVATIONAL,
            method="detector analysis",
            regime="declared regime",
        )


def test_rejects_excitation_referenced_to_different_vacuum():
    with pytest.raises(ValidationError):
        ParticleProductionRecord(
            production_id="wrong-reference",
            transition=make_transition(),
            excitations=(excitation(reference_state_id="other-vacuum"),),
            evidence_kind=EvidenceKind.EXPERIMENTAL,
            method="measurement",
            regime="declared regime",
        )


def test_rejects_empty_excitation_list():
    with pytest.raises(ValidationError):
        ParticleProductionRecord(
            production_id="empty",
            transition=make_transition(),
            excitations=(),
            evidence_kind=EvidenceKind.THEORETICAL,
            method="formal calculation",
            regime="declared regime",
        )
