from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.absence import (
    AbsenceBasis, AbsenceClaim, ParticleExcitation, PhysicalStateKind,
    PhysicalStateReference,
)


def test_not_detected_is_scoped_and_limited():
    claim = AbsenceClaim(
        claim_id="a-1", target="photon", scope="detector volume V during T",
        basis=AbsenceBasis.NOT_DETECTED, search_method="calibrated detector",
        coverage_fraction=Decimal("0.95"), detection_limit=Decimal("0.01"),
    )
    assert claim.coverage_fraction == Decimal("0.95")


def test_not_detected_requires_method_and_coverage():
    with pytest.raises(ValidationError):
        AbsenceClaim(claim_id="a-1", target="particle", scope="region",
                     basis=AbsenceBasis.NOT_DETECTED)


def test_empty_domain_requires_closed_world_declaration():
    with pytest.raises(ValidationError):
        AbsenceClaim(claim_id="a-1", target="element", scope="finite set S",
                     basis=AbsenceBasis.EMPTY_BY_DEFINITION)
    claim = AbsenceClaim(claim_id="a-2", target="element", scope="finite set S",
                         basis=AbsenceBasis.EMPTY_BY_DEFINITION, domain_closed=True)
    assert claim.domain_closed


def test_model_forbidden_absence_names_its_model():
    with pytest.raises(ValidationError):
        AbsenceClaim(claim_id="a-1", target="state", scope="model domain",
                     basis=AbsenceBasis.FORBIDDEN_BY_MODEL)
    claim = AbsenceClaim(claim_id="a-2", target="state", scope="model domain",
                         basis=AbsenceBasis.FORBIDDEN_BY_MODEL, model_id="model-7")
    assert claim.model_id == "model-7"


def test_unknown_does_not_claim_absence_or_accept_search_metadata():
    claim = AbsenceClaim(claim_id="a-1", target="dark matter", scope="region R",
                         basis=AbsenceBasis.UNKNOWN)
    assert claim.basis == AbsenceBasis.UNKNOWN
    with pytest.raises(ValidationError):
        AbsenceClaim(claim_id="a-2", target="dark matter", scope="region R",
                     basis=AbsenceBasis.UNKNOWN, search_method="survey",
                     coverage_fraction=Decimal("1"))


def test_vacuum_is_a_model_defined_physical_state_not_nothing():
    state = PhysicalStateReference(state_id="vacuum-1", model_id="QFT-model-A",
                                   kind=PhysicalStateKind.VACUUM)
    assert state.kind == PhysicalStateKind.VACUUM
    assert state.model_id == "QFT-model-A"


def test_particle_excitation_is_relative_to_model_and_reference_state():
    excitation = ParticleExcitation(
        excitation_id="exc-1", model_id="QFT-model-A",
        reference_state_id="vacuum-1", particle_label="scalar excitation",
        energy_above_reference=Decimal("2.5"), energy_unit="GeV",
        evidence_sha256="a" * 64,
    )
    assert excitation.energy_above_reference == Decimal("2.5")
    with pytest.raises(ValidationError):
        ParticleExcitation(
            excitation_id="exc-2", model_id="QFT-model-A",
            reference_state_id="vacuum-1", particle_label="scalar",
            energy_above_reference=Decimal("2.5"),
        )


def test_particle_excitation_does_not_allow_nonfinite_energy():
    with pytest.raises(ValidationError):
        ParticleExcitation(
            excitation_id="exc-1", model_id="m", reference_state_id="v",
            particle_label="particle", energy_above_reference=Decimal("NaN"),
            energy_unit="J",
        )
