"""Records for particle-like excitations produced from a model-defined vacuum.

This is not a claim that particles emerge from absolute nothingness. It
connects a vacuum-to-excited-state transition to excitations referenced to
that vacuum within the same physical model.
"""
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mosaic.core.absence import (
    ParticleExcitation,
    PhysicalStateKind,
)
from mosaic.core.physical_transitions import PhysicalTransition
from mosaic.core.vacuum_assessment import EvidenceKind


class ParticleProductionRecord(BaseModel):
    """A provenance-bearing record of excitations relative to a vacuum state."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    production_id: str = Field(min_length=1, max_length=120)
    transition: PhysicalTransition
    excitations: tuple[ParticleExcitation, ...] = Field(min_length=1, max_length=100)
    evidence_kind: EvidenceKind
    method: str = Field(min_length=1, max_length=500)
    regime: str = Field(min_length=1, max_length=300)
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_production(self):
        source = self.transition.source_state
        target = self.transition.target_state
        if source.kind != PhysicalStateKind.VACUUM:
            raise ValueError("particle production must reference a VACUUM source state")
        if target.kind != PhysicalStateKind.EXCITED:
            raise ValueError("particle production must target an EXCITED state")
        for excitation in self.excitations:
            if excitation.model_id != self.transition.model_id:
                raise ValueError("all excitations must belong to the transition model")
            if excitation.reference_state_id != source.state_id:
                raise ValueError("each excitation must reference the source vacuum state")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("assumptions must be nonblank")
        return self
