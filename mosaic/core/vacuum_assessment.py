"""Model-relative assessments of vacuum stability and transition evidence.

Stability labels are assessments within a stated model and regime. They are
not claims about absolute nothingness or proof that a physical transition
occurred.
"""
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mosaic.core.absence import PhysicalStateKind, PhysicalStateReference
from mosaic.core.physical_transitions import PhysicalTransition


class VacuumStability(StrEnum):
    STABLE_WITHIN_MODEL = "STABLE_WITHIN_MODEL"
    METASTABLE_WITHIN_MODEL = "METASTABLE_WITHIN_MODEL"
    UNASSESSED = "UNASSESSED"


class EvidenceKind(StrEnum):
    THEORETICAL = "THEORETICAL"
    SIMULATED = "SIMULATED"
    OBSERVATIONAL = "OBSERVATIONAL"
    EXPERIMENTAL = "EXPERIMENTAL"


class VacuumStabilityAssessment(BaseModel):
    """A stability classification scoped to one vacuum state, model, and regime."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: str = Field(min_length=1, max_length=120)
    state: PhysicalStateReference
    stability: VacuumStability
    regime: str = Field(min_length=1, max_length=300)
    method: str = Field(min_length=1, max_length=500)
    evidence_kind: EvidenceKind
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_vacuum_assessment(self):
        if self.state.kind != PhysicalStateKind.VACUUM:
            raise ValueError("stability assessment requires a VACUUM state")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("assumptions must be nonblank")
        return self


class VacuumTransitionAssessment(BaseModel):
    """Evidence classification for a transition between model-defined vacua.

    The embedded transition is a modelled transition record, not by itself
    evidence that the transition occurred.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: str = Field(min_length=1, max_length=120)
    transition: PhysicalTransition
    evidence_kind: EvidenceKind
    method: str = Field(min_length=1, max_length=500)
    regime: str = Field(min_length=1, max_length=300)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_vacuum_transition(self):
        if self.transition.source_state.kind != PhysicalStateKind.VACUUM:
            raise ValueError("source state must be a VACUUM state")
        if self.transition.target_state.kind != PhysicalStateKind.VACUUM:
            raise ValueError("target state must be a VACUUM state")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("assumptions must be nonblank")
        return self
