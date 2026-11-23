"""Typed representations of absence, vacuum states, and excitations.

The module deliberately does not define an entity called "nothing". It records
absence relative to a declared scope, and physical states relative to a model.
"""
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AbsenceBasis(StrEnum):
    NOT_DETECTED = "NOT_DETECTED"
    EMPTY_BY_DEFINITION = "EMPTY_BY_DEFINITION"
    FORBIDDEN_BY_MODEL = "FORBIDDEN_BY_MODEL"
    UNKNOWN = "UNKNOWN"


class AbsenceClaim(BaseModel):
    """A scoped claim that something is absent, not a representation of nothing."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=200)
    scope: str = Field(min_length=1, max_length=300)
    basis: AbsenceBasis
    search_method: str | None = Field(default=None, max_length=300)
    coverage_fraction: Decimal | None = Field(default=None, ge=0, le=1)
    detection_limit: Decimal | None = Field(default=None, ge=0)
    domain_closed: bool = False
    model_id: str | None = Field(default=None, max_length=120)
    notes: str = Field(default="", max_length=1000)

    @field_validator("coverage_fraction", "detection_limit")
    @classmethod
    def require_finite_measurements(cls, value):
        if value is not None and not value.is_finite():
            raise ValueError("absence measurement bounds must be finite")
        return value

    @model_validator(mode="after")
    def validate_basis(self):
        if self.basis == AbsenceBasis.NOT_DETECTED:
            if not self.search_method or self.coverage_fraction is None:
                raise ValueError("not-detected claims require a method and coverage")
        elif self.search_method is not None or self.coverage_fraction is not None or self.detection_limit is not None:
            raise ValueError("search metadata is only valid for NOT_DETECTED claims")
        if self.basis == AbsenceBasis.EMPTY_BY_DEFINITION and not self.domain_closed:
            raise ValueError("empty-by-definition requires a declared closed domain")
        if self.basis != AbsenceBasis.EMPTY_BY_DEFINITION and self.domain_closed:
            raise ValueError("domain_closed applies only to EMPTY_BY_DEFINITION")
        if self.basis == AbsenceBasis.FORBIDDEN_BY_MODEL and not self.model_id:
            raise ValueError("model-forbidden claims require a model identifier")
        if self.basis != AbsenceBasis.FORBIDDEN_BY_MODEL and self.model_id is not None:
            raise ValueError("model_id applies only to FORBIDDEN_BY_MODEL")
        return self


class PhysicalStateKind(StrEnum):
    VACUUM = "VACUUM"
    EXCITED = "EXCITED"
    OTHER = "OTHER"


class PhysicalStateReference(BaseModel):
    """A state label whose meaning is relative to a declared physical model."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    state_id: str = Field(min_length=1, max_length=120)
    model_id: str = Field(min_length=1, max_length=120)
    kind: PhysicalStateKind
    description: str = Field(default="", max_length=1000)


class ParticleExcitation(BaseModel):
    """A particle-like excitation relative to a model-defined reference state."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    excitation_id: str = Field(min_length=1, max_length=120)
    model_id: str = Field(min_length=1, max_length=120)
    reference_state_id: str = Field(min_length=1, max_length=120)
    particle_label: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    energy_above_reference: Decimal | None = Field(default=None, ge=0)
    energy_unit: str | None = Field(default=None, max_length=40)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("energy_above_reference")
    @classmethod
    def require_finite_energy(cls, value):
        if value is not None and not value.is_finite():
            raise ValueError("excitation energy must be finite")
        return value

    @model_validator(mode="after")
    def validate_energy_unit(self):
        if (self.energy_above_reference is None) != (self.energy_unit is None):
            raise ValueError("energy value and unit must be supplied together")
        return self
