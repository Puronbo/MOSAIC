"""Energy accounting and transitions between model-defined physical states.

These records check declared bookkeeping. They do not establish that a
transition occurred or that a chosen physical model is true.
"""
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mosaic.core.absence import PhysicalStateReference


class EnergyAccounting(BaseModel):
    """Energy ledger for a declared system boundary, in one consistent unit.

    Sign convention: initial energy + energy supplied - energy transferred out
    = final energy. The ledger is only as meaningful as its boundary, model,
    units, and measured or calculated inputs.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    system_boundary: str = Field(min_length=1, max_length=300)
    unit: str = Field(min_length=1, max_length=40)
    initial_energy: Decimal = Field(ge=0)
    final_energy: Decimal = Field(ge=0)
    energy_supplied: Decimal = Field(default=Decimal("0"), ge=0)
    energy_transferred_out: Decimal = Field(default=Decimal("0"), ge=0)

    @field_validator(
        "initial_energy", "final_energy", "energy_supplied",
        "energy_transferred_out",
    )
    @classmethod
    def require_finite_energy(cls, value):
        if not value.is_finite():
            raise ValueError("energy values must be finite")
        return value

    @property
    def residual(self) -> Decimal:
        return (
            self.initial_energy + self.energy_supplied
            - self.energy_transferred_out - self.final_energy
        )


class EnergyBalanceStatus(StrEnum):
    BALANCED = "BALANCED"
    UNBALANCED = "UNBALANCED"


class EnergyBalanceResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: EnergyBalanceStatus
    residual: Decimal
    tolerance: Decimal
    unit: str


def check_energy_balance(
    accounting: EnergyAccounting,
    *,
    tolerance: Decimal = Decimal("0"),
) -> EnergyBalanceResult:
    """Check the declared ledger within an explicit nonnegative tolerance."""
    if not isinstance(tolerance, Decimal) or not tolerance.is_finite() or tolerance < 0:
        raise ValueError("tolerance must be a finite nonnegative Decimal")
    residual = accounting.residual
    return EnergyBalanceResult(
        status=(
            EnergyBalanceStatus.BALANCED
            if abs(residual) <= tolerance
            else EnergyBalanceStatus.UNBALANCED
        ),
        residual=residual,
        tolerance=tolerance,
        unit=accounting.unit,
    )


class PhysicalTransition(BaseModel):
    """A proposed transition between two states in the same declared model."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    transition_id: str = Field(min_length=1, max_length=120)
    model_id: str = Field(min_length=1, max_length=120)
    source_state: PhysicalStateReference
    target_state: PhysicalStateReference
    mechanism: str = Field(min_length=1, max_length=1000)
    system_boundary: str = Field(min_length=1, max_length=300)
    energy_accounting: EnergyAccounting | None = None
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_transition(self):
        if self.source_state.model_id != self.model_id:
            raise ValueError("source state must belong to the transition model")
        if self.target_state.model_id != self.model_id:
            raise ValueError("target state must belong to the transition model")
        if self.source_state.state_id == self.target_state.state_id:
            raise ValueError("source and target states must differ")
        if (
            self.energy_accounting is not None
            and self.energy_accounting.system_boundary != self.system_boundary
        ):
            raise ValueError("energy ledger and transition must share a system boundary")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("assumptions must be nonblank")
        return self
