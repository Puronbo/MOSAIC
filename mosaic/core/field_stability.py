"""Conservative timestep screening for the finite-lattice field integrator.

The bound applies to the declared convex discrete potential over its entire
field domain. It is a sufficient linear-stability screen for semi-implicit
Euler, not a nonlinear error estimate or a physical stability theorem.
"""
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_potential import ScalarPotential


class FieldStabilityStatus(StrEnum):
    CERTIFIED_WITHIN_BOUND = "CERTIFIED_WITHIN_BOUND"
    TIME_STEP_EXCEEDS_BOUND = "TIME_STEP_EXCEEDS_BOUND"
    NOT_CERTIFIED_NONCONVEX_DOMAIN = "NOT_CERTIFIED_NONCONVEX_DOMAIN"


class FieldStabilityAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    configuration_id: str
    model_id: str
    potential_id: str
    boundary: LatticeBoundary
    time_step: Decimal
    time_step_upper_bound: Decimal | None
    maximum_absolute_potential_curvature: Decimal
    lower_bound_potential_curvature: Decimal
    maximum_squared_frequency_bound: Decimal | None
    inertia_coefficient: Decimal
    kinetic_coefficient: Decimal
    status: FieldStabilityStatus
    sufficient_condition: str


def _potential_curvature_bounds(potential: ScalarPotential) -> tuple[Decimal, Decimal]:
    """Bound V'' over [domain_min, domain_max] using coefficient magnitudes."""
    radius = max(abs(potential.domain_min), abs(potential.domain_max))
    lower = Decimal("0")
    upper = Decimal("0")
    for term in potential.terms:
        if term.power < 2:
            continue
        coefficient = term.coefficient * term.power * (term.power - 1)
        if term.power == 2:
            lower += coefficient
            upper += abs(coefficient)
        else:
            magnitude = abs(coefficient) * (radius ** (term.power - 2))
            lower -= magnitude
            upper += magnitude
    if not lower.is_finite() or not upper.is_finite():
        raise ValueError("potential curvature bound exceeded Decimal range")
    return lower, upper


def assess_field_time_step(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    kinetic_coefficient: Decimal,
    inertia_coefficient: Decimal,
    time_step: Decimal,
) -> FieldStabilityAssessment:
    """Check a sufficient timestep bound for semi-implicit Euler.

    For a convex potential on the complete declared domain, a conservative
    upper bound on the largest squared frequency is

      4 K / (M dx^2 w_min) + sup(|V''|) / M,

    where w_min is 1 for periodic lattices and 1/2 for open trapezoidal
    lattices. The sufficient condition is 0 < dt < 2/sqrt(omega_bound^2).
    Decimal square roots are used for the reported bound; the result is
    rounded conservatively downward at the active Decimal precision.
    """
    configuration.validate_against(potential)
    for name, value in (
        ("kinetic_coefficient", kinetic_coefficient),
        ("inertia_coefficient", inertia_coefficient),
        ("time_step", time_step),
    ):
        if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
            raise ValueError(f"{name} must be a finite positive Decimal")

    curvature_lower, curvature_upper = _potential_curvature_bounds(potential)
    if configuration.boundary == LatticeBoundary.PERIODIC:
        minimum_weight = Decimal("1")
    else:
        minimum_weight = Decimal("0.5")

    omega_squared_bound = (
        Decimal("4") * kinetic_coefficient
        / (inertia_coefficient * configuration.spacing ** 2 * minimum_weight)
        + curvature_upper / inertia_coefficient
    )
    if not omega_squared_bound.is_finite() or omega_squared_bound <= 0:
        raise ValueError("frequency bound is not finite and positive")

    if curvature_lower < 0:
        return FieldStabilityAssessment(
            configuration_id=configuration.configuration_id,
            model_id=configuration.model_id,
            potential_id=configuration.potential_id,
            boundary=configuration.boundary,
            time_step=time_step,
            time_step_upper_bound=None,
            maximum_absolute_potential_curvature=curvature_upper,
            lower_bound_potential_curvature=curvature_lower,
            maximum_squared_frequency_bound=omega_squared_bound,
            inertia_coefficient=inertia_coefficient,
            kinetic_coefficient=kinetic_coefficient,
            status=FieldStabilityStatus.NOT_CERTIFIED_NONCONVEX_DOMAIN,
            sufficient_condition="No bound certified: the potential curvature lower bound is negative.",
        )

    with __import__("decimal").localcontext() as context:
        context.prec += 8
        raw_bound = Decimal("2") / omega_squared_bound.sqrt()
        timestep_bound = raw_bound.next_minus()

    status = (
        FieldStabilityStatus.CERTIFIED_WITHIN_BOUND
        if time_step < timestep_bound
        else FieldStabilityStatus.TIME_STEP_EXCEEDS_BOUND
    )
    return FieldStabilityAssessment(
        configuration_id=configuration.configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        boundary=configuration.boundary,
        time_step=time_step,
        time_step_upper_bound=timestep_bound,
        maximum_absolute_potential_curvature=curvature_upper,
        lower_bound_potential_curvature=curvature_lower,
        maximum_squared_frequency_bound=omega_squared_bound,
        inertia_coefficient=inertia_coefficient,
        kinetic_coefficient=kinetic_coefficient,
        status=status,
        sufficient_condition="0 < time_step < 2 / sqrt(maximum_squared_frequency_bound), with V'' nonnegative over the declared domain.",
    )
