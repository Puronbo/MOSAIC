from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.absence import PhysicalStateKind, PhysicalStateReference
from mosaic.core.physical_transitions import (
    EnergyAccounting, EnergyBalanceStatus, PhysicalTransition,
    check_energy_balance,
)


def state(state_id, kind):
    return PhysicalStateReference(
        state_id=state_id, model_id="model-A", kind=kind,
    )


def test_closed_system_energy_ledger_can_balance():
    ledger = EnergyAccounting(
        system_boundary="isolated system",
        unit="J",
        initial_energy=Decimal("10"),
        final_energy=Decimal("10"),
    )
    result = check_energy_balance(ledger)
    assert result.status == EnergyBalanceStatus.BALANCED
    assert result.residual == Decimal("0")


def test_energy_input_can_account_for_excitation():
    ledger = EnergyAccounting(
        system_boundary="field and apparatus",
        unit="J",
        initial_energy=Decimal("0"),
        energy_supplied=Decimal("2.5"),
        final_energy=Decimal("2.5"),
    )
    assert check_energy_balance(ledger).status == EnergyBalanceStatus.BALANCED


def test_energy_output_is_included_in_declared_balance():
    ledger = EnergyAccounting(
        system_boundary="system S", unit="J",
        initial_energy=Decimal("10"), energy_transferred_out=Decimal("3"),
        final_energy=Decimal("7"),
    )
    assert check_energy_balance(ledger).status == EnergyBalanceStatus.BALANCED


def test_unbalanced_ledger_is_not_silently_accepted():
    ledger = EnergyAccounting(
        system_boundary="system S", unit="J",
        initial_energy=Decimal("10"), final_energy=Decimal("8"),
    )
    result = check_energy_balance(ledger)
    assert result.status == EnergyBalanceStatus.UNBALANCED
    assert result.residual == Decimal("2")


def test_tolerance_is_explicit():
    ledger = EnergyAccounting(
        system_boundary="system S", unit="J",
        initial_energy=Decimal("1"), final_energy=Decimal("1.001"),
    )
    assert check_energy_balance(
        ledger, tolerance=Decimal("0.001")
    ).status == EnergyBalanceStatus.BALANCED


def test_energy_ledger_rejects_nonfinite_or_negative_values():
    with pytest.raises(ValidationError):
        EnergyAccounting(
            system_boundary="system S", unit="J",
            initial_energy=Decimal("NaN"), final_energy=Decimal("0"),
        )
    with pytest.raises(ValidationError):
        EnergyAccounting(
            system_boundary="system S", unit="J",
            initial_energy=Decimal("-1"), final_energy=Decimal("0"),
        )


def test_transition_records_model_relative_state_change():
    transition = PhysicalTransition(
        transition_id="transition-1", model_id="model-A",
        source_state=state("vacuum", PhysicalStateKind.VACUUM),
        target_state=state("excited", PhysicalStateKind.EXCITED),
        mechanism="declared interaction with external field",
        system_boundary="field and apparatus",
        energy_accounting=EnergyAccounting(
            system_boundary="field and apparatus", unit="J",
            initial_energy=Decimal("0"), energy_supplied=Decimal("2"),
            final_energy=Decimal("2"),
        ),
        evidence_sha256="b" * 64,
        assumptions=("model-A applies in this regime",),
    )
    assert transition.target_state.kind == PhysicalStateKind.EXCITED
    assert check_energy_balance(transition.energy_accounting).status == EnergyBalanceStatus.BALANCED


def test_transition_rejects_cross_model_state_and_boundary_mismatch():
    with pytest.raises(ValidationError):
        PhysicalTransition(
            transition_id="t-1", model_id="model-A",
            source_state=state("vacuum", PhysicalStateKind.VACUUM),
            target_state=PhysicalStateReference(
                state_id="excited", model_id="model-B",
                kind=PhysicalStateKind.EXCITED,
            ),
            mechanism="interaction", system_boundary="system S",
        )
    with pytest.raises(ValidationError):
        PhysicalTransition(
            transition_id="t-2", model_id="model-A",
            source_state=state("vacuum", PhysicalStateKind.VACUUM),
            target_state=state("excited", PhysicalStateKind.EXCITED),
            mechanism="interaction", system_boundary="system S",
            energy_accounting=EnergyAccounting(
                system_boundary="system T", unit="J",
                initial_energy=Decimal("0"), final_energy=Decimal("0"),
            ),
        )


def test_tolerance_must_be_finite_nonnegative_decimal():
    ledger = EnergyAccounting(
        system_boundary="system S", unit="J",
        initial_energy=Decimal("1"), final_energy=Decimal("1"),
    )
    with pytest.raises(ValueError):
        check_energy_balance(ledger, tolerance=Decimal("NaN"))
