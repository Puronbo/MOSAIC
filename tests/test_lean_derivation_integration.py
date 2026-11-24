"""Integration tests that exercise the real pinned Lean/Mathlib kernel."""
from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.derivation import build_derivation_tree
from mosaic.verification.lean_derivation import (
    verify_derivation_root_derivative_with_lean,
)


def test_nested_polynomial_root_derivative_is_accepted_by_lean_kernel():
    request = MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression="(x**2+1)**3",
        variable="x",
    )
    tree = build_derivation_tree(request)
    receipt = verify_derivation_root_derivative_with_lean(
        request,
        tree,
        "6*x*(x**2+1)**2",
        timeout_seconds=60,
    )
    assert receipt.status == "FORMALLY_VERIFIED", receipt.explanation
    assert receipt.proof_source_sha256 is not None
    assert receipt.lean_version
