import hashlib

import pytest

from mosaic.verification.lean_calculus import (
    _source,
    verify_polynomial_real_derivative,
)


def test_derivative_source_uses_real_has_deriv_at_and_kernel_proof():
    source, derivative = _source("(x + 1)^3")
    assert "HasDerivAt (fun t : ℝ" in source
    assert "hasDerivAt_id' x" in source
    assert ".pow 3" in source
    assert "by\n  exact" in source
    assert "Lean" not in derivative


def test_product_rule_is_generated_from_mathlib_derivative_combinator():
    source, _ = _source("(x + 2) * (x - 3)")
    assert ".mul" in source
    assert ".add" in source
    assert ".sub" in source


def test_constant_and_unary_negative_are_supported():
    source, _ = _source("-x^2 + 7")
    assert ".neg" in source
    assert "hasDerivAt_const" in source


@pytest.mark.parametrize(
    "expression",
    ["", "x / 2", "sin(x)", "y + 1", "x^-1", "x^9", "x**2 + 1; sorry"],
)
def test_unsupported_derivative_syntax_is_not_formally_verified(expression):
    result = verify_polynomial_real_derivative(expression, lake_executable="missing-lake")
    assert result.status == "UNSUPPORTED"
    assert result.proof_source_sha256 is None


def test_derivative_reports_kernel_unavailable_without_lean():
    result = verify_polynomial_real_derivative("x^2 + 2*x + 1", lake_executable="missing-lake")
    assert result.status == "KERNEL_UNAVAILABLE"
    assert len(result.expression_sha256) == 64
    assert len(result.derivative_sha256) == 64
    assert len(result.proof_source_sha256) == 64
