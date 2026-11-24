import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.derivation import build_derivation_tree
from mosaic.verification.lean_calculus import LeanPolynomialDerivativeCheck
from mosaic.verification import lean_derivation


def request(expression="(x**2+1)**3", variable="x"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable=variable,
    )


def check(status="FORMALLY_VERIFIED"):
    return LeanPolynomialDerivativeCheck(
        status=status,
        expression_sha256="1" * 64,
        derivative_sha256="2" * 64,
        proof_source_sha256="3" * 64,
        lean_version="Lean (version test)",
        explanation="mocked kernel result",
    )


def test_root_derivative_receipt_binds_exact_request_and_validated_tree(monkeypatch):
    source = request()
    tree = build_derivation_tree(source)
    seen = {}

    def fake_verify(expression, **kwargs):
        seen["expression"] = expression
        seen.update(kwargs)
        return check()

    monkeypatch.setattr(
        lean_derivation, "verify_polynomial_real_derivative", fake_verify
    )
    receipt = lean_derivation.verify_derivation_root_derivative_with_lean(
        source, tree, "6*x*(x**2+1)**2"
    )

    assert receipt.status == "FORMALLY_VERIFIED"
    assert receipt.scope == "root_derivative"
    assert receipt.request_sha256
    assert receipt.derivation_tree_sha256
    assert receipt.expression_sha256 == "1" * 64
    assert receipt.derivative_sha256 == "2" * 64
    assert receipt.proof_source_sha256 == "3" * 64
    assert seen["expression"] == source.expression
    assert seen["candidate_derivative"] == "6*x*(x**2+1)**2"
    assert "not claimed as the proof term" in receipt.explanation


def test_root_derivative_receipt_preserves_non_success_status(monkeypatch):
    source = request()
    tree = build_derivation_tree(source)
    monkeypatch.setattr(
        lean_derivation,
        "verify_polynomial_real_derivative",
        lambda *args, **kwargs: check("KERNEL_UNAVAILABLE"),
    )
    receipt = lean_derivation.verify_derivation_root_derivative_with_lean(
        source, tree, "6*x*(x**2+1)**2"
    )
    assert receipt.status == "KERNEL_UNAVAILABLE"
    assert receipt.explanation == "mocked kernel result"


def test_root_derivative_rejects_incomplete_or_tampered_tree(monkeypatch):
    source = request()
    tree = build_derivation_tree(source)
    altered_root = tree.root.model_copy(update={"children": tree.root.children[:1]})
    altered = tree.model_copy(update={"root": altered_root})
    monkeypatch.setattr(
        lean_derivation,
        "verify_polynomial_real_derivative",
        lambda *args, **kwargs: pytest.fail("must not invoke Lean"),
    )
    with pytest.raises(ValueError, match="invalid derivation tree"):
        lean_derivation.verify_derivation_root_derivative_with_lean(
            source, altered, "6*x*(x**2+1)**2"
        )


def test_root_derivative_rejects_unsupported_operation_and_variable():
    integrate = request().model_copy(update={"operation": Operation.INTEGRATE})
    with pytest.raises(ValueError, match="differentiate"):
        lean_derivation.verify_derivation_root_derivative_with_lean(
            integrate, build_derivation_tree(integrate), "x"
        )

    y_request = request(variable="y")
    with pytest.raises(ValueError, match="only variable x"):
        lean_derivation.verify_derivation_root_derivative_with_lean(
            y_request, build_derivation_tree(y_request), "6*y*(y**2+1)**2"
        )
