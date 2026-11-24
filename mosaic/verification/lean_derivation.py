"""Request- and derivation-bound Lean verification for polynomial root derivatives.

This is an end-to-end theorem for the root derivative, not a proof that every
intermediate decomposition-tree edge was used in the proof. The tree is
validated and hashed as provenance; Lean independently proves the root
HasDerivAt proposition for the exact expression and submitted candidate.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.derivation import DerivationTree, validate_derivation_tree
from mosaic.verification.lean_calculus import (
    LeanPolynomialDerivativeCheck,
    verify_polynomial_real_derivative,
)
from mosaic.verification.obligations import request_fingerprint


class LeanDerivationReceipt(BaseModel):
    """Immutable receipt binding a root derivative theorem to request and tree."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    scope: Literal["root_derivative"] = "root_derivative"
    checker_id: Literal["lean.kernel.polynomial_real_derivative.v1"] = (
        "lean.kernel.polynomial_real_derivative.v1"
    )
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    derivation_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expression_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    derivative_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_source_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    lean_version: str | None = None
    mathlib_revision: str = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    explanation: str = Field(max_length=2000)


def _tree_fingerprint(tree: DerivationTree) -> str:
    canonical = json.dumps(
        tree.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_derivation_root_derivative_with_lean(
    request: MathRequest,
    tree: DerivationTree,
    candidate_derivative: str,
    *,
    timeout_seconds: float = 30.0,
    lake_executable: str = "lake",
) -> LeanDerivationReceipt:
    """Kernel-check a polynomial root derivative, bound to its validated tree.

    The registered derivation tree must be complete for the exact request.
    The current Lean calculus backend supports bounded univariate real
    polynomials in x. It proves the root HasDerivAt theorem directly, rather
    than claiming that the recursive tree itself has been formally composed.
    """
    if request.operation.value != "differentiate":
        raise ValueError("Lean derivation checking requires a differentiate request.")
    if request.variable != "x":
        raise ValueError("The current Lean calculus checker supports only variable x.")
    if not validate_derivation_tree(request, tree):
        raise ValueError("Cannot bind Lean verification to an invalid derivation tree.")
    if not isinstance(candidate_derivative, str) or not candidate_derivative.strip():
        raise ValueError("candidate_derivative must be non-empty text.")

    check: LeanPolynomialDerivativeCheck = verify_polynomial_real_derivative(
        request.expression,
        candidate_derivative=candidate_derivative,
        timeout_seconds=timeout_seconds,
        lake_executable=lake_executable,
    )
    return LeanDerivationReceipt(
        status=check.status,
        request_sha256=request_fingerprint(request),
        derivation_tree_sha256=_tree_fingerprint(tree),
        expression_sha256=check.expression_sha256,
        derivative_sha256=check.derivative_sha256,
        proof_source_sha256=check.proof_source_sha256,
        lean_version=check.lean_version,
        mathlib_revision=check.mathlib_revision,
        explanation=(
            "Lean kernel accepted the root HasDerivAt theorem for the exact request expression and candidate derivative. The validated derivation tree is bound as provenance, not claimed as the proof term."
            if check.status == "FORMALLY_VERIFIED"
            else check.explanation
        ),
    )
