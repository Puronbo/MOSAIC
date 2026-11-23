"""Restricted Mathlib ring checker for universally quantified Int polynomials.

This backend is deliberately separate from the core Lean/omega checker.
It accepts mathematical expressions, generates all Lean source internally,
and treats Lean's kernel as the only source of formal-verification status.
"""
import ast
import hashlib
import math
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.lean_kernel import _lean_environment


_MAX_INPUT_CHARS = 512
_MAX_AST_NODES = 64
_MAX_LITERAL = 1_000_000
_MAX_EXPONENT = 8
_MAX_TOTAL_DEGREE = 12
_MAX_MONOMIALS = 128
_MAX_COEFFICIENT_BITS = 256
_MAX_VARIABLES = 3
_ALLOWED_VARIABLES = frozenset({"x", "y", "z"})
_PROJECT_DIR = Path(__file__).resolve().parents[2] / "formal" / "polynomial"


class LeanPolynomialCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    checker_id: Literal["lean.kernel.polynomial_int_identity.v1"] = (
        "lean.kernel.polynomial_int_identity.v1"
    )
    lhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lean_version: str | None = None
    mathlib_revision: Literal[
        "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    ] = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    proof_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    variables: tuple[str, ...] = ()
    explanation: str


class _Unsupported(ValueError):
    pass


# A polynomial is a sparse map from sorted variable/exponent tuples to
# integer coefficients. The empty tuple denotes the constant term.
Polynomial = dict[tuple[tuple[str, int], ...], int]


def _bounded(poly: Polynomial) -> Polynomial:
    cleaned = {monomial: coefficient for monomial, coefficient in poly.items() if coefficient}
    if len(cleaned) > _MAX_MONOMIALS:
        raise _Unsupported("polynomial exceeds the monomial-count bound")
    for monomial, coefficient in cleaned.items():
        if sum(power for _, power in monomial) > _MAX_TOTAL_DEGREE:
            raise _Unsupported("polynomial exceeds the total-degree bound")
        if abs(coefficient).bit_length() > _MAX_COEFFICIENT_BITS:
            raise _Unsupported("polynomial coefficient exceeds the bit-length bound")
    return cleaned


def _constant(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and not isinstance(node.value, bool) and isinstance(node.value, int):
        if abs(node.value) > _MAX_LITERAL:
            raise _Unsupported("integer literal exceeds the polynomial bound")
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _constant(node.operand)
        if value is not None:
            return value if isinstance(node.op, ast.UAdd) else -value
    return None


def _add(left: Polynomial, right: Polynomial, sign: int = 1) -> Polynomial:
    result = dict(left)
    for monomial, coefficient in right.items():
        result[monomial] = result.get(monomial, 0) + sign * coefficient
    return _bounded(result)


def _multiply(left: Polynomial, right: Polynomial) -> Polynomial:
    result: Polynomial = {}
    for left_monomial, left_coefficient in left.items():
        for right_monomial, right_coefficient in right.items():
            powers: dict[str, int] = {}
            for name, power in (*left_monomial, *right_monomial):
                powers[name] = powers.get(name, 0) + power
            monomial = tuple(sorted((name, power) for name, power in powers.items() if power))
            result[monomial] = result.get(monomial, 0) + left_coefficient * right_coefficient
            _bounded(result)
    return _bounded(result)


def _polynomial(node: ast.AST) -> Polynomial:
    literal = _constant(node)
    if literal is not None:
        return {(): literal} if literal else {}
    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_VARIABLES:
            raise _Unsupported("only variables x, y, and z are supported")
        return {((node.id, 1),): 1}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _polynomial(node.operand)
        return value if isinstance(node.op, ast.UAdd) else {m: -c for m, c in value.items()}
    if not isinstance(node, ast.BinOp):
        raise _Unsupported("only polynomial arithmetic is supported")
    if isinstance(node.op, (ast.Add, ast.Sub)):
        return _add(_polynomial(node.left), _polynomial(node.right),
                    1 if isinstance(node.op, ast.Add) else -1)
    if isinstance(node.op, ast.Mult):
        return _multiply(_polynomial(node.left), _polynomial(node.right))
    if isinstance(node.op, ast.Pow):
        exponent = _constant(node.right)
        if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
            raise _Unsupported("powers must use a bounded nonnegative integer exponent")
        base = _polynomial(node.left)
        result: Polynomial = {(): 1}
        for _ in range(exponent):
            result = _multiply(result, base)
        return result
    raise _Unsupported("division, modulo, and unsupported operators are not polynomial syntax")


def _parse_polynomial(raw: str) -> tuple[ast.AST, tuple[str, ...]]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_INPUT_CHARS:
        raise _Unsupported("expression must be non-empty and within the input bound")
    tree = ast.parse(raw, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise _Unsupported("expression exceeds the syntax-node bound")
    _polynomial(tree.body)
    variables = tuple(sorted({
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }))
    if len(variables) > _MAX_VARIABLES:
        raise _Unsupported("polynomial has too many distinct variables")
    return tree.body, variables


def _render(node: ast.AST) -> str:
    literal = _constant(node)
    if literal is not None:
        return f"({literal} : Int)"
    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_VARIABLES:
            raise _Unsupported("only variables x, y, and z are supported")
        return node.id
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _render(node.operand) if isinstance(node.op, ast.UAdd) else f"(-{_render(node.operand)})"
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return f"({_render(node.left)} + {_render(node.right)})"
        if isinstance(node.op, ast.Sub):
            return f"({_render(node.left)} - {_render(node.right)})"
        if isinstance(node.op, ast.Mult):
            return f"({_render(node.left)} * {_render(node.right)})"
        if isinstance(node.op, ast.Pow):
            exponent = _constant(node.right)
            if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
                raise _Unsupported("powers must use a bounded nonnegative integer exponent")
            return f"({_render(node.left)} ^ {exponent})"
    raise _Unsupported("unsupported polynomial syntax")


def _generated_source(lhs: str, rhs: str) -> tuple[str, tuple[str, ...]]:
    left, left_variables = _parse_polynomial(lhs)
    right, right_variables = _parse_polynomial(rhs)
    variables = tuple(sorted(set(left_variables) | set(right_variables)))
    binders = " ".join(f"({name} : Int)" for name in variables)
    source = (
        "import Mathlib.Tactic.Ring\n"
        f"theorem mosaic_polynomial_certificate {binders} : "
        f"{_render(left)} = {_render(right)} := by ring\n"
    )
    return source, variables


def verify_polynomial_int_identity(
    lhs: str, rhs: str, *, timeout_seconds: float = 30.0,
    lake_executable: str = "lake",
) -> LeanPolynomialCheck:
    """Check a bounded polynomial identity with the pinned Mathlib ring tactic."""
    lhs_hash = hashlib.sha256(lhs.encode("utf-8") if isinstance(lhs, str) else b"").hexdigest()
    rhs_hash = hashlib.sha256(rhs.encode("utf-8") if isinstance(rhs, str) else b"").hexdigest()
    try:
        source, variables = _generated_source(lhs, rhs)
    except (SyntaxError, ValueError, RecursionError):
        return LeanPolynomialCheck(
            status="UNSUPPORTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The expression is outside the bounded polynomial grammar.",
        )

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 120:
        return LeanPolynomialCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The Mathlib wall-clock limit must be between 0 and 120 seconds.",
        )

    proof_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    executable = shutil.which(lake_executable)
    if executable is None or not (_PROJECT_DIR / "lakefile.lean").is_file():
        return LeanPolynomialCheck(
            status="KERNEL_UNAVAILABLE", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash, variables=variables,
            explanation="The pinned Mathlib Lake project is unavailable; no formal verification was performed.",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="mosaic-mathlib-") as directory:
            source_path = Path(directory) / "Certificate.lean"
            source_path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [executable, "env", "lean", str(source_path)],
                capture_output=True, text=True, timeout=timeout_seconds,
                check=False, cwd=_PROJECT_DIR, env=_lean_environment(),
            )
        version = None
        try:
            version_result = subprocess.run(
                [executable, "env", "lean", "--version"],
                capture_output=True, text=True, timeout=min(timeout_seconds, 5.0),
                check=False, cwd=_PROJECT_DIR, env=_lean_environment(),
            )
            version = (version_result.stdout or version_result.stderr).strip()[:160] or None
        except (OSError, subprocess.TimeoutExpired):
            pass
        if completed.returncode == 0:
            return LeanPolynomialCheck(
                status="FORMALLY_VERIFIED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
                lean_version=version, proof_source_sha256=proof_hash,
                variables=variables,
                explanation="The pinned Mathlib ring tactic produced a proof accepted by the Lean kernel for all integer assignments.",
            )
        return LeanPolynomialCheck(
            status="REJECTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            lean_version=version, proof_source_sha256=proof_hash,
            variables=variables,
            explanation="Lean rejected the generated polynomial identity theorem.",
        )
    except subprocess.TimeoutExpired:
        return LeanPolynomialCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash, variables=variables,
            explanation="Mathlib exceeded the configured wall-clock limit; no formal verification result is available.",
        )
    except OSError:
        return LeanPolynomialCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash, variables=variables,
            explanation="The pinned Mathlib project could not be executed; no formal verification result is available.",
        )
