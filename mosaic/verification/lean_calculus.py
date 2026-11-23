"""Pinned-Mathlib formal derivative checker for bounded real polynomials.

The parser builds a restricted syntax tree. Lean source and derivative proofs
are generated internally; only Lean kernel acceptance yields FORMALLY_VERIFIED.
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

_PROJECT_DIR = Path(__file__).resolve().parents[2] / "formal" / "polynomial"
_MAX_INPUT_CHARS = 512
_MAX_AST_NODES = 64
_MAX_LITERAL = 1_000_000
_MAX_EXPONENT = 8
_MAX_TOTAL_DEGREE = 12
_MAX_COEFFICIENT_BITS = 256


class LeanPolynomialDerivativeCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    checker_id: Literal["lean.kernel.polynomial_real_derivative.v1"] = (
        "lean.kernel.polynomial_real_derivative.v1"
    )
    expression_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    derivative_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    lean_version: str | None = None
    diagnostics: str | None = Field(default=None, max_length=2000)
    mathlib_revision: Literal[
        "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    ] = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    explanation: str


class _Unsupported(ValueError):
    pass


class _CandidateMismatch(ValueError):
    pass


def _integer(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        if abs(node.value) > _MAX_LITERAL:
            raise _Unsupported("integer literal exceeds the configured bound")
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _integer(node.operand)
        if value is not None:
            return value if isinstance(node.op, ast.UAdd) else -value
    return None


def _validate(node: ast.AST) -> int:
    literal = _integer(node)
    if literal is not None:
        return 0
    if isinstance(node, ast.Name):
        if node.id != "x":
            raise _Unsupported("only the variable x is supported")
        return 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _validate(node.operand)
    if not isinstance(node, ast.BinOp):
        raise _Unsupported("only bounded polynomial arithmetic is supported")
    left_degree = _validate(node.left)
    if isinstance(node.op, (ast.Add, ast.Sub)):
        return max(left_degree, _validate(node.right))
    if isinstance(node.op, ast.Mult):
        degree = left_degree + _validate(node.right)
        if degree > _MAX_TOTAL_DEGREE:
            raise _Unsupported("polynomial exceeds the total-degree bound")
        return degree
    if isinstance(node.op, (ast.Pow, ast.BitXor)):
        exponent = _integer(node.right)
        if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
            raise _Unsupported("powers must be bounded nonnegative integer literals")
        degree = left_degree * exponent
        if degree > _MAX_TOTAL_DEGREE:
            raise _Unsupported("polynomial exceeds the total-degree bound")
        return degree
    raise _Unsupported("division, modulo, calls, and unsupported operators are rejected")


def _polynomial(node: ast.AST) -> dict[int, int]:
    """Bound intermediate coefficients and term count independently of Lean."""
    literal = _integer(node)
    if literal is not None:
        result = {0: literal} if literal else {}
    elif isinstance(node, ast.Name):
        if node.id != "x":
            raise _Unsupported("only the variable x is supported")
        result = {1: 1}
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        child = _polynomial(node.operand)
        result = child if isinstance(node.op, ast.UAdd) else {power: -coefficient for power, coefficient in child.items()}
    elif isinstance(node, ast.BinOp):
        left = _polynomial(node.left)
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            exponent = _integer(node.right)
            if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
                raise _Unsupported("powers must be bounded nonnegative integer literals")
            result = {0: 1}
            for _ in range(exponent):
                result = _multiply_polynomials(result, left)
        else:
            right = _polynomial(node.right)
            if isinstance(node.op, ast.Add):
                result = dict(left)
                for power, coefficient in right.items():
                    result[power] = result.get(power, 0) + coefficient
            elif isinstance(node.op, ast.Sub):
                result = dict(left)
                for power, coefficient in right.items():
                    result[power] = result.get(power, 0) - coefficient
            elif isinstance(node.op, ast.Mult):
                result = _multiply_polynomials(left, right)
            else:
                raise _Unsupported("unsupported polynomial operator")
    else:
        raise _Unsupported("unsupported polynomial syntax")
    result = {power: coefficient for power, coefficient in result.items() if coefficient}
    if len(result) > 128:
        raise _Unsupported("polynomial exceeds the 128-term bound")
    if any(abs(coefficient).bit_length() > 256 for coefficient in result.values()):
        raise _Unsupported("polynomial coefficient exceeds the 256-bit bound")
    if any(power > _MAX_TOTAL_DEGREE for power in result):
        raise _Unsupported("polynomial exceeds the total-degree bound")
    return result


def _multiply_polynomials(left: dict[int, int], right: dict[int, int]) -> dict[int, int]:
    result: dict[int, int] = {}
    for left_power, left_coefficient in left.items():
        for right_power, right_coefficient in right.items():
            power = left_power + right_power
            result[power] = result.get(power, 0) + left_coefficient * right_coefficient
            if abs(result[power]).bit_length() > 256:
                raise _Unsupported("polynomial coefficient exceeds the 256-bit bound")
            if len(result) > 128:
                raise _Unsupported("polynomial exceeds the 128-term bound")
    return {power: coefficient for power, coefficient in result.items() if coefficient}


def _parse(raw: str) -> ast.AST:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_INPUT_CHARS:
        raise _Unsupported("expression must be non-empty and within 512 characters")
    tree = ast.parse(raw.replace("^", "**"), mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise _Unsupported("expression exceeds the syntax-node bound")
    _validate(tree.body)
    _polynomial(tree.body)
    return tree.body


def _real_literal(value: int) -> str:
    return f"({value} : ℝ)"


def _render(node: ast.AST, variable: str) -> str:
    literal = _integer(node)
    if literal is not None:
        return _real_literal(literal)
    if isinstance(node, ast.Name):
        return variable
    if isinstance(node, ast.UnaryOp):
        inner = _render(node.operand, variable)
        return inner if isinstance(node.op, ast.UAdd) else f"(-{inner})"
    if isinstance(node, ast.BinOp):
        left = _render(node.left, variable)
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            exponent = _integer(node.right)
            if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
                raise _Unsupported("invalid exponent")
            return f"({left} ^ {exponent})"
        right = _render(node.right, variable)
        if isinstance(node.op, ast.Add):
            return f"({left} + {right})"
        if isinstance(node.op, ast.Sub):
            return f"({left} - {right})"
        if isinstance(node.op, ast.Mult):
            return f"({left} * {right})"
    raise _Unsupported("unsupported polynomial syntax")


def _derivative(node: ast.AST) -> str:
    literal = _integer(node)
    if literal is not None:
        return _real_literal(0)
    if isinstance(node, ast.Name):
        return _real_literal(1)
    if isinstance(node, ast.UnaryOp):
        result = _derivative(node.operand)
        return result if isinstance(node.op, ast.UAdd) else f"(-{result})"
    if isinstance(node, ast.BinOp):
        left_d = _derivative(node.left)
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            exponent = _integer(node.right)
            if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
                raise _Unsupported("invalid exponent")
            base = _render(node.left, "x")
            return f"(({exponent} : ℝ) * ({base} ^ {max(exponent - 1, 0)}) * ({left_d}))"
        right_d = _derivative(node.right)
        left = _render(node.left, "x")
        right = _render(node.right, "x")
        if isinstance(node.op, ast.Add):
            return f"({left_d} + {right_d})"
        if isinstance(node.op, ast.Sub):
            return f"({left_d} - {right_d})"
        if isinstance(node.op, ast.Mult):
            return f"({left_d} * {right} + {left} * {right_d})"
    raise _Unsupported("unsupported polynomial syntax")


def _proof(node: ast.AST) -> str:
    literal = _integer(node)
    if literal is not None:
        return f"hasDerivAt_const x {_real_literal(literal)}"
    if isinstance(node, ast.Name):
        return "hasDerivAt_id' x"
    if isinstance(node, ast.UnaryOp):
        child = _proof(node.operand)
        return child if isinstance(node.op, ast.UAdd) else f"HasDerivAt.neg ({child})"
    if isinstance(node, ast.BinOp):
        left = _proof(node.left)
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            exponent = _integer(node.right)
            if exponent is None or exponent < 0 or exponent > _MAX_EXPONENT:
                raise _Unsupported("invalid exponent")
            return f"HasDerivAt.pow ({left}) {exponent}"
        right = _proof(node.right)
        method = {
            ast.Add: "add",
            ast.Sub: "sub",
            ast.Mult: "mul",
        }.get(type(node.op))
        if method is not None:
            return f"HasDerivAt.{method} ({left}) ({right})"
    raise _Unsupported("unsupported polynomial syntax")


def _source(raw: str) -> tuple[str, str]:
    tree = _parse(raw)
    expression = _render(tree, "t")
    derivative = _derivative(tree)
    proof = _proof(tree)
    source = (
        "import Mathlib.Analysis.Calculus.Deriv.Pow\n"
        "theorem mosaic_polynomial_has_derivative (x : ℝ) :\n"
        f"    HasDerivAt (fun t : ℝ => {expression}) ({derivative}) x := by\n"
        f"  exact {proof}\n"
    )
    return source, derivative


def verify_polynomial_real_derivative(
    expression: str,
    *,
    candidate_derivative: str | None = None,
    timeout_seconds: float = 30.0,
    lake_executable: str = "lake",
) -> LeanPolynomialDerivativeCheck:
    """Prove the derivative of a bounded polynomial over ℝ using pinned Mathlib."""
    expression_hash = hashlib.sha256(
        expression.encode("utf-8") if isinstance(expression, str) else b""
    ).hexdigest()
    try:
        source, derivative = _source(expression, candidate_derivative)
    except _CandidateMismatch:
        return LeanPolynomialDerivativeCheck(
            status="REJECTED",
            expression_sha256=expression_hash,
            derivative_sha256=hashlib.sha256(candidate_derivative.encode("utf-8")).hexdigest(),
            explanation="The submitted derivative does not match the independently computed polynomial derivative.",
        )
    except (SyntaxError, ValueError, RecursionError):
        return LeanPolynomialDerivativeCheck(
            status="UNSUPPORTED",
            expression_sha256=expression_hash,
            derivative_sha256=hashlib.sha256(b"").hexdigest(),
            explanation="Expression is outside the bounded univariate polynomial grammar.",
        )

    derivative_hash = hashlib.sha256(
        (candidate_derivative if candidate_derivative is not None else derivative).encode("utf-8")
    ).hexdigest()
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > 120
    ):
        return LeanPolynomialDerivativeCheck(
            status="KERNEL_ERROR",
            expression_sha256=expression_hash,
            derivative_sha256=derivative_hash,
            explanation="The Lean wall-clock limit must be between 0 and 120 seconds.",
        )

    proof_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    executable = shutil.which(lake_executable)
    if executable is None or not (_PROJECT_DIR / "lakefile.lean").is_file():
        return LeanPolynomialDerivativeCheck(
            status="KERNEL_UNAVAILABLE",
            expression_sha256=expression_hash,
            derivative_sha256=derivative_hash,
            proof_source_sha256=proof_hash,
            explanation="Pinned Mathlib is unavailable; no formal derivative proof was checked.",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="mosaic-derivative-") as directory:
            path = Path(directory) / "Derivative.lean"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [executable, "env", "lean", str(path)],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                cwd=_PROJECT_DIR,
                env=_lean_environment(),
            )
        version = None
        try:
            version_result = subprocess.run(
                [executable, "env", "lean", "--version"],
                capture_output=True,
                text=True,
                timeout=min(timeout_seconds, 5.0),
                check=False,
                cwd=_PROJECT_DIR,
                env=_lean_environment(),
            )
            version = (version_result.stdout or version_result.stderr).strip()[:160] or None
        except (OSError, subprocess.TimeoutExpired):
            pass
        if result.returncode == 0:
            return LeanPolynomialDerivativeCheck(
                status="FORMALLY_VERIFIED",
                expression_sha256=expression_hash,
                derivative_sha256=derivative_hash,
                proof_source_sha256=proof_hash,
                lean_version=version,
                explanation=(
                    "Lean kernel accepted a HasDerivAt proof for the generated derivative "
                    "of the polynomial over the real numbers."
                ),
            )
        return LeanPolynomialDerivativeCheck(
            status="REJECTED",
            expression_sha256=expression_hash,
            derivative_sha256=derivative_hash,
            proof_source_sha256=proof_hash,
            lean_version=version,
            diagnostics=((result.stderr or result.stdout).strip()[-2000:] or None),
            explanation="Lean rejected the internally generated derivative theorem.",
        )
    except subprocess.TimeoutExpired:
        return LeanPolynomialDerivativeCheck(
            status="KERNEL_ERROR",
            expression_sha256=expression_hash,
            derivative_sha256=derivative_hash,
            proof_source_sha256=proof_hash,
            explanation="Lean exceeded the configured wall-clock limit.",
        )
    except OSError:
        return LeanPolynomialDerivativeCheck(
            status="KERNEL_ERROR",
            expression_sha256=expression_hash,
            derivative_sha256=derivative_hash,
            proof_source_sha256=proof_hash,
            explanation="The pinned Mathlib project could not be executed.",
        )
