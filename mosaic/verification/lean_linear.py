"""Restricted Lean omega checker for universally quantified linear Int identities.

The expression language is parsed into affine forms; no caller-supplied Lean
source, binders, assumptions, imports, or tactics are accepted.
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
_MAX_COEFFICIENT = 1_000_000
_ALLOWED_VARIABLES = frozenset({"x", "y", "z"})


class LeanLinearCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    checker_id: Literal["lean.kernel.linear_int_identity.v1"] = "lean.kernel.linear_int_identity.v1"
    lhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lean_version: str | None = None
    proof_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    variables: tuple[str, ...] = ()
    explanation: str


class _Unsupported(ValueError):
    pass


def _constant(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and not isinstance(node.value, bool) and isinstance(node.value, int):
        if abs(node.value) > _MAX_LITERAL:
            raise _Unsupported("integer literal exceeds the linear arithmetic bound")
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _constant(node.operand)
        if value is not None:
            return value if isinstance(node.op, ast.UAdd) else -value
    return None


def _linear_form(node: ast.AST) -> dict[str, int]:
    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_VARIABLES:
            raise _Unsupported("only variables x, y, and z are supported")
        return {node.id: 1}
    literal = _constant(node)
    if literal is not None:
        return {"": literal}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        form = _linear_form(node.operand)
        sign = 1 if isinstance(node.op, ast.UAdd) else -1
        return {key: sign * value for key, value in form.items()}
    if not isinstance(node, ast.BinOp):
        raise _Unsupported("only affine integer expressions are supported")
    if isinstance(node.op, (ast.Add, ast.Sub)):
        left, right = _linear_form(node.left), _linear_form(node.right)
        sign = 1 if isinstance(node.op, ast.Add) else -1
        merged = dict(left)
        for key, value in right.items():
            merged[key] = merged.get(key, 0) + sign * value
        return {key: value for key, value in merged.items() if value}
    if isinstance(node.op, ast.Mult):
        left, right = _linear_form(node.left), _linear_form(node.right)
        left_is_constant = not any(key for key in left)
        right_is_constant = not any(key for key in right)
        if left_is_constant and right_is_constant:
            return {"": left.get("", 0) * right.get("", 0)}
        if not left_is_constant and not right_is_constant:
            raise _Unsupported("multiplication must have an integer literal factor")
        scalar = left.get("", 0) if left_is_constant else right.get("", 0)
        form = right if left_is_constant else left
        return {key: scalar * value for key, value in form.items() if key}
    raise _Unsupported("only addition, subtraction, and multiplication by integer literals are supported")


def _parse_linear(raw: str) -> tuple[dict[str, int], tuple[str, ...]]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_INPUT_CHARS:
        raise _Unsupported("expression must be non-empty and within the input bound")
    tree = ast.parse(raw, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise _Unsupported("expression exceeds the syntax-node bound")
    form = _linear_form(tree.body)
    if any(abs(value) > _MAX_COEFFICIENT for value in form.values()):
        raise _Unsupported("linear coefficient exceeds the arithmetic bound")
    variables = tuple(sorted(key for key in form if key))
    return form, variables


def _render_linear(node: ast.AST) -> str:
    literal = _constant(node)
    if literal is not None:
        return f"({literal} : Int)"
    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_VARIABLES:
            raise _Unsupported("only variables x, y, and z are supported")
        return node.id
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        if isinstance(node.op, ast.UAdd):
            return _render_linear(node.operand)
        return f"(-{_render_linear(node.operand)})"
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        operator = "+" if isinstance(node.op, ast.Add) else "-" if isinstance(node.op, ast.Sub) else "*"
        return f"({_render_linear(node.left)} {operator} {_render_linear(node.right)})"
    raise _Unsupported("only affine integer expressions are supported")


def _render_expression(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_INPUT_CHARS:
        raise _Unsupported("expression must be non-empty and within the input bound")
    tree = ast.parse(raw, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise _Unsupported("expression exceeds the syntax-node bound")
    _linear_form(tree.body)  # Validate the affine grammar before rendering.
    return _render_linear(tree.body)


def verify_linear_int_identity(
    lhs: str, rhs: str, *, timeout_seconds: float = 5.0,
    lean_executable: str = "lean",
) -> LeanLinearCheck:
    """Kernel-check a universally quantified affine identity over Int."""
    lhs_hash = hashlib.sha256(lhs.encode("utf-8") if isinstance(lhs, str) else b"").hexdigest()
    rhs_hash = hashlib.sha256(rhs.encode("utf-8") if isinstance(rhs, str) else b"").hexdigest()
    try:
        left, left_vars = _parse_linear(lhs)
        right, right_vars = _parse_linear(rhs)
    except (SyntaxError, ValueError, RecursionError):
        return LeanLinearCheck(
            status="UNSUPPORTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The expression is outside the restricted affine-integer grammar.",
        )

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 30:
        return LeanLinearCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The Lean wall-clock limit must be between 0 and 30 seconds.",
        )

    variables = tuple(sorted(set(left_vars) | set(right_vars)))
    binders = " ".join(f"({name} : Int)" for name in variables)
    theorem_header = (
        f"theorem mosaic_certificate {binders} : "
        f"{_render_expression(lhs)} = {_render_expression(rhs)} := by omega\n"
    )
    source = "import Lean\n" + theorem_header
    proof_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    executable = shutil.which(lean_executable)
    if executable is None:
        return LeanLinearCheck(
            status="KERNEL_UNAVAILABLE", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            variables=variables, explanation="Lean was not found; no formal verification was performed.",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="mosaic-lean-linear-") as directory:
            source_path = Path(directory) / "Certificate.lean"
            source_path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [executable, str(source_path)],
                capture_output=True, text=True, timeout=timeout_seconds,
                check=False, cwd=Path.cwd(), env=_lean_environment(),
            )
        version = None
        try:
            version_result = subprocess.run(
                [executable, "--version"], capture_output=True, text=True,
                timeout=min(timeout_seconds, 2.0), check=False,
                env=_lean_environment(),
            )
            version = (version_result.stdout or version_result.stderr).strip()[:160] or None
        except (OSError, subprocess.TimeoutExpired):
            pass
        if completed.returncode == 0:
            return LeanLinearCheck(
                status="FORMALLY_VERIFIED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
                lean_version=version, proof_source_sha256=proof_hash,
                variables=variables,
                explanation="Lean accepted the universally quantified affine Int identity using omega; the configured Lean kernel checked the theorem.",
            )
        return LeanLinearCheck(
            status="REJECTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            lean_version=version, proof_source_sha256=proof_hash,
            variables=variables,
            explanation="Lean rejected the generated affine Int identity theorem.",
        )
    except subprocess.TimeoutExpired:
        return LeanLinearCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash, variables=variables,
            explanation="Lean exceeded the configured wall-clock limit; no formal verification result is available.",
        )
    except OSError:
        return LeanLinearCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash, variables=variables,
            explanation="Lean could not be executed; no formal verification result is available.",
        )
