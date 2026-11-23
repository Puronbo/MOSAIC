"""Optional Lean-kernel checker for closed natural-number equalities.

MOSAIC constructs Lean source itself from a tiny arithmetic AST grammar.
Callers cannot submit Lean source, imports, tactics, macros, or elaborator code.
A successful Lean process means the configured Lean kernel accepted the
generated theorem; unavailable Lean remains explicitly unavailable.
"""
import ast
import os
import math
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


_MAX_INPUT_CHARS = 512
_MAX_AST_NODES = 64
_MAX_LITERAL = 1_000_000
_MAX_EXPONENT = 12
_MAX_RESULT_BITS = 4096
_LEAN_ENV_KEYS = (
    "PATH", "HOME", "ELAN_HOME", "LEAN_SYSROOT", "LEAN_PATH",
    "LEAN_SRC_PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME",
)


def _lean_environment() -> dict[str, str]:
    """Pass toolchain configuration without forwarding unrelated secrets."""
    return {key: os.environ[key] for key in _LEAN_ENV_KEYS if key in os.environ}


class LeanKernelCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "INVALID_CERTIFICATE",
        "UNSUPPORTED", "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    checker_id: Literal["lean.kernel.closed_nat_equality.v1"] = "lean.kernel.closed_nat_equality.v1"
    lhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rhs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lean_version: str | None = None
    proof_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    explanation: str


class _Unsupported(ValueError):
    pass


def _render_nat(node: ast.AST) -> tuple[str, int]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, int) or node.value < 0 or node.value > _MAX_LITERAL:
            raise _Unsupported("only bounded non-negative integer literals are supported")
        return str(node.value), node.value.bit_length()
    if not isinstance(node, ast.BinOp):
        raise _Unsupported("only closed integer arithmetic is supported")
    left, left_bits = _render_nat(node.left)
    right, right_bits = _render_nat(node.right)
    if isinstance(node.op, ast.Add):
        bits = max(left_bits, right_bits) + 1
        rendered = f"({left} + {right})"
    elif isinstance(node.op, ast.Mult):
        bits = left_bits + right_bits
        rendered = f"({left} * {right})"
    elif isinstance(node.op, ast.Pow):
        exponent = _literal_exponent(node.right)
        bits = max(1, left_bits * exponent)
        if bits > _MAX_RESULT_BITS:
            raise _Unsupported("estimated result exceeds the arithmetic bound")
        rendered = f"({left} ^ {exponent})"
    else:
        raise _Unsupported("only addition, multiplication, and bounded powers are supported")
    if bits > _MAX_RESULT_BITS:
        raise _Unsupported("estimated result exceeds the arithmetic bound")
    return rendered, bits


def _literal_exponent(node: ast.AST) -> int:
    if not isinstance(node, ast.Constant) or isinstance(node.value, bool) or not isinstance(node.value, int):
        raise _Unsupported("exponent must be a non-negative integer literal")
    if node.value > _MAX_EXPONENT:
        raise _Unsupported("exponent exceeds the arithmetic bound")
    return node.value


def _render_expression(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_INPUT_CHARS:
        raise _Unsupported("expression must be non-empty and within the input bound")
    tree = ast.parse(raw, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
        raise _Unsupported("expression exceeds the syntax-node bound")
    return _render_nat(tree.body)[0]


def verify_closed_nat_equality(
    lhs: str, rhs: str, *, timeout_seconds: float = 5.0,
    lean_executable: str = "lean",
) -> LeanKernelCheck:
    """Ask Lean to kernel-check a generated proof of a closed Nat equality."""
    lhs_hash = hashlib.sha256(lhs.encode("utf-8") if isinstance(lhs, str) else b"").hexdigest()
    rhs_hash = hashlib.sha256(rhs.encode("utf-8") if isinstance(rhs, str) else b"").hexdigest()
    try:
        rendered_lhs = _render_expression(lhs)
        rendered_rhs = _render_expression(rhs)
    except (SyntaxError, ValueError, RecursionError):
        return LeanKernelCheck(
            status="UNSUPPORTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The expression is outside the restricted closed-natural-number grammar.",
        )

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 30:
        return LeanKernelCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            explanation="The Lean wall-clock limit must be between 0 and 30 seconds.",
        )

    source = (
        "theorem mosaic_certificate : "
        f"({rendered_lhs} : Nat) = ({rendered_rhs} : Nat) := by decide\\n"
    )
    proof_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    executable = shutil.which(lean_executable)
    if executable is None:
        return LeanKernelCheck(
            status="KERNEL_UNAVAILABLE", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash,
            explanation="Lean was not found; no formal verification was performed.",
        )
    try:
        with tempfile.TemporaryDirectory(prefix="mosaic-lean-") as directory:
            source_path = Path(directory) / "Certificate.lean"
            source_path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [executable, str(source_path)],
                capture_output=True, text=True, timeout=timeout_seconds,
                check=False, cwd=Path.cwd(),
                env=_lean_environment(),
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
            return LeanKernelCheck(
                status="FORMALLY_VERIFIED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
                lean_version=version, proof_source_sha256=proof_hash,
                explanation="Lean accepted the generated closed Nat equality proof using by decide; the configured Lean kernel checked the theorem.",
            )
        return LeanKernelCheck(
            status="REJECTED", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            lean_version=version, proof_source_sha256=proof_hash,
            explanation="Lean rejected the generated equality theorem; the candidate equality is not established.",
        )
    except subprocess.TimeoutExpired:
        return LeanKernelCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash,
            explanation="Lean exceeded the configured wall-clock limit; no formal verification result is available.",
        )
    except OSError:
        return LeanKernelCheck(
            status="KERNEL_ERROR", lhs_sha256=lhs_hash, rhs_sha256=rhs_hash,
            proof_source_sha256=proof_hash,
            explanation="Lean could not be executed; no formal verification result is available.",
        )
