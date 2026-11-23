import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from mosaic.verification import lean_linear


def test_affine_renderer_extracts_bounded_integer_forms():
    form, variables = lean_linear._parse_linear("2*x - y + 3")
    assert form == {"x": 2, "y": -1, "": 3}
    assert variables == ("x", "y")
    assert lean_linear._render_expression("2*x - y + 3") == "((((2 : Int) * x) - y) + (3 : Int))"


@pytest.mark.parametrize("expression", [
    "x*y", "x**2", "x/2", "f(x)", "w + 1", "x + 1000001",
    "__import__('os')", "True",
])
def test_affine_parser_rejects_nonlinear_or_unsafe_input(expression):
    with pytest.raises(ValueError):
        lean_linear._parse_linear(expression)


def test_lean_omega_success_generates_universal_int_theorem(monkeypatch):
    monkeypatch.setattr(lean_linear.shutil, "which", lambda _: "/opt/lean/bin/lean")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="Lean version test", stderr="")
        source = Path(args[1]).read_text(encoding="utf-8")
        assert source == (
            "import Lean\n"
            "theorem mosaic_certificate (x : Int) (y : Int) : "
            "(x + y) = (y + x) := by omega\n"
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(lean_linear.subprocess, "run", fake_run)
    result = lean_linear.verify_linear_int_identity("x + y", "y + x")
    assert result.status == "FORMALLY_VERIFIED"
    assert result.variables == ("x", "y")
    assert result.proof_source_sha256 == hashlib.sha256(
        (
            "import Lean\n"
            "theorem mosaic_certificate (x : Int) (y : Int) : "
            "(x + y) = (y + x) := by omega\n"
        ).encode()
    ).hexdigest()
    assert len(calls) == 2


def test_lean_omega_rejection_is_not_formal_verification(monkeypatch):
    monkeypatch.setattr(lean_linear.shutil, "which", lambda _: "/opt/lean/bin/lean")
    monkeypatch.setattr(
        lean_linear.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="unsolved goals"),
    )
    result = lean_linear.verify_linear_int_identity("x + y", "x + z")
    assert result.status == "REJECTED"


def test_cancelled_variables_remain_explicitly_bound():
    form, variables = lean_linear._parse_linear("x - x")
    assert form == {}
    assert variables == ("x",)
    assert lean_linear._render_expression("x - x") == "(x - x)"


def test_constant_intermediate_growth_is_bounded():
    with pytest.raises(ValueError):
        lean_linear._parse_linear("(1000000 * 1000000) * x")


def test_scalar_multiplication_preserves_affine_constant_term():
    form, variables = lean_linear._parse_linear("2*(x + 3)")
    assert form == {"x": 2, "": 6}
    assert variables == ("x",)
