import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from mosaic.verification import lean_polynomial


def test_polynomial_parser_bounds_and_variables():
    tree, variables = lean_polynomial._parse_polynomial("(x + 1)^2 - y*x")
    assert variables == ("x", "y")
    assert lean_polynomial._polynomial(tree) == {
        (("x", 2),): 1,
        (("x", 1),): 2,
        (): 1,
        (("x", 1), ("y", 1)): -1,
    }


@pytest.mark.parametrize("expression", [
    "x / 2", "x // 2", "x % 2", "x**-1", "x**9",
    "f(x)", "w + 1", "True", "__import__('os')",
    "x*y*z*w", "x**8 * x**8",
])
def test_polynomial_parser_rejects_unsupported_or_excessive_syntax(expression):
    with pytest.raises(ValueError):
        lean_polynomial._parse_polynomial(expression)


def test_generated_source_uses_only_internal_mathlib_ring_theorem():
    source, variables = lean_polynomial._generated_source(
        "(x + 1)^2", "x^2 + 2*x + 1"
    )
    assert variables == ("x",)
    assert source.splitlines() == [
        "import Mathlib.Tactic.Ring",
        "theorem mosaic_polynomial_certificate (x : Int) : "
        "((x + (1 : Int)) ^ 2) = "
        "(((x ^ 2) + ((2 : Int) * x)) + (1 : Int)) := by ring",
    ]


def test_real_checker_returns_source_fingerprint_when_lake_unavailable(monkeypatch):
    monkeypatch.setattr(lean_polynomial.shutil, "which", lambda _: None)
    result = lean_polynomial.verify_polynomial_int_identity(
        "(x + 1)^2", "x^2 + 2*x + 1"
    )
    source, variables = lean_polynomial._generated_source(
        "(x + 1)^2", "x^2 + 2*x + 1"
    )
    assert result.status == "KERNEL_UNAVAILABLE"
    assert result.variables == variables
    assert result.proof_source_sha256 == hashlib.sha256(source.encode()).hexdigest()


def test_checker_executes_pinned_lake_project(monkeypatch):
    monkeypatch.setattr(lean_polynomial.shutil, "which", lambda _: "/usr/bin/lake")
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="Lean version pinned", stderr="")
        source = Path(args[-1]).read_text(encoding="utf-8")
        assert source.startswith("import Mathlib.Tactic.Ring\n")
        assert "by ring\n" in source
        assert kwargs["cwd"] == lean_polynomial._PROJECT_DIR
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(lean_polynomial.subprocess, "run", fake_run)
    result = lean_polynomial.verify_polynomial_int_identity(
        "(x + y)*(x - y)", "x^2 - y^2"
    )
    assert result.status == "FORMALLY_VERIFIED"
    assert result.variables == ("x", "y")
    assert result.lean_version == "Lean version pinned"
    assert len(calls) == 2


def test_nonidentity_is_reported_as_rejected(monkeypatch):
    monkeypatch.setattr(lean_polynomial.shutil, "which", lambda _: "/usr/bin/lake")
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(
        lean_polynomial.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="unsolved goals"),
    )
    result = lean_polynomial.verify_polynomial_int_identity("x^2 + 1", "x^2 + 2")
    assert result.status == "REJECTED"


def test_timeout_returns_error_not_verification(monkeypatch):
    monkeypatch.setattr(lean_polynomial.shutil, "which", lambda _: "/usr/bin/lake")
    monkeypatch.setattr(Path, "is_file", lambda self: True)

    def timeout(*args, **kwargs):
        raise lean_polynomial.subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(lean_polynomial.subprocess, "run", timeout)
    result = lean_polynomial.verify_polynomial_int_identity("x^2", "x*x")
    assert result.status == "KERNEL_ERROR"
