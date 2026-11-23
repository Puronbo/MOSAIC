import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from mosaic.verification import lean_kernel


def test_restricted_renderer_builds_only_nat_arithmetic():
    assert lean_kernel._render_expression("(2 + 3) * 4") == "((2 + 3) * 4)"
    assert lean_kernel._render_expression("2**3") == "(2 ^ 3)"


@pytest.mark.parametrize("expression", [
    "x", "-1", "True", "1 / 2", "f(2)", "__import__('os')",
    "2**13", "1000001",
])
def test_restricted_renderer_rejects_unsupported_input(expression):
    with pytest.raises(ValueError):
        lean_kernel._render_expression(expression)


def test_missing_lean_is_explicitly_unavailable(monkeypatch):
    monkeypatch.setattr(lean_kernel.shutil, "which", lambda _: None)
    result = lean_kernel.verify_closed_nat_equality("2 + 3", "5")
    assert result.status == "KERNEL_UNAVAILABLE"
    assert result.lhs_sha256 == hashlib.sha256(b"2 + 3").hexdigest()


def test_lean_kernel_success_uses_only_generated_closed_theorem(monkeypatch):
    monkeypatch.setattr(lean_kernel.shutil, "which", lambda _: "/opt/lean/bin/lean")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="Lean version test", stderr="")
        source = Path(args[1]).read_text(encoding="utf-8")
        assert source == "theorem mosaic_certificate : ((2 + 3) : Nat) = (5 : Nat) := by decide\n"
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(lean_kernel.subprocess, "run", fake_run)
    result = lean_kernel.verify_closed_nat_equality("(2 + 3)", "5")
    assert result.status == "FORMALLY_VERIFIED"
    assert result.lean_version == "Lean version test"
    assert len(calls) == 2


def test_lean_rejection_is_not_reported_as_formal_verification(monkeypatch):
    monkeypatch.setattr(lean_kernel.shutil, "which", lambda _: "/opt/lean/bin/lean")
    monkeypatch.setattr(
        lean_kernel.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="type mismatch"),
    )
    result = lean_kernel.verify_closed_nat_equality("2 + 3", "6")
    assert result.status == "REJECTED"


def test_no_user_supplied_lean_source_or_imports_can_enter_the_generated_file(monkeypatch):
    monkeypatch.setattr(lean_kernel.shutil, "which", lambda _: "/opt/lean/bin/lean")
    captured = {}

    def fake_run(args, **kwargs):
        if args[-1] != "--version":
            captured["source"] = Path(args[1]).read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(lean_kernel.subprocess, "run", fake_run)
    lean_kernel.verify_closed_nat_equality("7 * 8", "56")
    assert "import " not in captured["source"]
    assert "macro" not in captured["source"]
    assert captured["source"] == "theorem mosaic_certificate : ((7 * 8) : Nat) = (56 : Nat) := by decide\n"
    assert "sorry" not in captured["source"]
