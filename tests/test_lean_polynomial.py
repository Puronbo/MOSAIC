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
    assert source == (
        "import Mathlib.Tactic.Ring\\n"
        "theorem mosaic_polynomial_certificate (x : Int) : "
        "((x + (1 : Int)) ^ 2) = "
        "(((x ^ 2) + ((2 : Int) * x)) + (1 : Int)) := by ring\\n"
    )
