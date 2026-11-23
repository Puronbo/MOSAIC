import pytest
from mosaic.engines.algebra import ExpressionError, parse_expression, run_algebra

def test_expand_polynomial():
    assert str(run_algebra("expand", "(x+1)**2")) == "x**2 + 2*x + 1"

def test_differentiate():
    assert str(run_algebra("differentiate", "x**3", "x")) == "3*x**2"

def test_rejects_attribute_access():
    with pytest.raises(ExpressionError):
        parse_expression("x.__class__")

def test_rejects_unknown_function():
    with pytest.raises(ExpressionError):
        parse_expression("__import__('os')")


def test_caret_is_mathematical_exponent_not_xor():
    assert str(parse_expression("(x + 1)^2")) == "(x + 1)**2"
    assert str(parse_expression("-x^2")) == "-x**2"
    assert str(run_algebra("expand", "(x + 1)^2")) == "x**2 + 2*x + 1"
