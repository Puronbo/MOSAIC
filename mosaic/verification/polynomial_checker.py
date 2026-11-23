"""Independent exact rational-polynomial equivalence checker.

This deliberately small checker uses Python's AST and Fraction arithmetic;
it does not call SymPy or the main symbolic engine. It is a second experimental
implementation for polynomial/rational equivalence, not a proof kernel.
"""
import ast
from fractions import Fraction
from typing import TypeAlias

Monomial: TypeAlias = tuple[int, int, int]
Polynomial: TypeAlias = dict[Monomial, Fraction]
RationalFunction: TypeAlias = tuple[Polynomial, Polynomial]
_VARIABLES = {"x": 0, "y": 1, "z": 2}
_MAX_NODES = 200
_MAX_EXPONENT = 12


class UnsupportedPolynomialExpression(ValueError):
    """Expression is outside this checker's deliberately small grammar."""


def _clean(poly: Polynomial) -> Polynomial:
    return {monomial: coefficient for monomial, coefficient in poly.items() if coefficient}


def _add(left: Polynomial, right: Polynomial) -> Polynomial:
    result = dict(left)
    for monomial, coefficient in right.items():
        result[monomial] = result.get(monomial, Fraction(0)) + coefficient
    return _clean(result)


def _scale(poly: Polynomial, factor: Fraction) -> Polynomial:
    return _clean({monomial: coefficient * factor for monomial, coefficient in poly.items()})


def _multiply(left: Polynomial, right: Polynomial) -> Polynomial:
    result: Polynomial = {}
    for lm, lc in left.items():
        for rm, rc in right.items():
            monomial = tuple(a + b for a, b in zip(lm, rm))
            result[monomial] = result.get(monomial, Fraction(0)) + lc * rc
    return _clean(result)


def _power(poly: Polynomial, exponent: int) -> Polynomial:
    result: Polynomial = {(0, 0, 0): Fraction(1)}
    factor = poly
    remaining = exponent
    while remaining:
        if remaining & 1:
            result = _multiply(result, factor)
        remaining >>= 1
        if remaining:
            factor = _multiply(factor, factor)
    return result


def _negate(poly: Polynomial) -> Polynomial:
    return _scale(poly, Fraction(-1))


def _add_rational(left: RationalFunction, right: RationalFunction) -> RationalFunction:
    ln, ld = left
    rn, rd = right
    return _clean(_add(_multiply(ln, rd), _multiply(rn, ld))), _multiply(ld, rd)


def _multiply_rational(left: RationalFunction, right: RationalFunction) -> RationalFunction:
    return _multiply(left[0], right[0]), _multiply(left[1], right[1])


def _divide_rational(left: RationalFunction, right: RationalFunction) -> RationalFunction:
    if not right[0]:
        raise UnsupportedPolynomialExpression("division by the zero polynomial")
    return _multiply(left[0], right[1]), _multiply(left[1], right[0])


def _integer_exponent(node: ast.AST) -> int:
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        sign = -1
        node = node.operand
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
        node = node.operand
    if not isinstance(node, ast.Constant) or isinstance(node.value, bool) or not isinstance(node.value, int):
        raise UnsupportedPolynomialExpression("exponent must be an integer literal")
    exponent = sign * node.value
    if abs(exponent) > _MAX_EXPONENT:
        raise UnsupportedPolynomialExpression("exponent exceeds the independent checker bound")
    return exponent


def _parse(node: ast.AST) -> RationalFunction:
    one = {(0, 0, 0): Fraction(1)}
    zero: Polynomial = {}
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise UnsupportedPolynomialExpression("only numeric rational constants are supported")
        return {(0, 0, 0): Fraction(str(node.value))}, one
    if isinstance(node, ast.Name) and node.id in _VARIABLES:
        powers = [0, 0, 0]
        powers[_VARIABLES[node.id]] = 1
        return {tuple(powers): Fraction(1)}, one
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _parse(node.operand)
        return (value if isinstance(node.op, ast.UAdd) else (_negate(value[0]), value[1]))
    if not isinstance(node, ast.BinOp):
        raise UnsupportedPolynomialExpression("unsupported syntax node")
    left = _parse(node.left)
    right = _parse(node.right)
    if isinstance(node.op, ast.Add):
        return _add_rational(left, right)
    if isinstance(node.op, ast.Sub):
        return _add_rational(left, (_negate(right[0]), right[1]))
    if isinstance(node.op, ast.Mult):
        return _multiply_rational(left, right)
    if isinstance(node.op, ast.Div):
        return _divide_rational(left, right)
    if isinstance(node.op, ast.Pow):
        exponent = _integer_exponent(node.right)
        if exponent == 0:
            if not left[0]:
                raise UnsupportedPolynomialExpression("zero to the zero power is unsupported")
            return one, one
        if exponent < 0:
            if not left[0]:
                raise UnsupportedPolynomialExpression("negative power of zero")
            return _power(left[1], -exponent), _power(left[0], -exponent)
        return _power(left[0], exponent), _power(left[1], exponent)
    raise UnsupportedPolynomialExpression("unsupported arithmetic operator")


def rational_polynomial_equivalent(left: str, right: str) -> bool | None:
    """Return exact equivalence, or None when either input is unsupported.

    Rational functions are compared by cross multiplication. This establishes
    algebraic equivalence where both expressions are defined; it does not
    establish equal domains, which is a separate obligation.
    """
    try:
        left_tree = ast.parse(left, mode="eval")
        right_tree = ast.parse(right, mode="eval")
        if sum(1 for _ in ast.walk(left_tree)) + sum(1 for _ in ast.walk(right_tree)) > _MAX_NODES:
            return None
        left_value = _parse(left_tree.body)
        right_value = _parse(right_tree.body)
        return _multiply(left_value[0], right_value[1]) == _multiply(right_value[0], left_value[1])
    except (SyntaxError, ValueError, ZeroDivisionError, OverflowError):
        return None
