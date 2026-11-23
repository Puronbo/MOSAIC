"""Exact symbolic algebra operations over a restricted expression grammar."""
import ast
import sympy as sp

_ALLOWED_NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Name,
                  ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
                  ast.USub, ast.UAdd, ast.Call, ast.Load)
_ALLOWED_FUNCTIONS = {"sqrt": sp.sqrt, "sin": sp.sin, "cos": sp.cos,
                      "tan": sp.tan, "exp": sp.exp, "log": sp.log, "Abs": sp.Abs}
_MAX_NODES = 200
_MAX_POWER = 100

class ExpressionError(ValueError):
    """Raised when input is outside MOSAIC's accepted expression grammar."""

def parse_expression(source: str) -> sp.Expr:
    if not isinstance(source, str) or not source or len(source) > 2000:
        raise ExpressionError("Expression must contain 1–2000 characters.")
    # Accept conventional mathematical exponent notation as well as Python's
    # ** operator. XOR is not part of MOSAIC's expression language.
    normalized_source = source.replace("^", "**")
    try:
        tree = ast.parse(normalized_source, mode="eval")
    except SyntaxError as exc:
        raise ExpressionError("Invalid expression syntax.") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_NODES:
        raise ExpressionError("Expression is too complex.")
    for node in nodes:
        if not isinstance(node, _ALLOWED_NODES):
            raise ExpressionError(f"Unsupported syntax: {type(node).__name__}.")
        if isinstance(node, ast.Constant) and (isinstance(node.value, bool) or not isinstance(node.value, (int, float))):
            raise ExpressionError("Only numeric constants are allowed.")
        if isinstance(node, ast.Name) and node.id not in {"x", "y", "z", "pi", "E"}:
            raise ExpressionError(f"Unknown symbol: {node.id}.")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCTIONS or node.keywords:
                raise ExpressionError("Function is not allowed.")
    symbols = {name: sp.Symbol(name) for name in ("x", "y", "z")}
    symbols.update({"pi": sp.pi, "E": sp.E})
    return _convert(tree.body, symbols)

def _convert(node: ast.AST, symbols: dict) -> sp.Expr:
    if isinstance(node, ast.Constant):
        return sp.Integer(node.value) if isinstance(node.value, int) else sp.Rational(str(node.value))
    if isinstance(node, ast.Name):
        return symbols[node.id]
    if isinstance(node, ast.UnaryOp):
        value = _convert(node.operand, symbols)
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.BinOp):
        left, right = _convert(node.left, symbols), _convert(node.right, symbols)
        if isinstance(node.op, ast.Add): return left + right
        if isinstance(node.op, ast.Sub): return left - right
        if isinstance(node.op, ast.Mult): return left * right
        if isinstance(node.op, ast.Div): return left / right
        if isinstance(node.op, ast.Mod): return sp.Mod(left, right)
        if isinstance(node.op, ast.Pow):
            if right.is_Integer and abs(int(right)) > _MAX_POWER:
                raise ExpressionError("Exponent exceeds the configured limit.")
            if right.is_number and not right.is_Integer:
                raise ExpressionError("Non-integer numeric exponents are not supported.")
            return left ** right
    if isinstance(node, ast.Call):
        return _ALLOWED_FUNCTIONS[node.func.id](*[_convert(arg, symbols) for arg in node.args])
    raise ExpressionError("Unsupported expression node.")

def run_algebra(operation: str, expression: str, variable: str = "x") -> sp.Expr:
    value = parse_expression(expression)
    symbol = sp.Symbol(variable)
    if operation == "simplify": return sp.simplify(value)
    if operation == "expand": return sp.expand(value)
    if operation == "factor": return sp.factor(value)
    if operation == "differentiate": return sp.diff(value, symbol)
    if operation == "integrate": return sp.integrate(value, symbol)
    raise ExpressionError(f"Unsupported algebra operation: {operation}.")
