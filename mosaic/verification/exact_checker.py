"""Exact identity checker; only positive exact zero establishes identity."""
import sympy as sp
from mosaic.engines.algebra import parse_expression

def verify_identity(lhs: str, rhs: str) -> dict:
    left, right = parse_expression(lhs), parse_expression(rhs)
    reduced = sp.simplify(sp.together(left - right))
    if reduced == 0:
        return {"status": "PROVED", "equal": True,
                "certificate": {"kind": "exact-symbolic-zero", "difference": "0"},
                "explanation": "The exact symbolic difference simplifies to zero."}
    if reduced.is_zero is False:
        return {"status": "INCOMPLETE", "equal": False, "certificate": None,
                "explanation": "The difference is not identically zero; this does not establish a universal inequality."}
    return {"status": "INCOMPLETE", "equal": None, "certificate": None,
            "explanation": "The symbolic engine could not decide the identity."}
