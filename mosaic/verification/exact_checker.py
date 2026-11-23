"""Experimental symbolic identity checker.

A zero result from the symbolic engine is useful evidence, but this prototype
has no independent proof kernel. It therefore does not claim a formal proof.
"""
import sympy as sp
from mosaic.engines.algebra import parse_expression

def verify_identity(lhs: str, rhs: str) -> dict:
    left, right = parse_expression(lhs), parse_expression(rhs)
    reduced = sp.simplify(sp.together(left - right))
    if reduced == 0:
        return {"status": "EXPERIMENTAL", "equal": True,
                "certificate": {"kind": "symbolic-zero-candidate", "difference": "0"},
                "explanation": "The symbolic engine reduces the exact difference to zero. This candidate has not been independently proof-checked."}
    if reduced.is_zero is False:
        return {"status": "INCOMPLETE", "equal": False, "certificate": None,
                "explanation": "The difference is not identically zero; this does not establish a universal inequality."}
    return {"status": "INCOMPLETE", "equal": None, "certificate": None,
            "explanation": "The symbolic engine could not decide the identity."}
