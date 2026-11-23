from mosaic.verification.polynomial_checker import rational_polynomial_equivalent


def test_exact_fraction_checker_proves_polynomial_equivalence_without_sympy():
    assert rational_polynomial_equivalent("(x + 1)**2", "x**2 + 2*x + 1") is True


def test_exact_fraction_checker_compares_rational_functions():
    assert rational_polynomial_equivalent(
        "(x**2 - 1)/(x - 1)", "(x + 1)*(x - 1)/(x - 1)"
    ) is True


def test_exact_fraction_checker_detects_non_equivalent_expression():
    assert rational_polynomial_equivalent("(x + 1)**2", "x + 1") is False


def test_exact_fraction_checker_reports_unsupported_syntax_without_execution():
    assert rational_polynomial_equivalent("__import__('os').system('id')", "x") is None
    assert rational_polynomial_equivalent("sin(x)", "x") is None


def test_exact_fraction_checker_enforces_degree_bound():
    assert rational_polynomial_equivalent("(x**12)**12", "x**144") is None
