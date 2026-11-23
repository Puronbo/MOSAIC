# Deterministic chain-rule decomposition

MOSAIC currently supports a deliberately narrow, deterministic decomposition
for differentiation requests whose expression is a top-level power of a
nontrivial inner expression, such as `(x**2+1)**3`.

`decompose_power_chain_rule(request)` creates a request-bound
`ChainRulePlan` with:

1. the inner expression and outer integer exponent;
2. the derivative of the outer power using a placeholder variable;
3. the derivative of the inner expression;
4. the composed derivative obtained by substitution and multiplication;
5. the derivative independently recomputed from the original expression;
6. fingerprints and IDs for the three obligations.

`verify_chain_rule_plan` recomputes the complete plan and compares every
field. A caller cannot alter the inner expression, exponent, derivative
formula, or subgoal IDs and retain a valid plan.

`execute_power_chain_rule` creates a DAG with separate outer-derivative and
inner-derivative obligations. The final identity obligation depends on both.
It evaluates the graph using the existing restricted checker contracts.

## Scope and trust

This is a deterministic rule implementation, not open-ended AI decomposition.
It supports only a top-level integer power with a nontrivial inner expression.
Other expression shapes are rejected explicitly.

All three successful obligations still yield only `EXPERIMENTAL`. The
implementation does not establish formal proof, domain-sensitive equivalence,
or completeness of a general symbolic differentiation system. The narrow
shape and bounded expression parser are intentional; more rules should be
added as separately testable decomposers with explicit side conditions.
