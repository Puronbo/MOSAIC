# Decomposition rule registry

`mosaic.verification.decomposition` provides an explicit, static allow-list
for mathematical decomposition rules. It is the dispatch boundary between
rule discovery and rule execution.

## Registered interface

Each immutable `DecompositionRule` declares:

- a stable versioned `rule_id`;
- the operation it applies to;
- a human-readable description;
- a structural matcher;
- a deterministic decomposition function;
- a paired plan verifier.

The registry currently contains one rule:

`calculus.chain_rule.integer_power.v1`

It handles differentiation of a top-level integer power with a nontrivial
inner expression. The implementation and its scope are documented in
[Chain-rule decomposition](CHAIN_RULE_DECOMPOSITION.md).

## Dispatch

- `registered_decomposition_rules()` lists the built-in allow-list.
- `applicable_decomposition_rules(request)` discovers structural matches.
- `decompose_request(request)` dispatches when exactly one rule matches.
- `decompose_request(request, rule_id)` selects a specific registered rule.
- `verify_decomposition_plan(request, rule_id, plan)` invokes that rule's
  paired verifier, which recomputes the plan from the original request.

Rule IDs are resolved only from code-defined registry entries. A model cannot
register executable code or supply a callable. Unknown IDs and nonmatching
requests are rejected.

## Design constraints

The registry is deliberately not a plugin loader or proof system. Adding a
rule requires a code change, tests for its matcher and side conditions, and an
independent verifier. Rule discovery is structural and does not establish
mathematical validity. Successful execution remains subject to the existing
obligation checkers and their conservative `EXPERIMENTAL` status.
