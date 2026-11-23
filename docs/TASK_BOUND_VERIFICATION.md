# Task-bound candidate verification

`mosaic.verification.task_bound.verify_task_bound_candidate(request, raw)`
adds a binding between a structured candidate and the original `MathRequest`.
The candidate cannot choose a different operation or quietly substitute an
easier expression.

## Supported scope

- `verify_identity`: both sides must exactly match the request's expression
  and RHS before the existing restricted symbolic identity check is run.
- `simplify`, `expand`, `factor`, `differentiate`: the operation,
  expression, and variable must match the request. MOSAIC recomputes the
  expected result and compares the candidate result to it with the existing
  symbolic checker.
- Other operations, including `integrate`, return `UNSUPPORTED`. Integration
  needs explicit treatment of constants, domains, and branch conventions.

## Claim examples

Identity:

```json
{"operation":"verify_identity","expression":"(x+1)**2","rhs":"x**2+2*x+1"}
```

Transformation:

```json
{"operation":"expand","expression":"(x+1)**2","variable":"x","result":"x**2+2*x+1"}
```

## Trust limits

A matching request and a symbolic-zero result produce `EXPERIMENTAL`, not
`PROVED` or `FORMALLY_VERIFIED`. This is a binding and consistency check,
not a proof kernel. Request and candidate hashes provide provenance/integrity
only. The request object must itself come from the trusted caller; this helper
does not authenticate its origin or prove that the original task was well
specified.


## Domain-preserving algebraic rewrites

For simplify, expand, and factor claims, task-bound verification also compares the original and candidate rational-expression domains. The restricted checker extracts polynomial nonzero exclusions from division denominators and negative integer powers, then compares their irreducible factors.

- PRESERVED: the candidate retains the same exclusions; the ordinary algebraic result may remain EXPERIMENTAL.
- EXPANDED: an original exclusion is missing, so the candidate is not accepted as a domain-preserving rewrite.
- RESTRICTED or CHANGED: the candidate introduces or changes exclusions and is not accepted.
- UNSUPPORTED: the domain grammar is outside the checker, so the transformation is not accepted as verified.

A rejected domain change returns INCOMPLETE; an unsupported domain comparison returns UNSUPPORTED. Differentiation is deliberately not subjected to equality of input/output domains: its domain semantics require a separate derivative-specific contract. These checks compare rational-function exclusions only; they do not solve the excluded sets or establish a formal proof.
