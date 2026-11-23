# Structured candidate checking

MOSAIC accepts untrusted model text only through a narrow structured-claim
boundary before symbolic checking.

## First supported claim

The initial schema supports one claim type:

```json
{
  "claim_type": "identity",
  "lhs": "(x+1)**2",
  "rhs": "x**2+2*x+1"
}
```

Use `mosaic.verification.candidate.check_identity_candidate(raw_text)` to
validate the JSON schema, reject extra fields, enforce input bounds, parse both
expressions with MOSAIC's allow-listed expression grammar, and invoke the
existing symbolic identity checker.

## Result interpretation

- `EXPERIMENTAL`: SymPy reduced the exact difference to zero. This is a
  candidate result, not a formal proof.
- `INCOMPLETE`: the symbolic checker found a nonzero difference or could not
  decide the identity.
- `INVALID_CERTIFICATE`: the model output was malformed, used an unsupported
  claim shape, or contained expressions outside the restricted grammar.

The input and canonical claim are SHA-256 fingerprinted for provenance. Hashes
do not establish truth. This first checker does not establish that a claim is
the correct answer to an upstream task; it checks only the identity stated by
the candidate. A later task-bound verifier must compare claims against explicit
problem obligations and retain the exact checker configuration.
