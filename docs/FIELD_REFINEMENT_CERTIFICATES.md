# Field Refinement Assessment Certificates

MOSAIC can turn a completed `FieldRefinementResult` into a portable,
self-contained `FieldRefinementCertificate`. The record embeds every
refinement trajectory and records the acceptance tolerances, measured
quantities, decision, reasons, schema version, and SHA-256 digest.

## Acceptance criteria

The certificate evaluates three caller-declared limits:

- Maximum absolute field difference between the two finest runs.
- Maximum absolute velocity difference between the two finest runs.
- Maximum absolute relative total-energy drift across every refinement level.

A quantity is accepted when it is less than or equal to its tolerance.
Any exceeded tolerance makes the decision `REJECTED`. If a required
quantity is unavailable (for example, relative energy drift when an initial
energy is zero), the result is `INCONCLUSIVE` unless another criterion
already rejects it. All three criteria must be available and satisfied for
`ACCEPTED`.

The tolerances are caller policy, not universal physical or mathematical
constants. Field and velocity tolerances refer to their corresponding
declared units; the library does not perform dimensional analysis.

## Verification and trust boundary

`verify_field_refinement_certificate` independently recomputes the
reported endpoint differences, energy-drift summary, and decision from the
embedded refinement report. It also checks identity consistency and the
canonical SHA-256 digest. The digest uses sorted JSON keys and compact
separators over the complete certificate payload, excluding only the digest
field itself.

The digest detects accidental or deliberate payload changes when the
expected digest is trusted. It does not authenticate who created the record,
and it does not prove the numerical model is physically correct, that the
integrator converges, or that the chosen tolerances are appropriate.
An attacker able to replace both payload and digest can create a new
self-consistent record. For authenticated provenance, sign the digest using
an external trusted key-management system.

These are numerical assessment records, not Lean proofs or formal
mathematical certificates. A passing decision means only that the embedded
data satisfies the explicitly declared numerical criteria.
