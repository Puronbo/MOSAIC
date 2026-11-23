"""Parse and check structured mathematical claims from untrusted model output.

This layer validates claim shape before delegating to the experimental symbolic
checker. It does not turn symbolic computation into a formal proof.
"""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mosaic.engines.algebra import ExpressionError
from mosaic.verification.exact_checker import verify_identity


class IdentityClaim(BaseModel):
    """A narrowly scoped candidate identity: two restricted expressions."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_type: Literal["identity"]
    lhs: str = Field(min_length=1, max_length=2000)
    rhs: str = Field(min_length=1, max_length=2000)


class CandidateCheck(BaseModel):
    """Auditable result for one parsed candidate claim."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_type: str | None
    status: Literal["EXPERIMENTAL", "INCOMPLETE", "INVALID_CERTIFICATE"]
    equal: bool | None = None
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    certificate: dict | None = None
    explanation: str


def check_identity_candidate(raw: str) -> CandidateCheck:
    """Validate JSON claim data and check an identity with the restricted parser.

    Invalid JSON, unexpected fields, unsupported claim types, and expressions
    outside MOSAIC's grammar are rejected without attempting symbolic checking.
    """
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 10000:
        raise ValueError("candidate must be non-empty text no longer than 10000 characters")

    input_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    try:
        decoded = json.loads(raw)
        claim = IdentityClaim.model_validate(decoded)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        return CandidateCheck(
            claim_type=None,
            status="INVALID_CERTIFICATE",
            input_sha256=input_hash,
            explanation="Candidate is not a valid identity-claim JSON object.",
        )

    canonical = json.dumps(
        claim.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    claim_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    try:
        result = verify_identity(claim.lhs, claim.rhs)
    except ExpressionError:
        return CandidateCheck(
            claim_type=claim.claim_type,
            status="INVALID_CERTIFICATE",
            input_sha256=input_hash,
            claim_sha256=claim_hash,
            explanation="One or both expressions are outside MOSAIC's restricted algebra grammar.",
        )

    status = result["status"]
    return CandidateCheck(
        claim_type=claim.claim_type,
        status=status,
        equal=result["equal"],
        input_sha256=input_hash,
        claim_sha256=claim_hash,
        certificate=result["certificate"],
        explanation=result["explanation"],
    )
