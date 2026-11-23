"""Evidence provenance and conservative aggregation.

Evidence is emitted by registered in-process checks, never accepted as a
model-supplied assertion. Related checks share an independence group so that
multiple findings from one implementation do not become multiple votes.
"""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.task_bound import TaskBoundCheck


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_id: Literal["algebraic_equivalence", "rational_domain_preservation"]
    source_kind: Literal["deterministic_checker"]
    checker_id: str
    independence_group: str
    finding: Literal["supports", "refutes", "unresolved"]
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    explanation: str


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "NO_CHECKER_EVIDENCE", "UNRESOLVED", "SINGLE_SOURCE_SUPPORT",
        "MULTI_SOURCE_SUPPORT", "CONFLICT", "REFUTED_BY_CHECKER",
    ]
    independent_support_groups: tuple[str, ...] = ()
    independent_refutation_groups: tuple[str, ...] = ()
    independent_support_count: int = 0
    claim_conflicts: tuple[str, ...] = ()
    model_opinion_count: int = 0
    explanation: str


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[EvidenceItem, ...] = ()
    assessment: EvidenceAssessment


def _item(
    check: TaskBoundCheck, claim_id: str, checker_id: str,
    finding: str, explanation: str,
) -> EvidenceItem:
    identity = "|".join((
        checker_id, claim_id, check.request_sha256,
        check.candidate_sha256, finding,
    ))
    return EvidenceItem(
        evidence_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        claim_id=claim_id,
        source_kind="deterministic_checker",
        checker_id=checker_id,
        # These current checks share the same SymPy-backed symbolic runtime.
        independence_group="sympy_symbolic_runtime",
        finding=finding,
        request_sha256=check.request_sha256,
        candidate_sha256=check.candidate_sha256,
        explanation=explanation,
    )


def evidence_from_check(check: TaskBoundCheck) -> EvidenceBundle:
    """Translate checker outputs into provenance-labelled evidence findings."""
    items: list[EvidenceItem] = []
    if check.equal is True and check.status == "EXPERIMENTAL":
        algebra_finding = "supports"
    elif check.equal is False:
        algebra_finding = "refutes"
    else:
        algebra_finding = "unresolved"
    items.append(_item(
        check, "algebraic_equivalence", "mosaic.task_bound_candidate.v1",
        algebra_finding, check.explanation,
    ))

    if check.domain_certificate is not None:
        domain = check.domain_certificate
        if domain.status == "PRESERVED":
            domain_finding = "supports"
        elif domain.status in {"EXPANDED", "RESTRICTED", "CHANGED"}:
            domain_finding = "refutes"
        else:
            domain_finding = "unresolved"
        items.append(_item(
            check, "rational_domain_preservation",
            domain.checker_id, domain_finding, domain.explanation,
        ))

    support = sorted({
        item.independence_group for item in items if item.finding == "supports"
    })
    refute = sorted({
        item.independence_group for item in items if item.finding == "refutes"
    })
    unresolved = [item for item in items if item.finding == "unresolved"]
    claim_conflicts = sorted({
        item.claim_id for item in items
        if item.finding == "supports"
        and any(
            other.claim_id == item.claim_id
            and other.finding == "refutes"
            and other.independence_group != item.independence_group
            for other in items
        )
    })
    if not items:
        status = "NO_CHECKER_EVIDENCE"
        explanation = "No registered checker evidence is available."
    elif claim_conflicts:
        status = "CONFLICT"
        explanation = "Independent implementation groups disagree on the same claim: " + ", ".join(claim_conflicts)
    elif refute:
        status = "REFUTED_BY_CHECKER"
        explanation = "At least one registered checker finding refutes a required claim."
    elif unresolved:
        status = "UNRESOLVED"
        explanation = "At least one required claim remains unresolved by the available checkers."
    elif support and len(support) == 1:
        status = "SINGLE_SOURCE_SUPPORT"
        explanation = "Available findings support the checked claims, but all originate from one implementation group."
    elif support:
        status = "MULTI_SOURCE_SUPPORT"
        explanation = "Distinct registered implementation groups support the checked claims; this is still not a formal proof."
    else:
        status = "UNRESOLVED"
        explanation = "Available checker findings do not resolve the required claims."

    assessment = EvidenceAssessment(
        status=status,
        independent_support_groups=tuple(support),
        independent_refutation_groups=tuple(refute),
        independent_support_count=len(support),
        claim_conflicts=tuple(claim_conflicts),
        explanation=explanation,
    )
    return EvidenceBundle(items=tuple(items), assessment=assessment)
