"""Explicit rule preconditions whose mathematical checkers are not yet available.

These records expose assumptions that must not be silently accepted. They are
contracts only; an UNSUPPORTED condition is not evidence that it holds.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.obligations import request_fingerprint


class RuleSideCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    condition_id: str = Field(min_length=1, max_length=160)
    rule_id: str = Field(min_length=1, max_length=120)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predicate: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=2000)
    checker_id: str = "none"
    status: Literal["UNSUPPORTED"] = "UNSUPPORTED"


def make_unsupported_side_conditions(
    request: MathRequest,
    rule_id: str,
    conditions: tuple[tuple[str, str], ...],
) -> tuple[RuleSideCondition, ...]:
    """Create deterministic, request-bound unresolved precondition contracts."""
    fingerprint = request_fingerprint(request)
    output = []
    for predicate, statement in conditions:
        slug = re.sub(r"[^a-z0-9]+", "-", predicate.lower()).strip("-")
        digest_input = json.dumps(
            [fingerprint, rule_id, predicate, statement],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        output.append(RuleSideCondition(
            condition_id=f"side:{rule_id}:{slug}:{digest}",
            rule_id=rule_id,
            request_sha256=fingerprint,
            predicate=predicate,
            statement=statement,
        ))
    return tuple(output)


def verify_side_condition_contract(
    request: MathRequest,
    rule_id: str,
    supplied: RuleSideCondition,
    expected: tuple[RuleSideCondition, ...],
) -> bool:
    """Check contract integrity; this deliberately does not discharge it."""
    return (
        supplied.request_sha256 == request_fingerprint(request)
        and supplied.rule_id == rule_id
        and supplied in expected
        and supplied.status == "UNSUPPORTED"
        and supplied.checker_id == "none"
    )
