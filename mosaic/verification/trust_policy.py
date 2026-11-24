"""Content-addressed trust policies for reproducible historical receipt decisions."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HistoricalTrustPolicy(BaseModel):
    """Immutable policy document; its digest identifies the exact decision rules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["mosaic.historical-trust-policy.v1"] = "mosaic.historical-trust-policy.v1"
    policy_id: str = Field(min_length=1, max_length=120)
    policy_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    allowed_kernel_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    allowed_checker_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    require_external_timestamp: Literal[True] = True
    allow_retired_key_history: bool = True
    allow_revoked_key_history: bool = False
    max_timestamp_lag_seconds: int = Field(default=86400, ge=0, le=2592000)

    @field_validator("allowed_kernel_ids", "allowed_checker_ids")
    @classmethod
    def unique_nonempty_values(cls, values):
        if len(set(values)) != len(values) or any(not value for value in values):
            raise ValueError("policy lists must contain unique nonempty strings")
        return values

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class HistoricalTrustPolicyRecord(BaseModel):
    """Registry lifecycle for one immutable content-addressed policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy: HistoricalTrustPolicy
    activated_at_utc: str
    retired_at_utc: str | None = None


def verify_policy_record(record: HistoricalTrustPolicyRecord) -> bool:
    """Reject substitution: the registry digest must identify exact policy bytes."""
    try:
        if record.policy.digest() != record.policy_sha256:
            return False
        for value in (record.activated_at_utc, record.retired_at_utc):
            if value is not None:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    return False
        return True
    except (ValueError, TypeError):
        return False


def policy_timestamp_is_current(
    record: HistoricalTrustPolicyRecord,
    verified_timestamp_utc: str,
) -> bool:
    """Check policy activation/retirement against independently verified time."""
    if not verify_policy_record(record):
        return False
    try:
        witnessed = datetime.fromisoformat(verified_timestamp_utc.replace("Z", "+00:00"))
        activated = datetime.fromisoformat(record.activated_at_utc.replace("Z", "+00:00"))
        retired = (
            datetime.fromisoformat(record.retired_at_utc.replace("Z", "+00:00"))
            if record.retired_at_utc else None
        )
        if any(value.tzinfo is None or value.utcoffset() is None for value in (witnessed, activated)):
            return False
        if retired is not None and (retired.tzinfo is None or retired.utcoffset() is None):
            return False
        return activated <= witnessed and (retired is None or witnessed < retired)
    except (ValueError, TypeError):
        return False
