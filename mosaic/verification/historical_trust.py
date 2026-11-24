"""Versioned issuance timestamps and historical Ed25519 key lifecycle rules.

A signed issuance time is only a signer claim. Historical acceptance requires
an independently verified timestamp (for example a Sigstore transparency-log
timestamp from successful `gh attestation verify`) proving the signed receipt
existed no later than the key's retirement/revocation boundary.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Literal

from pydantic import ConfigDict, Field

from mosaic.verification.lean_runner_signature import (
    LeanTrustedKey,
    SignedLeanAttestation,
    _canonical,
)


def _utc(value: str | datetime, *, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    else:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _format_utc(value: str | datetime, *, field: str) -> str:
    parsed = _utc(value, field=field)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


class HistoricalSignedLeanAttestation(SignedLeanAttestation):
    """v2 receipt whose issuance timestamp is included in the signed payload."""

    schema_version: Literal["2.0"] = "2.0"
    issued_at_utc: str = Field(min_length=20, max_length=40)
    trust_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sign_v2(
        cls,
        *,
        issued_at_utc: str | datetime,
        trust_policy_sha256: str,
        private_key: bytes,
        **attestation_fields,
    ) -> "HistoricalSignedLeanAttestation":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        issued = _format_utc(issued_at_utc, field="issued_at_utc")
        base = SignedLeanAttestation.sign(private_key=private_key, **attestation_fields)
        payload = base.model_dump(mode="json", exclude={"signature_b64"})
        payload["schema_version"] = "2.0"
        payload["issued_at_utc"] = issued
        payload["trust_policy_sha256"] = trust_policy_sha256
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, public_key: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            issued = _format_utc(self.issued_at_utc, field="issued_at_utc")
            if issued != self.issued_at_utc:
                return False
            signature = base64.b64decode(self.signature_b64, validate=True)
            if len(signature) != 64 or len(public_key) != 32:
                return False
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, _canonical(self.model_dump(mode="json", exclude={"signature_b64"}))
            )
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


class HistoricalLeanTrustedKey(LeanTrustedKey):
    """Key registry entry with UTC lifecycle boundaries."""

    activated_at_utc: str
    retired_at_utc: str | None = None
    revoked_at_utc: str | None = None
    compromise_effective_at_utc: str | None = None


def verify_historical_with_keyring(
    attestation: HistoricalSignedLeanAttestation,
    keyring: dict[str, HistoricalLeanTrustedKey],
    *,
    verified_timestamp_utc: str | datetime,
    timestamp_evidence_verified: bool,
    trusted_policies: dict[str, object],
) -> bool:
    """Verify v2 receipt against lifecycle and independent timestamp evidence.

    The caller must set timestamp_evidence_verified only after validating the
    enclosing artifact attestation cryptographically and checking its subject
    digest, signer identity, and verified transparency timestamp.
    """
    if timestamp_evidence_verified is not True:
        return False
    from mosaic.verification.trust_policy import (
        HistoricalTrustPolicyRecord, policy_timestamp_is_current, verify_policy_record,
    )
    policy_record = trusted_policies.get(attestation.trust_policy_sha256)
    if not isinstance(policy_record, HistoricalTrustPolicyRecord):
        return False
    if (
        not verify_policy_record(policy_record)
        or policy_record.policy_sha256 != attestation.trust_policy_sha256
        or not policy_timestamp_is_current(policy_record, _format_utc(verified_timestamp_utc, field="verified_timestamp_utc"))
        or not policy_record.policy.require_external_timestamp
    ):
        return False
    record = keyring.get(attestation.key_id)
    if record is None or record.key_id != attestation.key_id:
        return False
    try:
        public_key = base64.b64decode(record.public_key_b64, validate=True)
        issued = _utc(attestation.issued_at_utc, field="issued_at_utc")
        witnessed = _utc(verified_timestamp_utc, field="verified_timestamp_utc")
        activated = _utc(record.activated_at_utc, field="activated_at_utc")
        if (
            not attestation.verify(public_key)
            or issued < activated or witnessed < issued
            or attestation.kernel_id not in policy_record.policy.allowed_kernel_ids
            or attestation.checker_id not in policy_record.policy.allowed_checker_ids
            or (witnessed - issued).total_seconds() > policy_record.policy.max_timestamp_lag_seconds
        ):
            return False
        retired = _utc(record.retired_at_utc, field="retired_at_utc") if record.retired_at_utc else None
        revoked = _utc(record.revoked_at_utc, field="revoked_at_utc") if record.revoked_at_utc else None
        compromised = (
            _utc(record.compromise_effective_at_utc, field="compromise_effective_at_utc")
            if record.compromise_effective_at_utc else None
        )
        if record.status == "active":
            return retired is None and revoked is None and compromised is None
        if record.status == "retired":
            if not policy_record.policy.allow_retired_key_history:
                return False
            return (
                retired is not None and issued < retired and witnessed <= retired
                and revoked is None and compromised is None
            )
        if record.status == "revoked":
            if not policy_record.policy.allow_revoked_key_history:
                return False
            if revoked is None or witnessed > revoked:
                return False
            if compromised is not None and issued >= compromised:
                return False
            return issued < revoked
        return False
    except (ValueError, TypeError):
        return False
