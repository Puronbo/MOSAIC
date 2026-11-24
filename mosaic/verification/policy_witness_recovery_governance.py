"""Independent approvals for signed policy-witness recovery proposals."""
from __future__ import annotations

import base64
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_witness_recovery import SignedPolicyWitnessRecoveryAuthorization


class PolicyWitnessRecoveryPolicy(BaseModel):
    """Deployment policy for distinct operator approvals."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    minimum_approvals: int = Field(default=2, ge=1, le=20)
    required_operator_key_ids: tuple[str, ...] = ()
    prohibited_operator_key_ids: tuple[str, ...] = ()

    def valid(self) -> bool:
        return (
            len(set(self.required_operator_key_ids)) == len(self.required_operator_key_ids)
            and len(set(self.prohibited_operator_key_ids)) == len(self.prohibited_operator_key_ids)
            and not set(self.required_operator_key_ids).intersection(self.prohibited_operator_key_ids)
            and len(self.required_operator_key_ids) <= self.minimum_approvals
            and all(self.required_operator_key_ids)
            and all(self.prohibited_operator_key_ids)
        )


class SignedPolicyWitnessRecoveryApproval(BaseModel):
    """One additional operator's signature over an exact recovery proposal."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    authorization_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_key_id: str = Field(min_length=1, max_length=160)
    approved_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls, *, authorization: SignedPolicyWitnessRecoveryAuthorization,
        operator_key_id: str, approved_at_utc: str, private_key: bytes,
    ) -> "SignedPolicyWitnessRecoveryApproval":
        from mosaic.verification.policy_registry import _canonical_timestamp
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "1.0",
            "authorization_sha256": authorization.digest(),
            "operator_key_id": operator_key_id,
            "approved_at_utc": _canonical_timestamp(approved_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(
        self, authorization: SignedPolicyWitnessRecoveryAuthorization,
        keyring: dict[str, PolicyPublisherKey],
    ) -> bool:
        from mosaic.verification.policy_registry import _canonical_timestamp
        record = keyring.get(self.operator_key_id) if isinstance(keyring, dict) else None
        if (record is None or self.authorization_sha256 != authorization.digest()
                or not record.permits(self.operator_key_id, self.approved_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.approved_at_utc) != self.approved_at_utc:
                return False
            public = record.public_key()
            signature = base64.b64decode(self.signature_b64, validate=True)
            if public is None or len(signature) != 64:
                return False
            payload = self.model_dump(mode="json", exclude={"signature_b64"})
            Ed25519PublicKey.from_public_bytes(public).verify(signature, _canonical(payload))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


def verify_policy_witness_recovery_approvals(
    authorization: SignedPolicyWitnessRecoveryAuthorization, *,
    policy: PolicyWitnessRecoveryPolicy,
    approvals: list[SignedPolicyWitnessRecoveryApproval],
    operator_keyring: dict[str, PolicyPublisherKey],
    witness_keyring: dict[str, PolicyPublisherKey],
    signer_keyring: dict[str, PolicyPublisherKey],
) -> bool:
    """Count only lifecycle-valid, distinct public keys approving one proposal."""
    if (not isinstance(policy, PolicyWitnessRecoveryPolicy) or not policy.valid()
            or not authorization.verify(operator_keyring)
            or not isinstance(approvals, list)
            or len(approvals) + 1 < policy.minimum_approvals):
        return False
    proposal = operator_keyring.get(authorization.operator_key_id)
    if proposal is None:
        return False
    proposal_public = proposal.public_key()
    forbidden = {
        item.public_key() for ring in (witness_keyring, signer_keyring)
        for item in ring.values() if isinstance(item, PolicyPublisherKey)
    }
    if proposal_public is None or proposal_public in forbidden:
        return False
    identities = {authorization.operator_key_id}
    public_keys = {proposal_public}
    for approval in approvals:
        if not isinstance(approval, SignedPolicyWitnessRecoveryApproval):
            return False
        record = operator_keyring.get(approval.operator_key_id)
        if (record is None or approval.operator_key_id in identities
                or not approval.verify(authorization, operator_keyring)):
            return False
        public = record.public_key()
        if public is None or public in public_keys or public in forbidden:
            return False
        identities.add(approval.operator_key_id)
        public_keys.add(public)
    if not set(policy.required_operator_key_ids).issubset(identities):
        return False
    if set(policy.prohibited_operator_key_ids).intersection(identities):
        return False
    return len(identities) >= policy.minimum_approvals
