"""Independently verify a portable MOSAIC operator-lifecycle recovery envelope.

The trust file is provisioned separately from the envelope. Never derive its
public keys or expected head digests from the artifact being verified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.recovery_operator_lifecycle import (
    OperatorLifecycleRecoveryEvidenceEnvelope,
    verify_operator_lifecycle_recovery_evidence_envelope_report,
)


def _read_json(path: Path) -> Any:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True,
                        help="Portable recovery evidence envelope JSON")
    parser.add_argument("--trust", type=Path, required=True,
                        help="Independently provisioned trust configuration JSON")
    parser.add_argument("--authorization-time-utc",
                        help="Optional canonical UTC policy bound, supplied independently")
    args = parser.parse_args()

    try:
        envelope = OperatorLifecycleRecoveryEvidenceEnvelope.model_validate(
            _read_json(args.envelope))
        trust = _read_json(args.trust)
        required = {
            "expected_registry_id", "expected_initial_key_id",
            "expected_rotation_head_sha256", "expected_rotation_sequence",
            "expected_rotation_sha256", "expected_restore_event_sequence",
            "expected_restore_ledger_entry_sha256",
            "expected_restore_receipt_sha256",
            "expected_restore_ledger_head_sha256", "authority_keyring",
        }
        missing = sorted(required - trust.keys())
        if missing:
            raise ValueError("trust configuration missing: " + ", ".join(missing))
        raw_keyring = trust["authority_keyring"]
        if not isinstance(raw_keyring, dict) or not raw_keyring:
            raise ValueError("authority_keyring must be a non-empty object")
        keyring: dict[str, PolicyPublisherKey] = {}
        for key_id, record in raw_keyring.items():
            key = PolicyPublisherKey.model_validate(record)
            if key.key_id != key_id:
                raise ValueError(f"authority_keyring key mismatch: {key_id}")
            keyring[key_id] = key

        report = verify_operator_lifecycle_recovery_evidence_envelope_report(
            envelope,
            authority_keyring=keyring,
            expected_registry_id=trust["expected_registry_id"],
            expected_initial_key_id=trust["expected_initial_key_id"],
            expected_rotation_head_sha256=trust["expected_rotation_head_sha256"],
            expected_rotation_sequence=trust["expected_rotation_sequence"],
            expected_rotation_sha256=trust["expected_rotation_sha256"],
            expected_restore_event_sequence=trust["expected_restore_event_sequence"],
            expected_restore_ledger_entry_sha256=trust["expected_restore_ledger_entry_sha256"],
            expected_restore_receipt_sha256=trust["expected_restore_receipt_sha256"],
            expected_restore_ledger_head_sha256=trust["expected_restore_ledger_head_sha256"],
            authorization_time_utc=args.authorization_time_utc,
        )
        print(json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2))
        return 0 if report.accepted else 1
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError,
            ValidationError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
