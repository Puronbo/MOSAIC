"""Independently verify a portable MOSAIC operator-lifecycle recovery envelope.

The trust file is provisioned separately from the envelope. Never derive its
public keys or expected head digests from the artifact being verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from importlib import metadata
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


def _execution_provenance() -> dict[str, Any]:
    """Describe the verifier and runtime; this is provenance, not attestation."""
    root = Path(__file__).resolve().parents[1]
    script_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    lock_candidates = (root / "uv.lock", root / "requirements-lock.txt",
                       root / "poetry.lock")
    lock_path = next((path for path in lock_candidates if path.is_file()), None)
    lock_digest = (hashlib.sha256(lock_path.read_bytes()).hexdigest()
                   if lock_path else None)
    distributions: dict[str, str | None] = {}
    for name in ("mosaic-math", "pydantic", "cryptography"):
        try:
            distributions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            distributions[name] = None
    manifest: dict[str, Any] = {
        "provenance_schema_version": "1.0",
        "verifier": "verify_operator_lifecycle_recovery_envelope",
        "verifier_sha256": script_digest,
        "mosaic_distribution_version": distributions["mosaic-math"],
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "dependency_versions": distributions,
        "dependency_lock_file": lock_path.name if lock_path else None,
        "dependency_lock_sha256": lock_digest,
        "source_revision": os.environ.get("GITHUB_SHA") or os.environ.get("MOSAIC_SOURCE_REVISION"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version",
                        version="MOSAIC recovery-envelope verifier 1.0")
    parser.add_argument("--provenance", action="store_true",
                        help="print verifier/runtime provenance and exit")
    parser.add_argument("--envelope", type=Path,
                        help="Portable recovery evidence envelope JSON")
    parser.add_argument("--trust", type=Path,
                        help="Independently provisioned trust configuration JSON")
    parser.add_argument("--authorization-time-utc",
                        help="Optional canonical UTC policy bound, supplied independently")
    args = parser.parse_args()

    if args.provenance:
        print(json.dumps(_execution_provenance(), sort_keys=True, indent=2))
        return 0
    if args.envelope is None or args.trust is None:
        parser.error("--envelope and --trust are required unless --provenance is used")

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
