"""Verify a portable MOSAIC Lean proof receipt bundle.

Before running this verifier, validate the GitHub artifact attestation for both
receipt and manifest with:
    gh attestation verify lean-proof-attestation.json -R Puronbo/MOSAIC
    gh attestation verify lean-provenance.json -R Puronbo/MOSAIC

The public key must come from a trusted registry or from the receipt only after
the receipt's GitHub artifact attestation has been successfully verified.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from mosaic.core.requests import MathRequest
from mosaic.verification.lean_runner_signature import (
    SignedLeanAttestation,
    replay_attested_proof_source,
    verify_lean_proof_receipt_bundle,
)
from mosaic.verification.obligations import request_fingerprint


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True, help="Original MathRequest JSON")
    parser.add_argument("--candidate", type=Path, required=True, help="Exact UTF-8 candidate bytes")
    parser.add_argument("--public-key-b64", type=Path, required=True, help="Trusted raw Ed25519 public key, base64 encoded")
    parser.add_argument("--replay", action="store_true", help="Replay exact signed Lean source with local Lake")
    args = parser.parse_args()

    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        manifest = args.manifest.read_bytes()
        request = MathRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
        candidate = args.candidate.read_bytes()
        public_key = base64.b64decode(args.public_key_b64.read_text(encoding="ascii").strip(), validate=True)
        if len(public_key) != 32:
            raise ValueError("trusted Ed25519 public key must decode to exactly 32 bytes")
        if not verify_lean_proof_receipt_bundle(
            receipt,
            manifest=manifest,
            trusted_public_key=public_key,
            request_sha256=request_fingerprint(request),
            candidate=candidate,
        ):
            print("INVALID: proof receipt bundle, signature, manifest, request, or candidate binding failed")
            return 1
        attestation = SignedLeanAttestation.model_validate(receipt["attestation"])
        if args.replay:
            replay = replay_attested_proof_source(attestation, public_key)
            if replay is not True:
                print(f"INCONCLUSIVE/INVALID: local exact-source replay returned {replay!r}")
                return 2
        print("VALID: signature, proof-source digest, environment manifest, request, and candidate bindings verified")
        if args.replay:
            print("VALID: exact signed Lean source replayed successfully in the local pinned Lake project")
        else:
            print("NOTE: source replay was not requested; the receipt's recorded replay flag is not a fresh local replay")
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"INVALID INPUT: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
