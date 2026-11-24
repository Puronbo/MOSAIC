#!/usr/bin/env python3
"""Apply MOSAIC's producer identity policy to gh attestation verify JSON."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mosaic.verification.github_attestation_policy import (
    AttestationPolicyError,
    verify_gh_attestation_result,
)
from mosaic.verification.lean_runner_signature import _strict_json_loads


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification-json", required=True, help="JSON output from successful gh attestation verify --format json")
    parser.add_argument("--commit", required=True, help="Expected 40-character source commit")
    parser.add_argument("--run-id", required=True, help="Expected GitHub Actions run ID")
    parser.add_argument("--subject-sha256", required=True, help="Expected artifact subject SHA-256")
    parser.add_argument("--policy", default="policies/github-lean-attestation-v1.json")
    args = parser.parse_args()
    try:
        result = _strict_json_loads(Path(args.verification_json).read_text(encoding="utf-8"))
        count = verify_gh_attestation_result(
            result,
            policy=args.policy,
            expected_commit=args.commit,
            expected_run_id=args.run_id,
            expected_subject_sha256=args.subject_sha256,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print(f"ACCEPTED: {count} cryptographically verified GitHub attestation(s) satisfy MOSAIC producer policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
