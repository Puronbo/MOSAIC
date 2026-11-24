"""Fail-closed policy checks for GitHub CLI-verified artifact attestations.

Cryptographic verification is delegated to `gh attestation verify`. This
module checks the verified result's certificate identity, source revision,
workflow, run, timestamp, predicate type, and artifact subject digest.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class AttestationPolicyError(ValueError):
    """A cryptographically verified attestation violates MOSAIC trust policy."""


def _load_policy(policy: dict[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(policy, dict):
        value = policy
    else:
        value = json.loads(Path(policy).read_text(encoding="utf-8"))
    required = {
        "schema_version", "repository", "repository_id", "workflow_path",
        "signer_workflow", "workflow_ref", "source_repository_uri",
        "oidc_issuer", "predicate_type", "require_github_hosted_runner",
        "require_verified_timestamp",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AttestationPolicyError("policy has missing or unexpected fields")
    if value["schema_version"] != "mosaic.github-attestation-policy.v1":
        raise AttestationPolicyError("unsupported policy schema version")
    if not re.fullmatch(r"[0-9]+", str(value["repository_id"])):
        raise AttestationPolicyError("repository_id must be a numeric immutable ID")
    return value


def verify_gh_attestation_result(
    result: Any,
    *,
    policy: dict[str, Any] | str | Path,
    expected_commit: str,
    expected_run_id: str,
    expected_subject_sha256: str,
) -> int:
    """Validate every entry emitted by successful `gh attestation verify --format json`.

    Returns the number of accepted attestations. The caller must run the GH CLI
    with --repo, --signer-workflow, --source-ref, and --deny-self-hosted-runners;
    this function does not perform Sigstore cryptographic verification itself.
    """
    rules = _load_policy(policy)
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise AttestationPolicyError("expected_commit must be a lowercase 40-hex SHA")
    if not re.fullmatch(r"[0-9]+", str(expected_run_id)):
        raise AttestationPolicyError("expected_run_id must be numeric")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_subject_sha256):
        raise AttestationPolicyError("expected_subject_sha256 must be lowercase SHA-256")
    if not isinstance(result, list) or not result:
        raise AttestationPolicyError("verified attestation output must be a nonempty array")

    accepted = 0
    expected_signer_prefix = (
        f"https://github.com/{rules['repository']}/{rules['workflow_path']}@"
    )
    for index, entry in enumerate(result):
        try:
            verified = entry["verificationResult"]
            certificate = verified["signature"]["certificate"]
            statement = verified["statement"]
            timestamps = verified["verifiedTimestamps"]
        except (KeyError, TypeError) as exc:
            raise AttestationPolicyError(f"attestation {index} lacks verified certificate, statement, or timestamp data") from exc

        if not isinstance(certificate, dict) or not isinstance(statement, dict):
            raise AttestationPolicyError(f"attestation {index} has malformed verification data")
        expected_cert = {
            "issuer": rules["oidc_issuer"],
            "sourceRepositoryURI": rules["source_repository_uri"],
            "sourceRepositoryIdentifier": str(rules["repository_id"]),
            "sourceRepositoryRef": rules["workflow_ref"],
            "sourceRepositoryDigest": expected_commit,
        }
        for field, expected in expected_cert.items():
            if certificate.get(field) != expected:
                raise AttestationPolicyError(f"attestation {index} certificate field {field} does not match policy")

        signer = certificate.get("buildSignerURI")
        config = certificate.get("buildConfigURI")
        if not isinstance(signer, str) or not signer.startswith(expected_signer_prefix):
            raise AttestationPolicyError(f"attestation {index} has an unauthorized build signer URI")
        if not isinstance(config, str) or not config.startswith(expected_signer_prefix):
            raise AttestationPolicyError(f"attestation {index} has an unauthorized build config URI")
        if not signer.endswith("@" + rules["workflow_ref"]) or not config.endswith("@" + rules["workflow_ref"]):
            raise AttestationPolicyError(f"attestation {index} signer/config ref is not the protected branch")
        if rules["require_github_hosted_runner"] and certificate.get("runnerEnvironment") != "github-hosted":
            raise AttestationPolicyError(f"attestation {index} was not produced on a GitHub-hosted runner")

        invocation = certificate.get("runInvocationURI")
        run_pattern = rf"^https://github\\.com/{re.escape(rules['repository'])}/actions/runs/{re.escape(str(expected_run_id))}/attempts/[1-9][0-9]*$"
        if not isinstance(invocation, str) or not re.fullmatch(run_pattern, invocation):
            raise AttestationPolicyError(f"attestation {index} run invocation does not match the expected workflow run")

        if statement.get("predicateType") != rules["predicate_type"]:
            raise AttestationPolicyError(f"attestation {index} has an unexpected predicate type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not subjects:
            raise AttestationPolicyError(f"attestation {index} has no subjects")
        matching = [
            subject for subject in subjects
            if isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_subject_sha256
        ]
        if len(matching) != 1:
            raise AttestationPolicyError(f"attestation {index} must contain exactly one matching SHA-256 subject")

        if rules["require_verified_timestamp"] and (
            not isinstance(timestamps, list) or not timestamps
            or any(not isinstance(item, dict) or not item.get("timestamp") for item in timestamps)
        ):
            raise AttestationPolicyError(f"attestation {index} has no verified transparency/timestamp evidence")
        accepted += 1
    return accepted
