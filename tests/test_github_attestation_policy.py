import copy

import pytest

from mosaic.verification.github_attestation_policy import (
    AttestationPolicyError,
    verify_gh_attestation_result,
)


POLICY = {
    "schema_version": "mosaic.github-attestation-policy.v1",
    "repository": "Puronbo/MOSAIC",
    "repository_id": "1468522236",
    "workflow_path": ".github/workflows/lean-polynomial.yml",
    "signer_workflow": "Puronbo/MOSAIC/.github/workflows/lean-polynomial.yml",
    "workflow_ref": "refs/heads/main",
    "source_repository_uri": "https://github.com/Puronbo/MOSAIC",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "predicate_type": "https://slsa.dev/provenance/v1",
    "require_github_hosted_runner": True,
    "require_verified_timestamp": True,
}
COMMIT = "a" * 40
RUN_ID = "123456789"
SUBJECT = "b" * 64
WORKFLOW_URI = (
    "https://github.com/Puronbo/MOSAIC/.github/workflows/"
    "lean-polynomial.yml@refs/heads/main"
)


def verified_result():
    return [{
        "verificationResult": {
            "signature": {
                "certificate": {
                    "issuer": POLICY["oidc_issuer"],
                    "sourceRepositoryURI": POLICY["source_repository_uri"],
                    "sourceRepositoryIdentifier": POLICY["repository_id"],
                    "sourceRepositoryRef": POLICY["workflow_ref"],
                    "sourceRepositoryDigest": COMMIT,
                    "buildSignerURI": WORKFLOW_URI,
                    "buildConfigURI": WORKFLOW_URI,
                    "runInvocationURI": (
                        "https://github.com/Puronbo/MOSAIC/actions/runs/"
                        f"{RUN_ID}/attempts/1"
                    ),
                    "runnerEnvironment": "github-hosted",
                }
            },
            "statement": {
                "predicateType": POLICY["predicate_type"],
                "subject": [{"name": "lean-provenance.json", "digest": {"sha256": SUBJECT}}],
                "predicate": {},
            },
            "verifiedTimestamps": [{"type": "Tlog", "timestamp": "2026-11-24T01:00:00Z"}],
        }
    }]


def check(result):
    return verify_gh_attestation_result(
        result,
        policy=POLICY,
        expected_commit=COMMIT,
        expected_run_id=RUN_ID,
        expected_subject_sha256=SUBJECT,
    )


def test_accepts_verified_attestation_with_exact_repository_workflow_run_and_subject():
    assert check(verified_result()) == 1


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("sourceRepositoryIdentifier",), "999"),
        (("sourceRepositoryDigest",), "c" * 40),
        (("sourceRepositoryRef",), "refs/heads/attacker"),
        (("buildSignerURI",), "https://github.com/attacker/repo/workflow.yml@refs/heads/main"),
        (("buildConfigURI",), "https://github.com/Puronbo/MOSAIC/.github/workflows/other.yml@refs/heads/main"),
        (("runInvocationURI",), "https://github.com/Puronbo/MOSAIC/actions/runs/999/attempts/1"),
        (("runnerEnvironment",), "self-hosted"),
        (("issuer",), "https://attacker.invalid"),
    ],
)
def test_rejects_forged_or_mismatched_certificate_identity(path, value):
    result = verified_result()
    result[0]["verificationResult"]["signature"]["certificate"][path[0]] = value
    with pytest.raises(AttestationPolicyError):
        check(result)


def test_rejects_subject_digest_predicate_timestamp_and_empty_result():
    for mutate in (
        lambda r: r[0]["verificationResult"]["statement"]["subject"][0]["digest"].update(sha256="0" * 64),
        lambda r: r[0]["verificationResult"]["statement"].update(predicateType="https://example.invalid"),
        lambda r: r[0]["verificationResult"].update(verifiedTimestamps=[]),
    ):
        result = verified_result()
        mutate(result)
        with pytest.raises(AttestationPolicyError):
            check(result)
    with pytest.raises(AttestationPolicyError):
        check([])


def test_every_returned_attestation_must_satisfy_policy():
    result = verified_result()
    second = copy.deepcopy(result[0])
    second["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"] = "999"
    with pytest.raises(AttestationPolicyError):
        check(result + [second])


def test_rejects_unexpected_policy_fields_and_noncanonical_expected_digests():
    with pytest.raises(AttestationPolicyError):
        verify_gh_attestation_result(
            verified_result(), policy={**POLICY, "trust_any_repo": True},
            expected_commit=COMMIT, expected_run_id=RUN_ID,
            expected_subject_sha256=SUBJECT,
        )
    with pytest.raises(AttestationPolicyError):
        verify_gh_attestation_result(
            verified_result(), policy=POLICY, expected_commit=COMMIT.upper(),
            expected_run_id=RUN_ID, expected_subject_sha256=SUBJECT,
        )
