from decimal import Decimal

import pytest

from mosaic.core.field_refinement_certificate import (
    FieldRefinementCertificate,
    RefinementDecision,
    create_field_refinement_certificate,
    verify_field_refinement_certificate,
)
from tests.test_field_refinement import run


def make_certificate():
    return create_field_refinement_certificate(
        run(),
        assessment_id="assessment-001",
        field_difference_tolerance=Decimal("1"),
        velocity_difference_tolerance=Decimal("1"),
        relative_energy_drift_tolerance=Decimal("1"),
    )


def test_certificate_is_self_contained_and_verifiable():
    certificate = make_certificate()
    assert certificate.decision == RefinementDecision.ACCEPTED
    assert len(certificate.sha256) == 64
    assert certificate.refinement.levels
    assert verify_field_refinement_certificate(certificate)


def test_certificate_digest_detects_payload_tampering():
    certificate = make_certificate()
    tampered = certificate.model_copy(update={"assessment_id": "changed"})
    assert not verify_field_refinement_certificate(tampered)


def test_certificate_verifier_recomputes_acceptance_metrics():
    certificate = make_certificate()
    tampered = certificate.model_copy(update={
        "decision": RefinementDecision.REJECTED,
        "reasons": ("fabricated rejection",),
    })
    # Even if an altered record is re-hashed, its decision must still agree
    # with the independently recomputed criteria.
    import hashlib
    import json

    payload = tampered.model_dump(mode="json", exclude={"sha256"})
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    tampered = tampered.model_copy(update={"sha256": digest})
    assert not verify_field_refinement_certificate(tampered)


def test_certificate_rejects_nonpositive_tolerances():
    refinement = run()
    with pytest.raises(ValueError, match="field_difference_tolerance"):
        create_field_refinement_certificate(
            refinement,
            assessment_id="assessment-002",
            field_difference_tolerance=Decimal("0"),
            velocity_difference_tolerance=Decimal("1"),
            relative_energy_drift_tolerance=Decimal("1"),
        )
