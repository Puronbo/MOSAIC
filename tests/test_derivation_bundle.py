import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.derivation import build_derivation_tree
from mosaic.verification.derivation_bundle import (
    create_derivation_bundle,
    load_derivation_bundle,
    serialize_derivation_bundle,
    validate_derivation_bundle,
)


def request(expression="x**2+1"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_derivation_bundle_round_trips_and_replays_exact_evaluation():
    source = request()
    tree = build_derivation_tree(source)
    bundle = create_derivation_bundle(source, tree, {})
    restored = load_derivation_bundle(serialize_derivation_bundle(bundle))
    assert validate_derivation_bundle(source, restored) == bundle
    assert restored.result.status == "INCOMPLETE"


def test_derivation_bundle_rejects_tampered_content():
    source = request()
    bundle = create_derivation_bundle(source, build_derivation_tree(source), {})
    tampered = bundle.model_copy(update={"request_sha256": "0" * 64})
    with pytest.raises(ValueError, match="integrity"):
        validate_derivation_bundle(source, tampered)


def test_derivation_bundle_rejects_stale_request_even_with_original_digest():
    source = request()
    bundle = create_derivation_bundle(source, build_derivation_tree(source), {})
    with pytest.raises(ValueError, match="different or stale"):
        validate_derivation_bundle(request("x**3+1"), bundle)


def test_derivation_bundle_rejects_unknown_candidate_ids():
    source = request()
    tree = build_derivation_tree(source)
    with pytest.raises(ValueError, match="unknown obligation"):
        create_derivation_bundle(source, tree, {"not-a-real-obligation": "{}"})


def test_derivation_bundle_rejects_duplicate_candidate_ids_on_replay():
    source = request()
    tree = build_derivation_tree(source)
    bundle = create_derivation_bundle(source, tree, {})
    duplicate = bundle.model_copy(update={
        "candidates": (
            # The graph contains exactly one obligation for this leaf.
            {"obligation_id": "x", "payload": "{}"},
            {"obligation_id": "x", "payload": "{}"},
        )
    })
    # The modified model is rejected by the digest before candidate processing.
    with pytest.raises(ValueError, match="integrity"):
        validate_derivation_bundle(source, duplicate)


def test_derivation_bundle_rejects_candidate_size_and_count_overflow():
    source = request()
    tree = build_derivation_tree(source)
    node = __import__(
        "mosaic.verification.derivation_graph",
        fromlist=["compile_derivation_obligation_graph"],
    ).compile_derivation_obligation_graph(source, tree).nodes[0]
    with pytest.raises(ValueError, match="size limit"):
        create_derivation_bundle(source, tree, {node.obligation.obligation_id: "x" * 16_385})
    too_many = {f"unknown-{i}": "" for i in range(257)}
    with pytest.raises(ValueError, match="bounded dictionary"):
        create_derivation_bundle(source, tree, too_many)
