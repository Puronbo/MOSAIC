"""Integrity-bound, replayable bundles for recursive derivation evaluations.

A bundle binds the registered derivation tree, compiled obligation graph, exact
candidate payloads, and deterministic graph evaluation. Its digest detects
mutation; replay recomputes the registered structure and checks again. The
result remains EXPERIMENTAL and is not a formal proof of the root claim.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.derivation import DerivationTree
from mosaic.verification.derivation_graph import (
    compile_derivation_obligation_graph,
    evaluate_derivation_tree,
)
from mosaic.verification.graph import ObligationGraph, ObligationGraphResult
from mosaic.verification.obligations import request_fingerprint

MAX_BUNDLE_BYTES = 1_000_000
MAX_CANDIDATES = 256
MAX_CANDIDATE_BYTES = 16_384


class DerivationCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=1, max_length=160)
    payload: str = Field(max_length=MAX_CANDIDATE_BYTES)


class DerivationBundle(BaseModel):
    """Immutable, request-bound record of a complete derivation evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tree: DerivationTree
    graph: ObligationGraph
    candidates: tuple[DerivationCandidate, ...]
    result: ObligationGraphResult
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _payload(bundle: DerivationBundle) -> bytes:
    value = bundle.model_dump(mode="json", exclude={"bundle_sha256"})
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ValueError("derivation bundle exceeds the maximum serialized size")
    return encoded


def _digest(bundle: DerivationBundle) -> str:
    return hashlib.sha256(_payload(bundle)).hexdigest()


def create_derivation_bundle(
    request: MathRequest,
    tree: DerivationTree,
    candidates: dict[str, str],
) -> DerivationBundle:
    """Compile, evaluate, and integrity-bind an exact recursive derivation run."""
    if not isinstance(candidates, dict) or len(candidates) > MAX_CANDIDATES:
        raise ValueError("candidate map must be a bounded dictionary")
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in candidates.items()):
        raise ValueError("candidate identifiers and payloads must be text")
    if any(len(value.encode("utf-8")) > MAX_CANDIDATE_BYTES
           for value in candidates.values()):
        raise ValueError("candidate payload exceeds the configured size limit")
    graph = compile_derivation_obligation_graph(request, tree)
    expected_ids = {node.obligation.obligation_id for node in graph.nodes}
    if set(candidates) - expected_ids:
        raise ValueError("candidate map contains unknown obligation identifiers")
    ordered_candidates = tuple(
        DerivationCandidate(obligation_id=key, payload=value)
        for key, value in sorted(candidates.items())
    )
    result = evaluate_derivation_tree(request, tree, candidates)
    provisional = DerivationBundle(
        request_sha256=request_fingerprint(request),
        tree=tree,
        graph=graph,
        candidates=ordered_candidates,
        result=result,
        bundle_sha256="0" * 64,
    )
    return provisional.model_copy(update={"bundle_sha256": _digest(provisional)})


def validate_derivation_bundle(
    request: MathRequest, bundle: DerivationBundle
) -> DerivationBundle:
    """Reject altered, stale, structurally inconsistent, or non-reproducible bundles."""
    if not hmac.compare_digest(bundle.bundle_sha256, _digest(bundle)):
        raise ValueError("derivation bundle integrity check failed")
    if not hmac.compare_digest(bundle.request_sha256, request_fingerprint(request)):
        raise ValueError("derivation bundle belongs to a different or stale request")
    rebuilt_graph = compile_derivation_obligation_graph(request, bundle.tree)
    if rebuilt_graph != bundle.graph:
        raise ValueError("stored obligation graph does not match the registered derivation")
    ids = [item.obligation_id for item in bundle.candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("derivation bundle contains duplicate candidate identifiers")
    candidates = {item.obligation_id: item.payload for item in bundle.candidates}
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError("derivation bundle exceeds the candidate count limit")
    expected_ids = {node.obligation.obligation_id for node in rebuilt_graph.nodes}
    if set(candidates) - expected_ids:
        raise ValueError("derivation bundle contains unknown candidate identifiers")
    replayed = evaluate_derivation_tree(request, bundle.tree, candidates)
    if replayed != bundle.result:
        raise ValueError("stored derivation result does not match deterministic replay")
    return bundle


def serialize_derivation_bundle(bundle: DerivationBundle) -> bytes:
    """Serialize a bounded bundle with its integrity digest."""
    encoded = json.dumps(
        bundle.model_dump(mode="json"),
        ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ValueError("derivation bundle exceeds the maximum serialized size")
    return encoded


def load_derivation_bundle(data: bytes | str) -> DerivationBundle:
    """Load a bounded bundle; call validate_derivation_bundle before trusting it."""
    encoded = data.encode("utf-8") if isinstance(data, str) else data
    if not isinstance(encoded, bytes):
        raise TypeError("derivation bundle must be bytes or text")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ValueError("derivation bundle exceeds the maximum serialized size")
    return DerivationBundle.model_validate_json(encoded)
