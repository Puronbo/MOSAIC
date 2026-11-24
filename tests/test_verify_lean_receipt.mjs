import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyAttestation } from "../scripts/verify_lean_receipt.mjs";

const vector = JSON.parse(readFileSync(new URL("./fixtures/lean_receipt_v1_vector.json", import.meta.url), "utf8"));

test("Node independently verifies the Python Ed25519 conformance vector", () => {
  assert.equal(verifyAttestation(vector.attestation, vector.public_key_b64), true);
});

test("Node rejects altered signed fields and untrusted keys", () => {
  const changed = { ...vector.attestation, runner_id: "forged-runner" };
  assert.equal(verifyAttestation(changed, vector.public_key_b64), false);
  assert.equal(verifyAttestation(vector.attestation, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), false);
});

test("Node rejects malformed schema, digest and partial environment binding", () => {
  assert.equal(verifyAttestation({ ...vector.attestation, schema_version: "2.0" }, vector.public_key_b64), false);
  assert.equal(verifyAttestation({ ...vector.attestation, proof_artifact_sha256: "0".repeat(64) }, vector.public_key_b64), false);
  assert.equal(verifyAttestation({ ...vector.attestation, source_commit: "a".repeat(40) }, vector.public_key_b64), false);
});