import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyAttestation, verifyReceiptBundle, parseJsonNoDuplicateKeys } from "../scripts/verify_lean_receipt.mjs";

const vector = JSON.parse(readFileSync(new URL("./fixtures/lean_receipt_v1_vector.json", import.meta.url), "utf8"));
const bundleVector = JSON.parse(readFileSync(new URL("./fixtures/lean_receipt_v1_bundle_vector.json", import.meta.url), "utf8"));

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

test("Node JSON parser rejects duplicate keys at every nesting level", () => {
  assert.throws(() => parseJsonNoDuplicateKeys('{"key":1,"key":2}'), /duplicate JSON key/);
  assert.throws(() => parseJsonNoDuplicateKeys('{"nested":{"x":1,"x":2}}'), /duplicate JSON key/);
  assert.deepEqual(parseJsonNoDuplicateKeys('{"escaped":"a\\\\nb","array":[true,null,3]}'), {
    escaped: "a\\nb",
    array: [true, null, 3],
  });
});


test("Node parser accepts JSON number grammar and rejects non-JSON whitespace", () => {
  assert.deepEqual(parseJsonNoDuplicateKeys('{"n":-12.5e+2,"items":[0,1.25]}'), {
    n: -1250,
    items: [0, 1.25],
  });
  assert.throws(() => parseJsonNoDuplicateKeys('{"a":1}\\u00a0'), /trailing data/);
});


test("Node verifier counts Unicode code points for source limits", () => {
  const supplementary = { ...vector.attestation, proof_source: "😀".repeat(10000) };
  assert.equal(verifyAttestation(supplementary, vector.public_key_b64), false);
  assert.equal(verifyAttestation({ ...vector.attestation, proof_source: "\\ud800" }, vector.public_key_b64), false);
});


test("Node verifies Unicode canonicalization conformance vector", () => {
  const unicodeVector = JSON.parse(readFileSync(
    new URL("./fixtures/lean_receipt_v1_unicode_vector.json", import.meta.url), "utf8"
  ));
  assert.equal(verifyAttestation(unicodeVector.attestation, unicodeVector.public_key_b64), true);
});


test("Node rejects non-string optional provenance values", () => {
  const bound = {
    environment_manifest_sha256: "2".repeat(64),
    source_commit: "a".repeat(40),
    workflow_run_id: "12345",
    lean_toolchain: "leanprover/lean4:v4.36.0",
    mathlib_revision: "b".repeat(40),
  };
  assert.equal(verifyAttestation({ ...vector.attestation, ...bound, environment_manifest_sha256: 123 }, vector.public_key_b64), false);
  assert.equal(verifyAttestation({ ...vector.attestation, ...bound, source_commit: 123 }, vector.public_key_b64), false);
});


test("published JSON Schema exactly describes the Node verifier field set", () => {
  const schema = JSON.parse(readFileSync(
    new URL("../schemas/lean-runner-attestation-v1.schema.json", import.meta.url), "utf8"
  ));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(vector.attestation).sort());
  assert.deepEqual(Object.keys(schema.properties).sort(), Object.keys(vector.attestation).sort());
});


test("Node CLI verifies a receipt file using an explicit trusted key", () => {
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("../scripts/verify_lean_receipt.mjs", import.meta.url)),
    fileURLToPath(new URL("./fixtures/lean_receipt_v1_vector.json", import.meta.url)),
    vector.public_key_b64,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Ed25519 Lean attestation verified/);
});


test("Node CLI rejects duplicate-key receipt JSON before verification", () => {
  const directory = mkdtempSync(join(tmpdir(), "mosaic-receipt-"));
  const receiptPath = join(directory, "duplicate.json");
  try {
    writeFileSync(receiptPath, '{"attestation":{},"attestation":{}}', "utf8");
    const result = spawnSync(process.execPath, [
      fileURLToPath(new URL("../scripts/verify_lean_receipt.mjs", import.meta.url)),
      receiptPath,
      vector.public_key_b64,
    ], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /duplicate JSON key/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});


test("Node independently verifies the complete signed proof bundle", () => {
  const manifestBytes = Buffer.from(bundleVector.manifest_b64, "base64");
  const candidateBytes = Buffer.from(bundleVector.candidate_b64, "base64");
  const valid = {
    manifestBytes,
    trustedPublicKeyB64: bundleVector.public_key_b64,
    request: bundleVector.request,
    candidateBytes,
  };
  assert.equal(verifyReceiptBundle(bundleVector.receipt, valid), true);
  assert.equal(verifyReceiptBundle(bundleVector.receipt, { ...valid, candidateBytes: Buffer.concat([candidateBytes, Buffer.from(" ")]) }), false);
  assert.equal(verifyReceiptBundle(bundleVector.receipt, { ...valid, manifestBytes: Buffer.concat([manifestBytes, Buffer.from(" ")]) }), false);
  assert.equal(verifyReceiptBundle(bundleVector.receipt, { ...valid, request: { ...valid.request, expression: "x + 2" } }), false);
  const tampered = { ...bundleVector.receipt, replay: { exact_signed_source_replayed: false } };
  assert.equal(verifyReceiptBundle(tampered, valid), false);
});


test("Node CLI verifies a complete receipt, manifest, request and candidate bundle", () => {
  const directory = mkdtempSync(join(tmpdir(), "mosaic-full-bundle-"));
  const paths = {
    receipt: join(directory, "receipt.json"),
    manifest: join(directory, "manifest.json"),
    request: join(directory, "request.json"),
    candidate: join(directory, "candidate.txt"),
  };
  try {
    writeFileSync(paths.receipt, JSON.stringify(bundleVector.receipt), "utf8");
    writeFileSync(paths.manifest, Buffer.from(bundleVector.manifest_b64, "base64"));
    writeFileSync(paths.request, JSON.stringify(bundleVector.request), "utf8");
    writeFileSync(paths.candidate, Buffer.from(bundleVector.candidate_b64, "base64"));
    const result = spawnSync(process.execPath, [
      fileURLToPath(new URL("../scripts/verify_lean_receipt.mjs", import.meta.url)),
      paths.receipt,
      bundleVector.public_key_b64,
      paths.manifest,
      paths.request,
      paths.candidate,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Complete Lean proof receipt bundle verified/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});


test("published bundle JSON Schema exactly describes the portable receipt wrapper", () => {
  const schema = JSON.parse(readFileSync(
    new URL("../schemas/lean-proof-receipt-bundle-v1.schema.json", import.meta.url), "utf8"
  ));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(bundleVector.receipt).sort());
  assert.deepEqual(Object.keys(schema.properties).sort(), Object.keys(bundleVector.receipt).sort());
  assert.equal(schema.properties.replay.additionalProperties, false);
});


test("Node bundle verifier rejects lone surrogates in request and signed fields", () => {
  const manifestBytes = Buffer.from(bundleVector.manifest_b64, "base64");
  const candidateBytes = Buffer.from(bundleVector.candidate_b64, "base64");
  const valid = {
    manifestBytes,
    trustedPublicKeyB64: bundleVector.public_key_b64,
    request: bundleVector.request,
    candidateBytes,
  };
  assert.equal(verifyReceiptBundle(bundleVector.receipt, {
    ...valid,
    request: { ...bundleVector.request, expression: "\ud800" },
  }), false);
  const attestation = { ...bundleVector.receipt.attestation, lean_toolchain: "\ud800" };
  assert.equal(verifyReceiptBundle({ ...bundleVector.receipt, attestation }, valid), false);
});


test("published MathRequest schema documents all request fingerprint fields and defaults", () => {
  const schema = JSON.parse(readFileSync(
    new URL("../schemas/math-request-v1.schema.json", import.meta.url), "utf8"
  ));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), ["expression", "operation"]);
  assert.deepEqual(Object.keys(schema.properties).sort(), ["expression", "operation", "rhs", "schema_version", "variable"]);
  assert.equal(schema.properties.variable.default, "x");
  assert.equal(schema.properties.schema_version.default, "1.0");
  assert.equal(schema.properties.rhs.default, null);
  assert.deepEqual(schema.properties.operation.enum, [
    "simplify", "expand", "factor", "differentiate", "integrate",
    "verify_identity", "solve", "verify_certificate", "search",
    "counterexample", "analyze",
  ]);
});


test("Node bundle fingerprinting applies MathRequest defaults before hashing", () => {
  const manifestBytes = Buffer.from(bundleVector.manifest_b64, "base64");
  const candidateBytes = Buffer.from(bundleVector.candidate_b64, "base64");
  const valid = {
    manifestBytes,
    trustedPublicKeyB64: bundleVector.public_key_b64,
    candidateBytes,
  };
  const requestWithDefaults = { ...bundleVector.request };
  delete requestWithDefaults.schema_version;
  delete requestWithDefaults.variable;
  assert.equal(verifyReceiptBundle(bundleVector.receipt, {
    ...valid,
    request: requestWithDefaults,
  }), true);
  assert.equal(verifyReceiptBundle(bundleVector.receipt, {
    ...valid,
    request: { ...requestWithDefaults, variable: null },
  }), false);
});
