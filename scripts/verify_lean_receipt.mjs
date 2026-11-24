import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync } from "node:fs";

const ATTESTATION_FIELDS = [
  "schema_version", "receipt_id", "runner_id", "key_id", "request_sha256",
  "artifact_sha256", "proof_artifact_sha256", "proof_source",
  "environment_manifest_sha256", "source_commit", "workflow_run_id",
  "lean_toolchain", "mathlib_revision", "checker_id", "kernel_id",
  "kernel_version", "outcome", "signature_b64",
];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function parseJsonNoDuplicateKeys(source) {
  let index = 0;
  const whitespace = () => { while (/[\u0009\u000a\u000d\u0020]/.test(source[index] ?? "") && index < source.length) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '"') throw new Error("expected JSON string");
    while (index < source.length) {
      const char = source[index++];
      if (char === "\\") { index += 1; continue; }
      if (char === '"') return JSON.parse(source.slice(start, index));
      if (char.charCodeAt(0) < 0x20) throw new Error("control character in JSON string");
    }
    throw new Error("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    const char = source[index];
    if (char === '"' ) return string();
    if (char === "{") {
      index += 1; whitespace(); const result = {}; const keys = new Set();
      if (source[index] === "}") { index += 1; return result; }
      while (true) {
        whitespace(); const key = string();
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        keys.add(key); whitespace();
        if (source[index++] !== ":") throw new Error("expected colon");
        result[key] = value(); whitespace();
        const separator = source[index++];
        if (separator === "}") return result;
        if (separator !== ",") throw new Error("expected comma or object end");
      }
    }
    if (char === "[") {
      index += 1; whitespace(); const result = [];
      if (source[index] === "]") { index += 1; return result; }
      while (true) {
        result.push(value()); whitespace(); const separator = source[index++];
        if (separator === "]") return result;
        if (separator !== ",") throw new Error("expected comma or array end");
      }
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, index)) { index += literal.length; return parsed; }
    }
    const number = source.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (number) { index += number[0].length; return Number(number[0]); }
    throw new Error("invalid JSON value");
  };
  const parsed = value(); whitespace();
  if (index !== source.length) throw new Error("trailing data after JSON value");
  return parsed;
}
function isWellFormedUnicode(value) {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (character.length === 1 && code >= 0xd800 && code <= 0xdfff) return false;
  }
  return true;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function verifyAttestation(attestation, trustedPublicKeyB64) {
  try {
    if (!attestation || typeof attestation !== "object" || Array.isArray(attestation)) return false;
    if (Object.keys(attestation).sort().join("|") !== [...ATTESTATION_FIELDS].sort().join("|")) return false;
    if (attestation.schema_version !== "1.0" || attestation.kernel_id !== "Lean") return false;
    if (!["PASSED", "FAILED"].includes(attestation.outcome)) return false;
    const limits = {
      receipt_id: 120, runner_id: 160, key_id: 160,
      checker_id: 160, kernel_version: 160, proof_source: 10000,
    };
    for (const [field, maximum] of Object.entries(limits)) {
      if (typeof attestation[field] !== "string" || Array.from(attestation[field]).length < 1 || Array.from(attestation[field]).length > maximum) return false;
    }
    for (const field of ["request_sha256", "artifact_sha256", "proof_artifact_sha256"]) {
      if (typeof attestation[field] !== "string" || !HEX64.test(attestation[field])) return false;
    }
    if (attestation.workflow_run_id !== null && attestation.workflow_run_id.length < 1) return false;
    if (sha256(Buffer.from(attestation.proof_source, "utf8")) !== attestation.proof_artifact_sha256) return false;
    const optional = ["environment_manifest_sha256", "source_commit", "workflow_run_id", "lean_toolchain", "mathlib_revision"];
    const values = optional.map((field) => attestation[field]);
    if (values.some((value) => value !== null) && values.some((value) => value === null)) return false;
    if (attestation.environment_manifest_sha256 !== null && (typeof attestation.environment_manifest_sha256 !== "string" || !HEX64.test(attestation.environment_manifest_sha256))) return false;
    if (attestation.source_commit !== null && (typeof attestation.source_commit !== "string" || !HEX40.test(attestation.source_commit))) return false;
    if (attestation.mathlib_revision !== null && (typeof attestation.mathlib_revision !== "string" || !HEX40.test(attestation.mathlib_revision))) return false;
    if (attestation.workflow_run_id !== null && (typeof attestation.workflow_run_id !== "string" || Array.from(attestation.workflow_run_id).length > 40)) return false;
    if (attestation.lean_toolchain !== null && (typeof attestation.lean_toolchain !== "string" || Array.from(attestation.lean_toolchain).length > 160)) return false;
    if (typeof attestation.signature_b64 !== "string" || attestation.signature_b64.length !== 88) return false;
    const publicKey = Buffer.from(trustedPublicKeyB64, "base64");
    if (publicKey.length !== 32 || publicKey.toString("base64") !== trustedPublicKeyB64) return false;
    const signature = Buffer.from(attestation.signature_b64, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== attestation.signature_b64) return false;
    const unsigned = Object.fromEntries(Object.entries(attestation).filter(([key]) => key !== "signature_b64"));
    const payload = Buffer.from(canonical(unsigned), "utf8");
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const key = createPublicKey({ key: Buffer.concat([spkiPrefix, publicKey]), format: "der", type: "spki" });
    return verifySignature(null, payload, key, signature);
  } catch {
    return false;
  }
}


function normalizeMathRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return null;
  const allowed = ["schema_version", "operation", "expression", "variable", "rhs"];
  if (Object.keys(request).some((key) => !allowed.includes(key))) return null;
  const normalized = {
    schema_version: Object.hasOwn(request, "schema_version") ? request.schema_version : "1.0",
    operation: request.operation,
    expression: request.expression,
    variable: Object.hasOwn(request, "variable") ? request.variable : "x",
    rhs: Object.hasOwn(request, "rhs") ? request.rhs : null,
  };
  if (typeof normalized.schema_version !== "string") return null;
  if (!["simplify", "expand", "factor", "differentiate", "integrate", "verify_identity", "solve", "verify_certificate", "search", "counterexample", "analyze"].includes(normalized.operation)) return null;
  if (typeof normalized.expression !== "string" || normalized.expression.length < 1 || Array.from(normalized.expression).length > 2000) return null;
  if (typeof normalized.variable !== "string" || normalized.variable.length < 1 || Array.from(normalized.variable).length > 32) return null;
  if (normalized.rhs !== null && (typeof normalized.rhs !== "string" || Array.from(normalized.rhs).length > 2000)) return null;
  return normalized;
}

export function verifyReceiptBundle(receipt, {
  manifestBytes, trustedPublicKeyB64, request, candidateBytes,
}) {
  try {
    if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return false;
    const wrapperFields = ["schema_version", "attestation", "public_key_b64", "environment_manifest_sha256", "replay"];
    if (Object.keys(receipt).sort().join("|") !== [...wrapperFields].sort().join("|")) return false;
    if (receipt.schema_version !== "mosaic.signed-lean-proof-receipt.v1") return false;
    if (receipt.public_key_b64 !== trustedPublicKeyB64) return false;
    if (!verifyAttestation(receipt.attestation, trustedPublicKeyB64)) return false;
    if (!Buffer.isBuffer(manifestBytes) || !Buffer.isBuffer(candidateBytes)) return false;
    const manifestDigest = sha256(manifestBytes);
    if (receipt.environment_manifest_sha256 !== manifestDigest ||
        receipt.attestation.environment_manifest_sha256 !== manifestDigest ||
        sha256(candidateBytes) !== receipt.attestation.artifact_sha256) return false;
    const normalizedRequest = normalizeMathRequest(request);
    if (!normalizedRequest || sha256(Buffer.from(canonical(normalizedRequest), "utf8")) !== receipt.attestation.request_sha256) return false;
    const manifest = parseJsonNoDuplicateKeys(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes));
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return false;
    if (manifest.schema_version !== "mosaic.lean-build-provenance.v1") return false;
    if (manifest.source?.commit !== receipt.attestation.source_commit ||
        manifest.execution?.run_id !== receipt.attestation.workflow_run_id ||
        manifest.environment?.lean_toolchain !== receipt.attestation.lean_toolchain ||
        manifest.environment?.mathlib_revision !== receipt.attestation.mathlib_revision) return false;
    if (!receipt.replay || typeof receipt.replay !== "object" || Array.isArray(receipt.replay) ||
        Object.keys(receipt.replay).join("|") !== "exact_signed_source_replayed" ||
        receipt.replay.exact_signed_source_replayed !== true) return false;
    return true;
  } catch {
    return false;
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const [, , receiptPath, trustedPublicKeyB64, manifestPath, requestPath, candidatePath] = process.argv;
  if (!receiptPath || !trustedPublicKeyB64) {
    process.stderr.write("Usage: node scripts/verify_lean_receipt.mjs <receipt-or-vector.json> <trusted-public-key-b64> [manifest.json request.json candidate.bin]\\n");
    process.exit(2);
  }
  try {
    const receiptBytes = readFileSync(receiptPath);
    const receiptText = new TextDecoder("utf-8", { fatal: true }).decode(receiptBytes);
    const document = parseJsonNoDuplicateKeys(receiptText);
    const fullArgs = [manifestPath, requestPath, candidatePath];
    if (fullArgs.some(Boolean) && !fullArgs.every(Boolean)) {
      process.stderr.write("Full bundle verification requires manifest, request, and candidate paths\\n");
      process.exit(2);
    }
    if (fullArgs.every(Boolean)) {
      const manifestBytes = readFileSync(manifestPath);
      const request = parseJsonNoDuplicateKeys(new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(requestPath)));
      const candidateBytes = readFileSync(candidatePath);
      if (!verifyReceiptBundle(document, { manifestBytes, trustedPublicKeyB64, request, candidateBytes })) {
        process.stderr.write("Invalid Lean proof receipt bundle or external binding\\n");
        process.exit(1);
      }
      process.stdout.write("Complete Lean proof receipt bundle verified\\n");
    } else {
      const attestation = document.attestation ?? document;
      if (!verifyAttestation(attestation, trustedPublicKeyB64)) {
        process.stderr.write("Invalid or untrusted Lean attestation\\n");
        process.exit(1);
      }
      process.stdout.write("Ed25519 Lean attestation verified\\n");
    }
  } catch (error) {
    process.stderr.write(`Unable to verify receipt: ${error.message}\n`);
    process.exit(1);
  }
}
