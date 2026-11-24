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
  const whitespace = () => { while (/\\s/.test(source[index] ?? "") && index < source.length) index += 1; };
  const string = () => {
    const start = index;
    if (source[index++] !== '" '.trim()) throw new Error("expected JSON string");
    while (index < source.length) {
      const char = source[index++];
      if (char === "\\\\") { index += 1; continue; }
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
    const number = source.slice(index).match(/^-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?/);
    if (number) { index += number[0].length; return Number(number[0]); }
    throw new Error("invalid JSON value");
  };
  const parsed = value(); whitespace();
  if (index !== source.length) throw new Error("trailing data after JSON value");
  return parsed;
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
    for (const field of ["receipt_id", "runner_id", "key_id", "checker_id", "kernel_version", "proof_source"]) {
      if (typeof attestation[field] !== "string" || attestation[field].length < 1) return false;
    }
    for (const field of ["request_sha256", "artifact_sha256", "proof_artifact_sha256"]) {
      if (typeof attestation[field] !== "string" || !HEX64.test(attestation[field])) return false;
    }
    if (Buffer.byteLength(attestation.proof_source, "utf8") > 10000) return false;
    if (sha256(Buffer.from(attestation.proof_source, "utf8")) !== attestation.proof_artifact_sha256) return false;
    const optional = ["environment_manifest_sha256", "source_commit", "workflow_run_id", "lean_toolchain", "mathlib_revision"];
    const values = optional.map((field) => attestation[field]);
    if (values.some((value) => value !== null) && values.some((value) => value === null)) return false;
    if (attestation.environment_manifest_sha256 !== null && !HEX64.test(attestation.environment_manifest_sha256)) return false;
    if (attestation.source_commit !== null && !HEX40.test(attestation.source_commit)) return false;
    if (attestation.mathlib_revision !== null && !HEX40.test(attestation.mathlib_revision)) return false;
    if (attestation.workflow_run_id !== null && (typeof attestation.workflow_run_id !== "string" || attestation.workflow_run_id.length > 40)) return false;
    if (attestation.lean_toolchain !== null && (typeof attestation.lean_toolchain !== "string" || attestation.lean_toolchain.length > 160)) return false;
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

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const [, , receiptPath, trustedPublicKeyB64] = process.argv;
  if (!receiptPath || !trustedPublicKeyB64) {
    process.stderr.write("Usage: node scripts/verify_lean_receipt.mjs <receipt-or-vector.json> <trusted-public-key-b64>\\n");
    process.exit(2);
  }
  try {
    const document = parseJsonNoDuplicateKeys(readFileSync(receiptPath, "utf8"));
    const attestation = document.attestation ?? document;
    if (!verifyAttestation(attestation, trustedPublicKeyB64)) {
      process.stderr.write("Invalid or untrusted Lean attestation\\n");
      process.exit(1);
    }
    process.stdout.write("Ed25519 Lean attestation verified\\n");
  } catch (error) {
    process.stderr.write(`Unable to verify receipt: ${error.message}\\n`);
    process.exit(1);
  }
}
