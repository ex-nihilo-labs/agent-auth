import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";
import { ValidationError } from "../errors.js";

/**
 * Cryptographic primitives for the vault.
 * Modeled after AgentSecrets' envelope: Base64(12-byte nonce || AES-256-GCM ciphertext || 16-byte tag)
 *
 * All operations work with Buffers — never JS strings — so we can zero memory after use.
 */

const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;

// Argon2id parameters (match AgentSecrets: 3 iterations, 64MB, 4 threads)
const ARGON2_ITERATIONS = 3;
const ARGON2_MEMORY_KB = 65536; // 64MB
const ARGON2_PARALLELISM = 4;
const SALT_BYTES = 32;

/**
 * Derive a 256-bit key from a passphrase using Argon2id.
 * Returns { key, salt } — salt must be stored alongside the vault.
 */
export function deriveKey(
  passphrase: Buffer,
  salt?: Buffer
): { key: Buffer; salt: Buffer } {
  const actualSalt = salt ?? Buffer.from(randomBytes(SALT_BYTES));

  const derived = argon2id(passphrase, actualSalt, {
    t: ARGON2_ITERATIONS,
    m: ARGON2_MEMORY_KB,
    p: ARGON2_PARALLELISM,
    dkLen: KEY_BYTES,
  });

  return {
    key: Buffer.from(derived),
    salt: actualSalt,
  };
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns Base64(nonce || ciphertext || tag).
 * Input and output are Buffers for memory hygiene.
 */
export function encrypt(key: Buffer, plaintext: Buffer): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const envelope = Buffer.concat([nonce, ciphertext, tag]);
  const encoded = envelope.toString("base64");

  // Zero intermediate buffers
  nonce.fill(0);
  ciphertext.fill(0);
  tag.fill(0);
  envelope.fill(0);

  return encoded;
}

/**
 * Decrypt a Base64(nonce || ciphertext || tag) envelope.
 * Returns plaintext as Buffer. Caller MUST zero it after use.
 */
export function decrypt(key: Buffer, encoded: string): Buffer {
  const envelope = Buffer.from(encoded, "base64");

  if (envelope.length < NONCE_BYTES + TAG_BYTES) {
    throw new ValidationError("invalid_envelope", "Invalid encrypted envelope: too short");
  }

  const nonce = envelope.subarray(0, NONCE_BYTES);
  const tag = envelope.subarray(envelope.length - TAG_BYTES);
  const ciphertext = envelope.subarray(NONCE_BYTES, envelope.length - TAG_BYTES);

  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  // Zero the envelope copy
  envelope.fill(0);

  return plaintext;
}

/**
 * Zero a buffer's memory. Call this when done with sensitive data.
 */
export function zeroBuffer(buf: Buffer): void {
  buf.fill(0);
}
