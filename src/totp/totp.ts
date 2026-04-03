import * as OTPAuth from "otpauth";
import { zeroBuffer } from "../vault/crypto.js";

/**
 * TOTP code generation from stored seeds.
 * Seeds are otpauth:// URIs (same format as QR codes from authenticator apps).
 *
 * The seed Buffer is zeroed after generating the code.
 * The returned code is ephemeral (30s) — acceptable for injection but
 * MUST NOT be returned to the agent. Only injected via browser/HTTP.
 */

export function generateTOTP(seedBuffer: Buffer): string {
  const uri = seedBuffer.toString("utf-8");

  let totp: OTPAuth.TOTP;

  if (uri.startsWith("otpauth://")) {
    // Parse full otpauth:// URI
    totp = OTPAuth.URI.parse(uri) as OTPAuth.TOTP;
  } else {
    // Treat as raw base32 secret
    totp = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(uri.trim()),
      digits: 6,
      period: 30,
      algorithm: "SHA1",
    });
  }

  const code = totp.generate();

  // Zero the seed buffer
  zeroBuffer(seedBuffer);

  return code;
}

/**
 * Validate a TOTP URI/secret format without generating a code.
 */
export function validateTOTPSeed(seed: string): boolean {
  try {
    if (seed.startsWith("otpauth://")) {
      OTPAuth.URI.parse(seed);
    } else {
      OTPAuth.Secret.fromBase32(seed.trim());
    }
    return true;
  } catch {
    return false;
  }
}
