import { describe, test, expect } from "bun:test";
import { generateTOTP, validateTOTPSeed } from "../src/totp/totp.ts";

describe("TOTP", () => {
  test("generates 6-digit code from base32 secret", () => {
    const code = generateTOTP(Buffer.from("JBSWY3DPEHPK3PXP"));
    expect(code).toMatch(/^\d{6}$/);
  });

  test("generates code from otpauth:// URI", () => {
    const uri = "otpauth://totp/AWS:admin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS";
    const code = generateTOTP(Buffer.from(uri));
    expect(code).toMatch(/^\d{6}$/);
  });

  test("same secret produces same code within the same 30s window", () => {
    const c1 = generateTOTP(Buffer.from("JBSWY3DPEHPK3PXP"));
    const c2 = generateTOTP(Buffer.from("JBSWY3DPEHPK3PXP"));
    expect(c1).toBe(c2);
  });

  test("validateTOTPSeed accepts valid base32", () => {
    expect(validateTOTPSeed("JBSWY3DPEHPK3PXP")).toBe(true);
  });

  test("validateTOTPSeed accepts valid otpauth URI", () => {
    expect(validateTOTPSeed("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")).toBe(true);
  });

  test("validateTOTPSeed rejects invalid input", () => {
    expect(validateTOTPSeed("not-valid-!!!")).toBe(false);
  });
});
