import { describe, test, expect } from "bun:test";
import { resolvePlaceholders, hasPlaceholders, cleanupResolved } from "../src/placeholder/resolver.ts";
import type { CredentialSecrets } from "../src/vault/store.ts";

function makeSecrets(overrides?: Partial<CredentialSecrets>): CredentialSecrets {
  return {
    username: Buffer.from("user@test.com"),
    password: Buffer.from("s3cret!"),
    totpSeed: Buffer.from("JBSWY3DPEHPK3PXP"),
    ...overrides,
  };
}

describe("placeholder resolver", () => {
  test("resolves {{email}} to username", () => {
    const r = resolvePlaceholders("{{email}}", makeSecrets());
    expect(r.value).toBe("user@test.com");
    cleanupResolved(r);
  });

  test("resolves {{username}} to username", () => {
    const r = resolvePlaceholders("{{username}}", makeSecrets());
    expect(r.value).toBe("user@test.com");
    cleanupResolved(r);
  });

  test("resolves {{password}}", () => {
    const r = resolvePlaceholders("{{password}}", makeSecrets());
    expect(r.value).toBe("s3cret!");
    cleanupResolved(r);
  });

  test("resolves {{totp}} to 6-digit code", () => {
    const r = resolvePlaceholders("{{totp}}", makeSecrets());
    expect(r.value).toMatch(/^\d{6}$/);
    cleanupResolved(r);
  });

  test("leaves non-placeholder text unchanged", () => {
    const r = resolvePlaceholders("hello world", makeSecrets());
    expect(r.value).toBe("hello world");
    cleanupResolved(r);
  });

  test("resolves multiple placeholders", () => {
    const r = resolvePlaceholders("user={{email}}&pass={{password}}", makeSecrets());
    expect(r.value).toContain("user@test.com");
    expect(r.value).toContain("s3cret!");
    cleanupResolved(r);
  });

  test("throws on missing password", () => {
    expect(() =>
      resolvePlaceholders("{{password}}", makeSecrets({ password: null }))
    ).toThrow("No password stored");
  });

  test("throws on missing username", () => {
    expect(() =>
      resolvePlaceholders("{{email}}", makeSecrets({ username: null }))
    ).toThrow("No username/email stored");
  });

  test("throws on missing TOTP seed", () => {
    expect(() =>
      resolvePlaceholders("{{totp}}", makeSecrets({ totpSeed: null }))
    ).toThrow("No TOTP seed stored");
  });

  test("hasPlaceholders detects placeholders", () => {
    expect(hasPlaceholders("{{password}}")).toBe(true);
    expect(hasPlaceholders("hello {{email}} world")).toBe(true);
    expect(hasPlaceholders("no placeholders here")).toBe(false);
    expect(hasPlaceholders("{{invalid}}")).toBe(false);
  });

  test("cleanupResolved zeroes buffers", () => {
    const secrets = makeSecrets();
    const r = resolvePlaceholders("{{email}}", secrets);
    cleanupResolved(r);
    // After cleanup, buffers should be zeroed
    for (const buf of r.buffersToZero) {
      expect(buf.every((b) => b === 0)).toBe(true);
    }
  });
});
