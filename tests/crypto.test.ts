import { describe, test, expect } from "bun:test";
import { deriveKey, encrypt, decrypt, zeroBuffer } from "../src/vault/crypto.ts";

describe("crypto", () => {
  test("deriveKey produces 32-byte key and salt", () => {
    const { key, salt } = deriveKey(Buffer.from("test-passphrase"));
    expect(key.length).toBe(32);
    expect(salt.length).toBe(32);
    zeroBuffer(key);
  });

  test("deriveKey with same salt produces same key", () => {
    const salt = Buffer.from("a".repeat(32));
    const { key: k1 } = deriveKey(Buffer.from("passphrase"), salt);
    const { key: k2 } = deriveKey(Buffer.from("passphrase"), Buffer.from(salt));
    expect(k1.equals(k2)).toBe(true);
    zeroBuffer(k1);
    zeroBuffer(k2);
  });

  test("deriveKey with different passphrase produces different key", () => {
    const salt = Buffer.from("b".repeat(32));
    const { key: k1 } = deriveKey(Buffer.from("pass1"), salt);
    const { key: k2 } = deriveKey(Buffer.from("pass2"), Buffer.from(salt));
    expect(k1.equals(k2)).toBe(false);
    zeroBuffer(k1);
    zeroBuffer(k2);
  });

  test("encrypt/decrypt round-trip", () => {
    const { key } = deriveKey(Buffer.from("test"));
    const plaintext = Buffer.from("my-secret-password");
    const encrypted = encrypt(key, plaintext);
    const decrypted = decrypt(key, encrypted);
    expect(decrypted.toString("utf-8")).toBe("my-secret-password");
    zeroBuffer(key);
    zeroBuffer(decrypted);
  });

  test("encrypt produces different ciphertext each time (random nonce)", () => {
    const { key } = deriveKey(Buffer.from("test"));
    const plaintext = Buffer.from("same-input");
    const e1 = encrypt(key, Buffer.from(plaintext));
    const e2 = encrypt(key, Buffer.from(plaintext));
    expect(e1).not.toBe(e2);
    // But both decrypt to same value
    expect(decrypt(key, e1).toString("utf-8")).toBe("same-input");
    expect(decrypt(key, e2).toString("utf-8")).toBe("same-input");
    zeroBuffer(key);
  });

  test("decrypt with wrong key throws", () => {
    const { key: k1 } = deriveKey(Buffer.from("key1"));
    const { key: k2 } = deriveKey(Buffer.from("key2"));
    const encrypted = encrypt(k1, Buffer.from("secret"));
    expect(() => decrypt(k2, encrypted)).toThrow();
    zeroBuffer(k1);
    zeroBuffer(k2);
  });

  test("decrypt with tampered ciphertext throws", () => {
    const { key } = deriveKey(Buffer.from("test"));
    const encrypted = encrypt(key, Buffer.from("secret"));
    // Flip a byte in the middle
    const buf = Buffer.from(encrypted, "base64");
    buf[buf.length - 20] ^= 0xff;
    const tampered = buf.toString("base64");
    expect(() => decrypt(key, tampered)).toThrow();
    zeroBuffer(key);
  });

  test("decrypt with too-short envelope throws", () => {
    const { key } = deriveKey(Buffer.from("test"));
    expect(() => decrypt(key, Buffer.from("short").toString("base64"))).toThrow(
      "Invalid encrypted envelope"
    );
    zeroBuffer(key);
  });

  test("zeroBuffer actually zeroes", () => {
    const buf = Buffer.from("sensitive-data");
    expect(buf.every((b) => b === 0)).toBe(false);
    zeroBuffer(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  test("encrypt handles empty plaintext", () => {
    const { key } = deriveKey(Buffer.from("test"));
    const encrypted = encrypt(key, Buffer.from(""));
    const decrypted = decrypt(key, encrypted);
    expect(decrypted.toString("utf-8")).toBe("");
    zeroBuffer(key);
    zeroBuffer(decrypted);
  });

  test("encrypt handles large plaintext", () => {
    const { key } = deriveKey(Buffer.from("test"));
    const large = Buffer.alloc(100_000, "x");
    const encrypted = encrypt(key, large);
    const decrypted = decrypt(key, encrypted);
    expect(decrypted.length).toBe(100_000);
    expect(decrypted.every((b) => b === "x".charCodeAt(0))).toBe(true);
    zeroBuffer(key);
    zeroBuffer(decrypted);
  });
});
