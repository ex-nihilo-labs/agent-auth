import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { VaultStore } from "../src/vault/store.ts";
import { unlinkSync, existsSync } from "node:fs";

const TEST_DB = "/tmp/agent-auth-test-vault.db";

// Force file-only keychain backend in tests (no macOS Keychain dialogs)
process.env.AGENT_AUTH_NO_KEYCHAIN = "1";

describe("VaultStore", () => {
  let vault: VaultStore;

  beforeEach(() => {
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
    vault = new VaultStore(TEST_DB);
  });

  afterEach(() => {
    vault.close();
    if (existsSync(TEST_DB)) unlinkSync(TEST_DB);
  });

  test("init creates vault and unlocks it", () => {
    vault.init(Buffer.from("passphrase"));
    expect(vault.isUnlocked()).toBe(true);
  });

  test("lock/unlock cycle", () => {
    vault.init(Buffer.from("passphrase"));
    vault.lock();
    expect(vault.isUnlocked()).toBe(false);

    const ok = vault.unlock(Buffer.from("passphrase"));
    expect(ok).toBe(true);
    expect(vault.isUnlocked()).toBe(true);
  });

  test("unlock with wrong passphrase fails", () => {
    vault.init(Buffer.from("correct"));
    vault.lock();

    const ok = vault.unlock(Buffer.from("wrong"));
    expect(ok).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
  });

  test("addCredential and listCredentials", () => {
    vault.init(Buffer.from("pass"));

    vault.addCredential("aws-root", {
      username: Buffer.from("admin@example.com"),
      password: Buffer.from("secret123"),
    }, {
      notes: "test",
      allowedDomains: ["aws.amazon.com"],
    });

    const list = vault.listCredentials();
    expect(list.length).toBe(1);
    expect(list[0]!.service).toBe("aws-root");
    expect(list[0]!.allowedDomains).toEqual(["aws.amazon.com"]);
    expect(list[0]!.notes).toBe("test");
  });

  test("listCredentials never exposes secrets", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("test-service", {
      username: Buffer.from("user"),
      password: Buffer.from("MySecretPassword"),
      totpSeed: Buffer.from("JBSWY3DPEHPK3PXP"),
    });

    const list = vault.listCredentials();
    const json = JSON.stringify(list);
    expect(json).not.toContain("MySecretPassword");
    expect(json).not.toContain("JBSWY3DPEHPK3PXP");
  });

  test("resolveSecrets returns decrypted Buffers", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("svc", {
      username: Buffer.from("user@example.com"),
      password: Buffer.from("p@ssw0rd!"),
      totpSeed: Buffer.from("JBSWY3DPEHPK3PXP"),
    });

    const secrets = vault.resolveSecrets("svc");
    expect(secrets).not.toBeNull();
    expect(secrets!.username!.toString("utf-8")).toBe("user@example.com");
    expect(secrets!.password!.toString("utf-8")).toBe("p@ssw0rd!");
    expect(secrets!.totpSeed!.toString("utf-8")).toBe("JBSWY3DPEHPK3PXP");

    // Returned values are Buffers, not strings
    expect(Buffer.isBuffer(secrets!.username)).toBe(true);
    expect(Buffer.isBuffer(secrets!.password)).toBe(true);
  });

  test("resolveSecrets returns null for unknown service", () => {
    vault.init(Buffer.from("pass"));
    expect(vault.resolveSecrets("nonexistent")).toBeNull();
  });

  test("resolveSecrets throws when locked", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("svc", { password: Buffer.from("x") });
    vault.lock();
    expect(() => vault.resolveSecrets("svc")).toThrow("Vault is locked");
  });

  test("removeCredential", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("to-remove", { password: Buffer.from("x") });
    expect(vault.listCredentials().length).toBe(1);

    const removed = vault.removeCredential("to-remove");
    expect(removed).toBe(true);
    expect(vault.listCredentials().length).toBe(0);
  });

  test("removeCredential returns false for unknown", () => {
    vault.init(Buffer.from("pass"));
    expect(vault.removeCredential("nope")).toBe(false);
  });

  test("getAllowedDomains", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("svc", { password: Buffer.from("x") }, {
      allowedDomains: ["a.com", "b.com"],
    });
    expect(vault.getAllowedDomains("svc")).toEqual(["a.com", "b.com"]);
    expect(vault.getAllowedDomains("unknown")).toEqual([]);
  });

  test("addCredential with optional fields", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("minimal", { password: Buffer.from("x") });

    const secrets = vault.resolveSecrets("minimal");
    expect(secrets!.username).toBeNull();
    expect(secrets!.totpSeed).toBeNull();
    expect(secrets!.password!.toString("utf-8")).toBe("x");
  });

  test("multiple credentials", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("aws", { password: Buffer.from("a") });
    vault.addCredential("github", { password: Buffer.from("b") });
    vault.addCredential("stripe", { password: Buffer.from("c") });

    expect(vault.listCredentials().length).toBe(3);
    expect(vault.resolveSecrets("github")!.password!.toString("utf-8")).toBe("b");
  });

  test("duplicate service name throws", () => {
    vault.init(Buffer.from("pass"));
    vault.addCredential("dup", { password: Buffer.from("a") });
    expect(() => vault.addCredential("dup", { password: Buffer.from("b") })).toThrow();
  });
});
