import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";

/**
 * Master key storage with OS keychain support and encrypted file fallback.
 *
 * Priority:
 * 1. macOS Keychain (via `security` CLI)
 * 2. Linux Secret Service (via `secret-tool` CLI)
 * 3. Encrypted file fallback (~/.agent-auth/keyring.json, mode 0600)
 *
 * No `keytar` dependency — it's dead (Feb 2022). Shell-out to native CLI tools instead.
 */

const SERVICE_NAME = "agent-auth";
const CONFIG_DIR = join(homedir(), ".agent-auth");
const KEYRING_FILE = join(CONFIG_DIR, "keyring.json");

type KeyringBackend = "macos-keychain" | "linux-secret-tool" | "file";

interface KeyringEntry {
  key: string; // Base64-encoded encrypted master key
  salt: string; // Base64-encoded Argon2id salt
}

function detectBackend(): KeyringBackend {
  // Skip native keychain in tests to avoid macOS permission dialogs
  if (process.env.AGENT_AUTH_NO_KEYCHAIN) return "file";

  if (process.platform === "darwin") {
    try {
      execSync("which security", { stdio: "ignore" });
      return "macos-keychain";
    } catch {
      // Fall through
    }
  }

  if (process.platform === "linux") {
    try {
      execSync("which secret-tool", { stdio: "ignore" });
      // Functional test: secret-tool needs a D-Bus session
      if (!process.env.WSL_DISTRO_NAME && process.env.DISPLAY) {
        return "linux-secret-tool";
      }
    } catch {
      // Fall through
    }
  }

  return "file";
}

function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

function readFileKeyring(): Record<string, KeyringEntry> {
  ensureConfigDir();
  if (!existsSync(KEYRING_FILE)) return {};
  const raw = readFileSync(KEYRING_FILE, "utf-8");
  return JSON.parse(raw);
}

function writeFileKeyring(data: Record<string, KeyringEntry>): void {
  ensureConfigDir();
  writeFileSync(KEYRING_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
  chmodSync(KEYRING_FILE, 0o600);
}

export function storeKey(profile: string, key: Buffer, salt: Buffer): void {
  const account = `${SERVICE_NAME}:${profile}`;
  const keyB64 = key.toString("base64");
  const saltB64 = salt.toString("base64");
  const combined = JSON.stringify({ key: keyB64, salt: saltB64 });

  const backend = detectBackend();

  switch (backend) {
    case "macos-keychain": {
      try {
        // Delete existing entry if present
        execSync(
          `security delete-generic-password -s "${SERVICE_NAME}" -a "${account}" 2>/dev/null || true`,
          { stdio: "ignore" }
        );
        execSync(
          `security add-generic-password -s "${SERVICE_NAME}" -a "${account}" -w "${keyB64}" -T ""`,
          { stdio: "ignore" }
        );
        // Store salt in file (salt is not secret)
        const keyring = readFileKeyring();
        keyring[profile] = { key: "keychain", salt: saltB64 };
        writeFileKeyring(keyring);
        return;
      } catch {
        // Fall through to file backend
      }
      break;
    }

    case "linux-secret-tool": {
      try {
        execSync(
          `echo -n "${keyB64}" | secret-tool store --label="${SERVICE_NAME}" service "${SERVICE_NAME}" account "${account}"`,
          { stdio: "ignore" }
        );
        const keyring = readFileKeyring();
        keyring[profile] = { key: "keychain", salt: saltB64 };
        writeFileKeyring(keyring);
        return;
      } catch {
        // Fall through to file backend
      }
      break;
    }
  }

  // File fallback
  const keyring = readFileKeyring();
  keyring[profile] = { key: keyB64, salt: saltB64 };
  writeFileKeyring(keyring);
}

export function loadKey(
  profile: string
): { key: Buffer; salt: Buffer } | null {
  const account = `${SERVICE_NAME}:${profile}`;
  const keyring = readFileKeyring();
  const entry = keyring[profile];

  if (!entry) return null;

  const salt = Buffer.from(entry.salt, "base64");

  if (entry.key === "keychain") {
    const backend = detectBackend();

    if (backend === "macos-keychain") {
      try {
        const result = execSync(
          `security find-generic-password -s "${SERVICE_NAME}" -a "${account}" -w`,
          { encoding: "utf-8" }
        ).trim();
        return { key: Buffer.from(result, "base64"), salt };
      } catch {
        return null;
      }
    }

    if (backend === "linux-secret-tool") {
      try {
        const result = execSync(
          `secret-tool lookup service "${SERVICE_NAME}" account "${account}"`,
          { encoding: "utf-8" }
        ).trim();
        return { key: Buffer.from(result, "base64"), salt };
      } catch {
        return null;
      }
    }

    return null; // Keychain entry but no keychain available
  }

  return { key: Buffer.from(entry.key, "base64"), salt };
}

export function deleteKey(profile: string): void {
  const account = `${SERVICE_NAME}:${profile}`;
  const backend = detectBackend();

  if (backend === "macos-keychain") {
    execSync(
      `security delete-generic-password -s "${SERVICE_NAME}" -a "${account}" 2>/dev/null || true`,
      { stdio: "ignore" }
    );
  } else if (backend === "linux-secret-tool") {
    execSync(
      `secret-tool clear service "${SERVICE_NAME}" account "${account}" 2>/dev/null || true`,
      { stdio: "ignore" }
    );
  }

  const keyring = readFileKeyring();
  delete keyring[profile];
  writeFileKeyring(keyring);
}

export function getConfigDir(): string {
  ensureConfigDir();
  return CONFIG_DIR;
}
