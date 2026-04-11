import { Database } from "bun:sqlite";
import { join } from "node:path";
import { chmodSync } from "node:fs";
import { encrypt, decrypt, deriveKey, zeroBuffer } from "./crypto.js";
import { getConfigDir, storeKey, loadKey } from "./keychain.js";
import { VaultError } from "../errors.js";
import { RateLimiter } from "../security/rate-limiter.js";
import { ApprovalGate } from "../approval/gate.js";

/**
 * Local encrypted vault backed by SQLite.
 * All credential fields are AES-256-GCM encrypted.
 * The vault key is derived from a passphrase via Argon2id and stored in OS keychain.
 */

const VAULT_FILE = "vault.db";
const DEFAULT_PROFILE = "default";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    service TEXT NOT NULL UNIQUE,
    username_enc TEXT,
    password_enc TEXT,
    totp_seed_enc TEXT,
    notes TEXT,
    allowed_domains TEXT DEFAULT '[]',
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    approved_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    UNIQUE(credential_id, domain)
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`;

export interface Credential {
  id: string;
  service: string;
  allowedDomains: string[];
  notes: string;
  createdAt: number;
  updatedAt: number;
}

export interface CredentialSecrets {
  username: Buffer | null;
  password: Buffer | null;
  totpSeed: Buffer | null;
}

export class VaultStore {
  private db: Database;
  private vaultKey: Buffer | null = null;
  private lastAccessAt: number = Date.now();
  private readonly idleTimeoutMs: number;

  /**
   * @param dbPath - Override vault DB path (for testing).
   * @param idleTimeoutMs - Lock vault if idle for this many ms (default: 2 hours).
   */
  constructor(dbPath?: string, idleTimeoutMs: number = 2 * 60 * 60 * 1000) {
    this.idleTimeoutMs = idleTimeoutMs;
    const path = dbPath ?? join(getConfigDir(), VAULT_FILE);
    this.db = new Database(path);
    this.db.exec("PRAGMA journal_mode=WAL;");
    this.db.exec("PRAGMA foreign_keys=ON;");
    this.db.exec(SCHEMA);

    // Set file permissions
    try {
      chmodSync(path, 0o600);
    } catch {
      // May fail on some platforms
    }
  }

  /**
   * Initialize the vault with a new passphrase.
   * Derives a key via Argon2id and stores it in the OS keychain.
   */
  init(passphrase: Buffer): void {
    const { key, salt } = deriveKey(passphrase);
    storeKey(DEFAULT_PROFILE, key, salt);
    this.vaultKey = key;

    // Store verification token and salt
    const token = encrypt(key, Buffer.from("agent-auth-vault-v1"));
    this.db.run(
      "INSERT OR REPLACE INTO meta (key, value) VALUES ('verify_token', ?)",
      [token]
    );
    this.db.run(
      "INSERT OR REPLACE INTO meta (key, value) VALUES ('salt', ?)",
      [salt.toString("base64")]
    );

    zeroBuffer(passphrase);
  }

  private touchAccess(): void {
    this.lastAccessAt = Date.now();
  }

  /**
   * Unlock the vault directly with a pre-derived key (e.g. loaded from OS keychain).
   * Preferred over unlock(passphrase) for unattended server startup — no passphrase in memory.
   */
  unlockWithKey(derivedKey: Buffer): boolean {
    if (!this.verifyKey(derivedKey)) {
      zeroBuffer(derivedKey);
      return false;
    }
    this.vaultKey = derivedKey;
    this.touchAccess();
    return true;
  }

  /**
   * Unlock the vault with a passphrase.
   * Derives the key and verifies it against the stored token.
   */
  unlock(passphrase: Buffer): boolean {
    // Resolve salt: try keychain first, then DB fallback
    let salt: Buffer | null = null;

    const stored = loadKey(DEFAULT_PROFILE);
    if (stored?.salt) {
      salt = stored.salt;
    } else {
      // Keychain unavailable — read salt from DB
      const row = this.db.query("SELECT value FROM meta WHERE key = 'salt'").get() as
        | { value: string }
        | null;
      if (row) salt = Buffer.from(row.value, "base64");
    }

    if (!salt) {
      zeroBuffer(passphrase);
      return false;
    }

    const { key } = deriveKey(passphrase, salt);
    zeroBuffer(passphrase);

    if (!this.verifyKey(key)) {
      zeroBuffer(key);
      return false;
    }

    this.vaultKey = key;
    this.touchAccess();
    return true;
  }

  /**
   * Lock the vault — zero the key from memory.
   */
  lock(): void {
    if (this.vaultKey) {
      zeroBuffer(this.vaultKey);
      this.vaultKey = null;
    }
  }

  isUnlocked(): boolean {
    return this.vaultKey !== null;
  }

  /**
   * Returns true if the vault is unlocked but has been idle past the timeout.
   * The server's periodic cleanup should call lock() when this returns true.
   */
  isIdleLockoutDue(): boolean {
    return this.vaultKey !== null && Date.now() - this.lastAccessAt > this.idleTimeoutMs;
  }

  /** Create a RateLimiter backed by this vault's database. */
  createRateLimiter(): RateLimiter {
    return new RateLimiter(this.db);
  }

  /** Create an ApprovalGate backed by this vault's database. */
  createApprovalGate(ttlSeconds?: number): ApprovalGate {
    return new ApprovalGate(this.db, ttlSeconds);
  }

  /**
   * Add a credential to the vault.
   * All secret fields are encrypted before storage.
   */
  addCredential(
    service: string,
    secrets: {
      username?: Buffer;
      password?: Buffer;
      totpSeed?: Buffer;
    },
    options?: {
      notes?: string;
      allowedDomains?: string[];
    }
  ): string {
    this.requireUnlocked();

    const id = crypto.randomUUID();
    const key = this.vaultKey!;

    const usernameEnc = secrets.username ? encrypt(key, secrets.username) : null;
    const passwordEnc = secrets.password ? encrypt(key, secrets.password) : null;
    const totpSeedEnc = secrets.totpSeed ? encrypt(key, secrets.totpSeed) : null;

    this.db.run(
      `INSERT INTO credentials (id, service, username_enc, password_enc, totp_seed_enc, notes, allowed_domains)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        service,
        usernameEnc,
        passwordEnc,
        totpSeedEnc,
        options?.notes ?? "",
        JSON.stringify(options?.allowedDomains ?? []),
      ]
    );

    // Zero input buffers
    if (secrets.username) zeroBuffer(secrets.username);
    if (secrets.password) zeroBuffer(secrets.password);
    if (secrets.totpSeed) zeroBuffer(secrets.totpSeed);

    return id;
  }

  /**
   * List credentials — service names and metadata only, no secrets.
   */
  listCredentials(): Credential[] {
    const rows = this.db
      .query(
        "SELECT id, service, notes, allowed_domains, created_at, updated_at FROM credentials ORDER BY service"
      )
      .all() as Array<{
      id: string;
      service: string;
      notes: string;
      allowed_domains: string;
      created_at: number;
      updated_at: number;
    }>;

    return rows.map((r) => ({
      id: r.id,
      service: r.service,
      allowedDomains: JSON.parse(r.allowed_domains),
      notes: r.notes,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }));
  }

  /**
   * Resolve secrets for a credential.
   * Returns Buffers — caller MUST zero them after use.
   */
  resolveSecrets(service: string): CredentialSecrets | null {
    this.requireUnlocked();
    this.touchAccess();

    const row = this.db
      .query(
        "SELECT username_enc, password_enc, totp_seed_enc FROM credentials WHERE service = ?"
      )
      .get(service) as {
      username_enc: string | null;
      password_enc: string | null;
      totp_seed_enc: string | null;
    } | null;

    if (!row) return null;

    const key = this.vaultKey!;

    return {
      username: row.username_enc ? decrypt(key, row.username_enc) : null,
      password: row.password_enc ? decrypt(key, row.password_enc) : null,
      totpSeed: row.totp_seed_enc ? decrypt(key, row.totp_seed_enc) : null,
    };
  }

  /**
   * Get allowed domains for a credential.
   */
  getAllowedDomains(service: string): string[] {
    const row = this.db
      .query("SELECT allowed_domains FROM credentials WHERE service = ?")
      .get(service) as { allowed_domains: string } | null;

    if (!row) return [];
    return JSON.parse(row.allowed_domains);
  }

  /**
   * Remove a credential from the vault.
   */
  removeCredential(service: string): boolean {
    const result = this.db.run(
      "DELETE FROM credentials WHERE service = ?",
      [service]
    );
    return result.changes > 0;
  }

  close(): void {
    this.lock();
    this.db.close();
  }

  private verifyKey(key: Buffer): boolean {
    const row = this.db
      .query("SELECT value FROM meta WHERE key = 'verify_token'")
      .get() as { value: string } | null;

    if (!row) return false;

    try {
      const plaintext = decrypt(key, row.value);
      const valid = plaintext.toString("utf-8") === "agent-auth-vault-v1";
      zeroBuffer(plaintext);
      return valid;
    } catch {
      return false;
    }
  }

  private requireUnlocked(): void {
    if (!this.vaultKey) {
      throw new VaultError("locked", "Vault is locked. Call unlock() first.");
    }
  }
}
