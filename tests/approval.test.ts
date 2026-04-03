import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { ApprovalGate } from "../src/approval/gate.ts";
import { Database } from "bun:sqlite";

describe("ApprovalGate", () => {
  let db: Database;
  let gate: ApprovalGate;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec(`
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        approved_at INTEGER NOT NULL DEFAULT (unixepoch()),
        expires_at INTEGER NOT NULL,
        UNIQUE(credential_id, domain)
      );
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    gate = new ApprovalGate(db, 3600); // 1 hour TTL for tests
  });

  afterEach(() => {
    db.close();
  });

  test("isApproved returns false when no approval exists", () => {
    expect(gate.isApproved("cred-1", "example.com")).toBe(false);
  });

  test("isApproved returns true after manual approval insert", () => {
    const now = Math.floor(Date.now() / 1000);
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      ["test-id", "cred-1", "example.com", now, now + 3600]
    );
    expect(gate.isApproved("cred-1", "example.com")).toBe(true);
  });

  test("isApproved returns false for expired approval", () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      ["test-id", "cred-1", "example.com", past - 3600, past]
    );
    expect(gate.isApproved("cred-1", "example.com")).toBe(false);
  });

  test("approve with valid code succeeds", () => {
    // Simulate a pending approval
    const id = "pending-1";
    const code = "1234";
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, 0, ?)",
      [id, "cred-1", "example.com", Math.floor(Date.now() / 1000) + 60]
    );
    db.run("INSERT INTO meta (key, value) VALUES (?, ?)", [`approval:${id}`, code]);

    const result = gate.approve("1234");
    expect(result).toBe(true);

    // Verify it's now approved
    expect(gate.isApproved("cred-1", "example.com")).toBe(true);
  });

  test("approve with wrong code fails", () => {
    const id = "pending-2";
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, 0, ?)",
      [id, "cred-1", "example.com", Math.floor(Date.now() / 1000) + 60]
    );
    db.run("INSERT INTO meta (key, value) VALUES (?, ?)", [`approval:${id}`, "5678"]);

    expect(gate.approve("0000")).toBe(false);
  });

  test("cleanup removes expired approvals", () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      ["expired", "cred-1", "example.com", past - 3600, past]
    );
    db.run(
      "INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      ["active", "cred-2", "other.com", past, Math.floor(Date.now() / 1000) + 3600]
    );

    gate.cleanup();

    const rows = db.query("SELECT id FROM approvals").all() as Array<{ id: string }>;
    expect(rows.length).toBe(1);
    expect(rows[0]!.id).toBe("active");
  });
});
