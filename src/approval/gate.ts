import { Database } from "bun:sqlite";
import { notify } from "./notify.js";

/**
 * Human approval gate.
 *
 * First use of a credential+domain pair requires human approval.
 * Subsequent uses are auto-approved until the TTL expires.
 *
 * Approval flow:
 * 1. Agent requests credential use for a domain
 * 2. Gate checks if an active approval exists
 * 3. If not: generates 4-digit code, sends Pushover notification, polls for approval
 * 4. Human approves via CLI (`agent-auth approve <code>`) or the approval auto-expires
 * 5. Approved credential+domain pair is cached for TTL (default 8 hours)
 */

const DEFAULT_TTL_SECONDS = 8 * 60 * 60; // 8 hours
const APPROVAL_TIMEOUT_MS = 50_000; // 50 seconds
const POLL_INTERVAL_MS = 2_000; // 2 seconds

export class ApprovalGate {
  private db: Database;
  private ttlSeconds: number;

  constructor(db: Database, ttlSeconds: number = DEFAULT_TTL_SECONDS) {
    this.db = db;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Check if a credential+domain pair has an active approval.
   */
  isApproved(credentialId: string, domain: string): boolean {
    const now = Math.floor(Date.now() / 1000);
    const row = this.db
      .query(
        "SELECT id FROM approvals WHERE credential_id = ? AND domain = ? AND expires_at > ?"
      )
      .get(credentialId, domain, now);

    return row !== null;
  }

  /**
   * Request approval for a credential+domain pair.
   * Sends a notification and waits for human approval.
   * Returns true if approved within the timeout.
   */
  async requestApproval(
    credentialId: string,
    service: string,
    domain: string
  ): Promise<boolean> {
    const code = this.generateCode();
    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    // Store pending approval
    this.db.run(
      `INSERT INTO approvals (id, credential_id, domain, approved_at, expires_at)
       VALUES (?, ?, ?, 0, ?)`,
      [id, credentialId, domain, now + Math.floor(APPROVAL_TIMEOUT_MS / 1000)]
    );

    // Store the approval code in meta for verification
    this.db.run(
      "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
      [`approval:${id}`, code]
    );

    // Notify human
    await notify(
      "agent-auth: Approval Required",
      `Service: ${service}\nDomain: ${domain}\nCode: ${code}\n\nRun: agent-auth approve ${code}`
    );

    // Poll for approval
    const deadline = Date.now() + APPROVAL_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const row = this.db
        .query("SELECT approved_at FROM approvals WHERE id = ?")
        .get(id) as { approved_at: number } | null;

      if (row && row.approved_at > 0) {
        // Approved — extend TTL
        this.db.run(
          "UPDATE approvals SET expires_at = ? WHERE id = ?",
          [Math.floor(Date.now() / 1000) + this.ttlSeconds, id]
        );
        // Clean up code
        this.db.run("DELETE FROM meta WHERE key = ?", [`approval:${id}`]);
        return true;
      }

      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }

    // Timed out — remove pending approval
    this.db.run("DELETE FROM approvals WHERE id = ?", [id]);
    this.db.run("DELETE FROM meta WHERE key = ?", [`approval:${id}`]);
    return false;
  }

  /**
   * Approve a pending request by code.
   * Called by the human via CLI: `agent-auth approve <code>`
   */
  approve(code: string): boolean {
    // Find the pending approval with this code
    const rows = this.db
      .query("SELECT key, value FROM meta WHERE key LIKE 'approval:%'")
      .all() as Array<{ key: string; value: string }>;

    for (const row of rows) {
      if (row.value === code) {
        const approvalId = row.key.replace("approval:", "");
        const now = Math.floor(Date.now() / 1000);

        this.db.run(
          "UPDATE approvals SET approved_at = ?, expires_at = ? WHERE id = ?",
          [now, now + this.ttlSeconds, approvalId]
        );
        this.db.run("DELETE FROM meta WHERE key = ?", [row.key]);
        return true;
      }
    }

    return false;
  }

  /**
   * Clean up expired approvals.
   */
  cleanup(): void {
    const now = Math.floor(Date.now() / 1000);
    this.db.run("DELETE FROM approvals WHERE expires_at < ?", [now]);
  }

  private generateCode(): string {
    return String(Math.floor(Math.random() * 10000)).padStart(4, "0");
  }
}
