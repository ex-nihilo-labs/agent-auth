import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { getConfigDir } from "../vault/keychain.js";

/**
 * Append-only audit logger.
 * Writes JSONL to ~/.agent-auth/audit.log
 * Credential values are NEVER logged — only service names, actions, and masked usernames.
 */

const LOG_FILE = "audit.log";

export type AuditAction =
  | "secure_login"
  | "auth_api"
  | "list_credentials"
  | "approval_requested"
  | "approval_granted"
  | "approval_denied"
  | "rate_limited"
  | "domain_blocked"
  | "vault_unlock"
  | "vault_lock"
  | "credential_added"
  | "credential_removed";

interface AuditEntry {
  timestamp: string;
  action: AuditAction;
  service?: string;
  domain?: string;
  username_masked?: string;
  success: boolean;
  error?: string;
}

function maskUsername(username: string): string {
  if (username.length <= 3) return "***";
  const atIdx = username.indexOf("@");
  if (atIdx > 0) {
    return username[0] + "***" + username.substring(atIdx);
  }
  return username[0] + "***" + username[username.length - 1];
}

export function audit(
  action: AuditAction,
  details: {
    service?: string;
    domain?: string;
    username?: string;
    success: boolean;
    error?: string;
  }
): void {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    action,
    service: details.service,
    domain: details.domain,
    username_masked: details.username ? maskUsername(details.username) : undefined,
    success: details.success,
    error: details.error?.substring(0, 500),
  };

  const dir = getConfigDir();
  const logPath = join(dir, LOG_FILE);

  try {
    appendFileSync(logPath, JSON.stringify(entry) + "\n", { mode: 0o600 });
  } catch {
    // Audit logging is best-effort — never crash the service
  }
}
