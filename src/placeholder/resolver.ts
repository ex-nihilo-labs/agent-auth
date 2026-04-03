import type { VaultStore, CredentialSecrets } from "../vault/store.js";
import { generateTOTP } from "../totp/totp.js";
import { zeroBuffer } from "../vault/crypto.js";
import { CredentialError } from "../errors.js";

/**
 * Placeholder resolver.
 * Replaces {{email}}, {{username}}, {{password}}, {{totp}} in step values
 * with actual credential data from the vault.
 *
 * Resolved values are Buffer-based and zeroed after injection.
 * The agent never sees the resolved values — only the MCP server does.
 */

const PLACEHOLDER_RE = /\{\{(email|username|password|totp)\}\}/g;

export interface ResolvedValue {
  /** The resolved string value. Caller MUST zero the backing buffer after use. */
  value: string;
  /** Buffers to zero after the value is consumed */
  buffersToZero: Buffer[];
}

/**
 * Resolve all placeholders in a string.
 * Returns the resolved string and a list of buffers that must be zeroed after use.
 */
export function resolvePlaceholders(
  template: string,
  secrets: CredentialSecrets
): ResolvedValue {
  const buffersToZero: Buffer[] = [];
  let result = template;

  // Collect all matches first to avoid regex state issues
  const matches = [...template.matchAll(PLACEHOLDER_RE)];

  for (const match of matches) {
    const placeholder = match[1];
    let replacement: string;

    switch (placeholder) {
      case "email":
      case "username": {
        const buf = secrets.username;
        if (!buf) {
          throw new CredentialError("missing_username", "No username/email stored for this credential");
        }
        replacement = buf.toString("utf-8");
        // Don't zero username yet — may be referenced multiple times
        break;
      }

      case "password": {
        const buf = secrets.password;
        if (!buf) {
          throw new CredentialError("missing_password", "No password stored for this credential");
        }
        replacement = buf.toString("utf-8");
        break;
      }

      case "totp": {
        const seed = secrets.totpSeed;
        if (!seed) {
          throw new CredentialError("missing_totp", "No TOTP seed stored for this credential");
        }
        // generateTOTP zeros the seed buffer internally
        // We need a copy since the seed may be used again
        const seedCopy = Buffer.from(seed);
        replacement = generateTOTP(seedCopy);
        // seedCopy is already zeroed by generateTOTP
        break;
      }

      default:
        throw new CredentialError("unknown_placeholder", `Unknown placeholder: {{${placeholder}}}`);
    }

    result = result.replace(match[0], replacement);
  }

  // Track all secret buffers for cleanup
  if (secrets.username) buffersToZero.push(secrets.username);
  if (secrets.password) buffersToZero.push(secrets.password);
  if (secrets.totpSeed) buffersToZero.push(secrets.totpSeed);

  return { value: result, buffersToZero };
}

/**
 * Check if a string contains any credential placeholders.
 */
export function hasPlaceholders(value: string): boolean {
  // Create fresh regex to avoid stateful lastIndex from the global regex
  return /\{\{(email|username|password|totp)\}\}/.test(value);
}

/**
 * Zero all buffers from a resolved value.
 * Call this immediately after the value has been injected.
 */
export function cleanupResolved(resolved: ResolvedValue): void {
  for (const buf of resolved.buffersToZero) {
    zeroBuffer(buf);
  }
}
