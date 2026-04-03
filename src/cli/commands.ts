import { VaultStore } from "../vault/store.js";
import { ApprovalGate } from "../approval/gate.js";
import { validateTOTPSeed } from "../totp/totp.js";
import { validateServiceName } from "../security/validator.js";

/**
 * CLI commands for human credential management.
 * These are NEVER exposed via MCP — only accessible from the terminal.
 */

function getFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function readLine(prompt: string): string {
  process.stdout.write(prompt);
  const buf = Buffer.alloc(1024);
  const bytesRead = require("fs").readSync(0, buf, 0, 1024);
  return buf.toString("utf-8", 0, bytesRead).trim();
}

function readSecret(prompt: string): Buffer {
  // Use Bun's prompt or fall back to basic stdin
  process.stdout.write(prompt);
  const buf = Buffer.alloc(1024);
  const bytesRead = require("fs").readSync(0, buf, 0, 1024);
  const value = buf.subarray(0, bytesRead).toString("utf-8").trim();
  buf.fill(0); // Zero the read buffer
  return Buffer.from(value);
}

export async function runCLI(args: string[]): Promise<void> {
  const command = args[0];
  const vault = new VaultStore();

  try {
    switch (command) {
      case "init": {
        console.log("Initializing agent-auth vault...");
        let passphrase: Buffer;

        // Support non-interactive init via env var
        if (process.env.AGENT_AUTH_PASSPHRASE) {
          passphrase = Buffer.from(process.env.AGENT_AUTH_PASSPHRASE);
        } else {
          const pass1 = readSecret("Passphrase: ");
          const pass2 = readSecret("Confirm passphrase: ");

          if (!pass1.equals(pass2)) {
            console.error("Passphrases do not match.");
            pass1.fill(0);
            pass2.fill(0);
            process.exit(1);
          }

          pass2.fill(0);
          passphrase = pass1;
        }

        vault.init(passphrase);
        console.log("Vault created at ~/.agent-auth/vault.db");
        console.log("Master key stored in OS keychain.");
        break;
      }

      case "add": {
        const service = args[1];
        if (!service) {
          console.error("Usage: agent-auth add <service-name>");
          process.exit(1);
        }

        const nameCheck = validateServiceName(service);
        if (!nameCheck.valid) {
          console.error(`Invalid service name: ${nameCheck.reason}`);
          process.exit(1);
        }

        // Unlock vault
        if (!vault.isUnlocked()) {
          const envPass = process.env.AGENT_AUTH_PASSPHRASE;
          const pass = envPass ? Buffer.from(envPass) : readSecret("Vault passphrase: ");
          if (!vault.unlock(pass)) {
            console.error("Failed to unlock vault. Wrong passphrase?");
            process.exit(1);
          }
        }

        // Support non-interactive add via flags: --username, --password, --totp, --domains
        const flagUsername = getFlag(args, "--username");
        const flagPassword = getFlag(args, "--password");
        const flagTotp = getFlag(args, "--totp");
        const flagDomains = getFlag(args, "--domains");

        const username = flagUsername !== undefined
          ? Buffer.from(flagUsername)
          : readSecret("Username/email (or empty): ");
        const password = flagPassword !== undefined
          ? Buffer.from(flagPassword)
          : readSecret("Password (or empty): ");

        let totpSeed: Buffer | undefined;
        const totpInput = flagTotp ?? readLine("TOTP seed (base32 or otpauth:// URI, or empty): ");
        if (totpInput) {
          if (!validateTOTPSeed(totpInput)) {
            console.error("Invalid TOTP seed format.");
            process.exit(1);
          }
          totpSeed = Buffer.from(totpInput);
        }

        const domainsInput = flagDomains ?? readLine("Allowed domains (comma-separated, e.g. 'aws.amazon.com,console.aws.amazon.com'): ");
        const domains = domainsInput
          ? domainsInput.split(",").map((d) => d.trim()).filter(Boolean)
          : [];

        const flagNotes = getFlag(args, "--notes");
        const notes = flagNotes ?? (flagUsername !== undefined ? "" : readLine("Notes (optional): "));

        const id = vault.addCredential(
          service,
          {
            username: username.length > 0 ? username : undefined,
            password: password.length > 0 ? password : undefined,
            totpSeed,
          },
          { notes, allowedDomains: domains }
        );

        console.log(`Credential "${service}" added (id: ${id})`);
        if (domains.length === 0) {
          console.log("WARNING: No domains configured. This credential cannot be used until domains are set.");
          console.log(`Run: agent-auth domains ${service}`);
        }
        break;
      }

      case "list": {
        if (!vault.isUnlocked()) {
          const envPass = process.env.AGENT_AUTH_PASSPHRASE;
          const pass = envPass ? Buffer.from(envPass) : readSecret("Vault passphrase: ");
          if (!vault.unlock(pass)) {
            console.error("Failed to unlock vault.");
            process.exit(1);
          }
        }

        const creds = vault.listCredentials();
        if (creds.length === 0) {
          console.log("No credentials stored.");
        } else {
          console.log("Credentials:");
          for (const c of creds) {
            const domains = c.allowedDomains.length > 0
              ? c.allowedDomains.join(", ")
              : "(no domains)";
            console.log(`  ${c.service} — domains: ${domains}${c.notes ? ` — ${c.notes}` : ""}`);
          }
        }
        break;
      }

      case "remove": {
        const service = args[1];
        if (!service) {
          console.error("Usage: agent-auth remove <service-name>");
          process.exit(1);
        }

        if (!vault.isUnlocked()) {
          const pass = readSecret("Vault passphrase: ");
          if (!vault.unlock(pass)) {
            console.error("Failed to unlock vault.");
            process.exit(1);
          }
        }

        const confirm = readLine(`Remove credential "${service}"? (yes/no): `);
        if (confirm !== "yes") {
          console.log("Cancelled.");
          break;
        }

        if (vault.removeCredential(service)) {
          console.log(`Credential "${service}" removed.`);
        } else {
          console.error(`Credential "${service}" not found.`);
        }
        break;
      }

      case "domains": {
        const service = args[1];
        if (!service) {
          console.error("Usage: agent-auth domains <service-name>");
          process.exit(1);
        }

        if (!vault.isUnlocked()) {
          const pass = readSecret("Vault passphrase: ");
          if (!vault.unlock(pass)) {
            console.error("Failed to unlock vault.");
            process.exit(1);
          }
        }

        const current = vault.getAllowedDomains(service);
        console.log(`Current domains for "${service}": ${current.join(", ") || "(none)"}`);

        const input = readLine("New domains (comma-separated, or empty to keep): ");
        if (input) {
          const newDomains = input.split(",").map((d) => d.trim()).filter(Boolean);
          // Update domains directly in DB
          vault["db"].run(
            "UPDATE credentials SET allowed_domains = ?, updated_at = unixepoch() WHERE service = ?",
            [JSON.stringify(newDomains), service]
          );
          console.log(`Domains updated: ${newDomains.join(", ")}`);
        }
        break;
      }

      case "approve": {
        const code = args[1];
        if (!code) {
          console.error("Usage: agent-auth approve <4-digit-code>");
          process.exit(1);
        }

        const gate = new ApprovalGate(vault["db"]);
        if (gate.approve(code)) {
          console.log("Approved.");
        } else {
          console.error("Invalid or expired code.");
          process.exit(1);
        }
        break;
      }

      case "unlock": {
        const pass = readSecret("Vault passphrase: ");
        if (vault.unlock(pass)) {
          console.log("Vault unlocked.");
        } else {
          console.error("Failed to unlock vault. Wrong passphrase?");
          process.exit(1);
        }
        break;
      }

      case "lock": {
        vault.lock();
        console.log("Vault locked.");
        break;
      }

      default:
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
  } finally {
    vault.close();
  }
}
