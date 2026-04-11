#!/usr/bin/env bun

import { startServer } from "./mcp/server.js";
import { validateServeEnv } from "./env.js";

/**
 * agent-auth — Zero-knowledge credential service for AI agents.
 *
 * Usage:
 *   agent-auth serve              Start MCP server (stdio)
 *   agent-auth init               Create vault with passphrase
 *   agent-auth add <service>      Add a credential (interactive)
 *   agent-auth list               List service names
 *   agent-auth remove <service>   Remove a credential
 *   agent-auth unlock             Unlock vault for session
 *   agent-auth lock               Lock vault
 */

const command = process.argv[2];

switch (command) {
  case "serve": {
    const env = validateServeEnv();

    const cdpUrl = env.AGENT_AUTH_CDP_URL;

    // Resolve passphrase: keychain first, env var fallback (dev only)
    let passphrase: Buffer | undefined;
    try {
      const { execSync } = await import("node:child_process");
      const keychainPass = execSync(
        'security find-generic-password -s "agent-auth" -a "mcp-passphrase" -w 2>/dev/null',
        { encoding: "utf-8" }
      ).trim();
      if (keychainPass) passphrase = Buffer.from(keychainPass);
    } catch {
      // Keychain unavailable — try env var as fallback
      if (env.AGENT_AUTH_PASSPHRASE) {
        passphrase = Buffer.from(env.AGENT_AUTH_PASSPHRASE);
      }
    }

    const allowedServices = env.AGENT_AUTH_ALLOWED_SERVICES
      ? new Set(env.AGENT_AUTH_ALLOWED_SERVICES.split(",").map((s) => s.trim()).filter(Boolean))
      : undefined;

    await startServer({ cdpUrl, passphrase, allowedServices });
    break;
  }

  case "init":
  case "add":
  case "list":
  case "remove":
  case "unlock":
  case "lock":
  case "domains":
  case "approve": {
    const { runCLI } = await import("./cli/commands.js");
    await runCLI(process.argv.slice(2));
    break;
  }

  default: {
    console.error(
      "Usage: agent-auth <command>\n\n" +
        "Commands:\n" +
        "  serve              Start MCP server (stdio)\n" +
        "  init               Create vault with passphrase\n" +
        "  add <service>      Add a credential\n" +
        "  list               List service names\n" +
        "  remove <service>   Remove a credential\n" +
        "  unlock             Unlock vault for session\n" +
        "  lock               Lock vault\n"
    );
    process.exit(1);
  }
}
