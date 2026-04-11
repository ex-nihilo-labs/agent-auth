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

    // Unlock strategy (in order):
    // 1. Derived key from OS keychain — preferred; no passphrase ever in memory
    // 2. AGENT_AUTH_PASSPHRASE env var — dev/CI fallback only
    let derivedKey: Buffer | undefined;
    let passphrase: Buffer | undefined;

    const { loadKey } = await import("./vault/keychain.js");
    const loaded = loadKey("default");
    if (loaded?.key) {
      derivedKey = loaded.key;
    } else if (env.AGENT_AUTH_PASSPHRASE) {
      passphrase = Buffer.from(env.AGENT_AUTH_PASSPHRASE);
    }

    const allowedServices = env.AGENT_AUTH_ALLOWED_SERVICES
      ? new Set(env.AGENT_AUTH_ALLOWED_SERVICES.split(",").map((s) => s.trim()).filter(Boolean))
      : undefined;

    const noApproval = !!env.AGENT_AUTH_NO_APPROVAL;

    await startServer({ cdpUrl, derivedKey, passphrase, allowedServices, noApproval });
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
