import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { VaultStore } from "../vault/store.js";
import { BrowserInjector } from "../browser/injector.js";
import { resolvePlaceholders, hasPlaceholders } from "../placeholder/resolver.js";
import { isDomainAllowed } from "../security/domains.js";
import { validateServiceName } from "../security/validator.js";
import { audit } from "../audit/logger.js";
import { zeroBuffer } from "../vault/crypto.js";
import { proxyRequest } from "../proxy/proxy.js";
import { BrowserSteps, type BrowserStep } from "../browser/steps.js";
import type { ApprovalGate } from "../approval/gate.js";

/**
 * agent-auth MCP server.
 *
 * Three tools for AI agents:
 * - secure_login: Browser-based credential injection via CDP
 * - auth_api: HTTP request with credential injection
 * - list_credentials: Service names only (no secrets)
 *
 * The agent NEVER receives credential values.
 */

/** Shorthand for MCP tool responses. */
function reply(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

/**
 * Common guard checks shared by secure_login and auth_api.
 * Returns an error response string if any check fails, null if all pass.
 */
function guardChecks(
  vault: VaultStore,
  rateLimiter: ReturnType<VaultStore["createRateLimiter"]>,
  toolName: string,
  service: string,
  url: string,
  allowedServices: Set<string> | null,
): string | null {
  const rateCheck = rateLimiter.check(toolName);
  if (!rateCheck.allowed) {
    audit("rate_limited", { service, success: false });
    return `Rate limited. Retry after ${rateCheck.retryAfter}s.`;
  }

  const nameCheck = validateServiceName(service);
  if (!nameCheck.valid) return `Invalid service name: ${nameCheck.reason}`;

  if (!vault.isUnlocked()) return "Vault is locked. Human must unlock first.";

  // Scope check: is this service available to this server instance?
  if (allowedServices !== null && !allowedServices.has(service)) {
    audit("service_blocked", { service, success: false });
    return `Service "${service}" is not available to this instance.`;
  }

  const allowedDomains = vault.getAllowedDomains(service);
  if (!isDomainAllowed(url, allowedDomains)) {
    audit("domain_blocked", { service, domain: url, success: false });
    return `Domain not in allowlist for "${service}". Allowed: ${allowedDomains.join(", ") || "(none)"}`;
  }

  return null;
}

async function checkApproval(
  vault: VaultStore,
  approvalGate: ApprovalGate,
  service: string,
  url: string,
): Promise<string | null> {
  const cred = vault.listCredentials().find((c) => c.service === service);
  const hostname = new URL(url).hostname;

  if (cred && !approvalGate.isApproved(cred.id, hostname)) {
    audit("approval_requested", { service, domain: url, success: true });
    const approved = await approvalGate.requestApproval(cred.id, service, hostname);
    if (!approved) {
      audit("approval_denied", { service, domain: url, success: false });
      return "Approval timed out or denied by human.";
    }
    audit("approval_granted", { service, domain: url, success: true });
  }

  return null;
}

export async function startServer(config: {
  cdpUrl?: string;
  passphrase?: Buffer;
  allowedServices?: Set<string>;
}): Promise<void> {
  const vault = new VaultStore();

  if (config.passphrase) {
    if (!vault.unlock(config.passphrase)) {
      console.error("Failed to unlock vault");
      process.exit(1);
    }
  }

  const rateLimiter = vault.createRateLimiter();
  const approvalGate = vault.createApprovalGate();
  const injector = config.cdpUrl ? new BrowserInjector({ cdpUrl: config.cdpUrl }) : null;
  const allowedServices = config.allowedServices ?? null; // null = unrestricted

  const cleanupInterval = setInterval(() => {
    approvalGate.cleanup();
    if (vault.isIdleLockoutDue()) {
      vault.lock();
      audit("vault_idle_locked", { success: true });
    }
  }, 60_000);
  process.on("exit", () => clearInterval(cleanupInterval));

  const server = new McpServer({ name: "agent-auth", version: "0.1.0" });

  // --- secure_login ---
  server.tool(
    "secure_login",
    "Authenticate to a website by injecting credentials into browser forms. " +
      "The agent provides steps with {{placeholder}} values. " +
      "Credentials are resolved locally and injected via browser automation. " +
      "The agent NEVER sees the actual credential values.",
    {
      service: z.string().describe("Credential service name (e.g. 'aws-root')"),
      url: z.string().url().describe("Target URL to navigate to"),
      steps: BrowserSteps.describe("Browser steps with {{placeholder}} values"),
    },
    async (args) => {
      const guardError = guardChecks(vault, rateLimiter, "secure_login", args.service, args.url, allowedServices);
      if (guardError) return reply(guardError);

      if (!injector) return reply("Browser injector not configured. Set CDP_URL.");

      const approvalError = await checkApproval(vault, approvalGate, args.service, args.url);
      if (approvalError) return reply(approvalError);

      const secrets = vault.resolveSecrets(args.service);
      if (!secrets) return reply(`Credential "${args.service}" not found in vault.`);

      try {
        await injector.connect();

        const resolvedSteps: BrowserStep[] = [];
        const buffersToCleanup: Buffer[] = [];

        for (const step of args.steps) {
          if ("value" in step && step.value && hasPlaceholders(step.value)) {
            const r = resolvePlaceholders(step.value, secrets);
            resolvedSteps.push({ ...step, value: r.value } as BrowserStep);
            buffersToCleanup.push(...r.buffersToZero);
          } else {
            resolvedSteps.push({ ...step } as BrowserStep);
          }
        }

        const result = await injector.execute(resolvedSteps, args.url);

        const allowedDomains = vault.getAllowedDomains(args.service);
        if (!isDomainAllowed(result.finalUrl, allowedDomains)) {
          audit("domain_blocked", { service: args.service, domain: result.finalUrl, success: false, error: "Redirect to unauthorized domain" });
          return reply(`Aborted: page redirected to unauthorized domain: ${new URL(result.finalUrl).hostname}`);
        }

        for (const buf of buffersToCleanup) zeroBuffer(buf);
        audit("secure_login", { service: args.service, domain: args.url, success: true });
        // Strip query params — credentials injected as query params would otherwise leak here.
        const safeUrl = (() => { try { const u = new URL(result.finalUrl); return `${u.origin}${u.pathname}`; } catch { return "(unknown)"; } })();
        return reply(`Login completed for "${args.service}". Final URL: ${safeUrl}`);
      } catch (error) {
        const msg = error instanceof Error ? error.message : "Unknown error";
        audit("secure_login", { service: args.service, domain: args.url, success: false, error: msg });
        return reply(`Login failed: ${msg}`);
      } finally {
        await injector.disconnect();
        if (secrets.username) zeroBuffer(secrets.username);
        if (secrets.password) zeroBuffer(secrets.password);
        if (secrets.totpSeed) zeroBuffer(secrets.totpSeed);
      }
    }
  );

  // --- list_credentials ---
  server.tool(
    "list_credentials",
    "List available credential service names. Returns names and allowed domains only — never passwords, TOTP seeds, or API keys.",
    {},
    async () => {
      if (!vault.isUnlocked()) return reply("Vault is locked.");

      const credentials = vault.listCredentials()
        .filter((c) => allowedServices === null || allowedServices.has(c.service));
      audit("list_credentials", { success: true });

      if (credentials.length === 0) {
        return reply("No credentials stored. Use `agent-auth add <service>` to add one.");
      }

      const lines = credentials.map(
        (c) => `- ${c.service} (domains: ${c.allowedDomains.join(", ") || "none configured"})`
      );
      return reply(`Available credentials:\n${lines.join("\n")}`);
    }
  );

  // --- auth_api ---
  server.tool(
    "auth_api",
    "Make an authenticated HTTP API call. Credentials are injected at the transport layer — " +
      "the agent sends the request details and receives only the API response. " +
      "Credential values never appear in the response (echoed values are redacted).",
    {
      service: z.string().describe("Credential service name"),
      url: z.string().describe("Target API URL"),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
      headers: z.record(z.string(), z.string()).optional().describe("Request headers"),
      body: z.string().optional().describe("Request body"),
      injection: z
        .enum(["bearer", "header", "query", "basic", "json_body", "form"])
        .default("bearer")
        .describe("How to inject the credential"),
      headerName: z.string().optional().describe("Header name (for 'header' injection)"),
      queryParam: z.string().optional().describe("Query param name (for 'query' injection)"),
      jsonField: z.string().optional().describe("JSON field (for 'json_body' injection)"),
    },
    async (args) => {
      const guardError = guardChecks(vault, rateLimiter, "auth_api", args.service, args.url, allowedServices);
      if (guardError) return reply(guardError);

      const approvalError = await checkApproval(vault, approvalGate, args.service, args.url);
      if (approvalError) return reply(approvalError);

      try {
        const resp = await proxyRequest(vault, args.service, {
          url: args.url,
          method: args.method,
          headers: args.headers,
          body: args.body,
          injection: args.injection,
          headerName: args.headerName,
          queryParam: args.queryParam,
          jsonField: args.jsonField,
        });

        audit("auth_api", { service: args.service, domain: args.url, success: true });
        return reply(`HTTP ${resp.status} ${resp.statusText}\n\n${resp.body.substring(0, 4000)}`);
      } catch (error) {
        const msg = error instanceof Error ? error.message : "Unknown error";
        audit("auth_api", { service: args.service, domain: args.url, success: false, error: msg });
        return reply(`API call failed: ${msg}`);
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
