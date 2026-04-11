import { z } from "zod";

/**
 * Environment variable validation.
 * Validated at startup — app crashes immediately if required vars are missing.
 */

const ServeEnvSchema = z.object({
  /** CDP endpoint for browser injection. Optional — browser tools disabled without it. */
  AGENT_AUTH_CDP_URL: z.string().url().optional(),
  /** Vault passphrase. Prefer OS keychain in production. */
  AGENT_AUTH_PASSPHRASE: z.string().min(1).optional(),
  /** Skip OS keychain, use file-only storage. */
  AGENT_AUTH_NO_KEYCHAIN: z.string().optional(),
  /** Pushover app token for approval notifications. */
  AGENT_AUTH_PUSHOVER_TOKEN: z.string().optional(),
  /** Pushover user key for approval notifications. */
  AGENT_AUTH_PUSHOVER_USER: z.string().optional(),
  /**
   * Comma-separated list of credential service names this server instance may access.
   * Empty or absent = all services allowed. Use to scope per-agent server processes.
   * Example: "github,aws-dev" — this instance can only use those two credentials.
   */
  AGENT_AUTH_ALLOWED_SERVICES: z.string().optional(),
});

export type ServeEnv = z.infer<typeof ServeEnvSchema>;

export function validateServeEnv(): ServeEnv {
  const result = ServeEnvSchema.safeParse(process.env);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    console.error(`Environment validation failed:\n${issues}`);
    process.exit(1);
  }
  return result.data;
}
