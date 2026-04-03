/**
 * Push notification adapter for human approval.
 * Supports Pushover. Falls back to stderr if no token is configured.
 */

const PUSHOVER_API = "https://api.pushover.net/1/messages.json";

export interface NotifyConfig {
  pushoverToken?: string;
  pushoverUser?: string;
}

let config: NotifyConfig = {
  pushoverToken: process.env.AGENT_AUTH_PUSHOVER_TOKEN ?? process.env.PUSHOVER_APP_TOKEN,
  pushoverUser: process.env.AGENT_AUTH_PUSHOVER_USER ?? process.env.PUSHOVER_USER_KEY,
};

export function configureNotify(c: NotifyConfig): void {
  config = { ...config, ...c };
}

export async function notify(
  title: string,
  message: string,
  priority: number = 0
): Promise<boolean> {
  if (config.pushoverToken && config.pushoverUser) {
    try {
      const resp = await fetch(PUSHOVER_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: config.pushoverToken,
          user: config.pushoverUser,
          title,
          message: message.substring(0, 512),
          priority,
        }),
      });
      return resp.ok;
    } catch {
      // Fall through to stdout
    }
  }

  // Fallback: print to stderr (visible to human, not to MCP agent)
  console.error(`[agent-auth] ${title}: ${message}`);
  return true;
}
