import type { VaultStore } from "../vault/store.js";
import { zeroBuffer } from "../vault/crypto.js";
import { CredentialError, ValidationError } from "../errors.js";

/**
 * HTTP credential proxy.
 * Makes authenticated API calls on behalf of the agent.
 * Credentials are injected at the transport layer — agent only sees the response.
 *
 * Six injection methods (modeled after AgentSecrets):
 * - bearer: Authorization: Bearer <credential>
 * - header: Custom header with credential value
 * - query: URL query parameter
 * - basic: Authorization: Basic base64(username:password)
 * - json_body: Inject into JSON request body
 * - form: Inject into form-encoded body
 */

export type InjectionMethod =
  | "bearer"
  | "header"
  | "query"
  | "basic"
  | "json_body"
  | "form";

export interface ProxyRequest {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  injection: InjectionMethod;
  headerName?: string;
  queryParam?: string;
  jsonField?: string;
}

export interface ProxyResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

export async function proxyRequest(
  vault: VaultStore,
  service: string,
  request: ProxyRequest
): Promise<ProxyResponse> {
  const secrets = vault.resolveSecrets(service);
  if (!secrets) {
    throw new CredentialError("not_found", `Credential "${service}" not found in vault.`, service);
  }

  try {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    let body = request.body;

    const password = secrets.password?.toString("utf-8") ?? "";
    const username = secrets.username?.toString("utf-8") ?? "";

    switch (request.injection) {
      case "bearer":
        headers.set("Authorization", `Bearer ${password}`);
        break;

      case "header":
        if (!request.headerName) throw new ValidationError("missing_field", "headerName required for header injection", "headerName");
        headers.set(request.headerName, password);
        break;

      case "query":
        if (!request.queryParam) throw new ValidationError("missing_field", "queryParam required for query injection", "queryParam");
        url.searchParams.set(request.queryParam, password);
        break;

      case "basic": {
        const encoded = Buffer.from(`${username}:${password}`).toString("base64");
        headers.set("Authorization", `Basic ${encoded}`);
        break;
      }

      case "json_body": {
        if (!request.jsonField) throw new ValidationError("missing_field", "jsonField required for json_body injection", "jsonField");
        const parsed = body ? JSON.parse(body) : {};
        parsed[request.jsonField] = password;
        body = JSON.stringify(parsed);
        headers.set("Content-Type", "application/json");
        break;
      }

      case "form": {
        const params = new URLSearchParams(body ?? "");
        params.set("password", password);
        if (username) params.set("username", username);
        body = params.toString();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        break;
      }
    }

    const resp = await fetch(url.toString(), {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method.toUpperCase()) ? undefined : body,
    });

    const respBody = await resp.text();

    // Redact any echoed credentials in response
    const redacted = redactCredentials(respBody, [password, username].filter(Boolean));

    const respHeaders: Record<string, string> = {};
    resp.headers.forEach((v, k) => {
      respHeaders[k] = v;
    });

    return {
      status: resp.status,
      statusText: resp.statusText,
      headers: respHeaders,
      body: redacted,
    };
  } finally {
    // Zero all secret buffers
    if (secrets.username) zeroBuffer(secrets.username);
    if (secrets.password) zeroBuffer(secrets.password);
    if (secrets.totpSeed) zeroBuffer(secrets.totpSeed);
  }
}

/**
 * Redact any credential values that appear in a response body.
 * Prevents API responses from echoing secrets back to the agent.
 */
function redactCredentials(body: string, secrets: string[]): string {
  let result = body;
  for (const secret of secrets) {
    if (secret.length >= 4) {
      // Only redact if the secret is long enough to not cause false positives
      result = result.replaceAll(secret, "[REDACTED_BY_AGENT_AUTH]");
    }
  }
  return result;
}
