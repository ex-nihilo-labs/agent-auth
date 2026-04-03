import { z } from "zod";
import { BrowserSteps } from "../browser/steps.js";

/**
 * MCP tool schemas.
 * These define the interface between the AI agent and agent-auth.
 */

export const SecureLoginInput = z.object({
  /** Credential service name (e.g. "aws-root", "github-enex") */
  service: z.string().max(100),
  /** Target URL to navigate to */
  url: z.url(),
  /** Browser steps with {{placeholder}} values */
  steps: BrowserSteps,
});

export type SecureLoginInput = z.infer<typeof SecureLoginInput>;

export const AuthApiInput = z.object({
  /** Credential service name */
  service: z.string().max(100),
  /** Target URL for the API call */
  url: z.url(),
  /** HTTP method */
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  /** Request headers (credential injection happens transparently) */
  headers: z.record(z.string(), z.string()).optional(),
  /** Request body */
  body: z.string().optional(),
  /** How to inject the credential */
  injection: z.enum(["bearer", "header", "query", "basic", "json_body", "form"]).default("bearer"),
  /** Header name for "header" injection type */
  headerName: z.string().optional(),
  /** Query parameter name for "query" injection type */
  queryParam: z.string().optional(),
  /** JSON field path for "json_body" injection type */
  jsonField: z.string().optional(),
});

export type AuthApiInput = z.infer<typeof AuthApiInput>;

export const ListCredentialsInput = z.object({}).optional();

export type ListCredentialsInput = z.infer<typeof ListCredentialsInput>;
