/**
 * Custom error classes for agent-auth.
 * Discriminated by type for structured catch handling.
 */

export class VaultError extends Error {
  readonly code: "locked" | "not_found" | "decrypt_failed" | "invalid_passphrase";

  constructor(code: VaultError["code"], message: string) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

export class InjectionError extends Error {
  readonly code: "not_connected" | "no_context" | "element_not_found" | "navigation_failed" | "ssrf_redirect";
  readonly selector?: string;

  constructor(code: InjectionError["code"], message: string, selector?: string) {
    super(message);
    this.name = "InjectionError";
    this.code = code;
    this.selector = selector;
  }
}

export class ValidationError extends Error {
  readonly code: "invalid_selector" | "invalid_service" | "missing_field" | "invalid_envelope";
  readonly field?: string;

  constructor(code: ValidationError["code"], message: string, field?: string) {
    super(message);
    this.name = "ValidationError";
    this.code = code;
    this.field = field;
  }
}

export class CredentialError extends Error {
  readonly code: "not_found" | "missing_username" | "missing_password" | "missing_totp" | "unknown_placeholder";
  readonly service?: string;

  constructor(code: CredentialError["code"], message: string, service?: string) {
    super(message);
    this.name = "CredentialError";
    this.code = code;
    this.service = service;
  }
}
