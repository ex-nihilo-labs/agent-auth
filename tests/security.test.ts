import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { isDomainAllowed } from "../src/security/domains.ts";
import { validateSelector, validateServiceName } from "../src/security/validator.ts";
import { RateLimiter } from "../src/security/rate-limiter.ts";
import { Database } from "bun:sqlite";

describe("domains", () => {
  test("exact domain match", () => {
    expect(isDomainAllowed("https://aws.amazon.com/console", ["aws.amazon.com"])).toBe(true);
  });

  test("subdomain match", () => {
    expect(isDomainAllowed("https://us-east-2.console.aws.amazon.com/bedrock", ["aws.amazon.com"])).toBe(true);
  });

  test("rejects non-matching domain", () => {
    expect(isDomainAllowed("https://evil.com/phish", ["aws.amazon.com"])).toBe(false);
  });

  test("rejects empty allowlist", () => {
    expect(isDomainAllowed("https://anything.com", [])).toBe(false);
  });

  test("rejects invalid URL", () => {
    expect(isDomainAllowed("not-a-url", ["example.com"])).toBe(false);
  });

  test("case insensitive", () => {
    expect(isDomainAllowed("https://AWS.Amazon.COM/x", ["aws.amazon.com"])).toBe(true);
  });

  test("partial domain doesn't match (amazon.com vs aws.amazon.com)", () => {
    expect(isDomainAllowed("https://evil-aws.amazon.com.attacker.com/x", ["aws.amazon.com"])).toBe(false);
  });
});

describe("validator", () => {
  test("validates clean selector", () => {
    expect(validateSelector("#password").valid).toBe(true);
    expect(validateSelector("input[name='email']").valid).toBe(true);
  });

  test("blocks javascript: in selector", () => {
    expect(validateSelector("javascript:alert(1)").valid).toBe(false);
  });

  test("blocks script tags in selector", () => {
    expect(validateSelector("<script>alert(1)</script>").valid).toBe(false);
  });

  test("blocks long selectors", () => {
    expect(validateSelector("a".repeat(501)).valid).toBe(false);
  });

  test("validates clean service name", () => {
    expect(validateServiceName("aws-root").valid).toBe(true);
    expect(validateServiceName("github-enex-prod").valid).toBe(true);
  });

  test("blocks shell metacharacters in service name", () => {
    expect(validateServiceName("aws;rm -rf /").valid).toBe(false);
    expect(validateServiceName("test$(whoami)").valid).toBe(false);
    expect(validateServiceName("test`id`").valid).toBe(false);
  });

  test("blocks long service name", () => {
    expect(validateServiceName("a".repeat(101)).valid).toBe(false);
  });
});

describe("rate limiter", () => {
  let db: Database;
  let limiter: RateLimiter;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT PRIMARY KEY,
        count INTEGER NOT NULL DEFAULT 0,
        window_start INTEGER NOT NULL DEFAULT (unixepoch())
      );
    `);
    limiter = new RateLimiter(db);
  });

  afterEach(() => {
    db.close();
  });

  test("allows first 3 requests", () => {
    expect(limiter.check("test").allowed).toBe(true);
    expect(limiter.check("test").allowed).toBe(true);
    expect(limiter.check("test").allowed).toBe(true);
  });

  test("blocks 4th request within minute", () => {
    limiter.check("test");
    limiter.check("test");
    limiter.check("test");
    const result = limiter.check("test");
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  test("different keys have independent limits", () => {
    limiter.check("key1");
    limiter.check("key1");
    limiter.check("key1");
    expect(limiter.check("key1").allowed).toBe(false);
    expect(limiter.check("key2").allowed).toBe(true);
  });
});
