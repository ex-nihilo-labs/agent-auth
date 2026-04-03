# agent-auth

Zero-knowledge credential service for AI agents. MCP server that injects credentials into browsers and HTTP requests without the agent ever seeing them.

## Architecture

```
agent-auth/
├── src/
│   ├── index.ts              # Entry point — CLI dispatcher + MCP serve
│   ├── mcp/                  # MCP stdio server, 3 tools
│   ├── browser/              # CDP injection via Playwright (fill/type/click/wait/select)
│   ├── placeholder/          # {{email}}, {{username}}, {{password}}, {{totp}} resolution
│   ├── vault/                # AES-256-GCM encrypted SQLite vault + Argon2id KDF
│   ├── totp/                 # TOTP code generation via otpauth
│   ├── proxy/                # HTTP credential injection (6 methods)
│   ├── approval/             # Human approval gate + Pushover notifications
│   ├── security/             # Rate limiter, input validator, domain allowlist
│   ├── audit/                # Append-only JSONL audit log
│   └── cli/                  # Human-only credential management
├── tests/                    # 65 tests across 6 suites
└── ~/.agent-auth/            # Vault data (gitignored, local only)
    ├── vault.db              # Encrypted SQLite
    ├── keyring.json          # Master key (file fallback when keychain unavailable)
    └── audit.log             # JSONL audit trail
```

## Stack

Bun, TypeScript (strict), @modelcontextprotocol/sdk, playwright-core, bun:sqlite, otpauth, @noble/hashes (Argon2id)

## How to Test

```bash
AGENT_AUTH_NO_KEYCHAIN=1 bun test    # 65 tests, all suites
bun run typecheck                     # TypeScript strict mode
```

`AGENT_AUTH_NO_KEYCHAIN=1` avoids macOS Keychain permission dialogs in tests and CI.

## Security Rules

These are non-negotiable. PRs that violate them will be rejected.

1. **Credentials are NEVER converted to JS strings.** They flow as `Buffer`/`Uint8Array` and are zeroed with `buf.fill(0)` after injection. JS strings are immutable and GC'd — cannot be zeroed.
2. **TOTP codes are NEVER returned to the agent.** They are only injected via browser CDP or HTTP proxy.
3. **Domain allowlist is deny-by-default.** Credentials can only be injected into explicitly listed domains.
4. **Domain is verified AFTER each navigation step** to catch redirects to unauthorized domains.
5. **Rate limiting persists across restarts** (SQLite-backed, not in-memory).
6. **First use of any credential+domain pair requires human approval** (Pushover notification with 4-digit code, 50s window).
7. **No cloud features.** The vault is local-only. No sync, no upload, no phoning home.
8. **No new runtime dependencies without justification.** We have 5. That's enough.

## Key Files

| What | Where |
|------|-------|
| MCP tool definitions | `src/mcp/server.ts` |
| Crypto (AES-256-GCM + Argon2id) | `src/vault/crypto.ts` |
| Vault store (SQLite CRUD) | `src/vault/store.ts` |
| Keychain integration | `src/vault/keychain.ts` |
| Browser injection | `src/browser/injector.ts` |
| Placeholder resolution | `src/placeholder/resolver.ts` |
| Approval gate | `src/approval/gate.ts` |
