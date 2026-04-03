# agent-auth

Zero-knowledge credential injection for AI agents. Your agent authenticates to websites and APIs without ever seeing a password, TOTP code, or API key.

```
Agent says:  fill #email with {{email}}, fill #password with {{password}}, click Sign In
agent-auth:  resolves {{email}} and {{password}} from encrypted vault, injects into browser
Agent gets:  "Login completed." (never sees the real values)
```

## Why

AI agents are getting good at browsing the web and calling APIs. But authentication is a wall — you either hand the agent your password (dangerous) or do it yourself every time (defeats the purpose).

agent-auth sits between the agent and the browser. The agent describes *what to do* with placeholder tokens. agent-auth resolves the real credentials from a local encrypted vault and injects them directly into the browser via CDP. The agent never touches the secret material.

Works with any MCP-compatible agent: Claude Code, Claude Desktop, OpenCode, Cursor, or your own.

## How It Works

```
AI Agent                        agent-auth                       Browser
   |                               |                               |
   |  "Log into AWS"               |                               |
   |  steps: [                     |                               |
   |    fill #email {{email}}      |                               |
   |    fill #pass  {{password}}   |  1. Decrypt from local vault  |
   |    fill #totp  {{totp}}       |  2. Generate TOTP from seed   |
   |    click Submit               |  3. Inject via CDP  --------->| Form filled
   |  ]                            |  4. Zero memory               |
   |                               |                               |
   |  "Login completed" <--------- |                               |
   |                               |                               |
   |  (never saw any secrets)      |  (secrets wiped from RAM)     |
```

## Quick Start

```bash
# Clone and install
git clone https://github.com/ex-nihilo-labs/agent-auth.git
cd agent-auth && bun install

# Create your vault (you'll set a passphrase)
bun run src/index.ts init

# Add a credential
bun run src/index.ts add github \
  --username "you@example.com" \
  --password "your-password" \
  --domains "github.com"

# Add one with TOTP
bun run src/index.ts add aws-root \
  --username "admin@company.com" \
  --password "hunter2" \
  --totp "JBSWY3DPEHPK3PXP" \
  --domains "signin.aws.amazon.com,console.aws.amazon.com"

# See what's stored (names only — no secrets shown)
bun run src/index.ts list
# → github (domains: github.com)
# → aws-root (domains: signin.aws.amazon.com, console.aws.amazon.com)
```

## Connect to Your Agent

agent-auth is an MCP server. Add it to your agent's config:

### Claude Code / Claude Desktop

Add to `.mcp.json` in your project root (or `~/.claude/settings.json` for global):

```json
{
  "mcpServers": {
    "agent-auth": {
      "type": "stdio",
      "command": "bun",
      "args": ["run", "/path/to/agent-auth/src/index.ts", "serve"],
      "env": {
        "AGENT_AUTH_CDP_URL": "http://localhost:9222"
      }
    }
  }
}
```

The passphrase is read from your OS keychain automatically (stored during `init`). For development, you can set `AGENT_AUTH_PASSPHRASE` in the env block instead.

### Other MCP Agents

Any agent that speaks [MCP](https://modelcontextprotocol.io/) over stdio can use agent-auth. Start the server:

```bash
bun run src/index.ts serve
```

It exposes three tools over stdin/stdout JSONRPC.

## MCP Tools

| Tool | What the agent sends | What the agent gets back |
|------|---------------------|------------------------|
| **`secure_login`** | Service name + browser steps with `{{placeholders}}` | "Login completed" or error |
| **`auth_api`** | Service name + HTTP request details | API response body (credentials redacted) |
| **`list_credentials`** | *(nothing)* | Service names and allowed domains only |

### secure_login

Browser-based authentication. The agent describes the login flow as steps:

```json
{
  "service": "github",
  "url": "https://github.com/login",
  "steps": [
    { "action": "fill", "selector": "#login_field", "value": "{{email}}" },
    { "action": "fill", "selector": "#password", "value": "{{password}}" },
    { "action": "click", "selector": "input[type='submit']" },
    { "action": "wait", "selector": ".logged-in", "timeout": 5000 }
  ]
}
```

Step actions: `fill`, `type` (character-by-character for SPAs), `click`, `wait`, `select`.

### auth_api

Authenticated HTTP requests. Six injection methods:

```json
{
  "service": "openai",
  "url": "https://api.openai.com/v1/models",
  "method": "GET",
  "injection": "bearer"
}
```

Injection methods: `bearer`, `header`, `query`, `basic`, `json_body`, `form`.

### list_credentials

Returns service names and allowed domains. Never returns passwords, TOTP seeds, or API keys.

## Security Model

**The core guarantee: credentials never appear in MCP responses.** They flow from vault to browser/HTTP and are zeroed from memory immediately after.

| Layer | Implementation |
|-------|---------------|
| **Encryption at rest** | AES-256-GCM, 12-byte random nonce per field |
| **Key derivation** | Argon2id (3 iterations, 64MB memory, 4 parallelism) |
| **Master key storage** | OS keychain (macOS Keychain, Linux secret-tool) with encrypted file fallback |
| **Memory hygiene** | All credentials as `Buffer`/`Uint8Array`, zeroed with `buf.fill(0)` after use. Never converted to JS strings (immutable, can't be wiped). |
| **Domain allowlist** | Deny-by-default. Each credential lists which domains it can be injected into. |
| **Redirect protection** | Domain re-verified after every navigation step. Aborts if redirect leaves the allowlist. |
| **Human approval** | First use of each credential+domain pair sends a push notification (Pushover) with a 4-digit code. 50-second window. |
| **Rate limiting** | 3 requests/minute, 20/hour. Persisted in SQLite across restarts. |
| **Audit trail** | Append-only JSONL log. All credential values masked. |
| **No cloud** | Everything local. Vault never synced, uploaded, or phoned home. |

## CLI Reference

All CLI commands are human-only — never exposed via MCP.

```bash
agent-auth init                   # Create vault, set passphrase
agent-auth add <service>          # Add credential (interactive or with flags)
agent-auth list                   # List services (names only)
agent-auth remove <service>       # Delete a credential
agent-auth domains <service>      # View/edit allowed domains
agent-auth approve <code>         # Approve a pending auth request
agent-auth unlock                 # Unlock vault for current session
agent-auth lock                   # Lock vault, clear key from memory
agent-auth serve                  # Start MCP server (stdio)
```

**Flags for `add`:** `--username`, `--password`, `--totp` (base32 or otpauth:// URI), `--domains` (comma-separated), `--notes`.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AGENT_AUTH_CDP_URL` | Chrome DevTools Protocol endpoint for browser injection | *(none — browser tools disabled)* |
| `AGENT_AUTH_PASSPHRASE` | Vault passphrase (dev/CI only — use keychain in production) | *(prompt or keychain)* |
| `AGENT_AUTH_NO_KEYCHAIN` | Skip OS keychain, use file-only key storage | `false` |
| `AGENT_AUTH_PUSHOVER_TOKEN` | Pushover app token for approval notifications | *(approval disabled)* |
| `AGENT_AUTH_PUSHOVER_USER` | Pushover user key | *(approval disabled)* |

## Architecture

```
agent-auth/
├── src/
│   ├── index.ts              # CLI dispatcher + MCP serve
│   ├── mcp/                  # MCP server (3 tools over stdio JSONRPC)
│   ├── browser/              # CDP injection via Playwright (fill/type/click/wait/select)
│   ├── placeholder/          # {{email}}, {{username}}, {{password}}, {{totp}} resolution
│   ├── vault/                # AES-256-GCM encrypted SQLite + Argon2id KDF
│   ├── totp/                 # TOTP generation via otpauth
│   ├── proxy/                # HTTP credential injection (6 methods)
│   ├── approval/             # Human approval gate + Pushover
│   ├── security/             # Rate limiter, input validator, domain allowlist
│   ├── audit/                # Append-only JSONL audit log
│   └── cli/                  # Human-only credential management
└── tests/                    # 65 tests across 6 suites
```

**Vault location:** `~/.agent-auth/vault.db` (SQLite, mode 0600)

**Dependencies (intentionally minimal):**
- `@modelcontextprotocol/sdk` — MCP protocol
- `playwright-core` — CDP browser automation (no bundled browser)
- `bun:sqlite` — Built-in SQLite (zero deps)
- `otpauth` — TOTP generation (5KB, pure JS)
- `@noble/hashes` — Argon2id KDF (audited, pure JS)
- `zod` — Input validation

## Testing

```bash
bun test              # 65 tests, 6 suites
bun run typecheck     # TypeScript strict mode
```

Tests use `AGENT_AUTH_NO_KEYCHAIN=1` to avoid macOS Keychain permission dialogs in CI.

## Acknowledgments

agent-auth was inspired by these projects:

- **[AgentSecrets](https://github.com/The-17/agentsecrets)** (MIT) — Crypto envelope design (AES-256-GCM + Argon2id), domain allowlists, HTTP credential proxy pattern.
- **[Virtual FIDO](https://github.com/bulwarkid/virtual-fido)** (MIT) — Passkey/WebAuthn emulation architecture. Planned for future passkey support.

## Roadmap

- [ ] Passkey/WebAuthn support via [Virtual FIDO](https://github.com/bulwarkid/virtual-fido) signing
- [ ] `npx agent-auth` / global install
- [ ] Credential import from 1Password, Bitwarden (CLI export)
- [ ] Browser profile persistence (stay logged in across sessions)
- [ ] Multi-page login flow templates (common services)

## Contributing

PRs welcome. The codebase is small (~1,500 lines) and intentionally simple.

**Ground rules:**
- No cloud features. The vault is local-only. This is not negotiable.
- No new runtime dependencies without justification. We have 5 — that's enough.
- Credentials must never be converted to JS strings. `Buffer`/`Uint8Array` only.
- Tests required for any new functionality.

```bash
# Development
bun install
AGENT_AUTH_NO_KEYCHAIN=1 bun test    # Run tests
bun run typecheck                     # Type check
```

## License

[MIT](LICENSE) — Ex Nihilo Labs, 2026
