# pp-connect

**The connection layer of the [Prompt Pipeline](https://prompt-pipeline.io) relay.**

Prompt Pipeline is a zero-trust web workspace. A browser cannot open raw SSH/SFTP sockets or reach most provider
APIs directly (CORS, TCP), so a small **stateless relay** sits between the browser and the target you choose. This
repository contains the part of that relay which handles your credentials and outbound connections — published
under **AGPL-3.0** for transparency, so anyone can audit how credentials are forwarded.

When you actively use a connector, the relay forwards your secret to the **target you selected** (your SSH host,
the AI provider, Google/Notion/GitHub, an FTP server…) and then forgets it. It is stateless: nothing is persisted,
and the logger redacts every secret.

## Modules

- `src/proxy.mjs` — AI pass-through proxy. Your API key is forwarded to the provider, streamed back, never logged.
- `src/log.mjs` — redacting logger: auth headers / API keys become `[redacted]`; only safe metadata is recorded.
- `src/ssh/` — SSH bridge and one-shot exec over `ssh2` (password forwarded to the host).
- `src/ftp/` — SFTP bridge (credentials forwarded to the host).
- `src/google/`, `src/notion/`, `src/github/` — OAuth code exchange and API proxies. App OAuth client secrets live
  in the relay's server environment, never in this code and never in the browser.
- `src/mcp/` — allowlisted MCP proxy.
- `src/http/` — generic HTTP request proxy and headless web rendering.
- `src/security/` — anti-SSRF host denylist (blocks private/link-local addresses) and strict Origin checks.

## What you can verify — and what you can't

- **Design (auditable):** read this code and confirm the intent — stateless, forward-then-forget, no secret
  logging, anti-SSRF. Credentials arrive as function arguments and are discarded after use.
- **Runtime (not remotely provable):** the binary running on the server cannot be cryptographically attested from
  the outside (no trusted execution environment). Assurance therefore comes from this open code **plus** behavioral
  verification in the browser: with DevTools open, decrypted secrets only ever travel to the relay endpoint for the
  connector you actively invoke, never to any undisclosed destination.

The relay's orchestration, configuration, and authentication are intentionally **not** part of this repository.

## Install

```bash
npm install   # ssh2, ipaddr.js (+ optional playwright for web rendering)
```

These modules are imported by the relay; they are not a standalone server.

## License

AGPL-3.0-or-later (full text in [`LICENSE`](./LICENSE)). Network use of a derivative obliges you to publish the
corresponding source — this deters closed-source re-hosting while keeping the credential-handling code auditable.
The copyright holder may use this code in their own (closed) relay, as is standard for the author of the work.
