# mcp-shell

[![CI](https://github.com/imajeure/mcp-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/imajeure/mcp-shell/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/@imajeure/mcp-shell.svg)](https://www.npmjs.com/package/@imajeure/mcp-shell) ![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg) ![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)

A native [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes a single `execute_command` tool over the **Streamable HTTP** transport.
The command runs directly in a subprocess of this server — there is no separate
gateway process and no stdio child.

## ⚠️ Security first

`execute_command` is remote command execution by design. This server ships
**locked down by default** with two independent, mandatory app-layer controls,
which are meant to sit on top of (not replace) OS- and network-level hardening —
defense in depth:

**Layer 1 — Bearer token (required).**
- Set `MCP_SHELL_TOKEN`. The server **refuses to start** without it.
- Every HTTP request must send `Authorization: Bearer <token>`; anything else
  gets **401**, checked *before* any MCP session handling.

**Layer 2 — Default-deny command allowlist.**
- `MCP_SHELL_ALLOWED_COMMANDS` is **empty by default**, which means **zero
  commands run** out of the box.
- A command executes only if its program (the first token, matched by name or
  basename) is explicitly allowlisted.
- Commands containing shell control characters (`;`, `&`, `|`, `` ` ``, `$`,
  `()`, `<>`, …) are rejected, so an allowlisted program can't be used to chain
  into a non-allowlisted one.

**Operational hardening (your responsibility, and just as important).**
- Run the server as a **dedicated least-privileged user**, never root.
- Keep the default bind of `127.0.0.1` and put access control in front of it
  (an authenticated reverse proxy / tunnel). Do not expose it on a public
  interface.
- Treat the token as a secret; rotate it; scope the allowlist as narrowly as the
  use case allows.

## The tool

| Tool | Arguments | Returns |
|---|---|---|
| `execute_command` | `command` (string, required) · `timeout_ms` (int, optional; default `30000`, max `300000`) | `stdout`, `stderr`, exit code as text. `isError: true` on non-zero exit or when the command is rejected by the allowlist. |

Output is capped at 100 KB per stream (truncated with a marker); a command that
exceeds its timeout is killed with a `[PROCESS KILLED]` note.

## Quickstart

```sh
npm install

# Token is mandatory; allowlist is default-deny — enable only what you need.
MCP_SHELL_TOKEN="$(openssl rand -hex 32)" \
MCP_SHELL_ALLOWED_COMMANDS="echo,ls,git" \
  npm start
```

Without a token the server exits immediately:

```sh
npm start
# [mcp-shell] FATAL: MCP_SHELL_TOKEN is not set. Refusing to start ...
```

Unauthenticated requests are refused:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# 401
```

MCP clients must send the bearer token on every request (e.g. via the client
transport's request headers: `Authorization: Bearer <MCP_SHELL_TOKEN>`).

### Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `MCP_SHELL_TOKEN` | — (**required**) | Bearer token; server refuses to start if unset. |
| `MCP_SHELL_ALLOWED_COMMANDS` | empty (deny all) | Comma-separated allowlisted program names. |
| `PORT` | `3000` | Port to listen on. |
| `HOST` | `127.0.0.1` | Bind address. Keep it loopback unless something else gates access. |
| `MCP_ENDPOINT` | `/mcp` | MCP Streamable HTTP mount path. |
| `ROUTE_PREFIX` | derived | Prefix for `/healthz` + `/ready` (defaults to `MCP_ENDPOINT` minus a trailing `/mcp`). |
| `MCP_SHELL_BIN` | `/bin/bash` | Shell used to run commands. |

## Endpoints

- `POST/GET/DELETE ${MCP_ENDPOINT}` — MCP Streamable HTTP transport (per-session).
- `GET ${ROUTE_PREFIX}/healthz` — liveness.
- `GET ${ROUTE_PREFIX}/ready` — readiness: spawns a throwaway shell and confirms
  a trivial command round-trips.

All endpoints require the bearer token (CORS preflight `OPTIONS` excepted).

## Testing

```sh
npm test   # node --test
```

Unit tests cover the helpers and the default-deny allowlist (including the
shell-metacharacter bypass guard). Integration tests boot the real server and,
over the MCP Streamable HTTP client, prove: an allowlisted command runs, a
non-allowlisted command is rejected without executing, and a request with no /
invalid token gets **401**.

## License

Apache-2.0
