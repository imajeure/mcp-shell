# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-06-25

### Security
- Validate the `Origin` header on every request as DNS-rebinding protection, per
  the MCP specification. A request carrying a disallowed `Origin` now gets `403`,
  checked before authentication. Accepted origins default to loopback and are
  configurable via `MCP_SHELL_ALLOWED_ORIGINS`; requests with no `Origin` header
  (non-browser clients) continue to be allowed.
- Scrub the server's own secret and control environment variables
  (`MCP_SHELL_TOKEN`, `MCP_SHELL_ALLOWED_COMMANDS`, `PORT`, `HOST`, and the
  other server-control vars) from the executed command's environment, so an
  allowlisted command such as `env` can no longer read the bearer token. `PATH`,
  `HOME`, and unrelated variables pass through unchanged.

### Fixed
- Report the real package version over MCP. The server now reads its version
  from `package.json` instead of a hardcoded constant that had drifted from the
  published version.

### Changed
- Require Node.js `>=22`; the previous `>=18` floor covered releases that are now
  end-of-life. CI runs on Node 22 and 24.
- Mark the package for npm provenance on publish (`publishConfig.provenance`).

## [0.1.0] - 2026-06-24

### Added
- Initial public release.
- Native Streamable HTTP MCP server exposing a single `execute_command` tool
  that runs the command in a subprocess of the server (no separate gateway
  process, no stdio child).
- Two mandatory security layers: a required bearer token (`MCP_SHELL_TOKEN` —
  the server refuses to start without it) and a default-deny command allowlist
  (`MCP_SHELL_ALLOWED_COMMANDS`) that also rejects shell control characters so
  the allowlist cannot be bypassed by chaining.
- `/healthz` liveness plus a `/ready` endpoint that spawns a real shell to prove
  the server can actually execute commands, not just that the port is open.
- Readiness-gated `systemd` watchdog support.
- Output truncation at 100 KB and a configurable per-command timeout
  (default 30s, max 5min).

[Unreleased]: https://github.com/imajeure/mcp-shell/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/imajeure/mcp-shell/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/imajeure/mcp-shell/releases/tag/v0.1.0
