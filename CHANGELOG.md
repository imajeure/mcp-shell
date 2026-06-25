# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/imajeure/mcp-shell/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/imajeure/mcp-shell/releases/tag/v0.1.0
