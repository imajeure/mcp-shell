#!/usr/bin/env node
/**
 * mcp-shell/server.js — native Streamable HTTP MCP server for shell execution.
 * ===========================================================================
 * Exposes a single `execute_command` tool over the MCP Streamable HTTP
 * transport. The command runs directly in a subprocess of this server — there
 * is no separate gateway process and no stdio child.
 *
 * SECURITY — independent layers, all on by default:
 *   1. Bearer token (env MCP_SHELL_TOKEN). The server refuses to start without
 *      it; every HTTP request must present `Authorization: Bearer <token>` or
 *      gets 401 — checked before any MCP session handling.
 *   2. Default-deny command allowlist (env MCP_SHELL_ALLOWED_COMMANDS). Empty by
 *      default => zero execution out of the box. A command runs only if its
 *      program is explicitly allowlisted, and commands containing shell control
 *      characters are rejected so the allowlist can't be bypassed by chaining.
 *   3. Origin validation (env MCP_SHELL_ALLOWED_ORIGINS). DNS-rebinding
 *      protection per the MCP spec: a request carrying a disallowed Origin
 *      header gets 403, before authentication. Defaults to loopback origins;
 *      requests with no Origin header (non-browser clients) are allowed.
 *
 * The executed command's environment is also scrubbed of this server's own
 * secret + control variables (the token and allowlist above all, plus
 * PORT/HOST/…), so an allowlisted command such as `env` cannot read the token.
 * PATH, HOME, and all other variables pass through unchanged.
 *
 * These are app-layer defense-in-depth on top of (not instead of) running as a
 * least-privileged user, binding to 127.0.0.1, and network-layer access control.
 */

import express from "express";
import { randomUUID } from "node:crypto";
import { exec } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import {
  createNotifier,
  startWatchdog,
  makeReadyRoute,
  withTimeout,
  selfReport,
} from "./smart-bridge.js";

// Single source of version truth: the package manifest (always included in the
// npm tarball), so the server can never report a version that has drifted from
// what was published.
const require = createRequire(import.meta.url);
export const VERSION = require("./package.json").version;

export const MAX_OUTPUT_BYTES = 100 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;
const READY_TIMEOUT_MS = 2500;
const READY_SHELL_TIMEOUT_MS = 1500;
const DEFAULT_SHELL = process.env.MCP_SHELL_BIN || "/bin/bash";

// Shell control characters that enable chaining / substitution / redirection.
// When an allowlist is in force these must be rejected, otherwise an allowlisted
// program could be used as a springboard (e.g. `echo x; rm -rf /`).
const SHELL_METACHARS = /[;&|`$(){}<>\n\r]/;

// Server-owned environment variables that must never leak into an executed
// command's environment: the bearer token and allowlist above all, plus the
// process-control vars. Everything else (PATH, HOME, user-defined vars) passes
// through so commands still resolve programs and behave normally.
const CHILD_ENV_DENYLIST = new Set([
  "MCP_SHELL_TOKEN",
  "MCP_SHELL_ALLOWED_COMMANDS",
  "MCP_SHELL_ALLOWED_ORIGINS",
  "MCP_SHELL_BIN",
  "NODE_ENV",
  "PORT",
  "HOST",
  "MCP_ENDPOINT",
  "ROUTE_PREFIX",
]);

// Returns a shallow copy of `base` (defaults to process.env) with the server's
// own secret/control variables removed.
export function buildChildEnv(base = process.env) {
  const env = {};
  for (const [key, value] of Object.entries(base)) {
    if (!CHILD_ENV_DENYLIST.has(key)) env[key] = value;
  }
  return env;
}

// Origin allowlist for DNS-rebinding protection. The MCP spec requires servers
// to validate the Origin header on incoming connections. Configurable via
// MCP_SHELL_ALLOWED_ORIGINS (comma-separated); when unset, only loopback
// origins are accepted.
const DEFAULT_ALLOWED_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

export function parseAllowedOrigins(value) {
  if (!value) return null; // null => fall back to the loopback default
  return value.split(",").map((s) => s.trim()).filter(Boolean);
}

// undefined Origin (a non-browser client) is allowed; the literal "null" opaque
// origin is rejected; with an explicit allowlist the Origin must match exactly;
// otherwise it must match the loopback default.
export function isOriginAllowed(origin, allowlist) {
  if (origin === undefined) return true;
  if (origin === "null") return false;
  if (allowlist) return allowlist.includes(origin);
  return DEFAULT_ALLOWED_ORIGIN_RE.test(origin);
}

// The /healthz + /ready prefix is derived from the MCP endpoint (drop a trailing
// /mcp) so health routes sit alongside the MCP endpoint. ROUTE_PREFIX overrides.
export function deriveRoutePrefix(mcpEndpoint, override) {
  return override || mcpEndpoint.replace(/\/mcp$/, "");
}

export function truncate(str, maxBytes = MAX_OUTPUT_BYTES) {
  if (Buffer.byteLength(str, "utf-8") <= maxBytes) return str;
  let truncated = str;
  while (Buffer.byteLength(truncated, "utf-8") > maxBytes) {
    truncated = truncated.slice(0, Math.floor(truncated.length * 0.9));
  }
  return truncated + "\n\n[OUTPUT TRUNCATED — exceeded 100KB limit]";
}

// Default-deny: returns { ok:false, reason } unless the command's program is
// explicitly allowlisted (matched by full first token or its basename) and the
// command is free of shell control characters.
export function checkAllowed(command, allowlist) {
  if (SHELL_METACHARS.test(command)) {
    return { ok: false, reason: "command contains shell control characters (;, &, |, `, $, (), <>, …)" };
  }
  const program = command.trim().split(/\s+/)[0] || "";
  const base = program.split("/").pop();
  if (allowlist.includes(program) || allowlist.includes(base)) {
    return { ok: true, program: base };
  }
  return { ok: false, reason: `'${base}' is not in the allowlist` };
}

export function runCommand(command, timeoutMs) {
  return new Promise((resolve) => {
    exec(
      command,
      { timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES * 2, shell: DEFAULT_SHELL, env: buildChildEnv() },
      (error, stdout, stderr) => {
        const exitCode = error ? (error.code ?? 1) : 0;
        const killed = error?.killed ?? false;
        let stdoutStr = truncate(String(stdout || ""), MAX_OUTPUT_BYTES);
        let stderrStr = truncate(String(stderr || ""), MAX_OUTPUT_BYTES);
        if (killed) {
          stderrStr += "\n\n[PROCESS KILLED — exceeded " + timeoutMs + "ms timeout]";
        }
        resolve({ stdout: stdoutStr, stderr: stderrStr, exitCode, killed });
      }
    );
  });
}

// Readiness real-path check: spawn a throwaway shell, run a trivial command,
// confirm exit 0 within a timeout. Proves the server can actually spawn a shell,
// not merely that the HTTP listener is up.
async function shellReadyCheck() {
  const r = await runCommand("true", READY_SHELL_TIMEOUT_MS);
  if (r.exitCode !== 0 || r.killed) {
    throw new Error("shell ready check failed (exit " + r.exitCode + (r.killed ? ", killed" : "") + ")");
  }
}
export const readyCheck = () => withTimeout(shellReadyCheck(), READY_TIMEOUT_MS, "mcp-shell /ready");

export function createMcpServer(allowedCommands = []) {
  const server = new McpServer({ name: "mcp-shell", version: VERSION });

  const allowList = allowedCommands.length
    ? "Allowlisted programs: " + allowedCommands.join(", ") + "."
    : "No commands are allowlisted; every command will be rejected until the operator configures MCP_SHELL_ALLOWED_COMMANDS.";

  server.registerTool(
    "execute_command",
    {
      description:
        "Execute a single allowlisted shell command on the host and return its stdout, stderr, and exit code as text. " +
        "Use it to run one concrete, non-interactive command — inspect a file, query a CLI, read system state — " +
        "not for interactive shells, background daemons, or chaining steps. " +
        "Behavior: exactly one program runs (the first token of `command` must be allowlisted); shell control " +
        "characters (; & | ` $ ( ) < > newlines) are rejected, so commands cannot be chained, piped, or redirected. " +
        "Output above 100 KB is truncated, and the process is killed if it exceeds its timeout (default 30s, max 5min); " +
        "a rejected or non-zero command returns with isError set and the reason in the text. " + allowList,
      inputSchema: {
        command: z.string().min(1).max(10_000)
          .describe("A single shell command. Its first token must be an allowlisted program, and shell operators (; & | ` $ () <> newlines) are not allowed — submit one command per call."),
        timeout_ms: z.number().int().min(1000).max(MAX_TIMEOUT_MS).optional()
          .describe("Max milliseconds the command may run before it is killed. Default 30000 (30s), max 300000 (5min)."),
      },
      annotations: {
        title: "Execute Shell Command",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ command, timeout_ms }) => {
      const verdict = checkAllowed(command, allowedCommands);
      if (!verdict.ok) {
        return { content: [{ type: "text", text: "Command rejected (default-deny allowlist): " + verdict.reason }], isError: true };
      }
      const timeout = Math.min(timeout_ms ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
      const result = await runCommand(command, timeout);
      const output = ["Command Output:", "stdout: " + result.stdout, "stderr: " + result.stderr].join("\n");
      return { content: [{ type: "text", text: output }], isError: result.exitCode !== 0 };
    }
  );

  return server;
}

export function parseAllowedCommands(value) {
  if (!value) return [];
  return value.split(",").map((s) => s.trim()).filter(Boolean);
}

export function createApp({
  token,
  allowedCommands = [],
  allowedOrigins = null,
  mcpEndpoint = process.env.MCP_ENDPOINT || "/mcp",
  routePrefix = process.env.ROUTE_PREFIX,
} = {}) {
  if (!token) {
    throw new Error("mcp-shell: a bearer token is required (createApp({ token }))");
  }
  const MCP_ENDPOINT = mcpEndpoint;
  const ROUTE_PREFIX = deriveRoutePrefix(MCP_ENDPOINT, routePrefix);
  const sessions = new Map();

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.use((_req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, Authorization");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
    next();
  });

  // DNS-rebinding guard: validate the Origin header before authentication, so a
  // rebinding attempt is refused before credentials are even consulted. CORS
  // preflight is exempt; non-browser clients (no Origin header) pass through.
  app.use((req, res, next) => {
    if (req.method === "OPTIONS") return next();
    if (!isOriginAllowed(req.headers["origin"], allowedOrigins)) {
      return res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32003, message: "Forbidden: origin not allowed" },
        id: null,
      });
    }
    next();
  });

  // Bearer auth on EVERY request (CORS preflight excepted), enforced before any
  // session lookup => missing/invalid token is 401, not 400.
  app.use((req, res, next) => {
    if (req.method === "OPTIONS") return next();
    const header = req.headers["authorization"] || "";
    const provided = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!provided || provided !== token) {
      return res.status(401).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized: missing or invalid bearer token" },
        id: null,
      });
    }
    next();
  });

  app.options(MCP_ENDPOINT, (_req, res) => res.sendStatus(204));

  app.get(`${ROUTE_PREFIX}/healthz`, (_req, res) => {
    res.json({ status: "ok", version: VERSION, sessions: sessions.size, uptime: Math.floor(process.uptime()) });
  });
  app.get(`${ROUTE_PREFIX}/ready`, makeReadyRoute(readyCheck));

  app.post(MCP_ENDPOINT, async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    try {
      if (sessionId && sessions.has(sessionId)) {
        const { transport } = sessions.get(sessionId);
        await transport.handleRequest(req, res, req.body);
        return;
      }
      if (!sessionId && req.body?.method === "initialize") {
        const mcpServer = createMcpServer(allowedCommands);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            sessions.set(sid, { transport, server: mcpServer });
            console.error("[mcp-shell] Session created: " + sid);
          },
        });
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && sessions.has(sid)) {
            sessions.delete(sid);
            console.error("[mcp-shell] Session closed: " + sid);
          }
        };
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32600, message: "Bad request: missing or invalid session" }, id: req.body?.id ?? null });
    } catch (err) {
      console.error("[mcp-shell] POST error:", err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: req.body?.id ?? null });
      }
    }
  });

  app.get(MCP_ENDPOINT, async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId && sessions.has(sessionId)) {
      const { transport } = sessions.get(sessionId);
      await transport.handleRequest(req, res);
      return;
    }
    res.status(400).json({ error: "Invalid or missing session" });
  });

  app.delete(MCP_ENDPOINT, async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId && sessions.has(sessionId)) {
      const { transport, server } = sessions.get(sessionId);
      await transport.close();
      await server.close();
      sessions.delete(sessionId);
      console.error("[mcp-shell] Session deleted: " + sessionId);
      res.sendStatus(204);
      return;
    }
    res.status(404).json({ error: "Session not found" });
  });

  app.locals.mcpEndpoint = MCP_ENDPOINT;
  app.locals.routePrefix = ROUTE_PREFIX;
  app.locals.allowedCommands = allowedCommands;
  app.locals.allowedOrigins = allowedOrigins;
  return app;
}

export function start() {
  const token = process.env.MCP_SHELL_TOKEN;
  if (!token) {
    console.error("[mcp-shell] FATAL: MCP_SHELL_TOKEN is not set. Refusing to start an unauthenticated shell server.");
    process.exit(1);
  }
  const allowedCommands = parseAllowedCommands(process.env.MCP_SHELL_ALLOWED_COMMANDS);
  if (allowedCommands.length === 0) {
    console.error("[mcp-shell] WARNING: MCP_SHELL_ALLOWED_COMMANDS is empty — default-deny is in effect, every command will be rejected.");
  }
  const allowedOrigins = parseAllowedOrigins(process.env.MCP_SHELL_ALLOWED_ORIGINS);

  const PORT = parseInt(process.env.PORT || "3000", 10);
  const HOST = process.env.HOST || "127.0.0.1";
  const app = createApp({ token, allowedCommands, allowedOrigins });

  const notifier = createNotifier({ selfReport });

  return app.listen(PORT, HOST, () => {
    console.error("[mcp-shell] v" + VERSION + " listening on " + HOST + ":" + PORT + app.locals.mcpEndpoint +
      " (allowlist: " + (allowedCommands.join(", ") || "<empty — default-deny>") +
      "; origins: " + (allowedOrigins ? allowedOrigins.join(", ") : "<loopback default>") + ")");
    startWatchdog({ notifier, readyCheck, intervalMs: 15_000 });
  });
}

// Auto-start only when run directly (`node server.js`), not when imported.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  start();
}
