/**
 * server.test.js — unit + integration tests for mcp-shell.
 *
 * Run: `npm test`  (node --test)
 *
 * Unit: route-prefix derivation, output truncation, the default-deny allowlist
 * check, Origin validation, and child-environment scrubbing. Integration: boots
 * the real server on an ephemeral port and exercises the security layers over the
 * MCP Streamable HTTP client — allowed command runs, non-allowlisted command is
 * rejected, a request with no/invalid bearer token gets 401 (before any MCP
 * session handling), a disallowed Origin gets 403 (before auth), and a loopback
 * Origin falls through to auth.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createApp,
  truncate,
  deriveRoutePrefix,
  checkAllowed,
  parseAllowedCommands,
  parseAllowedOrigins,
  isOriginAllowed,
  buildChildEnv,
  MAX_OUTPUT_BYTES,
} from "./server.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const TOKEN = "test-secret-token";
const ENDPOINT = "/mcp";

// ── Unit ──────────────────────────────────────────────────────────────────────
test("deriveRoutePrefix strips only a trailing /mcp and honors the override", () => {
  assert.equal(deriveRoutePrefix("/mcp"), "");
  assert.equal(deriveRoutePrefix("/shell/mcp"), "/shell");
  assert.equal(deriveRoutePrefix("/shell/mcp", "/custom"), "/custom");
  assert.equal(deriveRoutePrefix("/mcp-tool/mcp"), "/mcp-tool");
});

test("truncate passes short strings and caps oversized output", () => {
  assert.equal(truncate("hi", 100), "hi");
  const out = truncate("x".repeat(MAX_OUTPUT_BYTES * 2));
  assert.ok(Buffer.byteLength(out, "utf-8") <= MAX_OUTPUT_BYTES + 200);
  assert.match(out, /OUTPUT TRUNCATED/);
});

test("parseAllowedCommands splits, trims, and drops empties", () => {
  assert.deepEqual(parseAllowedCommands("echo, ls ,, git"), ["echo", "ls", "git"]);
  assert.deepEqual(parseAllowedCommands(""), []);
  assert.deepEqual(parseAllowedCommands(undefined), []);
});

test("checkAllowed is default-deny and blocks shell-metachar bypass", () => {
  assert.equal(checkAllowed("echo hi", []).ok, false, "empty allowlist denies everything");
  assert.equal(checkAllowed("echo hi", ["echo"]).ok, true, "allowlisted program runs");
  assert.equal(checkAllowed("/bin/echo hi", ["echo"]).ok, true, "matches by basename too");
  assert.equal(checkAllowed("whoami", ["echo"]).ok, false, "non-allowlisted program denied");
  const chained = checkAllowed("echo hi; rm -rf /tmp/x", ["echo"]);
  assert.equal(chained.ok, false, "shell control chars rejected even if program is allowlisted");
  assert.match(chained.reason, /shell control characters/);
});

test("isOriginAllowed: no Origin allowed, opaque null rejected, loopback is the default", () => {
  assert.equal(isOriginAllowed(undefined, null), true, "non-browser client (no Origin) is allowed");
  assert.equal(isOriginAllowed("null", null), false, "opaque 'null' origin is rejected");
  assert.equal(isOriginAllowed("http://localhost:3000", null), true);
  assert.equal(isOriginAllowed("http://127.0.0.1:8443", null), true);
  assert.equal(isOriginAllowed("http://[::1]:9000", null), true);
  assert.equal(isOriginAllowed("https://localhost", null), true);
  assert.equal(isOriginAllowed("http://evil.example.com", null), false, "off-host origin is rejected");
});

test("parseAllowedOrigins + isOriginAllowed: an explicit allowlist replaces the loopback default", () => {
  assert.equal(parseAllowedOrigins(""), null);
  assert.equal(parseAllowedOrigins(undefined), null);
  const allow = parseAllowedOrigins("https://app.example.com, https://admin.example.com ,");
  assert.deepEqual(allow, ["https://app.example.com", "https://admin.example.com"]);
  assert.equal(isOriginAllowed("https://app.example.com", allow), true);
  assert.equal(isOriginAllowed("http://localhost:3000", allow), false, "loopback is not auto-allowed once an allowlist is set");
  assert.equal(isOriginAllowed(undefined, allow), true, "no Origin still passes (non-browser client)");
});

test("buildChildEnv strips secret + control vars and preserves PATH/HOME and user vars", () => {
  const env = buildChildEnv({
    MCP_SHELL_TOKEN: "supersecret",
    MCP_SHELL_ALLOWED_COMMANDS: "echo",
    MCP_SHELL_ALLOWED_ORIGINS: "http://localhost",
    MCP_SHELL_BIN: "/bin/bash",
    NODE_ENV: "production",
    PORT: "3012",
    HOST: "127.0.0.1",
    MCP_ENDPOINT: "/mcp",
    ROUTE_PREFIX: "/shell",
    PATH: "/usr/bin:/bin",
    HOME: "/home/user",
    MY_APP_VAR: "keep-me",
  });
  for (const k of ["MCP_SHELL_TOKEN", "MCP_SHELL_ALLOWED_COMMANDS", "MCP_SHELL_ALLOWED_ORIGINS", "MCP_SHELL_BIN", "NODE_ENV", "PORT", "HOST", "MCP_ENDPOINT", "ROUTE_PREFIX"]) {
    assert.equal(env[k], undefined, k + " must be scrubbed");
  }
  assert.equal(env.PATH, "/usr/bin:/bin", "PATH preserved so commands still resolve");
  assert.equal(env.HOME, "/home/user", "HOME preserved");
  assert.equal(env.MY_APP_VAR, "keep-me", "unrelated vars pass through");
});

// ── Integration ────────────────────────────────────────────────────────────────
let server;
let baseUrl;

before(async () => {
  const app = createApp({ token: TOKEN, allowedCommands: ["echo"], mcpEndpoint: ENDPOINT });
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (server) {
    server.closeAllConnections?.();
    server.close();
  }
});

async function authedClient() {
  const client = new Client({ name: "mcp-shell-test", version: "1.0.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}${ENDPOINT}`), {
    requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
  });
  await client.connect(transport);
  return client;
}

test("no bearer token -> 401 (before the MCP session, not 400)", async () => {
  const res = await fetch(`${baseUrl}${ENDPOINT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(res.status, 401);
});

test("invalid bearer token -> 401", async () => {
  const res = await fetch(`${baseUrl}${ENDPOINT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer wrong-token" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(res.status, 401);
});

test("disallowed Origin -> 403, refused before auth (no token needed to be rejected)", async () => {
  const res = await fetch(`${baseUrl}${ENDPOINT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "http://evil.example.com" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(res.status, 403);
});

test("loopback Origin passes the rebinding guard and falls through to auth (401 without token)", async () => {
  const res = await fetch(`${baseUrl}${ENDPOINT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "http://localhost:3000" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(res.status, 401);
});

test("createApp refuses to build without a token", () => {
  assert.throws(() => createApp({ allowedCommands: ["echo"] }), /bearer token is required/);
});

test("allowlisted command runs over MCP (with token)", async () => {
  const client = await authedClient();
  try {
    const { tools } = await client.listTools();
    assert.ok(tools.some((t) => t.name === "execute_command"));

    const ok = await client.callTool({ name: "execute_command", arguments: { command: "echo allowed-ok" } });
    assert.equal(ok.isError, false);
    assert.match(ok.content.map((c) => c.text).join("\n"), /allowed-ok/);
  } finally {
    await client.close();
  }
});

test("non-allowlisted command is rejected without executing", async () => {
  const client = await authedClient();
  try {
    const denied = await client.callTool({ name: "execute_command", arguments: { command: "whoami" } });
    assert.equal(denied.isError, true);
    const text = denied.content.map((c) => c.text).join("\n");
    assert.match(text, /default-deny allowlist/);
    assert.match(text, /not in the allowlist/);
  } finally {
    await client.close();
  }
});

test("execute_command advertises behavioral annotations over MCP", async () => {
  const client = await authedClient();
  try {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "execute_command");
    assert.ok(tool, "execute_command is listed");
    assert.equal(tool.annotations?.title, "Execute Shell Command");
    assert.equal(tool.annotations?.destructiveHint, true);
    assert.equal(tool.annotations?.openWorldHint, true);
    assert.equal(tool.annotations?.readOnlyHint, false);
  } finally {
    await client.close();
  }
});
