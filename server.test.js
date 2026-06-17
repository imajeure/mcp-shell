/**
 * server.test.js — unit + integration tests for mcp-shell.
 *
 * Run: `npm test`  (node --test)
 *
 * Unit: route-prefix derivation, output truncation, and the default-deny
 * allowlist check. Integration: boots the real server on an ephemeral port and
 * exercises the two security layers over the MCP Streamable HTTP client —
 * allowed command runs, non-allowlisted command is rejected, and a request with
 * no/invalid bearer token gets 401 (before any MCP session handling).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createApp,
  truncate,
  deriveRoutePrefix,
  checkAllowed,
  parseAllowedCommands,
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
