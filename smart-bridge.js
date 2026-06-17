/**
 * smart-bridge.js — vendored from the `mcp-stdio-bridge` package.
 * ===============================================================
 * Kept in-tree (zero dependencies) so this server is fully self-contained.
 * To update, re-copy `index.js` from mcp-stdio-bridge.
 *
 * mcp-stdio-bridge — self-heal primitives for HTTP-bridged MCP servers
 *
 * Building blocks for an MCP server that is exposed over HTTP while its real
 * work happens in a child process (a stdio MCP server you proxy) or a
 * throwaway subprocess. The goal is to let the bridge detect and heal its own
 * *readiness* (not just liveness): a real `/ready` path, a systemd watchdog
 * that catches hangs `Restart=` cannot, and gentle child-respawn before a hard
 * unit restart.
 *
 * Two shapes are supported:
 *   - persistent stdio child  → use `ChildSupervisor` (owns the child + the
 *     gentle→hard respawn ladder).
 *   - no persistent child     → skip `ChildSupervisor`; the readiness check
 *     spawns a throwaway subprocess and confirms it round-trips.
 * Either way, `createNotifier` + `startWatchdog` + `makeReadyRoute` apply.
 *
 * ZERO DEPENDENCIES — Node built-ins only (child_process). This is load-
 * bearing: the same module must run identically under Node and Bun, which is
 * why sd_notify is a `systemd-notify` shell-out and NOT the native `sd-notify`
 * C binding, and also NOT Node's `dgram` (Node core `dgram` cannot open an
 * AF_UNIX SOCK_DGRAM socket — verified `ERR_SOCKET_BAD_TYPE` on Node 24.14.1;
 * see the "sd_notify" note below).
 */

import { execFile } from "node:child_process";

const SYSTEMD_NOTIFY = process.env.SYSTEMD_NOTIFY_BIN || "/usr/bin/systemd-notify";

// ── Self-report stub ─────────────────────────────────────────────────────────
// A structured readiness/heal event emitter with an injectable sink. The default
// sink writes one JSON line to stderr (journald captures it). Swap in your own
// logging/alerting backend without touching anything else.
//
// Event shapes (the `event` field): ready | not_ready | child_respawn |
// escalation | watchdog_skip | watchdog_halt | notify_error.
const defaultSink = (event) => {
  try {
    console.error("[mcp-stdio-bridge:selfreport] " + JSON.stringify(event));
  } catch {
    /* never let logging throw */
  }
};

export function selfReport(event, sink = defaultSink) {
  const enriched = { ts: new Date().toISOString(), ...event };
  try {
    sink(enriched);
  } catch {
    /* a broken sink must never break the bridge */
  }
}

// ── withTimeout ──────────────────────────────────────────────────────────────
// Races a promise against a timeout so a hung child can never wedge `/ready`
// or the watchdog tick. The timer is unref'd so it never holds the loop open.
export class TimeoutError extends Error {
  constructor(label, ms) {
    super(`${label} timed out after ${ms}ms`);
    this.name = "TimeoutError";
  }
}

export function withTimeout(promise, ms, label = "operation") {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError(label, ms)), ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ── sd_notify (systemd-notify shell-out) ─────────────────────────────────────
// NOTIFY_SOCKET is an AF_UNIX SOCK_DGRAM socket. Node core `dgram` only does
// udp4/udp6 and `net` only does stream Unix sockets, so we shell out to
// `systemd-notify` — dependency-free and byte-identical under Node and Bun.
//
//   - `--pid=<main pid>` attributes the notify to the server's main PID, not
//     the short-lived helper (belt-and-suspenders with NotifyAccess=all).
//   - execFile (no shell) keeps each ~15s beat cheap.
//   - A failed/slow notify is swallowed — it must never block or crash the
//     server. WATCHDOG=1 is fire-and-forget; if it genuinely can't be sent,
//     systemd's watchdog timeout will (correctly) restart us anyway.
export function createNotifier({ selfReport: report = selfReport } = {}) {
  const enabled = !!process.env.NOTIFY_SOCKET;
  let readySent = false;

  function send(state) {
    if (!enabled) return;
    execFile(
      SYSTEMD_NOTIFY,
      [`--pid=${process.pid}`, state],
      { env: process.env, timeout: 5000 },
      (err) => {
        if (err) report({ event: "notify_error", state, error: err.message });
      }
    );
  }

  return {
    enabled,
    /** Send READY=1 exactly once (first time /ready passes). Idempotent. */
    notifyReady() {
      if (readySent) return;
      readySent = true;
      send("READY=1");
      report({ event: "ready" });
    },
    /** Send a WATCHDOG=1 heartbeat. Caller gates this on a passing /ready. */
    beat() {
      send("WATCHDOG=1");
    },
  };
}

// ── Watchdog loop ────────────────────────────────────────────────────────────
// Runs readyCheck at WatchdogSec/2 (~15s). The heartbeat is GATED on a passing
// /ready — never heartbeat a hung tool, that's the whole point. First pass
// emits READY=1 (so Type=notify considers us started only on *real* readiness).
//
//   - readyCheck fails (e.g. child hung, /ready 503) → skip beat → after
//     WatchdogSec with no beat, systemd restarts the unit. This is the hang
//     fix `Restart=` could never do.
//   - halt() permanently stops beats (escalation lever): a supervisor that has
//     given up on gentle respawn calls it so systemd does a full unit restart
//     regardless of subsequent /ready state.
export function startWatchdog({
  notifier,
  readyCheck,
  intervalMs,
  onTick,
  selfReport: report = selfReport,
}) {
  let stopped = false;
  let halted = false;
  let timer = null;

  async function tick() {
    if (stopped) return;
    let ok = false;
    try {
      await readyCheck();
      ok = true;
    } catch (err) {
      report({ event: "not_ready", error: err && err.message });
    }
    if (stopped) return;

    if (ok) notifier.notifyReady(); // first successful check flips Type=notify to "started"
    if (ok && !halted) {
      notifier.beat();
    } else {
      report({ event: "watchdog_skip", halted, ready: ok });
    }
    if (onTick) {
      try {
        onTick({ ok, halted });
      } catch {
        /* observer must not break the loop */
      }
    }
  }

  // Kick an immediate check so READY isn't delayed a full interval on boot.
  tick();
  timer = setInterval(tick, intervalMs);
  if (timer.unref) timer.unref();

  return {
    stop() {
      stopped = true;
      if (timer) clearInterval(timer);
    },
    /** Escalation: stop heartbeating so systemd's watchdog hard-restarts us. */
    halt() {
      if (halted) return;
      halted = true;
      report({ event: "watchdog_halt" });
    },
    isHalted: () => halted,
  };
}

// ── /ready Express route factory ─────────────────────────────────────────────
// Returns a plain (req,res) handler — we don't import express here, keeping the
// module dependency-free. 200 on a passing real-path check, 503 otherwise.
export function makeReadyRoute(readyCheck) {
  return async (_req, res) => {
    try {
      await readyCheck();
      res.status(200).json({ ready: true });
    } catch (err) {
      res.status(503).json({ ready: false, error: err && err.message });
    }
  };
}

// ── ChildSupervisor — for a persistent stdio child ───────────────────────────
// Owns a persistent stdio child's lifecycle and the gentle→hard respawn ladder.
//
//   gentle: on child *exit* (transport close), respawn the child while the HTTP
//           listener stays up. A single child blip never drops a request.
//   hard:   after `escalateAfter` exits within `gentleWindowMs`, mark escalated
//           and fire onEscalate() (the server wires that to watchdog.halt()), so
//           systemd does a full unit restart.
//
// NOTE on hung vs exited children: the ladder is driven by child *exit* events.
// A child that *exits* makes /ready fail and is recovered gently here. A child
// that *hangs* without exiting is deliberately left to the systemd watchdog
// (skip-beat → restart) — we do not force-kill a hung child in-process. This
// keeps the watchdog as the authoritative hang-catcher.
export class ChildSupervisor {
  /**
   * @param {object}   opts
   * @param {string}   opts.name           label for logs/self-report
   * @param {Function} opts.spawn          async (onClose) => connected MCP Client
   * @param {number}  [opts.escalateAfter] exits-within-window before hard restart (default 2)
   * @param {number}  [opts.gentleWindowMs] sliding window for the counter (default 60000)
   * @param {number}  [opts.gentleDelayMs]  delay before a gentle respawn (default 3000)
   * @param {Function}[opts.selfReport]
   */
  constructor({
    name,
    spawn,
    escalateAfter = 2,
    gentleWindowMs = 60_000,
    gentleDelayMs = 3_000,
    selfReport: report = selfReport,
  }) {
    this.name = name;
    this._spawn = spawn;
    this.escalateAfter = escalateAfter;
    this.gentleWindowMs = gentleWindowMs;
    this.gentleDelayMs = gentleDelayMs;
    this._report = report;

    this.client = null;
    this.starting = false;
    this.escalated = false;
    this._failures = []; // timestamps of recent child exits/spawn-failures
    this._escalateCbs = [];
  }

  /** Register a callback fired once when the ladder escalates (→ watchdog.halt). */
  onEscalate(cb) {
    this._escalateCbs.push(cb);
  }

  /** The connected MCP client; throws if mid-respawn (caller treats as not-ready). */
  getClient() {
    if (!this.client) throw new Error(`${this.name} child not connected`);
    return this.client;
  }

  isHealthy() {
    return !!this.client;
  }

  /** Spawn (or respawn) the child. Keeps the HTTP listener untouched. */
  async start() {
    if (this.starting || this.escalated || this.client) return;
    this.starting = true;
    try {
      const client = await this._spawn(() => this._onChildClose());
      this.client = client;
      this.starting = false;
      this._report({ event: "child_respawn", name: this.name, phase: "connected" });
    } catch (err) {
      this.starting = false;
      this.client = null;
      this._report({
        event: "child_respawn",
        name: this.name,
        phase: "spawn_failed",
        error: err && err.message,
      });
      this._recordFailure();
      if (!this.escalated) {
        setTimeout(() => this.start().catch(() => {}), 5_000);
      }
    }
  }

  _onChildClose() {
    if (this.escalated) return;
    this.client = null;
    this._report({ event: "child_respawn", name: this.name, phase: "closed" });
    this._recordFailure();
    if (this.escalated) return; // _recordFailure may have escalated us
    setTimeout(() => this.start().catch(() => {}), this.gentleDelayMs);
  }

  _recordFailure() {
    const now = Date.now();
    this._failures = this._failures.filter((t) => now - t < this.gentleWindowMs);
    this._failures.push(now);
    if (this._failures.length >= this.escalateAfter && !this.escalated) {
      this.escalated = true;
      this._report({
        event: "escalation",
        name: this.name,
        failures: this._failures.length,
        windowMs: this.gentleWindowMs,
      });
      for (const cb of this._escalateCbs) {
        try {
          cb();
        } catch {
          /* escalation callback must not throw */
        }
      }
    }
  }
}
