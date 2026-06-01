/* minertop — main entry point.
 *
 * Two modes:
 *   • live (default)            — yeet run main.js
 *     Streams events to the interactive dashboard. Repaints every
 *     200 ms. Runs until Ctrl-C.
 *   • audit (one-shot scan)     — yeet run main.js -- --audit
 *     Watches everything for N seconds (default 60, set --duration N),
 *     then prints a structured report and exits.
 *     Add --json for machine-readable output.
 *
 * Both modes use the same kernel-side BPF surface (three CO-RE hooks)
 * and the same state model. The only differences are: audit mode
 * doesn't draw the dashboard, doesn't run the render loop, and exits
 * once its window closes. */

import { RingBuf } from "yeet:bpf";
import bpf from "./bin/minertop.bpf.o";

import { onEvent, advance, TICK_MS } from "./state.js";
import { renderDashboard, clearScreen } from "./dashboard.js";
import { runAudit } from "./audit.js";

const HIDE = "\x1b[?25l";
const SHOW = "\x1b[?25h";

const args = globalThis.yeet?.args ?? {};
const AUDIT_MODE = !!args.audit;
const AUDIT_JSON = !!args.json;

/* --duration N (seconds). Default to 60. Coerce defensively — yeet's
 * arg parsing may pass strings; we want a positive integer. */
function parseDuration() {
  const raw = args.duration;
  if (raw == null) return 60;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 60;
  return Math.min(3600, Math.floor(n));   /* hard cap at 1 hour */
}
const AUDIT_DURATION_MS = parseDuration() * 1000;

const tty = globalThis.tty;

/* The dashboard needs a live tty. Audit mode tolerates its absence —
 * its output is plain stdout-friendly text. */
if (!AUDIT_MODE && !tty) {
  console.error("minertop: no tty available (yeet didn't expose globalThis.tty)");
  throw new Error("missing tty");
}

let cols = 100, rows = 36;
function readSize() {
  if (!tty) return;
  const sz = tty.size?.();
  if (sz) { cols = sz.cols ?? cols; rows = sz.rows ?? rows; }
}
readSize();
tty?.on?.("resize", () => { readSize(); paint(); });

function paint() {
  if (!tty) return;
  const frame = renderDashboard(cols, rows);
  if (tty.beginFrame) {
    tty.beginFrame();
    tty.write(frame);
    tty.endFrame();
  } else {
    tty.write(frame);
  }
}

async function main() {
  /* Bind the BPF ringbuf — same for both modes. The classification
   * decision ("is this connection talking to a known mining pool?
   * is the process name spoofing a kernel thread?") lives in JS, so
   * the kernel side is identical regardless of mode. */
  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "conn_evt" })
    .start();

  await new RingBuf(control, "events").subscribe(
    (evt) => onEvent(evt.conn_evt ?? evt),
    (err) => console.error("minertop ringbuf error:", err?.message ?? err),
  );

  if (AUDIT_MODE) {
    /* One-shot scan: collect for AUDIT_DURATION_MS, print report,
     * then exit. We let the BPF ringbuf keep streaming events into
     * state during the wait. */
    await runAudit({
      durationMs: AUDIT_DURATION_MS,
      asJSON: AUDIT_JSON,
    });
    /* yeet doesn't expose process.exit predictably across runtimes,
     * but throwing a sentinel-free no-op return from main() lets the
     * runtime clean up. The runtime will also tear down on Ctrl-C
     * if the user wants to bail early. */
    return;
  }

  /* Live mode. */
  tty.write(HIDE);
  tty.write(clearScreen());
  setInterval(() => { advance(); paint(); }, TICK_MS);
  paint();   /* first frame so screen isn't blank until tick 1 */
}

main().catch((e) => {
  tty?.write(SHOW);
  console.error(e?.stack ?? e?.message ?? e);
});
