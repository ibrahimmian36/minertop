/* minertop — main entry point.
 *
 * One ringbuf in, three event kinds out (OPEN / BYTES / CLOSE).
 * state.js owns the model + mining detection; dashboard.js owns the
 * pixels. The classification decision ("is this connection talking to
 * a known mining pool? is the process name spoofing a kernel thread?")
 * lives entirely in JS — pure data + heuristics over BPF events. */

import { RingBuf } from "yeet:bpf";
import bpf from "./bin/minertop.bpf.o";

import { onEvent, advance, TICK_MS } from "./state.js";
import { renderDashboard, clearScreen } from "./dashboard.js";

const HIDE = "\x1b[?25l";
const SHOW = "\x1b[?25h";

const tty = globalThis.tty;
if (!tty) {
  console.error("minertop: no tty available (yeet didn't expose globalThis.tty)");
  throw new Error("missing tty");
}

let cols = 100, rows = 36;
function readSize() {
  const sz = tty.size?.();
  if (sz) { cols = sz.cols ?? cols; rows = sz.rows ?? rows; }
}
readSize();
tty.on?.("resize", () => { readSize(); paint(); });

function paint() {
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
  tty.write(HIDE);
  tty.write(clearScreen());

  /* Bind the BPF ringbuf and stream events into state. Some yeet builds
   * wrap the decoded record under its struct name; others hand it
   * directly. Accept either. */
  const control = await bpf
    .bind("events", { kind: "ringbuf", btf_struct: "conn_evt" })
    .start();

  await new RingBuf(control, "events").subscribe(
    (evt) => onEvent(evt.conn_evt ?? evt),
    (err) => console.error("minertop ringbuf error:", err?.message ?? err),
  );

  /* render cadence */
  setInterval(() => { advance(); paint(); }, TICK_MS);

  /* first frame so the screen isn't blank until tick 1 */
  paint();
}

main().catch((e) => {
  tty.write(SHOW);
  console.error(e?.stack ?? e?.message ?? e);
});
