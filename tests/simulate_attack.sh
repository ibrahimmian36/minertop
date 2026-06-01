#!/usr/bin/env bash
# simulate_attack.sh — reproduce the cryptominer attack pattern
# minertop detects, so you can verify the detection works on your box.
#
# What this does:
#   1. Spins up a fake mining-pool listener on a known Stratum port
#      (TCP/14444, Monero default). The listener just absorbs bytes.
#   2. Spawns a python process that calls prctl(PR_SET_NAME) to rename
#      itself to "kworker/u4:2" — a real kernel-thread name pattern.
#      Real kernel threads CANNOT make outbound TCP connections, so
#      this is the exact pattern Kinsing and similar malware use to
#      hide cryptojackers from `ps`.
#   3. The spoofed process repeatedly connects to the fake pool and
#      sends Stratum-like JSON-RPC payloads.
#
# Run minertop in another shell first:
#     yeet run main.js
# Then run this script. Within ~2 seconds the EGRESS ALERTS panel
# should turn red with "CRITICAL — pid X (kworker/u4:2) → 127.0.0.1:14444".
#
# To stop: Ctrl-C in this shell. The listener and miner both die.
#
# Audit-mode equivalent: run this script in one shell, then in another
#     yeet run main.js -- --audit --duration 15
# The 15-second scan will catch the attack and the verdict will be
# CRITICAL.

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "simulate_attack.sh: python3 not found in PATH" >&2
  echo "  install python3 and try again" >&2
  exit 1
fi

PORT="${PORT:-14444}"

cleanup() {
  echo "" >&2
  echo "simulate_attack.sh: stopping..." >&2
  # kill all our background jobs
  jobs -p | xargs -r kill 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

echo "simulate_attack.sh — fake mining pool on 127.0.0.1:$PORT" >&2
echo "                    + kworker-spoofed client connecting in a loop" >&2
echo "" >&2

# ---- background: fake mining pool listener -------------------------------
# Tries nc first (universally available); falls back to a python listener
# if nc isn't installed.
start_listener() {
  if command -v nc >/dev/null 2>&1; then
    # The -k flag (keep-open) varies between netcat flavors. Use a loop
    # so we re-listen after each client disconnect.
    ( while true; do
        nc -l -p "$PORT" -q 1 > /dev/null 2>&1 || true
      done ) &
  else
    python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(8)
while True:
    try:
        c, _ = s.accept()
        # drain forever; we don't reply, we just absorb
        while True:
            d = c.recv(4096)
            if not d: break
    except KeyboardInterrupt: break
    except Exception: pass
" &
  fi
  echo "  [listener] up on 127.0.0.1:$PORT (pid $!)" >&2
}

start_listener
sleep 0.3   # give the listener a moment to bind

# ---- foreground: kworker-spoofed client ----------------------------------
# prctl(PR_SET_NAME, "kworker/u4:2") makes /proc/<pid>/comm read "kworker/u4:2"
# — the same hiding technique used by the Kinsing malware family. minertop
# detects this in BPF because the kernel reports the spoofed comm via
# bpf_get_current_comm() in tcp_sendmsg, but the process is still
# observably opening TCP connections — something real kernel threads
# never do.
echo "  [client]   starting kworker-spoofed loop..." >&2
echo "  watch your minertop dashboard now." >&2
echo "  press Ctrl-C here to stop." >&2

python3 -c "
import socket, ctypes, time, sys
ctypes.CDLL('libc.so.6').prctl(15, b'kworker/u4:2', 0, 0, 0)
print('  [client]   comm spoofed to kworker/u4:2 (pid', __import__('os').getpid(), ')', file=sys.stderr, flush=True)
while True:
    try:
        s = socket.socket()
        s.connect(('127.0.0.1', $PORT))
        # Fake Stratum 'subscribe' message — the real protocol shape
        # malware would use. Doesn't matter that the listener doesn't
        # respond; minertop is observing the connection + bytes only.
        for _ in range(30):
            s.send(b'{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"mining.subscribe\",\"params\":[]}\n')
            time.sleep(0.1)
        s.close()
        time.sleep(0.4)
    except KeyboardInterrupt:
        break
    except Exception as e:
        time.sleep(0.5)
"
