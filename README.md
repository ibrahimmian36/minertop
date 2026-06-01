# minertop

**Behavioral hidden-cryptominer detector for Linux.** Scan your box; get a verdict in 60 seconds. No signature database, no agent, no cloud — just a kernel-side eBPF observer matching outbound TCP destinations against a mining-pool port database and flagging processes whose names lie about who they are.

```
$ yeet run https://github.com/ibrahimmian36/minertop -- --audit
```

That command runs a one-shot scan and prints a structured report. If your box is clean, the verdict says so. If something's mining behind a spoofed process name, it tells you the PID, the pool, and the bytes.

minertop catches the [Kinsing](https://en.wikipedia.org/wiki/Kinsing) family of cryptojackers — and anything else using the same pattern: a process renaming itself to `kworker/u4:2` or `systemd-resolved` while opening outbound TCP to a Monero pool. Real kernel threads can't open outbound TCP; if something claims to be one and is mining, it's malware.

It's built on [**yeet**](https://yeet.cx), a Linux runtime that makes a kernel-side BPF program, a per-tick render loop, and a JS state model feel like one program.

<p align="center"><img src="assets/minertop.gif" alt="minertop demo" width="820"></p>

---

## Why this isn't a signature scanner

Most "detect crypto miners" tools work by hashing files against a known-bad database (YARA, ClamAV, ETs). They miss anything that's not in their database — and the database is always behind.

**minertop is behavioral.** It doesn't care what the file on disk looks like. It watches what the process *does* at the kernel boundary:

1. **Does it talk to a known mining pool port?** Stratum on `14444` (Monero), `2020` (Ethereum), the NiceHash range, etc. — a curated database lives in `render.js` (~30 entries) and the kernel just reports the destination port. No payload inspection, no DPI.
2. **Is it lying about its identity?** Real kernel threads (`kworker/*`, `ksoftirqd`, `swapper`) physically cannot open outbound TCP. So if a process named like one is sending bytes to a mining pool, that's not coincidence — that's a spoofed `prctl(PR_SET_NAME, "kworker/u4:2")` call from malware trying to hide in `ps`.

Result: a miner running under a brand-new SHA256 still trips the detector because the *behavior* hasn't changed, just the file. The detection rules are 50 lines of JavaScript you can read in two minutes.

## How to verify it works — run the simulator

The repo ships a working attack simulator at `tests/simulate_attack.sh`. It launches a fake mining pool on `127.0.0.1:14444` and a Python process that renames itself to `kworker/u4:2` (using the same `prctl(PR_SET_NAME)` syscall real malware uses) and then sends Stratum-shaped traffic in a loop.

```sh
# In one shell — start minertop's audit
yeet run main.js -- --audit --duration 20

# In another shell — fire the simulated attack
./tests/simulate_attack.sh
```

After 20 seconds, the audit will print:

```
VERDICT: CRITICAL — hidden cryptominer detected
  1 process(es) talking to mining pools while spoofing kernel-thread names.
```

Stop the simulator with `Ctrl-C`. You've now verified the detection works on your box, without ever installing real malware.

## Audit mode (one-shot scan)

The default mode for "is this server compromised right now?" workflows. Runs for a fixed window, watches every outbound TCP connection, and prints a verdict + supporting evidence to stdout. Safe to redirect, pipe through `tee`, or paste in a ticket.

```sh
# 60-second scan (default)
yeet run main.js -- --audit

# Longer scan (90 seconds — useful for fleets where some miners are bursty)
yeet run main.js -- --audit --duration 90

# Machine-readable for scripting / dashboards
yeet run main.js -- --audit --duration 60 --json | tee scan-$(hostname).json
```

Sample clean output:

```
════════════════════════════════════════════════════════════════
  minertop audit · behavioral hidden-cryptominer scan
════════════════════════════════════════════════════════════════

  Scan started: 2026-05-31T14:18:01.234Z
  Scan ended:   2026-05-31 14:19:01 UTC
  Duration:     1m 0s

── Connections observed ────────────────────────────────────────
  TCP events seen:          847
  Connections opened:       42
  Connections closed:       39
  Distinct destinations:    18
  Total bytes ↑/↓:          12MB / 38MB

── Mining pool detection ───────────────────────────────────────
  High-confidence mining ports:  0
  Likely Stratum ports:          0
  Crypto P2P ports (BTC/ETH):    0  (informational, not mining)
  Mining traffic ↑/↓:            0B / 0B
  Overall:                       ✓ NONE

── Comm-name mimicry detection ─────────────────────────────────
  Kernel-thread name spoofing:   0
  System-daemon name spoofing:   0
  Overall:                       ✓ NO MIMICRY OBSERVED

── Top destinations by bandwidth ───────────────────────────────
   1. 140.82.114.4:443
      ↑3.2MB / ↓18MB    conns: 12
   2. 151.101.1.5:443
      ↑1.8MB / ↓8MB     conns: 8

════════════════════════════════════════════════════════════════
VERDICT: NO MINING ACTIVITY DETECTED
  No connections to known mining pools or Stratum-class ports.
  No processes mimicking kernel-thread names with outbound TCP.
════════════════════════════════════════════════════════════════
```

## Live mode (dashboard)

For watching activity in real time. Repaints every 200 ms.

```sh
yeet run main.js
```

The dashboard:

```
 ▌ MINERTOP · crypto-mining traffic detector ────────────────────────────────────────────────────────────────────
● LIVE 00:24   3 conn   ▲180KB/s ▼42KB/s   ⛏ 96% mining   ⚠ 1 CRITICAL · 0 susp

  ⚠ HIDDEN MINER ALERTS · process names spoofing kernel threads / daemons ──────────────────────────────────────
  CRITICAL  pid 8821 kworker/u4:2     → Ethereum Stratum         1.2MB↑ 340KB↓        12s

  MINING ACTIVITY · ⛏ confirmed  ⛏! kernel-thread mimicry  ⛏? daemon mimicry ────────────────────────────────────
   ⛏! kworker/u4:2     pid 8821    160KB/s   38KB/s    1 pool   12s
   ⛏  xmrig            pid 4231    18KB/s    4KB/s     1 pool   24s

  POOLS · sorted by current bandwidth · 2.4MB↑ 720KB↓ mining bytes total ────────────────────────────────────────
   ⛏ 142.93.124.5:2020         Ethereum Stratum    ▲160KB/s ▼38KB/s   1 miner
   ⛏ 65.21.198.20:14444        Monero Stratum      ▲18KB/s  ▼4KB/s    1 miner

  CONNECTION FEED · opens and closes, newest first ─────────────────────────────────────────────────────────────
   00:24  ⛏ ● OPEN  10.0.0.12:51932          → 142.93.124.5:2020    pid 8821 kworker/u4:2
   00:24  ⛏ ● OPEN  10.0.0.12:51931          → 65.21.198.20:14444   pid 4231 xmrig
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

**HIDDEN MINER ALERTS** — only shown when alerts exist. Two tiers:
- `CRITICAL` — process name matches a kernel-thread prefix. Kernel threads can't open outbound TCP. If you see this, it's malware.
- `suspicious` — process name matches a common system-daemon prefix. These *can* legitimately have network connections but should not be mining.

**MINING ACTIVITY** — every process talking to a mining pool, sorted with mimicry hits at the top.

**POOLS** — destination pools currently active, with coin and protocol inferred from the port.

**CONNECTION FEED** — every open and close, mining-highlighted.

For a shareable screenshot, anonymize identifying details:

```sh
yeet run main.js -- --anonymize
```

## Limitations & evasion paths

minertop is honest about what it catches and what it doesn't. Anyone designing around it should know these:

- **Custom mining pools on non-standard ports.** The port database covers public-pool defaults (NiceHash, 2miners, Ethermine, Monero defaults, etc.). A private pool running on port `443` looks like HTTPS traffic to minertop. The mitigation: pair with egresstop-style allowlist enforcement so unauthorized destinations are flagged independently.
- **Non-spoofed process names.** If the miner names itself `nginx-worker`, `nodejs`, or `chrome-helper`, the mimicry detector won't fire. The MINING ACTIVITY panel still surfaces the connection — it just doesn't promote it to a CRITICAL alert. Sophisticated attackers blend in; lazy ones (which is most cryptojacking malware) hide as kernel threads. minertop catches the lazy ones loudly and the sophisticated ones quietly.
- **Stratum over TLS on standard ports.** Some pools offer `stratum+ssl://`. If routed to a non-default port from the database, missed. If routed to `443`, missed (looks like HTTPS).
- **Theoretical: BPF-resident mining.** A maximally evasive miner could run *inside* an eBPF program itself, never touching the user-process syscall surface. This is exotic and not seen in the wild, but it's a real category. Defense against this would be checking which BPF programs are loaded — out of scope for minertop.
- **Connection-before-start blindness.** Connections opened before minertop launches are invisible until they next transition state. The audit window catches everything for its duration, but a long-lived miner that established its socket hours ago and rarely re-opens won't trigger an OPEN event during the scan. The BYTES path still catches active traffic, so any miner currently moving data is detected.
- **Process attribution edge cases.** TCP state transitions can fire from softirq context where the current task is `swapper` or a `kworker`. minertop refuses those as the real owner and waits for `tcp_sendmsg`/`tcp_cleanup_rbuf` in app context to fix attribution. Converges within microseconds for any process actually moving data.

## Real-world incidents this is designed for

- **[Kinsing](https://en.wikipedia.org/wiki/Kinsing)** — Linux cryptojacker family active 2020-present. Spreads through misconfigured Docker / Redis / SaltStack instances. Renames itself to look like a kernel thread. Detected by minertop's CRITICAL mimicry tier on first outbound Stratum byte.
- **TeamTNT** — campaigns 2020-2022 targeting cloud Linux hosts, installing XMRig-based miners disguised as system processes.
- **Sysrv-hello** — Go-based mining worm, also masquerades as system daemons.

The common thread: outbound to public mining pools + process-name camouflage. minertop is a focused detector for exactly that pattern.

## What's under the hood

Three BPF programs feed one ring buffer:

| BPF program        | hook                            | what it does                                                |
|--------------------|---------------------------------|-------------------------------------------------------------|
| `on_set_state`     | `tp_btf/inet_sock_set_state`    | track new conns at `TCP_ESTABLISHED`, reap at `TCP_CLOSE`   |
| `on_sendmsg`       | `fentry/tcp_sendmsg`            | count tx bytes; fix pid to the real sender (app ctx)        |
| `on_cleanup_rbuf`  | `fentry/tcp_cleanup_rbuf`       | count rx bytes; fix pid to the real receiver (app ctx)      |

One `HASH` map (`conns`, keyed by sock pointer) stores per-connection state and cumulative byte counts. One `RINGBUF` (256 KiB) carries three event kinds to JS: `OPEN`, `BYTES` (delta every 64 KiB), `CLOSE`. The kernel side is CO-RE — uses libbpf BTF relocations, no fixed offsets, portable across kernel versions.

All mining-specific intelligence (port database, mimicry detection, alert ranking, verdict logic) lives in JavaScript. A new mining-pool port shows up in a one-line patch to `render.js` rather than a kernel reload.

- `main.js` — entry: dispatches between live mode and audit mode, BPF bind/subscribe
- `state.js` — connection model + mining-aware aggregators + hidden-miner detection
- `audit.js` — one-shot scan logic + report formatting (human + JSON)
- `render.js` — ANSI, color ramps, byte/port formatters, **the mining pool port database**
- `dashboard.js` — panels + layout (`renderDashboard`) for live mode

## Requirements

- Linux ≥ 5.5 (for `fentry` and `tp_btf`); Debian 13, Ubuntu 22.04+, Fedora 36+, recent Arch all fine
- Kernel BTF: `CONFIG_DEBUG_INFO_BTF=y`, default on current Arch, Fedora, Ubuntu, and Debian 12+
- `CAP_BPF` + `CAP_PERFMON` — yeet handles this for you
- `clang` and `bpftool` to build the BPF object — `yeet run` does this for you on first launch

## Build it from a clone

```sh
git clone https://github.com/ibrahimmian36/minertop
cd minertop
make                    # builds bin/minertop.bpf.o
yeet run main.js        # run from source
```

`make clean` removes `bin/`. `make distclean` also removes the generated `include/vmlinux.h`.

---

Built on [yeet](https://yeet.cx). yeet is a Linux runtime for writing eBPF programs and live system dashboards in JavaScript.
