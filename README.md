# minertop

**Crypto-mining traffic detector for Linux** — in ten seconds, see who on your box is talking to a mining pool. Including the things lying about their name.

```
$ sudo yeet run https://github.com/ibrahimmian36/minertop
```

minertop catches the miner. No agents, no signature database, no proxy. The kernel sees every TCP connection; minertop classifies the destination port against a database of known mining pools and ranks processes by how confident the case against them is.

The headline feature is **hidden miner detection**: when a process with a name like `kworker/u4:2` or `systemd-resolved` is talking to a Monero pool, minertop flags it red. Real kernel threads can't open outbound TCP connections — anything claiming to be one and mining is malware that's lying about its identity.

It's built on [**yeet**](https://yeet.cx), a Linux runtime that makes a kernel-side BPF program, a per-tick render loop, and a JS state model feel like one program.

<p align="center">
  <img src="assets/minertop.gif" alt="minertop demo" width="820">
</p>

---

## What you actually see

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

Top to bottom:

A **header strip** with live system rates, the share of current bytes flowing on known mining ports, and a count of hidden-miner alerts. When that last cell goes red, attention.

A **HIDDEN MINER ALERTS** panel — only shown when alerts exist. Lists every process whose `comm` is mimicking a kernel thread or system daemon while talking to a mining pool. Two tiers:
- `CRITICAL` — process name matches a kernel-thread prefix (`kworker`, `ksoftirqd`, `swapper`, …). Kernel threads can't open outbound TCP. If you see this, it's malware.
- `suspicious` — process name matches a common system-daemon prefix (`systemd`, `dbus`, `cron`, …). These *can* legitimately have network connections but should not be mining.

A **MINING ACTIVITY** panel — every process talking to a mining pool, sorted with mimicry hits at the top. Glyph tells you the threat level at a glance: `⛏!` red for kernel-thread mimicry, `⛏?` orange for daemon mimicry, `⛏` for a process whose name doesn't look like an obvious lie (a known miner, or a custom-named one — could still be malware, just less obvious).

A **POOLS** panel — destination pools currently active, with the coin and protocol inferred from the port. Monero on `14444`, Ethereum on `2020`, NiceHash on `9200/9201`, Ravencoin on `12222`, and the generic Stratum ports (`3333/4444/5555/7777/8888/9999`) on which "we know it's Stratum, we just can't tell the coin."

A **CONNECTION FEED** — every open and close, mining-highlighted.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run https://github.com/ibrahimmian36/minertop
```

For a shareable screenshot, anonymize process names and remote addresses (everything identifying gets relabeled `proc-01`, `host-02`, …):

```sh
yeet run https://github.com/ibrahimmian36/minertop -- --anonymize
```

Runs until `Ctrl-C`. Resize the terminal and the layout reflows; minimum 80×28.

## What's under the hood

Three BPF programs feed one ring buffer:

| BPF program        | hook                            | what it does                                                |
|--------------------|---------------------------------|-------------------------------------------------------------|
| `on_set_state`     | `tp_btf/inet_sock_set_state`    | track new conns at `TCP_ESTABLISHED`, reap at `TCP_CLOSE`   |
| `on_sendmsg`       | `fentry/tcp_sendmsg`            | count tx bytes; fix pid to the real sender (app ctx)        |
| `on_cleanup_rbuf`  | `fentry/tcp_cleanup_rbuf`       | count rx bytes; fix pid to the real receiver (app ctx)      |

One `HASH` map (`conns`, keyed by sock pointer) stores per-connection state and cumulative byte counts. One `RINGBUF` (256 KiB) carries three event kinds to JS:

- `OPEN` — new connection observed, after we know who owns it
- `BYTES` — periodic delta, emitted every 64 KiB transferred in either direction
- `CLOSE` — connection ending, with the final cumulative byte counts

The kernel side is **identical to bytetop's** — same CO-RE-compliant hooks, same map shapes, same event format. The mining-specific intelligence (port database, mimicry detection, alert ranking) lives in JavaScript, which means a new mining pool port shows up in a 10-line patch to `render.js` rather than a kernel reload.

- `main.js` — entry: tty size, render loop, BPF bind/subscribe
- `state.js` — connection model + mining-aware aggregators + hidden-miner detection
- `render.js` — ANSI, color ramps, byte/port formatters, **the mining pool port database**
- `dashboard.js` — panels + layout (`renderDashboard`)

## Requirements

- Linux ≥ 5.5 (for `fentry` and `tp_btf`); Debian 13, Ubuntu 22.04+, Fedora 36+, recent Arch all fine
- Kernel BTF: `CONFIG_DEBUG_INFO_BTF=y`, default on current Arch, Fedora, Ubuntu, and Debian 12+
- `CAP_BPF` + `CAP_PERFMON` (typically root)
- `clang` and `bpftool` to build the BPF object — `yeet run` does this for you on first launch

## Build it from a clone

```sh
git clone https://github.com/ibrahimmian36/minertop
cd minertop
make                    # builds bin/minertop.bpf.o
sudo yeet main.js       # run from source
```

`make clean` removes `bin/`. `make distclean` also removes the generated `include/vmlinux.h`.

## How the detection actually works

**Port classification.** Every TCP destination port is matched against three sets:

- **High-confidence mining ports** (`14444`, `14433`, `18080`, NiceHash `3357/3858/9200/9201`, Ethermine `12020/12021`, Ravencoin `12222`). A connection to one of these is almost certainly mining.
- **Likely-mining Stratum ports** (`3333`, `4444`, `5555`, `7777`, `8888`, `9999`, `11111`, `2020`, `2021`, `8008`, `9000`, `5588`). Mining is the dominant use of these ports but they're not exclusive — a generic JSON-RPC service could plausibly land on `5555`.
- **Crypto P2P ports** (`8333` Bitcoin, `18333` testnet, `9333` Litecoin, `30303` Ethereum, `8233` Zcash, `22556` Dogecoin, `8767` Ravencoin). Not mining itself; running a full node. Surfaced informationally.

**Mimicry detection.** Process `comm` is checked against two prefix lists. Any match while the process is talking mining promotes the connection to an alert:

- `KERNEL_THREAD_PREFIXES` = `kworker`, `ksoftirqd`, `swapper`, `kthreadd`, `migration`, `rcu_`, `watchdog`, `idle_inject`, `writeback`, `kintegrityd`, `khungtaskd`, `kcompactd`, `kblockd`, `khugepaged`, `kthrotld`, `kswapd`, `kdevtmpfs`, `netns`, `irq/`, `ipv6_addrconf` → **critical**
- `SYSTEM_DAEMON_PREFIXES` = `systemd`, `dbus`, `cron`, `agetty`, `logind`, `rsyslogd`, `sshd`, `init`, `atd`, `udevd` → **suspicious**

## Caveats

- **Port heuristics are heuristics.** A mining pool reachable only on a non-standard port (say, port `1234`) won't be classified as mining. Conversely, a legitimate JSON-RPC service on port `5555` would be flagged. The classification is conservative on the high-confidence list and liberal on the likely-mining list; the dashboard distinguishes the two visually.
- **Mimicry detection only catches comm-spoofing.** Sophisticated malware can pick a process name that doesn't match either prefix list (`chrome-helper`, `node`, anything else). minertop will still surface the mining traffic — it just won't promote it to an alert. The mimicry detection catches the lazy attackers; the mining-activity panel catches everyone.
- **Process attribution is best-effort.** Same model as `bytetop`. TCP state transitions can fire from softirq context where `current` is `swapper` or a `kworker`. We refuse those as the real owner and let `tcp_sendmsg` / `tcp_cleanup_rbuf` (always app context) update us with the true PID. Attribution converges within microseconds for any process that actually does I/O.
- **Connections created before minertop starts are invisible** until they next transition state. No kernel walk on startup.
- **Ringbuf overflow drops events under extreme load.** The 256 KiB ringbuf can hold roughly 2 k threshold-emitted events; sustained tens of thousands of byte-emissions per second can drop. Mining traffic is sparse by nature so this is rarely an issue for the target use case.
- **TCP only.** Stratum and most P2P crypto protocols run on TCP. UDP-based mining (rare) won't be tracked.

## Differences from sibling tools

- **vs `bytetop`** — same BPF surface, but `bytetop` is system-wide byte accounting with no mining lens. `minertop` is a security tool that happens to use the same kernel hooks.
- **vs `httpsnoop`** — `httpsnoop` is a generic HTTP request snooper. `minertop` doesn't read TCP payloads at all — it classifies by destination port and process attribution. Lower kernel risk, narrower scope, different question.
- **vs Falco / commercial agents** — those are full-stack security platforms with signature databases, agents, and centralized alerting. `minertop` is one terminal window that gives you the answer right now, on this box, with no infrastructure.

---

Built on [yeet](https://yeet.cx). yeet is a Linux runtime for writing eBPF programs and live system dashboards in JavaScript.
