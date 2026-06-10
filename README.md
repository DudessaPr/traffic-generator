# tgen — Network Traffic Generator

A high-performance tool for injecting network traffic onto a live interface.
It has two distinct modes of operation:

- **Replay** (`tgen run`) — replays captured PCAP files with session-aware
  L3/L4 mutation, timing control, and session filtering.
- **Generate** (`tgen generate`) — synthesises fresh IPv4/IPv6 packets from a
  text template (no PCAP required); randomises addresses and ports per packet;
  supports multiple concurrent worker goroutines and pre-built packet buffers.

---

## Table of contents

1. [Requirements](#requirements)
2. [Build](#build)
3. [Quick start](#quick-start)
4. [Commands](#commands)
   - [run](#run)
   - [generate](#generate)
   - [inspect](#inspect)
   - [sessions](#sessions)
5. [Configuration file](#configuration-file)
   - [Full reference](#full-reference)
6. [Mutation rules](#mutation-rules)
7. [Session filtering](#session-filtering)
8. [Replay modes](#replay-modes)
9. [Metrics output](#metrics-output)
10. [Testing & benchmarks](#testing--benchmarks)
11. [Makefile targets](#makefile-targets)
12. [CLI examples](#cli-examples)

---

## Requirements

| Dependency | Notes |
|------------|-------|
| Go 1.22+   | `go version` to verify |
| libpcap    | macOS: pre-installed. Linux: `apt install libpcap-dev` / `yum install libpcap-devel` |
| Root / CAP_NET_RAW | Required at runtime for packet injection (`tgen run`) |

---

## Build

```bash
make build
# binary is written to ./build/tgen
```

Or directly:

```bash
CGO_ENABLED=1 go build -o build/tgen ./cmd/tgen/
```

---

## Quick start

```bash
# 1. Inspect what is inside a PCAP
./build/tgen inspect capture.pcap

# 2. List all sessions (flows) with verbose stats
./build/tgen sessions -v capture.pcap

# 3. Replay on interface eth0 at real-time speed (requires root)
sudo ./build/tgen run -i eth0 capture.pcap

# 4. Replay at 2× speed, overriding source IP
sudo ./build/tgen run -i eth0 --speed 2.0 --src-ip 10.0.0.1 capture.pcap

# 5. Use a config file for full control
sudo ./build/tgen run -c config/example.yaml

# 6. Generate synthetic TCP SYN flood — no PCAP needed (requires root)
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  -i eth0 --rate 100kpps

# 7. Generate ICMP echo requests from a /16 range until Ctrl-C
sudo ./build/tgen generate \
  -t "icmp:src=10.0.0.0/16:dst=192.168.1.1" \
  -i eth0
```

---

## Commands

### `run`

Replay one or more PCAP files onto a network interface.

```
tgen run [flags] <pcap files...>
tgen run -c <config.yaml>
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --interface` | *(required)* | Network interface(s) to inject traffic onto. Comma-separated or repeatable for multi-interface pool |
| `--target-ip` | — | Auto-resolve outbound interface and gateway MAC for this destination IP (alternative to `--interface`) |
| `--sender` | `pcap` | Packet injection backend: `pcap` (default) or `raw` (Linux AF_PACKET, lower overhead) |
| `-c, --config` | — | YAML config file (overrides all other flags) |
| `-s, --speed` | `1.0` | Replay speed multiplier. `1.0` = real-time, `2.0` = 2× faster, `0` = burst |
| `-m, --mode` | `sequential` | Replay mode: `sequential`, `parallel`, `burst`, `pcap` |
| `-l, --loop` | `false` | Repeat indefinitely |
| `--loop-count` | `0` | Number of replay passes (0 = once) |
| `--workers` | `4` | Goroutine count for `parallel` mode |
| `--rate` | — | Rate limit: `100kpps`, `1gbps`, `50000pps`, `100mbps` |
| `--rate-ramp` | — | Linearly ramp from 0 to `--rate` over this duration (e.g. `60s`) |
| `--cps` | `0` | Connections per second — new sessions to start per second (`0`=unlimited; `sequential`/`parallel` modes only) |
| `--multiplier` | `1.0` | Multiplicative rate scaler applied to both `--rate` and `--cps` (e.g. `2.0` doubles both) |
| `--pre-process` | `false` | Pre-mutate all packets before replay; removes gopacket overhead from send loop (`burst`/`parallel` only) |
| `--ip-pool-per-iter` | `false` | Clear mutation plan cache at start of each loop iteration for fresh random IPs |
| `--batch-size` | `32` | Frames per `SendBatch` call in `burst` mode (1–256). Has effect only when `--sender raw` is used (AF_PACKET); other senders fall back to per-packet `Send` |
| `--src-ip` | — | Override source IP for all sessions (fixed, same IP for every session) |
| `--dst-ip` | — | Override destination IP for all sessions (fixed) |
| `--src-ip-pool` | — | Pick a random source IP per session from this pool (CIDR or plain IP, repeatable) |
| `--dst-ip-pool` | — | Pick a random destination IP per session from this pool (CIDR or plain IP, repeatable) |
| `--ip-pool-limit` | `0` | Max hosts expanded per CIDR in the IP pool (`0` = default 256, max 65536) |
| `--src-port-min` | `0` | Randomise source port starting from this value |
| `--src-port-max` | `0` | Randomise source port up to this value |
| `--dst-port` | `0` | Override destination port for all sessions |
| `--ttl` | `0` | Override IPv4 TTL / IPv6 HopLimit (`0` = keep original) |
| `--dscp` | `0` | Override DSCP value (0–63); ECN bits preserved (`0` = keep original) |
| `--tcp-set-flags` | — | TCP flags to force **on**, comma-separated: `SYN,ACK,FIN,RST,PSH,URG` |
| `--tcp-clear-flags` | — | TCP flags to force **off**, comma-separated |
| `--tcp-window` | `0` | Override TCP window size in bytes (`0` = keep original) |
| `--min-duration` | — | Skip sessions shorter than this (e.g. `500ms`, `1s`) |
| `--max-duration` | — | Skip sessions longer than this |
| `--start-after` | — | Skip sessions that started before this time (RFC 3339) |
| `--start-before` | — | Skip sessions that started after this time (RFC 3339) |
| `--proto` | — | Include only these protocols: `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, `ah`, `ospf`, `sctp`, or `proto<N>` for any unlisted number |

#### Examples

```bash
# Real-time replay
sudo ./build/tgen run -i eth0 traffic.pcap

# Burst mode — maximum throughput, no inter-packet delays
sudo ./build/tgen run -i eth0 --mode burst traffic.pcap

# Parallel replay of 8 sessions at once, 2× speed
sudo ./build/tgen run -i eth0 --mode parallel --workers 8 --speed 2.0 traffic.pcap

# Loop 5 times, remapping both IPs and randomising source ports
sudo ./build/tgen run -i eth0 \
  --loop-count 5 \
  --src-ip 10.10.0.1 \
  --dst-ip 10.10.0.2 \
  --src-port-min 1024 --src-port-max 65535 \
  traffic.pcap

# Replay only TCP sessions longer than 1 second
sudo ./build/tgen run -i eth0 --proto tcp --min-duration 1s traffic.pcap

# Replay only GRE traffic (named protocol)
sudo ./build/tgen run -i eth0 --proto gre traffic.pcap

# CPS: start at most 500 new sessions per second in parallel mode
sudo ./build/tgen run -i eth0 --mode parallel --workers 8 --cps 500 traffic.pcap

# Multiplier: effectively double the rate without retyping the rate string
sudo ./build/tgen run -i eth0 --rate 100kpps --multiplier 2.0 traffic.pcap

# CPS + rate together: both limits apply simultaneously
sudo ./build/tgen run -i eth0 --mode sequential --cps 1000 --rate 100kpps traffic.pcap

# Replay multiple PCAP files in one pass
sudo ./build/tgen run -i eth0 capture1.pcap capture2.pcap capture3.pcap

# Use a config file (CLI --interface overrides config file value)
sudo ./build/tgen run -c config/example.yaml -i lo

# Set TTL to 64 on all outgoing packets
sudo ./build/tgen run -i eth0 --ttl 64 traffic.pcap

# Mark all packets with DSCP AF41 (value 34) for QoS testing
sudo ./build/tgen run -i eth0 --dscp 34 traffic.pcap

# Force SYN+ACK flags on every TCP packet (e.g. to test firewall rules)
sudo ./build/tgen run -i eth0 --tcp-set-flags SYN,ACK traffic.pcap

# Clear RST flag to suppress TCP resets mid-replay
sudo ./build/tgen run -i eth0 --tcp-clear-flags RST traffic.pcap

# Override TCP window size to 65535 to test receiver buffer behaviour
sudo ./build/tgen run -i eth0 --tcp-window 65535 traffic.pcap
```

---

### `generate`

Synthesise and inject IPv4 or IPv6 packets from a template string — no PCAP
file required.  Every packet is built from scratch; fields marked as CIDRs or
port ranges are randomised independently for each packet.

```
tgen generate -t <template> [flags]
```

#### Template format

```
"proto:field=value:field=value:..."
```

| Part | Values | Notes |
|------|--------|-------|
| `proto` | `tcp` `udp` `icmp` `tcp6` `udp6` | Protocol (required, case-insensitive) |
| `src=` | IP or CIDR | Source address / range (required; IPv4 for tcp/udp/icmp, IPv6 for tcp6/udp6) |
| `dst=` | IP or CIDR | Destination address / range (required) |
| `sport=` | `port` or `lo-hi` | Source port or range (default `1024-65535`) |
| `dport=` | `port` or `lo-hi` | Destination port or range (default `80`) |
| `ttl=` | `0–255` | IP TTL / IPv6 hop limit (default `64`) |
| `dscp=` | `0–63` | DSCP / DiffServ code point (default `0`) |
| `flags=` | `SYN,ACK,FIN,RST,PSH,URG` | TCP flags to set (`tcp` and `tcp6` only) |
| `size=` | `0–65535` | Extra zero-padded payload bytes appended after L4 header (default `0`) |

Fields are separated by `:`.  IPv6 addresses in field values (which also
contain `:`) are handled correctly by the parser.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --template` | *(required)* | Packet template string |
| `-i, --interface` | auto-detected | Outbound interface; auto-resolved from dst IP when omitted |
| `--rate` | unlimited | Rate limit: `100kpps`, `1mpps`, `1gbps`, `100mbps`, … |
| `--count` | `0` | Packets per cycle; `0` = run until Ctrl-C |
| `--workers` | `1` | Concurrent sender goroutines (each with its own RNG) |
| `--loop` | `false` | Restart after `--count` packets are sent; loop indefinitely |
| `--pre-build` | `0` | Pre-build N packets per worker before the send loop; cycles through the buffer at runtime (removes `Build()` from hot path) |
| `--cps` | `0` | Connections per second — new flow cycles (count-batches) to start per second across all workers (`0`=unlimited) |
| `--multiplier` | `1.0` | Multiplicative rate scaler applied to both `--rate` and `--cps` (e.g. `2.0` doubles both) |
| `--batch-size` | `32` | Frames per `SendBatch` call when `--pre-build > 0` (1–256). Has effect only when the sender implements `Batcher` (AF_PACKET raw sender on Linux) |

The gateway MAC for the Ethernet dst header is resolved automatically via ARP
(the same mechanism used by `--target-ip` in `tgen run`).  If the ARP entry is
missing, ping the gateway once to populate it and retry.

#### Examples

```bash
# TCP SYN flood: random source IPs from /24, fixed dst, rate-limited
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  -i eth0 --rate 100kpps

# UDP DNS queries: fixed src, fixed dst, 1 million packets total
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.1:dst=8.8.8.8:dport=53" \
  -i eth0 --count 1000000

# ICMP echo from large /16 range until Ctrl-C, auto-detect interface
sudo ./build/tgen generate \
  -t "icmp:src=10.0.0.0/16:dst=192.168.1.1"

# IPv6 TCP from randomised /32 range — tcp6 accepts IPv6 CIDRs
sudo ./build/tgen generate \
  -t "tcp6:src=2001:db8::/32:dst=2001:db8::1:dport=443:flags=SYN" \
  -i eth0 --workers 4 --rate 500kpps

# Fixed-size 1400-byte UDP frames for bandwidth benchmarking
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.0/8:dst=10.1.0.1:dport=5001:size=1400" \
  -i eth0 --rate 1gbps --workers 8 --pre-build 1000

# Repeat 100 k-packet cycles until Ctrl-C with 4 workers
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=80:flags=SYN" \
  -i eth0 --count 100000 --loop --workers 4

# CPS: start at most 200 new flow cycles per second across 4 workers
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  -i eth0 --count 100 --loop --workers 4 --cps 200

# Multiplier: scale both rate and CPS together
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.1:dst=10.0.0.2:dport=5000" \
  -i eth0 --rate 50kpps --cps 500 --multiplier 2.0

# Batch send: pre-build 1000 packets, send in 64-frame sendmmsg batches (Linux AF_PACKET)
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.0/8:dst=10.1.0.1:dport=5001:size=1400" \
  -i eth0 --rate 1gbps --workers 8 --pre-build 1000 --batch-size 64
```

---

### `inspect`

Print a summary of one or more PCAP files without sending any traffic.

```
tgen inspect <pcap files...>
```

Output example:

```
File:     capture.pcap
Packets:  1000
Bytes:    892843
Sessions: 19
Duration: 5.761751s
Start:    2026-05-08 09:48:40.015503 +0000 UTC
End:      2026-05-08 09:48:45.777254 +0000 UTC
Protocols: tcp=5 udp=9 igmp=2 icmpv6=2 proto0=1
```

Named protocols (icmp, igmp, tcp, udp, gre, esp, ah, icmpv6, ospf, sctp) are
shown by name; all others appear as `proto<N>`.

---

### `sessions`

List all reconstructed L4 sessions from a PCAP file.  Supports the same
filter flags as `run` so you can preview exactly which sessions would be
replayed before committing to a live replay.

```
tgen sessions [flags] <pcap files...>
```

#### Flags

| Flag | Description |
|------|-------------|
| `--min-duration` | Only show sessions longer than this |
| `--max-duration` | Only show sessions shorter than this |
| `--start-after` | Only show sessions starting after this time (RFC 3339) |
| `--start-before` | Only show sessions starting before this time |
| `--proto` | Filter by protocol name (`tcp`, `udp`, `icmp`, `icmpv6`, `gre`, …) or `proto<N>` |
| `-v, --verbose` | Show packet count and byte count per session |

#### Examples

```bash
# List all sessions
./build/tgen sessions traffic.pcap

# Verbose output for TCP sessions lasting over 100 ms
./build/tgen sessions -v --proto tcp --min-duration 100ms traffic.pcap

# Sessions captured in a specific time window
./build/tgen sessions \
  --start-after  2026-05-08T09:48:40Z \
  --start-before 2026-05-08T09:48:43Z \
  traffic.pcap
```

---

## Configuration file

All settings can be placed in a YAML file and passed with `--config` / `-c`.
CLI flags provided alongside `--config` override the corresponding config value.

```bash
sudo ./build/tgen run -c config/example.yaml
```

### Full reference

```yaml
# Network interface to send packets on.
interface: "eth0"

# PCAP source files.
pcap_files:
  - path: "capture1.pcap"
  - path: "capture2.pcap"

# Replay behaviour.
replay:
  mode: "sequential"   # sequential | parallel | burst
  speed: 1.0           # 1.0 = real-time, 0 = burst
  loop: false          # repeat indefinitely
  loop_count: 0        # number of passes (0 = once)
  workers: 4           # goroutines for parallel mode
  cps: 0               # new sessions per second (0 = unlimited; sequential/parallel only)
  multiplier: 1.0      # rate scaler applied to rate and cps (0 treated as 1.0)
  batch_size: 32       # frames per SendBatch in burst mode (0=default 32, max 256)

# L3/L4 field mutation.
mutations:
  preserve_sessions: true   # same plan applied to all packets in a flow

  # Global IP overrides (single address).
  src_ip: ""
  dst_ip: ""

  # Per-session random IP from a pool (CIDR or plain IP).
  # Network and broadcast addresses are excluded automatically.
  # Pool entries expanded up to 256 hosts per CIDR.
  src_ip_pool:
    - "10.10.0.0/24"
    - "10.10.1.1"
  dst_ip_pool: []

  # Randomise source port in [min, max].  0 = keep original.
  src_port_min: 1024
  src_port_max: 65535

  # Force a specific destination port.  0 = keep original.
  dst_port: 0

  # Override TTL (IPv4) / HopLimit (IPv6).  0 = keep original.
  ttl: 0

  # Override DSCP (6-bit, 0–63).  ECN bits are preserved.  0 = keep original.
  dscp: 0

  # Force TCP flags on or off (comma-separated: SYN,ACK,FIN,RST,PSH,URG,ECE,CWR,NS).
  tcp_set_flags: ""
  tcp_clear_flags: ""

  # Override TCP window size in bytes.  0 = keep original.
  tcp_window: 0

  # Rule-based overrides — evaluated in order; first match wins.
  # Rules take precedence over all global settings above.
  rules:
    - match:
        src_ip: "192.168.0.0/16"   # CIDR or plain IP
        proto: "tcp"               # tcp | udp | icmp | icmpv6 | gre | ...
      replace:
        src_ip: "10.0.0.1"
        dst_port: 8080
    - match:
        dst_port: 53
        proto: "udp"
      replace:
        dst_ip: "8.8.8.8"

# Session filter — applied once after reading the PCAP, before replay.
filter:
  min_duration: ""      # e.g. "500ms", "1s", "2m"
  max_duration: ""
  start_after:  ""      # RFC 3339 e.g. "2024-01-15T08:00:00Z"
  start_before: ""
  protocols: []         # [] = all; e.g. [tcp, udp, gre]

# Metrics reporting.
metrics:
  enabled: true
  report_interval: "1s"
  output: "stdout"      # stdout | stderr | /path/to/file.log
```

---

## Mutation rules

Mutations are applied per-session with full consistency — every packet in the
same flow receives the exact same L3/L4 rewrites so that TCP sequence numbers,
checksums, and application-layer framing remain coherent.

**Priority order** (highest to lowest):

1. `mutations.rules[]` — match conditions evaluated top-to-bottom; first match wins and skips all others.
2. `mutations.src_ip` / `mutations.dst_ip` — single fixed IP override (CLI: `--src-ip`, `--dst-ip`).
3. `mutations.src_ip_pool` / `mutations.dst_ip_pool` — one IP chosen randomly from the pool at session setup (CLI: `--src-ip-pool`, `--dst-ip-pool`).
4. Original values — used for any field not explicitly overridden.

**Fixed IP vs pool:** `--src-ip` assigns the same address to every session. `--src-ip-pool` draws a different random IP per session from the expanded pool, making each flow appear to come from a distinct host. If both are set, `--src-ip` wins.

The same priority applies to every mutable field: `ttl`, `dscp`, `tcp_set_flags`, `tcp_clear_flags`, `tcp_window`.

**Checksum recomputation** is automatic. IP, TCP, and UDP checksums are
recomputed after every mutation so injected packets are always valid on the
wire.

**IP family safety**: if a plan IP is IPv4 and the packet is IPv6 (or vice
versa), the mutation is silently skipped and the original address is preserved.
This prevents corrupted frames from reaching the wire.

**DSCP encoding**: DSCP occupies bits 7–2 of the IPv4 TOS byte and the IPv6
TrafficClass byte. Bits 1–0 (ECN) are always preserved:
`newTOS = (oldTOS & 0x03) | (dscp << 2)`.

**TCP flags**: `tcp_set_flags` forces listed flags to 1; `tcp_clear_flags`
forces them to 0. Both accept a comma-separated list of names: `SYN`, `ACK`,
`FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR`, `NS`. Apply order is set-then-clear,
so if the same flag appears in both lists it ends up cleared.

### Example: remap a subnet and randomise ports

```yaml
mutations:
  preserve_sessions: true
  src_ip_pool:
    - "172.16.1.0/24"
  src_port_min: 1024
  src_port_max: 65535
  rules:
    - match:
        src_ip: "192.168.0.0/16"
        proto: "tcp"
      replace:
        dst_ip: "10.0.0.5"
        dst_port: 443
```

### Example: QoS and firewall testing

```yaml
mutations:
  preserve_sessions: true
  ttl: 64           # normalise TTL across all flows
  dscp: 46          # Expedited Forwarding (EF) — highest priority queue
  tcp_set_flags: "ACK"
  tcp_clear_flags: "RST"
  tcp_window: 65535
```

---

## Session filtering

Session filtering is an advanced feature that lets you select a subset of
sessions from a PCAP before any traffic is sent.  This is useful when you want
to replay only the interesting part of a large capture.

```bash
# Preview what would be replayed
./build/tgen sessions --proto tcp --min-duration 1s traffic.pcap

# Then replay just those sessions
sudo ./build/tgen run -i eth0 --proto tcp --min-duration 1s traffic.pcap
```

**Filter by start time** — useful for picking sessions by the moment they
appear in the capture (not by wall-clock time):

```bash
./build/tgen sessions \
  --start-after  2026-05-08T09:48:40Z \
  --start-before 2026-05-08T09:48:42Z \
  traffic.pcap
```

The same flags work identically in `run` and `sessions`.

**Protocol names** supported in `--proto`: `icmp`, `igmp`, `tcp`, `udp`,
`gre`, `esp`, `ah`, `icmpv6`, `ospf`, `sctp`, or `proto<N>` for any IP
protocol number not in that list.

---

## Replay modes

| Mode | Description | Use case |
|------|-------------|----------|
| `sequential` | Sessions replayed one after another. Inter-packet gaps within each session are preserved, scaled by `--speed`. | Accurate simulation of a single network path |
| `parallel` | Up to `--workers` sessions run concurrently. Each session is individually timing-accurate. Workers are capped to the number of sessions automatically. | Simulate many clients / flows simultaneously |
| `burst` | All packets sent without any delay. | Stress / load testing; maximum throughput |
| `pcap` | All packets from all sessions merged by original capture timestamp and replayed in global order. Preserves inter-packet gaps scaled by `--speed`. | Replicate exact original traffic shape across sessions |

**Speed examples:**

```bash
--speed 1.0   # real-time (default)
--speed 0.5   # half speed (double the gaps)
--speed 2.0   # twice as fast
--speed 0     # burst (same as --mode burst)
```

Inter-packet gaps are capped at 1 hour regardless of speed to prevent
`time.Duration` overflow when speed is extremely small (e.g. `0.0001`).

---

## Metrics output

tgen prints a one-line report at each `report_interval`:

```
[metrics] elapsed=1.0s pkts=1234 pps=1234 bps=1543210 errors=0 active=43 open=12 cps=43 empty=0
```

| Field | Meaning |
|-------|---------|
| `elapsed` | Seconds since replay/generation started |
| `pkts` | Total packets injected so far |
| `pps` | Packets per second (current interval) |
| `bps` | Bytes per second (current interval) |
| `errors` | Mutation or injection errors |
| `active` | Flows currently in flight (started but not yet finished) |
| `open` | Flows with no FIN or RST sent yet |
| `cps` | New flows started per second (measured, current interval) |
| `empty` | Packets with zero-length data skipped without sending |

The `Snapshot` returned by `mc.Snapshot()` also exposes `TargetRate`, `TargetCPS`,
and `Multiplier` — the configured (pre-multiplier) values — for use in custom
reporting or testing.

To write metrics to a file:

```yaml
metrics:
  output: "/var/log/tgen-metrics.log"
```

---

## Testing & benchmarks

```bash
# Run all tests
make test

# Run unit tests only (skips PCAP integration tests)
make test-short

# Run benchmarks (mutation speed, replay throughput)
make bench
```

Benchmark results (Apple M3 Pro):

| Benchmark | Throughput | Notes |
|-----------|------------|-------|
| `BenchmarkApplyFullMutation` | ~2.1 M pkt/s | All L3+L4 fields rewritten, checksums recomputed |
| `BenchmarkApplyNoMutation` | ~2.1 M pkt/s | Pass-through baseline — same cost as full mutation |
| `BenchmarkApply` | ~2.1 M pkt/s | Realistic client→server TCP packet, all fields mutated |
| `BenchmarkSequential` | ~1.9 M pkt/s | 100 sessions × 100 pkts, Speed=0, no network I/O |
| `BenchmarkParallel` (8 workers) | ~4.3 M pkt/s | ~2.2× speedup over sequential |
| `BenchmarkBurst` | ~2.1 M pkt/s | 100 sessions × 100 pkts, burst mode, per-packet Send |
| `BenchmarkBurstBatch` | ~2.3 M pkt/s | Same workload, batch-size=32, SendBatch mock |
| `BenchmarkBurstReplay` | ~2.1 M pkt/s | 10 sessions × 100 pkts, original replay benchmark |

**Batch-send performance notes** (`--sender raw --mode burst --batch-size N` on Linux):

- `sendmmsg` reduces per-packet kernel transitions. At 100kpps, 32-frame batches
  cut syscall count by ~32×; the gain is most visible when the CPU is syscall-bound
  rather than memory-bandwidth-bound.
- Larger batch sizes (64–128) improve throughput at high packet rates but add
  latency to the first frame in each batch. Use 32 (default) as a starting point
  and tune upward for maximum throughput or downward for lower burst latency.
- On macOS or with `--sender pcap`, `Batcher` is not implemented; the code
  automatically falls back to per-packet `Send` with no configuration change needed.
- The generator (`tgen generate`) uses batch only when both `--pre-build > 0`
  and the sender implements `Batcher`. On-the-fly packet builds always use
  per-packet sends regardless of `--batch-size`.

---

## Makefile targets

| Target | Description |
|--------|-------------|
| `make build` | Compile binary to `./build/tgen` |
| `make test` | Run all tests |
| `make test-short` | Run unit tests only |
| `make bench` | Run all benchmarks |
| `make lint` | Run `golangci-lint` (install separately) |
| `make tidy` | Update `go.sum` |
| `make run-inspect` | `tgen inspect traffic.pcap` |
| `make run-sessions` | `tgen sessions -v traffic.pcap` |
| `make run-sessions-filter` | TCP sessions > 100 ms in `traffic.pcap` |
| `make clean` | Remove `./build/` |

---

## Stress testing examples

### Synthetic generation (no PCAP)

```bash
# Maximum-rate TCP SYN flood with randomised source IPs
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/8:dst=192.168.1.1:dport=443:flags=SYN" \
  -i eth0

# Rate-capped UDP flood from a /16 source range
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.0/16:dst=192.168.1.1:dport=5000-6000" \
  -i eth0 --rate 100kpps

# Fixed-count ICMP ping storm, auto-detect interface
sudo ./build/tgen generate \
  -t "icmp:src=10.0.0.0/24:dst=192.168.1.1" \
  --count 10000000

# Multi-worker 1 Gbps UDP flood with 1400-byte frames (pre-built buffers remove Build() from hot path)
sudo ./build/tgen generate \
  -t "udp:src=10.0.0.0/8:dst=10.1.0.1:dport=5001:size=1400" \
  -i eth0 --rate 1gbps --workers 8 --pre-build 2000

# IPv6 TCP SYN flood, 4 workers
sudo ./build/tgen generate \
  -t "tcp6:src=2001:db8::/32:dst=2001:db8::1:dport=443:flags=SYN" \
  -i eth0 --workers 4 --rate 500kpps

# Loop: repeat 1 M-packet cycles indefinitely until Ctrl-C
sudo ./build/tgen generate \
  -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  -i eth0 --count 1000000 --loop
```

### PCAP replay

# Rate-limited stress test at exactly 100 kpps
sudo ./build/tgen run -i eth0 --mode burst --rate 100kpps traffic.pcap

# Ramp from 0 to 1 Gbps over 60 seconds
sudo ./build/tgen run -i eth0 --mode burst --rate 1gbps --rate-ramp 60s traffic.pcap

# Multi-interface for higher bandwidth (round-robin across 3 NICs)
sudo ./build/tgen run -i eth0,eth1,eth2 --mode burst --rate 3gbps traffic.pcap

# Auto-detect interface from target IP (also sets gateway MAC)
sudo ./build/tgen run --target-ip 10.0.1.100 --mode burst traffic.pcap

# Fresh IP pool each loop iteration — every pass uses different source IPs
sudo ./build/tgen run -i eth0 --mode burst --loop-count 10 \
  --src-ip-pool 10.0.0.0/16 --ip-pool-per-iter traffic.pcap

# Large IP pool (up to 65536 hosts per CIDR)
sudo ./build/tgen run -i eth0 --mode burst \
  --src-ip-pool 10.0.0.0/16 --ip-pool-limit 65536 traffic.pcap

# Pre-process all packets before replay (removes gopacket from hot path)
sudo ./build/tgen run -i eth0 --mode parallel --workers 8 \
  --pre-process --src-ip 10.0.0.1 traffic.pcap

# AF_PACKET raw sender (Linux only, lower overhead)
sudo ./build/tgen run -i eth0 --sender raw --mode burst traffic.pcap

# Batch sending: send 64 frames per sendmmsg syscall (Linux AF_PACKET only)
sudo ./build/tgen run -i eth0 --sender raw --mode burst --batch-size 64 traffic.pcap

# Batch + pre-process: mutations done upfront, then sent in 128-frame batches
sudo ./build/tgen run -i eth0 --sender raw --mode burst \
  --pre-process --batch-size 128 --src-ip 10.0.0.1 traffic.pcap

# Pcap-order replay (global timestamp order across all sessions)
sudo ./build/tgen run -i eth0 --mode pcap --speed 2.0 traffic.pcap
```

## CLI examples

A comprehensive reference of every flag combination is in
[`docs/CLI_EXAMPLES.md`](docs/CLI_EXAMPLES.md).
