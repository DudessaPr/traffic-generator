# tgen — PCAP Traffic Generator

A high-performance, session-aware network traffic generator that replays
captured PCAP files onto a live interface with configurable L3/L4 mutation,
timing control, and session filtering.

---

## Table of contents

1. [Requirements](#requirements)
2. [Build](#build)
3. [Quick start](#quick-start)
4. [Commands](#commands)
   - [run](#run)
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
| `-i, --interface` | *(required)* | Network interface to inject traffic onto |
| `-c, --config` | — | YAML config file (overrides all other flags) |
| `-s, --speed` | `1.0` | Replay speed multiplier. `1.0` = real-time, `2.0` = 2× faster, `0` = burst |
| `-m, --mode` | `sequential` | Replay mode: `sequential`, `parallel`, `burst` |
| `-l, --loop` | `false` | Repeat indefinitely |
| `--loop-count` | `0` | Number of replay passes (0 = once) |
| `--workers` | `4` | Goroutine count for `parallel` mode |
| `--src-ip` | — | Override source IP for all sessions |
| `--dst-ip` | — | Override destination IP for all sessions |
| `--src-port-min` | `0` | Randomise source port starting from this value |
| `--src-port-max` | `0` | Randomise source port up to this value |
| `--dst-port` | `0` | Override destination port for all sessions |
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

# Replay multiple PCAP files in one pass
sudo ./build/tgen run -i eth0 capture1.pcap capture2.pcap capture3.pcap

# Use a config file (CLI --interface overrides config file value)
sudo ./build/tgen run -c config/example.yaml -i lo
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
2. `mutations.src_ip` / `mutations.dst_ip` — single fixed IP override.
3. `mutations.src_ip_pool` / `mutations.dst_ip_pool` — one IP chosen randomly from the pool at session setup.
4. Original values — used for any field not explicitly overridden.

**Checksum recomputation** is automatic. IP, TCP, and UDP checksums are
recomputed after every mutation so injected packets are always valid on the
wire.

**IP family safety**: if a plan IP is IPv4 and the packet is IPv6 (or vice
versa), the mutation is silently skipped and the original address is preserved.
This prevents corrupted frames from reaching the wire.

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
[metrics] elapsed=1.0s pkts=1234 bytes=1543210 pps=1234 bps=1543210 errors=0 sessions=5 empty=0
```

| Field | Meaning |
|-------|---------|
| `elapsed` | Seconds since replay started |
| `pkts` | Total packets injected so far |
| `bytes` | Total bytes injected so far |
| `pps` | Packets per second (current interval) |
| `bps` | Bytes per second (current interval) |
| `errors` | Mutation or injection errors |
| `sessions` | Completed sessions |
| `empty` | Packets with zero-length data skipped without sending |

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
| `BenchmarkBurst` | ~2.1 M pkt/s | 100 sessions × 100 pkts, burst mode |
| `BenchmarkBurstReplay` | ~2.1 M pkt/s | 10 sessions × 100 pkts, original replay benchmark |

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
