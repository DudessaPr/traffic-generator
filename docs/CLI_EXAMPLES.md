# tgen — CLI Examples

Every flag available in `tgen run`, `tgen inspect`, and `tgen sessions` is
demonstrated here with a real-world motivation for each example.

---

## Table of contents

1. [Build and verify](#build-and-verify)
2. [Inspect and explore PCAPs](#inspect-and-explore-pcaps)
3. [List and filter sessions](#list-and-filter-sessions)
4. [Basic replay](#basic-replay)
5. [Speed and timing control](#speed-and-timing-control)
6. [Replay modes](#replay-modes)
7. [IP mutation](#ip-mutation) — fixed IP, pool (random per session)
8. [Port mutation](#port-mutation)
9. [TTL / HopLimit mutation](#ttl--hoplimit-mutation)
10. [DSCP mutation](#dscp-mutation)
11. [TCP flag mutation](#tcp-flag-mutation)
12. [TCP window mutation](#tcp-window-mutation)
13. [Session filtering](#session-filtering)
14. [Looping](#looping)
15. [Multiple PCAP files](#multiple-pcap-files)
16. [Config file workflow](#config-file-workflow)
17. [Combined real-world recipes](#combined-real-world-recipes)

---

## Build and verify

```bash
# Compile the binary
make build

# Confirm the binary works (no root needed)
./build/tgen --help
./build/tgen run --help
./build/tgen inspect --help
./build/tgen sessions --help
```

---

## Inspect and explore PCAPs

`tgen inspect` reads a PCAP and prints a summary. No interface, no root required.

```bash
# Summary of a single file
./build/tgen inspect capture.pcap

# Summary of multiple files at once
./build/tgen inspect capture1.pcap capture2.pcap capture3.pcap
```

Example output:

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

---

## List and filter sessions

`tgen sessions` shows every reconstructed L4 flow. Supports the same filter
flags as `run`, so you can preview exactly what would be replayed.

```bash
# List all sessions
./build/tgen sessions traffic.pcap

# Verbose — show packet count and byte count per session
./build/tgen sessions -v traffic.pcap

# Only TCP sessions
./build/tgen sessions --proto tcp traffic.pcap

# Only UDP sessions lasting more than 100 ms
./build/tgen sessions -v --proto udp --min-duration 100ms traffic.pcap

# Sessions in a specific capture time window (RFC 3339)
./build/tgen sessions \
  --start-after  2026-05-08T09:48:40Z \
  --start-before 2026-05-08T09:48:43Z \
  traffic.pcap

# Sessions by duration range
./build/tgen sessions --min-duration 500ms --max-duration 10s traffic.pcap

# Protocol filter with numeric fallback (proto41 = IPv6-in-IPv4 encapsulation)
./build/tgen sessions --proto proto41 traffic.pcap
```

---

## Basic replay

All `run` commands require root (or `CAP_NET_RAW`) for packet injection.

```bash
# Real-time replay on interface eth0
sudo ./build/tgen run -i eth0 traffic.pcap

# Short form of --interface
sudo ./build/tgen run -i lo traffic.pcap

# Replay and write metrics to a file instead of stdout
sudo ./build/tgen run -i eth0 traffic.pcap
# (metrics go to stdout by default — pipe or redirect as needed)
```

---

## Speed and timing control

```bash
# Real-time speed (default — 1× captured inter-packet gaps)
sudo ./build/tgen run -i eth0 --speed 1.0 traffic.pcap

# Half speed — doubles every inter-packet gap
sudo ./build/tgen run -i eth0 --speed 0.5 traffic.pcap

# 2× speed — halves every inter-packet gap
sudo ./build/tgen run -i eth0 --speed 2.0 traffic.pcap

# 10× speed
sudo ./build/tgen run -i eth0 --speed 10.0 traffic.pcap

# Speed 0 is equivalent to burst mode (no inter-packet delay)
sudo ./build/tgen run -i eth0 --speed 0 traffic.pcap
```

Inter-packet gaps are capped at 1 hour to prevent `time.Duration` overflow
when `--speed` is extremely small (e.g. `0.0001`).

---

## Replay modes

```bash
# Sequential (default) — one session at a time, timing-accurate
sudo ./build/tgen run -i eth0 --mode sequential traffic.pcap

# Parallel — up to N sessions concurrently, each individually timing-accurate
sudo ./build/tgen run -i eth0 --mode parallel --workers 8 traffic.pcap

# Burst — all packets sent with zero delay; maximum throughput
sudo ./build/tgen run -i eth0 --mode burst traffic.pcap

# Parallel at 2× speed with 16 workers
sudo ./build/tgen run -i eth0 --mode parallel --workers 16 --speed 2.0 traffic.pcap
```

Workers are automatically capped to the number of available sessions, so
`--workers 1000` on a 5-session PCAP uses only 5 goroutines.

---

## IP mutation

All L3/L4 rewrites are applied per-session: every packet in a flow gets
identical values, preserving TCP sequence coherence.

### Fixed IP — same address for every session

```bash
# Override source IP for all sessions
sudo ./build/tgen run -i eth0 --src-ip 10.0.0.1 traffic.pcap

# Override destination IP for all sessions
sudo ./build/tgen run -i eth0 --dst-ip 192.168.1.100 traffic.pcap

# Remap both IPs at once
sudo ./build/tgen run -i eth0 \
  --src-ip 10.10.0.1 \
  --dst-ip 10.10.0.2 \
  traffic.pcap
```

### Pool — different random IP per session

`--src-ip-pool` and `--dst-ip-pool` each accept a comma-separated list of
plain IPs and/or CIDRs. One IP is drawn randomly per session; every packet in
that session uses the same IP (flow consistency is preserved). The pool is
expanded at startup — CIDRs are enumerated up to 256 hosts, with network and
broadcast addresses excluded for prefixes shorter than /31.

```bash
# Random source IP from a /24 — each session gets a distinct host address
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 10.10.0.0/24 \
  traffic.pcap

# Random destination IP from a /24
sudo ./build/tgen run -i eth0 \
  --dst-ip-pool 10.20.0.0/24 \
  traffic.pcap

# Both source and destination randomised from separate pools
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 10.10.0.0/24 \
  --dst-ip-pool 10.20.0.0/24 \
  traffic.pcap

# Mix plain IPs and CIDRs in the same pool (comma-separated)
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 10.0.0.1,10.0.0.2,10.1.0.0/24 \
  traffic.pcap

# Repeatable flag form (equivalent to comma-separated)
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 10.0.0.0/24 \
  --src-ip-pool 10.0.1.0/24 \
  traffic.pcap

# Pool + port randomisation — each session looks like a completely fresh client
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 172.16.0.0/24 \
  --src-port-min 1024 \
  --src-port-max 65535 \
  traffic.pcap
```

**Fixed IP vs pool:** if `--src-ip` and `--src-ip-pool` are both provided,
`--src-ip` wins (higher priority). Use one or the other, not both.

IPv4 pool addresses are silently skipped for IPv6 packets (and vice versa) to
prevent corrupted frames.

---

## Port mutation

```bash
# Randomise source port in [1024, 65535] for each session
sudo ./build/tgen run -i eth0 \
  --src-port-min 1024 \
  --src-port-max 65535 \
  traffic.pcap

# Force a specific source port range
sudo ./build/tgen run -i eth0 \
  --src-port-min 40000 \
  --src-port-max 50000 \
  traffic.pcap

# Override destination port for all sessions
sudo ./build/tgen run -i eth0 --dst-port 8080 traffic.pcap

# Remap to a specific server:port pair
sudo ./build/tgen run -i eth0 \
  --dst-ip 10.0.0.5 \
  --dst-port 443 \
  traffic.pcap
```

---

## TTL / HopLimit mutation

`--ttl` sets `TTL` on IPv4 packets and `HopLimit` on IPv6 packets.
`0` means "keep the original value".

```bash
# Normalise TTL to 64 (common Linux default) across all packets
sudo ./build/tgen run -i eth0 --ttl 64 traffic.pcap

# Set a very short TTL to test TTL-exceeded / ICMP responses
sudo ./build/tgen run -i eth0 --ttl 1 traffic.pcap

# Simulate a far-away host (low TTL when it arrives)
sudo ./build/tgen run -i eth0 --ttl 5 traffic.pcap

# Maximum TTL — packets won't expire in transit
sudo ./build/tgen run -i eth0 --ttl 255 traffic.pcap
```

---

## DSCP mutation

`--dscp` sets the upper 6 bits of the IPv4 TOS byte / IPv6 TrafficClass byte.
The lower 2 ECN bits are always preserved. `0` means "keep original".

Common DSCP values (RFC 4594):

| Name | Value | Use case |
|------|-------|----------|
| CS0 / Default | 0 | Best-effort (default) |
| AF11 | 10 | Low-priority data |
| AF21 | 18 | Medium-priority data |
| AF31 | 26 | Multimedia streaming |
| AF41 | 34 | Real-time interactive |
| EF   | 46 | Voice / Expedited Forwarding |
| CS6  | 48 | Network control |
| CS7  | 56 | Highest priority |

```bash
# Mark all packets as Expedited Forwarding (EF = 46) — highest priority queue
sudo ./build/tgen run -i eth0 --dscp 46 traffic.pcap

# Mark as AF41 — real-time interactive (video conferencing class)
sudo ./build/tgen run -i eth0 --dscp 34 traffic.pcap

# Test that your QoS policy correctly queues CS6 (network control)
sudo ./build/tgen run -i eth0 --dscp 48 traffic.pcap

# Strip DSCP — force all packets to best-effort (CS0)
# Note: DSCP 0 cannot be explicitly set (0 = "keep original").
# Use a config-file rule instead:
#   mutations:
#     rules:
#       - match: {}
#         replace:
#           dscp: 0   # same limitation applies; set dscp: 1 then subtract manually if needed
# Workaround: capture already has DSCP 0, then replay without --dscp.

# Combine DSCP with TTL — simulate traffic arriving from a specific network hop
sudo ./build/tgen run -i eth0 --ttl 64 --dscp 46 traffic.pcap
```

---

## TCP flag mutation

`--tcp-set-flags` forces the listed flags to 1 in every TCP packet.
`--tcp-clear-flags` forces the listed flags to 0.
Both accept a comma-separated list (no spaces): `SYN,ACK,FIN,RST,PSH,URG,ECE,CWR,NS`.
Apply order within a single packet: **set first, then clear** — if the same
flag appears in both, it ends up cleared.

```bash
# Force SYN on every TCP packet — test firewall SYN-flood rules
sudo ./build/tgen run -i eth0 --tcp-set-flags SYN traffic.pcap

# Force SYN+ACK — simulate handshake responses
sudo ./build/tgen run -i eth0 --tcp-set-flags SYN,ACK traffic.pcap

# Suppress TCP resets — prevent RST from disturbing stateful inspection
sudo ./build/tgen run -i eth0 --tcp-clear-flags RST traffic.pcap

# Force FIN to test half-close handling
sudo ./build/tgen run -i eth0 --tcp-set-flags FIN traffic.pcap

# Mark every packet as push (PSH) — test socket buffer behaviour
sudo ./build/tgen run -i eth0 --tcp-set-flags PSH traffic.pcap

# Set ECE (ECN Echo) — test ECN-capable network gear
sudo ./build/tgen run -i eth0 --tcp-set-flags ECE traffic.pcap

# Simulate a CWR+ECE negotiation packet
sudo ./build/tgen run -i eth0 --tcp-set-flags CWR,ECE traffic.pcap

# Clear all commonly-set flags, then set only ACK — minimal keep-alive traffic
sudo ./build/tgen run -i eth0 \
  --tcp-clear-flags SYN,FIN,RST,PSH,URG \
  --tcp-set-flags ACK \
  traffic.pcap
```

---

## TCP window mutation

`--tcp-window` overrides the TCP receive window size advertised in every TCP
packet. `0` means "keep original".

```bash
# Advertise maximum window size — test receive buffer / window scaling
sudo ./build/tgen run -i eth0 --tcp-window 65535 traffic.pcap

# Simulate a zero-window condition — test sender pause / probe behaviour
sudo ./build/tgen run -i eth0 --tcp-window 1 traffic.pcap

# Normalise window to a fixed value for reproducible throughput tests
sudo ./build/tgen run -i eth0 --tcp-window 8192 traffic.pcap

# Combine with flag mutation — force ACK-only packets with max window
sudo ./build/tgen run -i eth0 \
  --tcp-set-flags ACK \
  --tcp-clear-flags SYN,FIN,RST \
  --tcp-window 65535 \
  traffic.pcap
```

---

## Session filtering

Session filters are evaluated once after reading the PCAP. They select which
sessions are passed to the replay engine.

```bash
# Only sessions longer than 1 second
sudo ./build/tgen run -i eth0 --min-duration 1s traffic.pcap

# Only sessions shorter than 500 ms (short flows / DNS-like traffic)
sudo ./build/tgen run -i eth0 --max-duration 500ms traffic.pcap

# Duration band: 100 ms – 5 s
sudo ./build/tgen run -i eth0 \
  --min-duration 100ms \
  --max-duration 5s \
  traffic.pcap

# Only TCP sessions
sudo ./build/tgen run -i eth0 --proto tcp traffic.pcap

# Only UDP sessions
sudo ./build/tgen run -i eth0 --proto udp traffic.pcap

# Multiple protocols at once
sudo ./build/tgen run -i eth0 --proto tcp,udp traffic.pcap

# ICMP only (useful for ping-replay tests)
sudo ./build/tgen run -i eth0 --proto icmp traffic.pcap

# ICMPv6 only
sudo ./build/tgen run -i eth0 --proto icmpv6 traffic.pcap

# GRE tunnelled traffic
sudo ./build/tgen run -i eth0 --proto gre traffic.pcap

# Numeric fallback for unlisted protocols
sudo ./build/tgen run -i eth0 --proto proto41 traffic.pcap

# Capture time window — only sessions that started in a 3-second slice
sudo ./build/tgen run -i eth0 \
  --start-after  2026-05-08T09:48:40Z \
  --start-before 2026-05-08T09:48:43Z \
  traffic.pcap

# Preview before committing to a live replay
./build/tgen sessions \
  --proto tcp \
  --min-duration 1s \
  traffic.pcap
# then replay the same subset
sudo ./build/tgen run -i eth0 \
  --proto tcp \
  --min-duration 1s \
  traffic.pcap
```

---

## Looping

```bash
# Replay exactly 3 times
sudo ./build/tgen run -i eth0 --loop-count 3 traffic.pcap

# Replay indefinitely until Ctrl-C
sudo ./build/tgen run -i eth0 --loop traffic.pcap

# Loop 5 times at burst speed — saturation test
sudo ./build/tgen run -i eth0 \
  --mode burst \
  --loop-count 5 \
  traffic.pcap

# Continuous parallel replay — sustained load test
sudo ./build/tgen run -i eth0 \
  --mode parallel \
  --workers 8 \
  --loop \
  traffic.pcap
```

---

## Multiple PCAP files

All files are loaded, merged, filtered, and replayed as one combined session set.

```bash
# Replay two files in one pass
sudo ./build/tgen run -i eth0 capture1.pcap capture2.pcap

# Merge three captures — fixed destination, randomised source per session
sudo ./build/tgen run -i eth0 \
  --src-ip-pool 10.0.0.0/24 \
  --dst-ip 10.0.1.1 \
  morning.pcap afternoon.pcap evening.pcap

# Filter across merged captures — only long TCP sessions
sudo ./build/tgen run -i eth0 \
  --proto tcp \
  --min-duration 2s \
  capture1.pcap capture2.pcap capture3.pcap
```

---

## Config file workflow

A YAML config file unlocks features not available as CLI flags: per-flow
mutation rules and complex filter combinations. IP pools are now available on
the CLI too via `--src-ip-pool` / `--dst-ip-pool`.

```bash
# Use the annotated example as a starting point
cp config/example.yaml my-test.yaml
# edit my-test.yaml, then:
sudo ./build/tgen run -c my-test.yaml

# Override the interface at the command line without editing the file
sudo ./build/tgen run -c my-test.yaml -i lo
```

Minimal config that hits every new mutation field:

```yaml
interface: "eth0"
pcap_files:
  - path: "traffic.pcap"

mutations:
  preserve_sessions: true
  ttl: 64
  dscp: 46          # Expedited Forwarding
  tcp_set_flags: "ACK"
  tcp_clear_flags: "RST"
  tcp_window: 65535

replay:
  mode: "parallel"
  workers: 8
  speed: 2.0
  loop_count: 3

metrics:
  enabled: true
  report_interval: "1s"
  output: "stdout"
```

---

## Combined real-world recipes

### Load test: sustained parallel bursts, each session a unique client

```bash
# Pool gives every session a distinct source IP + random port — realistic multi-client load
sudo ./build/tgen run -i eth0 \
  --mode parallel \
  --workers 16 \
  --speed 0 \
  --loop-count 10 \
  --src-ip-pool 10.100.0.0/24 \
  --dst-ip 10.100.1.1 \
  --src-port-min 1024 \
  --src-port-max 65535 \
  traffic.pcap
```

### QoS validation: high-priority voice traffic simulation

```bash
sudo ./build/tgen run -i eth0 \
  --proto udp \
  --dscp 46 \
  --ttl 64 \
  --speed 1.0 \
  voip.pcap
```

### Firewall rule testing: SYN-only flood simulation

```bash
sudo ./build/tgen run -i eth0 \
  --mode burst \
  --tcp-set-flags SYN \
  --tcp-clear-flags ACK,FIN,RST \
  --src-port-min 1024 \
  --src-port-max 65535 \
  --dst-ip 192.168.1.10 \
  --dst-port 443 \
  --loop-count 5 \
  traffic.pcap
```

### ECN testing: mark traffic for congestion response

```bash
sudo ./build/tgen run -i eth0 \
  --proto tcp \
  --tcp-set-flags ECE,CWR \
  --dscp 10 \
  --mode parallel \
  --workers 4 \
  traffic.pcap
```

### Slice replay: pick a 2-second window from a long capture

```bash
# First, find the time window
./build/tgen inspect capture.pcap
# then replay only that slice
sudo ./build/tgen run -i eth0 \
  --start-after  2026-05-08T09:48:40Z \
  --start-before 2026-05-08T09:48:42Z \
  --proto tcp \
  --dst-ip 10.0.0.5 \
  capture.pcap
```

### Multi-file regression test: normalised headers, looped

```bash
sudo ./build/tgen run -i eth0 \
  --mode sequential \
  --speed 1.0 \
  --loop-count 3 \
  --ttl 64 \
  --dscp 0 \
  --tcp-clear-flags RST \
  --tcp-window 8192 \
  baseline1.pcap baseline2.pcap
```
