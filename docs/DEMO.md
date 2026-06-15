# tgen — Demo Playbook

Practical examples for live demonstrations and presentations.
All commands assume the binary is at `./build/tgen` (`make build`).

---

## Section 1 — Inspect & Analyze

### Inspect a PCAP file

```bash
./build/tgen inspect traffic.pcap
```

**What it does:** Prints a summary of the capture — packet count, byte count, duration, protocol breakdown, and the first/last timestamp.

**Expected output:**
```
File:      traffic.pcap
Packets:   42,317
Bytes:     61.2 MB
Duration:  4m23s
Protocols: TCP 78%  UDP 20%  ICMP 2%
```

**Use case:** Quick sanity-check before replaying — confirm the file is valid and understand its composition.

---

### List TCP sessions

```bash
./build/tgen sessions --proto tcp traffic.pcap
```

**What it does:** Reconstructs all TCP flows from the capture and prints each session's 5-tuple, packet count, byte count, and duration.

**Expected output:**
```
10.0.0.1:54321 → 192.168.1.1:443   TCP  143 pkts  208 KB  1.2s
10.0.0.2:60001 → 192.168.1.1:80    TCP   12 pkts    8 KB  0.1s
...
```

**Use case:** Understand what traffic is in the capture before replaying; identify interesting sessions to target with filters.

---

### List sessions with duration filter

```bash
./build/tgen sessions --min-duration 1s --proto tcp traffic.pcap
```

**What it does:** Same as above but only prints sessions lasting at least 1 second — filters out short-lived or incomplete flows.

**Expected output:** Subset of sessions — long-lived connections like HTTP keep-alive, TLS, or streaming flows.

**Use case:** Focus replay on sessions that matter for load testing; discard TCP handshakes-only or sub-second noise.

---

## Section 2 — Replay Modes

### Real-time replay

```bash
sudo ./build/tgen run -i en0 traffic.pcap
```

**What it does:** Replays the capture at the original inter-packet timing — each packet is sent at exactly the same relative time as it appeared in the file.

**Expected output (metrics every 1s):**
```
[metrics] pps=342 bps=498432 cps=12 active=8 open=6
```

**Use case:** Regression testing or protocol simulation where timing accuracy matters (e.g. verifying timeout logic in a firewall).

---

### 5× faster replay

```bash
sudo ./build/tgen run -i en0 --speed 5 traffic.pcap
```

**What it does:** Compresses all inter-packet gaps by 5×, replaying a 5-minute capture in 1 minute while preserving relative packet order.

**Expected output:** `pps` and `bps` metrics roughly 5× higher than real-time replay.

**Use case:** Accelerated soak testing — reproduce hours of production traffic in minutes.

---

### Burst mode — maximum throughput

```bash
sudo ./build/tgen run -i en0 --mode burst --loop traffic.pcap
```

**What it does:** Sends all packets back-to-back with no timing gaps, looping the file indefinitely. Maximises NIC utilisation.

**Expected output:**
```
[metrics] pps=473000 bps=687M cps=1842 active=120 open=98
```

**Use case:** Saturation testing — find the maximum packet rate a device under test can handle before dropping.

---

### Parallel mode — concurrent sessions

```bash
sudo ./build/tgen run -i en0 --mode parallel --workers 8 --speed 0 --loop traffic.pcap
```

**What it does:** Replays all sessions concurrently using 8 goroutines (`--speed 0` = no rate cap). Each worker handles one session at a time; sessions overlap in time as they did in the original capture.

**Expected output:** Higher `active` and `open` flow counts than sequential mode at similar pps.

**Use case:** Stateful device testing (firewalls, IDS, NAT) where the number of simultaneous flows matters, not just raw pps.

---

### Original capture order

```bash
sudo ./build/tgen run -i en0 --mode pcap traffic.pcap
```

**What it does:** Replays packets in the exact order they appear in the PCAP file (cross-session interleaving preserved), using a merge sort across session queues.

**Expected output:** Packet timestamps match the original capture to sub-millisecond accuracy.

**Use case:** Reproducing a specific sequence of events — e.g. a race condition, a retransmission pattern, or a known attack trace.

---

## Section 3 — Mutations

### Override DSCP (QoS priority)

```bash
sudo ./build/tgen run -i en0 --dscp 46 traffic.pcap
```

**What it does:** Rewrites the DSCP field in every IP header to 46 (Expedited Forwarding), overriding whatever was in the original capture. Checksums are recalculated automatically.

**Verification:**
```bash
sudo tcpdump -i en0 -n -v ip 2>/dev/null | grep "tos 0xb8"
```
*(DSCP 46 = TOS byte 0xb8)*

**Use case:** Test QoS policy enforcement — verify a router or switch applies the correct queue to EF-marked traffic.

---

### IP pool — simulate many clients

```bash
sudo ./build/tgen run -i en0 --src-ip-pool 10.0.0.0/24 traffic.pcap
```

**What it does:** Assigns each replayed session a unique source IP drawn from the 10.0.0.0/24 pool (up to 254 hosts). The same session always gets the same IP within a replay pass.

**Verification:**
```bash
sudo tcpdump -i en0 -n 'src net 10.0.0.0/24' 2>/dev/null | head -20
```

**Use case:** Stress-test a stateful device's connection table — simulate hundreds of distinct clients without needing hundreds of real machines.

---

### Full mutation example

```bash
sudo ./build/tgen run -i en0 \
  --src-ip-pool 10.0.0.0/24 \
  --dst-ip 192.168.1.1 \
  --ttl 64 \
  --dscp 46 \
  --tcp-set-flags SYN \
  --tcp-window 65535 \
  traffic.pcap
```

**What it does:** Combines all L3/L4 mutations in a single pass — rewrites source IPs from a pool, fixes the destination to a single target, normalises TTL/DSCP, forces SYN flags, and sets the TCP window. All checksums are recomputed per packet.

**Expected output:** Every packet arrives at 192.168.1.1 with a unique source IP from the /24, DSCP EF, and a clean SYN flag set.

**Use case:** Directed load test against a specific target with controlled traffic characteristics, regardless of what the original capture contained.

---

## Section 4 — Rate Control

### Limit to 1 kpps

```bash
sudo ./build/tgen run -i en0 --rate 1kpps --loop traffic.pcap
```

**What it does:** Applies a token-bucket rate limiter capped at 1,000 packets per second. Loops the file so the rate is sustained indefinitely.

**Expected output:**
```
[metrics] pps=1000 bps=1.4M ...
```

**Use case:** Simulate a specific traffic tier — e.g. reproduce a 1 kpps baseline before ramping to failure.

---

### Rate ramp — gradually increase load

```bash
sudo ./build/tgen run -i en0 --rate 100kpps --rate-ramp 60s --loop traffic.pcap
```

**What it does:** Linearly ramps the rate from 0 to 100 kpps over 60 seconds, then holds at 100 kpps. Useful for finding the knee of the curve on a device under test.

**Expected output:** `pps` climbs steadily in the metrics output — watch for when `errors` starts rising.

**Use case:** Find the maximum sustainable throughput of a device without a binary search — ramp until errors appear, note the rate.

---

### CPS limit

```bash
sudo ./build/tgen run -i en0 --cps 100 --mode parallel --loop traffic.pcap
```

**What it does:** Caps new session starts at 100 per second regardless of how fast packets within sessions are sent. Parallel mode allows in-flight sessions to overlap.

**Expected output:**
```
[metrics] cps=100 active=24 open=18 pps=8420
```

**Use case:** Test connection-table limits on a stateful device — drive exactly N new connections per second to find the CPS ceiling before sessions are dropped.

---

## Section 5 — Generator (stateless, no PCAP needed)

### TCP SYN flood simulation

```bash
sudo ./build/tgen generate \
  --template "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  --workers 4 \
  --sender raw \
  -i en0
```

**What it does:** Synthesises TCP SYN packets from scratch — each packet gets a random source IP from the /24 and a random source port. No PCAP file required. `--sender raw` uses AF_PACKET on Linux for lower overhead.

**Expected output:**
```
[metrics] pps=257000 actual_cps=257000 active=4 ...
```

**Use case:** Stress-test SYN cookie or half-open connection handling on a firewall or load balancer without any capture file.

---

### UDP bandwidth test

```bash
sudo ./build/tgen generate \
  --template "udp:src=10.0.0.0/24:dst=192.168.1.1:dport=9999:size=1400" \
  --workers 8 \
  --sender raw \
  --pre-build 10000 \
  --batch-size 32 \
  -i en0
```

**What it does:** Generates 1400-byte UDP packets at maximum rate. `--pre-build 10000` builds 10k packets upfront so the send loop never blocks on `Build()`; `--batch-size 32` groups frames into `sendmmsg` syscalls.

**Expected output (Linux, dummy0):**
```
[metrics] pps=1260000 bps=1.9G active=8 ...
```

**Use case:** Maximum-throughput bandwidth saturation test — find the physical link limit or the NIC driver ceiling.

---

### Target CPS with controlled flow size

```bash
sudo ./build/tgen generate \
  --template "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" \
  --cps 1000 \
  --count 10 \
  --workers 4 \
  -i en0
```

**What it does:** Starts exactly 1,000 new flows per second (ticker-based, not token-bucket). Each flow sends 10 packets, then the slot is released for the next flow. 4 workers drain the tick queue concurrently.

**Expected output:**
```
[metrics] target_cps=1000 actual_cps=998 active=12 open=10 pps=9980
```

**Use case:** Precise connection-rate testing — drive a firewall at exactly N CPS to measure latency or drop rate at a known load point.

---

## Section 6 — Verify Mutations with tcpdump

### Verify DSCP mutation

```bash
sudo tcpdump -i en0 -n -v tcp 2>/dev/null | grep "tos 0xb8"
```

**What it does:** Captures live traffic on en0 and filters for packets with TOS byte 0xb8 (DSCP 46 = Expedited Forwarding). Each matched line confirms a mutated packet arrived on the wire.

**Expected output:**
```
10.0.0.17.54321 > 192.168.1.1.443: Flags [S], tos 0xb8, ...
```

**Use case:** Confirm `--dscp 46` is being applied — essential before a QoS demo to avoid showing unmarked packets.

---

### Verify IP pool

```bash
sudo tcpdump -i en0 -n 'src net 10.0.0.0/24' 2>/dev/null | head -20
```

**What it does:** Captures the first 20 packets sourced from the 10.0.0.0/24 range and prints them. You should see a variety of source IPs if the pool is working correctly.

**Expected output:**
```
10.0.0.17.54321 > 192.168.1.1.443 ...
10.0.0.83.49152 > 192.168.1.1.443 ...
10.0.0.142.61000 > 192.168.1.1.443 ...
```

**Use case:** Quick visual check that the IP pool is distributing addresses — demonstrates the "simulate 254 clients" capability to an audience.

---

## Section 7 — Performance Tips

### Maximum throughput on Linux

```bash
sudo ./build/tgen generate \
  --template "udp:src=10.0.0.0/24:dst=192.168.1.1:dport=9999:size=1400" \
  --workers 16 \
  --sender raw \
  --pre-build 10000 \
  --batch-size 64 \
  -i eth0
```

**What it does:** Combines every throughput optimisation: 16 workers filling the send queues, a pre-built 10k-packet buffer removing all `Build()` overhead, and `sendmmsg` batching at 64 frames per syscall via AF_PACKET.

**Expected output (8-core server, 1 GbE):**
```
[metrics] pps=1530000 bps=2.3G active=16 ...
```

**Use case:** Demonstrate the full performance envelope — show that tgen saturates a 10 GbE link from a single host.

---

### AF_PACKET vs libpcap comparison

```bash
# libpcap (default)
sudo ./build/tgen run -i eth0 --mode burst --loop traffic.pcap

# AF_PACKET raw socket
sudo ./build/tgen run -i eth0 --sender raw --mode burst --loop traffic.pcap
```

**What it does:** The first command uses libpcap (`pcap_sendpacket`) — portable but one syscall per packet. The second bypasses libpcap and writes directly to an AF_PACKET socket using `sendmmsg`, batching multiple frames per syscall.

**Expected delta (Atom C3808, dummy0):**

| Sender | pps | MB/s |
|--------|----:|-----:|
| libpcap | ~93k | ~69 |
| AF_PACKET raw | ~110k | ~82 |

**Use case:** Demonstrate the `--sender raw` flag during a Linux performance demo — the 18% gain is visible in the live metrics output within seconds of switching.
