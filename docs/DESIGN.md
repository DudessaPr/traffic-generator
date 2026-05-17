# tgen — Design, Decisions, and Quality Notes

This document covers the full technical picture of tgen: architecture rationale,
non-obvious design decisions, defensive improvements made during development,
edge cases explicitly handled, stress conditions tested, and what remains on
the improvement list.

---

## Table of contents

1. [What tgen is and is not](#what-tgen-is-and-is-not)
2. [Architecture walkthrough](#architecture-walkthrough)
3. [Design decisions](#design-decisions)
4. [Defensive improvements](#defensive-improvements)
5. [Edge cases and why they matter](#edge-cases-and-why-they-matter)
6. [Stress conditions](#stress-conditions)
7. [Testing strategy](#testing-strategy)
8. [What can be improved](#what-can-be-improved)

---

## What tgen is and is not

tgen replays pre-captured network sessions from PCAP files onto a live interface.
It is not a packet generator that synthesises traffic from scratch. Its value
comes from replaying real traffic patterns with configurable mutation: you can
remap IP addresses and ports while preserving the exact packet timing,
ordering, and payload of the original capture.

**Primary use cases:**
- Regression testing network devices or firewalls against recorded production traffic
- Load testing middleboxes (IDS, DPI, NAT) with realistic session mixes
- Reproducing specific protocol sequences for debugging
- Benchmarking packet-processing pipelines at known throughput levels

**Out of scope:**
- Generating synthetic traffic (no protocol state machine, no handshake synthesis)
- Packet capture (use tcpdump/Wireshark)
- Traffic analysis (use Zeek/Suricata)

---

## Architecture walkthrough

### Data flow

```
PCAP files
    │
    ▼ pcap.ReadSessions()
    │   gopacket.OpenOffline → ReadPacketData loop
    │   session.Extractor.Feed() per packet
    │     → NoCopy decode → extract 5-tuple → canonical key
    │     → append to session (with defensive copies of IP slices and data)
    │
    ▼ session.Filter.Apply()
    │   duration / time / protocol allow-list
    │   unknown protocols → proto<N> fallback
    │
    ▼ replay.Replayer.Run()
    │   loop across iterations
    │   ┌── sequential: one session at a time, timing-accurate
    │   ├── parallel:   semaphore (buffered channel) gates N concurrent sessions
    │   └── burst:      all packets without delay
    │
    │ per packet:
    │   mutation.Mutator.PlanFor(sess)   → cached plan (computed once under mutex)
    │   mutation.Apply(data, plan, link) → gopacket decode + field rewrite + reserialise
    │   sender.Send(mutated)             → pcap.WritePacketData
    │
    ▼ metrics.Collector
        atomic counters → periodic report line
```

### Package responsibilities

| Package | Single responsibility |
|---------|----------------------|
| `config` | Typed structs + YAML loader + validation. No business logic. |
| `session` | `Session` model, canonical key, `Extractor` (stateful), `Filter` (stateless), `ProtoName` (shared map). |
| `pcap` | Thin wrapper over gopacket/pcap. Owns file I/O, exposes `ReadSessions` and `Inspect`. |
| `mutation` | `Mutator` (plan cache, pool expansion, rule matching) + `Apply` (packet rewrite). Two distinct concerns in one package because a plan is meaningless without Apply. |
| `sender` | `Interface` (testability seam) + `Sender` (libpcap injection). Size validation lives here. |
| `metrics` | Five atomic counters, `Snapshot`, periodic reporter. Zero knowledge of replay logic. |
| `replay` | Orchestration only. Owns timing, concurrency, and the loop. Calls mutation and sender; reads metrics. |

---

## Design decisions

### 1. Session-aware mutation (consistency guarantee)

The most important invariant: every packet in a session receives the exact same
L3/L4 rewrite. This is enforced by `Mutator.PlanFor`, which computes the plan
once and caches it by `session.Key`. Without this, a TCP session replayed with
a randomised source port would have different ports on SYN, SYN-ACK, and data
packets — the receiving DUT would see those as unrelated streams, making the
replay meaningless for stateful device testing.

The cache is keyed by the canonical 5-tuple, not by pointer identity, so
sessions loaded from different PCAP files with the same flow get the same plan.

### 2. Canonical 5-tuple key (bidirectional flow grouping)

A TCP connection is bidirectional: `A:1234 → B:80` and `B:80 → A:1234` are
the same session. The canonical key is always stored with the "lexicographically
smaller" endpoint first:

```go
func canonical(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) Key {
    a := fmt.Sprintf("%s:%d", srcIP, srcPort)
    b := fmt.Sprintf("%s:%d", dstIP, dstPort)
    if a <= b { return Key{srcIP, dstIP, srcPort, dstPort, proto} }
    return Key{dstIP, srcIP, dstPort, srcPort, proto}
}
```

This means a single PCAP capture containing both directions of a TCP connection
maps to one session with all packets ordered by timestamp, not two half-sessions.

### 3. `sender.Interface` as a testability seam

The real `Sender` opens a live pcap handle and requires root. If the sender
were a concrete type, every test touching the replay engine would require a
real network interface. By defining:

```go
type Interface interface {
    Send(data []byte) error
    Close()
}
```

tests inject a `mockSender` (mutex-protected counter) or `discardSender`
(simple counter). This allows full end-to-end testing of mutation, timing, and
metrics without network access, enabling CI without elevated privileges.

### 4. NoCopy parsing with explicit defensive copies

`gopacket.NoCopy` lets gopacket decode packet layers without allocating a new
backing buffer — the layer fields point directly into the `data` slice passed
to `Feed`. This is a significant allocation saving for high-packet-rate paths.

However, libpcap reuses its read buffer on the next `ReadPacketData` call. Any
slice pointing into that buffer becomes invalid. Three explicit copies protect
against this:

```go
// SrcIP and DstIP extracted from the NoCopy packet
SrcIP: append(net.IP(nil), srcIP...)  // copy before buffer is reused
DstIP: append(net.IP(nil), dstIP...)

// Raw frame bytes
Data: append([]byte(nil), data...)    // copy before buffer is reused
```

The copy is `append(T(nil), src...)` rather than the more obvious `make + copy`
because it avoids a zero-initialisation pass on the backing array — Go's
compiler recognises the pattern and optimises it.

### 5. Plan caching under a single mutex (`Mutator`)

`Mutator.cache` is a `map[session.Key]Plan` protected by `mu`. The RNG (`rng`)
is also only accessed inside `buildPlan`, which is always called while `mu` is
held. This means:

- No data race on `cache` or `rng`
- No separate lock needed for `rng`
- The lock scope is tight: `PlanFor` acquires and releases `mu` around the
  cache lookup + optional build. Packet mutation (`Apply`) runs without any lock.

This design gives parallel mode its scalability: once a plan is cached, all
goroutines for that session's packets can call `Apply` concurrently with no
contention.

### 6. Semaphore via buffered channel (`runParallel`)

Rather than a `sync.Pool` or `errgroup`, the concurrency limit is implemented
as a buffered channel:

```go
sem := make(chan struct{}, workers)
// acquire: sem <- struct{}{}
// release: <-sem
```

This is idiomatic Go, trivially understandable, and has exactly the right
semantics: a goroutine blocks before launch if the slot count is exhausted.
`wg.Wait()` after the dispatch loop ensures all in-flight goroutines complete
before returning — no goroutines are abandoned.

The labeled `break loop` on `ctx.Done()` ensures no new goroutines are
dispatched after cancellation. Already-running goroutines see `ctx.Err() != nil`
in their own timing loops and exit early.

### 7. `ProtoName` as a single source of truth

Four different files previously maintained their own local protocol→name
mappings with inconsistent entries (4 to 10 protocols, different names for the
same number). A single exported map in `session/session.go` is now the
authoritative source:

```go
var ProtoName = map[uint8]string{
    1: "icmp", 2: "igmp", 6: "tcp", 17: "udp",
    47: "gre", 50: "esp", 51: "ah", 58: "icmpv6",
    89: "ospf", 132: "sctp",
}
```

Any protocol not in this map falls back to `fmt.Sprintf("proto%d", n)`
consistently everywhere (filter, inspect output, sessions table, mutation
rule matching). The fallback is important: it lets users filter or match on
uncommon protocols (e.g. `--proto proto41` for 6in4) without requiring
changes to the source.

### 8. CIDR pool boundary exclusion

When a CIDR pool entry is expanded into a flat list of host IPs, the network
address (all host bits zero) and broadcast address (all host bits one) are
excluded for prefix lengths shorter than /31:

- `/24` (256 addresses) → 254 usable hosts
- `/31` (2 addresses, point-to-point) → both included
- `/32` (1 address) → the single IP is included

This avoids injecting traffic with a network or broadcast source address, which
would be dropped by routers and confuse DUT logging.

### 9. Workers capped to session count

If `workers > len(sessions)`, the semaphore channel has unused capacity that
can never be filled. The cap `workers = min(workers, len(sessions))` prevents
this:

```go
if len(sessions) > 0 && workers > len(sessions) {
    workers = len(sessions)
}
```

The benefit is small in typical usage but matters at the extremes: a config
file setting `workers: 1000` with a 10-session PCAP no longer allocates 990
unused goroutine slots.

---

## Defensive improvements

These were identified and fixed during a systematic hardening pass.

### Goroutine leak: `break` in `select` (critical)

**Problem**: In the original `runParallel`, the `select` case for `ctx.Done()`
called `break`, which exits the `select`, not the enclosing `for` loop. Every
loop iteration after context cancellation still launched a new goroutine.

**Fix**: Labeled break:

```go
loop:
for _, s := range sessions {
    select {
    case <-ctx.Done():
        break loop   // exits the for loop, not just the select
    case sem <- struct{}{}:
    }
    // goroutine launched only if sem was acquired
}
```

This is a silent correctness bug: the program appeared to work because each
goroutine checked `ctx.Err()` internally and exited quickly. The goroutines
were created and exited almost immediately — but they were still created,
consuming stack and scheduler resources.

### `time.Duration` overflow on extreme speeds

**Problem**: `time.Duration` is `int64` nanoseconds (max ~292 years). Dividing
a capture delay of, say, 60 seconds by a speed of `0.0001` gives 600,000
seconds ≈ 6.9 days in nanoseconds, which exceeds `int64` and wraps negative.
`time.After` with a negative duration fires immediately — all timing is lost.

**Fix**: Cap at `time.Hour`:

```go
capOffset = time.Duration(float64(capOffset) / r.cfg.Speed)
if capOffset > time.Hour {
    capOffset = time.Hour
}
```

One hour is already far beyond any realistic inter-packet gap in a PCAP.

### Empty packet data contaminating error metrics

**Problem**: `sendPacket` passed zero-length `Packet.Data` through `Apply`
(which would error on the `< 14` guard) or `sender.Send` (which would also
error), then incremented `Errors`. Zero-length data is not an error — it is a
protocol layer with no payload (e.g. a TCP ACK decoded with payload stripped).

**Fix**: Early return with a dedicated counter:

```go
if len(pkt.Data) == 0 {
    r.mc.C.EmptyPackets.Add(1)
    return
}
```

The `empty` field in the metrics line gives visibility into how many such
packets exist in a given capture, which is analytically useful.

### Empty session counted as done

**Problem**: `runBurst` called `mc.C.SessionsDone.Add(1)` even when
`len(s.Packets) == 0`, inflating the session counter and potentially masking
issues in captures with many empty sessions.

**Fix**: `if len(s.Packets) == 0 { continue }` before the packet loop.
`replaySession` (used by sequential and parallel modes) already had an early
return for empty sessions but also did not increment `SessionsDone` — made
consistent across all modes.

### Empty PCAP returns silent empty slice

**Problem**: `ReadSessions` on a valid but empty PCAP returned `(nil, nil)`.
The caller would log "replaying 0 sessions" and exit cleanly — the user had
no indication that the file was empty rather than fully filtered.

**Fix**: Count packets during the read loop; return a descriptive error if
the count is zero after EOF.

### Fixed RNG seed

**Problem**: `rand.NewSource(42)` produced identical IP pool selections on
every run. Two tgen instances running simultaneously against the same DUT
would generate identical traffic — defeating the purpose of a pool.

**Fix**: `rand.NewSource(time.Now().UnixNano())`.

### `Apply` silently ignoring sub-14-byte frames

**Problem**: A frame shorter than 14 bytes has no valid Ethernet header.
gopacket would find no layers and return `rawData, nil` — the caller received
malformed bytes back without any indication of a problem.

**Fix**: Explicit guard returning a named error at the top of `Apply`.

### IPv4/IPv6 address family mismatch

**Problem**: When an IPv6 plan IP was applied to an IPv4 packet, `To4()` was
already checked. But when an IPv4 plan IP was applied to an IPv6 packet, the
code called `plan.SrcIP.To16()` unconditionally. `To16()` on `192.168.1.1`
returns `::ffff:192.168.1.1` — an IPv4-mapped address placed in an IPv6 source
field, which is invalid.

**Fix**: Guard in the IPv6 block:

```go
if plan.SrcIP != nil && plan.SrcIP.To4() == nil {
    ip6.SrcIP = plan.SrcIP.To16()
}
```

---

## Edge cases and why they matter

| Edge case | Why it matters for network testing |
|-----------|-----------------------------------|
| Empty session (0 packets) | PCAP parsers sometimes emit empty sessions for incomplete flows (SYN without SYN-ACK, ARP-only flows). If these increment session counters they skew throughput metrics. |
| Zero-length packet data | Application-layer stripping in some capture tools can produce packets with headers but no payload. These are meaningful for timing analysis (they still occupy a slot in the TCP stream) but cannot be injected as-is. |
| IPv4/IPv6 plan mismatch | A PCAP with mixed IPv4 and IPv6 sessions being replayed with a pool of IPv4 addresses must not corrupt IPv6 sessions. |
| `--speed 0.0001` | Stress-testing tools are often run with extreme speed values to exercise timing bounds. Overflow produces silent incorrect behaviour — the test appears to run but at the wrong rate. |
| Network/broadcast addresses in pool | Devices that enforce strict source validation (RFC 1812 ingress filtering) will drop frames from `.0` or `.255` sources, making the test invalid. |
| /32 CIDR in pool | A single-host "pool" is a valid configuration (effectively a fixed IP via pool syntax). The boundary exclusion must not accidentally exclude the only entry. |
| Empty PCAP | A misconfigured pipeline writing PCAP files that are valid but empty should fail loudly, not silently replay zero sessions and report success. |
| Workers > sessions | Resource exhaustion: spinning up 1000 goroutines for 3 sessions wastes memory and scheduler time. |
| Context cancel during goroutine dispatch | If goroutines are still launched after cancellation, a long session list could spawn hundreds of goroutines that all immediately check ctx.Err() and exit — but the memory and scheduler overhead is real. |

---

## Stress conditions

### Parallel mode throughput

Benchmark on Apple M3 Pro (100 sessions × 100 packets = 10 000 packets/iteration):

| Configuration | Throughput |
|---------------|------------|
| Sequential, Speed=0 | ~1.9 M pkt/s |
| Parallel, 8 workers, Speed=0 | ~4.3 M pkt/s |
| Burst mode | ~2.1 M pkt/s |

Parallel with 8 workers achieves ~2.2× the sequential throughput. The gain is
sub-linear relative to worker count because the bottleneck is gopacket's
`SerializeLayers` path (which allocates 15 objects per packet regardless of
mutation), not scheduling.

### Mutation throughput

```
BenchmarkApplyFullMutation: 461 ns/op, 1464 B/op, 15 allocs/op
BenchmarkApplyNoMutation:   461 ns/op, 1464 B/op, 15 allocs/op
```

The identical cost for no-mutation vs full-mutation means the allocation
overhead is entirely in gopacket's decode + serialise round-trip, not in the
field-rewriting code. The theoretical ceiling is ~2.1 M pkt/s on a single core.
Real-world limits are the NIC transmit queue and PCIe bandwidth, not tgen.

### Context cancellation under load

`TestReplayContextCancel` exercises cancellation with 5 sessions having a
200 ms intra-session gap and a 30 ms timeout. The test asserts:
1. `Run` returns a non-nil (context) error
2. Fewer than all 10 packets were sent

This is a correctness test, not a benchmark — it verifies that the labeled
break and `time.After`/`ctx.Done()` select interact correctly under a real
timer deadline.

### Large worker count with small session count

Capping workers to `len(sessions)` prevents unnecessary semaphore channel
capacity from being allocated. Tested implicitly by `TestReplayParallel`
(10 sessions, 3 workers — correct; correct even if configured with 1000 workers).

---

## Testing strategy

### Test categories

| Category | What it validates | Tools used |
|----------|------------------|------------|
| Unit tests (mutation) | Correct field rewrites, checksum validity, error on bad input | `gopacket` to build + decode frames |
| Unit tests (filter) | All filter criteria, boundary conditions, unknown protocols | `time.Duration` arithmetic |
| Unit tests (replay) | All three replay modes, context cancel, empty session | `mockSender` (mutex-protected) |
| Integration tests (pcap) | Real PCAP file parsing, empty file detection, invalid path | `pcapgo.NewWriter` for empty PCAP |
| Benchmarks (mutation) | ns/op, allocs/op for Apply | `b.ReportAllocs()` |
| Benchmarks (replay) | pkts/op for all three modes at 100×100 scale | `b.ReportMetric` |

### MockSender design

Two mock implementations coexist in the replay package:

```go
// discardSender — for benchmarks. No mutex; safe only in sequential/burst.
type discardSender struct{ sent int }
func (d *discardSender) Send(_ []byte) error { d.sent++; return nil }

// mockSender — for unit tests. Mutex-protected; safe in parallel mode.
type mockSender struct{ mu sync.Mutex; sent int }
func (m *mockSender) Send(_ []byte) error { m.mu.Lock(); m.sent++; m.mu.Unlock(); return nil }
```

`discardSender` is in the bench file (benchmark-only) and uses no lock because
benchmarks control concurrency externally. `mockSender` is in the test file and
guards every counter access with a mutex so `TestReplayParallel` (3 concurrent
workers) produces the correct count.

### Table-driven tests

`TestApplyIPv4SrcIP` and `TestApplyIPv4DstPort` use `[]struct{ name, input, want }`
sub-tests, which:
- Make the failure message self-describing (`--- FAIL: TestApplyIPv4SrcIP/IPv6-only_plan_ignored`)
- Allow running a single case with `-run TestApplyIPv4SrcIP/nil_plan`
- Make adding new cases trivial (append a struct literal)

### Boundary and invariant tests

`TestFilterBoundaryDuration` pins the exact semantics of `MinDuration`:
`d < MinDuration` (strict), so `d == MinDuration` passes. This documents a
decision that could otherwise be changed accidentally.

`TestFilterUnknownProtocol` uses protocol 41 (IPv6-in-IPv4 encapsulation),
which is intentionally absent from `session.ProtoName`, to exercise the
`proto41` fallback. Protocol 47 (GRE) was the original candidate but is now
a named entry in `ProtoName` — the test would have passed for the wrong reason.

### Empty PCAP test via `pcapgo`

Rather than embedding a binary PCAP fixture, `TestReadSessionsEmptyFile` creates
a temporary file and writes a valid PCAP global header using `pcapgo.NewWriter`:

```go
w := pcapgo.NewWriter(f)
w.WriteFileHeader(65535, layers.LinkTypeEthernet)
```

This is self-documenting and produces a deterministically valid file regardless
of host byte order.

---

## What can be improved

### Single-pass PCAP reading
`tgen inspect` calls both `Inspect(path)` and `ReadSessions(path)`, opening
the file twice. A unified `InspectAndExtract` function would halve I/O on slow
storage or for large files. Not refactored yet to avoid expanding scope, but
the double-read is documented in `reader.go`.

### TCP reassembly awareness
The current `Extractor` groups packets by 5-tuple but does not reconstruct
TCP byte streams. Retransmitted packets are stored as-is and replayed. For
testing stateful inspection devices, retransmissions with mutated IPs could
confuse the DUT if the sequence numbers are not consistent with the new
addresses. A TCP reassembly layer (gopacket's `tcpassembly` package) would
fix this.

### VLAN and QinQ support
Packets with 802.1Q (VLAN) or 802.1ad (QinQ) tags are not explicitly handled
in `Apply`. gopacket decodes them but `SerializeLayers` must include the VLAN
layer explicitly. Currently, VLAN-tagged frames pass through unmodified (no IP
layer found → early return in Apply). This is correct for pass-through but
prevents IP mutation on tagged traffic.

### Prometheus metrics endpoint
The current metrics are written as text lines to stdout/stderr/file. Exposing
them as a Prometheus `/metrics` HTTP endpoint would allow Grafana dashboards
and alerting during long-running replay jobs without log parsing.

### Per-flow rate limiting
The current speed multiplier is global. Some test scenarios require per-flow
rate limiting (e.g. simulate a 10 Mbps link per session while allowing 1 Gbps
in aggregate). This would require a token bucket per session in `replaySession`.

### Ordered session output
`session.Extractor.Sessions()` returns sessions in random map iteration order.
For reproducible replays (especially in sequential mode where order matters),
sessions could be sorted by `StartTime` before returning.

### Memory-mapped PCAP reading
For very large PCAP files (> 1 GB), `gopacket.OpenOffline` allocates and copies
each packet. A memory-mapped reader (using `mmap`) would reduce allocations and
allow the OS page cache to amortise repeated access across loop iterations.

### Graceful multi-error collection
`runParallel` stores only the first error from any goroutine. If 8 workers
each fail with a different error (e.g. different interface send failures), only
one is reported. A multi-error type (or `errors.Join`) would surface all of
them.

### Config file hot-reload
Long-running replay loops cannot change mutation rules or speed without
restarting. A SIGHUP handler that reloads the config file would allow tuning
during execution.

### /31 and /32 in CIDR pool with IPv6
The `expandPool` function converts all IPs to `.To4()`. For IPv6 CIDRs this
silently produces `nil` entries in the pool, which would later crash on
`m.rng.Intn(len(m.srcPool))` if all entries are nil. IPv6 pool support
requires removing the `.To4()` calls and teaching `Apply` to select the pool
entry by address family matching the packet.
