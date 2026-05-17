# tgen — Architecture

## Overview

tgen is a PCAP-based traffic generator that replays captured network sessions
onto a live interface with configurable L3/L4 field mutation, timing control,
and session filtering.

```
┌──────────────┐    ┌──────────────────┐    ┌──────────────┐
│  PCAP files  │───▶│  Session Extract  │───▶│    Filter    │
└──────────────┘    └──────────────────┘    └──────┬───────┘
                                                    │
                    ┌───────────────────────────────▼──────────┐
                    │              Replay Engine               │
                    │  ┌─────────────┐   ┌──────────────────┐  │
                    │  │   Mutator   │   │  Timing / Sched  │  │
                    │  │ (per-sess.) │   │  (speed, mode)   │  │
                    │  └──────┬──────┘   └────────┬─────────┘  │
                    │         └──────────┬─────────┘            │
                    │              Apply (L3/L4)                │
                    └──────────────────┬────────────────────────┘
                                       │
                    ┌──────────────────▼──────────┐
                    │     Sender (libpcap inject)  │
                    └─────────────────────────────┘
                                       │
                    ┌──────────────────▼──────────┐
                    │    Network Interface (NIC)   │
                    └─────────────────────────────┘
```

---

## Package map

```
tgen/
├── cmd/tgen/           CLI entry point (cobra)
│   ├── main.go
│   ├── root.go         root command + global --config flag
│   ├── run.go          `tgen run`     — main replay workflow
│   ├── inspect.go      `tgen inspect` — PCAP statistics
│   └── sessions.go     `tgen sessions`— list/filter sessions
│
└── internal/
    ├── config/         typed configuration + YAML loader + validation
    ├── session/        Session model, bidirectional flow extractor, Filter, ProtoName
    ├── pcap/           PCAP file reader (wraps gopacket/pcap)
    ├── mutation/       Mutator (plan cache) + Apply (L3/L4 rewrite)
    ├── sender/         Sender interface + libpcap implementation
    ├── metrics/        atomic counters, Snapshot, periodic reporter
    └── replay/         Replayer: sequential / parallel / burst modes
```

---

## Key data structures

### `session.Session`
Represents one reconstructed L4 flow. All packets sharing the same canonical
5-tuple `(srcIP, dstIP, srcPort, dstPort, proto)` belong to a single session.
The key is stored in canonical (smallest-endpoint-first) form so that both
directions of a TCP connection map to the same session.

```
Session
  Key        — canonical 5-tuple (always ordered smaller-endpoint-first)
  SrcIP/DstIP/SrcPort/DstPort/Proto — original endpoints (defensive copies)
  Packets[]  — ordered list of Packet{Timestamp, Data, LinkType}
  StartTime / EndTime
```

### `mutation.Plan`
Resolved L3/L4 replacement values for one session. Computed once from
`MutationConfig` and cached in `Mutator.cache` (keyed by `session.Key`) so
that every packet in the session gets identical rewrites — preserving flow
consistency. A nil IP or zero port means "keep the original value".

### `session.ProtoName`
A single package-level `map[uint8]string` mapping IP protocol numbers to
canonical lower-case names (icmp, igmp, tcp, udp, gre, esp, ah, icmpv6,
ospf, sctp). All protocol-to-name lookups in the codebase reference this one
map. Unknown numbers fall back to `fmt.Sprintf("proto%d", n)`.

---

## Replay modes

| Mode       | Description                                              |
|------------|----------------------------------------------------------|
| sequential | Sessions replayed one after another; inter-packet gaps   |
|            | are preserved and scaled by `speed`.                     |
| parallel   | Up to `workers` sessions replayed concurrently; each    |
|            | session is still individually timing-accurate.           |
| burst      | No inter-packet delay; maximises throughput.             |

Speed formula: `wall_delay = capture_delay / speed`.
`speed = 0` is treated as burst (no delay within a session).

Workers are automatically capped to `min(cfg.Workers, len(sessions))` to avoid
allocating semaphore slots that can never be used.

---

## Mutation pipeline

```
raw packet bytes
      │
      ├─ len < 14?  → error (minimum Ethernet header guard)
      │
      ▼
gopacket.NewPacket()   — decode all layers
      │
      ├─ no IP layer?  → return rawData unchanged
      │
      ▼
Mutate IPv4/IPv6 SrcIP / DstIP
  (IPv6-only plan IP silently skipped for IPv4 packets, and vice versa)
      │
      ▼
Mutate TCP/UDP SrcPort / DstPort
      │
      ▼
tcp.SetNetworkLayerForChecksum(ip)   — bind pseudo-header
udp.SetNetworkLayerForChecksum(ip)
      │
      ▼
gopacket.SerializeLayers(
  opts{ComputeChecksums:true, FixLengths:true})
      │
      ▼
mutated raw bytes
```

Checksum correctness is guaranteed by gopacket's serialisation pass, which
recomputes IP, TCP, and UDP checksums using the updated headers.

---

## Session filtering (advanced)

`session.Filter` selects sessions from a loaded PCAP before replay. Criteria:

| Field         | Meaning                                                |
|---------------|--------------------------------------------------------|
| MinDuration   | Minimum session duration (first–last packet). Boundary is exclusive: sessions with duration exactly equal to MinDuration pass. |
| MaxDuration   | Maximum session duration                               |
| StartAfter    | Session start must be strictly after this timestamp    |
| StartBefore   | Session start must be at or before this timestamp      |
| Protocols     | Allow-list of protocol names; named entries in `session.ProtoName` (icmp, igmp, tcp, udp, gre, esp, ah, icmpv6, ospf, sctp) or `proto<N>` for any other number |

Filtering happens after session extraction and before replay, so the PCAP is
read only once regardless of how restrictive the filter is.

---

## Configuration

Configuration is loaded from a YAML file (`--config`) or built from CLI flags.
CLI flags override the config file when `--config` is used with `--interface`.

```
config.Config
  Interface       string
  PcapFiles[]     {Path}
  Mutations       {SrcIP, DstIP, SrcIPPool, DstIPPool, ports, Rules[]}
  Replay          {Mode, Speed, Loop, LoopCount, Workers}
  Filter          {MinDuration, MaxDuration, StartAfter, StartBefore, Protocols}
  Metrics         {Enabled, ReportInterval, Output}
```

See `config/example.yaml` for an annotated reference.

---

## Metrics

`metrics.Collector` maintains five atomic int64 counters:
- `PacketsSent`  — frames successfully injected onto the wire
- `BytesSent`    — total bytes injected
- `Errors`       — mutation or injection failures
- `SessionsDone` — sessions fully replayed (not incremented for empty sessions)
- `EmptyPackets` — frames whose data was zero-length (skipped, not errors)

`Snapshot()` reads all counters and computes per-interval PPS / BPS relative
to the previous snapshot. `Run(done)` loops on a ticker and calls `report()`
until the done channel is closed (which triggers a final report).

---

## Defensive hardening

The following edge cases and stress conditions are explicitly guarded against.

### Goroutine leak on context cancellation (`runParallel`)
The original `break` inside a `select` only exits the `select` statement, not
the enclosing `for` loop. New goroutines would keep being launched even after
the context was cancelled. Fixed with a labeled `break loop` so the dispatch
loop exits immediately on `ctx.Done()`. Already-running goroutines drain
naturally through `wg.Wait()`.

### Empty sessions not counted as done (`runBurst`, `replaySession`)
Sessions with zero packets are skipped with `continue` before `SessionsDone`
is incremented. Without this guard, the counter would misrepresent throughput
in captures that contain empty session records.

### Inter-packet gap overflow (`replaySession`)
Dividing a large nanosecond `time.Duration` by a very small speed (e.g.
`0.0001`) can overflow `int64` and wrap to a negative value, causing
`time.After` to fire immediately or panic. Capped at `time.Hour` per gap.

### Workers larger than session count (`runParallel`)
Allocating a semaphore channel larger than `len(sessions)` wastes memory with
no throughput benefit. Workers are capped to `min(workers, len(sessions))`.

### IPv4/IPv6 plan mismatch (`Apply`)
Applying an IPv4 plan address to an IPv6 packet via `To16()` produces an
IPv4-mapped address (`::ffff:192.168.x.x`) in the IPv6 source field, which is
invalid on the wire. Plan addresses are checked with `To4()` before application
and silently skipped when the family does not match the packet.

### Small packet rejection (`Apply`)
Frames shorter than 14 bytes cannot contain a valid Ethernet header. gopacket
would parse them silently and return the raw bytes unchanged, masking
misconfiguration. `Apply` now returns a descriptive error for such frames.

### Sender size guards (`Send`)
`sender.Send` validates three conditions before calling `WritePacketData`:
- nil / zero-length data → `"packet data is nil or empty"`
- shorter than 14 bytes → `"packet too small: N bytes (minimum 14)"`
- longer than 65535 bytes → `"packet too large: N bytes (maximum 65535)"`

### Empty PCAP file (`ReadSessions`)
An empty PCAP (valid header, zero packets) previously returned `(nil, nil)`,
causing the caller to silently replay nothing. Now returns a descriptive error:
`"pcap file %q contains no packets"`.

### Empty packet data (`sendPacket`)
Zero-length `Packet.Data` entries (which can arise from protocol layers with
no payload) are counted in the `EmptyPackets` metric and skipped, rather than
being passed to `Apply` (which would error) or `Send` (which would also error).

### Buffer reuse with NoCopy parsing (`extractor.Feed`)
`gopacket.NoCopy` allows the pcap library to reuse its read buffer on the next
call. Every field retained beyond the `Feed` call — `SrcIP`, `DstIP`, and
`Packet.Data` — is explicitly copied with `append([]byte(nil), ...)` /
`append(net.IP(nil), ...)` before being stored in the `Session`.

### Network and broadcast address exclusion (`expandPool`)
For CIDRs with prefix length shorter than /31, the network address (all host
bits zero) and broadcast address (all host bits one) are excluded from the
expanded pool. /31 (point-to-point) and /32 (single host) have no boundary
addresses and are included as-is.

### RNG concurrency safety (`Mutator`)
`rng` has no lock of its own. It is safe because `rng` is only ever accessed
inside `buildPlan`, which is called exclusively from `PlanFor` while `mu` is
held. No separate synchronisation is needed.

### RNG determinism (`Mutator`)
The original `rand.NewSource(42)` produced identical IP pool selections on
every run, making traffic patterns predictable. Changed to
`rand.NewSource(time.Now().UnixNano())`.

### Protocol name consolidation
Four separate local maps / switch statements previously defined protocol→name
mappings with inconsistent coverage (4–10 entries each). Consolidated into a
single exported `session.ProtoName` map used by all packages (`filter.go`,
`mutator.go`, `inspect.go`, `sessions.go`). Unknown protocols fall back to
`proto<N>` consistently everywhere.

---

## Extension points

| What to extend           | Where to change                          |
|--------------------------|------------------------------------------|
| New protocol mutations   | `internal/mutation/apply.go`             |
| New named protocols      | `session.ProtoName` in `session/session.go` |
| New output/injection     | Implement `sender.Interface`             |
| New replay scheduling    | Add a case to `Replayer.Run` switch      |
| New filter criteria      | `session.Filter.match()`                 |
| New CLI command          | Add `*cobra.Command` in `cmd/tgen/`      |
| New metrics counter      | Add `atomic.Int64` to `metrics.Counters`, update `Snapshot` and `report` |
