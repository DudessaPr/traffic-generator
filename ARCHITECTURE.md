# tgen — Architecture

## Package map

```
cmd/tgen/
  main.go       entry point
  root.go       root cobra command + --config flag
  run.go        tgen run: wires all components; buildConfig; buildSender; parseFilter
  generate.go   tgen generate: synthesise packets from template; MAC resolution; rate/count
  inspect.go    tgen inspect: PCAP file stats
  sessions.go   tgen sessions: list/filter sessions

internal/config/
  config.go     all config structs (Config, MutationConfig, ReplayConfig, …)
  loader.go     Load(yaml) + Default()
  validate.go   Validate(*Config) error-checking

internal/session/
  session.go    Key, Packet, Session types; ProtoName map
  extractor.go  Extractor.Feed(): reconstruct flows; canonical() key normalisation
  filter.go     Filter.Apply(): select sessions by duration/timestamp/protocol

internal/pcap/
  reader.go     ReadSessions(path) + Inspect(path) wrapping gopacket/pcap

internal/mutation/
  mutator.go    Mutator: plan cache; IPv4+IPv6 pool expansion; ResetCache/CacheLen/PoolStats
  apply.go      Apply(raw, plan, linkType): rewrite L2+L3+L4 headers, recompute checksums

internal/sender/
  sender.go     Interface (Send/Close); Batcher (SendBatch); *Sender: libpcap WritePacketData + mutex
  pool.go       *PoolSender: round-robin across N senders; SendBatch splits batch across pool; NewPoolFrom for tests
  raw_linux.go  *RawSender: AF_PACKET SOCK_RAW + sendmmsg batch (Linux only)
  raw_other.go  stub NewRaw + SendBatch returning ErrNotSupported on non-Linux

internal/ratelimit/
  rate.go       Limiter (token bucket via x/time/rate); New; ParseRate; rampUp goroutine
                CPSLimiter: token bucket for new connections/sessions; NewCPS; Wait
                ParseCPS: parses "1000", "1kcps", "1Mcps"; ApplyMultiplier: scales rate strings
                Shared by both the replay and generate pipelines.

internal/replay/
  replayer.go   Replayer.Run: dispatches to runSequential/runParallel/runBurst/runPcap
  rate.go       thin wrappers (rateLimiter alias, newRateLimiter, parseRate) → ratelimit pkg

internal/generate/
  template.go   Template: ParseTemplate; Build(srcMAC, dstMAC, rng) — Ethernet/IPv4+IPv6/TCP/UDP/ICMP
                splitTemplate custom tokeniser handles IPv6 ':' in field values
  generator.go  Generator: Config (Rate/Count/Loop/Workers/PreBuild/BatchSize); New; Run(ctx)
                Run spawns N worker goroutines; each has its own *rand.Rand + optional pre-built buffer
                Batch path active when PreBuild>0 and sender implements Batcher

internal/netutil/
  route.go      Resolve(targetIP): findOutbound via UDP connect trick
  route_darwin.go  gatewayIP via `route -n get`; gatewayMAC via `arp -n`
  route_linux.go   gatewayIP via /proc/net/route; gatewayMAC via /proc/net/arp
  route_other.go   stubs returning errors

internal/metrics/
  metrics.go    Counters (atomic); Snapshot; Collector.Run(done)
                Flow counters: ActiveFlows, OpenFlows, FlowsStarted (CPS source)
```

---

## Data flow

### Replay pipeline (`tgen run`)

```
PCAP file(s)
    │
    ▼ pcap.ReadSessions
[]*session.Session
    │
    ▼ session.Filter.Apply
[]*session.Session (filtered)
    │
    ├── [PreProcess=true] mutation.Apply × N packets ─────────┐
    │                                                          │
    ▼ Replayer.Run                                             │
  ┌──────────────────────────────────────────────────┐        │
  │ mode: sequential │ parallel │ burst │ pcap        │        │
  │                                                  │        │
  │  for each packet:                                │        │
  │    1. mutator.PlanFor(session) [cached]          │◄───────┘
  │    2. mutation.Apply(raw, plan)   OR sendRaw()   │
  │    3. ratelimit.Limiter.Wait(ctx, pktSize)       │
  │    4a. [burst + Batcher] accumulate in buf[]     │
  │        flush buf via sender.SendBatch when full  │
  │        or at session boundary                    │
  │    4b. [all other paths] sender.Send(frame)      │
  └──────────────────────────────────────────────────┘
    │
    ▼ metrics.Collector
  [packets, bytes, errors, pps, bps, active, open, cps]
```

### Generate pipeline (`tgen generate`)

```
CLI template string
    │
    ▼ generate.ParseTemplate  (splitTemplate handles ':' in IPv6 values)
*generate.Template
    │ (proto, src/dst CIDR, port ranges, TTL, DSCP, TCP flags, payloadSize, isIPv6)
    │
  netutil.Resolve(dstIP) ──► interface + gateway MAC (once, at startup)
    │
    ▼ Generator.Run
  ┌───────────────────────────────────────────────────────────────┐
  │  [optional] pre-build N packets per worker → [][]byte buffer  │
  │                                                               │
  │  spawn Workers goroutines, each with:                         │
  │    ├─ own *rand.Rand (seed = now.UnixNano ^ (i+1)<<32)       │
  │    ├─ own pre-built buffer slice (or nil for on-the-fly)      │
  │    └─ count = total_count / workers (+1 for first N workers)  │
  │                                                               │
  │  worker loop until count reached (or ctx cancelled):          │
  │    1. if pre-built: data = buf[idx % len(buf)]                │
  │       else: template.Build(srcMAC, dstMAC, rng)               │
  │         ├─ IPv4 or IPv6 network layer (isIPv6 flag)           │
  │         ├─ random src/dst IP from CIDR per packet             │
  │         ├─ random sport / dport from range                    │
  │         ├─ optional zero-padded payload (size field)          │
  │         └─ gopacket.SerializeLayers → []byte                  │
  │    2. ratelimit.Limiter.Wait(ctx, pktSize)  [shared]          │
  │    3a. [pre-built + Batcher] buf append; flush at BatchSize   │
  │    3b. [all other paths] sender.Send(frame)                   │
  │    4. if Loop && count reached: flush batch, restart cycle    │
  └───────────────────────────────────────────────────────────────┘
    │
    ▼ metrics.Collector  (atomic counters; mc.Run prints every second)
  [packets, bytes, errors, pps, bps, active, open, cps]
```

---

## Key design decisions

### Sender interface
`sender.Interface` (`Send([]byte) error` + `Close()`) decouples the injection
mechanism from the replay engine. An optional `sender.Batcher` extension
(`SendBatch([][]byte) (int, error)`) allows callers to amortise syscall overhead
over N frames. Callers type-assert to `Batcher`; its absence is not an error.

Three `Interface` implementations exist:

- `*Sender` — libpcap `WritePacketData`. Has a `sync.Mutex` because
  `pcap_sendpacket` is not goroutine-safe and parallel mode calls `Send`
  concurrently from multiple goroutines. Does **not** implement `Batcher`.
- `*PoolSender` — wraps N `Interface` values; dispatches via `atomic.Uint64`
  round-robin. Used when `--interface eth0,eth1,…` specifies multiple NICs.
  Each underlying `*Sender` has its own mutex, so contention occurs only when
  pool size < number of concurrent goroutines. Implements `Batcher`: splits a
  batch evenly across underlying senders at batch granularity (not per-packet).
  If an underlying sender does not implement `Batcher`, it falls back to
  sequential `Send` calls for its chunk.
- `*RawSender` (Linux only) — AF_PACKET SOCK_RAW via `syscall.Sendto`.
  Bypasses libpcap; lower per-packet overhead at >1 Gbps. Selected via
  `--sender raw`. Implements `Batcher` via `sendmmsg(2)` (one syscall for up
  to `BatchSize` frames). Falls back to a sequential `Sendto` loop if the
  kernel returns `ENOSYS`. On non-Linux the type is a stub; `SendBatch` returns
  `ErrNotSupported` (dead path since `NewRaw` also errors on non-Linux).

### Batch-send path (`--batch-size`, burst mode)
`runBurst` collects mutated frames into a `[][]byte` buffer (capacity =
`cfg.BatchSize`, default 32, max 256). The buffer is flushed:
- when it reaches `BatchSize` frames, or
- at the end of each session (session boundary flush).

If the sender implements `Batcher`, the flush calls `SendBatch`; otherwise it
loops over `Send`. This design means the batch path is opt-in and transparent:
pcap/libpcap senders, macOS, and all non-burst modes continue to work unchanged.

The generator uses the same `BatchSize` when `--pre-build > 0` and the sender
implements `Batcher`. On-the-fly `Build` calls always use per-packet `Send`
regardless of `--batch-size`.

### Session key canonical form
5-tuple keys are stored with the "smaller" endpoint first (`canonical()` in
`session/extractor.go`). Both directions of a TCP flow map to the same session
key, so the mutation plan is consistent across the full bidirectional flow.

### Mutation plan cache
`Mutator.cache` maps `session.Key → Plan`. Built once per session on first
`PlanFor` call, then returned from cache on all subsequent calls. This ensures
every packet in a flow receives identical rewrites (consistent source IP, port,
TTL, etc.).

`PlanFor` uses double-checked locking with `sync.RWMutex`: cache hits take an
`RLock` (multiple parallel goroutines read concurrently); only cache misses
compete for the write lock.  A second cache check under the write lock prevents
duplicate plan construction when two goroutines race on the same key.

`ResetCache()` discards the entire cache. Used by `--ip-pool-per-iter` to draw
fresh random IPs from the pool at the start of each loop iteration.

### IPv6 pool expansion
`expandPool` handles both IPv4 and IPv6 CIDRs. For IPv6, `.To4()` is not called
(it returns nil for IPv6 addresses); the full 16-byte representation is stored.
For IPv4, `.To4()` normalises to 4-byte form. Boundary-address skipping (network
and broadcast) applies only to IPv4 prefixes shorter than `/31`.

### Rate limiter (`internal/ratelimit`)
`ratelimit.Limiter` wraps `golang.org/x/time/rate.Limiter` (token bucket).
Both the replay and generate pipelines import this package; there is no
duplication.

- PPS mode: 1 token = 1 packet. Burst = 10% of rate (capped at 1000).
- BPS mode: 1 token = 1 byte. Burst = 65536 bytes (large enough for any
  Ethernet frame, so `WaitN` never fails due to `n > burst`).
- `--rate-ramp` (replay only): a goroutine ticks every 50 ms and calls
  `SetLimit` with a linearly increasing fraction of the target. The goroutine
  stops when the replay context is cancelled or the ramp duration elapses.

`internal/replay/rate.go` contains only thin forwarding wrappers
(`rateLimiter` type alias, `newRateLimiter`, `parseRate`) that preserve the
existing test API without duplicating any logic.

### CPS limiter (`ratelimit.CPSLimiter`)
`CPSLimiter` is a second token-bucket limiter that throttles how many new
*sessions* (connections) start per second, independently of the per-packet
`Limiter`. One token = one new session.

- Burst = 10% of CPS (capped at 1000), drained immediately so the limit is
  enforced from the first session.
- Applied in `runSequential` (before each `replaySession` call) and
  `runParallel` (after acquiring the semaphore slot, before the goroutine
  launches). Not applied in `runBurst` or `runPcap`.
- In the generator, the limiter is shared across all worker goroutines; each
  worker waits once per flow cycle (initial start + each loop restart).
- A nil `*CPSLimiter` is unlimited (zero value is safe to call `Wait` on).

### --multiplier
`ratelimit.ApplyMultiplier(rateStr, m)` parses the rate string, scales the
numeric value by `m`, and returns a canonical `<N>pps` or `<N>bps` string.
The scaled string is passed to `ratelimit.New` as if the user had typed it
directly. For CPS, `effectiveCPS = cfg.CPS * m`. A multiplier of `0` is
treated as `1.0` (no change) so YAML configs that omit the field behave
identically to the default.

### Packet template and generation (`internal/generate`)
`generate.Template` stores a protocol + field specification parsed from a
colon-separated string.  `Build(srcMAC, dstMAC, *rand.Rand)` is called once per
packet and uses `gopacket.SerializeLayers` to produce a complete Ethernet frame:

- **IPv6 support**: protocols `tcp6` and `udp6` produce `EthernetTypeIPv6` /
  `layers.IPv6` frames.  `randIPv6FromNet` handles 16-byte masks.  IPv6
  addresses in field values contain `:`, so the parser uses `splitTemplate`
  (splits on `:` only when followed by an all-alpha key then `=`) rather than
  `strings.Split(s, ":")`.
- **Payload size**: `size=N` appends `N` zero bytes after the L4 header.  This
  is implemented via `gopacket.Payload` added to `SerializeLayers`.
- **CIDR randomisation**: `randIPv4FromNet` / `randIPv6FromNet` pick a random
  address per build call by ORing the network base with a random host portion,
  bit-by-bit through the mask.  No pre-expansion or boundary exclusion — the
  generator is stateless.
- **Port ranges**: `pickPort(min, max, rng)` draws uniformly from `[min, max]`.
- **`*rand.Rand` injection**: `Build` accepts a seeded `*rand.Rand` so tests use
  a fixed seed for deterministic packet fields, and multi-worker production runs
  give each goroutine its own isolated RNG.
- **Workers**: `Generator.Run` spawns N goroutines (default 1); total count is
  distributed evenly with the remainder spread to the first N workers.  Each
  goroutine seeds its own `*rand.Rand` with `now.UnixNano ^ (i+1)<<32` to
  guarantee distinct initial states even when spawned in the same nanosecond.
- **Pre-build buffer**: when `PreBuild > 0`, `Run` builds all packets in the
  main goroutine before launching workers, so a build failure aborts cleanly.
  Workers cycle through the buffer with `buf[idx%len(buf)]`, removing `Build()`
  and all rand calls from the hot path.
- **MAC resolution**: `cmd/tgen/generate.go` calls `netutil.Resolve(dstIP)` once
  at startup to obtain the outbound interface and gateway MAC.  The same ARP
  resolution path is reused from the `--target-ip` logic in `tgen run`.

### Pcap-order replay (`--mode pcap`)
`runPcap` collects all packets from all sessions, applies mutations, and sorts
the resulting slice by original capture timestamp (`sort.Slice`). Replay then
proceeds packet-by-packet in that global order, honouring inter-packet gaps
scaled by `--speed`. Cost: O(N·M · log(N·M)) sort + one extra `mutation.Apply`
pass before sending begins.

### Pre-mutation buffer (`--pre-process`)
`Replayer.preProcess` mutates every packet in every session and stores the
results as `[][]byte` before the replay loop starts. The send loop then calls
`sendRaw` (no `mutation.Apply`). This removes all gopacket parsing and
serialisation from the hot path, yielding ~1.8× throughput improvement in
CPU-bound scenarios.

Pre-mutation is only used for `burst` and `parallel` modes. `sequential` and
`pcap` perform mutation inline (pcap mode sorts before sending anyway).

### Auto-interface resolution (`--target-ip`)
`netutil.Resolve(targetIP)` performs three steps:
1. **Outbound interface** — opens a connected UDP socket (no packet sent) to
   `targetIP:1` and reads `LocalAddr` to find the OS-selected local IP, then
   matches it against `net.Interfaces()`.
2. **Gateway IP** — platform-specific: `route -n get` on macOS; `/proc/net/route`
   on Linux.
3. **Gateway MAC** — platform-specific: `arp -n` on macOS; `/proc/net/arp` on
   Linux.

The resolved interface name is written to `cfg.Interface` and the gateway MAC
is written to `cfg.Mutations.DstMAC` before `config.Validate` runs. Subsequent
`mutation.Apply` calls rewrite the Ethernet dst MAC of every packet.

### DstMAC mutation (L2 rewriting)
`Plan.DstMAC net.HardwareAddr` — when non-nil, `mutation.Apply` calls
`copy(eth.DstMAC, plan.DstMAC)` before serialisation. This is needed whenever
the destination IP is mutated to a routed address: without it the packet
carries the original captured dst MAC rather than the gateway's MAC, and most
switches drop it.

### Flow tracking metrics
Three atomic counters in `metrics.Counters` track flow state at runtime:

- **`FlowsStarted`** — monotonically increasing; incremented once per flow at
  start.  The reporter computes CPS as the delta between successive snapshots
  divided by the elapsed interval.
- **`ActiveFlows`** — flows currently executing (incremented at start, decremented
  at end via `defer`).  Reflects in-flight goroutines in parallel/burst mode.
- **`OpenFlows`** — subset of active flows that have not yet sent a TCP FIN or RST.
  Decremented when a FIN/RST is detected in the last packet of a TCP session;
  otherwise decremented at session end.  UDP/ICMP/other flows are always counted
  as "open" until they complete.

All three counters are updated from whichever replay path is active:
`replaySession` (sequential/parallel), `replayProcessed` (pre-process mode),
`runBurst` (burst non-processed), and `runPcap` (pcap mode).  In the generator,
each worker goroutine counts as one flow for the lifetime of the worker.

### StartAfter filter uses strict `>`
`session.Filter.match()` uses `!s.StartTime.After(f.StartAfter)` (i.e. strict
greater-than). A session starting exactly at the boundary is excluded. See the
corresponding test in `session/filter_test.go`.

### Configurable CIDR pool cap
`expandPool` accepts a `limit int` parameter from `MutationConfig.IPPoolLimit`.
Default = 256; maximum = 65536. Without a cap, a `/8` prefix would expand to
~16 million addresses and exhaust memory.
