# tgen — Go Implementation Details

This document explains every significant Go language and runtime feature used
in the codebase: what was chosen, why, and what the alternatives are (including
`sync.Pool`, which was explicitly evaluated and rejected). The goal is to make
the design reasoning visible and to give a full picture of the concurrency and
memory safety story.

---

## Table of contents

1. [Goroutines](#goroutines)
2. [Channels — semaphore pattern](#channels--semaphore-pattern)
3. [Channels — error forwarding](#channels--error-forwarding)
4. [Channels — done signal](#channels--done-signal)
5. [sync.WaitGroup](#syncwaitgroup)
6. [Context cancellation](#context-cancellation)
7. [Labeled break — exiting a for from inside a select](#labeled-break--exiting-a-for-from-inside-a-select)
8. [Loop variable capture (s := s)](#loop-variable-capture-s--s)
9. [sync.Mutex — plan cache and RNG](#syncmutex--plan-cache-and-rng)
10. [sync/atomic — lock-free metrics counters](#syncatomic--lock-free-metrics-counters)
11. [Interfaces as testability seams](#interfaces-as-testability-seams)
12. [gopacket.NoCopy — zero-allocation parsing and its pitfalls](#gopacketnocopy--zero-allocation-parsing-and-its-pitfalls)
13. [Canonical map key for bidirectional flows](#canonical-map-key-for-bidirectional-flows)
14. [time.Duration arithmetic and overflow protection](#timeduration-arithmetic-and-overflow-protection)
15. [io.Writer abstraction for metrics output](#iowriter-abstraction-for-metrics-output)
16. [Error wrapping with %w](#error-wrapping-with-w)
17. [sync.Pool — why it was not used and how it could be](#syncpool--why-it-was-not-used-and-how-it-could-be)
18. [Overall concurrency safety summary](#overall-concurrency-safety-summary)

---

## Goroutines

**Where:** `runParallel` (`replay/replayer.go:95`) and the metrics reporter
(`cmd/tgen/run.go`, `go func() { mc.Run(done) }()`).

**What they do:**

`runParallel` launches one goroutine per session up to a configured worker
count, where each goroutine owns one timing-accurate session replay. The
metrics goroutine runs a `time.NewTicker` loop and writes a one-line report
to an `io.Writer` once per interval.

**Why goroutines instead of OS threads:**

Goroutines are multiplexed by the Go runtime scheduler (M:N threading). A
goroutine starts with an 8 KB stack that grows on demand, so launching one per
session costs microseconds and a few kilobytes rather than the ~8 MB a
POSIX thread demands. In parallel mode with 8 workers replaying 100-packet
sessions, the goroutine overhead is unmeasurable compared to the network I/O
and packet serialisation costs (~2 μs/packet as shown by benchmarks).

**Safety:** goroutines are safe here because:

- Each session goroutine gets its own copy of the session pointer (`s := s`,
  see the loop-capture section below).
- Shared mutable state (`Mutator.cache`, `Counters`) is protected by `Mutex`
  or `atomic` — no goroutine touches the same memory without coordination.
- Context propagation ensures goroutines observe cancellation and do not
  outlive the parent.

---

## Channels — semaphore pattern

**Where:** `runParallel` (`replayer.go:82`).

```go
sem := make(chan struct{}, workers)
// ... in the dispatch loop:
sem <- struct{}{}   // acquire slot (blocks when full)
// ... in each goroutine:
<-sem               // release slot on exit
```

**What it is:**

A buffered channel of `struct{}` (zero-size type, zero allocation) acts as a
counting semaphore. The channel capacity is the maximum allowed concurrency.
Sending into a full channel blocks the dispatch loop, naturally back-pressuring
it until a goroutine finishes and reads from the channel.

**Why this over other options:**

| Option | Problem |
|--------|---------|
| `runtime.NumCPU()` goroutines, work queue | More complexity; requires a separate job channel |
| `semaphore.Weighted` (golang.org/x/sync) | External dependency for something three lines solve |
| Raw counter + `sync.Mutex` | More code, same semantics |
| Unbounded goroutines | Memory exhaustion on large PCAPs |

The channel semaphore is idiomatic Go: it is self-documenting (capacity = max
concurrency), requires no library, and composes naturally with `select` for
cancellation.

**Worker cap:** workers are clamped to `min(cfg.Workers, len(sessions))`.
Creating a semaphore larger than the number of sessions wastes capacity that
can never be consumed — the buffer slots sit empty for the entire run.

**Safety:** The semaphore channel itself is written before each goroutine is
started and read in the goroutine's `defer`. Because `wg.Wait()` blocks until
all goroutines return, and goroutines always release before `wg.Done()`, the
semaphore drains completely before `runParallel` returns. There is no
possibility of the channel being left in a partially-full state.

---

## Channels — error forwarding

**Where:** `runParallel` (`replayer.go:83`).

```go
errc := make(chan error, 1)

// in each goroutine:
select {
case errc <- err:
default:
}

// after wg.Wait():
select {
case err := <-errc:
    return err
default:
    return ctx.Err()
}
```

**Why buffered with capacity 1:**

Multiple goroutines may fail simultaneously (e.g., the interface goes down).
A buffered channel of size 1 lets the first goroutine to fail write its error
without blocking, while all subsequent failures are silently discarded (the
`default` branch). The caller gets exactly one error — the first — which is
enough to diagnose the failure. Using an unbuffered channel would require a
dedicated drain goroutine to avoid the senders blocking forever. Using a larger
buffer would collect all errors but the caller only inspects one.

**Safety:** `errc` is written only from goroutines, read only from the
dispatch goroutine after `wg.Wait()`. There is no race because `wg.Wait()`
provides a happens-before guarantee between the goroutine writes and the
post-wait read.

---

## Channels — done signal

**Where:** `metrics.Collector.Run` (`metrics/metrics.go:61`).

```go
func (c *Collector) Run(done <-chan struct{}) {
    ticker := time.NewTicker(c.interval)
    defer ticker.Stop()
    for {
        select {
        case <-done:
            c.report()
            return
        case <-ticker.C:
            c.report()
        }
    }
}
```

**Why a `chan struct{}` instead of `context.Context`:**

The metrics goroutine does not need a cancellation reason or deadline — it just
needs to know "replay is over, emit a final report and exit." A plain
`chan struct{}` that is `close()`d communicates this with zero allocation and
maximum clarity. `close` broadcasts to all receivers at once (a channel receive
on a closed channel returns immediately), so if there were multiple metrics
goroutines they would all exit cleanly.

Using `context.Context` here would be valid but over-engineered: the metrics
goroutine has no cancellation value to propagate further.

**Why `<-done` is checked before `<-ticker.C`:**

`select` chooses randomly among ready cases. If both `done` and `ticker.C` are
ready simultaneously (e.g., the ticker fires at the exact instant replay
finishes), Go may pick either case. In practice the final report will still be
emitted because the `done` case calls `report()` before returning. The race
between final tick and shutdown is benign.

---

## sync.WaitGroup

**Where:** `runParallel` (`replayer.go:84`).

```go
var wg sync.WaitGroup
// ...
wg.Add(1)
go func() {
    defer wg.Done()
    // ...
}()
// ...
wg.Wait()
```

**Why `wg.Add(1)` before `go`:**

If `wg.Add` were called inside the goroutine, the dispatch loop could reach
`wg.Wait()` before any goroutine had a chance to call `Add`, causing `Wait`
to return immediately. Calling `Add` in the parent before launching the
goroutine establishes a happens-before relationship that prevents this.

**Why `defer wg.Done()`:**

Using `defer` guarantees `Done` is called even if `replaySession` panics.
Without it, a panic would leave the WaitGroup counter permanently above zero
and `Wait` would block forever, leaking the dispatch goroutine. With `defer`,
the panic still propagates up the stack but the counter is decremented first.

---

## Context cancellation

**Where:** `Run`, `runSequential`, `runParallel`, `runBurst`, `replaySession`
in `replay/replayer.go`; `signal.NotifyContext` in `cmd/tgen/run.go`.

**Pattern — polling:**

```go
if ctx.Err() != nil {
    return ctx.Err()
}
```

Used at the top of each session loop iteration. Cheap (one atomic load inside
the context implementation) and sufficient for coarse-grained cancellation
between sessions.

**Pattern — reactive (inside replaySession):**

```go
select {
case <-ctx.Done():
    return ctx.Err()
case <-time.After(wait):
}
```

Used during inter-packet sleep. This is the only place the code blocks for a
non-trivial duration. Without the `ctx.Done()` arm, a Ctrl-C signal would have
to wait up to `wait` (which can be up to 1 hour at very low speeds) before the
goroutine noticed cancellation.

**Signal wiring:**

```go
ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer cancel()
```

`signal.NotifyContext` is the idiomatic way since Go 1.16 to convert OS
signals into context cancellation. When SIGINT or SIGTERM arrives, the context
is cancelled, which propagates through every `ctx.Done()` check in the replay
engine. `defer cancel()` ensures the signal notification goroutine inside the
standard library is stopped when main exits, preventing a goroutine leak.

---

## Labeled break — exiting a for from inside a select

**Where:** `runParallel` (`replayer.go:86-90`).

```go
loop:
for _, s := range sessions {
    s := s
    select {
    case <-ctx.Done():
        break loop   // exits the for loop, not just the select
    case sem <- struct{}{}:
    }
    // ...
}
```

**The bug that was fixed:**

`break` inside a `select` statement breaks out of the `select`, not the
enclosing `for`. Without the label, a cancelled context would break out of the
`select` and immediately continue with the next `for` iteration, launching more
goroutines indefinitely. The result is a goroutine leak: the loop never exits,
goroutines pile up, and the semaphore never drains.

**Why `break loop` and not `return`:**

After the dispatch loop, `wg.Wait()` must run so that already-started
goroutines can finish cleanly. A `return` from inside the loop would skip
`wg.Wait()`, leaking those goroutines. `break loop` exits only the dispatch
loop, then falls through to `wg.Wait()`, which gives running goroutines a
chance to observe `ctx.Done()` on their own and return.

---

## Loop variable capture (s := s)

**Where:** `runParallel` (`replayer.go:88`).

```go
for _, s := range sessions {
    s := s   // new variable scoped to this iteration
    // ...
    go func() {
        replaySession(ctx, s)  // captures the inner s
    }()
}
```

**The bug this prevents:**

Before Go 1.22, a `for` loop reuses a single variable for each iteration. If
goroutines captured the outer `s` by reference, they would all see the value
of `s` at whatever point they happened to execute — almost certainly the last
value in the slice. With `s := s`, each iteration creates a new variable,
making the closure capture a distinct copy.

**Go 1.22 note:**

Go 1.22 changed the language specification so that each loop iteration gets its
own variable, making `s := s` unnecessary going forward. The code keeps it
explicitly because this project targets Go 1.22+ (`go.mod`) and the extra line
makes the intent obvious to readers who are not aware of the 1.22 change.

---

## sync.Mutex — plan cache and RNG

**Where:** `mutation/mutator.go`.

```go
type Mutator struct {
    mu    sync.Mutex
    cache map[session.Key]Plan
    rng   *rand.Rand
}

func (m *Mutator) PlanFor(sess *session.Session) Plan {
    m.mu.Lock()
    defer m.mu.Unlock()
    if p, ok := m.cache[key]; ok {
        return p
    }
    p := m.buildPlan(sess)
    m.cache[key] = p
    return p
}
```

**Why one lock covers both `cache` and `rng`:**

`buildPlan` reads from `m.rng` to pick a random IP from a pool. `rng` is a
`*rand.Rand` which is not goroutine-safe. If `rng` had its own lock, a call
to `buildPlan` would need to hold two locks — introducing potential for lock
ordering bugs and making the locking visible at two call sites. Since
`buildPlan` is called exclusively from `PlanFor` while `mu` is held, `rng`
gets `mu`'s protection for free. The comment in the source makes this
invariant explicit for future maintainers.

**Why not `sync.RWMutex`:**

A read-write mutex would let concurrent goroutines read a cached plan without
blocking each other. But the write path (cache miss → `buildPlan`) is short
and infrequent: it runs only once per unique session key. In parallel mode with
N workers, there are at most N concurrent cache misses total across the entire
run. The overhead of a `RWMutex` (heavier CAS operations on the reader count)
would cost more than it saves for this access pattern.

**Why not a `sync.Map`:**

`sync.Map` is optimised for two specific patterns: many readers/few writers, or
keys that are written once and only read thereafter. The plan cache is
write-once-read-many per key, which fits the second pattern. However:

1. `sync.Map` uses `interface{}` (now `any`) values, requiring a type assertion
   on every read, adding cognitive overhead.
2. The associated RNG also needs serialisation. A single `sync.Mutex` handling
   both cache and RNG is simpler.
3. Profile before optimising: benchmarks show `~2 M pkt/s` throughput, meaning
   the mutex is not a bottleneck.

---

## sync/atomic — lock-free metrics counters

**Where:** `metrics/metrics.go`.

```go
type Counters struct {
    PacketsSent  atomic.Int64
    BytesSent    atomic.Int64
    Errors       atomic.Int64
    SessionsDone atomic.Int64
    EmptyPackets atomic.Int64
}
```

**Why atomic instead of a mutex:**

Metrics counters are updated on the hot path — `PacketsSent.Add(1)` and
`BytesSent.Add(int64(len(data)))` are called once per packet. At 2 M pkt/s,
that is 4 M atomic operations per second. A `sync.Mutex` adds serialisation
that would be measurable at that rate; an atomic add on modern hardware
(via `LOCK XADD`) costs ~5 ns compared to ~100 ns for an uncontended mutex
round-trip.

**Why `atomic.Int64` (Go 1.19+) and not `sync/atomic.AddInt64`:**

`atomic.Int64` is a struct with methods (`Add`, `Load`, `Store`, `Swap`,
`CompareAndSwap`). It prevents misuse (the value cannot accidentally be passed
by value and lose alignment) and is more readable at call sites. The older
`sync/atomic.AddInt64(&c.PacketsSent, 1)` requires a pointer, making it easy
to accidentally dereference a copy.

**Why no mutex over the whole Snapshot read:**

`Snapshot()` reads five counters with five separate `Load()` calls. There is no
single atomic transaction over all five — the counts might reflect slightly
different instants. This is intentional: the metrics report is a best-effort
approximation for operational visibility, not a transactionally consistent
record. Introducing a mutex across all five reads would serialise every
`sendPacket` call against every `report()` call.

---

## Interfaces as testability seams

**Where:** `internal/sender/sender.go`.

```go
type Interface interface {
    Send(data []byte) error
    Close()
}
```

**Why an interface for a single implementation:**

The real `Sender` opens a live `pcap` handle, which requires root privileges
and a physical network interface. Tests cannot use the real sender without OS
resources. By accepting `sender.Interface` throughout the replay engine, tests
substitute a `mockSender` that records the packets it "sends" in a slice.

This pattern is tested in `replay/replayer_test.go`:

```go
type mockSender struct {
    mu   sync.Mutex
    sent [][]byte
}
func (m *mockSender) Send(data []byte) error { ... }
func (m *mockSender) Close() {}
```

The mock is thread-safe (its own `sync.Mutex`) because `runParallel` calls
`Send` from multiple goroutines simultaneously.

**Go interface satisfaction:**

Go interfaces are satisfied implicitly — `*Sender` satisfies `Interface` at
compile time without declaring `implements`. This means any future sender
(e.g., a raw socket implementation, a no-op null sender, a recording sender
for integration tests) just needs to implement two methods and drops in without
changing any other code.

---

## gopacket.NoCopy — zero-allocation parsing and its pitfalls

**Where:** `session/extractor.go:29`.

```go
pkt := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
```

**What it does:**

`gopacket.NoCopy` tells gopacket to decode layers in-place from the `data`
slice rather than copying it first. This eliminates an allocation per packet
during the session extraction phase, which processes every frame in the PCAP.

**The pitfall:**

`pcap.ReadPacketData()` returns a slice backed by a single read buffer that the
pcap library reuses on the next call. After `Feed` returns, the buffer is
overwritten. Any field decoded with `NoCopy` that is stored beyond the call
lifetime will point into garbage.

**The fix — explicit copies at retention points:**

```go
SrcIP: append(net.IP(nil), srcIP...),   // copy
DstIP: append(net.IP(nil), dstIP...),   // copy
// ...
Data: append([]byte(nil), data...),      // copy
```

`append(T(nil), src...)` is the idiomatic Go way to copy a slice: it allocates
a fresh backing array exactly the size needed and copies the bytes. The result
has no aliasing to the original buffer.

**Why not just use `gopacket.Default`:**

`gopacket.Default` copies the input unconditionally, which is safe but wastes
memory: the full frame is copied even for fields we discard (L2 headers, IP
options, ICMP bodies). With `NoCopy` we copy only the three fields we retain
(`SrcIP`, `DstIP`, `Packet.Data`). For a 1000-packet PCAP this is a
measurable reduction in GC pressure.

---

## Canonical map key for bidirectional flows

**Where:** `session/session.go`, `session/extractor.go`.

```go
type Key struct {
    SrcIP   string
    DstIP   string
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}

func canonical(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8) Key {
    a := fmt.Sprintf("%s:%d", srcIP, srcPort)
    b := fmt.Sprintf("%s:%d", dstIP, dstPort)
    if a <= b {
        return Key{srcIP, dstIP, srcPort, dstPort, proto}
    }
    return Key{dstIP, srcIP, dstPort, srcPort, proto}
}
```

**Why string fields in the Key:**

Go maps require that key types are comparable (support `==`). `net.IP` is a
`[]byte`, which is not comparable. Converting to `string` (which is
comparable) at ingestion time avoids a custom hash function or wrapping in an
array. The string conversion happens once per packet at `Feed` time; after
that, all lookups are `O(1)` map reads.

**Why canonical ordering:**

A TCP connection sends packets in both directions. Without canonicalisation,
the packet from `A→B` would create `Key{A, B, portA, portB}` and the return
packet from `B→A` would create `Key{B, A, portB, portA}` — two different keys
for the same flow. Sorting endpoints lexicographically ensures both directions
map to the same key and thus the same `Session`.

**The ordering rule:**

The smaller of `"srcIP:srcPort"` and `"dstIP:dstPort"` (string comparison)
goes first. This is a stable total order — it produces the same key regardless
of which direction a packet was captured from.

---

## time.Duration arithmetic and overflow protection

**Where:** `replay/replayer.go:151-158`.

```go
capOffset = time.Duration(float64(capOffset) / r.cfg.Speed)
if capOffset > time.Hour {
    capOffset = time.Hour
}
```

**The problem:**

`time.Duration` is `int64` nanoseconds. Its maximum value is about 292 years.
A PCAP containing a 10-second gap between packets, replayed at `--speed
0.0001`, produces a desired wall delay of `10s / 0.0001 = 100,000 seconds
≈ 27.7 hours`. `time.Duration(float64(time.Duration(27*time.Hour)))` overflows
`int64` and wraps to a negative value. `time.After` with a negative duration
fires immediately, and `time.NewTimer` with a negative duration panics in
some versions.

**The fix:**

Cap at `time.Hour` before using the duration. One hour is already far beyond
any realistic inter-packet gap; replaying with a gap longer than an hour is
functionally indistinguishable from having no gap at all (the next packet
arrives "eventually").

**Why float64 division:**

`time.Duration` is an integer. Integer division `capOffset / speed` is
impossible because `speed` is `float64`. Converting `capOffset` to `float64`,
dividing, and converting back loses at most 1 ns of precision — well within
acceptable limits for network traffic replay.

---

## io.Writer abstraction for metrics output

**Where:** `metrics/metrics.go`.

```go
type Collector struct {
    out io.Writer
    // ...
}

func New(interval time.Duration, output string) (*Collector, error) {
    var out io.Writer = os.Stdout
    switch output {
    case "stderr":
        out = os.Stderr
    default:
        f, err := os.OpenFile(output, ...)
        out = f
    }
    // ...
}
```

**Why `io.Writer`:**

`fmt.Fprintf(c.out, ...)` works identically whether `out` is `os.Stdout`,
`os.Stderr`, or an `*os.File`. The type switch happens once at construction
time; every subsequent `report()` call pays no extra cost.

This also makes `Collector` testable: pass a `*bytes.Buffer` as `out` and
inspect the formatted strings in tests without touching the filesystem.

---

## Error wrapping with %w

**Where:** throughout the codebase.

```go
return nil, fmt.Errorf("open pcap %s: %w", path, err)
return nil, fmt.Errorf("mutator: %w", err)
```

**Why `%w` and not `%v`:**

`%w` wraps the original error so callers can use `errors.Is` and `errors.As`
to inspect the error chain without string parsing. For example, a caller can
check `errors.Is(err, os.ErrNotExist)` to detect a missing PCAP file and give
a specific user message. `%v` would format the error message identically but
lose the type information needed for programmatic inspection.

**Error propagation pattern:**

Errors are wrapped with context at each layer boundary:

```
"config: filter: min_duration "abc": time: invalid duration "abc""
```

Each wrapping adds the subsystem name so the user immediately knows which
config field caused the problem. This is a standard Go convention: add context
at every `return nil, err` that crosses a package boundary.

---

## sync.Pool — why it was not used and how it could be

### What sync.Pool does

`sync.Pool` is a thread-safe free list. Objects `Put` into the pool are
available for reuse by `Get`, reducing allocations and GC pressure. The Go
runtime may evict pool entries at any GC cycle.

### Where it could theoretically apply in tgen

The two hot-path allocations are:

1. **`gopacket.SerializeBuffer`** — allocated once per `Apply` call, used to
   hold the re-serialised packet bytes.
2. **Packet byte slices** — `append([]byte(nil), data...)` in `extractor.Feed`
   and the output of `mutation.Apply`.

A pool for `SerializeBuffer` would look like:

```go
var bufPool = sync.Pool{
    New: func() any { return gopacket.NewSerializeBuffer() },
}

func Apply(rawData []byte, plan Plan, linkType layers.LinkType) ([]byte, error) {
    buf := bufPool.Get().(*gopacket.SerializeBuffer)
    defer bufPool.Put(buf)
    buf.Clear()
    // ... SerializeLayers(buf, ...) ...
    result := make([]byte, len(buf.Bytes())) // still need a copy here
    copy(result, buf.Bytes())
    return result, nil
}
```

### Why sync.Pool was not used

**Problem 1 — the returned slice would still need a copy.**

`buf.Bytes()` returns a slice backed by the pool object's internal buffer.
Returning that slice directly would be a use-after-free: the caller holds the
slice, but the pool can reclaim `buf` the moment `Put` is called. The fix is
to copy `buf.Bytes()` into a fresh slice before returning — which is exactly
what `gopacket.SerializeLayers` already does when you don't supply a reuse
buffer. Net gain: zero.

**Problem 2 — GC eviction.**

The Go specification says the GC may clear a Pool at any collection cycle.
In burst mode at 2 M pkt/s, a GC cycle during replay will evict all pooled
buffers and every subsequent `Get` allocates again — defeating the point of
the pool. Under sustained load, GC frequency increases precisely when pool
reuse would help most.

**Problem 3 — the bottleneck is not allocation.**

Benchmarks show `~2.1 M pkt/s` for `BenchmarkApplyFullMutation` with
`b.ReportAllocs()` active. The allocation path is not the bottleneck; packet
serialisation (gopacket decoding + re-encoding) and the libpcap write syscall
dominate. Adding a Pool would add code complexity and a non-obvious invariant
(the caller must not hold the buffer after it is put back) without a
measurable throughput improvement.

**Problem 4 — concurrent access in parallel mode.**

In `runParallel`, multiple goroutines call `Apply` simultaneously. `sync.Pool`
is goroutine-safe (that is its entire value proposition), but each goroutine's
`Get`/`Put` pair needs the caller to guarantee no two goroutines share a buffer
simultaneously. With a simple per-call borrow-and-return pattern this is safe,
but the code becomes harder to audit: a reviewer must verify that no code path
returns from `Apply` without calling `Put` (including error paths), or the pool
grows without bound.

### When sync.Pool would make sense

If the profiler showed allocations in `Apply` consuming significant GC time, and
`Apply` could return the buffer ownership to the caller (who would then `Put`
it back), pooling would reduce GC pause times at the cost of a more complex API.
This would require changing the `Apply` signature to:

```go
func Apply(rawData []byte, plan Plan, linkType layers.LinkType, dst []byte) ([]byte, error)
```

Where `dst` is a caller-supplied buffer (possibly from a pool), and the
returned `[]byte` is a subslice of `dst`. This is how `io.Reader` works. At
2 M pkt/s the investment is not justified; if throughput requirements scaled
to 100 M pkt/s it would be.

---

## Overall concurrency safety summary

| Shared resource | Access pattern | Protection mechanism |
|-----------------|---------------|---------------------|
| `Mutator.cache` (map) | read/write from multiple goroutines | `sync.Mutex` (`mu`) |
| `Mutator.rng` (*rand.Rand) | called only from `buildPlan` | protected by same `mu` (invariant in comment) |
| `Counters.PacketsSent/BytesSent/…` | incremented from multiple goroutines | `atomic.Int64` |
| `mockSender.sent` (tests only) | appended from multiple goroutines in parallel tests | `sync.Mutex` inside mock |
| `Replayer.sender` (libpcap handle) | called from multiple goroutines in parallel mode | libpcap's `pcap_inject` is documented as thread-safe |
| `Collector.prev` (Snapshot) | read and written by the metrics goroutine only | single goroutine — no synchronisation needed |
| Session slice (read-only after construction) | iterated by all replay modes | immutable after `ReadSessions` returns — no lock needed |

**What is not protected and why it does not need to be:**

- `Replayer.cfg` — set once at construction, never modified. Read-only
  concurrent access is safe in Go.
- `Session.Packets` — populated by `ReadSessions` before any goroutine is
  started. After the handoff to `Run`, only reads occur.
- `mutation.Plan` — a value type (struct), copied when passed to `sendPacket`.
  No aliasing is possible.

**The race detector:**

All tests in the test suite are designed to be run with `go test -race ./...`.
The mock sender uses its own mutex, parallel test helpers use `wg.Wait()` for
synchronisation, and the `Mutator` is exercised from concurrent goroutines in
benchmark mode — all of which the race detector can observe. The absence of
race detector warnings is part of the correctness proof for the implementation.
