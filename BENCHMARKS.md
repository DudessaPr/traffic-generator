# tgen — Benchmark Guide

## How to run

```bash
# All benchmarks, 3-second window, with allocation reporting
make bench

# Specific package only
go test -run='^$' -bench=. -benchmem -benchtime=3s ./internal/replay/

# One benchmark by name pattern
go test -run='^$' -bench=BenchmarkPreMutation -benchtime=5s ./internal/replay/

# With CPU profiling
go test -run='^$' -bench=BenchmarkBurst -benchtime=3s -cpuprofile=cpu.prof ./internal/replay/
go tool pprof cpu.prof
```

---

## Benchmarks reference

### `internal/mutation`

| Benchmark | What it measures |
|-----------|-----------------|
| `BenchmarkApplyFullMutation` | Per-packet cost of rewriting all L3+L4 fields and recomputing checksums |
| `BenchmarkApplyNoMutation` | Pass-through baseline (no fields changed); same gopacket parse+serialise cost |
| `BenchmarkApply` | Realistic client→server TCP packet with all mutable fields rewritten |

### `internal/replay`

| Benchmark | What it measures |
|-----------|-----------------|
| `BenchmarkSequential` | Sequential mode at Speed=0; per-packet mutation + discard send |
| `BenchmarkParallel` (8 workers) | Parallel mode concurrency benefit vs sequential |
| `BenchmarkBurst` | Burst mode; no timing delays, pure mutation+send throughput |
| `BenchmarkBurstReplay` | Mutation + serialisation (10 sessions × 100 pkts) |
| `BenchmarkRateLimiter` | Token-bucket check overhead on the hot path at 1 Mpps (never blocks) |
| `BenchmarkPreMutation/OnTheFly` | On-the-fly mutation (gopacket per packet) |
| `BenchmarkPreMutation/PreProcess` | Pre-mutated path (raw bytes copied, no gopacket in send loop) |
| `BenchmarkModePcap/Sequential` | Sequential mode baseline |
| `BenchmarkModePcap/Pcap` | Pcap-order mode: sort cost + merge overhead |
| `BenchmarkMultiInterface/interfaces=N` | PoolSender round-robin overhead for N mock handles |

---

## What each benchmark measures

### Mutation throughput (`BenchmarkApply*`)
Measures `mutation.Apply` in isolation: `gopacket.NewPacket` + field rewrites + `SerializeLayers`.
`FullMutation` vs `NoMutation` shows that the cost is dominated by parse/serialise, not field writes.

### Replay throughput (`BenchmarkSequential/Parallel/Burst`)
End-to-end pipeline: mutator plan lookup → `mutation.Apply` → mock sender.
No real NIC involved; measures the CPU-bound portion of the hot path.

### Rate limiter overhead (`BenchmarkRateLimiter`)
Measures the extra cost of a `rate.Limiter.Wait` call per packet on the fast path.
The rate is set to 1 Mpps so the limiter never actually blocks — this isolates
bookkeeping cost only. Compare against `BenchmarkBurst` for the overhead delta.

### Pre-mutation benefit (`BenchmarkPreMutation`)
`PreProcess=false` (on-the-fly): `mutation.Apply` called per packet in the send loop.
`PreProcess=true` (pre-processed): packets pre-mutated once; send loop copies raw bytes.
The pre-process path removes all `gopacket` work from the send hot path.
Expect a 1.5–2× throughput improvement on CPU-bound workloads.

### Pcap-order mode cost (`BenchmarkModePcap`)
Compares timestamp-sorted global replay vs session-by-session sequential.
`Pcap` has one-time `sort.Slice` overhead proportional to total packet count,
plus a pre-mutation pass over all packets. For N sessions × M packets, this is
O(N·M · log(N·M)) extra work before any packet is sent.

### Multi-interface pool (`BenchmarkMultiInterface`)
Measures round-robin atomic counter overhead in `PoolSender.Send`.
On current hardware the overhead is a single `atomic.Add` (~2 ns).
Scales near-linearly: use N interfaces to multiply effective injection bandwidth.

---

## How to interpret results

```
BenchmarkBurst-10    10000    105234 ns/op   1000 pkts/op   0 B/op   0 allocs/op
```

- **ns/op** — wall time per `Run` call (one full pass over all sessions)
- **pkts/op** — custom metric: total packets sent per `Run` call (via `b.ReportMetric`)
- **B/op / allocs/op** — heap pressure; 0 means the hot path is allocation-free

To get **packets per second**, divide `pkts/op` by `ns/op × 1e-9`:

```
1000 pkts / (105234 ns × 1e-9 s/ns) ≈ 9.5 M pkt/s
```

---

## Expected numbers on reference hardware (Apple M3 Pro)

| Benchmark | Throughput | Notes |
|-----------|------------|-------|
| `BenchmarkApplyFullMutation` | ~2.1 M pkt/s | All L3+L4 fields rewritten |
| `BenchmarkApplyNoMutation` | ~2.1 M pkt/s | Pass-through; same parse+serialise cost |
| `BenchmarkSequential` | ~1.9 M pkt/s | 100 sessions × 100 pkts, Speed=0 |
| `BenchmarkParallel` (8 workers) | ~4.3 M pkt/s | ~2.2× speedup over sequential |
| `BenchmarkBurst` | ~2.1 M pkt/s | 100 sessions × 100 pkts |
| `BenchmarkRateLimiter` | ~2.0 M pkt/s | ~5% overhead vs no-limiter burst |
| `BenchmarkPreMutation/OnTheFly` | ~2.1 M pkt/s | baseline |
| `BenchmarkPreMutation/PreProcess` | ~3.8 M pkt/s | ~1.8× faster; no gopacket on hot path |
| `BenchmarkModePcap/Sequential` | ~1.9 M pkt/s | baseline |
| `BenchmarkModePcap/Pcap` | ~1.5 M pkt/s | ~20% overhead from sort + pre-mutation |

> Numbers are indicative. Re-run on your hardware with `-benchtime=10s` for stable results.
> Use `-count=5` and `benchstat` to compute variance across runs.

---

## Profiling tips

```bash
# CPU profile — find the hot function
go test -run='^$' -bench=BenchmarkBurst -benchtime=10s \
  -cpuprofile=cpu.prof ./internal/replay/
go tool pprof -http=:6060 cpu.prof

# Memory profile — find allocation sources
go test -run='^$' -bench=BenchmarkBurst -benchtime=10s \
  -memprofile=mem.prof ./internal/replay/
go tool pprof -http=:6060 mem.prof

# Compare before/after with benchstat
go test -run='^$' -bench=. -benchtime=5s -count=5 ./internal/replay/ > before.txt
# make your change
go test -run='^$' -bench=. -benchtime=5s -count=5 ./internal/replay/ > after.txt
benchstat before.txt after.txt
```
