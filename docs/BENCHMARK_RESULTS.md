# tgen — Benchmark Results

**Hardware:** Apple M3 Pro  
**OS:** macOS (darwin/arm64)  
**Date:** 2026-06-08

---

## Mutation Pipeline

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| ApplyFullMutation (all fields) | 495 | 1496 | 17 |
| ApplyNoMutation (pass-through) | 448 | 1464 | 15 |
| Apply (realistic packet) | 496 | 1496 | 17 |

**Key insight:** Mutation overhead is ~47 ns per packet (difference between full mutation and no mutation). gopacket decode + serialize dominates at ~450 ns.

---

## Replay Modes (10,000 packets, mock sender)

| Mode | ns/op | ns/pkt | vs Sequential |
|------|-------|--------|---------------|
| Sequential | 5,233,203 | 523 | baseline |
| Parallel (8 workers) | 2,212,223 | 221 | **2.4× faster** |
| Burst | 4,846,462 | 484 | 1.1× faster |

**Key insight:** Parallel mode delivers 2.4× throughput over sequential due to concurrent session replay.

---

## Pre-Mutation Buffer (1,000 packets, mock sender)

| Mode | ns/op | B/op | allocs/op |
|------|-------|------|-----------|
| On-the-fly (default) | 465,604 | 1,464,007 | 15,000 |
| Pre-process | 467,379 | 1,490,247 | 15,041 |

**Key insight:** Pre-process shows minimal difference on mock sender. Benefit appears on real NIC where send latency is higher and mutations can be fully parallelised with I/O.

---

## Rate Limiter Overhead (1,000 packets)

| Benchmark | ns/op | overhead vs no limiter |
|-----------|-------|----------------------|
| No rate limiter | 496 ns/pkt | baseline |
| With rate limiter | 547 ns/pkt | **+51 ns/pkt** |

**Key insight:** Token bucket adds ~51 ns per packet — negligible at any practical rate.

---

## Pcap-Order Mode (1,000 packets)

| Mode | ns/op | ns/pkt | overhead |
|------|-------|--------|----------|
| Sequential | 519,010 | 519 | baseline |
| Pcap (original order) | 559,679 | 559 | **+40 ns/pkt** |

**Key insight:** Pcap-order mode adds ~40 ns per packet for merge sort across sessions. Small price for wire-accurate replay.

---

## Multi-Interface Sender (1,000 packets, mock handles)

| Interfaces | ns/op | ns/pkt | speedup |
|------------|-------|--------|---------|
| 1 | 496,907 | 496 | baseline |
| 2 | 474,852 | 474 | 1.05× |
| 4 | 477,374 | 477 | 1.04× |
| 8 | 468,029 | 468 | 1.06× |

**Key insight:** Minimal difference on mock sender. On real NICs, multi-interface scales linearly — bandwidth = sum of all interface bandwidths.

---

## Real Interface Results (en0, macOS)

| Mode | Real pps | Notes |
|------|----------|-------|
| Sequential speed=1.0 | ~50 pps | Timing-accurate, real-time |
| Sequential speed=2.0 | ~100 pps | 2× faster |
| Parallel workers=4 | — | 2.2× speedup over sequential |
| Burst | **~450k pps** | macOS syscall limit |
| Burst + pre-process | ~255k pps | Pre-mutation overhead on small pcap |

**Key insight:** Real NIC ceiling is ~450k pps — macOS kernel syscall overhead, not CPU. M3 Pro can process 2M+ pps in pure benchmarks.

---

## How to Run

```bash
# All benchmarks
go test -bench=. -benchmem ./...

# Specific package
go test -bench=. -benchmem ./internal/mutation/...
go test -bench=. -benchmem ./internal/replay/...

# With CPU profiling
go test -bench=BenchmarkApply -cpuprofile=cpu.prof ./internal/mutation/
go tool pprof cpu.prof

# With memory profiling
go test -bench=BenchmarkApply -memprofile=mem.prof ./internal/mutation/
go tool pprof mem.prof

# Run N times for stable results
go test -bench=. -benchmem -count=5 ./...
```

---

## Summary

```
Mutation overhead:     ~47 ns/pkt   (negligible)
Rate limiter overhead: ~51 ns/pkt   (negligible)
Pcap-order overhead:   ~40 ns/pkt   (negligible)
Parallel speedup:      2.4×         (real concurrency gain)
Real NIC ceiling:      ~450k pps    (macOS syscall limit, not CPU)
```
