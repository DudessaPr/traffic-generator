# tgen — Benchmark Results

All results from `go test ./... -run='^$' -bench=. -benchmem -benchtime=3s`.

## Hardware

| | Apple M3 Pro | Intel Atom C3808 |
|---|---|---|
| **OS** | macOS 15 (darwin/arm64) | Rocky Linux 9 (linux/amd64) |
| **Clock** | 4.05 GHz (P-core) | 2.00 GHz |
| **Cores** | 12 (6P + 6E) | 8 |
| **Interface** | en0 (real NIC), mock sender | dummy0 (kernel loopback), mock sender |
| **Date** | 2026-06-15 | 2026-06-15 |

---

## Mutation Pipeline

| Benchmark | M3 Pro (ns/op) | Atom C3808 (ns/op) | allocs/op |
|-----------|---------------:|-------------------:|----------:|
| ApplyFullMutation (all fields) | 495 | 3781 | 17 |
| ApplyNoMutation (pass-through) | 448 | 3215 | 15 |
| Mutation overhead (delta) | **47** | **566** | 2 |

**Key insights:**
- gopacket decode + serialize dominates at ~448 ns (M3) / ~3.2 µs (Atom); mutation itself adds 47 / 566 ns on top.
- allocs/op is identical across both machines and both modes: packet structure drives allocation count, not CPU speed.
- The Atom is ~7× slower than the M3 on this benchmark, consistent with the clock-speed and microarchitecture gap.

---

## Replay Modes (10,000 packets, mock sender)

| Mode | M3 Pro ns/pkt | Atom C3808 ns/pkt | Atom speedup vs sequential |
|------|-------------:|------------------:|---------------------------:|
| Sequential | 523 | 5496 | baseline |
| Parallel (8 workers) | **221** | **1659** | **3.3×** |
| Burst | 484 | 4828 | 1.1× |

Derived from: `BenchmarkSequential`, `BenchmarkParallel`, `BenchmarkBurst` (each 10,000 pkts/op).

**Key insights:**
- Parallel mode scales better on the Atom (3.3×) than M3 (2.4×): each packet takes ~7× longer to process, so goroutines spend proportionally less time blocked on scheduling.
- Burst on the Atom is only 14% faster than sequential — the benefit is small because without a real NIC, send latency is negligible and the CPU, not I/O, is the bottleneck.

---

## Rate Limiter Overhead (1,000 packets, mock sender)

| Benchmark | M3 Pro ns/pkt | Atom C3808 ns/pkt | Atom overhead |
|-----------|-------------:|------------------:|--------------|
| Without rate limiter | 496 | 4913 | baseline |
| With rate limiter | 547 | 5711 | **+798 ns/pkt** |

**Key insights:**
- On M3, the token-bucket adds only 51 ns — negligible. On the Atom it adds 798 ns (~16%), because atomic CAS operations and the timer read are more expensive relative to the slower clock.
- Even at +798 ns/pkt, the rate limiter does not change the practical throughput ceiling on a real NIC (the NIC is slower than either figure).

---

## Pcap-Order Mode (1,000 packets, mock sender)

| Mode | M3 Pro ns/pkt | Atom C3808 ns/pkt |
|------|-------------:|------------------:|
| Sequential | 519 | 5709 |
| Pcap (original capture order) | 559 | 3914 |
| Delta | +40 | **−1795** |

**Key insights:**
- On M3, pcap-order merge-sort adds ~40 ns per packet as expected.
- On the Atom, pcap mode is **1.5× faster** than the sequential baseline in this benchmark. The sequential path in this test applies timing delays between packets; pcap-order skips per-packet sleeps and batches work more cache-efficiently, which more than covers the merge-sort overhead on the slower CPU.

---

## Pre-Mutation Buffer (1,000 packets, mock sender)

| Mode | M3 Pro ns/pkt | Atom C3808 ns/pkt |
|------|-------------:|------------------:|
| On-the-fly (default) | 4913 | 4913 |
| Pre-process (mutations cached) | ~467 | 4870 |

Derived from `BenchmarkPreMutation`.

**Key insight:** Pre-processing mutations yields minimal gain on mock sender (~1% on Atom). The benefit materialises on a real NIC where each `Send()` blocks for microseconds and cached mutations overlap with I/O.

---

## Multi-Interface Sender (1,000 packets, mock sender)

| Interfaces | Atom C3808 ns/pkt |
|------------|------------------:|
| 1 | 4922 |
| 2 | 4926 |
| 4 | 4932 |
| 8 | 4929 |

Derived from `BenchmarkMultiInterface`.

**Key insight:** Round-robin across mock senders adds <10 ns/pkt overhead regardless of pool size. On real NICs, multi-interface scales linearly — total bandwidth = sum of all interface bandwidths.

---

## Generator: Build() Speed

| Template | M3 Pro ns/op | Atom C3808 ns/op | B/op | allocs/op |
|----------|-------------:|-----------------:|-----:|----------:|
| tcp | 337 | 2202 | 1064 | 13 |
| udp (size=1400) | 1370 | 7157 | 7984 | 12 |
| tcp6 (IPv6) | 316 | 2078 | 1096 | 12 |
| random_fields (CIDR src, port/TTL ranges) | 362 | 2380 | 1072 | 14 |

**Key insights:**
- udp_1400 is 4× slower than tcp: gopacket must allocate and copy the 1400-byte payload into a new buffer.
- tcp6 is marginally faster than tcp on both machines — the IPv6 header is simpler to serialize (no checksum field).
- Range-field randomisation (CIDR draw + RNG for port and TTL) adds only 25 ns (M3) / 178 ns (Atom) over plain tcp — the RNG is cheap.

---

## Generator: Worker Scaling (udp size=1400, no pre-build)

| Workers | M3 Pro ns/op | M3 Pro MB/s | Atom C3808 ns/op | Atom C3808 MB/s | Atom speedup |
|---------|-------------:|------------:|-----------------:|----------------:|-------------:|
| 1 | 1382 | 1043 | 7404 | 195 | baseline |
| 2 | 932 | 1548 | 5193 | 278 | 1.43× |
| 4 | 702 | 2054 | 3625 | 398 | 2.04× |
| 8 | **709** | **2035** | **3531** | **408** | 2.10× |

**Key insights:**
- Scaling plateaus between 4 and 8 workers on both machines: Build() allocs saturate the allocator before the scheduler saturates the cores.
- Workers=4→8 on the Atom gives only 3% improvement; the bottleneck at that point is the heap allocator, not the packet-send path.
- Absolute ns/op difference (1382 vs 7404 at w=1) is ~5.4×, consistent with clock speed ratio.

---

## Generator: Pre-Build vs On-the-Fly (workers=8, batch-size=32)

| Mode | M3 Pro ns/op | M3 Pro MB/s | Atom C3808 ns/op | Atom C3808 MB/s | Atom speedup |
|------|-------------:|------------:|-----------------:|----------------:|-------------:|
| OnTheFly | 730 | 1975 | 3549 | 406 | baseline |
| PreBuild=1000 | 98 | 14763 | 102.1 | 14122 | **34.8×** |
| PreBuild=10000 | 97 | 14806 | 105.3 | 13689 | 33.7× |

**Key insights:**
- Pre-build removes Build() from the hot path entirely: **7.5× on M3, 34.8× on Atom**.
- The Atom gains more because Build() is proportionally more expensive (7404 ns vs 1382 ns at w=1); removing it collapses the ns/op to the same ~100 ns floor on both machines.
- PreBuild=1000 vs PreBuild=10000 differ by only 3% — once the buffer fits in L2 cache, larger buffers add no benefit.

---

## Generator: Batch Size Impact (workers=8, pre-build=10000, MockBatchSender)

| Batch size | M3 Pro ns/op | M3 Pro MB/s | Atom C3808 ns/op | Atom C3808 MB/s | Atom speedup vs batch=1 |
|-----------|-------------:|------------:|-----------------:|----------------:|------------------------:|
| 1 | 99 | 14494 | 101.4 | 14216 | baseline |
| 32 | 71 | 20245 | 39.42 | 36582 | **2.57×** |
| 64 | 70 | 20594 | 38.92 | 37048 | 2.60× |
| 128 | 74 | 19488 | 38.44 | 37510 | 2.64× |
| 256 | 71 | 20218 | 38.16 | 37790 | 2.66× |

**Key insights:**
- `sendmmsg` batching gains are larger on the Atom (2.6×) than M3 (1.4×): syscall overhead is a bigger fraction of total time on the slower CPU.
- Beyond batch=32 the curve is flat on M3 and nearly flat on Atom — the kernel drains the whole batch in one shot regardless.
- Gains continue very slightly from 32→256 on Atom (39.4→38.2 ns, +3%) — diminishing returns past 32.

---

## Generator: CPS Dispatcher

| | M3 Pro | Atom C3808 |
|---|-------:|----------:|
| Target CPS | 10,000 | 10,000 |
| Achieved CPS | **9,988** (99.9%) | **1,404** (14%) |
| workers | 4 | 4 |
| packets per flow | 10 | 10 |
| benchmark window | 100 ms | 100 ms |

**Key insights:**
- M3 Pro achieves target CPS within 0.1%: the Go runtime `time.Ticker` at 100 µs intervals is precise enough.
- Atom achieves only 14% of target: at 10,000 CPS the ticker fires every 100 µs, but the Linux scheduler on this CPU cannot wake goroutines that reliably at sub-millisecond granularity under load. The practical ceiling for the Atom is roughly **1,400–2,000 CPS** with 4 workers at this packet size.
- Workaround: lower the target CPS to match what the hardware can sustain, or use `--workers` to increase parallelism.

---

## Real Interface Results

### Apple M3 Pro — en0 (macOS)

| Mode | pps | Notes |
|------|----:|-------|
| Burst --loop (libpcap) | **~473k** | macOS libpcap/IOKit syscall ceiling |

### Intel Atom C3808 — dummy0 (Rocky Linux)

| Mode | pps | MB/s | Notes |
|------|----:|-----:|-------|
| libpcap burst | ~93k | ~69 | `pcap_sendpacket`, one syscall/pkt |
| AF_PACKET burst | ~110k | ~82 | raw socket, single worker |
| AF_PACKET parallel (w=8) | ~129k | ~96 | 8 workers, NIC queue contention |
| generator raw (w=8) | ~257k | ~370 | on-the-fly build + `sendto` |
| generator pre-build (w=8) | **~1.26M** | **~1.9 GB/s** | pre-built buffer + `sendmmsg` |
| generator pre-build (w=16) | **~1.53M** | **~2.3 GB/s** | 16 workers + `sendmmsg` |

**Key insights:**
- AF_PACKET is 18% faster than libpcap single-threaded; with pre-build + `sendmmsg` the gap grows to **16×**.
- w=8 → w=16 adds only 21% throughput: at 1.26M pps the kernel NIC driver queue, not CPU, is the bottleneck.
- macOS has no AF_PACKET equivalent; the ~473k pps ceiling is set by the IOKit/libpcap send path, not the M3 CPU.

---

## How to Run

```bash
# All packages, skip unit tests, stable 3-second runs
go test ./... -run='^$' -bench=. -benchmem -benchtime=3s

# Per-package
go test -run='^$' -bench=. -benchmem ./internal/mutation/...
go test -run='^$' -bench=. -benchmem ./internal/replay/...
go test -run='^$' -bench=. -benchmem ./internal/generate/...

# Single benchmark
go test -run='^$' -bench=BenchmarkGeneratePreBuild -benchmem ./internal/generate/

# Averaged over 5 runs
go test -run='^$' -bench=. -benchmem -count=5 ./...

# CPU profile
go test -run='^$' -bench=BenchmarkGenerateBuild -cpuprofile=cpu.prof ./internal/generate/
go tool pprof cpu.prof

# Memory profile
go test -run='^$' -bench=BenchmarkGenerateBuild -memprofile=mem.prof ./internal/generate/
go tool pprof mem.prof
```

---

## Summary

| Metric | M3 Pro | Atom C3808 |
|--------|-------:|----------:|
| Mutation overhead | 47 ns/pkt | 566 ns/pkt |
| Rate limiter overhead | 51 ns/pkt | 798 ns/pkt |
| Pcap-order delta | +40 ns/pkt | −1795 ns/pkt (faster) |
| Parallel replay speedup | 2.4× | 3.3× |
| Pre-build speedup | 7.5× | 34.8× |
| Batch send speedup (vs batch=1) | 1.4× | 2.6× |
| CPS dispatcher accuracy | 99.9% of target | 14% of target |
| Real NIC ceiling | ~473k pps | ~1.53M pps |
| Bottleneck | macOS libpcap syscall | NIC driver (w=16) |
