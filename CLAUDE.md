# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build (requires CGO / libpcap headers)
make build                        # → ./build/tgen
CGO_ENABLED=1 go build -o build/tgen ./cmd/tgen/

# Test
go test ./...                     # all tests
go test -race ./...               # with race detector (required before merging)
go test -run TestName ./internal/pkg/   # single test
go test -short ./...              # skip integration tests that need pcap files
make bench                        # all benchmarks

# Lint (golangci-lint v2)
make lint                         # golangci-lint run ./...

# Module hygiene
go mod tidy
```

## Architecture

Two top-level modes share most infrastructure:

- **`tgen run`** — PCAP replay with L3/L4 mutation  
- **`tgen generate`** — synthetic packet generation from a template string (no PCAP)

### Package responsibilities

| Package | Role |
|---------|------|
| `cmd/tgen/run.go` | Wires replay pipeline: `buildConfig` → `buildSender` → `pcap.ReadSessions` → `session.Filter.Apply` → `mutation.Mutator` → `replay.Replayer.Run` |
| `cmd/tgen/generate.go` | Wires generate pipeline: parses template → `netutil.Resolve` for gateway MAC → `generate.Generator.Run` |
| `internal/config` | All structs (`Config`, `ReplayConfig`, `MutationConfig`, …); `loader.go` YAML→struct; `validate.go` semantic checks |
| `internal/session` | `Key` 5-tuple (canonical: smaller endpoint first so both flow directions share one key); `Extractor` reconstructs flows from gopacket; `Filter` selects by duration/time/proto |
| `internal/pcap` | Thin gopacket wrapper: `ReadSessions` and `Inspect` |
| `internal/mutation` | `Mutator.PlanFor(session)` — cached per session key (double-checked `RWMutex`); `Apply(raw, plan, linkType)` rewrites L2/L3/L4 and recomputes checksums |
| `internal/sender` | `Interface` (`Send`/`Close`); optional `Batcher` (`SendBatch`). Three impls: `*Sender` (libpcap+mutex), `*PoolSender` (round-robin across N), `*RawSender` (Linux AF_PACKET + `sendmmsg`) |
| `internal/ratelimit` | `Limiter` (token bucket, PPS or BPS); `CPSLimiter` (per-connection token bucket); `ApplyMultiplier`; shared by both pipelines |
| `internal/replay` | `Replayer.Run` dispatches to `runSequential`/`runParallel`/`runBurst`/`runPcap`; all flow-metric accounting lives here |
| `internal/generate` | `Template` (parsed from colon-separated string); `Generator.Run` spawns N workers each with own `*rand.Rand` |
| `internal/metrics` | Atomic `Counters`; `Snapshot`; `Collector.Run` prints `[metrics]` line every interval |
| `internal/netutil` | `Resolve(targetIP)` → outbound interface + gateway MAC; platform-specific in `route_linux.go` / `route_darwin.go` |

### Sender hierarchy

```
sender.Interface  ←  *Sender (pcap, mutex)
                  ←  *PoolSender (round-robin, also implements Batcher)
                  ←  *RawSender (Linux AF_PACKET, sendmmsg batch)
```

`buildSender()` in `run.go` selects which to construct. `--sender raw` with multiple interfaces builds a `PoolSender` of `RawSender`s via `NewPoolFrom`. Callers type-assert to `Batcher`; its absence is not an error — fallback to sequential `Send`.

### Batch-send path

`runBurst` accumulates frames into a `[][]byte` buffer (capacity = `cfg.BatchSize`, default 32). Flush triggers: buffer full **or** session boundary. If sender is `Batcher` → `SendBatch`; otherwise → loop over `Send`. Generator uses the same logic when `PreBuild > 0`.

### Rate limiting

Two independent limiters both from `internal/ratelimit`:
- `Limiter` — per-packet token bucket (`--rate`); PPS mode uses 1 token/pkt, BPS uses N tokens/byte
- `CPSLimiter` — per-session token bucket (`--cps`); burst capped at `min(cps/10, 1000)` and immediately drained so limiting is immediate from session one

`--multiplier` scales both; `ApplyMultiplier` rewrites the rate string numerically.

### Template parser (`internal/generate/template.go`)

`splitTemplate` is a custom tokeniser that splits on `:` only when followed by an all-alpha key then `=`. This lets IPv6 addresses (`2001:db8::1`) survive the parse without extra quoting. `ParseTemplate` sets `isIPv6` from the protocol prefix (`tcp6`, `udp6`).

Range syntax for numeric fields (`field=min-max`) is parsed by `parsePortRange`; the same pattern applies to `ttl`, `dscp`, and ports.

### Metrics

`metrics.Counters` has three flow counters (all `atomic.Int64`):
- `FlowsStarted` — monotonically increasing; CPS = delta / interval
- `ActiveFlows` — incremented at session start, decremented at end (`defer`)
- `OpenFlows` — subset without FIN/RST; TCP decrements on FIN/RST detection; UDP/ICMP decrements at session end

All four replay paths (`replaySession`, `replayProcessed`, `runBurst`, `runPcap`) and each generator worker update these counters consistently.

### Platform split

`internal/sender/raw_linux.go` (`//go:build linux`) implements `sendmmsg` via `unix.Syscall6(unix.SYS_SENDMMSG, …)` using a local `mmsghdr` struct (not yet in `golang.org/x/sys/unix`). `raw_other.go` (`//go:build !linux`) is a stub. `internal/netutil/` similarly splits by platform.

## Key invariants

- **Canonical session key**: `session/extractor.go canonical()` stores the smaller endpoint first so both flow directions map to the same key and mutation plan.
- **Mutation plan cache**: built once per session key, reused for every packet in that flow. `ResetCache()` is called between loop iterations when `--ip-pool-per-iter` is set.
- **`StartAfter` filter is strict `>`**: a session starting exactly at the boundary is excluded (see `session/filter_test.go`).
- **CIDR pool cap**: default 256 hosts, max 65536 (`--ip-pool-limit`). Prevents OOM on `/8` prefixes.
- **IPv4 vs IPv6 safety**: mutation silently skips if plan IP family mismatches packet IP family.
