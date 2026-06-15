# tgen — Architecture Diagrams

All diagrams are standalone SVG files (viewBox 1200×675, white background). Open them in any browser or SVG viewer. No external dependencies.

---

## Diagrams

| File | Title | What it shows |
|------|-------|---------------|
| [data_flow.svg](data_flow.svg) | Data Flow | Full pipeline from PCAP file(s) to NIC wire — session reconstruction, mutation, replay, and metrics |
| [mutation_pipeline.svg](mutation_pipeline.svg) | Mutation Pipeline | Step-by-step internals of `mutation.Apply()` — guards, L2/L3/L4 field rewrites, checksum recomputation |
| [replay_modes.svg](replay_modes.svg) | Replay Modes | Timeline comparison of all four replay modes: sequential, parallel, burst, and pcap |
| [session_consistency.svg](session_consistency.svg) | Session Consistency | Mutation plan cache lifecycle — cache miss, cache hit, and `--ip-pool-per-iter` reset |
| [sender_architecture.svg](sender_architecture.svg) | Sender Architecture | `sender.Interface` hierarchy — `*Sender`, `*PoolSender`, `*RawSender`, and how `buildSender` selects them |
| [scalability.svg](scalability.svg) | Scalability | Throughput scaling from single libpcap NIC to multi-NIC pool and multi-machine deployment |

---

## Quick reference

**Where to start:** `data_flow.svg` gives the full picture. The other diagrams zoom in on specific subsystems.

**For performance tuning:** `scalability.svg` and `replay_modes.svg`.

**For mutation behaviour:** `mutation_pipeline.svg` and `session_consistency.svg`.

**For multi-NIC / custom sender:** `sender_architecture.svg`.

---

## Color scheme (consistent across all diagrams)

| Color | Meaning |
|-------|---------|
| Purple `#7c3aed` | Input / external sources (PCAP files, CLI) |
| Blue `#1d4ed8` | Processing stages |
| Dark blue `#1e3a8a` | Main engine (Replay Engine) |
| Amber `#b45309` | Cache / state (Mutator, plan cache) |
| Teal `#0f766e` | Interfaces / abstractions |
| Green `#166534` | Output (NIC, result) |
| Red `#b91c1c` | Guards / error paths |
| Gray `#374151` | Metrics / system components |
| Gray `#4b5563` | Config / CLI |
