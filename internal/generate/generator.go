package generate

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"tgen/internal/metrics"
	"tgen/internal/ratelimit"
	"tgen/internal/sender"
)

// Config holds generate-command settings.
type Config struct {
	Rate       string  // e.g. "100kpps", "1gbps"; empty = unlimited
	Count      int64   // packets to send per worker cycle; 0 = run until ctx cancelled
	Loop       bool    // when Count > 0, restart after each cycle instead of stopping
	Workers    int     // goroutines to launch when CPS is not set (0 or 1 = single-threaded)
	PreBuild   int     // packets to pre-build per worker before the send loop (0 = disabled)
	CPS        float64 // new flows to start per second via ticker (0 = unlimited / workers model)
	Multiplier float64 // scales Rate and CPS; 0 or 1.0 = no change
	BatchSize  int     // frames per SendBatch call when pre-build > 0 (0=default 32, max 256)
}

// Generator builds and injects synthetic packets from a Template.
type Generator struct {
	tmpl   *Template
	snd    sender.Interface
	mc     *metrics.Collector
	cfg    Config
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
}

// New wires up a Generator. Returns an error only if cfg.Rate is syntactically invalid.
func New(cfg Config, tmpl *Template, snd sender.Interface, srcMAC, dstMAC net.HardwareAddr, mc *metrics.Collector) (*Generator, error) {
	if err := ratelimit.ParseRate(cfg.Rate); err != nil {
		return nil, err
	}
	return &Generator{
		tmpl:   tmpl,
		snd:    snd,
		mc:     mc,
		cfg:    cfg,
		srcMAC: srcMAC,
		dstMAC: dstMAC,
	}, nil
}

// Run generates packets until the count and loop policy are satisfied or ctx is cancelled.
//
// Two dispatch modes:
//   - CPS mode (cfg.CPS > 0 && cfg.Count > 0): a ticker fires at 1s/CPS intervals;
//     cfg.Workers goroutines drain the ticker channel, each executing one flow cycle
//     of cfg.Count packets.
//   - Workers mode (default): cfg.Workers goroutines each run indefinitely (or for
//     cfg.Count packets), respecting a CPSLimiter upper-bound if configured.
func (g *Generator) Run(ctx context.Context) error {
	m := g.cfg.Multiplier
	if m == 0 {
		m = 1.0
	}

	effectiveRate, err := ratelimit.ApplyMultiplier(g.cfg.Rate, m)
	if err != nil {
		return fmt.Errorf("rate multiplier: %w", err)
	}
	limiter, err := ratelimit.New(ctx, effectiveRate, "")
	if err != nil {
		return err
	}

	effectiveCPS := g.cfg.CPS * m

	baseNano := time.Now().UnixNano()

	// CPS-dispatcher mode: ticker-driven, fixed number of cps-workers.
	if effectiveCPS > 0 && g.cfg.Count > 0 {
		return g.runCPS(ctx, effectiveCPS, limiter, baseNano)
	}

	// Workers mode: existing behaviour with optional CPSLimiter upper-bound.
	cpsLimiter, err := ratelimit.NewCPS(ctx, effectiveCPS, "")
	if err != nil {
		return err
	}
	return g.runWorkers(ctx, limiter, cpsLimiter, baseNano)
}

// runCPS implements the ticker-based CPS dispatch model.
func (g *Generator) runCPS(ctx context.Context, effectiveCPS float64, limiter *ratelimit.Limiter, baseNano int64) error {
	dispatcher := ratelimit.NewCPSDispatcher(ctx, effectiveCPS)

	workers := g.cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	// Pre-build a shared read-only packet buffer (all workers cycle through it).
	var sharedBuf [][]byte
	if g.cfg.PreBuild > 0 {
		rng := rand.New(rand.NewSource(baseNano))
		sharedBuf = make([][]byte, g.cfg.PreBuild)
		for i := range sharedBuf {
			pkt, err := g.tmpl.Build(g.srcMAC, g.dstMAC, rng)
			if err != nil {
				return fmt.Errorf("pre-build packet %d: %w", i, err)
			}
			sharedBuf[i] = pkt
		}
	}

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		rng := rand.New(rand.NewSource(baseNano ^ int64(i+1)<<32))
		go func(rng *rand.Rand) {
			defer wg.Done()
			g.runCPSWorker(ctx, rng, sharedBuf, limiter, dispatcher)
		}(rng)
	}

	wg.Wait()
	return ctx.Err()
}

// runCPSWorker drains the CPS dispatcher channel, executing one flow cycle per tick.
func (g *Generator) runCPSWorker(ctx context.Context, rng *rand.Rand, sharedBuf [][]byte, limiter *ratelimit.Limiter, dispatcher *ratelimit.CPSDispatcher) {
	batcher, isBatcher := g.snd.(sender.Batcher)
	batchSize := g.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 32
	}

	var batchBuf [][]byte
	if isBatcher {
		batchBuf = make([][]byte, 0, batchSize)
	}

	flushBatch := func() {
		if len(batchBuf) == 0 {
			return
		}
		n, _ := batcher.SendBatch(batchBuf)
		for i := 0; i < n; i++ {
			g.mc.C.PacketsSent.Add(1)
			g.mc.C.BytesSent.Add(int64(len(batchBuf[i])))
		}
		if n < len(batchBuf) {
			g.mc.C.Errors.Add(int64(len(batchBuf) - n))
		}
		batchBuf = batchBuf[:0]
	}

	var bufIdx int64

	for {
		// Wait for the next flow-start tick.
		if err := dispatcher.Take(ctx); err != nil {
			return // context cancelled — normal shutdown
		}

		// --- flow start ---
		g.mc.C.FlowsStarted.Add(1)
		g.mc.C.ActiveFlows.Add(1)
		g.mc.C.OpenFlows.Add(1)

		var sent int64
		cancelled := false
		for sent < g.cfg.Count {
			if ctx.Err() != nil {
				cancelled = true
				break
			}

			var data []byte
			if len(sharedBuf) > 0 {
				data = sharedBuf[int(bufIdx)%len(sharedBuf)]
				bufIdx++
			} else {
				var buildErr error
				data, buildErr = g.tmpl.Build(g.srcMAC, g.dstMAC, rng)
				if buildErr != nil {
					g.mc.C.Errors.Add(1)
					sent++
					continue
				}
			}

			if limiter != nil {
				if err := limiter.Wait(ctx, len(data)); err != nil {
					cancelled = true
					break
				}
			}

			if batchBuf != nil {
				batchBuf = append(batchBuf, data)
				if len(batchBuf) >= batchSize {
					flushBatch()
				}
			} else {
				if err := g.snd.Send(data); err != nil {
					g.mc.C.Errors.Add(1)
					sent++
					continue
				}
				g.mc.C.PacketsSent.Add(1)
				g.mc.C.BytesSent.Add(int64(len(data)))
			}
			sent++
		}
		flushBatch()

		// --- flow end ---
		g.mc.C.ActiveFlows.Add(-1)
		g.mc.C.OpenFlows.Add(-1)

		if cancelled {
			return
		}
		// CPS mode always loops: the ticker controls flow rate; Ctrl-C stops the run.
	}
}

// runWorkers is the original multi-worker path (used when CPS == 0 or Count == 0).
func (g *Generator) runWorkers(ctx context.Context, limiter *ratelimit.Limiter, cpsLimiter *ratelimit.CPSLimiter, baseNano int64) error {
	workers := g.cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	workerRNGs := make([]*rand.Rand, workers)
	for i := range workerRNGs {
		workerRNGs[i] = rand.New(rand.NewSource(baseNano ^ int64(i+1)<<32))
	}

	// Phase 1: pre-build per-worker packet buffers.
	allPrebuilt := make([][][]byte, workers)
	if g.cfg.PreBuild > 0 {
		perWorker := g.cfg.PreBuild / workers
		if perWorker < 1 {
			perWorker = 1
		}
		for i := 0; i < workers; i++ {
			allPrebuilt[i] = make([][]byte, perWorker)
			for j := range allPrebuilt[i] {
				pkt, buildErr := g.tmpl.Build(g.srcMAC, g.dstMAC, workerRNGs[i])
				if buildErr != nil {
					return fmt.Errorf("pre-build worker %d packet %d: %w", i, j, buildErr)
				}
				allPrebuilt[i][j] = pkt
			}
		}
	}

	// Each worker runs for the full Count per cycle; 0 means run until ctx cancelled.
	workerCounts := make([]int64, workers)
	for i := range workerCounts {
		workerCounts[i] = g.cfg.Count
	}

	var wg sync.WaitGroup
	errc := make(chan error, 1)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(rng *rand.Rand, count int64, preBuf [][]byte) {
			defer wg.Done()
			if werr := g.runWorker(ctx, rng, count, preBuf, limiter, cpsLimiter); werr != nil {
				select {
				case errc <- werr:
				default:
				}
			}
		}(workerRNGs[i], workerCounts[i], allPrebuilt[i])
	}

	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return ctx.Err()
	}
}

// runWorker is the inner loop for a single worker goroutine (workers mode).
// count=0 means run until ctx cancelled. If cfg.Loop is true and count>0,
// restart after each cycle instead of returning.
func (g *Generator) runWorker(ctx context.Context, rng *rand.Rand, count int64, preBuf [][]byte, limiter *ratelimit.Limiter, cpsLimiter *ratelimit.CPSLimiter) error {
	batcher, isBatcher := g.snd.(sender.Batcher)
	useBatch := isBatcher && len(preBuf) > 0
	batchSize := g.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 32
	}

	var batchBuf [][]byte
	if useBatch {
		batchBuf = make([][]byte, 0, batchSize)
	}

	flushBatch := func() {
		if !useBatch || len(batchBuf) == 0 {
			return
		}
		n, _ := batcher.SendBatch(batchBuf)
		for i := 0; i < n; i++ {
			g.mc.C.PacketsSent.Add(1)
			g.mc.C.BytesSent.Add(int64(len(batchBuf[i])))
		}
		if n < len(batchBuf) {
			g.mc.C.Errors.Add(int64(len(batchBuf) - n))
		}
		batchBuf = batchBuf[:0]
	}

	flowRunning := false
	startCycle := func() error {
		if err := cpsLimiter.Wait(ctx); err != nil {
			return ctx.Err()
		}
		g.mc.C.FlowsStarted.Add(1)
		g.mc.C.ActiveFlows.Add(1)
		g.mc.C.OpenFlows.Add(1)
		flowRunning = true
		return nil
	}
	// endCycle is idempotent: safe to call from both the loop body and defer.
	endCycle := func() {
		if !flowRunning {
			return
		}
		g.mc.C.ActiveFlows.Add(-1)
		g.mc.C.OpenFlows.Add(-1)
		flowRunning = false
	}

	// For count>0 the first cycle starts before the loop; for count=0 (infinite)
	// the loop itself manages cycle boundaries so each iteration is one flow.
	if count > 0 {
		if err := startCycle(); err != nil {
			return err
		}
	}
	defer endCycle()

	var sent int64
	bufIdx := 0

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if count == 0 {
			// Infinite mode: each outer-loop iteration is one flow cycle.
			flushBatch()
			endCycle() // idempotent on very first iteration
			if err := startCycle(); err != nil {
				return err
			}
		} else if sent >= count {
			if !g.cfg.Loop {
				return nil
			}
			flushBatch()
			endCycle()
			if err := startCycle(); err != nil {
				return err
			}
			sent = 0
		}

		var data []byte
		if len(preBuf) > 0 {
			data = preBuf[bufIdx%len(preBuf)]
			bufIdx++
		} else {
			var err error
			data, err = g.tmpl.Build(g.srcMAC, g.dstMAC, rng)
			if err != nil {
				g.mc.C.Errors.Add(1)
				continue
			}
		}

		if limiter != nil {
			if err := limiter.Wait(ctx, len(data)); err != nil {
				return ctx.Err()
			}
		}

		if useBatch {
			batchBuf = append(batchBuf, data)
			if len(batchBuf) >= batchSize {
				flushBatch()
			}
		} else {
			if err := g.snd.Send(data); err != nil {
				g.mc.C.Errors.Add(1)
				continue
			}
			g.mc.C.PacketsSent.Add(1)
			g.mc.C.BytesSent.Add(int64(len(data)))
		}
		sent++
	}
}
