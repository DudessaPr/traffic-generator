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
	Workers    int     // goroutines to launch; 0 or 1 = single-threaded
	PreBuild   int     // packets to pre-build per worker before the send loop (0 = disabled)
	CPS        float64 // new flows (worker cycles) to start per second; 0 = unlimited
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
// When Workers > 1, N goroutines run concurrently; each has its own *rand.Rand and,
// if PreBuild > 0, its own pre-built packet buffer.
func (g *Generator) Run(ctx context.Context) error {
	workers := g.cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	// Normalise multiplier: 0 means no scaling (same as 1.0).
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
	cpsLimiter, err := ratelimit.NewCPS(ctx, effectiveCPS, "")
	if err != nil {
		return err
	}

	// Seed each worker's RNG distinctly even if called in the same nanosecond.
	baseNano := time.Now().UnixNano()
	workerRNGs := make([]*rand.Rand, workers)
	for i := range workerRNGs {
		workerRNGs[i] = rand.New(rand.NewSource(baseNano ^ int64(i+1)<<32))
	}

	// Phase 1 (pre-build): build packet buffers before launching goroutines so that
	// a build failure aborts cleanly without any worker having started.
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

	// Distribute total count evenly; first (Count%workers) workers get +1.
	workerCounts := make([]int64, workers)
	if g.cfg.Count > 0 {
		base := g.cfg.Count / int64(workers)
		rem := g.cfg.Count % int64(workers)
		for i := range workerCounts {
			workerCounts[i] = base
			if int64(i) < rem {
				workerCounts[i]++
			}
		}
	}

	// Phase 2: launch workers.
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

// runWorker is the inner loop for a single worker goroutine.
// count=0 means run until ctx cancelled. If cfg.Loop is true and count>0, restart
// after each cycle instead of returning.
func (g *Generator) runWorker(ctx context.Context, rng *rand.Rand, count int64, preBuf [][]byte, limiter *ratelimit.Limiter, cpsLimiter *ratelimit.CPSLimiter) error {
	// Batch mode: pre-built packets + Batcher sender → accumulate frames and
	// flush in groups to reduce per-packet syscall overhead.
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
	defer flushBatch()

	// Wait for a CPS token before the first flow cycle.
	if err := cpsLimiter.Wait(ctx); err != nil {
		return ctx.Err()
	}
	g.mc.C.FlowsStarted.Add(1)
	g.mc.C.ActiveFlows.Add(1)
	g.mc.C.OpenFlows.Add(1)
	defer func() {
		g.mc.C.ActiveFlows.Add(-1)
		g.mc.C.OpenFlows.Add(-1)
	}()

	var sent int64
	bufIdx := 0

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if count > 0 && sent >= count {
			if !g.cfg.Loop {
				return nil
			}
			// Flush before starting a new flow cycle.
			flushBatch()
			if err := cpsLimiter.Wait(ctx); err != nil {
				return ctx.Err()
			}
			g.mc.C.FlowsStarted.Add(1)
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
