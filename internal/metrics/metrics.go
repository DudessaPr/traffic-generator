package metrics

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Counters holds atomically updated traffic statistics.
// All fields are safe for concurrent access.
type Counters struct {
	PacketsSent  atomic.Int64
	BytesSent    atomic.Int64
	Errors       atomic.Int64
	SessionsDone atomic.Int64
	EmptyPackets atomic.Int64
	ActiveFlows  atomic.Int64 // flows currently in flight
	OpenFlows    atomic.Int64 // flows with no FIN/RST sent yet
	FlowsStarted atomic.Int64 // cumulative flows started (used for CPS delta)
}

// Snapshot is an immutable point-in-time copy of Counters plus derived rates.
type Snapshot struct {
	PacketsSent  int64
	BytesSent    int64
	Errors       int64
	SessionsDone int64
	EmptyPackets int64
	ActiveFlows  int64
	OpenFlows    int64
	FlowsStarted int64   // cumulative; used for CPS delta across snapshots
	PPS          float64 // packets / second since previous snapshot
	BPS          float64 // bytes / second since previous snapshot
	CPS          float64 // connections (flows) started / second since previous snapshot
	ElapsedSec   float64
	// Configuration metadata copied from Collector (not computed from counters).
	TargetRate string
	TargetCPS  float64
	Multiplier float64
}

// Collector gathers Counters and reports them periodically.
type Collector struct {
	C        Counters
	interval time.Duration
	out      io.Writer
	start    time.Time
	prev     Snapshot
	// Configuration metadata exposed in every Snapshot; set by the caller.
	TargetRate string
	TargetCPS  float64
	Multiplier float64
}

// New creates a Collector. output is "stdout", "stderr", or a file path.
func New(interval time.Duration, output string) (*Collector, error) {
	var out io.Writer = os.Stdout
	switch output {
	case "", "stdout":
	case "stderr":
		out = os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open metrics output %q: %w", output, err)
		}
		out = f
	}
	return &Collector{interval: interval, out: out, start: time.Now()}, nil
}

// Run reports metrics at the configured interval until done is closed.
// A final report is emitted when done is received.
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

// Snapshot reads all counters and computes per-interval rates.
func (c *Collector) Snapshot() Snapshot {
	now := time.Since(c.start).Seconds()
	pkts := c.C.PacketsSent.Load()
	bytes := c.C.BytesSent.Load()
	errs := c.C.Errors.Load()
	sess := c.C.SessionsDone.Load()
	empty := c.C.EmptyPackets.Load()
	active := c.C.ActiveFlows.Load()
	open := c.C.OpenFlows.Load()
	flowsStarted := c.C.FlowsStarted.Load()

	dt := now - c.prev.ElapsedSec
	var pps, bps, cps float64
	if dt > 0 {
		pps = float64(pkts-c.prev.PacketsSent) / dt
		bps = float64(bytes-c.prev.BytesSent) / dt
		cps = float64(flowsStarted-c.prev.FlowsStarted) / dt
	}
	return Snapshot{
		PacketsSent:  pkts,
		BytesSent:    bytes,
		Errors:       errs,
		SessionsDone: sess,
		EmptyPackets: empty,
		ActiveFlows:  active,
		OpenFlows:    open,
		FlowsStarted: flowsStarted,
		PPS:          pps,
		BPS:          bps,
		CPS:          cps,
		ElapsedSec:   now,
		TargetRate:   c.TargetRate,
		TargetCPS:    c.TargetCPS,
		Multiplier:   c.Multiplier,
	}
}

func (c *Collector) report() {
	snap := c.Snapshot()
	_, _ = fmt.Fprintf(c.out,
		"[metrics] elapsed=%.1fs pkts=%d pps=%.0f bps=%.0f errors=%d active=%d open=%d cps=%.0f empty=%d\n",
		snap.ElapsedSec,
		snap.PacketsSent,
		snap.PPS,
		snap.BPS,
		snap.Errors,
		snap.ActiveFlows,
		snap.OpenFlows,
		snap.CPS,
		snap.EmptyPackets,
	)
	c.prev = snap
}
