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
}

// Snapshot is an immutable point-in-time copy of Counters plus derived rates.
type Snapshot struct {
	PacketsSent  int64
	BytesSent    int64
	Errors       int64
	SessionsDone int64
	EmptyPackets int64
	PPS          float64 // packets / second since previous snapshot
	BPS          float64 // bytes / second since previous snapshot
	ElapsedSec   float64
}

// Collector gathers Counters and reports them periodically.
type Collector struct {
	C        Counters
	interval time.Duration
	out      io.Writer
	start    time.Time
	prev     Snapshot
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

	dt := now - c.prev.ElapsedSec
	var pps, bps float64
	if dt > 0 {
		pps = float64(pkts-c.prev.PacketsSent) / dt
		bps = float64(bytes-c.prev.BytesSent) / dt
	}
	return Snapshot{
		PacketsSent:  pkts,
		BytesSent:    bytes,
		Errors:       errs,
		SessionsDone: sess,
		EmptyPackets: empty,
		PPS:          pps,
		BPS:          bps,
		ElapsedSec:   now,
	}
}

func (c *Collector) report() {
	snap := c.Snapshot()
	fmt.Fprintf(c.out,
		"[metrics] elapsed=%.1fs pkts=%d bytes=%d pps=%.0f bps=%.0f errors=%d sessions=%d empty=%d\n",
		snap.ElapsedSec,
		snap.PacketsSent,
		snap.BytesSent,
		snap.PPS,
		snap.BPS,
		snap.Errors,
		snap.SessionsDone,
		snap.EmptyPackets,
	)
	c.prev = snap
}
