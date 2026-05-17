package replay

import (
	"context"
	"sync"
	"time"

	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/sender"
	"tgen/internal/session"

	"github.com/google/gopacket/layers"
)

// Replayer orchestrates timing-accurate replay of sessions.
type Replayer struct {
	cfg     config.ReplayConfig
	mutator *mutation.Mutator
	sender  sender.Interface
	mc      *metrics.Collector
}

// New creates a Replayer wired to the given dependencies.
func New(cfg config.ReplayConfig, mut *mutation.Mutator, snd sender.Interface, mc *metrics.Collector) *Replayer {
	return &Replayer{cfg: cfg, mutator: mut, sender: snd, mc: mc}
}

// Run replays sessions according to the configured mode and loop settings.
// It returns on context cancellation or after all iterations complete.
func (r *Replayer) Run(ctx context.Context, sessions []*session.Session) error {
	iters := r.cfg.LoopCount
	if iters == 0 {
		iters = 1
	}

	for i := 0; r.cfg.Loop || i < iters; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var err error
		switch r.cfg.Mode {
		case "parallel":
			err = r.runParallel(ctx, sessions)
		case "burst":
			err = r.runBurst(ctx, sessions)
		default:
			err = r.runSequential(ctx, sessions)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// runSequential replays sessions one after another, timing-accurate.
func (r *Replayer) runSequential(ctx context.Context, sessions []*session.Session) error {
	for _, s := range sessions {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.replaySession(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// runParallel replays sessions with up to cfg.Workers concurrent goroutines.
func (r *Replayer) runParallel(ctx context.Context, sessions []*session.Session) error {
	workers := r.cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	// No point creating more goroutine slots than there are sessions; excess
	// capacity in the semaphore channel would waste memory without benefit.
	if len(sessions) > 0 && workers > len(sessions) {
		workers = len(sessions)
	}
	sem := make(chan struct{}, workers)
	errc := make(chan error, 1)
	var wg sync.WaitGroup

loop:
	for _, s := range sessions {
		s := s //safety measure against goroutines using the same session which leads to concurrency bug
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			if err := r.replaySession(ctx, s); err != nil {
				select {
				case errc <- err:
				default:
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return ctx.Err()
	}
}

// runBurst sends all packets without inter-packet delays.
func (r *Replayer) runBurst(ctx context.Context, sessions []*session.Session) error {
	for _, s := range sessions {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(s.Packets) == 0 {
			continue
		}
		plan := r.mutator.PlanFor(s)
		for _, pkt := range s.Packets {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.sendPacket(pkt, plan)
		}
		r.mc.C.SessionsDone.Add(1)
	}
	return nil
}

// replaySession sends all packets in a session, honouring original inter-packet gaps
// scaled by the configured speed multiplier.
func (r *Replayer) replaySession(ctx context.Context, s *session.Session) error {
	if len(s.Packets) == 0 {
		return nil
	}
	plan := r.mutator.PlanFor(s)
	origin := s.Packets[0].Timestamp
	wallStart := time.Now()

	for _, pkt := range s.Packets {
		capOffset := pkt.Timestamp.Sub(origin)
		if r.cfg.Speed > 0 {
			capOffset = time.Duration(float64(capOffset) / r.cfg.Speed)
			// A very small speed (e.g. 0.0001) can push capOffset past the
			// int64 nanosecond limit (~292 years) and wrap negative. Cap at
			// 1 hour which is already far beyond any realistic replay gap.
			if capOffset > time.Hour {
				capOffset = time.Hour
			}
		} else {
			capOffset = 0 // burst inside session
		}
		if wait := wallStart.Add(capOffset).Sub(time.Now()); wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		r.sendPacket(pkt, plan)
	}
	r.mc.C.SessionsDone.Add(1)
	return nil
}

// sendPacket applies mutation and injects the packet, updating metrics.
func (r *Replayer) sendPacket(pkt *session.Packet, plan mutation.Plan) {
	if len(pkt.Data) == 0 {
		r.mc.C.EmptyPackets.Add(1)
		return
	}
	data, err := mutation.Apply(pkt.Data, plan, layers.LinkType(pkt.LinkType))
	if err != nil {
		r.mc.C.Errors.Add(1)
		return
	}
	if err := r.sender.Send(data); err != nil {
		r.mc.C.Errors.Add(1)
		return
	}
	r.mc.C.PacketsSent.Add(1)
	r.mc.C.BytesSent.Add(int64(len(data)))
}
