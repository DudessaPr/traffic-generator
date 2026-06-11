package replay

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/ratelimit"
	"tgen/internal/sender"
	"tgen/internal/session"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// processedSession holds pre-mutated packet bytes for one session.
// Used when cfg.PreProcess is true to move gopacket overhead off the hot path.
type processedSession struct {
	frames     [][]byte
	lastFINRST bool // true if the last original packet was TCP FIN or RST
}

// timestampedFrame is one pre-mutated frame with its original capture timestamp.
// Used internally by runPcap to sort all packets globally before sending.
type timestampedFrame struct {
	ts   time.Time
	data []byte
}

// Replayer orchestrates timing-accurate replay of sessions.
type Replayer struct {
	cfg         config.ReplayConfig
	mutator     *mutation.Mutator
	sender      sender.Interface
	mc          *metrics.Collector
	rateLimiter *rateLimiter          // nil = no packet-rate limiting
	cpsLimiter  *ratelimit.CPSLimiter // nil = no CPS limiting
}

// New creates a Replayer wired to the given dependencies.
func New(cfg config.ReplayConfig, mut *mutation.Mutator, snd sender.Interface, mc *metrics.Collector) *Replayer {
	return &Replayer{cfg: cfg, mutator: mut, sender: snd, mc: mc}
}

// Run replays sessions according to the configured mode and loop settings.
// It returns on context cancellation or after all iterations complete.
func (r *Replayer) Run(ctx context.Context, sessions []*session.Session) error {
	// Normalise multiplier: 0 means "no scaling" (same as 1.0).
	m := r.cfg.Multiplier
	if m == 0 {
		m = 1.0
	}

	// Apply multiplier to the packet-rate string, then build the limiter.
	effectiveRate, err := ratelimit.ApplyMultiplier(r.cfg.Rate, m)
	if err != nil {
		return fmt.Errorf("rate multiplier: %w", err)
	}
	r.rateLimiter, err = newRateLimiter(ctx, effectiveRate, r.cfg.RateRamp)
	if err != nil {
		return err
	}

	// Build the CPS limiter (applies to sequential and parallel modes only).
	effectiveCPS := r.cfg.CPS * m
	r.cpsLimiter, err = ratelimit.NewCPS(ctx, effectiveCPS, "")
	if err != nil {
		return err
	}

	iters := r.cfg.LoopCount
	if iters == 0 {
		iters = 1
	}

	for i := 0; r.cfg.Loop || i < iters; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if r.cfg.IPPoolPerIter {
			r.mutator.ResetCache()
		}

		var processed []*processedSession
		if r.cfg.PreProcess && (r.cfg.Mode == "burst" || r.cfg.Mode == "parallel") {
			processed = r.preProcess(sessions)
		}

		switch r.cfg.Mode {
		case "parallel":
			err = r.runParallel(ctx, sessions, processed)
		case "burst":
			err = r.runBurst(ctx, sessions, processed)
		case "pcap":
			err = r.runPcap(ctx, sessions)
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
		if err := r.cpsLimiter.Wait(ctx); err != nil {
			return err
		}
		if err := r.replaySession(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// runParallel replays sessions with up to cfg.Workers concurrent goroutines.
func (r *Replayer) runParallel(ctx context.Context, sessions []*session.Session, processed []*processedSession) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// in case of one session returns error, we stop everything

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
	for i, s := range sessions {
		s := s //safety measure against goroutines using the same session which leads to concurrency bug
		idx := i
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}: // take semaphore slot
		}
		if err := r.cpsLimiter.Wait(ctx); err != nil {
			<-sem
			break loop
		}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			var err error
			if processed != nil {
				err = r.replayProcessed(ctx, processed[idx])
			} else {
				err = r.replaySession(ctx, s)
			}
			if err != nil &&
				err != context.Canceled &&
				err != context.DeadlineExceeded {
				r.mc.C.Errors.Add(1) // только неожиданные ошибки
				select {
				case errc <- err:
					cancel()
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

// pktHasTCPFINorRST reports whether pkt is a TCP frame with FIN or RST set.
func pktHasTCPFINorRST(pkt *session.Packet) bool {
	if pkt == nil || len(pkt.Data) == 0 {
		return false
	}
	p := gopacket.NewPacket(pkt.Data, layers.LinkType(pkt.LinkType),
		gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			return tcp.FIN || tcp.RST
		}
	}
	return false
}

// updateFlowMetrics after each session
func (r *Replayer) updateFlowMetrics(s *session.Session) {
	r.mc.C.ActiveFlows.Add(-1)
	if s.Proto != 6 {
		r.mc.C.OpenFlows.Add(-1) // UDP/ICMP
		// UDP/ICMP flows have no open/closed markers so we close flow when done with the session
	}
	// TCP without FIN/RST → OpenFlows not decremented to tack open TCP flows
}

// trackTCPClose check packet for FIN/RST and decrement OpenFlows
// return true if FIN/RST found
func (r *Replayer) trackTCPClose(s *session.Session, pkt *session.Packet, seen bool) bool {
	if s.Proto == 6 && !seen && pktHasTCPFINorRST(pkt) {
		r.mc.C.OpenFlows.Add(-1)
		return true
	}
	return seen
}

func (r *Replayer) trackSessionClose(s *session.Session) {
	for _, pkt := range s.Packets {
		if r.trackTCPClose(s, pkt, false) {
			break
		}
	}
}

// startSession increment metrics when start session
func (r *Replayer) startSession() {
	r.mc.C.FlowsStarted.Add(1)
	r.mc.C.ActiveFlows.Add(1)
	r.mc.C.OpenFlows.Add(1)
}

// sendBurstFrames sends pre-mutated frames via addFrame.
// Returns (cancelled bool).
func (r *Replayer) sendBurstFrames(
	ctx context.Context,
	frames [][]byte,
	addFrame func([]byte) bool,
) bool {
	for _, frame := range frames {
		if ctx.Err() != nil {
			return true
		}
		if !addFrame(frame) {
			return true
		}
	}
	return false
}

// sendBurstPackets mutates and sends packets via addFrame.
// Returns (cancelled bool, finRSTSeen bool).
func (r *Replayer) sendBurstPackets(
	ctx context.Context,
	s *session.Session,
	plan mutation.Plan,
	addFrame func([]byte) bool,
) (cancelled bool) {
	for _, pkt := range s.Packets {
		if ctx.Err() != nil {
			return true
		}
		if len(pkt.Data) == 0 {
			r.mc.C.EmptyPackets.Add(1)
			continue
		}
		data, err := mutation.Apply(pkt.Data, plan, layers.LinkType(pkt.LinkType))
		if err != nil {
			r.mc.C.Errors.Add(1)
			continue
		}
		if !addFrame(data) {
			return true
		}
	}
	return false
}

const defaultBatchSize = 32

// runBurst sends all packets without inter-packet delays.
// When the sender implements sender.Batcher, frames are collected into a buffer
// and flushed either when the buffer reaches cfg.BatchSize or a session ends,
// reducing per-packet syscall overhead.
func (r *Replayer) runBurst(ctx context.Context, sessions []*session.Session, processed []*processedSession) error {
	batcher, isBatcher := r.sender.(sender.Batcher)
	batchSize := r.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	buf := make([][]byte, 0, batchSize)

	flushBuf := func() {
		if len(buf) == 0 {
			return
		}
		if isBatcher {
			n, _ := batcher.SendBatch(buf)
			for i := 0; i < n; i++ {
				r.mc.C.PacketsSent.Add(1)
				r.mc.C.BytesSent.Add(int64(len(buf[i])))
			}
			if n < len(buf) {
				r.mc.C.Errors.Add(int64(len(buf) - n))
			}
		} else {
			for _, f := range buf {
				if err := r.sender.Send(f); err != nil {
					r.mc.C.Errors.Add(1)
					continue
				}
				r.mc.C.PacketsSent.Add(1)
				r.mc.C.BytesSent.Add(int64(len(f)))
			}
		}
		buf = buf[:0]
	}

	// addFrame rate-limits (if configured) and enqueues one frame; returns
	// false only if the context is cancelled.
	addFrame := func(data []byte) bool {
		if r.rateLimiter != nil {
			if err := r.rateLimiter.Wait(ctx, len(data)); err != nil {
				return false
			}
		}
		buf = append(buf, data)
		if len(buf) >= batchSize {
			flushBuf()
		}
		return true
	}

	for i, s := range sessions {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// processed path
		if processed != nil {
			ps := processed[i]
			if ps == nil || len(ps.frames) == 0 {
				continue
			}
			r.startSession()
			cancelled := r.sendBurstFrames(ctx, ps.frames, addFrame)
			flushBuf()
			r.trackSessionClose(s)
			r.updateFlowMetrics(s)
			if cancelled {
				return ctx.Err()
			}
			r.mc.C.SessionsDone.Add(1)
			continue
		}

		// on-the-fly path
		if len(s.Packets) == 0 {
			continue
		}
		r.startSession()
		plan := r.mutator.PlanFor(s)
		cancelled := r.sendBurstPackets(ctx, s, plan, addFrame)
		flushBuf()
		r.trackSessionClose(s)
		r.updateFlowMetrics(s)
		if cancelled {
			return ctx.Err()
		}
		r.mc.C.SessionsDone.Add(1)
	}

	return nil
}

// runPcap merges all session packets by original capture timestamp and replays
// them in that order, honouring inter-packet gaps scaled by cfg.Speed.
func (r *Replayer) runPcap(ctx context.Context, sessions []*session.Session) error {
	numFlows := int64(0)
	for _, s := range sessions {
		if len(s.Packets) > 0 {
			numFlows++
		}
	}
	if numFlows > 0 {
		r.mc.C.FlowsStarted.Add(numFlows)
		r.mc.C.ActiveFlows.Add(numFlows)
		r.mc.C.OpenFlows.Add(numFlows)
		defer func() {
			r.mc.C.ActiveFlows.Add(-numFlows)
			r.mc.C.OpenFlows.Add(-numFlows)
			r.mc.C.SessionsDone.Add(numFlows)
		}()
	}

	var all []timestampedFrame
	for _, s := range sessions {
		if len(s.Packets) == 0 {
			continue
		}
		plan := r.mutator.PlanFor(s)
		for _, pkt := range s.Packets {
			if len(pkt.Data) == 0 {
				r.mc.C.EmptyPackets.Add(1)
				continue
			}
			data, err := mutation.Apply(pkt.Data, plan, layers.LinkType(pkt.LinkType))
			if err != nil {
				r.mc.C.Errors.Add(1)
				continue
			}
			all = append(all, timestampedFrame{ts: pkt.Timestamp, data: data})
		}
	}
	if len(all) == 0 {
		return nil
	}

	sort.Slice(all, func(i, j int) bool { return all[i].ts.Before(all[j].ts) })

	origin := all[0].ts
	wallStart := time.Now()

	timer := time.NewTimer(0)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	for _, frame := range all {
		capOffset := frame.ts.Sub(origin)
		if r.cfg.Speed > 0 {
			capOffset = time.Duration(float64(capOffset) / r.cfg.Speed)
			if capOffset > time.Hour {
				capOffset = time.Hour
			}
		} else {
			capOffset = 0
		}
		if wait := time.Until(wallStart.Add(capOffset)); wait > 0 {
			timer.Reset(wait)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
		r.sendRaw(ctx, frame.data)
	}
	return nil
}

// preProcess applies mutations to every packet in every session and stores the
// results as raw byte slices, removing gopacket overhead from the send hot path.
func (r *Replayer) preProcess(sessions []*session.Session) []*processedSession {
	out := make([]*processedSession, len(sessions))
	for i, s := range sessions {
		ps := &processedSession{}
		if len(s.Packets) == 0 {
			out[i] = ps
			continue
		}
		plan := r.mutator.PlanFor(s)
		ps.frames = make([][]byte, 0, len(s.Packets))
		for _, pkt := range s.Packets {
			if len(pkt.Data) == 0 {
				r.mc.C.EmptyPackets.Add(1)
				continue
			}
			data, err := mutation.Apply(pkt.Data, plan, layers.LinkType(pkt.LinkType))
			if err != nil {
				r.mc.C.Errors.Add(1)
				continue
			}
			ps.frames = append(ps.frames, data)
		}
		if s.Proto == 6 {
			ps.lastFINRST = pktHasTCPFINorRST(s.Packets[len(s.Packets)-1])
		}
		out[i] = ps
	}
	return out
}

// replayProcessed sends all pre-mutated frames in ps without further mutation.
func (r *Replayer) replayProcessed(ctx context.Context, ps *processedSession) error {
	if ps == nil || len(ps.frames) == 0 {
		return nil
	}
	r.mc.C.FlowsStarted.Add(1)
	r.mc.C.ActiveFlows.Add(1)
	r.mc.C.OpenFlows.Add(1)
	openDecremented := false
	defer func() {
		r.mc.C.ActiveFlows.Add(-1)
		if !openDecremented {
			r.mc.C.OpenFlows.Add(-1)
		}
	}()
	for _, frame := range ps.frames {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.sendRaw(ctx, frame)
	}
	if ps.lastFINRST {
		r.mc.C.OpenFlows.Add(-1)
		openDecremented = true
	}
	r.mc.C.SessionsDone.Add(1)
	return nil
}

// replaySession sends all packets in a session, honouring original inter-packet gaps
// scaled by the configured speed multiplier.
func (r *Replayer) replaySession(ctx context.Context, s *session.Session) error {
	if len(s.Packets) == 0 {
		return nil
	}
	r.startSession()
	finRSTSeen := false
	defer func() {
		r.updateFlowMetrics(s)
	}()

	plan := r.mutator.PlanFor(s)
	origin := s.Packets[0].Timestamp
	wallStart := time.Now()

	timer := time.NewTimer(0)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	for _, pkt := range s.Packets {
		capOffset := pkt.Timestamp.Sub(origin)
		if r.cfg.Speed > 0 {
			capOffset = time.Duration(float64(capOffset) / r.cfg.Speed)
			if capOffset > time.Hour {
				capOffset = time.Hour
			}
		} else {
			capOffset = 0
		}
		if wait := time.Until(wallStart.Add(capOffset)); wait > 0 {
			timer.Reset(wait)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
		r.sendPacket(ctx, pkt, plan)
		finRSTSeen = r.trackTCPClose(s, pkt, finRSTSeen)
	}
	r.mc.C.SessionsDone.Add(1)
	return nil
}

// sendPacket applies mutation and delegates to sendRaw.
func (r *Replayer) sendPacket(ctx context.Context, pkt *session.Packet, plan mutation.Plan) {
	if len(pkt.Data) == 0 {
		r.mc.C.EmptyPackets.Add(1)
		return
	}
	data, err := mutation.Apply(pkt.Data, plan, layers.LinkType(pkt.LinkType))
	if err != nil {
		r.mc.C.Errors.Add(1)
		return
	}
	r.sendRaw(ctx, data)
}

// sendRaw injects one already-mutated frame, enforcing the rate limit if set.
func (r *Replayer) sendRaw(ctx context.Context, data []byte) {
	if r.rateLimiter != nil {
		if err := r.rateLimiter.Wait(ctx, len(data)); err != nil {
			return // context cancelled — do not count as an error
		}
	}
	if err := r.sender.Send(data); err != nil {
		r.mc.C.Errors.Add(1)
		return
	}
	r.mc.C.PacketsSent.Add(1)
	r.mc.C.BytesSent.Add(int64(len(data)))
}
