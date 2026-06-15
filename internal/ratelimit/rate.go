// Package ratelimit provides a token-bucket rate limiter shared by the replay
// and generate pipelines.
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// rateSpec holds a parsed rate in either packets/sec or bits/sec.
type rateSpec struct {
	pps int64
	bps int64
}

func parseRateSpec(s string) (rateSpec, error) {
	if s == "" {
		return rateSpec{}, nil
	}
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))

	for _, entry := range []struct {
		suffix string
		scale  float64
	}{
		{"mpps", 1e6},
		{"kpps", 1e3},
		{"pps", 1},
	} {
		if strings.HasSuffix(s, entry.suffix) {
			num := strings.TrimSuffix(s, entry.suffix)
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return rateSpec{}, fmt.Errorf("invalid rate %q", orig)
			}
			return rateSpec{pps: int64(v * entry.scale)}, nil
		}
	}

	for _, entry := range []struct {
		suffix string
		scale  float64
	}{
		{"gbps", 1e9},
		{"mbps", 1e6},
		{"kbps", 1e3},
		{"bps", 1},
	} {
		if strings.HasSuffix(s, entry.suffix) {
			num := strings.TrimSuffix(s, entry.suffix)
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return rateSpec{}, fmt.Errorf("invalid rate %q", orig)
			}
			return rateSpec{bps: int64(v * entry.scale)}, nil
		}
	}

	return rateSpec{}, fmt.Errorf("unrecognised rate unit in %q (use pps/kpps/mpps/bps/kbps/mbps/gbps)", orig)
}

// ParseRate validates a rate string. Returns nil if s is empty or syntactically valid.
func ParseRate(s string) error {
	if s == "" {
		return nil
	}
	_, err := parseRateSpec(s)
	return err
}

// ApplyMultiplier scales a rate string by m and returns a canonical rate string.
// m=0 and m=1 are no-ops (return rateStr unchanged). Returns an error for m<0.
func ApplyMultiplier(rateStr string, m float64) (string, error) {
	if rateStr == "" {
		return "", nil
	}
	if m < 0 {
		return "", fmt.Errorf("multiplier must be >= 0, got %g", m)
	}
	if m == 0 || m == 1.0 {
		return rateStr, nil
	}
	spec, err := parseRateSpec(rateStr)
	if err != nil {
		return "", err
	}
	if spec.pps > 0 {
		scaled := int64(float64(spec.pps) * m)
		if scaled < 1 {
			scaled = 1
		}
		return fmt.Sprintf("%dpps", scaled), nil
	}
	scaled := int64(float64(spec.bps) * m)
	if scaled < 1 {
		scaled = 1
	}
	return fmt.Sprintf("%dbps", scaled), nil
}

// ParseCPS parses a connections-per-second value. Accepts plain numbers or
// suffixed forms: "1000", "500cps", "1kcps", "1Mcps". Returns 0 for empty input.
func ParseCPS(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))

	for _, entry := range []struct {
		suffix string
		scale  float64
	}{
		{"mcps", 1e6},
		{"kcps", 1e3},
		{"cps", 1},
	} {
		if strings.HasSuffix(s, entry.suffix) {
			num := strings.TrimSuffix(s, entry.suffix)
			v, err := strconv.ParseFloat(num, 64)
			if err != nil || v < 0 {
				return 0, fmt.Errorf("invalid CPS value %q", orig)
			}
			return v * entry.scale, nil
		}
	}

	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid CPS value %q (use e.g. 1000, 1kcps, 1Mcps)", orig)
	}
	return v, nil
}

// CPSLimiter is a token-bucket rate limiter for new connections (sessions) per second.
// A nil *CPSLimiter permits unlimited new sessions.
type CPSLimiter struct {
	lim *rate.Limiter
}

// NewCPS returns a CPSLimiter for the given target connections-per-second.
// Returns nil when cps <= 0 (unlimited). If rampStr is non-empty the rate
// linearly ramps from 0 to cps over that duration; the ramp goroutine stops
// when ctx is cancelled.
func NewCPS(ctx context.Context, cps float64, rampStr string) (*CPSLimiter, error) {
	if cps <= 0 {
		return nil, nil
	}
	var rampDur time.Duration
	if rampStr != "" {
		var err error
		rampDur, err = time.ParseDuration(rampStr)
		if err != nil {
			return nil, fmt.Errorf("cps ramp %q: %w", rampStr, err)
		}
	}
	startRate := cps
	if rampDur > 0 {
		startRate = 0
	}
	burst := int(cps / 10)
	if burst < 1 {
		burst = 1
	}
	if burst > 1000 {
		burst = 1000
	}
	lim := rate.NewLimiter(rate.Limit(startRate), burst)
	lim.AllowN(time.Now(), burst) // drain initial bucket so limiting is immediate
	cl := &CPSLimiter{lim: lim}
	if rampDur > 0 {
		go rampUp(ctx, lim, cps, rampDur)
	}
	return cl, nil
}

// Wait blocks until the limiter permits starting one new session.
// Returns nil immediately when c is nil (unlimited).
func (c *CPSLimiter) Wait(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.lim.Wait(ctx)
}

// CPSDispatcher fires flow-start signals at a fixed ticker interval, making
// --cps a throughput target rather than a ceiling. Unlike CPSLimiter (token
// bucket), the ticker cannot be "saved up": excess capacity is bounded by the
// channel buffer. A nil *CPSDispatcher is unlimited.
type CPSDispatcher struct {
	ch  <-chan struct{}
	cps float64
}

// cpsDispatchBuf is the maximum number of queued flow-start signals.
const cpsDispatchBuf = 1024

// NewCPSDispatcher starts a ticker goroutine that emits one flow-start signal
// per 1s/cps interval. Returns nil when cps <= 0 (unlimited). The goroutine
// stops when ctx is cancelled.
func NewCPSDispatcher(ctx context.Context, cps float64) *CPSDispatcher {
	if cps <= 0 {
		return nil
	}
	ch := make(chan struct{}, cpsDispatchBuf)
	interval := time.Duration(float64(time.Second) / cps)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case ch <- struct{}{}:
				default: // buffer full; this tick is skipped
				}
			}
		}
	}()
	return &CPSDispatcher{ch: ch, cps: cps}
}

// Take blocks until a flow-start signal arrives or ctx is cancelled.
// Returns nil on signal, ctx.Err() on cancellation.
// Safe to call concurrently from multiple goroutines.
func (d *CPSDispatcher) Take(ctx context.Context) error {
	if d == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.ch:
		return nil
	}
}

// Limiter wraps a token-bucket rate limiter.
// A nil *Limiter is valid and means unlimited.
type Limiter struct {
	lim  *rate.Limiter
	spec rateSpec
}

// New returns a configured Limiter for rateStr/rampStr, or nil for unlimited.
// If rampStr is non-empty, a goroutine linearly increases the rate from 0 to
// target over the ramp duration; the goroutine stops when ctx is done.
func New(ctx context.Context, rateStr, rampStr string) (*Limiter, error) {
	if rateStr == "" {
		return nil, nil
	}
	spec, err := parseRateSpec(rateStr)
	if err != nil {
		return nil, err
	}
	var rampDur time.Duration
	if rampStr != "" {
		rampDur, err = time.ParseDuration(rampStr)
		if err != nil {
			return nil, fmt.Errorf("rate_ramp %q: %w", rampStr, err)
		}
	}

	target := targetEventsPerSec(spec)
	startRate := target
	if rampDur > 0 {
		startRate = 0
	}
	burst := burstFor(spec)
	lim := rate.NewLimiter(rate.Limit(startRate), burst)
	// Drain the initial full bucket so the limit is enforced from packet one.
	lim.AllowN(time.Now(), burst)
	rl := &Limiter{lim: lim, spec: spec}

	if rampDur > 0 {
		go rampUp(ctx, lim, target, rampDur)
	}
	return rl, nil
}

// Wait blocks until the limiter permits sending one packet of pktSize bytes.
// Returns nil immediately when l is nil (no rate limiting configured).
func (l *Limiter) Wait(ctx context.Context, pktSize int) error {
	if l == nil {
		return nil
	}
	if l.spec.pps > 0 {
		return l.lim.Wait(ctx)
	}
	n := pktSize
	if n < 1 {
		n = 1
	}
	if b := l.lim.Burst(); n > b {
		n = b
	}
	return l.lim.WaitN(ctx, n)
}

func targetEventsPerSec(spec rateSpec) float64 {
	if spec.pps > 0 {
		return float64(spec.pps)
	}
	return float64(spec.bps) / 8.0
}

func burstFor(spec rateSpec) int {
	if spec.pps > 0 {
		b := int(spec.pps / 10)
		if b < 1 {
			b = 1
		}
		if b > 1000 {
			b = 1000
		}
		return b
	}
	return 65536
}

func rampUp(ctx context.Context, lim *rate.Limiter, target float64, ramp time.Duration) {
	start := time.Now()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			lim.SetLimit(rate.Limit(target))
			return
		case t := <-tick.C:
			frac := float64(t.Sub(start)) / float64(ramp)
			if frac >= 1 {
				lim.SetLimit(rate.Limit(target))
				return
			}
			lim.SetLimit(rate.Limit(target * frac))
		}
	}
}
