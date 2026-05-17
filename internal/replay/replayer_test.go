package replay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/session"
)

// mockSender counts injected packets safely under concurrent access.
// discardSender (defined in replay_bench_test.go) lacks a mutex so it
// cannot be used in parallel-mode tests.
type mockSender struct {
	mu   sync.Mutex
	sent int
}

func (m *mockSender) Send(_ []byte) error {
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()
	return nil
}
func (m *mockSender) Close() {}

func (m *mockSender) Sent() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sent
}

// makeSessionsWithGap builds n sessions each containing exactly 2 packets
// separated by gap. Used when a realistic inter-packet wait is needed to
// test timing-sensitive paths (e.g. context cancellation mid-wait).
func makeSessionsWithGap(n int, gap time.Duration) []*session.Session {
	raw := buildRawTCPPacket() // helper defined in replay_bench_test.go
	now := time.Now()
	out := make([]*session.Session, n)
	for i := range out {
		out[i] = &session.Session{
			Key:     session.Key{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: uint16(3000 + i), DstPort: 80, Proto: 6},
			SrcIP:   net.ParseIP("1.2.3.4"),
			DstIP:   net.ParseIP("5.6.7.8"),
			SrcPort: uint16(3000 + i),
			DstPort: 80,
			Proto:   6,
			Packets: []*session.Packet{
				{Timestamp: now, Data: raw, LinkType: layers.LinkTypeEthernet},
				{Timestamp: now.Add(gap), Data: raw, LinkType: layers.LinkTypeEthernet},
			},
		}
	}
	return out
}

// newMC creates a metrics Collector whose ticker fires so far in the future
// it never interferes with test timing.
func newMC(t *testing.T) *metrics.Collector {
	t.Helper()
	mc, err := metrics.New(time.Hour, "stdout")
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

// newMut returns a no-op Mutator (pass-through plan, no field rewrites).
func newMut(t *testing.T) *mutation.Mutator {
	t.Helper()
	mut, err := mutation.New(config.MutationConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return mut
}

// TestReplaySequential verifies that sequential mode sends every packet from
// every session and increments SessionsDone once per completed session.
func TestReplaySequential(t *testing.T) {
	sessions := makeBenchSessions(3, 2) // 3 sessions × 2 packets = 6 packets
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "sequential", Speed: 0}, newMut(t), ms, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := ms.Sent(); got != 6 {
		t.Errorf("packets sent: want 6, got %d", got)
	}
	if got := mc.C.SessionsDone.Load(); got != 3 {
		t.Errorf("SessionsDone: want 3, got %d", got)
	}
}

// TestReplayBurst verifies that burst mode sends all packets and completes
// without introducing any timing delays.
func TestReplayBurst(t *testing.T) {
	sessions := makeBenchSessions(3, 2) // 6 packets total
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "burst"}, newMut(t), ms, mc)

	start := time.Now()
	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)

	if got := ms.Sent(); got != 6 {
		t.Errorf("packets sent: want 6, got %d", got)
	}
	// Burst should finish well under 100 ms even on a heavily loaded CI host.
	if elapsed > 100*time.Millisecond {
		t.Errorf("burst mode too slow: %v (want < 100ms)", elapsed)
	}
}

// TestReplayParallel verifies that parallel mode with workers < session count
// still delivers all packets and records the correct SessionsDone count.
func TestReplayParallel(t *testing.T) {
	const nSessions, pktsPerSession = 10, 5
	sessions := makeBenchSessions(nSessions, pktsPerSession)
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "parallel", Workers: 3, Speed: 0}, newMut(t), ms, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := nSessions * pktsPerSession
	if got := ms.Sent(); got != want {
		t.Errorf("packets sent: want %d, got %d", want, got)
	}
	if got := mc.C.SessionsDone.Load(); got != nSessions {
		t.Errorf("SessionsDone: want %d, got %d", nSessions, got)
	}
}

// TestReplayContextCancel verifies that cancelling the context stops replay
// before all packets are delivered. Each session has a 200 ms intra-session
// gap, so a 30 ms timeout expires during the wait for the second packet of
// the first session — only the very first packet can reach the sender.
func TestReplayContextCancel(t *testing.T) {
	sessions := makeSessionsWithGap(5, 200*time.Millisecond)
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "sequential", Speed: 1.0}, newMut(t), ms, mc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	err := rp.Run(ctx, sessions)
	if err == nil {
		t.Error("expected context error, got nil")
	}
	// With a 30 ms timeout and a 200 ms intra-session gap, at most the first
	// packet of the first session can be sent before cancellation fires.
	total := 5 * 2
	if got := ms.Sent(); got >= total {
		t.Errorf("context cancel had no effect: %d/%d packets sent", got, total)
	}
}

// TestReplayEmptySession verifies that a session with zero packets is skipped
// in all replay modes without incrementing SessionsDone.
func TestReplayEmptySession(t *testing.T) {
	empty := &session.Session{
		Key:   session.Key{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: 9999, DstPort: 80, Proto: 6},
		SrcIP: net.ParseIP("1.2.3.4"),
		DstIP: net.ParseIP("5.6.7.8"),
		// Packets intentionally nil — this is the empty-session edge case.
	}

	for _, mode := range []string{"sequential", "burst", "parallel"} {
		ms := &mockSender{}
		mc := newMC(t)
		rp := New(config.ReplayConfig{Mode: mode, Speed: 0, Workers: 1}, newMut(t), ms, mc)

		if err := rp.Run(context.Background(), []*session.Session{empty}); err != nil {
			t.Fatalf("mode=%s Run: %v", mode, err)
		}
		if got := ms.Sent(); got != 0 {
			t.Errorf("mode=%s: want 0 packets sent for empty session, got %d", mode, got)
		}
		// SessionsDone must not be incremented; there was no traffic to complete.
		if got := mc.C.SessionsDone.Load(); got != 0 {
			t.Errorf("mode=%s: SessionsDone should be 0 for empty session, got %d", mode, got)
		}
	}
}
