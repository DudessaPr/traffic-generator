package session

import (
	"net"
	"testing"
	"time"
)

func makeSession(proto uint8, dur time.Duration, start time.Time) *Session {
	return &Session{
		Proto:     proto,
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		StartTime: start,
		EndTime:   start.Add(dur),
	}
}

func TestFilterEmpty(t *testing.T) {
	sessions := []*Session{
		makeSession(6, 2*time.Second, time.Now()),
		makeSession(17, 500*time.Millisecond, time.Now()),
	}
	f := &Filter{}
	got := f.Apply(sessions)
	if len(got) != len(sessions) {
		t.Fatalf("empty filter: want %d sessions, got %d", len(sessions), len(got))
	}
}

func TestFilterMinDuration(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		makeSession(6, 100*time.Millisecond, now),
		makeSession(6, 2*time.Second, now),
		makeSession(6, 5*time.Second, now),
	}
	f := &Filter{MinDuration: time.Second}
	got := f.Apply(sessions)
	if len(got) != 2 {
		t.Fatalf("min_duration: want 2, got %d", len(got))
	}
}

func TestFilterMaxDuration(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		makeSession(6, 100*time.Millisecond, now),
		makeSession(6, 2*time.Second, now),
		makeSession(6, 30*time.Second, now),
	}
	f := &Filter{MaxDuration: 5 * time.Second}
	got := f.Apply(sessions)
	if len(got) != 2 {
		t.Fatalf("max_duration: want 2, got %d", len(got))
	}
}

func TestFilterStartAfter(t *testing.T) {
	base := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	sessions := []*Session{
		makeSession(6, time.Second, base.Add(-time.Hour)),
		makeSession(6, time.Second, base),
		makeSession(6, time.Second, base.Add(time.Hour)),
	}
	f := &Filter{StartAfter: base}
	got := f.Apply(sessions)
	// sessions starting exactly at base are NOT after base, so only the +1h one passes
	if len(got) != 1 {
		t.Fatalf("start_after: want 1, got %d", len(got))
	}
}

func TestFilterProtocol(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		makeSession(6, time.Second, now),  // tcp
		makeSession(17, time.Second, now), // udp
		makeSession(1, time.Second, now),  // icmp
	}
	f := &Filter{Protocols: map[string]bool{"tcp": true}}
	got := f.Apply(sessions)
	if len(got) != 1 || got[0].Proto != 6 {
		t.Fatalf("proto filter: want 1 TCP session, got %d", len(got))
	}
}

// TestFilterEmptySession verifies that a session with zero packets passes an
// empty filter (filter.isEmpty() → return unchanged) and is excluded when
// MinDuration > 0 because its duration is 0. The decision: packet count is
// not a filter criterion; duration and protocol are.
func TestFilterEmptySession(t *testing.T) {
	noPackets := &Session{
		Proto:     6,
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		StartTime: time.Now(),
		EndTime:   time.Now(), // duration = 0
		// Packets is intentionally nil.
	}

	t.Run("empty filter passes empty session", func(t *testing.T) {
		f := &Filter{}
		got := f.Apply([]*Session{noPackets})
		if len(got) != 1 {
			t.Errorf("want 1, got %d", len(got))
		}
	})

	t.Run("min_duration excludes zero-duration session", func(t *testing.T) {
		f := &Filter{MinDuration: time.Second}
		got := f.Apply([]*Session{noPackets})
		if len(got) != 0 {
			t.Errorf("want 0, got %d", len(got))
		}
	})
}

// TestFilterUnknownProtocol verifies that protocols not listed in ProtoName
// fall back to the "proto<N>" naming convention so callers can still filter
// on them. Protocol 41 (IPv6-in-IPv4 encapsulation) is not in ProtoName
// and exercises the fmt.Sprintf("proto%d") fallback path.
func TestFilterUnknownProtocol(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		makeSession(41, time.Second, now), // 6in4 — absent from ProtoName, falls back to "proto41"
		makeSession(6, time.Second, now),  // TCP — named
	}
	f := &Filter{Protocols: map[string]bool{"proto41": true}}
	got := f.Apply(sessions)
	if len(got) != 1 {
		t.Fatalf("want 1 proto41 session, got %d", len(got))
	}
	if got[0].Proto != 41 {
		t.Errorf("want proto=41, got %d", got[0].Proto)
	}
}

// TestFilterBoundaryDuration verifies that the MinDuration check is exclusive
// (d < MinDuration), so a session whose duration equals MinDuration exactly
// is included (passes the filter).
func TestFilterBoundaryDuration(t *testing.T) {
	exact := time.Second
	now := time.Now()
	sessions := []*Session{
		makeSession(6, exact-time.Nanosecond, now), // 1 ns shorter → excluded
		makeSession(6, exact, now),                 // exactly equal → included
		makeSession(6, exact+time.Nanosecond, now), // 1 ns longer → included
	}
	f := &Filter{MinDuration: exact}
	got := f.Apply(sessions)
	if len(got) != 2 {
		t.Errorf("want 2 sessions (equal and longer), got %d", len(got))
	}
}

func TestFilterCombined(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		makeSession(6, 500*time.Millisecond, now),  // tcp, too short
		makeSession(6, 3*time.Second, now),          // tcp, ok
		makeSession(17, 3*time.Second, now),         // udp, filtered by proto
	}
	f := &Filter{
		MinDuration: time.Second,
		Protocols:   map[string]bool{"tcp": true},
	}
	got := f.Apply(sessions)
	if len(got) != 1 {
		t.Fatalf("combined filter: want 1, got %d", len(got))
	}
}
