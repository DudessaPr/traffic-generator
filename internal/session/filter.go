package session

import (
	"fmt"
	"time"
)

// Filter holds parsed selection criteria for sessions.
// Zero/empty values are treated as "no constraint" for that field.
type Filter struct {
	MinDuration time.Duration
	MaxDuration time.Duration
	StartAfter  time.Time
	StartBefore time.Time
	// Protocols is a set of lower-case protocol names to include.
	// Empty means all protocols pass.
	Protocols map[string]bool
}

// Apply returns the subset of sessions that satisfy all filter criteria.
// Returns the original slice unchanged when no constraints are set.
func (f *Filter) Apply(sessions []*Session) []*Session {
	if f.isEmpty() {
		return sessions
	}
	out := make([]*Session, 0, len(sessions))
	for _, s := range sessions {
		if f.match(s) {
			out = append(out, s)
		}
	}
	return out
}

func (f *Filter) match(s *Session) bool {
	d := s.Duration()
	if f.MinDuration > 0 && d < f.MinDuration {
		return false
	}
	if f.MaxDuration > 0 && d > f.MaxDuration {
		return false
	}

	// Both boundaries are exclusive: StartAfter filters sessions at or before the
	// boundary; StartBefore filters sessions strictly after it.
	if !f.StartAfter.IsZero() && !s.StartTime.After(f.StartAfter) {
		return false
	}
	if !f.StartBefore.IsZero() && s.StartTime.After(f.StartBefore) {
		return false
	}

	// Unknown protocols fall back to "protoN" so callers can still filter
	// on protocols not listed in protoByNumber (e.g. "proto47" for GRE).
	if len(f.Protocols) > 0 {
		name, known := ProtoName[s.Proto]
		if !known {
			name = fmt.Sprintf("proto%d", s.Proto)
		}
		if !f.Protocols[name] {
			return false
		}
	}
	return true
}

func (f *Filter) isEmpty() bool {
	return f.MinDuration == 0 &&
		f.MaxDuration == 0 &&
		f.StartAfter.IsZero() &&
		f.StartBefore.IsZero() &&
		len(f.Protocols) == 0
}
