package mutation

import (
	"net"
	"testing"

	"tgen/internal/config"
	"tgen/internal/session"
)

func makeTestSession(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) *session.Session {
	return &session.Session{
		Proto:   proto,
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

// TestMutatorNewFields verifies that TTL, DSCP, TCPSetFlags, TCPClearFlags, and
// TCPWindow propagate from MutationConfig into the per-session Plan.
func TestMutatorNewFields(t *testing.T) {
	cfg := config.MutationConfig{
		TTL:           128,
		DSCP:          46,
		TCPSetFlags:   "SYN,ACK",
		TCPClearFlags: "RST",
		TCPWindow:     65535,
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6)
	plan := m.PlanFor(sess)

	if plan.TTL != 128 {
		t.Errorf("TTL: want 128, got %d", plan.TTL)
	}
	if plan.DSCP != 46 {
		t.Errorf("DSCP: want 46, got %d", plan.DSCP)
	}
	if plan.TCPSetFlags != "SYN,ACK" {
		t.Errorf("TCPSetFlags: want SYN,ACK, got %q", plan.TCPSetFlags)
	}
	if plan.TCPClearFlags != "RST" {
		t.Errorf("TCPClearFlags: want RST, got %q", plan.TCPClearFlags)
	}
	if plan.TCPWindow != 65535 {
		t.Errorf("TCPWindow: want 65535, got %d", plan.TCPWindow)
	}
}

// TestMutatorZeroNewFieldsKeepOriginal verifies that zero/empty config values
// for the new fields leave the plan fields at their zero/empty state (keeping
// original packet values at Apply time).
func TestMutatorZeroNewFieldsKeepOriginal(t *testing.T) {
	cfg := config.MutationConfig{} // all new fields at zero/empty
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6)
	plan := m.PlanFor(sess)

	if plan.TTL != 0 {
		t.Errorf("TTL: want 0 (keep original), got %d", plan.TTL)
	}
	if plan.DSCP != 0 {
		t.Errorf("DSCP: want 0 (keep original), got %d", plan.DSCP)
	}
	if plan.TCPSetFlags != "" {
		t.Errorf("TCPSetFlags: want empty, got %q", plan.TCPSetFlags)
	}
	if plan.TCPClearFlags != "" {
		t.Errorf("TCPClearFlags: want empty, got %q", plan.TCPClearFlags)
	}
	if plan.TCPWindow != 0 {
		t.Errorf("TCPWindow: want 0 (keep original), got %d", plan.TCPWindow)
	}
}

// TestMutatorRuleApplyReplace verifies that rule-based replace values for the
// new fields are applied by applyReplace and take precedence over global config.
func TestMutatorRuleApplyReplace(t *testing.T) {
	cfg := config.MutationConfig{
		TTL:  64, // global — overridden by rule
		DSCP: 10, // global — overridden by rule
		Rules: []config.MutationRule{
			{
				Match: config.MatchCondition{Proto: "tcp"},
				Replace: config.ReplaceValues{
					TTL:           200,
					DSCP:          46,
					TCPSetFlags:   "ACK",
					TCPClearFlags: "RST",
					TCPWindow:     32768,
				},
			},
		},
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6) // TCP
	plan := m.PlanFor(sess)

	if plan.TTL != 200 {
		t.Errorf("TTL: want 200 (from rule), got %d", plan.TTL)
	}
	if plan.DSCP != 46 {
		t.Errorf("DSCP: want 46 (from rule), got %d", plan.DSCP)
	}
	if plan.TCPSetFlags != "ACK" {
		t.Errorf("TCPSetFlags: want ACK, got %q", plan.TCPSetFlags)
	}
	if plan.TCPClearFlags != "RST" {
		t.Errorf("TCPClearFlags: want RST, got %q", plan.TCPClearFlags)
	}
	if plan.TCPWindow != 32768 {
		t.Errorf("TCPWindow: want 32768, got %d", plan.TCPWindow)
	}
}

// TestMutatorPlanCached verifies that PlanFor returns the same plan on repeated
// calls for the same session (plan is built once and cached).
func TestMutatorPlanCached(t *testing.T) {
	cfg := config.MutationConfig{TTL: 128, TCPWindow: 65535}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6)

	p1 := m.PlanFor(sess)
	p2 := m.PlanFor(sess)

	if p1.TTL != p2.TTL {
		t.Errorf("TTL: first=%d second=%d — plan not cached", p1.TTL, p2.TTL)
	}
	if p1.TCPWindow != p2.TCPWindow {
		t.Errorf("TCPWindow: first=%d second=%d — plan not cached", p1.TCPWindow, p2.TCPWindow)
	}
}
