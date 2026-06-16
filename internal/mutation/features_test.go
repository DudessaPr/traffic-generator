package mutation

import (
	"net"
	"testing"

	"tgen/internal/config"
)

// TestResetCache verifies that ResetCache empties the plan cache and that
// PlanFor continues to work correctly after a reset.
func TestResetCache(t *testing.T) {
	m, err := New(config.MutationConfig{TTL: 64})
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6)

	m.PlanFor(sess)
	if got := m.CacheLen(); got != 1 {
		t.Fatalf("CacheLen after first PlanFor: want 1, got %d", got)
	}

	m.ResetCache()
	if got := m.CacheLen(); got != 0 {
		t.Fatalf("CacheLen after ResetCache: want 0, got %d", got)
	}

	// PlanFor must still work and re-populate the cache.
	plan := m.PlanFor(sess)
	if plan.TTL != 64 {
		t.Errorf("TTL after reset: want 64, got %d", plan.TTL)
	}
	if got := m.CacheLen(); got != 1 {
		t.Errorf("CacheLen after PlanFor post-reset: want 1, got %d", got)
	}
}

// TestIPPoolPerIter verifies that resetting the cache causes the mutator to
// draw fresh IPs from the pool. With a pool of multiple distinct addresses,
// repeated PlanFor calls after ResetCache will eventually pick different IPs.
func TestIPPoolPerIter(t *testing.T) {
	cfg := config.MutationConfig{
		SrcIPPool: []string{
			"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
			"10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
		},
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("192.168.1.1", "10.10.0.1", 5000, 80, 6)

	firstPlan := m.PlanFor(sess)
	firstIP := firstPlan.SrcIP.String()

	// Try up to 50 resets; with an 8-address pool the probability that all
	// 50 draws pick the same address is (1/8)^50 ≈ 10^-45 — negligible.
	differentSeen := false
	for i := 0; i < 50; i++ {
		m.ResetCache()
		p := m.PlanFor(sess)
		if p.SrcIP.String() != firstIP {
			differentSeen = true
			break
		}
	}
	if !differentSeen {
		t.Error("ip_pool_per_iter: after 50 resets, PlanFor always returned the same IP — pool randomisation is broken")
	}
}

// TestPoolStats verifies PoolStats returns the correct pool sizes.
func TestPoolStats(t *testing.T) {
	cfg := config.MutationConfig{
		SrcIPPool: []string{"10.0.0.0/28"}, // 14 usable hosts in /28
		DstIPPool: []string{"10.0.1.1", "10.0.1.2"},
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srcLen, dstLen := m.PoolStats()
	if srcLen != 14 {
		t.Errorf("srcPool len: want 14, got %d", srcLen)
	}
	if dstLen != 2 {
		t.Errorf("dstPool len: want 2, got %d", dstLen)
	}
}

// TestIPv6PoolExpansion verifies that IPv6 CIDRs are correctly expanded without
// calling To4() on IPv6 addresses (which would silently produce empty IPs).
func TestIPv6PoolExpansion(t *testing.T) {
	// /126 has 4 addresses; no boundary skipping for IPv6.
	cfg := config.MutationConfig{
		SrcIPPool: []string{"2001:db8::/126"},
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New with IPv6 CIDR: %v", err)
	}
	srcLen, _ := m.PoolStats()
	if srcLen != 4 {
		t.Errorf("IPv6 /126 pool: want 4 addresses, got %d", srcLen)
	}

	// Every IP in the pool must be a valid 16-byte IPv6 address (non-empty).
	// We verify by calling PlanFor many times and checking that SrcIP is non-nil
	// and has length 16 each time.
	sess := makeTestSession("192.168.0.1", "10.0.0.1", 1234, 80, 6)
	for i := 0; i < 20; i++ {
		m.ResetCache()
		plan := m.PlanFor(sess)
		if plan.SrcIP == nil {
			t.Fatal("IPv6 pool produced nil SrcIP")
		}
		if len(plan.SrcIP) != 16 {
			t.Errorf("IPv6 pool produced %d-byte IP (want 16): %v", len(plan.SrcIP), plan.SrcIP)
		}
	}
}

// TestIPv6PoolPlainAddress verifies that a plain IPv6 address (not a CIDR) is
// accepted and stored correctly in the pool.
func TestIPv6PoolPlainAddress(t *testing.T) {
	cfg := config.MutationConfig{
		DstIPPool: []string{"2001:db8::1"},
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New with plain IPv6 address: %v", err)
	}
	_, dstLen := m.PoolStats()
	if dstLen != 1 {
		t.Errorf("single IPv6 address pool: want 1, got %d", dstLen)
	}
}

// TestIPPoolLimit verifies that the configurable CIDR cap is honoured.
func TestIPPoolLimit(t *testing.T) {
	// /24 has 254 usable hosts by default; cap to 10.
	cfg := config.MutationConfig{
		SrcIPPool:   []string{"10.0.0.0/24"},
		IPPoolLimit: 10,
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srcLen, _ := m.PoolStats()
	if srcLen != 10 {
		t.Errorf("pool with limit=10: want 10, got %d", srcLen)
	}
}

// TestDstMACPlan verifies that a DstMAC set in MutationConfig propagates into
// every plan returned by PlanFor.
func TestDstMACPlan(t *testing.T) {
	cfg := config.MutationConfig{DstMAC: "aa:bb:cc:dd:ee:ff"}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := makeTestSession("10.0.0.1", "10.0.0.2", 1234, 80, 6)
	plan := m.PlanFor(sess)

	want := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if len(plan.DstMAC) != 6 {
		t.Fatalf("DstMAC len: want 6, got %d", len(plan.DstMAC))
	}
	for i, b := range want {
		if plan.DstMAC[i] != b {
			t.Errorf("DstMAC[%d]: want %02x, got %02x", i, b, plan.DstMAC[i])
		}
	}
}
