package mutation

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"tgen/internal/config"
	"tgen/internal/session"
)

// Plan is the resolved set of L2/L3/L4 replacements for one session.
// A nil IP field means "keep the original". Zero numeric fields mean "keep original".
type Plan struct {
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	TTL           uint8  // 0 = keep original
	DSCP          uint8  // 0 = keep original (DSCP 0 is Default Forwarding but indistinguishable from "unset")
	TCPSetFlags   string // comma-separated flag names to force on
	TCPClearFlags string // comma-separated flag names to force off
	TCPWindow     uint16 // 0 = keep original
	DstMAC        net.HardwareAddr // if non-nil, rewrite Ethernet dst MAC
}

// Mutator resolves and caches per-session mutation plans, ensuring that
// every packet belonging to the same flow receives identical rewrites.
type Mutator struct {
	cfg     config.MutationConfig
	mu      sync.RWMutex
	cache   map[session.Key]Plan
	srcPool []net.IP         // expanded from src_ip_pool CIDRs
	dstPool []net.IP         // expanded from dst_ip_pool CIDRs
	dstMAC  net.HardwareAddr // parsed once from cfg.DstMAC
	// rng is accessed only inside buildPlan, which is always called under the
	// write lock (mu.Lock). No separate lock is needed for rng itself.
	rng *rand.Rand
}

// New builds a Mutator from the given MutationConfig.
func New(cfg config.MutationConfig) (*Mutator, error) {
	m := &Mutator{
		cfg:   cfg,
		cache: make(map[session.Key]Plan),
		// Seed with wall-clock nanoseconds so pool selection differs on every run.
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	if cfg.DstMAC != "" {
		mac, err := net.ParseMAC(cfg.DstMAC)
		if err != nil {
			return nil, fmt.Errorf("dst_mac: %w", err)
		}
		m.dstMAC = mac
	}
	var err error
	if m.srcPool, err = expandPool(cfg.SrcIPPool, cfg.IPPoolLimit); err != nil {
		return nil, fmt.Errorf("src_ip_pool: %w", err)
	}
	if m.dstPool, err = expandPool(cfg.DstIPPool, cfg.IPPoolLimit); err != nil {
		return nil, fmt.Errorf("dst_ip_pool: %w", err)
	}
	return m, nil
}

// PlanFor returns the mutation plan for sess, creating and caching it on first call.
// Uses double-checked locking: concurrent cache-hit reads proceed in parallel
// under RLock; only cache misses (rare after warm-up) compete for the write lock.
func (m *Mutator) PlanFor(sess *session.Session) Plan {
	key := sess.Key

	m.mu.RLock()
	if p, ok := m.cache[key]; ok {
		m.mu.RUnlock()
		return p
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.cache[key]; ok { // another goroutine may have built the plan while we waited
		return p
	}
	p := m.buildPlan(sess)
	m.cache[key] = p
	return p
}

// ResetCache discards all cached plans. The next PlanFor call for any session
// will draw a fresh random IP from the pool, enabling per-iteration IP diversity
// when used with --ip-pool-per-iter.
func (m *Mutator) ResetCache() {
	m.mu.Lock()
	m.cache = make(map[session.Key]Plan)
	m.mu.Unlock()
}

// CacheLen returns the number of currently cached plans.
func (m *Mutator) CacheLen() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// PoolStats returns the number of IPs in the source and destination pools.
func (m *Mutator) PoolStats() (srcLen, dstLen int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.srcPool), len(m.dstPool)
}

func (m *Mutator) buildPlan(sess *session.Session) Plan {
	plan := Plan{
		SrcIP:   append(net.IP(nil), sess.SrcIP...),
		DstIP:   append(net.IP(nil), sess.DstIP...),
		SrcPort: sess.SrcPort,
		DstPort: sess.DstPort,
	}

	// Rule-based mutations are evaluated first and short-circuit on first match.
	for _, rule := range m.cfg.Rules {
		if matchesCondition(rule.Match, sess) {
			applyReplace(&plan, rule.Replace)
			// DstMAC global override still applies even for rule-matched sessions.
			if len(m.dstMAC) > 0 {
				plan.DstMAC = append(net.HardwareAddr(nil), m.dstMAC...)
			}
			return plan
		}
	}

	// Global / pool-based mutations.
	if m.cfg.SrcIP != "" {
		if ip := net.ParseIP(m.cfg.SrcIP); ip != nil {
			plan.SrcIP = normaliseIP(ip)
		}
	} else if len(m.srcPool) > 0 {
		plan.SrcIP = m.srcPool[m.rng.Intn(len(m.srcPool))]
	}

	if m.cfg.DstIP != "" {
		if ip := net.ParseIP(m.cfg.DstIP); ip != nil {
			plan.DstIP = normaliseIP(ip)
		}
	} else if len(m.dstPool) > 0 {
		plan.DstIP = m.dstPool[m.rng.Intn(len(m.dstPool))]
	}

	if m.cfg.SrcPortMin > 0 {
		hi := m.cfg.SrcPortMax
		if hi == 0 || hi < m.cfg.SrcPortMin {
			hi = 65535
		}
		plan.SrcPort = m.cfg.SrcPortMin + uint16(m.rng.Intn(int(hi-m.cfg.SrcPortMin)+1))
	}
	if m.cfg.DstPort != 0 {
		plan.DstPort = m.cfg.DstPort
	}

	if m.cfg.TTL != 0 {
		plan.TTL = m.cfg.TTL
	}
	if m.cfg.DSCP != 0 {
		plan.DSCP = m.cfg.DSCP
	}
	if m.cfg.TCPSetFlags != "" {
		plan.TCPSetFlags = m.cfg.TCPSetFlags
	}
	if m.cfg.TCPClearFlags != "" {
		plan.TCPClearFlags = m.cfg.TCPClearFlags
	}
	if m.cfg.TCPWindow != 0 {
		plan.TCPWindow = m.cfg.TCPWindow
	}
	if len(m.dstMAC) > 0 {
		plan.DstMAC = append(net.HardwareAddr(nil), m.dstMAC...)
	}

	return plan
}

// normaliseIP returns a 4-byte slice for IPv4-mappable addresses, 16-byte otherwise.
func normaliseIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// applyReplace overwrites plan fields with non-zero values from r.
func applyReplace(plan *Plan, r config.ReplaceValues) {
	if r.SrcIP != "" {
		if ip := net.ParseIP(r.SrcIP); ip != nil {
			plan.SrcIP = normaliseIP(ip)
		}
	}
	if r.DstIP != "" {
		if ip := net.ParseIP(r.DstIP); ip != nil {
			plan.DstIP = normaliseIP(ip)
		}
	}
	if r.SrcPort != 0 {
		plan.SrcPort = r.SrcPort
	}
	if r.DstPort != 0 {
		plan.DstPort = r.DstPort
	}
	if r.TTL != 0 {
		plan.TTL = r.TTL
	}
	if r.DSCP != 0 {
		plan.DSCP = r.DSCP
	}
	if r.TCPSetFlags != "" {
		plan.TCPSetFlags = r.TCPSetFlags
	}
	if r.TCPClearFlags != "" {
		plan.TCPClearFlags = r.TCPClearFlags
	}
	if r.TCPWindow != 0 {
		plan.TCPWindow = r.TCPWindow
	}
}

// matchesCondition returns true when sess satisfies all non-empty fields in cond.
func matchesCondition(cond config.MatchCondition, sess *session.Session) bool {
	if cond.SrcIP != "" && !ipMatchesCIDROrAddr(cond.SrcIP, sess.SrcIP) {
		return false
	}
	if cond.DstIP != "" && !ipMatchesCIDROrAddr(cond.DstIP, sess.DstIP) {
		return false
	}
	if cond.SrcPort != 0 && cond.SrcPort != sess.SrcPort {
		return false
	}
	if cond.DstPort != 0 && cond.DstPort != sess.DstPort {
		return false
	}
	if cond.Proto != "" {
		name, ok := session.ProtoName[sess.Proto]
		if !ok {
			name = fmt.Sprintf("proto%d", sess.Proto)
		}
		if name != cond.Proto {
			return false
		}
	}
	return true
}

func ipMatchesCIDROrAddr(s string, ip net.IP) bool {
	if _, cidr, err := net.ParseCIDR(s); err == nil {
		return cidr.Contains(ip)
	}
	if parsed := net.ParseIP(s); parsed != nil {
		return parsed.Equal(ip)
	}
	return false
}

// expandPool converts a list of IP strings / CIDRs into a flat list of host IPs.
// limit caps the number of hosts expanded per CIDR (0 → default 256, max 65536).
// Both IPv4 and IPv6 CIDRs are supported; for IPv4 network/broadcast addresses
// are excluded for prefix lengths < /31.
func expandPool(pool []string, limit int) ([]net.IP, error) {
	const defaultLimit = 256
	const maxLimit = 65536
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	var out []net.IP
	for _, s := range pool {
		ip := net.ParseIP(s)
		if ip != nil {
			out = append(out, normaliseIP(ip))
			continue
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q", s)
		}

		isIPv6 := cidr.IP.To4() == nil
		ones, _ := cidr.Mask.Size()

		// For IPv4, skip network and broadcast addresses for prefix lengths < /31.
		// /31 (point-to-point) and /32 (single host) have no boundary addresses.
		// For IPv6, all addresses including the first and last are valid hosts.
		skipBoundaries := !isIPv6 && ones < 31

		networkAddr := cidr.IP.Mask(cidr.Mask)
		broadcast := make(net.IP, len(networkAddr))
		for i := range networkAddr {
			broadcast[i] = networkAddr[i] | ^cidr.Mask[i]
		}

		count := 0
		for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); incrementIP(ip) {
			if count >= limit {
				break
			}
			if skipBoundaries && (ip.Equal(networkAddr) || ip.Equal(broadcast)) {
				continue
			}
			if isIPv6 {
				out = append(out, append(net.IP(nil), ip...))
			} else {
				out = append(out, append(net.IP(nil), ip.To4()...))
			}
			count++
		}
	}
	return out, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
