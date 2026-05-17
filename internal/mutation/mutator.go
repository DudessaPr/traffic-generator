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

// Plan is the resolved set of L3/L4 replacements for one session.
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
}

// Mutator resolves and caches per-session mutation plans, ensuring that
// every packet belonging to the same flow receives identical rewrites.
type Mutator struct {
	cfg     config.MutationConfig
	mu      sync.Mutex
	cache   map[session.Key]Plan
	srcPool []net.IP // expanded from src_ip_pool CIDRs
	dstPool []net.IP // expanded from dst_ip_pool CIDRs
	// rng is accessed only inside buildPlan, which is always called while mu
	// is held (via PlanFor). No separate lock is needed for rng itself.
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
	var err error
	if m.srcPool, err = expandPool(cfg.SrcIPPool); err != nil {
		return nil, fmt.Errorf("src_ip_pool: %w", err)
	}
	if m.dstPool, err = expandPool(cfg.DstIPPool); err != nil {
		return nil, fmt.Errorf("dst_ip_pool: %w", err)
	}
	return m, nil
}

// PlanFor returns the mutation plan for sess, creating and caching it on first call.
func (m *Mutator) PlanFor(sess *session.Session) Plan {
	key := sess.Key
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.cache[key]; ok {
		return p
	}
	p := m.buildPlan(sess)
	m.cache[key] = p
	return p
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
			return plan
		}
	}

	// Global / pool-based mutations.
	if m.cfg.SrcIP != "" {
		if ip := net.ParseIP(m.cfg.SrcIP); ip != nil {
			plan.SrcIP = ip.To4()
			if plan.SrcIP == nil {
				plan.SrcIP = ip.To16()
			}
		}
	} else if len(m.srcPool) > 0 {
		plan.SrcIP = m.srcPool[m.rng.Intn(len(m.srcPool))]
	}

	if m.cfg.DstIP != "" {
		if ip := net.ParseIP(m.cfg.DstIP); ip != nil {
			plan.DstIP = ip.To4()
			if plan.DstIP == nil {
				plan.DstIP = ip.To16()
			}
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

	return plan
}

// applyReplace overwrites plan fields with non-zero values from r.
func applyReplace(plan *Plan, r config.ReplaceValues) {
	if r.SrcIP != "" {
		if ip := net.ParseIP(r.SrcIP); ip != nil {
			plan.SrcIP = ip.To4()
			if plan.SrcIP == nil {
				plan.SrcIP = ip.To16()
			}
		}
	}
	if r.DstIP != "" {
		if ip := net.ParseIP(r.DstIP); ip != nil {
			plan.DstIP = ip.To4()
			if plan.DstIP == nil {
				plan.DstIP = ip.To16()
			}
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
// CIDRs larger than /24 are capped at 256 hosts to avoid memory blowout.
func expandPool(pool []string) ([]net.IP, error) {
	const maxPerCIDR = 256
	var out []net.IP
	for _, s := range pool {
		ip := net.ParseIP(s)
		if ip != nil {
			out = append(out, ip.To4())
			continue
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q", s)
		}
		ones, _ := cidr.Mask.Size()
		// For prefix lengths shorter than /31 the first address is the network
		// address and the last is the broadcast address; neither is a valid host.
		// /31 (point-to-point) and /32 (single host) have no boundary addresses,
		// so skipBoundaries is false for those and the single IP is included.
		skipBoundaries := ones < 31
		networkAddr := cidr.IP.Mask(cidr.Mask)
		broadcast := make(net.IP, len(networkAddr))
		for i := range networkAddr {
			broadcast[i] = networkAddr[i] | ^cidr.Mask[i]
		}
		count := 0
		for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); incrementIP(ip) {
			if count >= maxPerCIDR {
				break
			}
			if skipBoundaries && (ip.Equal(networkAddr) || ip.Equal(broadcast)) {
				continue
			}
			out = append(out, append(net.IP(nil), ip.To4()...))
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
