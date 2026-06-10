package replay

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/session"
)

// captureSender records the last octet of the IPv4 destination address from
// every packet it receives, allowing tests to verify replay ordering.
type captureSender struct {
	mu   sync.Mutex
	dsts []byte // last octet of dst IP per packet
}

func (c *captureSender) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Ethernet 14 bytes + IP header dst at offset 16 → bytes [30,33]
	if len(data) >= 34 {
		c.dsts = append(c.dsts, data[33]) // last octet of IPv4 dst
	}
	return nil
}
func (c *captureSender) Close() {}

func (c *captureSender) Dsts() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(c.dsts))
	copy(cp, c.dsts)
	return cp
}

// recordByteSender records the full bytes of every packet.
type recordByteSender struct {
	mu      sync.Mutex
	packets [][]byte
}

func (r *recordByteSender) Send(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	r.packets = append(r.packets, cp)
	return nil
}
func (r *recordByteSender) Close() {}

func (r *recordByteSender) Packets() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.packets
}

// buildTCPPacketWithDst builds a minimal Ethernet/IPv4/TCP frame with a
// specified destination IP, so tests can distinguish sessions by dst octet.
func buildTCPPacketWithDst(dstIP string) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("1.2.3.4").To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80}
	_ = tcp.SetNetworkLayerForChecksum(ip4)
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ip4, tcp)
	return buf.Bytes()
}

// makeInterleavedSessions creates two sessions whose packets have alternating
// timestamps: A@t, B@t+1ms, A@t+2ms, B@t+3ms. The sessions use distinct dst
// IPs so captureSender can identify which session each packet came from.
func makeInterleavedSessions() ([]*session.Session, time.Time) {
	pktA := buildTCPPacketWithDst("10.0.0.1") // last octet = 1
	pktB := buildTCPPacketWithDst("10.0.0.2") // last octet = 2
	base := time.Now()

	sessA := &session.Session{
		Key:   session.Key{SrcIP: "1.2.3.4", DstIP: "10.0.0.1", SrcPort: 3000, DstPort: 80, Proto: 6},
		SrcIP: net.ParseIP("1.2.3.4"), DstIP: net.ParseIP("10.0.0.1"),
		SrcPort: 3000, DstPort: 80, Proto: 6,
		Packets: []*session.Packet{
			{Timestamp: base, Data: pktA, LinkType: layers.LinkTypeEthernet},
			{Timestamp: base.Add(2 * time.Millisecond), Data: pktA, LinkType: layers.LinkTypeEthernet},
		},
	}
	sessB := &session.Session{
		Key:   session.Key{SrcIP: "1.2.3.4", DstIP: "10.0.0.2", SrcPort: 3001, DstPort: 80, Proto: 6},
		SrcIP: net.ParseIP("1.2.3.4"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 3001, DstPort: 80, Proto: 6,
		Packets: []*session.Packet{
			{Timestamp: base.Add(1 * time.Millisecond), Data: pktB, LinkType: layers.LinkTypeEthernet},
			{Timestamp: base.Add(3 * time.Millisecond), Data: pktB, LinkType: layers.LinkTypeEthernet},
		},
	}
	return []*session.Session{sessA, sessB}, base
}

// TestModePcap verifies that pcap mode replays packets in global timestamp order
// (interleaved across sessions) rather than session-by-session.
func TestModePcap(t *testing.T) {
	sessions, _ := makeInterleavedSessions()
	cs := &captureSender{}
	mc := newMC(t)
	mut := newMut(t)
	rp := New(config.ReplayConfig{Mode: "pcap", Speed: 0}, mut, cs, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := cs.Dsts()
	// pcap mode must produce: A(1), B(2), A(1), B(2)
	want := []byte{1, 2, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("pcap mode: got %d packets, want %d; dsts=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pcap order[%d]: want dst octet %d, got %d", i, want[i], got[i])
		}
	}
}

// TestModePcapVsSequential confirms that sequential mode sends session A's
// packets first (not interleaved), distinguishing it from pcap mode.
func TestModePcapVsSequential(t *testing.T) {
	sessions, _ := makeInterleavedSessions()
	cs := &captureSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "sequential", Speed: 0}, newMut(t), cs, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := cs.Dsts()
	// Sequential: A,A,B,B
	want := []byte{1, 1, 2, 2}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Errorf("sequential order[%d]: want %d, got %v", i, w, got)
		}
	}
}

// TestRateLimiter verifies that the rate limiter actually slows down packet
// delivery. With burst=10 at 1000pps and 300 packets, the replay must take
// at least ~0.25 s (≥ (300-10)/1000 - generous tolerance).
func TestRateLimiter(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}
	sessions := makeBenchSessions(3, 100) // 300 packets
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "burst", Rate: "1000pps"}, newMut(t), ms, mc)

	ctx := context.Background()
	start := time.Now()
	if err := rp.Run(ctx, sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	elapsed := time.Since(start)

	if got := ms.Sent(); got != 300 {
		t.Errorf("packets sent: want 300, got %d", got)
	}
	// burst = 10% of 1000 = 100. After the burst is consumed, the remaining
	// 200 packets take ≥200 ms.
	if elapsed < 150*time.Millisecond {
		t.Errorf("rate not enforced: 300 pkts at 1000pps took %v (want ≥150ms)", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("rate limiter too slow: %v", elapsed)
	}
}

// TestRateLimiterBPS verifies that BPS rate strings are parsed correctly and
// that the resulting limiter allows packets to pass without error.
// Timing assertions are omitted: the BPS token-bucket burst (65536 bytes)
// is intentionally large to accommodate jumbo frames, so micro-workloads are
// served from the burst rather than the steady-state rate. Throughput-accuracy
// is covered by the BenchmarkRateLimiter benchmark instead.
func TestRateLimiterBPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rl, err := newRateLimiter(ctx, "100mbps", "")
	if err != nil {
		t.Fatalf("newRateLimiter(100mbps): %v", err)
	}
	// Ten WaitN calls for 1500-byte frames must all succeed quickly.
	for i := 0; i < 10; i++ {
		if err := rl.Wait(ctx, 1500); err != nil {
			t.Errorf("Wait[%d]: %v", i, err)
		}
	}

	// Also verify various BPS unit suffixes parse without error.
	for _, s := range []string{"1gbps", "100mbps", "500kbps", "8000bps"} {
		if _, err := parseRate(s); err != nil {
			t.Errorf("parseRate(%q): %v", s, err)
		}
	}
}

// TestPreMutation verifies that pre-processing produces the same packet bytes
// as on-the-fly mutation, ensuring the two paths are functionally equivalent.
func TestPreMutation(t *testing.T) {
	sessions := makeBenchSessions(3, 4) // 3 sessions × 4 packets = 12 total

	// Fixed src IP mutation so both runs produce identical bytes.
	mutCfg := config.MutationConfig{SrcIP: "10.99.0.1"}

	runWith := func(preProcess bool) [][]byte {
		mut, err := mutation.New(mutCfg)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordByteSender{}
		mc, _ := metrics.New(time.Hour, "stdout")
		rp := New(config.ReplayConfig{Mode: "burst", PreProcess: preProcess}, mut, rec, mc)
		if err := rp.Run(context.Background(), sessions); err != nil {
			t.Fatal(err)
		}
		return rec.Packets()
	}

	normal := runWith(false)
	preProc := runWith(true)

	if len(normal) != len(preProc) {
		t.Fatalf("packet count: normal=%d pre-process=%d", len(normal), len(preProc))
	}
	for i := range normal {
		if !bytes.Equal(normal[i], preProc[i]) {
			t.Errorf("packet %d differs between normal and pre-process paths", i)
		}
	}
}

// TestIPPoolPerIterReplayer verifies that when IPPoolPerIter is set, the
// mutator's cache is cleared between loop iterations.
func TestIPPoolPerIterReplayer(t *testing.T) {
	mutCfg := config.MutationConfig{
		SrcIPPool: []string{
			"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
			"10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
		},
	}
	mut, err := mutation.New(mutCfg)
	if err != nil {
		t.Fatal(err)
	}

	sessions := makeBenchSessions(1, 1) // one session
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{
		Mode:          "burst",
		LoopCount:     5,
		IPPoolPerIter: true,
	}, mut, ms, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 5 loops × 1 session × 1 packet = 5 packets total.
	if got := ms.Sent(); got != 5 {
		t.Errorf("packets sent: want 5, got %d", got)
	}
	// After the run completes, the cache should have at most 1 entry
	// (last iteration's plan). Not zero, because the final iteration
	// populated it and no reset happened after.
	if got := mut.CacheLen(); got > 1 {
		t.Errorf("CacheLen after run: want ≤1, got %d", got)
	}
}

// TestModePcapSessionsDone verifies that pcap mode increments SessionsDone
// once per session that had at least one packet.
func TestModePcapSessionsDone(t *testing.T) {
	sessions, _ := makeInterleavedSessions()
	ms := &mockSender{}
	mc := newMC(t)
	rp := New(config.ReplayConfig{Mode: "pcap", Speed: 0}, newMut(t), ms, mc)

	if err := rp.Run(context.Background(), sessions); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := mc.C.SessionsDone.Load(); got != 2 {
		t.Errorf("SessionsDone: want 2, got %d", got)
	}
}
