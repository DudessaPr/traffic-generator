package generate

import (
	"context"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"tgen/internal/metrics"
)

var (
	testSrcMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testDstMAC = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
)

// discardSender is goroutine-safe so multi-worker tests pass -race.
type discardSender struct {
	n atomic.Int64
}

func (d *discardSender) Send([]byte) error { d.n.Add(1); return nil }
func (d *discardSender) Close()            {}
func (d *discardSender) Sent() int         { return int(d.n.Load()) }

func fixedRNG() *rand.Rand { return rand.New(rand.NewSource(42)) }

func newTestMC(t *testing.T) *metrics.Collector {
	t.Helper()
	mc, err := metrics.New(time.Hour, "stdout")
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

// decodePacket parses an Ethernet frame into its IPv4 layers for assertions.
func decodePacket(data []byte) (eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.TCP, udp *layers.UDP, icmp *layers.ICMPv4) {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if l := pkt.Layer(layers.LayerTypeEthernet); l != nil {
		eth, _ = l.(*layers.Ethernet)
	}
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip4, _ = l.(*layers.IPv4)
	}
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp, _ = l.(*layers.TCP)
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		udp, _ = l.(*layers.UDP)
	}
	if l := pkt.Layer(layers.LayerTypeICMPv4); l != nil {
		icmp, _ = l.(*layers.ICMPv4)
	}
	return
}

// decodeIPv6Packet parses an Ethernet frame into its IPv6 layers for assertions.
func decodeIPv6Packet(data []byte) (eth *layers.Ethernet, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP) {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if l := pkt.Layer(layers.LayerTypeEthernet); l != nil {
		eth, _ = l.(*layers.Ethernet)
	}
	if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		ip6, _ = l.(*layers.IPv6)
	}
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp, _ = l.(*layers.TCP)
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		udp, _ = l.(*layers.UDP)
	}
	return
}

// ---- ParseTemplate tests ----

func TestParseTemplate_Valid(t *testing.T) {
	cases := []struct {
		tmpl  string
		proto string
	}{
		{"tcp:src=10.0.0.1:dst=192.168.1.1:dport=443:flags=SYN", "tcp"},
		{"udp:src=10.0.0.0/24:dst=8.8.8.8:dport=53", "udp"},
		{"icmp:src=10.0.0.1:dst=192.168.1.1", "icmp"},
		{"tcp:src=10.0.0.0/8:dst=172.16.0.1:sport=1024-65535:dport=80:ttl=128:dscp=46:flags=SYN,ACK", "tcp"},
		{"UDP:src=10.1.2.3:dst=10.4.5.6:dport=123", "udp"},
		{"tcp6:src=2001:db8::1:dst=2001:db8::2:dport=443:flags=SYN", "tcp6"},
		{"udp6:src=2001:db8::/32:dst=2001:db8::1:dport=53", "udp6"},
		{"udp:src=10.0.0.1:dst=10.0.0.2:dport=80:size=512", "udp"},
	}
	for _, c := range cases {
		t.Run(c.tmpl, func(t *testing.T) {
			tmpl, err := ParseTemplate(c.tmpl)
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			if tmpl.proto != c.proto {
				t.Errorf("proto: want %q, got %q", c.proto, tmpl.proto)
			}
		})
	}
}

func TestParseTemplate_Invalid(t *testing.T) {
	cases := []struct {
		input string
		desc  string
	}{
		{"", "empty string"},
		{"sctp:src=10.0.0.1:dst=10.0.0.2", "unsupported proto"},
		{"tcp:dst=10.0.0.1", "missing src"},
		{"tcp:src=10.0.0.1", "missing dst"},
		{"tcp:src=bad:dst=10.0.0.1", "bad src IP"},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:dport=99999", "port out of range"},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:sport=100-50", "sport lo>hi"},
		{"udp:src=10.0.0.1:dst=10.0.0.2:flags=SYN", "flags on UDP"},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:dscp=64", "DSCP > 63"},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:junk", "field missing ="},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:unknown=1", "unknown field"},
		{"tcp:src=10.0.0.1:dst=10.0.0.2:flags=XMAS", "unknown flag"},
		{"tcp6:src=10.0.0.1:dst=2001:db8::1:dport=80", "IPv4 src for tcp6"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if _, err := ParseTemplate(c.input); err == nil {
				t.Errorf("ParseTemplate(%q) want error, got nil", c.input)
			}
		})
	}
}

// ---- IPv4 Build tests ----

func TestBuildTCP(t *testing.T) {
	tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=192.168.1.1:sport=12345:dport=443:flags=SYN:ttl=128:dscp=46")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(data) < 54 {
		t.Fatalf("packet too short: %d bytes", len(data))
	}
	eth, ip4, tcp, _, _ := decodePacket(data)
	if eth == nil || ip4 == nil || tcp == nil {
		t.Fatal("failed to decode TCP packet layers")
	}
	if ip4.SrcIP.String() != "10.0.0.1" {
		t.Errorf("src IP: want 10.0.0.1, got %s", ip4.SrcIP)
	}
	if ip4.DstIP.String() != "192.168.1.1" {
		t.Errorf("dst IP: want 192.168.1.1, got %s", ip4.DstIP)
	}
	if tcp.SrcPort != 12345 {
		t.Errorf("src port: want 12345, got %d", tcp.SrcPort)
	}
	if tcp.DstPort != 443 {
		t.Errorf("dst port: want 443, got %d", tcp.DstPort)
	}
	if !tcp.SYN {
		t.Error("SYN flag not set")
	}
	if tcp.ACK {
		t.Error("ACK flag unexpectedly set")
	}
	if ip4.TTL != 128 {
		t.Errorf("TTL: want 128, got %d", ip4.TTL)
	}
	if ip4.TOS>>2 != 46 {
		t.Errorf("DSCP: want 46, got %d", ip4.TOS>>2)
	}
}

func TestBuildUDP(t *testing.T) {
	tmpl, err := ParseTemplate("udp:src=10.0.0.1:dst=8.8.8.8:dport=53")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, ip4, _, udp, _ := decodePacket(data)
	if ip4 == nil || udp == nil {
		t.Fatal("failed to decode UDP packet layers")
	}
	if ip4.Protocol != layers.IPProtocolUDP {
		t.Errorf("IP protocol: want UDP, got %v", ip4.Protocol)
	}
	if udp.DstPort != 53 {
		t.Errorf("dst port: want 53, got %d", udp.DstPort)
	}
}

func TestBuildICMP(t *testing.T) {
	tmpl, err := ParseTemplate("icmp:src=10.0.0.1:dst=192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, ip4, _, _, icmp := decodePacket(data)
	if ip4 == nil || icmp == nil {
		t.Fatal("failed to decode ICMP packet layers")
	}
	if ip4.Protocol != layers.IPProtocolICMPv4 {
		t.Errorf("IP protocol: want ICMPv4, got %v", ip4.Protocol)
	}
	wantType := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
	if icmp.TypeCode != wantType {
		t.Errorf("ICMP type/code: want %v, got %v", wantType, icmp.TypeCode)
	}
}

// ---- IPv6 Build tests ----

func TestBuildIPv6TCP(t *testing.T) {
	tmpl, err := ParseTemplate("tcp6:src=2001:db8::1:dst=2001:db8::2:sport=12345:dport=443:flags=SYN")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, ip6, tcp, _ := decodeIPv6Packet(data)
	if ip6 == nil || tcp == nil {
		t.Fatal("failed to decode IPv6/TCP layers")
	}
	if ip6.SrcIP.String() != "2001:db8::1" {
		t.Errorf("src IP: want 2001:db8::1, got %s", ip6.SrcIP)
	}
	if ip6.DstIP.String() != "2001:db8::2" {
		t.Errorf("dst IP: want 2001:db8::2, got %s", ip6.DstIP)
	}
	if tcp.SrcPort != 12345 {
		t.Errorf("src port: want 12345, got %d", tcp.SrcPort)
	}
	if tcp.DstPort != 443 {
		t.Errorf("dst port: want 443, got %d", tcp.DstPort)
	}
	if !tcp.SYN {
		t.Error("SYN flag not set")
	}
}

func TestBuildIPv6UDP(t *testing.T) {
	tmpl, err := ParseTemplate("udp6:src=2001:db8::1:dst=2001:db8::2:dport=53")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, ip6, _, udp := decodeIPv6Packet(data)
	if ip6 == nil || udp == nil {
		t.Fatal("failed to decode IPv6/UDP layers")
	}
	if udp.DstPort != 53 {
		t.Errorf("dst port: want 53, got %d", udp.DstPort)
	}
}

func TestIPv6CIDRRandomisation(t *testing.T) {
	tmpl, err := ParseTemplate("tcp6:src=2001:db8::/48:dst=2001:db8::1:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	rng := fixedRNG()
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		data, err := tmpl.Build(testSrcMAC, testDstMAC, rng)
		if err != nil {
			t.Fatal(err)
		}
		_, ip6, _, _ := decodeIPv6Packet(data)
		if ip6 == nil {
			t.Fatal("no IPv6 layer")
		}
		seen[ip6.SrcIP.String()] = true
	}
	if len(seen) < 5 {
		t.Errorf("IPv6 CIDR randomisation: only %d distinct IPs in 20 packets", len(seen))
	}
}

// ---- Payload size tests ----

func TestPayloadSize(t *testing.T) {
	tmpl, err := ParseTemplate("udp:src=10.0.0.1:dst=10.0.0.2:dport=80:size=512")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet(14) + IPv4(20) + UDP(8) + payload(512)
	want := 14 + 20 + 8 + 512
	if len(data) != want {
		t.Errorf("packet size: want %d, got %d", want, len(data))
	}
}

func TestPayloadSizeTCP(t *testing.T) {
	tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=10.0.0.2:dport=80:size=100")
	if err != nil {
		t.Fatal(err)
	}
	data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
	if err != nil {
		t.Fatal(err)
	}
	// Ethernet(14) + IPv4(20) + TCP(20, no options) + payload(100)
	want := 14 + 20 + 20 + 100
	if len(data) != want {
		t.Errorf("packet size: want %d, got %d", want, len(data))
	}
}

// ---- IPv4 randomisation tests ----

func TestCIDRRandomisation(t *testing.T) {
	tmpl, err := ParseTemplate("udp:src=10.0.0.0/16:dst=192.168.0.0/24:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	rng := fixedRNG()
	seenSrc := make(map[string]bool)
	seenDst := make(map[string]bool)
	for i := 0; i < 30; i++ {
		data, err := tmpl.Build(testSrcMAC, testDstMAC, rng)
		if err != nil {
			t.Fatal(err)
		}
		_, ip4, _, _, _ := decodePacket(data)
		if ip4 == nil {
			t.Fatal("no IPv4 layer")
		}
		seenSrc[ip4.SrcIP.String()] = true
		seenDst[ip4.DstIP.String()] = true
	}
	if len(seenSrc) < 5 {
		t.Errorf("src CIDR: only %d distinct IPs in 30 packets", len(seenSrc))
	}
	if len(seenDst) < 5 {
		t.Errorf("dst CIDR: only %d distinct IPs in 30 packets", len(seenDst))
	}
}

func TestPortRange(t *testing.T) {
	tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=10.0.0.2:sport=8000-9000:dport=1-1023")
	if err != nil {
		t.Fatal(err)
	}
	rng := fixedRNG()
	seenSport := make(map[uint16]bool)
	seenDport := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		data, err := tmpl.Build(testSrcMAC, testDstMAC, rng)
		if err != nil {
			t.Fatal(err)
		}
		_, _, tcp, _, _ := decodePacket(data)
		if tcp == nil {
			t.Fatal("no TCP layer")
		}
		sp, dp := uint16(tcp.SrcPort), uint16(tcp.DstPort)
		if sp < 8000 || sp > 9000 {
			t.Errorf("sport %d outside [8000,9000]", sp)
		}
		if dp < 1 || dp > 1023 {
			t.Errorf("dport %d outside [1,1023]", dp)
		}
		seenSport[sp] = true
		seenDport[dp] = true
	}
	if len(seenSport) < 5 {
		t.Errorf("sport range: only %d distinct values in 100 packets", len(seenSport))
	}
	if len(seenDport) < 5 {
		t.Errorf("dport range: only %d distinct values in 100 packets", len(seenDport))
	}
}

func TestTCPFlags(t *testing.T) {
	cases := []struct {
		flags string
		check func(tcp *layers.TCP) bool
		desc  string
	}{
		{"SYN", func(tcp *layers.TCP) bool { return tcp.SYN && !tcp.ACK && !tcp.FIN }, "SYN only"},
		{"SYN,ACK", func(tcp *layers.TCP) bool { return tcp.SYN && tcp.ACK }, "SYN+ACK"},
		{"RST", func(tcp *layers.TCP) bool { return tcp.RST && !tcp.SYN }, "RST only"},
		{"FIN,ACK", func(tcp *layers.TCP) bool { return tcp.FIN && tcp.ACK }, "FIN+ACK"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=10.0.0.2:flags=" + c.flags)
			if err != nil {
				t.Fatal(err)
			}
			data, err := tmpl.Build(testSrcMAC, testDstMAC, fixedRNG())
			if err != nil {
				t.Fatal(err)
			}
			_, _, tcp, _, _ := decodePacket(data)
			if tcp == nil {
				t.Fatal("no TCP layer")
			}
			if !c.check(tcp) {
				t.Errorf("flag check failed for flags=%q", c.flags)
			}
		})
	}
}

// ---- Generator tests ----

func TestGeneratorCount(t *testing.T) {
	tmpl, err := ParseTemplate("udp:src=10.0.0.1:dst=10.0.0.2:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	g, err := New(Config{Count: 50}, tmpl, snd, testSrcMAC, testDstMAC, newTestMC(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if snd.Sent() != 50 {
		t.Errorf("packets sent: want 50, got %d", snd.Sent())
	}
}

func TestGeneratorContextCancel(t *testing.T) {
	tmpl, err := ParseTemplate("icmp:src=10.0.0.1:dst=10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	g, err := New(Config{Count: 0}, tmpl, snd, testSrcMAC, testDstMAC, newTestMC(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.Run(ctx); err == nil {
		t.Error("Run should return an error when ctx is cancelled")
	}
	if snd.Sent() == 0 {
		t.Error("no packets were sent before context cancel")
	}
}

func TestGeneratorMetrics(t *testing.T) {
	tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=10.0.0.2:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	mc := newTestMC(t)
	g, err := New(Config{Count: 100}, tmpl, snd, testSrcMAC, testDstMAC, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := mc.C.PacketsSent.Load(); got != 100 {
		t.Errorf("PacketsSent: want 100, got %d", got)
	}
	if got := mc.C.BytesSent.Load(); got == 0 {
		t.Error("BytesSent should be > 0")
	}
	if got := mc.C.Errors.Load(); got != 0 {
		t.Errorf("Errors: want 0, got %d", got)
	}
}

func TestMultiWorkerCount(t *testing.T) {
	tmpl, err := ParseTemplate("udp:src=10.0.0.1:dst=10.0.0.2:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	g, err := New(Config{Count: 100, Workers: 4}, tmpl, snd, testSrcMAC, testDstMAC, newTestMC(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if snd.Sent() != 100 {
		t.Errorf("packets sent: want 100, got %d", snd.Sent())
	}
}

func TestLoopMode(t *testing.T) {
	tmpl, err := ParseTemplate("icmp:src=10.0.0.1:dst=10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	g, err := New(Config{Count: 10, Loop: true, Workers: 1}, tmpl, snd, testSrcMAC, testDstMAC, newTestMC(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = g.Run(ctx) // context.Canceled is expected
	if snd.Sent() < 20 {
		t.Errorf("loop mode: want ≥20 packets (≥2 iterations), got %d", snd.Sent())
	}
}

func TestPreBuild(t *testing.T) {
	tmpl, err := ParseTemplate("tcp:src=10.0.0.1:dst=10.0.0.2:dport=80")
	if err != nil {
		t.Fatal(err)
	}
	snd := &discardSender{}
	g, err := New(Config{Count: 50, PreBuild: 20}, tmpl, snd, testSrcMAC, testDstMAC, newTestMC(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if snd.Sent() != 50 {
		t.Errorf("pre-build: want 50, got %d", snd.Sent())
	}
}

func TestRouteDstIP(t *testing.T) {
	cases := []struct {
		tmpl string
		want string
	}{
		{"tcp:src=10.0.0.1:dst=192.168.1.1", "192.168.1.1"},
		{"udp:src=10.0.0.1:dst=10.0.0.0/24", "10.0.0.0"},
		{"tcp6:src=2001:db8::1:dst=2001:db8::2", "2001:db8::2"},
		{"udp6:src=2001:db8::1:dst=2001:db8::/32", "2001:db8::"},
	}
	for _, c := range cases {
		tmpl, err := ParseTemplate(c.tmpl)
		if err != nil {
			t.Fatal(err)
		}
		if got := tmpl.RouteDstIP().String(); got != c.want {
			t.Errorf("RouteDstIP(%q): want %s, got %s", c.tmpl, c.want, got)
		}
	}
}
