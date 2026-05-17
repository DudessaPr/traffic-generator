package replay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/session"
)

// discardSender counts packets without touching a network interface.
type discardSender struct{ sent int }

func (d *discardSender) Send(_ []byte) error { d.sent++; return nil }
func (d *discardSender) Close()              {}

func buildRawTCPPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version: 4, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("1.2.3.4").To4(),
		DstIP:    net.ParseIP("5.6.7.8").To4(),
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip4)
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		eth, ip4, tcp)
	return buf.Bytes()
}

func makeBenchSessions(n, pktsPerSession int) []*session.Session {
	raw := buildRawTCPPacket()
	now := time.Now()
	out := make([]*session.Session, n)
	for i := range out {
		s := &session.Session{
			Key:       session.Key{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: uint16(1000 + i), DstPort: 80, Proto: 6},
			SrcIP:     net.ParseIP("1.2.3.4"),
			DstIP:     net.ParseIP("5.6.7.8"),
			SrcPort:   uint16(1000 + i),
			DstPort:   80,
			Proto:     6,
			StartTime: now,
			EndTime:   now.Add(time.Duration(pktsPerSession) * time.Millisecond),
		}
		for j := 0; j < pktsPerSession; j++ {
			s.Packets = append(s.Packets, &session.Packet{
				Timestamp: now.Add(time.Duration(j) * time.Millisecond),
				Data:      raw,
				LinkType:  layers.LinkTypeEthernet,
			})
		}
		out[i] = s
	}
	return out
}

// BenchmarkSequential measures throughput of sequential mode with Speed=0
// (burst within sessions) to isolate the per-packet mutation + send cost.
// 100 sessions × 100 packets = 10 000 packets per iteration.
func BenchmarkSequential(b *testing.B) {
	sessions := makeBenchSessions(100, 100)
	ds := &discardSender{}
	mc, _ := metrics.New(time.Hour, "stdout")
	mut, _ := mutation.New(config.MutationConfig{PreserveSessions: true, SrcIP: "172.16.0.1", DstIP: "172.16.0.2"})
	rp := New(config.ReplayConfig{Mode: "sequential", Speed: 0}, mut, ds, mc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rp.runSequential(context.Background(), sessions)
	}
	b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
}

// BenchmarkParallel measures throughput with 8 concurrent workers.
// 100 sessions × 100 packets = 10 000 packets per iteration.
func BenchmarkParallel(b *testing.B) {
	sessions := makeBenchSessions(100, 100)
	ds := &discardSender{}
	mc, _ := metrics.New(time.Hour, "stdout")
	mut, _ := mutation.New(config.MutationConfig{PreserveSessions: true, SrcIP: "172.16.0.1", DstIP: "172.16.0.2"})
	rp := New(config.ReplayConfig{Mode: "parallel", Workers: 8, Speed: 0}, mut, ds, mc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rp.runParallel(context.Background(), sessions)
	}
	b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
}

// BenchmarkBurst measures burst-mode throughput at 100 sessions × 100 packets.
func BenchmarkBurst(b *testing.B) {
	sessions := makeBenchSessions(100, 100)
	ds := &discardSender{}
	mc, _ := metrics.New(time.Hour, "stdout")
	mut, _ := mutation.New(config.MutationConfig{PreserveSessions: true, SrcIP: "172.16.0.1", DstIP: "172.16.0.2"})
	rp := New(config.ReplayConfig{Mode: "burst"}, mut, ds, mc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rp.runBurst(context.Background(), sessions)
	}
	b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
}

// BenchmarkBurstReplay measures mutation + serialisation throughput without
// network I/O.  10 sessions × 100 packets = 1 000 packets per iteration.
func BenchmarkBurstReplay(b *testing.B) {
	sessions := makeBenchSessions(10, 100)
	ds := &discardSender{}
	mc, _ := metrics.New(time.Hour, "stdout")
	mut, _ := mutation.New(config.MutationConfig{
		PreserveSessions: true,
		SrcIP:            "172.16.0.1",
		DstIP:            "172.16.0.2",
	})

	rp := New(config.ReplayConfig{Mode: "burst"}, mut, ds, mc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rp.runBurst(context.Background(), sessions)
	}
	// Total packets / iterations gives a stable pkts/op across all b.N.
	b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
	b.ReportMetric(float64(mc.C.Errors.Load())/float64(b.N), "errors/op")
}
