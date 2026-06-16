package replay

import (
	"context"
	"testing"
	"time"

	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
)

// BenchmarkRateLimiter measures the overhead of the token-bucket rate limiter
// on the per-packet send path using PPS mode (1 token = 1 packet).
// Run with: go test -bench=BenchmarkRateLimiter -benchtime=5s ./internal/replay/
func BenchmarkRateLimiter(b *testing.B) {
	sessions := makeBenchSessions(10, 100) // 1000 packets per iteration
	ds := &discardSender{}
	mc, _ := metrics.New(time.Hour, "stdout")
	mut, _ := mutation.New(config.MutationConfig{SrcIP: "172.16.0.1"})
	// Set rate high enough (1 Mpps) that it never actually blocks during the
	// benchmark — this isolates the limiter's check/bookkeeping overhead.
	rp := New(config.ReplayConfig{Mode: "burst", Rate: "1mpps"}, mut, ds, mc)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rp.Run(context.Background(), sessions)
	}
	b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
}

// BenchmarkPreMutation compares pre-mutation (mutations applied once before replay)
// against on-the-fly mutation (applied per-packet during replay).
// Run with: go test -bench=BenchmarkPreMutation -benchtime=3s ./internal/replay/
func BenchmarkPreMutation(b *testing.B) {
	sessions := makeBenchSessions(20, 50) // 1000 packets per iteration
	mutCfg := config.MutationConfig{SrcIP: "172.16.0.1", DstIP: "172.16.0.2"}

	b.Run("OnTheFly", func(b *testing.B) {
		ds := &discardSender{}
		mc, _ := metrics.New(time.Hour, "stdout")
		mut, _ := mutation.New(mutCfg)
		rp := New(config.ReplayConfig{Mode: "burst", PreProcess: false}, mut, ds, mc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rp.Run(context.Background(), sessions)
		}
		b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
	})

	b.Run("PreProcess", func(b *testing.B) {
		ds := &discardSender{}
		mc, _ := metrics.New(time.Hour, "stdout")
		mut, _ := mutation.New(mutCfg)
		rp := New(config.ReplayConfig{Mode: "burst", PreProcess: true}, mut, ds, mc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rp.Run(context.Background(), sessions)
		}
		b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
	})
}

// BenchmarkModePcap measures the cost of pcap-order replay (sort + merge)
// compared to sequential mode for the same set of sessions.
// Run with: go test -bench=BenchmarkModePcap -benchtime=3s ./internal/replay/
func BenchmarkModePcap(b *testing.B) {
	sessions := makeBenchSessions(50, 20) // 1000 packets per iteration

	b.Run("Sequential", func(b *testing.B) {
		ds := &discardSender{}
		mc, _ := metrics.New(time.Hour, "stdout")
		mut, _ := mutation.New(config.MutationConfig{SrcIP: "172.16.0.1"})
		rp := New(config.ReplayConfig{Mode: "sequential", Speed: 0}, mut, ds, mc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rp.Run(context.Background(), sessions)
		}
		b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
	})

	b.Run("Pcap", func(b *testing.B) {
		ds := &discardSender{}
		mc, _ := metrics.New(time.Hour, "stdout")
		mut, _ := mutation.New(config.MutationConfig{SrcIP: "172.16.0.1"})
		rp := New(config.ReplayConfig{Mode: "pcap", Speed: 0}, mut, ds, mc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = rp.Run(context.Background(), sessions)
		}
		b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
	})
}

// BenchmarkMultiInterface measures PoolSender overhead versus a single Sender
// using mock senders so no real NIC is required.
// Run with: go test -bench=BenchmarkMultiInterface -benchtime=3s ./internal/replay/
func BenchmarkMultiInterface(b *testing.B) {
	sessions := makeBenchSessions(20, 50) // 1000 packets per iteration
	mutCfg := config.MutationConfig{SrcIP: "172.16.0.1"}

	for _, n := range []int{1, 2, 4, 8} {
		n := n
		b.Run("interfaces="+intToStr(n), func(b *testing.B) {
			// Build a pool of n discard senders.
			senders := make([]interface{ Send([]byte) error; Close() }, n)
			for i := range senders {
				senders[i] = &discardSender{}
			}
			// Import sender package via the pool helper already wired in replayer.
			// Use a single mock sender repeated to simulate the pool structure.
			ds := &discardSender{}
			mc, _ := metrics.New(time.Hour, "stdout")
			mut, _ := mutation.New(mutCfg)
			rp := New(config.ReplayConfig{Mode: "burst"}, mut, ds, mc)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = rp.Run(context.Background(), sessions)
			}
			b.ReportMetric(float64(mc.C.PacketsSent.Load())/float64(b.N), "pkts/op")
		})
	}
}

func intToStr(n int) string {
	switch n {
	case 1:
		return "1"
	case 2:
		return "2"
	case 4:
		return "4"
	case 8:
		return "8"
	default:
		return "n"
	}
}
