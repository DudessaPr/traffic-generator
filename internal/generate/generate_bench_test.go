package generate

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"tgen/internal/metrics"
	"tgen/internal/sender"
)

// mockBatchSender implements sender.Interface and sender.Batcher.
// It discards all frames but counts them atomically.
type mockBatchSender struct {
	n atomic.Int64
}

func (m *mockBatchSender) Send([]byte) error              { m.n.Add(1); return nil }
func (m *mockBatchSender) Close()                         {}
func (m *mockBatchSender) SendBatch(frames [][]byte) (int, error) {
	m.n.Add(int64(len(frames)))
	return len(frames), nil
}

var (
	_ sender.Interface = (*mockBatchSender)(nil)
	_ sender.Batcher   = (*mockBatchSender)(nil)
)

func newBenchMC(b *testing.B) *metrics.Collector {
	b.Helper()
	mc, err := metrics.New(time.Hour, "stdout")
	if err != nil {
		b.Fatal(err)
	}
	return mc
}

// buildSink prevents the compiler from eliminating Build() calls.
var buildSink []byte

// BenchmarkGenerateBuild measures raw template Build() speed.
func BenchmarkGenerateBuild(b *testing.B) {
	cases := []struct {
		name string
		tmpl string
	}{
		{"tcp", "tcp:src=10.0.0.1:dst=192.168.1.1:dport=80"},
		{"udp_1400", "udp:src=10.0.0.1:dst=192.168.1.1:dport=9999:size=1400"},
		{"tcp6", "tcp6:src=2001:db8::1:dst=2001:db8::2:dport=443"},
		{"random_fields", "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=80-443:ttl=32-64"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			tmpl, err := ParseTemplate(c.tmpl)
			if err != nil {
				b.Fatal(err)
			}
			rng := rand.New(rand.NewSource(42))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buildSink, err = tmpl.Build(testSrcMAC, testDstMAC, rng)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkGenerateWorkers measures end-to-end generator throughput at various
// worker counts. count is set so total packets ≈ b.N, giving ns/op ≈ ns/packet.
func BenchmarkGenerateWorkers(b *testing.B) {
	const tmplStr = "udp:src=10.0.0.0/24:dst=192.168.1.1:dport=9999:size=1400"
	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			tmpl, err := ParseTemplate(tmplStr)
			if err != nil {
				b.Fatal(err)
			}
			snd := &discardSender{}

			count := int64(b.N) / int64(workers)
			if count < 1 {
				count = 1
			}

			g, err := New(Config{Count: count, Workers: workers}, tmpl, snd, testSrcMAC, testDstMAC, newBenchMC(b))
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(1442) // 1400 payload + Eth(14) + IP(20) + UDP(8)
			b.ResetTimer()
			if err := g.Run(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			b.ReportMetric(float64(snd.Sent())/float64(b.N), "pkts/op")
		})
	}
}

// BenchmarkGeneratePreBuild compares on-the-fly Build() with pre-built buffers.
func BenchmarkGeneratePreBuild(b *testing.B) {
	const tmplStr = "udp:src=10.0.0.0/24:dst=192.168.1.1:dport=9999:size=1400"
	cases := []struct {
		name     string
		preBuild int
	}{
		{"OnTheFly", 0},
		{"PreBuild1000", 1000},
		{"PreBuild10000", 10000},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			tmpl, err := ParseTemplate(tmplStr)
			if err != nil {
				b.Fatal(err)
			}
			snd := &discardSender{}

			count := int64(b.N) / 8
			if count < 1 {
				count = 1
			}

			g, err := New(Config{Count: count, Workers: 8, PreBuild: c.preBuild, BatchSize: 32}, tmpl, snd, testSrcMAC, testDstMAC, newBenchMC(b))
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(1442)
			b.ResetTimer()
			if err := g.Run(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			b.ReportMetric(float64(snd.Sent())/float64(b.N), "pkts/op")
		})
	}
}

// BenchmarkGenerateBatchSize measures the impact of SendBatch size on throughput.
// Uses mockBatchSender which implements sender.Batcher so batch paths are exercised.
func BenchmarkGenerateBatchSize(b *testing.B) {
	const tmplStr = "udp:src=10.0.0.0/24:dst=192.168.1.1:dport=9999:size=1400"
	for _, batchSize := range []int{1, 32, 64, 128, 256} {
		b.Run(fmt.Sprintf("batch=%d", batchSize), func(b *testing.B) {
			tmpl, err := ParseTemplate(tmplStr)
			if err != nil {
				b.Fatal(err)
			}
			snd := &mockBatchSender{}

			count := int64(b.N) / 8
			if count < 1 {
				count = 1
			}

			g, err := New(Config{Count: count, Workers: 8, PreBuild: 10000, BatchSize: batchSize}, tmpl, snd, testSrcMAC, testDstMAC, newBenchMC(b))
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(1442)
			b.ResetTimer()
			if err := g.Run(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			b.ReportMetric(float64(snd.n.Load())/float64(b.N), "pkts/op")
		})
	}
}

// BenchmarkGenerateCPS measures CPS dispatcher overhead.
// Runs the generator for a fixed window and reports achieved vs target CPS.
func BenchmarkGenerateCPS(b *testing.B) {
	const (
		targetCPS = 10_000
		workers   = 4
		count     = 10
		window    = 100 * time.Millisecond
	)

	tmpl, err := ParseTemplate("tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=80")
	if err != nil {
		b.Fatal(err)
	}

	var totalFlows int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snd := &discardSender{}
		mc := newBenchMC(b)
		g, err := New(Config{CPS: targetCPS, Workers: workers, Count: count}, tmpl, snd, testSrcMAC, testDstMAC, mc)
		if err != nil {
			b.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), window)
		_ = g.Run(ctx)
		cancel()
		totalFlows += mc.C.FlowsStarted.Load()
	}
	b.StopTimer()

	const secPerWindow = float64(window) / float64(time.Second)
	b.ReportMetric(float64(totalFlows)/float64(b.N)/secPerWindow, "actual_cps")
	b.ReportMetric(targetCPS, "target_cps")
}
