package mutation

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

// BenchmarkApplyFullMutation measures packet mutation throughput with every
// mutable field overridden: IPs, ports, TTL, DSCP, TCP flags, and window.
func BenchmarkApplyFullMutation(b *testing.B) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{
		SrcIP:         net.ParseIP("172.16.0.99").To4(),
		DstIP:         net.ParseIP("10.20.30.40").To4(),
		SrcPort:       54321,
		DstPort:       443,
		TTL:           128,
		DSCP:          46,
		TCPSetFlags:   "ACK",
		TCPClearFlags: "RST",
		TCPWindow:     65535,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(raw, plan, layers.LinkTypeEthernet); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkApplyNoMutation measures the baseline cost for pass-through (no fields changed).
func BenchmarkApplyNoMutation(b *testing.B) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(raw, plan, layers.LinkTypeEthernet); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkApply measures the realistic cost of a full mutation on a typical
// client→server TCP packet with all mutable fields rewritten, checksums
// recomputed. Reports allocs/op to catch regressions in allocation paths.
func BenchmarkApply(b *testing.B) {
	raw := buildEthIPTCP("192.168.100.200", "93.184.216.34", 54321, 443)
	plan := Plan{
		SrcIP:         net.ParseIP("10.0.0.1").To4(),
		DstIP:         net.ParseIP("172.16.0.1").To4(),
		SrcPort:       12345,
		DstPort:       8443,
		TTL:           64,
		DSCP:          46,
		TCPSetFlags:   "ACK",
		TCPClearFlags: "RST",
		TCPWindow:     65535,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(raw, plan, layers.LinkTypeEthernet); err != nil {
			b.Fatal(err)
		}
	}
}
