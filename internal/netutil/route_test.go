package netutil

import (
	"net"
	"testing"
)

// TestFindOutbound verifies that findOutbound correctly identifies the local
// interface and IP used to reach a well-known public address. The test is
// skipped when there is no usable network connectivity.
func TestFindOutbound(t *testing.T) {
	// Use a connectivity check first so the test is skipped cleanly in
	// network-isolated environments (e.g. CI without outbound access).
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Skipf("no network connectivity, skipping: %v", err)
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	targetIP := net.ParseIP("8.8.8.8")
	iface, resolved, err := findOutbound(targetIP)
	if err != nil {
		t.Fatalf("findOutbound: %v", err)
	}
	if iface == nil {
		t.Fatal("findOutbound returned nil interface")
	}
	if iface.Name == "" {
		t.Error("interface name is empty")
	}
	if !resolved.Equal(localIP) {
		t.Errorf("local IP mismatch: want %s, got %s", localIP, resolved)
	}
}

// TestAutoInterface exercises the full Resolve path. It skips on environments
// without outbound connectivity. GatewayMAC may legitimately be nil when the
// target is directly attached or the ARP cache is empty.
func TestAutoInterface(t *testing.T) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Skipf("no network connectivity, skipping: %v", err)
	}
	_ = conn.Close()

	targetIP := net.ParseIP("8.8.8.8")
	info, err := Resolve(targetIP)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Interface == nil || info.Interface.Name == "" {
		t.Error("Resolve: interface is nil or has empty name")
	}
	if info.LocalIP == nil {
		t.Error("Resolve: LocalIP is nil")
	}
	t.Logf("Resolved: iface=%s localIP=%s gatewayIP=%s gatewayMAC=%s",
		info.Interface.Name, info.LocalIP, info.GatewayIP, info.GatewayMAC)
}
