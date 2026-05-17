package mutation

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildEthIPv6TCP builds a raw Ethernet/IPv6/TCP frame for IPv6 tests.
func buildEthIPv6TCP(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip6)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, tcp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// buildEthIPTCP returns a raw Ethernet/IPv4/TCP frame for use in tests.
func buildEthIPTCP(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestApplyNoMutation(t *testing.T) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{}
	got, err := Apply(raw, plan, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	// With an empty plan, source/dest should be identical to originals
	pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.SrcIP.String() != "192.168.1.1" {
		t.Errorf("src IP: want 192.168.1.1, got %s", ip.SrcIP)
	}
}

func TestApplySrcIPMutation(t *testing.T) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{SrcIP: net.ParseIP("172.16.0.5").To4()}
	got, err := Apply(raw, plan, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.SrcIP.String() != "172.16.0.5" {
		t.Errorf("src IP: want 172.16.0.5, got %s", ip.SrcIP)
	}
}

func TestApplyDstPortMutation(t *testing.T) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{DstPort: 8080}
	got, err := Apply(raw, plan, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if uint16(tcp.DstPort) != 8080 {
		t.Errorf("dst port: want 8080, got %d", tcp.DstPort)
	}
}

func TestApplyChecksumValid(t *testing.T) {
	raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 12345, 80)
	plan := Plan{
		SrcIP:   net.ParseIP("172.16.0.99").To4(),
		DstIP:   net.ParseIP("10.20.30.40").To4(),
		SrcPort: 54321,
		DstPort: 443,
	}
	got, err := Apply(raw, plan, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)

	// gopacket's decode will flag checksum errors on the ErrorLayer
	if errLayer := pkt.ErrorLayer(); errLayer != nil {
		t.Errorf("checksum error after mutation: %v", errLayer.Error())
	}

	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)

	if ip.SrcIP.String() != "172.16.0.99" {
		t.Errorf("srcIP: want 172.16.0.99, got %s", ip.SrcIP)
	}
	if uint16(tcp.DstPort) != 443 {
		t.Errorf("dstPort: want 443, got %d", tcp.DstPort)
	}
}

func buildEthIPUDP(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("hello"))); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// TestApplyIPv4SrcIP is a table-driven test that verifies src-IP rewriting
// and confirms the dst IP and transport ports are not disturbed.
func TestApplyIPv4SrcIP(t *testing.T) {
	cases := []struct {
		name      string
		planSrcIP net.IP
		wantSrc   string
	}{
		{"nil plan leaves src unchanged", nil, "192.168.1.1"},
		{"IPv4 plan rewrites src", net.ParseIP("172.16.0.5").To4(), "172.16.0.5"},
		// An IPv6-only plan IP must be ignored for an IPv4 packet (To4()==nil guard).
		{"IPv6-only plan ignored for IPv4 packet", net.ParseIP("2001:db8::1"), "192.168.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 1234, 80)
			plan := Plan{SrcIP: tc.planSrcIP}
			got, err := Apply(raw, plan, layers.LinkTypeEthernet)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
			ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if ip.SrcIP.String() != tc.wantSrc {
				t.Errorf("SrcIP: want %s, got %s", tc.wantSrc, ip.SrcIP)
			}
			// dst IP must be untouched.
			if ip.DstIP.String() != "10.0.0.1" {
				t.Errorf("DstIP changed unexpectedly: %s", ip.DstIP)
			}
		})
	}
}

// TestApplyIPv4DstPort is a table-driven test that verifies dst-port rewriting
// and confirms the TCP checksum is valid after the mutation.
func TestApplyIPv4DstPort(t *testing.T) {
	cases := []struct {
		name     string
		dstPort  uint16
		wantPort uint16
	}{
		{"zero plan leaves port unchanged", 0, 80},
		{"non-zero plan rewrites port", 8443, 8443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildEthIPTCP("192.168.1.1", "10.0.0.1", 1234, 80)
			plan := Plan{DstPort: tc.dstPort}
			got, err := Apply(raw, plan, layers.LinkTypeEthernet)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
			if errLayer := pkt.ErrorLayer(); errLayer != nil {
				t.Fatalf("checksum error after mutation: %v", errLayer.Error())
			}
			tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if uint16(tcp.DstPort) != tc.wantPort {
				t.Errorf("DstPort: want %d, got %d", tc.wantPort, tcp.DstPort)
			}
		})
	}
}

// TestApplyIPv6 verifies that a genuine IPv6 plan address is applied to an
// IPv6 packet and that an IPv4 plan address is silently ignored (it would
// produce an IPv4-mapped address in the IPv6 header, corrupting the packet).
func TestApplyIPv6(t *testing.T) {
	raw := buildEthIPv6TCP("2001:db8::1", "2001:db8::2", 1234, 443)

	t.Run("IPv6 plan applied", func(t *testing.T) {
		plan := Plan{SrcIP: net.ParseIP("2001:db8::ff")}
		got, err := Apply(raw, plan, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
		ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ip6.SrcIP.String() != "2001:db8::ff" {
			t.Errorf("SrcIP: want 2001:db8::ff, got %s", ip6.SrcIP)
		}
	})

	t.Run("IPv4 plan ignored for IPv6 packet", func(t *testing.T) {
		// plan.SrcIP.To4() != nil → the guard in Apply must leave the original src.
		plan := Plan{SrcIP: net.ParseIP("192.168.1.1").To4()}
		got, err := Apply(raw, plan, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
		ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ip6.SrcIP.String() != "2001:db8::1" {
			t.Errorf("SrcIP should be unchanged, got %s", ip6.SrcIP)
		}
	})
}

// TestApplySmallPacket verifies that a frame shorter than the 14-byte Ethernet
// header minimum is rejected with a descriptive error rather than being parsed
// silently and returned unchanged.
func TestApplySmallPacket(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"nil slice", nil},
		{"empty slice", []byte{}},
		{"6 bytes (too short)", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
		{"13 bytes (one short of minimum)", make([]byte, 13)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Apply(tc.data, Plan{}, layers.LinkTypeEthernet)
			if err == nil {
				t.Fatalf("want error for %d-byte packet, got nil", len(tc.data))
			}
		})
	}
}

func TestApplyUDPMutation(t *testing.T) {
	raw := buildEthIPUDP("1.2.3.4", "5.6.7.8", 1234, 53)
	plan := Plan{
		DstIP:   net.ParseIP("8.8.8.8").To4(),
		DstPort: 5353,
	}
	got, err := Apply(raw, plan, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(got, layers.LinkTypeEthernet, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip.DstIP.String() != "8.8.8.8" {
		t.Errorf("dstIP: want 8.8.8.8, got %s", ip.DstIP)
	}
	if uint16(udp.DstPort) != 5353 {
		t.Errorf("dstPort: want 5353, got %d", udp.DstPort)
	}
}
