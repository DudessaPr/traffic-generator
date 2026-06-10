// Package generate builds and injects synthetic packets from a text template.
package generate

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Template describes the shape of a synthetically generated packet.
type Template struct {
	proto  string // "tcp", "udp", "icmp", "tcp6", "udp6"
	isIPv6 bool

	srcNet *net.IPNet
	srcIP  net.IP
	dstNet *net.IPNet
	dstIP  net.IP

	sportMin, sportMax uint16
	dportMin, dportMax uint16

	ttl  uint8
	dscp uint8

	payloadSize int // extra payload bytes appended to the L4 body

	// TCP-only flags
	tcpSYN, tcpACK, tcpFIN, tcpRST, tcpPSH, tcpURG bool
}

// ParseTemplate parses a colon-separated template string.
//
// Format: "proto:field=value:field=value:..."
//
// Protocols: tcp  udp  icmp  tcp6  udp6
//
// Fields:
//   - src=<IP|CIDR>  dst=<IP|CIDR>  (required; IPv4 for tcp/udp/icmp, IPv6 for tcp6/udp6)
//   - sport=<port|lo-hi>  dport=<port|lo-hi>
//   - ttl=<0-255>  dscp=<0-63>
//   - flags=<SYN,ACK,FIN,RST,PSH,URG>  (tcp and tcp6 only)
//   - size=<0-65535>  (extra payload bytes)
func ParseTemplate(s string) (*Template, error) {
	if s == "" {
		return nil, fmt.Errorf("empty template")
	}
	parts := splitTemplate(s)
	t := &Template{
		proto:    strings.ToLower(parts[0]),
		ttl:      64,
		sportMin: 1024,
		sportMax: 65535,
		dportMin: 80,
		dportMax: 80,
	}
	switch t.proto {
	case "tcp", "udp", "icmp":
		t.isIPv6 = false
	case "tcp6", "udp6":
		t.isIPv6 = true
	default:
		return nil, fmt.Errorf("unsupported protocol %q: want tcp, udp, icmp, tcp6 or udp6", parts[0])
	}
	for _, field := range parts[1:] {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid field %q: expected key=value", field)
		}
		key, val := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		switch key {
		case "src":
			if err := parseCIDROrIP(val, t.isIPv6, &t.srcNet, &t.srcIP); err != nil {
				return nil, fmt.Errorf("src: %w", err)
			}
		case "dst":
			if err := parseCIDROrIP(val, t.isIPv6, &t.dstNet, &t.dstIP); err != nil {
				return nil, fmt.Errorf("dst: %w", err)
			}
		case "sport":
			lo, hi, err := parsePortRange(val)
			if err != nil {
				return nil, fmt.Errorf("sport: %w", err)
			}
			t.sportMin, t.sportMax = lo, hi
		case "dport":
			lo, hi, err := parsePortRange(val)
			if err != nil {
				return nil, fmt.Errorf("dport: %w", err)
			}
			t.dportMin, t.dportMax = lo, hi
		case "ttl":
			v, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("ttl: %w", err)
			}
			t.ttl = uint8(v)
		case "dscp":
			v, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("dscp: %w", err)
			}
			if v > 63 {
				return nil, fmt.Errorf("dscp %d exceeds maximum 63", v)
			}
			t.dscp = uint8(v)
		case "flags":
			if t.proto != "tcp" && t.proto != "tcp6" {
				return nil, fmt.Errorf("flags: only valid for tcp and tcp6")
			}
			if err := parseTCPFlags(val, t); err != nil {
				return nil, fmt.Errorf("flags: %w", err)
			}
		case "size":
			v, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("size: %w", err)
			}
			if v > 65535 {
				return nil, fmt.Errorf("size %d exceeds maximum 65535", v)
			}
			t.payloadSize = int(v)
		default:
			return nil, fmt.Errorf("unknown field %q", key)
		}
	}
	if t.srcIP == nil && t.srcNet == nil {
		return nil, fmt.Errorf("src is required")
	}
	if t.dstIP == nil && t.dstNet == nil {
		return nil, fmt.Errorf("dst is required")
	}
	return t, nil
}

// RouteDstIP returns a single IP address from the dst field suitable for
// route resolution (first address in the CIDR, or the explicit IP).
func (t *Template) RouteDstIP() net.IP {
	if t.dstNet != nil {
		if t.isIPv6 {
			ip := make(net.IP, 16)
			copy(ip, t.dstNet.IP.To16())
			return ip
		}
		ip := make(net.IP, 4)
		copy(ip, t.dstNet.IP.To4())
		return ip
	}
	return t.dstIP
}

// Build serialises one Ethernet frame from the template.
// CIDRs and port ranges are resolved uniformly at random using rng.
// Build is safe for concurrent use when each caller supplies its own rng.
func (t *Template) Build(srcMAC, dstMAC net.HardwareAddr, rng *rand.Rand) ([]byte, error) {
	srcIP := t.pickIP(t.srcNet, t.srcIP, rng)
	dstIP := t.pickIP(t.dstNet, t.dstIP, rng)
	sport := t.pickPort(t.sportMin, t.sportMax, rng)
	dport := t.pickPort(t.dportMin, t.dportMax, rng)

	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC}
	payload := gopacket.Payload(make([]byte, t.payloadSize))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	var serErr error

	if t.isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version:      6,
			HopLimit:     t.ttl,
			TrafficClass: t.dscp << 2,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		}
		switch t.proto {
		case "tcp6":
			ip6.NextHeader = layers.IPProtocolTCP
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(sport),
				DstPort: layers.TCPPort(dport),
				Window:  65535,
				SYN:     t.tcpSYN,
				ACK:     t.tcpACK,
				FIN:     t.tcpFIN,
				RST:     t.tcpRST,
				PSH:     t.tcpPSH,
				URG:     t.tcpURG,
			}
			if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
				return nil, err
			}
			serErr = gopacket.SerializeLayers(buf, opts, eth, ip6, tcp, payload)
		case "udp6":
			ip6.NextHeader = layers.IPProtocolUDP
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(sport),
				DstPort: layers.UDPPort(dport),
			}
			if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
				return nil, err
			}
			serErr = gopacket.SerializeLayers(buf, opts, eth, ip6, udp, payload)
		default:
			return nil, fmt.Errorf("unknown IPv6 protocol %q", t.proto)
		}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     t.ttl,
			TOS:     t.dscp << 2,
			SrcIP:   srcIP,
			DstIP:   dstIP,
		}
		switch t.proto {
		case "tcp":
			ip4.Protocol = layers.IPProtocolTCP
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(sport),
				DstPort: layers.TCPPort(dport),
				Window:  65535,
				SYN:     t.tcpSYN,
				ACK:     t.tcpACK,
				FIN:     t.tcpFIN,
				RST:     t.tcpRST,
				PSH:     t.tcpPSH,
				URG:     t.tcpURG,
			}
			if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
				return nil, err
			}
			serErr = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, payload)
		case "udp":
			ip4.Protocol = layers.IPProtocolUDP
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(sport),
				DstPort: layers.UDPPort(dport),
			}
			if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
				return nil, err
			}
			serErr = gopacket.SerializeLayers(buf, opts, eth, ip4, udp, payload)
		case "icmp":
			ip4.Protocol = layers.IPProtocolICMPv4
			icmp := &layers.ICMPv4{
				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			}
			serErr = gopacket.SerializeLayers(buf, opts, eth, ip4, icmp, payload)
		default:
			return nil, fmt.Errorf("unknown protocol %q", t.proto)
		}
	}

	if serErr != nil {
		return nil, serErr
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out, nil
}

func (t *Template) pickIP(n *net.IPNet, ip net.IP, rng *rand.Rand) net.IP {
	if n != nil {
		if t.isIPv6 {
			return randIPv6FromNet(n, rng)
		}
		return randIPv4FromNet(n, rng)
	}
	return ip
}

func (t *Template) pickPort(min, max uint16, rng *rand.Rand) uint16 {
	if min == max {
		return min
	}
	return min + uint16(rng.Intn(int(max-min)+1))
}

// randIPv4FromNet returns a random IPv4 address within the given network.
// Every bit covered by the host portion of the mask is independently randomised.
func randIPv4FromNet(n *net.IPNet, rng *rand.Rand) net.IP {
	ip4 := n.IP.To4()
	result := make(net.IP, 4)
	for i := range result {
		result[i] = ip4[i] | (^n.Mask[i] & byte(rng.Intn(256)))
	}
	return result
}

// randIPv6FromNet returns a random IPv6 address within the given network.
func randIPv6FromNet(n *net.IPNet, rng *rand.Rand) net.IP {
	ip16 := n.IP.To16()
	result := make(net.IP, 16)
	for i := range result {
		result[i] = ip16[i] | (^n.Mask[i] & byte(rng.Intn(256)))
	}
	return result
}

// parseCIDROrIP parses s as an IP address or CIDR.
// When isIPv6 is true only IPv6 addresses/CIDRs are accepted; false for IPv4 only.
func parseCIDROrIP(s string, isIPv6 bool, netOut **net.IPNet, ipOut *net.IP) error {
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return err
		}
		addrIsIPv6 := ipnet.IP.To4() == nil
		if isIPv6 && !addrIsIPv6 {
			return fmt.Errorf("expected IPv6 CIDR for tcp6/udp6 protocol")
		}
		if !isIPv6 && addrIsIPv6 {
			return fmt.Errorf("only IPv4 CIDRs are supported")
		}
		*netOut = ipnet
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("invalid IP %q", s)
	}
	if isIPv6 {
		if ip.To4() != nil {
			return fmt.Errorf("expected IPv6 address for tcp6/udp6 protocol")
		}
		*ipOut = ip.To16()
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("only IPv4 addresses are supported")
		}
		*ipOut = ip4
	}
	return nil
}

func parsePortRange(s string) (lo, hi uint16, err error) {
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		a, e1 := strconv.ParseUint(s[:idx], 10, 16)
		b, e2 := strconv.ParseUint(s[idx+1:], 10, 16)
		if e1 != nil || e2 != nil {
			return 0, 0, fmt.Errorf("invalid port range %q", s)
		}
		if a > b {
			return 0, 0, fmt.Errorf("port range %q: low > high", s)
		}
		return uint16(a), uint16(b), nil
	}
	v, e := strconv.ParseUint(s, 10, 16)
	if e != nil {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(v), uint16(v), nil
}

// splitTemplate splits s on ':' only when followed by an all-alpha key then '='.
// This lets IPv6 addresses in field values contain ':' without being mis-tokenised.
//
// "tcp6:src=2001:db8::1:dst=::1:dport=80" →
//   ["tcp6", "src=2001:db8::1", "dst=::1", "dport=80"]
func splitTemplate(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			continue
		}
		rest := s[i+1:]
		eqIdx := strings.IndexByte(rest, '=')
		if eqIdx > 0 && isAlphaOnly(rest[:eqIdx]) {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func isAlphaOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func parseTCPFlags(s string, t *Template) error {
	for _, f := range strings.Split(s, ",") {
		switch strings.ToUpper(strings.TrimSpace(f)) {
		case "SYN":
			t.tcpSYN = true
		case "ACK":
			t.tcpACK = true
		case "FIN":
			t.tcpFIN = true
		case "RST":
			t.tcpRST = true
		case "PSH":
			t.tcpPSH = true
		case "URG":
			t.tcpURG = true
		default:
			return fmt.Errorf("unknown flag %q (valid: SYN,ACK,FIN,RST,PSH,URG)", f)
		}
	}
	return nil
}
