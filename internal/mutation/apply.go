package mutation

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// applyTCPFlagBits forces individual TCP flag bits on (val=true) or off (val=false).
// Unknown tokens in the comma-separated flags string are silently ignored.
func applyTCPFlagBits(tcp *layers.TCP, flags string, val bool) {
	for _, tok := range strings.Split(flags, ",") {
		switch strings.TrimSpace(strings.ToUpper(tok)) {
		case "SYN":
			tcp.SYN = val
		case "ACK":
			tcp.ACK = val
		case "FIN":
			tcp.FIN = val
		case "RST":
			tcp.RST = val
		case "PSH":
			tcp.PSH = val
		case "URG":
			tcp.URG = val
		case "ECE":
			tcp.ECE = val
		case "CWR":
			tcp.CWR = val
		case "NS":
			tcp.NS = val
		}
	}
}

// mutateIPv4 applies plan fields to ip4 in place.
// To4() returns nil for IPv6-only addresses, leaving the original IP intact.
func mutateIPv4(ip4 *layers.IPv4, plan Plan) {
	if plan.SrcIP != nil {
		if v4 := plan.SrcIP.To4(); v4 != nil {
			ip4.SrcIP = v4
		}
	}
	if plan.DstIP != nil {
		if v4 := plan.DstIP.To4(); v4 != nil {
			ip4.DstIP = v4
		}
	}
	if plan.TTL != 0 {
		ip4.TTL = plan.TTL
	}
	if plan.DSCP != 0 {
		// DSCP occupies the high 6 bits of the TOS byte; ECN occupies bits 1–0.
		ip4.TOS = (ip4.TOS & 0x03) | (plan.DSCP << 2)
	}
}

// mutateIPv6 applies plan fields to ip6 in place.
// To4() != nil means the plan IP is IPv4; applying it via To16() would produce
// an IPv4-mapped address in an IPv6 header, corrupting the packet.
func mutateIPv6(ip6 *layers.IPv6, plan Plan) {
	if plan.SrcIP != nil && plan.SrcIP.To4() == nil {
		ip6.SrcIP = plan.SrcIP.To16()
	}
	if plan.DstIP != nil && plan.DstIP.To4() == nil {
		ip6.DstIP = plan.DstIP.To16()
	}
	if plan.TTL != 0 {
		ip6.HopLimit = plan.TTL
	}
	if plan.DSCP != 0 {
		// TrafficClass high 6 bits = DSCP, low 2 bits = ECN.
		ip6.TrafficClass = (ip6.TrafficClass & 0x03) | (plan.DSCP << 2)
	}
}

// mutateTCP applies plan fields to tcp in place and binds the checksum pseudo-header.
func mutateTCP(tcp *layers.TCP, plan Plan, nl gopacket.NetworkLayer) {
	if plan.SrcPort != 0 {
		tcp.SrcPort = layers.TCPPort(plan.SrcPort)
	}
	if plan.DstPort != 0 {
		tcp.DstPort = layers.TCPPort(plan.DstPort)
	}
	if plan.TCPSetFlags != "" {
		applyTCPFlagBits(tcp, plan.TCPSetFlags, true)
	}
	if plan.TCPClearFlags != "" {
		applyTCPFlagBits(tcp, plan.TCPClearFlags, false)
	}
	if plan.TCPWindow != 0 {
		tcp.Window = plan.TCPWindow
	}
	_ = tcp.SetNetworkLayerForChecksum(nl)
}

// mutateUDP applies plan port fields to udp and binds the checksum pseudo-header.
func mutateUDP(udp *layers.UDP, plan Plan, nl gopacket.NetworkLayer) {
	if plan.SrcPort != 0 {
		udp.SrcPort = layers.UDPPort(plan.SrcPort)
	}
	if plan.DstPort != 0 {
		udp.DstPort = layers.UDPPort(plan.DstPort)
	}
	_ = udp.SetNetworkLayerForChecksum(nl)
}

// Apply rewrites L3/L4 headers in rawData according to plan and returns the
// updated frame. Checksums are recomputed automatically.
// Packets that lack an IP layer are returned unmodified.
func Apply(rawData []byte, plan Plan, linkType layers.LinkType) ([]byte, error) {
	// A valid Ethernet frame requires at least 14 bytes (header). Frames shorter
	// than this cannot contain an IP layer; gopacket would parse silently and
	// return unmodified bytes, masking the misconfiguration — return an error instead.
	if len(rawData) < 14 {
		return nil, fmt.Errorf("packet too small: %d bytes (minimum Ethernet header is 14)", len(rawData))
	}

	pkt := gopacket.NewPacket(rawData, linkType, gopacket.Default)

	ip4, hasIP4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ip6, hasIP6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	tcp, hasTCP := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	udp, hasUDP := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	eth, hasEth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	if !hasIP4 && !hasIP6 {
		return rawData, nil
	}

	if hasEth && len(plan.DstMAC) == 6 {
		copy(eth.DstMAC, plan.DstMAC)
	}

	// Mutate the IP layer and keep a reference for checksum pseudo-header binding.
	var nl gopacket.NetworkLayer
	if hasIP4 {
		mutateIPv4(ip4, plan)
		nl = ip4
	} else {
		mutateIPv6(ip6, plan)
		nl = ip6
	}

	if hasTCP {
		mutateTCP(tcp, plan, nl)
	}
	if hasUDP {
		mutateUDP(udp, plan, nl)
	}

	// Assemble layers in wire order for serialisation.
	var layerList []gopacket.SerializableLayer
	if hasEth {
		layerList = append(layerList, eth)
	}
	if hasIP4 {
		layerList = append(layerList, ip4)
	} else {
		layerList = append(layerList, ip6)
	}
	if hasTCP {
		layerList = append(layerList, tcp)
	} else if hasUDP {
		layerList = append(layerList, udp)
	}
	if app := pkt.ApplicationLayer(); app != nil {
		layerList = append(layerList, gopacket.Payload(app.Payload()))
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, layerList...); err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	return buf.Bytes(), nil
}
