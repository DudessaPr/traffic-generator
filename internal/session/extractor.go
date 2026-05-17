package session

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Extractor reconstructs sessions from a raw packet stream.
// Feed packets in capture order; call Sessions to retrieve results.
type Extractor struct {
	sessions map[Key]*Session
}

// NewExtractor creates a ready-to-use Extractor.
func NewExtractor() *Extractor {
	return &Extractor{sessions: make(map[Key]*Session)}
}

// Feed decodes one raw frame and adds it to the appropriate session.
// Frames that do not contain an IP layer are silently dropped.
func (e *Extractor) Feed(data []byte, ts time.Time, linkType layers.LinkType) {
	// NoCopy lets gopacket decode without an extra allocation; the packet
	// layers point directly into data. All fields we retain beyond this call
	// (SrcIP, DstIP, Packet.Data) are explicitly copied below so they remain
	// valid after the pcap library reuses its read buffer for the next packet.
	pkt := gopacket.NewPacket(data, linkType, gopacket.NoCopy)

	srcIP, dstIP, srcPort, dstPort, proto := extractTuple(pkt)
	if srcIP == nil {
		return
	}

	key := canonical(srcIP.String(), srcPort, dstIP.String(), dstPort, proto)
	sess, ok := e.sessions[key]
	if !ok {
		sess = &Session{
			Key:       key,
			SrcIP:     append(net.IP(nil), srcIP...), // copy: srcIP points into the NoCopy packet buffer which will be overwritten
			DstIP:     append(net.IP(nil), dstIP...),  // same reason
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Proto:     proto,
			StartTime: ts,
		}
		e.sessions[key] = sess
	}
	sess.EndTime = ts
	sess.Packets = append(sess.Packets, &Packet{
		Timestamp: ts,
		Data:      append([]byte(nil), data...), // copy: pcap reuses the underlying buffer after Feed returns
		LinkType:  linkType,
	})
}

// Sessions returns all reconstructed sessions (order is unspecified).
func (e *Extractor) Sessions() []*Session {
	out := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		out = append(out, s)
	}
	return out
}

// extractTuple pulls the L3/L4 addresses and protocol number from a packet.
// Returns nil srcIP when the packet cannot be identified.
func extractTuple(pkt gopacket.Packet) (srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) {
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
		proto = uint8(ip4.Protocol)
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
		proto = uint8(ip6.NextHeader)
	} else {
		return
	}

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}
	return
}
