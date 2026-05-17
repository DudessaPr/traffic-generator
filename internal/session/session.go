package session

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

// ProtoName maps IP protocol numbers to canonical lower-case names.
// Callers that need a name for an unlisted number should use fmt.Sprintf("proto%d", n).
var ProtoName = map[uint8]string{
	1:   "icmp",
	2:   "igmp",
	6:   "tcp",
	17:  "udp",
	47:  "gre",
	50:  "esp",
	51:  "ah",
	58:  "icmpv6",
	89:  "ospf",
	132: "sctp",
}

// Key is the canonical 5-tuple that uniquely identifies a bidirectional flow.
// It is always stored in "smaller endpoint first" order so that packets in
// both directions map to the same session.
type Key struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func (k Key) String() string {
	return fmt.Sprintf("%s:%d↔%s:%d proto=%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}

// canonical returns the Key with the smaller endpoint first.
func canonical(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8) Key {
	a := fmt.Sprintf("%s:%d", srcIP, srcPort)
	b := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if a <= b {
		return Key{srcIP, dstIP, srcPort, dstPort, proto}
	}
	return Key{dstIP, srcIP, dstPort, srcPort, proto}
}

// Packet is one captured frame with its original timestamp and raw bytes.
type Packet struct {
	Timestamp time.Time
	Data      []byte
	LinkType  layers.LinkType
}

// Session is a reconstructed L4 flow.
type Session struct {
	Key       Key
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	Packets   []*Packet
	StartTime time.Time
	EndTime   time.Time
}

// Duration is the time span between the first and last packet.
func (s *Session) Duration() time.Duration {
	return s.EndTime.Sub(s.StartTime)
}

// PacketCount returns the number of captured packets.
func (s *Session) PacketCount() int { return len(s.Packets) }

// ByteCount returns the total captured bytes across all packets.
func (s *Session) ByteCount() int {
	total := 0
	for _, p := range s.Packets {
		total += len(p.Data)
	}
	return total
}
