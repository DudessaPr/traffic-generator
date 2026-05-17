package sender

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// Interface is satisfied by any type that can inject raw Ethernet frames (e.g. mock_sender for tests).
type Interface interface {
	Send(data []byte) error
	Close()
}

// Sender injects raw packet frames onto a network interface using libpcap.
type Sender struct {
	handle *pcap.Handle
	iface  string
}

// New opens a live pcap handle on iface for packet injection.
// The caller must call Close when done.
func New(iface string) (*Sender, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", iface, err)
	}
	return &Sender{handle: handle, iface: iface}, nil
}

// Send injects one raw Ethernet frame onto the interface.
func (s *Sender) Send(data []byte) error {
	// Guard against callers passing uninitialized or zero-length buffers.
	if len(data) == 0 {
		return fmt.Errorf("packet data is nil or empty")
	}
	// A valid Ethernet frame must carry at least a 14-byte header.
	if len(data) < 14 {
		return fmt.Errorf("packet too small: %d bytes (minimum 14)", len(data))
	}
	// Frames above 65535 bytes cannot be represented in a standard IP length field.
	if len(data) > 65535 {
		return fmt.Errorf("packet too large: %d bytes (maximum 65535)", len(data))
	}
	if err := s.handle.WritePacketData(data); err != nil {
		return fmt.Errorf("write packet to %s: %w", s.iface, err)
	}
	return nil
}

// Interface returns the name of the underlying network interface.
func (s *Sender) Interface() string { return s.iface }

// Close releases the pcap handle.
func (s *Sender) Close() { s.handle.Close() }
