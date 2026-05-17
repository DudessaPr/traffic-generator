package pcap

import (
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket/pcap"
	"tgen/internal/session"
)

// ReadSessions opens a PCAP file, reconstructs all L3/L4 sessions, and returns them.
// NOTE: callers that also call Inspect on the same path open the file twice.
// This is intentional (two separate read passes with different purposes) but
// worth noting if the path is on slow storage or the file is very large.
func ReadSessions(path string) ([]*session.Session, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer handle.Close()

	ext := session.NewExtractor()
	linkType := handle.LinkType()

	packetCount := 0
	for {
		data, ci, err := handle.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from %s: %w", path, err)
		}
		packetCount++
		ext.Feed(data, ci.Timestamp, linkType)
	}
	// An empty file is likely a misconfiguration; return an error so the
	// caller gets a clear message instead of silently replaying nothing.
	if packetCount == 0 {
		return nil, fmt.Errorf("pcap file %q contains no packets", path)
	}
	return ext.Sessions(), nil
}

// FileStats summarises a PCAP file without full session reconstruction.
type FileStats struct {
	Path         string
	PacketCount  int
	ByteCount    int
	FirstPacket  time.Time
	LastPacket   time.Time
	Duration     time.Duration
}

// Inspect returns statistics for the given PCAP file.
func Inspect(path string) (*FileStats, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer handle.Close()

	stats := &FileStats{Path: path}
	for {
		data, ci, err := handle.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		stats.PacketCount++
		stats.ByteCount += len(data)
		if stats.FirstPacket.IsZero() {
			stats.FirstPacket = ci.Timestamp
		}
		stats.LastPacket = ci.Timestamp
	}
	if !stats.FirstPacket.IsZero() {
		stats.Duration = stats.LastPacket.Sub(stats.FirstPacket)
	}
	return stats, nil
}
