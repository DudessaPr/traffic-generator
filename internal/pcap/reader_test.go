package pcap

import (
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const testPCAP = "../../traffic.pcap"

// TestReadSessionsEmptyFile verifies that a syntactically valid PCAP that
// contains zero packet records is rejected with a descriptive error rather
// than silently returning an empty session slice.
func TestReadSessionsEmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "tgen-empty-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	// pcapgo writes a valid PCAP global header; no packets follow.
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = ReadSessions(f.Name())
	if err == nil {
		t.Fatal("expected error for empty PCAP, got nil")
	}
	if !strings.Contains(err.Error(), "no packets") {
		t.Errorf("error should mention 'no packets', got: %v", err)
	}
}

// TestReadSessionsInvalidPath verifies that a non-existent file path returns
// an error immediately rather than panicking or returning an empty slice.
func TestReadSessionsInvalidPath(t *testing.T) {
	_, err := ReadSessions("/nonexistent/path/tgen-test-does-not-exist.pcap")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestReadSessions(t *testing.T) {
	if _, err := os.Stat(testPCAP); os.IsNotExist(err) {
		t.Skip("traffic.pcap not found, skipping integration test")
	}

	sessions, err := ReadSessions(testPCAP)
	if err != nil {
		t.Fatalf("ReadSessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least one session")
	}
	for _, s := range sessions {
		if s.PacketCount() == 0 {
			t.Errorf("session %s has no packets", s.Key)
		}
		if s.StartTime.IsZero() {
			t.Errorf("session %s has zero StartTime", s.Key)
		}
		if s.EndTime.Before(s.StartTime) {
			t.Errorf("session %s: EndTime before StartTime", s.Key)
		}
	}
	t.Logf("Extracted %d sessions from %s", len(sessions), testPCAP)
}

func TestInspect(t *testing.T) {
	if _, err := os.Stat(testPCAP); os.IsNotExist(err) {
		t.Skip("traffic.pcap not found, skipping integration test")
	}

	stats, err := Inspect(testPCAP)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if stats.PacketCount == 0 {
		t.Error("expected PacketCount > 0")
	}
	if stats.ByteCount == 0 {
		t.Error("expected ByteCount > 0")
	}
	if stats.FirstPacket.IsZero() {
		t.Error("FirstPacket is zero")
	}
	t.Logf("packets=%d bytes=%d duration=%s", stats.PacketCount, stats.ByteCount, stats.Duration)
}
