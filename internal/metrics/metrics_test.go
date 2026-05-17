package metrics

import (
	"testing"
	"time"
)

func TestCounters(t *testing.T) {
	mc, err := New(time.Second, "stdout")
	if err != nil {
		t.Fatal(err)
	}
	mc.C.PacketsSent.Add(100)
	mc.C.BytesSent.Add(150_000)
	mc.C.Errors.Add(2)
	mc.C.SessionsDone.Add(5)

	snap := mc.Snapshot()
	if snap.PacketsSent != 100 {
		t.Errorf("PacketsSent: want 100, got %d", snap.PacketsSent)
	}
	if snap.BytesSent != 150_000 {
		t.Errorf("BytesSent: want 150000, got %d", snap.BytesSent)
	}
	if snap.Errors != 2 {
		t.Errorf("Errors: want 2, got %d", snap.Errors)
	}
	if snap.SessionsDone != 5 {
		t.Errorf("SessionsDone: want 5, got %d", snap.SessionsDone)
	}
}

func TestRates(t *testing.T) {
	mc, _ := New(time.Second, "stdout")
	mc.C.PacketsSent.Add(1000)
	mc.C.BytesSent.Add(1_000_000)

	snap1 := mc.Snapshot()
	mc.prev = snap1

	time.Sleep(100 * time.Millisecond)
	mc.C.PacketsSent.Add(100)
	mc.C.BytesSent.Add(100_000)

	snap2 := mc.Snapshot()
	// PPS should be roughly 100 packets / 0.1s ≈ 1000, allow wide tolerance
	if snap2.PPS < 100 || snap2.PPS > 100_000 {
		t.Errorf("PPS out of expected range: %.0f", snap2.PPS)
	}
	if snap2.BPS < 100_000 || snap2.BPS > 100_000_000 {
		t.Errorf("BPS out of expected range: %.0f", snap2.BPS)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	mc, _ := New(time.Second, "stdout")
	done := make(chan struct{})
	const goroutines = 10
	const perGoroutine = 1000

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < perGoroutine; j++ {
				mc.C.PacketsSent.Add(1)
				mc.C.BytesSent.Add(1500)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}

	snap := mc.Snapshot()
	expected := int64(goroutines * perGoroutine)
	if snap.PacketsSent != expected {
		t.Errorf("concurrent PacketsSent: want %d, got %d", expected, snap.PacketsSent)
	}
}
