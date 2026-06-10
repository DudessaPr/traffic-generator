package sender_test

import (
	"sync"
	"testing"

	"tgen/internal/sender"
)

// countSender is a mock sender that counts received packets.
type countSender struct {
	mu    sync.Mutex
	count int
}

func (c *countSender) Send(_ []byte) error {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	return nil
}
func (c *countSender) Close() {}

func (c *countSender) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// TestMultiInterface verifies that PoolSender distributes packets in
// round-robin order across all underlying senders.
func TestMultiInterface(t *testing.T) {
	const numSenders = 3
	const numPackets = 90 // divisible by numSenders for clean assertion

	senders := make([]sender.Interface, numSenders)
	counters := make([]*countSender, numSenders)
	for i := range senders {
		c := &countSender{}
		counters[i] = c
		senders[i] = c
	}

	pool := sender.NewPoolFrom(senders)
	data := make([]byte, 60) // dummy payload

	for i := 0; i < numPackets; i++ {
		if err := pool.Send(data); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
	}

	for i, c := range counters {
		got := c.Count()
		want := numPackets / numSenders
		if got != want {
			t.Errorf("sender[%d]: want %d packets, got %d", i, want, got)
		}
	}
}

// TestMultiInterfaceConcurrent verifies thread-safety of PoolSender.Send when
// called from multiple goroutines simultaneously.
func TestMultiInterfaceConcurrent(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 100

	senders := make([]sender.Interface, 4)
	counters := make([]*countSender, 4)
	for i := range senders {
		c := &countSender{}
		counters[i] = c
		senders[i] = c
	}
	pool := sender.NewPoolFrom(senders)
	data := make([]byte, 60)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = pool.Send(data)
			}
		}()
	}
	wg.Wait()

	total := 0
	for _, c := range counters {
		total += c.Count()
	}
	want := goroutines * perGoroutine
	if total != want {
		t.Errorf("total packets: want %d, got %d", want, total)
	}
}

// TestPoolSenderClose verifies that Close is propagated to all underlying senders.
type closeSender struct {
	countSender
	closed bool
}

func (c *closeSender) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func TestPoolSenderClose(t *testing.T) {
	cs1 := &closeSender{}
	cs2 := &closeSender{}
	pool := sender.NewPoolFrom([]sender.Interface{cs1, cs2})
	pool.Close()
	if !cs1.closed {
		t.Error("sender[0] not closed")
	}
	if !cs2.closed {
		t.Error("sender[1] not closed")
	}
}
