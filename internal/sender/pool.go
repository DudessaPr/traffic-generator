package sender

import "sync/atomic"

// PoolSender distributes Send calls across multiple underlying senders in
// round-robin order. Each underlying sender has its own mutex, so concurrent
// goroutines hitting different pool slots contend only when the pool is
// smaller than the concurrency level.
type PoolSender struct {
	senders []Interface
	next    atomic.Uint64
}

// NewPool opens one pcap handle per interface name and wraps them in a
// PoolSender. If any open fails, already-opened handles are closed before
// returning the error.
func NewPool(ifaces []string) (*PoolSender, error) {
	senders := make([]Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		s, err := New(iface)
		if err != nil {
			for _, prev := range senders {
				prev.Close()
			}
			return nil, err
		}
		senders = append(senders, s)
	}
	return &PoolSender{senders: senders}, nil
}

// NewPoolFrom builds a PoolSender from an existing slice of Interface values.
// Intended for tests that inject mock senders without opening real NIC handles.
func NewPoolFrom(senders []Interface) *PoolSender {
	return &PoolSender{senders: senders}
}

// Send injects data through the next sender in the round-robin rotation.
func (p *PoolSender) Send(data []byte) error {
	n := int(p.next.Add(1)-1) % len(p.senders)
	return p.senders[n].Send(data)
}

// SendBatch splits frames evenly across underlying senders, advancing the
// round-robin counter at batch granularity rather than packet granularity.
// Each sub-slice is sent via SendBatch if the underlying sender supports it;
// otherwise it falls back to sequential Send calls.
func (p *PoolSender) SendBatch(frames [][]byte) (int, error) {
	n := len(p.senders)
	if n == 0 || len(frames) == 0 {
		return 0, nil
	}
	if n == 1 {
		if b, ok := p.senders[0].(Batcher); ok {
			return b.SendBatch(frames)
		}
		return sendSeq(p.senders[0], frames)
	}

	// Advance the round-robin pointer once per batch call.
	startIdx := int(p.next.Add(1)-1) % n

	perSender := len(frames) / n
	remainder := len(frames) % n

	total := 0
	offset := 0
	for i := 0; i < n && offset < len(frames); i++ {
		sIdx := (startIdx + i) % n
		count := perSender
		if i < remainder {
			count++
		}
		if count == 0 {
			break
		}
		chunk := frames[offset : offset+count]
		offset += count

		var sent int
		var err error
		if b, ok := p.senders[sIdx].(Batcher); ok {
			sent, err = b.SendBatch(chunk)
		} else {
			sent, err = sendSeq(p.senders[sIdx], chunk)
		}
		total += sent
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sendSeq sends frames one-by-one through s; used as a fallback when s does
// not implement Batcher.
func sendSeq(s Interface, frames [][]byte) (int, error) {
	sent := 0
	for _, f := range frames {
		if err := s.Send(f); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// Close shuts down every underlying sender.
func (p *PoolSender) Close() {
	for _, s := range p.senders {
		s.Close()
	}
}
