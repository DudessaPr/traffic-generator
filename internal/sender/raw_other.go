//go:build !linux

package sender

import "fmt"

// NewRaw is not supported on this platform; use New or NewPool instead.
func NewRaw(_ string) (*RawSender, error) {
	return nil, fmt.Errorf("AF_PACKET raw sender is only supported on Linux")
}

// RawSender is a placeholder type on non-Linux platforms so that code
// referencing the type still compiles.
type RawSender struct{}

func (s *RawSender) Send(_ []byte) error              { return fmt.Errorf("not supported") }
func (s *RawSender) SendBatch(_ [][]byte) (int, error) { return 0, ErrNotSupported }
func (s *RawSender) Close()                           {}
