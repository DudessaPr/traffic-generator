//go:build linux

package sender

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RawSender injects raw Ethernet frames via AF_PACKET SOCK_RAW, bypassing the
// libpcap overhead. Requires CAP_NET_RAW or root privileges.
type RawSender struct {
	fd    int
	iface string
	ll    syscall.SockaddrLinklayer
}

// NewRaw opens an AF_PACKET socket bound to iface.
func NewRaw(iface string) (*RawSender, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	// ETH_P_ALL in network byte order captures/injects all Ethernet types.
	proto := htons(0x0003)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	ll := syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, &ll); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET on %q: %w", iface, err)
	}
	return &RawSender{fd: fd, iface: iface, ll: ll}, nil
}

// Send writes one raw Ethernet frame via the kernel socket.
func (s *RawSender) Send(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("packet data is nil or empty")
	}
	if len(data) < 14 {
		return fmt.Errorf("packet too small: %d bytes (minimum 14)", len(data))
	}
	if err := syscall.Sendto(s.fd, data, 0, &s.ll); err != nil {
		return fmt.Errorf("sendto %s: %w", s.iface, err)
	}
	return nil
}

// SendBatch injects multiple raw Ethernet frames. It attempts sendmmsg (one
// syscall for all frames); if the kernel does not support it (ENOSYS) it falls
// back to a sequential loop of Sendto.
func (s *RawSender) SendBatch(frames [][]byte) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	n, err := s.trySendmmsg(frames)
	if err == syscall.ENOSYS {
		return s.sendBatchSeq(frames)
	}
	return n, err
}

// trySendmmsg builds one Mmsghdr per frame and issues a single sendmmsg syscall.
func (s *RawSender) trySendmmsg(frames [][]byte) (int, error) {
	// Heap-allocate rsa so its address is stable for the duration of the syscall.
	// A stack variable's address would be valid too (the runtime pins goroutine
	// stacks during blocking syscalls), but an explicit heap allocation makes the
	// intent unambiguous to the compiler and escape analysis.
	rsa := &syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: s.ll.Protocol,
		Ifindex:  int32(s.ll.Ifindex),
	}
	rsaLen := uint32(unsafe.Sizeof(*rsa))

	hdrs := make([]unix.Mmsghdr, len(frames))
	iovs := make([]unix.Iovec, len(frames))
	for i, f := range frames {
		if len(f) == 0 {
			continue
		}
		iovs[i].Base = &f[0]
		iovs[i].SetLen(len(f))
		hdrs[i].Hdr.Iov = &iovs[i]
		hdrs[i].Hdr.SetIovlen(1)
		hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(rsa))
		hdrs[i].Hdr.Namelen = rsaLen
	}
	return unix.Sendmmsg(s.fd, hdrs, 0)
}

// sendBatchSeq is the fallback used when sendmmsg is unavailable.
func (s *RawSender) sendBatchSeq(frames [][]byte) (int, error) {
	sent := 0
	for _, f := range frames {
		if len(f) == 0 {
			continue
		}
		if err := syscall.Sendto(s.fd, f, 0, &s.ll); err != nil {
			return sent, fmt.Errorf("sendto %s: %w", s.iface, err)
		}
		sent++
	}
	return sent, nil
}

// Close releases the AF_PACKET socket.
func (s *RawSender) Close() { _ = syscall.Close(s.fd) }

func htons(i uint16) uint16 { return (i << 8) | (i >> 8) }
