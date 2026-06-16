//go:build linux

package sender

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr mirrors the kernel's struct mmsghdr layout, which is not yet exported
// by golang.org/x/sys/unix. Padding after Len is added automatically by the
// compiler to match the kernel's alignment on all supported Linux architectures.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// RawSender injects raw Ethernet frames via AF_PACKET SOCK_RAW, bypassing the
// libpcap overhead. Requires CAP_NET_RAW or root privileges.
type RawSender struct {
	fd    int
	iface string
	ll    syscall.SockaddrLinklayer
	rll   unix.RawSockaddrLinklayer // pre-built address for sendmmsg headers
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
	rll := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: proto,
		Ifindex:  int32(ifi.Index),
	}
	return &RawSender{fd: fd, iface: iface, ll: ll, rll: rll}, nil
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

// SendBatch injects multiple raw Ethernet frames via a single sendmmsg(2) syscall,
// reducing per-packet kernel-crossing overhead compared to sequential Send calls.
// Falls back to sequential Sendto when the kernel returns ENOSYS.
func (s *RawSender) SendBatch(frames [][]byte) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}

	// Pre-allocate with exact capacity so append never reallocates;
	// &iovecs[i] pointers passed into hdrs must remain stable.
	iovecs := make([]unix.Iovec, 0, len(frames))
	for _, f := range frames {
		if len(f) == 0 {
			continue
		}
		var iov unix.Iovec
		iov.Base = &f[0]
		iov.SetLen(len(f))
		iovecs = append(iovecs, iov)
	}
	if len(iovecs) == 0 {
		return 0, nil
	}

	hdrs := make([]mmsghdr, len(iovecs))
	for i := range iovecs {
		hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&s.rll))
		hdrs[i].Hdr.Namelen = unix.SizeofSockaddrLinklayer
		hdrs[i].Hdr.Iov = &iovecs[i]
		hdrs[i].Hdr.SetIovlen(1)
	}

	n, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(s.fd),
		uintptr(unsafe.Pointer(&hdrs[0])),
		uintptr(len(hdrs)),
		0, 0, 0,
	)
	if errno == syscall.ENOSYS {
		return s.sendBatchSeq(frames)
	}
	if errno != 0 {
		return int(n), fmt.Errorf("sendmmsg %s: %w", s.iface, errno)
	}
	return int(n), nil
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
