//go:build !linux && !darwin

package netutil

import (
	"fmt"
	"net"
)

func gatewayIP(_ net.IP) (net.IP, error) {
	return nil, fmt.Errorf("gateway resolution is not supported on this platform")
}

func gatewayMAC(_ *net.Interface, _ net.IP) (net.HardwareAddr, error) {
	return nil, fmt.Errorf("ARP resolution is not supported on this platform")
}
