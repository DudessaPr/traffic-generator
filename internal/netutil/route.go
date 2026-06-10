// Package netutil provides helpers for resolving outbound network paths.
package netutil

import (
	"fmt"
	"net"
)

// OutboundInfo describes the local network path to a remote IP.
type OutboundInfo struct {
	Interface  *net.Interface
	LocalIP    net.IP
	GatewayIP  net.IP       // nil when target is directly attached
	GatewayMAC net.HardwareAddr // nil when not resolvable or not needed
}

// Resolve returns the outbound interface, local IP, gateway IP and gateway MAC
// for targetIP. Uses a connected UDP socket to identify the local IP, then
// calls OS-specific helpers for the gateway details.
//
// GatewayIP and GatewayMAC may be nil when the target is on a directly
// attached network or when OS resolution is unavailable on the current
// platform — callers must check before using.
func Resolve(targetIP net.IP) (*OutboundInfo, error) {
	iface, localIP, err := findOutbound(targetIP)
	if err != nil {
		return nil, err
	}
	info := &OutboundInfo{Interface: iface, LocalIP: localIP}

	gwIP, err := gatewayIP(targetIP)
	if err == nil {
		info.GatewayIP = gwIP
		if gwMAC, err := gatewayMAC(iface, gwIP); err == nil {
			info.GatewayMAC = gwMAC
		}
	}
	return info, nil
}

// findOutbound uses a connected UDP socket (no actual packet sent) to ask the
// OS which local address it would use to reach targetIP, then finds the
// corresponding interface.
func findOutbound(targetIP net.IP) (*net.Interface, net.IP, error) {
	network := "udp4"
	if targetIP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.Dial(network, targetIP.String()+":1")
	if err != nil {
		return nil, nil, fmt.Errorf("dial to find outbound path to %s: %w", targetIP, err)
	}
	defer func() { _ = conn.Close() }()
	localIP := conn.LocalAddr().(*net.UDPAddr).IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localIP) {
				ifCopy := iface
				return &ifCopy, localIP, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no interface found with local IP %s", localIP)
}
