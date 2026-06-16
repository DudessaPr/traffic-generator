//go:build darwin

package netutil

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// gatewayIP returns the gateway IP for targetIP on macOS by parsing `route -n get`.
func gatewayIP(targetIP net.IP) (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", targetIP.String()).Output()
	if err != nil {
		return nil, fmt.Errorf("route get %s: %w", targetIP, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(parts[1]))
		if ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no gateway found in route output for %s", targetIP)
}

// gatewayMAC returns the MAC address of gwIP from the macOS ARP cache.
func gatewayMAC(_ *net.Interface, gwIP net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("arp", "-n", gwIP.String()).Output()
	if err != nil {
		return nil, fmt.Errorf("arp -n %s: %w", gwIP, err)
	}
	// Output format: ? (192.168.0.1) at e4:c3:2a:f7:f7:e on en0 ifscope [ethernet]
	// macOS arp omits leading zeros in each octet (e.g. "e" instead of "0e"),
	// which net.ParseMAC rejects. normaliseMAC pads every octet to two digits.
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, gwIP.String()) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "at" && i+1 < len(fields) {
				mac, err := net.ParseMAC(normaliseMAC(fields[i+1]))
				if err == nil {
					return mac, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("MAC not found in ARP cache for %s", gwIP)
}

// normaliseMAC zero-pads each colon-separated octet to two hex digits.
// macOS arp output uses abbreviated octets (e.g. "e4:c3:2a:f7:f7:e"),
// but net.ParseMAC requires the canonical "e4:c3:2a:f7:f7:0e" form.
func normaliseMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return s
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
