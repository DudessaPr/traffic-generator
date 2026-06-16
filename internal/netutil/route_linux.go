//go:build linux

package netutil

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// gatewayIP returns the default gateway IP by reading /proc/net/route.
func gatewayIP(_ net.IP) (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Destination field "00000000" is the default route.
		if fields[1] != "00000000" {
			continue
		}
		gwHex, err := hex.DecodeString(fields[2])
		if err != nil || len(gwHex) < 4 {
			continue
		}
		// /proc/net/route stores addresses in little-endian hex.
		return net.IP{gwHex[3], gwHex[2], gwHex[1], gwHex[0]}, nil
	}
	return nil, fmt.Errorf("default gateway not found in /proc/net/route")
}

// gatewayMAC resolves the MAC for gwIP from the Linux ARP table at /proc/net/arp.
func gatewayMAC(_ *net.Interface, gwIP net.IP) (net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/arp: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[0] != gwIP.String() {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err == nil {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("MAC not found in ARP cache for %s", gwIP)
}
