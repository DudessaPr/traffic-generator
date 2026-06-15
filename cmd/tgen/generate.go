package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"tgen/internal/config"
	"tgen/internal/generate"
	"tgen/internal/metrics"
	"tgen/internal/netutil"
)

var genFlags struct {
	template   string
	ifaces     []string
	sender     string
	rate       string
	count      int64
	workers    int
	loop       bool
	preBuild   int
	cps        float64
	multiplier float64
	batchSize  int
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Synthesise and inject packets from a template (no PCAP required)",
	Long: `Generate injects synthetic packets directly onto the wire.

Template format:  "proto:field=value:field=value:..."

  Protocols:  tcp  udp  icmp  tcp6  udp6
  Fields:
    src=<IP|CIDR>      source address or range (required)
    dst=<IP|CIDR>      destination address or range (required)
    sport=<port|lo-hi> source port or range (default 1024-65535, TCP/UDP only)
    dport=<port|lo-hi> destination port or range (default 80, TCP/UDP only)
    ttl=<0-255>        IP TTL / IPv6 hop limit (default 64)
    dscp=<0-63>        DSCP / DiffServ code point (default 0)
    flags=SYN,ACK,…    TCP flags to set (tcp and tcp6 only)
    size=<bytes>       extra zero-padded payload bytes (default 0)

Examples:
  tgen generate -t "tcp:src=10.0.0.0/24:dst=192.168.1.1:dport=443:flags=SYN" -i eth0
  tgen generate -t "udp:src=10.0.0.1:dst=8.8.8.8:dport=53" --rate 100kpps
  tgen generate -t "icmp:src=10.0.0.0/16:dst=192.168.1.1" --count 1000000
  tgen generate -t "tcp6:src=2001:db8::/32:dst=2001:db8::1:dport=443" --workers 4
  tgen generate -t "udp:src=10.0.0.0/8:dst=10.1.0.1:dport=5001:size=1400" --rate 1gbps --workers 8 --pre-build 1000
  tgen generate -t "tcp:src=10.0.0.1:dst=10.0.0.2:dport=80" --count 100000 --loop`,
	RunE: runGenerate,
}

func init() {
	f := generateCmd.Flags()
	f.StringVarP(&genFlags.template, "template", "t", "",
		"packet template string (required)")
	f.StringSliceVarP(&genFlags.ifaces, "interface", "i", nil,
		"outbound interface(s); comma-separated or repeatable for multi-interface pool (auto-detected from dst IP when omitted)")
	f.StringVar(&genFlags.rate, "rate", "",
		"rate limit: 100kpps, 1mpps, 1gbps, 100mbps, … (default: unlimited)")
	f.Int64Var(&genFlags.count, "count", 0,
		"packets to send per cycle; 0 = run until Ctrl-C")
	f.IntVar(&genFlags.workers, "workers", 1,
		"number of concurrent sender goroutines")
	f.BoolVar(&genFlags.loop, "loop", false,
		"restart after --count packets are sent (loop indefinitely)")
	f.IntVar(&genFlags.preBuild, "pre-build", 0,
		"pre-build N packets per worker before the send loop (0 = disabled)")
	f.Float64Var(&genFlags.cps, "cps", 0,
		"target new flows per second via ticker (0=unlimited); requires --count > 0 for ticker mode")
	f.Float64Var(&genFlags.multiplier, "multiplier", 1.0,
		"rate multiplier applied to --rate and --cps (e.g. 2.0 doubles the effective rate)")
	f.IntVar(&genFlags.batchSize, "batch-size", 32,
		"frames per SendBatch call when --pre-build > 0 (1–256; requires AF_PACKET raw sender)")
	f.StringVar(&genFlags.sender, "sender", "pcap",
		"packet injection backend: pcap (default) or raw (Linux AF_PACKET)")
	_ = generateCmd.MarkFlagRequired("template")
	rootCmd.AddCommand(generateCmd)
}

func runGenerate(_ *cobra.Command, _ []string) error {
	tmpl, err := generate.ParseTemplate(genFlags.template)
	if err != nil {
		return fmt.Errorf("--template: %w", err)
	}

	// Resolve outbound interface and gateway MAC from the dst IP.
	dstIP := tmpl.RouteDstIP()
	info, err := netutil.Resolve(dstIP)
	if err != nil {
		return fmt.Errorf("resolve outbound path to %s: %w", dstIP, err)
	}
	if info.GatewayMAC == nil {
		return fmt.Errorf(
			"could not resolve gateway MAC for %s — ping the gateway to populate the ARP table, then retry",
			dstIP)
	}

	// Primary interface: first from --interface list, or auto-detected.
	primaryIface := info.Interface.Name
	if len(genFlags.ifaces) > 0 {
		primaryIface = genFlags.ifaces[0]
	}
	iface, err := net.InterfaceByName(primaryIface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", primaryIface, err)
	}
	srcMAC := iface.HardwareAddr
	dstMAC := info.GatewayMAC

	// Collect all interfaces; fall back to the single resolved one.
	allIfaces := genFlags.ifaces
	if len(allIfaces) == 0 {
		allIfaces = []string{primaryIface}
	}

	if len(allIfaces) == 1 {
		fmt.Fprintf(os.Stderr, "Interface: %s  src-MAC: %s  gateway-MAC: %s\n",
			allIfaces[0], srcMAC, dstMAC)
	} else {
		fmt.Fprintf(os.Stderr, "Interfaces: %v  src-MAC: %s  gateway-MAC: %s\n",
			allIfaces, srcMAC, dstMAC)
	}

	snd, err := buildSender(&config.Config{
		Interface:  primaryIface,
		Interfaces: allIfaces,
		Sender:     genFlags.sender,
	})
	if err != nil {
		return err
	}
	defer snd.Close()

	mc, err := metrics.New(time.Second, "stdout")
	if err != nil {
		return err
	}

	cfg := generate.Config{
		Rate:      genFlags.rate,
		Count:     genFlags.count,
		Loop:      genFlags.loop,
		Workers:   genFlags.workers,
		PreBuild:  genFlags.preBuild,
		CPS:       genFlags.cps,
		Multiplier: genFlags.multiplier,
		BatchSize: genFlags.batchSize,
	}
	mc.TargetRate = genFlags.rate
	mc.TargetCPS = genFlags.cps
	mc.Multiplier = genFlags.multiplier
	g, err := generate.New(cfg, tmpl, snd, srcMAC, dstMAC, mc)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	done := make(chan struct{})
	go func() { mc.Run(done) }()

	fmt.Fprintf(os.Stderr,
		"Generating… (template=%q  rate=%q  count=%d  cps=%.0f  workers=%d  loop=%v  pre-build=%d  batch-size=%d)\n",
		genFlags.template, genFlags.rate, genFlags.count, genFlags.cps, genFlags.workers, genFlags.loop, genFlags.preBuild, genFlags.batchSize)

	runErr := g.Run(ctx)
	close(done)

	snap := mc.Snapshot()
	fmt.Fprintf(os.Stderr,
		"\nDone. packets=%d bytes=%d errors=%d elapsed=%.1fs\n",
		snap.PacketsSent, snap.BytesSent, snap.Errors, snap.ElapsedSec,
	)

	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return nil
	}
	return runErr
}
