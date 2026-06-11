package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	"tgen/internal/netutil"
	pcapreader "tgen/internal/pcap"
	"tgen/internal/replay"
	"tgen/internal/sender"
	"tgen/internal/session"

	"github.com/spf13/cobra"
)

var runFlags struct {
	ifaces     []string
	targetIP   string
	senderType string
	speed      float64
	mode       string
	loop       bool
	loopCount  int
	workers    int
	// IP mutation
	srcIP       string
	dstIP       string
	srcIPPool   []string
	dstIPPool   []string
	ipPoolLimit int
	// port mutation
	srcPortMin uint16
	srcPortMax uint16
	dstPort    uint16
	// L3 header mutations
	ttl  uint8
	dscp uint8
	// TCP header mutations
	tcpSetFlags   string
	tcpClearFlags string
	tcpWindow     uint16
	// rate control
	rate       string
	rateRamp   string
	cps        float64
	multiplier float64
	// replay behaviour
	preProcess    bool
	ipPoolPerIter bool
	batchSize     int
	// filter flags
	minDuration string
	maxDuration string
	startAfter  string
	startBefore string
	protos      []string
}

var runCmd = &cobra.Command{
	Use:   "run [flags] <pcap files...>",
	Short: "Replay PCAP sessions onto a network interface",
	Args:  cobra.ArbitraryArgs,
	RunE:  runReplay,
}

func init() {
	f := runCmd.Flags()
	f.StringSliceVarP(&runFlags.ifaces, "interface", "i", nil,
		"network interface(s) to send on; comma-separated or repeatable for multi-interface pool (required)")
	f.StringVar(&runFlags.targetIP, "target-ip", "",
		"auto-resolve outbound interface and gateway MAC for this destination IP")
	f.StringVar(&runFlags.senderType, "sender", "",
		"packet injection backend: pcap (default) or raw (Linux AF_PACKET)")

	f.Float64VarP(&runFlags.speed, "speed", "s", 1.0,
		"replay speed multiplier (0=burst, 1=real-time, 2=2×)")
	f.StringVarP(&runFlags.mode, "mode", "m", "sequential",
		"sequential|parallel|burst|pcap")
	f.BoolVarP(&runFlags.loop, "loop", "l", false, "replay indefinitely")
	f.IntVar(&runFlags.loopCount, "loop-count", 0, "number of replay passes (0=once)")

	f.IntVar(&runFlags.workers, "workers", 4, "goroutine count for parallel mode")

	f.StringVar(&runFlags.srcIP, "src-ip", "", "override source IP for all sessions")
	f.StringVar(&runFlags.dstIP, "dst-ip", "", "override destination IP for all sessions")
	f.StringSliceVar(&runFlags.srcIPPool, "src-ip-pool", nil,
		"source IP pool: random IP per session (CIDR or plain IP, repeatable)")
	f.StringSliceVar(&runFlags.dstIPPool, "dst-ip-pool", nil,
		"destination IP pool: random IP per session (CIDR or plain IP, repeatable)")
	f.IntVar(&runFlags.ipPoolLimit, "ip-pool-limit", 0,
		"max hosts expanded per CIDR in the IP pool (0=default 256, max 65536)")

	f.Uint16Var(&runFlags.srcPortMin, "src-port-min", 0,
		"randomise source port from this value")
	f.Uint16Var(&runFlags.srcPortMax, "src-port-max", 0,
		"randomise source port up to this value")
	f.Uint16Var(&runFlags.dstPort, "dst-port", 0,
		"override destination port for all sessions")

	f.Uint8Var(&runFlags.ttl, "ttl", 0,
		"override TTL (IPv4) / HopLimit (IPv6); 0=keep original")
	f.Uint8Var(&runFlags.dscp, "dscp", 0, "override DSCP (0–63); 0=keep original")

	f.StringVar(&runFlags.tcpSetFlags, "tcp-set-flags", "",
		"TCP flags to force on, comma-separated: SYN,ACK,FIN,RST,PSH,URG")
	f.StringVar(&runFlags.tcpClearFlags, "tcp-clear-flags", "",
		"TCP flags to force off, comma-separated: SYN,ACK,FIN,RST,PSH,URG")
	f.Uint16Var(&runFlags.tcpWindow, "tcp-window", 0,
		"override TCP window size; 0=keep original")

	f.StringVar(&runFlags.rate, "rate", "",
		"rate limit: e.g. 100kpps, 1gbps, 50000pps, 100mbps")
	f.StringVar(&runFlags.rateRamp, "rate-ramp", "",
		"linearly ramp from 0 to --rate over this duration (e.g. 60s)")

	f.Float64Var(&runFlags.cps, "cps", 0,
		"connections per second: new sessions to start per second (0=unlimited; sequential/parallel only)")
	f.Float64Var(&runFlags.multiplier, "multiplier", 1.0,
		"rate multiplier applied to --rate and --cps (e.g. 2.0 doubles the effective rate)")

	f.BoolVar(&runFlags.preProcess, "pre-process", false,
		"pre-mutate all packets before replay starts (burst/parallel only)")

	f.BoolVar(&runFlags.ipPoolPerIter, "ip-pool-per-iter", false,
		"clear mutation plan cache at start of each loop iteration for fresh IP assignments")

	f.IntVar(&runFlags.batchSize, "batch-size", 32,
		"frames per SendBatch call in burst mode (1–256; requires AF_PACKET raw sender)")

	f.StringVar(&runFlags.minDuration, "min-duration", "",
		"skip sessions shorter than this (e.g. 500ms)")
	f.StringVar(&runFlags.maxDuration, "max-duration", "",
		"skip sessions longer than this (e.g. 30s)")
	f.StringVar(&runFlags.startAfter, "start-after", "",
		"skip sessions that start before this time (RFC 3339)")
	f.StringVar(&runFlags.startBefore, "start-before", "",
		"skip sessions that start after this time (RFC 3339)")

	f.StringSliceVar(&runFlags.protos, "proto", nil,
		"include only these protocols (tcp,udp,icmp)")

	rootCmd.AddCommand(runCmd)
}

func runReplay(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(args)
	if err != nil {
		return err
	}

	// Auto-resolve interface from target IP before validation (which checks
	// that cfg.Interface is non-empty).
	if cfg.TargetIP != "" {
		targetIP := net.ParseIP(cfg.TargetIP)
		if targetIP == nil {
			return fmt.Errorf("invalid --target-ip %q", cfg.TargetIP)
		}
		info, err := netutil.Resolve(targetIP)
		if err != nil {
			return fmt.Errorf("auto-interface: %w", err)
		}
		if cfg.Interface == "" && len(cfg.Interfaces) == 0 {
			cfg.Interface = info.Interface.Name
		}
		if info.GatewayMAC != nil && cfg.Mutations.DstMAC == "" {
			cfg.Mutations.DstMAC = info.GatewayMAC.String()
		}
		fmt.Fprintf(os.Stderr, "Auto-resolved: interface=%s gateway=%v gatewayMAC=%v\n",
			cfg.Interface, info.GatewayIP, info.GatewayMAC)
	}

	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	filter, err := parseFilter(cfg.Filter)
	if err != nil {
		return fmt.Errorf("filter: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Loading sessions from %d PCAP file(s)…\n", len(cfg.PcapFiles))
	var allSessions []*session.Session
	for _, src := range cfg.PcapFiles {
		sessions, err := pcapreader.ReadSessions(src.Path)
		if err != nil {
			return err
		}
		allSessions = append(allSessions, sessions...)
	}

	allSessions = filter.Apply(allSessions)
	fmt.Fprintf(os.Stderr, "Replaying %d sessions (mode=%s speed=%.1f)…\n",
		len(allSessions), cfg.Replay.Mode, cfg.Replay.Speed)

	mut, err := mutation.New(cfg.Mutations)
	if err != nil {
		return fmt.Errorf("mutator: %w", err)
	}

	snd, err := buildSender(cfg)
	if err != nil {
		return err
	}
	defer snd.Close()

	interval, err := time.ParseDuration(cfg.Metrics.ReportInterval)
	if err != nil {
		interval = time.Second
	}
	mc, err := metrics.New(interval, cfg.Metrics.Output)
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	mc.TargetRate = cfg.Replay.Rate
	mc.TargetCPS = cfg.Replay.CPS
	mc.Multiplier = cfg.Replay.Multiplier

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	done := make(chan struct{})
	if cfg.Metrics.Enabled {
		go func() {
			mc.Run(done)
		}()
	}

	rp := replay.New(cfg.Replay, mut, snd, mc)
	err = rp.Run(ctx, allSessions)

	close(done)

	snap := mc.Snapshot()
	fmt.Fprintf(os.Stderr,
		"\nDone. packets=%d bytes=%d errors=%d sessions=%d elapsed=%.1fs\n",
		snap.PacketsSent, snap.BytesSent, snap.Errors, snap.SessionsDone, snap.ElapsedSec,
	)
	return err
}

// buildSender creates the appropriate sender.Interface based on config.
// Multi-interface lists produce a PoolSender; --sender raw produces a RawSender.
func buildSender(cfg *config.Config) (sender.Interface, error) {
	// Collect effective interface list.
	ifaces := cfg.Interfaces
	if len(ifaces) == 0 && cfg.Interface != "" {
		ifaces = []string{cfg.Interface}
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no interface specified")
	}

	// TODO: add functionality for RawSender (linux sockets) to be able to send to many interfaces instead of just one.
	switch strings.ToLower(cfg.Sender) {
	case "raw":
		if len(ifaces) != 1 {
			return nil, fmt.Errorf("--sender raw requires exactly one interface")
		}
		return sender.NewRaw(ifaces[0])
	default: // "pcap" or ""
		if len(ifaces) > 1 {
			return sender.NewPool(ifaces)
		}
		return sender.New(ifaces[0])
	}
}

// buildConfig produces a Config from CLI flags, merging a file if --config is set.
func buildConfig(args []string) (*config.Config, error) {
	if cfgFile != "" {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return nil, err
		}
		// CLI flags override config file fields when they are explicitly set.
		if len(runFlags.ifaces) > 0 {
			if len(runFlags.ifaces) == 1 {
				cfg.Interface = runFlags.ifaces[0]
			} else {
				cfg.Interfaces = runFlags.ifaces
			}
		}
		if runFlags.targetIP != "" {
			cfg.TargetIP = runFlags.targetIP
		}
		return cfg, nil
	}

	if len(runFlags.ifaces) == 0 && runFlags.targetIP == "" {
		return nil, fmt.Errorf("--interface or --target-ip is required when no config file is provided")
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one PCAP file is required")
	}

	cfg := config.Default()
	if len(runFlags.ifaces) == 1 {
		cfg.Interface = runFlags.ifaces[0]
	} else if len(runFlags.ifaces) > 1 {
		cfg.Interfaces = runFlags.ifaces
		cfg.Interface = runFlags.ifaces[0]
	}
	cfg.TargetIP = runFlags.targetIP
	cfg.Sender = runFlags.senderType

	for _, p := range args {
		cfg.PcapFiles = append(cfg.PcapFiles, config.PcapSource{Path: p})
	}
	cfg.Replay = config.ReplayConfig{
		Mode:          runFlags.mode,
		Speed:         runFlags.speed,
		Loop:          runFlags.loop,
		LoopCount:     runFlags.loopCount,
		Workers:       runFlags.workers,
		Rate:          runFlags.rate,
		RateRamp:      runFlags.rateRamp,
		CPS:           runFlags.cps,
		Multiplier:    runFlags.multiplier,
		PreProcess:    runFlags.preProcess,
		IPPoolPerIter: runFlags.ipPoolPerIter,
		BatchSize:     runFlags.batchSize,
	}
	cfg.Mutations = config.MutationConfig{
		PreserveSessions: true,
		SrcIP:            runFlags.srcIP,
		DstIP:            runFlags.dstIP,
		SrcIPPool:        runFlags.srcIPPool,
		DstIPPool:        runFlags.dstIPPool,
		IPPoolLimit:      runFlags.ipPoolLimit,
		SrcPortMin:       runFlags.srcPortMin,
		SrcPortMax:       runFlags.srcPortMax,
		DstPort:          runFlags.dstPort,
		TTL:              runFlags.ttl,
		DSCP:             runFlags.dscp,
		TCPSetFlags:      runFlags.tcpSetFlags,
		TCPClearFlags:    runFlags.tcpClearFlags,
		TCPWindow:        runFlags.tcpWindow,
	}
	cfg.Filter = config.FilterConfig{
		MinDuration: runFlags.minDuration,
		MaxDuration: runFlags.maxDuration,
		StartAfter:  runFlags.startAfter,
		StartBefore: runFlags.startBefore,
		Protocols:   runFlags.protos,
	}
	return cfg, nil
}

// parseFilter converts the string-based FilterConfig into a typed session.Filter.
func parseFilter(fc config.FilterConfig) (*session.Filter, error) {
	f := &session.Filter{}
	var err error

	if fc.MinDuration != "" {
		if f.MinDuration, err = time.ParseDuration(fc.MinDuration); err != nil {
			return nil, fmt.Errorf("min_duration %q: %w", fc.MinDuration, err)
		}
	}
	if fc.MaxDuration != "" {
		if f.MaxDuration, err = time.ParseDuration(fc.MaxDuration); err != nil {
			return nil, fmt.Errorf("max_duration %q: %w", fc.MaxDuration, err)
		}
	}
	if fc.StartAfter != "" {
		if f.StartAfter, err = time.Parse(time.RFC3339, fc.StartAfter); err != nil {
			return nil, fmt.Errorf("start_after %q: %w", fc.StartAfter, err)
		}
	}
	if fc.StartBefore != "" {
		if f.StartBefore, err = time.Parse(time.RFC3339, fc.StartBefore); err != nil {
			return nil, fmt.Errorf("start_before %q: %w", fc.StartBefore, err)
		}
	}
	if len(fc.Protocols) > 0 {
		f.Protocols = make(map[string]bool, len(fc.Protocols))
		for _, p := range fc.Protocols {
			f.Protocols[p] = true
		}
	}
	return f, nil
}
